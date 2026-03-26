# X509CertRevokedParams 参数实现设计

## 1. 接口定义分析

### 1.1 JSDoc 定义的参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `revocationFlags` | `Array<CertRevocationFlag>` | 必填，吊销检查标志 |
| `crls` | `Array<X509CRL>?` | 可选，CRL列表 |
| `allowDownloadCrl` | `boolean?` | 可选，默认false，是否允许从网络下载CRL |
| `ocspResponses` | `Array<Uint8Array>?` | 可选，OCSP响应数据 |
| `allowOcspCheckOnline` | `boolean?` | 可选，默认false，是否允许在线OCSP检查 |
| `ocspDigest` | `OcspDigest?` | 可选，默认SHA256，OCSP摘要算法 |

### 1.2 CertRevocationFlag 枚举

| 值 | 说明 |
|-----|------|
| `CERT_REVOCATION_PREFER_OCSP = 0` | 优先使用OCSP而非CRL |
| `CERT_REVOCATION_CRL_CHECK = 1` | 启用CRL检查 |
| `CERT_REVOCATION_OCSP_CHECK = 2` | 启用OCSP检查 |
| `CERT_REVOCATION_CHECK_ALL_CERT = 3` | 检查所有证书（自签名证书除外） |

### 1.3 C 结构体定义

```c
typedef struct {
    HcfInt32Array revocationFlags;
    HcfX509CrlArray crls;
    bool allowDownloadCrl;
    bool allowOcspCheckOnline;
    CfBlobArray ocspResponses;
    HcfInt32Array ocspDigest;
} HcfX509CertRevokedParams;
```

---

## 2. 整体架构

```
validateX509Cert()
    │
    ├── 1. BuildAndVerifyCertChain()        // 证书链构建与验证
    │
    └── 2. if (revokedParams != NULL)
            │
            └── CheckCertRevocation()       // 吊销状态检查
                    │
                    ├── 遍历证书链（跳过自签名证书）
                    │
                    ├── if (优先CRL)
                    │       CheckSingleCertByCrl()
                    │       └── 找不到CRL时回退到OCSP
                    │
                    └── if (优先OCSP)
                            CheckSingleCertByOcsp()
                            └── OCSP不可用时回退到CRL
```

---

## 3. 核心实现

### 3.1 主入口函数

```c
static CfResult CheckCertRevocation(STACK_OF(X509) *certChain,
    HcfX509CertValidatorParams *params,
    X509_STORE *trustStore,              // 配置的信任证书存储
    CertVerifyResultInner *result)
{
    HcfX509CertRevokedParams *revo = params->revokedParams;
    
    bool checkCrl = HasFlag(revo, CERT_REVOCATION_CRL_CHECK);
    bool checkOcsp = HasFlag(revo, CERT_REVOCATION_OCSP_CHECK);
    bool preferOcsp = HasFlag(revo, CERT_REVOCATION_PREFER_OCSP);
    bool checkAll = HasFlag(revo, CERT_REVOCATION_CHECK_ALL_CERT);
    
    int chainLen = sk_X509_num(certChain);
    int checkCount = checkAll ? chainLen : 1;
    
    for (int i = 0; i < checkCount; i++) {
        X509 *cert = sk_X509_value(certChain, i);
        
        // 使用X509_self_signed判断自签名证书，跳过
        // 参数0表示只比较subject/issuer，不验证签名
        if (X509_self_signed(cert, 0)) {
            LOGD("Skip self-signed certificate at index %d", i);
            continue;
        }
        
        X509 *issuer = (i + 1 < chainLen) ? sk_X509_value(certChain, i + 1) : NULL;
        if (issuer == NULL) {
            return ReturnVerifyError(CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                "No issuer certificate.", result);
        }
        
        CfResult res = CF_SUCCESS;
        
        if (checkOcsp && checkCrl) {
            if (preferOcsp) {
                res = CheckSingleCertByOcsp(cert, issuer, revo, certChain, trustStore, result);
                if (res == CF_ERR_OCSP_RESPONSE_NOT_FOUND) {
                    res = CheckSingleCertByCrl(cert, issuer, revo, result);
                }
            } else {
                res = CheckSingleCertByCrl(cert, issuer, revo, result);
                if (res == CF_ERR_CRL_NOT_FOUND) {
                    res = CheckSingleCertByOcsp(cert, issuer, revo, certChain, trustStore, result);
                }
            }
        } else if (checkOcsp) {
            res = CheckSingleCertByOcsp(cert, issuer, revo, certChain, trustStore, result);
        } else if (checkCrl) {
            res = CheckSingleCertByCrl(cert, issuer, revo, result);
        }
        
        if (res != CF_SUCCESS) {
            return res;
        }
    }
    
    return CF_SUCCESS;
}
```

---

## 4. CRL 校验实现

### 4.1 关键OpenSSL接口

| 接口 | 说明 |
|------|------|
| `X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK)` | 启用CRL检查 |
| `X509_STORE_add_crl(store, crl)` | 添加CRL到store |
| `X509_CRL_load_http(url, NULL, NULL, timeout)` | 从网络下载CRL |
| `X509_self_signed(cert, 0)` | 判断是否自签名证书 |

### 4.2 CRL相关错误码

| 错误码 | 值 | 说明 |
|--------|-----|------|
| `X509_V_ERR_UNABLE_TO_GET_CRL` | 3 | 无法获取CRL |
| `X509_V_ERR_CRL_NOT_YET_VALID` | 11 | CRL未生效 |
| `X509_V_ERR_CRL_HAS_EXPIRED` | 12 | CRL已过期 |
| `X509_V_ERR_CRL_SIGNATURE_FAILURE` | 8 | CRL签名失败 |

### 4.3 CRL单证书校验流程

```
CheckSingleCertByCrl(cert, issuer, params)
    │
    ├── 1. 创建X509_STORE，只添加issuer作为信任锚
    │
    ├── 2. 添加用户提供的CRL到store
    │
    ├── 3. 创建X509_STORE_CTX，untrusted=NULL（不使用untrusted链）
    │
    ├── 4. 调用 X509_verify_cert()
    │       │
    │       ├── 成功 → 返回 CF_SUCCESS
    │       │
    │       └── 失败，错误码为 X509_V_ERR_UNABLE_TO_GET_CRL
    │               │
    │               ├── 5. 判断是否允许下载CRL (allowDownloadCrl)
    │               │       │
    │               │       ├── 是 → 从CDP下载
    │               │       │       ├── 成功 → 重新验证
    │               │       │       └── 失败 → 进入步骤6
    │               │       │
    │               │       └── 否 → 进入步骤6
    │               │
    │               └── 6. 判断是否开启了OCSP校验
    │                       ├── 是 → 返回 CF_ERR_CRL_NOT_FOUND（触发回退）
    │                       └── 否 → 返回错误
    │
    └── 其他错误（CRL过期、签名失败等）→ 直接返回错误，不回退
```

### 4.4 CRL单证书校验实现

```c
static CfResult CheckSingleCertByCrl(X509 *cert, X509 *issuer,
    HcfX509CertRevokedParams *params, CertVerifyResultInner *result)
{
    // 1. 创建临时X509_STORE，只添加issuer作为信任锚
    X509_STORE *store = X509_STORE_new();
    if (store == NULL) {
        return ReturnVerifyError(CF_ERR_MALLOC, "Failed to create store.", result);
    }
    X509_STORE_add_cert(store, issuer);
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    
    // 2. 添加用户提供的CRL
    for (uint32_t i = 0; i < params->crls.count; i++) {
        HcfX509Crl *x509Crl = params->crls.data[i];
        if (x509Crl == NULL) {
            continue;
        }
        X509_CRL *crl = GetX509CrlFromHcfX509Crl(x509Crl);
        if (crl != NULL) {
            X509_STORE_add_crl(store, crl);
        }
    }
    
    // 3. 创建验证上下文，不使用untrusted
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        X509_STORE_free(store);
        return ReturnVerifyError(CF_ERR_MALLOC, "Failed to create context.", result);
    }
    X509_STORE_CTX_init(ctx, store, cert, NULL);  // untrusted=NULL
    
    // 4. 执行验证
    int ret = X509_verify_cert(ctx);
    CfResult res = CF_SUCCESS;
    
    if (ret != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        
        if (err == X509_V_ERR_UNABLE_TO_GET_CRL) {
            // 5. 尝试从网络下载CRL
            if (params->allowDownloadCrl) {
                X509_CRL *crl = DownloadCrlFromCdp(cert);
                if (crl != NULL) {
                    X509_STORE_add_crl(store, crl);
                    X509_CRL_free(crl);
                    // 重新验证
                    X509_STORE_CTX_cleanup(ctx);
                    X509_STORE_CTX_init(ctx, store, cert, NULL);
                    ret = X509_verify_cert(ctx);
                    if (ret == 1) {
                        goto cleanup;
                    }
                    err = X509_STORE_CTX_get_error(ctx);
                }
            }
            
            // 6. CRL仍不可用，判断是否回退到OCSP
            if (HasFlag(params, CERT_REVOCATION_OCSP_CHECK)) {
                res = CF_ERR_CRL_NOT_FOUND;  // 触发回退
            } else {
                res = ReturnVerifyError(CF_ERR_CRL_NOT_FOUND, 
                    "CRL not available and OCSP not enabled.", result);
            }
        } else if (err == X509_V_ERR_CRL_HAS_EXPIRED) {
            // CRL有效期检查 - 依赖OpenSSL自动检查
            res = ReturnVerifyError(CF_ERR_CRL_HAS_EXPIRED, 
                "CRL has expired.", result);
        } else if (err == X509_V_ERR_CRL_NOT_YET_VALID) {
            res = ReturnVerifyError(CF_ERR_CRL_NOT_YET_VALID, 
                "CRL not yet valid.", result);
        } else if (err == X509_V_ERR_CRL_SIGNATURE_FAILURE) {
            res = ReturnVerifyError(CF_ERR_CRL_SIGNATURE_FAILURE, 
                "CRL signature verification failed.", result);
        } else if (err == X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER) {
            res = ReturnVerifyError(CF_ERR_UNABLE_TO_GET_CRL_ISSUER,
                "Unable to get CRL issuer certificate.", result);
        } else {
            res = ConvertVerifyErrorToResult(err, result);
        }
    }
    
cleanup:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return res;
}

// 从CDP下载CRL
static X509_CRL *DownloadCrlFromCdp(X509 *cert)
{
    STACK_OF(DIST_POINT) *crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (crldp == NULL) {
        return NULL;
    }
    
    X509_CRL *crl = NULL;
    for (int i = 0; i < sk_DIST_POINT_num(crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        char *url = GetDpUrl(dp);
        if (url != NULL) {
            crl = X509_CRL_load_http(url, NULL, NULL, CRL_DOWNLOAD_TIMEOUT);
            if (crl != NULL) {
                break;
            }
        }
    }
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    return crl;
}
```

---

## 5. OCSP 校验实现

### 5.1 关键OpenSSL接口

| 接口 | 说明 |
|------|------|
| `X509_get1_ocsp(cert)` | 从证书获取OCSP URL |
| `OCSP_cert_to_id(dgst, subject, issuer)` | 创建OCSP证书ID |
| `OCSP_request_add0_id(req, cid)` | 添加证书ID到请求 |
| `OCSP_sendreq_bio(bio, path, req)` | 发送OCSP请求 |
| `OCSP_response_status(resp)` | 获取响应状态 |
| `OCSP_response_get1_basic(resp)` | 解析基本响应 |
| `OCSP_check_nonce(req, bs)` | 验证nonce |
| `OCSP_basic_verify(bs, certs, store, flags)` | 验证响应签名 |
| `OCSP_resp_find_status(bs, id, &status, ...)` | 获取证书状态 |

### 5.2 OCSP状态码

| 状态 | 值 | 说明 |
|------|-----|------|
| `V_OCSP_CERTSTATUS_GOOD` | 0 | 证书有效 |
| `V_OCSP_CERTSTATUS_REVOKED` | 1 | 证书已吊销 |
| `V_OCSP_CERTSTATUS_UNKNOWN` | 2 | 状态未知 |

### 5.3 OCSP摘要算法映射

```c
static const EVP_MD *GetOcspDigest(int32_t digestType)
{
    switch (digestType) {
        case OCSP_DIGEST_SHA1:   return EVP_sha1();
        case OCSP_DIGEST_SHA224: return EVP_sha224();
        case OCSP_DIGEST_SHA256: return EVP_sha256();  // 默认
        case OCSP_DIGEST_SHA384: return EVP_sha384();
        case OCSP_DIGEST_SHA512: return EVP_sha512();
        default: return EVP_sha256();
    }
}
```

### 5.4 OCSP单证书校验流程

```
CheckSingleCertByOcsp(cert, issuer, params)
    │
    ├── 1. 尝试使用配置的OCSP响应 (ocspResponses)
    │       │
    │       ├── 找到匹配的响应 → 验证响应 → 返回结果
    │       │
    │       └── 未找到匹配的响应
    │               │
    │               ├── 2. 判断是否允许在线OCSP检查 (allowOcspCheckOnline)
    │               │       │
    │               │       ├── 是 → 在线获取OCSP响应
    │               │       │       ├── 成功 → 验证响应 → 返回结果
    │               │       │       └── 失败 → 进入步骤3
    │               │       │
    │               │       └── 否 → 进入步骤3
    │               │
    │               └── 3. 判断是否开启了CRL校验
    │                       ├── 是 → 返回 CF_ERR_OCSP_RESPONSE_NOT_FOUND（触发回退）
    │                       └── 否 → 返回错误
```

### 5.5 OCSP单证书校验实现

```c
static CfResult CheckSingleCertByOcsp(X509 *cert, X509 *issuer,
    HcfX509CertRevokedParams *params,
    STACK_OF(X509) *certChain,          // 已验证的证书链
    X509_STORE *trustStore,              // 配置的信任证书存储
    CertVerifyResultInner *result)
{
    // 1. 尝试使用配置的OCSP响应
    if (params->ocspResponses.count > 0) {
        for (uint32_t i = 0; i < params->ocspResponses.count; i++) {
            CfResult res = VerifyOcspResponseForCert(cert, issuer, 
                &params->ocspResponses.data[i], params, certChain, trustStore, result);
            if (res == CF_SUCCESS || res == CF_ERR_CERT_REVOKED) {
                return res;
            }
        }
    }
    
    // 2. 尝试在线OCSP检查
    if (params->allowOcspCheckOnline) {
        CfResult res = PerformOnlineOcspCheck(cert, issuer, params, certChain, trustStore, result);
        if (res != CF_ERR_OCSP_RESPONSE_NOT_FOUND && res != CF_ERR_NETWORK_TIMEOUT) {
            return res;
        }
    }
    
    // 3. OCSP不可用，判断是否回退到CRL
    if (HasFlag(params, CERT_REVOCATION_CRL_CHECK)) {
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;  // 触发回退
    }
    
    return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, 
        "OCSP not available and CRL not enabled.", result);
}

static CfResult PerformOnlineOcspCheck(X509 *cert, X509 *issuer,
    HcfX509CertRevokedParams *params,
    STACK_OF(X509) *certChain,          // 已验证的证书链
    X509_STORE *trustStore,              // 配置的信任证书存储
    CertVerifyResultInner *result)
{
    // 1. 获取OCSP URL
    STACK_OF(OPENSSL_STRING) *ocspUrls = X509_get1_ocsp(cert);
    if (ocspUrls == NULL || sk_OPENSSL_STRING_num(ocspUrls) == 0) {
        X509_email_free(ocspUrls);
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    
    // 2. 构建OCSP请求，使用配置的摘要算法
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    const EVP_MD *md = GetOcspDigest(params->ocspDigest.data[0]);
    OCSP_CERTID *certId = OCSP_cert_to_id(md, cert, issuer);
    OCSP_request_add0_id(req, certId);
    OCSP_request_add1_nonce(req, NULL, -1);
    
    // 3. 发送请求
    char *url = sk_OPENSSL_STRING_value(ocspUrls, 0);
    char *host = NULL, *port = NULL, *path = NULL;
    int ssl = 0;
    OCSP_parse_url(url, &host, &port, &path, &ssl);
    
    BIO *bio = CreateConnectBio(host, port, ssl);
    if (bio == NULL) {
        OCSP_REQUEST_free(req);
        X509_email_free(ocspUrls);
        return CF_ERR_NETWORK_TIMEOUT;
    }
    
    OCSP_RESPONSE *resp = OCSP_sendreq_bio(bio, path, req);
    
    // 4. 验证响应 - 使用请求时的certId直接查找
    // 在线OCSP：请求和响应的certID摘要算法应该相同（RFC 6960）
    CfResult res = VerifyOnlineOcspResponse(cert, issuer, resp, certId, certChain, trustStore, result);
    
    // 5. 清理资源
    // 注意：certId会被OCSP_REQUEST_free释放，不需要单独释放
    if (resp != NULL) OCSP_RESPONSE_free(resp);
    BIO_free(bio);
    OCSP_REQUEST_free(req);
    X509_email_free(ocspUrls);
    
    return res;
}

// 验证本地配置的OCSP响应
// 本地响应的certID摘要算法未知，需要遍历响应查找匹配
static CfResult VerifyLocalOcspResponse(X509 *cert, X509 *issuer,
    OCSP_BASICRESP *bs,
    STACK_OF(X509) *certChain,
    X509_STORE *trustStore,
    CertVerifyResultInner *result)
{
    // 1. 遍历响应中的每个单响应，查找匹配的certID
    int status = V_OCSP_CERTSTATUS_UNKNOWN;
    ASN1_GENERALIZEDTIME *thisUpdate = NULL, *nextUpdate = NULL;
    bool found = false;
    
    int respCount = OCSP_resp_count(bs);
    for (int i = 0; i < respCount; i++) {
        OCSP_SINGLERESP *singleResp = OCSP_resp_get0(bs, i);
        if (singleResp == NULL) {
            continue;
        }
        
        // 从响应中获取certID
        const OCSP_CERTID *respCertId = OCSP_SINGLERESP_get0_id(singleResp);
        if (respCertId == NULL) {
            continue;
        }
        
        // 从响应的certID中提取摘要算法
        ASN1_OBJECT *hashAlg = NULL;
        OCSP_id_get0_info(NULL, &hashAlg, NULL, NULL, (OCSP_CERTID *)respCertId);
        if (hashAlg == NULL) {
            continue;
        }
        
        // 使用响应中的摘要算法创建待验证证书的certID
        const EVP_MD *respMd = EVP_get_digestbyobj(hashAlg);
        if (respMd == NULL) {
            continue;
        }
        
        OCSP_CERTID *certId = OCSP_cert_to_id(respMd, cert, issuer);
        if (certId == NULL) {
            continue;
        }
        
        // 比较certID是否匹配
        if (OCSP_id_cmp(certId, respCertId) == 0) {
            // 找到匹配的响应，获取状态
            int reason;
            status = OCSP_single_get0_status(singleResp, &reason, NULL, &thisUpdate, &nextUpdate);
            found = true;
            OCSP_CERTID_free(certId);
            break;
        }
        OCSP_CERTID_free(certId);
    }
    
    if (!found) {
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    
    // 2. 验证有效期
    if (OCSP_check_validity(thisUpdate, nextUpdate, 0, -1) != 1) {
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    
    // 3. 验证签名
    int verifyRet = OCSP_basic_verify(bs, certChain, trustStore, 0);
    if (verifyRet != 1) {
        return CF_ERR_OCSP_SIGNATURE_FAILURE;
    }
    
    // 4. 返回状态
    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            return CF_SUCCESS;
        case V_OCSP_CERTSTATUS_REVOKED:
            return ReturnVerifyError(CF_ERR_CERT_REVOKED, 
                "Certificate is revoked by OCSP.", result);
        default:
            return CF_ERR_OCSP_CERT_STATUS_UNKNOWN;
    }
}

static CfResult VerifyOcspResponseForCert(X509 *cert, X509 *issuer,
    CfBlob *ocspResponseData,
    STACK_OF(X509) *certChain,
    X509_STORE *trustStore,
    CertVerifyResultInner *result)
{
    // 1. 解析OCSP响应数据
    const unsigned char *p = ocspResponseData->data;
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, ocspResponseData->size);
    if (resp == NULL) {
        return CF_ERR_OCSP_RESPONSE_INVALID;
    }
    
    // 2. 检查响应状态
    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        OCSP_RESPONSE_free(resp);
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    
    // 3. 解析基本响应
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
    OCSP_RESPONSE_free(resp);
    if (bs == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    
    // 4. 调用VerifyLocalOcspResponse验证
    // 本地响应：从响应中获取摘要算法
    CfResult res = VerifyLocalOcspResponse(cert, issuer, bs, certChain, trustStore, result);
    
    OCSP_BASICRESP_free(bs);
    return res;
}

// 验证在线OCSP响应
// 使用请求时计算的certId直接查找
static CfResult VerifyOnlineOcspResponse(X509 *cert, X509 *issuer,
    OCSP_RESPONSE *resp,
    OCSP_CERTID *certId,                // 请求时计算的certId
    STACK_OF(X509) *certChain,
    X509_STORE *trustStore,
    CertVerifyResultInner *result)
{
    // 1. 检查响应状态
    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    
    // 2. 解析基本响应
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
    if (bs == NULL) {
        return CF_ERR_CRYPTO_OPERATION;
    }
    
    // 3. 使用请求时的certId直接查找状态
    int status;
    ASN1_GENERALIZEDTIME *thisUpdate = NULL, *nextUpdate = NULL;
    if (OCSP_resp_find_status(bs, certId, &status, NULL, NULL, &thisUpdate, &nextUpdate) != 1) {
        OCSP_BASICRESP_free(bs);
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    
    // 4. 验证有效期
    if (OCSP_check_validity(thisUpdate, nextUpdate, 0, -1) != 1) {
        OCSP_BASICRESP_free(bs);
        return CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    }
    
    // 5. 验证签名
    int verifyRet = OCSP_basic_verify(bs, certChain, trustStore, 0);
    if (verifyRet != 1) {
        OCSP_BASICRESP_free(bs);
        return CF_ERR_OCSP_SIGNATURE_FAILURE;
    }
    
    OCSP_BASICRESP_free(bs);
    
    // 6. 返回状态
    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            return CF_SUCCESS;
        case V_OCSP_CERTSTATUS_REVOKED:
            return ReturnVerifyError(CF_ERR_CERT_REVOKED, 
                "Certificate is revoked by OCSP.", result);
        default:
            return CF_ERR_OCSP_CERT_STATUS_UNKNOWN;
    }
}
```

---

## 6. 错误码定义

错误码已在 `cf_result.h` 中定义，无需新增：

| 错误码 | 值 | 说明 |
|--------|-----|------|
| `CF_ERR_CERT_REVOKED` | -30015 | 证书已被吊销 |
| `CF_ERR_CRL_NOT_FOUND` | -30020 | 找不到CRL |
| `CF_ERR_CRL_NOT_YET_VALID` | -30021 | CRL未生效 |
| `CF_ERR_CRL_HAS_EXPIRED` | -30022 | CRL已过期 |
| `CF_ERR_CRL_SIGNATURE_FAILURE` | -30023 | CRL签名验证失败 |
| `CF_ERR_UNABLE_TO_GET_CRL_ISSUER` | -30024 | 找不到CRL颁发者 |
| `CF_ERR_OCSP_RESPONSE_NOT_FOUND` | -30025 | 找不到OCSP响应 |
| `CF_ERR_OCSP_RESPONSE_INVALID` | -30026 | OCSP响应无效 |
| `CF_ERR_OCSP_SIGNATURE_FAILURE` | -30027 | OCSP签名验证失败 |
| `CF_ERR_OCSP_CERT_STATUS_UNKNOWN` | -30029 | OCSP证书状态未知 |
| `CF_ERR_NETWORK_TIMEOUT` | -30030 | 网络超时 |

### 6.1 错误码映射

| OpenSSL错误码 | CfResult错误码 | 说明 |
|---------------|----------------|------|
| `X509_V_ERR_UNABLE_TO_GET_CRL` | `CF_ERR_CRL_NOT_FOUND` | 找不到CRL |
| `X509_V_ERR_CRL_NOT_YET_VALID` | `CF_ERR_CRL_NOT_YET_VALID` | CRL未生效 |
| `X509_V_ERR_CRL_HAS_EXPIRED` | `CF_ERR_CRL_HAS_EXPIRED` | CRL已过期 |
| `X509_V_ERR_CRL_SIGNATURE_FAILURE` | `CF_ERR_CRL_SIGNATURE_FAILURE` | CRL签名失败 |
| `X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER` | `CF_ERR_UNABLE_TO_GET_CRL_ISSUER` | 找不到CRL颁发者证书 |
| `V_OCSP_CERTSTATUS_REVOKED` | `CF_ERR_CERT_REVOKED` | 证书已吊销 |
| `V_OCSP_CERTSTATUS_UNKNOWN` | `CF_ERR_OCSP_CERT_STATUS_UNKNOWN` | 证书状态未知 |
| OCSP响应未找到 | `CF_ERR_OCSP_RESPONSE_NOT_FOUND` | 无可用OCSP响应 |
| OCSP签名验证失败 | `CF_ERR_OCSP_SIGNATURE_FAILURE` | OCSP签名失败 |
| 网络错误 | `CF_ERR_NETWORK_TIMEOUT` | 网络超时 |

---

## 7. 关键设计决策

### 7.1 自签名证书处理

| 决策 | 实现 |
|------|------|
| 判断方式 | `X509_self_signed(cert, 0)` |
| 参数说明 | `verify_signature=0` 只比较subject/issuer，不验证签名 |
| 处理策略 | 跳过检查，因为自己签名的证书无需检查吊销状态 |

### 7.2 CRL单证书校验

| 决策 | 实现 |
|------|------|
| untrusted链 | 不使用，`X509_STORE_CTX_init(ctx, store, cert, NULL)` |
| 信任锚 | 只添加issuer到X509_STORE |
| 有效期检查 | 依赖OpenSSL自动检查，通过错误码判断 |

### 7.3 回退逻辑

| 场景 | 触发条件 | 回退目标 |
|------|----------|----------|
| CRL优先，找不到CRL | `X509_V_ERR_UNABLE_TO_GET_CRL` 且已开启OCSP | OCSP校验 |
| OCSP优先，OCSP不可用 | 配置响应无效且在线检查失败且已开启CRL | CRL校验 |
| 其他错误（CRL过期等） | - | 不回退，直接返回错误 |

### 7.4 OCSP签名验证

| 决策 | 实现 |
|------|------|
| OCSP_basic_verify 参数 | `OCSP_basic_verify(bs, certChain, trustStore, 0)` |
| certChain 参数 | 已验证的证书链，用于查找OCSP响应签名者证书 |
| trustStore 参数 | 配置的信任证书存储，用于验证签名者是否可信 |
| 不创建临时store | 直接使用传入的 trustStore，避免重复构建 |

### 7.5 OCSP摘要算法与certID验证

**关键区别：**

| 场景 | 函数 | 摘要算法来源 | 验证方式 |
|------|------|-------------|----------|
| 在线OCSP | `VerifyOnlineOcspResponse` | 配置的ocspDigest | 直接用请求时的certId调用`OCSP_resp_find_status` |
| 本地配置的OCSP响应 | `VerifyLocalOcspResponse` | 从响应中提取 | 遍历单响应，用响应中的摘要算法计算certID匹配 |

**在线OCSP验证流程：**

```c
// RFC 6960: OCSP服务器必须使用与请求相同的摘要算法
// 因此可以直接用请求时的certId查找

// 1. 请求时计算certId
const EVP_MD *md = GetOcspDigest(params->ocspDigest.data[0]);
OCSP_CERTID *certId = OCSP_cert_to_id(md, cert, issuer);

// 2. 发送请求...

// 3. 验证响应时直接用certId查找
int status;
OCSP_resp_find_status(bs, certId, &status, NULL, NULL, &thisUpdate, &nextUpdate);
```

**本地配置OCSP响应验证流程：**

```c
// 响应是外部提供的，摘要算法未知，需要遍历查找

int respCount = OCSP_resp_count(bs);
for (int i = 0; i < respCount; i++) {
    OCSP_SINGLERESP *singleResp = OCSP_resp_get0(bs, i);
    const OCSP_CERTID *respCertId = OCSP_SINGLERESP_get0_id(singleResp);
    
    // 从响应的certID中提取摘要算法
    ASN1_OBJECT *hashAlg = NULL;
    OCSP_id_get0_info(NULL, &hashAlg, NULL, NULL, (OCSP_CERTID *)respCertId);
    
    // 使用响应中的摘要算法创建待验证证书的certID
    const EVP_MD *respMd = EVP_get_digestbyobj(hashAlg);
    OCSP_CERTID *certId = OCSP_cert_to_id(respMd, cert, issuer);
    
    // 比较certID是否匹配
    if (OCSP_id_cmp(certId, respCertId) == 0) {
        // 找到匹配的响应
    }
}
```

**关键OpenSSL接口：**

| 接口 | 说明 |
|------|------|
| `OCSP_resp_find_status` | 用certId直接查找状态（在线OCSP） |
| `OCSP_resp_count` | 获取单响应数量 |
| `OCSP_resp_get0` | 获取指定索引的单响应 |
| `OCSP_SINGLERESP_get0_id` | 获取单响应中的certID |
| `OCSP_id_get0_info` | 从certID提取摘要算法 |
| `EVP_get_digestbyobj` | ASN1_OBJECT → EVP_MD |
| `OCSP_id_cmp` | 比较两个certID是否匹配 |

---

## 8. 需要修改的文件

| 文件 | 修改内容 |
|------|----------|
| `x509_cert_chain_validator_openssl.c` | 添加吊销检查函数 |

---

## 9. 测试用例设计

### 9.1 CRL测试用例

| 用例 | 预期结果 |
|------|----------|
| 用户提供有效CRL，证书未吊销 | CF_SUCCESS |
| 用户提供有效CRL，证书已吊销 | CF_ERR_CERT_REVOKED |
| CRL已过期 | CF_ERR_CRL_HAS_EXPIRED |
| CRL未生效 | CF_ERR_CRL_NOT_YET_VALID |
| CRL签名无效 | CF_ERR_CRL_SIGNATURE_FAILURE |
| CRL颁发者证书不在信任链中 | CF_ERR_UNABLE_TO_GET_CRL_ISSUER |
| 允许下载CRL，下载成功 | CF_SUCCESS |
| 允许下载CRL，下载失败，已开启OCSP | 回退到OCSP |
| 允许下载CRL，下载失败，未开启OCSP | CF_ERR_CRL_NOT_FOUND |
| 自签名证书 | 跳过检查 |

### 9.2 OCSP测试用例

| 用例 | 预期结果 |
|------|----------|
| 配置的OCSP响应有效，状态GOOD | CF_SUCCESS |
| 配置的OCSP响应有效，状态REVOKED | CF_ERR_CERT_REVOKED |
| 配置的响应无效，允许在线检查，成功 | CF_SUCCESS |
| 配置的响应无效，允许在线检查，失败，已开启CRL | 回退到CRL |
| 配置的响应无效，允许在线检查，失败，未开启CRL | CF_ERR_OCSP_RESPONSE_NOT_FOUND |
| OCSP响应签名验证失败 | CF_ERR_OCSP_SIGNATURE_FAILURE |

### 9.3 混合测试用例

| 用例 | 预期结果 |
|------|----------|
| CERT_REVOCATION_CHECK_ALL_CERT，检查整个链 | 跳过自签名证书，检查其他所有证书 |
| 优先CRL，CRL失败回退OCSP成功 | CF_SUCCESS |
| 优先OCSP，OCSP失败回退CRL成功 | CF_SUCCESS |
| 只开启CRL，CRL过期 | CF_ERR_CRL_HAS_EXPIRED（不回退） |
| 只开启OCSP，OCSP不可用 | CF_ERR_OCSP_RESPONSE_NOT_FOUND（不回退） |