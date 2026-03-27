# 证书链校验特性开发设计文档 v5

## 1 简介

### 1.1 背景说明

#### 1.1.1 证书链校验的重要性

在PKI（公钥基础设施）体系中，X.509证书用于验证实体身份和建立信任关系。证书链校验是确保证书可信的关键环节，其核心目标是验证：

1. **身份真实性**：证书由可信的证书颁发机构（CA）签发
2. **完整性**：证书内容未被篡改
3. **有效性**：证书在有效期内，且未被吊销
4. **用途匹配**：证书的密钥用途符合预期

在实际应用场景中（如HTTPS、代码签名、电子邮件加密等），客户端需要验证服务器或用户证书的合法性，以防止中间人攻击、身份伪造等安全威胁。

#### 1.1.2 功能需求背景

原有的 `validate(certChain: CertChainData)` 接口仅支持验证预先组装好的完整证书链，存在以下局限性：

1. **证书链不完整**：实际场景中，服务器可能只发送终端证书，中间证书需要客户端自行获取
2. **信任锚不灵活**：无法动态指定信任的根证书或使用系统CA
3. **验证参数受限**：无法自定义验证时间、主机名、密钥用途等参数
4. **错误信息不足**：验证失败时无法返回详细的错误原因和已验证的证书链

为解决上述问题，新增 `validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>` 接口，提供更灵活、更完整的证书链校验能力。

#### 1.1.3 各项功能说明

X509CertValidatorParams 提供了丰富的参数配置，用于控制证书链验证的各个方面。根据功能类型，可将参数分为以下几类：

- **信任锚配置**：trustedCerts、trustSystemCa、partialChain --- 定义验证的信任起点
- **证书链构建**：untrustedCerts、allowDownloadIntermediateCa --- 辅助构建完整的证书链
- **时间验证**：date、validateDate --- 控制证书有效期的验证方式
- **扩展验证**：hostnames、emailAddresses、keyUsage --- 验证证书的具体用途和属性
- **特殊场景**：ignoreErrs、userId --- 处理特殊验证需求，如测试环境或国密证书
- **吊销检查**：revokedParams --- 检查证书是否已被吊销

**X509CertValidatorParams 参数功能说明：**

| 参数名 | 类型 | 状态 | 功能作用说明 |
|--------|------|------|-------------|
| trustedCerts | Array\<X509Cert\> | ✅ 已实现 | **信任证书列表**。指定信任的根证书或中间CA证书，作为验证的信任锚点。验证时，证书链必须能追溯到这些信任证书。必须设置此参数或将trustSystemCa设为true。 |
| untrustedCerts | Array\<X509Cert\> | ✅ 已实现 | **非信任证书列表**。提供辅助构建证书链的中间证书。这些证书仅用于构建链，不作为信任锚点。适用于服务器未发送完整证书链的场景。 |
| trustSystemCa | boolean | ✅ 已实现 | **是否信任系统CA**。默认值为false。设为true时，使用操作系统预置的CA证书库作为信任锚。适用于验证公共网站证书，无需手动配置根证书。 |
| partialChain | boolean | ✅ 已实现 | **是否允许部分链验证**。默认值为false。设为true时，允许信任链中的任意证书作为信任锚，而非必须追溯到根证书。 |
| allowDownloadIntermediateCa | boolean | ✅ 已实现 | **是否允许从网络下载中间CA证书**。默认值为false。设为true时，当证书链缺失中间证书时，自动从证书的AIA扩展下载颁发者证书，解决证书链不完整的问题。 |
| date | string | ✅ 已实现 | **验证日期**。格式为YYMMDDHHMMSSZ或YYYYMMDDHHMMSSZ。默认使用当前系统时间。支持自定义验证时间，适用于离线验证历史签名等场景。 |
| validateDate | boolean | ✅ 已实现 | **是否验证日期**。默认值为true。设为false时跳过证书有效期验证。 |
| ignoreErrs | Array\<CertResult\> | ✅ 已实现 | **忽略指定错误**。允许忽略特定的验证错误。例如，可使用CertResult.ERR_CERT_HAS_EXPIRED忽略证书过期错误。适用于特殊场景，如测试环境。 |
| hostnames | Array\<string\> | ✅ 已实现 | **主机名列表**。验证证书的主题备用名（SAN）或通用名（CN）是否包含指定的主机名。用于HTTPS等场景，防止证书被用于非授权域名。 |
| emailAddresses | Array\<string\> | ✅ 已实现 | **邮箱地址列表**。验证证书是否包含指定的邮箱地址。目前仅支持1个邮箱。用于S/MIME邮件加密签名等场景。 |
| keyUsage | Array\<KeyUsageType\> | ✅ 已实现 | **密钥用途列表**。验证证书的密钥用途扩展是否包含指定的用途。确保证书用于预期目的，如数字签名、数据加密、证书签发等。 |
| userId | Uint8Array | ✅ 已实现 | **SM2用户ID**。用于验证国密SM2证书时设置签名验证所需的用户标识符。最常用的SM2用户ID为[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]。 |
| revokedParams | X509CertRevokedParams | ✅ 已实现 | **吊销检查参数**。用于检查证书是否被吊销。包含CRL列表、OCSP响应数据、是否允许在线检查等配置。 |

**X509CertRevokedParams 吊销检查参数功能说明：**

| 参数名 | 类型 | 状态 | 功能作用说明 |
|--------|------|------|-------------|
| revocationFlags | Array\<CertRevocationFlag\> | ✅ 已实现 | **吊销检查标志**。必填参数。设置吊销检查策略：PREFER_OCSP（优先OCSP）、CRL_CHECK（使用CRL）、OCSP_CHECK（使用OCSP）、CHECK_ALL_CERT（检查所有证书）。 |
| crls | Array\<X509CRL\> | ✅ 已实现 | **CRL列表**。提供用于验证的证书吊销列表。如果匹配的CRL存在，则跳过下载。 |
| allowDownloadCrl | boolean | ✅ 已实现 | **是否允许下载CRL**。默认值为false。设为true时，从证书的CRL分发点扩展下载CRL。 |
| ocspResponses | Array\<Uint8Array\> | ✅ 已实现 | **OCSP响应数据**。预置的OCSP响应数据。如果找到匹配的OCSP响应，则跳过在线检查。 |
| allowOcspCheckOnline | boolean | ✅ 已实现 | **是否允许在线OCSP检查**。默认值为false。设为true时，从证书的AIA扩展获取OCSP URL并发送请求。 |
| ocspDigest | OcspDigest | ✅ 已实现 | **OCSP摘要算法**。默认值为SHA256。设置OCSP请求使用的摘要算法（SHA1/SHA224/SHA256/SHA384/SHA512）。 |

**VerifyCertResult 返回结果说明：**

| 参数名 | 类型 | 说明 |
|--------|------|------|
| certChain | Array\<X509Cert\> | **验证后的证书链**。验证成功时返回完整的证书链，从终端证书到信任锚点。可用于后续的证书信息查询或其他验证操作。 |

### 1.2 功能概述

本次需求新增 `validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>` 接口，提供以下功能：

| 功能 | 状态 | 说明 |
|------|------|------|
| 信任证书列表 | ✅ 已实现 | 提供信任的根证书用于验证 |
| 非信任证书列表 | ✅ 已实现 | 提供中间证书辅助构建证书链 |
| 系统CA信任 | ✅ 已实现 | 信任系统预置的CA证书 |
| AIA自动下载中间证书 | ✅ 已实现 | 自动下载缺失的中间证书 |
| 日期验证 | ✅ 已实现 | 验证证书有效期 |
| 主机名验证 | ✅ 已实现 | 验证证书主机名匹配 |
| 邮箱验证 | ✅ 已实现 | 验证证书邮箱地址匹配 |
| 密钥用途验证 | ✅ 已实现 | 验证证书密钥用途匹配 |
| 网络超时处理 | ✅ 已实现 | 下载超时检测和错误返回 |
| DoS防护 | ✅ 已实现 | 下载次数限制防止攻击 |
| 部分链验证 | ✅ 已实现 | 允许部分证书链验证 |
| 忽略错误码 | ✅ 已实现 | 忽略指定验证错误 |
| SM2用户ID | ✅ 已实现 | 国密SM2证书验证支持 |
| 吊销检查（CRL） | ✅ 已实现 | 通过CRL检查证书是否被吊销 |
| 吊销检查（CRL下载） | ✅ 已实现 | 从CDP扩展下载CRL |
| 吊销检查（OCSP） | ✅ 已实现 | 通过OCSP检查证书是否被吊销 |
| 吊销检查（OCSP在线） | ✅ 已实现 | 在线OCSP检查 |

### 1.3 代码量统计

| 模块 | 文件数 | 行数 |
|------|--------|------|
| Adapter层 (OpenSSL适配) | 1 | 1688 行 |
| NAPI层 (JS接口绑定) | 4 | 1852 行 |
| 接口层 (Inner API) | 2 | 352 行 |
| Core层 (核心框架) | 1 | 229 行 |
| **总计** | **8** | **4121 行** |

## 2 实现方案

### 2.1 JS接口

#### 2.1.1 接口定义

**CertChainValidator 类**

```typescript
interface CertChainValidator {
    // 原有接口：验证证书链
    validate(certChain: CertChainData, callback: AsyncCallback<void>): void;
    validate(certChain: CertChainData): Promise<void>;

    // 新增接口：带参数验证单个证书
    validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>;

    // 获取算法名称
    readonly algorithm: string;
}
```

**创建验证器**

```typescript
function createCertChainValidator(algorithm: string): CertChainValidator;
```

- 参数 `algorithm`：验证器类型，目前仅支持 "PKIX"
- 返回值：CertChainValidator 实例

#### 2.1.2 参数结构定义

**X509CertValidatorParams 参数结构**

```typescript
interface X509CertValidatorParams {
    // 信任证书列表（必填，或设置trustSystemCa为true）
    trustedCerts?: Array<X509Cert>;
    // 非信任证书列表（用于提供中间证书）
    untrustedCerts?: Array<X509Cert>;
    // 是否信任系统CA证书
    trustSystemCa?: boolean;
    // 是否允许部分链验证
    partialChain?: boolean;
    // 是否允许自动下载中间证书（核心特性）
    allowDownloadIntermediateCa?: boolean;
    // 验证日期（字符串格式）
    date?: string;
    // 是否验证日期
    validateDate?: boolean;
    // 忽略的错误码列表
    ignoreErrs?: Array<CertResult>;
    // 主机名列表
    hostnames?: Array<string>;
    // 邮箱地址列表
    emailAddresses?: Array<string>;
    // 密钥用途列表
    keyUsage?: Array<KeyUsageType>;
    // SM2用户ID
    userId?: Uint8Array;
    // 吊销检查参数
    revokedParams?: X509CertRevokedParams;
}
```

**X509CertRevokedParams 吊销检查参数**

```typescript
interface X509CertRevokedParams {
    // 吊销检查标志（必填）
    revocationFlags: Array<CertRevocationFlag>;
    // CRL列表
    crls?: Array<X509CRL>;
    // 是否允许下载CRL
    allowDownloadCrl?: boolean;
    // OCSP响应数据
    ocspResponses?: Array<Uint8Array>;
    // 是否允许在线OCSP检查
    allowOcspCheckOnline?: boolean;
    // OCSP摘要算法
    ocspDigest?: OcspDigest;
}
```

**VerifyCertResult 结果结构**

```typescript
interface VerifyCertResult {
    // 验证后的证书链
    readonly certChain: Array<X509Cert>;
}
```

#### 2.1.3 枚举类型定义

**KeyUsageType 密钥用途枚举**

```typescript
enum KeyUsageType {
    KEYUSAGE_DIGITAL_SIGNATURE = 0,    // 数字签名
    KEYUSAGE_NON_REPUDIATION = 1,      // 不可否认
    KEYUSAGE_KEY_ENCIPHERMENT = 2,     // 密钥加密
    KEYUSAGE_DATA_ENCIPHERMENT = 3,    // 数据加密
    KEYUSAGE_KEY_AGREEMENT = 4,        // 密钥协商
    KEYUSAGE_KEY_CERT_SIGN = 5,        // 证书签名
    KEYUSAGE_CRL_SIGN = 6,             // CRL签名
    KEYUSAGE_ENCIPHER_ONLY = 7,        // 仅加密
    KEYUSAGE_DECIPHER_ONLY = 8         // 仅解密
}
```

**CertRevocationFlag 吊销检查标志枚举**

```typescript
enum CertRevocationFlag {
    CERT_REVOCATION_PREFER_OCSP = 0,    // 优先使用OCSP
    CERT_REVOCATION_CRL_CHECK = 1,      // 使用CRL检查
    CERT_REVOCATION_OCSP_CHECK = 2,     // 使用OCSP检查
    CERT_REVOCATION_CHECK_ALL_CERT = 3  // 检查所有证书
}
```

**OcspDigest OCSP摘要算法枚举**

```typescript
enum OcspDigest {
    SHA1 = 0,
    SHA224 = 1,
    SHA256 = 2,
    SHA384 = 3,
    SHA512 = 4
}
```

**CertResult 错误码枚举**

```typescript
enum CertResult {
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 19020001,
    ERR_RUNTIME_ERROR = 19020002,
    ERR_PARAMETER_CHECK_FAILED = 19020003,
    ERR_CRYPTO_OPERATION = 19030001,
    ERR_CERT_SIGNATURE_FAILURE = 19030002,
    ERR_CERT_NOT_YET_VALID = 19030003,
    ERR_CERT_HAS_EXPIRED = 19030004,
    ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 19030005,
    ERR_KEYUSAGE_NO_CERTSIGN = 19030006,
    ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 19030007,
    ERR_CERT_UNTRUSTED = 19030009,
    ERR_CERT_HAS_REVOKED = 19030010,
    ERR_UNKNOWN_CRITICAL_EXTENSION = 19030011,
    ERR_CERT_HOSTNAME_MISMATCH = 19030012,
    ERR_CERT_EMAIL_ADDRESS_MISMATCH = 19030013,
    ERR_CERT_KEYUSAGE_MISMATCH = 19030014,
    ERR_CRL_NOT_FOUND = 19030015,
    ERR_CRL_NOT_YET_VALID = 19030016,
    ERR_CRL_HAS_EXPIRED = 19030017,
    ERR_CRL_SIGNATURE_FAILURE = 19030018,
    ERR_CRL_ISSUER_NOT_FOUND = 19030019,
    ERR_OCSP_RESPONSE_NOT_FOUND = 19030020,
    ERR_OCSP_RESPONSE_INVALID = 19030021,
    ERR_OCSP_SIGNATURE_FAILURE = 19030022,
    ERR_OCSP_VERIFY_FAILED = 19030023,
    ERR_OCSP_CERT_STATUS_UNKNOWN = 19030024,
    ERR_NETWORK_TIMEOUT = 19030025,
}
```

#### 2.1.4 使用示例

**示例1：基本使用（AIA自动下载）**

```typescript
import cert from '@ohos.security.cert';

// 创建证书链验证器
let validator = cert.createCertChainValidator("PKIX");

// 准备验证参数
let params = {
    trustedCerts: [rootCert],                    // 信任的根证书
    allowDownloadIntermediateCa: true,           // 启用自动下载中间证书
    validateDate: true                            // 验证日期
};

// 验证证书
try {
    let result = await validator.validate(leafCert, params);
    console.log("Verification succeeded");
    console.log("Certificate chain length:", result.certChain.length);
} catch (err) {
    console.log("Verification failed:", err.code, err.message);
}
```

**示例2：完整参数**

```typescript
let params = {
    trustedCerts: [rootCert],
    untrustedCerts: [intermediateCert1, intermediateCert2],
    trustSystemCa: false,
    allowDownloadIntermediateCa: true,
    validateDate: true,
    date: "20241231235959Z",
    hostnames: ["example.com", "www.example.com"],
    emailAddresses: ["admin@example.com"],
    keyUsage: [cert.KeyUsageType.KEYUSAGE_DIGITAL_SIGNATURE]
};

let result = await validator.validate(leafCert, params);
```

**示例3：使用系统CA**

```typescript
let params = {
    trustSystemCa: true,                         // 使用系统预置CA
    allowDownloadIntermediateCa: true,
    hostnames: ["www.example.com"]
};

let result = await validator.validate(leafCert, params);
```

**示例4：吊销检查**

```typescript
let params = {
    trustedCerts: [rootCert],
    revokedParams: {
        revocationFlags: [
            cert.CertRevocationFlag.CERT_REVOCATION_PREFER_OCSP,
            cert.CertRevocationFlag.CERT_REVOCATION_CRL_CHECK
        ],
        allowDownloadCrl: true,
        allowOcspCheckOnline: true
    }
};

let result = await validator.validate(leafCert, params);
```

**示例5：忽略错误**

```typescript
let params = {
    trustedCerts: [rootCert],
    ignoreErrs: [cert.CertResult.ERR_CERT_HAS_EXPIRED]  // 忽略证书过期错误
};

let result = await validator.validate(leafCert, params);
```

### 2.2 Inner C接口

#### 2.2.1 核心数据结构

**验证参数结构体 HcfX509CertValidatorParams**

```c
typedef struct {
    HcfX509CertificateArray untrustedCerts;    // 非信任证书列表
    HcfX509CertificateArray trustedCerts;      // 信任证书列表
    bool trustSystemCa;                        // 是否信任系统CA
    bool partialChain;                         // 是否允许部分链验证
    bool allowDownloadIntermediateCa;          // 是否允许下载中间证书
    bool validateDate;                         // 是否验证日期
    char *date;                                // 验证日期字符串
    HcfInt32Array ignoreErrs;                  // 忽略的错误码列表
    HcfStringArray hostnames;                  // 主机名列表
    HcfStringArray emailAddresses;             // 邮箱地址列表
    HcfInt32Array keyUsage;                    // 密钥用途列表
    CfBlob userId;                             // 用户ID
    HcfX509CertRevokedParams *revokedParams;   // 吊销检查参数
} HcfX509CertValidatorParams;
```

**验证结果结构体 HcfVerifyCertResult**

```c
#define MAX_VERIFY_ERROR_MSG_LEN 512

typedef struct {
    HcfX509CertificateArray certs;               // 验证后的证书链
    char errorMsgBuf[MAX_VERIFY_ERROR_MSG_LEN];  // 错误信息缓冲区
    const char *errorMsg;                        // 错误信息
} HcfVerifyCertResult;
```

**吊销检查参数结构体 HcfX509CertRevokedParams**

```c
typedef struct {
    HcfInt32Array revocationFlags;    // 吊销检查标志
    HcfX509CrlArray crls;             // CRL列表
    bool allowDownloadCrl;            // 是否允许下载CRL
    bool allowOcspCheckOnline;        // 是否允许在线OCSP检查
    CfBlobArray ocspResponses;        // OCSP响应数据
    int32_t ocspDigest;               // OCSP摘要算法
} HcfX509CertRevokedParams;
```

**证书链验证器接口 HcfCertChainValidator**

```c
struct HcfCertChainValidator {
    struct CfObjectBase base;

    // 验证证书链（原有接口）
    CfResult (*validate)(HcfCertChainValidator *self,
                         const HcfCertChainData *certChainData);

    // 获取算法名称
    const char *(*getAlgorithm)(HcfCertChainValidator *self);

    // 验证单个X509证书（新增接口）
    CfResult (*validateX509Cert)(HcfCertChainValidator *self,
                                 HcfX509Certificate *cert,
                                 const HcfX509CertValidatorParams *params,
                                 HcfVerifyCertResult *result);
};
```

**创建函数**

```c
CfResult HcfCertChainValidatorCreate(const char *algorithm,
                                     HcfCertChainValidator **pathValidator);
```

#### 2.2.2 辅助类型定义

```c
// 整数数组
typedef struct {
    int32_t *data;
    uint32_t count;
} HcfInt32Array;

// 字符串数组
typedef struct {
    char **data;
    uint32_t count;
} HcfStringArray;

// 证书数组
typedef struct {
    HcfX509Certificate **data;
    uint32_t count;
} HcfX509CertificateArray;

// CRL数组
typedef struct {
    HcfX509Crl **data;
    uint32_t count;
} HcfX509CrlArray;

// Blob数组
typedef struct {
    CfBlob *data;
    uint32_t count;
} CfBlobArray;
```

#### 2.2.3 枚举类型定义

**吊销检查标志 HcfCertRevocationFlag**

```c
typedef enum {
    CERT_REVOCATION_PREFER_OCSP     = 0,
    CERT_REVOCATION_CRL_CHECK       = 1,
    CERT_REVOCATION_OCSP_CHECK      = 2,
    CERT_REVOCATION_CHECK_ALL_CERT  = 3,
} HcfCertRevocationFlag;
```

**OCSP摘要算法 HcfOcspDigest**

```c
typedef enum {
    OCSP_DIGEST_SHA1   = 0,
    OCSP_DIGEST_SHA224 = 1,
    OCSP_DIGEST_SHA256 = 2,
    OCSP_DIGEST_SHA384 = 3,
    OCSP_DIGEST_SHA512 = 4
} HcfOcspDigest;
```

#### 2.2.4 错误码定义 CfResult

```c
typedef enum CfResult {
    CF_SUCCESS = 0,
    CF_INVALID_PARAMS = -10001,
    CF_NOT_SUPPORT = -10002,
    CF_NULL_POINTER = -10003,
    CF_NOT_EXIST = -10004,

    CF_ERR_MALLOC = -20001,
    CF_ERR_COPY = -20002,
    CF_ERR_NAPI = -20003,
    CF_ERR_INTERNAL = -20004,
    CF_ERR_PARAMETER_CHECK = -20005,

    CF_ERR_CRYPTO_OPERATION = -30001,
    CF_ERR_CERT_SIGNATURE_FAILURE = -30002,
    CF_ERR_CERT_NOT_YET_VALID = -30003,
    CF_ERR_CERT_HAS_EXPIRED = -30004,
    CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = -30005,
    CF_ERR_KEYUSAGE_NO_CERTSIGN = -30006,
    CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = -30007,
    CF_ERR_CERT_UNTRUSTED = -30014,
    CF_ERR_CERT_REVOKED = -30015,
    CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION = -30016,
    CF_ERR_CERT_HOST_NAME_MISMATCH = -30017,
    CF_ERR_CERT_EMAIL_MISMATCH = -30018,
    CF_ERR_CERT_KEY_USAGE_MISMATCH = -30019,
    CF_ERR_CRL_NOT_FOUND = -30020,
    CF_ERR_CRL_NOT_YET_VALID = -30021,
    CF_ERR_CRL_HAS_EXPIRED = -30022,
    CF_ERR_CRL_SIGNATURE_FAILURE = -30023,
    CF_ERR_UNABLE_TO_GET_CRL_ISSUER = -30024,
    CF_ERR_OCSP_RESPONSE_NOT_FOUND = -30025,
    CF_ERR_OCSP_RESPONSE_INVALID = -30026,
    CF_ERR_OCSP_SIGNATURE_FAILURE = -30027,
    CF_ERR_OCSP_CERT_STATUS_UNKNOWN = -30029,
    CF_ERR_NETWORK_TIMEOUT = -30030,
} CfResult;
```

### 2.3 实现逻辑

#### 2.3.1 架构层次

```
┌─────────────────────────────────────────────────────────────────┐
│                      JS Application Layer                        │
│                    (ArkTS/TypeScript)                            │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                        NAPI Layer                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_cert_chain_validator.cpp                             │  │
│  │ - CreateCertChainValidator()                              │  │
│  │ - Validate() / ValidateX509Cert()                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_x509_cert_chain_validate_params.cpp                  │  │
│  │ - BuildX509CertValidatorParams()                          │  │
│  │ - 参数解析和转换                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_x509_cert_chain_validate_result.cpp                  │  │
│  │ - BuildVerifyCertResultJS()                               │  │
│  │ - 结果构建和返回                                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ napi_cert_crl_common.cpp                                  │  │
│  │ - CRL相关公共方法                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Core Layer                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ cert_chain_validator.c                                    │  │
│  │ - HcfCertChainValidatorCreate()                           │  │
│  │ - 验证器创建和分发                                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ cert_chain_validator_spi.h                                │  │
│  │ - SPI接口定义                                              │  │
│  │ - engineValidateX509Cert()                                │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Adapter Layer                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ x509_cert_chain_validator_openssl.c                       │  │
│  │                                                           │  │
│  │ 核心验证函数:                                              │  │
│  │ - ValidateX509Cert()         入口函数                      │  │
│  │ - BuildAndVerifyCertChain()  核心验证+下载重试             │  │
│  │                                                           │  │
│  │ AIA下载函数:                                               │  │
│  │ - GetDownloadedCertFromAIAWithRetry()                     │  │
│  │ - TryDownloadFromAccessDescriptionWithRetry()             │  │
│  │ - DownloadCertificateFromUrlWithResult()                  │  │
│  │                                                           │  │
│  │ 吊销检查函数:                                               │  │
│  │ - CheckCertRevocation()       吊销检查入口                 │  │
│  │ - CheckSingleCertByCrl()      CRL检查                      │  │
│  │ - CheckSingleCertByOcsp()     OCSP检查                     │  │
│  │ - DownloadCrlFromCdp()        CRL下载                      │  │
│  │ - PerformOnlineOcspCheck()    在线OCSP检查                 │  │
│  │                                                           │  │
│  │ 参数处理函数:                                               │  │
│  │ - ParseOpenSSLParams()        解析OpenSSL参数              │  │
│  │ - ConstructTrustedStore()     构建信任存储                 │  │
│  │ - ConstructUntrustedStack()   构建非信任栈                 │  │
│  │ - CheckCertValidatorExtensions() 扩展检查                  │  │
│  │ - CheckCertValidatorParams()  参数校验                     │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                     OpenSSL Library                              │
│  X509_verify_cert()      - 证书链验证                            │
│  X509_load_http()        - HTTP下载证书                          │
│  X509_CRL_load_http()    - HTTP下载CRL                           │
│  X509_get_ext_d2i()      - 获取扩展                              │
│  X509_check_host()       - 主机名检查                            │
│  X509_check_email()      - 邮箱检查                              │
│  X509_self_signed()      - 自签名检查                            │
│  OCSP_sendreq_bio()      - 发送OCSP请求                          │
│  OCSP_basic_verify()     - OCSP签名验证                          │
│  ERR_peek_error()        - 错误获取                              │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.3.2 已实现功能详解

##### 2.3.2.1 AIA自动下载中间证书

**背景：**
在证书链验证场景中，当验证过程遇到"无法获取本地颁发者证书"错误（X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY）时，通常是因为缺少中间证书。根据 X.509 标准的 Authority Information Access (AIA) 扩展，证书中可能包含指向颁发者证书的下载URL。本特性实现了自动从AIA扩展下载缺失的中间证书，提高证书链验证的成功率。

**下载参数配置：**

| 参数名 | 宏定义 | 值 | 说明 |
|--------|--------|-----|------|
| 中间CA下载总次数限制 | `MAX_TOTAL_DOWNLOAD_CERT_COUNT` | 5 | 单次验证最多下载5个中间证书 |
| AIA扩展遍历次数限制 | `MAX_INFO_ACCESS_TRAVERSE_COUNT` | 3 | 遍历AIA扩展的最大次数 |
| 单次下载超时 | `DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | HTTP下载证书的超时时间 |

**流程说明：**

```
BuildAndVerifyCertChain() 主循环：
├── remainingCount = 5 (MAX_TOTAL_DOWNLOAD_CERT_COUNT)
├── 循环执行验证
│   ├── 调用 ExecuteSingleVerification() 执行X509_verify_cert()
│   ├── 如果验证成功 → 返回成功
│   ├── 如果错误码不是 X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY → 返回错误
│   ├── 如果 allowDownloadIntermediateCa == false → 返回错误
│   ├── remainingCount--
│   └── 调用 DownloadAndAddIntermediateCert() 下载中间证书
│       ├── 获取证书的AIA扩展 (NID_info_access)
│       ├── 遍历 ACCESS_DESCRIPTION (最多3次: MAX_INFO_ACCESS_TRAVERSE_COUNT)
│       │   ├── 检查 method == NID_ad_ca_issuers (颁发者证书类型)
│       │   ├── 检查 location->type == GEN_URI (URI类型)
│       │   ├── remainingCount--
│       │   └── 调用 DownloadCertFromAiaUrl()
│       │       └── X509_load_http(url, NULL, NULL, 3秒超时)
│       │           ├── 成功 → 返回证书
│       │           ├── 超时 (BIO_R_CONNECT_TIMEOUT/BIO_R_TRANSFER_TIMEOUT) → 返回 CF_ERR_NETWORK_TIMEOUT
│       │           └── 其他失败 → 返回 CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
│       └── 将下载的证书添加到 untrustedCertStack
└── 循环结束（remainingCount == 0 或下载成功）
```

**关键代码实现：**

```c
static CfResult BuildAndVerifyCertChain(
    HcfX509CertValidatorOpenSSLParams *opensslParams,
    const HcfX509CertValidatorParams *params,
    CertVerifyResultInner *result)
{
    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;

    while (remainingCount > 0) {
        // 1. 创建验证上下文
        X509_STORE_CTX *verifyCtx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(verifyCtx, opensslParams->store,
                           opensslParams->cert, opensslParams->untrustedCertStack);

        // 2. 设置验证时间
        if (params->validateDate == false) {
            X509_STORE_CTX_set_flags(verifyCtx, X509_V_FLAG_NO_CHECK_TIME);
        } else if (params->date != NULL) {
            X509_STORE_CTX_set_time(verifyCtx, opensslParams->date);
        }

        // 3. 执行验证
        if (X509_verify_cert(verifyCtx) > 0) {
            // 验证成功，返回证书链
            result->certChain = X509_STORE_CTX_get1_chain(verifyCtx);
            return CF_SUCCESS;
        }

        // 4. 检查错误类型
        int errCode = X509_STORE_CTX_get_error(verifyCtx);
        if (errCode != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
            return ConvertOpensslErrorMsgEx(errCode);
        }

        // 5. 检查是否允许下载
        if (!params->allowDownloadIntermediateCa) {
            return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
        }

        // 6. 获取当前链最后一个证书
        STACK_OF(X509) *currentChain = X509_STORE_CTX_get0_chain(verifyCtx);
        X509 *lastCert = sk_X509_value(currentChain, sk_X509_num(currentChain) - 1);

        // 7. 尝试从AIA下载颁发者证书
        X509 *downloadedCert = NULL;
        DownloadResult downloadRet = GetDownloadedCertFromAIAWithRetry(
            lastCert, &remainingCount, &downloadedCert);

        if (downloadRet == DOWNLOAD_RESULT_TIMEOUT) {
            return CF_ERR_NETWORK_TIMEOUT;
        }
        if (downloadedCert == NULL) {
            return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
        }

        // 8. 将下载的证书添加到非信任栈
        sk_X509_push(opensslParams->untrustedCertStack, downloadedCert);
    }

    return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
}
```

##### 2.3.2.2 DoS防护机制

为防止恶意证书导致无限下载，实现了多层防护：

**下载限制参数汇总：**

| 场景 | 参数 | 值 | 说明 |
|------|------|-----|------|
| 中间CA下载 | `MAX_TOTAL_DOWNLOAD_CERT_COUNT` | 5次 | 单次验证最多下载中间CA证书数量 |
| 中间CA下载 | `MAX_INFO_ACCESS_TRAVERSE_COUNT` | 3次 | 遍历AIA扩展的最大次数 |
| 中间CA下载 | `DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | 单次HTTP下载证书超时 |
| CRL下载 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | CRL下载总次数限制 |
| CRL下载 | `CRL_DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | 单次HTTP下载CRL超时 |
| OCSP请求 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | OCSP请求总次数限制 |
| OCSP请求 | `OCSP_REQUEST_TIMEOUT_SECONDS` | 3秒 | 单次OCSP连接/请求超时 |

**防护策略：**
- 中间CA下载：单次验证最多下载5个证书，每个证书最多遍历3个AIA条目
- CRL下载：单次验证最多下载6次
- OCSP请求：单次验证最多请求6次
- 所有网络操作超时均为3秒
- 超时错误立即返回，不继续重试

##### 2.3.2.3 网络超时检测

```c
static CfResult DownloadCertFromAiaUrl(const char *url, X509 **cert)
{
    ERR_clear_error();
    *cert = X509_load_http(url, NULL, NULL, DOWNLOAD_TIMEOUT_SECONDS);
    if (*cert != NULL) {
        return CF_SUCCESS;
    }

    unsigned long err = ERR_peek_error();
    int reason = ERR_GET_REASON(err);
    
    // 检测超时错误
    if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
        LOGW("Download certificate timeout from URL: %s", url);
        return CF_ERR_NETWORK_TIMEOUT;
    }
    if (reason == ERR_R_MALLOC_FAILURE) {
        return CF_ERR_MALLOC;
    }
    return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
}
```

**超时错误映射：**

| OpenSSL错误原因 | 错误码 | 返回结果 |
|-----------------|--------|----------|
| `BIO_R_CONNECT_TIMEOUT` | 连接超时 | `CF_ERR_NETWORK_TIMEOUT` |
| `BIO_R_TRANSFER_TIMEOUT` | 传输超时 | `CF_ERR_NETWORK_TIMEOUT` |
| `ERR_R_MALLOC_FAILURE` | 内存分配失败 | `CF_ERR_MALLOC` |
| 其他 | 其他错误 | `CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY` |

##### 2.3.2.4 CRL吊销检查

**CRL下载参数配置：**

| 参数名 | 宏定义 | 值 | 说明 |
|--------|--------|-----|------|
| CRL下载总次数限制 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | 单次验证最多下载CRL次数 |
| CRL下载超时 | `CRL_DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | HTTP下载CRL的超时时间 |

**CRL检查流程：**

1. 检查 `revocationFlags` 是否包含 `CERT_REVOCATION_CRL_CHECK`
2. 首先使用 `crls` 参数中提供的 CRL
3. 如果 `allowDownloadCrl` 为 true，尝试从证书的 CRL Distribution Points 扩展下载 CRL
4. 验证 CRL 签名和有效期
5. 检查证书是否在 CRL 中

**CRL下载详细流程：**

```
DownloadCrlFromCdp()：
├── remainingCount = 6 (MAX_TOTAL_DOWNLOAD_COUNT)
├── 获取证书的CRL Distribution Points扩展 (NID_crl_distribution_points)
├── 遍历每个DistributionPoint
│   └── 遍历每个GENERAL_NAME (fullname类型)
│       ├── 检查 type == GEN_URI (URI类型)
│       ├── 校验URL为http/https (IsValidHttpUrl)
│       ├── remainingCount--
│       ├── ERR_clear_error()
│       ├── 调用 X509_CRL_load_http(url, NULL, NULL, 3秒超时)
│       │   ├── 成功 → 返回CRL
│       │   └── 失败 → 检查错误原因
│       │       ├── BIO_R_CONNECT_TIMEOUT → ret = CF_ERR_NETWORK_TIMEOUT
│       │       └── 其他 → 继续
│       └── 如果成功则跳出循环
├── 释放DIST_POINT栈
└── 返回结果
    ├── CRL不为空 → CF_SUCCESS
    ├── 超时 → CF_ERR_NETWORK_TIMEOUT
    └── 其他 → CF_ERR_CRL_NOT_FOUND
```

**关键代码实现：**

```c
static CfResult CheckSingleCertByCrl(X509 *cert, const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    // 1. 创建临时X509_STORE，启用CRL检查
    X509_STORE *store = X509_STORE_new();
    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    
    // 2. 添加用户提供的CRL
    for (uint32_t i = 0; i < revokedParams->crls.count; i++) {
        X509_CRL *crl = GetX509CrlFromHcfX509Crl(revokedParams->crls.data[i]);
        X509_STORE_add_crl(store, crl);
    }
    
    // 3. 创建验证上下文
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    
    // 4. 执行验证
    int ret = X509_verify_cert(ctx);
    if (ret != 1) {
        int err = X509_STORE_CTX_get_error(ctx);
        
        if (err == X509_V_ERR_UNABLE_TO_GET_CRL) {
            // 5. 尝试从网络下载CRL
            if (revokedParams->allowDownloadCrl) {
                X509_CRL *crl = DownloadCrlFromCdp(cert);
                if (crl != NULL) {
                    X509_STORE_add_crl(store, crl);
                    X509_CRL_free(crl);
                    // 重新验证...
                }
            }
        }
    }
    
    return CF_SUCCESS;
}
```

**CRL下载实现：**

```c
static CfResult DownloadCrlFromCdp(X509 *cert, X509_CRL **crlOut, CertVerifyResultInner *result)
{
    STACK_OF(DIST_POINT) *crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
    if (crldp == NULL) {
        return ReturnVerifyError(CF_ERR_CRL_NOT_FOUND, "No CRL distribution points extension found.", result);
    }

    X509_CRL *crl = NULL;
    CfResult ret = CF_ERR_CRL_NOT_FOUND;
    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;
    int num = sk_DIST_POINT_num(crldp);
    
    for (int i = 0; i < num && crl == NULL && remainingCount > 0; i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
        // 检查distpoint类型为fullname
        if (dp == NULL || dp->distpoint == NULL || dp->distpoint->type != 0) {
            continue;
        }

        STACK_OF(GENERAL_NAME) *names = dp->distpoint->name.fullname;
        int nameCount = sk_GENERAL_NAME_num(names);
        
        for (int j = 0; j < nameCount && crl == NULL && remainingCount > 0; j++) {
            GENERAL_NAME *genName = sk_GENERAL_NAME_value(names, j);
            if (genName == NULL || genName->type != GEN_URI) {
                continue;
            }
            
            char *url = (char *)genName->d.uniformResourceIdentifier->data;
            if (!IsValidHttpUrl(url)) {
                LOGW("Invalid CRL URL (not http/https): %s", url);
                continue;
            }
            
            remainingCount--;
            ERR_clear_error();
            crl = X509_CRL_load_http(url, NULL, NULL, CRL_DOWNLOAD_TIMEOUT_SECONDS);
            
            if (crl != NULL) {
                break;
            }
            
            // 检查超时错误
            unsigned long err = ERR_peek_error();
            int reason = ERR_GET_REASON(err);
            if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
                ret = CF_ERR_NETWORK_TIMEOUT;
            }
        }
    }
    
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
    
    if (crl != NULL) {
        *crlOut = crl;
        return CF_SUCCESS;
    }
    
    if (ret == CF_ERR_NETWORK_TIMEOUT) {
        return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "Failed to download CRL from CDP, network timeout.", result);
    }
    return ReturnVerifyError(CF_ERR_CRL_NOT_FOUND, "Failed to download CRL from CDP.", result);
}
```

##### 2.3.2.5 OCSP吊销检查

**OCSP请求参数配置：**

| 参数名 | 宏定义 | 值 | 说明 |
|--------|--------|-----|------|
| OCSP请求总次数限制 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | 单次验证最多OCSP请求次数 |
| OCSP连接超时 | `OCSP_REQUEST_TIMEOUT_SECONDS` | 3秒 | TCP连接超时时间 |
| OCSP响应超时 | `OCSP_REQUEST_TIMEOUT_SECONDS` | 3秒 | HTTP响应超时时间 |

**OCSP检查流程：**

1. 检查 `revocationFlags` 是否包含 `CERT_REVOCATION_OCSP_CHECK`
2. 首先使用 `ocspResponses` 参数中提供的 OCSP 响应
3. 如果 `allowOcspCheckOnline` 为 true，从证书的 AIA 扩展获取 OCSP URL 并发送请求
4. 使用 `ocspDigest` 指定的摘要算法
5. 验证 OCSP 响应签名
6. 检查证书状态

**OCSP在线请求详细流程：**

```
PerformOnlineOcspCheck()：
├── remainingCount = 6 (MAX_TOTAL_DOWNLOAD_COUNT)
├── 获取证书中的OCSP URL列表 (X509_get1_ocsp)
├── 创建OCSP请求
│   ├── 获取摘要算法 (GetOcspDigestByType)
│   ├── 创建 OCSP_CERTID (OCSP_cert_to_id)
│   └── 添加nonce (OCSP_request_add1_nonce)
├── 遍历每个OCSP URL (remainingCount > 0)
│   └── TrySingleOcspUrl()
│       ├── 解析URL (OCSP_parse_url)
│       ├── remainingCount--
│       ├── 创建连接BIO (CreateConnectBio)
│       │   └── BIO_do_connect_retry(bio, 3秒超时, 0)
│       │       ├── 成功 → 返回BIO
│       │       ├── 超时 (BIO_R_CONNECT_TIMEOUT) → CF_ERR_NETWORK_TIMEOUT
│       │       └── 其他失败 → CF_ERR_OCSP_RESPONSE_NOT_FOUND
│       ├── 发送OCSP请求 (SendOcspRequestWithTimeout)
│       │   ├── 创建请求上下文 (OCSP_sendreq_new)
│       │   ├── 设置响应超时 (OSSL_HTTP_REQ_CTX_set_expected, 3秒)
│       │   └── 发送请求 (OCSP_sendreq_nbio)
│       │       ├── 成功 → 返回响应
│       │       ├── 超时 → CF_ERR_NETWORK_TIMEOUT
│       │       └── 其他失败 → CF_ERR_OCSP_RESPONSE_NOT_FOUND
│       └── 验证响应 (VerifyOnlineOcspResponse)
│           ├── 检查响应状态
│           ├── 验证签名 (OCSP_basic_verify)
│           └── 获取证书状态
│               ├── V_OCSP_CERTSTATUS_GOOD → CF_SUCCESS
│               ├── V_OCSP_CERTSTATUS_REVOKED → CF_ERR_CERT_REVOKED
│               └── V_OCSP_CERTSTATUS_UNKNOWN → CF_ERR_OCSP_CERT_STATUS_UNKNOWN
└── 返回最终结果
```

**OCSP在线请求实现：**

```c
static CfResult PerformOnlineOcspCheck(X509 *cert, X509 *issuer,
    const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    // 1. 获取OCSP URL列表
    STACK_OF(OPENSSL_STRING) *ocspUrls = X509_get1_ocsp(cert);
    if (ocspUrls == NULL || sk_OPENSSL_STRING_num(ocspUrls) == 0) {
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "No OCSP URL found in certificate.", result);
    }

    // 2. 创建OCSP请求，使用配置的摘要算法
    OCSP_REQUEST *req = NULL;
    CfResult res = CreateOcspRequest(cert, issuer, params->revokedParams, result, &req);
    if (res != CF_SUCCESS) {
        X509_email_free(ocspUrls);
        return res;
    }

    // 3. 获取certId用于后续验证
    OCSP_CERTID *certId = OCSP_CERTID_dup(OCSP_onereq_get0_id(OCSP_request_onereq_get0(req, 0)));
    
    // 4. 遍历URL发送请求
    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;
    OcspCheckContext ctx = { req, certId, cert, &remainingCount };
    res = CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    
    for (int i = 0; i < sk_OPENSSL_STRING_num(ocspUrls) && remainingCount > 0; i++) {
        res = TrySingleOcspUrl(sk_OPENSSL_STRING_value(ocspUrls, i), &ctx, opensslParams, result);
        // 只有不超时和找不到响应时才继续尝试下一个URL
        if (res != CF_ERR_OCSP_RESPONSE_NOT_FOUND && res != CF_ERR_NETWORK_TIMEOUT) {
            break;
        }
    }
    
    OCSP_CERTID_free(certId);
    OCSP_REQUEST_free(req);
    X509_email_free(ocspUrls);
    return res;
}

static CfResult TrySingleOcspUrl(const char *url, OcspCheckContext *ctx,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    char *host = NULL, *port = NULL, *path = NULL;
    int use_ssl = 0;

    // 解析URL
    if (OCSP_parse_url(url, &host, &port, &path, &use_ssl) != 1) {
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "Failed to parse OCSP URL.", result);
    }

    (*ctx->remainingCount)--;
    
    // 创建连接 (3秒超时)
    int errReason = 0;
    BIO *bio = CreateConnectBio(host, port, &errReason);
    if (bio == NULL) {
        FreeConnectInfo(host, port, path);
        if (errReason == BIO_R_CONNECT_TIMEOUT || errReason == BIO_R_TRANSFER_TIMEOUT) {
            return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "OCSP connection timeout.", result);
        }
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "Failed to connect to OCSP server.", result);
    }

    // 发送请求 (3秒响应超时)
    OCSP_RESPONSE *resp = NULL;
    CfResult sendRes = SendOcspRequestWithTimeout(bio, path, ctx->req, &resp, result);
    BIO_free(bio);
    FreeConnectInfo(host, port, path);

    if (sendRes != CF_SUCCESS) {
        return sendRes;
    }

    // 验证响应
    CfResult res = VerifyOnlineOcspResponse(resp, ctx->certId, ctx->cert, opensslParams, result);
    OCSP_RESPONSE_free(resp);
    return res;
}

static BIO *CreateConnectBio(const char *host, const char *port, int *errReason)
{
    BIO *bio = BIO_new_connect(host);
    if (bio == NULL) {
        *errReason = ERR_GET_REASON(ERR_peek_last_error());
        return NULL;
    }
    BIO_set_conn_port(bio, port);
    // 3秒连接超时
    int ret = BIO_do_connect_retry(bio, OCSP_REQUEST_TIMEOUT_SECONDS, 0);
    if (ret != 1) {
        *errReason = ERR_GET_REASON(ERR_peek_last_error());
        BIO_free(bio);
        return NULL;
    }
    return bio;
}

static CfResult SendOcspRequestWithTimeout(BIO *bio, const char *path, OCSP_REQUEST *req,
    OCSP_RESPONSE **respOut, CertVerifyResultInner *result)
{
    OSSL_HTTP_REQ_CTX *ctx = OCSP_sendreq_new(bio, path, req, -1);
    if (ctx == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP request context.", result);
    }

    // 3秒响应超时
    if (OSSL_HTTP_REQ_CTX_set_expected(ctx, NULL, 1, OCSP_REQUEST_TIMEOUT_SECONDS, 0) != 1) {
        OSSL_HTTP_REQ_CTX_free(ctx);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to set OCSP request timeout.", result);
    }

    OCSP_RESPONSE *resp = NULL;
    int ret = OCSP_sendreq_nbio(&resp, ctx);
    OSSL_HTTP_REQ_CTX_free(ctx);
    
    if (ret == 1) {
        *respOut = resp;
        return CF_SUCCESS;
    }

    int reason = ERR_GET_REASON(ERR_peek_error());
    if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
        return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "OCSP request timeout.", result);
    }
    return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response not found.", result);
}
```

**OCSP摘要算法映射：**

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

##### 2.3.2.6 吊销检查回退逻辑

当同时启用CRL和OCSP检查时，支持自动回退：

| 场景 | 触发条件 | 回退目标 |
|------|----------|----------|
| CRL优先，找不到CRL | `X509_V_ERR_UNABLE_TO_GET_CRL` 且已开启OCSP | OCSP校验 |
| OCSP优先，OCSP不可用 | 配置响应无效且在线检查失败且已开启CRL | CRL校验 |
| 其他错误（CRL过期等） | - | 不回退，直接返回错误 |

##### 2.3.2.7 自签名证书处理

```c
// 使用X509_self_signed判断自签名证书，跳过吊销检查
// 参数0表示只比较subject/issuer，不验证签名
if (X509_self_signed(cert, 0)) {
    LOGD("Skip self-signed certificate at index %d", i);
    continue;
}
```

##### 2.3.2.8 主机名验证

```c
static CfResult CheckCertValidatorExtensions(X509 *x509,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params->hostnames.count > 0) {
        bool match = false;
        for (uint32_t i = 0; i < params->hostnames.count; i++) {
            if (X509_check_host(x509, params->hostnames.data[i],
                strlen(params->hostnames.data[i]), 0, NULL) == 1) {
                match = true;
                break;
            }
        }
        if (!match) {
            return CF_ERR_CERT_HOST_NAME_MISMATCH;
        }
    }
    return CF_SUCCESS;
}
```

##### 2.3.2.9 邮箱验证

```c
if (params->emailAddresses.count > 0) {
    bool match = false;
    for (uint32_t i = 0; i < params->emailAddresses.count; i++) {
        if (X509_check_email(x509, params->emailAddresses.data[i],
            strlen(params->emailAddresses.data[i]), 0) == 1) {
            match = true;
            break;
        }
    }
    if (!match) {
        return CF_ERR_CERT_EMAIL_MISMATCH;
    }
}
```

##### 2.3.2.10 密钥用途验证

```c
if (params->keyUsage.count > 0) {
    uint32_t keyUsage = X509_get_key_usage(x509);
    for (uint32_t i = 0; i < params->keyUsage.count; i++) {
        uint32_t kuBit = ConvertHcfKeyUsageToOpenssl(params->keyUsage.data[i]);
        if (!(keyUsage & kuBit)) {
            return CF_ERR_CERT_KEY_USAGE_MISMATCH;
        }
    }
}
```

##### 2.3.2.11 系统CA信任

```c
static CfResult ConstructTrustedStore(const HcfX509CertValidatorParams *params,
    X509_STORE **store, CertVerifyResultInner *result)
{
    X509_STORE *storeTmp = X509_STORE_new();

    // 添加用户提供的信任证书
    for (uint32_t i = 0; i < params->trustedCerts.count; i++) {
        X509 *cert = GetX509FromHcfX509Certificate(params->trustedCerts.data[i]);
        X509_STORE_add_cert(storeTmp, cert);
    }

    // 加载系统CA证书
    if (params->trustSystemCa) {
        X509_STORE_load_locations(storeTmp, NULL, CERT_VERIFY_DIR);
    }

    *store = storeTmp;
    return CF_SUCCESS;
}
```

#### 2.3.3 下载逻辑详细总结

##### 2.3.3.1 参数配置汇总

| 场景 | 参数名 | 宏定义 | 值 | 说明 |
|------|--------|--------|-----|------|
| **中间CA下载** | 总下载次数限制 | `MAX_TOTAL_DOWNLOAD_CERT_COUNT` | 5次 | 单次验证最多下载中间CA证书数量 |
| **中间CA下载** | AIA遍历次数限制 | `MAX_INFO_ACCESS_TRAVERSE_COUNT` | 3次 | 遍历AIA扩展的最大次数 |
| **中间CA下载** | 下载超时 | `DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | HTTP下载证书超时 |
| **CRL下载** | 总下载次数限制 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | CRL下载总次数限制 |
| **CRL下载** | 下载超时 | `CRL_DOWNLOAD_TIMEOUT_SECONDS` | 3秒 | HTTP下载CRL超时 |
| **OCSP请求** | 总请求次数限制 | `MAX_TOTAL_DOWNLOAD_COUNT` | 6次 | OCSP请求总次数限制 |
| **OCSP请求** | 连接超时 | `OCSP_REQUEST_TIMEOUT_SECONDS` | 3秒 | TCP连接超时 |
| **OCSP请求** | 响应超时 | `OCSP_REQUEST_TIMEOUT_SECONDS` | 3秒 | HTTP响应超时 |

##### 2.3.3.2 中间CA下载流程图

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        BuildAndVerifyCertChain() 主循环                        │
├──────────────────────────────────────────────────────────────────────────────┤
│  remainingCount = MAX_TOTAL_DOWNLOAD_CERT_COUNT (5)                          │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ 循环: while (remainingCount > 0)                                         │ │
│  │   ├── ExecuteSingleVerification()                                       │ │
│  │   │   └── X509_verify_cert()                                            │ │
│  │   │                                                                      │ │
│  │   ├── 成功? ──────────────────────────────────────────────→ 返回成功    │ │
│  │   │                                                                      │ │
│  │   ├── 错误不是 UNABLE_TO_GET_ISSUER_CERT_LOCALLY? ─────────→ 返回错误   │ │
│  │   │                                                                      │ │
│  │   ├── allowDownloadIntermediateCa == false? ───────────────→ 返回错误   │ │
│  │   │                                                                      │ │
│  │   ├── remainingCount--                                                   │ │
│  │   │                                                                      │ │
│  │   └── DownloadAndAddIntermediateCert()                                  │ │
│  │       ├── 获取AIA扩展 (NID_info_access)                                 │ │
│  │       ├── 遍历ACCESS_DESCRIPTION (最多3次)                              │ │
│  │       │   ├── 检查 method == NID_ad_ca_issuers                         │ │
│  │       │   ├── 检查 location->type == GEN_URI                            │ │
│  │       │   ├── remainingCount--                                          │ │
│  │       │   └── TryDownloadFromSingleAia()                                │ │
│  │       │       └── DownloadCertFromAiaUrl()                              │ │
│  │       │           └── X509_load_http(url, NULL, NULL, 3秒)              │ │
│  │       │                   ├── 成功 → 返回证书                           │ │
│  │       │                   ├── 超时 → CF_ERR_NETWORK_TIMEOUT             │ │
│  │       │                   └── 其他 → CF_ERR_UNABLE_TO_GET_ISSUER_CERT   │ │
│  │       └── 添加到untrustedCertStack                                       │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  循环结束 (remainingCount == 0) → 返回错误                                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

##### 2.3.3.3 CRL下载流程图

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           DownloadCrlFromCdp()                                │
├──────────────────────────────────────────────────────────────────────────────┤
│  remainingCount = MAX_TOTAL_DOWNLOAD_COUNT (6)                               │
│                                                                              │
│  获取CRL Distribution Points扩展 (NID_crl_distribution_points)               │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ 遍历每个DistributionPoint:                                               │ │
│  │   └── 遍历每个GENERAL_NAME (fullname):                                   │ │
│  │       ├── 检查 type == GEN_URI                                           │ │
│  │       ├── 校验URL为http/https                                            │ │
│  │       ├── remainingCount--                                               │ │
│  │       ├── ERR_clear_error()                                              │ │
│  │       └── X509_CRL_load_http(url, NULL, NULL, 3秒)                       │ │
│  │           ├── 成功 → 返回CRL                                             │ │
│  │           └── 失败 → 检查错误原因                                        │ │
│  │               ├── BIO_R_CONNECT_TIMEOUT → ret = CF_ERR_NETWORK_TIMEOUT   │ │
│  │               └── 其他 → 继续                                            │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  返回结果:                                                                    │
│    ├── CRL不为空 → CF_SUCCESS                                                │
│    ├── 超时 → CF_ERR_NETWORK_TIMEOUT                                         │
│    └── 其他 → CF_ERR_CRL_NOT_FOUND                                           │
└──────────────────────────────────────────────────────────────────────────────┘
```

##### 2.3.3.4 OCSP在线请求流程图

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         PerformOnlineOcspCheck()                             │
├──────────────────────────────────────────────────────────────────────────────┤
│  remainingCount = MAX_TOTAL_DOWNLOAD_COUNT (6)                               │
│                                                                              │
│  获取OCSP URL列表 (X509_get1_ocsp)                                           │
│  创建OCSP请求 (使用配置的摘要算法)                                            │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │ 遍历每个OCSP URL: while (remainingCount > 0)                             │ │
│  │   └── TrySingleOcspUrl()                                                 │ │
│  │       ├── OCSP_parse_url() 解析URL                                       │ │
│  │       ├── remainingCount--                                               │ │
│  │       ├── CreateConnectBio() 建立连接                                    │ │
│  │       │   └── BIO_do_connect_retry(bio, 3秒, 0)                          │ │
│  │       │       ├── 成功 → 返回BIO                                         │ │
│  │       │       ├── 超时 → CF_ERR_NETWORK_TIMEOUT                          │ │
│  │       │       └── 其他 → CF_ERR_OCSP_RESPONSE_NOT_FOUND                  │ │
│  │       │                                                                  │ │
│  │       ├── SendOcspRequestWithTimeout() 发送请求                          │ │
│  │       │   └── OSSL_HTTP_REQ_CTX_set_expected(..., 3秒) 设置响应超时      │ │
│  │       │   └── OCSP_sendreq_nbio() 发送请求                               │ │
│  │       │       ├── 成功 → 返回响应                                        │ │
│  │       │       ├── 超时 → CF_ERR_NETWORK_TIMEOUT                          │ │
│  │       │       └── 其他 → CF_ERR_OCSP_RESPONSE_NOT_FOUND                  │ │
│  │       │                                                                  │ │
│  │       └── VerifyOnlineOcspResponse() 验证响应                            │ │
│  │           ├── OCSP_basic_verify() 验证签名                               │ │
│  │           └── 获取证书状态                                               │ │
│  │               ├── V_OCSP_CERTSTATUS_GOOD → CF_SUCCESS                    │ │
│  │               ├── V_OCSP_CERTSTATUS_REVOKED → CF_ERR_CERT_REVOKED        │ │
│  │               └── V_OCSP_CERTSTATUS_UNKNOWN → CF_ERR_OCSP_CERT_STATUS_   │ │
│  │                   UNKNOWN                                                │ │
│  │                                                                          │ │
│  │   如果成功或REVOKED，退出循环                                             │ │
│  │   如果超时或找不到响应，继续下一个URL                                      │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  返回最终结果                                                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

##### 2.3.3.5 超时错误处理

所有网络操作都会检测超时错误并返回统一的错误码：

| OpenSSL错误原因 | 错误码含义 | 返回结果 |
|-----------------|------------|----------|
| `BIO_R_CONNECT_TIMEOUT` | TCP连接超时 | `CF_ERR_NETWORK_TIMEOUT` (-30030) |
| `BIO_R_TRANSFER_TIMEOUT` | 数据传输超时 | `CF_ERR_NETWORK_TIMEOUT` (-30030) |

**超时错误特点：**
- 立即返回，不继续重试
- 包含详细的错误信息
- 错误信息中包含证书主题名称

#### 2.3.4 内存管理

| 资源 | 分配时机 | 释放函数 |
|------|----------|----------|
| X509证书（下载） | 下载成功后 | sk_X509_pop_free() |
| X509_STORE | ParseOpenSSLParams | X509_STORE_free() |
| X509_STORE_CTX | BuildAndVerifyCertChain | X509_STORE_CTX_free() |
| AUTHORITY_INFO_ACCESS | GetDownloadedCertFromAIAWithRetry | AUTHORITY_INFO_ACCESS_free() |
| URL字符串 | TryDownloadFromAccessDescriptionWithRetry | CfFree() |
| X509_CRL | DownloadCrlFromCdp | X509_CRL_free() |
| OCSP_REQUEST | PerformOnlineOcspCheck | OCSP_REQUEST_free() |
| OCSP_RESPONSE | PerformOnlineOcspCheck | OCSP_RESPONSE_free() |
| 参数内存 | BuildX509CertValidatorParams | FreeX509CertValidatorParams() |
| 结果内存 | FillVerifyCertResult | 用户调用destroy |

#### 2.3.5 安全考虑

**已实现的安全措施：**
- DoS防护：
  - 中间CA下载：最多5次
  - CRL下载：最多6次
  - OCSP请求：最多6次
- 超时控制：所有网络操作均为3秒超时
- 参数控制：默认不启用自动下载，需显式设置
- 吊销检查：支持CRL和OCSP双重验证
- 自签名证书：自动跳过吊销检查

## 附录

### A. 修改文件清单

| 序号 | 文件路径 | 修改行数 | 说明 |
|------|----------|----------|------|
| 1 | frameworks/adapter/v1.0/src/x509_cert_chain_validator_openssl.c | +1688 | OpenSSL适配层，核心实现 |
| 2 | frameworks/core/v1.0/certificate/cert_chain_validator.c | +229 | 验证器创建和分发 |
| 3 | frameworks/js/napi/certificate/src/napi_cert_chain_validator.cpp | +553 | NAPI接口实现 |
| 4 | frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_params.cpp | +903 | 参数解析 |
| 5 | frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_result.cpp | +151 | 结果构建 |
| 6 | frameworks/js/napi/certificate/src/napi_cert_crl_common.cpp | +245 | CRL相关公共方法 |
| 7 | interfaces/inner_api/certificate/cert_chain_validator.h | +123 | Inner API接口定义 |
| 8 | interfaces/inner_api/common/cf_result.h | +105 | 错误码定义 |

### B. 参考标准

| 标准 | 说明 |
|------|------|
| RFC 5280 | Internet X.509 Public Key Infrastructure Certificate and CRL Profile |
| RFC 4325 | Internet X.509 Public Key Infrastructure Authority Information Access Certificate Extension |
| RFC 5246 | The Transport Layer Security (TLS) Protocol Version 1.2 |
| RFC 6960 | X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP |

### C. 术语说明

| 术语 | 全称 | 说明 |
|------|------|------|
| AIA | Authority Information Access | 权威信息访问扩展，包含颁发者证书的访问方式 |
| OCSP | Online Certificate Status Protocol | 在线证书状态协议 |
| CRL | Certificate Revocation List | 证书吊销列表 |
| CDP | CRL Distribution Points | CRL分发点扩展 |
| PKIX | Public Key Infrastructure (X.509) | 基于X.509的公钥基础设施 |
| CA | Certificate Authority | 证书颁发机构 |
| DoS | Denial of Service | 拒绝服务攻击 |
| PKI | Public Key Infrastructure | 公钥基础设施 |
| SAN | Subject Alternative Name | 主题备用名 |
| CN | Common Name | 通用名 |