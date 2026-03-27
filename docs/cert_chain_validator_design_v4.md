# Table of Contents {#table-of-contents .TOC-Heading}

# 证书链校验特性开发设计文档 v4

## 1 简介

### 1.1 背景说明

#### 1.1.1 证书链校验的重要性

在PKI（公钥基础设施）体系中，X.509证书用于验证实体身份和建立信任关系。证书链校验是确保证书可信的关键环节，其核心目标是验证：

1.  **身份真实性**：证书由可信的证书颁发机构（CA）签发
2.  **完整性**：证书内容未被篡改
3.  **有效性**：证书在有效期内，且未被吊销
4.  **用途匹配**：证书的密钥用途符合预期

在实际应用场景中（如HTTPS、代码签名、电子邮件加密等），客户端需要验证服务器或用户证书的合法性，以防止中间人攻击、身份伪造等安全威胁。

#### 1.1.2 功能需求背景

原有的 `validate(certChain: CertChainData)`
接口仅支持验证预先组装好的完整证书链，存在以下局限性：

1.  **证书链不完整**：实际场景中，服务器可能只发送终端证书，中间证书需要客户端自行获取
2.  **信任锚不灵活**：无法动态指定信任的根证书或使用系统CA
3.  **验证参数受限**：无法自定义验证时间、主机名、密钥用途等参数
4.  **错误信息不足**：验证失败时无法返回详细的错误原因和已验证的证书链

为解决上述问题，新增
`validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>`
接口，提供更灵活、更完整的证书链校验能力。

#### 1.1.3 各项功能说明

X509CertValidatorParams
提供了丰富的参数配置，用于控制证书链验证的各个方面。根据功能类型，可将参数分为以下几类：

-   **信任锚配置**：trustedCerts、trustSystemCa、partialChain ---
    定义验证的信任起点
-   **证书链构建**：untrustedCerts、allowDownloadIntermediateCa ---
    辅助构建完整的证书链
-   **时间验证**：date、validateDate --- 控制证书有效期的验证方式
-   **扩展验证**：hostnames、emailAddresses、keyUsage ---
    验证证书的具体用途和属性
-   **特殊场景**：ignoreErrs、userId ---
    处理特殊验证需求，如测试环境或国密证书
-   **吊销检查**：revokedParams --- 检查证书是否已被吊销

**X509CertValidatorParams 参数功能说明：**

  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  参数名                        类型                    状态         功能作用说明
  ----------------------------- ----------------------- ------------ -------------------------------------------------------------------------------------------------------------------------------------------------------
  trustedCerts                  Array\<X509Cert\>       ✅ 已实现    **信任证书列表**。指定信任的根证书或中间CA证书，作为验证的信任锚点。验证时，证书链必须能追溯到这些信任证书。必须设置此参数或将trustSystemCa设为true。

  untrustedCerts                Array\<X509Cert\>       ✅ 已实现    **非信任证书列表**。提供辅助构建证书链的中间证书。这些证书仅用于构建链，不作为信任锚点。适用于服务器未发送完整证书链的场景。

  trustSystemCa                 boolean                 ✅ 已实现    **是否信任系统CA**。默认值为false。设为true时，使用操作系统预置的CA证书库作为信任锚。适用于验证公共网站证书，无需手动配置根证书。

  partialChain                  boolean                 📋 规划中    **是否允许部分链验证**。默认值为false。设为true时，允许信任链中的任意证书作为信任锚，而非必须追溯到根证书。

  allowDownloadIntermediateCa   boolean                 ✅ 已实现    **是否允许从网络下载中间CA证书**。默认值为false。设为true时，当证书链缺失中间证书时，自动从证书的AIA扩展下载颁发者证书，解决证书链不完整的问题。

  date                          string                  ✅ 已实现    **验证日期**。格式为YYMMDDHHMMSSZ或YYYYMMDDHHMMSSZ。默认使用当前系统时间。支持自定义验证时间，适用于离线验证历史签名等场景。

  validateDate                  boolean                 ✅ 已实现    **是否验证日期**。默认值为true。设为false时跳过证书有效期验证。

  ignoreErrs                    Array\<CertResult\>     📋 规划中    **忽略指定错误**。允许忽略特定的验证错误。例如，可使用CertResult.ERR_CERT_HAS_EXPIRED忽略证书过期错误。适用于特殊场景，如测试环境。

  hostnames                     Array\<string\>         ✅ 已实现    **主机名列表**。验证证书的主题备用名（SAN）或通用名（CN）是否包含指定的主机名。用于HTTPS等场景，防止证书被用于非授权域名。

  emailAddresses                Array\<string\>         ✅ 已实现    **邮箱地址列表**。验证证书是否包含指定的邮箱地址。目前仅支持1个邮箱。用于S/MIME邮件加密签名等场景。

  keyUsage                      Array\<KeyUsageType\>   ✅ 已实现    **密钥用途列表**。验证证书的密钥用途扩展是否包含指定的用途。确保证书用于预期目的，如数字签名、数据加密、证书签发等。

  userId                        Uint8Array              📋 规划中    **SM2用户ID**。用于验证国密SM2证书时设置签名验证所需的用户标识符。最常用的SM2用户ID为\[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32,
                                                                     0x33, 0x34, 0x35, 0x36, 0x37, 0x38\]。

  revokedParams                 X509CertRevokedParams   📋 规划中    **吊销检查参数**。用于检查证书是否被吊销。包含CRL列表、OCSP响应数据、是否允许在线检查等配置。
  --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**X509CertRevokedParams 吊销检查参数功能说明：**

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  参数名                 类型                          状态         功能作用说明
  ---------------------- ----------------------------- ------------ -------------------------------------------------------------------------------------------------------------------------------------------------------
  revocationFlags        Array\<CertRevocationFlag\>   📋 规划中    **吊销检查标志**。必填参数。设置吊销检查策略：PREFER_OCSP（优先OCSP）、CRL_CHECK（使用CRL）、OCSP_CHECK（使用OCSP）、CHECK_ALL_CERT（检查所有证书）。

  crls                   Array\<X509CRL\>              📋 规划中    **CRL列表**。提供用于验证的证书吊销列表。如果匹配的CRL存在，则跳过下载。

  allowDownloadCrl       boolean                       📋 规划中    **是否允许下载CRL**。默认值为false。设为true时，从证书的CRL分发点扩展下载CRL。

  ocspResponses          Array\<Uint8Array\>           📋 规划中    **OCSP响应数据**。预置的OCSP响应数据。如果找到匹配的OCSP响应，则跳过在线检查。

  allowOcspCheckOnline   boolean                       📋 规划中    **是否允许在线OCSP检查**。默认值为false。设为true时，从证书的AIA扩展获取OCSP URL并发送请求。

  ocspDigest             OcspDigest                    📋 规划中    **OCSP摘要算法**。默认值为SHA256。设置OCSP请求使用的摘要算法（SHA1/SHA224/SHA256/SHA384/SHA512）。
  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

**VerifyCertResult 返回结果说明：**

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------
  参数名                       类型                  说明
  ---------------------------- --------------------- ----------------------------------------------------------------------------------------------------------------
  certChain                    Array\<X509Cert\>     **验证后的证书链**。验证成功时返回完整的证书链，从终端证书到信任锚点。可用于后续的证书信息查询或其他验证操作。

  -------------------------------------------------------------------------------------------------------------------------------------------------------------------

### 1.2 功能概述

本次需求新增
`validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>`
接口，提供以下功能：

  ----------------------------------------------------------------------------
  功能                    状态                    说明
  ----------------------- ----------------------- ----------------------------
  信任证书列表            ✅ 已实现               提供信任的根证书用于验证

  非信任证书列表          ✅ 已实现               提供中间证书辅助构建证书链

  系统CA信任              ✅ 已实现               信任系统预置的CA证书

  AIA自动下载中间证书     ✅ 已实现               自动下载缺失的中间证书

  日期验证                ✅ 已实现               验证证书有效期

  主机名验证              ✅ 已实现               验证证书主机名匹配

  邮箱验证                ✅ 已实现               验证证书邮箱地址匹配

  密钥用途验证            ✅ 已实现               验证证书密钥用途匹配

  网络超时处理            ✅ 已实现               下载超时检测和错误返回

  DoS防护                 ✅ 已实现               下载次数限制防止攻击

  部分链验证              📋 规划中               允许部分证书链验证

  忽略错误码              📋 规划中               忽略指定验证错误

  SM2用户ID               📋 规划中               国密SM2证书验证支持

  吊销检查（CRL）         📋 规划中               通过CRL检查证书是否被吊销

  吊销检查（OCSP）        📋 规划中               通过OCSP检查证书是否被吊销
  ----------------------------------------------------------------------------

### 1.3 代码量统计

  -----------------------------------------------------------------------
  模块                    文件数                  行数
  ----------------------- ----------------------- -----------------------
  Adapter层 (OpenSSL适配) 1                       858 行

  NAPI层 (JS接口绑定)     7                       903 行

  接口层 (Inner API)      4                       138 行

  Core层 (核心框架)       2                       25 行

  **总计**                **14**                  **1924 行**
  -----------------------------------------------------------------------

## 2 实现方案

### 2.1 JS接口

#### 2.1.1 接口定义

**CertChainValidator 类**

    interface CertChainValidator {
        // 原有接口：验证证书链
        validate(certChain: CertChainData, callback: AsyncCallback<void>): void;
        validate(certChain: CertChainData): Promise<void>;

        // 新增接口：带参数验证单个证书
        validate(cert: X509Cert, params: X509CertValidatorParams): Promise<VerifyCertResult>;

        // 获取算法名称
        readonly algorithm: string;
    }

**创建验证器**

    function createCertChainValidator(algorithm: string): CertChainValidator;

-   参数 `algorithm`：验证器类型，目前仅支持 "PKIX"
-   返回值：CertChainValidator 实例

#### 2.1.2 参数结构定义

**X509CertValidatorParams 参数结构**

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

**X509CertRevokedParams 吊销检查参数**

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

**VerifyCertResult 结果结构**

    interface VerifyCertResult {
        // 验证后的证书链
        readonly certChain: Array<X509Cert>;
    }

#### 2.1.3 枚举类型定义

**KeyUsageType 密钥用途枚举**

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

**CertRevocationFlag 吊销检查标志枚举**

    enum CertRevocationFlag {
        CERT_REVOCATION_PREFER_OCSP = 0,    // 优先使用OCSP
        CERT_REVOCATION_CRL_CHECK = 1,      // 使用CRL检查
        CERT_REVOCATION_OCSP_CHECK = 2,     // 使用OCSP检查
        CERT_REVOCATION_CHECK_ALL_CERT = 3  // 检查所有证书
    }

**OcspDigest OCSP摘要算法枚举**

    enum OcspDigest {
        SHA1 = 0,
        SHA224 = 1,
        SHA256 = 2,
        SHA384 = 3,
        SHA512 = 4
    }

**CertResult 错误码枚举**

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

#### 2.1.4 使用示例

**示例1：基本使用（AIA自动下载）**

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

**示例2：完整参数**

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

**示例3：使用系统CA**

    let params = {
        trustSystemCa: true,                         // 使用系统预置CA
        allowDownloadIntermediateCa: true,
        hostnames: ["www.example.com"]
    };

    let result = await validator.validate(leafCert, params);

**示例4：吊销检查（规划中）**

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

**示例5：忽略错误（规划中）**

    let params = {
        trustedCerts: [rootCert],
        ignoreErrs: [cert.CertResult.ERR_CERT_HAS_EXPIRED]  // 忽略证书过期错误
    };

    let result = await validator.validate(leafCert, params);

### 2.2 Inner C接口

#### 2.2.1 核心数据结构

**验证参数结构体 HcfX509CertValidatorParams**

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

**验证结果结构体 HcfVerifyCertResult**

    typedef struct {
        HcfX509CertificateArray certs;    // 验证后的证书链
        const char *errorMsg;             // 错误信息
    } HcfVerifyCertResult;

**吊销检查参数结构体 HcfX509CertRevokedParams**

    typedef struct {
        HcfInt32Array revocationFlags;    // 吊销检查标志
        HcfX509CrlArray crls;             // CRL列表
        bool allowDownloadCrl;            // 是否允许下载CRL
        bool allowOcspCheckOnline;        // 是否允许在线OCSP检查
        CfBlobArray ocspResponses;        // OCSP响应数据
        HcfInt32Array ocspDigest;         // OCSP摘要算法
    } HcfX509CertRevokedParams;

**证书链验证器接口 HcfCertChainValidator**

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

**创建函数**

    CfResult HcfCertChainValidatorCreate(const char *algorithm,
                                         HcfCertChainValidator **pathValidator);

#### 2.2.2 辅助类型定义

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

#### 2.2.3 枚举类型定义

**密钥用途类型 CfValidationKeyUsageType**

    typedef enum {
        CF_KEYUSAGE_DIGITAL_SIGNATURE,
        CF_KEYUSAGE_NON_REPUDIATION,
        CF_KEYUSAGE_KEY_ENCIPHERMENT,
        CF_KEYUSAGE_DATA_ENCIPHERMENT,
        CF_KEYUSAGE_KEY_AGREEMENT,
        CF_KEYUSAGE_KEY_CERT_SIGN,
        CF_KEYUSAGE_CRL_SIGN,
        CF_KEYUSAGE_ENCIPHER_ONLY,
        CF_KEYUSAGE_DECIPHER_ONLY,
    } CfValidationKeyUsageType;

**吊销检查标志 CfCertRevocationFlag**

    typedef enum {
        CF_REVOCATION_FLAG_PREFER_OCSP = 0,
        CF_REVOCATION_FLAG_CRL_CHECK = 1,
        CF_REVOCATION_FLAG_OCSP_CHECK = 2,
        CF_REVOCATION_FLAG_CHECK_ALL_CERT = 3,
    } CfCertRevocationFlag;

**OCSP摘要算法 CfOcspDigestType**

    typedef enum {
        CF_OCSP_DIGEST_SHA1 = 0,
        CF_OCSP_DIGEST_SHA224 = 1,
        CF_OCSP_DIGEST_SHA256 = 2,
        CF_OCSP_DIGEST_SHA384 = 3,
        CF_OCSP_DIGEST_SHA512 = 4,
    } CfOcspDigestType;

#### 2.2.4 错误码定义 CfResult

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
        CF_ERR_OCSP_VERIFY_FAILED = -30028,
        CF_ERR_OCSP_CERT_STATUS_UNKNOWN = -30029,
        CF_ERR_NETWORK_TIMEOUT = -30030,
    } CfResult;

### 2.3 实现逻辑

#### 2.3.1 架构层次

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
    │  X509_get_ext_d2i()      - 获取扩展                              │
    │  X509_check_host()       - 主机名检查                            │
    │  X509_check_email()      - 邮箱检查                              │
    │  ERR_peek_error()        - 错误获取                              │
    └─────────────────────────────────────────────────────────────────┘

#### 2.3.2 已实现功能详解

##### 2.3.2.1 AIA自动下载中间证书

**背景：**
在证书链验证场景中，当验证过程遇到"无法获取本地颁发者证书"错误（X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY）时，通常是因为缺少中间证书。根据
X.509 标准的 Authority Information Access (AIA)
扩展，证书中可能包含指向颁发者证书的下载URL。本特性实现了自动从AIA扩展下载缺失的中间证书，提高证书链验证的成功率。

**流程说明：**

1.  证书链验证失败，错误码为
    `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY`
2.  检查 `allowDownloadIntermediateCa` 参数是否启用
3.  从当前链中最后一个证书获取 AIA 扩展
4.  遍历 ACCESS_DESCRIPTION 寻找 caIssuers 类型
5.  提取 URI 并调用 `X509_load_http()` 下载证书
6.  将下载的证书添加到非信任证书栈
7.  重新执行证书链验证
8.  循环直到验证成功或达到下载次数限制

**关键代码实现：**

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

##### 2.3.2.2 DoS防护机制

为防止恶意证书导致无限下载，实现了多层防护：

    #define MAX_TOTAL_DOWNLOAD_COUNT 6    // 总下载次数限制
    #define MAX_AIA_URL_RETRY_COUNT 2     // 每个URL重试次数
    #define DOWNLOAD_TIMEOUT_SECONDS 5    // 单次下载超时（秒）

**防护策略：** - 单次验证最多下载 6 个证书 - 每个 URL 最多重试 2 次 -
单次下载超时 5 秒 - 超时错误立即返回，不继续重试

##### 2.3.2.3 网络超时检测

    static DownloadResult DownloadCertificateFromUrlWithResult(const char *url, X509 **cert)
    {
        *cert = X509_load_http(url, NULL, NULL, DOWNLOAD_TIMEOUT_SECONDS);
        if (*cert == NULL) {
            unsigned long err = ERR_peek_error();
            int reason = ERR_GET_REASON(err);

            // 检测超时错误
            if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
                LOGE("Download certificate timeout from URL: %s", url);
                return DOWNLOAD_RESULT_TIMEOUT;
            }
            return DOWNLOAD_RESULT_FAILED;
        }
        return DOWNLOAD_RESULT_SUCCESS;
    }

##### 2.3.2.4 主机名验证

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

##### 2.3.2.5 邮箱验证

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
            return CF_ERR_CERT_EMAIL_ADDRESS_MISMATCH;
        }
    }

##### 2.3.2.6 密钥用途验证

    if (params->keyUsage.count > 0) {
        uint32_t keyUsage = X509_get_key_usage(x509);
        for (uint32_t i = 0; i < params->keyUsage.count; i++) {
            uint32_t kuBit = ConvertHcfKeyUsageToOpenssl(params->keyUsage.data[i]);
            if (!(keyUsage & kuBit)) {
                return CF_ERR_CERT_KEY_USAGE_MISMATCH;
            }
        }
    }

##### 2.3.2.7 系统CA信任

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

#### 2.3.3 规划中功能

以下功能已在接口层定义，实现逻辑待后续开发：

##### 2.3.3.1 吊销检查（CRL/OCSP）

根据 JSDOC 描述，吊销检查将支持：

**CRL检查流程（规划）：** 1. 检查 `revocationFlags` 是否包含
`CERT_REVOCATION_CRL_CHECK` 2. 首先使用 `crls` 参数中提供的 CRL 3. 如果
`allowDownloadCrl` 为 true，尝试从证书的 CRL Distribution Points
扩展下载 CRL 4. 验证 CRL 签名和有效期 5. 检查证书是否在 CRL 中

**OCSP检查流程（规划）：** 1. 检查 `revocationFlags` 是否包含
`CERT_REVOCATION_OCSP_CHECK` 2. 首先使用 `ocspResponses` 参数中提供的
OCSP 响应 3. 如果 `allowOcspCheckOnline` 为 true，从证书的 AIA 扩展获取
OCSP URL 并发送请求 4. 使用 `ocspDigest` 指定的摘要算法 5. 验证 OCSP
响应签名 6. 检查证书状态

##### 2.3.3.2 忽略错误码

    // 使用示例
    let params = {
        trustedCerts: [rootCert],
        ignoreErrs: [cert.CertResult.ERR_CERT_HAS_EXPIRED]  // 忽略证书过期错误
    };

##### 2.3.3.3 SM2用户ID

    // 使用示例
    let params = {
        trustedCerts: [rootCert],
        userId: new Uint8Array([0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
                                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38])
    };

#### 2.3.4 内存管理

  ---------------------------------------------------------------------------------------------------
  资源                    分配时机                                    释放函数
  ----------------------- ------------------------------------------- -------------------------------
  X509证书（下载）        下载成功后                                  sk_X509_pop_free()

  X509_STORE              ParseOpenSSLParams                          X509_STORE_free()

  X509_STORE_CTX          BuildAndVerifyCertChain                     X509_STORE_CTX_free()

  AUTHORITY_INFO_ACCESS   GetDownloadedCertFromAIAWithRetry           AUTHORITY_INFO_ACCESS_free()

  URL字符串               TryDownloadFromAccessDescriptionWithRetry   CfFree()

  参数内存                BuildX509CertValidatorParams                FreeX509CertValidatorParams()

  结果内存                FillVerifyCertResult                        用户调用destroy
  ---------------------------------------------------------------------------------------------------

#### 2.3.5 安全考虑

**已实现的安全措施：** - DoS防护：下载次数限制为 6 次 -
超时控制：单次下载 5 秒超时 - 参数控制：默认不启用自动下载，需显式设置

**待完善的安全措施：** - SSL/TLS 验证下载的证书 - 下载证书的签名验证

## 附录

### A. 修改文件清单

  --------------------------------------------------------------------------------------------------------------------------------------------
  序号          文件路径                                                                      修改行数               说明
  ------------- ----------------------------------------------------------------------------- ---------------------- -------------------------
  1             frameworks/adapter/v1.0/src/x509_cert_chain_validator_openssl.c               +858                   OpenSSL适配层，核心实现

  2             frameworks/core/v1.0/certificate/cert_chain_validator.c                       +20                    验证器创建和分发

  3             frameworks/core/v1.0/spi/cert_chain_validator_spi.h                           +5                     SPI接口定义

  4             frameworks/js/napi/certificate/src/napi_cert_chain_validator.cpp              +156                   NAPI接口实现

  5             frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_params.cpp   +643                   参数解析

  6             frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_result.cpp   +57                    结果构建

  7             frameworks/js/napi/certificate/inc/napi_cert_defines.h                        +39                    NAPI常量定义

  8             frameworks/js/napi/certificate/inc/napi_cert_chain_validator.h                +1                     头文件

  9             frameworks/js/napi/certificate/inc/napi_x509_cert_chain_validate_params.h     +4                     参数头文件

  10            frameworks/js/napi/certificate/inc/napi_x509_cert_chain_validate_result.h     +3                     结果头文件

  11            interfaces/inner_api/certificate/cert_chain_validator.h                       +83                    Inner API接口定义

  12            interfaces/inner_api/common/cf_result.h                                       +35                    错误码定义

  13            interfaces/inner_api/include/cf_type.h                                        +15                    类型定义

  14            interfaces/inner_api/common/cf_blob.h                                         +5                     Blob类型定义
  --------------------------------------------------------------------------------------------------------------------------------------------

### B. 参考标准

  -----------------------------------------------------------------------
  标准                                说明
  ----------------------------------- -----------------------------------
  RFC 5280                            Internet X.509 Public Key
                                      Infrastructure Certificate and CRL
                                      Profile

  RFC 4325                            Internet X.509 Public Key
                                      Infrastructure Authority
                                      Information Access Certificate
                                      Extension

  RFC 5246                            The Transport Layer Security (TLS)
                                      Protocol Version 1.2

  RFC 6960                            X.509 Internet Public Key
                                      Infrastructure Online Certificate
                                      Status Protocol - OCSP
  -----------------------------------------------------------------------

### C. 术语说明

  --------------------------------------------------------------------------------------------
  术语                    全称                    说明
  ----------------------- ----------------------- --------------------------------------------
  AIA                     Authority Information   权威信息访问扩展，包含颁发者证书的访问方式
                          Access                  

  OCSP                    Online Certificate      在线证书状态协议
                          Status Protocol         

  CRL                     Certificate Revocation  证书吊销列表
                          List                    

  PKIX                    Public Key              基于X.509的公钥基础设施
                          Infrastructure (X.509)  

  CA                      Certificate Authority   证书颁发机构

  DoS                     Denial of Service       拒绝服务攻击

  PKI                     Public Key              公钥基础设施
                          Infrastructure          

  SAN                     Subject Alternative     主题备用名
                          Name                    

  CN                      Common Name             通用名
  --------------------------------------------------------------------------------------------
