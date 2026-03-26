# AGENTS.md

This file provides context for AI agents working on the OpenHarmony Certificate Framework project.

## Project Overview

OpenHarmony Certificate Framework - a C/C++ framework that provides unified JavaScript APIs for certificate parsing, validation, and management. It shields differences between third-party certificate algorithm libraries (OpenSSL/Mbed TLS).

## Current Work Focus: validateX509Cert Interface

### Commit: 8c9027f

**Summary:** 新增validateX509Cert接口支持X509证书链验证

### 功能概述

`validateX509Cert`接口提供完整的X509证书链验证功能，支持：
- 证书链完整性验证
- 中间证书AIA自动下载
- 多种验证参数配置
- 详细错误信息返回

### 关键文件

| 文件 | 描述 |
|------|------|
| `interfaces/inner_api/certificate/cert_chain_validator.h` | 内部API接口定义，HcfX509CertValidatorParams和HcfVerifyCertResult结构体 |
| `interfaces/js/@ohos.security.cert.d.ts` | JavaScript API类型定义 |
| `frameworks/adapter/v1.0/src/x509_cert_chain_validator_openssl.c` | OpenSSL适配器实现(981行) |
| `frameworks/core/v1.0/certificate/cert_chain_validator.c` | 核心层实现 |
| `frameworks/js/napi/certificate/src/napi_cert_chain_validator.cpp` | NAPI接口实现，validateX509Cert方法绑定 |
| `frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_params.cpp` | NAPI参数解析，JS对象转C结构体 |
| `frameworks/js/napi/certificate/src/napi_x509_cert_chain_validate_result.cpp` | NAPI结果转换，C结构体转JS对象 |
| `frameworks/js/napi/certificate/inc/napi_cert_defines.h` | NAPI常量定义，参数名称字符串 |
| `frameworks/js/napi/certificate/src/napi_cert_crl_common.cpp` | NAPI CRL相关公共方法 |

### 接口定义

```c
CfResult (*validateX509Cert)(HcfCertChainValidator *self, 
    HcfX509Certificate *cert,
    const HcfX509CertValidatorParams *params, 
    HcfVerifyCertResult *result);
```

### 验证参数(HcfX509CertValidatorParams)

| 参数 | 类型 | 说明 |
|------|------|------|
| trustedCerts | HcfX509CertificateArray | 信任锚证书列表 |
| trustSystemCa | bool | 是否信任系统CA |
| untrustedCerts | HcfX509CertificateArray | 不信任的中间证书 |
| allowDownloadIntermediateCa | bool | 是否允许下载中间证书 |
| validateDate | bool | 是否验证日期 |
| date | char* | 自定义验证时间 |
| hostnames | HcfStringArray | 主机名匹配列表 |
| emailAddresses | HcfStringArray | 邮箱地址匹配列表 |
| keyUsage | HcfInt32Array | 密钥用法校验 |
| revokedParams | HcfX509CertRevokedParams* | 吊销检查参数 |

### 吊销检查参数(HcfX509CertRevokedParams)

| 参数 | 类型 | 说明 |
|------|------|------|
| revocationFlags | HcfInt32Array | CRL_CHECK/OCSP_CHECK等标志 |
| crls | HcfX509CrlArray | CRL列表 |
| allowDownloadCrl | bool | 是否允许下载CRL |
| allowOcspCheckOnline | bool | 是否允许在线OCSP检查 |

### 中间证书AIA下载

- 通过证书的Authority Information Access扩展获取下载URL
- 下载超时: 5秒
- 最大下载次数: 6次(防止DoS攻击)
- 每个URL重试次数: 2次

### 错误码

| 代码 | 常量 | 描述 |
|------|------|------|
| -20005 | CF_ERR_PARAMETER_CHECK | 参数校验失败 |
| -30001 | CF_ERR_CRYPTO_OPERATION | OpenSSL操作失败 |
| -30003 | CF_ERR_CERT_NOT_YET_VALID | 证书未生效 |
| -30004 | CF_ERR_CERT_HAS_EXPIRED | 证书已过期 |
| -30005 | CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY | 无法获取颁发者证书 |
| -30014 | CF_ERR_CERT_UNTRUSTED | 证书不受信任 |
| -30017 | CF_ERR_HOSTNAME_NOT_MATCHED | 主机名不匹配 |
| -30018 | CF_ERR_EMAIL_NOT_MATCHED | 邮箱地址不匹配 |
| -30019 | CF_ERR_KEYUSAGE_NOT_MATCHED | 密钥用法不匹配 |
| -30030 | CF_ERR_NETWORK_TIMEOUT | 网络超时 |

### 项目结构

```
base/security/certificate_framework
├── frameworks/
│   ├── adapter/v1.0/src/        # OpenSSL适配器实现
│   ├── core/v1.0/               # 核心框架逻辑
│   └── js/napi/                 # NAPI JavaScript绑定
├── interfaces/inner_api/        # 内部API头文件
└── test/unittest/v1.0/          # 单元测试
    ├── src/                     # 测试实现
    └── include/                 # 测试头文件和Mock
```

### 构建命令

```bash
# 同步代码到构建目录
rsync -av --exclude='.git' /home/lm/code/security_certificate_framework/ /home/lm/test_tdd/build_asan_tdd/security/certificate_framework/

# 构建TDD
cd /home/lm/test_tdd/build_asan_tdd && bash build.sh certificate

# 运行validateX509Cert测试
cd /home/lm/test_tdd/build_asan_tdd && export LD_LIBRARY_PATH=/home/lm/test_tdd/build_asan_tdd/output/lib:$LD_LIBRARY_PATH && ./output/bin/cf_version1_test --gtest_filter="*ValidateX509Cert*"
```

### GN构建命令

```bash
# 同步代码到构建目录
rsync -av --exclude='.git' /home/lm/code/security_certificate_framework/ /home/lm/openharmony2/base/security/certificate_framework/

# 构建版本
cd /home/lm/openharmony2 && time hb build certificate_framework -i --skip-download

# 构建tdd
cd /home/lm/openharmony2 && time hb build certificate_framework -t --skip-download
```

### 测试覆盖率报告

```
/home/lm/test_tdd/build_asan_tdd/coverage/report/frameworks/adapter/v1.0/src/x509_cert_chain_validator_openssl.c.gcov.html
```

### 待覆盖分支

| 行号 | 代码 | 分支 | 描述 |
|------|------|------|------|
| 666 | `while (remainingCount > 0)` | 循环退出条件 | 超过最大下载次数 |
| 733 | `result == NULL \|\| result->certChain != NULL` | 分支1,2 | 无效result参数 |
| 766 | `verifiedChain == NULL \|\| sk_X509_num(verifiedChain) == 0` | 分支2 | 空证书链 |

### 注意事项

- 本地环境LSP报错"missing gtest/gtest.h"是正常的，代码在构建环境中可以正确编译
- Mock框架使用wrap机制，函数需添加到`wrap_certificate_framework.txt`
- `FreeValidatorParams()`会释放trustedCerts和untrustedCerts，不要单独调用`CfObjDestroy`