# OCSP测试数据设计方案

## Context

当前OCSP测试数据分散在多组证书链中，不便于统一管理和复用。需要创建一套统一的测试数据，满足多种OCSP场景测试需求。

## 现有数据分析

### 当前数据分布

| 数据组 | 证书链 | 用途 |
|--------|--------|------|
| 主证书链 | `g_testRootCaCert` + `g_testIntermediateCaCert` + `g_testEndEntityCert` | 无OCSP URL场景 |
| OCSP专用链 | `g_testRootCaForOcsp` + `g_testIntermediateCaForOcsp` + `g_testEndEntityForOcsp` | 有OCSP URL场景 |
| 本地OCSP测试 | `g_ocspLocalTestCa` + `g_ocspLocalTestEe` | 本地OCSP响应测试 |

### 问题

1. 多套证书链导致数据冗余
2. 终端实体证书的OCSP URL差异较大，不是同一证书的不同版本
3. 不同测试用例使用不同证书链，难以统一

## 设计方案

### 证书链结构

创建一套统一的证书链：

```
根CA (g_ocspTestRootCa)
  └── 中间CA (g_ocspTestIntermediateCa)
        ├── 终端实体1 (g_ocspTestEeNoOcspUrl)     - 无OCSP URL
        ├── 终端实体2 (g_ocspTestEeValidOcspUrl)  - 有效OCSP URL
        └── 终端实体3 (g_ocspTestEeInvalidOcspUrl)- 无效OCSP URL
```

### 终端实体证书设计

**关键点：** 3本终端实体证书的主体名、密钥、有效期完全相同，仅OCSP URL扩展不同。

| 证书 | OCSP URL | 测试场景 |
|------|----------|----------|
| `g_ocspTestEeNoOcspUrl` | 无 | 在线OCSP失败 → CF_ERR_OCSP_RESPONSE_NOT_FOUND |
| `g_ocspTestEeValidOcspUrl` | `http://localhost:9999/ocsp` (可配置) | 在线OCSP服务不可达 |
| `g_ocspTestEeInvalidOcspUrl` | `not-a-valid-url` | URL解析失败 |

### OCSP响应数据

为终端实体证书生成3种OCSP响应：

| 响应 | 状态 | 测试场景 |
|------|------|----------|
| `g_ocspTestResponseGood` | V_OCSP_CERTSTATUS_GOOD | 验证通过 → CF_SUCCESS |
| `g_ocspTestResponseRevoked` | V_OCSP_CERTSTATUS_REVOKED | 证书已吊销 → CF_ERR_CERT_REVOKED |
| `g_ocspTestResponseUnknown` | V_OCSP_CERTSTATUS_UNKNOWN | 状态未知 → CF_ERR_OCSP_CERT_STATUS_UNKNOWN |

## 实施步骤

### Step 1: 生成测试证书

使用OpenSSL生成统一证书链（证书有效期均为20年）：

```bash
# 创建工作目录
mkdir -p /tmp/ocsp_unified_test && cd /tmp/ocsp_unified_test

# 1. 创建根CA (有效期20年 = 7300天)
openssl genrsa -out ocsp_test_root_ca.key 2048
openssl req -x509 -new -nodes -key ocsp_test_root_ca.key -sha256 -days 7300 \
    -out ocsp_test_root_ca.pem -subj "/C=US/O=Test Org/CN=OCSP Test Root CA"

# 2. 创建中间CA扩展配置文件
cat > intermediate_ext.cnf << 'EOF'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF

# 3. 创建中间CA (有效期20年)
openssl genrsa -out ocsp_test_intermediate_ca.key 2048
openssl req -new -key ocsp_test_intermediate_ca.key \
    -out ocsp_test_intermediate_ca.csr -subj "/C=US/O=Test Org/CN=OCSP Test Intermediate CA"
openssl x509 -req -in ocsp_test_intermediate_ca.csr -CA ocsp_test_root_ca.pem \
    -CAkey ocsp_test_root_ca.key -CAcreateserial -out ocsp_test_intermediate_ca.pem \
    -days 7300 -sha256 -extfile intermediate_ext.cnf

# 4. 创建终端实体证书扩展配置文件

# 4.1 无OCSP URL
cat > ee_no_ocsp.cnf << 'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
EOF

# 4.2 有效OCSP URL
cat > ee_valid_ocsp.cnf << 'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
authorityInfoAccess = OCSP;URI:http://localhost:9999/ocsp
EOF

# 4.3 无效OCSP URL
cat > ee_invalid_ocsp.cnf << 'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always, issuer
authorityInfoAccess = OCSP;URI:not-a-valid-url
EOF

# 5. 创建终端实体证书（3本，使用相同密钥，区别仅在OCSP URL，有效期20年）
openssl genrsa -out ocsp_test_ee.key 2048
openssl req -new -key ocsp_test_ee.key -out ocsp_test_ee.csr \
    -subj "/C=US/O=Test Org/CN=OCSP Test End Entity"

# 无OCSP URL (有效期20年)
openssl x509 -req -in ocsp_test_ee.csr -CA ocsp_test_intermediate_ca.pem \
    -CAkey ocsp_test_intermediate_ca.key -CAcreateserial -out ocsp_test_ee_no_url.pem \
    -days 7300 -sha256 -extfile ee_no_ocsp.cnf

# 有效OCSP URL (有效期20年)
openssl x509 -req -in ocsp_test_ee.csr -CA ocsp_test_intermediate_ca.pem \
    -CAkey ocsp_test_intermediate_ca.key -CAcreateserial -out ocsp_test_ee_valid_url.pem \
    -days 7300 -sha256 -extfile ee_valid_ocsp.cnf

# 无效OCSP URL (有效期20年)
openssl x509 -req -in ocsp_test_ee.csr -CA ocsp_test_intermediate_ca.pem \
    -CAkey ocsp_test_intermediate_ca.key -CAcreateserial -out ocsp_test_ee_invalid_url.pem \
    -days 7300 -sha256 -extfile ee_invalid_ocsp.cnf
```

### Step 2: 生成OCSP响应

使用Python cryptography库生成OCSP响应（OpenSSL ocsp命令对所有状态显示"unknown"，需用Python精确控制状态）：

```python
#!/usr/bin/env python3
"""generate_ocsp_responses.py - 生成OCSP测试响应"""

from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding

# 加载证书和私钥
with open("ocsp_test_root_ca.pem", "rb") as f:
    root_cert = x509.load_pem_x509_certificate(f.read())
with open("ocsp_test_root_ca.key", "rb") as f:
    root_key = serialization.load_pem_private_key(f.read(), password=None)
with open("ocsp_test_intermediate_ca.pem", "rb") as f:
    issuer_cert = x509.load_pem_x509_certificate(f.read())
with open("ocsp_test_ee_valid_url.pem", "rb") as f:
    ee_cert = x509.load_pem_x509_certificate(f.read())

now = datetime.now(timezone.utc)

# 生成GOOD状态响应
builder = ocsp.OCSPResponseBuilder()
builder = builder.responder_name(root_cert)
builder = builder.add_response(
    cert=ee_cert,
    issuer=issuer_cert,
    cert_status=ocsp.OCSPCertStatus.GOOD,
    this_update=now,
    next_update=now + timedelta(days=7),
    revocation_time=None,
    revocation_reason=None,
)
response = builder.sign(root_key, hashes.SHA256())
with open("ocsp_response_good.der", "wb") as f:
    f.write(response)
print(f"Generated ocsp_response_good.der ({len(response)} bytes)")

# 生成REVOKED状态响应
builder = ocsp.OCSPResponseBuilder()
builder = builder.responder_name(root_cert)
builder = builder.add_response(
    cert=ee_cert,
    issuer=issuer_cert,
    cert_status=ocsp.OCSPCertStatus.REVOKED,
    this_update=now,
    next_update=now + timedelta(days=7),
    revocation_time=now - timedelta(days=30),
    revocation_reason=x509.ReasonFlags.key_compromise,
)
response = builder.sign(root_key, hashes.SHA256())
with open("ocsp_response_revoked.der", "wb") as f:
    f.write(response)
print(f"Generated ocsp_response_revoked.der ({len(response)} bytes)")

# 生成UNKNOWN状态响应
builder = ocsp.OCSPResponseBuilder()
builder = builder.responder_name(root_cert)
builder = builder.add_response(
    cert=ee_cert,
    issuer=issuer_cert,
    cert_status=ocsp.OCSPCertStatus.UNKNOWN,
    this_update=now,
    next_update=now + timedelta(days=7),
    revocation_time=None,
    revocation_reason=None,
)
response = builder.sign(root_key, hashes.SHA256())
with open("ocsp_response_unknown.der", "wb") as f:
    f.write(response)
print(f"Generated ocsp_response_unknown.der ({len(response)} bytes)")
```

### Step 3: 验证OCSP响应

```bash
# 验证GOOD响应
openssl ocsp -respin ocsp_response_good.der -CAfile ocsp_test_root_ca.pem \
    -issuer ocsp_test_intermediate_ca.pem -cert ocsp_test_ee_valid_url.pem
# 预期输出: ...: good

# 验证REVOKED响应
openssl ocsp -respin ocsp_response_revoked.der -CAfile ocsp_test_root_ca.pem \
    -issuer ocsp_test_intermediate_ca.pem -cert ocsp_test_ee_valid_url.pem
# 预期输出: ...: revoked

# 验证UNKNOWN响应
openssl ocsp -respin ocsp_response_unknown.der -CAfile ocsp_test_root_ca.pem \
    -issuer ocsp_test_intermediate_ca.pem -cert ocsp_test_ee_valid_url.pem
# 预期输出: ...: unknown
```

### Step 4: 转换为C数组格式

```python
#!/usr/bin/env python3
"""convert_to_c_array.py - 将证书和响应转换为C数组"""

import os

def file_to_c_array(filename, array_name):
    with open(filename, "rb") as f:
        data = f.read()

    c_array = f"static const uint8_t {array_name}[] = {{\n"
    for i, byte in enumerate(data):
        if i % 16 == 0:
            c_array += "    "
        c_array += f"0x{byte:02x}, "
        if i % 16 == 15:
            c_array += "\n"
    c_array = c_array.rstrip(", \n") + "\n};\n"

    return c_array, len(data)

def pem_to_c_array(filename, array_name):
    with open(filename, "r") as f:
        pem_data = f.read()

    lines = pem_data.split('\n')
    c_array = f'static const char {array_name}[] =\n'
    for line in lines:
        if line:
            c_array += f'    "{line}\\n"\n'
    c_array = c_array.rstrip('\n') + ';\n'

    return c_array, len(pem_data.encode())

# 转换证书
cert_files = [
    ("ocsp_test_root_ca.pem", "g_ocspTestRootCa"),
    ("ocsp_test_intermediate_ca.pem", "g_ocspTestIntermediateCa"),
    ("ocsp_test_ee_no_url.pem", "g_ocspTestEeNoOcspUrl"),
    ("ocsp_test_ee_valid_url.pem", "g_ocspTestEeValidOcspUrl"),
    ("ocsp_test_ee_invalid_url.pem", "g_ocspTestEeInvalidOcspUrl"),
]

# 转换OCSP响应
response_files = [
    ("ocsp_response_good.der", "g_ocspTestResponseGood"),
    ("ocsp_response_revoked.der", "g_ocspTestResponseRevoked"),
    ("ocsp_response_unknown.der", "g_ocspTestResponseUnknown"),
]

print("/* ============== OCSP Test Certificates ============== */\n")
for filename, array_name in cert_files:
    c_array, size = pem_to_c_array(filename, array_name)
    print(f"/* {filename} ({size} bytes) */")
    print(c_array)
    print()

print("/* ============== OCSP Test Responses ============== */\n")
for filename, array_name in response_files:
    c_array, size = file_to_c_array(filename, array_name)
    print(f"/* {filename} ({size} bytes) */")
    print(c_array)
    print()
```

### Step 5: 添加到测试文件

将生成的C数组添加到测试文件：

```c
// 文件: test/unittest/v1.0/src/crypto_x509_cert_validator_test.cpp

/* ============== OCSP Test Certificates ============== */

/* OCSP Test Root CA */
static const char g_ocspTestRootCa[] = ...;

/* OCSP Test Intermediate CA */
static const char g_ocspTestIntermediateCa[] = ...;

/* End Entity without OCSP URL */
static const char g_ocspTestEeNoOcspUrl[] = ...;

/* End Entity with valid OCSP URL (http://localhost:9999/ocsp) */
static const char g_ocspTestEeValidOcspUrl[] = ...;

/* End Entity with invalid OCSP URL */
static const char g_ocspTestEeInvalidOcspUrl[] = ...;

/* ============== OCSP Test Responses ============== */

/* OCSP Response - GOOD status */
static const uint8_t g_ocspTestResponseGood[] = ...;

/* OCSP Response - REVOKED status */
static const uint8_t g_ocspTestResponseRevoked[] = ...;

/* OCSP Response - UNKNOWN status */
static const uint8_t g_ocspTestResponseUnknown[] = ...;
```

### Step 6: 重构测试用例

使用统一数据重构现有OCSP测试用例：

| 测试场景 | 使用数据 | 预期结果 |
|----------|----------|----------|
| 在线OCSP - 无URL | `g_ocspTestEeNoOcspUrl` | CF_ERR_OCSP_RESPONSE_NOT_FOUND |
| 在线OCSP - 服务不可达 | `g_ocspTestEeValidOcspUrl` | 网络错误 |
| 在线OCSP - URL无效 | `g_ocspTestEeInvalidOcspUrl` | URL解析错误 |
| 本地OCSP - GOOD | `g_ocspTestEeNoOcspUrl` + `g_ocspTestResponseGood` | CF_SUCCESS |
| 本地OCSP - REVOKED | `g_ocspTestEeNoOcspUrl` + `g_ocspTestResponseRevoked` | CF_ERR_CERT_REVOKED |
| 本地OCSP - UNKNOWN | `g_ocspTestEeNoOcspUrl` + `g_ocspTestResponseUnknown` | CF_ERR_OCSP_CERT_STATUS_UNKNOWN |

## 关键文件

- 设计文档: `docs/ocsp_test_data_design.md`
- 测试文件: `test/unittest/v1.0/src/crypto_x509_cert_validator_test.cpp`
- 生成脚本: `/tmp/ocsp_unified_test/` (临时目录)

## 验证方法

### 方式一：OpenHarmony构建验证（仅构建）

```bash
rsync -av --exclude='.git' /home/lm/code/security_certificate_framework/ /home/lm/openharmony2/base/security/certificate_framework/
cd /home/lm/openharmony2 && hb build certificate_framework -t --skip-download
```

### 方式二：build_asan_tdd验证（构建+执行TDD）

```bash
# 同步代码
rsync -av --exclude='.git' /home/lm/code/security_certificate_framework/ /home/lm/test_tdd/build_asan_tdd/security/certificate_framework/

# 构建
cd /home/lm/test_tdd/build_asan_tdd && bash build.sh certificate

# 执行TDD
cd /home/lm/test_tdd/build_asan_tdd
export LD_LIBRARY_PATH=/home/lm/test_tdd/build_asan_tdd/output/lib:$LD_LIBRARY_PATH
./output/bin/cf_version1_test --gtest_filter="*Ocsp*"
```

## 预期收益

1. **数据统一**：一套证书链满足所有OCSP测试场景
2. **易于维护**：证书更新只需修改一处
3. **测试清晰**：测试用例专注于验证逻辑，而非数据配置
4. **覆盖全面**：覆盖GOOD、REVOKED、UNKNOWN三种状态

## 生成结果

测试数据已生成在 `/tmp/ocsp_unified_test/` 目录：

| 文件 | 大小 | 说明 |
|------|------|------|
| `ocsp_test_root_ca.pem` | 1350 bytes | 根CA证书 |
| `ocsp_test_intermediate_ca.pem` | 1468 bytes | 中间CA证书 |
| `ocsp_test_ee_no_url.pem` | 1290 bytes | 终端实体证书（无OCSP URL） |
| `ocsp_test_ee_valid_url.pem` | 1354 bytes | 终端实体证书（有效OCSP URL） |
| `ocsp_test_ee_invalid_url.pem` | 1350 bytes | 终端实体证书（无效OCSP URL） |
| `ocsp_response_good.der` | 545 bytes | GOOD状态OCSP响应 |
| `ocsp_response_revoked.der` | 567 bytes | REVOKED状态OCSP响应 |
| `ocsp_response_unknown.der` | 545 bytes | UNKNOWN状态OCSP响应 |

证书有效期：2024年 ~ 2044年（20年）