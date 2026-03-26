# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

OpenHarmony Certificate Framework - a C/C++ framework that provides unified JavaScript APIs for certificate parsing, validation, and management. It shields differences between third-party certificate algorithm libraries (OpenSSL/Mbed TLS).

## GN Build

After each code modification, build validation must be performed according to the following steps:

1. **Copy code** (excluding .git directory):
```shell
rsync -av --exclude='.git' /home/lm/code/security_certificate_framework/ /home/lm/openharmony2/base/security/certificate_framework/
```

2. **Execute build**:

Build release version:
```shell
cd /home/lm/openharmony2
time hb build certificate_framework -i --skip-download
```
Build TDD (since the target platform is not a build environment, there is no need to execute TDD, just build):
```shell
cd /home/lm/openharmony2
time hb build certificate_framework -t --skip-download
```

Build completion detection:
- GN Build release: Look for `build src success` in build log
- GN Build TDD: Look for `build test success` or `Cost Time` in build log

## Local Build
1. **Copy code** (excluding .git directory):
```shell
rsync -av --exclude='.git' /home/lm/code/security_certificate_framework/ /home/lm/test_tdd/build_asan_tdd/security/certificate_framework/
```

2. **Execute build**:
Build TDD:
```shell
cd /home/lm/test_tdd/build_asan_tdd/
bash build.sh certificate
```

Execute cf_version1_test TDD:
```shell
cd /home/lm/test_tdd/build_asan_tdd
export LD_LIBRARY_PATH=/home/lm/test_tdd/build_asan_tdd/output/lib:$LD_LIBRARY_PATH
./output/bin/cf_version1_test
```

Execute ALL TDD:
```shell
cd /home/lm/test_tdd/build_asan_tdd/
bash build.sh test certificate_framework_test
```

code coverage:
/home/lm/test_tdd/build_asan_tdd/coverage/report/

## Architecture

```
base/security/certificate_framework
├── bundle.json              # Component config (dependencies: crypto_framework, openssl, napi, hilog)
├── BUILD.gn / cf.gni        # Build configuration
├── frameworks/              # Core implementation
│   ├── ability/             # Framework ability registration
│   ├── adapter/             # Algorithm library adaptation (v1.0, v2.0, attestation)
│   ├── common/              # Shared utilities (logging, memory, macros)
│   ├── core/                # Core framework (cert/extension objects, SPI interfaces)
│   ├── js/                  # JS binding implementations
│   │   ├── ani/             # ANI-based JS bindings (legacy)
│   │   └── napi/            # NAPI-based JS bindings (Node-API)
│   └── cj/                  # CJS (ArkTS) FFI bindings
├── interfaces/inner_api/    # Internal API headers exposed to other components
└── test/
    ├── unittest/            # Unit tests (adapter, core, SDK, v1.0)
    └── fuzztest/            # Fuzz tests (cfcreate, cfparam, x509certificate, etc.)
```

### Layer Design

1. **API Layer** (`frameworks/js/`): JavaScript interfaces via NAPI (Node-API) or ANI
2. **Framework Layer** (`frameworks/core/`): Object management, lifecycle, adapter loading
3. **Adapter Layer** (`frameworks/adapter/`): OpenSSL/Mbed TLS implementation abstraction
4. **SPI Layer** (`frameworks/core/v1.0/spi/`): Service Provider Interface for extensibility

### Key Components

- **Certificate Operations**: Parse X509 certs, extract fields (version, serial, issuer, subject, keys, extensions)
- **CRL Operations**: Certificate Revocation List parsing and lookup
- **Cert Chain Validation**: Build and validate certificate chains with trust anchors
- **CMS Operations**: PKCS#7/CMS signed and enveloped data generation/parsing
- **CSR Operations**: Certificate Signing Request generation

### JS API Entry Points (NAPI)

- `napi_x509_certificate` - X509Cert class
- `napi_x509_cert_chain` - X509CertChain class
- `napi_x509_crl` - X509CRL class
- `napi_cert_chain_validator` - CertChainValidator class
- `napi_cert_extension` - CertExtension class
- `napi_cert_cms_generator` / `napi_cert_cms_parser` - CMS operations
- Type definitions in `frameworks/js/ani/dts/cert.d.ts`

### Internal Core Objects

- `cf_object_cert.h` - Certificate object base
- `cf_object_extension.h` - Extension object base
- SPI interfaces in `frameworks/core/v1.0/spi/` define plugin contracts

### Adapter Pattern

Adapters implement the SPI interfaces using OpenSSL:
- `v1.0/` - Original OpenSSL adapter (X509Certificate, X509Crl, CertChainValidator)
- `v2.0/` - Updated adapter implementation
- `attestation/` - Hardware attestation certificate verification

## Dependencies

From `bundle.json`:
- c_utils, crypto_framework, hilog, napi, openssl, runtime_core

## Coding Conventions

- C/C++ with GN build system
- All source files include Apache 2.0 license header
- Error handling via `CfResult` return codes
- Object-oriented pattern using structs with function pointers (e.g., `HcfCertificate`)
- HILOG for logging (`CF_LOG_*` macros in `cf_log.h`)
- Memory management via `cf_malloc`/`cf_free` wrappers
- Sanitizers enabled: CFI, integer overflow, UBSan

## Testing

- **Unit tests**: Google Test based in `test/unittest/`
- **Fuzz tests**: LLVM libFuzzer in `test/fuzztest/`
- Test targets defined in `BUILD.gn` files under each test subdirectory

## openssl dir

- **header file dir**: `/home/lm/openssl/third_party_openssl/include/`
- **lib dir**: `/home/lm/openssl/third_party_openssl/`
- **crypto lib name**: `libcrypto.so`
- **ssl lib name**: `libssl.so`

