/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <openssl/pem.h>

#include "certificate_openssl_common.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "config.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "securec.h"
#include "x509_certificate.h"
#include "x509_certificate_openssl.h"

#define OID_STR_MAX_LEN 128
#define CONSTRUCT_EXTENDED_KEY_USAGE_DATA_SIZE 1
#define ARRAY_INDEX2 2

using namespace std;
using namespace testing::ext;
using namespace CFMock;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

#ifdef __cplusplus
extern "C" {
#endif

int __real_OPENSSL_sk_num(const OPENSSL_STACK *st);
void *__real_OPENSSL_sk_value(const OPENSSL_STACK *st, int i);
long __real_ASN1_INTEGER_get(const ASN1_INTEGER *a);
void *__real_X509V3_EXT_d2i(X509_EXTENSION *ext);
X509_EXTENSION *__real_X509_get_ext(const X509 *x, X509_EXTENSION *loc);
void *__real_X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
CfResult __real_DeepCopyDataToBlob(const unsigned char *data, uint32_t len, CfBlob *outBlob);
int __real_X509_print(BIO *bp, X509 *x);
BIO *__real_BIO_new(const BIO_METHOD *type);
BIO *__real_BIO_new_mem_buf(const void *buf, int len);
EVP_PKEY *__real_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
EVP_PKEY *__real_d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length);
EVP_PKEY *__real_X509_get_pubkey(X509 *x);

#ifdef __cplusplus
}
#endif

namespace {
class CryptoX509CertificateTestPart3 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static const char g_testPriKeyDisMatch[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9kBV6Cqd3vSi5\n"
    "RuRAWjXEvsfD20ekCYyeJvnnSrHwnKodbF8VWFSv4sqYzMnxObpDLyQw0Uu08tbn\n"
    "EQvxv0lOwnWkZR+Oc3M9Ow1uhDkm3eFbY5858mAmtY7Sqzhd0LS9k8Q57FRqOrQm\n"
    "7ngHb0O+yjCIn/zmjyEuw51/cPDTM4h3P3di9nhbIg+UOMfkDbuSKRD7UvVV/JZi\n"
    "BklF5ZrjFYgzYnWKv7N7XkYMGkaOx8+tue24eK06SapQWDLRnRPCVePV6xtoCmbN\n"
    "A3ib/Uvr0qvRwPDCzGGOW9JvQdrI6Z/GD9nt5hqHB15iJVNxkDQtugv14qeDsFPS\n"
    "IU8CtkCbAgMBAAECggEBAKbMmMlJhLCM5r+ZDJE/j55ujRLe6XwC1xP2keEeTdK9\n"
    "18aKLGR41BPsSH8JfAxh0m75lSvLjoVLRSQPUOZIfjXqUF/2hzzug5F2W8xKVovH\n"
    "o1uqHlp71nVZPrJK7Q9H7TH/SyP4uxK6UvkKzt0j34WLHgeqV3t8qCMhB34zIAWG\n"
    "BcAuKJNRZGvMvjK99OSOh0SyvGQ5Yb5vyj1/znx3gM4z4deYXxDSyCO0m5I16jmM\n"
    "gBEUG0UDUp8Xr2xs/EkhhWYRT1bkDlYZ9IuCbH/vB1YJJFdaO2tDivDUF6IObvNt\n"
    "GaVuLlA/rSOJmJFBetrm7n+O2vNJxvoQmBYDKm3+qYkCgYEA9p5C1ZY5XfwwOcqi\n"
    "KQ+Asd2NWLG2blhsII5wB8uPhFapjV0S9xTabScUD35AfxHgctafpZeQk4x5niRP\n"
    "BHq7hpitaDdYs6A/jhZ7fdVYKb1KRTDt1LXmcg0qVmi/ANNvjhqjvyZM+pEj8yxM\n"
    "aOl4isbBfUbzSsEbda3LcHi6+w8CgYEAxMYtkl3gbXJcgbAEdW+nMMQGoFDLkgyu\n"
    "n0ZYuRRrWLnnUzZUyqNBwQUaZpwxHaAqi0OAEGSRSZBKRHz9IA2iP9YzcaJ0WtpB\n"
    "CPqwBZjrCaVEpHldo2pIdujysXgiXRUiE+VR9ViDmftoVbdL6kttGS08jBBDVIV/\n"
    "uQgC/q29UbUCgYAJHirMaMRwNB24VUSPjhItAUrzh4Z+J+i/f2Sm9SC2PNoB7vn/\n"
    "hpbYyEQWmo1Z5VhOBp9aaPMgcWYhsaf2O29pd4WZv8oYwgj3gN9J9LRQvr3bNwbk\n"
    "AWGmv9Pb4/2D001hjJyXOZxI+0q/99hPXKpnPxfyQMhH8EHKpQVLgDsxgwKBgEiH\n"
    "+DJUci5Fkj2ngO08u7bo+rxLK85o6FEDYB7QnQT2eYMdqsGKzej1FZcvCZeu+x+c\n"
    "QO9J8pfYHNgD7lXLULwRG6NOS29VtdU2en2FsVU72wJ5Tf+3ZICYOyUZcCk5afdF\n"
    "dyFlgBTZK8s0pkH1jYBTQVcrg3X7Q2oTvu7bYcZlAoGAUwQI11mMR8oqfgWMoI/1\n"
    "smOoq9qSMlutuWBjoPkbtJEGHEXAvjW1kgdBlPjUCwn6j+oIDLYu8DbfQRdiFQeP\n"
    "rVCbbgOgayVpr+8Tv2DqB370GwBpOpuq0yiiN+c39Y0u03Yfve3icyl8+lN1t4h6\n"
    "a20rj9HG4sb8tUIHPBv0dgY=\n"
    "-----END PRIVATE KEY-----\n";

static const char g_testCertDataDisMatch[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDTTCCAjWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdSb290\n"
    "IENBMB4XDTI0MDMxOTAyMDM1NFoXDTM0MDMxNzAyMDM1NFowETEPMA0GA1UEAwwG\n"
    "ZGV2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoGk2J0aKWTP\n"
    "J3D7lS3oFdME3MMA1z0Y0ftthrtUKybE2xh8P90ztMV73bewmgAPqiApqhaWEZM/\n"
    "6DSLc/MxbOeYjg6njveJIu721gchiuB2PFikDFSWlcLOJNw+CgBx77Ct3KllivHs\n"
    "oi/gjuxrWiF/3VhbBErPNj/fw9se3pVrFRXIFdkcybtom2mUmkcxDfSg587SO14i\n"
    "ZzXGM6nhMzYWXxLho6SJrsnzfs4pD6ifksWmY4089zitqsN+9jQXafY1+/sh1mgu\n"
    "FvAwg9IbigGOBIiF8t5qdNGpqCHXbEHblNCWfT4fVNDV0Vc9pByjZaMYEGMhpz+6\n"
    "lxlc2CqbNQIDAQABo4GuMIGrMAkGA1UdEwQCMAAwHQYDVR0OBBYEFAEVpuP+pPpg\n"
    "kr3dA3aV2XdFZ9rGMB8GA1UdIwQYMBaAFHRb+SgJu8O0UYdRBkszePocqxbYMB0G\n"
    "A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjALBgNVHQ8EBAMCB4AwMgYIKwYB\n"
    "BQUHAQEEJjAkMCIGCCsGAQUFBzABhhZodHRwczovLzEyNy4wLjAuMTo5OTk5MA0G\n"
    "CSqGSIb3DQEBCwUAA4IBAQBjM1agcDcgVHsD0dS39gxtlyRbZRvDcW3YsdwgpN6S\n"
    "e4wGzdZbhsiZv7y3+PSuozKwp5Yjn+UqnnEz7QuTGJRt/pzHDVY3QceNvlx2HPRe\n"
    "fECS4bpGLcM5B17oZZjE4HenIrGmigXnnwYL5TjhC4ybtddXPYv/M6z2eFCnfQNa\n"
    "zFwz8LJ7ukWvf5koBqcHq2zsuVByOIPXLIrAJPtMmBb/pHCFt8hxOxwqujdrxz16\n"
    "pe5LQUYzvG1YCxw3Ye9OrM1yXJQr/4KYncQC1yQQo+UK7NsDRK30PsMEYxhierLA\n"
    "JKyPn1xSlOJiGa2rRn/uevmEOhfagj5TtprU9Gu1+nZo\n"
    "-----END CERTIFICATE-----\n";

static const char g_testCertDataRsa[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICfDCCAeWgAwIBAgIGAXKnJjrAMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYT\n"
    "AkNOMQ8wDQYDVQQIDAbpmZXopb8xDzANBgNVBAcMBuilv+WuiTEPMA0GA1UECgwG\n"
    "5rWL6K+VMRUwEwYDVQQDDAzkuK3mlofmtYvor5UwHhcNMjYwMzA0MDYzMTAwWhcN\n"
    "MzYwMzAxMDYzMTAwWjBXMQswCQYDVQQGEwJDTjEPMA0GA1UECAwG6ZmV6KW/MQ8w\n"
    "DQYDVQQHDAbopb/lrokxDzANBgNVBAoMBua1i+ivlTEVMBMGA1UEAwwM5Lit5paH\n"
    "5rWL6K+VMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDATjc6n8zP8oCcL+Rs\n"
    "GfQ0rZY+HW20JA0aSD7XpkSVfVOqvKRlUk9me9ucFsV14NHOPORdtuCwrwcmFVWo\n"
    "IdxpJaZ8THe2nDpFdP+qCVrFQRIGI6miRhujI+Oi8bYeRqC9mvZwHM21DrRLCgoN\n"
    "/g5PWFB9AwrpsD55wp/mCX/QFQIDAQABo1MwUTAdBgNVHQ4EFgQUy1C1+slmuQLc\n"
    "vA0yVy4963VFHd0wHwYDVR0jBBgwFoAUy1C1+slmuQLcvA0yVy4963VFHd0wDwYD\n"
    "VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQBrWuy8crSw4F1o5pmW++fc\n"
    "abJGqrczB61WJV6CRi5btEGBP7agfgvX8GcbPpYmAyq/MwwEL32FxFeL0hySRfhP\n"
    "Md1TgtZHSNKCJQWiTxwm2Gl/MsNbor/KaOeoPqrEbWQHqQAo6yWR4WwnvlFKldRm\n"
    "8zGEW1+b2VpGuWhS3Ip4kw==\n"
    "-----END CERTIFICATE-----\n";

static const char g_testPrivateDataRsaP1[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQDATjc6n8zP8oCcL+RsGfQ0rZY+HW20JA0aSD7XpkSVfVOqvKRl\n"
    "Uk9me9ucFsV14NHOPORdtuCwrwcmFVWoIdxpJaZ8THe2nDpFdP+qCVrFQRIGI6mi\n"
    "RhujI+Oi8bYeRqC9mvZwHM21DrRLCgoN/g5PWFB9AwrpsD55wp/mCX/QFQIDAQAB\n"
    "AoGAShmZdHCA9hvmbMiThwgVLns46mRikkhV+Cugc24w/T1WkPKxkg0+ZSoSvDmW\n"
    "Cs7/aS3TfTzrpYk8AvOzlt69U+Y6CHcPZCOlqBnxkoU48DbR+N0+OOXajceXEuOi\n"
    "ZYnvxkRut0isK9v+HoOdq9/g9Sp20AJYPLRtGcB8BIZAMt0CQQD+xFTsy75I6hUn\n"
    "IweuIvo4cT4iW/9SVbTNRXuVXBcHlj1bwU4WjBBq32Q1T8mdH+FTtRzdU74wQzxs\n"
    "Ug0R6CufAkEAwTx9y0/uMqHeS+s1BCxqHMTqCMDd9hmmQol9JX7I6G8XqDs1RX0s\n"
    "u6efdMZv6cnAjXEg0TzsImeq4tyScEAnywJAKAg9t//D5L0zmbS9bjV80AWrV8bQ\n"
    "9eUVxfOXGb8gt0Z6WcKkPJLBualkm6Pv8EqkI30gDf8ssXS/N94kw52RzQJAPY8V\n"
    "zAVEruCePrVJiHDVxSB+Jhe7HkGBk8TVF3LScimh8bga+m4sKAP4am0lDed17hlS\n"
    "CRZNa5B3AhqelB/8DQJBAPm6Ce8FUJ+So1T8D5fBMwNzyFwrG2u2PuePWMgutQl7\n"
    "Lgn1bJIKF5Ngm88pKwK/RApblq6e4gzUo74i6H/AY28=\n"
    "-----END RSA PRIVATE KEY-----\n";

static const char g_testPrivateDataRsaP8[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAMBONzqfzM/ygJwv\n"
    "5GwZ9DStlj4dbbQkDRpIPtemRJV9U6q8pGVST2Z725wWxXXg0c485F224LCvByYV\n"
    "Vagh3GklpnxMd7acOkV0/6oJWsVBEgYjqaJGG6Mj46Lxth5GoL2a9nAczbUOtEsK\n"
    "Cg3+Dk9YUH0DCumwPnnCn+YJf9AVAgMBAAECgYBKGZl0cID2G+ZsyJOHCBUuezjq\n"
    "ZGKSSFX4K6BzbjD9PVaQ8rGSDT5lKhK8OZYKzv9pLdN9POuliTwC87OW3r1T5joI\n"
    "dw9kI6WoGfGShTjwNtH43T445dqNx5cS46Jlie/GRG63SKwr2/4eg52r3+D1KnbQ\n"
    "Alg8tG0ZwHwEhkAy3QJBAP7EVOzLvkjqFScjB64i+jhxPiJb/1JVtM1Fe5VcFweW\n"
    "PVvBThaMEGrfZDVPyZ0f4VO1HN1TvjBDPGxSDRHoK58CQQDBPH3LT+4yod5L6zUE\n"
    "LGocxOoIwN32GaZCiX0lfsjobxeoOzVFfSy7p590xm/pycCNcSDRPOwiZ6ri3JJw\n"
    "QCfLAkAoCD23/8PkvTOZtL1uNXzQBatXxtD15RXF85cZvyC3RnpZwqQ8ksG5qWSb\n"
    "o+/wSqQjfSAN/yyxdL833iTDnZHNAkA9jxXMBUSu4J4+tUmIcNXFIH4mF7seQYGT\n"
    "xNUXctJyKaHxuBr6biwoA/hqbSUN53XuGVIJFk1rkHcCGp6UH/wNAkEA+boJ7wVQ\n"
    "n5KjVPwPl8EzA3PIXCsba7Y+549YyC61CXsuCfVskgoXk2CbzykrAr9ECluWrp7i\n"
    "DNSjviLof8Bjbw==\n"
    "-----END PRIVATE KEY-----\n";

const uint8_t g_testPrivateDataRsaP1Der[] = {
    0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xc0, 0x4e, 0x37, 0x3a, 0x9f,
    0xcc, 0xcf, 0xf2, 0x80, 0x9c, 0x2f, 0xe4, 0x6c, 0x19, 0xf4, 0x34, 0xad, 0x96, 0x3e, 0x1d, 0x6d,
    0xb4, 0x24, 0x0d, 0x1a, 0x48, 0x3e, 0xd7, 0xa6, 0x44, 0x95, 0x7d, 0x53, 0xaa, 0xbc, 0xa4, 0x65,
    0x52, 0x4f, 0x66, 0x7b, 0xdb, 0x9c, 0x16, 0xc5, 0x75, 0xe0, 0xd1, 0xce, 0x3c, 0xe4, 0x5d, 0xb6,
    0xe0, 0xb0, 0xaf, 0x07, 0x26, 0x15, 0x55, 0xa8, 0x21, 0xdc, 0x69, 0x25, 0xa6, 0x7c, 0x4c, 0x77,
    0xb6, 0x9c, 0x3a, 0x45, 0x74, 0xff, 0xaa, 0x09, 0x5a, 0xc5, 0x41, 0x12, 0x06, 0x23, 0xa9, 0xa2,
    0x46, 0x1b, 0xa3, 0x23, 0xe3, 0xa2, 0xf1, 0xb6, 0x1e, 0x46, 0xa0, 0xbd, 0x9a, 0xf6, 0x70, 0x1c,
    0xcd, 0xb5, 0x0e, 0xb4, 0x4b, 0x0a, 0x0a, 0x0d, 0xfe, 0x0e, 0x4f, 0x58, 0x50, 0x7d, 0x03, 0x0a,
    0xe9, 0xb0, 0x3e, 0x79, 0xc2, 0x9f, 0xe6, 0x09, 0x7f, 0xd0, 0x15, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x02, 0x81, 0x80, 0x4a, 0x19, 0x99, 0x74, 0x70, 0x80, 0xf6, 0x1b, 0xe6, 0x6c, 0xc8, 0x93, 0x87,
    0x08, 0x15, 0x2e, 0x7b, 0x38, 0xea, 0x64, 0x62, 0x92, 0x48, 0x55, 0xf8, 0x2b, 0xa0, 0x73, 0x6e,
    0x30, 0xfd, 0x3d, 0x56, 0x90, 0xf2, 0xb1, 0x92, 0x0d, 0x3e, 0x65, 0x2a, 0x12, 0xbc, 0x39, 0x96,
    0x0a, 0xce, 0xff, 0x69, 0x2d, 0xd3, 0x7d, 0x3c, 0xeb, 0xa5, 0x89, 0x3c, 0x02, 0xf3, 0xb3, 0x96,
    0xde, 0xbd, 0x53, 0xe6, 0x3a, 0x08, 0x77, 0x0f, 0x64, 0x23, 0xa5, 0xa8, 0x19, 0xf1, 0x92, 0x85,
    0x38, 0xf0, 0x36, 0xd1, 0xf8, 0xdd, 0x3e, 0x38, 0xe5, 0xda, 0x8d, 0xc7, 0x97, 0x12, 0xe3, 0xa2,
    0x65, 0x89, 0xef, 0xc6, 0x44, 0x6e, 0xb7, 0x48, 0xac, 0x2b, 0xdb, 0xfe, 0x1e, 0x83, 0x9d, 0xab,
    0xdf, 0xe0, 0xf5, 0x2a, 0x76, 0xd0, 0x02, 0x58, 0x3c, 0xb4, 0x6d, 0x19, 0xc0, 0x7c, 0x04, 0x86,
    0x40, 0x32, 0xdd, 0x02, 0x41, 0x00, 0xfe, 0xc4, 0x54, 0xec, 0xcb, 0xbe, 0x48, 0xea, 0x15, 0x27,
    0x23, 0x07, 0xae, 0x22, 0xfa, 0x38, 0x71, 0x3e, 0x22, 0x5b, 0xff, 0x52, 0x55, 0xb4, 0xcd, 0x45,
    0x7b, 0x95, 0x5c, 0x17, 0x07, 0x96, 0x3d, 0x5b, 0xc1, 0x4e, 0x16, 0x8c, 0x10, 0x6a, 0xdf, 0x64,
    0x35, 0x4f, 0xc9, 0x9d, 0x1f, 0xe1, 0x53, 0xb5, 0x1c, 0xdd, 0x53, 0xbe, 0x30, 0x43, 0x3c, 0x6c,
    0x52, 0x0d, 0x11, 0xe8, 0x2b, 0x9f, 0x02, 0x41, 0x00, 0xc1, 0x3c, 0x7d, 0xcb, 0x4f, 0xee, 0x32,
    0xa1, 0xde, 0x4b, 0xeb, 0x35, 0x04, 0x2c, 0x6a, 0x1c, 0xc4, 0xea, 0x08, 0xc0, 0xdd, 0xf6, 0x19,
    0xa6, 0x42, 0x89, 0x7d, 0x25, 0x7e, 0xc8, 0xe8, 0x6f, 0x17, 0xa8, 0x3b, 0x35, 0x45, 0x7d, 0x2c,
    0xbb, 0xa7, 0x9f, 0x74, 0xc6, 0x6f, 0xe9, 0xc9, 0xc0, 0x8d, 0x71, 0x20, 0xd1, 0x3c, 0xec, 0x22,
    0x67, 0xaa, 0xe2, 0xdc, 0x92, 0x70, 0x40, 0x27, 0xcb, 0x02, 0x40, 0x28, 0x08, 0x3d, 0xb7, 0xff,
    0xc3, 0xe4, 0xbd, 0x33, 0x99, 0xb4, 0xbd, 0x6e, 0x35, 0x7c, 0xd0, 0x05, 0xab, 0x57, 0xc6, 0xd0,
    0xf5, 0xe5, 0x15, 0xc5, 0xf3, 0x97, 0x19, 0xbf, 0x20, 0xb7, 0x46, 0x7a, 0x59, 0xc2, 0xa4, 0x3c,
    0x92, 0xc1, 0xb9, 0xa9, 0x64, 0x9b, 0xa3, 0xef, 0xf0, 0x4a, 0xa4, 0x23, 0x7d, 0x20, 0x0d, 0xff,
    0x2c, 0xb1, 0x74, 0xbf, 0x37, 0xde, 0x24, 0xc3, 0x9d, 0x91, 0xcd, 0x02, 0x40, 0x3d, 0x8f, 0x15,
    0xcc, 0x05, 0x44, 0xae, 0xe0, 0x9e, 0x3e, 0xb5, 0x49, 0x88, 0x70, 0xd5, 0xc5, 0x20, 0x7e, 0x26,
    0x17, 0xbb, 0x1e, 0x41, 0x81, 0x93, 0xc4, 0xd5, 0x17, 0x72, 0xd2, 0x72, 0x29, 0xa1, 0xf1, 0xb8,
    0x1a, 0xfa, 0x6e, 0x2c, 0x28, 0x03, 0xf8, 0x6a, 0x6d, 0x25, 0x0d, 0xe7, 0x75, 0xee, 0x19, 0x52,
    0x09, 0x16, 0x4d, 0x6b, 0x90, 0x77, 0x02, 0x1a, 0x9e, 0x94, 0x1f, 0xfc, 0x0d, 0x02, 0x41, 0x00,
    0xf9, 0xba, 0x09, 0xef, 0x05, 0x50, 0x9f, 0x92, 0xa3, 0x54, 0xfc, 0x0f, 0x97, 0xc1, 0x33, 0x03,
    0x73, 0xc8, 0x5c, 0x2b, 0x1b, 0x6b, 0xb6, 0x3e, 0xe7, 0x8f, 0x58, 0xc8, 0x2e, 0xb5, 0x09, 0x7b,
    0x2e, 0x09, 0xf5, 0x6c, 0x92, 0x0a, 0x17, 0x93, 0x60, 0x9b, 0xcf, 0x29, 0x2b, 0x02, 0xbf, 0x44,
    0x0a, 0x5b, 0x96, 0xae, 0x9e, 0xe2, 0x0c, 0xd4, 0xa3, 0xbe, 0x22, 0xe8, 0x7f, 0xc0, 0x63, 0x6f};

const uint8_t g_testPriKeyDerDisMatch[] = {
    0x30, 0x82, 0x04, 0xa3, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xbd, 0x90, 0x15, 0x7a,
    0x0a, 0xa7, 0x77, 0xbd, 0x28, 0xb9, 0x46, 0xe4, 0x40, 0x5a, 0x35, 0xc4, 0xbe, 0xc7, 0xc3, 0xdb,
    0x47, 0xa4, 0x09, 0x8c, 0x9e, 0x26, 0xf9, 0xe7, 0x4a, 0xb1, 0xf0, 0x9c, 0xaa, 0x1d, 0x6c, 0x5f,
    0x15, 0x58, 0x54, 0xaf, 0xe2, 0xca, 0x98, 0xcc, 0xc9, 0xf1, 0x39, 0xba, 0x43, 0x2f, 0x24, 0x30,
    0xd1, 0x4b, 0xb4, 0xf2, 0xd6, 0xe7, 0x11, 0x0b, 0xf1, 0xbf, 0x49, 0x4e, 0xc2, 0x75, 0xa4, 0x65,
    0x1f, 0x8e, 0x73, 0x73, 0x3d, 0x3b, 0x0d, 0x6e, 0x84, 0x39, 0x26, 0xdd, 0xe1, 0x5b, 0x63, 0x9f,
    0x39, 0xf2, 0x60, 0x26, 0xb5, 0x8e, 0xd2, 0xab, 0x38, 0x5d, 0xd0, 0xb4, 0xbd, 0x93, 0xc4, 0x39,
    0xec, 0x54, 0x6a, 0x3a, 0xb4, 0x26, 0xee, 0x78, 0x07, 0x6f, 0x43, 0xbe, 0xca, 0x30, 0x88, 0x9f,
    0xfc, 0xe6, 0x8f, 0x21, 0x2e, 0xc3, 0x9d, 0x7f, 0x70, 0xf0, 0xd3, 0x33, 0x88, 0x77, 0x3f, 0x77,
    0x62, 0xf6, 0x78, 0x5b, 0x22, 0x0f, 0x94, 0x38, 0xc7, 0xe4, 0x0d, 0xbb, 0x92, 0x29, 0x10, 0xfb,
    0x52, 0xf5, 0x55, 0xfc, 0x96, 0x62, 0x06, 0x49, 0x45, 0xe5, 0x9a, 0xe3, 0x15, 0x88, 0x33, 0x62,
    0x75, 0x8a, 0xbf, 0xb3, 0x7b, 0x5e, 0x46, 0x0c, 0x1a, 0x46, 0x8e, 0xc7, 0xcf, 0xad, 0xb9, 0xed,
    0xb8, 0x78, 0xad, 0x3a, 0x49, 0xaa, 0x50, 0x58, 0x32, 0xd1, 0x9d, 0x13, 0xc2, 0x55, 0xe3, 0xd5,
    0xeb, 0x1b, 0x68, 0x0a, 0x66, 0xcd, 0x03, 0x78, 0x9b, 0xfd, 0x4b, 0xeb, 0xd2, 0xab, 0xd1, 0xc0,
    0xf0, 0xc2, 0xcc, 0x61, 0x8e, 0x5b, 0xd2, 0x6f, 0x41, 0xda, 0xc8, 0xe9, 0x9f, 0xc6, 0x0f, 0xd9,
    0xed, 0xe6, 0x1a, 0x87, 0x07, 0x5e, 0x62, 0x25, 0x53, 0x71, 0x90, 0x34, 0x2d, 0xba, 0x0b, 0xf5,
    0xe2, 0xa7, 0x83, 0xb0, 0x53, 0xd2, 0x21, 0x4f, 0x02, 0xb6, 0x40, 0x9b, 0x02, 0x03, 0x01, 0x00,
    0x01, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa6, 0xcc, 0x98, 0xc9, 0x49, 0x84, 0xb0, 0x8c, 0xe6, 0xbf,
    0x99, 0x0c, 0x91, 0x3f, 0x8f, 0x9e, 0x6e, 0x8d, 0x12, 0xde, 0xe9, 0x7c, 0x02, 0xd7, 0x13, 0xf6,
    0x91, 0xe1, 0x1e, 0x4d, 0xd2, 0xbd, 0xd7, 0xc6, 0x8a, 0x2c, 0x64, 0x78, 0xd4, 0x13, 0xec, 0x48,
    0x7f, 0x09, 0x7c, 0x0c, 0x61, 0xd2, 0x6e, 0xf9, 0x95, 0x2b, 0xcb, 0x8e, 0x85, 0x4b, 0x45, 0x24,
    0x0f, 0x50, 0xe6, 0x48, 0x7e, 0x35, 0xea, 0x50, 0x5f, 0xf6, 0x87, 0x3c, 0xee, 0x83, 0x91, 0x76,
    0x5b, 0xcc, 0x4a, 0x56, 0x8b, 0xc7, 0xa3, 0x5b, 0xaa, 0x1e, 0x5a, 0x7b, 0xd6, 0x75, 0x59, 0x3e,
    0xb2, 0x4a, 0xed, 0x0f, 0x47, 0xed, 0x31, 0xff, 0x4b, 0x23, 0xf8, 0xbb, 0x12, 0xba, 0x52, 0xf9,
    0x0a, 0xce, 0xdd, 0x23, 0xdf, 0x85, 0x8b, 0x1e, 0x07, 0xaa, 0x57, 0x7b, 0x7c, 0xa8, 0x23, 0x21,
    0x07, 0x7e, 0x33, 0x20, 0x05, 0x86, 0x05, 0xc0, 0x2e, 0x28, 0x93, 0x51, 0x64, 0x6b, 0xcc, 0xbe,
    0x32, 0xbd, 0xf4, 0xe4, 0x8e, 0x87, 0x44, 0xb2, 0xbc, 0x64, 0x39, 0x61, 0xbe, 0x6f, 0xca, 0x3d,
    0x7f, 0xce, 0x7c, 0x77, 0x80, 0xce, 0x33, 0xe1, 0xd7, 0x98, 0x5f, 0x10, 0xd2, 0xc8, 0x23, 0xb4,
    0x9b, 0x92, 0x35, 0xea, 0x39, 0x8c, 0x80, 0x11, 0x14, 0x1b, 0x45, 0x03, 0x52, 0x9f, 0x17, 0xaf,
    0x6c, 0x6c, 0xfc, 0x49, 0x21, 0x85, 0x66, 0x11, 0x4f, 0x56, 0xe4, 0x0e, 0x56, 0x19, 0xf4, 0x8b,
    0x82, 0x6c, 0x7f, 0xef, 0x07, 0x56, 0x09, 0x24, 0x57, 0x5a, 0x3b, 0x6b, 0x43, 0x8a, 0xf0, 0xd4,
    0x17, 0xa2, 0x0e, 0x6e, 0xf3, 0x6d, 0x19, 0xa5, 0x6e, 0x2e, 0x50, 0x3f, 0xad, 0x23, 0x89, 0x98,
    0x91, 0x41, 0x7a, 0xda, 0xe6, 0xee, 0x7f, 0x8e, 0xda, 0xf3, 0x49, 0xc6, 0xfa, 0x10, 0x98, 0x16,
    0x03, 0x2a, 0x6d, 0xfe, 0xa9, 0x89, 0x02, 0x81, 0x81, 0x00, 0xf6, 0x9e, 0x42, 0xd5, 0x96, 0x39,
    0x5d, 0xfc, 0x30, 0x39, 0xca, 0xa2, 0x29, 0x0f, 0x80, 0xb1, 0xdd, 0x8d, 0x58, 0xb1, 0xb6, 0x6e,
    0x58, 0x6c, 0x20, 0x8e, 0x70, 0x07, 0xcb, 0x8f, 0x84, 0x56, 0xa9, 0x8d, 0x5d, 0x12, 0xf7, 0x14,
    0xda, 0x6d, 0x27, 0x14, 0x0f, 0x7e, 0x40, 0x7f, 0x11, 0xe0, 0x72, 0xd6, 0x9f, 0xa5, 0x97, 0x90,
    0x93, 0x8c, 0x79, 0x9e, 0x24, 0x4f, 0x04, 0x7a, 0xbb, 0x86, 0x98, 0xad, 0x68, 0x37, 0x58, 0xb3,
    0xa0, 0x3f, 0x8e, 0x16, 0x7b, 0x7d, 0xd5, 0x58, 0x29, 0xbd, 0x4a, 0x45, 0x30, 0xed, 0xd4, 0xb5,
    0xe6, 0x72, 0x0d, 0x2a, 0x56, 0x68, 0xbf, 0x00, 0xd3, 0x6f, 0x8e, 0x1a, 0xa3, 0xbf, 0x26, 0x4c,
    0xfa, 0x91, 0x23, 0xf3, 0x2c, 0x4c, 0x68, 0xe9, 0x78, 0x8a, 0xc6, 0xc1, 0x7d, 0x46, 0xf3, 0x4a,
    0xc1, 0x1b, 0x75, 0xad, 0xcb, 0x70, 0x78, 0xba, 0xfb, 0x0f, 0x02, 0x81, 0x81, 0x00, 0xc4, 0xc6,
    0x2d, 0x92, 0x5d, 0xe0, 0x6d, 0x72, 0x5c, 0x81, 0xb0, 0x04, 0x75, 0x6f, 0xa7, 0x30, 0xc4, 0x06,
    0xa0, 0x50, 0xcb, 0x92, 0x0c, 0xae, 0x9f, 0x46, 0x58, 0xb9, 0x14, 0x6b, 0x58, 0xb9, 0xe7, 0x53,
    0x36, 0x54, 0xca, 0xa3, 0x41, 0xc1, 0x05, 0x1a, 0x66, 0x9c, 0x31, 0x1d, 0xa0, 0x2a, 0x8b, 0x43,
    0x80, 0x10, 0x64, 0x91, 0x49, 0x90, 0x4a, 0x44, 0x7c, 0xfd, 0x20, 0x0d, 0xa2, 0x3f, 0xd6, 0x33,
    0x71, 0xa2, 0x74, 0x5a, 0xda, 0x41, 0x08, 0xfa, 0xb0, 0x05, 0x98, 0xeb, 0x09, 0xa5, 0x44, 0xa4,
    0x79, 0x5d, 0xa3, 0x6a, 0x48, 0x76, 0xe8, 0xf2, 0xb1, 0x78, 0x22, 0x5d, 0x15, 0x22, 0x13, 0xe5,
    0x51, 0xf5, 0x58, 0x83, 0x99, 0xfb, 0x68, 0x55, 0xb7, 0x4b, 0xea, 0x4b, 0x6d, 0x19, 0x2d, 0x3c,
    0x8c, 0x10, 0x43, 0x54, 0x85, 0x7f, 0xb9, 0x08, 0x02, 0xfe, 0xad, 0xbd, 0x51, 0xb5, 0x02, 0x81,
    0x80, 0x09, 0x1e, 0x2a, 0xcc, 0x68, 0xc4, 0x70, 0x34, 0x1d, 0xb8, 0x55, 0x44, 0x8f, 0x8e, 0x12,
    0x2d, 0x01, 0x4a, 0xf3, 0x87, 0x86, 0x7e, 0x27, 0xe8, 0xbf, 0x7f, 0x64, 0xa6, 0xf5, 0x20, 0xb6,
    0x3c, 0xda, 0x01, 0xee, 0xf9, 0xff, 0x86, 0x96, 0xd8, 0xc8, 0x44, 0x16, 0x9a, 0x8d, 0x59, 0xe5,
    0x58, 0x4e, 0x06, 0x9f, 0x5a, 0x68, 0xf3, 0x20, 0x71, 0x66, 0x21, 0xb1, 0xa7, 0xf6, 0x3b, 0x6f,
    0x69, 0x77, 0x85, 0x99, 0xbf, 0xca, 0x18, 0xc2, 0x08, 0xf7, 0x80, 0xdf, 0x49, 0xf4, 0xb4, 0x50,
    0xbe, 0xbd, 0xdb, 0x37, 0x06, 0xe4, 0x01, 0x61, 0xa6, 0xbf, 0xd3, 0xdb, 0xe3, 0xfd, 0x83, 0xd3,
    0x4d, 0x61, 0x8c, 0x9c, 0x97, 0x39, 0x9c, 0x48, 0xfb, 0x4a, 0xbf, 0xf7, 0xd8, 0x4f, 0x5c, 0xaa,
    0x67, 0x3f, 0x17, 0xf2, 0x40, 0xc8, 0x47, 0xf0, 0x41, 0xca, 0xa5, 0x05, 0x4b, 0x80, 0x3b, 0x31,
    0x83, 0x02, 0x81, 0x80, 0x48, 0x87, 0xf8, 0x32, 0x54, 0x72, 0x2e, 0x45, 0x92, 0x3d, 0xa7, 0x80,
    0xed, 0x3c, 0xbb, 0xb6, 0xe8, 0xfa, 0xbc, 0x4b, 0x2b, 0xce, 0x68, 0xe8, 0x51, 0x03, 0x60, 0x1e,
    0xd0, 0x9d, 0x04, 0xf6, 0x79, 0x83, 0x1d, 0xaa, 0xc1, 0x8a, 0xcd, 0xe8, 0xf5, 0x15, 0x97, 0x2f,
    0x09, 0x97, 0xae, 0xfb, 0x1f, 0x9c, 0x40, 0xef, 0x49, 0xf2, 0x97, 0xd8, 0x1c, 0xd8, 0x03, 0xee,
    0x55, 0xcb, 0x50, 0xbc, 0x11, 0x1b, 0xa3, 0x4e, 0x4b, 0x6f, 0x55, 0xb5, 0xd5, 0x36, 0x7a, 0x7d,
    0x85, 0xb1, 0x55, 0x3b, 0xdb, 0x02, 0x79, 0x4d, 0xff, 0xb7, 0x64, 0x80, 0x98, 0x3b, 0x25, 0x19,
    0x70, 0x29, 0x39, 0x69, 0xf7, 0x45, 0x77, 0x21, 0x65, 0x80, 0x14, 0xd9, 0x2b, 0xcb, 0x34, 0xa6,
    0x41, 0xf5, 0x8d, 0x80, 0x53, 0x41, 0x57, 0x2b, 0x83, 0x75, 0xfb, 0x43, 0x6a, 0x13, 0xbe, 0xee,
    0xdb, 0x61, 0xc6, 0x65, 0x02, 0x81, 0x80, 0x53, 0x04, 0x08, 0xd7, 0x59, 0x8c, 0x47, 0xca, 0x2a,
    0x7e, 0x05, 0x8c, 0xa0, 0x8f, 0xf5, 0xb2, 0x63, 0xa8, 0xab, 0xda, 0x92, 0x32, 0x5b, 0xad, 0xb9,
    0x60, 0x63, 0xa0, 0xf9, 0x1b, 0xb4, 0x91, 0x06, 0x1c, 0x45, 0xc0, 0xbe, 0x35, 0xb5, 0x92, 0x07,
    0x41, 0x94, 0xf8, 0xd4, 0x0b, 0x09, 0xfa, 0x8f, 0xea, 0x08, 0x0c, 0xb6, 0x2e, 0xf0, 0x36, 0xdf,
    0x41, 0x17, 0x62, 0x15, 0x07, 0x8f, 0xad, 0x50, 0x9b, 0x6e, 0x03, 0xa0, 0x6b, 0x25, 0x69, 0xaf,
    0xef, 0x13, 0xbf, 0x60, 0xea, 0x07, 0x7e, 0xf4, 0x1b, 0x00, 0x69, 0x3a, 0x9b, 0xaa, 0xd3, 0x28,
    0xa2, 0x37, 0xe7, 0x37, 0xf5, 0x8d, 0x2e, 0xd3, 0x76, 0x1f, 0xbd, 0xed, 0xe2, 0x73, 0x29, 0x7c,
    0xfa, 0x53, 0x75, 0xb7, 0x88, 0x7a, 0x6b, 0x6d, 0x2b, 0x8f, 0xd1, 0xc6, 0xe2, 0xc6, 0xfc, 0xb5,
    0x42, 0x07, 0x3c, 0x1b, 0xf4, 0x76, 0x06 };

static HcfX509Certificate *g_x509CertExtAttrObj = nullptr;
static HcfX509Certificate *g_testCertWithPrivateKeyValidObj = nullptr;

void CryptoX509CertificateTestPart3::SetUpTestCase()
{
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testExtAttrCert));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testExtAttrCert) + 1;
    (void)HcfX509CertificateCreate(&inStream, &g_x509CertExtAttrObj);

    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertWithPrivateKeyValid));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testCertWithPrivateKeyValid) + 1;
    (void)HcfX509CertificateCreate(&inStream, &g_testCertWithPrivateKeyValidObj);
}

void CryptoX509CertificateTestPart3::TearDownTestCase()
{
    CfObjDestroy(g_x509CertExtAttrObj);
    CfObjDestroy(g_testCertWithPrivateKeyValidObj);
}

void CryptoX509CertificateTestPart3::SetUp() {}

void CryptoX509CertificateTestPart3::TearDown() {}

static CfArray *constructExtendedKeyUsageData()
{
    CfArray *newBlobArr = static_cast<CfArray *>(CfMalloc(sizeof(CfArray), 0));
    if (newBlobArr == nullptr) {
        CF_LOG_E("Failed to allocate newBlobArr memory!");
        return nullptr;
    }

    newBlobArr->count = CONSTRUCT_EXTENDED_KEY_USAGE_DATA_SIZE;
    newBlobArr->format = CF_FORMAT_DER;
    newBlobArr->data = static_cast<CfBlob *>(CfMalloc(newBlobArr->count * sizeof(CfBlob), 0));
    if (newBlobArr->data == nullptr) {
        CF_LOG_E("Failed to allocate data memory!");
        CfFree(newBlobArr);
        return nullptr;
    }

    newBlobArr->data[0].data = const_cast<uint8_t *>(g_testExtendedKeyUsage);
    newBlobArr->data[0].size = sizeof(g_testExtendedKeyUsage);

    return newBlobArr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareSubjectAlternativeNamesTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.subjectAlternativeNames = ConstructSubAltNameArrayData();
    EXPECT_NE(certMatchParameters.subjectAlternativeNames, nullptr);

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    CfFree(certMatchParameters.subjectAlternativeNames->data);
    CfFree(certMatchParameters.subjectAlternativeNames);
    certMatchParameters.subjectAlternativeNames = nullptr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareSubjectAlternativeNamesTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams matchParams = { 0 };
    matchParams.subjectAlternativeNames = ConstructSubAltNameArrayData();
    EXPECT_NE(matchParams.subjectAlternativeNames, nullptr);

    // test CompareSubAltNameX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_get_ext_d2i));
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    SetMockFlag(true);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    CfFree(matchParams.subjectAlternativeNames->data);
    CfFree(matchParams.subjectAlternativeNames);
    matchParams.subjectAlternativeNames = nullptr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareMatchAllSubjectAltNamesTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;
    CfResult ret = CF_SUCCESS;
    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.matchAllSubjectAltNames = true;
    certMatchParameters.subjectAlternativeNames = ConstructSubAltNameArrayData();
    EXPECT_NE(certMatchParameters.subjectAlternativeNames, nullptr);

    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    certMatchParameters.subjectAlternativeNames->count = 2;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // add failed case ret != CF_SUCCESS
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_num(_))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_num));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfFree(certMatchParameters.subjectAlternativeNames->data);
    CfFree(certMatchParameters.subjectAlternativeNames);
    certMatchParameters.subjectAlternativeNames = nullptr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareAuthorityKeyIdentifierTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testIssuer);
    blob.size = sizeof(g_testIssuer);

    certMatchParameters.authorityKeyIdentifier = &blob;

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    blob.data = const_cast<uint8_t *>(g_testAuthorityKeyIdentifier);
    blob.size = sizeof(g_testAuthorityKeyIdentifier);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test GetAuKeyIdDNX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_AUTHORITY_KEYID(_, _)).WillRepeatedly(Return(-1));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), DeepCopyDataToBlob(_, _, _))
        .WillOnce(Return(CF_INVALID_PARAMS))
        .WillRepeatedly(Invoke(__real_DeepCopyDataToBlob));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareMinPathLenConstraintTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.minPathLenConstraint = 100000;

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // test DetailForMinPathLenConstraint failed case
    certMatchParameters.minPathLenConstraint = -2;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    BASIC_CONSTRAINTS *constraints = BASIC_CONSTRAINTS_new();
    EXPECT_NE(constraints, nullptr);
    constraints->ca = 1;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509V3_EXT_d2i(_)).WillRepeatedly(Return(constraints));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareMinPathLenConstraintTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    certMatchParameters.minPathLenConstraint = 100000;

    CfResult ret;

    BASIC_CONSTRAINTS *constraints = BASIC_CONSTRAINTS_new();
    EXPECT_NE(constraints, nullptr);
    ASN1_INTEGER *pathlen = ASN1_INTEGER_new();
    EXPECT_NE(pathlen, nullptr);
    pathlen->type = V_ASN1_NEG_INTEGER;
    constraints->ca = 0;
    constraints->pathlen = pathlen;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509V3_EXT_d2i(_)).WillRepeatedly(Return(constraints));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_INTEGER_get(_))
        .WillOnce(Return(10))
        .WillRepeatedly(Invoke(__real_ASN1_INTEGER_get));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509V3_EXT_d2i(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509V3_EXT_d2i));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext(_, _)).WillRepeatedly(Return(nullptr));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    certMatchParameters.minPathLenConstraint = 2;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_get_ext));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareExtendedKeyUsageTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;
    CfResult ret;
    HcfX509CertMatchParams certMatchParameters = { 0 };

    certMatchParameters.extendedKeyUsage = constructExtendedKeyUsageData();
    EXPECT_NE(certMatchParameters.extendedKeyUsage, nullptr);

    certMatchParameters.minPathLenConstraint = -1;

    // todo add failed case bResult = true
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // todo add failed case ret != CF_SUCCESS
    SetMockFlag(true);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    // test IsSubset failed case
    certMatchParameters.extendedKeyUsage->data[0].size -= 1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfFree(certMatchParameters.extendedKeyUsage->data);
    CfFree(certMatchParameters.extendedKeyUsage);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest000, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob = {};
    certMatchParameters.nameConstraints = &blob;
    certMatchParameters.minPathLenConstraint = -1;
    CfResult ret =
        g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.minPathLenConstraint = 0;
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test CompareNameConstraintsX509Openssl failed case
    // GEN_OTHERNAME
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_OTHERNAME;
    tree->base->d.otherName = OTHERNAME_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(tree))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    OTHERNAME_free(tree->base->d.otherName);
    tree->base->d.otherName = nullptr;
    GENERAL_NAME_free(tree->base);
    tree->base = nullptr;
    GENERAL_SUBTREE_free(tree);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    CfResult ret =
        g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    certMatchParameters.minPathLenConstraint = -1;
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // GEN_X400
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_X400;
    tree->base->d.x400Address = ASN1_STRING_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _))
        .WillOnce(Return(tree))
        .WillRepeatedly(Invoke(__real_OPENSSL_sk_value));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    ASN1_STRING_free(tree->base->d.x400Address);
    tree->base->d.x400Address = nullptr;
    GENERAL_NAME_free(tree->base);
    tree->base = nullptr;
    GENERAL_SUBTREE_free(tree);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    // GEN_IPADD
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_IPADD;
    tree->base->d.ip = ASN1_OCTET_STRING_new();
    blob.data = const_cast<uint8_t *>(g_testNameConstraintsIPADDR);
    blob.size = sizeof(g_testNameConstraintsIPADDR);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).WillRepeatedly(Return(tree));
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    ASN1_OCTET_STRING_free(tree->base->d.ip);
    tree->base->d.ip = nullptr;
    GENERAL_NAME_free(tree->base);
    tree->base = nullptr;
    GENERAL_SUBTREE_free(tree);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest003, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraintsEDIParty);
    blob.size = sizeof(g_testNameConstraintsEDIParty);
    certMatchParameters.nameConstraints = &blob;

    // GEN_EDIPARTY g_testNameConstraintsEDIPartyInvalid
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_EDIPARTY;
    tree->base->d.ediPartyName = EDIPARTYNAME_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).WillRepeatedly(Return(tree));
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    EDIPARTYNAME_free(tree->base->d.ediPartyName);
    tree->base->d.ediPartyName = nullptr;
    GENERAL_NAME_free(tree->base);
    tree->base = nullptr;
    GENERAL_SUBTREE_free(tree);

    tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_EDIPARTY;
    tree->base->d.ediPartyName = EDIPARTYNAME_new();
    blob.data = const_cast<uint8_t *>(g_testNameConstraintsEDIPartyInvalid);
    blob.size = sizeof(g_testNameConstraintsEDIPartyInvalid);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).WillRepeatedly(Return(tree));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    EDIPARTYNAME_free(tree->base->d.ediPartyName);
    tree->base->d.ediPartyName = nullptr;
    GENERAL_NAME_free(tree->base);
    tree->base = nullptr;
    GENERAL_SUBTREE_free(tree);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest004, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    CfResult ret;

    // GEN_DIRNAME
    GENERAL_SUBTREE *tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_DIRNAME;
    tree->base->d.directoryName = X509_NAME_new();

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_value(_, _)).WillRepeatedly(Return(tree));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    X509_NAME_free(tree->base->d.directoryName);
    tree->base->d.directoryName = nullptr;
    GENERAL_NAME_free(tree->base);
    tree->base = nullptr;
    GENERAL_SUBTREE_free(tree);

    // GEN_RID
    tree = reinterpret_cast<GENERAL_SUBTREE *>sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(tree, nullptr);
    tree->base = GENERAL_NAME_new();
    EXPECT_NE(tree->base, nullptr);
    tree->base->type = GEN_RID;
    tree->base->d.registeredID = ASN1_OBJECT_new();

    X509OpensslMock::SetMockFlag(true);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    ASN1_OBJECT_free(tree->base->d.registeredID);
    tree->base->d.registeredID = nullptr;
    GENERAL_NAME_free(tree->base);
    tree->base = nullptr;
    GENERAL_SUBTREE_free(tree);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareNameConstraintsTest005, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = const_cast<uint8_t *>(g_testNameConstraints);
    blob.size = sizeof(g_testNameConstraints);
    certMatchParameters.nameConstraints = &blob;

    CfResult ret;

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).WillRepeatedly(Return(nullptr));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    NAME_CONSTRAINTS *nc = NAME_CONSTRAINTS_new();
    EXPECT_NE(nc, nullptr);
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).WillRepeatedly(Return(nc));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    NAME_CONSTRAINTS_free(nc);

    nc = NAME_CONSTRAINTS_new();
    EXPECT_NE(nc, nullptr);
    nc->permittedSubtrees = sk_GENERAL_SUBTREE_new_null();
    EXPECT_NE(nc, nullptr);
    X509OpensslMock::SetMockFlag(true);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    NAME_CONSTRAINTS_free(nc);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareCertPolicyTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams matchParams = { 0 };
    matchParams.certPolicy = ConstructCertPolicyData();
    EXPECT_NE(matchParams.certPolicy, nullptr);
    SetMockFlag(true);
    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    SetMockFlag(false);

    CfFree(matchParams.certPolicy->data);
    CfFree(matchParams.certPolicy);
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareCertPolicyTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    certMatchParameters.certPolicy = ConstructCertPolicyData();

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // todo add failed case bResult = true
    certMatchParameters.minPathLenConstraint = -1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test IsSubset failed case
    certMatchParameters.certPolicy->data[0].size -= 1;
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfFree(certMatchParameters.certPolicy->data);
    CfFree(certMatchParameters.certPolicy);
}

HWTEST_F(CryptoX509CertificateTestPart3, ComparePrivateKeyValidTest001, TestSize.Level0)
{
    ASSERT_NE(g_testCertWithPrivateKeyValidObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateKeyValid));
    blob.size = strlen(g_testPrivateKeyValid) + 1;
    certMatchParameters.privateKeyValid = &blob;

    CfResult ret =
        g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // todo add failed case bResult = true
    certMatchParameters.minPathLenConstraint = -1;
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test asn1TimeToStr failed case
    X509OpensslMock::SetMockFlag(true);
    PKEY_USAGE_PERIOD *pKeyValid = reinterpret_cast<PKEY_USAGE_PERIOD *>(CfMalloc(sizeof(PKEY_USAGE_PERIOD), 0));
    EXPECT_NE(pKeyValid, nullptr);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(pKeyValid));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    pKeyValid = reinterpret_cast<PKEY_USAGE_PERIOD *>(CfMalloc(sizeof(PKEY_USAGE_PERIOD), 0));
    ASSERT_NE(pKeyValid, nullptr);
    pKeyValid->notBefore = reinterpret_cast<ASN1_GENERALIZEDTIME *>(CfMalloc(sizeof(ASN1_GENERALIZEDTIME), 0));
    ASSERT_NE(pKeyValid->notBefore, nullptr);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(pKeyValid));
    ret = g_testCertWithPrivateKeyValidObj->match(g_testCertWithPrivateKeyValidObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, ComparePrivateKeyValidTest002, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };

    CfBlob blob;
    blob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateKeyInvalid));
    blob.size = strlen(g_testPrivateKeyInvalid) + 1;
    certMatchParameters.privateKeyValid = &blob;

    CfResult ret;

    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    X509OpensslMock::SetMockFlag(true);
    PKEY_USAGE_PERIOD *pKeyValid = reinterpret_cast<PKEY_USAGE_PERIOD *>(CfMalloc(sizeof(PKEY_USAGE_PERIOD), 0));
    ASSERT_NE(pKeyValid, nullptr);
    pKeyValid->notBefore = reinterpret_cast<ASN1_GENERALIZEDTIME *>(CfMalloc(sizeof(ASN1_GENERALIZEDTIME), 0));
    ASSERT_NE(pKeyValid->notBefore, nullptr);
    pKeyValid->notBefore->data = (unsigned char *)strdup(g_testPrivateKeyValid);
    ASSERT_NE(pKeyValid->notBefore->data, nullptr);

    pKeyValid->notBefore->length = strlen(g_testPrivateKeyValid);
    pKeyValid->notAfter = nullptr;
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(pKeyValid));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);

    // test ComparePrivateKeyValidX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).WillRepeatedly(Return(nullptr));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);
    X509OpensslMock::SetMockFlag(false);
    CfFree(pKeyValid->notBefore->data);
    pKeyValid->notBefore->data = nullptr;
    CfFree(pKeyValid->notBefore);
    pKeyValid->notBefore = nullptr;
    CfFree(pKeyValid);
    pKeyValid = nullptr;
}

HWTEST_F(CryptoX509CertificateTestPart3, CompareSubjectKeyIdentifierTest001, TestSize.Level0)
{
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);
    bool bResult = true;

    HcfX509CertMatchParams certMatchParameters = { 0 };
    CfBlob blob;

    blob.data = const_cast<uint8_t *>(g_testIssuer);
    blob.size = sizeof(g_testIssuer);
    certMatchParameters.subjectKeyIdentifier = &blob;

    CfResult ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    // todo add failed case bResult = true
    certMatchParameters.minPathLenConstraint = -1;
    blob.data = const_cast<uint8_t *>(g_testSubjectKeyIdentifier);
    blob.size = sizeof(g_testSubjectKeyIdentifier);
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    // test GetSubKeyIdDNX509Openssl failed case
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_ASN1_OCTET_STRING(_, _)).WillRepeatedly(Return(-1));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_ext_d2i(_, _, _, _)).WillRepeatedly(Return(nullptr));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), DeepCopyDataToBlob(_, _, _))
        .Times(AnyNumber())
        .WillOnce(Return(CF_INVALID_PARAMS));
    ret = g_x509CertExtAttrObj->match(g_x509CertExtAttrObj, &certMatchParameters, &bResult);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, ToStringTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertificateTestPart3 - ToStringTest001");
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    HcfX509Certificate invalidCert;
    invalidCert.base.base.getClass = GetInvalidCertClass;

    ret = g_x509CertExtAttrObj->toString(&invalidCert, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->toString(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->toString(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new));
    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_print(_, _))
        .WillOnce(Return(-1))
        .WillRepeatedly(Invoke(__real_X509_print));
    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_ctrl(_, _, _, _)).WillRepeatedly(Return(0));
    ret = g_x509CertExtAttrObj->toString(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);
}

HWTEST_F(CryptoX509CertificateTestPart3, HashCodeTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertificateTestPart3 - HashCodeTest001");
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    SetMockFlag(true);
    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509(_, _)).WillRepeatedly(Return(-1));
    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509(_, _)).WillRepeatedly(Return(0));
    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    HcfX509Certificate invalidCert;
    invalidCert.base.base.getClass = GetInvalidCertClass;

    ret = g_x509CertExtAttrObj->hashCode(&invalidCert, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->hashCode(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->hashCode(g_x509CertExtAttrObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->hashCode(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertificateTestPart3, GetExtensionsObjectTest001, TestSize.Level0)
{
    CF_LOG_I("CryptoX509CertificateTestPart3 - GetExtensionsObjectTest001");
    ASSERT_NE(g_x509CertExtAttrObj, nullptr);

    CfBlob blob = { 0, nullptr };
    CfResult ret = g_x509CertExtAttrObj->getExtensionsObject(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_SUCCESS);
    CfBlobDataFree(&blob);

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), i2d_X509_EXTENSIONS(_, _)).WillRepeatedly(Return(-1));
    ret = g_x509CertExtAttrObj->getExtensionsObject(g_x509CertExtAttrObj, &blob);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    HcfX509Certificate invalidCert;
    invalidCert.base.base.getClass = GetInvalidCertClass;

    ret = g_x509CertExtAttrObj->getExtensionsObject(&invalidCert, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->getExtensionsObject(NULL, &blob);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->getExtensionsObject(g_x509CertExtAttrObj, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);

    ret = g_x509CertExtAttrObj->getExtensionsObject(NULL, NULL);
    EXPECT_EQ(ret, CF_INVALID_PARAMS);
}

HWTEST_F(CryptoX509CertificateTestPart3, MatchX509CertPrivateKeyTest001, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertDataDisMatch));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testCertDataDisMatch) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    CfEncodingBlob privateKeyBlob = { 0 };
    privateKeyBlob.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPriKeyDisMatch));
    privateKeyBlob.encodingFormat = CF_FORMAT_PEM;
    privateKeyBlob.len = strlen(g_testPriKeyDisMatch) + 1;

    bool bResult = true;
    HcfX509CertMatchParams matchParams = { 0 };
    matchParams.privateKey = &privateKeyBlob;
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfEncodingBlob privateKeyBlobDer = { 0 };
    privateKeyBlobDer.data = const_cast<uint8_t *>(g_testPriKeyDerDisMatch);
    privateKeyBlobDer.encodingFormat = CF_FORMAT_DER;
    privateKeyBlobDer.len = sizeof(g_testPriKeyDerDisMatch);
    HcfX509CertMatchParams matchDerParams = { 0 };
    matchDerParams.privateKey = &privateKeyBlobDer;
    ret = x509Cert->match(x509Cert, &matchDerParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, false);

    CfObjDestroy(x509Cert);
}

HWTEST_F(CryptoX509CertificateTestPart3, MatchX509CertPrivateKeyTest002, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertDataRsa));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testCertDataRsa) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_NE(x509Cert, nullptr);

    CfEncodingBlob privateKeyBlobP1 = { 0 };
    privateKeyBlobP1.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateDataRsaP1));
    privateKeyBlobP1.encodingFormat = CF_FORMAT_PEM;
    privateKeyBlobP1.len = strlen(g_testPrivateDataRsaP1) + 1;

    bool bResult = false;
    HcfX509CertMatchParams matchParamsP1 = { 0 };
    matchParamsP1.privateKey = &privateKeyBlobP1;
    ret = x509Cert->match(x509Cert, &matchParamsP1, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    CfEncodingBlob privateKeyBlobP8 = { 0 };
    privateKeyBlobP8.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateDataRsaP8));
    privateKeyBlobP8.encodingFormat = CF_FORMAT_PEM;
    privateKeyBlobP8.len = strlen(g_testPrivateDataRsaP8) + 1;

    bResult = false;
    HcfX509CertMatchParams matchParamsP8 = { 0 };
    matchParamsP8.privateKey = &privateKeyBlobP8;
    ret = x509Cert->match(x509Cert, &matchParamsP8, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    CfEncodingBlob privateKeyBlobDer = { 0 };
    privateKeyBlobDer.data = const_cast<uint8_t *>(g_testPrivateDataRsaP1Der);
    privateKeyBlobDer.encodingFormat = CF_FORMAT_DER;
    privateKeyBlobDer.len = sizeof(g_testPrivateDataRsaP1Der);

    bResult = false;
    HcfX509CertMatchParams matchParamsDer = { 0 };
    matchParamsDer.privateKey = &privateKeyBlobDer;
    ret = x509Cert->match(x509Cert, &matchParamsDer, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);
    EXPECT_EQ(bResult, true);

    CfObjDestroy(x509Cert);
}

HWTEST_F(CryptoX509CertificateTestPart3, MatchX509CertPrivateKeyTest003, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertDataRsa));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testCertDataRsa) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    bool bResult = true;
    HcfX509CertMatchParams matchParams = { 0 };

    // cover: if (privateKey == NULL) { return CF_SUCCESS; }
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_SUCCESS);

    // cover: if ((privateKey->len == 0) || (privateKey->data == NULL))
    CfEncodingBlob invalidPrivateKey = { 0 };
    invalidPrivateKey.encodingFormat = CF_FORMAT_DER;
    invalidPrivateKey.data = nullptr;
    invalidPrivateKey.len = 1;
    matchParams.privateKey = &invalidPrivateKey;
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);

    // cover: if ((privateKey->len == 0) || (privateKey->data == NULL)) with len == 0
    uint8_t dummyKeyData = 0x01;
    invalidPrivateKey.data = &dummyKeyData;
    invalidPrivateKey.len = 0;
    matchParams.privateKey = &invalidPrivateKey;
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);

    // cover: if (certPubKey == NULL)
    CfEncodingBlob privateKeyBlobP1 = { 0 };
    privateKeyBlobP1.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateDataRsaP1));
    privateKeyBlobP1.encodingFormat = CF_FORMAT_PEM;
    privateKeyBlobP1.len = strlen(g_testPrivateDataRsaP1) + 1;
    matchParams.privateKey = &privateKeyBlobP1;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get_pubkey(_))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_X509_get_pubkey));
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(x509Cert);
}

HWTEST_F(CryptoX509CertificateTestPart3, MatchX509CertPrivateKeyTest004, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertDataRsa));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testCertDataRsa) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    bool bResult = true;
    HcfX509CertMatchParams matchParams = { 0 };

    // cover: BIO_new_mem_buf returns NULL
    CfEncodingBlob privateKeyBlobPem = { 0 };
    privateKeyBlobPem.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateDataRsaP1));
    privateKeyBlobPem.encodingFormat = CF_FORMAT_PEM;
    privateKeyBlobPem.len = strlen(g_testPrivateDataRsaP1) + 1;
    matchParams.privateKey = &privateKeyBlobPem;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_new_mem_buf(_, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_BIO_new_mem_buf));
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_MALLOC);
    X509OpensslMock::SetMockFlag(false);

    // cover: PEM_read_bio_PrivateKey returns NULL
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), PEM_read_bio_PrivateKey(_, _, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_PEM_read_bio_PrivateKey));
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    // cover: d2i_AutoPrivateKey returns NULL
    CfEncodingBlob privateKeyBlobDer = { 0 };
    privateKeyBlobDer.data = const_cast<uint8_t *>(g_testPrivateDataRsaP1Der);
    privateKeyBlobDer.encodingFormat = CF_FORMAT_DER;
    privateKeyBlobDer.len = sizeof(g_testPrivateDataRsaP1Der);
    matchParams.privateKey = &privateKeyBlobDer;
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), d2i_AutoPrivateKey(_, _, _))
        .WillOnce(Return(nullptr))
        .WillRepeatedly(Invoke(__real_d2i_AutoPrivateKey));
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_CRYPTO_OPERATION);
    X509OpensslMock::SetMockFlag(false);

    CfObjDestroy(x509Cert);
}

HWTEST_F(CryptoX509CertificateTestPart3, MatchX509CertPrivateKeyTest005, TestSize.Level0)
{
    HcfX509Certificate *x509Cert = nullptr;
    CfEncodingBlob inStream = { 0 };
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertDataRsa));
    inStream.encodingFormat = CF_FORMAT_PEM;
    inStream.len = strlen(g_testCertDataRsa) + 1;
    CfResult ret = HcfX509CertificateCreate(&inStream, &x509Cert);
    EXPECT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(x509Cert, nullptr);

    bool bResult = true;
    HcfX509CertMatchParams matchParams = { 0 };
    CfEncodingBlob invalidFormatPrivateKey = { 0 };
    invalidFormatPrivateKey.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_testPrivateDataRsaP1));
    invalidFormatPrivateKey.len = strlen(g_testPrivateDataRsaP1) + 1;
    invalidFormatPrivateKey.encodingFormat = static_cast<CfEncodingFormat>(0xFF);
    matchParams.privateKey = &invalidFormatPrivateKey;

    // cover: private key encoding format is invalid
    ret = x509Cert->match(x509Cert, &matchParams, &bResult);
    EXPECT_EQ(ret, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(x509Cert);
}
} // namespace
