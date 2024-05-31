/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef CRYPTO_X509_CERT_CHAIN_DATA_PEM_H
#define CRYPTO_X509_CERT_CHAIN_DATA_PEM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * validity Validity SEQUENCE (2 elem)
 *    notBefore Time UTCTime 2023-12-05 07:39:00 UTC  (*)
 *    notAfter Time UTCTime 2024-10-31 23:59:00 UTC
 *
 * validity Validity SEQUENCE (2 elem)
 *    notBefore Time UTCTime 2023-12-05 07:37:00 UTC
 *    notAfter Time UTCTime 2024-09-01 23:59:00 UTC (*)
 *
 * validity Validity SEQUENCE (2 elem)
 *    notBefore Time UTCTime 2023-12-05 00:00:00 UTC
 *    notAfter Time UTCTime 2024-12-04 23:59:59 UTC
 */

#define TEST_SUBJECT_ALTERNATIVE_NAMES_SIZE 13
#define VARIABLE_ARRAY_SIZE_OFFSET 30

struct VariableArray {
    uint8_t size;
    uint8_t data[VARIABLE_ARRAY_SIZE_OFFSET];
};

static const char g_testCertChainValidatorCaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testCertChainValidatorSecondCaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "-----END CERTIFICATE-----\r\n";

    static const char g_testCertChainValidatorInvalidCaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "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\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testSelfSignedCaCertValid[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDHTCCAgWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAXMRUwEwYDVQQDDAxUZXN0\r\n"
    "IE5DIENBIDEwIBcNMjExMjAyMTcyNTAyWhgPMjEyMTEyMDMxNzI1MDJaMDwxIzAh\r\n"
    "BgNVBAoMGkdvb2QgTkMgVGVzdCBDZXJ0aWZpY2F0ZSAxMRUwEwYDVQQDDAx3d3cu\r\n"
    "Z29vZC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDqx1t7HiPe\r\n"
    "kRAWdiGUt4pklKGZ7338An6R7/y0e/8Grx2jeUfyc19BAB7MW1p8L+zdMjbclNE0\r\n"
    "UZ6RZZNexfgMksNI/nW+4Lzu8qu2wFx1MjbTpMT8w/vnsGBMthxLu6+2wdnpdD1B\r\n"
    "0led8xu7PSBgVULqyHcUvoLeRGEsB14yGx7dbIsokYxno1nr4u3BK5ic9KTTSxJR\r\n"
    "Ig93qwo2pAZR7mfnOo33B9alhzvSwmEKJ9v7pERDnIP5ED0HaWFAeXl7GFgoH2y9\r\n"
    "QDyJVuwWsoSWIx4Mr8UIr0IbVJU6KsqEiqqc5P5rX/y4tYMkpHZd9U1EONd2uwmX\r\n"
    "dwSp0LEmQb/DAgMBAAGjTTBLMB0GA1UdDgQWBBSfJPZqs1tk+xjjDrovr13ORDWn\r\n"
    "ojAfBgNVHSMEGDAWgBQI0Zv55tVkcKDxaxqe7VLa3fVQQzAJBgNVHRMEAjAAMA0G\r\n"
    "CSqGSIb3DQEBCwUAA4IBAQAEKXs56hB4DOO1vJe7pByfCHU33ij/ux7u68BdkDQ8\r\n"
    "S9SNaoD7h1XNSmC8kKULvpoKctJzJxh1IH4wtvGGGXsUt1By0a6Y5SnKW9/mG4NM\r\n"
    "D4fGea0G2AeI8BHFs6vl8voYK9wgx9Ygus3Kj/8h6V7t2zB8ZhhVqpZkAQEjj0C2\r\n"
    "1IV273wD0VdZl7uB+MEKk+7eTjNMeo6JzlBBf5GhtA1WbLNdszMfI0ljo7HAX+9L\r\n"
    "yco0xKSKkZQ+v7VdJBfC6odp+epPMZqfyHrkFzUr8XRJfriP1lydPK7AbXLVrLJg\r\n"
    "fIXCvUdxQx4B1LaclUDORL5r2tRhRYdAEKtUz7RpQzJK\r\n"
    "-----END CERTIFICATE-----\r\n";

static const uint8_t g_testChainPubkeyPemRootData[] = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03,
    0x21, 0x00, 0xBB, 0x16, 0x9D, 0x8F, 0x5C, 0x30, 0xD0, 0xBA, 0x8F, 0x37, 0x6E, 0x33, 0xAF, 0x6F, 0x23, 0x71, 0x23,
    0xA5, 0x49, 0x60, 0x1E, 0xD1, 0x07, 0x4B, 0xC9, 0x11, 0x7E, 0x66, 0x01, 0xBA, 0x92, 0x52 };

static const uint8_t g_testChainPubkeyPemRootHasPubKey[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xC9, 0xC1,
    0x89, 0x06, 0x0E, 0x5A, 0xDC, 0x3D, 0xE2, 0x04, 0xBE, 0x53, 0x5C, 0xA0, 0xD8, 0xC1, 0x36, 0x43, 0x19, 0x7B, 0xAC,
    0xDF, 0xB6, 0x86, 0x8C, 0x0B, 0x0C, 0x60, 0x13, 0xD4, 0xAC, 0x14, 0xAB, 0x4E, 0xC8, 0xEC, 0x16, 0x1F, 0x0E, 0xAE,
    0x43, 0x5A, 0x7B, 0xA0, 0x9E, 0x80, 0x18, 0x24, 0x73, 0x4C, 0x0F, 0x7F, 0xDE, 0x85, 0xBA, 0x8B, 0x3D, 0x69, 0xC9,
    0x53, 0x42, 0x24, 0x03, 0xE1 };

static const uint8_t g_testChainSubjectPemRootData[] = { 0x30, 0x5a, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x45, 0x4e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x07, 0x45, 0x6e, 0x67,
    0x6c, 0x61, 0x6e, 0x64, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x06, 0x4c, 0x6f, 0x6e, 0x64,
    0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x03, 0x74, 0x73, 0x31, 0x31, 0x0c, 0x30,
    0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x03, 0x74, 0x73, 0x31, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x13, 0x03, 0x74, 0x73, 0x31 };

static const uint8_t g_testChainSubjectPemOtherSubjectData[] = { 0x30, 0x6e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x43, 0x4e, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x09, 0x67, 0x75,
    0x61, 0x6e, 0x67, 0x64, 0x6f, 0x6e, 0x67, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x09, 0x73,
    0x68, 0x65, 0x6e, 0x7a, 0x68, 0x65, 0x6e, 0x67, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x08,
    0x74, 0x65, 0x73, 0x74, 0x72, 0x6f, 0x6f, 0x74, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x08,
    0x74, 0x65, 0x73, 0x74, 0x72, 0x6f, 0x6f, 0x74, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x08,
    0x74, 0x65, 0x73, 0x74, 0x72, 0x6f, 0x6f, 0x74 };

static const uint8_t g_testChainPubkeyPemNoRootLast[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xC0, 0xE7,
    0x66, 0x0A, 0x74, 0x6F, 0xDB, 0xDF, 0x6C, 0x94, 0xE1, 0xAE, 0x7A, 0xCF, 0xB3, 0xD9, 0xA5, 0x24, 0x95, 0x51, 0x11,
    0x13, 0xEA, 0x92, 0x13, 0x51, 0x6B, 0x28, 0x8C, 0x51, 0x0B, 0x8F, 0xF8, 0xED, 0x87, 0xAC, 0x7F, 0xA0, 0x5B, 0xB8,
    0x34, 0x4A, 0xBF, 0x3F, 0x86, 0x4B, 0x27, 0xF8, 0x09, 0xE5, 0x6F, 0xF6, 0xC6, 0x66, 0x8D, 0x45, 0xA2, 0x6E, 0x17,
    0xBD, 0x52, 0xAF, 0x83, 0x00 };

static const uint8_t g_testChainSubjectPemNoRootLastUp[] = { 0x30, 0x2d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x43, 0x4e, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x04, 0x74, 0x65, 0x73,
    0x74, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x72, 0x6f, 0x6f, 0x74, 0x63, 0x61 };

static const uint8_t g_testChainPubkeyPemNoRootLastUp[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xc9, 0xc1,
    0x89, 0x06, 0x0e, 0x5a, 0xdc, 0x3d, 0xe2, 0x04, 0xbe, 0x53, 0x5c, 0xa0, 0xd8, 0xc1, 0x36, 0x43, 0x19, 0x7b, 0xac,
    0xdf, 0xb6, 0x86, 0x8c, 0x0b, 0x0c, 0x60, 0x13, 0xd4, 0xac, 0x14, 0xab, 0x4e, 0xc8, 0xec, 0x16, 0x1f, 0x0e, 0xae,
    0x43, 0x5a, 0x7b, 0xa0, 0x9e, 0x80, 0x18, 0x24, 0x73, 0x4c, 0x0f, 0x7f, 0xde, 0x85, 0xba, 0x8b, 0x3d, 0x69, 0xc9,
    0x53, 0x42, 0x24, 0x03, 0xe1 };

static const uint8_t g_testChainSubjectPemNoRootLast[] = { 0x30, 0x2c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x43, 0x4e, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x04, 0x74, 0x65, 0x73,
    0x74, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x05, 0x73, 0x75, 0x62, 0x63, 0x61 };

const uint8_t g_testIssuer[] = { 0x30, 0x76, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
    0x4E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x02, 0x42, 0x4A, 0x31, 0x0B, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x0C, 0x02, 0x42, 0x4A, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x02,
    0x48, 0x44, 0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x03, 0x64, 0x65, 0x76, 0x31, 0x0B, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x02, 0x63, 0x61, 0x31, 0x25, 0x30, 0x23, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x16, 0x63, 0x61, 0x40, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x66, 0x72,
    0x61, 0x6D, 0x65, 0x77, 0x6F, 0x72, 0x6B, 0x2E, 0x63, 0x6F, 0x6D };

const uint8_t g_testSubject[] = { 0x30, 0x76, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43,
    0x4E, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x02, 0x42, 0x4A, 0x31, 0x0B, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x07, 0x0C, 0x02, 0x42, 0x4A, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x02,
    0x48, 0x44, 0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x03, 0x64, 0x65, 0x76, 0x31, 0x0B, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x02, 0x63, 0x61, 0x31, 0x25, 0x30, 0x23, 0x06, 0x09, 0x2A, 0x86, 0x48,
    0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x16, 0x63, 0x61, 0x40, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6F, 0x66, 0x72,
    0x61, 0x6D, 0x65, 0x77, 0x6F, 0x72, 0x6B, 0x2E, 0x63, 0x6F, 0x6D };

const struct VariableArray g_testSubjectAlternativeNames[TEST_SUBJECT_ALTERNATIVE_NAMES_SIZE] = {
    { 20, { 0x82, 0x12, 0x77, 0x77, 0x77, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67, 0x6E, 0x2E, 0x63,
            0x6F, 0x6D } },
    { 23, { 0x82, 0x15, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67,
            0x6E, 0x2E, 0x63, 0x6F, 0x6D } },
    { 19, { 0x82, 0x11, 0x74, 0x68, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67, 0x6E, 0x2E, 0x63, 0x6F,
            0x6D } },
    { 20, { 0x82, 0x12, 0x64, 0x65, 0x76, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67, 0x6E, 0x2E, 0x63,
            0x6F, 0x6D } },
    { 21, { 0x82, 0x13, 0x69, 0x6E, 0x66, 0x6F, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67, 0x6E, 0x2E,
            0x63, 0x6F, 0x6D } },
    { 24, { 0x82, 0x16, 0x61, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69,
            0x67, 0x6E, 0x2E, 0x63, 0x6F, 0x6D } },
    { 24, { 0x82, 0x16, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x31, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69,
            0x67, 0x6E, 0x2E, 0x63, 0x6F, 0x6D } },
    { 24, { 0x82, 0x16, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x32, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69,
            0x67, 0x6E, 0x2E, 0x63, 0x6F, 0x6D } },
    { 21, { 0x82, 0x13, 0x62, 0x6C, 0x6F, 0x67, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67, 0x6E, 0x2E,
            0x63, 0x6F, 0x6D } },
    { 25, { 0x82, 0x17, 0x73, 0x73, 0x6C, 0x63, 0x68, 0x65, 0x63, 0x6B, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73,
            0x69, 0x67, 0x6E, 0x2E, 0x63, 0x6F, 0x6D } },
    { 23, { 0x82, 0x15, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67,
            0x6E, 0x2E, 0x63, 0x6F, 0x6D } },
    { 26, { 0x82, 0x18, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C,
            0x73, 0x69, 0x67, 0x6E, 0x2E, 0x63, 0x6F, 0x6D } },
    { 16, { 0x82, 0x0E, 0x67, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x73, 0x69, 0x67, 0x6E, 0x2E, 0x63, 0x6F, 0x6D } }
};

const uint8_t g_testAuthorityKeyIdentifier[] = { 0x30, 0x16, 0x80, 0x14, 0xB0, 0xB0, 0x4A, 0xFD, 0x1C, 0x75, 0x28, 0xF8,
    0x1C, 0x61, 0xAA, 0x13, 0xF6, 0xFA, 0xC1, 0x90, 0x3D, 0x6B, 0x16, 0xA3 };

const uint8_t g_testExtendedKeyUsage[] = { 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x35, 0x2e, 0x35, 0x2e, 0x37,
    0x2e, 0x33, 0x2e, 0x31, 0x00 };

const uint8_t g_testNameConstraints[] = { 0x16, 0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
    0x6d };

const uint8_t g_testNameConstraintsEDIParty[] = { 0x30, 0x04, 0xa1, 0x02, 0x1f, 0x00 };
const uint8_t g_testNameConstraintsEDIPartyInvalid[] = { 0x30, 0x04, 0xa1, 0x02, 0x1f, 0x01 };
const uint8_t g_testNameConstraintsIPADDR[] = { 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

const uint8_t g_testCertPolicy[] = { 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x31,
    0x34, 0x36, 0x2e, 0x31, 0x2e, 0x31, 0x00 };

const char g_testPrivateKeyValid[] = "241121-00:00:00Z";
const char g_testPrivateKeyInvalid[] = "abc";

const uint8_t g_testSubjectKeyIdentifier[] = { 0x04, 0x14, 0xAF, 0x32, 0x84, 0xC3, 0x94, 0x50, 0x74, 0x69, 0x58, 0x15,
    0xAC, 0xD9, 0x24, 0x4B, 0x54, 0x12, 0x99, 0x87, 0xF1, 0xD7 };

const char g_testUpdateDateTime[] = "20250101080000Z";

#ifdef __cplusplus
}
#endif
#endif
