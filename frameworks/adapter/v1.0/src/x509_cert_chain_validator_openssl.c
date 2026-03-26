/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "x509_cert_chain_validator_openssl.h"

#include <string.h>
#include <securec.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bioerr.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>

#include "cf_blob.h"
#include "config.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "utils.h"
#include "cf_result.h"
#include "certificate_openssl_common.h"
#include "cert_chain_validator.h"
#include "x509_cert_chain_openssl.h"
#include "x509_cert_chain_openssl_ex.h"
#include "x509_crl_openssl.h"

#define X509_CERT_CHAIN_VALIDATOR_OPENSSL_CLASS "X509CertChainValidatorOpensslClass"

#define MAX_TOTAL_DOWNLOAD_CERT_COUNT 5    // Max total download count
#define MAX_TOTAL_DOWNLOAD_COUNT 6    // Max total download count
#define MAX_INFO_ACCESS_TRAVERSE_COUNT 3  // Max traverse count for infoAccess
#define DOWNLOAD_TIMEOUT_SECONDS 3    // Download timeout in seconds
#define CRL_DOWNLOAD_TIMEOUT_SECONDS 3    // CRL download timeout in seconds
#define OCSP_REQUEST_TIMEOUT_SECONDS 3    // OCSP request timeout in seconds
#define MAX_REVOCATION_FLAGS_COUNT 4      // Max revocation flags count

typedef struct {
    uint8_t *data;
    size_t len;
    X509 *x509;
} CertsInfo;

#define MAX_ERROR_MSG_BUF_LEN 512
#define MAX_SUBJECT_NAME_LEN 256

typedef struct {
    STACK_OF(X509) *certChain;   // Verified certificate chain on success (owned by caller)
    char errorMsgBuf[MAX_ERROR_MSG_BUF_LEN]; // Temporary error message buffer
    const char *errorMsg;         // Error message on failure
    int32_t errCode;              // OpenSSL error code
    X509 *lastCert;               // Last cert in chain (used for downloading intermediate cert)
} CertVerifyResultInner;

typedef struct {
    X509 *cert;
    X509 *issuer;
    X509_STORE *store;
    STACK_OF(X509) *untrustedCertStack;
    STACK_OF(X509) *certChain;
    time_t date;
    bool crlCheck;
    bool ocspCheck;
    bool preferOcsp;
    bool revocationCheckAll;
} HcfX509CertValidatorOpenSSLParams;

static const OpensslErrorToResult ERROR_TO_RESULT_MAP[] = {
    { X509_V_OK, CF_SUCCESS },
    { X509_V_ERR_CERT_SIGNATURE_FAILURE, CF_ERR_CERT_SIGNATURE_FAILURE },
    { X509_V_ERR_CERT_NOT_YET_VALID, CF_ERR_CERT_NOT_YET_VALID },
    { X509_V_ERR_CERT_HAS_EXPIRED, CF_ERR_CERT_HAS_EXPIRED },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { X509_V_ERR_KEYUSAGE_NO_CERTSIGN, CF_ERR_KEYUSAGE_NO_CERTSIGN },
    { X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
    { X509_V_ERR_INVALID_CA, CF_ERR_KEYUSAGE_NO_CERTSIGN },
};

static const OpensslErrorToResult ERROR_TO_RESULT_MAP_EX[] = {
    { X509_V_ERR_CERT_REVOKED, CF_ERR_CERT_REVOKED },
    { X509_V_ERR_CERT_UNTRUSTED, CF_ERR_CERT_UNTRUSTED },
    { X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, CF_ERR_CERT_UNTRUSTED },
    { X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN, CF_ERR_CERT_UNTRUSTED },
    { X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION, CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION },
    { X509_V_ERR_UNABLE_TO_GET_CRL, CF_ERR_CRL_NOT_FOUND },
    { X509_V_ERR_CRL_NOT_YET_VALID, CF_ERR_CRL_NOT_YET_VALID },
    { X509_V_ERR_CRL_HAS_EXPIRED, CF_ERR_CRL_HAS_EXPIRED },
    { X509_V_ERR_CRL_SIGNATURE_FAILURE, CF_ERR_CRL_SIGNATURE_FAILURE },
    { X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER, CF_ERR_UNABLE_TO_GET_CRL_ISSUER },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY},
};

static CfResult ConvertOpensslErrorMsg(int32_t errCode)
{
    for (uint32_t i = 0; i < sizeof(ERROR_TO_RESULT_MAP) / sizeof(OpensslErrorToResult); i++) {
        if (ERROR_TO_RESULT_MAP[i].errCode == errCode) {
            return ERROR_TO_RESULT_MAP[i].result;
        }
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static CfResult ConvertOpensslErrorMsgEx(int32_t errCode)
{
    for (uint32_t i = 0; i < sizeof(ERROR_TO_RESULT_MAP_EX) / sizeof(OpensslErrorToResult); i++) {
        if (ERROR_TO_RESULT_MAP_EX[i].errCode == errCode) {
            return ERROR_TO_RESULT_MAP_EX[i].result;
        }
    }
    return ConvertOpensslErrorMsg(errCode);
}

static CfResult DownloadCertFromAiaUrl(const char *url, X509 **cert)
{
    ERR_clear_error();
    *cert = X509_load_http(url, NULL, NULL, DOWNLOAD_TIMEOUT_SECONDS);
    if (*cert != NULL) {
        return CF_SUCCESS;
    }

    unsigned long err = ERR_peek_error();
    int reason = ERR_GET_REASON(err);
    if (reason == BIO_R_CONNECT_TIMEOUT || reason == BIO_R_TRANSFER_TIMEOUT) {
        LOGW("Download certificate timeout from URL: %s", url);
        return CF_ERR_NETWORK_TIMEOUT;
    }
    if (reason == ERR_R_MALLOC_FAILURE) {
        return CF_ERR_MALLOC;
    }
    LOGW("Failed to download certificate from URL: %s, reason=%d", url, reason);
    return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
}

static CfResult TryDownloadFromSingleAia(ACCESS_DESCRIPTION *ad, uint32_t *remainingCount, X509 **cert)
{
    if (ad == NULL || ad->method == NULL || ad->location == NULL || remainingCount == NULL) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    if (OBJ_obj2nid(ad->method) != NID_ad_ca_issuers) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    if (ad->location->type != GEN_URI) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    ASN1_IA5STRING *uri = ad->location->d.uniformResourceIdentifier;
    if (uri == NULL || uri->data == NULL) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    int len = ASN1_STRING_length(uri);
    if (len <= 0) {
        return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    }
    char *url = (char *)CfMallocEx(len + 1);
    if (url == NULL) {
        return CF_ERR_MALLOC;
    }
    (void)memcpy_s(url, len + 1, uri->data, len);

    (*remainingCount)--;
    CfResult res = DownloadCertFromAiaUrl(url, cert);
    CfFree(url);
    return res;
}

// static CfResult GetDownloadedCertFromAIAWithRetry(X509 *leafCert, int *remainingCount, X509 **cert)
// {
//     AUTHORITY_INFO_ACCESS *infoAccess = X509_get_ext_d2i(leafCert, NID_info_access, NULL, NULL);
//     if (infoAccess == NULL) {
//         LOGD("No AIA extension found in certificate.");
//         return CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
//     }

//     CfResult res = CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
//     int num = sk_ACCESS_DESCRIPTION_num(infoAccess);

//     for (int traverse = 0; traverse < MAX_INFO_ACCESS_TRAVERSE_COUNT && *remainingCount > 0; traverse++) {
//         for (int i = 0; i < num && *remainingCount > 0; i++) {
//             ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(infoAccess, i);
//             res = TryDownloadFromSingleAia(ad, remainingCount, cert);
//             if (res == CF_SUCCESS) {
//                 AUTHORITY_INFO_ACCESS_free(infoAccess);
//                 return CF_SUCCESS;
//             }
//             if (res == CF_ERR_MALLOC) {
//                 AUTHORITY_INFO_ACCESS_free(infoAccess);
//                 return CF_ERR_MALLOC;
//             }
//         }
//     }
//     AUTHORITY_INFO_ACCESS_free(infoAccess);
//     return res;
// }

static const char *GetX509CertChainValidatorClass(void)
{
    return X509_CERT_CHAIN_VALIDATOR_OPENSSL_CLASS;
}

static void DestroyX509CertChainValidator(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid params!");
        return;
    }
    if (!CfIsClassMatch(self, GetX509CertChainValidatorClass())) {
        LOGE("Class is not match.");
        return;
    }
    CfFree((HcfCertChainValidatorSpi *)self);
}

static CfResult InitX509Certs(const CfArray *certsList, CertsInfo **certs)
{
    uint32_t certsInfoLen = sizeof(CertsInfo) * certsList->count;
    CertsInfo *certsInfo = (CertsInfo *)CfMalloc(certsInfoLen, 0);
    if (certsInfo == NULL) {
        LOGE("Failed to new memory for cert info.");
        return CF_ERR_MALLOC;
    }
    for (uint32_t i = 0; i < certsList->count; ++i) {
        CertsInfo *info = &(certsInfo[i]);
        info->data = certsList->data[i].data;
        info->len = certsList->data[i].size;
    }
    *certs = certsInfo;
    return CF_SUCCESS;
}

static void FreeX509Certs(CertsInfo **certs, uint32_t certNum)
{
    if (certs == NULL) {
        LOGD("Input NULL certs, no need to free.");
        return;
    }
    for (uint32_t i = 0; i < certNum; ++i) {
        if ((*certs)[i].x509 != NULL) {
            X509_free((*certs)[i].x509);
            (*certs)[i].x509 = NULL;
        }
    }
    CfFree(*certs);
    *certs = NULL;
}

static X509 *GetX509Cert(const uint8_t *data, size_t len, enum CfEncodingFormat format)
{
    X509 *x509 = NULL;
    BIO *bio = BIO_new_mem_buf(data, len);
    if (bio == NULL) {
        LOGE("Failed to new memory for bio.");
        return NULL;
    }

    if (format == CF_FORMAT_DER) {
        x509 = d2i_X509_bio(bio, NULL);
    } else if (format == CF_FORMAT_PEM) {
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);
    return x509;
}

static CfResult ValidateCertChainInner(CertsInfo *certs, uint32_t certNum)
{
    CfResult res = CF_SUCCESS;
    X509_STORE *store = X509_STORE_new();
    X509_STORE_CTX *verifyCtx = X509_STORE_CTX_new();
    do {
        if ((store == NULL) || (verifyCtx == NULL)) {
            LOGE("Failed to verify cert chain init.");
            res = CF_ERR_MALLOC;
            break;
        }

        for (uint32_t i = certNum - 1; i > 0; i--) { // certs[certNum - 1] represents the 0th cert.
            if (X509_STORE_add_cert(store, certs[i].x509) != CF_OPENSSL_SUCCESS) {
                LOGE("Failed to add cert to store.");
                CfPrintOpensslError();
                res = CF_ERR_MALLOC;
                break;
            }
        }
        if (res != CF_SUCCESS) {
            break;
        }
        /* Do not check cert validity against current time. */
        X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME);
        int32_t resOpenssl = X509_STORE_CTX_init(verifyCtx, store, certs[0].x509, NULL);
        if (resOpenssl != CF_OPENSSL_SUCCESS) {
            LOGE("Failed to init verify ctx.");
            res = CF_ERR_CRYPTO_OPERATION;
            CfPrintOpensslError();
            break;
        }
        resOpenssl = X509_verify_cert(verifyCtx);
        if (resOpenssl != CF_OPENSSL_SUCCESS) {
            int32_t errCode = X509_STORE_CTX_get_error(verifyCtx);
            const char *pChError = X509_verify_cert_error_string(errCode);
            LOGE("Failed to verify cert, openssl openssl error code = %{public}d, error msg:%{public}s.",
                errCode, pChError);
            res = ConvertOpensslErrorMsg(errCode);
            break;
        }
    } while (0);

    if (verifyCtx != NULL) {
        X509_STORE_CTX_free(verifyCtx);
    }
    if (store != NULL) {
        X509_STORE_free(store);
    }
    return res;
}

static CfResult ValidateCertChain(CertsInfo *certs, uint32_t certNum, enum CfEncodingFormat format)
{
    for (uint32_t i = 0; i < certNum; ++i) {
        X509 *x509 = GetX509Cert(certs[i].data, certs[i].len, format);
        if (x509 == NULL) {
            LOGE("Failed to convert cert blob to x509.");
            return CF_ERR_CRYPTO_OPERATION; /* X509 will be freed by caller func. */
        }
        certs[i].x509 = x509;
    }
    return ValidateCertChainInner(certs, certNum);
}

static CfResult Validate(HcfCertChainValidatorSpi *self, const CfArray *certsList)
{
    if ((self == NULL) || (certsList == NULL) || (certsList->count <= 1)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!CfIsClassMatch((CfObjectBase *)self, GetX509CertChainValidatorClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }
    CertsInfo *certs = NULL;
    CfResult res = InitX509Certs(certsList, &certs);
    if (res != CF_SUCCESS) {
        LOGE("Failed to init certs, res = %{public}d.", res);
        return res;
    }
    res = ValidateCertChain(certs, certsList->count, certsList->format);
    if (res != CF_SUCCESS) {
        LOGE("Failed to validate cert chain, res = %{public}d.", res);
    }
    FreeX509Certs(&certs, certsList->count);
    return res;
}

static char *GetCertSubjectName(X509 *cert, char *buf, size_t bufLen)
{
    if (cert == NULL) {
        return NULL;
    }
    X509_NAME *subjectName = X509_get_subject_name(cert);
    if (subjectName == NULL) {
        return NULL;
    }
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }
    char *result = NULL;
    int ret = X509_NAME_print_ex(bio, subjectName, 0, XN_FLAG_SEP_COMMA_PLUS | ASN1_STRFLGS_UTF8_CONVERT);
    if (ret > 0) {
        long len = BIO_get_mem_data(bio, NULL);
        if (len > 0 && (size_t)len < bufLen) {
            ret = BIO_read(bio, buf, len);
            if (ret > 0) {
                buf[ret] = '\0';
                result = buf;
            }
        }
    }
    BIO_free(bio);
    return result;
}

static void AppendCertSubjectToErrorMsg(X509 *cert, CertVerifyResultInner *result)
{
    if (cert == NULL || result->errorMsg == NULL) {
        return;
    }

    char subjectNameBuf[MAX_SUBJECT_NAME_LEN] = {0};
    char *subjectName = GetCertSubjectName(cert, subjectNameBuf, sizeof(subjectNameBuf));
    if (subjectName == NULL) {
        return;
    }

    const char *subjectNamePrefix = " cert subject: ";
    if (strlen(subjectName) + strlen(result->errorMsg) + strlen(subjectNamePrefix) + 1 >= sizeof(result->errorMsgBuf)) {
        return;
    }

    (void)snprintf_s(result->errorMsgBuf, sizeof(result->errorMsgBuf),
        sizeof(result->errorMsgBuf) - 1, "%s%s%s", result->errorMsg, subjectNamePrefix, subjectName);
    result->errorMsg = result->errorMsgBuf;
}

static void CopyVerifyErrorMsg(const CertVerifyResultInner *inner, HcfVerifyCertResult *result)
{
    if (inner->errorMsg == NULL) {
        result->errorMsg = NULL;
        return;
    }
    /* Check if errorMsg points to inner->errorMsgBuf */
    if (inner->errorMsg >= inner->errorMsgBuf && 
        inner->errorMsg < inner->errorMsgBuf + sizeof(inner->errorMsgBuf)) {
        (void)memcpy_s(result->errorMsgBuf, sizeof(result->errorMsgBuf),
            inner->errorMsgBuf, sizeof(inner->errorMsgBuf));
        result->errorMsg = result->errorMsgBuf;
    } else {
        result->errorMsg = inner->errorMsg;
    }
}

static CfResult ReturnVerifyError(CfResult errorcode, const char *errorMsg, CertVerifyResultInner *result)
{
    LOGE("%{public}d, %{public}s", errorcode, errorMsg);
    result->errorMsg = errorMsg;
    return errorcode;
}

// static CfResult ReturnVerifyErrorWithCert(CfResult errorcode, X509 *cert, const char *baseMsg,
//     CertVerifyResultInner *result)
// {
//     if (result == NULL || baseMsg == NULL) {
//         return errorcode;
//     }
//     char subjectNameBuf[MAX_SUBJECT_NAME_LEN] = {0};
//     char *subjectName = GetCertSubjectName(cert, subjectNameBuf, sizeof(subjectNameBuf));
//     if (subjectName != NULL) {
//         (void)snprintf_s(result->errorMsgBuf, sizeof(result->errorMsgBuf),
//             sizeof(result->errorMsgBuf) - 1, "%s Certificate subject: %s", baseMsg, subjectName);
//         result->errorMsg = result->errorMsgBuf;
//     } else {
//         result->errorMsg = baseMsg;
//     }
//     LOGE("%{public}d, %{public}s", errorcode, result->errorMsg);
//     return errorcode;
// }

static CfResult ReturnVerifyOpensslError(CfResult errorcode, const char *errorMsg, CertVerifyResultInner *result)
{
    CfPrintOpensslError();
    return ReturnVerifyError(errorcode, errorMsg, result);
}

/* KeyUsage type to OpenSSL KU_* bit mapping table */
static const uint32_t KEYUSAGE_TO_OPENSSL_MAP[] = {
    KU_DIGITAL_SIGNATURE,   /* KEYUSAGE_DIGITAL_SIGNATURE = 0 */
    KU_NON_REPUDIATION,     /* KEYUSAGE_NON_REPUDIATION = 1 */
    KU_KEY_ENCIPHERMENT,    /* KEYUSAGE_KEY_ENCIPHERMENT = 2 */
    KU_DATA_ENCIPHERMENT,   /* KEYUSAGE_DATA_ENCIPHERMENT = 3 */
    KU_KEY_AGREEMENT,       /* KEYUSAGE_KEY_AGREEMENT = 4 */
    KU_KEY_CERT_SIGN,       /* KEYUSAGE_KEY_CERT_SIGN = 5 */
    KU_CRL_SIGN,            /* KEYUSAGE_CRL_SIGN = 6 */
    KU_ENCIPHER_ONLY,       /* KEYUSAGE_ENCIPHER_ONLY = 7 */
    KU_DECIPHER_ONLY,       /* KEYUSAGE_DECIPHER_ONLY = 8 */
};
#define KEYUSAGE_MAP_SIZE (sizeof(KEYUSAGE_TO_OPENSSL_MAP) / sizeof(KEYUSAGE_TO_OPENSSL_MAP[0]))

static CfResult CheckCertValidatorExtensions(X509 *x509, const HcfX509CertValidatorParams *params,
    CertVerifyResultInner *result)
{
    if (params->keyUsage.count > 0) {
        uint32_t keyUsage = X509_get_key_usage(x509);
        for (uint32_t i = 0; i < params->keyUsage.count; i++) {
            int32_t kuType = params->keyUsage.data[i];
            if (kuType < 0 || (uint32_t)kuType >= KEYUSAGE_MAP_SIZE) {
                return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "Invalid key usage type.", result);
            }
            uint32_t kuBit = KEYUSAGE_TO_OPENSSL_MAP[kuType];
            if (!(keyUsage & kuBit)) {
                return ReturnVerifyError(CF_ERR_CERT_KEY_USAGE_MISMATCH,
                    "The certificate key usage is not matched.", result);
            }
        }
    }

    if (params->hostnames.count > 0) {
        bool match = false;
        for (uint32_t i = 0; i < params->hostnames.count; i++) {
            if (X509_check_host(x509, params->hostnames.data[i], strlen(params->hostnames.data[i]), 0, NULL) == 1) {
                match = true;
                break;
            }
        }
        if (!match) {
            return ReturnVerifyError(CF_ERR_CERT_HOST_NAME_MISMATCH,
                "The certificate hostname is not matched.", result);
        }
    }

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
            return ReturnVerifyError(CF_ERR_CERT_EMAIL_MISMATCH,
                "The certificate email address is not matched.", result);
        }
    }

    return CF_SUCCESS;
}

static CfResult ConstructUntrustedStack(const HcfX509CertValidatorParams *params, STACK_OF(X509) **untrustedStack,
    CertVerifyResultInner *result)
{
    STACK_OF(X509) *tmpStack = sk_X509_new_null();
    if (tmpStack == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Call sk_X509_new_null failed.", result);
    }
    for (uint32_t i = 0; i < params->untrustedCerts.count; i++) {
        X509 *untrustedX509 = GetX509FromHcfX509Certificate((HcfCertificate *)params->untrustedCerts.data[i]);
        if (untrustedX509 == NULL) {
            sk_X509_pop_free(tmpStack, X509_free);
            return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "The x509Cert parameter is null.", result);
        }

        if (X509_up_ref(untrustedX509) != 1) {
            sk_X509_pop_free(tmpStack, X509_free);
            return ReturnVerifyOpensslError(CF_ERR_CRYPTO_OPERATION, "Call X509_up_ref failed.", result);
        }

        if (!sk_X509_push(tmpStack, untrustedX509)) {
            sk_X509_pop_free(tmpStack, X509_free);
            X509_free(untrustedX509);
            return ReturnVerifyOpensslError(CF_ERR_CRYPTO_OPERATION, "Call sk_X509_push failed.", result);
        }
    }
    *untrustedStack = tmpStack;
    return CF_SUCCESS;
}

static CfResult ConstructTrustedStore(const HcfX509CertValidatorParams *params, X509_STORE **store,
    CertVerifyResultInner *result)
{
    X509_STORE *storeTmp = X509_STORE_new();
    if (storeTmp == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_new failed.", result);
    }

    for (uint32_t i = 0; i < params->trustedCerts.count; i++) {
        X509 *cert = GetX509FromHcfX509Certificate((HcfCertificate *)params->trustedCerts.data[i]);
        if (cert == NULL) {
            X509_STORE_free(storeTmp);
            return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "The x509Cert parameter is null.", result);
        }
        if (X509_STORE_add_cert(storeTmp, cert) != 1) {
            X509_STORE_free(storeTmp);
            return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_add_cert failed.", result);
        }
    }

    if (params->trustSystemCa) {
        X509_STORE_load_locations(storeTmp, NULL, CERT_VERIFY_DIR);
    }
    *store = storeTmp;
    return CF_SUCCESS;
}

static CfResult ConvertTimeStrToTimeT(const char *timeStr, time_t *result, CertVerifyResultInner *resultInner) {
    struct tm tm;
    time_t ret = 0;
    ASN1_TIME *asn1_time = ASN1_TIME_new();
    if (asn1_time == NULL) {
        return ReturnVerifyOpensslError(CF_ERR_CRYPTO_OPERATION, "Call ASN1_TIME_new failed.", resultInner);
    }

    if (ASN1_TIME_set_string(asn1_time, timeStr) != 1) {
        ASN1_TIME_free(asn1_time);
        return ReturnVerifyOpensslError(CF_ERR_PARAMETER_CHECK, "Invalid time string.", resultInner);
    }

    if (ASN1_TIME_to_tm(asn1_time, &tm) != 1) {
        ASN1_TIME_free(asn1_time);
        return ReturnVerifyOpensslError(CF_ERR_CRYPTO_OPERATION, "Call ASN1_TIME_to_tm failed.", resultInner);
    }
    ASN1_TIME_free(asn1_time);

    ret = timegm(&tm);
    if (ret == -1) {
        LOGE("Call timegm failed, errno = %{public}d.", errno);
        return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "Call timegm failed.", resultInner);
    }
    *result = ret;
    return CF_SUCCESS;
}

static void FreeOpenSSLParams(HcfX509CertValidatorOpenSSLParams *opensslParams)
{
    if (opensslParams == NULL) {
        return;
    }
    /* Note: opensslParams->cert is obtained from GetX509FromHcfX509Certificate which doesn't increment
     * refcount. The original HcfX509Certificate owns this reference, so we should NOT free it here. */
    opensslParams->cert = NULL;
    if (opensslParams->store != NULL) {
        X509_STORE_free(opensslParams->store);
        opensslParams->store = NULL;
    }
    if (opensslParams->untrustedCertStack != NULL) {
        sk_X509_pop_free(opensslParams->untrustedCertStack, X509_free);
        opensslParams->untrustedCertStack = NULL;
    }
}

static bool HasRevocationFlag(const HcfX509CertRevokedParams *revo, int32_t flag);

static CfResult ParseOpenSSLParams(const HcfX509Certificate *x509Cert, const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    CfResult ret = CF_SUCCESS;

    /* Get X509 from HcfX509Certificate */
    opensslParams->cert = GetX509FromHcfX509Certificate((HcfCertificate *)x509Cert);
    if (opensslParams->cert == NULL) {
        return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "Failed to obtain the certificate to be verified.", result);
    }

    /* Construct trusted store */
    ret = ConstructTrustedStore(params, &opensslParams->store, result);
    if (ret != CF_SUCCESS) {
        LOGE("Failed to construct trusted store.");
        return ret;
    }

    /* Construct untrusted cert stack */
    ret = ConstructUntrustedStack(params, &opensslParams->untrustedCertStack, result);
    if (ret != CF_SUCCESS) {
        LOGE("Failed to construct untrusted stack.");
        return ret;
    }

    /* Parse date if needed */
    if (params->validateDate && params->date != NULL) {
        ret = ConvertTimeStrToTimeT(params->date, &opensslParams->date, result);
        if (ret != CF_SUCCESS) {
            LOGE("Failed to convert date string to time_t.");
            return ret;
        }
    }

    /* Parse revocation check flags if revokedParams exists */
    if (params->revokedParams != NULL) {
        opensslParams->crlCheck = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_CRL_CHECK);
        opensslParams->ocspCheck = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_OCSP_CHECK);
        opensslParams->preferOcsp = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_PREFER_OCSP);
        opensslParams->revocationCheckAll = HasRevocationFlag(params->revokedParams, CERT_REVOCATION_CHECK_ALL_CERT);
        
        if (!opensslParams->crlCheck && !opensslParams->ocspCheck) {
            return ReturnVerifyError(CF_ERR_PARAMETER_CHECK,
                "If enabling revocation checking CERT_REVOCATION_CRL_CHECK or CERT_REVOCATION_OCSP_CHECK must be set.",
                result);
        }
    }

    return CF_SUCCESS;
}

static CfResult DownloadAndAddIntermediateCert(X509 *lastCert, STACK_OF(X509) *untrustedStack,
    CertVerifyResultInner *result)
{
    AUTHORITY_INFO_ACCESS *infoAccess = X509_get_ext_d2i(lastCert, NID_info_access, NULL, NULL);
    if (infoAccess == NULL) {
        return ReturnVerifyError(CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "No AIA extension found in certificate.",
            result);
    }

    X509 *downloadedCert = NULL;
    CfResult res = CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    int num = sk_ACCESS_DESCRIPTION_num(infoAccess);
    if (num <= 0) {
        return ReturnVerifyError(CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, "No AIA extension found in certificate.",
            result);
    }
    uint32_t remainingCount = MAX_INFO_ACCESS_TRAVERSE_COUNT;
    for (int i = 0; i < num && remainingCount > 0; i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(infoAccess, i);
        res = TryDownloadFromSingleAia(ad, &remainingCount, &downloadedCert);
        if (res == CF_SUCCESS || res == CF_ERR_MALLOC) {
            break;
        }
    }
    AUTHORITY_INFO_ACCESS_free(infoAccess);
    if (res == CF_SUCCESS) {
        if (!sk_X509_push(untrustedStack, downloadedCert)) {
            X509_free(downloadedCert);
            return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to add downloaded cert to stack.", result);
        }
        return CF_SUCCESS;
    } else if (res == CF_ERR_MALLOC) {
        return ReturnVerifyError(CF_ERR_MALLOC, "Failed to malloc when downloaded cert.", result);
    } else {
        return ReturnVerifyError(res, "Failed to download intermediate certificate from AIA.", result);
    }
}

static CfResult ExecuteSingleVerification(HcfX509CertValidatorOpenSSLParams *opensslParams,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    X509_STORE_CTX *verifyCtx = X509_STORE_CTX_new();
    if (verifyCtx == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_CTX_new failed.", result);
    }

    if (X509_STORE_CTX_init(verifyCtx, opensslParams->store, opensslParams->cert,
        opensslParams->untrustedCertStack) != 1) {
        X509_STORE_CTX_free(verifyCtx);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_CTX_init failed.", result);
    }

    if (params->partialChain) {
        X509_STORE_CTX_set_flags(verifyCtx, X509_V_FLAG_PARTIAL_CHAIN);
    }

    if (params->validateDate == false) {
        X509_STORE_CTX_set_flags(verifyCtx, X509_V_FLAG_NO_CHECK_TIME);
    } else if (params->date != NULL) {
        X509_STORE_CTX_set_time(verifyCtx, 0, opensslParams->date);
    }

    if (X509_verify_cert(verifyCtx) == 1) {
        result->certChain = X509_STORE_CTX_get1_chain(verifyCtx);
        X509_STORE_CTX_free(verifyCtx);
        if (result->certChain == NULL) {
            return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Call X509_STORE_CTX_get1_chain failed.", result);
        }
        result->errorMsg = NULL;
        return CF_SUCCESS;
    }

    result->errCode = X509_STORE_CTX_get_error(verifyCtx);
    result->lastCert = X509_STORE_CTX_get_current_cert(verifyCtx);
    const char *opensslErrMsg = X509_verify_cert_error_string(result->errCode);
    result->errorMsg = opensslErrMsg;
    AppendCertSubjectToErrorMsg(result->lastCert, result);
    X509_STORE_CTX_free(verifyCtx);
    CfResult ret = ConvertOpensslErrorMsgEx(result->errCode);
    return ReturnVerifyError(ret, result->errorMsg, result);
}

static CfResult BuildAndVerifyCertChain(HcfX509CertValidatorOpenSSLParams *opensslParams,
    const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    uint32_t remainingCount = MAX_TOTAL_DOWNLOAD_CERT_COUNT;
    CfResult ret = CF_SUCCESS;
    while (remainingCount > 0) {
        ret = ExecuteSingleVerification(opensslParams, params, result);
        if (ret == CF_SUCCESS) {
            return CF_SUCCESS;
        }

        if (ret != CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
            return ret;
        }

        if (result->lastCert == NULL) {
            return ret;
        }

        if (!params->allowDownloadIntermediateCa) {
            return ret;
        }

        remainingCount--;
        ret = DownloadAndAddIntermediateCert(result->lastCert, opensslParams->untrustedCertStack, result);
        if (ret != CF_SUCCESS) {
            AppendCertSubjectToErrorMsg(result->lastCert, result);
            return ret;
        }
    }
    return ret;
}

static bool HasRevocationFlag(const HcfX509CertRevokedParams *revo, int32_t flag)
{
    if (revo == NULL) {
        return false;
    }
    for (uint32_t i = 0; i < revo->revocationFlags.count; i++) {
        if (revo->revocationFlags.data[i] == flag) {
            return true;
        }
    }
    return false;
}

static const EVP_MD *GetOcspDigestByType(int32_t digestType)
{
    switch (digestType) {
        case OCSP_DIGEST_SHA1:
            return EVP_sha1();
        case OCSP_DIGEST_SHA224:
            return EVP_sha224();
        case OCSP_DIGEST_SHA384:
            return EVP_sha384();
        case OCSP_DIGEST_SHA512:
            return EVP_sha512();
        case OCSP_DIGEST_SHA256:
        default:
            return EVP_sha256();
    }
}

static bool IsValidHttpUrl(const char *url)
{
    if (url == NULL) {
        return false;
    }
    // Only allow http:// or https://
    if (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0) {
        return true;
    }
    return false;
}

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
        if (dp == NULL || dp->distpoint == NULL || dp->distpoint->type != 0) {
            continue;
        }

        STACK_OF(GENERAL_NAME) *names = dp->distpoint->name.fullname;
        if (names == NULL) {
            continue;
        }
        
        int nameCount = sk_GENERAL_NAME_num(names);
        for (int j = 0; j < nameCount && crl == NULL && remainingCount > 0; j++) {
            GENERAL_NAME *genName = sk_GENERAL_NAME_value(names, j);
            if (genName == NULL || genName->type != GEN_URI) {
                continue;
            }
            
            ASN1_IA5STRING *uri = genName->d.uniformResourceIdentifier;
            if (uri == NULL || uri->data == NULL) {
                continue;
            }

            char *url = (char *)uri->data;
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
            unsigned long err = ERR_peek_error();
            int reason = ERR_GET_REASON(err);
            LOGW("Failed to download CRL from: %s, reason=%d", url, reason);
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

static CfResult CheckCertRevocation(CertVerifyResultInner *result,
    const HcfX509CertValidatorParams *params, HcfX509CertValidatorOpenSSLParams *opensslParams);

static CfResult AddCrlsToStore(X509_STORE *store, const HcfX509CertRevokedParams *revokedParams,
    CertVerifyResultInner *result)
{
    for (uint32_t i = 0; i < revokedParams->crls.count; i++) {
        HcfX509Crl *x509Crl = revokedParams->crls.data[i];
        if (x509Crl == NULL) {
            continue;
        }
        X509_CRL *crl = GetX509CrlFromHcfX509Crl(x509Crl);
        if (crl == NULL) {
            return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "Failed to parse CRL.", result);
        }
        if (X509_STORE_add_crl(store, crl) != 1) {
            return ReturnVerifyOpensslError(CF_ERR_CRYPTO_OPERATION, "Failed to add CRL to store.", result);
        }
    }
    return CF_SUCCESS;
}

static CfResult AddCertChainToStore(X509_STORE *store, STACK_OF(X509) *certChain,
    CertVerifyResultInner *result)
{
    int chainLen = sk_X509_num(certChain);
    for (int i = 0; i < chainLen; i++) {
        X509 *chainCert = sk_X509_value(certChain, i);
        if (chainCert == NULL) {
            continue;
        }
        if (X509_STORE_add_cert(store, chainCert) != 1) {
            unsigned long err = ERR_peek_error();
            if (ERR_GET_REASON(err) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                return ReturnVerifyOpensslError(CF_ERR_CRYPTO_OPERATION, "Failed to add cert to store.", result);
            }
            ERR_clear_error();  // Clear the "cert already in hash table" error
        }
    }
    return CF_SUCCESS;
}

static CfResult PerformRevocationCheck(CertVerifyResultInner *result, const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams)
{
    HcfX509CertRevokedParams *revokedParams = params->revokedParams;

    CfResult res = AddCrlsToStore(opensslParams->store, revokedParams, result);
    if (res != CF_SUCCESS) {
        return res;
    }
    res = AddCertChainToStore(opensslParams->store, result->certChain, result);
    if (res != CF_SUCCESS) {
        return res;
    }

    return CheckCertRevocation(result, params, opensslParams);
}

static CfResult MapCrlErrorToResult(int err, X509 *cert, CertVerifyResultInner *result)
{
    result->errCode = err;
    switch (err) {
        case X509_V_ERR_UNABLE_TO_GET_CRL:
            return ReturnVerifyError(CF_ERR_CRL_NOT_FOUND, "Unable to get CRL.", result);
        case X509_V_ERR_CRL_HAS_EXPIRED:
            return ReturnVerifyError(CF_ERR_CRL_HAS_EXPIRED, "CRL has expired.", result);
        case X509_V_ERR_CRL_NOT_YET_VALID:
            return ReturnVerifyError(CF_ERR_CRL_NOT_YET_VALID, "CRL not yet valid.", result);
        case X509_V_ERR_CRL_SIGNATURE_FAILURE:
            return ReturnVerifyError(CF_ERR_CRL_SIGNATURE_FAILURE, "CRL signature verification failed.", result);
        case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
            return ReturnVerifyError(CF_ERR_UNABLE_TO_GET_CRL_ISSUER, "Unable to get CRL issuer certificate.", result);
        case X509_V_ERR_CERT_REVOKED:
            return ReturnVerifyError(CF_ERR_CERT_REVOKED, "Certificate is revoked by CRL.", result);
        default:
            result->errorMsg = X509_verify_cert_error_string(err);
            return ConvertOpensslErrorMsgEx(err);
    }
}

static CfResult HandleCrlNotFound(X509 *cert, X509_STORE_CTX *ctx,
    const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    X509_CRL *downloadedCrl = NULL;
    CfResult ret = DownloadCrlFromCdp(cert, &downloadedCrl, result);
    if (ret != CF_SUCCESS) {
        return ret;
    }
    
    if (X509_STORE_add_crl(opensslParams->store, downloadedCrl) != 1) {
        X509_CRL_free(downloadedCrl);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to add downloaded CRL to store.", result);
    }
    X509_CRL_free(downloadedCrl);
    
    X509_STORE_CTX_cleanup(ctx);
    if (X509_STORE_CTX_init(ctx, opensslParams->store, cert, NULL) != 1) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to re-init X509_STORE_CTX.", result);
    }

    // Set CRL check flags on ctx
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_PARTIAL_CHAIN);

    if (params->validateDate == false) {
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_NO_CHECK_TIME);
    } else if (params->date != NULL) {
        X509_STORE_CTX_set_time(ctx, 0, opensslParams->date);
    }

    if (X509_verify_cert(ctx) == 1) {
        return CF_SUCCESS;
    }

    int err = X509_STORE_CTX_get_error(ctx);
    return MapCrlErrorToResult(err, cert, result);
}

static CfResult CheckSingleCertByCrl(X509 *cert, const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    HcfX509CertRevokedParams *revo = params->revokedParams;
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create X509_STORE_CTX.", result);
    }
    
    if (X509_STORE_CTX_init(ctx, opensslParams->store, cert, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to init X509_STORE_CTX.", result);
    }

    // Set CRL check flags on ctx, not on store (store may be used by OCSP)
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_PARTIAL_CHAIN);

    if (params->validateDate == false) {
        X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_NO_CHECK_TIME);
    } else if (params->date != NULL) {
        X509_STORE_CTX_set_time(ctx, 0, opensslParams->date);
    }

    if (X509_verify_cert(ctx) == 1) {
        X509_STORE_CTX_free(ctx);
        return CF_SUCCESS;
    }

    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_UNABLE_TO_GET_CRL && revo->allowDownloadCrl) {
        CfResult res = HandleCrlNotFound(cert, ctx, params, opensslParams, result);
        X509_STORE_CTX_free(ctx);
        return res;
    } else {
        X509_STORE_CTX_free(ctx);
        return MapCrlErrorToResult(err, cert, result);
    }
}

static CfResult GetOcspStatusResult(int status, X509 *cert, CertVerifyResultInner *result)
{
    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            return CF_SUCCESS;
        case V_OCSP_CERTSTATUS_REVOKED:
            return ReturnVerifyError(CF_ERR_CERT_REVOKED, "Certificate is revoked by OCSP.", result);
        case V_OCSP_CERTSTATUS_UNKNOWN:
            return ReturnVerifyError(CF_ERR_OCSP_CERT_STATUS_UNKNOWN,
                "OCSP certificate status unknown.", result);
        default:
            LOGD("OCSP certificate status: %d", status);
            return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "OCSP certificate status unknown.", result);
    }
}

static CfResult VerifyLocalOcspResponse(X509 *cert, X509 *issuer,
    OCSP_BASICRESP *bs,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    int status = V_OCSP_CERTSTATUS_UNKNOWN;
    ASN1_GENERALIZEDTIME *thisUpdate = NULL;
    ASN1_GENERALIZEDTIME *nextUpdate = NULL;
    bool found = false;
    
    int respCount = OCSP_resp_count(bs);
    for (int i = 0; i < respCount && !found; i++) {
        OCSP_SINGLERESP *singleResp = OCSP_resp_get0(bs, i);
        if (singleResp == NULL) {
            continue;
        }
        
        const OCSP_CERTID *respCertId = OCSP_SINGLERESP_get0_id(singleResp);
        if (respCertId == NULL) {
            continue;
        }
        
        ASN1_OBJECT *hashAlg = NULL;
        OCSP_id_get0_info(NULL, &hashAlg, NULL, NULL, (OCSP_CERTID *)respCertId);
        if (hashAlg == NULL) {
            continue;
        }
        
        const EVP_MD *respMd = EVP_get_digestbyobj(hashAlg);
        if (respMd == NULL) {
            continue;
        }
        
        OCSP_CERTID *certId = OCSP_cert_to_id(respMd, cert, issuer);
        if (certId == NULL) {
            return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP_CERTID.", result);
        }
        
        if (OCSP_id_cmp(certId, respCertId) == 0) {
            int reason;
            status = OCSP_single_get0_status(singleResp, &reason, NULL, &thisUpdate, &nextUpdate);
            if (status >= 0) {
                found = true;
            }
        }
        OCSP_CERTID_free(certId);
    }
    
    if (!found) {
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response not found for certificate.", result);
    }
    
    if (OCSP_check_validity(thisUpdate, nextUpdate, 0, -1) != 1) {
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_INVALID, "OCSP response has expired.", result);
    }
    
    if (OCSP_basic_verify(bs, result->certChain, opensslParams->store, 0) != 1) {
        return ReturnVerifyError(CF_ERR_OCSP_SIGNATURE_FAILURE,
            "OCSP signature verification failed or cert verification failed.", result);
    }

    return GetOcspStatusResult(status, cert, result);
}

static CfResult VerifyOcspResponseForCert(X509 *cert, X509 *issuer,
    CfBlob *ocspResponseData,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    const unsigned char *p = ocspResponseData->data;
    OCSP_RESPONSE *resp = d2i_OCSP_RESPONSE(NULL, &p, ocspResponseData->size);
    if (resp == NULL) {
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_INVALID, "Failed to parse OCSP response.", result);
    }
    
    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        OCSP_RESPONSE_free(resp);
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_INVALID, "OCSP response status is not successful.", result);
    }
    
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
    OCSP_RESPONSE_free(resp);
    if (bs == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to get basic OCSP response.", result);
    }
    
    CfResult res = VerifyLocalOcspResponse(cert, issuer, bs, opensslParams, result);
    
    OCSP_BASICRESP_free(bs);
    return res;
}

static CfResult VerifyOnlineOcspResponse(OCSP_RESPONSE *resp, OCSP_CERTID *certId, X509 *cert,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    int status = OCSP_response_status(resp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        LOGD("OCSP response status is %d", status);
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response status is not successful.", result);
    }
    
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
    if (bs == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to get basic OCSP response.", result);
    }
    
    ASN1_GENERALIZEDTIME *thisUpdate = NULL;
    ASN1_GENERALIZEDTIME *nextUpdate = NULL;
    
    if (OCSP_resp_find_status(bs, certId, &status, NULL, NULL, &thisUpdate, &nextUpdate) != 1) {
        OCSP_BASICRESP_free(bs);
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND,
            "OCSP response not found for certificate.", result);
    }
    
    if (OCSP_check_validity(thisUpdate, nextUpdate, 0, -1) != 1) {
        OCSP_BASICRESP_free(bs);
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_INVALID, "OCSP response has expired.", result);
    }
    
    if (OCSP_basic_verify(bs, result->certChain, opensslParams->store, 0) != 1) {
        OCSP_BASICRESP_free(bs);
        return ReturnVerifyError(CF_ERR_OCSP_SIGNATURE_FAILURE,
            "OCSP signature verification failed or cert verification failed.", result);
    }
    
    OCSP_BASICRESP_free(bs);

    return GetOcspStatusResult(status, cert, result);
}

static BIO *CreateConnectBio(const char *host, const char *port, int *errReason)
{
    BIO *bio = BIO_new_connect(host);
    if (bio == NULL) {
        *errReason = ERR_GET_REASON(ERR_peek_last_error());
        return NULL;
    }
    BIO_set_conn_port(bio, port);
    int ret = BIO_do_connect_retry(bio, OCSP_REQUEST_TIMEOUT_SECONDS, 0);
    if (ret != 1) {
        *errReason = ERR_GET_REASON(ERR_peek_last_error());
        BIO_free(bio);
        return NULL;
    }
    return bio;
}

static CfResult CreateOcspRequest(X509 *cert, X509 *issuer,
    const HcfX509CertRevokedParams *revo, CertVerifyResultInner *result, OCSP_REQUEST **reqOut)
{
    const EVP_MD *md = GetOcspDigestByType(revo->ocspDigest);
    *reqOut = OCSP_REQUEST_new();
    if (*reqOut == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP request.", result);
    }

    OCSP_CERTID *certId = OCSP_cert_to_id(md, cert, issuer);
    if (certId == NULL) {
        OCSP_REQUEST_free(*reqOut);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP cert ID.", result);
    }

    if (OCSP_request_add0_id(*reqOut, certId) == NULL) {
        OCSP_REQUEST_free(*reqOut);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to add cert ID to OCSP request.", result);
    }

    OCSP_request_add1_nonce(*reqOut, NULL, -1);
    return CF_SUCCESS;
}

static inline void FreeConnectInfo(char *host, char *port, char *path)
{
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
}

static CfResult SendOcspRequestWithTimeout(BIO *bio, const char *path, OCSP_REQUEST *req,
    OCSP_RESPONSE **respOut, CertVerifyResultInner *result)
{
    OSSL_HTTP_REQ_CTX *ctx = OCSP_sendreq_new(bio, path, req, -1);
    if (ctx == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create OCSP request context.", result);
    }

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
        LOGW("OCSP request timeout, reason=%d", reason);
        return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "OCSP request timeout.", result);
    }
    return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response not found.", result);
}

typedef struct {
    OCSP_REQUEST *req;
    OCSP_CERTID *certId;
    X509 *cert;
    int *remainingCount;
} OcspCheckContext;

static CfResult TrySingleOcspUrl(const char *url, OcspCheckContext *ctx,
    const HcfX509CertValidatorOpenSSLParams *opensslParams, CertVerifyResultInner *result)
{
    char *host = NULL, *port = NULL, *path = NULL;
    int use_ssl = 0;

    if (OCSP_parse_url(url, &host, &port, &path, &use_ssl) != 1) {
        LOGW("Failed to parse OCSP URL: %s", url);
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "Failed to parse OCSP URL.", result);
    }

    (*ctx->remainingCount)--;
    int errReason = 0;
    BIO *bio = CreateConnectBio(host, port, &errReason);
    if (bio == NULL) {
        if (errReason == BIO_R_CONNECT_TIMEOUT || errReason == BIO_R_TRANSFER_TIMEOUT) {
            LOGW("OCSP connection timeout: %s:%s, reason=%d", host, port, errReason);
            FreeConnectInfo(host, port, path);
            return ReturnVerifyError(CF_ERR_NETWORK_TIMEOUT, "OCSP connection timeout.", result);
        } else if (errReason == ERR_R_MALLOC_FAILURE) {
            FreeConnectInfo(host, port, path);
            return ReturnVerifyError(CF_ERR_MALLOC, "Failed to connect to OCSP server.", result);
        }
        LOGW("Failed to connect to OCSP server: %s:%s, reason=%d", host, port, errReason);
        FreeConnectInfo(host, port, path);
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "Failed to connect to OCSP server.", result);
    }

    OCSP_RESPONSE *resp = NULL;
    CfResult sendRes = SendOcspRequestWithTimeout(bio, path, ctx->req, &resp, result);
    BIO_free(bio);
    FreeConnectInfo(host, port, path);

    if (sendRes != CF_SUCCESS) {
        return sendRes;
    }

    CfResult res = VerifyOnlineOcspResponse(resp, ctx->certId, ctx->cert, opensslParams, result);
    OCSP_RESPONSE_free(resp);
    return res;
}

static CfResult PerformOnlineOcspCheck(X509 *cert, X509 *issuer,
    const HcfX509CertValidatorParams *params,
    const HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    STACK_OF(OPENSSL_STRING) *ocspUrls = X509_get1_ocsp(cert);
    if (ocspUrls == NULL || sk_OPENSSL_STRING_num(ocspUrls) == 0) {
        X509_email_free(ocspUrls);
        return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "No OCSP URL found in certificate.", result);
    }

    OCSP_REQUEST *req = NULL;
    CfResult res = CreateOcspRequest(cert, issuer, params->revokedParams, result, &req);
    if (res != CF_SUCCESS) {
        X509_email_free(ocspUrls);
        return res;
    }

    OCSP_ONEREQ *oneReq = OCSP_request_onereq_get0(req, 0);
    if (oneReq == NULL) {
        OCSP_REQUEST_free(req);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to get OCSP onereq.", result);
    }

    OCSP_CERTID *certId = OCSP_CERTID_dup(OCSP_onereq_get0_id(oneReq));
    if (certId == NULL) {
        OCSP_REQUEST_free(req);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to duplicate OCSP cert ID.", result);
    }

    int remainingCount = MAX_TOTAL_DOWNLOAD_COUNT;
    OcspCheckContext ctx = { req, certId, cert, &remainingCount };
    res = CF_ERR_OCSP_RESPONSE_NOT_FOUND;
    for (int i = 0; i < sk_OPENSSL_STRING_num(ocspUrls) && remainingCount > 0; i++) {
        res = TrySingleOcspUrl(sk_OPENSSL_STRING_value(ocspUrls, i), &ctx, opensslParams, result);
        if (res != CF_ERR_OCSP_RESPONSE_NOT_FOUND && res != CF_ERR_NETWORK_TIMEOUT) {
            break;
        }
    }
    OCSP_CERTID_free(certId);
    OCSP_REQUEST_free(req);
    X509_email_free(ocspUrls);
    return res;
}

static CfResult GetIssuerFromStore(X509 *cert, X509_STORE *store,
    X509 **issuer, CertVerifyResultInner *result)
{
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to create X509_STORE_CTX.", result);
    }
    
    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        return ReturnVerifyError(CF_ERR_CRYPTO_OPERATION, "Failed to init X509_STORE_CTX.", result);
    }
    
    // Get issuer from store
    int ret = X509_STORE_CTX_get1_issuer(issuer, ctx, cert);
    X509_STORE_CTX_free(ctx);
    
    if (ret != 1 || *issuer == NULL) {
        return ReturnVerifyError(CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
            "Failed to get issuer from store when checking OCSP.", result);
    }
    
    return CF_SUCCESS;
}

static CfResult CheckSingleCertByOcsp(X509 *cert,
    const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    X509 *issuer = opensslParams->issuer;
    bool issuerFromStore = false;
    
    // If issuer not found in certChain, try to get from store
    if (issuer == NULL) {
        CfResult ret = GetIssuerFromStore(cert, opensslParams->store, &issuer, result);
        if (ret != CF_SUCCESS) {
            return ret;
        }
        issuerFromStore = true;
    }
    
    const HcfX509CertRevokedParams *revo = params->revokedParams;
    // Step 1: Check local OCSP responses
    if (revo->ocspResponses.count > 0) {
        for (uint32_t i = 0; i < revo->ocspResponses.count; i++) {
            CfResult ret = VerifyOcspResponseForCert(cert, issuer,
                &revo->ocspResponses.data[i], opensslParams, result);
            
            // Only CF_ERR_OCSP_RESPONSE_NOT_FOUND means try next response,
            // all other results are definitive and should return immediately.
            if (ret != CF_ERR_OCSP_RESPONSE_NOT_FOUND) {
                if (issuerFromStore) {
                    X509_free(issuer);
                }
                return ret;
            }
        }
    }
    
    // Step 2: Try online OCSP check if allowed
    if (revo->allowOcspCheckOnline) {
        CfResult res = PerformOnlineOcspCheck(cert, issuer, params, opensslParams, result);
        if (issuerFromStore) {
            X509_free(issuer);
        }
        return res;
    }
    
    // Step 3: No OCSP response available
    if (issuerFromStore) {
        X509_free(issuer);
    }
    return ReturnVerifyError(CF_ERR_OCSP_RESPONSE_NOT_FOUND, "OCSP response not found.", result);
}

static CfResult CheckSingleCertRevocation(X509 *cert,
    const HcfX509CertValidatorParams *params,
    HcfX509CertValidatorOpenSSLParams *opensslParams,
    CertVerifyResultInner *result)
{
    CfResult res;
    
    // Case 1: Both CRL and OCSP enabled
    if (opensslParams->crlCheck && opensslParams->ocspCheck) {
        if (opensslParams->preferOcsp) {
            res = CheckSingleCertByOcsp(cert, params, opensslParams, result);
            if (res == CF_ERR_OCSP_RESPONSE_NOT_FOUND || res == CF_ERR_NETWORK_TIMEOUT) {
                res = CheckSingleCertByCrl(cert, params, opensslParams, result);
            }
        } else {
            res = CheckSingleCertByCrl(cert, params, opensslParams, result);
            if (res == CF_ERR_CRL_NOT_FOUND) {
                res = CheckSingleCertByOcsp(cert, params, opensslParams, result);
            }
        }
        return res;
    }
    
    // Case 2: OCSP only
    if (opensslParams->ocspCheck) {
        return CheckSingleCertByOcsp(cert, params, opensslParams, result);
    }
    
    // Case 3: CRL only
    if (opensslParams->crlCheck) {
        return CheckSingleCertByCrl(cert, params, opensslParams, result);
    }
    
    return CF_SUCCESS;
}

static CfResult CheckCertRevocation(CertVerifyResultInner *result,
    const HcfX509CertValidatorParams *params, HcfX509CertValidatorOpenSSLParams *opensslParams)
{   
    int chainLen = sk_X509_num(result->certChain);
    int checkCount = opensslParams->revocationCheckAll ? chainLen : 1;
    
    for (int i = 0; i < checkCount; i++) {
        X509 *cert = sk_X509_value(result->certChain, i);
        
        if (X509_self_signed(cert, 0)) {
            continue;
        }

        // Set issuer from certChain
        opensslParams->issuer = (i + 1 < chainLen) ? sk_X509_value(result->certChain, i + 1) : NULL;

        CfResult res = CheckSingleCertRevocation(cert, params, opensslParams, result);
        if (res != CF_SUCCESS) {
            AppendCertSubjectToErrorMsg(cert, result);
            return res;
        }
    }

    return CF_SUCCESS;
}

static CfResult CheckCertValidatorParams(const HcfX509CertValidatorParams *params, CertVerifyResultInner *result)
{
    if (params == NULL) {
        return ReturnVerifyError(CF_ERR_PARAMETER_CHECK,
            "The HcfX509CertValidatorParams parameter is null.", result);
    }

    if (params->trustedCerts.count == 0 && params->trustSystemCa == false) {
        return ReturnVerifyError(CF_ERR_PARAMETER_CHECK,
            "Must set trustedCerts, or set trustSystemCa to true.", result);
    }

    if (params->keyUsage.count > KEYUSAGE_MAP_SIZE) {
        return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "The number of keyUsage cannot exceed 9.", result);
    }

    if (params->emailAddresses.count > 1) {
        return ReturnVerifyError(CF_ERR_PARAMETER_CHECK, "The number of emailAddresse cannot exceed 1.", result);
    }

    if (params->revokedParams != NULL) {
        if (params->revokedParams->revocationFlags.count == 0 ||
            params->revokedParams->revocationFlags.count > MAX_REVOCATION_FLAGS_COUNT) {
            return ReturnVerifyError(CF_ERR_PARAMETER_CHECK,
                "If enabling revocation checking, the length of revocationFlags must be in [1, 4].", result);
        }
    }

    if (params->revokedParams != NULL) {
        if (params->revokedParams->ocspDigest < OCSP_DIGEST_SHA1 ||
            params->revokedParams->ocspDigest > OCSP_DIGEST_SHA512) {
            return ReturnVerifyError(CF_ERR_PARAMETER_CHECK,
                "The ocspDigest must be within the scope of OcspDigest enumeration.", result);
        }
    }

    return CF_SUCCESS;
}

static CfResult FillVerifyCertResult(STACK_OF(X509) *verifiedChain, HcfVerifyCertResult *result)
{
    if (verifiedChain == NULL || sk_X509_num(verifiedChain) == 0) {
        LOGE("Invalid verified chain.");
        result->errorMsg = "Invalid verified chain.";
        return CF_ERR_CRYPTO_OPERATION;
    }

    uint32_t chainSize = sk_X509_num(verifiedChain);

    result->certs.data = (HcfX509Certificate **)CfMallocEx(sizeof(HcfX509Certificate *) * chainSize);
    if (result->certs.data == NULL) {
        LOGE("Failed to allocate memory for certs data.");
        result->errorMsg = "Failed to allocate memory for certs data.";
        return CF_ERR_MALLOC;
    }
    result->certs.count = 0;

    for (uint32_t i = 0; i < chainSize; i++) {
        X509 *vX509 = sk_X509_value(verifiedChain, i);
        HcfX509Certificate *hcfCert = NULL;
        CfResult ret = X509ToHcfX509Certificate(vX509, &hcfCert);
        if (ret != CF_SUCCESS) { // In theory, this should never fail, except in the case of insufficient memory.
            LOGE("Failed to convert x509 certificate to hcf certificate.");
            for (uint32_t j = 0; j < result->certs.count; j++) {
                CfObjDestroy(result->certs.data[j]);
            }
            CfFree(result->certs.data);
            result->certs.data = NULL;
            result->errorMsg = "Failed to convert x509 certificate to hcf certificate.";
            return ret;
        }
        result->certs.data[result->certs.count] = hcfCert;
        result->certs.count++;
    }
    return CF_SUCCESS;
}

static CfResult ValidateX509Cert(HcfCertChainValidatorSpi *self, HcfX509Certificate *x509Cert,
    const HcfX509CertValidatorParams *params, HcfVerifyCertResult *result)
{
    if (self == NULL) {
        LOGE("The HcfCertChainValidatorSpi parameter is null.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (result == NULL) {
        LOGE("The result parameter is null.");
        return CF_ERR_PARAMETER_CHECK;
    }
    if (x509Cert == NULL) {
        LOGE("The x509Cert parameter is null.");
        result->errorMsg = "The x509Cert parameter is null.";
        return CF_ERR_PARAMETER_CHECK;
    }
    if (result->certs.count != 0 || result->certs.data != NULL) {
        LOGE("The result parameter already contains data.");
        result->errorMsg = "The result parameter already contains data.";
        return CF_ERR_PARAMETER_CHECK;
    }

    CertVerifyResultInner resultInner = { 0 };
    CfResult res = CheckCertValidatorParams(params, &resultInner);
    if (res != CF_SUCCESS) {
        CopyVerifyErrorMsg(&resultInner, result);
        return res;
    }

    /* Parse all OpenSSL params including the cert to be verified */
    HcfX509CertValidatorOpenSSLParams opensslParams = {};
    res = ParseOpenSSLParams(x509Cert, params, &opensslParams, &resultInner);
    if (res != CF_SUCCESS) {
        CopyVerifyErrorMsg(&resultInner, result);
        FreeOpenSSLParams(&opensslParams);
        return res;
    }

    /* Check certificate extensions */
    res = CheckCertValidatorExtensions(opensslParams.cert, params, &resultInner);
    if (res != CF_SUCCESS) {
        CopyVerifyErrorMsg(&resultInner, result);
        FreeOpenSSLParams(&opensslParams);
        return res;
    }

    res = BuildAndVerifyCertChain(&opensslParams, params, &resultInner);

    if (res == CF_SUCCESS && params->revokedParams != NULL) {
        res = PerformRevocationCheck(&resultInner, params, &opensslParams);
    }

    FreeOpenSSLParams(&opensslParams);

    if (res == CF_SUCCESS) {
        res = FillVerifyCertResult(resultInner.certChain, result);
    } else {
        CopyVerifyErrorMsg(&resultInner, result);
    }

    if (resultInner.certChain != NULL) {
        sk_X509_pop_free(resultInner.certChain, X509_free);
    }
    return res;
}

CfResult HcfCertChainValidatorSpiCreate(HcfCertChainValidatorSpi **spi)
{
    if (spi == NULL) {
        LOGE("Invalid params, spi is null!");
        return CF_INVALID_PARAMS;
    }
    HcfCertChainValidatorSpi *validator = (HcfCertChainValidatorSpi *)CfMalloc(sizeof(HcfCertChainValidatorSpi), 0);
    if (validator == NULL) {
        LOGE("Failed to allocate certChain validator spi object memory!");
        return CF_ERR_MALLOC;
    }
    validator->base.getClass = GetX509CertChainValidatorClass;
    validator->base.destroy = DestroyX509CertChainValidator;
    validator->engineValidate = Validate;
    validator->engineValidateX509Cert = ValidateX509Cert;

    *spi = validator;
    return CF_SUCCESS;
}