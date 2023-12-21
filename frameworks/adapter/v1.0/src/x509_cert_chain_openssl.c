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

#include "x509_cert_chain_openssl.h"

#include <securec.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "cf_blob.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "config.h"
#include "utils.h"
#include "fwk_class.h"
#include "certificate_openssl_common.h"
#include "certificate_openssl_class.h"
#include "x509_cert_chain_spi.h"
#include "cert_crl_common.h"

#define X509_CERT_CHAIN_OPENSSL_CLASS "X509CertChainOpensslClass"
#define MAX_CERT_NUM 256     /* max certs number of a certchain */
#define TIMET_NUM 6
#define TIMET_YEAR_START 1900
#define TIMET_YEAR_OFFSET 100 // start time year from 1900 + 100

typedef struct {
    HcfX509CertChainSpi base;
    STACK_OF(X509) * x509CertChain;
} HcfX509CertChainOpensslImpl;

// helper functions
typedef struct {
    int32_t errCode;
    CfResult result;
} OpensslErrorToResult;

static const OpensslErrorToResult ERROR_TO_RESULT_MAP[] = {
    { X509_V_OK, CF_SUCCESS },
    { X509_V_ERR_CERT_SIGNATURE_FAILURE, CF_ERR_CERT_SIGNATURE_FAILURE },
    { X509_V_ERR_CERT_NOT_YET_VALID, CF_ERR_CERT_NOT_YET_VALID },
    { X509_V_ERR_CERT_HAS_EXPIRED, CF_ERR_CERT_HAS_EXPIRED },
    { X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY },
    { X509_V_ERR_KEYUSAGE_NO_CERTSIGN, CF_ERR_KEYUSAGE_NO_CERTSIGN },
    { X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE, CF_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE },
};

static CfResult ConvertOpensslErrorMsg(int32_t errCode)
{
    for (uint32_t i = 0; i < sizeof(ERROR_TO_RESULT_MAP) / sizeof(OpensslErrorToResult); ++i) {
        if (ERROR_TO_RESULT_MAP[i].errCode == errCode) {
            return ERROR_TO_RESULT_MAP[i].result;
        }
    }
    return CF_ERR_CRYPTO_OPERATION;
}

static bool CheckIsSelfSigned(const X509 *cert)
{
    bool ret = false;
    X509_NAME *issuer = X509_get_issuer_name(cert);
    X509_NAME *subject = X509_get_subject_name(cert);
    ret = (X509_NAME_cmp(issuer, subject) == 0);
    LOGI("CheckIsSelfSigned() ret: %d .", ret);

    return ret;
}
// helper functions end

static const char *GetX509CertChainClass(void)
{
    return X509_CERT_CHAIN_OPENSSL_CLASS;
}

static void DestroyX509CertChain(CfObjectBase *self)
{
    if (self == NULL || !IsClassMatch(self, GetX509CertChainClass())) {
        LOGE("Invalid params!");
        return;
    }
    HcfX509CertChainOpensslImpl *impl = (HcfX509CertChainOpensslImpl *)self;
    if (impl->x509CertChain != NULL) {
        sk_X509_pop_free(impl->x509CertChain, X509_free);
        impl->x509CertChain = NULL;
    }

    CfFree(impl);
}

static CfResult X509ToHcfX509Certificate(X509 *cert, HcfX509Certificate **returnObj)
{
    if (cert == NULL) {
        LOGE("X509ToHcfX509Certificate() failed !");
        return CF_INVALID_PARAMS;
    }

    int dataLength = 0;
    uint8_t *certData = GetX509EncodedDataStream(cert, &dataLength);
    if (certData == NULL) {
        LOGE("Falied to get certificate data!");
        return CF_ERR_CRYPTO_OPERATION;
    }

    HcfX509Certificate *x509cert = NULL;
    CfEncodingBlob encodingBlob = { certData, dataLength, CF_FORMAT_DER };
    CfResult res = HcfX509CertificateCreate(&encodingBlob, &x509cert);
    if (res != CF_SUCCESS) {
        LOGE("HcfX509CertificateCreate fail, res : %d!", res);
        CfFree(certData);
        return CF_ERR_MALLOC;
    }

    *returnObj = x509cert;
    CfFree(certData);
    return res;
}

static CfResult GetCertlist(HcfX509CertChainSpi *self, HcfX509CertificateArray *certsList)
{
    if ((self == NULL) || (certsList == NULL)) {
        LOGE("[GetCertlist openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
        LOGE("[GetCertlist openssl] Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    CfResult res = CF_SUCCESS;
    HcfX509CertChainOpensslImpl *certChain = (HcfX509CertChainOpensslImpl *)self;
    STACK_OF(X509) *x509CertChain = certChain->x509CertChain;

    int32_t certsNum = sk_X509_num(x509CertChain);
    /* the list count has checked when create cert chain */
    certsList->data = (HcfX509Certificate **)HcfMalloc(certsNum * sizeof(HcfX509Certificate *), 0);
    if (certsList->data == NULL) {
        LOGE("malloc failed");
        return CF_ERR_MALLOC;
    }

    certsList->count = certsNum;
    for (int32_t i = 0; i < certsNum; ++i) {
        X509 *cert = sk_X509_value(x509CertChain, i);
        HcfX509Certificate *x509Cert = NULL;
        res = X509ToHcfX509Certificate(cert, &x509Cert);
        if (res != CF_SUCCESS) {
            LOGE("convert x509 to HcfX509Certificate failed !");
            FreeCertArrayData(certsList);
            return res;
        }
        certsList->data[i] = x509Cert;
    }

    return res;
}

static CfResult CompareSubjectName(const X509 *cert, const CfBlob *subject, bool *compareResult)
{
    /* input param has checked in outside */
    CfResult res = CF_SUCCESS;
    CfBlob cfBlobDataParam = { 0 };
    res = ConvertNameDerDataToString(subject->data, subject->size, &cfBlobDataParam);
    if (res != CF_SUCCESS) {
        LOGE("x509Cert ConvertNameDerDataToString failed!");
        return res;
    }

    *compareResult = true;
    char *subj = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
    if (subj == NULL) {
        LOGE("x509Cert X509_get_subject_name failed!");
        CfFree(cfBlobDataParam.data);
        return CF_INVALID_PARAMS;
    }

    uint32_t nameLength = strlen(subj) + 1;
    if (nameLength != cfBlobDataParam.size ||
        (strncmp((const char *)subj, (const char *)cfBlobDataParam.data, cfBlobDataParam.size)) != 0) {
        LOGI("the subject is differ !");
        // compare issuer & subject
        char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
        if (issuer == NULL) {
            LOGE("x509Cert X509_get_issuer_name failed!");
            CfFree(cfBlobDataParam.data);
            OPENSSL_free(subj);
            return CF_INVALID_PARAMS;
        }

        uint32_t issuerLength = strlen(issuer) + 1;
        if (issuerLength != cfBlobDataParam.size ||
            (strncmp((const char *)issuer, (const char *)cfBlobDataParam.data, cfBlobDataParam.size)) != 0) {
            LOGI("the subject & issuer is differ !");
            *compareResult = false;
        }

        OPENSSL_free(issuer);
    }

    OPENSSL_free(subj);
    CfFree(cfBlobDataParam.data);
    return CF_SUCCESS;
}

static X509 *GetX509FromHcfX509Certificate(const HcfCertificate *cert)
{
    if (!IsClassMatch((CfObjectBase *)cert, HCF_X509_CERTIFICATE_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfX509CertificateImpl *impl = (HcfX509CertificateImpl *)cert;
    if (!IsClassMatch((CfObjectBase *)(impl->spiObj), X509_CERT_OPENSSL_CLASS)) {
        LOGE("Input wrong openssl class type!");
        return NULL;
    }
    HcfOpensslX509Cert *realCert = (HcfOpensslX509Cert *)(impl->spiObj);

    return realCert->x509;
}

// Transform time string of format 'YYMMDDHHMMSS' to struct time_t.
static time_t ConvertYMDtoTimeT(const char *datetime)
{
    struct tm tm = { 0 };
    if (sscanf_s(datetime, "%2d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min,
        &tm.tm_sec) != TIMET_NUM) {
        LOGE("ConvertYMDtoTimeT Parse failed. ");
        return (time_t)-1;
    }
    tm.tm_year += TIMET_YEAR_OFFSET;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    time_t time = mktime(&tm);
    if (time == (time_t)(-1)) {
        LOGE("ConvertYMDDtoTimeT() failed. \n");
    }
    LOGI("time_t for YYMMDDHHMMSS: %ld", (long)time);
    return time;
}

// Transform time string of format 'YYYYMMDDHHMMSSZ' to struct time_t.
static time_t ConvertYMDZtoTimeT(const char *datetime)
{
    struct tm tm = { 0 };
    if (sscanf_s(datetime, "%4d%2d%2d%2d%2d%2dZ", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min,
        &tm.tm_sec) != TIMET_NUM) {
        LOGE("ConvertYMDZtoTimeT Parse failed. ");
        return (time_t)-1;
    }
    tm.tm_year -= TIMET_YEAR_START;
    tm.tm_mon -= 1;
    tm.tm_isdst = -1;
    time_t time = mktime(&tm);
    if (time == (time_t)(-1)) {
        LOGE("ConvertYMDDtoTimeT() failed. \n");
    }
    LOGI("time_t for YYYYMMDDHHMMSSZ: %ld", (long)time);
    return time;
}

static bool CheckCertChainIsRevoked(const STACK_OF(X509_CRL) *crlStack, const STACK_OF(X509) *certChain)
{
    X509 *cert = NULL;
    X509_CRL *crl = NULL;

    int32_t res = 0;
    int cerNum = sk_X509_num(certChain);
    int crlNum = sk_X509_CRL_num(crlStack);
    for (int i = 0; i < crlNum; ++i) {
        crl = sk_X509_CRL_value(crlStack, i);
        /* crl in certcrlcollection object is not null. */
        X509_REVOKED *rev = NULL;
        for (int j = 0; j < cerNum; ++j) {
            cert = sk_X509_value(certChain, j);
            res = X509_CRL_get0_by_cert(crl, &rev, cert);
            if (res != 0) {
                LOGI("cert is revoked : %d .", (res != 0));
                return true;
            }
        }
    }

    return false;
}

static CfResult SetVerifyParams(X509_STORE *store, time_t datetime, X509 *mostTrustCert)
{
    LOGI("add most-trusted cert's to store: ");
    if (X509_STORE_add_cert(store, mostTrustCert) != CF_OPENSSL_SUCCESS) {
        LOGE("add cert to store failed !");
        CfPrintOpensslError();
        return CF_ERR_MALLOC;
    }

    unsigned long flags = 0;
    if (!CheckIsSelfSigned(mostTrustCert)) {
        flags |= X509_V_FLAG_PARTIAL_CHAIN; // is not self signed
        LOGI("SetVerifyFlag() is a partitial chain, not self signed !");
    }

    if (datetime != (time_t)-1 && datetime != 0) {
        flags |= X509_V_FLAG_USE_CHECK_TIME;
        LOGI("set time flag for verify cert chain .");
    } else {
        flags |= X509_V_FLAG_NO_CHECK_TIME;
        LOGI("no date time, set X509_V_FLAG_NO_CHECK_TIME flag .");
    }

    X509_STORE_set_flags(store, flags); // return void

    return CF_SUCCESS;
}

static CfResult VerifyCertChain(time_t datetime, X509 *mostTrustCert, STACK_OF(X509) *x509CertChain)
{
    if (mostTrustCert == NULL || x509CertChain == NULL) {
        LOGE("VerifyCertChainWithDataAndCrl() invalid params !");
        return CF_INVALID_PARAMS;
    }

    X509 *cert = sk_X509_value(x509CertChain, 0); // leaf cert
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE *store = X509_STORE_new();
    if ((store == NULL) || (ctx == NULL)) {
        LOGE("verify cert chain malloc failed !");
        return CF_ERR_MALLOC;
    }

    CfResult res = SetVerifyParams(store, datetime, mostTrustCert);
    if (res != CF_SUCCESS) {
        LOGE("SetVerifyParams() failed !");
        return res;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, x509CertChain) != CF_OPENSSL_SUCCESS) {
        LOGE("init verify ctx failed !");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    if (datetime != (time_t)-1 && datetime != 0) {
        X509_STORE_CTX_set_time(ctx, 0, datetime); // return void, must set time after X509_STORE_CTX_init
        LOGI("set current time :: %ld to certificate verify ctx .", (long)datetime);
    }

    if (X509_verify_cert(ctx) == CF_OPENSSL_SUCCESS) {
        LOGI("Certificate verification succeeded.");
        res = CF_SUCCESS;
    } else {
        LOGE("get the offending certificate causing the failure: ");
        int32_t errCode = X509_STORE_CTX_get_error(ctx);
        const char *pChError = X509_verify_cert_error_string(errCode);
        LOGE("Failed to verify cert, openssl openssl error code = %d, error msg:%s.", errCode, pChError);
        res = ConvertOpensslErrorMsg(errCode);
    }

    X509_STORE_CTX_free(ctx); // Cleanup: Free the allocated memory and release resources.
    X509_STORE_free(store);
    return res;
}

static EVP_PKEY *ConvertByteArrayToPubKey(const uint8_t *pubKeyBytes, size_t len)
{
    if (pubKeyBytes == NULL) {
        LOGE("ConvertByteArrayToPubkey invalid params.");
        return NULL;
    }
    LOGI("pubkeyBytes  len: %d .", len);
    EVP_PKEY *pubKey = d2i_PUBKEY(NULL, &pubKeyBytes, len); // pubkey DER format.
    if (pubKey == NULL) {
        LOGE("d2i_PUBKEY() failed !");
        CfPrintOpensslError();
        return NULL;
    }

    return pubKey;
}

static CfResult CheckOthersInTrustAnchor(const HcfX509TrustAnchor *anchor, X509 *rootCert, bool *checkResult)
{
    *checkResult = false;
    if (anchor->CAPubKey == NULL) {
        return CF_SUCCESS;
    }

    // 1. validate public key of the root CA.
    EVP_PKEY *pubKey = ConvertByteArrayToPubKey(anchor->CAPubKey->data, anchor->CAPubKey->size);
    if (pubKey == NULL) {
        LOGE("ConvertByteArrayToPubKey failed !");
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }
    if (X509_verify(rootCert, pubKey) != CF_OPENSSL_SUCCESS) {
        LOGE("X509_verify() pubkey failed !");
        CfPrintOpensslError();
        EVP_PKEY_free(pubKey);
        return CF_SUCCESS;
    }

    if (anchor->CASubject != NULL) {
        // 2. compare subject name of root CA.
        bool compareSubjectFlag = false;
        CfResult res = CompareSubjectName(rootCert, anchor->CASubject, &compareSubjectFlag);
        if (res != CF_SUCCESS) {
            LOGI("CompareSubjectName failed");
            EVP_PKEY_free(pubKey);
            return res;
        }
        *checkResult = compareSubjectFlag;
    } else {
        *checkResult = true;
    }

    EVP_PKEY_free(pubKey);
    return CF_SUCCESS;
}

static CfResult GetTrustAnchor(const HcfX509TrustAnchor *trustAnchors, X509 *rootCert, X509 **mostTrustCertOut)
{
    if (trustAnchors == NULL || rootCert == NULL || mostTrustCertOut == NULL) {
        LOGE("GetTrustAnchorCert() invalid params !");
        return CF_INVALID_PARAMS;
    }

    if (trustAnchors->CACert != NULL) {
        X509 *cert = GetX509FromHcfX509Certificate((HcfCertificate *)trustAnchors->CACert);
        if (cert == NULL) {
            LOGE("GetTrustAnchorCert() cert is null.");
            return CF_INVALID_PARAMS;
        }

        // validate public key of the trustAnchor CACert. X509_check_issued
        EVP_PKEY *pubKey = X509_get_pubkey(cert);
        if (pubKey == NULL) {
            LOGE("X509_get_pubkey() failed !");
            CfPrintOpensslError();
            return CF_ERR_CRYPTO_OPERATION;
        }
        if (X509_verify(rootCert, pubKey) != CF_OPENSSL_SUCCESS &&
            X509_NAME_cmp(X509_get_subject_name(cert), X509_get_subject_name(rootCert))) {
            LOGE("X509_verify() failed! ");
            CfPrintOpensslError();
            EVP_PKEY_free(pubKey);
            return CF_SUCCESS; // continue to try next trustAnchor
        }
        EVP_PKEY_free(pubKey);
        *mostTrustCertOut = cert;
        LOGI("GetTrustAnchorCert() use trustAnchor->CACert .");
        return CF_SUCCESS;
    }

    bool checkResult = false;
    CfResult res = CheckOthersInTrustAnchor(trustAnchors, rootCert, &checkResult);
    if (res != CF_SUCCESS) {
        LOGE("CheckOthersInTrustAnchor failed.");
        return res;
    }

    if (checkResult) {
        *mostTrustCertOut = rootCert;
    }
    return CF_SUCCESS;
}

static void FreeTrustAnchorData(HcfX509TrustAnchor *trustAnchor)
{
    if (trustAnchor == NULL) {
        return;
    }
    CfBlobFree(&trustAnchor->CAPubKey);
    CfBlobFree(&trustAnchor->CASubject);
    CfObjDestroy(trustAnchor->CACert);
    trustAnchor->CACert = NULL;
}

static CfResult CopyHcfX509TrustAnchor(const HcfX509TrustAnchor *inputAnchor, HcfX509TrustAnchor *outAnchor)
{
    HcfX509Certificate *CACert = inputAnchor->CACert;
    CfBlob *CAPubKey = inputAnchor->CAPubKey;
    CfBlob *CASubject = inputAnchor->CASubject;
    CfResult res = CF_SUCCESS;
    if (CACert != NULL) {
        CfEncodingBlob encodedByte = { NULL, 0, CF_FORMAT_DER };
        CACert->base.getEncoded((HcfCertificate *)CACert, &encodedByte);
        res = HcfX509CertificateCreate(&encodedByte, &outAnchor->CACert);
        if (res != CF_SUCCESS) {
            LOGE("HcfX509CertificateCreate fail, res : %d!", res);
            CfFree(encodedByte.data);
            return CF_ERR_MALLOC;
        }
        CfFree(encodedByte.data);
    }
    if (CAPubKey != NULL) {
        res = DeepCopyBlobToBlob(CAPubKey, &outAnchor->CAPubKey);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            CfObjDestroy(outAnchor->CACert);
            return res;
        }
    }
    if (CASubject != NULL) {
        res = DeepCopyBlobToBlob(CASubject, &outAnchor->CASubject);
        if (res != CF_SUCCESS) {
            LOGE("DeepCopyDataToBlob failed");
            CfObjDestroy(outAnchor->CACert);
            CfBlobFree(&outAnchor->CAPubKey);
            return res;
        }
    }

    return res;
}

static CfResult FillValidateResult(HcfX509TrustAnchor *inputAnchor, X509 *cert, HcfX509CertChainValidateResult *result)
{
    if (inputAnchor == NULL || cert == NULL) {
        LOGE("FillValidateResult() invalidate params !");
        return CF_INVALID_PARAMS;
    }
    CfResult res = CF_SUCCESS;
    HcfX509TrustAnchor *validateTrustAnchors = (HcfX509TrustAnchor *)HcfMalloc(sizeof(HcfX509TrustAnchor), 0);
    if (validateTrustAnchors == NULL) {
        LOGE("FillValidateResult() malloc failed");
        return CF_ERR_MALLOC;
    }
    res = CopyHcfX509TrustAnchor(inputAnchor, validateTrustAnchors);
    if (res != CF_SUCCESS) {
        LOGE("CopyHcfX509TrustAnchor() failed !");
        CfFree(validateTrustAnchors);
        return res;
    }

    result->trustAnchor = validateTrustAnchors;
    HcfX509Certificate *entityCert = NULL;
    res = X509ToHcfX509Certificate(cert, &entityCert);
    if (res != CF_SUCCESS) {
        LOGE("X509ToHcfX509Certificate() failed !");
        FreeTrustAnchorData(result->trustAnchor);
        CF_FREE_PTR(result->trustAnchor);
        return res;
    }

    result->entityCert = entityCert;
    LOGI("FillValidateResult() success !");
    return res;
}

static X509_CRL *ParseX509CRL(const CfEncodingBlob *inStream)
{
    if ((inStream->data == NULL) || (inStream->len <= 0)) {
        LOGE("Invalid Paramas!");
        return NULL;
    }
    BIO *bio = BIO_new_mem_buf(inStream->data, inStream->len);
    if (bio == NULL) {
        LOGE("bio get null!");
        CfPrintOpensslError();
        return NULL;
    }
    X509_CRL *crlOut = NULL;
    switch (inStream->encodingFormat) {
        case CF_FORMAT_DER:
            crlOut = d2i_X509_CRL_bio(bio, NULL);
            break;
        case CF_FORMAT_PEM:
            crlOut = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
            break;
        default:
            LOGE("Not support format!");
            break;
    }
    BIO_free_all(bio);
    if (crlOut == NULL) {
        LOGE("Parse X509 CRL fail!");
        CfPrintOpensslError();
        return NULL;
    }
    return crlOut;
}

static CfResult PushCrl2Stack(HcfX509CrlArray *crlArray, STACK_OF(X509_CRL) *outCrls)
{
    CfResult res = CF_SUCCESS;
    HcfX509Crl *x509Crl = NULL;
    X509_CRL *crl = NULL;
    STACK_OF(X509_CRL) *stackCrls = sk_X509_CRL_new_null();
    for (uint32_t i = 0; i < crlArray->count; i++) {
        CfEncodingBlob encodedBlob = { 0 };
        x509Crl = crlArray->data[i];
        res = x509Crl->getEncoded(x509Crl, &encodedBlob);
        if (res != CF_SUCCESS) {
            LOGE("Failed to getEncoded of crl !");
            sk_X509_CRL_pop_free(stackCrls, X509_CRL_free);
            return res;
        }

        crl = ParseX509CRL(&encodedBlob);
        if (crl == NULL) {
            LOGE("Failed to Parse x509 CRL!");
            CfFree(encodedBlob.data);
            sk_X509_CRL_pop_free(stackCrls, X509_CRL_free);
            return CF_INVALID_PARAMS;
        }
        sk_X509_CRL_push(stackCrls, crl);
        CfFree(encodedBlob.data);
    }

    /* Move stackCrls elements to outCrls */
    while (sk_X509_CRL_num(stackCrls) > 0) {
        X509_CRL *crlTemp = sk_X509_CRL_pop(stackCrls);
        LOGI("push crl to crlStack .");
        sk_X509_CRL_push(outCrls, crlTemp);
    }

    sk_X509_CRL_free(stackCrls); /* Only free the stack, do not free elements */
    return res;
}

static CfResult GetX509Crls(const HcfCertCRLCollectionArray *certCRLCollections, STACK_OF(X509_CRL) *outCrls)
{
    if (certCRLCollections == NULL) { // certCRLCollection is not force params for verify certchain
        LOGI("certcrlcollections is null!");
        return CF_SUCCESS;
    }

    CfResult res = CF_SUCCESS;
    HcfX509CrlArray *crlArray = NULL;
    HcfCertCrlCollection *crlCollection = NULL;
    for (uint32_t i = 0; i < certCRLCollections->count; i++) {
        crlCollection = certCRLCollections->data[i];
        res = crlCollection->getCRLs(crlCollection, &crlArray);
        if (res != CF_SUCCESS) {
            LOGE("getCRLs() from CertCrlCollection failed !");
            /* Warning: free outCrls in outside */
            return res;
        }
        if (crlArray->count == 0) {
            LOGI("crls array is empty.");
            continue;
        }
        res = PushCrl2Stack(crlArray, outCrls);
        if (res != CF_SUCCESS) {
            LOGE("push crls to stack failed !");
            /* Warning: free outCrls in outside */
            return res;
        }
    }

    return res;
}

static CfResult ValidateCrls(const HcfCertCRLCollectionArray *collectionArr, STACK_OF(X509) *x509CertChain)
{
    STACK_OF(X509_CRL) *crlStack = sk_X509_CRL_new_null();
    CfResult res = GetX509Crls(collectionArr, crlStack);
    if (res != CF_SUCCESS) {
        LOGE("GetX509Crls failed");
        sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
        return res;
    }

    if (sk_X509_CRL_num(crlStack) == 0) {
        LOGI("crls count is 0");
        sk_X509_CRL_free(crlStack);
        return CF_SUCCESS;
    }

    if (CheckCertChainIsRevoked(crlStack, x509CertChain)) {
        LOGE("certchain is revoked, verify failed!");
        sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
        return CF_ERR_CRYPTO_OPERATION;
    }

    sk_X509_CRL_pop_free(crlStack, X509_CRL_free);
    return CF_SUCCESS;
}

static CfResult ValidateTrustAnchor(const HcfX509TrustAnchorArray *trustAnchorsArray, X509 *rootCert,
    STACK_OF(X509) *x509CertChain, time_t datetime, HcfX509TrustAnchor **trustAnchorResult)
{
    CfResult res = CF_SUCCESS;
    for (uint32_t i = 0; i < trustAnchorsArray->count; ++i) {
        X509 *mostTrustAnchorCert = NULL;
        HcfX509TrustAnchor *trustAnchor = trustAnchorsArray->data[i];
        res = GetTrustAnchor(trustAnchor, rootCert, &mostTrustAnchorCert);
        if (res != CF_SUCCESS) {
            LOGE("GetTrustAnchor() failed ! try next trustAnchor .");
            return res;
        }
        if (mostTrustAnchorCert == NULL) {
            LOGE("most trust anchor cert is null.");
            res = CF_INVALID_PARAMS; /* if validate trust anchor list failed, return the last error. */
            continue;
        }

        res = VerifyCertChain(datetime, mostTrustAnchorCert, x509CertChain);
        if (res != CF_SUCCESS) { // verify the data & crl list of certchain
            LOGI("verify one trustanchor failed ! try next trustAnchor .");
            continue;
        }
        *trustAnchorResult = trustAnchor;
        LOGI("VerifyCertChainWithDate() success ! FillValidateResult.");
        break;
    }

    return res;
}

static CfResult Validate(
    HcfX509CertChainSpi *self, const HcfX509CertChainValidateParams *params, HcfX509CertChainValidateResult *result)
{
    if ((self == NULL) || (params == NULL) || (params->trustAnchors == NULL) || (params->trustAnchors->data == NULL) ||
        (params->trustAnchors->count == 0) || (result == NULL)) {
        LOGE("[Validate openssl] The input data is null!");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetX509CertChainClass())) {
        LOGE("[Validate openssl] Input wrong class type!");
        return CF_INVALID_PARAMS;
    }

    STACK_OF(X509) *x509CertChain = ((HcfX509CertChainOpensslImpl *)self)->x509CertChain;
    time_t datetime = 0;
    if (params->date != NULL) { // get datetime for verify certchain
        datetime = (params->date->size == 16) ? ConvertYMDZtoTimeT((const char *)params->date->data)
                                              : ConvertYMDtoTimeT((const char *)params->date->data);
    }

    X509 *rootCert = sk_X509_value(x509CertChain, sk_X509_num(x509CertChain) - 1); // root CA
    HcfX509TrustAnchor *trustAnchorResult = NULL;
    /* Verify trust anchor */
    CfResult res = ValidateTrustAnchor(params->trustAnchors, rootCert, x509CertChain, datetime, &trustAnchorResult);
    if (res == CF_SUCCESS) {
        /* Verify Crls */
        res = ValidateCrls(params->certCRLCollections, x509CertChain);
        if (res != CF_SUCCESS) {
            LOGE("Validate Crls failed");
            return res;
        }
        X509 *entityCert = sk_X509_value(x509CertChain, 0);              // leaf CA
        res = FillValidateResult(trustAnchorResult, entityCert, result); // build return result
    }

    return res;
}

static int32_t CreateX509CertChainPEM(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    STACK_OF(X509) *certsChain = NULL;
    X509 *cert = NULL;

    BIO *bio = BIO_new_mem_buf(inData->data, inData->len);
    if (bio == NULL) {
        LOGE("malloc failed");
        CfPrintOpensslError();
        return CF_ERR_MALLOC;
    }
    LOGI("createX509CertChainPEM CfEncodingBlob inData len: %u .", inData->len);

    /* Create cert chain object */
    certsChain = sk_X509_new_null();
    if (certsChain == NULL) {
        BIO_free(bio);
        LOGE("Error creating certificate chain.");
        CfPrintOpensslError();
        return CF_ERR_MALLOC;
    }

    /* Add cert to cert chain object */
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) && cert != NULL) {
        if (sk_X509_push(certsChain, cert) <= 0) {
            LOGE("Memory allocation failure !\n");
            X509_free(cert);
            BIO_free(bio);
            sk_X509_pop_free(certsChain, X509_free);
            return CF_ERR_MALLOC;
        }
        LOGI("push cert to certsChain.");
    }

    if (sk_X509_num(certsChain) == 0) {
        LOGE("cert chain size = 0.");
        CfPrintOpensslError();
        BIO_free(bio);
        sk_X509_free(certsChain);
        return CF_ERR_CRYPTO_OPERATION;
    }

    *certchainObj = certsChain;
    BIO_free(bio);
    return CF_SUCCESS;
}

/*
 * create x509 certchain from DER format streams
 * input params: inData
 * output params: certchainObj
 */
static int32_t CreateX509CertChainDER(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    STACK_OF(X509) *certsChain = NULL;
    X509 *cert = NULL;
    const unsigned char *p = inData->data; // DER data
    size_t length = inData->len;

    LOGI("createX509CertChainDER CfEncodingBlob inData len: %u.", length);
    certsChain = sk_X509_new_null();
    if (certsChain == NULL) {
        LOGE("Error creating certificate chain.");
        return CF_ERR_MALLOC;
    }

    while (p < inData->data + length) {
        size_t lengthLeft = (inData->data + length - p);
        cert = d2i_X509(NULL, &p, lengthLeft);
        if (cert == NULL) {
            LOGE("Failed to parse certificate.");
            CfPrintOpensslError();
            sk_X509_pop_free(certsChain, X509_free);
            return CF_ERR_CRYPTO_OPERATION;
        }
        if (sk_X509_push(certsChain, cert) <= 0) {
            LOGE("Memory allocation failure !\n");
            X509_free(cert);
            sk_X509_pop_free(certsChain, X509_free);
            return CF_ERR_MALLOC;
        }
        LOGI("push cert to certsChain.");
    }

    if (sk_X509_num(certsChain) == 0) {
        sk_X509_free(certsChain);
        LOGE("certs chain count = 0.");
        return CF_INVALID_PARAMS;
    }
    *certchainObj = certsChain;
    return CF_SUCCESS;
}

/*
 * create x509 certchain from pkcs#7 streams
 * input params: inData
 * output params: certchainObj
 */
static CfResult CreateX509CertChainPKCS7(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    size_t dataLength = inData->len;
    uint8_t *data = inData->data;
    BIO *bio = BIO_new_mem_buf(data, dataLength);
    if (bio == NULL) {
        LOGE("malloc failed");
        CfPrintOpensslError();
        return CF_ERR_MALLOC;
    }

    PKCS7 *pkcs7 = d2i_PKCS7_bio(bio, NULL); // DER format .p7b file
    if (pkcs7 == NULL) {
        LOGE("Failed to parse PKCS7 data .");
        BIO_free(bio);
        CfPrintOpensslError();
        return CF_ERR_CRYPTO_OPERATION;
    }

    /* Get cert chain from pkcs7 object */
    STACK_OF(X509) *oriCertsChain = NULL;
    int i = OBJ_obj2nid(pkcs7->type);
    LOGE("pkcs7->type : %d .", i);
    if (i == NID_pkcs7_signed) {
        oriCertsChain = pkcs7->d.sign->cert;
    } else if (i == NID_pkcs7_signedAndEnveloped) {
        oriCertsChain = pkcs7->d.signed_and_enveloped->cert;
    }

    if (oriCertsChain == NULL || sk_X509_num(oriCertsChain) == 0) {
        LOGE("Failed to get certchain object.");
        PKCS7_free(pkcs7);
        BIO_free(bio);
        return CF_ERR_CRYPTO_OPERATION;
    }

    /* Clone a cert chain object for free pkcs7 object */
    int count = sk_X509_num(oriCertsChain);
    STACK_OF(X509) *certsChain = sk_X509_dup(oriCertsChain);
    for (int index = 0; index < count; ++index) {
        X509 *originalCert = sk_X509_value(oriCertsChain, index);
        X509 *copiedCert = X509_dup(originalCert);
        sk_X509_set(certsChain, index, copiedCert);
    }

    *certchainObj = certsChain;
    PKCS7_free(pkcs7);
    BIO_free(bio);
    return CF_SUCCESS;
}

static int32_t CreateX509CertChainInner(const CfEncodingBlob *inData, STACK_OF(X509) **certchainObj)
{
    int32_t ret = CF_SUCCESS;
    if (inData->encodingFormat == CF_FORMAT_PKCS7) {
        ret = CreateX509CertChainPKCS7(inData, certchainObj);
    } else if (inData->encodingFormat == CF_FORMAT_DER) {
        // create certchain from CF_FORMAT_DER
        ret = CreateX509CertChainDER(inData, certchainObj);
    } else if (inData->encodingFormat == CF_FORMAT_PEM) {
        // create certchain from CF_FORMAT_PEM
        ret = CreateX509CertChainPEM(inData, certchainObj);
    } else {
        LOGE("invalid input params");
        return CF_INVALID_PARAMS;
    }

    if (ret != CF_SUCCESS) {
        LOGE("error happened");
        return ret;
    }

    int num = sk_X509_num(*certchainObj);
    if (num > MAX_CERT_NUM) {
        LOGE("certchain certs number :%u  invalid. create certChain failed! ", num);
        sk_X509_pop_free(*certchainObj, X509_free);
        return CF_INVALID_PARAMS;
    }

    return CF_SUCCESS;
}

CfResult HcfX509CertChainByEncSpiCreate(const CfEncodingBlob *inStream, HcfX509CertChainSpi **spi)
{
    int32_t ret = CF_SUCCESS;
    if (inStream == NULL || inStream->data == NULL || inStream->len == 0 || spi == NULL) {
        LOGE("HcfX509CertChainByEncSpiCreate(), Invalid params !");
        return CF_INVALID_PARAMS;
    }
    HcfX509CertChainOpensslImpl *certChain =
        (HcfX509CertChainOpensslImpl *)HcfMalloc(sizeof(HcfX509CertChainOpensslImpl), 0);
    if (certChain == NULL) {
        LOGE("Failed to allocate certChain spi object memory!");
        return CF_ERR_MALLOC;
    }

    ret = CreateX509CertChainInner(inStream, &(certChain->x509CertChain));
    if (ret != CF_SUCCESS || certChain->x509CertChain == NULL) {
        CfFree(certChain);
        LOGE("Failed to create x509 cert chain");
        return CF_INVALID_PARAMS;
    }

    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;

    *spi = (HcfX509CertChainSpi *)certChain;
    return CF_SUCCESS;
}

CfResult HcfX509CertChainByArrSpiCreate(const HcfX509CertificateArray *inCerts, HcfX509CertChainSpi **spi)
{
    if (spi == NULL || inCerts == NULL || inCerts->data == NULL || inCerts->count == 0 ||
        inCerts->count > MAX_CERT_NUM) {
        LOGE("Invalid params, is null !");
        return CF_INVALID_PARAMS;
    }

    HcfX509CertChainOpensslImpl *certChain =
        (HcfX509CertChainOpensslImpl *)HcfMalloc(sizeof(HcfX509CertChainOpensslImpl), 0);
    if (certChain == NULL) {
        LOGE("Failed to allocate certChain spi object memory!");
        return CF_ERR_MALLOC;
    }

    STACK_OF(X509) *certStack = sk_X509_new_null();
    if (certStack == NULL) {
        LOGE("Error creating certificate chain.");
        CfFree(certChain);
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < inCerts->count; ++i) {
        X509 *cert = GetX509FromHcfX509Certificate((HcfCertificate *)inCerts->data[i]);
        if (cert == NULL) {
            LOGE("GetX509Cert from encodedBlob failed!");
            sk_X509_pop_free(certStack, X509_free);
            CfFree(certChain);
            return CF_INVALID_PARAMS;
        }

        X509 *certDup = X509_dup(cert);
        if (certDup == NULL) {
            LOGE("Memory allocation failure !\n");
            sk_X509_pop_free(certStack, X509_free);
            CfFree(certChain);
            return CF_ERR_MALLOC;
        }

        if (sk_X509_push(certStack, certDup) <= 0) {
            LOGE("Memory allocation failure !\n");
            X509_free(certDup);
            sk_X509_pop_free(certStack, X509_free);
            CfFree(certChain);
            return CF_ERR_MALLOC;
        }
    }

    certChain->x509CertChain = certStack;
    certChain->base.base.getClass = GetX509CertChainClass;
    certChain->base.base.destroy = DestroyX509CertChain;
    certChain->base.engineGetCertList = GetCertlist;
    certChain->base.engineValidate = Validate;
    *spi = (HcfX509CertChainSpi *)certChain;

    return CF_SUCCESS;
}