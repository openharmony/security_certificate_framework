/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "napi_x509_cert_chain_validate_params.h"

#include <securec.h>

#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "cf_type.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_cert_crl_collection.h"
#include "napi_cert_defines.h"
#include "napi_cert_utils.h"
#include "napi_common.h"
#include "napi_object.h"
#include "napi_x509_crl.h"
#include "napi_x509_trust_anchor.h"
#include "napi_x509_certificate.h"
#include "utils.h"
#include "x509_cert_chain_validate_params.h"

namespace OHOS {
namespace CertFramework {

static bool GetValidDate(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_DATE.c_str());
    if (obj == nullptr) {
        LOGI("prop date do not exist!");
        return true;
    }
    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("get blob failed!");
        return false;
    }
    return true;
}

static bool GetArrayLength(napi_env env, napi_value arg, uint32_t &length)
{
    length = 0;
    bool flag = false;
    napi_status status = napi_is_array(env, arg, &flag);
    if (status != napi_ok || !flag) {
        LOGE("param type not array!");
        return false;
    }
    status = napi_get_array_length(env, arg, &length);
    if (status != napi_ok || length == 0 || length > MAX_LEN_OF_ARRAY) {
        LOGE("array length is invalid!");
        return false;
    }
    return true;
}

static void FreeTrustAnchorArray(HcfX509TrustAnchorArray *&trustAnchors)
{
    for (uint32_t i = 0; i < trustAnchors->count; ++i) {
        FreeX509TrustAnchorObj(trustAnchors->data[i]);
    }
    CfFree(trustAnchors);
    trustAnchors = nullptr;
}

static bool GetX509TrustAnchorArray(napi_env env, napi_value arg, bool isTrustSystemCa, HcfX509TrustAnchorArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_TRUSTANCHORS.c_str());
    if (obj == nullptr) {
        LOGE("param type not array!");
        return false;
    }

    uint32_t length;
    if (!GetArrayLength(env, obj, length)) {
        LOGE("get array length failed!");
        return isTrustSystemCa;
    }

    out = static_cast<HcfX509TrustAnchorArray *>(CfMalloc(sizeof(HcfX509TrustAnchorArray), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }

    out->count = length;
    out->data = static_cast<HcfX509TrustAnchor **>(CfMalloc(length * sizeof(HcfX509TrustAnchor *), 0));
    if (out->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; ++i) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok) {
            LOGE("get element failed!");
            FreeTrustAnchorArray(out);
            out = nullptr;
            return false;
        }

        if (!BuildX509TrustAnchorObj(env, element, out->data[i])) {
            LOGE("build x509 trust anchor obj failed!");
            FreeTrustAnchorArray(out);
            out = nullptr;
            return false;
        }
    }
    out->count = length;
    return true;
}

static bool GetCertCRLCollectionElement(napi_env env, napi_value obj, uint32_t index,
    HcfCertCrlCollection **collection)
{
    napi_value element;
    napi_status status = napi_get_element(env, obj, index, &element);
    if (status != napi_ok) {
        LOGE("get element failed!");
        return false;
    }
    NapiCertCRLCollection *napiCertCrlCollectionObj = nullptr;
    napi_unwrap(env, element, reinterpret_cast<void **>(&napiCertCrlCollectionObj));
    if (napiCertCrlCollectionObj == nullptr) {
        LOGE("napi cert crl collection object is nullptr!");
        return false;
    }
    *collection = napiCertCrlCollectionObj->GetCertCrlCollection();
    return true;
}

static bool GetCertCRLCollectionArray(napi_env env, napi_value arg, HcfCertCRLCollectionArray *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_CERTCRLS.c_str());
    if (obj == nullptr) {
        LOGI("prop certCRLs do not exist!");
        return true;
    }

    uint32_t length;
    if (!GetArrayLength(env, obj, length)) {
        LOGE("get array length failed!");
        return false;
    }

    out = static_cast<HcfCertCRLCollectionArray *>(CfMalloc(sizeof(HcfCertCRLCollectionArray), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }
    out->count = length;
    out->data = static_cast<HcfCertCrlCollection **>(CfMalloc(length * sizeof(HcfCertCrlCollection *), 0));
    if (out->data == nullptr) {
        LOGE("Failed to allocate data memory!");
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        if (!GetCertCRLCollectionElement(env, obj, i, &out->data[i])) {
            CfFree(out->data);
            out->data = nullptr;
            CfFree(out);
            out = nullptr;
            return false;
        }
    }
    return true;
}

static bool IsRevocationOptionValid(HcfRevChkOption option)
{
    switch (option) {
        case REVOCATION_CHECK_OPTION_PREFER_OCSP:
        case REVOCATION_CHECK_OPTION_ACCESS_NETWORK:
        case REVOCATION_CHECK_OPTION_FALLBACK_NO_PREFER:
        case REVOCATION_CHECK_OPTION_FALLBACK_LOCAL:
        case REVOCATION_CHECK_OPTION_CHECK_INTERMEDIATE_CA_ONLINE:
        case REVOCATION_CHECK_OPTION_LOCAL_CRL_ONLY_CHECK_END_ENTITY_CERT:
        case REVOCATION_CHECK_OPTION_IGNORE_NETWORK_ERROR:
            return true;
        default:
            return false;
    }
}

static bool GetRevocationOptions(napi_env env, napi_value rckObj, HcfRevocationCheckParam *&out)
{
    napi_value obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OPTIONS.c_str());
    if (obj == nullptr) {
        return true;
    }
    bool flag = false;
    napi_status status = napi_is_array(env, obj, &flag);
    if (status != napi_ok || !flag) {
        return false;
    }

    uint32_t length = 0;
    status = napi_get_array_length(env, obj, &length);
    if (status != napi_ok || length == 0 || length > MAX_NAPI_ARRAY_OF_U8ARR) {
        return false;
    }
    out->options = static_cast<HcfRevChkOpArray *>(CfMalloc(sizeof(HcfRevChkOpArray), 0));
    if (out->options == nullptr) {
        return false;
    }
    out->options->count = length;
    out->options->data = static_cast<HcfRevChkOption *>(CfMalloc(length * sizeof(HcfRevChkOption), 0));
    if (out->options->data == nullptr) {
        CF_FREE_PTR(out->options);
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok ||
            napi_get_value_int32(env, element, (int32_t *)&(out->options->data[i])) != napi_ok) {
            CF_FREE_PTR(out->options->data);
            CF_FREE_PTR(out->options);
            return false;
        }
        if (!IsRevocationOptionValid(out->options->data[i])) {
            CF_FREE_PTR(out->options->data);
            CF_FREE_PTR(out->options);
            return false;
        }
    }
    return true;
}

static bool GetRevocationocspDigest(napi_env env, napi_value rckObj, HcfRevocationCheckParam *&out)
{
    napi_value obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_DIGEST.c_str());
    if (obj == nullptr) {
        return true;
    }

    out->ocspDigest = CertGetBlobFromStringJSParams(env, obj);
    if (out->ocspDigest == nullptr) {
        return false;
    }

    char *mdName = reinterpret_cast<char *>(out->ocspDigest->data);
    if (strcmp(mdName, "SHA1") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA224") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA256") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA384") == 0) {
        return true;
    } else if (strcmp(mdName, "SHA512") == 0) {
        return true;
    } else if (strcmp(mdName, "MD5") == 0) {
        return true;
    }

    CfFree(out->ocspDigest->data);
    out->ocspDigest->data = nullptr;
    CfFree(out->ocspDigest);
    out->ocspDigest = nullptr;
    return false;
}

static bool GetRevocationDetail(napi_env env, napi_value rckObj, HcfRevocationCheckParam *&out)
{
    napi_value obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_REQ_EXTENSION.c_str());
    if (obj != nullptr) {
        out->ocspRequestExtension = CertGetBlobArrFromArrUarrJSParams(env, obj);
        if (out->ocspRequestExtension == nullptr) {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_RESP_URI.c_str());
    if (obj != nullptr) {
        out->ocspResponderURI = CertGetBlobFromStringJSParams(env, obj);
        if (out->ocspResponderURI == nullptr) {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_RESP_CERT.c_str());
    if (obj != nullptr) {
        NapiX509Certificate *napiX509Cert = nullptr;
        napi_unwrap(env, obj, reinterpret_cast<void **>(&napiX509Cert));
        if (napiX509Cert != nullptr) {
            out->ocspResponderCert = napiX509Cert->GetX509Cert();
            if (out->ocspResponderCert == nullptr) {
                return false;
            }
        } else {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_OCSP_RESPS.c_str());
    if (obj != nullptr) {
        out->ocspResponses = CertGetBlobFromUint8ArrJSParams(env, obj);
        if (out->ocspResponses == nullptr) {
            return false;
        }
    }
    obj = GetProp(env, rckObj, CERT_CHAIN_VALIDATE_TAG_CRL_DOWNLOAD_URI.c_str());
    if (obj != nullptr) {
        out->crlDownloadURI = CertGetBlobFromStringJSParams(env, obj);
        if (out->crlDownloadURI == nullptr) {
            return false;
        }
    }
    if (!GetRevocationocspDigest(env, rckObj, out)) {
        return false;
    }
    return GetRevocationOptions(env, rckObj, out);
}

static void FreeHcfRevocationCheckParam(HcfRevocationCheckParam *param)
{
    if (param == nullptr) {
        return;
    }
    if (param->ocspRequestExtension != nullptr) {
        FreeCfBlobArray(param->ocspRequestExtension->data, param->ocspRequestExtension->count);
        param->ocspRequestExtension->data = nullptr;
        param->ocspRequestExtension->count = 0;
        CfFree(param->ocspRequestExtension);
        param->ocspRequestExtension = nullptr;
    }
    CfBlobFree(&param->ocspResponderURI);
    CfBlobFree(&param->ocspResponses);
    CfBlobFree(&param->crlDownloadURI);
    if (param->options != nullptr) {
        if (param->options->data != nullptr) {
            CfFree(param->options->data);
            param->options->data = nullptr;
        }
        CfFree(param->options);
        param->options = nullptr;
    }
    CfBlobFree(&param->ocspDigest);
    CfFree(param);
}

static bool GetRevocationCheckParam(napi_env env, napi_value arg, HcfRevocationCheckParam *&out)
{
    napi_value rckObj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_REVOCATIONCHECKPARAM.c_str());
    if (rckObj == nullptr) {
        LOGI("RevocationCheckParam do not exist!");
        return true;
    }
    napi_valuetype valueType;
    napi_typeof(env, rckObj, &valueType);
    if (valueType == napi_null || valueType != napi_object) {
        LOGE("Failed to check input param!");
        return false;
    }

    out = static_cast<HcfRevocationCheckParam *>(CfMalloc(sizeof(HcfRevocationCheckParam), 0));
    if (out == nullptr) {
        LOGE("Failed to allocate out memory!");
        return false;
    }
    if (!GetRevocationDetail(env, rckObj, out)) {
        LOGE("Failed to get revocation detail!");
        FreeHcfRevocationCheckParam(out);
        out = nullptr;
        return false;
    }

    return true;
}

static bool GetValidationPolicyType(napi_env env, napi_value arg, HcfValPolicyType &out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_POLICY.c_str());
    if (obj != nullptr) {
        napi_status status = napi_get_value_int32(env, obj, (int32_t *)&out);
        if (status != napi_ok) {
            return false;
        }
    }
    return true;
}

static bool GetSSLHostname(napi_env env, napi_value arg, CfBlob *&out)
{
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_SSLHOSTNAME.c_str());
    if (obj == nullptr) {
        LOGI("Param type not SSLHostname!");
        return true;
    }
    out = CertGetBlobFromStringJSParams(env, obj);
    if (out == nullptr) {
        LOGE("SSLHostname is nullptr");
        return false;
    }
    return true;
}

static bool GetKeyUsage(napi_env env, napi_value arg, HcfKuArray *&out)
{
    out = nullptr;
    napi_value obj = GetProp(env, arg, CERT_CHAIN_VALIDATE_TAG_KEYUSAGE.c_str());
    if (obj == nullptr) {
        return true;
    }
    bool flag = false;
    napi_status status = napi_is_array(env, obj, &flag);
    if (status != napi_ok || !flag) {
        return false;
    }
    uint32_t length = 0;
    status = napi_get_array_length(env, obj, &length);
    if (status != napi_ok || length == 0 || length > MAX_NAPI_ARRAY_OF_U8ARR) {
        return false;
    }
    out = static_cast<HcfKuArray *>(CfMalloc(sizeof(HcfKuArray), 0));
    if (out == nullptr) {
        return false;
    }
    out->count = length;
    out->data = static_cast<HcfKeyUsageType *>(CfMalloc(length * sizeof(HcfKeyUsageType), 0));
    if (out->data == nullptr) {
        CfFree(out);
        out = nullptr;
        return false;
    }
    for (uint32_t i = 0; i < length; i++) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok ||
            napi_get_value_int32(env, element, (int32_t *)&(out->data[i])) != napi_ok) {
            CfFree(out->data);
            out->data = nullptr;
            CfFree(out);
            out = nullptr;
            return false;
        }
    }
    return true;
}

static bool GetUseSystemCa(napi_env env, napi_value arg, bool *trustSystemCa)
{
    bool result = false;
    napi_has_named_property(env, arg, CERT_CHAIN_VALIDATE_TAG_TRUST_SYSTEM_CA.c_str(), &result);
    if (!result) {
        LOGI("%{public}s do not exist!", CERT_CHAIN_VALIDATE_TAG_TRUST_SYSTEM_CA.c_str());
        *trustSystemCa = false;
        return true;
    }
    napi_value obj = nullptr;
    napi_status status = napi_get_named_property(env, arg, CERT_CHAIN_VALIDATE_TAG_TRUST_SYSTEM_CA.c_str(), &obj);
    if (status != napi_ok || obj == nullptr) {
        LOGE("get property %{public}s failed!", CERT_CHAIN_VALIDATE_TAG_TRUST_SYSTEM_CA.c_str());
        return false;
    }
    napi_valuetype valueType;
    napi_typeof(env, obj, &valueType);
    if (valueType == napi_undefined) {
        LOGE("%{public}s valueType is null or undefined.", CERT_CHAIN_VALIDATE_TAG_TRUST_SYSTEM_CA.c_str());
        return false;
    }
    napi_get_value_bool(env, obj, trustSystemCa);
    return true;
}

void FreeX509CertChainValidateParams(HcfX509CertChainValidateParams &param)
{
    CfBlobFree(&param.date);
    if (param.trustAnchors != nullptr) {
        for (uint32_t i = 0; i < param.trustAnchors->count; ++i) {
            FreeX509TrustAnchorObj(param.trustAnchors->data[i]);
        }
        CfFree(param.trustAnchors);
        param.trustAnchors = nullptr;
    }

    if (param.certCRLCollections != nullptr) {
        CfFree(param.certCRLCollections->data);
        param.certCRLCollections->data = nullptr;
        CfFree(param.certCRLCollections);
        param.certCRLCollections = nullptr;
    }

    CfBlobFree(&(param.sslHostname));
    if (param.keyUsage != nullptr) {
        CfFree(param.keyUsage->data);
        param.keyUsage->data = nullptr;
        CfFree(param.keyUsage);
        param.keyUsage = nullptr;
    }

    FreeHcfRevocationCheckParam(param.revocationCheckParam);
    param.revocationCheckParam = nullptr;
}

void FreeTrustAnchorArray(HcfX509TrustAnchorArray *trustAnchorArray, bool freeCertFlag)
{
    if (trustAnchorArray == NULL) {
        return;
    }
    for (uint32_t i = 0; i < trustAnchorArray->count; i++) {
        if (trustAnchorArray->data[i] != NULL) {
            if (freeCertFlag) {
                CfObjDestroy(trustAnchorArray->data[i]->CACert);
            }
            trustAnchorArray->data[i]->CACert = NULL;
            CfBlobFree(&trustAnchorArray->data[i]->CAPubKey);
            CfBlobFree(&trustAnchorArray->data[i]->CASubject);
            CfBlobFree(&trustAnchorArray->data[i]->nameConstraints);
            CfFree(trustAnchorArray->data[i]);
            trustAnchorArray->data[i] = NULL;
        }
    }

    CfFree(trustAnchorArray);
}

bool BuildX509CertChainValidateParams(napi_env env, napi_value arg, HcfX509CertChainValidateParams &param)
{
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type != napi_object) {
        LOGE("wrong argument type. expect string type. [Type]: %{public}d", type);
        return false;
    }

    if (!GetValidDate(env, arg, param.date)) {
        LOGE("Get valid date failed");
        return false;
    }
    if (!GetUseSystemCa(env, arg, &(param.trustSystemCa))) {
        LOGE("Get use system ca failed!");
        return false;
    }

    if (GetBoolFromNameValue(env, arg, &(param.allowDownloadIntermediateCa),
        CERT_CHAIN_VALIDATE_TAG_ALLOW_DOWNLOAD_INTERMEDIATE_CA.c_str()) != CF_SUCCESS) {
        LOGE("Get allow download intermediate CA failed!");
        return false;
    }

    if (!GetX509TrustAnchorArray(env, arg, param.trustSystemCa, param.trustAnchors)) {
        LOGE("Get X509 trust anchor array failed");
        return false;
    }
    if (!GetCertCRLCollectionArray(env, arg, param.certCRLCollections)) {
        LOGE("Get cert CRL collection array failed");
        return false;
    }
    if (!GetRevocationCheckParam(env, arg, param.revocationCheckParam)) {
        LOGE("Get revocation check param failed!");
        return false;
    }
    if (!GetValidationPolicyType(env, arg, param.policy)) {
        LOGE("Get validation policy type failed!");
        return false;
    }
    if (!GetSSLHostname(env, arg, param.sslHostname)) {
        LOGE("Get SSL hostname failed!");
        return false;
    }
    if (!GetKeyUsage(env, arg, param.keyUsage)) {
        LOGE("Get key usage failed!");
        return false;
    }
    return true;
}

static CfResult GetCertArrayFromNapiValue(napi_env env, napi_value arg, const char *name, HcfX509CertificateArray &value)
{
    napi_value obj = nullptr;
    uint32_t length = 0;
    CfResult ret = NapiGetArrayBaseInfo(env, arg, name, obj, length, MAX_LEN_OF_ARRAY);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    HcfX509CertificateArray out = {};
    out.count = length;
    out.data = static_cast<HcfX509Certificate **>(CfMallocEx(length * sizeof(HcfX509Certificate *)));
    if (out.data == nullptr) {
        LOGE("Failed to allocate out memory, size: %{public}zu!", length * sizeof(HcfX509Certificate *));
        return CF_ERR_MALLOC;
    }

    for (uint32_t i = 0; i < length; ++i) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok) {
            LOGE("get element failed!");
            CfFree(out.data);
            return CF_ERR_NAPI;
        }

        NapiX509Certificate *napiCert = nullptr;
        if (napi_unwrap(env, element, reinterpret_cast<void **>(&napiCert)) != napi_ok) {
            LOGE("unwrap napi certificate object failed!");
            CfFree(out.data);
            return CF_ERR_NAPI;
        }
        if (napiCert == nullptr) {
            LOGE("napi certificate object is nullptr!");
            CfFree(out.data);
            return CF_INVALID_PARAMS;
        }
        out.data[i] = napiCert->GetX509Cert();
    }

    value = out;
    return CF_SUCCESS;
}

static CfResult GetCrlArrayFromNapiValue(napi_env env, napi_value arg, const char *name, HcfX509CrlArray &value)
{
    napi_value obj = nullptr;
    uint32_t length = 0;
    CfResult ret = NapiGetArrayBaseInfo(env, arg, name, obj, length, MAX_LEN_OF_ARRAY);
    if (ret != CF_SUCCESS) {
        return ret;
    }

    HcfX509CrlArray out = { 0 };
    out.data = static_cast<HcfX509Crl **>(CfMallocEx(length * sizeof(HcfX509Crl *)));
    if (out.data == nullptr) {
        LOGE("Failed to allocate out memory, size: %{public}zu!", length * sizeof(HcfX509Crl *));
        return CF_ERR_MALLOC;
    }
    out.count = length;

    for (uint32_t i = 0; i < length; ++i) {
        napi_value element;
        if (napi_get_element(env, obj, i, &element) != napi_ok) {
            LOGE("get element failed!");
            CfFree(out.data);
            out.data = nullptr;
            out.count = 0;
            return CF_ERR_NAPI;
        }

        NapiX509Crl *napiCrl = nullptr;
        if (napi_unwrap(env, element, reinterpret_cast<void **>(&napiCrl)) != napi_ok) {
            LOGE("unwrap napi CRL object failed!");
            CfFree(out.data);
            out.data = nullptr;
            out.count = 0;
            return CF_ERR_NAPI;
        }
        if (napiCrl == nullptr) {
            LOGE("napi CRL object is nullptr!");
            CfFree(out.data);
            out.data = nullptr;
            out.count = 0;
            return CF_INVALID_PARAMS;
        }
        out.data[i] = napiCrl->GetX509Crl();
    }

    value = out;
    return CF_SUCCESS;
}

static CfResult GetRevokedParamsFields(napi_env env, napi_value obj, HcfX509CertRevokedParams *param)
{
    CfResult ret = NapiGetInt32Array(env, obj, CERT_REVOKED_TAG_REVOCATION_FLAGS.c_str(),
        param->revocationFlags);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get revocation flags failed");
        return ret;
    }

    ret = GetCrlArrayFromNapiValue(env, obj, CERT_REVOKED_TAG_CRLS.c_str(), param->crls);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get crls failed");
        return ret;
    }

    ret = NapiGetBoolValue(env, obj, CERT_REVOKED_TAG_ALLOW_DOWNLOAD_CRL.c_str(),
        param->allowDownloadCrl);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get allow download crl failed");
        return ret;
    }

    ret = NapiGetBoolValue(env, obj, CERT_REVOKED_TAG_ALLOW_OCSP_CHECK_ONLINE.c_str(),
        param->allowOcspCheckOnline);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get allow ocsp check online failed");
        return ret;
    }

    ret = NapiGetInt32Ex(env, obj, CERT_REVOKED_TAG_OCSP_DIGEST.c_str(), param->ocspDigest);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get ocsp digest failed");
        return ret;
    }

    ret = NapiGetBlobArray(env, obj, CERT_REVOKED_TAG_OCSP_RESPONSES.c_str(),
        param->ocspResponses);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get ocsp responses failed!");
        return ret;
    }
    return CF_SUCCESS;
}

static CfResult BuildX509CertRevokedParams(napi_env env, napi_value arg, HcfX509CertRevokedParams *&param)
{
    napi_value revokedParamsObj = nullptr;
    CfResult ret = NapiGetProperty(env, arg, CERT_VALIDATOR_TAG_REVOKED_PARAMS.c_str(), false, revokedParamsObj);
    if (ret != CF_SUCCESS || revokedParamsObj == nullptr) {
        return ret;
    }

    param = static_cast<HcfX509CertRevokedParams *>(CfMallocEx(sizeof(HcfX509CertRevokedParams)));
    if (param == nullptr) {
        LOGE("Failed to allocate revoked params memory!");
        return CF_ERR_MALLOC;
    }

    ret = GetRevokedParamsFields(env, revokedParamsObj, param);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        CfFree(param);
        param = nullptr;
        return ret;
    }
    return CF_SUCCESS;
}


static CfResult GetBoolParams(napi_env env, napi_value arg, HcfX509CertValidatorParams &param)
{
    CfResult ret = NapiGetBoolValue(env, arg, CERT_CHAIN_VALIDATE_TAG_TRUST_SYSTEM_CA.c_str(),
        param.trustSystemCa);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get trust system ca failed!");
        return ret;
    }

    ret = NapiGetBoolValue(env, arg, CERT_VALIDATOR_TAG_PARTIAL_CHAIN.c_str(), param.partialChain);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get partial chain failed!");
        return ret;
    }

    ret = NapiGetBoolValue(env, arg, CERT_CHAIN_VALIDATE_TAG_ALLOW_DOWNLOAD_INTERMEDIATE_CA.c_str(),
        param.allowDownloadIntermediateCa);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get allow download intermediate ca failed!");
        return ret;
    }

    ret = NapiGetBoolValue(env, arg, CERT_VALIDATOR_TAG_VALIDATE_DATE.c_str(), param.validateDate);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get validate date failed!");
        return ret;
    }
    return CF_SUCCESS;
}

static CfResult GetArrayParams(napi_env env, napi_value arg, HcfX509CertValidatorParams &param)
{
    CfResult ret = GetCertArrayFromNapiValue(env, arg, CERT_VALIDATOR_TAG_TRUSTED_CERTS.c_str(), param.trustedCerts);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get trusted certs failed");
        return ret;
    }

    ret = GetCertArrayFromNapiValue(env, arg, CERT_VALIDATOR_TAG_UNTRUSTED_CERTS.c_str(), param.untrustedCerts);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get untrusted certs failed");
        return ret;
    }

    ret = NapiGetInt32Array(env, arg, CERT_VALIDATOR_TAG_IGNORE_ERRS.c_str(), param.ignoreErrs);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get ignore errs failed");
        return ret;
    }

    ret = NapiGetStringArray(env, arg, CERT_VALIDATOR_TAG_HOSTNAMES.c_str(), param.hostnames);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get hostnames failed");
        return ret;
    }

    ret = NapiGetStringArray(env, arg, CERT_VALIDATOR_TAG_EMAIL_ADDRESSES.c_str(), param.emailAddresses);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get email addresses failed");
        return ret;
    }

    ret = NapiGetInt32Array(env, arg, CERT_VALIDATOR_TAG_KEY_USAGE.c_str(), param.keyUsage);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get key usage failed");
        return ret;
    }

    ret = NapiGetBlobValue(env, arg, CERT_VALIDATOR_TAG_USER_ID.c_str(), param.userId);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get user id failed");
        return ret;
    }
    return CF_SUCCESS;
}

static CfResult BuildX509BaseVerifyParams(napi_env env, napi_value arg, HcfX509CertValidatorParams &param)
{
    CfResult ret = GetBoolParams(env, arg, param);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        return ret;
    }

    ret = NapiGetStringValue(env, arg, CERT_CHAIN_VALIDATE_TAG_DATE.c_str(), param.date);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Get date failed!");
        return ret;
    }

    ret = GetArrayParams(env, arg, param);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        return ret;
    }

    return CF_SUCCESS;
}

CfResult BuildX509CertValidatorParams(napi_env env, napi_value arg, HcfX509CertValidatorParams &param)
{
    CfResult ret = CF_SUCCESS;
    napi_valuetype type;
    if (napi_typeof(env, arg, &type) != napi_ok) {
        LOGE("get argument type failed!");
        return CF_ERR_NAPI;
    }
    if (type != napi_object) {
        LOGE("wrong argument type. expect object type.");
        return CF_INVALID_PARAMS;
    }

    (void)memset_s(&param, sizeof(HcfX509CertValidatorParams), 0, sizeof(HcfX509CertValidatorParams));

    ret = BuildX509BaseVerifyParams(env, arg, param);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Build base verify params failed!");
        FreeX509CertValidatorParams(param);
        return ret;
    }

    ret = BuildX509CertRevokedParams(env, arg, param.revokedParams);
    if (ret != CF_SUCCESS && ret != CF_NOT_EXIST) {
        LOGE("Build revoked params failed!");
        FreeX509CertValidatorParams(param);
        return ret;
    }

    return CF_SUCCESS;
}


static void FreeX509CertRevokedParams(HcfX509CertRevokedParams *&param)
{
    if (param == nullptr) {
        return;
    }

    CfFree(param->revocationFlags.data);
    CfFree(param->crls.data);
    FreeCfBlobArray(param->ocspResponses.data, param->ocspResponses.count);
    CfFree(param);

    param = nullptr;
}

void FreeX509CertValidatorParams(HcfX509CertValidatorParams &param)
{
    CfFree(param.untrustedCerts.data);
    CfFree(param.trustedCerts.data);
    CfFree(param.date);
    CfFree(param.ignoreErrs.data);
    NapiFreeStringArray(param.hostnames);
    NapiFreeStringArray(param.emailAddresses);
    CfFree(param.keyUsage.data);
    CfBlobDataFree(&param.userId);
    FreeX509CertRevokedParams(param.revokedParams);

    (void)memset_s(&param, sizeof(HcfX509CertValidatorParams), 0, sizeof(HcfX509CertValidatorParams));
}

} // namespace CertFramework
} // namespace OHOS
