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

#include "x509_cert_chain.h"

#include <securec.h>

#include "cf_blob.h"
#include "cf_log.h"
#include "cf_memory.h"
#include "cf_result.h"
#include "config.h"
#include "utils.h"
#include "x509_cert_chain_openssl.h"
#include "x509_cert_chain_spi.h"
#include "x509_certificate.h"

#define LV_LENGTH_LEN sizeof(uint16_t)
#define MAX_CERT_PATH_DATA_LEM 8192

typedef CfResult (*CertChainSpiCreateByEncFunc)(const CfEncodingBlob *, HcfX509CertChainSpi **);
typedef CfResult (*CertChainSpiCreateByArrFunc)(const HcfX509CertificateArray *, HcfX509CertChainSpi **);

typedef struct {
    HcfCertChain base;
    HcfX509CertChainSpi *spiObj;
} CertChainImpl;

typedef struct {
    CertChainSpiCreateByEncFunc createByEncFunc;
    CertChainSpiCreateByArrFunc createByArrFunc;
} HcfCertChainFuncSet;

typedef struct {
    char *certType;
    HcfCertChainFuncSet funcSet;
} HcfCertChainAbility;

static const HcfCertChainAbility X509_CERT_CHAIN_ABILITY_SET[] = { { "X509",
    { HcfX509CertChainByEncSpiCreate, HcfX509CertChainByArrSpiCreate } } };

static const HcfCertChainFuncSet *FindAbility(const char *certType)
{
    if (certType == NULL) {
        LOGE("CertType is null!");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(X509_CERT_CHAIN_ABILITY_SET) / sizeof(HcfCertChainAbility); i++) {
        if (strcmp(X509_CERT_CHAIN_ABILITY_SET[i].certType, certType) == 0) {
            return &(X509_CERT_CHAIN_ABILITY_SET[i].funcSet);
        }
    }
    LOGE("Cert not support! [cert]: %s", certType);
    return NULL;
}

static const char *GetCertChainClass(void)
{
    return "HcfCertChain";
}

static void DestroyCertChain(CfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    if (!IsClassMatch(self, GetCertChainClass())) {
        LOGE("Class is not match.");
        return;
    }
    CertChainImpl *impl = (CertChainImpl *)self;
    CfObjDestroy(impl->spiObj);
    CfFree(impl);
}

static CfResult GetCertList(HcfCertChain *self, HcfX509CertificateArray *out)
{
    if ((self == NULL) || (out == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetCertChainClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }

    return ((CertChainImpl *)self)->spiObj->engineGetCertList(((CertChainImpl *)self)->spiObj, out);
}

static CfResult Validate(
    HcfCertChain *self, const HcfX509CertChainValidateParams *params, HcfX509CertChainValidateResult *result)
{
    if ((self == NULL) || (params == NULL) || (result == NULL)) {
        LOGE("Invalid input parameter.");
        return CF_INVALID_PARAMS;
    }
    if (!IsClassMatch((CfObjectBase *)self, GetCertChainClass())) {
        LOGE("Class is not match.");
        return CF_INVALID_PARAMS;
    }

    return ((CertChainImpl *)self)->spiObj->engineValidate(((CertChainImpl *)self)->spiObj, params, result);
}

CfResult HcfCertChainCreate(
    const CfEncodingBlob *inStream, const HcfX509CertificateArray *inCerts, HcfCertChain **returnObj)
{
    CF_LOG_I("enter");
    if ((inStream == NULL && inCerts == NULL) || (inStream != NULL && inCerts != NULL) || returnObj == NULL) {
        LOGE("invalid param!");
        return CF_INVALID_PARAMS;
    }

    const HcfCertChainFuncSet *func = FindAbility("X509");
    if (func == NULL) {
        LOGE("Func is null!");
        return CF_NOT_SUPPORT;
    }

    HcfX509CertChainSpi *spiObj = NULL;
    CfResult res = CF_SUCCESS;
    if (inStream != NULL) {
        res = func->createByEncFunc(inStream, &spiObj);
    } else {
        res = func->createByArrFunc(inCerts, &spiObj);
    }
    if (res != CF_SUCCESS) {
        LOGE("Failed to create certChain spi object!");
        return res;
    }
    CertChainImpl *impl = (CertChainImpl *)HcfMalloc(sizeof(CertChainImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate return memory!");
        CfObjDestroy(spiObj);
        return CF_ERR_MALLOC;
    }
    impl->base.base.destroy = DestroyCertChain;
    impl->base.base.getClass = GetCertChainClass;
    impl->base.getCertList = GetCertList;
    impl->base.validate = Validate;
    impl->spiObj = spiObj;

    *returnObj = (HcfCertChain *)impl;
    return CF_SUCCESS;
}