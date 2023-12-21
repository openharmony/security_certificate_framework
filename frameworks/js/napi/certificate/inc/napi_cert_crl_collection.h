/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef NAPI_CERT_CRL_COLLECTION_H
#define NAPI_CERT_CRL_COLLECTION_H

#include <string>
#include <vector>
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_x509_certificate.h"
#include "napi_x509_crl.h"
#include "cert_crl_collection.h"
#include "cf_result.h"

namespace OHOS {
namespace CertFramework {

class NapiCertCRLCollection {
public:
    explicit NapiCertCRLCollection(HcfCertCrlCollection *collection);
    ~NapiCertCRLCollection();

    static void DefineCertCRLCollectionJSClass(napi_env env, napi_value exports);
    static napi_value CreateCertCRLCollection(napi_env env);

    napi_value SelectCerts(napi_env env, napi_callback_info info);
    napi_value SelectCRLs(napi_env env, napi_callback_info info);
    napi_value SelectCRLsRet(napi_env env, const HcfX509CrlArray *certs);

    HcfCertCrlCollection *GetCertCrlCollection()
    {
        return certCrlCollection_;
    }

    static thread_local napi_ref classRef_;

private:
    HcfCertCrlCollection *certCrlCollection_;
};

} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_CERT_CRL_COLLECTION_H