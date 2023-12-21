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

#ifndef NAPI_X509_CERT_CHAIN_H
#define NAPI_X509_CERT_CHAIN_H

#include <string>

#include "cf_api.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi_x509_certificate.h"
#include "x509_cert_chain.h"

namespace OHOS {
namespace CertFramework {
class NapiX509CertChain {
public:
    explicit NapiX509CertChain(HcfCertChain *certChain);
    ~NapiX509CertChain();

    static void DefineX509CertChainJsClass(napi_env env, napi_value exports);
    napi_value Validate(napi_env env, napi_callback_info info);

    HcfCertChain *GetCertChain()
    {
        return certChain_;
    }

    static thread_local napi_ref classRef_;

private:
    HcfCertChain *certChain_ = nullptr;
};
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_X509_CERT_CHAIN_H