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

#ifndef NAPI_COMMON_H
#define NAPI_COMMON_H

#include "cf_blob.h"
#include "cf_result.h"
#include "cf_type.h"
#include "cert_chain_validator.h"
#include "napi_cert_defines.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace CertFramework {
constexpr int32_t CALLBACK_NUM = 2;

struct AsyncContext {
    AsyncType asyncType = ASYNC_TYPE_CALLBACK;
    napi_value promise = nullptr;
    napi_ref callback = nullptr;
    napi_deferred deferred = nullptr;
    napi_async_work asyncWork = nullptr;
    napi_ref paramRef = nullptr;
    int32_t errCode = 0;
    const char *errMsg = nullptr;
};
using AsyncCtx = AsyncContext *;

bool GetCallbackAndPromise(napi_env env, AsyncCtx async, napi_value arg);
void ReturnJSResult(napi_env env, AsyncCtx async, napi_value result);
napi_value GetResourceName(napi_env env, const char *name);
napi_value ConvertBlobArrayToNapiValue(napi_env env,  const CfParamSet *paramSet);
int32_t GetBlobArrayFromParamSet(const CfParamSet *paramSet, CfArray *outArray);
void FreeAsyncContext(napi_env env, AsyncCtx &ctx);

CfResult NapiGetProperty(napi_env env, napi_value arg, const char *name, bool mustExist, napi_value &value);
CfResult NapiGetBoolValue(napi_env env, napi_value arg, const char *name, bool &value);
CfResult NapiGetStringValue(napi_env env, napi_value arg, const char *name, char *&value);
CfResult NapiGetBlobValue(napi_env env, napi_value arg, const char *name, CfBlob &value);
CfResult NapiGetArrayBaseInfo(napi_env env, napi_value arg, const char *name,
    napi_value &arrayObj, uint32_t &length, uint32_t maxLen = MAX_LEN_OF_ARRAY);
CfResult NapiGetStringArray(napi_env env, napi_value arg, const char *name, HcfStringArray &value);
CfResult NapiGetBlobArray(napi_env env, napi_value arg, const char *name, CfBlobArray &value);
CfResult NapiGetInt32Array(napi_env env, napi_value arg, const char *name, HcfInt32Array &value);
CfResult NapiGetInt32Ex(napi_env env, napi_value arg, const char *name, int32_t &value);
void NapiFreeStringArray(HcfStringArray &array);

inline napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

inline napi_value NapiGetInt32(napi_env env, int32_t value)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_int32(env, value, &result));
    return result;
}
} // namespace CertFramework
} // namespace OHOS

#endif // NAPI_COMMON_H