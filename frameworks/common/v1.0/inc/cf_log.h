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

#ifndef CF_LOG_H
#define CF_LOG_H

#include <stdint.h>
#include <stdlib.h>

#ifdef HILOG_ENABLE

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#include "hilog/log.h"

#undef LOG_TAG
#define LOG_TAG "CertFramework"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F17 /* CertFramework's domain id */

#define CF_LOG_D(fmt, ...) \
HILOG_DEBUG(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define CF_LOG_I(fmt, ...) \
HILOG_INFO(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define CF_LOG_W(fmt, ...) \
HILOG_WARN(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define CF_LOG_E(fmt, ...) \
HILOG_ERROR(LOG_CORE, "%{public}s[%{public}u]: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#else

#include <stdio.h>

#define CF_LOG_D(fmt, ...) printf("[CertificateFramework][D][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define CF_LOG_I(fmt, ...) printf("[CertificateFramework][I][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define CF_LOG_W(fmt, ...) printf("[CertificateFramework][W][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define CF_LOG_E(fmt, ...) printf("[CertificateFramework][E][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)

#endif

#define LOGD CF_LOG_D
#define LOGI CF_LOG_I
#define LOGW CF_LOG_W
#define LOGE CF_LOG_E

#endif
