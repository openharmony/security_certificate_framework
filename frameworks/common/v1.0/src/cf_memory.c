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

#include "cf_memory.h"

#include "cf_log.h"
#include "securec.h"

void *CfMalloc(uint32_t size, char val)
{
    if ((size == 0) || (size > MAX_MEMORY_SIZE)) {
        LOGE("malloc size is invalid");
        return NULL;
    }
    void *addr = malloc(size);
    if (addr != NULL) {
        (void)memset_s(addr, size, val, size);
    }
    return addr;
}

void CfFree(void *addr)
{
    if (addr != NULL) {
        free(addr);
    }
}
