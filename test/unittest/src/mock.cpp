/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <cstdlib>
#include "mock.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfMock *g_mock = nullptr;
void SetMock(HcfMock *mock)
{
    g_mock = mock;
}

void ResetMock(void)
{
    g_mock = nullptr;
}

void *__wrap_HcfMalloc(uint32_t size, char val)
{
    if (g_mock != nullptr) {
        return g_mock->HcfMalloc(size, val);
    }
    return __real_HcfMalloc(size, val);
}

int __wrap_OpensslEvpMdCtxSize(const EVP_MD_CTX *ctx)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpMdCtxSize(ctx);
    }
    return __real_OpensslEvpMdCtxSize(ctx);
}

bool __wrap_HcfIsClassMatch(const HcfObjectBase *obj, const char *className)
{
    if (g_mock != nullptr) {
        return g_mock->HcfIsClassMatch(obj, className);
    }
    return __real_HcfIsClassMatch(obj, className);
}

bool __wrap_HcfIsStrValid(const char *str, uint32_t maxLen)
{
    if (g_mock != nullptr) {
        return g_mock->HcfIsStrValid(str, maxLen);
    }
    return __real_HcfIsStrValid(str, maxLen);
}

int __wrap_OpensslEvpDigestInitEx(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    if (g_mock != nullptr) {
        return g_mock->OpensslEvpDigestInitEx(ctx, type, impl);
    }
    return __real_OpensslEvpDigestInitEx(ctx, type, impl);
}

#ifdef __cplusplus
} /* extern "C" */
#endif
