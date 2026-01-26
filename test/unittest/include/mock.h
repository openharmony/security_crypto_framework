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

#ifndef MOCK_H
#define MOCK_H

#include <gmock/gmock.h>
#include <cstdint>
#include <openssl/types.h>

#include "object_base.h"

#ifdef __cplusplus
extern "C" {
#endif

class HcfMock final {
public:
    MOCK_METHOD(void *, HcfMalloc, (uint32_t, char));
    MOCK_METHOD(int, OpensslEvpMdCtxSize, (const EVP_MD_CTX *));
    MOCK_METHOD(bool, HcfIsClassMatch, (const HcfObjectBase *, const char *));
    MOCK_METHOD(bool, HcfIsStrValid, (const char *, uint32_t));
    MOCK_METHOD(int, OpensslEvpDigestInitEx, (EVP_MD_CTX *, const EVP_MD *, ENGINE *));
};

extern HcfMock *g_mock;
void SetMock(HcfMock *mock);
void ResetMock(void);

void *__real_HcfMalloc(uint32_t size, char val);
int __real_OpensslEvpMdCtxSize(const EVP_MD_CTX *ctx);
bool __real_HcfIsClassMatch(const HcfObjectBase *obj, const char *className);
bool __real_HcfIsStrValid(const char *str, uint32_t maxLen);
int __real_OpensslEvpDigestInitEx(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
