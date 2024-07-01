/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "digest.h"
#include "result.h"
#include "md.h"
#include "crypto_common.h"

struct OH_CryptoDigest {
    HcfObjectBase base;

    HcfResult (*update)(HcfMd *self, HcfBlob *input);

    HcfResult (*doFinal)(HcfMd *self, HcfBlob *output);

    uint32_t (*getMdLength)(HcfMd *self);

    const char *(*getAlgoName)(HcfMd *self);
};

Crypto_Result OH_CryptoDigest_Create(const char *algoName, OH_CryptoDigest **md)
{
    return (Crypto_Result)HcfMdCreate(algoName, (HcfMd **)md);
}

Crypto_Result OH_CryptoDigest_Update(OH_CryptoDigest *ctx, Crypto_DataBlob *in)
{
    return (Crypto_Result)ctx->update((HcfMd *)ctx, (HcfBlob *)in);
}

Crypto_Result OH_CryptoDigest_Final(OH_CryptoDigest *ctx, Crypto_DataBlob *out)
{
    return (Crypto_Result)ctx->doFinal((HcfMd *)ctx, (HcfBlob *)out);
}

uint32_t OH_CryptoDigest_GetLength(OH_CryptoDigest *ctx)
{
    return ctx->getMdLength((HcfMd *)ctx);
}

const char *OH_CryptoDigest_GetAlgoName(OH_CryptoDigest *ctx)
{
    return ctx->getAlgoName((HcfMd *)ctx);
}

void OH_DigestCrypto_Destroy(OH_CryptoDigest *ctx)
{
    return ctx->base.destroy((HcfObjectBase *)ctx);
}