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


#include "crypto_sym_key.h"
#include "crypto_common.h"
#include "sym_key_generator.h"
#include "result.h"
#include "blob.h"
#include "object_base.h"
#include "native_common.h"


struct OH_CryptoSymKeyGenerator {
    HcfObjectBase base;

    /** Generate symmetric key object */
    HcfResult (*generateSymKey)(HcfSymKeyGenerator *self, HcfSymKey **symKey);

    /** Convert byte data to symmetric key object */
    HcfResult (*convertSymKey)(HcfSymKeyGenerator *self, const HcfBlob *key, HcfSymKey **symKey);

    /** Get the algorithm name of the current these key generator objects */
    const char *(*getAlgoName)(HcfSymKeyGenerator *self);
};

struct OH_CryptoSymKey {
    HcfKey key;

    void (*clearMem)(HcfSymKey *self);
};

OH_Crypto_ErrCode OH_CryptoSymKeyGenerator_Create(const char *algoName, OH_CryptoSymKeyGenerator **ctx)
{
    if (ctx == NULL) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = HcfSymKeyGeneratorCreate(algoName, (HcfSymKeyGenerator **)ctx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoSymKeyGenerator_Generate(OH_CryptoSymKeyGenerator *ctx, OH_CryptoSymKey **keyCtx)
{
    if ((ctx == NULL) || (keyCtx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->generateSymKey((HcfSymKeyGenerator *)ctx, (HcfSymKey **)keyCtx);
    return GetOhCryptoErrCode(ret);
}

OH_Crypto_ErrCode OH_CryptoSymKeyGenerator_Convert(OH_CryptoSymKeyGenerator *ctx,
    const Crypto_DataBlob *keyData, OH_CryptoSymKey **keyCtx)
{
    if ((ctx == NULL) || (keyData == NULL) || (keyCtx == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = ctx->convertSymKey((HcfSymKeyGenerator *)ctx, (HcfBlob *)keyData, (HcfSymKey **)keyCtx);
    return GetOhCryptoErrCode(ret);
}

const char *OH_CryptoSymKeyGenerator_GetAlgoName(OH_CryptoSymKeyGenerator *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    return ctx->getAlgoName((HcfSymKeyGenerator *)ctx);
}

void OH_CryptoSymKeyGenerator_Destroy(OH_CryptoSymKeyGenerator *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->base.destroy((HcfObjectBase *)ctx);
}

const char *OH_CryptoSymKey_GetAlgoName(OH_CryptoSymKey *keyCtx)
{
    if (keyCtx == NULL) {
        return NULL;
    }
    return keyCtx->key.getAlgorithm((HcfKey *)keyCtx);
}

OH_Crypto_ErrCode OH_CryptoSymKey_GetKeyData(OH_CryptoSymKey *keyCtx, Crypto_DataBlob *out)
{
    if ((keyCtx == NULL) || (out == NULL)) {
        return CRYPTO_INVALID_PARAMS;
    }
    HcfResult ret = keyCtx->key.getEncoded((HcfKey *)keyCtx, (HcfBlob *)out);
    return GetOhCryptoErrCode(ret);
}

void OH_CryptoSymKey_Destroy(OH_CryptoSymKey *keyCtx)
{
    if (keyCtx == NULL) {
        return;
    }
    keyCtx->key.base.destroy((HcfObjectBase *)keyCtx);
}
