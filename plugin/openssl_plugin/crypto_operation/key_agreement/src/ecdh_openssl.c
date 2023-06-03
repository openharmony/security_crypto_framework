/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#include "ecdh_openssl.h"

#include <openssl/bio.h>
#include <openssl/err.h>

#include "algorithm_parameter.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

typedef struct {
    HcfKeyAgreementSpi base;
} HcfKeyAgreementSpiEcdhOpensslImpl;

static EVP_PKEY *AssignEcKeyToPkey(EC_KEY *ecKey)
{
    EVP_PKEY *pKey = Openssl_EVP_PKEY_new();
    if (pKey == NULL) {
        HcfPrintOpensslError();
        return NULL;
    }
    if (Openssl_EVP_PKEY_assign_EC_KEY(pKey, ecKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_free(pKey);
        return NULL;
    }
    return pKey;
}

static EVP_PKEY *NewPKeyByEccPubKey(HcfOpensslEccPubKey *publicKey)
{
    EC_KEY *ecKey = Openssl_EC_KEY_dup(publicKey->ecKey);
    if (ecKey == NULL) {
        return NULL;
    }
    EVP_PKEY *res = AssignEcKeyToPkey(ecKey);
    if (res == NULL) {
        Openssl_EC_KEY_free(ecKey);
    }
    return res;
}

static EVP_PKEY *NewPKeyByEccPriKey(HcfOpensslEccPriKey *privateKey)
{
    EC_KEY *ecKey = Openssl_EC_KEY_dup(privateKey->ecKey);
    if (ecKey == NULL) {
        return NULL;
    }
    EVP_PKEY *res = AssignEcKeyToPkey(ecKey);
    if (res == NULL) {
        Openssl_EC_KEY_free(ecKey);
    }
    return res;
}

static HcfResult EcdhDerive(EVP_PKEY *priPKey, EVP_PKEY *pubPKey, HcfBlob *returnSecret)
{
    EVP_PKEY_CTX *ctx = Openssl_EVP_PKEY_CTX_new(priPKey, NULL);
    if (ctx == NULL) {
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EVP_PKEY_derive_init(ctx) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_CTX_free(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EVP_PKEY_derive_set_peer(ctx, pubPKey) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_CTX_free(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    size_t maxLen;
    if (Openssl_EVP_PKEY_derive(ctx, NULL, &maxLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_CTX_free(ctx);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    uint8_t *secretData = (uint8_t *)HcfMalloc(maxLen, 0);
    if (secretData == NULL) {
        LOGE("Failed to allocate secretData memory!");
        Openssl_EVP_PKEY_CTX_free(ctx);
        return HCF_ERR_MALLOC;
    }
    size_t actualLen = maxLen;
    if (Openssl_EVP_PKEY_derive(ctx, secretData, &actualLen) != HCF_OPENSSL_SUCCESS) {
        HcfPrintOpensslError();
        Openssl_EVP_PKEY_CTX_free(ctx);
        HcfFree(secretData);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_EVP_PKEY_CTX_free(ctx);
    if (actualLen > maxLen) {
        LOGE("signature data too long.");
        HcfFree(secretData);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    returnSecret->data = secretData;
    returnSecret->len = actualLen;
    return HCF_SUCCESS;
}

static const char *GetEcdhClass(void)
{
    return "HcfKeyAgreement.HcfKeyAgreementSpiEcdhOpensslImpl";
}

static void DestroyEcdh(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetEcdhClass())) {
        return;
    }
    HcfFree(self);
}

static HcfResult EngineGenerateSecret(HcfKeyAgreementSpi *self, HcfPriKey *priKey,
    HcfPubKey *pubKey, HcfBlob *returnSecret)
{
    if ((self == NULL) || (priKey == NULL) || (pubKey == NULL) || (returnSecret == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if ((!IsClassMatch((HcfObjectBase *)self, GetEcdhClass())) ||
        (!IsClassMatch((HcfObjectBase *)priKey, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) ||
        (!IsClassMatch((HcfObjectBase *)pubKey, HCF_OPENSSL_ECC_PUB_KEY_CLASS))) {
        return HCF_INVALID_PARAMS;
    }

    EVP_PKEY *priPKey = NewPKeyByEccPriKey((HcfOpensslEccPriKey *)priKey);
    if (priPKey == NULL) {
        LOGE("Gen EVP_PKEY priKey failed");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EVP_PKEY *pubPKey = NewPKeyByEccPubKey((HcfOpensslEccPubKey *)pubKey);
    if (pubPKey == NULL) {
        LOGE("Gen EVP_PKEY pubKey failed");
        EVP_PKEY_free(priPKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult res = EcdhDerive(priPKey, pubPKey, returnSecret);
    Openssl_EVP_PKEY_free(priPKey);
    Openssl_EVP_PKEY_free(pubPKey);
    return res;
}

HcfResult HcfKeyAgreementSpiEcdhCreate(HcfKeyAgreementParams *params, HcfKeyAgreementSpi **returnObj)
{
    if ((params == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    HcfKeyAgreementSpiEcdhOpensslImpl *returnImpl = (HcfKeyAgreementSpiEcdhOpensslImpl *)HcfMalloc(
        sizeof(HcfKeyAgreementSpiEcdhOpensslImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEcdhClass;
    returnImpl->base.base.destroy = DestroyEcdh;
    returnImpl->base.engineGenerateSecret = EngineGenerateSecret;

    *returnObj = (HcfKeyAgreementSpi *)returnImpl;
    return HCF_SUCCESS;
}
