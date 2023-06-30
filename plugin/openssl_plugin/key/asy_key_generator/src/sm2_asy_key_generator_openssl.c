/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "sm2_asy_key_generator_openssl.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

#define OPENSSL_SM2_KEY_GENERATOR_CLASS "OPENSSL.SM2.KEY_GENERATOR_CLASS"
#define OPENSSL_SM2_ALGORITHM "SM2"
#define OPENSSL_SM2_PUB_KEY_FORMAT "X.509"
#define OPENSSL_SM2_PRI_KEY_FORMAT "PKCS#8"

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t curveId;
} HcfAsyKeyGeneratorSpiOpensslSm2Impl;

static HcfResult NewEcKeyPair(int32_t curveId, EC_KEY **returnEcKey)
{
    EC_KEY *ecKey = Openssl_EC_KEY_new_by_curve_name(curveId);
    if (ecKey == NULL) {
        LOGE("new ec key failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EC_KEY_generate_key(ecKey) <= 0) {
        LOGE("generate ec key failed.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EC_KEY_check_key(ecKey) <= 0) {
        LOGE("check key fail.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return HCF_SUCCESS;
}

static const char *GetSm2KeyPairGeneratorClass(void)
{
    return OPENSSL_SM2_KEY_GENERATOR_CLASS;
}

static const char *GetSm2KeyPairClass(void)
{
    return HCF_OPENSSL_SM2_KEY_PAIR_CLASS;
}

static const char *GetSm2PubKeyClass(void)
{
    return HCF_OPENSSL_SM2_PUB_KEY_CLASS;
}

static const char *GetSm2PriKeyClass(void)
{
    return HCF_OPENSSL_SM2_PRI_KEY_CLASS;
}

static void DestroySm2KeyPairGenerator(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, self->getClass())) {
        return;
    }
    HcfFree(self);
}

static void DestroySm2PubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, self->getClass())) {
        return;
    }
    HcfOpensslSm2PubKey *impl = (HcfOpensslSm2PubKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl);
}

static void DestroySm2PriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, self->getClass())) {
        return;
    }
    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl);
}

static void DestroySm2KeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, self->getClass())) {
        return;
    }
    HcfOpensslSm2KeyPair *impl = (HcfOpensslSm2KeyPair *)self;
    if (impl->base.pubKey != NULL) {
        DestroySm2PubKey((HcfObjectBase *)impl->base.pubKey);
        impl->base.pubKey = NULL;
    }
    if (impl->base.priKey != NULL) {
        DestroySm2PriKey((HcfObjectBase *)impl->base.priKey);
        impl->base.priKey = NULL;
    }
    HcfFree(impl);
}

static const char *GetSm2PubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PUB_KEY_CLASS)) {
        LOGE("Invalid SM2 public key class for algorithm");
        return NULL;
    }
    return OPENSSL_SM2_ALGORITHM;
}

static const char *GetSm2PriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PRI_KEY_CLASS)) {
        LOGE("Invalid SM2 private key class for algorithm");
        return NULL;
    }
    return OPENSSL_SM2_ALGORITHM;
}

static const char *GetSm2PubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PUB_KEY_CLASS)) {
        LOGE("Invalid SM2 public key class for format");
        return NULL;
    }
    return OPENSSL_SM2_PUB_KEY_FORMAT;
}

static const char *GetSm2PriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PRI_KEY_CLASS)) {
        LOGE("Invalid SM2 private key class for format");
        return NULL;
    }
    return OPENSSL_SM2_PRI_KEY_FORMAT;
}

static HcfResult GetSm2PubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PUB_KEY_CLASS)) {
        LOGE("Invalid SM2 public key class for encode");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslSm2PubKey *impl = (HcfOpensslSm2PubKey *)self;
    if (impl->curveId != 0) {
        LOGE("have a curveId");
        Openssl_EC_KEY_set_asn1_flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        Openssl_EC_KEY_set_asn1_flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }

    unsigned char *returnData = NULL;
    int returnDataLen = Openssl_i2d_EC_PUBKEY(impl->ecKey, &returnData);
    if (returnDataLen <= 0) {
        LOGE("i2d_EC_PUBKEY fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult GetSm2PriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_SM2_PRI_KEY_CLASS)) {
        LOGE("Invalid SM2 private key class for encode");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    if (impl->curveId != 0) {
        LOGD("have a curveId");
        Openssl_EC_KEY_set_asn1_flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        Openssl_EC_KEY_set_asn1_flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }
    // keep consistence of 3.2
    Openssl_EC_KEY_set_enc_flags(impl->ecKey, EC_PKEY_NO_PUBKEY);
    // if the convert key has no pubKey, it will generate pub key automatically,
    // and set the no pubKey flag to ensure the consistency of blob.
    unsigned char *returnData = NULL;
    int returnDataLen = Openssl_i2d_ECPrivateKey(impl->ecKey, &returnData);
    if (returnDataLen <= 0) {
        LOGE("i2d_ECPrivateKey fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static void Sm2PriKeyClearMem(HcfPriKey *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.base.getClass())) {
        return;
    }
    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
}

static HcfResult PackSm2PubKey(int32_t curveId, EC_KEY *ecKey, HcfOpensslSm2PubKey **returnObj)
{
    HcfOpensslSm2PubKey *returnPubKey = (HcfOpensslSm2PubKey *)HcfMalloc(sizeof(HcfOpensslSm2PubKey), 0);
    if (returnPubKey == NULL) {
        LOGE("Failed to allocate returnPubKey memory!");
        return HCF_ERR_MALLOC;
    }

    returnPubKey->base.base.base.destroy = DestroySm2PubKey;
    returnPubKey->base.base.base.getClass = GetSm2PubKeyClass;
    returnPubKey->base.base.getAlgorithm = GetSm2PubKeyAlgorithm;
    returnPubKey->base.base.getEncoded = GetSm2PubKeyEncoded;
    returnPubKey->base.base.getFormat = GetSm2PubKeyFormat;
    returnPubKey->curveId = curveId;
    returnPubKey->ecKey = ecKey;

    *returnObj = returnPubKey;
    return HCF_SUCCESS;
}

static HcfResult PackSm2PriKey(int32_t curveId, EC_KEY *ecKey, HcfOpensslSm2PriKey **returnObj)
{
    HcfOpensslSm2PriKey *returnPriKey = (HcfOpensslSm2PriKey *)HcfMalloc(sizeof(HcfOpensslSm2PriKey), 0);
    if (returnPriKey == NULL) {
        LOGE("Failed to allocate returnPriKey memory!");
        return HCF_ERR_MALLOC;
    }

    returnPriKey->base.base.base.destroy = DestroySm2PriKey;
    returnPriKey->base.base.base.getClass = GetSm2PriKeyClass;
    returnPriKey->base.base.getAlgorithm = GetSm2PriKeyAlgorithm;
    returnPriKey->base.base.getEncoded = GetSm2PriKeyEncoded;
    returnPriKey->base.base.getFormat = GetSm2PriKeyFormat;
    returnPriKey->base.clearMem = Sm2PriKeyClearMem;
    returnPriKey->curveId = curveId;
    returnPriKey->ecKey = ecKey;

    *returnObj = returnPriKey;
    return HCF_SUCCESS;
}

static HcfResult PackSm2KeyPair(HcfOpensslSm2PubKey *pubKey, HcfOpensslSm2PriKey *priKey,
    HcfOpensslSm2KeyPair **returnObj)
{
    HcfOpensslSm2KeyPair *returnKeyPair = (HcfOpensslSm2KeyPair *)HcfMalloc(sizeof(HcfOpensslSm2KeyPair), 0);
    if (returnKeyPair == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    returnKeyPair->base.base.getClass = GetSm2KeyPairClass;
    returnKeyPair->base.base.destroy = DestroySm2KeyPair;
    returnKeyPair->base.pubKey = (HcfPubKey *)pubKey;
    returnKeyPair->base.priKey = (HcfPriKey *)priKey;

    *returnObj = returnKeyPair;
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPubKey(int32_t curveId, HcfBlob *pubKeyBlob, HcfOpensslSm2PubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    EC_KEY *ecKey = Openssl_d2i_EC_PUBKEY(NULL, &tmpData, pubKeyBlob->len);
    if (ecKey == NULL) {
        LOGE("d2i_EC_PUBKEY fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = PackSm2PubKey(curveId, ecKey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("CreateSm2PubKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPriKey(int32_t curveId, HcfBlob *priKeyBlob, HcfOpensslSm2PriKey **returnPriKey)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    EC_KEY *ecKey = Openssl_d2i_ECPrivateKey(NULL, &tmpData, priKeyBlob->len);
    if (ecKey == NULL) {
        LOGE("d2i_ECPrivateKey fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = PackSm2PriKey(curveId, ecKey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        Openssl_EC_KEY_free(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineConvertSm2Key(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        return HCF_INVALID_PARAMS;
    }
    bool pubKeyValid = IsBlobValid(pubKeyBlob);
    bool priKeyValid = IsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("The private key and public key cannot both be NULL.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    HcfResult ret = HCF_SUCCESS;
    HcfOpensslSm2PubKey *pubKey = NULL;
    HcfOpensslSm2PriKey *priKey = NULL;
    HcfOpensslSm2KeyPair *keyPair = NULL;
    do {
        if (pubKeyValid) {
            ret = ConvertEcPubKey(impl->curveId, pubKeyBlob, &pubKey);
            if (ret != HCF_SUCCESS) {
                break;
            }
        }
        if (priKeyValid) {
            ret = ConvertEcPriKey(impl->curveId, priKeyBlob, &priKey);
            if (ret != HCF_SUCCESS) {
                break;
            }
        }
        ret = PackSm2KeyPair(pubKey, priKey, &keyPair);
    } while (0);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return ret;
    }

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult CreateAndAssignKeyPair(const HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl,
    EC_KEY *ecKey, HcfKeyPair **returnObj)
{
    EC_KEY *ecPriKey = EC_KEY_dup(ecKey);
    if (ecPriKey == NULL) {
        LOGE("copy ecKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslSm2PriKey *priKey = NULL;
    HcfResult ret = PackSm2PriKey(impl->curveId, ecPriKey, &priKey);
    if (ret != HCF_SUCCESS) {
        Openssl_EC_KEY_free(ecPriKey);
        return ret;
    }
    HcfOpensslSm2PubKey *pubKey = NULL;
    EC_KEY *ecPubKey = EC_KEY_dup(ecKey);
    if (ecPubKey == NULL) {
        LOGE("copy ecKey fail.");
        HcfObjDestroy(priKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = PackSm2PubKey(impl->curveId, ecPubKey, &pubKey);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(priKey);
        Openssl_EC_KEY_free(ecPubKey);
        return ret;
    }

    HcfOpensslSm2KeyPair *returnKeyPair = NULL;
    ret = PackSm2KeyPair(pubKey, priKey, &returnKeyPair);
    if (ret != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
    }
    *returnObj = (HcfKeyPair *)returnKeyPair;
    return ret;
}

static HcfResult EngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnObj)
{
    if ((self == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, self->base.getClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = NewEcKeyPair(impl->curveId, &ecKey);
    if (ret == HCF_SUCCESS) {
        ret = CreateAndAssignKeyPair(impl, ecKey, returnObj);
        if (ret != HCF_SUCCESS) {
            LOGE("CreateAndAssignKeyPair failed.");
        }
        Openssl_EC_KEY_free(ecKey);
    }
    return ret;
}

HcfResult HcfAsyKeyGeneratorSpiSm2Create(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
{
    if (params == NULL || returnObj == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    int32_t curveId = 0;
    if (params->bits != 0) {
        if (GetOpensslCurveId(params->bits, &curveId) != HCF_SUCCESS) {
            return HCF_INVALID_PARAMS;
        }
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *returnImpl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiOpensslSm2Impl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetSm2KeyPairGeneratorClass;
    returnImpl->base.base.destroy = DestroySm2KeyPairGenerator;
    returnImpl->base.engineConvertKey = EngineConvertSm2Key;
    returnImpl->base.engineGenerateKeyPair = EngineGenerateKeyPair;
    returnImpl->curveId = curveId;

    *returnObj = (HcfAsyKeyGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
