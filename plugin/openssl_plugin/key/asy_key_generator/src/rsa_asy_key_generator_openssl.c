/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "rsa_asy_key_generator_openssl.h"
#include "algorithm_parameter.h"
#include "asy_key_generator_spi.h"
#include "log.h"

#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "rsa_openssl_common.h"
#include "securec.h"
#include "string.h"
#include "utils.h"

#define OPENSSL_BITS_PER_BYTE 8
#define OPENSSL_RSA_KEYPAIR_CNT 3
#define OPENSSL_RSA_KEYGEN_DEFAULT_PRIMES 2
#define MAX_KEY_SIZE 8192
#define MIN_KEY_SIZE 512

enum OpensslRsaKeySize {
    OPENSSL_RSA_KEY_SIZE_512 = 512,
    OPENSSL_RSA_KEY_SIZE_768 = 768,
    OPENSSL_RSA_KEY_SIZE_1024 = 1024,
    OPENSSL_RSA_KEY_SIZE_2048 = 2048,
    OPENSSL_RSA_KEY_SIZE_3072 = 3072,
    OPENSSL_RSA_KEY_SIZE_4096 = 4096,
    OPENSSL_RSA_KEY_SIZE_8192 = 8192,
};

enum OpensslRsaPrimesSize {
    OPENSSL_RSA_PRIMES_SIZE_2 = 2,
    OPENSSL_RSA_PRIMES_SIZE_3 = 3,
    OPENSSL_RSA_PRIMES_SIZE_4 = 4,
    OPENSSL_RSA_PRIMES_SIZE_5 = 5,
};

typedef struct {
    uint32_t keySize;

    uint32_t nSize;

    uint32_t eSize;

    uint32_t dSize;
} KeyMaterialRsa;

typedef struct {
    int32_t bits;
    int32_t primes;
    BIGNUM *pubExp;
} HcfAsyKeyGenSpiRsaParams;

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    HcfAsyKeyGenSpiRsaParams *params;
} HcfAsyKeyGeneratorSpiRsaOpensslImpl;

static HcfResult CheckRsaKeyGenParams(HcfAsyKeyGenSpiRsaParams *params)
{
    if (params->pubExp == NULL) {
        LOGE("pubExp is NULL.");
        return HCF_INVALID_PARAMS;
    }
    switch (params->bits) {
        case OPENSSL_RSA_KEY_SIZE_512:
        case OPENSSL_RSA_KEY_SIZE_768:
            if (params->primes != OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %d to Keygen bits %d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_1024:
        case OPENSSL_RSA_KEY_SIZE_2048:
        case OPENSSL_RSA_KEY_SIZE_3072:
            if (params->primes > OPENSSL_RSA_PRIMES_SIZE_3 || params->primes < OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %d to Keygen bits %d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_4096:
            if (params->primes > OPENSSL_RSA_PRIMES_SIZE_4 || params->primes < OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %d to Keygen bits %d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        case OPENSSL_RSA_KEY_SIZE_8192:
            if (params->primes > OPENSSL_RSA_PRIMES_SIZE_5 || params->primes < OPENSSL_RSA_PRIMES_SIZE_2) {
                LOGE("Set invalid primes %d to Keygen bits %d.", params->primes, params->bits);
                return HCF_INVALID_PARAMS;
            }
            break;
        default:
            LOGE("The current bits %d is invalid.", params->bits);
            return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult DuplicatePkAndSkFromRSA(const RSA *rsa, RSA **pubKey, RSA **priKey)
{
    if (rsa == NULL) {
        LOGE("Rsa is NULL.");
        return HCF_INVALID_PARAMS;
    }
    if (DuplicateRsa(rsa, false, pubKey) != HCF_SUCCESS) {
        LOGE("Duplicate pubkey rsa fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (DuplicateRsa(rsa, true, priKey) != HCF_SUCCESS) {
        LOGE("Duplicate prikey rsa fail");
        RSA_free(*pubKey);
        *pubKey = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static const char *GetOpensslPubkeyClass()
{
    return OPENSSL_RSA_PUBKEY_CLASS;
}

static const char *GetOpensslPrikeyClass()
{
    return OPENSSL_RSA_PRIKEY_CLASS;
}

static const char *GetOpensslKeyPairClass()
{
    return OPENSSL_RSA_KEYPAIR_CLASS;
}

static void DestroyPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("PubKey is NULL.");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;
    RSA_free(impl->pk);
    impl->pk = NULL;
    HcfFree(self);
    self = NULL;
}

static void DestroyPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("PubKey is NULL.");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey*)self;
    if (impl->sk != NULL) {
        RSA_free(impl->sk);
        impl->sk = NULL;
    }
    HcfFree(impl);
    self = NULL;
}

static void DestroyKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("PubKey is NULL.");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_KEYPAIR_CLASS)) {
        LOGE("Class not match");
        return;
    }
    HcfOpensslRsaKeyPair *impl = (HcfOpensslRsaKeyPair*)self;
    OH_HCF_ObjDestroy((HcfObjectBase *)impl->base.priKey);
    impl->base.priKey = NULL;
    OH_HCF_ObjDestroy((HcfObjectBase *)impl->base.pubKey);
    impl->base.pubKey = NULL;
    HcfFree(self);
    self = NULL;
}

static HcfResult RsaSaveKeyMaterial(const RSA *rsa, const uint32_t keySize, HcfBlob *key, bool needPrivate)
{
    const uint32_t keyByteLen = keySize / OPENSSL_BITS_PER_BYTE;
    const uint32_t rawMaterialLen = sizeof(KeyMaterialRsa) + keyByteLen * OPENSSL_RSA_KEYPAIR_CNT;
    uint8_t *rawMaterial = (uint8_t *)HcfMalloc(rawMaterialLen, 0);
    if (rawMaterial == NULL) {
        LOGE("Malloc rawMaterial fail.");
        return HCF_ERR_MALLOC;
    }
    KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)rawMaterial;
    keyMaterial->keySize = keySize;
    uint8_t *tmp_buff = (uint8_t *)HcfMalloc(sizeof(uint8_t) * keyByteLen, 0);
    if (tmp_buff == NULL) {
        HcfFree(rawMaterial);
        return HCF_ERR_MALLOC;
    }
    HcfResult ret = HCF_SUCCESS;
    uint32_t offset = sizeof(*keyMaterial);
    keyMaterial->nSize = (uint32_t)BN_bn2bin(RSA_get0_n(rsa), tmp_buff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->nSize) != HCF_SUCCESS) {
        LOGE("copy n fail");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR;
    }
    offset += keyMaterial->nSize;
    keyMaterial->eSize = (uint32_t)BN_bn2bin(RSA_get0_e(rsa), tmp_buff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->eSize) != HCF_SUCCESS) {
        LOGE("copy e fail");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR;
    }
    offset += keyMaterial->eSize;
    if (needPrivate) {
        keyMaterial->dSize = (uint32_t)BN_bn2bin(RSA_get0_d(rsa), tmp_buff);
        if (memcpy_s(rawMaterial + offset, keyByteLen, tmp_buff, keyMaterial->dSize) != HCF_SUCCESS) {
            LOGE("copy d fail");
            ret = HCF_ERR_CRYPTO_OPERATION;
            goto ERR;
        }
    }
    key->data = rawMaterial;
    key->len = sizeof(KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize;
    HcfFree(tmp_buff);
    return HCF_SUCCESS;
ERR:
    HcfFree(keyMaterial);
    HcfFree(tmp_buff);
    return ret;
}

static HcfResult GetPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Input params is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PUBKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPubKey *impl = (HcfOpensslRsaPubKey *)self;

    return RsaSaveKeyMaterial(impl->pk, impl->bits, returnBlob, false);
}

static HcfResult GetPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if (self == NULL || returnBlob == NULL) {
        LOGE("Key is null.");
        return HCF_INVALID_PARAMS;
    }

    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfOpensslRsaPriKey *impl = (HcfOpensslRsaPriKey *)self;

    return RsaSaveKeyMaterial(impl->sk, impl->bits, returnBlob, true);
}

static const char *GetKeyFormat()
{
    return OPENSSL_RSA_KEY_FORMAT;
}

static const char *GetAlgorithm()
{
    return OPENSSL_RSA_ALGORITHM;
}

static void ClearPriKeyMem(HcfPriKey *self)
{
    if (self == NULL) {
        LOGE("PriKey is NULL.");
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_PRIKEY_CLASS)) {
        LOGE("Class not match");
        return;
    }
    RSA_free(((HcfOpensslRsaPriKey *)self)->sk);
    ((HcfOpensslRsaPriKey *)self)->sk = NULL;
}

static HcfResult PackPubKey(RSA *rsaPubKey, uint32_t bits, HcfOpensslRsaPubKey **retPubKey)
{
    if (retPubKey == NULL || rsaPubKey == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    *retPubKey = (HcfOpensslRsaPubKey *)HcfMalloc(sizeof(HcfOpensslRsaPubKey), 0);
    if (*retPubKey == NULL) {
        LOGE("Malloc retPubKey fail");
        return HCF_ERR_MALLOC;
    }
    (*retPubKey)->pk = rsaPubKey;
    (*retPubKey)->bits = bits;
    (*retPubKey)->base.base.getAlgorithm = GetAlgorithm;
    (*retPubKey)->base.base.getEncoded = GetPubKeyEncoded;
    (*retPubKey)->base.base.getFormat = GetKeyFormat;
    (*retPubKey)->base.base.base.getClass = GetOpensslPubkeyClass;
    (*retPubKey)->base.base.base.destroy = DestroyPubKey;
    return HCF_SUCCESS;
}

static HcfResult PackPriKey(RSA *rsaPriKey, uint32_t bits, HcfOpensslRsaPriKey **retPriKey)
{
    if (retPriKey == NULL || rsaPriKey == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    *retPriKey = (HcfOpensslRsaPriKey *)HcfMalloc(sizeof(HcfOpensslRsaPriKey), 0);
    if (*retPriKey == NULL) {
        LOGE("Malloc retPriKey fail");
        return HCF_ERR_MALLOC;
    }
    (*retPriKey)->sk = rsaPriKey;
    (*retPriKey)->bits = bits;
    (*retPriKey)->base.clearMem = ClearPriKeyMem;
    (*retPriKey)->base.base.getAlgorithm = GetAlgorithm;
    (*retPriKey)->base.base.getEncoded = GetPriKeyEncoded;
    (*retPriKey)->base.base.getFormat = GetKeyFormat;
    (*retPriKey)->base.base.base.getClass = GetOpensslPrikeyClass;
    (*retPriKey)->base.base.base.destroy = DestroyPriKey;
    return HCF_SUCCESS;
}

static HcfResult PackKeyPair(RSA *rsa, uint32_t realBits, HcfOpensslRsaKeyPair **retKeyPair)
{
    if (retKeyPair == NULL || rsa == NULL) {
        LOGE("Invalid params");
        return HCF_INVALID_PARAMS;
    }
    RSA *pubKey = NULL, *priKey = NULL;
    if (DuplicatePkAndSkFromRSA(rsa, &pubKey, &priKey) != HCF_SUCCESS) {
        LOGE("DuplicatePkAndSkFromRSA fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    *retKeyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (*retKeyPair == NULL) {
        LOGE("Malloc keypair fail");
        RSA_free(pubKey);
        RSA_free(priKey);
        return HCF_ERR_MALLOC;
    }
    HcfOpensslRsaPriKey *priKeyImpl = NULL;
    HcfOpensslRsaPubKey *pubKeyImpl = NULL;
    ret = PackPubKey(pubKey, realBits, &pubKeyImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Pack pubKey fail.");
        goto ERR2;
    }
    ret = PackPriKey(priKey, realBits, &priKeyImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Pack priKey fail.");
        goto ERR1;
    }
    (*retKeyPair)->base.priKey = (HcfPriKey *)priKeyImpl;
    (*retKeyPair)->base.pubKey = (HcfPubKey *)pubKeyImpl;
    (*retKeyPair)->base.base.getClass = GetOpensslKeyPairClass;
    (*retKeyPair)->base.base.destroy = DestroyKeyPair;
    return HCF_SUCCESS;
ERR1:
    HcfFree(pubKeyImpl);
ERR2:
    RSA_free(pubKey);
    RSA_free(priKey);
    HcfFree(*retKeyPair);
    *retKeyPair = NULL;
    return ret;
}

static HcfResult GenerateKeyPairByOpenssl(HcfAsyKeyGenSpiRsaParams *params, HcfKeyPair **keyPair)
{
    // check input params is valid
    HcfResult  res = CheckRsaKeyGenParams(params);
    if (res != HCF_SUCCESS) {
        LOGE("Rsa CheckRsaKeyGenParams fail.");
        return HCF_INVALID_PARAMS;
    }
    // Generate keyPair RSA
    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        LOGE("new RSA fail.");
        return HCF_ERR_MALLOC;
    }
    LOGI("keygen bits is %d, primes is %d", params->bits, GetRealPrimes(params->primes));
    if (GetRealPrimes(params->primes) != OPENSSL_RSA_KEYGEN_DEFAULT_PRIMES) {
        if (RSA_generate_multi_prime_key(rsa, params->bits, GetRealPrimes(params->primes), params->pubExp, NULL)
            != HCF_OPENSSL_SUCCESS) {
            LOGE("Generate multi-primes rsa key fail");
            HcfPrintOpensslError();
            RSA_free(rsa);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        if (RSA_generate_key_ex(rsa, params->bits, params->pubExp, NULL) != HCF_OPENSSL_SUCCESS) {
            LOGE("Generate rsa key fail");
            HcfPrintOpensslError();
            RSA_free(rsa);
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }

    // devided to pk and sk;
    HcfOpensslRsaKeyPair *keyPairImpl = NULL;
    res = PackKeyPair(rsa, params->bits, &keyPairImpl);
    if (res != HCF_SUCCESS) {
        LOGE("Generate keyPair fail.");
        RSA_free(rsa);
        return res;
    }
    *keyPair = (HcfKeyPair *)keyPairImpl;
    RSA_free(rsa);
    LOGI("Generate keypair success.");
    return res;
}

static HcfResult EngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **keyPair)
{
    LOGI("EngineGenerateKeyPair start");
    if (self == NULL || keyPair == NULL) {
        LOGE("Invalid params.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)self;
    return GenerateKeyPairByOpenssl(impl->params, keyPair);
}

static const char *GetKeyGeneratorClass()
{
    return OPENSSL_RSA_GENERATOR_CLASS;
}

static void DestroyKeyGeneratorSpiImpl(HcfObjectBase *self)
{
    LOGI("DestroyKeyGeneratorSpiImpl start.");
    if (self == NULL) {
        LOGE("DestroyKeyGeneratorSpiImpl is null");
        return;
    }
    if (!IsClassMatch(self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return;
    }
    // destroy pubExp first.
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)self;
    if (impl->params != NULL && impl->params->pubExp != NULL) {
        BN_free(impl->params->pubExp);
    }
    HcfFree(impl->params);
    impl->params = NULL;
    HcfFree(self);
    self = NULL;
    LOGI("DestroyKeyGeneratorSpiImpl end.");
}

static HcfResult InitRsaKeyBuf(const KeyMaterialRsa *keyMaterial, HcfBlob *bufBlob)
{
    uint32_t maxSize;
    if (keyMaterial->nSize >= keyMaterial->eSize) {
        maxSize = keyMaterial->nSize;
    } else {
        maxSize = keyMaterial->eSize;
    }

    if (maxSize < keyMaterial->dSize) {
        maxSize = keyMaterial->dSize;
    }

    bufBlob->data = (uint8_t *)HcfMalloc(maxSize, 0);
    if (bufBlob->data == NULL) {
        LOGE("HcfMalloc failed!");
        return HCF_ERR_MALLOC;
    }
    bufBlob->len = maxSize;
    return HCF_SUCCESS;
}

static HcfResult ParseRsaBnFromBin(const HcfBlob *key, BIGNUM **n, BIGNUM **e, BIGNUM **d, const bool needPrivate)
{
    const KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)(key->data);
    HcfBlob bufBlob = { .len = 0, .data = NULL };
    HcfResult ret = InitRsaKeyBuf(keyMaterial, &bufBlob);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = HCF_SUCCESS;
    do {
        uint32_t offset = sizeof(*keyMaterial);
        if (memcpy_s(bufBlob.data, bufBlob.len, key->data + offset, keyMaterial->nSize) != HCF_SUCCESS) {
            LOGE("memcpy_s n bin data fail");
            ret = HCF_ERR_COPY;
            break;
        }
        *n = BN_bin2bn(bufBlob.data, keyMaterial->nSize, NULL);
        offset += keyMaterial->nSize;
        if (memcpy_s(bufBlob.data, bufBlob.len, key->data + offset, keyMaterial->eSize) != HCF_SUCCESS) {
            LOGE("memcpy_s e bin data fail");
            ret = HCF_ERR_COPY;
            break;
        }
        *e = BN_bin2bn(bufBlob.data, keyMaterial->eSize, NULL);
        offset += keyMaterial->eSize;
        *d = NULL;
        if (needPrivate) {
            if (memcpy_s(bufBlob.data, bufBlob.len, key->data + offset, keyMaterial->dSize) != HCF_SUCCESS) {
                LOGE("memcpy_s d bin data fail");
                ret = HCF_ERR_COPY;
                break;
            }
            *d = BN_bin2bn(bufBlob.data, keyMaterial->dSize, NULL);
        }
    } while (0);
    (void)memset_s(bufBlob.data, bufBlob.len, 0,
        (((keyMaterial->keySize) + OPENSSL_BITS_PER_BYTE - 1) / OPENSSL_BITS_PER_BYTE));
    HcfFree(bufBlob.data);
    return ret;
}

static RSA *InitRsaStructByBin(const HcfBlob *key, const bool needPrivateExponent)
{
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;

    RSA *rsa = NULL;
    do {
        if (ParseRsaBnFromBin(key, &n, &e, &d, needPrivateExponent) != HCF_SUCCESS) {
            LOGE("ParseRsaBnFromBin fail");
            break;
        }
        rsa = RSA_new();
        if (rsa != NULL) {
            if (RSA_set0_key(rsa, n, e, d) != HCF_OPENSSL_SUCCESS) {
                LOGE("set rsa Bn fail");
                HcfPrintOpensslError();
                RSA_free(rsa);
                rsa = NULL;
                break;
            }
        }
    } while (0);

    if (rsa == NULL) {
        BN_clear_free(n);
        BN_clear_free(e);
        BN_clear_free(d);
    }

    return rsa;
}

static HcfResult RsaCheckKeyMaterial(const HcfBlob *key)
{
    const KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)(key->data);
    if ((keyMaterial->keySize < MIN_KEY_SIZE) || (keyMaterial->keySize > MAX_KEY_SIZE)) {
        LOGE("Input keySize is invalid");
        return HCF_INVALID_PARAMS;
    }
    if (key->len != sizeof(KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize) {
        LOGE("Input len dismatch with data");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertPubKey(HcfBlob *pubKeyBlob, HcfOpensslRsaPubKey **pubkeyRet)
{
    if ((pubKeyBlob == NULL) || (pubKeyBlob->data == NULL)) {
        LOGE("PubKeyBlob is NULL.");
        return HCF_INVALID_PARAMS;
    }
    if (RsaCheckKeyMaterial(pubKeyBlob) != HCF_SUCCESS) {
        LOGE("check input key material fail");
        return HCF_INVALID_PARAMS;
    }

    RSA *rsaPk = InitRsaStructByBin(pubKeyBlob, false);
    if (rsaPk == NULL) {
        LOGE("Init rsaPk fail.");
        return HCF_ERR_MALLOC;
    }
    KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)(pubKeyBlob->data);
    HcfOpensslRsaPubKey *pubKey = NULL;
    HcfResult ret = PackPubKey(rsaPk, keyMaterial->keySize, &pubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("PackPubKey fail");
        goto ERR;
    }
    *pubkeyRet = pubKey;
    return ret;
ERR:
    RSA_free(rsaPk);
    return ret;
}

static HcfResult ConvertPriKey(HcfBlob *priKeyBlob, HcfOpensslRsaPriKey **priKeyRet)
{
    if (priKeyBlob == NULL || priKeyBlob->data == NULL) {
        LOGE("PriKeyBlob is NULL.");
        return HCF_INVALID_PARAMS;
    }
    if (RsaCheckKeyMaterial(priKeyBlob) != HCF_SUCCESS) {
        LOGE("check input key material fail");
        return HCF_INVALID_PARAMS;
    }
    RSA *rsaSk = InitRsaStructByBin(priKeyBlob, true);
    if (rsaSk == NULL) {
        LOGE("Init rsaSk fail.");
        return HCF_ERR_MALLOC;
    }
    KeyMaterialRsa *keyMaterial = (KeyMaterialRsa *)(priKeyBlob->data);
    HcfOpensslRsaPriKey *priKey = NULL;
    HcfResult ret = PackPriKey(rsaSk, keyMaterial->keySize, &priKey);
    if (ret != HCF_SUCCESS) {
        LOGE("PackPriKey fail");
        goto ERR;
    }
    *priKeyRet = priKey;
    return ret;
ERR:
    RSA_free(rsaSk);
    return ret;
}

static HcfResult EngineConvertKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    LOGI("EngineConvertKey start");
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL) || ((pubKeyBlob == NULL) && (priKeyBlob == NULL))) {
        LOGE("ConvertKeyParams is invalid.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, OPENSSL_RSA_GENERATOR_CLASS)) {
        LOGE("Class not match.");
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslRsaPubKey *pubKey = NULL;
    if ((pubKeyBlob != NULL) && (pubKeyBlob->data != NULL)) {
        if (ConvertPubKey(pubKeyBlob, &pubKey) != HCF_SUCCESS) {
            LOGE("convert pubkey fail.");
            return HCF_INVALID_PARAMS;
        }
    }

    HcfOpensslRsaPriKey *priKey = NULL;
    if (priKeyBlob != NULL && priKeyBlob->data != NULL) {
        if (ConvertPriKey(priKeyBlob, &priKey) != HCF_SUCCESS) {
            LOGE("convert prikey fail.");
            OH_HCF_ObjDestroy((HcfObjectBase *)pubKey);
            return HCF_INVALID_PARAMS;
        }
    }

    HcfOpensslRsaKeyPair *keyPair = (HcfOpensslRsaKeyPair *)HcfMalloc(sizeof(HcfOpensslRsaKeyPair), 0);
    if (keyPair == NULL) {
        LOGE("Malloc keyPair fail.");
        OH_HCF_ObjDestroy((HcfObjectBase *)pubKey);
        OH_HCF_ObjDestroy((HcfObjectBase *)priKey);
        return HCF_ERR_MALLOC;
    }

    keyPair->base.priKey = (HcfPriKey *)priKey;
    keyPair->base.pubKey = (HcfPubKey *)pubKey;
    keyPair->base.base.getClass = GetOpensslKeyPairClass;
    keyPair->base.base.destroy = DestroyKeyPair;
    *returnKeyPair = (HcfKeyPair *)keyPair;
    LOGI("EngineConvertKey end");
    return HCF_SUCCESS;
}

static HcfResult SetDefaultValue(HcfAsyKeyGenSpiRsaParams *params)
{
    if (params->primes == 0) {
        LOGI("set default primes 2");
        params->primes = OPENSSL_RSA_PRIMES_SIZE_2;
    }
    if (params->pubExp == NULL) {
        BIGNUM *e = BN_new();
        if (e == NULL) {
            LOGE("Rsa new BN fail.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (BN_set_word(e, RSA_F4) != HCF_OPENSSL_SUCCESS) {
            LOGE("Rsa keygen Bn_set_word fail.");
            BN_free(e);
            return HCF_ERR_CRYPTO_OPERATION;
        }
        params->pubExp = e;
    }
    return HCF_SUCCESS;
}

static HcfResult DecodeParams(HcfAsyKeyGenParams *from, HcfAsyKeyGenSpiRsaParams **to)
{
    *to = (HcfAsyKeyGenSpiRsaParams *)HcfMalloc(sizeof(HcfAsyKeyGenSpiRsaParams), 0);
    if (*to == NULL) {
        LOGE("Malloc HcfAsyKeyGenSpiRsaParams fail");
        return HCF_ERR_MALLOC;
    }

    (*to)->bits = from->bits;
    (*to)->primes = from->primes;

    // set 2 as default primes, RSA_F4 as default pubExp
    if (SetDefaultValue(*to) != HCF_SUCCESS) {
        LOGE("Set default value fail.");
        HcfFree(*to);
        *to = NULL;
        return HCF_INVALID_PARAMS;
    }
    if (CheckRsaKeyGenParams(*to) != HCF_SUCCESS) {
        LOGE("Invalid keyGen params");
        HcfFree(*to);
        *to = NULL;
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorSpiRsaCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **generator)
{
    LOGI("HcfAsyKeyGeneratorSpiRsaCreate start.");
    if (params == NULL || generator == NULL) {
        LOGE("Invalid input, params is invalid or generator is null.");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiRsaOpensslImpl *impl = (HcfAsyKeyGeneratorSpiRsaOpensslImpl *)
        HcfMalloc(sizeof(HcfAsyKeyGeneratorSpiRsaOpensslImpl), 0);
    if (impl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    if (DecodeParams(params, &impl->params) != HCF_SUCCESS) {
        LOGE("Keygen params is invalid.");
        HcfFree(impl);
        return HCF_INVALID_PARAMS;
    }
    impl->base.base.getClass = GetKeyGeneratorClass;
    impl->base.base.destroy = DestroyKeyGeneratorSpiImpl;
    impl->base.engineGenerateKeyPair = EngineGenerateKeyPair;
    impl->base.engineConvertKey = EngineConvertKey;
    *generator = (HcfAsyKeyGeneratorSpi *)impl;
    LOGI("HcfAsyKeyGeneratorSpiRsaCreate end.");
    return HCF_SUCCESS;
}
