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

#include "asy_key_generator.h"

#include <securec.h>

#include "asy_key_generator_spi.h"
#include "config.h"
#include "detailed_dsa_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "dsa_asy_key_generator_openssl.h"
#include "ecc_asy_key_generator_openssl.h"
#include "params_parser.h"
#include "rsa_asy_key_generator_openssl.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define ALG_NAME_DSA "DSA"
#define ALG_NAME_ECC "ECC"
#define ALG_NAME_RSA "RSA"
#define ASY_KEY_GENERATOR_CLASS "HcfAsyKeyGenerator"
#define ASY_KEY_GENERATOR_BY_SPEC_CLASS "HcfAsyKeyGeneratorBySpec"

typedef HcfResult (*HcfAsyKeyGeneratorSpiCreateFunc)(HcfAsyKeyGenParams *, HcfAsyKeyGeneratorSpi **);

typedef struct {
    HcfAsyKeyGenerator base;

    HcfAsyKeyGeneratorSpi *spiObj;

    char algoName[HCF_MAX_ALGO_NAME_LEN];
} HcfAsyKeyGeneratorImpl;

typedef struct {
    HcfAsyKeyGeneratorBySpec base;

    HcfAsyKeyGeneratorSpi *spiObj;

    HcfAsyKeyParamsSpec *paramsSpec;
} HcfAsyKeyGeneratorBySpecImpl;

typedef struct {
    HcfAlgValue algo;

    HcfAsyKeyGeneratorSpiCreateFunc createSpiFunc;
} HcfAsyKeyGenAbility;

static const HcfAsyKeyGenAbility ASY_KEY_GEN_ABILITY_SET[] = {
    { HCF_ALG_RSA, HcfAsyKeyGeneratorSpiRsaCreate },
    { HCF_ALG_ECC, HcfAsyKeyGeneratorSpiEccCreate },
    { HCF_ALG_DSA, HcfAsyKeyGeneratorSpiDsaCreate }
};

typedef struct {
    HcfAlgParaValue value;
    int32_t bits; // keyLen
    HcfAlgValue algo; // algType
} KeyTypeAlg;

static const KeyTypeAlg KEY_TYPE_MAP[] = {
    { HCF_ALG_ECC_224, HCF_ALG_ECC_224, HCF_ALG_ECC },
    { HCF_ALG_ECC_256, HCF_ALG_ECC_256, HCF_ALG_ECC },
    { HCF_ALG_ECC_384, HCF_ALG_ECC_384, HCF_ALG_ECC },
    { HCF_ALG_ECC_521, HCF_ALG_ECC_521, HCF_ALG_ECC },
    { HCF_OPENSSL_RSA_512, HCF_RSA_KEY_SIZE_512, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_768, HCF_RSA_KEY_SIZE_768, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_1024, HCF_RSA_KEY_SIZE_1024, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_2048, HCF_RSA_KEY_SIZE_2048, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_3072, HCF_RSA_KEY_SIZE_3072, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_4096, HCF_RSA_KEY_SIZE_4096, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_4096, HCF_RSA_KEY_SIZE_4096, HCF_ALG_RSA },
    { HCF_OPENSSL_RSA_8192, HCF_RSA_KEY_SIZE_8192, HCF_ALG_RSA },
    { HCF_ALG_DSA_1024, HCF_DSA_KEY_SIZE_1024, HCF_ALG_DSA },
    { HCF_ALG_DSA_2048, HCF_DSA_KEY_SIZE_2048, HCF_ALG_DSA },
    { HCF_ALG_DSA_3072, HCF_DSA_KEY_SIZE_3072, HCF_ALG_DSA }
};
static bool IsDsaCommParamsSpecValid(HcfDsaCommParamsSpec *paramsSpec)
{
    if ((paramsSpec->p.data == NULL) || (paramsSpec->p.len == 0)) {
        LOGE("BigInteger p is invalid");
        return false;
    }
    if ((paramsSpec->q.data == NULL) || (paramsSpec->q.len == 0)) {
        LOGE("BigInteger q is invalid");
        return false;
    }
    if ((paramsSpec->g.data == NULL) || (paramsSpec->g.len == 0)) {
        LOGE("BigInteger g is invalid");
        return false;
    }
    return true;
}

static bool IsDsaPubKeySpecValid(HcfDsaPubKeyParamsSpec *paramsSpec)
{
    if (!IsDsaCommParamsSpecValid(&(paramsSpec->base))) {
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    return true;
}

static bool IsDsaKeyPairSpecValid(HcfDsaKeyPairParamsSpec *paramsSpec)
{
    if (!IsDsaCommParamsSpecValid(&(paramsSpec->base))) {
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsDsaParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = IsDsaCommParamsSpecValid((HcfDsaCommParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsDsaPubKeySpecValid((HcfDsaPubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsDsaKeyPairSpecValid((HcfDsaKeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsEccCommParamsSpecValid(HcfEccCommParamsSpec *paramsSpec)
{
    if ((paramsSpec->a.data == NULL) || (paramsSpec->a.len == 0)) {
        LOGE("BigInteger a is invalid");
        return false;
    }
    if ((paramsSpec->b.data == NULL) || (paramsSpec->b.len == 0)) {
        LOGE("BigInteger b is invalid");
        return false;
    }
    if ((paramsSpec->n.data == NULL) || (paramsSpec->n.len == 0)) {
        LOGE("BigInteger n is invalid");
        return false;
    }
    if ((paramsSpec->g.x.data == NULL) || (paramsSpec->g.x.len == 0) ||
        (paramsSpec->g.y.data == NULL) || (paramsSpec->g.y.len == 0)) {
        LOGE("Point g is invalid");
        return false;
    }
    if (paramsSpec->field == NULL) {
        LOGE("Field is null.");
        return false;
    }
    if (strcmp(paramsSpec->field->fieldType, "Fp") != 0) {
        LOGE("Unknown field type.");
        return false;
    }
    HcfECFieldFp *tmp = (HcfECFieldFp *)(paramsSpec->field);
    if ((tmp->p.data == NULL) || (tmp->p.len == 0)) {
        LOGE("EcFieldFp p is invalid");
        return false;
    }
    return true;
}

static bool IsEccPriKeySpecValid(HcfEccPriKeyParamsSpec *paramsSpec)
{
    if (!IsEccCommParamsSpecValid(&(paramsSpec->base))) {
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsEccPubKeySpecValid(HcfEccPubKeyParamsSpec *paramsSpec)
{
    if (!IsEccCommParamsSpecValid(&(paramsSpec->base))) {
        return false;
    }
    if ((paramsSpec->pk.x.data == NULL) || (paramsSpec->pk.x.len == 0) ||
        (paramsSpec->pk.y.data == NULL) || (paramsSpec->pk.y.len == 0)) {
        LOGE("Point pk is invalid");
        return false;
    }
    return true;
}

static bool IsEccKeyPairSpecValid(HcfEccKeyPairParamsSpec *paramsSpec)
{
    if (!IsEccCommParamsSpecValid(&(paramsSpec->base))) {
        return false;
    }
    if ((paramsSpec->pk.x.data == NULL) || (paramsSpec->pk.x.len == 0) ||
        (paramsSpec->pk.y.data == NULL) || (paramsSpec->pk.y.len == 0)) {
        LOGE("Point pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsEccParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = IsEccCommParamsSpecValid((HcfEccCommParamsSpec *)paramsSpec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            ret = IsEccPriKeySpecValid((HcfEccPriKeyParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsEccPubKeySpecValid((HcfEccPubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsEccKeyPairSpecValid((HcfEccKeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsRsaCommParamsSpecValid(HcfRsaCommParamsSpec *paramsSpec)
{
    if ((paramsSpec->n.data == NULL) || (paramsSpec->n.len == 0)) {
        LOGE("BigInteger n is invalid");
        return false;
    }
    return true;
}

static bool IsRsaPubKeySpecValid(HcfRsaPubKeyParamsSpec *paramsSpec)
{
    if (!IsRsaCommParamsSpecValid(&(paramsSpec->base))) {
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    return true;
}

static bool IsRsaKeyPairSpecValid(HcfRsaKeyPairParamsSpec *paramsSpec)
{
    if (!IsRsaCommParamsSpecValid(&(paramsSpec->base))) {
        return false;
    }
    if ((paramsSpec->pk.data == NULL) || (paramsSpec->pk.len == 0)) {
        LOGE("BigInteger pk is invalid");
        return false;
    }
    if ((paramsSpec->sk.data == NULL) || (paramsSpec->sk.len == 0)) {
        LOGE("BigInteger sk is invalid");
        return false;
    }
    return true;
}

static bool IsRsaParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    bool ret = false;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = IsRsaCommParamsSpecValid((HcfRsaCommParamsSpec *)paramsSpec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = IsRsaPubKeySpecValid((HcfRsaPubKeyParamsSpec *)paramsSpec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = IsRsaKeyPairSpecValid((HcfRsaKeyPairParamsSpec *)paramsSpec);
            break;
        default:
            LOGE("SpecType not support! [SpecType]: %d", paramsSpec->specType);
            break;
    }
    return ret;
}

static bool IsParamsSpecValid(const HcfAsyKeyParamsSpec *paramsSpec)
{
    if ((paramsSpec == NULL) || (paramsSpec->algName == NULL)) {
        LOGE("Params spec is null");
        return false;
    }
    if (strcmp(paramsSpec->algName, ALG_NAME_DSA) == 0) {
        return IsDsaParamsSpecValid(paramsSpec);
    } else if (strcmp(paramsSpec->algName, ALG_NAME_ECC) == 0) {
        return IsEccParamsSpecValid(paramsSpec);
    } else if (strcmp(paramsSpec->algName, ALG_NAME_RSA) == 0) {
        return IsRsaParamsSpecValid(paramsSpec);
    } else {
        LOGE("AlgName not support! [AlgName]: %s", paramsSpec->algName);
        return false;
    }
}

static HcfAsyKeyGeneratorSpiCreateFunc FindAbility(HcfAsyKeyGenParams *params)
{
    for (uint32_t i = 0; i < sizeof(ASY_KEY_GEN_ABILITY_SET) / sizeof(ASY_KEY_GEN_ABILITY_SET[0]); i++) {
        if (ASY_KEY_GEN_ABILITY_SET[i].algo == params->algo) {
            return ASY_KEY_GEN_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %d", params->algo);
    return NULL;
}

static void SetPrimes(HcfAlgParaValue value, HcfAsyKeyGenParams *params)
{
    if (params == NULL) {
        LOGE("params is null.");
        return;
    }
    switch (value) {
        case HCF_OPENSSL_PRIMES_2:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_2;
            break;
        case HCF_OPENSSL_PRIMES_3:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_3;
            break;
        case HCF_OPENSSL_PRIMES_4:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_4;
            break;
        case HCF_OPENSSL_PRIMES_5:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_5;
            break;
        default:
            params->primes = (int32_t)HCF_RSA_PRIMES_SIZE_2; // default primes is 2
            LOGD("user default primes 2");
            break;
    }
    LOGD("Set primes:%d!", params->primes);
}

static void SetKeyType(HcfAlgParaValue value, HcfAsyKeyGenParams *params)
{
    for (uint32_t i = 0; i < sizeof(KEY_TYPE_MAP) / sizeof(KEY_TYPE_MAP[0]); i++) {
        if (KEY_TYPE_MAP[i].value == value) {
            params->bits = KEY_TYPE_MAP[i].bits;
            params->algo = KEY_TYPE_MAP[i].algo;
            return;
        }
    }
    LOGE("There is not matched algorithm.");
}

static HcfResult ParseAsyKeyGenParams(const HcfParaConfig* config, void *params)
{
    if (config == NULL || params == NULL) {
        return HCF_INVALID_PARAMS;
    }
    HcfResult ret = HCF_SUCCESS;
    HcfAsyKeyGenParams *paramsObj = (HcfAsyKeyGenParams *)params;
    LOGD("Set Parameter: %s", config->tag);
    switch (config->paraType) {
        case HCF_ALG_KEY_TYPE:
            SetKeyType(config->paraValue, paramsObj);
            break;
        case HCF_ALG_PRIMES:
            SetPrimes(config->paraValue, paramsObj);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult CopyAsyKeyParamsSpec(const HcfAsyKeyParamsSpec *srcSpec, HcfAsyKeyParamsSpec *destSpec)
{
    int srcAlgNameLen = strlen(srcSpec->algName);
    destSpec->algName = (char *)HcfMalloc(srcAlgNameLen + 1, 0);
    if (destSpec->algName == NULL) {
        LOGE("Failed to allocate alg name memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(destSpec->algName, srcAlgNameLen, srcSpec->algName, srcAlgNameLen);
    destSpec->specType = srcSpec->specType;
    return HCF_SUCCESS;
}

static HcfResult CopyDsaCommonSpec(const HcfDsaCommParamsSpec *srcSpec, HcfDsaCommParamsSpec *destSpec)
{
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(destSpec->base)) != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    destSpec->p.data = (unsigned char *)HcfMalloc(srcSpec->p.len, 0);
    if (destSpec->p.data == NULL) {
        LOGE("Failed to allocate p data memory");
        FreeDsaCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->q.data = (unsigned char *)HcfMalloc(srcSpec->q.len, 0);
    if (destSpec->q.data == NULL) {
        LOGE("Failed to allocate q data memory");
        FreeDsaCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->g.data = (unsigned char *)HcfMalloc(srcSpec->g.len, 0);
    if (destSpec->g.data == NULL) {
        LOGE("Failed to allocate g data memory");
        FreeDsaCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(destSpec->p.data, srcSpec->p.len, srcSpec->p.data, srcSpec->p.len);
    (void)memcpy_s(destSpec->q.data, srcSpec->q.len, srcSpec->q.data, srcSpec->q.len);
    (void)memcpy_s(destSpec->g.data, srcSpec->g.len, srcSpec->g.data, srcSpec->g.len);
    destSpec->p.len = srcSpec->p.len;
    destSpec->q.len = srcSpec->q.len;
    destSpec->g.len = srcSpec->g.len;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaCommonSpecImpl(const HcfDsaCommParamsSpec *srcSpec, HcfDsaCommParamsSpec **destSpec)
{
    HcfDsaCommParamsSpec *spec = (HcfDsaCommParamsSpec *)HcfMalloc(sizeof(HcfDsaCommParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }

    if (CopyDsaCommonSpec(srcSpec, spec) != HCF_SUCCESS) {
        HcfFree(spec);
        return HCF_INVALID_PARAMS;
    }

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaPubKeySpecImpl(const HcfDsaPubKeyParamsSpec *srcSpec, HcfDsaPubKeyParamsSpec **destSpec)
{
    HcfDsaPubKeyParamsSpec *spec = (HcfDsaPubKeyParamsSpec *)HcfMalloc(sizeof(HcfDsaPubKeyParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyDsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        FreeDsaCommParamsSpec(&(spec->base));
        HcfFree(spec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    spec->pk.len = srcSpec->pk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaKeyPairSpecImpl(const HcfDsaKeyPairParamsSpec *srcSpec, HcfDsaKeyPairParamsSpec **destSpec)
{
    HcfDsaKeyPairParamsSpec *spec = (HcfDsaKeyPairParamsSpec *)HcfMalloc(sizeof(HcfDsaKeyPairParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyDsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        FreeDsaCommParamsSpec(&(spec->base));
        HcfFree(spec);
        return HCF_ERR_MALLOC;
    }
    spec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (spec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeDsaCommParamsSpec(&(spec->base));
        HcfFree(spec->pk.data);
        HcfFree(spec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    (void)memcpy_s(spec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    spec->pk.len = srcSpec->pk.len;
    spec->sk.len = srcSpec->sk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateDsaParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfDsaCommParamsSpec *spec = NULL;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = CreateDsaCommonSpecImpl((HcfDsaCommParamsSpec *)paramsSpec, &spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateDsaPubKeySpecImpl((HcfDsaPubKeyParamsSpec *)paramsSpec, (HcfDsaPubKeyParamsSpec **)&spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateDsaKeyPairSpecImpl((HcfDsaKeyPairParamsSpec *)paramsSpec, (HcfDsaKeyPairParamsSpec **)&spec);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            break;
    }
    if (ret == HCF_SUCCESS) {
        *impl = (HcfAsyKeyParamsSpec *)spec;
    }
    return ret;
}

static HcfResult CopyEcField(const HcfECField *src, HcfECField **dest)
{
    HcfECField *tmpField = (HcfECField *)HcfMalloc(sizeof(HcfECFieldFp), 0);
    if (tmpField == NULL) {
        LOGE("Alloc memory failed.");
        return HCF_ERR_MALLOC;
    }

    int32_t srcFieldTypeLen = strlen(src->fieldType);
    tmpField->fieldType = (char *)HcfMalloc(srcFieldTypeLen + 1, 0);
    if (tmpField->fieldType == NULL) {
        LOGE("Failed to allocate field memory.");
        HcfFree(tmpField);
        return HCF_ERR_MALLOC;
    }
    HcfECFieldFp *tmpDest = (HcfECFieldFp *)(tmpField);
    HcfECFieldFp *tmpSrc = (HcfECFieldFp *)(src);
    tmpDest->p.data = (unsigned char *)HcfMalloc(tmpSrc->p.len, 0);
    if (tmpDest->p.data == NULL) {
        LOGE("Failed to allocate b data memory");
        HcfFree(tmpField->fieldType);
        HcfFree(tmpField);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpField->fieldType, srcFieldTypeLen, src->fieldType, srcFieldTypeLen);
    (void)memcpy_s(tmpDest->p.data, tmpSrc->p.len, tmpSrc->p.data, tmpSrc->p.len);
    tmpDest->p.len = tmpSrc->p.len;

    *dest = tmpField;
    return HCF_SUCCESS;
}

static HcfResult CopyPoint(const HcfPoint *src, HcfPoint *dest)
{
    dest->x.data = (unsigned char *)HcfMalloc(src->x.len, 0);
    if (dest->x.data == NULL) {
        LOGE("Failed to allocate x data memory");
        return HCF_ERR_MALLOC;
    }
    dest->y.data = (unsigned char *)HcfMalloc(src->y.len, 0);
    if (dest->y.data == NULL) {
        LOGE("Failed to allocate y data memory");
        HcfFree(dest->x.data);
        dest->x.data = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(dest->x.data, src->x.len, src->x.data, src->x.len);
    (void)memcpy_s(dest->y.data, src->y.len, src->y.data, src->y.len);
    dest->x.len = src->x.len;
    dest->y.len = src->y.len;
    return HCF_SUCCESS;
}

static HcfResult CopyEccCommonSpec(const HcfEccCommParamsSpec *srcSpec, HcfEccCommParamsSpec *destSpec)
{
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(destSpec->base)) != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    destSpec->a.data = (unsigned char *)HcfMalloc(srcSpec->a.len, 0);
    if (destSpec->a.data == NULL) {
        LOGE("Failed to allocate a data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->b.data = (unsigned char *)HcfMalloc(srcSpec->b.len, 0);
    if (destSpec->b.data == NULL) {
        LOGE("Failed to allocate b data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->n.data = (unsigned char *)HcfMalloc(srcSpec->n.len, 0);
    if (destSpec->n.data == NULL) {
        LOGE("Failed to allocate n data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    HcfResult res = CopyEcField(srcSpec->field, &(destSpec->field));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate field data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    res = CopyPoint(&(srcSpec->g), &(destSpec->g));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate field data memory");
        FreeEccCommParamsSpec(destSpec);
        return HCF_ERR_MALLOC;
    }
    destSpec->h = srcSpec->h;
    (void)memcpy_s(destSpec->a.data, srcSpec->a.len, srcSpec->a.data, srcSpec->a.len);
    (void)memcpy_s(destSpec->b.data, srcSpec->b.len, srcSpec->b.data, srcSpec->b.len);
    (void)memcpy_s(destSpec->n.data, srcSpec->n.len, srcSpec->n.data, srcSpec->n.len);
    destSpec->a.len = srcSpec->a.len;
    destSpec->b.len = srcSpec->b.len;
    destSpec->n.len = srcSpec->n.len;
    return HCF_SUCCESS;
}

static HcfResult CreateEccCommonSpecImpl(const HcfEccCommParamsSpec *srcSpec, HcfEccCommParamsSpec **destSpec)
{
    HcfEccCommParamsSpec *tmpSpec = (HcfEccCommParamsSpec *)HcfMalloc(sizeof(HcfEccCommParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }

    if (CopyEccCommonSpec(srcSpec, tmpSpec) != HCF_SUCCESS) {
        HcfFree(tmpSpec);
        return HCF_INVALID_PARAMS;
    }

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateEccPubKeySpecImpl(const HcfEccPubKeyParamsSpec *srcSpec, HcfEccPubKeyParamsSpec **destSpec)
{
    HcfEccPubKeyParamsSpec *tmpSpec = (HcfEccPubKeyParamsSpec *)HcfMalloc(sizeof(HcfEccPubKeyParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyEccCommonSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        HcfFree(tmpSpec);
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = CopyPoint(&(srcSpec->pk), &(tmpSpec->pk));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate public key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec);
        return res;
    }

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateEccPriKeySpecImpl(const HcfEccPriKeyParamsSpec *srcSpec, HcfEccPriKeyParamsSpec **destSpec)
{
    HcfEccPriKeyParamsSpec *tmpSpec = (HcfEccPriKeyParamsSpec *)HcfMalloc(sizeof(HcfEccPriKeyParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyEccCommonSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        HcfFree(tmpSpec);
        return HCF_INVALID_PARAMS;
    }
    tmpSpec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (tmpSpec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpSpec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    tmpSpec->sk.len = srcSpec->sk.len;

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateEccKeyPairSpecImpl(const HcfEccKeyPairParamsSpec *srcSpec, HcfEccKeyPairParamsSpec **destSpec)
{
    HcfEccKeyPairParamsSpec *tmpSpec = (HcfEccKeyPairParamsSpec *)HcfMalloc(sizeof(HcfEccKeyPairParamsSpec), 0);
    if (tmpSpec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyEccCommonSpec(&(srcSpec->base), &(tmpSpec->base)) != HCF_SUCCESS) {
        HcfFree(tmpSpec);
        return HCF_INVALID_PARAMS;
    }
    HcfResult res = CopyPoint(&(srcSpec->pk), &(tmpSpec->pk));
    if (res != HCF_SUCCESS) {
        LOGE("Failed to allocate public key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec);
        return res;
    }
    tmpSpec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (tmpSpec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeEccCommParamsSpec(&(tmpSpec->base));
        HcfFree(tmpSpec->pk.x.data);
        HcfFree(tmpSpec->pk.y.data);
        HcfFree(tmpSpec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tmpSpec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    tmpSpec->sk.len = srcSpec->sk.len;

    *destSpec = tmpSpec;
    return HCF_SUCCESS;
}

static HcfResult CreateEccParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfEccCommParamsSpec *spec = NULL;
    switch (paramsSpec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = CreateEccCommonSpecImpl((HcfEccCommParamsSpec *)paramsSpec, &spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateEccPubKeySpecImpl((HcfEccPubKeyParamsSpec *)paramsSpec, (HcfEccPubKeyParamsSpec **)(&spec));
            break;
        case HCF_PRIVATE_KEY_SPEC:
            ret = CreateEccPriKeySpecImpl((HcfEccPriKeyParamsSpec *)paramsSpec, (HcfEccPriKeyParamsSpec **)(&spec));
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateEccKeyPairSpecImpl((HcfEccKeyPairParamsSpec *)paramsSpec, (HcfEccKeyPairParamsSpec **)(&spec));
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            break;
    }
    if (ret == HCF_SUCCESS) {
        *impl = (HcfAsyKeyParamsSpec *)spec;
    }
    return ret;
}

static HcfResult CopyRsaCommonSpec(const HcfRsaCommParamsSpec *srcSpec, HcfRsaCommParamsSpec *destSpec)
{
    if (CopyAsyKeyParamsSpec(&(srcSpec->base), &(destSpec->base)) != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    destSpec->n.data = (unsigned char *)HcfMalloc(srcSpec->n.len, 0);
    if (destSpec->n.data == NULL) {
        LOGE("Failed to allocate n data memory");
        HcfFree(destSpec->base.algName);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(destSpec->n.data, srcSpec->n.len, srcSpec->n.data, srcSpec->n.len);
    destSpec->n.len = srcSpec->n.len;
    return HCF_SUCCESS;
}

static HcfResult CreateRsaPubKeySpecImpl(const HcfRsaPubKeyParamsSpec *srcSpec, HcfRsaPubKeyParamsSpec **destSpec)
{
    HcfRsaPubKeyParamsSpec *spec = (HcfRsaPubKeyParamsSpec *)HcfMalloc(sizeof(HcfRsaPubKeyParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyRsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        DestroyRsaPubKeySpec(spec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    spec->pk.len = srcSpec->pk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateRsaKeyPairSpecImpl(const HcfRsaKeyPairParamsSpec *srcSpec, HcfRsaKeyPairParamsSpec **destSpec)
{
    HcfRsaKeyPairParamsSpec *spec = (HcfRsaKeyPairParamsSpec *)HcfMalloc(sizeof(HcfRsaKeyPairParamsSpec), 0);
    if (spec == NULL) {
        LOGE("Failed to allocate dest spec memory");
        return HCF_ERR_MALLOC;
    }
    if (CopyRsaCommonSpec(&(srcSpec->base), &(spec->base)) != HCF_SUCCESS) {
        HcfFree(spec);
        return HCF_INVALID_PARAMS;
    }
    spec->pk.data = (unsigned char *)HcfMalloc(srcSpec->pk.len, 0);
    if (spec->pk.data == NULL) {
        LOGE("Failed to allocate public key memory");
        FreeRsaCommParamsSpec(&(spec->base));
        HcfFree(spec);
        return HCF_ERR_MALLOC;
    }
    spec->sk.data = (unsigned char *)HcfMalloc(srcSpec->sk.len, 0);
    if (spec->sk.data == NULL) {
        LOGE("Failed to allocate private key memory");
        FreeRsaCommParamsSpec(&(spec->base));
        HcfFree(spec->pk.data);
        HcfFree(spec);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(spec->pk.data, srcSpec->pk.len, srcSpec->pk.data, srcSpec->pk.len);
    (void)memcpy_s(spec->sk.data, srcSpec->sk.len, srcSpec->sk.data, srcSpec->sk.len);
    spec->pk.len = srcSpec->pk.len;
    spec->sk.len = srcSpec->sk.len;

    *destSpec = spec;
    return HCF_SUCCESS;
}

static HcfResult CreateRsaParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    HcfRsaCommParamsSpec *spec = NULL;
    switch (paramsSpec->specType) {
        // commonspe should not be used in RSA
        case HCF_COMMON_PARAMS_SPEC:
            LOGE("RSA not support comm spec");
            ret = HCF_INVALID_PARAMS;
            break;
        case HCF_PUBLIC_KEY_SPEC:
            ret = CreateRsaPubKeySpecImpl((HcfRsaPubKeyParamsSpec *)paramsSpec, (HcfRsaPubKeyParamsSpec **)&spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = CreateRsaKeyPairSpecImpl((HcfRsaKeyPairParamsSpec *)paramsSpec, (HcfRsaKeyPairParamsSpec **)&spec);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            break;
    }
    if (ret == HCF_SUCCESS) {
        *impl = (HcfAsyKeyParamsSpec *)spec;
    }
    return ret;
}

static HcfResult CreateAsyKeyParamsSpecImpl(const HcfAsyKeyParamsSpec *paramsSpec, HcfAlgValue alg,
    HcfAsyKeyParamsSpec **impl)
{
    HcfResult ret = HCF_SUCCESS;
    switch (alg) {
        case HCF_ALG_DSA:
            ret = CreateDsaParamsSpecImpl(paramsSpec, impl);
            break;
        case HCF_ALG_ECC:
            ret = CreateEccParamsSpecImpl(paramsSpec, impl);
            break;
        case HCF_ALG_RSA:
            ret = CreateRsaParamsSpecImpl(paramsSpec, impl);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

// export interfaces
static const char *GetAsyKeyGeneratorClass(void)
{
    return ASY_KEY_GENERATOR_CLASS;
}

static const char *GetAsyKeyGeneratorBySpecClass(void)
{
    return ASY_KEY_GENERATOR_BY_SPEC_CLASS;
}

static const char *GetAlgoName(HcfAsyKeyGenerator *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return NULL;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    return impl->algoName;
}

static const char *GetAlgNameBySpec(const HcfAsyKeyGeneratorBySpec *self)
{
    if (self == NULL) {
        LOGE("The input self ptr is NULL!");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return NULL;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    return impl->paramsSpec->algName;
}

static HcfResult ConvertKey(HcfAsyKeyGenerator *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    return impl->spiObj->engineConvertKey(impl->spiObj, params, pubKeyBlob, priKeyBlob, returnKeyPair);
}

static HcfResult GenerateKeyPair(HcfAsyKeyGenerator *self, HcfParamsSpec *params,
    HcfKeyPair **returnKeyPair)
{
    (void)params;
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    return impl->spiObj->engineGenerateKeyPair(impl->spiObj, returnKeyPair);
}

static HcfResult GenerateKeyPairBySpec(const HcfAsyKeyGeneratorBySpec *self, HcfKeyPair **returnKeyPair)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    return impl->spiObj->engineGenerateKeyPairBySpec(impl->spiObj, impl->paramsSpec, returnKeyPair);
}

static HcfResult GeneratePubKeyBySpec(const HcfAsyKeyGeneratorBySpec *self, HcfPubKey **returnPubKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    return impl->spiObj->engineGeneratePubKeyBySpec(impl->spiObj, impl->paramsSpec, returnPubKey);
}

static HcfResult GeneratePriKeyBySpec(const HcfAsyKeyGeneratorBySpec *self, HcfPriKey **returnPriKey)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    return impl->spiObj->engineGeneratePriKeyBySpec(impl->spiObj, impl->paramsSpec, returnPriKey);
}

static void DestroyAsyKeyGenerator(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorClass())) {
        return;
    }
    HcfAsyKeyGeneratorImpl *impl = (HcfAsyKeyGeneratorImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    HcfFree(impl);
}

static void DestroyAsyKeyGeneratorBySpec(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetAsyKeyGeneratorBySpecClass())) {
        return;
    }
    HcfAsyKeyGeneratorBySpecImpl *impl = (HcfAsyKeyGeneratorBySpecImpl *)self;
    HcfObjDestroy(impl->spiObj);
    impl->spiObj = NULL;
    FreeAsyKeySpec(impl->paramsSpec);
    impl->paramsSpec = NULL;
    HcfFree(impl);
}

HcfResult HcfAsyKeyGeneratorCreate(const char *algoName, HcfAsyKeyGenerator **returnObj)
{
    if ((!IsStrValid(algoName, HCF_MAX_ALGO_NAME_LEN)) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGenParams params = { 0 };
    if (ParseAndSetParameter(algoName, &params, ParseAsyKeyGenParams) != HCF_SUCCESS) {
        LOGE("Failed to parser parmas!");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        return HCF_NOT_SUPPORT;
    }

    HcfAsyKeyGeneratorImpl *returnGenerator = (HcfAsyKeyGeneratorImpl *)HcfMalloc(sizeof(HcfAsyKeyGeneratorImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    if (strcpy_s(returnGenerator->algoName, HCF_MAX_ALGO_NAME_LEN, algoName) != EOK) {
        LOGE("Failed to copy algoName!");
        HcfFree(returnGenerator);
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpi *spiObj = NULL;
    HcfResult res = HCF_SUCCESS;
    res = createSpiFunc(&params, &spiObj);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        return res;
    }
    returnGenerator->base.base.destroy = DestroyAsyKeyGenerator;
    returnGenerator->base.base.getClass = GetAsyKeyGeneratorClass;
    returnGenerator->base.convertKey = ConvertKey;
    returnGenerator->base.generateKeyPair = GenerateKeyPair;
    returnGenerator->base.getAlgoName = GetAlgoName;
    returnGenerator->spiObj = spiObj;
    *returnObj = (HcfAsyKeyGenerator *)returnGenerator;
    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorBySpecCreate(const HcfAsyKeyParamsSpec *paramsSpec, HcfAsyKeyGeneratorBySpec **returnObj)
{
    if ((!IsParamsSpecValid(paramsSpec)) || (returnObj == NULL)) {
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGenParams params = { 0 };
    if (ParseAlgNameToParams(paramsSpec->algName, &params) != HCF_SUCCESS) {
        LOGE("Failed to parser parmas!");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGeneratorSpiCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        return HCF_NOT_SUPPORT;
    }
    HcfAsyKeyGeneratorBySpecImpl *returnGenerator =
        (HcfAsyKeyGeneratorBySpecImpl *)HcfMalloc(sizeof(HcfAsyKeyGeneratorBySpecImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    HcfAsyKeyParamsSpec *paramsSpecImpl = NULL;
    HcfResult ret = CreateAsyKeyParamsSpecImpl(paramsSpec, params.algo, &paramsSpecImpl);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create asy key params spec impl!");
        HcfFree(returnGenerator);
        return ret;
    }
    HcfAsyKeyGeneratorSpi *spiObj = NULL;
    ret = createSpiFunc(&params, &spiObj);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        HcfFree(returnGenerator);
        FreeAsyKeySpec(paramsSpecImpl);
        return ret;
    }
    returnGenerator->base.base.destroy = DestroyAsyKeyGeneratorBySpec;
    returnGenerator->base.base.getClass = GetAsyKeyGeneratorBySpecClass;
    returnGenerator->base.generateKeyPair = GenerateKeyPairBySpec;
    returnGenerator->base.generatePubKey = GeneratePubKeyBySpec;
    returnGenerator->base.generatePriKey = GeneratePriKeyBySpec;
    returnGenerator->base.getAlgName = GetAlgNameBySpec;
    returnGenerator->paramsSpec = paramsSpecImpl;
    returnGenerator->spiObj = spiObj;
    *returnObj = (HcfAsyKeyGeneratorBySpec *)returnGenerator;
    return HCF_SUCCESS;
}