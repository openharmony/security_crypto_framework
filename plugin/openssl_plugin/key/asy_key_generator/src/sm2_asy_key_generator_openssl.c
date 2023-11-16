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
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "detailed_ecc_key_params.h"
#include "ecc_openssl_common.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

#define OPENSSL_SM2_256_BITS 256
#define OPENSSL_SM2_KEY_GENERATOR_CLASS "OPENSSL.SM2.KEY_GENERATOR_CLASS"
#define OPENSSL_SM2_ALGORITHM "SM2"
#define OPENSSL_SM2_PUB_KEY_FORMAT "X.509"
#define OPENSSL_SM2_PRI_KEY_FORMAT "PKCS#8"
static const char *const g_sm2GenerateFieldType = "Fp";

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

static void FreeCurveBigNum(BIGNUM *pStd, BIGNUM *bStd, BIGNUM *xStd, BIGNUM *yStd)
{
    Openssl_BN_free(pStd);
    Openssl_BN_free(bStd);
    Openssl_BN_free(xStd);
    Openssl_BN_free(yStd);
}

static HcfResult CheckSm256CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_sm256CorrectBigP, NID_X9_62_prime256v1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_sm256CorrectBigB, NID_X9_62_prime256v1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_sm256CorrectBigGX, NID_X9_62_prime256v1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_sm256CorrectBigGY, NID_X9_62_prime256v1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("EC 256 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("EC 256 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckParamsSpecToGetCurveId(const HcfEccCommParamsSpec *ecParams, int32_t *curveId)
{
    BIGNUM *p = NULL, *b = NULL, *x = NULL, *y = NULL;
    HcfECFieldFp *field = (HcfECFieldFp *)(ecParams->field);
    if (BigIntegerToBigNum(&(field->p), &p) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->b), &b) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.x), &x) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.y), &y) != HCF_SUCCESS) {
        LOGE("BigIntegerToBigNum failed.");
        FreeCurveBigNum(p, b, x, y);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    int32_t bitLenP = (int32_t)Openssl_BN_num_bits(p);
    HcfResult ret = HCF_INVALID_PARAMS;
    if (bitLenP != OPENSSL_SM2_256_BITS) {
        LOGE("Find no bit len");
        FreeCurveBigNum(p, b, x, y);
        return ret;
    }
    ret = CheckSm256CurveId(p, b, x, y);
    if (ret == HCF_SUCCESS) {
        *curveId = NID_sm2;
    }
    FreeCurveBigNum(p, b, x, y);
    return ret;
}

static HcfResult NewGroupFromCurveGFp(const HcfEccCommParamsSpec *ecParams, EC_GROUP **ecGroup, BN_CTX *ctx)
{
    HcfResult ret = HCF_SUCCESS;
    HcfECFieldFp *field = (HcfECFieldFp *)(ecParams->field);
    BIGNUM *p = NULL, *a = NULL, *b = NULL;
    EC_GROUP *group = NULL;
    do {
        if (BigIntegerToBigNum(&(field->p), &p) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->a), &a) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->b), &b) != HCF_SUCCESS) {
            LOGE("BigInteger to BigNum failed");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        group = Openssl_EC_GROUP_new_curve_GFp(p, a, b, ctx);
        if (group == NULL) {
            LOGE("Alloc group memory failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    Openssl_BN_free(p);
    Openssl_BN_free(a);
    Openssl_BN_free(b);

    if (ret != HCF_SUCCESS) {
        Openssl_EC_GROUP_free(group);
        return ret;
    }
    *ecGroup = group;
    return ret;
}

static HcfResult SetSm2PointToGroup(const HcfEccCommParamsSpec *ecParams, EC_GROUP *group, BN_CTX *ctx)
{
    HcfResult ret = HCF_SUCCESS;
    BIGNUM *x = NULL, *y = NULL;
    BIGNUM *order = NULL;
    EC_POINT *generator = NULL;
    BIGNUM *cofactor = Openssl_BN_new();
    if (cofactor == NULL) {
        LOGE("Alloc cofactor memory failed.");
        return HCF_ERR_MALLOC;
    }
    do {
        if (BigIntegerToBigNum(&(ecParams->g.x), &x) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->g.y), &y) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->n), &order) != HCF_SUCCESS ||
            !Openssl_BN_set_word(cofactor, (uint32_t)ecParams->h)) {
            LOGE("BigInteger to BigNum failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        generator = Openssl_EC_POINT_new(group);
        if (generator == NULL) {
            LOGE("Alloc group memory failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (!Openssl_EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, ctx)) {
            LOGE("Openssl_EC_POINT_set_affine_coordinates_GFp failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            HcfPrintOpensslError();
            break;
        }

        if (!Openssl_EC_GROUP_set_generator(group, generator, order, cofactor)) {
            LOGE("Openssl_EC_GROUP_set_generator failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            HcfPrintOpensslError();
            break;
        }
    } while (0);
    Openssl_BN_free(x);
    Openssl_BN_free(y);
    Openssl_BN_free(order);
    Openssl_BN_free(cofactor);
    Openssl_EC_POINT_free(generator);
    return ret;
}

static HcfResult GenerateSm2GroupWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_GROUP **ecGroup)
{
    if (ecParams == NULL || ecGroup == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_GROUP *group = NULL;
    BN_CTX *ctx = Openssl_BN_CTX_new();
    if (ctx == NULL) {
        LOGE("Alloc ctx memory failed.");
        return HCF_ERR_MALLOC;
    }
    HcfResult ret = NewGroupFromCurveGFp(ecParams, &group, ctx);
    if (ret != HCF_SUCCESS) {
        LOGE("New Ec group fail");
        Openssl_BN_CTX_free(ctx);
        return ret;
    }
    ret = SetSm2PointToGroup(ecParams, group, ctx);
    if (ret != HCF_SUCCESS) {
        Openssl_BN_CTX_free(ctx);
        Openssl_EC_GROUP_free(group);
        LOGE("Set Ec point fail");
        return ret;
    }
    *ecGroup = group;
    return ret;
}

static HcfResult GenerateSm2KeyWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnKey)
{
    if (ecParams == NULL || returnKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    int32_t curveId = 0;
    HcfResult ret = CheckParamsSpecToGetCurveId(ecParams, &curveId);
    if (ret == HCF_SUCCESS && curveId != 0) {
        ecKey = Openssl_EC_KEY_new_by_curve_name(curveId);
        LOGD("generate EC_KEY by curve name");
        if (ecKey == NULL) {
            LOGE("new ec key failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    } else {
        EC_GROUP *group = NULL;
        ret = GenerateSm2GroupWithParamsSpec(ecParams, &group);
        if (ret != HCF_SUCCESS) {
            LOGE("GenerateSm2GroupWithParamsSpec failed.");
            return ret;
        }
        ecKey = Openssl_EC_KEY_new();
        if (ecKey == NULL) {
            LOGE("Openssl_EC_KEY_new failed.");
            Openssl_EC_GROUP_free(group);
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (Openssl_EC_KEY_set_group(ecKey, group) != HCF_OPENSSL_SUCCESS) {
            LOGE("Openssl_EC_KEY_set_group failed.");
            Openssl_EC_GROUP_free(group);
            Openssl_EC_KEY_free(ecKey);
            return HCF_ERR_CRYPTO_OPERATION;
        }
        Openssl_EC_GROUP_free(group);
        LOGD("generate EC_KEY by group spec parmas");
    }
    // all exceptions have been returned above.
    *returnKey = ecKey;
    return HCF_SUCCESS;
}

static HcfResult InitEcKeyByPubKey(const HcfPoint *pubKey, EC_KEY *ecKey)
{
    const EC_GROUP *group = Openssl_EC_KEY_get0_group(ecKey);
    if (group == NULL) {
        LOGE("Not find group from ecKey.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EC_POINT *point = Openssl_EC_POINT_new(group);
    if (point == NULL) {
        LOGE("New ec point failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *pkX = NULL, *pkY = NULL;
    if (BigIntegerToBigNum(&(pubKey->x), &pkX) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(pubKey->y), &pkY) != HCF_SUCCESS) {
        LOGE("BigInteger to BigNum failed.");
        Openssl_EC_POINT_free(point);
        Openssl_BN_free(pkX);
        Openssl_BN_free(pkY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    // only support fp point.
    // can use EC_POINT_set_affine_coordinates() set x and y by group, deep copy.
    int32_t ret = (int32_t)Openssl_EC_POINT_set_affine_coordinates_GFp(group, point, pkX, pkY, NULL);
    Openssl_BN_free(pkX);
    Openssl_BN_free(pkY);

    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_POINT_set_affine_coordinates_GFp failed.");
        Openssl_EC_POINT_free(point);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = Openssl_EC_KEY_set_public_key(ecKey, point);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_KEY_set_public_key failed.");
        Openssl_EC_POINT_free(point);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_EC_POINT_free(point);
    return HCF_SUCCESS;
}

static HcfResult InitEcKeyByPriKey(const HcfBigInteger *priKey, EC_KEY *ecKey)
{
    BIGNUM *sk = NULL;
    if (BigIntegerToBigNum(priKey, &sk) != HCF_SUCCESS) {
        LOGE("BigInteger to BigNum failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t ret = (int32_t)Openssl_EC_KEY_set_private_key(ecKey, sk);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_KEY_set_private_key failed.");
        Openssl_BN_free(sk);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_BN_free(sk);
    return HCF_SUCCESS;
}

static HcfResult SetEcPubKeyFromPriKey(const HcfBigInteger *priKey, EC_KEY *ecKey)
{
    const EC_GROUP *group = Openssl_EC_KEY_get0_group(ecKey);
    if (group == NULL) {
        LOGE("Not find group from ecKey.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *sk = NULL;
    if (BigIntegerToBigNum(priKey, &sk) != HCF_SUCCESS) {
        LOGE("BigInteger to BigNum failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    EC_POINT *point = Openssl_EC_POINT_new(group);
    if (point == NULL) {
        LOGE("Openssl_EC_POINT_new failed.");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }
    if (!Openssl_EC_POINT_mul(group, point, sk, NULL, NULL, NULL)) {
        LOGE("Openssl_EC_POINT_new or Openssl_EC_POINT_mul failed.");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }
    if (!Openssl_EC_KEY_set_public_key(ecKey, point)) {
        LOGE("Openssl_EC_KEY_set_public_key failed.");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_EC_POINT_free(point);
    Openssl_BN_free(sk);
    return ret;
}

static HcfResult SetEcKey(const HcfPoint *pubKey, const HcfBigInteger *priKey, EC_KEY *ecKey)
{
    HcfResult ret = HCF_SUCCESS;
    if (pubKey != NULL) {
        ret = InitEcKeyByPubKey(pubKey, ecKey);
        if (ret != HCF_SUCCESS) {
            LOGE("InitEcKeyByPubKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (priKey != NULL) {
        ret = InitEcKeyByPriKey(priKey, ecKey);
        if (ret != HCF_SUCCESS) {
            LOGE("InitEcKeyByPriKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (pubKey == NULL) {
            ret = SetEcPubKeyFromPriKey(priKey, ecKey);
            if (ret != HCF_SUCCESS) {
                LOGE("SetEcPubKeyFromPriKey failed.");
                return HCF_ERR_CRYPTO_OPERATION;
            }
        }
    }
    return ret;
}

static HcfResult NewSm2KeyPairWithCommSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnEckey)
{
    if (ecParams == NULL || returnEckey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec(ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    if (Openssl_EC_KEY_generate_key(ecKey) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_KEY_generate_key failed.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_KEY_check_key(ecKey) <= 0) {
        LOGE("Check key fail.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEckey = ecKey;
    return ret;
}

static HcfResult NewSm2PubKeyWithPubSpec(const HcfEccPubKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    ret = SetEcKey(&(ecParams->pk), NULL, ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Set pub ecKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_KEY_check_key(ecKey) <= 0) {
        LOGE("Check key fail.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult NewSm2PriKeyWithPriSpec(const HcfEccPriKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    ret = SetEcKey(NULL, &(ecParams->sk), ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Set pri ecKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_KEY_check_key(ecKey) <= 0) {
        LOGE("Check key fail.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
}

static HcfResult NewSm2KeyWithKeyPairSpec(const HcfEccKeyPairParamsSpec *ecParams, EC_KEY **returnEcKey,
    bool needPrivate)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateSm2KeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("generate EC key fails");
        return ret;
    }
    if (needPrivate) {
        ret = SetEcKey(&(ecParams->pk), &(ecParams->sk), ecKey);
    } else {
        ret = SetEcKey(&(ecParams->pk), NULL, ecKey);
    }
    if (ret != HCF_SUCCESS) {
        LOGE("SetEcKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_KEY_check_key(ecKey) <= 0) {
        LOGE("Check key fail.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return ret;
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
    if (!IsClassMatch(self, GetSm2KeyPairGeneratorClass())) {
        return;
    }
    HcfFree(self);
}

static void DestroySm2PubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetSm2PubKeyClass())) {
        return;
    }
    HcfOpensslSm2PubKey *impl = (HcfOpensslSm2PubKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroySm2PriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetSm2PriKeyClass())) {
        return;
    }
    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroySm2KeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetSm2KeyPairClass())) {
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
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2PriKeyClass())) {
        return;
    }
    HcfOpensslSm2PriKey *impl = (HcfOpensslSm2PriKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
}

static HcfResult GetCurveGFp(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    BIGNUM *p = Openssl_BN_new();
    BIGNUM *a = Openssl_BN_new();
    BIGNUM *b = Openssl_BN_new();
    if (p == NULL || a == NULL || b == NULL) {
        LOGE("new BN failed.");
        Openssl_BN_free(p);
        Openssl_BN_free(a);
        Openssl_BN_free(b);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_GROUP_get_curve_GFp(group, p, a, b, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_GROUP_get_curve_GFp failed.");
        Openssl_BN_free(p);
        Openssl_BN_free(a);
        Openssl_BN_free(b);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case ECC_FP_P_BN:
            ret = BigNumToBigInteger(p, returnBigInteger);
            break;
        case ECC_A_BN:
            ret = BigNumToBigInteger(a, returnBigInteger);
            break;
        case ECC_B_BN:
            ret = BigNumToBigInteger(b, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            break;
    }
    Openssl_BN_free(p);
    Openssl_BN_free(a);
    Openssl_BN_free(b);
    return ret;
}

static HcfResult GetGenerator(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    const EC_POINT *generator = Openssl_EC_GROUP_get0_generator(group);
    if (generator == NULL) {
        LOGE("Openssl_EC_GROUP_get0_generator failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    BIGNUM *gX = Openssl_BN_new();
    BIGNUM *gY = Openssl_BN_new();
    if (gX == NULL || gY == NULL) {
        LOGE("new BN failed.");
        Openssl_BN_free(gX);
        Openssl_BN_free(gY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_POINT_get_affine_coordinates_GFp(group, generator, gX, gY, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
        Openssl_BN_free(gX);
        Openssl_BN_free(gY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case ECC_G_X_BN:
            ret = BigNumToBigInteger(gX, returnBigInteger);
            break;
        case ECC_G_Y_BN:
            ret = BigNumToBigInteger(gY, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            break;
    }
    Openssl_BN_free(gX);
    Openssl_BN_free(gY);
    return ret;
}

static HcfResult GetOrder(const EC_GROUP *group, HcfBigInteger *returnBigInteger)
{
    BIGNUM *order = Openssl_BN_new();
    if (order == NULL) {
        LOGE("new BN failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_GROUP_get_order(group, order, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
        Openssl_BN_free(order);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = BigNumToBigInteger(order, returnBigInteger);
    Openssl_BN_free(order);
    return ret;
}

static HcfResult GetCofactor(const EC_GROUP *group, int *returnCofactor)
{
    BIGNUM *cofactor = Openssl_BN_new();
    if (cofactor == NULL) {
        LOGE("new BN failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_GROUP_get_cofactor(group, cofactor, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
        Openssl_BN_free(cofactor);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    *returnCofactor = (int)(Openssl_BN_get_word(cofactor));
    // cofactor should not be zero.
    if (*returnCofactor == 0) {
        LOGE("Openssl_BN_get_word failed.");
        Openssl_BN_free(cofactor);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_BN_free(cofactor);
    return HCF_SUCCESS;
}

static HcfResult GetFieldSize(const EC_GROUP *group, int32_t *fieldSize)
{
    *fieldSize = Openssl_EC_GROUP_get_degree(group);
    if (*fieldSize == 0) {
        LOGE("Openssl_EC_GROUP_get_degree failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GetPubKeyXOrY(const EC_GROUP *group, const EC_POINT *point, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    BIGNUM *pkX = Openssl_BN_new();
    BIGNUM *pkY = Openssl_BN_new();
    if (pkX == NULL || pkY == NULL) {
        LOGE("new BN failed.");
        Openssl_BN_free(pkX);
        Openssl_BN_free(pkY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_POINT_get_affine_coordinates_GFp(group, point, pkX, pkY, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
        Openssl_BN_free(pkX);
        Openssl_BN_free(pkY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = HCF_INVALID_PARAMS;
    switch (item) {
        case ECC_PK_X_BN:
            ret = BigNumToBigInteger(pkX, returnBigInteger);
            break;
        case ECC_PK_Y_BN:
            ret = BigNumToBigInteger(pkY, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            break;
    }
    Openssl_BN_free(pkX);
    Openssl_BN_free(pkY);
    return ret;
}

static HcfResult GetFieldType(const HcfKey *self, bool isPrivate, char **returnString)
{
    char *fieldType = NULL;
    if (isPrivate) {
        fieldType = ((HcfOpensslSm2PriKey *)self)->fieldType;
    } else {
        fieldType = ((HcfOpensslSm2PubKey *)self)->fieldType;
    }

    if (fieldType == NULL) {
        LOGE("No fieldType in Sm2PubKey struct.");
        return HCF_INVALID_PARAMS;
    }

    size_t len = HcfStrlen(fieldType);
    if (!len) {
        LOGE("fieldType is empty!");
        return HCF_INVALID_PARAMS;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Alloc returnString memory failed.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(*returnString, len, fieldType, len) != EOK) {
        LOGE("memcpy returnString failed.");
        HcfFree(*returnString);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult GetCurveName(const HcfKey *self, bool isPriavte, char **returnString)
{
    int32_t curveId = 0;
    if (isPriavte) {
        curveId = ((HcfOpensslSm2PriKey *)self)->curveId;
    } else {
        curveId = ((HcfOpensslSm2PubKey *)self)->curveId;
    }

    char *tmp = NULL;
    if (curveId != NID_sm2) {
        LOGE("No curve name.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    tmp = "NID_sm2";

    size_t len = HcfStrlen(tmp);
    if (!len) {
        LOGE("tmp is empty!");
        return HCF_INVALID_PARAMS;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Alloc returnString memory failed.");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(*returnString, len, tmp, len) != EOK) {
        LOGE("memcpy returnString failed.");
        HcfFree(*returnString);
        return HCF_ERR_MALLOC;
    }
    return HCF_SUCCESS;
}

static HcfResult CheckSm2KeySelf(const HcfKey *self, bool *isPrivate)
{
    if (IsClassMatch((HcfObjectBase *)self, GetSm2PubKeyClass())) {
        *isPrivate = false;
        return HCF_SUCCESS;
    } else if (IsClassMatch((HcfObjectBase *)self, GetSm2PriKeyClass())) {
        if (((HcfOpensslSm2PriKey *)self)->ecKey == NULL) {
            LOGE("Cannot use priKey after free");
            return HCF_INVALID_PARAMS;
        }
        *isPrivate = true;
        return HCF_SUCCESS;
    } else {
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult GetPkSkBigInteger(const HcfKey *self, bool isPrivate,
    const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    if (item == ECC_SK_BN) {
        if (!isPrivate) {
            LOGE("ecc pub key has no private key spec item");
            return ret;
        }
        ret = BigNumToBigInteger(Openssl_EC_KEY_get0_private_key(((HcfOpensslEccPriKey *)self)->ecKey),
            returnBigInteger);
    } else {
        if (isPrivate) {
            LOGE("ecc pri key cannot get pub key spec item");
            return ret;
        }
        ret = GetPubKeyXOrY(Openssl_EC_KEY_get0_group(((HcfOpensslEccPubKey *)self)->ecKey),
            Openssl_EC_KEY_get0_public_key(((HcfOpensslEccPubKey *)self)->ecKey), item, returnBigInteger);
    }
    return ret;
}

static HcfResult GetSm2KeySpecBigInteger(const HcfKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult ret = CheckSm2KeySelf(self, &isPrivate);
    if (ret != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPriKey *)self)->ecKey);
    } else {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPubKey *)self)->ecKey);
    }
    if (group == NULL) {
        LOGE("get group failed");
        return HCF_INVALID_PARAMS;
    }
    switch (item) {
        case ECC_FP_P_BN:
        case ECC_A_BN:
        case ECC_B_BN:
            ret = GetCurveGFp(group, item, returnBigInteger);
            break;
        case ECC_G_X_BN:
        case ECC_G_Y_BN:
            ret = GetGenerator(group, item, returnBigInteger);
            break;
        case ECC_N_BN:
            ret = GetOrder(group, returnBigInteger);
            break;
        case ECC_SK_BN:
        case ECC_PK_X_BN:
        case ECC_PK_Y_BN:
            ret = GetPkSkBigInteger(self, isPrivate, item, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            ret = HCF_INVALID_PARAMS;
            break;
    }
    return ret;
}

static HcfResult GetSm2KeySpecString(const HcfKey *self, const AsyKeySpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult ret = CheckSm2KeySelf(self, &isPrivate);
    if (ret != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }

    switch (item) {
        case ECC_FIELD_TYPE_STR:
            ret = GetFieldType(self, isPrivate, returnString);
            break;
        case ECC_CURVE_NAME_STR:
            ret = GetCurveName(self, isPrivate, returnString);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            LOGE("Invalid spec of ec string");
            break;
    }
    return ret;
}

static HcfResult GetSm2KeySpecInt(const HcfKey *self, const AsyKeySpecItem item, int *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult ret = CheckSm2KeySelf(self, &isPrivate);
    if (ret != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPriKey *)self)->ecKey);
    } else {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPubKey *)self)->ecKey);
    }
    if (group == NULL) {
        LOGE("get group failed");
        return HCF_INVALID_PARAMS;
    }
    switch (item) {
        case ECC_H_INT:
            ret = GetCofactor(group, returnInt);
            break;
        case ECC_FIELD_SIZE_INT:
            ret = GetFieldSize(group, returnInt);
            break;
        default:
            ret = HCF_INVALID_PARAMS;
            LOGE("invalid ec key int spec");
            break;
    }
    return ret;
}

static HcfResult GetSm2PubKeySpecBigInteger(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetSm2KeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetSm2PriKeySpecBigInteger(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetSm2KeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetSm2PubKeySpecString(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetSm2KeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetSm2PriKeySpecString(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetSm2KeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetSm2PubKeySpecInt(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetSm2KeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult GetSm2PriKeySpecInt(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetSm2KeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult PackSm2PubKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslSm2PubKey **returnObj)
{
    HcfOpensslSm2PubKey *returnPubKey = (HcfOpensslSm2PubKey *)HcfMalloc(sizeof(HcfOpensslSm2PubKey), 0);
    if (returnPubKey == NULL) {
        LOGE("Failed to allocate returnPubKey memory!");
        return HCF_ERR_MALLOC;
    }

    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        size_t len = HcfStrlen(fieldType);
        if (!len) {
            LOGE("fieldType is empty!");
            return HCF_INVALID_PARAMS;
        }
        tmpFieldType = (char *)HcfMalloc(len + 1, 0);
        if (tmpFieldType == NULL) {
            LOGE("Alloc tmpFieldType memory failed.");
            HcfFree(returnPubKey);
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(tmpFieldType, len, fieldType, len);
    }
    returnPubKey->base.base.base.destroy = DestroySm2PubKey;
    returnPubKey->base.base.base.getClass = GetSm2PubKeyClass;
    returnPubKey->base.base.getAlgorithm = GetSm2PubKeyAlgorithm;
    returnPubKey->base.base.getEncoded = GetSm2PubKeyEncoded;
    returnPubKey->base.base.getFormat = GetSm2PubKeyFormat;
    returnPubKey->base.getAsyKeySpecBigInteger = GetSm2PubKeySpecBigInteger;
    returnPubKey->base.getAsyKeySpecString = GetSm2PubKeySpecString;
    returnPubKey->base.getAsyKeySpecInt = GetSm2PubKeySpecInt;
    returnPubKey->curveId = curveId;
    returnPubKey->ecKey = ecKey;
    returnPubKey->fieldType = tmpFieldType;

    *returnObj = returnPubKey;
    return HCF_SUCCESS;
}

static HcfResult PackSm2PriKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslSm2PriKey **returnObj)
{
    HcfOpensslSm2PriKey *returnPriKey = (HcfOpensslSm2PriKey *)HcfMalloc(sizeof(HcfOpensslSm2PriKey), 0);
    if (returnPriKey == NULL) {
        LOGE("Failed to allocate returnPriKey memory!");
        return HCF_ERR_MALLOC;
    }

    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        int32_t len = (int32_t)strlen(fieldType);
        tmpFieldType = (char *)HcfMalloc(len + 1, 0);
        if (tmpFieldType == NULL) {
            LOGE("Alloc tmpFieldType memory failed.");
            HcfFree(returnPriKey);
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(tmpFieldType, len, fieldType, len);
    }
    returnPriKey->base.base.base.destroy = DestroySm2PriKey;
    returnPriKey->base.base.base.getClass = GetSm2PriKeyClass;
    returnPriKey->base.base.getAlgorithm = GetSm2PriKeyAlgorithm;
    returnPriKey->base.base.getEncoded = GetSm2PriKeyEncoded;
    returnPriKey->base.base.getFormat = GetSm2PriKeyFormat;
    returnPriKey->base.getAsyKeySpecBigInteger = GetSm2PriKeySpecBigInteger;
    returnPriKey->base.getAsyKeySpecString = GetSm2PriKeySpecString;
    returnPriKey->base.getAsyKeySpecInt = GetSm2PriKeySpecInt;
    returnPriKey->base.clearMem = Sm2PriKeyClearMem;
    returnPriKey->curveId = curveId;
    returnPriKey->ecKey = ecKey;
    returnPriKey->fieldType = tmpFieldType;

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
    HcfResult ret = PackSm2PubKey(curveId, ecKey, g_sm2GenerateFieldType, returnPubKey);
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
    HcfResult ret = PackSm2PriKey(curveId, ecKey, g_sm2GenerateFieldType, returnPriKey);
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

static HcfResult PackAndAssignPubKey(const HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPubKey **returnObj)
{
    HcfOpensslSm2PubKey *pubKey = NULL;
    HcfResult ret = PackSm2PubKey(impl->curveId, ecKey, fieldType, &pubKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnObj = (HcfPubKey *)pubKey;
    return HCF_SUCCESS;
}

static HcfResult PackAndAssignPriKey(const HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPriKey **returnObj)
{
    HcfOpensslSm2PriKey *priKey = NULL;
    HcfResult ret = PackSm2PriKey(impl->curveId, ecKey, fieldType, &priKey);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    *returnObj = (HcfPriKey *)priKey;
    return HCF_SUCCESS;
}

static HcfResult CreateAndAssignKeyPair(const HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfKeyPair **returnObj)
{
    EC_KEY *ecPriKey = EC_KEY_dup(ecKey);
    if (ecPriKey == NULL) {
        LOGE("copy ecKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslSm2PriKey *priKey = NULL;
    HcfResult ret = PackSm2PriKey(impl->curveId, ecPriKey, fieldType, &priKey);
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
    ret = PackSm2PubKey(impl->curveId, ecPubKey, fieldType, &pubKey);
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
        ret = CreateAndAssignKeyPair(impl, g_sm2GenerateFieldType, ecKey, returnObj);
        if (ret != HCF_SUCCESS) {
            LOGE("CreateAndAssignKeyPair failed.");
        }
        Openssl_EC_KEY_free(ecKey);
    }
    return ret;
}

static HcfResult GenKeyPairSm2KeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = NewSm2KeyPairWithCommSpec((HcfEccCommParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewSm2KeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invaild input spec to gen key pair.");
            break;
    }
    return ret;
}

static HcfResult GenPubKeySm2KeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            ret = NewSm2PubKeyWithPubSpec((HcfEccPubKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewSm2KeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, false);
            break;
        default:
            LOGE("Invaild input spec to gen pub key");
            break;
    }
    return ret;
}

static HcfResult GenPriKeySm2KeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            ret = NewSm2PriKeyWithPriSpec((HcfEccPriKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewSm2KeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invaild input spec to gen pri key");
            break;
    }
    return ret;
}

static HcfResult EngineGenerateKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2KeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenKeyPairSm2KeyBySpec(params, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Gen ec key pair with spec failed.");
        return ret;
    }

    // curveId == 0 means no curve to match.
    int32_t curveId = (int32_t)Openssl_EC_GROUP_get_curve_name(Openssl_EC_KEY_get0_group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }
    // deep copy of ecKey, free ecKey whether it succeed or failed.
    ret = CreateAndAssignKeyPair(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnKeyPair);
    Openssl_EC_KEY_free(ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("CreateAndAssignKeyPair failed.");
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGeneratePubKeyBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfPubKey **returnPubKey)
{
    if ((self == NULL) || (returnPubKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2KeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenPubKeySm2KeyBySpec(params, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Gen ec pubKey with spec failed.");
        return ret;
    }
    int32_t curveId = (int32_t)Openssl_EC_GROUP_get_curve_name(Openssl_EC_KEY_get0_group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }
    ret = PackAndAssignPubKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPubKey);
    if (ret != HCF_SUCCESS) {
        LOGE("PackAndAssignPubKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGeneratePriKeyBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfPriKey **returnPriKey)
{
    if ((self == NULL) || (returnPriKey == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetSm2KeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslSm2Impl *impl = (HcfAsyKeyGeneratorSpiOpensslSm2Impl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenPriKeySm2KeyBySpec(params, &ecKey);
    if (ret != HCF_SUCCESS) {
        LOGE("Gen ec priKey with spec failed.");
        return ret;
    }

    int32_t curveId = (int32_t)Openssl_EC_GROUP_get_curve_name(Openssl_EC_KEY_get0_group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }

    ret = PackAndAssignPriKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPriKey);
    if (ret != HCF_SUCCESS) {
        LOGE("PackAndAssignPriKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return ret;
    }
    return HCF_SUCCESS;
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
    returnImpl->base.engineGenerateKeyPairBySpec = EngineGenerateKeyPairBySpec;
    returnImpl->base.engineGeneratePubKeyBySpec = EngineGeneratePubKeyBySpec;
    returnImpl->base.engineGeneratePriKeyBySpec = EngineGeneratePriKeyBySpec;
    returnImpl->curveId = curveId;

    *returnObj = (HcfAsyKeyGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
