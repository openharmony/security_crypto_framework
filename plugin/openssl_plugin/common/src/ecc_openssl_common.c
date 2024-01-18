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
#include "ecc_openssl_common.h"

#include "securec.h"

#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "utils.h"

HcfResult NewEcKeyPair(int32_t curveId, EC_KEY **returnEcKey)
{
    EC_KEY *ecKey = Openssl_EC_KEY_new_by_curve_name(curveId);
    if (ecKey == NULL) {
        LOGD("[error] new ec key failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EC_KEY_generate_key(ecKey) <= 0) {
        LOGD("[error] generate ec key failed.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_EC_KEY_check_key(ecKey) <= 0) {
        LOGD("[error] check key fail.");
        Openssl_EC_KEY_free(ecKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnEcKey = ecKey;
    return HCF_SUCCESS;
}

void FreeCurveBigNum(BIGNUM *pStd, BIGNUM *bStd, BIGNUM *xStd, BIGNUM *yStd)
{
    Openssl_BN_free(pStd);
    Openssl_BN_free(bStd);
    Openssl_BN_free(xStd);
    Openssl_BN_free(yStd);
}

static HcfResult NewGroupFromCurveGFp(const HcfEccCommParamsSpec *ecParams, EC_GROUP **ecGroup, BN_CTX *ctx)
{
    HcfResult ret = HCF_SUCCESS;
    HcfECFieldFp *field = (HcfECFieldFp *)(ecParams->field);
    BIGNUM *p = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    EC_GROUP *group = NULL;
    do {
        if (BigIntegerToBigNum(&(field->p), &p) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->a), &a) != HCF_SUCCESS ||
            BigIntegerToBigNum(&(ecParams->b), &b) != HCF_SUCCESS) {
            LOGD("[error] BigInteger to BigNum failed");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        group = Openssl_EC_GROUP_new_curve_GFp(p, a, b, ctx);
        if (group == NULL) {
            LOGD("[error] Alloc group memory failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    Openssl_BN_free(p);
    Openssl_BN_free(a);
    Openssl_BN_free(b);

    if (ret == HCF_SUCCESS) {
        *ecGroup = group;
        return ret;
    }
    Openssl_EC_GROUP_free(group);
    return ret;
}

static HcfResult SetEcPointToGroup(const HcfEccCommParamsSpec *ecParams, EC_GROUP *group, BN_CTX *ctx)
{
    HcfResult ret = HCF_SUCCESS;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
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
            LOGD("[error] BigInteger to BigNum failed.");
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
            LOGD("[error] Openssl_EC_POINT_set_affine_coordinates_GFp failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            HcfPrintOpensslError();
            break;
        }

        if (!Openssl_EC_GROUP_set_generator(group, generator, order, cofactor)) {
            LOGD("[error] Openssl_EC_GROUP_set_generator failed.");
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

HcfResult GenerateEcGroupWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_GROUP **ecGroup)
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
        LOGD("[error] New Ec group fail");
        Openssl_BN_CTX_free(ctx);
        return ret;
    }
    ret = SetEcPointToGroup(ecParams, group, ctx);
    if (ret != HCF_SUCCESS) {
        Openssl_BN_CTX_free(ctx);
        Openssl_EC_GROUP_free(group);
        LOGD("[error] Set Ec point fail");
        return ret;
    }
    *ecGroup = group;
    return ret;
}

static HcfResult InitEcKeyByPubKey(const HcfPoint *pubKey, EC_KEY *ecKey)
{
    const EC_GROUP *group = Openssl_EC_KEY_get0_group(ecKey);
    if (group == NULL) {
        LOGD("[error] Not find group from ecKey.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    EC_POINT *point = Openssl_EC_POINT_new(group);
    if (point == NULL) {
        LOGD("[error] New ec point failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *pkX = NULL;
    BIGNUM *pkY = NULL;
    if (BigIntegerToBigNum(&(pubKey->x), &pkX) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(pubKey->y), &pkY) != HCF_SUCCESS) {
        LOGD("[error] BigInteger to BigNum failed.");
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
        LOGD("[error] Openssl_EC_POINT_set_affine_coordinates_GFp failed.");
        Openssl_EC_POINT_free(point);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = Openssl_EC_KEY_set_public_key(ecKey, point);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl_EC_KEY_set_public_key failed.");
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
        LOGD("[error] BigInteger to BigNum failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    int32_t ret = (int32_t)Openssl_EC_KEY_set_private_key(ecKey, sk);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl_EC_KEY_set_private_key failed.");
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
        LOGD("[error] Not find group from ecKey.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *sk = NULL;
    if (BigIntegerToBigNum(priKey, &sk) != HCF_SUCCESS) {
        LOGD("[error] BigInteger to BigNum failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;
    EC_POINT *point = Openssl_EC_POINT_new(group);
    do {
        if (point == NULL) {
            LOGD("[error] Openssl_EC_POINT_new failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (!Openssl_EC_POINT_mul(group, point, sk, NULL, NULL, NULL)) {
            LOGD("[error] EC_POINT_mul failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (!Openssl_EC_KEY_set_public_key(ecKey, point)) {
            LOGD("[error] Openssl_EC_KEY_set_public_key failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
        }
    } while (0);
    Openssl_EC_POINT_free(point);
    Openssl_BN_free(sk);
    return ret;
}

HcfResult SetEcKey(const HcfPoint *pubKey, const HcfBigInteger *priKey, EC_KEY *ecKey)
{
    HcfResult ret = HCF_SUCCESS;
    if (pubKey != NULL) {
        ret = InitEcKeyByPubKey(pubKey, ecKey);
        if (ret != HCF_SUCCESS) {
            LOGD("[error] InitEcKeyByPubKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    if (priKey != NULL) {
        ret = InitEcKeyByPriKey(priKey, ecKey);
        if (ret != HCF_SUCCESS) {
            LOGD("[error] InitEcKeyByPriKey failed.");
            return HCF_ERR_CRYPTO_OPERATION;
        }
        if (pubKey == NULL) {
            ret = SetEcPubKeyFromPriKey(priKey, ecKey);
            if (ret != HCF_SUCCESS) {
                LOGD("[error] SetEcPubKeyFromPriKey failed.");
                return HCF_ERR_CRYPTO_OPERATION;
            }
        }
    }
    return ret;
}

HcfResult GetCurveGFp(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    BIGNUM *p = Openssl_BN_new();
    BIGNUM *a = Openssl_BN_new();
    BIGNUM *b = Openssl_BN_new();
    if (p == NULL || a == NULL || b == NULL) {
        LOGD("[error] new BN failed.");
        Openssl_BN_free(p);
        Openssl_BN_free(a);
        Openssl_BN_free(b);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_GROUP_get_curve_GFp(group, p, a, b, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl_EC_GROUP_get_curve_GFp failed.");
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
            LOGD("[error] Invalid ecc key big number spec!");
            break;
    }
    Openssl_BN_free(p);
    Openssl_BN_free(a);
    Openssl_BN_free(b);
    return ret;
}

HcfResult GetGenerator(const EC_GROUP *group, const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    const EC_POINT *generator = Openssl_EC_GROUP_get0_generator(group);
    if (generator == NULL) {
        LOGD("[error] Openssl_EC_GROUP_get0_generator failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    BIGNUM *gX = Openssl_BN_new();
    BIGNUM *gY = Openssl_BN_new();
    if (gX == NULL || gY == NULL) {
        LOGD("[error] new BN failed.");
        Openssl_BN_free(gX);
        Openssl_BN_free(gY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_POINT_get_affine_coordinates_GFp(group, generator, gX, gY, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
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

HcfResult GetOrder(const EC_GROUP *group, HcfBigInteger *returnBigInteger)
{
    BIGNUM *order = Openssl_BN_new();
    if (order == NULL) {
        LOGD("[error] new BN failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_GROUP_get_order(group, order, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
        Openssl_BN_free(order);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    HcfResult ret = BigNumToBigInteger(order, returnBigInteger);
    Openssl_BN_free(order);
    return ret;
}

HcfResult GetCofactor(const EC_GROUP *group, int *returnCofactor)
{
    BIGNUM *cofactor = Openssl_BN_new();
    if (cofactor == NULL) {
        LOGD("[error] new BN failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_GROUP_get_cofactor(group, cofactor, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
        Openssl_BN_free(cofactor);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    *returnCofactor = (int)(Openssl_BN_get_word(cofactor));
    // cofactor should not be zero.
    if (*returnCofactor == 0) {
        LOGD("[error] Openssl_BN_get_word failed.");
        Openssl_BN_free(cofactor);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Openssl_BN_free(cofactor);
    return HCF_SUCCESS;
}

HcfResult GetFieldSize(const EC_GROUP *group, int32_t *fieldSize)
{
    *fieldSize = Openssl_EC_GROUP_get_degree(group);
    if (*fieldSize == 0) {
        LOGD("[error] Openssl_EC_GROUP_get_degree failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult GetFieldType(const HcfKey *self, const bool isPrivate, char **returnString)
{
    char *fieldType = NULL;
    if (isPrivate) {
        fieldType = ((HcfOpensslEccPriKey *)self)->fieldType;
    } else {
        fieldType = ((HcfOpensslEccPubKey *)self)->fieldType;
    }

    if (fieldType == NULL) {
        LOGE("No fieldType in EccPubKey struct.");
        return HCF_INVALID_PARAMS;
    }

    size_t len = HcfStrlen(fieldType);
    if (len == 0) {
        LOGE("fieldType is empty!");
        return HCF_INVALID_PARAMS;
    }
    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Alloc returnString memory failed.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(*returnString, len, fieldType, len);

    return HCF_SUCCESS;
}

static HcfResult GetPubKeyXOrY(const EC_GROUP *group, const EC_POINT *point, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    BIGNUM *pkX = Openssl_BN_new();
    BIGNUM *pkY = Openssl_BN_new();
    if (pkX == NULL || pkY == NULL) {
        LOGD("[error] new BN failed.");
        Openssl_BN_free(pkX);
        Openssl_BN_free(pkY);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (Openssl_EC_POINT_get_affine_coordinates_GFp(group, point, pkX, pkY, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGD("[error] Openssl_EC_POINT_get_affine_coordinates_GFp failed.");
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
            LOGD("[error] Invalid ecc key big number spec!");
            break;
    }
    Openssl_BN_free(pkX);
    Openssl_BN_free(pkY);
    return ret;
}

HcfResult GetPkSkBigInteger(const HcfKey *self, bool isPrivate,
    const AsyKeySpecItem item, HcfBigInteger *returnBigInteger)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    if (item == ECC_SK_BN) {
        if (!isPrivate) {
            LOGD("[error] ecc pub key has no private key spec item");
            return ret;
        }
        ret = BigNumToBigInteger(Openssl_EC_KEY_get0_private_key(((HcfOpensslEccPriKey *)self)->ecKey),
            returnBigInteger);
    } else {
        if (isPrivate) {
            LOGD("[error] ecc pri key cannot get pub key spec item");
            return ret;
        }
        ret = GetPubKeyXOrY(Openssl_EC_KEY_get0_group(((HcfOpensslEccPubKey *)self)->ecKey),
            Openssl_EC_KEY_get0_public_key(((HcfOpensslEccPubKey *)self)->ecKey), item, returnBigInteger);
    }
    return ret;
}
