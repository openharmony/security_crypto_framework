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

#include "ecc_asy_key_generator_openssl.h"

#include "securec.h"

#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "utils.h"

#define OPENSSL_ECC_KEY_GENERATOR_CLASS "OPENSSL.ECC.KEY_GENERATOR_CLASS"
#define OPENSSL_ECC_ALGORITHM "EC"
#define OPENSSL_ECC_PUB_KEY_FORMAT "X.509"
#define OPENSSL_ECC_PRI_KEY_FORMAT "PKCS#8"
#define OPENSSL_ECC160_BITS 160
#define OPENSSL_ECC192_BITS 192
#define OPENSSL_ECC224_BITS 224
#define OPENSSL_ECC256_BITS 256
#define OPENSSL_ECC320_BITS 320
#define OPENSSL_ECC384_BITS 384
#define OPENSSL_ECC512_BITS 512
#define OPENSSL_ECC521_BITS 521

static const char *g_eccGenerateFieldType = "Fp";

typedef struct {
    BIGNUM *p;
    BIGNUM *b;
    BIGNUM *x;
    BIGNUM *y;
}HcfBigIntegerParams;

typedef struct {
    HcfAsyKeyGeneratorSpi base;

    int32_t curveId;
} HcfAsyKeyGeneratorSpiOpensslEccImpl;

static HcfResult CheckEc224CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_ecc224CorrectBigP, NID_secp224r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_ecc224CorrectBigB, NID_secp224r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_ecc224CorrectBigGX, NID_secp224r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_ecc224CorrectBigGY, NID_secp224r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("EC 224 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("EC 224 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckEc256CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_ecc256CorrectBigP, NID_X9_62_prime256v1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_ecc256CorrectBigB, NID_X9_62_prime256v1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_ecc256CorrectBigGX, NID_X9_62_prime256v1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_ecc256CorrectBigGY, NID_X9_62_prime256v1_len, NULL);
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

static HcfResult CheckEc384CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_ecc384CorrectBigP, NID_secp384r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_ecc384CorrectBigB, NID_secp384r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_ecc384CorrectBigGX, NID_secp384r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_ecc384CorrectBigGY, NID_secp384r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("EC 384 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("EC 384 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckEc521CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_ecc521CorrectBigP, NID_secp521r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_ecc521CorrectBigB, NID_secp521r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_ecc521CorrectBigGX, NID_secp521r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_ecc521CorrectBigGY, NID_secp521r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("EC 521 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("EC 521 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP160r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp160r1CorrectBigP, NID_brainpoolP160r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp160r1CorrectBigB, NID_brainpoolP160r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp160r1CorrectBigGX, NID_brainpoolP160r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp160r1CorrectBigGY, NID_brainpoolP160r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 160r1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("BP 160r1 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP160t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp160t1CorrectBigP, NID_brainpoolP160t1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp160t1CorrectBigB, NID_brainpoolP160t1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp160t1CorrectBigGX, NID_brainpoolP160t1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp160t1CorrectBigGY, NID_brainpoolP160t1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 160t1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("BP 160t1 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP192r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp192r1CorrectBigP, NID_brainpoolP192r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp192r1CorrectBigB, NID_brainpoolP192r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp192r1CorrectBigGX, NID_brainpoolP192r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp192r1CorrectBigGY, NID_brainpoolP192r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 192r1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("BP 192r1 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP192t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp192t1CorrectBigP, NID_brainpoolP192t1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp192t1CorrectBigB, NID_brainpoolP192t1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp192t1CorrectBigGX, NID_brainpoolP192t1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp192t1CorrectBigGY, NID_brainpoolP192t1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 192t1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("BP 192t1 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP224r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp224r1CorrectBigP, NID_brainpoolP224r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp224r1CorrectBigB, NID_brainpoolP224r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp224r1CorrectBigGX, NID_brainpoolP224r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp224r1CorrectBigGY, NID_brainpoolP224r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 224r1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("BP 224r1 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP224t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp224t1CorrectBigP, NID_brainpoolP224t1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp224t1CorrectBigB, NID_brainpoolP224t1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp224t1CorrectBigGX, NID_brainpoolP224t1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp224t1CorrectBigGY, NID_brainpoolP224t1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 224t1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("BP 224t1 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP256r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp256r1CorrectBigP, NID_brainpoolP256r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp256r1CorrectBigB, NID_brainpoolP256r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp256r1CorrectBigGX, NID_brainpoolP256r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp256r1CorrectBigGY, NID_brainpoolP256r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 256r1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    LOGE("BP 256r1 compare fail");
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP256t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp256t1CorrectBigP, NID_brainpoolP256t1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp256t1CorrectBigB, NID_brainpoolP256t1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp256t1CorrectBigGX, NID_brainpoolP256t1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp256t1CorrectBigGY, NID_brainpoolP256t1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 256t1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP320r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp320r1CorrectBigP, NID_brainpoolP320r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp320r1CorrectBigB, NID_brainpoolP320r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp320r1CorrectBigGX, NID_brainpoolP320r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp320r1CorrectBigGY, NID_brainpoolP320r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 320r1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP320t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp320t1CorrectBigP, NID_brainpoolP320t1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp320t1CorrectBigB, NID_brainpoolP320t1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp320t1CorrectBigGX, NID_brainpoolP320t1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp320t1CorrectBigGY, NID_brainpoolP320t1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 320t1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP384r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp384r1CorrectBigP, NID_brainpoolP384r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp384r1CorrectBigB, NID_brainpoolP384r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp384r1CorrectBigGX, NID_brainpoolP384r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp384r1CorrectBigGY, NID_brainpoolP384r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 384r1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP384t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp384t1CorrectBigP, NID_brainpoolP384t1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp384t1CorrectBigB, NID_brainpoolP384t1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp384t1CorrectBigGX, NID_brainpoolP384t1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp384t1CorrectBigGY, NID_brainpoolP384t1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 384t1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP512r1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp512r1CorrectBigP, NID_brainpoolP512r1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp512r1CorrectBigB, NID_brainpoolP512r1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp512r1CorrectBigGX, NID_brainpoolP512r1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp512r1CorrectBigGY, NID_brainpoolP512r1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 512r1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CheckBP512t1CurveId(BIGNUM *p, BIGNUM *b, BIGNUM *x, BIGNUM *y)
{
    BIGNUM *pStd = NULL, *bStd = NULL, *xStd = NULL, *yStd = NULL;
    pStd = Openssl_BN_bin2bn(g_bp512t1CorrectBigP, NID_brainpoolP512t1_len, NULL);
    bStd = Openssl_BN_bin2bn(g_bp512t1CorrectBigB, NID_brainpoolP512t1_len, NULL);
    xStd = Openssl_BN_bin2bn(g_bp512t1CorrectBigGX, NID_brainpoolP512t1_len, NULL);
    yStd = Openssl_BN_bin2bn(g_bp512t1CorrectBigGY, NID_brainpoolP512t1_len, NULL);
    if ((pStd == NULL) || (bStd == NULL) || (xStd == NULL) || (yStd == NULL)) {
        LOGE("BP 512t1 Curve convert to BN fail");
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_BN_cmp(p, pStd) == 0 && Openssl_BN_cmp(b, bStd) == 0 &&
        Openssl_BN_cmp(x, xStd) == 0 && Openssl_BN_cmp(y, yStd) == 0) {
        FreeCurveBigNum(pStd, bStd, xStd, yStd);
        return HCF_SUCCESS;
    }
    FreeCurveBigNum(pStd, bStd, xStd, yStd);
    return HCF_INVALID_PARAMS;
}

static HcfResult CompareOpenssl160BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckBP160r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP160r1;
        return HCF_SUCCESS;
    } else if (CheckBP160t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP160t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl192BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckBP192r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP192r1;
        return HCF_SUCCESS;
    } else if (CheckBP192t1CurveId(bigIntegerParams->p, bigIntegerParams->b,
        bigIntegerParams->x, bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP192t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl224BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = HCF_INVALID_PARAMS;
    res = CheckEc224CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_secp224r1;
        return res;
    } else if (CheckBP224r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP224r1;
        return HCF_SUCCESS;
    } else if (CheckBP224t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP224t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl256BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = HCF_INVALID_PARAMS;
    res = CheckEc256CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_X9_62_prime256v1;
        return res;
    } else if (CheckBP256r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP256r1;
        return HCF_SUCCESS;
    } else if (CheckBP256t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP256t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl320BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckBP320r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP320r1;
        return HCF_SUCCESS;
    } else if (CheckBP320t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP320t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl384BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = HCF_INVALID_PARAMS;
    res = CheckBP384r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_brainpoolP384r1;
        return res;
    } else if (CheckEc384CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_secp384r1;
        return HCF_SUCCESS;
    } else if (CheckBP384t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP384t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl512BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    if (CheckBP512r1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP512r1;
        return HCF_SUCCESS;
    } else if (CheckBP512t1CurveId(bigIntegerParams->p, bigIntegerParams->b, bigIntegerParams->x,
        bigIntegerParams->y) == HCF_SUCCESS) {
        *curveId = NID_brainpoolP512t1;
        return HCF_SUCCESS;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CompareOpenssl521BitsType(const HcfEccCommParamsSpec *ecParams, int32_t *curveId,
    HcfBigIntegerParams *bigIntegerParams)
{
    HcfResult res = CheckEc521CurveId(bigIntegerParams->p, bigIntegerParams->b,
        bigIntegerParams->x, bigIntegerParams->y);
    if (res == HCF_SUCCESS) {
        *curveId = NID_secp521r1;
        return res;
    }
    return HCF_NOT_SUPPORT;
}

static HcfResult CheckParamsSpecToGetCurveId(const HcfEccCommParamsSpec *ecParams, int32_t *curveId)
{
    HcfBigIntegerParams bigIntegerParams;
    bigIntegerParams.p = NULL;
    bigIntegerParams.b = NULL;
    bigIntegerParams.x = NULL;
    bigIntegerParams.y = NULL;
    HcfECFieldFp *field = (HcfECFieldFp *)(ecParams->field);
    if (BigIntegerToBigNum(&(field->p), &(bigIntegerParams.p)) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->b), &(bigIntegerParams.b)) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.x), &(bigIntegerParams.x)) != HCF_SUCCESS ||
        BigIntegerToBigNum(&(ecParams->g.y), &(bigIntegerParams.y)) != HCF_SUCCESS) {
        LOGE("BigIntegerToBigNum failed.");
        FreeCurveBigNum(bigIntegerParams.p, bigIntegerParams.b, bigIntegerParams.x, bigIntegerParams.y);
        return HCF_ERR_CRYPTO_OPERATION;
    }

    int32_t bitLenP = (int32_t)Openssl_BN_num_bits(bigIntegerParams.p);
    HcfResult res = HCF_INVALID_PARAMS;
    switch (bitLenP) {
        case OPENSSL_ECC160_BITS:
            res = CompareOpenssl160BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        case OPENSSL_ECC192_BITS:
            res = CompareOpenssl192BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        case OPENSSL_ECC224_BITS:
            res = CompareOpenssl224BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        case OPENSSL_ECC256_BITS:
            res = CompareOpenssl256BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        case OPENSSL_ECC320_BITS:
            res = CompareOpenssl320BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        case OPENSSL_ECC384_BITS:
            res = CompareOpenssl384BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        case OPENSSL_ECC512_BITS:
            res = CompareOpenssl512BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        case OPENSSL_ECC521_BITS:
            res = CompareOpenssl521BitsType(ecParams, curveId, &bigIntegerParams);
            break;
        default:
            LOGE("Find no bit len:%d", bitLenP);
            break;
    }
    FreeCurveBigNum(bigIntegerParams.p, bigIntegerParams.b, bigIntegerParams.x, bigIntegerParams.y);
    return res;
}

static HcfResult GenerateEcKeyWithParamsSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnKey)
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
        ret = GenerateEcGroupWithParamsSpec(ecParams, &group);
        if (ret != HCF_SUCCESS) {
            LOGE("GenerateEcGroupWithParamsSpec failed.");
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

static HcfResult NewEcKeyPairWithCommSpec(const HcfEccCommParamsSpec *ecParams, EC_KEY **returnEckey)
{
    if (ecParams == NULL || returnEckey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec(ecParams, &ecKey);
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

static HcfResult NewEcPubKeyWithPubSpec(const HcfEccPubKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
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

static HcfResult NewEcPriKeyWithPriSpec(const HcfEccPriKeyParamsSpec *ecParams, EC_KEY **returnEcKey)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
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

static HcfResult NewEcKeyWithKeyPairSpec(const HcfEccKeyPairParamsSpec *ecParams, EC_KEY **returnEcKey,
    bool needPrivate)
{
    if (ecParams == NULL || returnEcKey == NULL) {
        LOGE("Invalid input parameters.");
        return HCF_INVALID_PARAMS;
    }
    EC_KEY *ecKey = NULL;
    HcfResult ret = GenerateEcKeyWithParamsSpec((HcfEccCommParamsSpec *)ecParams, &ecKey);
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

static HcfResult GenKeyPairEcKeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            ret = NewEcKeyPairWithCommSpec((HcfEccCommParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewEcKeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invaild input spec to gen key pair.");
            break;
    }
    return ret;
}

static HcfResult GenPubKeyEcKeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PUBLIC_KEY_SPEC:
            ret = NewEcPubKeyWithPubSpec((HcfEccPubKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewEcKeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, false);
            break;
        default:
            LOGE("Invaild input spec to gen pub key");
            break;
    }
    return ret;
}

static HcfResult GenPriKeyEcKeyBySpec(const HcfAsyKeyParamsSpec *params, EC_KEY **ecKey)
{
    HcfResult ret = HCF_INVALID_PARAMS;
    switch (params->specType) {
        case HCF_PRIVATE_KEY_SPEC:
            ret = NewEcPriKeyWithPriSpec((HcfEccPriKeyParamsSpec *)params, ecKey);
            break;
        case HCF_KEY_PAIR_SPEC:
            ret = NewEcKeyWithKeyPairSpec((HcfEccKeyPairParamsSpec *)params, ecKey, true);
            break;
        default:
            LOGE("Invaild input spec to gen pri key");
            break;
    }
    return ret;
}

static const char *GetEccKeyPairGeneratorClass(void)
{
    return OPENSSL_ECC_KEY_GENERATOR_CLASS;
}

static const char *GetEccKeyPairClass(void)
{
    return HCF_OPENSSL_ECC_KEY_PAIR_CLASS;
}

static const char *GetEccPubKeyClass(void)
{
    return HCF_OPENSSL_ECC_PUB_KEY_CLASS;
}

static const char *GetEccPriKeyClass(void)
{
    return HCF_OPENSSL_ECC_PRI_KEY_CLASS;
}

static void DestroyEccKeyPairGenerator(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetEccKeyPairGeneratorClass())) {
        return;
    }
    HcfFree(self);
}

static void DestroyEccPubKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetEccPubKeyClass())) {
        return;
    }
    HcfOpensslEccPubKey *impl = (HcfOpensslEccPubKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroyEccPriKey(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetEccPriKeyClass())) {
        return;
    }
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
    HcfFree(impl->fieldType);
    impl->fieldType = NULL;
    HcfFree(impl);
}

static void DestroyEccKeyPair(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch(self, GetEccKeyPairClass())) {
        return;
    }
    HcfOpensslEccKeyPair *impl = (HcfOpensslEccKeyPair *)self;
    if (impl->base.pubKey != NULL) {
        DestroyEccPubKey((HcfObjectBase *)impl->base.pubKey);
        impl->base.pubKey = NULL;
    }
    if (impl->base.priKey != NULL) {
        DestroyEccPriKey((HcfObjectBase *)impl->base.priKey);
        impl->base.priKey = NULL;
    }
    HcfFree(impl);
}

static const char *GetEccPubKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_ALGORITHM;
}

static const char *GetEccPriKeyAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_ALGORITHM;
}

static const char *GetEccPubKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_PUB_KEY_FORMAT;
}

static const char *GetEccPriKeyFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter.");
        return NULL;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        return NULL;
    }
    return OPENSSL_ECC_PRI_KEY_FORMAT;
}

static HcfResult GetEccPubKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PUB_KEY_CLASS)) {
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslEccPubKey *impl = (HcfOpensslEccPubKey *)self;
    if (impl->curveId != 0) {
        LOGE("have a curveId");
        Openssl_EC_KEY_set_asn1_flag(impl->ecKey, OPENSSL_EC_NAMED_CURVE);
    } else {
        Openssl_EC_KEY_set_asn1_flag(impl->ecKey, OPENSSL_EC_EXPLICIT_CURVE);
    }

    unsigned char *returnData = NULL;
    LOGE("Begin trans");
    int returnDataLen = Openssl_i2d_EC_PUBKEY(impl->ecKey, &returnData);
    LOGE("ECC i2d complete");
    if (returnDataLen <= 0) {
        LOGE("i2d_EC_PUBKEY fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    LOGD("ECC pubKey i2d success");
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static HcfResult GetEccPriKeyEncoded(HcfKey *self, HcfBlob *returnBlob)
{
    if ((self == NULL) || (returnBlob == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, HCF_OPENSSL_ECC_PRI_KEY_CLASS)) {
        return HCF_INVALID_PARAMS;
    }

    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
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
    LOGD("ECC priKey i2d success");
    returnBlob->data = returnData;
    returnBlob->len = returnDataLen;
    return HCF_SUCCESS;
}

static void EccPriKeyClearMem(HcfPriKey *self)
{
    if (self == NULL) {
        return;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass())) {
        return;
    }
    HcfOpensslEccPriKey *impl = (HcfOpensslEccPriKey *)self;
    Openssl_EC_KEY_free(impl->ecKey);
    impl->ecKey = NULL;
}

static HcfResult GetCurveName(const HcfKey *self, const bool isPriavte, char **returnString)
{
    int32_t curveId = 0;
    if (isPriavte) {
        curveId = ((HcfOpensslEccPriKey *)self)->curveId;
    } else {
        curveId = ((HcfOpensslEccPubKey *)self)->curveId;
    }

    char *tmp = NULL;
    if (GetCurveNameByCurveId(curveId, &tmp) != HCF_SUCCESS) {
        LOGE("get vurveName by curveId failed.");
        return HCF_INVALID_PARAMS;
    }

    if (tmp == NULL) {
        LOGE("tmp is null.");
        return HCF_INVALID_PARAMS;
    }
    size_t len = HcfStrlen(tmp);
    if (len == 0) {
        LOGE("fieldType is empty!");
        return HCF_INVALID_PARAMS;
    }

    *returnString = (char *)HcfMalloc(len + 1, 0);
    if (*returnString == NULL) {
        LOGE("Alloc returnString memory failed.");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(*returnString, len, tmp, len);
    return HCF_SUCCESS;
}

static HcfResult CheckEcKeySelf(const HcfKey *self, bool *isPrivate)
{
    if (IsClassMatch((HcfObjectBase *)self, GetEccPubKeyClass())) {
        *isPrivate = false;
        return HCF_SUCCESS;
    } else if (IsClassMatch((HcfObjectBase *)self, GetEccPriKeyClass())) {
        if (((HcfOpensslEccPriKey *)self)->ecKey == NULL) {
            LOGE("Cannot use priKey after free");
            return HCF_INVALID_PARAMS;
        }
        *isPrivate = true;
        return HCF_SUCCESS;
    } else {
        return HCF_INVALID_PARAMS;
    }
}

static HcfResult GetEcKeySpecBigInteger(const HcfKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    if (self == NULL || returnBigInteger == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult res = CheckEcKeySelf(self, &isPrivate);
    if (res != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPriKey *)self)->ecKey);
    } else {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPubKey *)self)->ecKey);
    }
    switch (item) {
        case ECC_FP_P_BN:
        case ECC_A_BN:
        case ECC_B_BN:
            res = GetCurveGFp(group, item, returnBigInteger);
            break;
        case ECC_G_X_BN:
        case ECC_G_Y_BN:
            res = GetGenerator(group, item, returnBigInteger);
            break;
        case ECC_N_BN:
            res = GetOrder(group, returnBigInteger);
            break;
        case ECC_SK_BN:
        case ECC_PK_X_BN:
        case ECC_PK_Y_BN:
            res = GetPkSkBigInteger(self, isPrivate, item, returnBigInteger);
            break;
        default:
            LOGE("Invalid ecc key big number spec!");
            res = HCF_INVALID_PARAMS;
            break;
    }
    return res;
}

static HcfResult GetEcKeySpecString(const HcfKey *self, const AsyKeySpecItem item, char **returnString)
{
    if (self == NULL || returnString == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult res = CheckEcKeySelf(self, &isPrivate);
    if (res != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }

    switch (item) {
        case ECC_FIELD_TYPE_STR:
            res = GetFieldType(self, isPrivate, returnString);
            break;
        case ECC_CURVE_NAME_STR:
            res = GetCurveName(self, isPrivate, returnString);
            break;
        default:
            res = HCF_INVALID_PARAMS;
            LOGE("Invalid spec of ec string");
            break;
    }
    return res;
}

static HcfResult GetEcKeySpecInt(const HcfKey *self, const AsyKeySpecItem item, int *returnInt)
{
    if (self == NULL || returnInt == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    bool isPrivate;
    HcfResult res = CheckEcKeySelf(self, &isPrivate);
    if (res != HCF_SUCCESS) {
        LOGE("Invalid input key");
        return HCF_INVALID_PARAMS;
    }
    const EC_GROUP *group = NULL;
    if (isPrivate) {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPriKey *)self)->ecKey);
    } else {
        group = Openssl_EC_KEY_get0_group(((HcfOpensslEccPubKey *)self)->ecKey);
    }
    switch (item) {
        case ECC_H_INT:
            res = GetCofactor(group, returnInt);
            break;
        case ECC_FIELD_SIZE_INT:
            res = GetFieldSize(group, returnInt);
            break;
        default:
            res = HCF_INVALID_PARAMS;
            LOGE("invalid ec key int spec");
            break;
    }
    return res;
}

static HcfResult GetECPubKeySpecBigInteger(const HcfPubKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetEcKeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetECPubKeySpecString(const HcfPubKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetEcKeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetECPubKeySpecInt(const HcfPubKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetEcKeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult GetECPriKeySpecBigInteger(const HcfPriKey *self, const AsyKeySpecItem item,
    HcfBigInteger *returnBigInteger)
{
    return GetEcKeySpecBigInteger((HcfKey *)self, item, returnBigInteger);
}

static HcfResult GetECPriKeySpecString(const HcfPriKey *self, const AsyKeySpecItem item, char **returnString)
{
    return GetEcKeySpecString((HcfKey *)self, item, returnString);
}

static HcfResult GetECPriKeySpecInt(const HcfPriKey *self, const AsyKeySpecItem item, int *returnInt)
{
    return GetEcKeySpecInt((HcfKey *)self, item, returnInt);
}

static HcfResult PackEccPubKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslEccPubKey **returnObj)
{
    HcfOpensslEccPubKey *returnPubKey = (HcfOpensslEccPubKey *)HcfMalloc(sizeof(HcfOpensslEccPubKey), 0);
    if (returnPubKey == NULL) {
        LOGE("Failed to allocate returnPubKey memory!");
        return HCF_ERR_MALLOC;
    }
    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        size_t len = HcfStrlen(fieldType);
        if (!len) {
            LOGE("fieldType is empty!");
            HcfFree(returnPubKey);
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

    returnPubKey->base.base.base.destroy = DestroyEccPubKey;
    returnPubKey->base.base.base.getClass = GetEccPubKeyClass;
    returnPubKey->base.base.getAlgorithm = GetEccPubKeyAlgorithm;
    returnPubKey->base.base.getEncoded = GetEccPubKeyEncoded;
    returnPubKey->base.base.getFormat = GetEccPubKeyFormat;
    returnPubKey->base.getAsyKeySpecBigInteger = GetECPubKeySpecBigInteger;
    returnPubKey->base.getAsyKeySpecString = GetECPubKeySpecString;
    returnPubKey->base.getAsyKeySpecInt = GetECPubKeySpecInt;
    returnPubKey->curveId = curveId;
    returnPubKey->ecKey = ecKey;
    returnPubKey->fieldType = tmpFieldType;

    *returnObj = returnPubKey;
    return HCF_SUCCESS;
}

static HcfResult PackEccPriKey(int32_t curveId, EC_KEY *ecKey, const char *fieldType,
    HcfOpensslEccPriKey **returnObj)
{
    HcfOpensslEccPriKey *returnPriKey = (HcfOpensslEccPriKey *)HcfMalloc(sizeof(HcfOpensslEccPriKey), 0);
    if (returnPriKey == NULL) {
        LOGE("Failed to allocate returnPriKey memory!");
        return HCF_ERR_MALLOC;
    }
    char *tmpFieldType = NULL;
    if (fieldType != NULL) {
        size_t len = HcfStrlen(fieldType);
        if (!len) {
            LOGE("fieldType is empty!");
            HcfFree(returnPriKey);
            return HCF_INVALID_PARAMS;
        }
        tmpFieldType = (char *)HcfMalloc(len + 1, 0);
        if (tmpFieldType == NULL) {
            LOGE("Alloc tmpFieldType memory failed.");
            HcfFree(returnPriKey);
            return HCF_ERR_MALLOC;
        }
        (void)memcpy_s(tmpFieldType, len, fieldType, len);
    }

    returnPriKey->base.base.base.destroy = DestroyEccPriKey;
    returnPriKey->base.base.base.getClass = GetEccPriKeyClass;
    returnPriKey->base.base.getAlgorithm = GetEccPriKeyAlgorithm;
    returnPriKey->base.base.getEncoded = GetEccPriKeyEncoded;
    returnPriKey->base.base.getFormat = GetEccPriKeyFormat;
    returnPriKey->base.clearMem = EccPriKeyClearMem;
    returnPriKey->base.getAsyKeySpecBigInteger = GetECPriKeySpecBigInteger;
    returnPriKey->base.getAsyKeySpecString = GetECPriKeySpecString;
    returnPriKey->base.getAsyKeySpecInt = GetECPriKeySpecInt;
    returnPriKey->curveId = curveId;
    returnPriKey->ecKey = ecKey;
    returnPriKey->fieldType = tmpFieldType;

    *returnObj = returnPriKey;
    return HCF_SUCCESS;
}

static HcfResult PackEccKeyPair(HcfOpensslEccPubKey *pubKey, HcfOpensslEccPriKey *priKey,
    HcfOpensslEccKeyPair **returnObj)
{
    HcfOpensslEccKeyPair *returnKeyPair = (HcfOpensslEccKeyPair *)HcfMalloc(sizeof(HcfOpensslEccKeyPair), 0);
    if (returnKeyPair == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    returnKeyPair->base.base.getClass = GetEccKeyPairClass;
    returnKeyPair->base.base.destroy = DestroyEccKeyPair;
    returnKeyPair->base.pubKey = (HcfPubKey *)pubKey;
    returnKeyPair->base.priKey = (HcfPriKey *)priKey;

    *returnObj = returnKeyPair;
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPubKey(int32_t curveId, HcfBlob *pubKeyBlob, HcfOpensslEccPubKey **returnPubKey)
{
    const unsigned char *tmpData = (const unsigned char *)(pubKeyBlob->data);
    EC_KEY *ecKey = Openssl_d2i_EC_PUBKEY(NULL, &tmpData, pubKeyBlob->len);
    if (ecKey == NULL) {
        LOGE("d2i_EC_PUBKEY fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = PackEccPubKey(curveId, ecKey, g_eccGenerateFieldType, returnPubKey);
    if (res != HCF_SUCCESS) {
        LOGE("PackEccPubKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult ConvertEcPriKey(int32_t curveId, HcfBlob *priKeyBlob, HcfOpensslEccPriKey **returnPriKey)
{
    const unsigned char *tmpData = (const unsigned char *)(priKeyBlob->data);
    EC_KEY *ecKey = Openssl_d2i_ECPrivateKey(NULL, &tmpData, priKeyBlob->len);
    if (ecKey == NULL) {
        LOGE("d2i_ECPrivateKey fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = PackEccPriKey(curveId, ecKey, g_eccGenerateFieldType, returnPriKey);
    if (res != HCF_SUCCESS) {
        LOGE("PackEccPriKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineConvertEccKey(HcfAsyKeyGeneratorSpi *self, HcfParamsSpec *params, HcfBlob *pubKeyBlob,
    HcfBlob *priKeyBlob, HcfKeyPair **returnKeyPair)
{
    (void)params;
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }
    bool pubKeyValid = IsBlobValid(pubKeyBlob);
    bool priKeyValid = IsBlobValid(priKeyBlob);
    if ((!pubKeyValid) && (!priKeyValid)) {
        LOGE("The private key and public key cannot both be NULL.");
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    HcfResult res = HCF_SUCCESS;
    HcfOpensslEccPubKey *pubKey = NULL;
    HcfOpensslEccPriKey *priKey = NULL;
    HcfOpensslEccKeyPair *keyPair = NULL;
    do {
        if (pubKeyValid) {
            res = ConvertEcPubKey(impl->curveId, pubKeyBlob, &pubKey);
            if (res != HCF_SUCCESS) {
                break;
            }
        }
        if (priKeyValid) {
            res = ConvertEcPriKey(impl->curveId, priKeyBlob, &priKey);
            if (res != HCF_SUCCESS) {
                break;
            }
        }
        res = PackEccKeyPair(pubKey, priKey, &keyPair);
    } while (0);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return res;
    }

    *returnKeyPair = (HcfKeyPair *)keyPair;
    return HCF_SUCCESS;
}

static HcfResult PackAndAssignPubKey(const HcfAsyKeyGeneratorSpiOpensslEccImpl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPubKey **returnObj)
{
    HcfOpensslEccPubKey *pubKey = NULL;
    HcfResult res = PackEccPubKey(impl->curveId, ecKey, fieldType, &pubKey);
    if (res != HCF_SUCCESS) {
        return res;
    }
    *returnObj = (HcfPubKey *)pubKey;
    return HCF_SUCCESS;
}

static HcfResult PackAndAssignPriKey(const HcfAsyKeyGeneratorSpiOpensslEccImpl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfPriKey **returnObj)
{
    HcfOpensslEccPriKey *priKey = NULL;
    HcfResult res = PackEccPriKey(impl->curveId, ecKey, fieldType, &priKey);
    if (res != HCF_SUCCESS) {
        return res;
    }
    *returnObj = (HcfPriKey *)priKey;
    return HCF_SUCCESS;
}

static HcfResult CreateAndAssignKeyPair(const HcfAsyKeyGeneratorSpiOpensslEccImpl *impl, const char *fieldType,
    EC_KEY *ecKey, HcfKeyPair **returnObj)
{
    EC_KEY *ecPriKey = EC_KEY_dup(ecKey);
    if (ecPriKey == NULL) {
        LOGE("copy ecKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfOpensslEccPriKey *priKey = NULL;
    HcfResult res = PackEccPriKey(impl->curveId, ecPriKey, fieldType, &priKey);
    if (res != HCF_SUCCESS) {
        Openssl_EC_KEY_free(ecPriKey);
        return res;
    }
    HcfOpensslEccPubKey *pubKey = NULL;
    EC_KEY *ecPubKey = EC_KEY_dup(ecKey);
    if (ecPubKey == NULL) {
        LOGE("copy ecKey fail.");
        HcfObjDestroy(priKey);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = PackEccPubKey(impl->curveId, ecPubKey, fieldType, &pubKey);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(priKey);
        Openssl_EC_KEY_free(ecPubKey);
        return res;
    }

    HcfOpensslEccKeyPair *returnKeyPair = (HcfOpensslEccKeyPair *)HcfMalloc(sizeof(HcfOpensslEccKeyPair), 0);
    if (returnKeyPair == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        HcfObjDestroy(pubKey);
        HcfObjDestroy(priKey);
        return HCF_ERR_MALLOC;
    }
    returnKeyPair->base.base.getClass = GetEccKeyPairClass;
    returnKeyPair->base.base.destroy = DestroyEccKeyPair;
    returnKeyPair->base.pubKey = (HcfPubKey *)pubKey;
    returnKeyPair->base.priKey = (HcfPriKey *)priKey;

    *returnObj = (HcfKeyPair *)returnKeyPair;
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateKeyPair(HcfAsyKeyGeneratorSpi *self, HcfKeyPair **returnObj)
{
    if ((self == NULL) || (returnObj == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = NewEcKeyPair(impl->curveId, &ecKey);
    if (res != HCF_SUCCESS) {
        return res;
    }
    res = CreateAndAssignKeyPair(impl, g_eccGenerateFieldType, ecKey, returnObj);
    Openssl_EC_KEY_free(ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("CreateAndAssignKeyPair failed.");
        return res;
    }
    return HCF_SUCCESS;
}

static HcfResult EngineGenerateKeyPairBySpec(const HcfAsyKeyGeneratorSpi *self, const HcfAsyKeyParamsSpec *params,
    HcfKeyPair **returnKeyPair)
{
    if ((self == NULL) || (returnKeyPair == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!IsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = GenKeyPairEcKeyBySpec(params, &ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Gen ec key pair with spec failed.");
        return res;
    }

    // curveId == 0 means no curve to match.
    int32_t curveId = (int32_t)Openssl_EC_GROUP_get_curve_name(Openssl_EC_KEY_get0_group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }
    // deep copy of ecKey, free ecKey whether it succeed or failed.
    res = CreateAndAssignKeyPair(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnKeyPair);
    Openssl_EC_KEY_free(ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("CreateAndAssignKeyPair failed.");
        return res;
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
    if (!IsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = GenPubKeyEcKeyBySpec(params, &ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Gen ec pubKey with spec failed.");
        return res;
    }
    int32_t curveId = (int32_t)Openssl_EC_GROUP_get_curve_name(Openssl_EC_KEY_get0_group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }
    res = PackAndAssignPubKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPubKey);
    if (res != HCF_SUCCESS) {
        LOGE("PackAndAssignPubKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return res;
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
    if (!IsClassMatch((HcfObjectBase *)self, GetEccKeyPairGeneratorClass())) {
        return HCF_INVALID_PARAMS;
    }

    HcfAsyKeyGeneratorSpiOpensslEccImpl *impl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)self;
    EC_KEY *ecKey = NULL;
    HcfResult res = GenPriKeyEcKeyBySpec(params, &ecKey);
    if (res != HCF_SUCCESS) {
        LOGE("Gen ec pubKey with spec failed.");
        return res;
    }

    int32_t curveId = (int32_t)Openssl_EC_GROUP_get_curve_name(Openssl_EC_KEY_get0_group(ecKey));
    if (curveId != 0) {
        impl->curveId = curveId;
    }

    res = PackAndAssignPriKey(impl, ((HcfEccCommParamsSpec *)params)->field->fieldType, ecKey, returnPriKey);
    if (res != HCF_SUCCESS) {
        LOGE("PackAndAssignPriKey failed.");
        Openssl_EC_KEY_free(ecKey);
        return res;
    }

    return HCF_SUCCESS;
}

HcfResult HcfAsyKeyGeneratorSpiEccCreate(HcfAsyKeyGenParams *params, HcfAsyKeyGeneratorSpi **returnObj)
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

    HcfAsyKeyGeneratorSpiOpensslEccImpl *returnImpl = (HcfAsyKeyGeneratorSpiOpensslEccImpl *)HcfMalloc(
        sizeof(HcfAsyKeyGeneratorSpiOpensslEccImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memroy!");
        return HCF_ERR_MALLOC;
    }
    returnImpl->base.base.getClass = GetEccKeyPairGeneratorClass;
    returnImpl->base.base.destroy = DestroyEccKeyPairGenerator;
    returnImpl->base.engineConvertKey = EngineConvertEccKey;
    returnImpl->base.engineGenerateKeyPair = EngineGenerateKeyPair;
    returnImpl->base.engineGenerateKeyPairBySpec = EngineGenerateKeyPairBySpec;
    returnImpl->base.engineGeneratePubKeyBySpec = EngineGeneratePubKeyBySpec;
    returnImpl->base.engineGeneratePriKeyBySpec = EngineGeneratePriKeyBySpec;
    returnImpl->curveId = curveId;

    *returnObj = (HcfAsyKeyGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
