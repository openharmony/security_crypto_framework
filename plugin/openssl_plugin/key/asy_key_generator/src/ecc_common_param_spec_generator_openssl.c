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

#include "ecc_common_param_spec_generator_openssl.h"
#include "securec.h"

#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "utils.h"

static EC_POINT *BuildEcPoint(const EC_GROUP *ecGroup)
{
    EC_POINT *point = Openssl_EC_POINT_new(ecGroup);
    if (point == NULL) {
        LOGE("new ec point failed.");
        return NULL;
    }
    const EC_POINT *tmpPoint = Openssl_EC_GROUP_get0_generator(ecGroup);
    if (tmpPoint == NULL) {
        LOGE("Get ec generator failed.");
        Openssl_EC_POINT_free(point);
        return NULL;
    }
    if (!Openssl_EC_POINT_copy(point, tmpPoint)) {
        LOGE("Ec point copy failed.");
        Openssl_EC_POINT_free(point);
        return NULL;
    }

    return point;
}

static HcfResult BuildCommonParamPart(const EC_GROUP *ecGroup, HcfEccCommParamsSpecSpi *returnCommonParamSpec)
{
    EC_POINT *point = NULL;
    point = BuildEcPoint(ecGroup);
    if (point == NULL) {
        LOGE("Build ec point failed.");
        return HCF_ERR_MALLOC;
    }
    BIGNUM *x = Openssl_BN_new();
    if (x == NULL) {
        LOGE("New x failed.");
        Openssl_EC_POINT_free(point);
        return HCF_ERR_MALLOC;
    }
    BIGNUM *y = Openssl_BN_new();
    if (y == NULL) {
        LOGE("New y failed.");
        Openssl_BN_free(x);
        Openssl_EC_POINT_free(point);
        return HCF_ERR_MALLOC;
    }
    HcfResult ret = HCF_SUCCESS;
    do {
        if (!Openssl_EC_POINT_get_affine_coordinates_GFp(ecGroup, point, x, y, NULL)) {
            LOGE("EC_POINT_get_affine_coordinates_GFp failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (BigNumToBigInteger(x, &(returnCommonParamSpec->paramsSpec.g.x)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec x failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (BigNumToBigInteger(y, &(returnCommonParamSpec->paramsSpec.g.y)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec y failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);
    Openssl_BN_free(x);
    Openssl_BN_free(y);
    Openssl_EC_POINT_free(point);
    return ret;
}

static HcfResult BuildCommonParamGFp(const EC_GROUP *ecGroup, HcfEccCommParamsSpecSpi *returnCommonParamSpec)
{
    BIGNUM *p = Openssl_BN_new();
    if (p == NULL) {
        LOGE("New p failed.");
        return HCF_ERR_MALLOC;
    }
    BIGNUM *a = Openssl_BN_new();
    if (a == NULL) {
        LOGE("New a failed.");
        Openssl_BN_free(p);
        return HCF_ERR_MALLOC;
    }
    BIGNUM *b = Openssl_BN_new();
    if (b == NULL) {
        LOGE("New b failed.");
        Openssl_BN_free(p);
        Openssl_BN_free(a);
        return HCF_ERR_MALLOC;
    }
    if (!Openssl_EC_GROUP_get_curve_GFp(ecGroup, p, a, b, NULL)) {
        LOGE("EC_GROUP_get_curve_GFp failed.");
        Openssl_BN_free(p);
        Openssl_BN_free(a);
        Openssl_BN_free(b);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult ret = HCF_SUCCESS;

    do {
        if (BigNumToBigInteger(a, &(returnCommonParamSpec->paramsSpec.a)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec a failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        if (BigNumToBigInteger(b, &(returnCommonParamSpec->paramsSpec.b)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec b failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
        HcfECFieldFp *tmpField = (HcfECFieldFp *)(returnCommonParamSpec->paramsSpec.field);
        if (BigNumToBigInteger(p, &(tmpField->p)) != HCF_SUCCESS) {
            LOGE("Build commonParamSpec p failed.");
            ret = HCF_ERR_CRYPTO_OPERATION;
            break;
        }
    } while (0);

    Openssl_BN_free(p);
    Openssl_BN_free(a);
    Openssl_BN_free(b);
    return ret;
}

static HcfResult BuildCommonParam(const EC_GROUP *ecGroup, HcfEccCommParamsSpecSpi *returnCommonParamSpec)
{
    if (BuildCommonParamPart(ecGroup, returnCommonParamSpec)!= HCF_SUCCESS) {
        LOGE("BuildCommonParamPartOne failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BuildCommonParamGFp(ecGroup, returnCommonParamSpec)!= HCF_SUCCESS) {
        LOGE("BuildCommonParamGFp failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (GetOrder(ecGroup, &(returnCommonParamSpec->paramsSpec.n)) != HCF_SUCCESS) {
        LOGE("Failed to get curve order data.");
        return HCF_ERR_CRYPTO_OPERATION;
    }

    if (GetCofactor(ecGroup, &(returnCommonParamSpec->paramsSpec.h)) != HCF_SUCCESS) {
        LOGE("Failed to get curve cofactor data.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfEccCommParamsSpecSpi *BuildEccCommonParamObject(void)
{
    HcfEccCommParamsSpecSpi *spi = (HcfEccCommParamsSpecSpi*)HcfMalloc(sizeof(HcfEccCommParamsSpecSpi), 0);
    if (spi == NULL) {
        LOGE("failed to build ecc commonParam object.");
        return NULL;
    }
    spi->paramsSpec.field = (HcfECField *)HcfMalloc(sizeof(HcfECFieldFp), 0);
    if (spi->paramsSpec.field == NULL) {
        LOGE("field malloc failed.");
        HcfFree(spi);
        return NULL;
    }
    char *fieldType = "Fp";
    size_t srcFieldTypeLen = HcfStrlen(fieldType);
    if (!srcFieldTypeLen) {
        LOGE("fieldType is empty!");
        HcfFree(spi->paramsSpec.field);
        HcfFree(spi);
        return NULL;
    }
    spi->paramsSpec.field->fieldType = (char *)HcfMalloc(srcFieldTypeLen + 1, 0);
    if (spi->paramsSpec.field->fieldType == NULL) {
        LOGE("fieldType malloc failed.");
        HcfFree(spi->paramsSpec.field);
        HcfFree(spi);
        return NULL;
    }

    if (memcpy_s(spi->paramsSpec.field->fieldType, srcFieldTypeLen, fieldType, srcFieldTypeLen) != EOK) {
        LOGE("memcpy fieldType failed.");
        HcfFree(spi->paramsSpec.field->fieldType);
        HcfFree(spi->paramsSpec.field);
        HcfFree(spi);
        return NULL;
    }
    return spi;
}

static void FreeEccCommParamObject(HcfEccCommParamsSpecSpi *spec)
{
    if (spec == NULL) {
        LOGE("Invalid input parameter.");
        return;
    }
    HcfFree(spec->paramsSpec.base.algName);
    spec->paramsSpec.base.algName = NULL;
    if (spec->paramsSpec.field != NULL) {
        HcfFree(spec->paramsSpec.field->fieldType);
        spec->paramsSpec.field->fieldType = NULL;
        HcfFree(spec->paramsSpec.field);
        spec->paramsSpec.field = NULL;
    }
    HcfFree(spec->paramsSpec.a.data);
    spec->paramsSpec.a.data = NULL;
    HcfFree(spec->paramsSpec.b.data);
    spec->paramsSpec.b.data = NULL;
    HcfFree(spec->paramsSpec.n.data);
    spec->paramsSpec.n.data = NULL;
    HcfFree(spec->paramsSpec.g.x.data);
    spec->paramsSpec.g.x.data = NULL;
    HcfFree(spec->paramsSpec.g.y.data);
    spec->paramsSpec.g.y.data = NULL;
    HcfFree(spec);
}

HcfResult HcfECCCommonParamSpecCreate(HcfAsyKeyGenParams *params, HcfEccCommParamsSpecSpi **returnCommonParamSpec)
{
    if ((params == NULL) || (returnCommonParamSpec == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    int32_t curveId = 0;
    if (params->bits != 0) {
        if (GetOpensslCurveId(params->bits, &curveId) != HCF_SUCCESS) {
            LOGE("Get curveId parameter failed.");
            return HCF_INVALID_PARAMS;
        }
    }
    EC_GROUP *ecGroup = Openssl_EC_GROUP_new_by_curve_name(curveId);
    if (ecGroup == NULL) {
        LOGE("Create ecGroup failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfEccCommParamsSpecSpi *object = BuildEccCommonParamObject();
    if (object == NULL) {
        LOGE("Build ecc common params object failed.");
        Openssl_EC_GROUP_free(ecGroup);
        return HCF_ERR_MALLOC;
    }
    object->paramsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    if (GetAlgNameByBits(params->bits, &(object->paramsSpec.base.algName)) != HCF_SUCCESS) {
        LOGE("Get algName parameter by bits failed.");
        FreeEccCommParamObject(object);
        object = NULL;
        Openssl_EC_GROUP_free(ecGroup);
        return HCF_INVALID_PARAMS;
    }
    if (BuildCommonParam(ecGroup, object)!= HCF_SUCCESS) {
        LOGE("Get common params failed.");
        FreeEccCommParamObject(object);
        object = NULL;
        Openssl_EC_GROUP_free(ecGroup);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *returnCommonParamSpec = object;
    Openssl_EC_GROUP_free(ecGroup);
    return HCF_SUCCESS;
}
