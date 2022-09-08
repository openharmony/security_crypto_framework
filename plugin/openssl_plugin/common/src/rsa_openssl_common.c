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
#include "rsa_openssl_common.h"
#include "log.h"
#include "plugin_defines.h"

static HcfResult DuplicateBigNumFromRSA(BIGNUM **n, BIGNUM **e, BIGNUM **d, bool needPrivate, const RSA *rsa)
{
    const BIGNUM *tmpN = NULL, *tmpE = NULL, *tmpD = NULL;
    RSA_get0_key(rsa, &tmpN, &tmpE, &tmpD);
    if (tmpN == NULL || tmpE == NULL || (needPrivate && tmpD == NULL)) {
        LOGE("Rsa get bignum n e d fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    BIGNUM *retN = NULL, *retE = NULL, *retD = NULL;
    retN = BN_dup(tmpN);
    if (retN == NULL) {
        LOGE("Dup n fail");
        goto ERR;
    }
    retE = BN_dup(tmpE);
    if (retE == NULL) {
        LOGE("Dup e fail");
        goto ERR;
    }
    if (needPrivate) {
        retD = BN_dup(tmpD);
        if (retD == NULL) {
            LOGE("Dup d fail");
            goto ERR;
        }
    }
    *n = retN;
    *e = retE;
    *d = retD;

    return HCF_SUCCESS;
ERR:
    BN_clear_free(retN);
    BN_clear_free(retE);
    BN_clear_free(retD);
    return HCF_ERR_CRYPTO_OPERATION;
}

static HcfResult InitRsaStruct(BIGNUM *n, BIGNUM *e, BIGNUM *d, const bool needPrivateExponent, RSA **rsa)
{
    HcfResult ret = HCF_ERR_CRYPTO_OPERATION;
    if (rsa == NULL || n == NULL || e == NULL) {
        LOGE("InitRsaStruct params error.");
        ret = HCF_INVALID_PARAMS;
        goto ERR;
    }
    // private key need d, public key can't set key
    if ((needPrivateExponent && d == NULL) || (!needPrivateExponent && d != NULL)) {
        LOGE("The input BigNum is invalid.");
        ret = HCF_INVALID_PARAMS;
        goto ERR;
    }
    *rsa = RSA_new();
    if (*rsa == NULL) {
        LOGE("New RSA fail");
        ret = HCF_ERR_MALLOC;
        goto ERR;
    }
    if (RSA_set0_key(*rsa, n, e, d) != HCF_OPENSSL_SUCCESS) {
        LOGE("RSA_set0_key fail.");
        RSA_free(*rsa);
        *rsa = NULL;
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto ERR;
    }
    return HCF_SUCCESS;
ERR:
    BN_clear_free(n);
    BN_clear_free(e);
    BN_clear_free(d);
    return ret;
}

HcfResult DuplicateRsa(const RSA *rsa, bool needPrivate, RSA **dupRsa)
{
    if (rsa == NULL || dupRsa == NULL) {
        LOGE("Rsa or dupRsa is NULL.");
        return HCF_INVALID_PARAMS;
    }
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;
    if (DuplicateBigNumFromRSA(&n, &e, &d, needPrivate, rsa) != HCF_SUCCESS) {
        LOGE("duplicate pk bignum fail");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (InitRsaStruct(n, e, d, needPrivate, dupRsa) != HCF_SUCCESS) {
        LOGE("Generate PriKey fail.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}