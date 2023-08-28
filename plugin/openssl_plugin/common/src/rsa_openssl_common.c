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
#include "rsa_openssl_common.h"
#include "log.h"
#include "openssl_adapter.h"
#include "openssl_common.h"

static RSA *DuplicateRsaPriKeyForSpec(const RSA *rsa)
{
    RSA *tmp = Openssl_RSA_new();
    if (tmp == NULL) {
        LOGE("malloc rsa failed");
        return NULL;
    }
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    Openssl_RSA_get0_key(rsa, &n, &e, &d);
    if (n == NULL || e == NULL || d == NULL) {
        LOGE("get key attribute fail");
        Openssl_RSA_free(tmp);
        return NULL;
    }
    BIGNUM *dupN = Openssl_BN_dup(n);
    BIGNUM *dupE = Openssl_BN_dup(e);
    BIGNUM *dupD = Openssl_BN_dup(d);
    if (dupN == NULL || dupE == NULL || dupD == NULL) {
        LOGE("Duplicate key attribute fail");
        Openssl_BN_free(dupN);
        Openssl_BN_free(dupE);
        Openssl_BN_clear_free(dupD);
        Openssl_RSA_free(tmp);
        return NULL;
    }
    if (Openssl_RSA_set0_key(tmp, dupN, dupE, dupD) != HCF_OPENSSL_SUCCESS) {
        LOGE("assign RSA n, e, d failed");
        Openssl_BN_free(dupN);
        Openssl_BN_free(dupE);
        Openssl_BN_clear_free(dupD);
        Openssl_RSA_free(tmp);
        return NULL;
    }
    return tmp;
}

HcfResult DuplicateRsa(RSA *rsa, bool needPrivate, RSA **dupRsa)
{
    RSA *retRSA = NULL;
    if (rsa == NULL || dupRsa == NULL) {
        LOGE("Rsa or dupRsa is NULL.");
        return HCF_INVALID_PARAMS;
    }
    if (needPrivate) {
        retRSA = Openssl_RSAPrivateKey_dup(rsa);
        // RSAPrivateKey_dup needs p&q, it fails when the key only contains n, e, d, so it needs another func.
        if (retRSA == NULL) {
            retRSA = DuplicateRsaPriKeyForSpec(rsa);
        }
    } else {
        retRSA = Openssl_RSAPublicKey_dup(rsa);
    }
    if (retRSA == NULL) {
        LOGE("Duplicate RSA fail.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    *dupRsa = retRSA;
    return HCF_SUCCESS;
}

EVP_PKEY *NewEvpPkeyByRsa(RSA *rsa, bool withDuplicate)
{
    if (rsa == NULL) {
        LOGE("RSA is NULL");
        return NULL;
    }
    EVP_PKEY *pKey = Openssl_EVP_PKEY_new();
    if (pKey == NULL) {
        LOGE("EVP_PKEY_new fail");
        HcfPrintOpensslError();
        return NULL;
    }
    if (withDuplicate) {
        if (Openssl_EVP_PKEY_set1_RSA(pKey, rsa) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_set1_RSA fail");
            HcfPrintOpensslError();
            Openssl_EVP_PKEY_free(pKey);
            return NULL;
        }
    } else {
        if (Openssl_EVP_PKEY_assign_RSA(pKey, rsa) != HCF_OPENSSL_SUCCESS) {
            LOGE("EVP_PKEY_assign_RSA fail");
            HcfPrintOpensslError();
            Openssl_EVP_PKEY_free(pKey);
            return NULL;
        }
    }
    return pKey;
}
