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

#include "openssl_common.h"

#include "securec.h"

#include <string.h>
#include <openssl/err.h>
#include "config.h"
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "result.h"
#include "params_parser.h"

#define PRIMES_2 2
#define PRIMES_3 3
#define PRIMES_4 4
#define PRIMES_5 5

#define HCF_OPENSSL_DIGEST_NONE_STR "NONE"
#define HCF_OPENSSL_DIGEST_MD5_STR "MD5"
#define HCF_OPENSSL_DIGEST_SHA1_STR "SHA1"
#define HCF_OPENSSL_DIGEST_SHA224_STR "SHA224"
#define HCF_OPENSSL_DIGEST_SHA256_STR "SHA256"
#define HCF_OPENSSL_DIGEST_SHA384_STR "SHA384"
#define HCF_OPENSSL_DIGEST_SHA512_STR "SHA512"
#define HCF_OPENSSL_MGF1 "MGF1"

static const uint32_t ASCII_CODE_ZERO = 48;

HcfResult GetOpensslCurveId(int32_t keyLen, int32_t *returnCurveId)
{
    switch (keyLen) {
        case HCF_ALG_ECC_224:
            *returnCurveId = NID_secp224r1;
            break;
        case HCF_ALG_ECC_256:
            *returnCurveId = NID_X9_62_prime256v1;
            break;
        case HCF_ALG_ECC_384:
            *returnCurveId = NID_secp384r1;
            break;
        case HCF_ALG_ECC_521:
            *returnCurveId = NID_secp521r1;
            break;
        default:
            LOGE("invalid key size.");
            return HCF_INVALID_PARAMS;
    }

    return HCF_SUCCESS;
}

HcfResult GetOpensslDigestAlg(uint32_t alg, EVP_MD **digestAlg)
{
    if (digestAlg == NULL) {
        LOGE("Invalid MD pointer");
        return HCF_INVALID_PARAMS;
    }
    switch (alg) {
        case HCF_OPENSSL_DIGEST_NONE:
            *digestAlg = NULL;
            break;
        case HCF_OPENSSL_DIGEST_MD5:
            *digestAlg = (EVP_MD *)EVP_md5();
            break;
        case HCF_OPENSSL_DIGEST_SHA1:
            *digestAlg = (EVP_MD *)EVP_sha1();
            break;
        case HCF_OPENSSL_DIGEST_SHA224:
            *digestAlg = (EVP_MD *)EVP_sha224();
            break;
        case HCF_OPENSSL_DIGEST_SHA256:
            *digestAlg = (EVP_MD *)EVP_sha256();
            break;
        case HCF_OPENSSL_DIGEST_SHA384:
            *digestAlg = (EVP_MD *)EVP_sha384();
            break;
        case HCF_OPENSSL_DIGEST_SHA512:
            *digestAlg = (EVP_MD *)EVP_sha512();
            break;
        default:
            LOGE("Invalid digest num is %u.", alg);
            return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

HcfResult GetRsaSpecStringMd(const HcfAlgParaValue md, char **returnString)
{
    if (returnString == NULL) {
        LOGE("return string is null");
        return HCF_INVALID_PARAMS;
    }
    char *tmp = NULL;
    switch (md) {
        case HCF_OPENSSL_DIGEST_MD5:
            tmp = HCF_OPENSSL_DIGEST_MD5_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA1:
            tmp = HCF_OPENSSL_DIGEST_SHA1_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA224:
            tmp = HCF_OPENSSL_DIGEST_SHA224_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA256:
            tmp = HCF_OPENSSL_DIGEST_SHA256_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA384:
            tmp = HCF_OPENSSL_DIGEST_SHA384_STR;
            break;
        case HCF_OPENSSL_DIGEST_SHA512:
            tmp = HCF_OPENSSL_DIGEST_SHA512_STR;
            break;
        default:
            LOGE("Invalid digest num is %u.", md);
            return HCF_INVALID_PARAMS;
    }
    size_t mdLen = strlen(tmp);
    char *mdStr = (char *)HcfMalloc(mdLen + 1, 0);
    if (mdStr == NULL) {
        LOGE("Failed to allocate md name memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(mdStr, mdLen, tmp, mdLen);
    *returnString = mdStr;
    return HCF_SUCCESS;
}

HcfResult GetRsaSpecStringMGF(char **returnString)
{
    if (returnString == NULL) {
        LOGE("return string is null");
        return HCF_INVALID_PARAMS;
    }
    uint32_t mgf1Len = strlen(HCF_OPENSSL_MGF1);
    char *mgf1Str = (char *)HcfMalloc(mgf1Len + 1, 0);
    if (mgf1Str == NULL) {
        LOGE("Failed to allocate mgf1 name memory");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(mgf1Str, mgf1Len, HCF_OPENSSL_MGF1, mgf1Len);
    *returnString = mgf1Str;
    return HCF_SUCCESS;
}

void HcfPrintOpensslError(void)
{
    char szErr[LOG_PRINT_MAX_LEN] = {0};
    unsigned long errCode;

    errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, LOG_PRINT_MAX_LEN);

    LOGE("[Openssl]: engine fail, error code = %lu, error string = %s", errCode, szErr);
}

HcfResult GetOpensslPadding(int32_t padding, int32_t *opensslPadding)
{
    if (opensslPadding == NULL) {
        LOGE("return openssl padding pointer is null");
        return HCF_INVALID_PARAMS;
    }
    switch (padding) {
        case HCF_ALG_NOPADDING:
            *opensslPadding = RSA_NO_PADDING;
            return HCF_SUCCESS;

        case HCF_OPENSSL_RSA_PKCS1_PADDING:
            *opensslPadding = RSA_PKCS1_PADDING;
            return HCF_SUCCESS;

        case HCF_OPENSSL_RSA_PKCS1_OAEP_PADDING:
            *opensslPadding = RSA_PKCS1_OAEP_PADDING;
            return HCF_SUCCESS;

        case HCF_OPENSSL_RSA_PSS_PADDING:
            *opensslPadding = RSA_PKCS1_PSS_PADDING;
            return HCF_SUCCESS;

        default:
            LOGE("Invalid framwork padding = %d", padding);
            return HCF_INVALID_PARAMS;
    }
}

int32_t GetRealPrimes(int32_t primesFlag)
{
    switch (primesFlag) {
        case HCF_OPENSSL_PRIMES_2:
            return PRIMES_2;
        case HCF_OPENSSL_PRIMES_3:
            return PRIMES_3;
        case HCF_OPENSSL_PRIMES_4:
            return PRIMES_4;
        case HCF_OPENSSL_PRIMES_5:
            return PRIMES_5;
        default:
            LOGI("set default primes 2");
            return PRIMES_2;
    }
}

bool IsBigEndian(void)
{
    uint32_t *pointer = (uint32_t *)&ASCII_CODE_ZERO;
    char firstChar = *((char *)pointer);
    if (firstChar == '0') {
        return false;
    } else {
        return true;
    }
}

HcfResult BigIntegerToBigNum(const HcfBigInteger *src, BIGNUM **dest)
{
    if (src == NULL || dest == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    if (IsBigEndian()) {
        *dest = Openssl_BN_bin2bn((src->data), (src->len), NULL);
    } else {
        *dest = Openssl_BN_lebin2bn((src->data), (src->len), NULL);
    }

    if (*dest == NULL) {
        LOGE("translate BigInteger to BIGNUM failed.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult BigNumToBigInteger(const BIGNUM *src, HcfBigInteger *dest)
{
    if (src == NULL || dest == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }

    int32_t len = Openssl_BN_num_bytes(src);
    if (len <= 0) {
        LOGE("Invalid input parameter.");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    dest->data = (unsigned char *)HcfMalloc(len, 0);
    if (dest->data == NULL) {
        LOGE("Alloc dest->data memeory failed.");
        return HCF_ERR_MALLOC;
    }
    dest->len = len;

    int32_t resLen = -1;
    if (IsBigEndian()) {
        resLen = Openssl_BN_bn2binpad(src, dest->data, dest->len);
    } else {
        resLen = Openssl_BN_bn2lebinpad(src, dest->data, dest->len);
    }

    if (resLen != dest->len) {
        LOGE("translate BIGNUM to BigInteger failed.");
        HcfPrintOpensslError();
        HcfFree(dest->data);
        dest->data = NULL;
        dest->len = 0;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}
