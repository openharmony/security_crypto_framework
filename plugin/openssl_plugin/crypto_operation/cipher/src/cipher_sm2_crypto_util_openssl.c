/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "cipher_sm2_crypto_util_openssl.h"
#include <stdbool.h>
#include <string.h>
#include "log.h"
#include "memory.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "securec.h"
#include "utils.h"

static HcfResult BuildSM2Ciphertext(const Sm2CipherTextSpec *spec, struct SM2_Ciphertext_st *sm2Text)
{
    if (BigIntegerToBigNum(&(spec->xCoordinate), &(sm2Text->C1x)) != HCF_SUCCESS) {
        LOGE("Build x failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigIntegerToBigNum(&(spec->yCoordinate), &(sm2Text->C1y)) != HCF_SUCCESS) {
        LOGE("Build y failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    sm2Text->C3 = Openssl_ASN1_OCTET_STRING_new();
    sm2Text->C2 = Openssl_ASN1_OCTET_STRING_new();
    if (sm2Text->C3 == NULL || sm2Text->C2 == NULL) {
        LOGE("SM2 openssl [ASN1_OCTET_STRING_new] C3 C2 fail");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_ASN1_OCTET_STRING_set(sm2Text->C3, spec->hashData.data, HCF_SM2_C3_LEN) != HCF_OPENSSL_SUCCESS) {
        LOGE("SM2 openssl [ASN1_OCTET_STRING_set] c3 error");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (Openssl_ASN1_OCTET_STRING_set(sm2Text->C2, spec->cipherTextData.data, spec->cipherTextData.len) !=
        HCF_OPENSSL_SUCCESS) {
        LOGE("SM2 openssl [ASN1_OCTET_STRING_set] c2 error");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

HcfResult HcfSm2ConstructToAsn1(Sm2CipherTextSpec *spec, HcfBlob *output)
{
    struct SM2_Ciphertext_st *sm2Text = Openssl_SM2_Ciphertext_new();
    if (sm2Text == NULL) {
        LOGE("SM2 openssl [SM2_Ciphertext_new] failed");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    HcfResult res = BuildSM2Ciphertext(spec, sm2Text);
    if (res != HCF_SUCCESS) {
        Openssl_SM2_Ciphertext_free(sm2Text);
        LOGE("SM2 build SM2Ciphertext fail");
        return res;
    }
    unsigned char *returnData = NULL;
    size_t returnDataLen = Openssl_i2d_SM2_Ciphertext(sm2Text, &returnData);
    if (returnDataLen < 0) {
        LOGE("SM2 openssl [i2d_SM2_Ciphertext] error");
        HcfPrintOpensslError();
        Openssl_SM2_Ciphertext_free(sm2Text);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = returnData;
    output->len = returnDataLen;
    Openssl_SM2_Ciphertext_free(sm2Text);
    return HCF_SUCCESS;
}

static HcfResult BuildSm2CipherTextSpec(Sm2CipherTextSpec *tempSpec, struct SM2_Ciphertext_st *sm2Text)
{
    if (BigNumToBigInteger(sm2Text->C1x, &(tempSpec->xCoordinate)) != HCF_SUCCESS) {
        LOGE("BigNumToBigInteger xCoordinate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (BigNumToBigInteger(sm2Text->C1y, &(tempSpec->yCoordinate)) != HCF_SUCCESS) {
        LOGE("BigNumToBigInteger yCoordinate failed.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const unsigned char *c2Data = Openssl_ASN1_STRING_get0_data(sm2Text->C2);
    int c2Len = Openssl_ASN1_STRING_length(sm2Text->C2);
    if (c2Data == NULL) {
        LOGE("SM2 openssl [Openssl_ASN1_STRING_get0_data] error.");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    const unsigned char *c3Data = Openssl_ASN1_STRING_get0_data(sm2Text->C3);
    int c3Len = Openssl_ASN1_STRING_length(sm2Text->C3);
    if (c3Data == NULL) {
        LOGE("SM2 openssl [Openssl_ASN1_STRING_get0_data] error.");
        // const c2Data can free？
        return HCF_ERR_CRYPTO_OPERATION;
    }
    
    tempSpec->cipherTextData.data = (unsigned char *)HcfMalloc(c2Len, 0);
    if (tempSpec->cipherTextData.data == NULL) {
        LOGE("Failed to allocate cipherTextData.data memory");
        return HCF_ERR_MALLOC;
    }
    tempSpec->hashData.data = (unsigned char *)HcfMalloc(c3Len, 0);
    if (tempSpec->hashData.data == NULL) {
        LOGE("Failed to allocate hashData.data memory");
        HcfFree(tempSpec->cipherTextData.data);
        tempSpec->cipherTextData.data = NULL;
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(tempSpec->cipherTextData.data, c2Len, c2Data, c2Len);
    (void)memcpy_s(tempSpec->hashData.data, c3Len, c3Data, c3Len);
    tempSpec->cipherTextData.len = c2Len;
    tempSpec->hashData.len = c3Len;
    return HCF_SUCCESS;
}

HcfResult HcfAsn1ToSm2Construct(HcfBlob *input, Sm2CipherTextSpec **returnSpec)
{
    struct SM2_Ciphertext_st *sm2Text = Openssl_d2i_SM2_Ciphertext(input->data, input->len);
    if (sm2Text == NULL) {
        LOGE("SM2 openssl [d2i_SM2_Ciphertext] error");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    Sm2CipherTextSpec *tempSpec = (Sm2CipherTextSpec *)(HcfMalloc(sizeof(Sm2CipherTextSpec), 0));
    if (tempSpec == NULL) {
        LOGE("Failed to allocate Sm2CipherTextSpec memory");
        Openssl_SM2_Ciphertext_free(sm2Text);
        return HCF_ERR_MALLOC;
    }
    HcfResult res = BuildSm2CipherTextSpec(tempSpec, sm2Text);
    if (res != HCF_SUCCESS) {
        LOGE("SM2 build SM2Ciphertext fail");
        HcfFree(tempSpec);
        Openssl_SM2_Ciphertext_free(sm2Text);
        return res;
    }
    *returnSpec = tempSpec;
    Openssl_SM2_Ciphertext_free(sm2Text);
    return HCF_SUCCESS;
}