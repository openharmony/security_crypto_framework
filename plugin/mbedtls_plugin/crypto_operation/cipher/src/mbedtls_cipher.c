/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "mbedtls_cipher.h"

#include "mbedtls_common.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "result.h"
#include "utils.h"
#include "mbedtls_sym_key.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_aead_params.h"

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE_128 16
#define GCM_TAG_SIZE 16
#define GCM_IV_MIN_LEN 1
#define GCM_IV_MAX_LEN 128
#define BUFFER_GROWTH_FACTOR 2

typedef enum {
    CIPHER_UNINIT = 0,
    CIPHER_INIT = 1,
} CipherStatus;

typedef struct {
    HcfCipherGeneratorSpi base;
    HcfCipherAttr attr;
    enum HcfCryptoMode enc;
    CipherStatus initFlag;
    unsigned char *iv;
    uint32_t ivLen;
    unsigned char *aad;
    uint32_t aadLen;
    unsigned char *tag;
    uint32_t tagLen;
    uint8_t *keyBuf;
    size_t keyLen;
    uint8_t *dataBuf;
    size_t dataLen;
    size_t dataCap;
} MbedtlsAesCipherSpiImpl;

static const char *GetAesCipherClass(void)
{
    return MBEDTLS_AES_CIPHER_CLASS;
}

static void FreeCipherInner(MbedtlsAesCipherSpiImpl *impl)
{
    if (impl == NULL) {
        return;
    }
    if (impl->aad != NULL) {
        HcfFree(impl->aad);
        impl->aad = NULL;
    }
    impl->aadLen = 0;
    if (impl->tag != NULL) {
        HcfFree(impl->tag);
        impl->tag = NULL;
    }
    impl->tagLen = 0;
    if (impl->iv != NULL) {
        HcfFree(impl->iv);
        impl->iv = NULL;
    }
    impl->ivLen = 0;
    if (impl->keyBuf != NULL) {
        (void)memset_s(impl->keyBuf, impl->keyLen, 0, impl->keyLen);
        HcfFree(impl->keyBuf);
        impl->keyBuf = NULL;
    }
    impl->keyLen = 0;
    if (impl->dataBuf != NULL) {
        (void)memset_s(impl->dataBuf, impl->dataLen, 0, impl->dataLen);
        HcfFree(impl->dataBuf);
        impl->dataBuf = NULL;
    }
    impl->dataLen = 0;
    impl->dataCap = 0;
}

#define MAX_CIPHER_DATA_LEN (1024 * 1024)

static HcfResult AppendData(MbedtlsAesCipherSpiImpl *impl, const HcfBlob *input)
{
    if ((input == NULL) || (input->data == NULL) || (input->len == 0)) {
        return HCF_SUCCESS;
    }
    if (impl->dataCap - impl->dataLen < input->len) {
        size_t need = impl->dataLen + input->len;
        if (need > MAX_CIPHER_DATA_LEN) {
            LOGE("cipher data length exceeds limit!");
            return HCF_INVALID_PARAMS;
        }
        size_t newCap = (impl->dataCap == 0) ? AES_BLOCK_SIZE : impl->dataCap;
        while (newCap < need) {
            if (newCap > (SIZE_MAX / BUFFER_GROWTH_FACTOR)) {
                newCap = need;
                break;
            }
            newCap *= BUFFER_GROWTH_FACTOR;
        }
        uint8_t *tmp = (uint8_t *)HcfMalloc(newCap, 0);
        if (tmp == NULL) {
            LOGE("malloc dataBuf failed!");
            return HCF_ERR_MALLOC;
        }
        if (impl->dataLen > 0) {
            (void)memcpy_s(tmp, newCap, impl->dataBuf, impl->dataLen);
        }
        if (impl->dataBuf != NULL) {
            HcfFree(impl->dataBuf);
        }
        impl->dataBuf = tmp;
        impl->dataCap = newCap;
    }
    if (memcpy_s(impl->dataBuf + impl->dataLen, impl->dataCap - impl->dataLen, input->data, input->len) != EOK) {
        LOGE("Failed to append input data!");
        return HCF_ERR_MALLOC;
    }
    impl->dataLen += input->len;
    return HCF_SUCCESS;
}

static HcfResult ParseGcmParamsType(HcfParamsSpec *params, HcfBlob **ivBlob, HcfBlob **aadBlob,
    HcfBlob **tagBlob, uint32_t *tagLen)
{
    const char *typeName = (params->getType == NULL) ? NULL : params->getType();
    *tagBlob = NULL;
    *tagLen = 0;
    if ((typeName != NULL) && (strcmp(typeName, "GcmParamsSpec") == 0)) {
        HcfGcmParamsSpec *gcm = (HcfGcmParamsSpec *)params;
        *ivBlob = &gcm->iv;
        *aadBlob = &gcm->aad;
        *tagBlob = &gcm->tag;
        *tagLen = gcm->tag.len;
    } else if ((typeName != NULL) && (strcmp(typeName, "AeadParamsSpec") == 0)) {
        HcfAeadParamsSpec *aead = (HcfAeadParamsSpec *)params;
        *ivBlob = &aead->nonce;
        *aadBlob = &aead->aad;
        *tagLen = (aead->tagLen > 0) ? (uint32_t)aead->tagLen : GCM_TAG_SIZE;
    } else {
        LOGE("gcm params type is invalid!");
        return HCF_INVALID_PARAMS;
    }
    return HCF_SUCCESS;
}

static HcfResult StoreGcmIvAndAad(MbedtlsAesCipherSpiImpl *impl, HcfBlob *ivBlob, HcfBlob *aadBlob)
{
    if ((ivBlob->data == NULL) || (ivBlob->len < GCM_IV_MIN_LEN) || (ivBlob->len > GCM_IV_MAX_LEN)) {
        LOGE("gcm iv is invalid!");
        return HCF_INVALID_PARAMS;
    }
    impl->iv = (unsigned char *)HcfMalloc(ivBlob->len, 0);
    if (impl->iv == NULL) {
        LOGE("malloc iv failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(impl->iv, ivBlob->len, ivBlob->data, ivBlob->len);
    impl->ivLen = ivBlob->len;
    if ((aadBlob->data != NULL) && (aadBlob->len != 0)) {
        impl->aad = (unsigned char *)HcfMalloc(aadBlob->len, 0);
        if (impl->aad == NULL) {
            LOGE("malloc aad failed!");
            HcfFree(impl->iv);
            impl->iv = NULL;
            impl->ivLen = 0;
            return HCF_ERR_MALLOC;
        }
        if (memcpy_s(impl->aad, aadBlob->len, aadBlob->data, aadBlob->len) != EOK) {
            LOGE("Failed to copy aad!");
            HcfFree(impl->aad);
            impl->aad = NULL;
            HcfFree(impl->iv);
            impl->iv = NULL;
            impl->ivLen = 0;
            return HCF_ERR_MALLOC;
        }
        impl->aadLen = aadBlob->len;
    }
    return HCF_SUCCESS;
}

static HcfResult StoreGcmParams(MbedtlsAesCipherSpiImpl *impl, enum HcfCryptoMode opMode, HcfParamsSpec *params)
{
    if (params == NULL) {
        LOGE("gcm params is null!");
        return HCF_INVALID_PARAMS;
    }
    HcfBlob *ivBlob = NULL;
    HcfBlob *aadBlob = NULL;
    HcfBlob *tagBlob = NULL;
    uint32_t tagLen = 0;
    HcfResult ret = ParseGcmParamsType(params, &ivBlob, &aadBlob, &tagBlob, &tagLen);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    ret = StoreGcmIvAndAad(impl, ivBlob, aadBlob);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    if (opMode == DECRYPT_MODE) {
        if ((tagBlob != NULL) && (tagBlob->data != NULL) && (tagBlob->len != 0)) {
            impl->tag = (unsigned char *)HcfMalloc(tagBlob->len, 0);
            if (impl->tag == NULL) {
                LOGE("malloc tag failed!");
                return HCF_ERR_MALLOC;
            }
            (void)memcpy_s(impl->tag, tagBlob->len, tagBlob->data, tagBlob->len);
            impl->tagLen = tagBlob->len;
        } else {
            impl->tagLen = tagLen;
        }
    } else {
        impl->tagLen = tagLen;
    }
    return HCF_SUCCESS;
}

static HcfResult StoreIvParams(MbedtlsAesCipherSpiImpl *impl, HcfParamsSpec *params)
{
    if (params == NULL) {
        LOGE("cbc params is null!");
        return HCF_INVALID_PARAMS;
    }
    const char *typeName = (params->getType == NULL) ? NULL : params->getType();
    HcfIvParamsSpec *ivSpec = NULL;
    if ((typeName != NULL) && (strcmp(typeName, "IvParamsSpec") == 0)) {
        ivSpec = (HcfIvParamsSpec *)params;
    } else {
        LOGE("iv params type is invalid!");
        return HCF_INVALID_PARAMS;
    }
    if ((ivSpec->iv.data == NULL) || (ivSpec->iv.len != AES_BLOCK_SIZE)) {
        LOGE("cbc iv is invalid!");
        return HCF_INVALID_PARAMS;
    }
    impl->iv = (unsigned char *)HcfMalloc(ivSpec->iv.len, 0);
    if (impl->iv == NULL) {
        LOGE("malloc iv failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(impl->iv, ivSpec->iv.len, ivSpec->iv.data, ivSpec->iv.len);
    impl->ivLen = ivSpec->iv.len;
    return HCF_SUCCESS;
}

static HcfResult EngineCipherInit(HcfCipherGeneratorSpi *self, enum HcfCryptoMode opMode,
    HcfKey *key, HcfParamsSpec *params)
{
    if ((self == NULL) || (key == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetAesCipherClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)key, MBEDTLS_SYM_KEY_CLASS)) {
        LOGE("Sym key class is not match.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsAesCipherSpiImpl *impl = (MbedtlsAesCipherSpiImpl *)self;
    SymKeyImpl *keyImpl = (SymKeyImpl *)key;
    if (opMode != ENCRYPT_MODE && opMode != DECRYPT_MODE) {
        LOGE("Invalid operation mode: %d", opMode);
        return HCF_INVALID_PARAMS;
    }
    if ((keyImpl->keyMaterial.data == NULL) || (keyImpl->keyMaterial.len != AES_KEY_SIZE_128)) {
        LOGE("Key material is invalid, only support AES128.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    FreeCipherInner(impl);
    impl->enc = opMode;
    impl->keyBuf = (uint8_t *)HcfMalloc(keyImpl->keyMaterial.len, 0);
    if (impl->keyBuf == NULL) {
        LOGE("malloc keyBuf failed!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(impl->keyBuf, keyImpl->keyMaterial.len, keyImpl->keyMaterial.data, keyImpl->keyMaterial.len);
    impl->keyLen = keyImpl->keyMaterial.len;
    HcfResult ret;
    if (impl->attr.mode == HCF_ALG_MODE_GCM) {
        ret = StoreGcmParams(impl, opMode, params);
    } else if (impl->attr.mode == HCF_ALG_MODE_CBC) {
        ret = StoreIvParams(impl, params);
    } else {
        LOGE("Not support mode: %d", impl->attr.mode);
        return HCF_NOT_SUPPORT;
    }
    if (ret != HCF_SUCCESS) {
        FreeCipherInner(impl);
        return ret;
    }
    impl->initFlag = CIPHER_INIT;
    return HCF_SUCCESS;
}

static HcfResult EngineUpdate(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (input == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetAesCipherClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsAesCipherSpiImpl *impl = (MbedtlsAesCipherSpiImpl *)self;
    if (impl->initFlag != CIPHER_INIT) {
        LOGE("Cipher instance is not initialized!");
        return HCF_ERR_INVALID_CALL;
    }
    HcfResult ret = AppendData(impl, input);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to append data.");
        return ret;
    }
    output->data = NULL;
    output->len = 0;
    return HCF_SUCCESS;
}

static HcfResult CbcEncryptWithPadding(MbedtlsAesCipherSpiImpl *impl, uint8_t *inBuf, size_t totalLen,
    HcfBlob *output)
{
    output->data = (uint8_t *)HcfMalloc(totalLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    uint8_t ivCopy[AES_BLOCK_SIZE];
    if (memcpy_s(ivCopy, AES_BLOCK_SIZE, impl->iv, impl->ivLen) != EOK) {
        LOGE("Failed to copy iv for cbc encrypt!");
        HcfFree(output->data);
        output->data = NULL;
        return HCF_ERR_MALLOC;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int32_t ret = mbedtls_aes_setkey_enc(&ctx, impl->keyBuf, impl->keyLen * HCF_BITS_PER_BYTE);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_aes_setkey_enc failed ret %d!", ret);
        mbedtls_aes_free(&ctx);
        HcfFree(output->data);
        output->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, totalLen, ivCopy, inBuf, output->data);
    mbedtls_aes_free(&ctx);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_aes_crypt_cbc encrypt failed ret %d!", ret);
        HcfFree(output->data);
        output->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len = totalLen;
    return HCF_SUCCESS;
}

static HcfResult CbcEncryptFinal(MbedtlsAesCipherSpiImpl *impl, HcfBlob *output)
{
    bool noPadding = (impl->attr.paddingMode == HCF_ALG_NOPADDING);
    size_t padLen = 0;
    size_t totalLen = impl->dataLen;
    if (!noPadding) {
        padLen = AES_BLOCK_SIZE - (impl->dataLen % AES_BLOCK_SIZE);
        totalLen = impl->dataLen + padLen;
    } else if ((impl->dataLen % AES_BLOCK_SIZE) != 0) {
        LOGE("cbc noPadding encrypt data len is not block aligned!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    uint8_t *inBuf = (uint8_t *)HcfMalloc(totalLen, 0);
    if (inBuf == NULL) {
        LOGE("malloc inBuf failed!");
        return HCF_ERR_MALLOC;
    }
    if (impl->dataLen > 0) {
        if (memcpy_s(inBuf, totalLen, impl->dataBuf, impl->dataLen) != EOK) {
            LOGE("Failed to copy data to inBuf!");
            HcfFree(inBuf);
            return HCF_ERR_MALLOC;
        }
    }
    if (!noPadding) {
        for (size_t i = impl->dataLen; i < totalLen; i++) {
            inBuf[i] = (uint8_t)padLen;
        }
    }
    HcfResult ret = CbcEncryptWithPadding(impl, inBuf, totalLen, output);
    HcfFree(inBuf);
    return ret;
}

static HcfResult ValidateAndStripPkcs7Padding(uint8_t *outBuf, size_t dataLen, bool noPadding, size_t *plainLen)
{
    if (noPadding) {
        *plainLen = dataLen;
        return HCF_SUCCESS;
    }
    uint8_t padLen = outBuf[dataLen - 1];
    if ((padLen == 0) || (padLen > AES_BLOCK_SIZE)) {
        LOGE("Invalid pkcs7 padding %d!", padLen);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    for (size_t i = dataLen - padLen; i < dataLen; i++) {
        if (outBuf[i] != padLen) {
            LOGE("Invalid pkcs7 padding data!");
            return HCF_ERR_CRYPTO_OPERATION;
        }
    }
    *plainLen = dataLen - padLen;
    return HCF_SUCCESS;
}

static HcfResult CbcDecryptFinal(MbedtlsAesCipherSpiImpl *impl, HcfBlob *output)
{
    if ((impl->dataLen == 0) || (impl->dataLen % AES_BLOCK_SIZE != 0)) {
        LOGE("cbc decrypt data len is invalid!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    uint8_t *outBuf = (uint8_t *)HcfMalloc(impl->dataLen, 0);
    if (outBuf == NULL) {
        LOGE("malloc outBuf failed!");
        return HCF_ERR_MALLOC;
    }
    uint8_t ivCopy[AES_BLOCK_SIZE];
    if (memcpy_s(ivCopy, AES_BLOCK_SIZE, impl->iv, impl->ivLen) != EOK) {
        LOGE("Failed to copy iv for cbc decrypt!");
        HcfFree(outBuf);
        return HCF_ERR_MALLOC;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int32_t ret = mbedtls_aes_setkey_dec(&ctx, impl->keyBuf, impl->keyLen * HCF_BITS_PER_BYTE);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_aes_setkey_dec failed ret %d!", ret);
        mbedtls_aes_free(&ctx);
        HcfFree(outBuf);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, impl->dataLen, ivCopy, impl->dataBuf, outBuf);
    mbedtls_aes_free(&ctx);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_aes_crypt_cbc decrypt failed ret %d!", ret);
        HcfFree(outBuf);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    size_t plainLen = impl->dataLen;
    bool noPadding = (impl->attr.paddingMode == HCF_ALG_NOPADDING);
    HcfResult res = ValidateAndStripPkcs7Padding(outBuf, impl->dataLen, noPadding, &plainLen);
    if (res != HCF_SUCCESS) {
        HcfFree(outBuf);
        return res;
    }
    output->data = (uint8_t *)HcfMalloc(plainLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        HcfFree(outBuf);
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(output->data, plainLen, outBuf, plainLen);
    output->len = plainLen;
    HcfFree(outBuf);
    return HCF_SUCCESS;
}

static HcfResult GcmEncryptFinal(MbedtlsAesCipherSpiImpl *impl, HcfBlob *output)
{
    uint32_t tagLen = (impl->tagLen != 0) ? impl->tagLen : GCM_TAG_SIZE;
    size_t outLen = impl->dataLen + tagLen;
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        return HCF_ERR_MALLOC;
    }
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int32_t ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, impl->keyBuf, impl->keyLen * HCF_BITS_PER_BYTE);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_gcm_setkey failed ret %d!", ret);
        mbedtls_gcm_free(&ctx);
        HcfFree(output->data);
        output->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, impl->dataLen,
        impl->iv, impl->ivLen,
        impl->aad, impl->aadLen, impl->dataBuf, output->data, tagLen, output->data + impl->dataLen);
    mbedtls_gcm_free(&ctx);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_gcm_crypt_and_tag failed ret %d!", ret);
        HcfFree(output->data);
        output->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len = outLen;
    return HCF_SUCCESS;
}

static HcfResult ExtractGcmDecryptTag(MbedtlsAesCipherSpiImpl *impl, uint32_t tagLen,
    unsigned char **tag, size_t *cipherLen, unsigned char **extractedTag)
{
    *tag = impl->tag;
    *cipherLen = impl->dataLen;
    *extractedTag = NULL;
    if (impl->tag != NULL) {
        return HCF_SUCCESS;
    }
    if (*cipherLen < tagLen) {
        LOGE("gcm decrypt data is too short to contain authTag!");
        return HCF_INVALID_PARAMS;
    }
    *extractedTag = (unsigned char *)HcfMalloc(tagLen, 0);
    if (*extractedTag == NULL) {
        LOGE("malloc extracted tag failed!");
        return HCF_ERR_MALLOC;
    }
    *cipherLen -= tagLen;
    if (memcpy_s(*extractedTag, tagLen, impl->dataBuf + *cipherLen, tagLen) != EOK) {
        LOGE("Failed to extract gcm tag!");
        HcfFree(*extractedTag);
        *extractedTag = NULL;
        return HCF_ERR_MALLOC;
    }
    *tag = *extractedTag;
    return HCF_SUCCESS;
}

static HcfResult GcmDecryptFinal(MbedtlsAesCipherSpiImpl *impl, HcfBlob *output)
{
    uint32_t tagLen = (impl->tagLen != 0) ? impl->tagLen : GCM_TAG_SIZE;
    if (output == NULL) {
        return HCF_INVALID_PARAMS;
    }
    unsigned char *tag = NULL;
    size_t cipherLen = 0;
    unsigned char *extractedTag = NULL;
    HcfResult ret = ExtractGcmDecryptTag(impl, tagLen, &tag, &cipherLen, &extractedTag);
    if (ret != HCF_SUCCESS) {
        return ret;
    }
    output->data = (uint8_t *)HcfMalloc(cipherLen, 0);
    if (output->data == NULL) {
        LOGE("malloc output failed!");
        HcfFree(extractedTag);
        return HCF_ERR_MALLOC;
    }
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int32_t res = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, impl->keyBuf, impl->keyLen * HCF_BITS_PER_BYTE);
    if (res != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_gcm_setkey failed ret %d!", res);
        mbedtls_gcm_free(&ctx);
        HcfFree(output->data);
        output->data = NULL;
        HcfFree(extractedTag);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    res = mbedtls_gcm_auth_decrypt(&ctx, cipherLen, impl->iv, impl->ivLen,
        impl->aad, impl->aadLen, tag, tagLen, impl->dataBuf, output->data);
    mbedtls_gcm_free(&ctx);
    HcfFree(extractedTag);
    if (res != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_gcm_auth_decrypt failed ret %d!", res);
        HcfFree(output->data);
        output->data = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->len = cipherLen;
    return HCF_SUCCESS;
}

static HcfResult EngineDoFinal(HcfCipherGeneratorSpi *self, HcfBlob *input, HcfBlob *output)
{
    if ((self == NULL) || (output == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetAesCipherClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsAesCipherSpiImpl *impl = (MbedtlsAesCipherSpiImpl *)self;
    if (impl->initFlag != CIPHER_INIT) {
        LOGE("Cipher instance is not initialized!");
        return HCF_ERR_INVALID_CALL;
    }
    HcfResult ret = AppendData(impl, input);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to append final data.");
        return ret;
    }
    if (impl->attr.mode == HCF_ALG_MODE_GCM) {
        ret = (impl->enc == ENCRYPT_MODE) ? GcmEncryptFinal(impl, output) : GcmDecryptFinal(impl, output);
    } else if (impl->attr.mode == HCF_ALG_MODE_CBC) {
        ret = (impl->enc == ENCRYPT_MODE) ? CbcEncryptFinal(impl, output) : CbcDecryptFinal(impl, output);
    } else {
        LOGE("Not support mode: %d", impl->attr.mode);
        ret = HCF_NOT_SUPPORT;
    }
    FreeCipherInner(impl);
    impl->initFlag = CIPHER_UNINIT;
    if (ret != HCF_SUCCESS) {
        HcfBlobDataClearAndFree(output);
    }
    return ret;
}

static void EngineAesCipherDestroy(HcfObjectBase *self)
{
    if (self == NULL) {
        return;
    }
    if (!HcfIsClassMatch(self, GetAesCipherClass())) {
        LOGE("Class is not match.");
        return;
    }
    MbedtlsAesCipherSpiImpl *impl = (MbedtlsAesCipherSpiImpl *)self;
    FreeCipherInner(impl);
    HcfFree(impl);
}

static HcfResult GetCipherSpecString(HcfCipherGeneratorSpi *self, CipherSpecItem item, char **returnString)
{
    (void)self;
    (void)item;
    (void)returnString;
    return HCF_NOT_SUPPORT;
}

static HcfResult GetCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob *returnUint8Array)
{
    (void)self;
    (void)item;
    (void)returnUint8Array;
    return HCF_NOT_SUPPORT;
}

static HcfResult SetCipherSpecUint8Array(HcfCipherGeneratorSpi *self, CipherSpecItem item, HcfBlob blob)
{
    (void)self;
    (void)item;
    (void)blob;
    return HCF_NOT_SUPPORT;
}

HcfResult MbedtlsAesCipherSpiCreate(HcfCipherAttr *attr, HcfCipherGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsAesCipherSpiImpl *returnImpl = (MbedtlsAesCipherSpiImpl *)HcfMalloc(sizeof(MbedtlsAesCipherSpiImpl), 0);
    if (returnImpl == NULL) {
        LOGE("Failed to allocate returnImpl memory!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(&returnImpl->attr, sizeof(HcfCipherAttr), attr, sizeof(HcfCipherAttr));
    returnImpl->base.init = EngineCipherInit;
    returnImpl->base.update = EngineUpdate;
    returnImpl->base.doFinal = EngineDoFinal;
    returnImpl->base.getCipherSpecString = GetCipherSpecString;
    returnImpl->base.getCipherSpecUint8Array = GetCipherSpecUint8Array;
    returnImpl->base.setCipherSpecUint8Array = SetCipherSpecUint8Array;
    returnImpl->base.base.destroy = EngineAesCipherDestroy;
    returnImpl->base.base.getClass = GetAesCipherClass;
    *generator = (HcfCipherGeneratorSpi *)returnImpl;
    return HCF_SUCCESS;
}
