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

#include "mbedtls_sym_key.h"

#include <limits.h>
#include <string.h>
#include "mbedtls_common.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "result.h"
#include "utils.h"

#define MAX_KEY_STR_SIZE 12
#define MAX_KEY_LEN 4096
#define AES_ALG_NAME "AES"
#define HMAC_ALG_NAME "HMAC"

typedef struct {
    HcfSymKeyGeneratorSpi base;
    SymKeyAttr attr;
} MbedtlsSymKeyGeneratorSpiImpl;

static const char *GetMbedtlsSymKeyGeneratorClass(void)
{
    return MBEDTLS_SYM_GENERATOR_CLASS;
}

static const char *GetMbedtlsSymKeyClass(void)
{
    return MBEDTLS_SYM_KEY_CLASS;
}

static HcfResult MbedtlsRandBytes(uint8_t *buf, size_t len)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctrDrbg);
    int32_t ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_ctr_drbg_seed failed ret is %d!", ret);
        mbedtls_ctr_drbg_free(&ctrDrbg);
        mbedtls_entropy_free(&entropy);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    ret = mbedtls_ctr_drbg_random(&ctrDrbg, buf, len);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_entropy_free(&entropy);
    if (ret != HCF_MBEDTLS_SUCCESS) {
        LOGE("mbedtls_ctr_drbg_random failed ret is %d!", ret);
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult GetEncoded(HcfKey *self, HcfBlob *key)
{
    (void)self;
    (void)key;
    LOGE("getEncoded is not supported.");
    return HCF_NOT_SUPPORT;
}

static void ClearMem(HcfSymKey *self)
{
    if (self == NULL) {
        LOGE("symKey is NULL.");
        return;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetMbedtlsSymKeyClass())) {
        LOGE("Class is not match.");
        return;
    }
    SymKeyImpl *impl = (SymKeyImpl *)self;
    if ((impl->keyMaterial.data != NULL) && (impl->keyMaterial.len > 0)) {
        if (memset_s(impl->keyMaterial.data, impl->keyMaterial.len, 0, impl->keyMaterial.len) != EOK) {
            LOGE("Failed to clear keyMaterial!");
        }
    }
}

static const char *GetFormat(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter!");
        return NULL;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetMbedtlsSymKeyClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return "PKCS#8";
}

static const char *GetAlgorithm(HcfKey *self)
{
    if (self == NULL) {
        LOGE("Invalid input parameter!");
        return NULL;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetMbedtlsSymKeyClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    SymKeyImpl *impl = (SymKeyImpl *)self;
    return (const char *)impl->algoName;
}

static HcfResult GetSymKeySize(HcfKey *self, int *keySize)
{
    (void)self;
    (void)keySize;
    LOGE("getKeySize is not supported.");
    return HCF_NOT_SUPPORT;
}

static void DestroySymKeyGeneratorSpi(HcfObjectBase *base)
{
    if (base == NULL) {
        LOGE("Invalid input parameter!");
        return;
    }
    if (!HcfIsClassMatch(base, GetMbedtlsSymKeyGeneratorClass())) {
        LOGE("Class is not match!");
        return;
    }
    HcfFree(base);
}

static void DestroySymKeySpi(HcfObjectBase *base)
{
    if (base == NULL) {
        LOGE("Invalid input parameter!");
        return;
    }
    if (!HcfIsClassMatch(base, GetMbedtlsSymKeyClass())) {
        LOGE("Class is not match.");
        return;
    }
    SymKeyImpl *impl = (SymKeyImpl *)base;
    if (impl->algoName != NULL) {
        HcfFree(impl->algoName);
        impl->algoName = NULL;
    }
    if (impl->keyMaterial.data != NULL) {
        if (memset_s(impl->keyMaterial.data, impl->keyMaterial.len, 0, impl->keyMaterial.len) != EOK) {
            LOGE("Failed to clear keyMaterial in destroy!");
        }
        HcfFree(impl->keyMaterial.data);
        impl->keyMaterial.data = NULL;
        impl->keyMaterial.len = 0;
    }
    HcfFree(impl);
}

static char *GetAlgoNameType(HcfAlgValue type)
{
    switch (type) {
        case HCF_ALG_AES:
            return AES_ALG_NAME;
        case HCF_ALG_HMAC:
            return HMAC_ALG_NAME;
        default:
            LOGE("unsupport type!");
            break;
    }
    return NULL;
}

static char *BuildAlgoName(MbedtlsSymKeyGeneratorSpiImpl *impl, int keySize)
{
    char keySizeChar[MAX_KEY_STR_SIZE] = { 0 };
    if (sprintf_s(keySizeChar, MAX_KEY_STR_SIZE, "%d", keySize) < 0) {
        LOGE("Invalid input parameter!");
        return NULL;
    }
    char *nameType = GetAlgoNameType(impl->attr.algo);
    if (nameType == NULL) {
        LOGE("get algo name type failed!");
        return NULL;
    }
    int32_t nameSize = strlen(nameType);
    char *algoName = (char *)HcfMalloc(MAX_KEY_STR_SIZE, 0);
    if (algoName == NULL) {
        LOGE("algoName malloc failed!");
        return NULL;
    }
    if (strcpy_s(algoName, MAX_KEY_STR_SIZE, nameType) != EOK) {
        LOGE("algoName strcpy_s failed!");
        goto clearup;
    }
    if (strcpy_s(algoName + nameSize, MAX_KEY_STR_SIZE - nameSize, keySizeChar) != EOK) {
        LOGE("algoName size strcpy_s failed!");
        goto clearup;
    }
    return algoName;
clearup:
    HcfFree(algoName);
    algoName = NULL;
    return NULL;
}

static HcfResult RandomSymmKey(int32_t keyLen, HcfBlob *symmKey)
{
    if ((keyLen <= 0) || (symmKey == NULL)) {
        LOGE("Invalid keyLen input parameter!");
        return HCF_INVALID_PARAMS;
    }
    uint8_t *keyMaterial = (uint8_t *)HcfMalloc(keyLen, 0);
    if (keyMaterial == NULL) {
        LOGE("keyMaterial malloc failed!");
        return HCF_ERR_MALLOC;
    }
    HcfResult res = MbedtlsRandBytes(keyMaterial, keyLen);
    if (res != HCF_SUCCESS) {
        LOGE("MbedtlsRandBytes failed!");
        HcfFree(keyMaterial);
        keyMaterial = NULL;
        return res;
    }
    symmKey->data = keyMaterial;
    symmKey->len = keyLen;
    return HCF_SUCCESS;
}

static HcfResult CopySymmKey(const HcfBlob *srcKey, HcfBlob *dstKey)
{
    if ((srcKey->data == NULL) || (srcKey->len == 0)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    uint8_t *keyMaterial = (uint8_t *)HcfMalloc(srcKey->len, 0);
    if (keyMaterial == NULL) {
        LOGE("keyMaterial malloc failed!");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(keyMaterial, srcKey->len, srcKey->data, srcKey->len) != EOK) {
        LOGE("Failed to copy symmetric key material!");
        HcfFree(keyMaterial);
        return HCF_ERR_MALLOC;
    }
    dstKey->data = keyMaterial;
    dstKey->len = srcKey->len;
    return HCF_SUCCESS;
}

static void InitSymKeyMethods(SymKeyImpl *returnSymmKey)
{
    returnSymmKey->key.clearMem = ClearMem;
    returnSymmKey->key.key.getEncoded = GetEncoded;
    returnSymmKey->key.key.getFormat = GetFormat;
    returnSymmKey->key.key.getAlgorithm = GetAlgorithm;
    returnSymmKey->key.key.getKeySize = GetSymKeySize;
    returnSymmKey->key.key.base.destroy = DestroySymKeySpi;
    returnSymmKey->key.key.base.getClass = GetMbedtlsSymKeyClass;
}

static HcfResult GenerateSymmKey(HcfSymKeyGeneratorSpi *self, HcfSymKey **symmKey)
{
    if ((self == NULL) || (symmKey == NULL)) {
        LOGE("Invalid input parameter!");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetMbedtlsSymKeyGeneratorClass())) {
        LOGE("Class is not match!");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsSymKeyGeneratorSpiImpl *impl = (MbedtlsSymKeyGeneratorSpiImpl *)self;
    SymKeyImpl *returnSymmKey = (SymKeyImpl *)HcfMalloc(sizeof(SymKeyImpl), 0);
    if (returnSymmKey == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    HcfResult res = RandomSymmKey(impl->attr.keySize / HCF_BITS_PER_BYTE, &returnSymmKey->keyMaterial);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to create symmetric key SPI.");
        HcfFree(returnSymmKey);
        returnSymmKey = NULL;
        return res;
    }
    returnSymmKey->algoName = BuildAlgoName(impl, impl->attr.keySize);
    if (returnSymmKey->algoName == NULL) {
        LOGE("Failed to build algoName.");
        HcfBlobDataClearAndFree(&returnSymmKey->keyMaterial);
        HcfFree(returnSymmKey);
        returnSymmKey = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    InitSymKeyMethods(returnSymmKey);
    *symmKey = (HcfSymKey *)returnSymmKey;
    return res;
}

static bool IsBlobKeyLenValid(SymKeyAttr attr, const HcfBlob *key)
{
    if ((key->len == 0) || (key->len > MAX_KEY_LEN)) {
        return false;
    }
    if ((attr.keySize / HCF_BITS_PER_BYTE) == (int32_t)key->len) {
        return true;
    }
    if ((attr.algo == HCF_ALG_HMAC) && (attr.keySize == 0)) {
        return true;
    }
    return false;
}

static HcfResult ConvertSymmKey(HcfSymKeyGeneratorSpi *self, const HcfBlob *key, HcfSymKey **symmKey)
{
    if ((self == NULL) || (symmKey == NULL) || !HcfIsBlobValid(key)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    if (!HcfIsClassMatch((const HcfObjectBase *)self, GetMbedtlsSymKeyGeneratorClass())) {
        LOGE("Class is not match.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsSymKeyGeneratorSpiImpl *impl = (MbedtlsSymKeyGeneratorSpiImpl *)self;
    if (!IsBlobKeyLenValid(impl->attr, key)) {
        LOGE("Invalid param: input key length is invalid!");
        return HCF_INVALID_PARAMS;
    }
    SymKeyImpl *returnSymmKey = (SymKeyImpl *)HcfMalloc(sizeof(SymKeyImpl), 0);
    if (returnSymmKey == NULL) {
        LOGE("Failed to allocate returnKeyPair memory!");
        return HCF_ERR_MALLOC;
    }
    HcfResult res = CopySymmKey(key, &returnSymmKey->keyMaterial);
    if (res != HCF_SUCCESS) {
        LOGE("Failed to copy symmetric key.");
        HcfFree(returnSymmKey);
        returnSymmKey = NULL;
        return res;
    }
    int keySize = impl->attr.keySize;
    if (impl->attr.algo == HCF_ALG_HMAC && keySize == 0) {
        keySize = (int)returnSymmKey->keyMaterial.len * HCF_BITS_PER_BYTE;
    }
    returnSymmKey->algoName = BuildAlgoName(impl, keySize);
    if (returnSymmKey->algoName == NULL) {
        LOGE("Failed to build algoName.");
        HcfBlobDataClearAndFree(&returnSymmKey->keyMaterial);
        HcfFree(returnSymmKey);
        returnSymmKey = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    InitSymKeyMethods(returnSymmKey);
    *symmKey = (HcfSymKey *)returnSymmKey;
    return HCF_SUCCESS;
}

HcfResult MbedtlsSymKeyGeneratorSpiCreate(SymKeyAttr *attr, HcfSymKeyGeneratorSpi **generator)
{
    if ((attr == NULL) || (generator == NULL)) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    MbedtlsSymKeyGeneratorSpiImpl *returnGenerator =
        (MbedtlsSymKeyGeneratorSpiImpl *)HcfMalloc(sizeof(MbedtlsSymKeyGeneratorSpiImpl), 0);
    if (returnGenerator == NULL) {
        LOGE("Failed to allocate returnGenerator memory!");
        return HCF_ERR_MALLOC;
    }
    if (memcpy_s(&returnGenerator->attr, sizeof(SymKeyAttr), attr, sizeof(SymKeyAttr)) != EOK) {
        LOGE("Failed to copy sym key attr!");
        HcfFree(returnGenerator);
        return HCF_ERR_MALLOC;
    }
    returnGenerator->base.engineGenerateSymmKey = GenerateSymmKey;
    returnGenerator->base.engineConvertSymmKey = ConvertSymmKey;
    returnGenerator->base.base.destroy = DestroySymKeyGeneratorSpi;
    returnGenerator->base.base.getClass = GetMbedtlsSymKeyGeneratorClass;
    *generator = (HcfSymKeyGeneratorSpi *)returnGenerator;
    return HCF_SUCCESS;
}
