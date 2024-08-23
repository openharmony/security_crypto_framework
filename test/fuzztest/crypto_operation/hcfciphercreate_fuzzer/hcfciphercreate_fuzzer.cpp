/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hcfciphercreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include "securec.h"

#include "asy_key_generator.h"
#include "blob.h"
#include "cipher.h"
#include "mac.h"
#include "result.h"
#include "sym_key_generator.h"
#include "detailed_gcm_params.h"

namespace OHOS {
    static int32_t AesEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
        uint8_t *cipherText, int *cipherTextLen)
    {
        HcfBlob output = {};
        int32_t maxLen = *cipherTextLen;
        int32_t ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
        if (ret != 0) {
            return ret;
        }

        ret = cipher->update(cipher, input, &output);
        if (ret != 0) {
            return ret;
        }
        *cipherTextLen = output.len;
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(cipherText, maxLen, output.data, output.len);
        }
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
            output.data = nullptr;
        }
        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            return ret;
        }
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len);
        }
        *cipherTextLen += output.len;
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
            output.data = nullptr;
        }
        return 0;
    }

    static int32_t AesDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
        uint8_t *cipherText, int cipherTextLen)
    {
        HcfBlob output = {};
        if (cipherTextLen <= 0) {
            return -1;
        }
        int32_t maxLen = cipherTextLen;
        int32_t ret = cipher->init(cipher, DECRYPT_MODE, &(key->key), nullptr);
        if (ret != 0) {
            return ret;
        }

        ret = cipher->update(cipher, input, &output);
        if (ret != 0) {
            return ret;
        }
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(cipherText, maxLen, output.data, output.len);
        }
        cipherTextLen = output.len;
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
            output.data = nullptr;
            output.len = 0;
        }
        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            return ret;
        }
        if (output.len > 0 && output.data != nullptr) {
            (void)memcpy_s(cipherText + cipherTextLen, maxLen - cipherTextLen, output.data, output.len);
        }
        cipherTextLen += output.len;
        if (output.data != nullptr) {
            HcfBlobDataClearAndFree(&output);
            output.data = nullptr;
            output.len = 0;
        }
        ret = memcmp(cipherText, input->data, cipherTextLen);
        ret =  ret || (cipherTextLen == input->len - 1) ? 0 : 1;
        return ret;
    }

    static int32_t Sm4Encrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
        uint8_t *cipherText, int *cipherTextLen)
    {
        HcfBlob output = {};
        int32_t maxLen = *cipherTextLen;
        int32_t ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(key), nullptr);
        if (ret != 0) {
            return ret;
        }

        ret = cipher->update(cipher, input, &output);
        if (ret != 0) {
            return ret;
        }
        *cipherTextLen = output.len;
        if (output.data != nullptr) {
            if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return -1;
            }
            HcfBlobDataFree(&output);
        }

        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            return ret;
        }
        if (output.data != nullptr) {
            if (memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return -1;
            }
            *cipherTextLen += output.len;
            HcfBlobDataFree(&output);
        }
        return 0;
    }

    static int32_t Sm4Decrypt(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
        uint8_t *cipherText, int cipherTextLen)
    {
        HcfBlob output = {};
        if (cipherTextLen <= 0) {
            return -1;
        }
        int32_t maxLen = cipherTextLen;
        int32_t ret = cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(key), nullptr);
        if (ret != 0) {
            return ret;
        }

        ret = cipher->update(cipher, input, &output);
        if (ret != 0) {
            return ret;
        }
        cipherTextLen = output.len;
        if (output.data != nullptr) {
            if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return -1;
            }
            HcfBlobDataFree(&output);
        }

        ret = cipher->doFinal(cipher, nullptr, &output);
        if (ret != 0) {
            return ret;
        }
        if (output.data != nullptr) {
            if (memcpy_s(cipherText + cipherTextLen, maxLen - cipherTextLen, output.data, output.len) != EOK) {
                HcfBlobDataFree(&output);
                return -1;
            }
            cipherTextLen += output.len;
            HcfBlobDataFree(&output);
        }

        if (cipherTextLen != input->len - 1) {
            return -1;
        }
        return memcmp(cipherText, input->data, cipherTextLen);
    }

    static void TestAesCipher(const uint8_t* plan, size_t size)
    {
        int ret = 0;
        HcfBlob input = {.data = const_cast<uint8_t *>(plan), .len = size};
        uint8_t cipherText[128] = {0};
        int cipherTextLen = 128;
        HcfSymKeyGenerator *generator = nullptr;
        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;
        ret = HcfSymKeyGeneratorCreate("AES128", &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        ret = generator->generateSymKey(generator, &key);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(key);
            return;
        }

        (void)AesEncrypt(cipher, key, &input, cipherText, &cipherTextLen);
        (void)AesDecrypt(cipher, key, &input, cipherText, cipherTextLen);
        HcfObjDestroy(generator);
        HcfObjDestroy(key);
        HcfObjDestroy(cipher);
    }

    static void TestSm4Cipher(const uint8_t* plan, size_t size)
    {
        int ret = 0;
        HcfBlob input = {.data = const_cast<uint8_t *>(plan), .len = size};
        uint8_t cipherText[128] = {0};
        int cipherTextLen = 128;
        HcfSymKeyGenerator *generator = nullptr;
        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;
        ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        ret = generator->generateSymKey(generator, &key);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(key);
            return;
        }

        (void)Sm4Encrypt(cipher, key, &input, cipherText, &cipherTextLen);
        (void)Sm4Decrypt(cipher, key, &input, cipherText, cipherTextLen);
        HcfObjDestroy(generator);
        HcfObjDestroy(key);
        HcfObjDestroy(cipher);
    }

    static void TestSm4GcmCipher(const uint8_t* plan, size_t size)
    {
        int ret = 0;
        HcfBlob input = {.data = const_cast<uint8_t *>(plan), .len = size};
        uint8_t aad[8] = {0};
        uint8_t tag[16] = {0};
        uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
        uint8_t cipherText[128] = {0};
        int cipherTextLen = 128;

        HcfGcmParamsSpec spec = {};
        spec.aad.data = aad;
        spec.aad.len = sizeof(aad);
        spec.tag.data = tag;
        spec.tag.len = sizeof(tag);
        spec.iv.data = iv;
        spec.iv.len = sizeof(iv);
        HcfSymKeyGenerator *generator = nullptr;
        HcfCipher *cipher = nullptr;
        HcfSymKey *key = nullptr;
        ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        ret = generator->generateSymKey(generator, &key);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        ret = HcfCipherCreate("SM4_128|GCM|PKCS5", &cipher);
        if (ret != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(key);
            return;
        }

        (void)Sm4Encrypt(cipher, key, &input, cipherText, &cipherTextLen);
        (void)Sm4Decrypt(cipher, key, &input, cipherText, cipherTextLen);
        HcfObjDestroy(generator);
        HcfObjDestroy(key);
        HcfObjDestroy(cipher);
    }

    static void TestRsaCipher(const uint8_t* plan, size_t size)
    {
        HcfResult res = HCF_SUCCESS;
        HcfAsyKeyGenerator *generator = nullptr;
        res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }

        HcfBlob input = { .data = const_cast<uint8_t *>(plan), .len = size };
        HcfBlob encoutput = {.data = nullptr, .len = 0};
        HcfCipher *cipher = nullptr;
        res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            return;
        }

        (void)cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(keyPair->pubKey), nullptr);
        (void)cipher->doFinal(cipher, &input, &encoutput);
        HcfObjDestroy(cipher);

        HcfBlob decoutput = {.data = nullptr, .len = 0};
        cipher = nullptr;
        res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            HcfObjDestroy(keyPair);
            return;
        }
        (void)cipher->init(cipher, DECRYPT_MODE, reinterpret_cast<HcfKey *>(keyPair->priKey), nullptr);
        (void)cipher->doFinal(cipher, &encoutput, &decoutput);
        HcfBlobDataClearAndFree(&encoutput);
        HcfBlobDataClearAndFree(&decoutput);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(cipher);
    }

    bool HcfCipherCreateFuzzTest(const uint8_t* data, size_t size)
    {
        TestRsaCipher(data, size);
        TestAesCipher(data, size);
        TestSm4Cipher(data, size);
        TestSm4GcmCipher(data, size);
        HcfCipher *cipher = nullptr;
        std::string algoName(reinterpret_cast<const char *>(data), size);
        HcfResult res = HcfCipherCreate(algoName.c_str(), &cipher);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(cipher);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfCipherCreateFuzzTest(data, size);
    return 0;
}
