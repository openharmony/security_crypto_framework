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

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "securec.h"
#include "aes_openssl.h"
#include "blob.h"
#include "cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"
#include "log.h"
#include "memory.h"
#include "sym_common_defines.h"
#include "sym_key_generator.h"
#include "sm4_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int32_t PLAINTEXT_LEN = 13;
constexpr int32_t CIPHER_TEXT_LEN = 128;
constexpr int32_t AES_IV_LEN = 16;   // iv for CBC|CTR|OFB|CFB mode
class CryptoSM4CipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoSM4CipherTest::SetUpTestCase() {}
void CryptoSM4CipherTest::TearDownTestCase() {}

void CryptoSM4CipherTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoSM4CipherTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static HcfResult GenerateSm4SymKey(HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    HcfResult ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != HCF_SUCCESS) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != HCF_SUCCESS) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy(generator);
    return ret;
}

static int32_t GenerateSymKey(const char *algoName, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = nullptr;

    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    HcfObjDestroy((HcfObjectBase *)generator);
    return ret;
}


// use ECB, test abnormal input
static int32_t Sm4EncryptWithInput(HcfCipher *cipher, HcfSymKey *key, HcfBlob *input,
    uint8_t *cipherText, int *cipherTextLen)
{
    HcfBlob output = { .data = nullptr, .len = 0 };
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        return ret;
    }

    ret = cipher->update(cipher, input, &output);
    if (ret != 0) {
        LOGE("update failed!");
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
        LOGE("doFinal failed!");
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

// test encrypt and decrypt with null plain text
static int32_t Sm4DecryptEmptyMsg(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    HcfBlob input = { .data = cipherText, .len = cipherTextLen };
    HcfBlob output = { .data = nullptr, .len = 0 };
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, &(key->key), params);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        return ret;
    }

    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.len == 0 && output.data == nullptr) {
        ret = 0;
    } else {
        ret = -1;
    }
    HcfBlobDataFree(&output);
    return ret;
}


static int32_t Sm4Encrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! ");
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
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
        LOGE("doFinal failed!");
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

static int32_t Sm4Decrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)cipherText, .len = cipherTextLen};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! ");
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
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
        LOGE("doFinal failed!");
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

    if (cipherTextLen != sizeof(plainText) - 1) {
        return -1;
    }
    return memcmp(cipherText, plainText, cipherTextLen);
}

static int32_t Sm4NoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! ");
        return ret;
    }

    *cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        *cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }
    return 0;
}

static int32_t Sm4NoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)cipherText, .len = cipherTextLen};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! ");
        return ret;
    }

    cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            HcfBlobDataFree(&output);
            return -1;
        }
        cipherTextLen += output.len;
        HcfBlobDataFree(&output);
    }

    if (cipherTextLen != sizeof(plainText) - 1) {
        return -1;
    }
    return memcmp(cipherText, plainText, cipherTextLen);
}

static const char *GetMockClass(void)
{
    return "HcfMock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest001, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest002, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest003, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest004, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest005, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }
    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest006, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest007, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest008, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest009, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest010, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest011, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest012, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest013, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest014, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest015, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest016, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CTR|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest017, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CTR|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest018, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CTR|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed! ");
        goto clearup;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest019, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest020, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest021, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest022, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest023, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest024, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest025, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest026, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest027, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }


clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest028, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest029, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest030, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest031, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest032, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;


    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest033, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = Sm4NoUpdateEncrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateEncrypt failed! ");
        goto clearup;
    }

    ret = Sm4NoUpdateDecrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4NoUpdateDecrypt failed! ");
        goto clearup;
    }

clearup:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    HcfObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest034, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSm4SymKey(&key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    
    ret = cipher->init(nullptr, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! ");
    }

clearup:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest035, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSm4SymKey(&key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    
    ret = cipher->init(cipher, ENCRYPT_MODE, reinterpret_cast<HcfKey *>(cipher), nullptr);
    if (ret != 0) {
        LOGE("init failed! ");
    }

clearup:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest036, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    ret = GenerateSm4SymKey(&key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    
    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! ");
        goto clearup;
    }
    ret = cipher->update(nullptr, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
    }
clearup:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest037, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    ret = GenerateSm4SymKey(&key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    
    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! ");
        goto clearup;
    }
    ret = cipher->update(reinterpret_cast<HcfCipher *>(key), &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
    }
clearup:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest038, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    ret = GenerateSm4SymKey(&key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    
    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! ");
        goto clearup;
    }
    ret = cipher->doFinal(nullptr, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
    }
clearup:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest039, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };
    HcfBlob output = { .data = nullptr, .len = 0 };

    ret = GenerateSm4SymKey(&key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    
    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! ");
        goto clearup;
    }
    ret = cipher->doFinal(reinterpret_cast<HcfCipher *>(key), &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
    }
clearup:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    if (output.data != nullptr) {
        HcfFree(output.data);
        output.data = nullptr;
    }
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest040, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;
    ret = HcfCipherCreate(cipherName, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    retAlgo = cipher->getAlgorithm(nullptr);
    if (retAlgo == nullptr) {
        LOGE("cipher getAlgorithm failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest041, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKeyGenerator *generator = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate(cipherName, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    retAlgo = cipher->getAlgorithm(reinterpret_cast<HcfCipher *>(generator));
    if (retAlgo == nullptr) {
        LOGE("cipher getAlgorithm failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
    }

CLEAR_UP:
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest042, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM3|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should not select SM3 for CFB generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest043, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    // not allow '|' without content, because findAbility will fail for "" input
    ret = HcfCipherCreate("SM4_128|CFB|", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should select padding mode for SM4_128 generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest044, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest045, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate(nullptr, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest046, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    if (ret != 0) {
        LOGE("init failed! Should input key when init.");
    }

CLEAR_UP:
    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest047, TestSize.Level0)
{
    int ret = 0;

    ret = HcfCipherCreate(nullptr, nullptr);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should not select SM3 for CFB generator.");
    }

    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoAesCipherTest048, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }
    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4EncryptWithInput(cipher, key, &input, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4EncryptWithInput failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4DecryptEmptyMsg(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4EncryptWithInput failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoAesCipherTest049, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfBlob input = { .data = nullptr, .len = 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }
    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4EncryptWithInput(cipher, key, &input, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4EncryptWithInput failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4DecryptEmptyMsg(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4DecryptEmptyMsg failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoAesCipherTest050, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Encrypt failed!");
        goto CLEAR_UP;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);

    cipherTextLen -= 12;

    ret = Sm4Decrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("Sm4Decrypt failed!");
        goto CLEAR_UP;
    }

CLEAR_UP:
    HcfObjDestroy((HcfObjectBase *)key);
    HcfObjDestroy((HcfObjectBase *)cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoAesCipherTest051, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    const char *cipherName = "SM4_128|CFB|NoPadding";
    const char *retAlgo = nullptr;
    ret = HcfCipherCreate(cipherName, &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    retAlgo = cipher->getAlgorithm(cipher);
    if (retAlgo == nullptr) {
        LOGE("cipher getAlgorithm failed!");
        ret = HCF_ERR_CRYPTO_OPERATION;
        goto CLEAR_UP;
    }

    ret = strcmp(retAlgo, cipherName);
    if (ret != 0) {
        LOGE("cipher getAlgorithm failed!");
    }
CLEAR_UP:
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest052, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM4_128|CCC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed! Should not select CCC for SM4 generator.");
    }

    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest053, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = cipher->init(reinterpret_cast<HcfCipher *>(generator), ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed! Should input key when init.");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    HcfObjDestroy(generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest054, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    uint8_t plainText[] = "this is test!";
    HcfBlob input = { .data = plainText, .len = PLAINTEXT_LEN };

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = cipher->init(cipher, ENCRYPT_MODE, &(key->key), nullptr);
    if (ret != 0) {
        LOGE("init failed!");
        goto CLEAR_UP;
    }
    
    ret = cipher->doFinal(cipher, &input, nullptr);
    if (ret != 0) {
        LOGE("update failed! Blob data should not be nullptr.");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest055, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[AES_IV_LEN] = { 0 };
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = AES_IV_LEN;

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, &(ivSpec.base), cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, &(ivSpec.base), cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest057, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // allow input without encryption mode. It will use default aes128ecb.
    ret = HcfCipherCreate("SM4_128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest058, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // allow input with more than one padding mode. It will pick the last PKCS5.
    ret = HcfCipherCreate("SM4_128|ECB|NoPadding|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest059, TestSize.Level0)
{
    int ret = 0;
    HcfSymKeyGenerator *generator = nullptr;
    HcfSymKey *key = nullptr;
    HcfCipher *cipher = nullptr;

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }
    ret = HcfSymKeyGeneratorCreate("SM4_128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto CLEAR_UP;
    }
    ret = generator->generateSymKey(reinterpret_cast<HcfSymKeyGenerator *>(cipher), &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest060, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("SM4_128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    // allow input without encryption mode. It will pick the last PKCS5, and use default aes128ecb.
    ret = HcfCipherCreate("SM4_128|NoPadding|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }
CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest061, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}


HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest062, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;

    res = HcfCipherSm4GeneratorSpiCreate(nullptr, &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest063, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm4GeneratorSpiCreate(&params, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest064, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    retkey = GenerateSymKey("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init((HcfCipherGeneratorSpi *)(&obj), ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest065, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    retkey = GenerateSymKey("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(nullptr, ENCRYPT_MODE, (HcfKey *)key, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest066, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest067, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    retkey = GenerateSymKey("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    cipher->base.destroy(nullptr);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest069, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    retkey = GenerateSymKey("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob blob;
    res = cipher->update(nullptr, &input, &blob);
    EXPECT_NE(res, 0);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest070, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };

    retkey = GenerateSymKey("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob blob;
    res = cipher->update(cipher, nullptr, &blob);
    EXPECT_NE(res, 0);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest071, TestSize.Level0)
{
    int retkey = 0;
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    HcfSymKey *key = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM4,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };

    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    retkey = GenerateSymKey("SM4_128", &key);
    EXPECT_EQ(retkey, 0);
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, &input, nullptr);
    EXPECT_NE(res, 0);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest073, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(nullptr, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest074, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    uint8_t plan[] = "12312123123";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};

    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest075, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfBlob input = {
        .data = nullptr,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest077, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    uint8_t plan[] = "12312123123";
    HcfBlob input = {
        .data = (uint8_t *)plan,
        .len = -1
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest078, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipherGeneratorSpi *cipher = nullptr;
    CipherAttr params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfBlob input = {
        .data = nullptr,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = HcfCipherSm4GeneratorSpiCreate(&params, &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(cipher);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest079, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}


HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest080, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CTR|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest081, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest082, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoSM4CipherTest, CryptoSm4CipherTest083, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[CIPHER_TEXT_LEN] = { 0 };
    int cipherTextLen = CIPHER_TEXT_LEN;
    HcfCipher *cipher = nullptr;
    HcfSymKey *key = nullptr;

    ret = GenerateSymKey("AES256", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto CLEAR_UP;
    }

    ret = HcfCipherCreate("SM4_128|CFB128|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto CLEAR_UP;
    }

    // It is not allowed that AES128 in key is smaller AES256 in cipher. -> now only use the size of input key.
    ret = Sm4Encrypt(cipher, key, nullptr, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto CLEAR_UP;
    }

    ret = Sm4Decrypt(cipher, key, nullptr, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
    }

CLEAR_UP:
    HcfObjDestroy(key);
    HcfObjDestroy(cipher);
    EXPECT_NE(ret, 0);
}
}
