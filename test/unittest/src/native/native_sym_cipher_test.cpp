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

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include "crypto_common.h"
#include "crypto_sym_cipher.h"
#include "sym_key.h"
#include "log.h"
#include "memory.h"
#include "memory_mock.h"
#include "securec.h"

using namespace std;
using namespace testing::ext;

static constexpr int32_t GCM_TAG_LEN = 16;

namespace {
class NativeSymCipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeSymCipherTest::SetUpTestCase() {}
void NativeSymCipherTest::TearDownTestCase() {}

void NativeSymCipherTest::SetUp() // add init here, this will be called before test.
{
}

void NativeSymCipherTest::TearDown() // add destroy here, this will be called when test case done.
{
}

OH_Crypto_ErrCode AesEncrypt(OH_CryptoSymCipher *cipher, OH_CryptoSymKey *key, OH_CryptoSymCipherParams *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    Crypto_DataBlob input = {.data = reinterpret_cast<uint8_t *>(plainText), .len = 13};
    Crypto_DataBlob output = {};
    int32_t maxLen = *cipherTextLen;
    OH_Crypto_ErrCode ret = OH_CryptoSymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, key, params);
    if (ret != CRYPTO_SUCCESS) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = OH_CryptoSymCipher_Update(cipher, &input, &output);
    if (ret != CRYPTO_SUCCESS) {
        LOGE("update failed!");
        return ret;
    }
    *cipherTextLen = output.len;
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            OH_Crypto_FreeDataBlob(&output);
            return CRYPTO_INVALID_PARAMS;
        }
        OH_Crypto_FreeDataBlob(&output);
    }

    ret = OH_CryptoSymCipher_Final(cipher, nullptr, &output);
    if (ret != CRYPTO_SUCCESS) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len) != EOK) {
            OH_Crypto_FreeDataBlob(&output);
            return CRYPTO_INVALID_PARAMS;
        }
        *cipherTextLen += output.len;
        OH_Crypto_FreeDataBlob(&output);
    }

    return CRYPTO_SUCCESS;
}

OH_Crypto_ErrCode AesDecrypt(OH_CryptoSymCipher *cipher, OH_CryptoSymKey *key, OH_CryptoSymCipherParams *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    Crypto_DataBlob input = {.data = reinterpret_cast<uint8_t *>(cipherText), .len = cipherTextLen};
    Crypto_DataBlob output = {};
    int32_t maxLen = cipherTextLen;
    OH_Crypto_ErrCode ret = OH_CryptoSymCipher_Init(cipher, CRYPTO_DECRYPT_MODE, key, params);
    if (ret != CRYPTO_SUCCESS) {
        LOGE("init failed! %{public}d", ret);
        return ret;
    }

    ret = OH_CryptoSymCipher_Update(cipher, &input, &output);
    if (ret != CRYPTO_SUCCESS) {
        LOGE("update failed!");
        return ret;
    }
    cipherTextLen = output.len;
    if (output.data != nullptr) {
        if (memcpy_s(cipherText, maxLen, output.data, output.len) != EOK) {
            OH_Crypto_FreeDataBlob(&output);
            return CRYPTO_INVALID_PARAMS;
        }
        OH_Crypto_FreeDataBlob(&output);
    }

    ret = OH_CryptoSymCipher_Final(cipher, nullptr, &output);
    if (ret != CRYPTO_SUCCESS) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.data != nullptr) {
        if (memcpy_s(cipherText + cipherTextLen, maxLen - cipherTextLen, output.data, output.len) != EOK) {
            OH_Crypto_FreeDataBlob(&output);
            return CRYPTO_INVALID_PARAMS;
        }
        cipherTextLen += output.len;
        OH_Crypto_FreeDataBlob(&output);
    }

    if (cipherTextLen != sizeof(plainText) - 1) {
        return CRYPTO_INVALID_PARAMS;
    }
    if (memcmp(cipherText, plainText, cipherTextLen) != 0) {
        return CRYPTO_INVALID_PARAMS;
    }
    return CRYPTO_SUCCESS;
}

HWTEST_F(NativeSymCipherTest, NativeSymCipherTest001, TestSize.Level0)
{
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;
    Crypto_DataBlob ivData = { .data = iv, .len = sizeof(iv) };
    Crypto_DataBlob aadData = { .data = aad, .len = sizeof(aad) };
    Crypto_DataBlob tagData = { .data = tag, .len = sizeof(tag) };
    OH_CryptoSymCipherParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoSymCipherParams_Create(&params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoSymCipherParams_SetParam(params, CRYPTO_IV_DATABLOB, &ivData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSymCipherParams_SetParam(params, CRYPTO_AAD_DATABLOB, &aadData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSymCipherParams_SetParam(params, CRYPTO_TAG_DATABLOB, &tagData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoSymKeyGenerator *ctx = nullptr;
    OH_CryptoSymKey *symKey = nullptr;
    ret = OH_CryptoSymKeyGenerator_Create("AES128", &ctx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSymKeyGenerator_Generate(ctx, &symKey);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoSymCipher *cipher = nullptr;
    ret = OH_CryptoSymCipher_Create("AES128|GCM|PKCS7", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    ret = AesEncrypt(cipher, symKey, params, cipherText, &cipherTextLen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    (void)memcpy_s(tagData.data, GCM_TAG_LEN, cipherText + cipherTextLen - GCM_TAG_LEN, GCM_TAG_LEN);
    cipherTextLen -= GCM_TAG_LEN;
    ret = OH_CryptoSymCipherParams_SetParam(params, CRYPTO_TAG_DATABLOB, &tagData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = AesDecrypt(cipher, symKey, params, cipherText, cipherTextLen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoSymCipherParams_Destroy(params);
    OH_CryptoSymCipher_Destroy(cipher);
    OH_CryptoSymKey_Destroy(symKey);
    OH_CryptoSymKeyGenerator_Destroy(ctx);
}
}