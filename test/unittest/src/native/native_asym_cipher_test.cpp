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
#include "crypto_common.h"
#include "crypto_asym_cipher.h"
#include "log.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

class NativeAsymCipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeAsymCipherTest::SetUpTestCase() {}

void NativeAsymCipherTest::TearDownTestCase() {}

void NativeAsymCipherTest::SetUp()
{
}

void NativeAsymCipherTest::TearDown()
{
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("RSA3072", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyGen, nullptr);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("RSA3072|PKCS1", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *testData = "Hello, RSA!";
    Crypto_DataBlob in = {
        .data = (uint8_t *)testData,
        .len = strlen(testData)
    };

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoAsymCipher_Final(cipher, &in, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, 0);

    OH_CryptoAsymCipher_Destroy(cipher);
    cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("RSA3072|PKCS1", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_DECRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob decrypted = { 0 };
    ret = OH_CryptoAsymCipher_Final(cipher, &out, &decrypted);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(decrypted.data, nullptr);
    ASSERT_EQ(decrypted.len, strlen(testData));
    EXPECT_EQ(memcmp(decrypted.data, testData, decrypted.len), 0);

    OH_Crypto_FreeDataBlob(&out);
    OH_Crypto_FreeDataBlob(&decrypted);
    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest002, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Create(nullptr, &keyGen);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest003, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(nullptr, &keyPair);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ASSERT_EQ(keyPair, nullptr);

    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest004, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create(nullptr, &cipher);
    ASSERT_NE(ret, CRYPTO_SUCCESS);
    EXPECT_EQ(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Create("SM2|SM3", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Create("SM2|SM3", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest005, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("SM2|SM3", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(nullptr, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Init(cipher, (Crypto_CipherMode)2, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *testData = "Hello, SM2!";
    Crypto_DataBlob in = {
        .data = (uint8_t *)testData,
        .len = strlen(testData)
    };

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoAsymCipher_Final(nullptr, &in, &out);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Final(cipher, &in, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymCipher_Final(cipher, &in, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, 0);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeAsymCipherTest, NativeAsymCipherTest006, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyGen = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("SM2_256", &keyGen);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Generate(keyGen, &keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoAsymCipher *cipher = nullptr;
    ret = OH_CryptoAsymCipher_Create("SM2|SM3", &cipher);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(cipher, nullptr);

    ret = OH_CryptoAsymCipher_Init(cipher, CRYPTO_ENCRYPT_MODE, keyPair);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *testData = "Hello, SM2!";
    Crypto_DataBlob in = {
        .data = (uint8_t *)testData,
        .len = strlen(testData)
    };

    Crypto_DataBlob out = { 0 };
    ret = OH_CryptoAsymCipher_Final(cipher, &in, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_GT(out.len, 0);

    OH_CryptoSm2CiphertextSpec *sm2CipherSpec = nullptr;
    ret = OH_CryptoSm2CiphertextSpec_Create(&out, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_Create(&out, &sm2CipherSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(sm2CipherSpec, nullptr);

    Crypto_DataBlob c1x = { 0 };
    Crypto_DataBlob c1y = { 0 };
    Crypto_DataBlob c2 = { 0 };
    Crypto_DataBlob c3 = { 0 };
    ret = OH_CryptoSm2CiphertextSpec_GetItem(nullptr, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, (CryptoSm2CiphertextSpec_item)4, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_Y, &c1y);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C2, &c2);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_GetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C3, &c3);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoSm2CiphertextSpec_Destroy(sm2CipherSpec);
    sm2CipherSpec = nullptr;
    ret = OH_CryptoSm2CiphertextSpec_Create(nullptr, &sm2CipherSpec);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(sm2CipherSpec, nullptr);

    ret = OH_CryptoSm2CiphertextSpec_SetItem(nullptr, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, (CryptoSm2CiphertextSpec_item)4, &c1x);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_X, &c1x);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C1_Y, &c1y);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C2, &c2);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_SetItem(sm2CipherSpec, CRYPTO_SM2_CIPHERTEXT_C3, &c3);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob encoded = { 0 };
    ret = OH_CryptoSm2CiphertextSpec_Encode(nullptr, &encoded);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoSm2CiphertextSpec_Encode(sm2CipherSpec, nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoSm2CiphertextSpec_Encode(sm2CipherSpec, &encoded);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(encoded.data, nullptr);
    ASSERT_GT(encoded.len, 0);

    OH_Crypto_FreeDataBlob(&out);
    OH_Crypto_FreeDataBlob(&c1x);
    OH_Crypto_FreeDataBlob(&c1y);
    OH_Crypto_FreeDataBlob(&c2);
    OH_Crypto_FreeDataBlob(&c3);
    OH_Crypto_FreeDataBlob(&encoded);
    OH_CryptoSm2CiphertextSpec_Destroy(sm2CipherSpec);
    OH_CryptoAsymCipher_Destroy(cipher);
    OH_CryptoAsymKeyGenerator_Destroy(keyGen);
    OH_CryptoKeyPair_Destroy(keyPair);
}