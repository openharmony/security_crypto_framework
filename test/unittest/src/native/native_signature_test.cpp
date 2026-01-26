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
#include "crypto_signature.h"
#include "crypto_common.h"
#include "crypto_asym_key.h"
#include "log.h"
#include "blob.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class NativeSignatureTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeSignatureTest::SetUpTestCase() {}
void NativeSignatureTest::TearDownTestCase() {}

void NativeSignatureTest::SetUp() // add init here, this will be called before test.
{
}

void NativeSignatureTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubkey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoVerify *verify = nullptr;
    res = OH_CryptoVerify_Create("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoVerify_GetAlgoName(verify);
    ASSERT_NE(algoName, nullptr);

    int32_t buf[] = {32};
    Crypto_DataBlob value = {.data = reinterpret_cast<uint8_t *>(buf), .len = sizeof(buf)};
    res = OH_CryptoVerify_SetParam(verify, CRYPTO_PSS_SALT_LEN_INT, &value);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    res = OH_CryptoVerify_Init(verify, pubkey);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    res = OH_CryptoVerify_Update(verify, nullptr);
    EXPECT_NE(res, 1);

    OH_CryptoVerify_Destroy(verify);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest002, TestSize.Level0)
{
    OH_Crypto_ErrCode res = CRYPTO_SUCCESS;
    OH_CryptoVerify *verify = nullptr;
    res = OH_CryptoVerify_Create("RSA512|NoPadding|NoHash|Recover", &verify);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(verify, nullptr);
    EXPECT_NE(OH_CryptoVerify_Destroy, nullptr);
    EXPECT_NE(OH_CryptoVerify_Init, nullptr);
    EXPECT_NE(OH_CryptoVerify_Update, nullptr);
    EXPECT_NE(OH_CryptoVerify_Final, nullptr);
    EXPECT_NE(OH_CryptoVerify_Recover, nullptr);
    OH_CryptoVerify_Destroy(verify);
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest003, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyCtx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoVerify *verify = nullptr;

    uint8_t plainText[] = {
        0xe4, 0x2b, 0xcc, 0x08, 0x11, 0x79, 0x16, 0x1b, 0x35, 0x7f, 0xb3, 0xaf, 0x40, 0x3b, 0x3f, 0x7c};
    Crypto_DataBlob msgBlob = {
        .data = reinterpret_cast<uint8_t *>(plainText),
        .len = sizeof(plainText)};

    uint8_t pubKeyText[] = {
        0x30, 0x39, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x22, 0x00, 0x03, 0x4d, 0xe4, 0xbb, 0x11, 0x10,
        0x1a, 0xd2, 0x05, 0x74, 0xf1, 0x0b, 0xb4, 0x75, 0x57, 0xf4, 0x3e, 0x55, 0x14, 0x17, 0x05, 0x4a,
        0xb2, 0xfb, 0x8c, 0x84, 0x64, 0x38, 0x02, 0xa0, 0x2a, 0xa6, 0xf0};

    Crypto_DataBlob keyBlob = {
        .data = reinterpret_cast<uint8_t *>(pubKeyText),
        .len = sizeof(pubKeyText)};

    uint8_t signText[] = {
        0x30, 0x44, 0x02, 0x20, 0x21, 0x89, 0x99, 0xb1, 0x56, 0x4e, 0x3a, 0x2c, 0x16, 0x08, 0xb5, 0x8a,
        0x06, 0x6f, 0x67, 0x47, 0x1b, 0x04, 0x18, 0x7d, 0x53, 0x2d, 0xba, 0x00, 0x38, 0xd9, 0xe3, 0xe7,
        0x8c, 0xcf, 0x76, 0x83, 0x02, 0x20, 0x13, 0x54, 0x84, 0x9d, 0x73, 0x40, 0xc3, 0x92, 0x66, 0xdc,
        0x3e, 0xc9, 0xf1, 0x4c, 0x33, 0x84, 0x2a, 0x76, 0xaf, 0xc6, 0x61, 0x84, 0x5c, 0xae, 0x4b, 0x0d,
        0x3c, 0xb0, 0xc8, 0x04, 0x89, 0x71};

    Crypto_DataBlob signBlob = {
        .data = reinterpret_cast<uint8_t *>(signText),
        .len = sizeof(signText)};

    // keypair
    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Create((const char *)"ECC256", &keyCtx), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Convert(keyCtx, CRYPTO_DER, &keyBlob, nullptr, &keyPair), CRYPTO_SUCCESS);
    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    // verify
    ASSERT_EQ(OH_CryptoVerify_Create((const char *)"ECC|SHA256", &verify), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoVerify_Init(verify, pubKey), CRYPTO_SUCCESS);
    ASSERT_TRUE(OH_CryptoVerify_Final(verify, &msgBlob, &signBlob));

    OH_CryptoVerify_Destroy(verify);
    OH_CryptoAsymKeyGenerator_Destroy(keyCtx);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest_Sign001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA2048|PRIMES_2", &generator);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *keyPair = nullptr;
    res = OH_CryptoAsymKeyGenerator_Generate(generator, &keyPair);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    OH_CryptoSign *sign = nullptr;
    res = OH_CryptoSign_Create("RSA2048|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algoName = OH_CryptoSign_GetAlgoName(sign);
    ASSERT_NE(algoName, nullptr);
    EXPECT_STREQ(algoName, "RSA2048|PKCS1|SHA256");

    res = OH_CryptoSign_Init(sign, privKey);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    uint8_t plainText[] = {
        0xe4, 0x2b, 0xcc, 0x08, 0x11, 0x79, 0x16, 0x1b, 0x35, 0x7f, 0xb3, 0xaf, 0x40, 0x3b, 0x3f, 0x7c};
    Crypto_DataBlob msgBlob = {
        .data = reinterpret_cast<uint8_t *>(plainText),
        .len = sizeof(plainText)};

    res = OH_CryptoSign_Update(sign, &msgBlob);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    Crypto_DataBlob signBlob = {.data = nullptr, .len = 0};
    res = OH_CryptoSign_Final(sign, nullptr, &signBlob);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    ASSERT_NE(signBlob.data, nullptr);
    ASSERT_GT(signBlob.len, 0);

    // Clean up
    free(signBlob.data);
    OH_CryptoSign_Destroy(sign);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest_Sign002, TestSize.Level0)
{
    OH_CryptoSign *sign = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoSign_Create("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algoName = OH_CryptoSign_GetAlgoName(sign);
    ASSERT_NE(algoName, nullptr);
    EXPECT_STREQ(algoName, "RSA2048|PSS|SHA256|MGF1_SHA256");

    uint8_t buf[] = {32};
    Crypto_DataBlob value = {.data = reinterpret_cast<uint8_t *>(buf), .len = sizeof(buf)};
    res = OH_CryptoSign_SetParam(sign, CRYPTO_PSS_SALT_LEN_INT, &value);
    EXPECT_EQ(res, CRYPTO_PARAMETER_CHECK_FAILED);

    Crypto_DataBlob outValue = {.data = nullptr, .len = 0};
    res = OH_CryptoSign_GetParam(sign, CRYPTO_PSS_SALT_LEN_INT, &outValue);
    EXPECT_EQ(res, CRYPTO_PARAMETER_CHECK_FAILED);

    OH_CryptoSign_Destroy(sign);
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest_Sign003, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyCtx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoSign *sign = nullptr;

    uint8_t plainText[] = {
        0xe4, 0x2b, 0xcc, 0x08, 0x11, 0x79, 0x16, 0x1b, 0x35, 0x7f, 0xb3, 0xaf, 0x40, 0x3b, 0x3f, 0x7c};
    Crypto_DataBlob msgBlob = {
        .data = reinterpret_cast<uint8_t *>(plainText),
        .len = sizeof(plainText)};

    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Create((const char *)"ECC256", &keyCtx), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Generate(keyCtx, &keyPair), CRYPTO_SUCCESS);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    ASSERT_EQ(OH_CryptoSign_Create((const char *)"ECC|SHA256", &sign), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoSign_Init(sign, privKey), CRYPTO_SUCCESS);

    ASSERT_EQ(OH_CryptoSign_Update(sign, &msgBlob), CRYPTO_SUCCESS);

    Crypto_DataBlob signBlob = {.data = nullptr, .len = 0};
    ASSERT_EQ(OH_CryptoSign_Final(sign, nullptr, &signBlob), CRYPTO_SUCCESS);
    ASSERT_NE(signBlob.data, nullptr);
    ASSERT_GT(signBlob.len, 0);

    // Clean up
    free(signBlob.data);
    OH_CryptoSign_Destroy(sign);
    OH_CryptoAsymKeyGenerator_Destroy(keyCtx);
    OH_CryptoKeyPair_Destroy(keyPair);
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest_SignVerify001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyCtx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoSign *sign = nullptr;

    uint8_t plainText[] = {
        0xe4, 0x2b, 0xcc, 0x08, 0x11, 0x79, 0x16, 0x1b, 0x35, 0x7f, 0xb3, 0xaf, 0x40, 0x3b, 0x3f, 0x7c};
    Crypto_DataBlob msgBlob = {
        .data = reinterpret_cast<uint8_t *>(plainText),
        .len = sizeof(plainText)};

    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Create((const char *)"RSA2048|PRIMES_2", &keyCtx), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Generate(keyCtx, &keyPair), CRYPTO_SUCCESS);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    ASSERT_EQ(OH_CryptoSign_Create((const char *)"RSA1024|PSS|SHA256|MGF1_SHA512", &sign), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoSign_Init(sign, privKey), CRYPTO_SUCCESS);

    ASSERT_EQ(OH_CryptoSign_Update(sign, &msgBlob), CRYPTO_SUCCESS);

    Crypto_DataBlob signBlob = {.data = nullptr, .len = 0};
    ASSERT_EQ(OH_CryptoSign_Final(sign, nullptr, &signBlob), CRYPTO_SUCCESS);
    ASSERT_NE(signBlob.data, nullptr);
    ASSERT_GT(signBlob.len, 0);

    OH_CryptoPubKey *pubkey = OH_CryptoKeyPair_GetPubKey(keyPair);
    OH_CryptoVerify *verify = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoVerify_Create("RSA1024|PSS|SHA256|MGF1_SHA512", &verify);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoVerify_GetAlgoName(verify);
    ASSERT_NE(algoName, nullptr);

    int32_t buf[] = {32};
    Crypto_DataBlob value = {.data = reinterpret_cast<uint8_t *>(buf), .len = sizeof(buf)};
    res = OH_CryptoVerify_SetParam(verify, CRYPTO_PSS_SALT_LEN_INT, &value);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    res = OH_CryptoVerify_Init(verify, pubkey);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    bool result = OH_CryptoVerify_Final(verify, &msgBlob, &signBlob);
    EXPECT_FALSE(result);

    HcfBlobDataClearAndFree((HcfBlob *)&signBlob);
    OH_CryptoVerify_Destroy(verify);
    OH_CryptoSign_Destroy(sign);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoAsymKeyGenerator_Destroy(keyCtx);
}

HWTEST_F(NativeSignatureTest, NativeSignatureTest_DerToRS001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *keyCtx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_CryptoSign *sign = nullptr;

    uint8_t plainText[] = {
        0xe4, 0x2b, 0xcc, 0x08, 0x11, 0x79, 0x16, 0x1b, 0x35, 0x7f, 0xb3, 0xaf, 0x40, 0x3b, 0x3f, 0x7c};
    Crypto_DataBlob msgBlob = {
        .data = reinterpret_cast<uint8_t *>(plainText),
        .len = sizeof(plainText)};

    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Create((const char *)"SM2_256", &keyCtx), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoAsymKeyGenerator_Generate(keyCtx, &keyPair), CRYPTO_SUCCESS);

    OH_CryptoPrivKey *privKey = OH_CryptoKeyPair_GetPrivKey(keyPair);
    ASSERT_NE(privKey, nullptr);

    ASSERT_EQ(OH_CryptoSign_Create((const char *)"SM2|SM3", &sign), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoSign_Init(sign, privKey), CRYPTO_SUCCESS);

    ASSERT_EQ(OH_CryptoSign_Update(sign, &msgBlob), CRYPTO_SUCCESS);

    Crypto_DataBlob signBlob = {.data = nullptr, .len = 0};
    ASSERT_EQ(OH_CryptoSign_Final(sign, nullptr, &signBlob), CRYPTO_SUCCESS);
    ASSERT_NE(signBlob.data, nullptr);
    ASSERT_GT(signBlob.len, 0);

    OH_CryptoEccSignatureSpec *eccSignSpec = nullptr;
    ASSERT_EQ(OH_CryptoEccSignatureSpec_Create(&signBlob, &eccSignSpec), CRYPTO_SUCCESS);
    ASSERT_NE(eccSignSpec, nullptr);
    Crypto_DataBlob r = {.data = nullptr, .len = 0};
    Crypto_DataBlob s = {.data = nullptr, .len = 0};
    ASSERT_EQ(OH_CryptoEccSignatureSpec_GetRAndS(eccSignSpec, &r, &s), CRYPTO_SUCCESS);
    ASSERT_NE(r.data, nullptr);
    ASSERT_NE(s.data, nullptr);
    OH_CryptoEccSignatureSpec_Destroy(eccSignSpec);
    OH_CryptoEccSignatureSpec *eccSignSpec1 = nullptr;
    Crypto_DataBlob signBlob1 = {.data = nullptr, .len = 0};
    ASSERT_EQ(OH_CryptoEccSignatureSpec_Create(nullptr, &eccSignSpec1), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoEccSignatureSpec_SetRAndS(eccSignSpec1, &r, &s), CRYPTO_SUCCESS);
    ASSERT_EQ(OH_CryptoEccSignatureSpec_Encode(eccSignSpec1, &signBlob1), CRYPTO_SUCCESS);
    ASSERT_NE(signBlob1.data, nullptr);
    ASSERT_GT(signBlob1.len, 0);


    // Clean up
    HcfBlobDataClearAndFree((HcfBlob *)&signBlob);
    HcfBlobDataClearAndFree((HcfBlob *)&signBlob1);
    HcfBlobDataClearAndFree((HcfBlob *)&r);
    HcfBlobDataClearAndFree((HcfBlob *)&s);
    OH_CryptoSign_Destroy(sign);
    OH_CryptoEccSignatureSpec_Destroy(eccSignSpec1);
    OH_CryptoAsymKeyGenerator_Destroy(keyCtx);
    OH_CryptoKeyPair_Destroy(keyPair);
}
}