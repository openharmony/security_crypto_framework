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
#include "crypto_asym_key.h"
#include "log.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

static string g_testPubkeyX509Str512 = "-----BEGIN PUBLIC KEY-----\n"
"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKG0KN3tjZM8dCNfCg9bcmZM3Bhv/mRr\n"
"Mxuvua2Ru8Kr1NL+/wyeEMnIARFr+Alf1Tyfjy0PWwFnf8jHWRsz0vkCAwEAAQ==\n"
"-----END PUBLIC KEY-----\n";

static string g_testPubkeyPkcs1Str512 = "-----BEGIN RSA PUBLIC KEY-----\n"
"MEgCQQChtCjd7Y2TPHQjXwoPW3JmTNwYb/5kazMbr7mtkbvCq9TS/v8MnhDJyAER\n"
"a/gJX9U8n48tD1sBZ3/Ix1kbM9L5AgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n";

namespace {
class NativeAsymKeyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeAsymKeyTest::SetUpTestCase() {}
void NativeAsymKeyTest::TearDownTestCase() {}

void NativeAsymKeyTest::SetUp() // add init here, this will be called before test.
{
}

void NativeAsymKeyTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest001, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *keyCtx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("DSA2048", &generator);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Generate(generator, &keyCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoAsymKeyGenerator_GetAlgoName(generator);
    ASSERT_NE(algoName, nullptr);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);

    Crypto_DataBlob dataBlob = { .data = nullptr, .len = 0 };
    ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_DSA_Q_DATABLOB, &dataBlob);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlob.data, nullptr);
    ASSERT_NE(dataBlob.len, 0);
    HcfFree(dataBlob.data);
    OH_CryptoKeyPair_Destroy(keyCtx);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest002, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_Crypto_ErrCode res = OH_CryptoAsymKeyGenerator_Create("RSA512", &generator);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    EXPECT_NE(generator, nullptr);

    OH_CryptoKeyPair *dupKeyPair = nullptr;
    Crypto_DataBlob pubKeyX509Str = {};
    pubKeyX509Str.data = reinterpret_cast<uint8_t*>(const_cast<char*>(g_testPubkeyX509Str512.c_str()));
    pubKeyX509Str.len = strlen(g_testPubkeyX509Str512.c_str());

    Crypto_DataBlob pubKeyPkcs1Str = {};
    pubKeyPkcs1Str.data = reinterpret_cast<uint8_t*>(const_cast<char*>(g_testPubkeyPkcs1Str512.c_str()));
    pubKeyPkcs1Str.len = strlen(g_testPubkeyPkcs1Str512.c_str());
    res = OH_CryptoAsymKeyGenerator_Convert(generator, CRYPTO_PEM, &pubKeyX509Str, nullptr, &dupKeyPair);
    EXPECT_EQ(res, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubkey = OH_CryptoKeyPair_GetPubKey(dupKeyPair);
    Crypto_DataBlob retBlob = { .data = nullptr, .len = 0 };
    res = OH_CryptoPubKey_Encode(pubkey, CRYPTO_PEM, "PKCS1", &retBlob);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    int32_t cmpRes = strcmp(reinterpret_cast<const char*>(retBlob.data),
        reinterpret_cast<const char*>(pubKeyPkcs1Str.data));
    EXPECT_EQ(cmpRes, CRYPTO_SUCCESS);

    Crypto_DataBlob retBlobX509 = { .data = nullptr, .len = 0 };
    res = OH_CryptoPubKey_Encode(pubkey, CRYPTO_PEM, "X509", &retBlobX509);
    EXPECT_EQ(res, CRYPTO_SUCCESS);
    cmpRes = strcmp(reinterpret_cast<const char*>(retBlobX509.data), reinterpret_cast<const char*>(pubKeyX509Str.data));
    EXPECT_EQ(cmpRes, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&retBlob);
    OH_Crypto_FreeDataBlob(&retBlobX509);
    OH_CryptoKeyPair_Destroy(dupKeyPair);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest003, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *generator = nullptr;
    OH_CryptoKeyPair *keyCtx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoAsymKeyGenerator_Create("RSA768", &generator);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoAsymKeyGenerator_Generate(generator, &keyCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyCtx);
    Crypto_DataBlob dataBlobE = { .data = nullptr, .len = 0 };
    ret = OH_CryptoPubKey_GetParam(pubKey, CRYPTO_RSA_E_DATABLOB, &dataBlobE);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlobE.data, nullptr);
    ASSERT_NE(dataBlobE.len, 0);
    HcfFree(dataBlobE.data);
    OH_CryptoKeyPair_Destroy(keyCtx);
    OH_CryptoAsymKeyGenerator_Destroy(generator);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest004, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_Crypto_ErrCode ret;

    ret = OH_CryptoAsymKeyGenerator_Create("RSA512|PRIMES_2", &ctx);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymKeyGenerator_Generate(ctx, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoAsymKeyGenerator_GetAlgoName(ctx);
    EXPECT_NE(algoName, nullptr);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob retBlob = { .data = nullptr, .len = 0 };
    ret = OH_CryptoPubKey_Encode(pubKey, CRYPTO_PEM, "PKCS1", &retBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *dupKeyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_PEM, &retBlob, nullptr, &dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey1 = OH_CryptoKeyPair_GetPubKey(dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    Crypto_DataBlob dataBlob = { .data = nullptr, .len = 0 };

    ret = OH_CryptoPubKey_GetParam(pubKey1, CRYPTO_RSA_N_DATABLOB, &dataBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlob.data, nullptr);
    ASSERT_NE(dataBlob.len, 0);
    OH_Crypto_FreeDataBlob(&dataBlob);

    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoKeyPair_Destroy(dupKeyPair);
}

HWTEST_F(NativeAsymKeyTest, NativeAsymKeyTest005, TestSize.Level0)
{
    OH_CryptoAsymKeyGenerator *ctx = nullptr;
    OH_CryptoKeyPair *keyPair = nullptr;
    OH_Crypto_ErrCode ret;

    ret = OH_CryptoAsymKeyGenerator_Create("Ed25519", &ctx);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    ret = OH_CryptoAsymKeyGenerator_Generate(ctx, &keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    const char *algoName = OH_CryptoAsymKeyGenerator_GetAlgoName(ctx);
    EXPECT_NE(algoName, nullptr);

    OH_CryptoPubKey *pubKey = OH_CryptoKeyPair_GetPubKey(keyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob retBlob = { .data = nullptr, .len = 0 };
    ret = OH_CryptoPubKey_Encode(pubKey, CRYPTO_DER, nullptr, &retBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoKeyPair *dupKeyPair = nullptr;
    ret = OH_CryptoAsymKeyGenerator_Convert(ctx, CRYPTO_DER, &retBlob, nullptr, &dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);

    OH_CryptoPubKey *pubKey1 = OH_CryptoKeyPair_GetPubKey(dupKeyPair);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    Crypto_DataBlob dataBlob = { .data = nullptr, .len = 0 };

    ret = OH_CryptoPubKey_GetParam(pubKey1, CRYPTO_ED25519_PK_DATABLOB, &dataBlob);
    ASSERT_EQ(ret, CRYPTO_SUCCESS);
    ASSERT_NE(dataBlob.data, nullptr);
    ASSERT_NE(dataBlob.len, 0);
    OH_Crypto_FreeDataBlob(&dataBlob);

    OH_CryptoAsymKeyGenerator_Destroy(ctx);
    OH_CryptoKeyPair_Destroy(keyPair);
    OH_CryptoKeyPair_Destroy(dupKeyPair);
}
}