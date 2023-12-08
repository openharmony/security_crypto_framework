/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include <cstring>

#include "asy_key_generator.h"
#include "blob.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "detailed_alg_25519_key_params.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEd25519AsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static string g_ed25519AlgoName = "Ed25519";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";
static string g_algorithmName = "Alg25519";

HcfAlg25519KeyPairParamsSpec g_ed25519KeyPairSpec;
HcfAlg25519PriKeyParamsSpec g_ed25519PriKeySpec;
HcfAlg25519PubKeyParamsSpec g_ed25519PubKeySpec;

void CryptoEd25519AsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoEd25519AsyKeyGeneratorBySpecTest::TearDown() {}
void CryptoEd25519AsyKeyGeneratorBySpecTest::SetUpTestCase() {}
void CryptoEd25519AsyKeyGeneratorBySpecTest::TearDownTestCase() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *GetMockClass(void)
{
    return "ed25519generator";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static HcfResult ConstructEd25519KeyPairParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    HcfAlg25519KeyPairParamsSpec *ed25519KeyPairSpec = &g_ed25519KeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    ed25519KeyPairSpec->base.algName = g_ed25519AlgoName.data();
    ed25519KeyPairSpec->base.specType = HCF_KEY_PAIR_SPEC;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519KeyPairSpec->pk.data = retBigInt.data;
    ed25519KeyPairSpec->pk.len = retBigInt.len;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519KeyPairSpec->sk.data = retBigInt.data;
    ed25519KeyPairSpec->sk.len = retBigInt.len;
    *spec = (HcfAsyKeyParamsSpec *)ed25519KeyPairSpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructEd25519PubKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfAlg25519PubKeyParamsSpec *ed25519PubKeySpec = &g_ed25519PubKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    ed25519PubKeySpec->base.algName = g_ed25519AlgoName.data();
    ed25519PubKeySpec->base.specType = HCF_PUBLIC_KEY_SPEC;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519PubKeySpec->pk.data = retBigInt.data;
    ed25519PubKeySpec->pk.len = retBigInt.len;
    *spec = (HcfAsyKeyParamsSpec *)ed25519PubKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructEd25519PriKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfAlg25519PriKeyParamsSpec *ed25519PriKeySpec = &g_ed25519PriKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    ed25519PriKeySpec->base.algName = g_ed25519AlgoName.data();
    ed25519PriKeySpec->base.specType = HCF_PRIVATE_KEY_SPEC;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519PriKeySpec->sk.data = retBigInt.data;
    ed25519PriKeySpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)ed25519PriKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest001_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest001_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519PubKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest001_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519PriKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *className = returnObj->base.getClass();
    ASSERT_NE(className, NULL);
    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    returnObj->base.destroy(&g_obj);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *algoName = returnObj->getAlgName(returnObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(algoName, g_ed25519AlgoName);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_EQ(algorithmName, g_algorithmName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    const char *formatName = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    ASSERT_EQ(formatName, g_pubkeyformatName);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    ASSERT_EQ(algorithmName, g_algorithmName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    const char *formatName = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    ASSERT_EQ(formatName, g_prikeyformatName);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest015, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *pubparamSpec = nullptr;
    HcfResult res = ConstructEd25519PubKeyParamsSpec(g_ed25519AlgoName, &pubparamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubparamSpec, nullptr);

    HcfAsyKeyParamsSpec *priparamSpec = nullptr;
    res = ConstructEd25519PriKeyParamsSpec(g_ed25519AlgoName, &priparamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priparamSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnpriObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(priparamSpec, &returnpriObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnpriObj, nullptr);

    HcfAsyKeyGeneratorBySpec *returnpubObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(pubparamSpec, &returnpubObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnpubObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnpubObj->generatePubKey(returnpubObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnpriObj->generatePriKey(returnpriObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, ED25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    res = priKey->getAsyKeySpecBigInteger(priKey, ED25519_SK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(returnpubObj);
    HcfObjDestroy(returnpriObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest016, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("Ed25519", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("Ed25519", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(flag, true);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest017, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);
    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructEd25519KeyPairParamsSpec("Ed25519", &paramsSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramsSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructEd25519PubKeyParamsSpec("Ed25519", &paramsSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramsSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ED25519,
        .bits = HCF_ALG_ED25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiEd25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructEd25519PriKeyParamsSpec("Ed25519", &paramsSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramsSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519PubKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519PriKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(pubKey);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob1 = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob1.data, nullptr);
    ASSERT_NE(blob1.len, 0);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEd25519PubKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob2 = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob2.data, nullptr);
    ASSERT_NE(blob2.len, 0);

    ASSERT_EQ(*(blob1.data), *(blob2.data));
    ASSERT_EQ(blob1.len, blob2.len);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest024, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob1 = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob1.data, nullptr);
    ASSERT_NE(blob1.len, 0);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEd25519PriKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob2 = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob2.data, nullptr);
    ASSERT_NE(blob2.len, 0);

    ASSERT_EQ(*(blob1.data), *(blob2.data));
    ASSERT_EQ(blob1.len, blob2.len);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest025, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519PriKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generator;
    res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &blob, &keyPair);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoEd25519AsyKeyGeneratorBySpecTest, CryptoEd25519AsyKeyGeneratorBySpecTest026, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructEd25519PubKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generator;
    res = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &blob, nullptr, &keyPair);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
}
}