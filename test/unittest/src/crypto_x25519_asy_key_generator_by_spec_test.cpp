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
#include "securec.h"

#include "asy_key_generator.h"
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "signature.h"
#include "memory.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "key_utils.h"
#include "key_pair.h"
#include "object_base.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "detailed_alg_25519_key_params.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX25519AsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static string g_x25519AlgoName = "X25519";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";
static string g_algorithmName = "Alg25519";

HcfAlg25519KeyPairParamsSpec g_x25519KeyPairSpec;
HcfAlg25519PriKeyParamsSpec g_x25519PriKeySpec;
HcfAlg25519PubKeyParamsSpec g_x25519PubKeySpec;

void CryptoX25519AsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoX25519AsyKeyGeneratorBySpecTest::TearDown() {}
void CryptoX25519AsyKeyGeneratorBySpecTest::SetUpTestCase() {}
void CryptoX25519AsyKeyGeneratorBySpecTest::TearDownTestCase() {}

static HcfResult ConstructX25519KeyPairParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
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

    HcfAlg25519KeyPairParamsSpec *x25519KeyPairSpec = &g_x25519KeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    x25519KeyPairSpec->base.algName = g_x25519AlgoName.data();
    x25519KeyPairSpec->base.specType = HCF_KEY_PAIR_SPEC;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, X25519_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    x25519KeyPairSpec->pk.data = retBigInt.data;
    x25519KeyPairSpec->pk.len = retBigInt.len;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, X25519_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    x25519KeyPairSpec->sk.data = retBigInt.data;
    x25519KeyPairSpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)x25519KeyPairSpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructX25519PubKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return HCF_INVALID_PARAMS;
    }

    HcfAlg25519PubKeyParamsSpec *x25519PubKeySpec = &g_x25519PubKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    x25519PubKeySpec->base.algName = g_x25519AlgoName.data();
    x25519PubKeySpec->base.specType = HCF_PUBLIC_KEY_SPEC;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, X25519_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    x25519PubKeySpec->pk.data = retBigInt.data;
    x25519PubKeySpec->pk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)x25519PubKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructX25519PriKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
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

    HcfAlg25519PriKeyParamsSpec *x25519PriKeySpec = &g_x25519PriKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    x25519PriKeySpec->base.algName = g_x25519AlgoName.data();
    x25519PriKeySpec->base.specType = HCF_PRIVATE_KEY_SPEC;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, X25519_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    x25519PriKeySpec->sk.data = retBigInt.data;
    x25519PriKeySpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)x25519PriKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);

    return HCF_SUCCESS;
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest001_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest001_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519PubKeyParamsSpec(g_x25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest001_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519PriKeyParamsSpec(g_x25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    returnObj->base.destroy((HcfObjectBase *)returnObj);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *algoName = returnObj->getAlgName(returnObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(algoName, g_x25519AlgoName);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

    ASSERT_NE(returnObj, nullptr);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest015, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *pubparamSpec = nullptr;
    HcfResult res = ConstructX25519PubKeyParamsSpec(g_x25519AlgoName, &pubparamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubparamSpec, nullptr);

    HcfAsyKeyParamsSpec *priparamSpec = nullptr;
    res = ConstructX25519PriKeyParamsSpec(g_x25519AlgoName, &priparamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priparamSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnpubObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(pubparamSpec, &returnpubObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnpubObj, nullptr);

    HcfAsyKeyGeneratorBySpec *returnpriObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(priparamSpec, &returnpriObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnpriObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnpubObj->generatePubKey(returnpubObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnpriObj->generatePriKey(returnpriObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, X25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    res = priKey->getAsyKeySpecBigInteger(priKey, X25519_SK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(priKey);
    HcfObjDestroy(returnpubObj);
    HcfObjDestroy(returnpriObj);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest016, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);
    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest017, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramsSpec = nullptr;
    res = ConstructX25519KeyPairParamsSpec("X25519", &paramsSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramsSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructX25519PubKeyParamsSpec("X25519", &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_X25519,
        .bits = HCF_ALG_X25519_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiX25519Create(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructX25519PriKeyParamsSpec("X25519", &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator;
    HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);
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
    res = ConstructX25519PubKeyParamsSpec("X25519", &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator;
    HcfResult res = HcfAsyKeyGeneratorCreate("X25519", &generator);
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
    res = ConstructX25519PriKeyParamsSpec("X25519", &paramSpec);
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

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519PriKeyParamsSpec("X25519", &paramSpec);
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
    res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &blob, &keyPair);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoX25519AsyKeyGeneratorBySpecTest, CryptoX25519AsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructX25519PubKeyParamsSpec("X25519", &paramSpec);
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
    res = HcfAsyKeyGeneratorCreate("X25519", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &blob, nullptr, &keyPair);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
}
}