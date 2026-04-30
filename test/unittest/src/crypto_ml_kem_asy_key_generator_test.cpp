/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "securec.h"

#include "blob.h"
#include "params_parser.h"
#include "key_pair.h"
#include "object_base.h"
#include "asy_key_generator.h"
#include "pub_key.h"
#include "pri_key.h"
#include "memory.h"
#include "big_integer.h"
#include "key.h"

#include "ml_kem_asy_key_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMlKemAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoMlKemAsyKeyGeneratorTest::SetUpTestCase() {}
void CryptoMlKemAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoMlKemAsyKeyGeneratorTest::SetUp() {}
void CryptoMlKemAsyKeyGeneratorTest::TearDown() {}

static string g_mlKem512AlgoName = "ML-KEM-512";
static string g_mlKem768AlgoName = "ML-KEM-768";
static string g_mlKem1024AlgoName = "ML-KEM-1024";
static string g_pubkeyformatName = "X.509";
static string g_prikeyformatName = "PKCS#8";

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-KEM");

    const char *pubFormat = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    EXPECT_STREQ(pubFormat, g_pubkeyformatName.c_str());

    const char *priFormat = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    EXPECT_STREQ(priFormat, g_prikeyformatName.c_str());

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-KEM");

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algoName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    EXPECT_STREQ(algoName, "ML-KEM");

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetEncodedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeyBlob.len, 0);
    EXPECT_NE(pubKeyBlob.data, nullptr);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeyBlob.len, 0);
    EXPECT_NE(priKeyBlob.data, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeyBlob.len, 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetEncodedTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeyBlob.len, 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512ConvertKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);

    HcfBlob convertedPubKeyBlob = { .data = nullptr, .len = 0 };
    res = convertedKeyPair->pubKey->base.getEncoded(&(convertedKeyPair->pubKey->base), &convertedPubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubKeyBlob.len, convertedPubKeyBlob.len);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(convertedPubKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768ConvertKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024ConvertKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAlgoNameTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *algoName = generator->getAlgoName(generator);
    EXPECT_STREQ(algoName, g_mlKem768AlgoName.c_str());

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetKeySizeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int pubKeySize = 0;
    res = keyPair->pubKey->base.getKeySize(&(keyPair->pubKey->base), &pubKeySize);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubKeySize, 0);

    int priKeySize = 0;
    res = keyPair->priKey->base.getKeySize(&(keyPair->priKey->base), &priKeySize);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priKeySize, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyPubOnlyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);
    EXPECT_NE(convertedKeyPair->pubKey, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyPriOnlyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &priKeyBlob, &convertedKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(convertedKeyPair, nullptr);
    EXPECT_NE(convertedKeyPair->priKey, nullptr);

    HcfFree(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(convertedKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemConvertKeyBothNullTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *convertedKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, nullptr, &convertedKeyPair);
    EXPECT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemCreateInvalidAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ML-KEM-256", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemCreateNullAlgoTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(nullptr, &generator);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGenerateKeyPairTwiceTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair1 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair1);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pub1 = { .data = nullptr, .len = 0 };
    keyPair1->pubKey->base.getEncoded(&(keyPair1->pubKey->base), &pub1);

    HcfBlob pub2 = { .data = nullptr, .len = 0 };
    keyPair2->pubKey->base.getEncoded(&(keyPair2->pubKey->base), &pub2);

    EXPECT_EQ(pub1.len, pub2.len);
    bool keyDifferent = (memcmp(pub1.data, pub2.data, pub1.len) != 0);
    EXPECT_TRUE(keyDifferent);

    HcfFree(pub1.data);
    HcfFree(pub2.data);
    HcfObjDestroy(keyPair1);
    HcfObjDestroy(keyPair2);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512EncodeDecodeRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob restoredPubKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->base.getEncoded(&(restoredKeyPair->pubKey->base), &restoredPubKeyBlob);
    EXPECT_EQ(pubKeyBlob.len, restoredPubKeyBlob.len);
    EXPECT_EQ(memcmp(pubKeyBlob.data, restoredPubKeyBlob.data, pubKeyBlob.len), 0);

    HcfBlob restoredPriKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->base.getEncoded(&(restoredKeyPair->priKey->base), &restoredPriKeyBlob);
    EXPECT_EQ(priKeyBlob.len, restoredPriKeyBlob.len);
    EXPECT_EQ(memcmp(priKeyBlob.data, restoredPriKeyBlob.data, priKeyBlob.len), 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(restoredPubKeyBlob.data);
    HcfFree(restoredPriKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768EncodeDecodeRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob restoredPubKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->base.getEncoded(&(restoredKeyPair->pubKey->base), &restoredPubKeyBlob);
    EXPECT_EQ(pubKeyBlob.len, restoredPubKeyBlob.len);
    EXPECT_EQ(memcmp(pubKeyBlob.data, restoredPubKeyBlob.data, pubKeyBlob.len), 0);

    HcfBlob restoredPriKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->base.getEncoded(&(restoredKeyPair->priKey->base), &restoredPriKeyBlob);
    EXPECT_EQ(priKeyBlob.len, restoredPriKeyBlob.len);
    EXPECT_EQ(memcmp(priKeyBlob.data, restoredPriKeyBlob.data, priKeyBlob.len), 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(restoredPubKeyBlob.data);
    HcfFree(restoredPriKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024EncodeDecodeRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob restoredPubKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->base.getEncoded(&(restoredKeyPair->pubKey->base), &restoredPubKeyBlob);
    EXPECT_EQ(pubKeyBlob.len, restoredPubKeyBlob.len);
    EXPECT_EQ(memcmp(pubKeyBlob.data, restoredPubKeyBlob.data, pubKeyBlob.len), 0);

    HcfBlob restoredPriKeyBlob = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->base.getEncoded(&(restoredKeyPair->priKey->base), &restoredPriKeyBlob);
    EXPECT_EQ(priKeyBlob.len, restoredPriKeyBlob.len);
    EXPECT_EQ(memcmp(priKeyBlob.data, restoredPriKeyBlob.data, priKeyBlob.len), 0);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfFree(restoredPubKeyBlob.data);
    HcfFree(restoredPriKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

// ==================== getEncodedDer tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedDerPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubDerBlob.len, 0);
    EXPECT_NE(pubDerBlob.data, nullptr);

    HcfFree(pubDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedDerPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priDerBlob.len, 0);
    EXPECT_NE(priDerBlob.data, nullptr);

    HcfFree(priDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubDerBlob.len, 0);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priDerBlob.len, 0);

    HcfFree(pubDerBlob.data);
    HcfFree(priDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetEncodedDerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(pubDerBlob.len, 0);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(priDerBlob.len, 0);

    HcfFree(pubDerBlob.data);
    HcfFree(priDerBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedDerInvalidFormatTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "PKCS8", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "X509", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "PKCS1", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedDerNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(nullptr, "X509", &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, nullptr, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getEncodedPem tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedPemPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", &pemStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pemStr, nullptr);
    EXPECT_GT(strlen(pemStr), 0);
    EXPECT_NE(strstr(pemStr, "BEGIN PUBLIC KEY"), nullptr);

    HcfFree(pemStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetEncodedPemPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &pemStr);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pemStr, nullptr);
    EXPECT_GT(strlen(pemStr), 0);
    EXPECT_NE(strstr(pemStr, "BEGIN PRIVATE KEY"), nullptr);

    HcfFree(pemStr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetEncodedPemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pubPem = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", &pubPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubPem, nullptr);
    HcfFree(pubPem);

    char *priPem = nullptr;
    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &priPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priPem, nullptr);
    HcfFree(priPem);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetEncodedPemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pubPem = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", &pubPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubPem, nullptr);
    HcfFree(pubPem);

    char *priPem = nullptr;
    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", &priPem);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priPem, nullptr);
    HcfFree(priPem);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedPemInvalidFormatTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "PKCS8", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "X509", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS1", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetEncodedPemNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *pemStr = nullptr;
    res = keyPair->pubKey->base.getEncodedPem(nullptr, "X509", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), nullptr, &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->base.getEncodedPem(&(keyPair->pubKey->base), "X509", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(nullptr, nullptr, "PKCS8", &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, nullptr, &pemStr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getEncodedPem(keyPair->priKey, nullptr, "PKCS8", nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getKeyData tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetKeyDataPubKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob rawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, &rawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(rawBlob.len, 0);
    EXPECT_NE(rawBlob.data, nullptr);
    EXPECT_EQ(rawBlob.len, 1184);

    HcfFree(rawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetKeyDataPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob rawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIKEY_RAW_DATA_TYPE, &rawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_GT(rawBlob.len, 0);
    EXPECT_NE(rawBlob.data, nullptr);
    EXPECT_EQ(rawBlob.len, 2400);

    HcfFree(rawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, &pubRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubRawBlob.len, 800);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIKEY_RAW_DATA_TYPE, &priRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priRawBlob.len, 1632);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, &pubRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubRawBlob.len, 1568);

    HcfBlob priRawBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIKEY_RAW_DATA_TYPE, &priRawBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priRawBlob.len, 3168);

    HcfFree(pubRawBlob.data);
    HcfFree(priRawBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetKeyDataInvalidTypeTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, 99, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, 99, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetKeyDataNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(nullptr, ML_KEM_PUBKEY_RAW_DATA_TYPE, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(nullptr, ML_KEM_PRIKEY_RAW_DATA_TYPE, &blob);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getKeyData(keyPair->priKey, ML_KEM_PRIKEY_RAW_DATA_TYPE, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getPubKey from priKey tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetPubKeyFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob originalPubBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &originalPubBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(extractedPubKey, nullptr);

    HcfBlob extractedPubBlob = { .data = nullptr, .len = 0 };
    res = extractedPubKey->base.getEncoded(&(extractedPubKey->base), &extractedPubBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(originalPubBlob.len, extractedPubBlob.len);
    EXPECT_EQ(memcmp(originalPubBlob.data, extractedPubBlob.data, originalPubBlob.len), 0);

    HcfFree(originalPubBlob.data);
    HcfFree(extractedPubBlob.data);
    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetPubKeyFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(extractedPubKey, nullptr);

    const char *algo = extractedPubKey->base.getAlgorithm(&(extractedPubKey->base));
    EXPECT_STREQ(algo, "ML-KEM");

    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetPubKeyFromPriKeyTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(extractedPubKey, nullptr);

    HcfBlob extractedPubBlob = { .data = nullptr, .len = 0 };
    res = extractedPubKey->getKeyData(extractedPubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, &extractedPubBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(extractedPubBlob.len, 1568);

    HcfFree(extractedPubBlob.data);
    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetPubKeyFromPriKeyNullParamTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(nullptr, &pubKey);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAsyKeySpecBigInteger tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_768_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(pubBigInt.data, nullptr);
    EXPECT_EQ(pubBigInt.len, 1184);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_768_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(priBigInt.data, nullptr);
    EXPECT_EQ(priBigInt.len, 2400);

    HcfFree(pubBigInt.data);
    HcfFree(priBigInt.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem512GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem512AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_512_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubBigInt.len, 800);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_512_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priBigInt.len, 1632);

    HcfFree(pubBigInt.data);
    HcfFree(priBigInt.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem1024GetAsyKeySpecBigIntegerTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem1024AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_1024_PK_BN, &pubBigInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(pubBigInt.len, 1568);

    HcfBigInteger priBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_1024_SK_BN, &priBigInt);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(priBigInt.len, 3168);

    HcfFree(pubBigInt.data);
    HcfFree(priBigInt.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAsyKeySpecBigIntegerInvalidItemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger bigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_512_PK_BN, &bigInt);
    EXPECT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ML_KEM_512_SK_BN, &bigInt);
    EXPECT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAsyKeySpecInt/String not support tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAsyKeySpecIntNotSupportTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    int returnInt = 0;
    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, ML_KEM_768_PK_BN, &returnInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ML_KEM_768_SK_BN, &returnInt);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemGetAsyKeySpecStringNotSupportTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    char *returnStr = nullptr;
    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, ML_KEM_768_PK_BN, &returnStr);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, ML_KEM_768_SK_BN, &returnStr);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== clearMem test ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKemClearMemTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== DER round-trip tests ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768DerRoundTripTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getEncodedDer(keyPair->pubKey, "X509", &pubDerBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priDerBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getEncodedDer(keyPair->priKey, "PKCS8", &priDerBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *restoredKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubDerBlob, &priDerBlob, &restoredKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(restoredKeyPair, nullptr);

    HcfBlob restoredPubDer = { .data = nullptr, .len = 0 };
    restoredKeyPair->pubKey->getEncodedDer(restoredKeyPair->pubKey, "X509", &restoredPubDer);
    EXPECT_EQ(pubDerBlob.len, restoredPubDer.len);
    EXPECT_EQ(memcmp(pubDerBlob.data, restoredPubDer.data, pubDerBlob.len), 0);

    HcfBlob restoredPriDer = { .data = nullptr, .len = 0 };
    restoredKeyPair->priKey->getEncodedDer(restoredKeyPair->priKey, "PKCS8", &restoredPriDer);
    EXPECT_EQ(priDerBlob.len, restoredPriDer.len);
    EXPECT_EQ(memcmp(priDerBlob.data, restoredPriDer.data, priDerBlob.len), 0);

    HcfFree(pubDerBlob.data);
    HcfFree(priDerBlob.data);
    HcfFree(restoredPubDer.data);
    HcfFree(restoredPriDer.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(restoredKeyPair);
    HcfObjDestroy(generator);
}

// ==================== Cross-validation: getPubKey raw matches getKeyData raw ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768GetPubKeyCrossValidateTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob originalRawPub = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, &originalRawPub);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *extractedPubKey = nullptr;
    res = keyPair->priKey->getPubKey(keyPair->priKey, &extractedPubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob extractedRawPub = { .data = nullptr, .len = 0 };
    res = extractedPubKey->getKeyData(extractedPubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, &extractedRawPub);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_EQ(originalRawPub.len, extractedRawPub.len);
    EXPECT_EQ(memcmp(originalRawPub.data, extractedRawPub.data, originalRawPub.len), 0);

    HcfFree(originalRawPub.data);
    HcfFree(extractedRawPub.data);
    HcfObjDestroy(extractedPubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// ==================== getAsyKeySpecBigInteger matches getKeyData ====================

HWTEST_F(CryptoMlKemAsyKeyGeneratorTest, CryptoMlKem768BigIntegerMatchesKeyDataTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(g_mlKem768AlgoName.c_str(), &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBigInteger pubBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ML_KEM_768_PK_BN, &pubBigInt);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob pubRawData = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getKeyData(keyPair->pubKey, ML_KEM_PUBKEY_RAW_DATA_TYPE, &pubRawData);
    ASSERT_EQ(res, HCF_SUCCESS);

    EXPECT_EQ(pubBigInt.len, pubRawData.len);
    EXPECT_EQ(memcmp(pubBigInt.data, pubRawData.data, pubBigInt.len), 0);

    HcfFree(pubBigInt.data);
    HcfFree(pubRawData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
