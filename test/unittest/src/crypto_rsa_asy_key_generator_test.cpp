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
#include "securec.h"

#include "asy_key_generator.h"
#include "blob.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoCryptoRsaAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoCryptoRsaAsyKeyGeneratorTest::SetUpTestCase() {}
void CryptoCryptoRsaAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoCryptoRsaAsyKeyGeneratorTest::SetUp() {}
void CryptoCryptoRsaAsyKeyGeneratorTest::TearDown() {}

// HcfAsyKeyGeneratorCreate correct case: no primes
HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest100, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest110, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest120, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}


HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest130, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest140, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest150, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate correct case: with primes
HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest200, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest210, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest220, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest230, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest240, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest250, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest260, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest270, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_4", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    EXPECT_NE(generator->base.getClass(), nullptr);
    EXPECT_NE(generator->base.destroy, nullptr);
    EXPECT_NE(generator->generateKeyPair, nullptr);
    EXPECT_NE(generator->getAlgoName, nullptr);
    OH_HCF_ObjDestroy(generator);
}

// HcfAsyKeyGeneratorCreate Incorrect case : algname is null
HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest300, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate(NULL, &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest310, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("111111111111111111111111111111111111111111111111111111111111111111111111"
        "111111111111111111111111111111111111111111111111111111111111111111111", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest320, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", NULL);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest330, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA12315", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest340, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_777", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest350, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512|PRIMES_3", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest360, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_3", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest370, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_4", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest380, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_4", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest390, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_5", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest400, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
    generator = NULL;
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest410, TestSize.Level0)
{
    OH_HCF_ObjDestroy(NULL);
}

// generateKeyPair correct case
HWTEST_F(CryptoCryptoRsaAsyKeyGeneratorTest, CryptoCryptoRsaAsyKeyGeneratorTest500, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);
    EXPECT_NE(keyPair->base.getClass(), nullptr);
    EXPECT_NE(keyPair->base.destroy, nullptr);

    HcfPubKey *pubkey = keyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = keyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest510, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);
    EXPECT_NE(keyPair->base.getClass(), nullptr);
    EXPECT_NE(keyPair->base.destroy, nullptr);

    HcfPubKey *pubkey = keyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = keyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

// generateKeyPair conrrect case: use getEncode encode pubkey and prikey
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest520, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

// generateKeyPair correct case: getEncode encode pubkey
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest530, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, NULL, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfFree(pubKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

// generateKeyPair correct case: getEncode encode prikey
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest540, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, NULL, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest550, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest560, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest570, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA512", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest580, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

// generateKeyPair incorrect case: user wrong ECC class, ignore in this version
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest600, TestSize.Level0)
{
    HcfAsyKeyGenerator *eccGenerator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC224", &eccGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(eccGenerator, nullptr);

    HcfAsyKeyGenerator *rsaGenerator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = rsaGenerator->generateKeyPair(eccGenerator, NULL, &keyPair);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(eccGenerator);
    OH_HCF_ObjDestroy(rsaGenerator);
}

// generateKeyPair incorrect case: generator class is null
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest610, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = rsaGenerator->generateKeyPair(NULL, NULL, &keyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(keyPair, nullptr);

    OH_HCF_ObjDestroy(rsaGenerator);
}

// generateKeyPair incorrect case: keypair is null
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest620, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    res = rsaGenerator->generateKeyPair(rsaGenerator, NULL, NULL);
    EXPECT_NE(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(rsaGenerator);
}

// convertKey correct case
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest700, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfPubKey *pubkey = dupKeyPair->pubKey;
    EXPECT_NE(pubkey->base.getAlgorithm((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.getFormat((HcfKey *)pubkey), nullptr);
    EXPECT_NE(pubkey->base.base.getClass(), nullptr);
    EXPECT_NE(pubkey->base.base.destroy, nullptr);

    HcfPriKey *prikey = dupKeyPair->priKey;
    EXPECT_NE(prikey->base.getAlgorithm((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.getFormat((HcfKey *)prikey), nullptr);
    EXPECT_NE(prikey->base.base.getClass(), nullptr);
    EXPECT_NE(prikey->base.base.destroy, nullptr);
    EXPECT_NE(prikey->clearMem, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(dupKeyPair);
}

// convertKey incorrect case: input ECC class
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest710, TestSize.Level0)
{
    HcfAsyKeyGenerator *eccGenerator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC224", &eccGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(eccGenerator, nullptr);

    HcfAsyKeyGenerator *rsaGenerator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *dupKeyPair = NULL;
    res = rsaGenerator->convertKey(eccGenerator, NULL, NULL, NULL, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    OH_HCF_ObjDestroy(eccGenerator);
    OH_HCF_ObjDestroy(rsaGenerator);
}


// convertKey incorrect case: input null generator
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest720, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = rsaGenerator->generateKeyPair(rsaGenerator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = rsaGenerator->convertKey(NULL, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(rsaGenerator);
}

// convertKey incorrect case: input null dupkeypair
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest730, TestSize.Level0)
{
    HcfAsyKeyGenerator *rsaGenerator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &rsaGenerator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(rsaGenerator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = rsaGenerator->generateKeyPair(rsaGenerator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = rsaGenerator->convertKey(rsaGenerator, NULL, &pubKeyBlob, &priKeyBlob, NULL);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(rsaGenerator);
}

// Incorrect case: use wrong bits or primes
HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest800, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1111", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(CryptoRsaAsyKeyGeneratorTest, CryptoRsaAsyKeyGeneratorTest810, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|Primessf", &generator);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(generator, nullptr);
    OH_HCF_ObjDestroy(generator);
}
}