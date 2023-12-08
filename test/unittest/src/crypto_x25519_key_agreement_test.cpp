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
#include "alg_25519_asy_key_generator_openssl.h"
#include "detailed_alg_25519_key_params.h"
#include "key_agreement.h"
#include "params_parser.h"
#include "x25519_openssl.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoX25519KeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *ed25519KeyPair_;
    static HcfKeyPair *x25519KeyPair_;
};

HcfKeyPair *CryptoX25519KeyAgreementTest::ed25519KeyPair_ = nullptr;
HcfKeyPair *CryptoX25519KeyAgreementTest::x25519KeyPair_ = nullptr;

static string g_ed25519AlgoName = "Ed25519";
static string g_x25519AlgoName = "X25519";

HcfAlg25519KeyPairParamsSpec g_x25519KeyPairSpec;

void CryptoX25519KeyAgreementTest::SetUp() {}
void CryptoX25519KeyAgreementTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

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
        return res;
    }
    HcfAlg25519KeyPairParamsSpec *x25519KeyPairSpec = &g_x25519KeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    x25519KeyPairSpec->base.algName = const_cast<char*>(g_x25519AlgoName.c_str());
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

void CryptoX25519KeyAgreementTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t ret = HcfAsyKeyGeneratorCreate(g_ed25519AlgoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    ed25519KeyPair_ = keyPair;

    ret = HcfAsyKeyGeneratorCreate(g_x25519AlgoName.c_str(), &generator);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    ret = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    x25519KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoX25519KeyAgreementTest::TearDownTestCase()
{
    HcfObjDestroy(ed25519KeyPair_);
    HcfObjDestroy(x25519KeyPair_);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest001, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest002, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *className = keyAgreement->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest003, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest004, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);
    ASSERT_EQ(algName, g_x25519AlgoName);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructX25519KeyPairParamsSpec(g_x25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, keyPair->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest005, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("x25519", &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest006, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    keyAgreement->base.destroy(nullptr);
    keyAgreement->base.destroy(&g_obj);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest007, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = nullptr;
    algName = keyAgreement->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);

    algName = keyAgreement->getAlgoName((HcfKeyAgreement *)(&g_obj));
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest008, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate("X25519", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret(keyAgreement, nullptr, x25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret(keyAgreement, ed25519KeyPair_->priKey, ed25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    res = keyAgreement->generateSecret((HcfKeyAgreement *)&g_obj, ed25519KeyPair_->priKey,
    ed25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest009, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_X25519,
    };

    HcfResult res = HcfKeyAgreementSpiX25519Create(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest010, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_X25519,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = HcfKeyAgreementSpiX25519Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineGenerateSecret((HcfKeyAgreementSpi *)&g_obj, x25519KeyPair_->priKey, x25519KeyPair_->pubKey,
        &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = spiObj->engineGenerateSecret(spiObj, (HcfPriKey *)&g_obj, x25519KeyPair_->pubKey, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = spiObj->engineGenerateSecret(spiObj, x25519KeyPair_->priKey, (HcfPubKey *)&g_obj, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest011, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_X25519,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = HcfKeyAgreementSpiX25519Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest012, TestSize.Level0)
{
    HcfKeyAgreementParams params = {
        .algo = HCF_ALG_X25519,
    };

    HcfKeyAgreementSpi *spiObj = nullptr;
    HcfResult res = HcfKeyAgreementSpiX25519Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest013, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_x25519AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetMallocNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate(g_x25519AlgoName.c_str(), &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        out = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &out);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        free(out.data);
    }
    EndRecordMallocNum();
}

HWTEST_F(CryptoX25519KeyAgreementTest, CryptoX25519KeyAgreementTest014, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfKeyAgreement *keyAgreement = nullptr;
    HcfResult res = HcfKeyAgreementCreate(g_x25519AlgoName.c_str(), &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(keyAgreement);

    uint32_t mallocCount = GetOpensslCallNum();

    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        keyAgreement = nullptr;
        res = HcfKeyAgreementCreate(g_x25519AlgoName.c_str(), &keyAgreement);

        if (res != HCF_SUCCESS) {
            continue;
        }

        out = {
            .data = nullptr,
            .len = 0
        };
        res = keyAgreement->generateSecret(keyAgreement, x25519KeyPair_->priKey, x25519KeyPair_->pubKey, &out);

        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyAgreement);
            continue;
        }

        HcfObjDestroy(keyAgreement);
        free(out.data);
    }
    EndRecordOpensslCallNum();
}
}