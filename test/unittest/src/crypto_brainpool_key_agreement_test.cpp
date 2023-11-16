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
#include "detailed_ecc_key_params.h"
#include "ecdh_openssl.h"
#include "key_agreement.h"
#include "ecc_key_util.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoBrainPoolKeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoBrainPoolKeyAgreementTest::SetUp() {}
void CryptoBrainPoolKeyAgreementTest::TearDown() {}

static string g_brainpool160r1AlgName = "ECC_BrainPoolP160r1";
HcfEccCommParamsSpec *g_eccCommSpec = nullptr;
HcfEccKeyPairParamsSpec g_brainpool160r1KeyPairSpec;

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static HcfResult ConstructEccBrainPool160r1KeyPairCommParamsSpec(const string &algoName, HcfEccCommParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;

    HcfEccKeyUtilCreate(algoName.c_str(), &eccCommSpec);

    *spec = eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult Constructbrainpool160r1KeyPairParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_brainpool160r1KeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    
    eccKeyPairSpec->base.base.algName = g_eccCommSpec->base.algName;
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = g_eccCommSpec->field;
    eccKeyPairSpec->base.field->fieldType = g_eccCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data = ((HcfECFieldFp *)(g_eccCommSpec->field))->p.data;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = ((HcfECFieldFp *)(g_eccCommSpec->field))->p.len;
    eccKeyPairSpec->base.a.data = g_eccCommSpec->a.data;
    eccKeyPairSpec->base.a.len = g_eccCommSpec->a.len;
    eccKeyPairSpec->base.b.data = g_eccCommSpec->b.data;
    eccKeyPairSpec->base.b.len = g_eccCommSpec->b.len;
    eccKeyPairSpec->base.g.x.data = g_eccCommSpec->g.x.data;
    eccKeyPairSpec->base.g.x.len = g_eccCommSpec->g.x.len;
    eccKeyPairSpec->base.g.y.data = g_eccCommSpec->g.y.data;
    eccKeyPairSpec->base.g.y.len = g_eccCommSpec->g.y.len;
    eccKeyPairSpec->base.n.data = g_eccCommSpec->n.data;
    eccKeyPairSpec->base.n.len = g_eccCommSpec->n.len;
    eccKeyPairSpec->base.h = g_eccCommSpec->h;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_X_BN, &retBigInt);
    eccKeyPairSpec->pk.x.data = retBigInt.data;
    eccKeyPairSpec->pk.x.len = retBigInt.len;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_Y_BN, &retBigInt);
    eccKeyPairSpec->pk.y.data =retBigInt.data;
    eccKeyPairSpec->pk.y.len = retBigInt.len;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, &retBigInt);
    eccKeyPairSpec->sk.data = retBigInt.data;
    eccKeyPairSpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    HcfObjDestroy(generator);
    return HCF_SUCCESS;
}

void CryptoBrainPoolKeyAgreementTest::SetUpTestCase()
{
    ConstructEccBrainPool160r1KeyPairCommParamsSpec("NID_brainpoolP160r1", &g_eccCommSpec);
}

void CryptoBrainPoolKeyAgreementTest::TearDownTestCase()
{
    FreeEccCommParamsSpec(g_eccCommSpec);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest001, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest002, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate(nullptr, &keyAgreement);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(keyAgreement, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest003, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &keyAgreement);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(keyAgreement, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest004, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("SM257", &keyAgreement);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(keyAgreement, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest005, TestSize.Level0)
{
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP512t1", nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest006, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *className = keyAgreement->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest007, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);
    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest008, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest009, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(&obj);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest010, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest011, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest012, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName((HcfKeyAgreement *)(&obj));
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(keyAgreement);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest013, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, &paramSpec);
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
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest014, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, &paramSpec);
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
    res = keyAgreement->generateSecret(nullptr, keyPair->priKey, keyPair->pubKey, &out);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest015, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, &paramSpec);
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
    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, nullptr, &out);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest016, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, &paramSpec);
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
    res = keyAgreement->generateSecret(keyAgreement, nullptr, keyPair->pubKey, &out);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolKeyAgreementTest, CryptoBrainPoolKeyAgreementTest017, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = nullptr;
    int32_t res = HcfKeyAgreementCreate("ECC_BrainPoolP160r1", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, &paramSpec);
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

    res = keyAgreement->generateSecret(keyAgreement, keyPair->priKey, keyPair->pubKey, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(keyAgreement);
    HcfObjDestroy(generator);
}
}
