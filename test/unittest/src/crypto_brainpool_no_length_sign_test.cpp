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
#include "ecc_key_util.h"
#include "key_utils.h"
#include "blob.h"
#include "detailed_ecc_key_params.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_common.h"
#include "object_base.h"
#include "ecc_common_param_spec_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoBrainPoolNoLengthSignTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static string g_brainpool160r1AlgName = "ECC_BrainPoolP160r1";
static string g_brainpool160r1curveName = "NID_brainpoolP160r1";

HcfEccCommParamsSpec *g_eccCommSpec = nullptr;
HcfEccKeyPairParamsSpec g_brainpool160r1KeyPairSpec;

void CryptoBrainPoolNoLengthSignTest::SetUp() {}
void CryptoBrainPoolNoLengthSignTest::TearDown() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase obj = {
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

static HcfResult Constructbrainpool160r1KeyPairParamsSpec(const string &algoName, const string &curveName,
    HcfAsyKeyParamsSpec **spec)
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

void CryptoBrainPoolNoLengthSignTest::SetUpTestCase()
{
    ConstructEccBrainPool160r1KeyPairCommParamsSpec("NID_brainpoolP160r1", &g_eccCommSpec);
}

void CryptoBrainPoolNoLengthSignTest::TearDownTestCase()
{
    FreeEccCommParamsSpec(g_eccCommSpec);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_1, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA1", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_2, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_3, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_4, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA384", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_5, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA512", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest001_6, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|MD5", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest002, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *className = sign->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest003, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest004, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);
    sign->base.destroy(nullptr);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest005, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&obj);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest006, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest007, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest008, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName((HcfSign *)&obj);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest009, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest010, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(nullptr, nullptr, keyPair->priKey);
    ASSERT_NE(res, HCF_SUCCESS);
    
    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest011, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init((HcfSign *)(&obj), nullptr, keyPair->priKey);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest012, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest013, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest014, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest015, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfBlob g_mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };
    res = sign->update(sign, &g_mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest016, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfBlob g_mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };
    res = sign->update(nullptr, &g_mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest017, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfBlob g_mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };

    res = sign->update((HcfSign *)(&obj), &g_mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest018, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfBlob g_mockInput = {
        .data = (uint8_t *)g_mockMessage,
        .len = 1
    };

    res = sign->update(sign, &g_mockInput);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(sign);
}


HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest019, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest020, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };

    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest021, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };

    res = sign->update(sign, &input);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest022, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest023, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest024, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(nullptr, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign((HcfSign *)(&obj), nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest026, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest027, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest028, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC_BrainPoolP160r1|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, (const unsigned int)0);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HcfSignatureParams g_params = {
    .algo = HCF_ALG_ECC,
    .padding = HCF_ALG_NOPADDING,
    .md = HCF_OPENSSL_DIGEST_SHA256,
    .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
};

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest029, TestSize.Level0)
{
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest030, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = Constructbrainpool160r1KeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1curveName, &paramSpec);
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

    res = spiObj->engineInit((HcfSignSpi *)&obj, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest031, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit(spiObj, nullptr, (HcfPriKey *)&obj);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest032, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate(nullptr, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest033, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate((HcfSignSpi *)&obj, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest034, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolNoLengthSignTest, CryptoBrainPoolNoLengthSignTest035, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = spiObj->engineSign((HcfSignSpi *)&obj, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}
}
