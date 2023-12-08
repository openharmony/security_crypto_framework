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
#include <string>
#include "securec.h"

#include "asy_key_generator.h"
#include "sm2_asy_key_generator_openssl.h"
#include "detailed_ecc_key_params.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecc_key_util.h"
#include "key_utils.h"
#include "blob.h"
#include "cipher.h"
#include "cipher_sm2_openssl.h"
#include "sm2_openssl.h"
#include "signature.h"
#include "key_pair.h"
#include "memory.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int ZERO = 0;
constexpr int ONE = 1;
constexpr int TWO = 2;
constexpr int THREE = 3;
constexpr int FOUR = 4;
constexpr int FIVE = 5;
constexpr int SIX = 6;
constexpr int SEVEN = 7;
constexpr int EIGHT = 8;

class CryptoSm2AsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoSm2AsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoSm2AsyKeyGeneratorBySpecTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static string g_sm2AlgName = "SM2_256";
static string g_sm2CurveName = "NID_sm2";

HcfEccPubKeyParamsSpec g_sm2256PubKeySpec;
HcfEccPriKeyParamsSpec g_sm2256PriKeySpec;
HcfEccKeyPairParamsSpec g_sm2256KeyPairSpec;
HcfEccCommParamsSpec g_sm2256CommSpec;
HcfEccCommParamsSpec *g_eccCommSpec = nullptr;

static HcfResult ConstructSm2256CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_sm2256CommSpec;
    HcfEccKeyUtilCreate(g_sm2CurveName.c_str(), &eccCommSpec);

    *spec = (HcfAsyKeyParamsSpec *)eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructSm2256KeyPairCommParamsSpec(const string &algoName, HcfEccCommParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;

    HcfEccKeyUtilCreate(algoName.c_str(), &eccCommSpec);

    *spec = eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructSm2256KeyPairParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_sm2256KeyPairSpec;
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

static HcfResult ConstructSm2256PriKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_sm2256PriKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    eccPriKeySpec->base.base.algName = g_eccCommSpec->base.algName;
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = g_eccCommSpec->field;
    eccPriKeySpec->base.field->fieldType = g_eccCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data = ((HcfECFieldFp *)(g_eccCommSpec->field))->p.data;
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = ((HcfECFieldFp *)(g_eccCommSpec->field))->p.len;
    eccPriKeySpec->base.a.data = g_eccCommSpec->a.data;
    eccPriKeySpec->base.a.len = g_eccCommSpec->a.len;
    eccPriKeySpec->base.b.data = g_eccCommSpec->b.data;
    eccPriKeySpec->base.b.len = g_eccCommSpec->b.len;
    eccPriKeySpec->base.g.x.data = g_eccCommSpec->g.x.data;
    eccPriKeySpec->base.g.x.len = g_eccCommSpec->g.x.len;
    eccPriKeySpec->base.g.y.data = g_eccCommSpec->g.y.data;
    eccPriKeySpec->base.g.y.len = g_eccCommSpec->g.y.len;
    eccPriKeySpec->base.n.data = g_eccCommSpec->n.data;
    eccPriKeySpec->base.n.len = g_eccCommSpec->n.len;
    eccPriKeySpec->base.h = g_eccCommSpec->h;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, &retBigInt);
    eccPriKeySpec->sk.data = retBigInt.data;
    eccPriKeySpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)eccPriKeySpec;
    HcfObjDestroy(generator);
    return HCF_SUCCESS;
}

static HcfResult ConstructSm2256PubKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_sm2256PubKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    eccPubKeySpec->base.base.algName = g_eccCommSpec->base.algName;
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = g_eccCommSpec->field;
    eccPubKeySpec->base.field->fieldType = g_eccCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data = ((HcfECFieldFp *)(g_eccCommSpec->field))->p.data;
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = ((HcfECFieldFp *)(g_eccCommSpec->field))->p.len;
    eccPubKeySpec->base.a.data = g_eccCommSpec->a.data;
    eccPubKeySpec->base.a.len = g_eccCommSpec->a.len;
    eccPubKeySpec->base.b.data = g_eccCommSpec->b.data;
    eccPubKeySpec->base.b.len = g_eccCommSpec->b.len;
    eccPubKeySpec->base.g.x.data = g_eccCommSpec->g.x.data;
    eccPubKeySpec->base.g.x.len = g_eccCommSpec->g.x.len;
    eccPubKeySpec->base.g.y.data = g_eccCommSpec->g.y.data;
    eccPubKeySpec->base.g.y.len = g_eccCommSpec->g.y.len;
    eccPubKeySpec->base.n.data = g_eccCommSpec->n.data;
    eccPubKeySpec->base.n.len = g_eccCommSpec->n.len;
    eccPubKeySpec->base.h = g_eccCommSpec->h;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_X_BN, &retBigInt);
    eccPubKeySpec->pk.x.data = retBigInt.data;
    eccPubKeySpec->pk.x.len = retBigInt.len;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ECC_PK_Y_BN, &retBigInt);
    eccPubKeySpec->pk.y.data =retBigInt.data;
    eccPubKeySpec->pk.y.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)eccPubKeySpec;
    HcfObjDestroy(generator);
    return HCF_SUCCESS;
}

void CryptoSm2AsyKeyGeneratorBySpecTest::SetUpTestCase()
{
    ConstructSm2256KeyPairCommParamsSpec("NID_sm2", &g_eccCommSpec);
}

void CryptoSm2AsyKeyGeneratorBySpecTest::TearDownTestCase()
{
    FreeEccCommParamsSpec(g_eccCommSpec);
}

/**
 * @tc.name: CryptoEccAsyKeyGeneratorBySpecTest.CryptoSm2AsyKeyGeneratorBySpecTest001
 * @tc.desc: Verify that the creation of the sm2 key pair generator is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEI
 */
HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest001, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;

    int32_t res = HcfAsyKeyGeneratorBySpecCreate(nullptr, &generator);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *className = generator->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&g_obj);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName(generator);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName((HcfAsyKeyGeneratorBySpec *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(nullptr, &keyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generateKeyPair(generator, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generateKeyPair(nullptr, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest015, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest016, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest017, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->base.destroy(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->pubKey->base.base.destroy(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->pubKey->base.base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest024, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *format = keyPair->pubKey->base.getFormat(nullptr);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest025, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *format = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest026, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest027, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *algName = keyPair->pubKey->base.getAlgorithm(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest028, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest029, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest030, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest031, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest032, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest033, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest034, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->priKey->clearMem(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest035, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest036, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest037, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest038, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->priKey->base.base.destroy(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest039, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    keyPair->priKey->base.base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest040, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *format = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest041, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *format = keyPair->priKey->base.getFormat(nullptr);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest042, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}


HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest043, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *algName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest044, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *algName = keyPair->priKey->base.getAlgorithm(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest045, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    const char *algName = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest046, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest047, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest048, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest049, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

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

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest050, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest051, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(nullptr, &pubKey);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest052, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generatePubKey(generator, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest053, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generatePubKey(nullptr, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest054, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *className = pubKey->base.base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest055, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    pubKey->base.base.destroy((HcfObjectBase *)(&(pubKey->base.base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest056, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest057, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    pubKey->base.base.destroy(&g_obj);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest058, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *format = pubKey->base.getFormat(&(pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest059, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *format = pubKey->base.getFormat(nullptr);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest060, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *format = pubKey->base.getFormat((HcfKey *)&g_obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest061, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *algName = pubKey->base.getAlgorithm(&(pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest062, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *algName = pubKey->base.getAlgorithm(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest063, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *algName = pubKey->base.getAlgorithm((HcfKey *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest064, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(&(pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest065, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest066, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest067, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    res = pubKey->base.getEncoded(&(pubKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest068, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest069, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(nullptr, &priKey);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest070, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generatePriKey(generator, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest071, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generatePriKey(nullptr, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest072, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *className = priKey->base.base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest073, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy((HcfObjectBase *)(&(priKey->base.base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest074, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy(nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest075, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy(&g_obj);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest076, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    res = priKey->base.getEncoded(&(priKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest077, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->clearMem(priKey);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest078, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->clearMem(nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest079, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat(&priKey->base);

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest080, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat(nullptr);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest081, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat((HcfKey *)&g_obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest082, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm(&priKey->base);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest083, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest084, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm((HcfKey *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest085, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = {.data = nullptr, .len = 0};
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest086, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = {.data = nullptr, .len = 0};
    res = priKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest087, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = {.data = nullptr, .len = 0};
    res = priKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest088, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    res = priKey->base.getEncoded(&(priKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest089, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    HcfBlob outPubKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->pubKey->base.getEncoded(&(outKeyPair->pubKey->base), &outPubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPubKeyBlob.data, nullptr);
    ASSERT_NE(outPubKeyBlob.len, 0);
    HcfBlob outPriKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->priKey->base.getEncoded(&(outKeyPair->priKey->base), &outPriKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPriKeyBlob.data, nullptr);
    ASSERT_NE(outPriKeyBlob.len, 0);
    free(pubKeyBlob.data);
    free(priKeyBlob.data);
    free(outPubKeyBlob.data);
    free(outPriKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest090, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);
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

    uint8_t plan[] = "this is sm2 cipher test!\0";
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = nullptr, .len = 0};
    HcfCipher *cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);

    HcfBlob decoutput = {.data = nullptr, .len = 0};
    cipher = nullptr;
    res = HcfCipherCreate("SM2|SM3", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, nullptr);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest091, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);
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

    HcfSign *sign = nullptr;
    res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    uint8_t pSourceData[] = "1234567812345678\0";
    HcfBlob pSource = {.data = (uint8_t *)pSourceData, .len = strlen((char *)pSourceData)};
    res = sign->setSignSpecUint8Array(sign, SM2_USER_ID_UINT8ARR, pSource);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, keyPair->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest092, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = HCF_ALG_SM2_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest093, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = HCF_ALG_SM2_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest094, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = HCF_ALG_SM2_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest095, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_SM2,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest096, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest097, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    res = pubKey->getAsyKeySpecString(pubKey, ECC_CURVE_NAME_STR, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    char *retStr = nullptr;
    res = pubKey->getAsyKeySpecString(pubKey, ECC_FIELD_SIZE_INT, &retStr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest098, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);
    retStr = nullptr;
    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);
    

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest099, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest100, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;
    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);
    retInt = 0;
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest101, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ECC_FIELD_SIZE_INT, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    int retInt = 0;
    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, ECC_FIELD_TYPE_STR, &retInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DSA_SK_BN, &retBigInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

static HcfResult ConstructSm2256KeyPairParamsSpecByGet(HcfEccKeyPairParamsSpec *eccKeyPairSpec,
    HcfBigInteger *params, int h)
{
    eccKeyPairSpec->base.base.algName = g_eccCommSpec->base.algName;
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = g_eccCommSpec->field;
    eccKeyPairSpec->base.field->fieldType = g_eccCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data = params[ZERO].data;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = params[ZERO].len;
    eccKeyPairSpec->base.a.data = params[ONE].data;
    eccKeyPairSpec->base.a.len = params[ONE].len;
    eccKeyPairSpec->base.b.data = params[TWO].data;
    eccKeyPairSpec->base.b.len = params[TWO].len;
    eccKeyPairSpec->base.g.x.data = params[THREE].data;
    eccKeyPairSpec->base.g.x.len = params[THREE].len;
    eccKeyPairSpec->base.g.y.data = params[FOUR].data;
    eccKeyPairSpec->base.g.y.len = params[FOUR].len;

    eccKeyPairSpec->base.n.data = params[FIVE].data;
    eccKeyPairSpec->base.n.len = params[FIVE].len;
    eccKeyPairSpec->base.h = h;
    eccKeyPairSpec->pk.x.data = params[SIX].data;
    eccKeyPairSpec->pk.x.len = params[SIX].len;
    eccKeyPairSpec->pk.y.data = params[SEVEN].data;
    eccKeyPairSpec->pk.y.len = params[SEVEN].len;

    eccKeyPairSpec->sk.data = params[EIGHT].data;
    eccKeyPairSpec->sk.len = params[EIGHT].len;
    return HCF_SUCCESS;
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest102, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(g_sm2AlgName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    HcfPriKey *priKey = keyPair->priKey;
    HcfPubKey *pubKey = keyPair->pubKey;
    HcfBigInteger retFp = { .data = nullptr, .len = 0 };
    HcfBigInteger retA = { .data = nullptr, .len = 0 };
    HcfBigInteger retB = { .data = nullptr, .len = 0 };
    HcfBigInteger retGX = { .data = nullptr, .len = 0 };
    HcfBigInteger retGY = { .data = nullptr, .len = 0 };
    HcfBigInteger retN = { .data = nullptr, .len = 0 };
    HcfBigInteger retSk = { .data = nullptr, .len = 0 };
    HcfBigInteger retPkX = { .data = nullptr, .len = 0 };
    HcfBigInteger retPkY = { .data = nullptr, .len = 0 };
    int retH = 0;
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_FP_P_BN, &retFp);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_A_BN, &retA);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_B_BN, &retB);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_G_X_BN, &retGX);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_G_Y_BN, &retGY);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_N_BN, &retN);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, ECC_PK_X_BN, &retPkX);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecBigInteger(pubKey, ECC_PK_Y_BN, &retPkY);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = priKey->getAsyKeySpecBigInteger(priKey, ECC_SK_BN, &retSk);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = pubKey->getAsyKeySpecInt(pubKey, ECC_H_INT, &retH);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBigInteger params[9];
    params[0].data = retFp.data;
    params[0].len = retFp.len;
    params[1].data = retA.data;
    params[1].len = retA.len;
    params[2].data = retB.data;
    params[2].len = retB.len;
    params[3].data = retGX.data;
    params[3].len = retGX.len;
    params[4].data = retGY.data;
    params[4].len = retGY.len;
    params[5].data = retN.data;
    params[5].len = retN.len;
    params[6].data = retPkX.data;
    params[6].len = retPkX.len;
    params[7].data = retPkY.data;
    params[7].len = retPkY.len;
    params[8].data = retSk.data;
    params[8].len = retSk.len;

    HcfEccKeyPairParamsSpec eccKeyPairSpec = {};
    res = ConstructSm2256KeyPairParamsSpecByGet(&eccKeyPairSpec, params, retH);
    HcfAsyKeyGeneratorBySpec *generatorSpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&eccKeyPairSpec), &generatorSpec);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorSpec, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorSpec->generateKeyPair(generatorSpec, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair, nullptr);

    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorSpec);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (int i = 0; i < mallocCount - THREE; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        int32_t res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
        res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
        res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        free(pubKeyBlob.data);
        free(priKeyBlob.data);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest103, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256KeyPairParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    free(pubKeyBlob.data);
    free(priKeyBlob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, paramSpec);

    EndRecordOpensslCallNum();
}

static void OpensslMockTestFunc1(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (int i = 0; i < mallocCount - 1; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        int32_t res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest104, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc1(mallocCount, paramSpec);

    EndRecordOpensslCallNum();
}

static void OpensslMockTestFunc2(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (int i = 0; i < mallocCount - FIVE; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        int32_t res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfPriKey *priKey = nullptr;
        res = generatorBySpec->generatePriKey(generatorBySpec, &priKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfObjDestroy(priKey);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest105, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PriKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfPriKey *priKey = nullptr;
    res = generatorBySpec->generatePriKey(generatorBySpec, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc2(mallocCount, paramSpec);

    EndRecordOpensslCallNum();
}

static void OpensslMockTestFunc3(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (int i = 0; i < mallocCount - 1; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
        int32_t res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfPubKey *pubKey = nullptr;
        res = generatorBySpec->generatePubKey(generatorBySpec, &pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generatorBySpec);
            continue;
        }
        HcfObjDestroy(pubKey);
        HcfObjDestroy(generatorBySpec);
    }
}

HWTEST_F(CryptoSm2AsyKeyGeneratorBySpecTest, CryptoSm2AsyKeyGeneratorBySpecTest106, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructSm2256PubKeyParamsSpec(g_sm2AlgName, &paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    StartRecordOpensslCallNum();
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generatorBySpec, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = generatorBySpec->generatePubKey(generatorBySpec, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generatorBySpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc3(mallocCount, paramSpec);

    EndRecordOpensslCallNum();
}
}
