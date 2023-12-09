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
#include "detailed_ecc_key_params.h"
#include "ecc_key_util.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "ecc_common_param_spec_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccKeyUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static string g_brainpool160r1AlgName = "ECC_BrainPoolP160r1";
static string g_brainpool160t1AlgName = "ECC_BrainPoolP160t1";
static string g_brainpool192r1AlgName = "ECC_BrainPoolP192r1";
static string g_brainpool192t1AlgName = "ECC_BrainPoolP192t1";
static string g_brainpool224r1AlgName = "ECC_BrainPoolP224r1";
static string g_brainpool224t1AlgName = "ECC_BrainPoolP224t1";
static string g_brainpool256r1AlgName = "ECC_BrainPoolP256r1";
static string g_brainpool256t1AlgName = "ECC_BrainPoolP256t1";
static string g_brainpool320r1AlgName = "ECC_BrainPoolP320r1";
static string g_brainpool320t1AlgName = "ECC_BrainPoolP320t1";
static string g_brainpool384r1AlgName = "ECC_BrainPoolP384r1";
static string g_brainpool384t1AlgName = "ECC_BrainPoolP384t1";
static string g_brainpool512r1AlgName = "ECC_BrainPoolP512r1";
static string g_brainpool512t1AlgName = "ECC_BrainPoolP512t1";

HcfEccCommParamsSpec *g_brainpool160r1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool160t1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool192r1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool192t1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool224r1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool224t1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool256r1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool256t1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool320r1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool320t1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool384r1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool384t1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool512r1CommSpec = nullptr;
HcfEccCommParamsSpec *g_brainpool512t1CommSpec = nullptr;

HcfEccKeyPairParamsSpec g_brainpoolKeyPairSpec;
HcfEccPriKeyParamsSpec g_brainpool160r1PriKeySpec;
HcfEccPubKeyParamsSpec g_brainpool160r1PubKeySpec;

void CryptoEccKeyUtilTest::SetUp() {}
void CryptoEccKeyUtilTest::TearDown() {}

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

static const char *GetMockClass(void)
{
    return "HcfEcc";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr};


static HcfResult ConstructEccBrainPoolKeyPairCommParamsSpec(const string &algoName, HcfEccCommParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = nullptr;
    HcfEccKeyUtilCreate(algoName.c_str(), &eccCommSpec);

    *spec = eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructbrainpoolKeyPairParamsSpec(const string &algoName,
    HcfEccCommParamsSpec *brainpoolCommSpec, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_brainpoolKeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    eccKeyPairSpec->base.base.algName = brainpoolCommSpec->base.algName;
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = brainpoolCommSpec->field;
    eccKeyPairSpec->base.field->fieldType = brainpoolCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data = ((HcfECFieldFp *)(brainpoolCommSpec->field))->p.data;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = ((HcfECFieldFp *)(brainpoolCommSpec->field))->p.len;
    eccKeyPairSpec->base.a.data = brainpoolCommSpec->a.data;
    eccKeyPairSpec->base.a.len = brainpoolCommSpec->a.len;
    eccKeyPairSpec->base.b.data = brainpoolCommSpec->b.data;
    eccKeyPairSpec->base.b.len = brainpoolCommSpec->b.len;
    eccKeyPairSpec->base.g.x.data = brainpoolCommSpec->g.x.data;
    eccKeyPairSpec->base.g.x.len = brainpoolCommSpec->g.x.len;
    eccKeyPairSpec->base.g.y.data = brainpoolCommSpec->g.y.data;
    eccKeyPairSpec->base.g.y.len = brainpoolCommSpec->g.y.len;
    eccKeyPairSpec->base.n.data = brainpoolCommSpec->n.data;
    eccKeyPairSpec->base.n.len = brainpoolCommSpec->n.len;
    eccKeyPairSpec->base.h = brainpoolCommSpec->h;
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

static HcfResult Constructbrainpool160r1PubKeyParamsSpec(const string &algoName,
    HcfEccCommParamsSpec *brainpoolCommSpec, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_brainpool160r1PubKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    eccPubKeySpec->base.base.algName = brainpoolCommSpec->base.algName;
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = brainpoolCommSpec->field;
    eccPubKeySpec->base.field->fieldType = brainpoolCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data = ((HcfECFieldFp *)(brainpoolCommSpec->field))->p.data;
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = ((HcfECFieldFp *)(brainpoolCommSpec->field))->p.len;
    eccPubKeySpec->base.a.data = brainpoolCommSpec->a.data;
    eccPubKeySpec->base.a.len = brainpoolCommSpec->a.len;
    eccPubKeySpec->base.b.data = brainpoolCommSpec->b.data;
    eccPubKeySpec->base.b.len = brainpoolCommSpec->b.len;
    eccPubKeySpec->base.g.x.data = brainpoolCommSpec->g.x.data;
    eccPubKeySpec->base.g.x.len = brainpoolCommSpec->g.x.len;
    eccPubKeySpec->base.g.y.data = brainpoolCommSpec->g.y.data;
    eccPubKeySpec->base.g.y.len = brainpoolCommSpec->g.y.len;
    eccPubKeySpec->base.n.data = brainpoolCommSpec->n.data;
    eccPubKeySpec->base.n.len = brainpoolCommSpec->n.len;
    eccPubKeySpec->base.h = brainpoolCommSpec->h;
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

static HcfResult Constructbrainpool160r1PriKeyParamsSpec(const string &algoName,
    HcfEccCommParamsSpec *brainpoolCommSpec, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_brainpool160r1PriKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    eccPriKeySpec->base.base.algName = brainpoolCommSpec->base.algName;
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = brainpoolCommSpec->field;
    eccPriKeySpec->base.field->fieldType = brainpoolCommSpec->field->fieldType;
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data = ((HcfECFieldFp *)(brainpoolCommSpec->field))->p.data;
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = ((HcfECFieldFp *)(brainpoolCommSpec->field))->p.len;
    eccPriKeySpec->base.a.data = brainpoolCommSpec->a.data;
    eccPriKeySpec->base.a.len = brainpoolCommSpec->a.len;
    eccPriKeySpec->base.b.data = brainpoolCommSpec->b.data;
    eccPriKeySpec->base.b.len = brainpoolCommSpec->b.len;
    eccPriKeySpec->base.g.x.data = brainpoolCommSpec->g.x.data;
    eccPriKeySpec->base.g.x.len = brainpoolCommSpec->g.x.len;
    eccPriKeySpec->base.g.y.data = brainpoolCommSpec->g.y.data;
    eccPriKeySpec->base.g.y.len = brainpoolCommSpec->g.y.len;
    eccPriKeySpec->base.n.data = brainpoolCommSpec->n.data;
    eccPriKeySpec->base.n.len = brainpoolCommSpec->n.len;
    eccPriKeySpec->base.h = brainpoolCommSpec->h;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ECC_SK_BN, &retBigInt);
    eccPriKeySpec->sk.data = retBigInt.data;
    eccPriKeySpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)eccPriKeySpec;
    HcfObjDestroy(generator);

    return HCF_SUCCESS;
}

void CryptoEccKeyUtilTest::SetUpTestCase()
{
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP160r1", &g_brainpool160r1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP160t1", &g_brainpool160t1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP192r1", &g_brainpool192r1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP192t1", &g_brainpool192t1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP224r1", &g_brainpool224r1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP224t1", &g_brainpool224t1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP256r1", &g_brainpool256r1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP256t1", &g_brainpool256t1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP320r1", &g_brainpool320r1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP320t1", &g_brainpool320t1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP384r1", &g_brainpool384r1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP384t1", &g_brainpool384t1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP512r1", &g_brainpool512r1CommSpec);
    ConstructEccBrainPoolKeyPairCommParamsSpec("NID_brainpoolP512t1", &g_brainpool512t1CommSpec);
}

void CryptoEccKeyUtilTest::TearDownTestCase()
{
    FreeEccCommParamsSpec(g_brainpool160r1CommSpec);
    FreeEccCommParamsSpec(g_brainpool160t1CommSpec);
    FreeEccCommParamsSpec(g_brainpool192r1CommSpec);
    FreeEccCommParamsSpec(g_brainpool192t1CommSpec);
    FreeEccCommParamsSpec(g_brainpool224r1CommSpec);
    FreeEccCommParamsSpec(g_brainpool224t1CommSpec);
    FreeEccCommParamsSpec(g_brainpool256r1CommSpec);
    FreeEccCommParamsSpec(g_brainpool256t1CommSpec);
    FreeEccCommParamsSpec(g_brainpool320r1CommSpec);
    FreeEccCommParamsSpec(g_brainpool320t1CommSpec);
    FreeEccCommParamsSpec(g_brainpool384r1CommSpec);
    FreeEccCommParamsSpec(g_brainpool384t1CommSpec);
    FreeEccCommParamsSpec(g_brainpool512r1CommSpec);
    FreeEccCommParamsSpec(g_brainpool512t1CommSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_1, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_2, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP160t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_3, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP192r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_4, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP192t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_5, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP224r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_6, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP224t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_7, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP256r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_8, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP256t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_9, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP320r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_10, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP320t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_11, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP384r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_12, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP384t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_13, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP512r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_14, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP512t1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_15, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_secp224r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_16, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_X9_62_prime256v1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_17, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_secp384r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_18, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_secp521r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest001_19, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("NID_sm2", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest002, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate(nullptr, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest003, TestSize.Level0)
{
    int32_t res = HcfEccKeyUtilCreate("ECC_BrainPoolP160r1", nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest004, TestSize.Level0)
{
    HcfEccCommParamsSpec *returnCommonParamSpec;
    int32_t res = HcfEccKeyUtilCreate("BrainPoolP999", &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *classname = returnObj->base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    returnObj->base.destroy(&g_obj);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *algName = returnObj->getAlgName(returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *classname = returnKeyPair->base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);

    returnKeyPair->base.destroy(&(returnKeyPair->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest011, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->base.destroy(nullptr);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest012, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->base.destroy(&g_obj);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest013, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *classname = returnKeyPair->pubKey->base.base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest014, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->pubKey->base.base.destroy(&(returnKeyPair->pubKey->base.base));

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest015, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->pubKey->base.base.destroy(nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest016, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->pubKey->base.base.destroy(&g_obj);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest017, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char * format = returnKeyPair->pubKey->base.getFormat(&(returnKeyPair->pubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest018, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char * algorithm = returnKeyPair->pubKey->base.getAlgorithm(&(returnKeyPair->pubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest019, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
    res = returnKeyPair->pubKey->base.getEncoded(&(returnKeyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest020, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    returnKeyPair->priKey->clearMem(returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest021, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    returnKeyPair->priKey->clearMem(nullptr);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    returnKeyPair->priKey->clearMem((HcfPriKey *)&g_obj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest023, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *classname = returnKeyPair->priKey->base.base.getClass();
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(classname, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest024, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->priKey->base.base.destroy(&(returnKeyPair->priKey->base.base));
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest025, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->priKey->base.base.destroy(nullptr);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest026, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    returnKeyPair->priKey->base.base.destroy(&g_obj);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest027, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *format = returnKeyPair->priKey->base.getFormat(&(returnKeyPair->priKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest028, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    const char *algorithm = returnKeyPair->priKey->base.getAlgorithm(&(returnKeyPair->priKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest029, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
    res = returnKeyPair->priKey->base.getEncoded(&(returnKeyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest030, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PubKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    ASSERT_NE(res, HCF_INVALID_PARAMS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPubKey, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest031, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PubKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPubKey, nullptr);

    returnPubKey->base.base.destroy(&(returnPubKey->base.base));
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest032, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PubKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    const char *format = returnPubKey->base.getFormat(&(returnPubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPubKey, nullptr);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest033, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PubKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    const char *algorithm = returnPubKey->base.getAlgorithm(&(returnPubKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPubKey, nullptr);
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest034, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PubKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = returnPubKey->base.getEncoded(&(returnPubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPubKey, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest035, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PriKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest036, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PriKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPriKey, nullptr);

    returnPriKey->base.base.destroy(&(returnPriKey->base.base));
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest037, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PriKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    returnPriKey->clearMem(returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest038, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PriKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    const char *algorithm = returnPriKey->base.getAlgorithm(&(returnPriKey->base));
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPriKey, nullptr);
    ASSERT_NE(algorithm, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP160r1|SHA224", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP160r1|SHA224", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160t1AlgName, g_brainpool160t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP160t1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP160t1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool192r1AlgName, g_brainpool192r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP192r1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP192r1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool192t1AlgName, g_brainpool192t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP192t1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP192t1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool224r1AlgName, g_brainpool224r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP224r1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP224r1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool224t1AlgName, g_brainpool224t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP224t1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP224t1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool256r1AlgName, g_brainpool256r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP256r1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP256r1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool256t1AlgName, g_brainpool256t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP256t1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP256t1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_9, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool320r1AlgName, g_brainpool320r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP320r1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP320r1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_10, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool320t1AlgName, g_brainpool320t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP320t1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP320t1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_11, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool384r1AlgName, g_brainpool384r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP384r1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP384r1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_12, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool384t1AlgName, g_brainpool384t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP384t1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP384t1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_13, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool512r1AlgName, g_brainpool512r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP512r1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP512r1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest039_14, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool512t1AlgName, g_brainpool512t1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC_BrainPoolP512t1|SHA224", &sign);
    res = sign->init(sign, nullptr, returnKeyPair->priKey);
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);
    HcfVerify *verify;
    res = HcfVerifyCreate("ECC_BrainPoolP512t1|SHA224", &verify);
    res = verify->init(verify, nullptr, returnKeyPair->pubKey);
    res = verify->verify(verify, &g_mockInput, &out);
    ASSERT_EQ(res, true);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest040, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnKeyPair;
    res = returnObj->generateKeyPair(returnObj, &returnKeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnKeyPair, nullptr);

    HcfObjDestroy(returnKeyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest041, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PubKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPubKey;
    res = returnObj->generatePubKey(returnObj, &returnPubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPubKey, nullptr);

    HcfObjDestroy(returnPubKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest042, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PriKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest043, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PriKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *returnPriKey;
    res = returnObj->generateKeyPair(returnObj, &returnPriKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_EQ(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest044, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructbrainpoolKeyPairParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *returnPriKey;
    res = returnObj->generatePriKey(returnObj, &returnPriKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_NE(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest045, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = Constructbrainpool160r1PriKeyParamsSpec(g_brainpool160r1AlgName, g_brainpool160r1CommSpec,
        &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *returnPriKey;
    res = returnObj->generatePubKey(returnObj, &returnPriKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);
    ASSERT_EQ(returnPriKey, nullptr);

    HcfObjDestroy(returnPriKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest046, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_BP160R1,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    int32_t res = HcfECCCommonParamSpecCreate(&params, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest047, TestSize.Level0)
{
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    int32_t res = HcfECCCommonParamSpecCreate(nullptr, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest048, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_BP160R1,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    int32_t res = HcfECCCommonParamSpecCreate(&params, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest049, TestSize.Level0)
{
    HcfAsyKeyGenParams obj = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_OPENSSL_RSA_2048,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    int32_t res = HcfECCCommonParamSpecCreate(&obj, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    HcfObjDestroy(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest050, TestSize.Level0)
{
    HcfAsyKeyGenParams obj = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2
    };
    HcfEccCommParamsSpecSpi *returnCommonParamSpec = nullptr;
    int32_t res = HcfECCCommonParamSpecCreate(&obj, &returnCommonParamSpec);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(returnCommonParamSpec, nullptr);

    HcfObjDestroy(returnCommonParamSpec);
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest051, TestSize.Level0)
{
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfEccCommParamsSpec *returnCommonParamSpec)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            continue;
        }

        FreeEccCommParamsSpec(returnCommonParamSpec);
    }
}

HWTEST_F(CryptoEccKeyUtilTest, CryptoEccKeyUtilTest052, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfEccCommParamsSpec *returnCommonParamSpec = NULL;
    int32_t res = HcfEccKeyUtilCreate("NID_brainpoolP160r1", &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnCommonParamSpec, nullptr);

    FreeEccCommParamsSpec(returnCommonParamSpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, returnCommonParamSpec);

    EndRecordOpensslCallNum();
}
}