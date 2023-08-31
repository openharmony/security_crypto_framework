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
#include "ecc_openssl_common.h"
#include "ecc_common.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_common.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccNoLengthSignTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *ecc224KeyPair_;
    static HcfKeyPair *ecc256KeyPair_;
    static HcfKeyPair *ecc384KeyPair_;
    static HcfKeyPair *ecc521KeyPair_;
};

HcfKeyPair *CryptoEccNoLengthSignTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *CryptoEccNoLengthSignTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *CryptoEccNoLengthSignTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *CryptoEccNoLengthSignTest::ecc521KeyPair_ = nullptr;

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

void CryptoEccNoLengthSignTest::SetUp() {}
void CryptoEccNoLengthSignTest::TearDown() {}

static const bool IS_BIG_ENDIAN = IsBigEndian();

static string g_eccAlgName = "ECC";
static string g_eccFieldType = "Fp";
static int32_t g_ecc224CorrectH = 1;
static int32_t g_ecc256CorrectH = 1;
static int32_t g_ecc384CorrectH = 1;
static int32_t g_ecc521CorrectH = 1;

HcfEccKeyPairParamsSpec g_ecc224KeyPairSpec;
HcfEccKeyPairParamsSpec g_ecc256KeyPairSpec;
HcfEccKeyPairParamsSpec g_ecc384KeyPairSpec;
HcfEccKeyPairParamsSpec g_ecc521KeyPairSpec;
HcfECFieldFp g_fieldFp;

static HcfResult ConstructEcc224KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc224KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_secp224r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp224r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp224r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp224r1_len;
    eccKeyPairSpec->base.h = g_ecc224CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp224r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp224r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp224r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc256KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc256KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.h = g_ecc256CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkX : g_ecc256CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkY : g_ecc256CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigSk : g_ecc256CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_X9_62_prime256v1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc384KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc384KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_secp384r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp384r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp384r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp384r1_len;
    eccKeyPairSpec->base.h = g_ecc384CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkX : g_ecc384CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp384r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkY : g_ecc384CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp384r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigSk : g_ecc384CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp384r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc521KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc521KeyPairSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = NID_secp521r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp521r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp521r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp521r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp521r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp521r1_len;
    eccKeyPairSpec->base.h = g_ecc521CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkX : g_ecc521CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp521r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkY : g_ecc521CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp521r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigSk : g_ecc521CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp521r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccKeyPairSpec;
    return HCF_SUCCESS;
}

void CryptoEccNoLengthSignTest::SetUpTestCase()
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc224KeyPair_ = keyPair;

    HcfObjDestroy(generator);

    HcfAsyKeyParamsSpec *paramSpec2 = nullptr;
    res = ConstructEcc256KeyPairParamsSpec(&paramSpec2);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator2 = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec2, &generator2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator2, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator2->generateKeyPair(generator2, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    ecc256KeyPair_ = keyPair2;

    HcfObjDestroy(generator2);

    HcfAsyKeyParamsSpec *paramSpec3 = nullptr;
    res = ConstructEcc384KeyPairParamsSpec(&paramSpec3);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator3 = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec3, &generator3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator3, nullptr);

    HcfKeyPair *keyPair3 = nullptr;
    res = generator3->generateKeyPair(generator3, &keyPair3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair3, nullptr);

    ecc384KeyPair_ = keyPair3;
    HcfObjDestroy(generator3);

    HcfAsyKeyParamsSpec *paramSpec4 = nullptr;
    res = ConstructEcc521KeyPairParamsSpec(&paramSpec4);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator4 = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec4, &generator4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator4, nullptr);

    HcfKeyPair *keyPair4 = nullptr;
    res = generator4->generateKeyPair(generator4, &keyPair4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair4, nullptr);

    ecc521KeyPair_ = keyPair4;
    HcfObjDestroy(generator4);
}

void CryptoEccNoLengthSignTest::TearDownTestCase()
{
    HcfObjDestroy(ecc224KeyPair_);
    HcfObjDestroy(ecc256KeyPair_);
    HcfObjDestroy(ecc384KeyPair_);
    HcfObjDestroy(ecc521KeyPair_);
}

static const char *GetMockClass(void)
{
    return "HcfMock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest002, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest003, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest004, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest005, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest006, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ecc|SHA512", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest007, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|MD5", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest008, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECCSHA256", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest009, TestSize.Level0)
{
    int32_t res = HcfSignCreate("ECC|SHA256", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest101, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *className = sign->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest102, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest103, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest104, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&obj);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest105, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest106, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest107, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName((HcfSign *)(&obj));

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest201, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest202, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest203, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest204, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest205, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest206, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest207, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest208, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest209, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest210, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest211, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest212, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest213, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest214, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest215, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest216, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest217, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest218, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest219, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest220, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest221, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(nullptr, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest222, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init((HcfSign *)(&obj), nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest223, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest224, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest225, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest301, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest302, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest303, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest304, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest305, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest306, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest307, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest308, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest309, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest310, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest311, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest312, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest313, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest314, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest315, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest316, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest317, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest318, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest319, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest320, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest321, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(nullptr, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest322, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update((HcfSign *)(&obj), &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest323, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest324, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest325, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest326, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest401, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest402, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest403, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest404, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest405, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest406, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest407, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest408, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest409, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest410, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest411, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest412, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest413, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest414, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest415, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest416, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest417, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest418, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest419, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest420, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

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
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest421, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest422, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest423, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest424, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest425, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest426, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest427, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest428, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest429, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest430, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest431, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest432, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest433, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest434, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest435, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest436, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest437, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest438, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest439, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest440, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest441, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(nullptr, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest442, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign((HcfSign *)(&obj), nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest443, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest444, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest445, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest446, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->sign(sign, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest447, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out2 = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out2);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->init(verify, nullptr, ecc256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    verify->update(verify, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);
    ASSERT_EQ(flag, true);

    verify->update(verify, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    flag = verify->verify(verify, nullptr, &out2);
    ASSERT_EQ(flag, true);

    free(out.data);
    free(out2.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest448, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out2 = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out2);

    free(out2.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest927, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest928, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HcfSignatureParams g_params = {
    .algo = HCF_ALG_ECC,
    .padding = HCF_ALG_NOPADDING,
    .md = HCF_OPENSSL_DIGEST_SHA256,
    .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
};

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1001, TestSize.Level0)
{
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1003, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit((HcfSignSpi *)&obj, nullptr, ecc256KeyPair_->priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1004, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit(spiObj, nullptr, (HcfPriKey *)&obj);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1005, TestSize.Level0)
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

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1006, TestSize.Level0)
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

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1007, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1008, TestSize.Level0)
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

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1009, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1010, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&obj);

    HcfObjDestroy(spiObj);
}

static void MemoryMallocTestFunc(uint32_t mallocCount, HcfBlob *input)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfAsyKeyGenerator *generator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfSign *sign = nullptr;
        res = HcfSignCreate("ECC|SHA256", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->init(sign, nullptr, keyPair->priKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->update(sign, input);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        res = sign->sign(sign, nullptr, &out);
        HcfObjDestroy(sign);
        HcfObjDestroy(keyPair);
        if (res == HCF_SUCCESS) {
            free(out.data);
        }
    }
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1101, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFunc(mallocCount, &input);

    EndRecordMallocNum();
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfBlob *input)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGenerator *generator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfSign *sign = nullptr;
        res = HcfSignCreate("ECC|SHA256", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->init(sign, nullptr, keyPair->priKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        res = sign->update(sign, input);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(sign);
            HcfObjDestroy(keyPair);
            continue;
        }
        HcfBlob out = {
            .data = nullptr,
            .len = 0
        };
        res = sign->sign(sign, input, &out);
        HcfObjDestroy(sign);
        HcfObjDestroy(keyPair);
        if (res == HCF_SUCCESS) {
            free(out.data);
        }
    }
}

HWTEST_F(CryptoEccNoLengthSignTest, CryptoEccNoLengthSignTest1102, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(generator);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256", &sign);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfParamsSpec params;
    res = sign->init(sign, &params, keyPair->priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, &input);

    EndRecordOpensslCallNum();
}
}
