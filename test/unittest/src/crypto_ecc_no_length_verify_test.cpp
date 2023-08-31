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
class CryptoEccNoLengthVerifyTest : public testing::Test {
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

HcfKeyPair *CryptoEccNoLengthVerifyTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *CryptoEccNoLengthVerifyTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *CryptoEccNoLengthVerifyTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *CryptoEccNoLengthVerifyTest::ecc521KeyPair_ = nullptr;

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

void CryptoEccNoLengthVerifyTest::SetUp() {}
void CryptoEccNoLengthVerifyTest::TearDown() {}

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

void CryptoEccNoLengthVerifyTest::SetUpTestCase()
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

void CryptoEccNoLengthVerifyTest::TearDownTestCase()
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

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest002, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest003, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest004, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest005, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest006, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ecc|SHA512", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest007, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA257", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest008, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|MD5", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest009, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECCSHA256", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest010, TestSize.Level0)
{
    int32_t res = HcfVerifyCreate("ECC|SHA256", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest101, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *className = verify->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest102, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy((HcfObjectBase *)verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest103, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest104, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(&obj);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest105, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(verify);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest106, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest107, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName((HcfVerify *)(&obj));

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest201, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest202, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest203, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest204, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest205, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest206, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest207, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest208, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest209, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest210, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest211, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest212, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest213, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest214, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest215, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest216, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest217, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest218, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest219, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest220, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest221, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(nullptr, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest222, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init((HcfVerify *)(&obj), nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest223, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest224, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest225, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, (HcfPubKey *)(&obj));

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest301, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest302, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest303, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest304, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest305, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest306, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest307, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest308, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest309, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest310, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest311, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest312, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest313, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest314, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest315, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest316, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest317, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest318, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest319, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest320, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest321, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(nullptr, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest322, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update((HcfVerify *)(&obj), &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest323, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest324, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest325, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest326, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest401, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest402, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest403, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest404, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest405, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest406, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest407, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest408, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest409, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest410, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest411, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest412, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest413, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest414, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest415, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest416, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest417, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest418, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest419, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest420, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest421, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest422, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest423, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest424, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest425, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest426, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest427, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest428, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest429, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest430, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest431, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest432, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest433, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest434, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest435, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest436, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest437, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest438, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest439, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest440, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc521KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest441, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(nullptr, nullptr, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest442, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify((HcfVerify *)(&obj), nullptr, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest443, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest444, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    bool flag = verify->verify(verify, &input, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest445, TestSize.Level0)
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

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    bool flag = verify->verify(verify, &input, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest446, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, nullptr);

    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest447, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mockOut = {
        .data = nullptr,
        .len = 1
    };
    bool flag = verify->verify(verify, nullptr, &mockOut);

    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest448, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mockOut = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    bool flag = verify->verify(verify, nullptr, &mockOut);

    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HcfSignatureParams g_params = {
    .algo = HCF_ALG_ECC,
    .padding = HCF_ALG_NOPADDING,
    .md = HCF_OPENSSL_DIGEST_SHA256,
    .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
};

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest501, TestSize.Level0)
{
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest503, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit((HcfVerifySpi *)&obj, nullptr, ecc256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest504, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit(spiObj, nullptr, (HcfPubKey *)&obj);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest505, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

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

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest506, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = spiObj->engineUpdate((HcfVerifySpi *)&obj, &input);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest507, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest508, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = { .data = nullptr, .len = 0 };
    bool isOk = spiObj->engineVerify(nullptr, &input, &out);
    ASSERT_EQ(isOk, false);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest509, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    bool isOk = spiObj->engineVerify((HcfVerifySpi *)&obj, &input, &input);
    ASSERT_EQ(isOk, false);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest510, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest511, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiEcdsaCreate(&g_params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&obj);

    HcfObjDestroy(spiObj);
}

static bool GetSignTestData(HcfBlob *out)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC|SHA224", &sign);
    if (res != HCF_SUCCESS) {
        return false;
    }
    res = sign->init(sign, nullptr, CryptoEccNoLengthVerifyTest::ecc224KeyPair_->priKey);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(sign);
        return false;
    }
    res = sign->update(sign, &g_mockInput);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(sign);
        return false;
    }
    res = sign->sign(sign, &g_mockInput, out);
    HcfObjDestroy(sign);
    return res == HCF_SUCCESS;
}

static void MemoryMockTestFunc(uint32_t mallocCount, HcfBlob *out)
{
    for (int i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfVerify *verify = nullptr;
        int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, CryptoEccNoLengthVerifyTest::ecc224KeyPair_->pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        res = verify->update(verify, &g_mockInput);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        (void)verify->verify(verify, nullptr, out);
        HcfObjDestroy(verify);
    }
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest601, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    GetSignTestData(&out);
    StartRecordMallocNum();

    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);

    uint32_t mallocCount = GetMallocNum();
    MemoryMockTestFunc(mallocCount, &out);
    EndRecordMallocNum();
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfBlob *out)
{
    for (int i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfVerify *verify = nullptr;
        int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, CryptoEccNoLengthVerifyTest::ecc224KeyPair_->pubKey);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        res = verify->update(verify, &g_mockInput);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(verify);
            continue;
        }
        (void)verify->verify(verify, &g_mockInput, out);
        HcfObjDestroy(verify);
    }
}

HWTEST_F(CryptoEccNoLengthVerifyTest, CryptoEccNoLengthVerifyTest602, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    ASSERT_EQ(GetSignTestData(&out), true);
    StartRecordOpensslCallNum();

    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ECC|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);
    HcfObjDestroy(verify);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, &out);
    EndRecordOpensslCallNum();
}
}
