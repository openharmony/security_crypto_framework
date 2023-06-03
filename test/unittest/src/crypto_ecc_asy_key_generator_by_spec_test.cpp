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
#include "detailed_ecc_key_params.h"
#include "ecc_asy_key_generator_openssl.h"
#include "ecc_openssl_common.h"
#include "blob.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "params_parser.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccAsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoEccAsyKeyGeneratorBySpecTest::SetUpTestCase() {}
void CryptoEccAsyKeyGeneratorBySpecTest::TearDownTestCase() {}
void CryptoEccAsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoEccAsyKeyGeneratorBySpecTest::TearDown() {}

const int ECC224_PUB_KEY_LEN = 80;
const int ECC224_PRI_KEY_LEN = 44;

uint8_t g_mockEcc224PubKeyBlobData[ECC224_PUB_KEY_LEN] = { 48, 78, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1,
    6, 5, 43, 129, 4, 0, 33, 3, 58, 0, 4, 252, 171, 11, 115, 79, 252, 109, 120, 46, 97, 131, 145, 207, 141, 146,
    235, 133, 37, 218, 180, 8, 149, 47, 244, 137, 238, 207, 95, 153, 65, 250, 32, 77, 184, 249, 181, 172, 192, 2,
    99, 194, 170, 25, 44, 255, 87, 246, 42, 133, 83, 66, 197, 97, 95, 12, 84 };

uint8_t g_mockEcc224PriKeyBlobData[ECC224_PRI_KEY_LEN] = { 48, 42, 2, 1, 1, 4, 28, 250, 86, 6, 147, 222, 43,
    252, 139, 90, 139, 5, 33, 184, 230, 26, 68, 94, 57, 145, 229, 146, 49, 221, 119, 206, 32, 198, 19, 160, 7, 6,
    5, 43, 129, 4, 0, 33 };

HcfBlob g_mockEcc224PubKeyBlob = {
    .data = g_mockEcc224PubKeyBlobData,
    .len = ECC224_PUB_KEY_LEN
};

HcfBlob g_mockEcc224PriKeyBlob = {
    .data = g_mockEcc224PriKeyBlobData,
    .len = ECC224_PRI_KEY_LEN
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static const bool IS_BIG_ENDIAN = IsBigEndian();

static string g_eccAlgName = "ECC";
static string g_eccFieldType = "Fp";
static int32_t g_ecc224CorrectH = 1;
static int32_t g_ecc256CorrectH = 1;
static int32_t g_ecc384CorrectH = 1;
static int32_t g_ecc521CorrectH = 1;

HcfEccCommParamsSpec g_ecc224CommSpec;
HcfEccPubKeyParamsSpec g_ecc224PubKeySpec;
HcfEccPriKeyParamsSpec g_ecc224PriKeySpec;
HcfEccKeyPairParamsSpec g_ecc224KeyPairSpec;
HcfEccCommParamsSpec g_ecc256CommSpec;
HcfEccPubKeyParamsSpec g_ecc256PubKeySpec;
HcfEccPriKeyParamsSpec g_ecc256PriKeySpec;
HcfEccKeyPairParamsSpec g_ecc256KeyPairSpec;
HcfEccCommParamsSpec g_ecc384CommSpec;
HcfEccPubKeyParamsSpec g_ecc384PubKeySpec;
HcfEccPriKeyParamsSpec g_ecc384PriKeySpec;
HcfEccKeyPairParamsSpec g_ecc384KeyPairSpec;
HcfEccCommParamsSpec g_ecc521CommSpec;
HcfEccPubKeyParamsSpec g_ecc521PubKeySpec;
HcfEccPriKeyParamsSpec g_ecc521PriKeySpec;
HcfEccKeyPairParamsSpec g_ecc521KeyPairSpec;
HcfECFieldFp g_fieldFp;

static HcfResult ConstructEcc224CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc224CommSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccCommSpec->field))->p.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccCommSpec->field))->p.len = NID_secp224r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccCommSpec->a.len = NID_secp224r1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccCommSpec->b.len = NID_secp224r1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp224r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp224r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccCommSpec->n.len = NID_secp224r1_len;
    eccCommSpec->h = g_ecc224CorrectH;

    *spec = (HcfAsyKeyParamsSpec *)eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc224PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc224PubKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp224r1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_secp224r1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp224r1_len;
    eccPubKeySpec->base.h = g_ecc224CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp224r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp224r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPubKeySpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc224PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc224PriKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_secp224r1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_secp224r1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp224r1_len;
    eccPriKeySpec->base.h = g_ecc224CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp224r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPriKeySpec;
    return HCF_SUCCESS;
}

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

static HcfResult ConstructEcc256CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc256CommSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccCommSpec->field))->p.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    ((HcfECFieldFp *)(eccCommSpec->field))->p.len = NID_X9_62_prime256v1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccCommSpec->a.len = NID_X9_62_prime256v1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccCommSpec->b.len = NID_X9_62_prime256v1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccCommSpec->g.x.len = NID_X9_62_prime256v1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccCommSpec->g.y.len = NID_X9_62_prime256v1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccCommSpec->n.len = NID_X9_62_prime256v1_len;
    eccCommSpec->h = g_ecc256CorrectH;

    *spec = (HcfAsyKeyParamsSpec *)eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc256PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc256PubKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.h = g_ecc256CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkX : g_ecc256CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkY : g_ecc256CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_X9_62_prime256v1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPubKeySpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc256PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc256PriKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.h = g_ecc256CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigSk : g_ecc256CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_X9_62_prime256v1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPriKeySpec;
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

static HcfResult ConstructEcc384CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc384CommSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccCommSpec->field))->p.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    ((HcfECFieldFp *)(eccCommSpec->field))->p.len = NID_secp384r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccCommSpec->a.len = NID_secp384r1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccCommSpec->b.len = NID_secp384r1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp384r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp384r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccCommSpec->n.len = NID_secp384r1_len;
    eccCommSpec->h = g_ecc384CorrectH;

    *spec = (HcfAsyKeyParamsSpec *)eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc384PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc384PubKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = NID_secp384r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp384r1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_secp384r1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp384r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp384r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp384r1_len;
    eccPubKeySpec->base.h = g_ecc384CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkX : g_ecc384CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp384r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkY : g_ecc384CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp384r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPubKeySpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc384PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc384PriKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = NID_secp384r1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_secp384r1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_secp384r1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp384r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp384r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp384r1_len;
    eccPriKeySpec->base.h = g_ecc384CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigSk : g_ecc384CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp384r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPriKeySpec;
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

static HcfResult ConstructEcc521CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc521CommSpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccCommSpec->field))->p.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    ((HcfECFieldFp *)(eccCommSpec->field))->p.len = NID_secp521r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccCommSpec->a.len = NID_secp521r1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccCommSpec->b.len = NID_secp521r1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp521r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp521r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccCommSpec->n.len = NID_secp521r1_len;
    eccCommSpec->h = g_ecc521CorrectH;

    *spec = (HcfAsyKeyParamsSpec *)eccCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc521PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc521PubKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    ((HcfECFieldFp *)(eccPubKeySpec->base.field))->p.len = NID_secp521r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp521r1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_secp521r1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp521r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp521r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp521r1_len;
    eccPubKeySpec->base.h = g_ecc521CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkX : g_ecc521CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp521r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkY : g_ecc521CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp521r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPubKeySpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructEcc521PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc521PriKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    ((HcfECFieldFp *)(eccPriKeySpec->base.field))->p.len = NID_secp521r1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_secp521r1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_secp521r1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp521r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp521r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp521r1_len;
    eccPriKeySpec->base.h = g_ecc521CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigSk : g_ecc521CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp521r1_len;

    *spec = (HcfAsyKeyParamsSpec *)eccPriKeySpec;
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

/**
 * @tc.name: CryptoEccAsyKeyGeneratorBySpecTest.CryptoEccAsyKeyGeneratorBySpecTest001
 * @tc.desc: Verify that the creation of the ECC224 key pair generator is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEI
 */
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

/**
 * @tc.name: CryptoEccAsyKeyGeneratorBySpecTest.CryptoEccAsyKeyGeneratorBySpecTest001
 * @tc.desc: Verify that the creation of the ECC256 key pair generator is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEI
 */
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

/**
 * @tc.name: CryptoEccAsyKeyGeneratorBySpecTest.CryptoEccAsyKeyGeneratorBySpecTest001
 * @tc.desc: Verify that the creation of the ECC384 key pair generator is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEI
 */
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_9, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_10, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_11, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_12, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

/**
 * @tc.name: CryptoEccAsyKeyGeneratorBySpecTest.CryptoEccAsyKeyGeneratorBySpecTest001
 * @tc.desc: Verify that the creation of the ECC521 key pair generator is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEI
 */
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_13, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_14, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_15, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest001_16, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

// for test:Generator的异常用例
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest002, TestSize.Level0)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorBySpecCreate(nullptr, &generator);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(generator, nullptr);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

// for test:generator函数指针测试（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest101, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *className = generator->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest102_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest102_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest102_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest102_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
}

// for test:generator函数指针测试（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest103, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest104, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&g_obj);

    HcfObjDestroy(generator);
}

// for test:generator函数指针测试（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest105, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName(generator);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(generator);
}

// for test:generator函数指针测试（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest106, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest107, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgName((HcfAsyKeyGeneratorBySpec *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
}

// for test:测试keyPair生成函数（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest201_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest201_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest201_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest201_4, TestSize.Level0)
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

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest201_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest201_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

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

// for test:测试keyPair生成函数（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest202, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(nullptr, &keyPair);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest203, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair((HcfAsyKeyGeneratorBySpec *)&g_obj, &keyPair);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest204, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generateKeyPair(generator, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest301_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest301_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *className = pubKey->base.base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest301_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *className = priKey->base.base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest301_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest301_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *className = pubKey->base.base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest301_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *className = priKey->base.base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest302_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest302_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    pubKey->base.base.destroy((HcfObjectBase *)(&(pubKey->base.base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest302_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy((HcfObjectBase *)(&(priKey->base.base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest302_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest302_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    pubKey->base.base.destroy((HcfObjectBase *)(&(pubKey->base.base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest302_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->base.base.destroy((HcfObjectBase *)(&(priKey->base.base)));

    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest303, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest304, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest305_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest305_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest305_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest305_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest306, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest307, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest308_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest308_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *format = pubKey->base.getFormat(&(pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest308_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat(&(priKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest308_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest308_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *format = pubKey->base.getFormat(&(pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest308_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *format = priKey->base.getFormat(&(priKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest309, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(nullptr);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest310, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest311_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest311_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *algName = pubKey->base.getAlgorithm(&(pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest311_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm(&(priKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest311_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest311_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    const char *algName = pubKey->base.getAlgorithm(&(pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest311_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    const char *algName = priKey->base.getAlgorithm(&(priKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest312, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest313, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_9, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_10, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_11, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_12, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_13, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_14, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_15, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_16, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_17, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_18, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_19, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_20, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_21, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_22, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_23, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest314_24, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest315, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest316, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest317, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest318_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest318_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->clearMem(priKey);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest318_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest318_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    priKey->clearMem(priKey);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest319, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest320, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest321_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.base.getClass();

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest321_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.base.getClass();

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest322_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest322_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest323, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest324, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest325_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest325_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest326, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(nullptr);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest327, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest328_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(&keyPair->priKey->base);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest328_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(&keyPair->priKey->base);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（异常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest329, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest330, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:测试keyPair的函数指针（正常）
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc256KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc384KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest331_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc521KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest332, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest333, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest334, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_FP_P_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest401_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_A_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest402_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_B_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest403_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_G_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest404_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_G_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest405_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_N_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest406_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_H_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest407_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_FIELD_SIZE_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

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

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

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

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = pubKey->getAsyKeySpecInt(pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest408_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = priKey->getAsyKeySpecInt(priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_FIELD_TYPE_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

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

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

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

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest409_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = priKey->getAsyKeySpecString(priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:ECC_CURVE_NAME_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

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

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_7, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = pubKey->getAsyKeySpecString(pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest410_8, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

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

// for test:ECC_PK_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest411_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest411_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest411_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest411_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// for test:ECC_PK_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest412_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest412_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest412_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest412_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPubKey *pubKey = nullptr;
    res = generator->generatePubKey(generator, &pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = pubKey->getAsyKeySpecBigInteger(pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(generator);
}

// for test:ECC_SK_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest413_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest413_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest413_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest413_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generator);

    HcfPriKey *priKey = nullptr;
    res = generator->generatePriKey(generator, &priKey);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = priKey->getAsyKeySpecBigInteger(priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(priKey);
    HcfObjDestroy(generator);
}

// for test:测试Convert功能（新增的BySpec无此convert函数，但是需要测试旧版convert后密钥Key的get方法，因此先保留此部分，后续改动）
// for test:测试convertKey以后的函数指针功能
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest501, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest502, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_FP_P_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_A_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest503, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest504, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_A_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_B_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest505, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest506, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_B_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_G_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest507, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest508, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_X_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_G_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest509, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest510, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_G_Y_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_N_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest511, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest512, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_N_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_H_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest513, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest514, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_H_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_FIELD_SIZE_INT
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest515, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->pubKey->getAsyKeySpecInt(keyPair->pubKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest516, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    int retInt = 0;
    AsyKeySpecItem item = ECC_FIELD_SIZE_INT;

    res = keyPair->priKey->getAsyKeySpecInt(keyPair->priKey, item, &retInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retInt, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_FIELD_TYPE_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest517, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest518, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_FIELD_TYPE_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_CURVE_NAME_STR
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest519, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->pubKey->getAsyKeySpecString(keyPair->pubKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest520, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    char *retStr = nullptr;
    AsyKeySpecItem item = ECC_CURVE_NAME_STR;

    res = keyPair->priKey->getAsyKeySpecString(keyPair->priKey, item, &retStr);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retStr, nullptr);

    free(retStr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_PK_X_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest521, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_X_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_PK_Y_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest522, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_PK_Y_BN;

    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:ECC_SK_BN
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest523, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockEcc224PubKeyBlob, &g_mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    AsyKeySpecItem item = ECC_SK_BN;

    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, item, &retBigInt);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(retBigInt.data, nullptr);
    ASSERT_NE(retBigInt.len, 0);

    free(retBigInt.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// for test:generateKey after convertKey
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest524, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);
    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
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
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest525, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, nullptr, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_NE(outKeyPair->pubKey, nullptr);
    ASSERT_EQ(outKeyPair->priKey, nullptr);

    HcfBlob outPubKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->pubKey->base.getEncoded(&(outKeyPair->pubKey->base), &outPubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPubKeyBlob.data, nullptr);
    ASSERT_NE(outPubKeyBlob.len, 0);

    free(pubKeyBlob.data);
    free(outPubKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest526, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    int32_t res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfAsyKeyGeneratorBySpec *generatorBySpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &generatorBySpec);

    HcfKeyPair *keyPair = nullptr;
    res = generatorBySpec->generateKeyPair(generatorBySpec, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &priKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_EQ(outKeyPair->pubKey, nullptr);
    ASSERT_NE(outKeyPair->priKey, nullptr);

    HcfBlob outPriKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->priKey->base.getEncoded(&(outKeyPair->priKey->base), &outPriKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPriKeyBlob.data, nullptr);
    ASSERT_NE(outPriKeyBlob.len, 0);

    free(priKeyBlob.data);
    free(outPriKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorBySpec);
}

// for test:测试ecc的spi类
HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest601, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest602, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_MODE_NONE,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest603, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224CommParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest604, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224PubKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = nullptr;
    res = spiObj->engineGeneratePubKeyBySpec(spiObj, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest605, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224PriKeyParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfPriKey *priKey = nullptr;
    res = spiObj->engineGeneratePriKeyBySpec(spiObj, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest606, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructEcc224KeyPairParamsSpec(&paramSpec);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPairBySpec(spiObj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest607, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest608, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = 0,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);

    HcfObjDestroy(spiObj);
}

static HcfResult ConstructEcc521KeyPairParamsSpecByGet(HcfEccKeyPairParamsSpec *eccKeyPairSpec,
    HcfBigInteger *params, int h)
{
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.data = params[0].data;
    ((HcfECFieldFp *)(eccKeyPairSpec->base.field))->p.len = params[0].len;
    eccKeyPairSpec->base.a.data = params[1].data;
    eccKeyPairSpec->base.a.len = params[1].len;
    eccKeyPairSpec->base.b.data = params[2].data;
    eccKeyPairSpec->base.b.len = params[2].len;
    eccKeyPairSpec->base.g.x.data = params[3].data;
    eccKeyPairSpec->base.g.x.len = params[3].len;
    eccKeyPairSpec->base.g.y.data = params[4].data;
    eccKeyPairSpec->base.g.y.len = params[4].len;

    eccKeyPairSpec->base.n.data = params[5].data;
    eccKeyPairSpec->base.n.len = params[5].len;
    eccKeyPairSpec->base.h = h;
    eccKeyPairSpec->pk.x.data = params[6].data;
    eccKeyPairSpec->pk.x.len = params[6].len;
    eccKeyPairSpec->pk.y.data = params[7].data;
    eccKeyPairSpec->pk.y.len = params[7].len;

    eccKeyPairSpec->sk.data = params[8].data;
    eccKeyPairSpec->sk.len = params[8].len;
    return HCF_SUCCESS;
}

HWTEST_F(CryptoEccAsyKeyGeneratorBySpecTest, CryptoEccAsyKeyGeneratorBySpecTest609, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC521", &generator);

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
    res = ConstructEcc521KeyPairParamsSpecByGet(&eccKeyPairSpec, params, retH);
    HcfAsyKeyGeneratorBySpec *generatorSpec = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(reinterpret_cast<HcfAsyKeyParamsSpec *>(&eccKeyPairSpec), &generatorSpec);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generatorSpec, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generatorSpec->generateKeyPair(generatorSpec, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair, nullptr);

    HcfOpensslEccPubKey *eccPubKey = reinterpret_cast<HcfOpensslEccPubKey *>(dupKeyPair->pubKey);
    int32_t curveId = eccPubKey->curveId;
    EXPECT_EQ(curveId, NID_secp521r1) << "the curId is " << NID_secp521r1;
    for (HcfBigInteger tmp: params) {
        if (tmp.data != nullptr) {
            free(tmp.data);
        }
    }
    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
    HcfObjDestroy(generatorSpec);
}
}
