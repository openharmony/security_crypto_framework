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
#include "key_agreement.h"

using namespace std;
using namespace testing::ext;

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = NULL
};

class KeyAgreementTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *ecc224KeyPair_;
    static HcfKeyPair *ecc256KeyPair_;
    static HcfKeyPair *ecc384KeyPair_;
    static HcfKeyPair *ecc512KeyPair_;
};

HcfKeyPair *KeyAgreementTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *KeyAgreementTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *KeyAgreementTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *KeyAgreementTest::ecc512KeyPair_ = nullptr;

void KeyAgreementTest::SetUp() {}
void KeyAgreementTest::TearDown() {}

void KeyAgreementTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc224KeyPair_ = keyPair;

    OH_HCF_ObjDestroy(generator);

    HcfAsyKeyGenerator *generator2 = NULL;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator2, nullptr);

    HcfKeyPair *keyPair2 = NULL;
    res = generator2->generateKeyPair(generator2, NULL, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    ecc256KeyPair_ = keyPair2;

    OH_HCF_ObjDestroy(generator2);

    HcfAsyKeyGenerator *generator3 = NULL;
    res = HcfAsyKeyGeneratorCreate("ECC384", &generator3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator3, nullptr);

    HcfKeyPair *keyPair3 = NULL;
    res = generator3->generateKeyPair(generator3, NULL, &keyPair3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair3, nullptr);

    ecc384KeyPair_ = keyPair3;

    OH_HCF_ObjDestroy(generator3);

    HcfAsyKeyGenerator *generator4 = NULL;
    res = HcfAsyKeyGeneratorCreate("ECC512", &generator4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator4, nullptr);

    HcfKeyPair *keyPair4 = NULL;
    res = generator4->generateKeyPair(generator4, NULL, &keyPair4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair4, nullptr);

    ecc512KeyPair_ = keyPair4;

    OH_HCF_ObjDestroy(generator4);
}

void KeyAgreementTest::TearDownTestCase()
{
    OH_HCF_ObjDestroy(ecc224KeyPair_);
    OH_HCF_ObjDestroy(ecc256KeyPair_);
    OH_HCF_ObjDestroy(ecc384KeyPair_);
    OH_HCF_ObjDestroy(ecc512KeyPair_);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest001, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC224", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest002, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest003, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC384", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest004, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC512", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest005, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate(NULL, &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest006, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest007, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC257", &keyAgreement);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyAgreement, nullptr);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest008, TestSize.Level0)
{
    int32_t res = HcfKeyAgreementCreate("ECC256", NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest101, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *className = keyAgreement->base.getClass();

    ASSERT_NE(className, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest102, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy((HcfObjectBase *)keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest103, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(NULL);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest104, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    keyAgreement->base.destroy(&obj);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest105, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(keyAgreement);

    ASSERT_NE(algName, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest106, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName(NULL);

    ASSERT_EQ(algName, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest107, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    const char *algName = keyAgreement->getAlgoName((HcfKeyAgreement *)(&obj));

    ASSERT_EQ(algName, nullptr);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest201, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC224", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(keyAgreement, ecc224KeyPair_->priKey, ecc224KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest202, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest203, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC384", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(keyAgreement, ecc384KeyPair_->priKey, ecc384KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest204, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC512", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(keyAgreement, ecc512KeyPair_->priKey, ecc512KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest205, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(NULL, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest206, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret((HcfKeyAgreement *)(&obj), ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest207, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(keyAgreement, (HcfPriKey *)(&obj), ecc256KeyPair_->pubKey, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest208, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, (HcfPubKey *)(&obj), &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest209, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = keyAgreement->generateSecret(keyAgreement, NULL, NULL, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(out.data, nullptr);
    ASSERT_EQ(out.len, 0);

    OH_HCF_ObjDestroy(keyAgreement);
}

HWTEST_F(KeyAgreementTest, KeyAgreementTest210, TestSize.Level0)
{
    HcfKeyAgreement *keyAgreement = NULL;
    int32_t res = HcfKeyAgreementCreate("ECC256", &keyAgreement);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyAgreement, nullptr);

    res = keyAgreement->generateSecret(keyAgreement, ecc256KeyPair_->priKey, ecc256KeyPair_->pubKey, NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(keyAgreement);
}
