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
#include <cstring>

#include "asy_key_generator.h"
#include "blob.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"

using namespace std;
using namespace testing::ext;

static const char *GetMockClass(void)
{
    return "HcfMock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = NULL
};

class EccSignTest : public testing::Test {
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

HcfKeyPair *EccSignTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *EccSignTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *EccSignTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *EccSignTest::ecc512KeyPair_ = nullptr;

static const char *g_mockMessage = "hello world";
static HcfBlob mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

void EccSignTest::SetUp() {}
void EccSignTest::TearDown() {}

void EccSignTest::SetUpTestCase()
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

void EccSignTest::TearDownTestCase()
{
    OH_HCF_ObjDestroy(ecc224KeyPair_);
    OH_HCF_ObjDestroy(ecc256KeyPair_);
    OH_HCF_ObjDestroy(ecc384KeyPair_);
    OH_HCF_ObjDestroy(ecc512KeyPair_);
}

HWTEST_F(EccSignTest, EccSignTest001, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest002, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest003, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest004, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest005, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest006, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest007, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest008, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest009, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest010, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest011, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest012, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest013, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest014, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest015, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest016, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest017, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest018, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest019, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest020, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest021, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate(NULL, &sign);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(EccSignTest, EccSignTest022, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &sign);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(EccSignTest, EccSignTest023, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC257|SHA256", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(EccSignTest, EccSignTest024, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA257", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(EccSignTest, EccSignTest025, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|MD5", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(EccSignTest, EccSignTest026, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256SHA256", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(EccSignTest, EccSignTest027, TestSize.Level0)
{
    int32_t res = HcfSignCreate("ECC256|SHA256", NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(EccSignTest, EccSignTest101, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *className = sign->base.getClass();

    ASSERT_NE(className, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest102, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(EccSignTest, EccSignTest103, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(NULL);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest104, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&obj);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest105, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);

    ASSERT_NE(algName, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest106, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(NULL);

    ASSERT_EQ(algName, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest107, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName((HcfSign *)(&obj));

    ASSERT_EQ(algName, nullptr);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest201, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest202, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest203, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest204, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest205, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest206, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest207, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest208, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest209, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest210, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest211, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest212, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest213, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest214, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest215, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest216, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest217, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest218, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest219, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest220, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest221, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(NULL, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest222, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init((HcfSign *)(&obj), NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest223, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest224, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, (HcfPriKey *)(&obj));

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest301, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest302, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest303, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest304, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest305, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest306, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest307, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest308, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest309, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest310, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest311, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest312, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest313, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest314, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest315, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest316, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest317, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest318, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest319, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest320, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest321, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(NULL, &mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest322, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update((HcfSign *)(&obj), &mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest323, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest324, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = NULL,
        .len = 1
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest325, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest401, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest402, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest403, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest404, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest405, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest406, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest407, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest408, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest409, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest410, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest411, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest412, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest413, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest414, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest415, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest416, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest417, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest418, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest419, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest420, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest421, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest422, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest423, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest424, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest425, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest426, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest427, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest428, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest429, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest430, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest431, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest432, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest433, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest434, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest435, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest436, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest437, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest438, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest439, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest440, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC512|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc512KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest441, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(NULL, NULL, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest442, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign((HcfSign *)(&obj), NULL, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest443, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest444, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = NULL,
        .len = 1
    };
    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest445, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest446, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->sign(sign, NULL, NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest447, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out2 = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out2);

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->init(verify, NULL, ecc256KeyPair_->pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);

    verify->update(verify, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);
    ASSERT_EQ(flag, true);

    verify->update(verify, &input);
    ASSERT_EQ(res, HCF_SUCCESS);

    flag = verify->verify(verify, NULL, &out2);
    ASSERT_EQ(flag, true);

    free(out.data);
    free(out2.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccSignTest, EccSignTest448, TestSize.Level0)
{
    HcfSign *sign = NULL;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, NULL, ecc256KeyPair_->priKey);

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

    HcfBlob out2 = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out2);

    free(out2.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest927, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_HCF_ObjDestroy(generator);

    HcfSign *sign = NULL;
    res = HcfSignCreate("ECC256|SHA256", &sign);
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

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(EccSignTest, EccSignTest928, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    OH_HCF_ObjDestroy(generator);

    HcfSign *sign = NULL;
    res = HcfSignCreate("ECC224|SHA256", &sign);
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

    HcfBlob out = {
        .data = NULL,
        .len = 0
    };
    res = sign->sign(sign, NULL, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
}
