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

class EccVerifyTest : public testing::Test {
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

HcfKeyPair *EccVerifyTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *EccVerifyTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *EccVerifyTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *EccVerifyTest::ecc512KeyPair_ = nullptr;

static const char *g_mockMessage = "hello world";
static HcfBlob mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

void EccVerifyTest::SetUp() {}
void EccVerifyTest::TearDown() {}

void EccVerifyTest::SetUpTestCase()
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

void EccVerifyTest::TearDownTestCase()
{
    OH_HCF_ObjDestroy(ecc224KeyPair_);
    OH_HCF_ObjDestroy(ecc256KeyPair_);
    OH_HCF_ObjDestroy(ecc384KeyPair_);
    OH_HCF_ObjDestroy(ecc512KeyPair_);
}

HWTEST_F(EccVerifyTest, EccVerifyTest001, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest002, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest003, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest004, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest005, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest006, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest007, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest008, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest009, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest010, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest011, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest012, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest013, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest014, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest015, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest016, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest017, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest018, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest019, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest020, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest021, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate(NULL, &verify);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(EccVerifyTest, EccVerifyTest022, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &verify);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(EccVerifyTest, EccVerifyTest023, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC257|SHA256", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(EccVerifyTest, EccVerifyTest024, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA257", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(EccVerifyTest, EccVerifyTest025, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|MD5", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(EccVerifyTest, EccVerifyTest026, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256SHA256", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(EccVerifyTest, EccVerifyTest027, TestSize.Level0)
{
    int32_t res = HcfVerifyCreate("ECC256|SHA256", NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(EccVerifyTest, EccVerifyTest101, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *className = verify->base.getClass();

    ASSERT_NE(className, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest102, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy((HcfObjectBase *)verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest103, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(NULL);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest104, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(&obj);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest105, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(verify);

    ASSERT_NE(algName, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest106, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(NULL);

    ASSERT_EQ(algName, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest107, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName((HcfVerify *)(&obj));

    ASSERT_EQ(algName, nullptr);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest201, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest202, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest203, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest204, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest205, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest206, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest207, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest208, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest209, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest210, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest211, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest212, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest213, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest214, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest215, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest216, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest217, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest218, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest219, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest220, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest221, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(NULL, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest222, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init((HcfVerify *)(&obj), NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest223, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest224, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, (HcfPubKey *)(&obj));

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest301, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest302, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest303, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest304, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest305, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC224|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest306, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest307, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest308, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest309, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest310, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest311, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest312, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest313, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest314, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest315, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC384|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest316, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest317, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest318, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest319, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest320, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC512|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest321, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(NULL, &mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest322, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update((HcfVerify *)(&obj), &mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest323, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest324, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = NULL,
        .len = 1
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest325, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest401, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest402, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest403, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest404, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest405, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest406, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest407, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest408, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest409, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest410, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest411, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest412, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest413, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest414, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest415, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest416, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest417, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest418, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest419, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest420, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest421, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest422, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest423, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest424, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest425, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC224|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc224KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest426, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest427, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest428, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest429, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest430, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest431, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest432, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest433, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest434, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest435, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC384|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc384KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest436, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA1", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest437, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA224", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest438, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest439, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA384", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest440, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC512|SHA512", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc512KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest441, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(NULL, NULL, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest442, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify((HcfVerify *)(&obj), NULL, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest443, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest444, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = NULL,
        .len = 1
    };
    bool flag = verify->verify(verify, &input, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest445, TestSize.Level0)
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

    HcfVerify *verify = NULL;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    bool flag = verify->verify(verify, &input, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    OH_HCF_ObjDestroy(sign);
    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest446, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, NULL, NULL);

    ASSERT_EQ(flag, false);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest447, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mockOut = {
        .data = NULL,
        .len = 1
    };
    bool flag = verify->verify(verify, NULL, &mockOut);

    ASSERT_EQ(flag, false);

    OH_HCF_ObjDestroy(verify);
}

HWTEST_F(EccVerifyTest, EccVerifyTest448, TestSize.Level0)
{
    HcfVerify *verify = NULL;
    int32_t res = HcfVerifyCreate("ECC256|SHA256", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, NULL, ecc256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob mockOut = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    bool flag = verify->verify(verify, NULL, &mockOut);

    ASSERT_EQ(flag, false);

    OH_HCF_ObjDestroy(verify);
}
