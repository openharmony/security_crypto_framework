/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccSignTest : public testing::Test {
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

HcfKeyPair *CryptoEccSignTest::ecc224KeyPair_ = nullptr;
HcfKeyPair *CryptoEccSignTest::ecc256KeyPair_ = nullptr;
HcfKeyPair *CryptoEccSignTest::ecc384KeyPair_ = nullptr;
HcfKeyPair *CryptoEccSignTest::ecc521KeyPair_ = nullptr;

static const char *MOCK_MESSAGE = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)MOCK_MESSAGE,
    .len = 12
};

void CryptoEccSignTest::SetUp() {}
void CryptoEccSignTest::TearDown() {}

void CryptoEccSignTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    ecc224KeyPair_ = keyPair;

    HcfObjDestroy(generator);

    HcfAsyKeyGenerator *generator2 = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator2, nullptr);

    HcfKeyPair *keyPair2 = nullptr;
    res = generator2->generateKeyPair(generator2, nullptr, &keyPair2);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair2, nullptr);

    ecc256KeyPair_ = keyPair2;

    HcfObjDestroy(generator2);

    HcfAsyKeyGenerator *generator3 = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC384", &generator3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator3, nullptr);

    HcfKeyPair *keyPair3 = nullptr;
    res = generator3->generateKeyPair(generator3, nullptr, &keyPair3);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair3, nullptr);

    ecc384KeyPair_ = keyPair3;

    HcfObjDestroy(generator3);

    HcfAsyKeyGenerator *generator4 = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC521", &generator4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator4, nullptr);

    HcfKeyPair *keyPair4 = nullptr;
    res = generator4->generateKeyPair(generator4, nullptr, &keyPair4);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair4, nullptr);

    ecc521KeyPair_ = keyPair4;

    HcfObjDestroy(generator4);
}

void CryptoEccSignTest::TearDownTestCase()
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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest001, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest002, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest003, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest004, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest005, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest006, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest007, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest008, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest009, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest010, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest011, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest012, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest013, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest014, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest015, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest016, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest017, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest018, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest019, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest020, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest021, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate(nullptr, &sign);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest022, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &sign);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest023, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC257|SHA256", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest024, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA257", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest025, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|MD5", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest026, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256SHA256", &sign);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(sign, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest027, TestSize.Level0)
{
    int32_t res = HcfSignCreate("ECC256|SHA256", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest101, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *className = sign->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest102, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy((HcfObjectBase *)sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest103, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest104, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    sign->base.destroy(&obj);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest105, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(sign);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest106, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest107, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    const char *algName = sign->getAlgoName((HcfSign *)(&obj));

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest201, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest202, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest203, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest204, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest205, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest206, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest207, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest208, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest209, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest210, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest211, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest212, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest213, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest214, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest215, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest216, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest217, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest218, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest219, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest220, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest221, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(nullptr, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest222, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init((HcfSign *)(&obj), nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest223, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest224, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest225, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, (HcfPriKey *)(&obj));

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest301, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest302, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest303, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest304, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest305, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest306, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest307, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest308, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest309, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest310, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest311, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest312, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest313, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest314, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest315, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest316, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest317, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest318, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest319, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest320, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest321, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(nullptr, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest322, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update((HcfSign *)(&obj), &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest323, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest324, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest325, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest326, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)MOCK_MESSAGE,
        .len = 0
    };
    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest401, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest402, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest403, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest404, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest405, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest406, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest407, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest408, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest409, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest410, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest411, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest412, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest413, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest414, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest415, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest416, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest417, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest418, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest419, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest420, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest421, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest422, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest423, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest424, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest425, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC224|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc224KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest426, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest427, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest428, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest429, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest430, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest431, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest432, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest433, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest434, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest435, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC384|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc384KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest436, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA1", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest437, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA224", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest438, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest439, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA384", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest440, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC521|SHA512", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc521KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest441, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(nullptr, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest442, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign((HcfSign *)(&obj), nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest443, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest444, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

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

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest445, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, ecc256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)MOCK_MESSAGE,
        .len = 0
    };
    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest446, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest447, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

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

    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    res = sign->update(sign, &input);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out2 = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out2);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC256|SHA256", &verify);
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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest448, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("ECC256|SHA256", &sign);

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

    HcfBlob out2 = {
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out2);

    free(out2.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest927, TestSize.Level0)
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
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, &input, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest928, TestSize.Level0)
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
        .data = nullptr,
        .len = 0
    };
    res = sign->sign(sign, nullptr, &out);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    free(out.data);
    HcfObjDestroy(sign);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1001, TestSize.Level0)
{
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(nullptr, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1002, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    int32_t res = HcfSignSpiEcdsaCreate(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1003, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_NOPADDING,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1004, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit((HcfSignSpi *)&obj, nullptr, ecc256KeyPair_->priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1005, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineInit(spiObj, nullptr, (HcfPriKey *)&obj);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1006, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1007, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1008, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1009, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    const char *message = "hello world";
    HcfBlob input = {
        .data = (uint8_t *)message,
        .len = 12
    };
    HcfBlob out = {
        .data = nullptr,
        .len = 0
    };
    res = spiObj->engineSign((HcfSignSpi *)&obj, &input, &out);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1010, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1011, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_ECC,
        .keyLen = HCF_ALG_ECC_256,
        .padding = HCF_ALG_NOPADDING,
        .md = HCF_OPENSSL_DIGEST_SHA256,
        .mgf1md = HCF_OPENSSL_DIGEST_SHA256,
    };
    HcfSignSpi *spiObj = nullptr;
    int32_t res = HcfSignSpiEcdsaCreate(&params, &spiObj);

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
        res = HcfSignCreate("ECC224|SHA256", &sign);
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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1101, TestSize.Level0)
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
        .data = nullptr,
        .len = 0
    };
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
        res = HcfSignCreate("ECC224|SHA256", &sign);
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

HWTEST_F(CryptoEccSignTest, CryptoEccSignTest1102, TestSize.Level0)
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
        .data = nullptr,
        .len = 0
    };
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
