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
#include "cstring"
#include "securec.h"
#include "asy_key_generator.h"
#include "blob.h"
#include "signature.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

class RsaSignTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void RsaSignTest::SetUp() {}
void RsaSignTest::TearDown() {}
void RsaSignTest::SetUpTestCase() {}
void RsaSignTest::TearDownTestCase() {}

// HcfSignCreate correct_case
HWTEST_F(RsaSignTest, RsaSignTest100, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PKCS1|MD5", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(RsaSignTest, RsaSignTest110, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(RsaSignTest, RsaSignTest120, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(RsaSignTest, RsaSignTest130, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(RsaSignTest, RsaSignTest140, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA1|MGF1_SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(RsaSignTest, RsaSignTest150, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    OH_HCF_ObjDestroy(sign);
}

HWTEST_F(RsaSignTest, RsaSignTest160, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    OH_HCF_ObjDestroy(sign);
}

// HcfSignCreate Incorrect case
HWTEST_F(RsaSignTest, RsaSignTest200, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSSaa|SHA256|MGF1_SHA256", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(RsaSignTest, RsaSignTest210, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate(NULL, &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(RsaSignTest, RsaSignTest220, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256|123123123123123123212312312321"
        "123123123123213asdasdasdasdasdasdasdasdasdasdasdasdasdsasdasds12", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(RsaSignTest, RsaSignTest230, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(RsaSignTest, RsaSignTest240, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256asdasdas", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(RsaSignTest, RsaSignTest250, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256", &sign);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(sign, nullptr);
}

HWTEST_F(RsaSignTest, RsaSignTest260, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    res = HcfSignCreate("RSA1024|PSS|SHA256aa|MGF1_SHA256", NULL);
    EXPECT_NE(res, HCF_SUCCESS);
}

// correct case: sign and update
HWTEST_F(RsaSignTest, RsaSignTest300, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA768|PKCS1|SHA1", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest310, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest320, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest330, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA4096|PKCS1|SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest340, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA4096|PKCS1|SHA512", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest350, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA1024|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);

    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest360, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA2048|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    
    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest370, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA3072|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA3072|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    
    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest380, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA4096|PSS|SHA256|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    
    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest390, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA4096|PSS|SHA512|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    
    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest400, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA4096|PSS|SHA1|MGF1_SHA256", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    
    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaSignTest, RsaSignTest410, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa verify test.";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob verifyData = {.data = NULL, .len = 0};
    HcfSign *sign = NULL;
    res = HcfSignCreate("RSA4096|PSS|SHA256|MGF1_MD5", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, NULL, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    
    OH_HCF_ObjDestroy(sign);
    HcfFree(verifyData.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

