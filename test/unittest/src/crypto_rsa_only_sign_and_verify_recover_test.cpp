/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "openssl_common.h"
#include "signature.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRsaOnlySignAndVerifyRecoverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRsaOnlySignAndVerifyRecoverTest::SetUp() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::TearDown() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::SetUpTestCase() {}
void CryptoRsaOnlySignAndVerifyRecoverTest::TearDownTestCase() {}

static void RsaOnlySignCreateTest(const char *algoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(sign, nullptr);
    EXPECT_NE(sign->base.getClass(), nullptr);
    EXPECT_NE(sign->base.destroy, nullptr);
    EXPECT_NE(sign->init, nullptr);
    EXPECT_NE(sign->update, nullptr);
    EXPECT_NE(sign->sign, nullptr);
    HcfObjDestroy(sign);
}

static void RsaOnlySignCreateIncorrectTest(const char *algoName, HcfResult ret)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, ret);
    EXPECT_EQ(sign, nullptr);
}

static void RsaOnlySignTest(const char *keyAlgoName, const char *algoName, const char *plan)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen(plan)};
    HcfBlob verifyData = {.data = nullptr, .len = 0};
    HcfSign *sign = nullptr;
    res = HcfSignCreate(algoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, &input, &verifyData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(sign);
    HcfFree(verifyData.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// HcfSignCreate OnlySign correct_case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest100, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA1024|PKCS1|MD5|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest110, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA1|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest120, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA256|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest130, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA1024|PKCS1|SHA512|OnlySign");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest140, TestSize.Level0)
{
    RsaOnlySignCreateTest("RSA1024|PKCS1|NoHash|OnlySign");
}

// HcfSignCreate OnlySign Incorrect case
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest200, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024aa|PKCS1|SHA256|OnlySign", HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest210, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1aa|SHA256|OnlySign", HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest220, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256|OnlySignaa", HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest230, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256aa|OnlySign", HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest240, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024|PKCS1|SHA256|123123123123123123212312312321"
        "123123123123213asdasdasdasdasdasdasdasdasdasdasdasdasdsasdasds12|OnlySign", HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest250, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("RSA1024|PSS|SHA256|MGF1_SHA256|OnlySign", HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest260, TestSize.Level0)
{
    RsaOnlySignCreateIncorrectTest("DSA1024|PKCS1|SHA256|OnlySign", HCF_NOT_SUPPORT);
}

// incorrect case : OnlySign init signer with nullptr private key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

// incorrect case : OnlySign init signer with public Key.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA768|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPubKey *pubKey = keyPair->pubKey;

    res = sign->init(sign, nullptr, (HcfPriKey *)pubKey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

// incorrect case : OnlySign use update function.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest290, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &input);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// incorrect case : use OnlySign sign function before intialize.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest291, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &input, &signatureData);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
}

// incorrect case : OnlySign sign with nullptr outputBlob.
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest292, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA1024|PKCS1|NoHash|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->sign(sign, nullptr, nullptr);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

// correct case: OnlySign init and sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest300, TestSize.Level0)
{
    RsaOnlySignTest("RSA512|PRIMES_2", "RSA512|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA2048|PRIMES_2", "RSA2048|PKCS1|NoHash|OnlySign", "01234567890123456789");
    RsaOnlySignTest("RSA4096|PRIMES_2", "RSA4096|PKCS1|NoHash|OnlySign", "01234567890123456789");
}

HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest310, TestSize.Level0)
{
    RsaOnlySignTest("RSA1024|PRIMES_2", "RSA1024|NoPadding|NoHash|OnlySign",
        "0123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567");
}

// incorrect case: OnlySign double init sign
HWTEST_F(CryptoRsaOnlySignAndVerifyRecoverTest, CryptoRsaOnlySignTest500, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_2", &generator);
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfPriKey *prikey = keyPair->priKey;
    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA4096|PKCS1|SHA512|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, prikey);
    EXPECT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
