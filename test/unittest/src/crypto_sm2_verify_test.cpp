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
#include "sm2_openssl.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoSm2VerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static HcfKeyPair *sm2256KeyPair_;
};

HcfKeyPair *CryptoSm2VerifyTest::sm2256KeyPair_ = nullptr;

static const char *g_mockMessage = "hello world";
static HcfBlob g_mockInput = {
    .data = (uint8_t *)g_mockMessage,
    .len = 12
};

void CryptoSm2VerifyTest::SetUp() {}
void CryptoSm2VerifyTest::TearDown() {}

void CryptoSm2VerifyTest::SetUpTestCase()
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("SM2_256", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    sm2256KeyPair_ = keyPair;

    HcfObjDestroy(generator);
}

void CryptoSm2VerifyTest::TearDownTestCase()
{
    HcfObjDestroy(sm2256KeyPair_);
}

static const char *GetMockClass(void)
{
    return "HcfMock";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest001, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest002, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate(nullptr, &verify);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest003, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &verify);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest004, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM5|SM3", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest005, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM5", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest006, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|MD5", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest007, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2SM3", &verify);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(verify, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest008, TestSize.Level0)
{
    int32_t res = HcfVerifyCreate("SM2|SM3", nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest009, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *className = verify->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest010, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy((HcfObjectBase *)verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest011, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest012, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    verify->base.destroy(&obj);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest013, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(verify);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest014, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    const char *algName = verify->getAlgoName(nullptr);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest016, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest017, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(nullptr, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest019, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest020, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest022, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest023, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(nullptr, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest025, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest026, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest027, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = nullptr,
        .len = 1
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest028, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {
        .data = (uint8_t *)g_mockMessage,
        .len = 0
    };
    res = verify->update(verify, &input);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest029, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest030, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, &g_mockInput, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, &g_mockInput, &out);

    ASSERT_EQ(flag, true);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest031, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(nullptr, nullptr, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest032, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify((HcfVerify *)(&obj), nullptr, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest033, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, &out);

    ASSERT_EQ(flag, false);

    free(out.data);
    HcfObjDestroy(sign);
    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest034, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest035, TestSize.Level0)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(sign, nullptr);

    res = sign->init(sign, nullptr, sm2256KeyPair_->priKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = sign->update(sign, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob out = { .data = nullptr, .len = 0 };
    res = sign->sign(sign, nullptr, &out);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(out.data, nullptr);
    ASSERT_NE(out.len, (const unsigned int)0);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest036, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

    ASSERT_EQ(res, HCF_SUCCESS);

    res = verify->update(verify, &g_mockInput);

    ASSERT_EQ(res, HCF_SUCCESS);

    bool flag = verify->verify(verify, nullptr, nullptr);

    ASSERT_EQ(flag, false);

    HcfObjDestroy(verify);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest037, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest038, TestSize.Level0)
{
    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest039, TestSize.Level0)
{
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(nullptr, &spiObj);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(spiObj, nullptr);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest040, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    int32_t res = HcfVerifySpiSm2Create(&params, nullptr);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest043, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest045, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    res = spiObj->engineUpdate(spiObj, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest046, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest048, TestSize.Level0)
{
    HcfSignatureParams params = {
        .algo = HCF_ALG_SM2,
        .md = HCF_OPENSSL_DIGEST_SM3,
    };
    HcfVerifySpi *spiObj = nullptr;
    int32_t res = HcfVerifySpiSm2Create(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(nullptr);

    HcfObjDestroy(spiObj);
}

static bool GetSignTestData(HcfBlob *out)
{
    HcfSign *sign = nullptr;
    int32_t res = HcfSignCreate("SM2|SM3", &sign);
    if (res != HCF_SUCCESS) {
        return false;
    }
    res = sign->init(sign, nullptr, CryptoSm2VerifyTest::sm2256KeyPair_->priKey);
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
        int32_t res = HcfVerifyCreate("SM2|SM3", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, CryptoSm2VerifyTest::sm2256KeyPair_->pubKey);
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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest050, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    GetSignTestData(&out);
    StartRecordMallocNum();

    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

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
        int32_t res = HcfVerifyCreate("SM2|SM3", &verify);
        if (res != HCF_SUCCESS) {
            continue;
        }
        res = verify->init(verify, nullptr, CryptoSm2VerifyTest::sm2256KeyPair_->pubKey);
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

HWTEST_F(CryptoSm2VerifyTest, CryptoSm2VerifyTest051, TestSize.Level0)
{
    HcfBlob out = { .data = nullptr, .len = 0 };
    ASSERT_EQ(GetSignTestData(&out), true);
    StartRecordOpensslCallNum();

    HcfVerify *verify = nullptr;
    int32_t res = HcfVerifyCreate("SM2|SM3", &verify);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(verify, nullptr);

    res = verify->init(verify, nullptr, sm2256KeyPair_->pubKey);

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
