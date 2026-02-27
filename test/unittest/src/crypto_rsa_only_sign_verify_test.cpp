/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include "md.h"
#include "memory.h"
#include "securec.h"
#include "signature.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "mock.h"
#include "detailed_rsa_key_params.h"
#include "openssl_common.h"
#include <string>

using namespace std;
using namespace testing::ext;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

namespace {
class CryptoRSAOnlySignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
public:
 	std::shared_ptr<HcfMock> mock_ = std::make_shared<HcfMock>();
};

void CryptoRSAOnlySignVerifyTest::SetUp()
{
    SetMock(mock_.get());
    // set default call function
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillRepeatedly(Invoke(__real_HcfMalloc));
    EXPECT_CALL(*mock_, OpensslEvpMdCtxSize(_)).WillRepeatedly(Invoke(__real_OpensslEvpMdCtxSize));
    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _)).WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    EXPECT_CALL(*mock_, HcfIsStrValid(_, _)).WillRepeatedly(Invoke(__real_HcfIsStrValid));
    EXPECT_CALL(*mock_, OpensslEvpDigestInitEx(_, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpDigestInitEx));
    EXPECT_CALL(*mock_, OpensslEvpPkeyNew()).WillRepeatedly(Invoke(__real_OpensslEvpPkeyNew));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxNewFromPkey(_, _, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxNewFromPkey));
    EXPECT_CALL(*mock_, OpensslEvpPkeySignInit(_)).WillRepeatedly(Invoke(__real_OpensslEvpPkeySignInit));
    EXPECT_CALL(*mock_, OpensslEvpPkeySign(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpPkeySign));
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerifyInit(_)).WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerifyInit));
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerify(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerify));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetSignatureMd(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetSignatureMd));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetRsaPadding(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetRsaPadding));
}

void CryptoRSAOnlySignVerifyTest::TearDown()
{
    ResetMock();
}

void CryptoRSAOnlySignVerifyTest::SetUpTestCase() {}
void CryptoRSAOnlySignVerifyTest::TearDownTestCase() {}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest001, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    // Test SetOnlyVerifyParams with InitRsaEvpKey failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyNew())
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyNew));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyCtxNewFromPkey failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxNewFromPkey(_, _, _))
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxNewFromPkey));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyVerifyInit failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerifyInit(_))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerifyInit));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest002, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyCtxSetSignatureMd failure
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetSignatureMd(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetSignatureMd));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    // Test SetOnlyVerifyParams with OpensslEvpPkeyCtxSetRsaPadding failure
    verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetRsaPadding(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetRsaPadding));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(verify);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest003, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test EngineOnlyVerifyWithData with OpensslEvpPkeyVerify failure
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    EXPECT_CALL(*mock_, OpensslEvpPkeyVerify(_, _, _, _, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerify));
    bool result = verify->verify(verify, &digest, &signatureData);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest004, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with data = NULL
    bool result = verify->verify(verify, nullptr, &signatureData);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest005, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with data->len = 0
    HcfBlob emptyData = {.data = digest.data, .len = 0};
    bool result = verify->verify(verify, &emptyData, &signatureData);
    EXPECT_EQ(result, false);

    // Test with data->data = NULL
    HcfBlob nullDataPtr = {.data = nullptr, .len = digest.len};
    result = verify->verify(verify, &nullDataPtr, &signatureData);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest006, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("RSA2048|PKCS1|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with signatureData = NULL
    bool result = verify->verify(verify, &digest, nullptr);
    EXPECT_EQ(result, false);

    // Test with signatureData->data = NULL
    HcfBlob nullSigPtr = {.data = nullptr, .len = signatureData.len};
    result = verify->verify(verify, &digest, &nullSigPtr);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(sign);
    HcfBlobDataClearAndFree(&signatureData);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoRSAOnlySignVerifyTest, CryptoRSAOnlySignVerifyTest007, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("RSA2048", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is rsa only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("RSA2048|PKCS1|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test with signatureData = NULL
    bool result = verify->verify(verify, &digest, nullptr);
    EXPECT_EQ(result, false);

    // Test with signatureData->data = NULL
    HcfBlob nullSigPtr = {.data = nullptr, .len = 32};
    result = verify->verify(verify, &digest, &nullSigPtr);
    EXPECT_EQ(result, false);

    HcfObjDestroy(verify);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}

