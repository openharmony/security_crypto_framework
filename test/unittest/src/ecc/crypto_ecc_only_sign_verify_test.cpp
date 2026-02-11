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

using namespace std;
using namespace testing::ext;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Invoke;
using ::testing::Return;

namespace {
class CryptoEccOnlySignVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
public:
 	std::shared_ptr<HcfMock> mock_ = std::make_shared<HcfMock>();
};

void CryptoEccOnlySignVerifyTest::SetUp()
{
    SetMock(mock_.get());
    // set default call function
    EXPECT_CALL(*mock_, OpensslEcKeyDup(_)).WillRepeatedly(Invoke(__real_OpensslEcKeyDup));
    EXPECT_CALL(*mock_, HcfMalloc(_, _)).WillRepeatedly(Invoke(__real_HcfMalloc));
    EXPECT_CALL(*mock_, OpensslEvpMdCtxSize(_)).WillRepeatedly(Invoke(__real_OpensslEvpMdCtxSize));
    EXPECT_CALL(*mock_, HcfIsClassMatch(_, _)).WillRepeatedly(Invoke(__real_HcfIsClassMatch));
    EXPECT_CALL(*mock_, HcfIsStrValid(_, _)).WillRepeatedly(Invoke(__real_HcfIsStrValid));
    EXPECT_CALL(*mock_, OpensslEvpDigestInitEx(_, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpDigestInitEx));
    EXPECT_CALL(*mock_, OpensslEvpPkeyNew()).WillRepeatedly(Invoke(__real_OpensslEvpPkeyNew));
    EXPECT_CALL(*mock_, OpensslEvpPkeyAssignEcKey(_, _)).WillRepeatedly(Invoke(__real_OpensslEvpPkeyAssignEcKey));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxNewFromPkey(_, _, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxNewFromPkey));
    EXPECT_CALL(*mock_, OpensslEvpPkeySignInit(_)).WillRepeatedly(Invoke(__real_OpensslEvpPkeySignInit));
    EXPECT_CALL(*mock_, OpensslEvpPkeySign(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpPkeySign));
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerifyInit(_)).WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerifyInit));
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerify(_, _, _, _, _)).WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerify));
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetSignatureMd(_, _))
        .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetSignatureMd));
}

void CryptoEccOnlySignVerifyTest::TearDown()
{
    ResetMock();
}

void CryptoEccOnlySignVerifyTest::SetUpTestCase() {}
void CryptoEccOnlySignVerifyTest::TearDownTestCase() {}

static void EccOnlySignVerifyDigestTest(const char *keyAlgoName, const char *mdName,
    const char *signAlgoName, const char *verifyAlgoName)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate(keyAlgoName, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is ecc only sign verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate(mdName, &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate(signAlgoName, &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->update(sign, &digest);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate(verifyAlgoName, &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->update(verify, &digest);
    EXPECT_EQ(res, HCF_ERR_INVALID_CALL);
    bool result = verify->verify(verify, &digest, &signatureData);
    EXPECT_EQ(result, true);

    HcfObjDestroy(verify);
    HcfObjDestroy(mdObj);
    HcfFree(signatureData.data);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest001, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC224", "SHA1",
        "ECC224|SHA1|OnlySign", "ECC224|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC224", "SHA224",
        "ECC224|SHA224|OnlySign", "ECC224|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC224", "SHA256",
        "ECC224|SHA256|OnlySign", "ECC224|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC224", "SHA384",
        "ECC224|SHA384|OnlySign", "ECC224|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC224", "SHA512",
        "ECC224|SHA512|OnlySign", "ECC224|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest002, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC256", "SHA1",
        "ECC256|SHA1|OnlySign", "ECC256|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC256", "SHA224",
        "ECC256|SHA224|OnlySign", "ECC256|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC256", "SHA256",
        "ECC256|SHA256|OnlySign", "ECC256|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC256", "SHA384",
        "ECC256|SHA384|OnlySign", "ECC256|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC256", "SHA512",
        "ECC256|SHA512|OnlySign", "ECC256|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest003, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC384", "SHA1",
        "ECC384|SHA1|OnlySign", "ECC384|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC384", "SHA224",
        "ECC384|SHA224|OnlySign", "ECC384|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC384", "SHA256",
        "ECC384|SHA256|OnlySign", "ECC384|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC384", "SHA384",
        "ECC384|SHA384|OnlySign", "ECC384|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC384", "SHA512",
        "ECC384|SHA512|OnlySign", "ECC384|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest004, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC521", "SHA1",
        "ECC521|SHA1|OnlySign", "ECC521|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC521", "SHA224",
        "ECC521|SHA224|OnlySign", "ECC521|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC521", "SHA256",
        "ECC521|SHA256|OnlySign", "ECC521|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC521", "SHA384",
        "ECC521|SHA384|OnlySign", "ECC521|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC521", "SHA512",
        "ECC521|SHA512|OnlySign", "ECC521|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest005, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160r1", "SHA1",
        "ECC_BrainPoolP160r1|SHA1|OnlySign", "ECC_BrainPoolP160r1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160r1", "SHA224",
        "ECC_BrainPoolP160r1|SHA224|OnlySign", "ECC_BrainPoolP160r1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160r1", "SHA256",
        "ECC_BrainPoolP160r1|SHA256|OnlySign", "ECC_BrainPoolP160r1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160r1", "SHA384",
        "ECC_BrainPoolP160r1|SHA384|OnlySign", "ECC_BrainPoolP160r1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160r1", "SHA512",
        "ECC_BrainPoolP160r1|SHA512|OnlySign", "ECC_BrainPoolP160r1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest006, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160t1", "SHA1",
        "ECC_BrainPoolP160t1|SHA1|OnlySign", "ECC_BrainPoolP160t1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160t1", "SHA224",
        "ECC_BrainPoolP160t1|SHA224|OnlySign", "ECC_BrainPoolP160t1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160t1", "SHA256",
        "ECC_BrainPoolP160t1|SHA256|OnlySign", "ECC_BrainPoolP160t1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160t1", "SHA384",
        "ECC_BrainPoolP160t1|SHA384|OnlySign", "ECC_BrainPoolP160t1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160t1", "SHA512",
        "ECC_BrainPoolP160t1|SHA512|OnlySign", "ECC_BrainPoolP160t1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest007, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192r1", "SHA1",
        "ECC_BrainPoolP192r1|SHA1|OnlySign", "ECC_BrainPoolP192r1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192r1", "SHA224",
        "ECC_BrainPoolP192r1|SHA224|OnlySign", "ECC_BrainPoolP192r1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192r1", "SHA256",
        "ECC_BrainPoolP192r1|SHA256|OnlySign", "ECC_BrainPoolP192r1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192r1", "SHA384",
        "ECC_BrainPoolP192r1|SHA384|OnlySign", "ECC_BrainPoolP192r1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192r1", "SHA512",
        "ECC_BrainPoolP192r1|SHA512|OnlySign", "ECC_BrainPoolP192r1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest008, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192t1", "SHA1",
        "ECC_BrainPoolP192t1|SHA1|OnlySign", "ECC_BrainPoolP192t1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192t1", "SHA224",
        "ECC_BrainPoolP192t1|SHA224|OnlySign", "ECC_BrainPoolP192t1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192t1", "SHA256",
        "ECC_BrainPoolP192t1|SHA256|OnlySign", "ECC_BrainPoolP192t1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192t1", "SHA384",
        "ECC_BrainPoolP192t1|SHA384|OnlySign", "ECC_BrainPoolP192t1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192t1", "SHA512",
        "ECC_BrainPoolP192t1|SHA512|OnlySign", "ECC_BrainPoolP192t1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest009, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224r1", "SHA1",
        "ECC_BrainPoolP224r1|SHA1|OnlySign", "ECC_BrainPoolP224r1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224r1", "SHA224",
        "ECC_BrainPoolP224r1|SHA224|OnlySign", "ECC_BrainPoolP224r1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224r1", "SHA256",
        "ECC_BrainPoolP224r1|SHA256|OnlySign", "ECC_BrainPoolP224r1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224r1", "SHA384",
        "ECC_BrainPoolP224r1|SHA384|OnlySign", "ECC_BrainPoolP224r1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224r1", "SHA512",
        "ECC_BrainPoolP224r1|SHA512|OnlySign", "ECC_BrainPoolP224r1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest010, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224t1", "SHA1",
        "ECC_BrainPoolP224t1|SHA1|OnlySign", "ECC_BrainPoolP224t1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224t1", "SHA224",
        "ECC_BrainPoolP224t1|SHA224|OnlySign", "ECC_BrainPoolP224t1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224t1", "SHA256",
        "ECC_BrainPoolP224t1|SHA256|OnlySign", "ECC_BrainPoolP224t1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224t1", "SHA384",
        "ECC_BrainPoolP224t1|SHA384|OnlySign", "ECC_BrainPoolP224t1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224t1", "SHA512",
        "ECC_BrainPoolP224t1|SHA512|OnlySign", "ECC_BrainPoolP224t1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest011, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256r1", "SHA1",
        "ECC_BrainPoolP256r1|SHA1|OnlySign", "ECC_BrainPoolP256r1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256r1", "SHA224",
        "ECC_BrainPoolP256r1|SHA224|OnlySign", "ECC_BrainPoolP256r1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256r1", "SHA256",
        "ECC_BrainPoolP256r1|SHA256|OnlySign", "ECC_BrainPoolP256r1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256r1", "SHA384",
        "ECC_BrainPoolP256r1|SHA384|OnlySign", "ECC_BrainPoolP256r1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256r1", "SHA512",
        "ECC_BrainPoolP256r1|SHA512|OnlySign", "ECC_BrainPoolP256r1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest012, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256t1", "SHA1",
        "ECC_BrainPoolP256t1|SHA1|OnlySign", "ECC_BrainPoolP256t1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256t1", "SHA224",
        "ECC_BrainPoolP256t1|SHA224|OnlySign", "ECC_BrainPoolP256t1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256t1", "SHA256",
        "ECC_BrainPoolP256t1|SHA256|OnlySign", "ECC_BrainPoolP256t1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256t1", "SHA384",
        "ECC_BrainPoolP256t1|SHA384|OnlySign", "ECC_BrainPoolP256t1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256t1", "SHA512",
        "ECC_BrainPoolP256t1|SHA512|OnlySign", "ECC_BrainPoolP256t1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest013, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320r1", "SHA1",
        "ECC_BrainPoolP320r1|SHA1|OnlySign", "ECC_BrainPoolP320r1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320r1", "SHA224",
        "ECC_BrainPoolP320r1|SHA224|OnlySign", "ECC_BrainPoolP320r1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320r1", "SHA256",
        "ECC_BrainPoolP320r1|SHA256|OnlySign", "ECC_BrainPoolP320r1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320r1", "SHA384",
        "ECC_BrainPoolP320r1|SHA384|OnlySign", "ECC_BrainPoolP320r1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320r1", "SHA512",
        "ECC_BrainPoolP320r1|SHA512|OnlySign", "ECC_BrainPoolP320r1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest014, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320t1", "SHA1",
        "ECC_BrainPoolP320t1|SHA1|OnlySign", "ECC_BrainPoolP320t1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320t1", "SHA224",
        "ECC_BrainPoolP320t1|SHA224|OnlySign", "ECC_BrainPoolP320t1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320t1", "SHA256",
        "ECC_BrainPoolP320t1|SHA256|OnlySign", "ECC_BrainPoolP320t1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320t1", "SHA384",
        "ECC_BrainPoolP320t1|SHA384|OnlySign", "ECC_BrainPoolP320t1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320t1", "SHA512",
        "ECC_BrainPoolP320t1|SHA512|OnlySign", "ECC_BrainPoolP320t1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest015, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384r1", "SHA1",
        "ECC_BrainPoolP384r1|SHA1|OnlySign", "ECC_BrainPoolP384r1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384r1", "SHA224",
        "ECC_BrainPoolP384r1|SHA224|OnlySign", "ECC_BrainPoolP384r1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384r1", "SHA256",
        "ECC_BrainPoolP384r1|SHA256|OnlySign", "ECC_BrainPoolP384r1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384r1", "SHA384",
        "ECC_BrainPoolP384r1|SHA384|OnlySign", "ECC_BrainPoolP384r1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384r1", "SHA512",
        "ECC_BrainPoolP384r1|SHA512|OnlySign", "ECC_BrainPoolP384r1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest016, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384t1", "SHA1",
        "ECC_BrainPoolP384t1|SHA1|OnlySign", "ECC_BrainPoolP384t1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384t1", "SHA224",
        "ECC_BrainPoolP384t1|SHA224|OnlySign", "ECC_BrainPoolP384t1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384t1", "SHA256",
        "ECC_BrainPoolP384t1|SHA256|OnlySign", "ECC_BrainPoolP384t1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384t1", "SHA384",
        "ECC_BrainPoolP384t1|SHA384|OnlySign", "ECC_BrainPoolP384t1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384t1", "SHA512",
        "ECC_BrainPoolP384t1|SHA512|OnlySign", "ECC_BrainPoolP384t1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest017, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512r1", "SHA1",
        "ECC_BrainPoolP512r1|SHA1|OnlySign", "ECC_BrainPoolP512r1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512r1", "SHA224",
        "ECC_BrainPoolP512r1|SHA224|OnlySign", "ECC_BrainPoolP512r1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512r1", "SHA256",
        "ECC_BrainPoolP512r1|SHA256|OnlySign", "ECC_BrainPoolP512r1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512r1", "SHA384",
        "ECC_BrainPoolP512r1|SHA384|OnlySign", "ECC_BrainPoolP512r1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512r1", "SHA512",
        "ECC_BrainPoolP512r1|SHA512|OnlySign", "ECC_BrainPoolP512r1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest018, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512t1", "SHA1",
        "ECC_BrainPoolP512t1|SHA1|OnlySign", "ECC_BrainPoolP512t1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512t1", "SHA224",
        "ECC_BrainPoolP512t1|SHA224|OnlySign", "ECC_BrainPoolP512t1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512t1", "SHA256",
        "ECC_BrainPoolP512t1|SHA256|OnlySign", "ECC_BrainPoolP512t1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512t1", "SHA384",
        "ECC_BrainPoolP512t1|SHA384|OnlySign", "ECC_BrainPoolP512t1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512t1", "SHA512",
        "ECC_BrainPoolP512t1|SHA512|OnlySign", "ECC_BrainPoolP512t1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest019, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_Secp256k1", "SHA1",
        "ECC_Secp256k1|SHA1|OnlySign", "ECC_Secp256k1|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_Secp256k1", "SHA224",
        "ECC_Secp256k1|SHA224|OnlySign", "ECC_Secp256k1|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_Secp256k1", "SHA256",
        "ECC_Secp256k1|SHA256|OnlySign", "ECC_Secp256k1|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_Secp256k1", "SHA384",
        "ECC_Secp256k1|SHA384|OnlySign", "ECC_Secp256k1|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_Secp256k1", "SHA512",
        "ECC_Secp256k1|SHA512|OnlySign", "ECC_Secp256k1|SHA512|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest020, TestSize.Level0)
{
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC224", "SHA1",
        "ECC|SHA1|OnlySign", "ECC|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC256", "SHA224",
        "ECC|SHA224|OnlySign", "ECC|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC384", "SHA256",
        "ECC|SHA256|OnlySign", "ECC|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC521", "SHA384",
        "ECC|SHA384|OnlySign", "ECC|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160r1", "SHA512",
        "ECC|SHA512|OnlySign", "ECC|SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP160t1", "SHA1",
        "ECC|SHA1|OnlySign", "ECC|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192r1", "SHA224",
        "ECC|SHA224|OnlySign", "ECC|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP192t1", "SHA256",
        "ECC|SHA256|OnlySign", "ECC|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224r1", "SHA384",
        "ECC|SHA384|OnlySign", "ECC|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP224t1", "SHA512",
        "ECC|SHA512|OnlySign", "ECC|SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256r1", "SHA1",
        "ECC|SHA1|OnlySign", "ECC|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP256r1", "SHA224",
        "ECC|SHA224|OnlySign", "ECC|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320r1", "SHA256",
        "ECC|SHA256|OnlySign", "ECC|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP320t1", "SHA384",
        "ECC|SHA384|OnlySign", "ECC|SHA384|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384r1", "SHA512",
        "ECC|SHA512|OnlySign", "ECC|SHA512|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP384t1", "SHA1",
        "ECC|SHA1|OnlySign", "ECC|SHA1|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512r1", "SHA224",
        "ECC|SHA224|OnlySign", "ECC|SHA224|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_BrainPoolP512t1", "SHA256",
        "ECC|SHA256|OnlySign", "ECC|SHA256|OnlyVerify"));
    ASSERT_NO_FATAL_FAILURE(EccOnlySignVerifyDigestTest("ECC_Secp256k1", "SHA384",
        "ECC|SHA384|OnlySign", "ECC|SHA384|OnlyVerify"));
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest021, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("DSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("DSA1024|SHA1|OnlySign", &sign);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(sign, nullptr);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("DSA1024|SHA1|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_NOT_SUPPORT);
    EXPECT_EQ(verify, nullptr);

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest022, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEcKeyDup(_))
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEcKeyDup));
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);

    sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyNew())
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyNew));
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);

    sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyAssignEcKey(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyAssignEcKey));
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);

    sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxNewFromPkey(_, _, _))
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxNewFromPkey));
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
    sign = nullptr;
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest023, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeySignInit(_))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeySignInit));
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);

    sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetSignatureMd(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetSignatureMd));
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(sign);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest024, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEcKeyDup(_))
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEcKeyDup));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);

    verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyNew())
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyNew));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);

    verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyAssignEcKey(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyAssignEcKey));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest025, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxNewFromPkey(_, _, _))
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxNewFromPkey));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);

    verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyVerifyInit(_))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerifyInit));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);

    verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeyCtxSetSignatureMd(_, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyCtxSetSignatureMd));
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);

    HcfObjDestroy(verify);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest026, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is ecc only sign test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test OpensslEvpPkeySign first call failure (get maxLen)
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeySign(_, _, _, _, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeySign));
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(sign);

    // Test HcfMalloc failure
    sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, HcfMalloc(_, _))
             .WillOnce(Return(nullptr))
             .WillRepeatedly(Invoke(__real_HcfMalloc));
    signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_ERR_MALLOC);
    HcfObjDestroy(sign);

    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest027, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is ecc only sign test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test OpensslEvpPkeySign second call failure (actual sign)
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_CALL(*mock_, OpensslEvpPkeySign(_, _, _, _, _))
             .WillOnce(Invoke(__real_OpensslEvpPkeySign))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeySign));
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    HcfObjDestroy(sign);

    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest028, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is ecc only sign test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Test invalid blob data (data is nullptr)
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob invalidDigest = {.data = nullptr, .len = 32};
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &invalidDigest, &signatureData);
    EXPECT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(sign);

    // Test status not READY (sign without init)
    sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_ERR_PARAMETER_CHECK_FAILED);
    HcfObjDestroy(sign);

    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest029, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is ecc only verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Create a valid signature first
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    // Test invalid blob data (data is nullptr)
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob invalidDigest = {.data = nullptr, .len = 32};
    bool result = verify->verify(verify, &invalidDigest, &signatureData);
    EXPECT_EQ(result, false);
    HcfObjDestroy(verify);

    HcfFree(signatureData.data);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccOnlySignVerifyTest, CryptoEccOnlySignVerifyDigestTest030, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("ECC256", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    uint8_t plan[] = "this is ecc only verify test.";
    HcfBlob input = {.data = plan, .len = strlen((char *)plan)};
    HcfBlob digest = {.data = nullptr, .len = 0};

    HcfMd *mdObj = nullptr;
    res = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = mdObj->update(mdObj, &input);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = mdObj->doFinal(mdObj, &digest);
    EXPECT_EQ(res, HCF_SUCCESS);

    // Create a valid signature first
    HcfSign *sign = nullptr;
    res = HcfSignCreate("ECC|SHA256|OnlySign", &sign);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = sign->init(sign, nullptr, keyPair->priKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob signatureData = {.data = nullptr, .len = 0};
    res = sign->sign(sign, &digest, &signatureData);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfObjDestroy(sign);

    // Test status not READY (verify without init)
    HcfVerify *verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    bool result = verify->verify(verify, &digest, &signatureData);
    EXPECT_EQ(result, false);
    HcfObjDestroy(verify);

    // Test OpensslEvpPkeyVerify failure
    verify = nullptr;
    res = HcfVerifyCreate("ECC|SHA256|OnlyVerify", &verify);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = verify->init(verify, nullptr, keyPair->pubKey);
    EXPECT_EQ(res, HCF_SUCCESS);

    EXPECT_CALL(*mock_, OpensslEvpPkeyVerify(_, _, _, _, _))
             .WillOnce(Return(-1))
             .WillRepeatedly(Invoke(__real_OpensslEvpPkeyVerify));
    result = verify->verify(verify, &digest, &signatureData);
    EXPECT_EQ(result, false);
    HcfObjDestroy(verify);

    HcfFree(signatureData.data);
    HcfObjDestroy(mdObj);
    HcfBlobDataClearAndFree(&digest);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}

