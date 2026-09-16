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
#include "securec.h"

#include "md.h"
#include "md_openssl.h"
#include "crypto_digest.h"

#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMdShakeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

constexpr uint32_t SHAKE128_MIN_LEN = 32;
constexpr uint32_t SHAKE256_MIN_LEN = 64;
constexpr uint32_t SHAKE_MAX_LEN = 65536;

void CryptoMdShakeTest::SetUpTestCase() {}
void CryptoMdShakeTest::TearDownTestCase() {}

void CryptoMdShakeTest::SetUp() {}

void CryptoMdShakeTest::TearDown() {}

static void UpdateTestData(HcfMd *mdObj)
{
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    HcfResult ret = mdObj->update(mdObj, &inBlob);
    ASSERT_EQ(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeCreateTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeCreateTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeCreateTest003, TestSize.Level0)
{
    HcfResult ret = HcfMdCreate("SHAKE128", nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeCreateTest004, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate(nullptr, &mdObj);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(mdObj, nullptr);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeCreateTest005, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE64", &mdObj);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(mdObj, nullptr);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeAlgoNameTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    const char *algoName = mdObj->getAlgoName(mdObj);
    EXPECT_STREQ(algoName, "SHAKE128");
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeAlgoNameTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    const char *algoName = mdObj->getAlgoName(mdObj);
    EXPECT_STREQ(algoName, "SHAKE256");
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeUpdateTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeUpdateTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeGetLenTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, 0);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeGetLenTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    uint32_t len = mdObj->getMdLength(mdObj);
    EXPECT_EQ(len, 0);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalLenTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE128_MIN_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(outBlob.len, SHAKE128_MIN_LEN);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalLenTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 64, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(outBlob.len, 64);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalLenTest003, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE_MAX_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(outBlob.len, SHAKE_MAX_LEN);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalLenTest004, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE256_MIN_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(outBlob.len, SHAKE256_MIN_LEN);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalLenTest005, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 128, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(outBlob.len, 128);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalLenTest006, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE_MAX_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(outBlob.len, SHAKE_MAX_LEN);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDoFinalLenTest007, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob32 = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE128_MIN_LEN, &outBlob32);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfMd *mdObj2 = nullptr;
    ret = HcfMdCreate("SHAKE128", &mdObj2);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj2);
    HcfBlob outBlob64 = { .data = nullptr, .len = 0 };
    ret = mdObj2->squeeze(mdObj2, 64, &outBlob64);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(memcmp(outBlob32.data, outBlob64.data, SHAKE128_MIN_LEN), 0);
    HcfBlobDataClearAndFree(&outBlob32);
    HcfBlobDataClearAndFree(&outBlob64);
    HcfObjDestroy(mdObj);
    HcfObjDestroy(mdObj2);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeLenRangeTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE128_MIN_LEN - 1, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeLenRangeTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 0, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeLenRangeTest003, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, -1, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeLenRangeTest004, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE_MAX_LEN + 1, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeLenRangeTest005, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE256_MIN_LEN - 1, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeLenRangeTest006, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE_MAX_LEN + 1, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeNotXofTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHA256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 32, &outBlob);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeNotXofTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SM3", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 32, &outBlob);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeNullTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(nullptr, 32, &outBlob);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeNullTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    ret = mdObj->squeeze(mdObj, 32, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeNullTest003, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    ret = mdObj->squeeze(nullptr, 32, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeFinalizedTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob1 = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 64, &outBlob1);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob1);
    HcfBlob outBlob2 = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 64, &outBlob2);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfBlobDataClearAndFree(&outBlob2);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeFinalizedTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 64, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    uint8_t testData[] = "My test data";
    HcfBlob inBlob = {.data = reinterpret_cast<uint8_t *>(testData), .len = sizeof(testData)};
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeFinalizedTest003, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 64, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob);
    HcfBlob outBlob2 = { .data = nullptr, .len = 0 };
    ret = mdObj->doFinal(mdObj, &outBlob2);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfBlobDataClearAndFree(&outBlob2);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeFinalizedTest004, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    UpdateTestData(mdObj);
    HcfBlob outBlob1 = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 64, &outBlob1);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfBlobDataClearAndFree(&outBlob1);
    HcfBlob outBlob2 = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 128, &outBlob2);
    EXPECT_EQ(ret, HCF_ERR_INVALID_CALL);
    HcfBlobDataClearAndFree(&outBlob2);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeStressTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    for (int i = 0; i < 10; i++) {
        HcfMd *md = nullptr;
        ret = HcfMdCreate("SHAKE128", &md);
        ASSERT_EQ(ret, HCF_SUCCESS);
        UpdateTestData(md);
        HcfBlob outBlob = { .data = nullptr, .len = 0 };
        ret = md->squeeze(md, 64, &outBlob);
        EXPECT_EQ(ret, HCF_SUCCESS);
        EXPECT_EQ(outBlob.len, 64);
        HcfBlobDataClearAndFree(&outBlob);
        HcfObjDestroy(md);
    }
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeStressTest002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    uint8_t part1[] = "Hello ";
    uint8_t part2[] = "World";
    HcfBlob inBlob1 = {.data = part1, .len = sizeof(part1) - 1};
    HcfBlob inBlob2 = {.data = part2, .len = sizeof(part2) - 1};
    ret = mdObj->update(mdObj, &inBlob1);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->update(mdObj, &inBlob2);
    EXPECT_EQ(ret, HCF_SUCCESS);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, 128, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(outBlob.len, 128);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeDestroyTest001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeSpiTest001, TestSize.Level0)
{
    HcfMdSpi *spiObj = nullptr;
    HcfResult ret = OpensslMdSpiCreate("SHAKE128", &spiObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeSpiTest002, TestSize.Level0)
{
    HcfResult ret = OpensslMdSpiCreate("SHAKE128", nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeSpiTest003, TestSize.Level0)
{
    HcfMdSpi *spiObj = nullptr;
    HcfResult ret = OpensslMdSpiCreate(nullptr, &spiObj);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeNativeCreateTest001, TestSize.Level0)
{
    OH_CryptoDigest *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoDigest_Create("SHAKE128", &ctx);
    EXPECT_EQ(ret, CRYPTO_INVALID_PARAMS);
    EXPECT_EQ(ctx, nullptr);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShakeNativeCreateTest002, TestSize.Level0)
{
    OH_CryptoDigest *ctx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoDigest_Create("SHAKE256", &ctx);
    EXPECT_EQ(ret, CRYPTO_INVALID_PARAMS);
    EXPECT_EQ(ctx, nullptr);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShake128Vector001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE128_MIN_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t expectedDigest[SHAKE128_MIN_LEN] = {
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
        0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
        0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
        0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26
    };
    ASSERT_EQ(outBlob.len, SHAKE128_MIN_LEN);
    ASSERT_NE(outBlob.data, nullptr);
    EXPECT_EQ(memcmp(outBlob.data, expectedDigest, SHAKE128_MIN_LEN), 0);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShake128Vector002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    const char *input = "abc";
    HcfBlob inBlob = { .data = reinterpret_cast<uint8_t *>(const_cast<char *>(input)), .len = 3 };
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->squeeze(mdObj, SHAKE128_MIN_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t expectedDigest[SHAKE128_MIN_LEN] = {
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c,
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7,
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f,
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8
    };
    ASSERT_EQ(outBlob.len, SHAKE128_MIN_LEN);
    ASSERT_NE(outBlob.data, nullptr);
    EXPECT_EQ(memcmp(outBlob.data, expectedDigest, SHAKE128_MIN_LEN), 0);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShake128Vector003, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE128", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    const char *input = "abc";
    HcfBlob inBlob = { .data = reinterpret_cast<uint8_t *>(const_cast<char *>(input)), .len = 3 };
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->squeeze(mdObj, 64, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t expectedDigest[64] = {
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c,
        0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb, 0xa7,
        0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f,
        0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f, 0x2c, 0xc8,
        0x44, 0xc5, 0x0a, 0xf3, 0x2a, 0xcd, 0x3f, 0x2c,
        0xdd, 0x06, 0x65, 0x68, 0x70, 0x6f, 0x50, 0x9b,
        0xc1, 0xbd, 0xde, 0x58, 0x29, 0x5d, 0xae, 0x3f,
        0x89, 0x1a, 0x9a, 0x0f, 0xca, 0x57, 0x83, 0x78
    };
    ASSERT_EQ(outBlob.len, 64);
    ASSERT_NE(outBlob.data, nullptr);
    EXPECT_EQ(memcmp(outBlob.data, expectedDigest, 64), 0);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShake256Vector001, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->squeeze(mdObj, SHAKE256_MIN_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t expectedDigest[SHAKE256_MIN_LEN] = {
        0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
        0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
        0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
        0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
        0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00,
        0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
        0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
        0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe
    };
    ASSERT_EQ(outBlob.len, SHAKE256_MIN_LEN);
    ASSERT_NE(outBlob.data, nullptr);
    EXPECT_EQ(memcmp(outBlob.data, expectedDigest, SHAKE256_MIN_LEN), 0);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShake256Vector002, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    const char *input = "abc";
    HcfBlob inBlob = { .data = reinterpret_cast<uint8_t *>(const_cast<char *>(input)), .len = 3 };
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->squeeze(mdObj, SHAKE256_MIN_LEN, &outBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    uint8_t expectedDigest[SHAKE256_MIN_LEN] = {
        0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77,
        0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
        0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee,
        0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39,
        0xd5, 0xa1, 0x5b, 0xef, 0x18, 0x6a, 0x53, 0x86,
        0xc7, 0x57, 0x44, 0xc0, 0x52, 0x7e, 0x1f, 0xaa,
        0x9f, 0x87, 0x26, 0xe4, 0x62, 0xa1, 0x2a, 0x4f,
        0xeb, 0x06, 0xbd, 0x88, 0x01, 0xe7, 0x51, 0xe4
    };
    ASSERT_EQ(outBlob.len, SHAKE256_MIN_LEN);
    ASSERT_NE(outBlob.data, nullptr);
    EXPECT_EQ(memcmp(outBlob.data, expectedDigest, SHAKE256_MIN_LEN), 0);
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdShakeTest, CryptoFrameworkMdShake256Vector003, TestSize.Level0)
{
    HcfMd *mdObj = nullptr;
    HcfResult ret = HcfMdCreate("SHAKE256", &mdObj);
    ASSERT_EQ(ret, HCF_SUCCESS);
    const char *input = "abc";
    HcfBlob inBlob = { .data = reinterpret_cast<uint8_t *>(const_cast<char *>(input)), .len = 3 };
    HcfBlob outBlob64 = { .data = nullptr, .len = 0 };
    HcfBlob outBlob96 = { .data = nullptr, .len = 0 };
    uint8_t expected64[64] = {
        0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
        0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39,
        0xd5, 0xa1, 0x5b, 0xef, 0x18, 0x6a, 0x53, 0x86, 0xc7, 0x57, 0x44, 0xc0, 0x52, 0x7e, 0x1f, 0xaa,
        0x9f, 0x87, 0x26, 0xe4, 0x62, 0xa1, 0x2a, 0x4f, 0xeb, 0x06, 0xbd, 0x88, 0x01, 0xe7, 0x51, 0xe4
    };
    uint8_t expected96[96] = {
        0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
        0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39,
        0xd5, 0xa1, 0x5b, 0xef, 0x18, 0x6a, 0x53, 0x86, 0xc7, 0x57, 0x44, 0xc0, 0x52, 0x7e, 0x1f, 0xaa,
        0x9f, 0x87, 0x26, 0xe4, 0x62, 0xa1, 0x2a, 0x4f, 0xeb, 0x06, 0xbd, 0x88, 0x01, 0xe7, 0x51, 0xe4,
        0x13, 0x85, 0x14, 0x12, 0x04, 0xf3, 0x29, 0x97, 0x9f, 0xd3, 0x04, 0x7a, 0x13, 0xc5, 0x65, 0x77,
        0x24, 0xad, 0xa6, 0x4d, 0x24, 0x70, 0x15, 0x7b, 0x3c, 0xdc, 0x28, 0x86, 0x20, 0x94, 0x4d, 0x78
    };
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj->squeeze(mdObj, 64, &outBlob64);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(memcmp(outBlob64.data, expected64, 64), 0);
    HcfBlobDataClearAndFree(&outBlob64);
    HcfObjDestroy(mdObj);

    HcfMd *mdObj2 = nullptr;
    ret = HcfMdCreate("SHAKE256", &mdObj2);
    ASSERT_EQ(ret, HCF_SUCCESS);
    ret = mdObj2->update(mdObj2, &inBlob);
    EXPECT_EQ(ret, HCF_SUCCESS);
    ret = mdObj2->squeeze(mdObj2, 96, &outBlob96);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(memcmp(outBlob96.data, expected96, 96), 0);
    EXPECT_EQ(memcmp(outBlob96.data, expected64, 64), 0);
    HcfBlobDataClearAndFree(&outBlob96);
    HcfObjDestroy(mdObj2);
}
}
