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

#include "rand.h"

#include "log.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoRandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoRandTest::SetUpTestCase() {}
void CryptoRandTest::TearDownTestCase() {}

void CryptoRandTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoRandTest::TearDown() // add destroy here, this will be called when test case done.
{
}

/**
 * @tc.name: CryptoFrameworkRandTest.CryptoFrameworkRandCreateTest001
 * @tc.desc: Verify that the creation of the random obj is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEN
 */
HWTEST_F(CryptoRandTest, CryptoFrameworkRandCreateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    ret = (int32_t)HcfRandCreate(nullptr);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoRandTest, CryptoFrameworkRandGenerateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int32_t)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // preset params
    int32_t randomLen = 0;
    uint8_t randomBuf[32] = {0};
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {.data = (uint8_t *)randomBuf, .len = 0};
    // test generate random with length 0
    ret = randObj->generateRandom(randObj, randomLen, &randomBlob);
    EXPECT_NE(ret, 0);
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoRandTest, CryptoFrameworkRandGenerateTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int32_t)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // preset params
    int32_t randomLen = 32;
    uint8_t randomBuf[32] = {0};
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {.data = (uint8_t *)randomBuf, .len = 0};
    // test generate random
    ret = randObj->generateRandom(randObj, randomLen, &randomBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&randomBlob);
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoRandTest, CryptoFrameworkRandGenerateTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int32_t)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // preset params
    int32_t randomLen = 8192;
    uint8_t randomBuf[8192] = {0};
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {.data = (uint8_t *)randomBuf, .len = 0};
    // test generate random
    ret = randObj->generateRandom(randObj, randomLen, &randomBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&randomBlob);
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoRandTest, CryptoFrameworkRandGenerateTest004, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int32_t)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // preset params
    int32_t randomLen = 8193;
    uint8_t randomBuf[8193] = {0};
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {.data = (uint8_t *)randomBuf, .len = 0};
    // test generate random
    ret = randObj->generateRandom(randObj, randomLen, &randomBlob);
    EXPECT_NE(ret, 0);
    // destroy the API obj and blob data
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoRandTest, CryptoFrameworkSetSeedTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int32_t)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // define randomBlob and seedBlob
    struct HcfBlob *seedBlob = nullptr;
    // test set seed
    ret = randObj->setSeed(randObj, seedBlob);
    EXPECT_NE(ret, 0);
    // destroy the API obj and blob data
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoRandTest, CryptoFrameworkSetSeedTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int32_t)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // preset params
    int32_t seedLen = 32;
    uint8_t seedBuf[32] = {0};
    // define randomBlob and seedBlob
    struct HcfBlob seedBlob = {.data = (uint8_t *)seedBuf, .len = 0};
    // test generate seed
    ret = randObj->generateRandom(randObj, seedLen, &seedBlob);
    EXPECT_EQ(ret, 0);
    // test set seed
    ret = randObj->setSeed(randObj, &seedBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&seedBlob);
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoRandTest, CryptoFrameworkSetSeedTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int32_t)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // preset params
    int32_t seedLen = 1000;
    uint8_t seedBuf[1000] = {0};
    // define randomBlob and seedBlob
    struct HcfBlob seedBlob = {.data = (uint8_t *)seedBuf, .len = 0};
    // test generate seed
    ret = randObj->generateRandom(randObj, seedLen, &seedBlob);
    EXPECT_EQ(ret, 0);
    // test set seed
    ret = randObj->setSeed(randObj, &seedBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&seedBlob);
    OH_HCF_ObjDestroy(randObj);
}
}