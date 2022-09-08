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

class CryptoFrameworkRandTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoFrameworkRandTest::SetUpTestCase() {}
void CryptoFrameworkRandTest::TearDownTestCase() {}

void CryptoFrameworkRandTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoFrameworkRandTest::TearDown() // add destroy here, this will be called when test case done.
{
}

HWTEST_F(CryptoFrameworkRandTest, CryptoFrameworkRandCreateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    ret = (int)HcfRandCreate(nullptr);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoFrameworkRandTest, CryptoFrameworkRandGenerateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int)HcfRandCreate(&randObj);
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

HWTEST_F(CryptoFrameworkRandTest, CryptoFrameworkRandGenerateTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int)HcfRandCreate(&randObj);
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

HWTEST_F(CryptoFrameworkRandTest, CryptoFrameworkRandGenerateTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // preset params
    int32_t randomLen = 1000;
    uint8_t randomBuf[1000] = {0};
    // define randomBlob and seedBlob
    struct HcfBlob randomBlob = {.data = (uint8_t *)randomBuf, .len = 0};
    // test generate random
    ret = randObj->generateRandom(randObj, randomLen, &randomBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&randomBlob);
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoFrameworkRandTest, CryptoFrameworkSetSeedTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int)HcfRandCreate(&randObj);
    EXPECT_EQ(ret, 0);
    // define randomBlob and seedBlob
    struct HcfBlob *seedBlob = nullptr;
    // test set seed
    ret = randObj->setSeed(randObj, seedBlob);
    EXPECT_NE(ret, 0);
    // destroy the API obj and blob data
    OH_HCF_ObjDestroy(randObj);
}

HWTEST_F(CryptoFrameworkRandTest, CryptoFrameworkSetSeedTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int)HcfRandCreate(&randObj);
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

HWTEST_F(CryptoFrameworkRandTest, CryptoFrameworkSetSeedTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a rand obj
    HcfRand *randObj = nullptr;
    ret = (int)HcfRandCreate(&randObj);
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