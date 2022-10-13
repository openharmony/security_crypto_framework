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

#include "md.h"

#include "log.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMdTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static char g_testBigData[] = "VqRH5dzdeeturr5zN5vE77DtqjV7kNKbDJqk4mNqyYRTXymhjR\r\n"
"Yz8c2pNvJiCxyFwvLvWfPh2Y2eDAuxbdm2Dt4UzKJtNqEpNYKVZLiyH4a4MhR4BpFhvhJVHy2ALbYq2rW\r\n"
"LqJfNzA6v8kHNaFypNDMgX35kifyCiYkq85XUKDJCdewUzCZ2N8twC8Z9kL37K67bkL35VYFZSXyrNTdV\r\n"
"pB6kqPjwZYrjx5tXzMMgJW8ePqmAhZUVjtPGXTLVt8BUnaVRuWjD97xjS3VH9EwFeyrqJ46B92rkuGexY\r\n"
"cjXuvhHTnQNPbYfake7KMEWG2wgGLmZmjnakULhFgjt6TQhvCWMJAHYn8Zgczd3C3HkPrQgUXJgAiwf3r\r\n"
"jJbgbBpQkkbcfMBZZ3SSLe2J9jw6MkdEf3eBQX9rFVQSgBQgZ9KEW8XLb5kCTcyhRZPBbiHD4qQRyrwKT\r\n"
"mnGZqP5Aru6GDkhFk78jfjtk35HyB7AY7UZXkczRfVYAxa5Mk256MhAHkE3uAvPZTyY7N3qk9U7cLTrce\r\n"
"wJLH6wrymrMvQWgpvrBevMghnURZUcZAWUznDn56WnwGAzYAWmJqdXqAfcvgZwCFTjxdiaEZGpEyUrcS8\r\n"
"nr48ZeXS5aytz5Y7RnU5SxcHbgF8PerWVdftxmghPAvGkQ6f3dcXr9w9bbGqg5KJHyQCxabp8bjZpyFdb\r\n"
"VTq8DpQ6AJjxdjn8cuLTf9giGFxDjtQncicUdqP7YvVDr5AFgWc83cddyryVLZEBGAFfqbbKWF9KnPjRZ\r\n"
"AbuZ7SqrkxhQHu87Hxh3xHUHB8Lb3DGZ4vhnqaLnJBxFK8Ve4F2FfbgfHfQtALFDUWp6dSz8Hvdpj4CGw\r\n"
"FaSb8b5hTemaQRguYAqaUwJVvZ7G2AwkFnV9PHUngmybAFxg8HMAT3K7yAiQJWWqPxdGq8jXPAqZFNkGu\r\n"
"2mnJ5xfnY3z63PFk6TXU9Ga2YmHvtycXxwqMBEctQRa3zVWGVSrh3NF6jXa\r\n";
constexpr uint32_t MAX_MD_BLOB_LEN = 5000;

void CryptoMdTest::SetUpTestCase() {}
void CryptoMdTest::TearDownTestCase() {}

void CryptoMdTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoMdTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static void PrintfBlobInHex(uint8_t *data, size_t dataLen)
{
    for (size_t i = 0; i < dataLen; i++) {
        printf("%02hhX", data[i]);
    }
    printf("\n");
}

/**
 * @tc.name: CryptoFrameworkMdTest.CryptoFrameworkMdCreateTest001
 * @tc.desc: Verify that the creation of the SHA1 Md obj is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEM
 */
HWTEST_F(CryptoMdTest, CryptoFrameworkMdCreateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    ret = (int32_t)HcfMdCreate("SHA1", nullptr);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoSuppTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(mdObj, nullptr);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoSuppTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA3 obj (not supported)
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA3", &mdObj);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(mdObj, nullptr);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoSuppTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create an obj with null algoInput (not supported)
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate(nullptr, &mdObj);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(mdObj, nullptr);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoNameTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(mdObj, nullptr);
    // test api functions
    const char *algoName =  mdObj->getAlgoName(mdObj);
    ret = strcmp(algoName, "SHA1");
    EXPECT_EQ(ret, 0);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdUpdateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    // define input and output data in blob form
    HcfBlob *inBlob= nullptr;
    // test api functions
    ret = mdObj->update(mdObj, inBlob);
    EXPECT_NE(ret, 0);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdUpdateTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    // define input and output data in blob form
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdDoFinalTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t outBuf[20] = {0};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api functions
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdDoFinalTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    uint8_t outBuf[20] = {0};
    // define input and output data in blob form
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdDoFinalTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA256", &mdObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t outBuf[20] = {0};
    // define input and output data in blob form
    HcfBlob inBlob= {.data = (uint8_t *)g_testBigData, .len = strnlen(g_testBigData, MAX_MD_BLOB_LEN)};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    PrintfBlobInHex(outBlob.data, outBlob.len);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdLenTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    // test api functions
    ret = mdObj->getMdLength(mdObj);
    EXPECT_EQ(ret, 20);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA1", &mdObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t testData[] = "My test data";
    size_t testDataLen = 12;
    uint8_t outBuf[20] = {0};
    // define input and output data in blob form
    struct HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    struct HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->getMdLength(mdObj);
    EXPECT_EQ(ret, 20);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA224", &mdObj);
    EXPECT_EQ(ret, 0);
    
    // set input and output buf
    uint8_t testData[] = "My test data";
    size_t testDataLen = 12;
    uint8_t outBuf[28] = {0};

    // define input and output data in blob form
    struct HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    struct HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};

    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->getMdLength(mdObj);
    EXPECT_EQ(ret, 28);

    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA256", &mdObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t testData[] = "My test data";
    size_t testDataLen = 12;
    uint8_t outBuf[32] = {0};

    // define input and output data in blob form
    struct HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    struct HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};

    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->getMdLength(mdObj);
    EXPECT_EQ(ret, 32);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest004, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA384", &mdObj);
    EXPECT_EQ(ret, 0);
    
    // set input and output buf
    uint8_t testData[] = "My test data";
    size_t testDataLen = 12;
    uint8_t outBuf[48] = {0};

    // define input and output data in blob form
    struct HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    struct HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};

    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->getMdLength(mdObj);
    EXPECT_EQ(ret, 48);

    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest005, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("SHA512", &mdObj);
    EXPECT_EQ(ret, 0);
    
    // set input and output buf
    uint8_t testData[] = "My test data";
    size_t testDataLen = 12;
    uint8_t outBuf[64] = {0};

    // define input and output data in blob form
    struct HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    struct HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};

    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->getMdLength(mdObj);
    EXPECT_EQ(ret, 64);

    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}

HWTEST_F(CryptoMdTest, CryptoFrameworkMdAlgoTest006, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMd *mdObj = nullptr;
    ret = (int32_t)HcfMdCreate("MD5", &mdObj);
    EXPECT_EQ(ret, 0);
    
    // set input and output buf
    uint8_t testData[] = "My test data";
    size_t testDataLen = 12;
    uint8_t outBuf[16] = {0};

    // define input and output data in blob form
    struct HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    struct HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};

    // test api functions
    ret = mdObj->update(mdObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->doFinal(mdObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = mdObj->getMdLength(mdObj);
    EXPECT_EQ(ret, 16);

    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
}
}