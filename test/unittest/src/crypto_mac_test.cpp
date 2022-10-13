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
#include <string>
#include "securec.h"

#include "mac.h"
#include "sym_key_generator.h"

#include "log.h"
#include "memory.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoMacTest : public testing::Test {
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
constexpr uint32_t MAX_MAC_BLOB_LEN = 5000;

void CryptoMacTest::SetUpTestCase() {}
void CryptoMacTest::TearDownTestCase() {}

void CryptoMacTest::SetUp() // add init here, this will be called before test.
{
}

void CryptoMacTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static void PrintfBlobInHex(uint8_t *data, size_t dataLen)
{
    for (size_t i = 0; i < dataLen; i++) {
        printf("%02hhX", data[i]);
    }
    printf("\n");
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacCreateTest002, TestSize.Level0)
{
    int32_t ret = 0;
    ret = (int32_t)HcfMacCreate("SHA1", nullptr);
    EXPECT_NE(ret, 0);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoSuppTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(macObj, nullptr);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoSuppTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA3", &macObj);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(macObj, nullptr);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoSuppTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate(nullptr, &macObj);
    EXPECT_NE(ret, 0);
    EXPECT_EQ(macObj, nullptr);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoNameTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(macObj, nullptr);
    // test api functions
    const char *algoName =  macObj->getAlgoName(macObj);
    ret = strcmp(algoName, "SHA1");
    EXPECT_EQ(ret, 0);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacInitTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // set a nullptr key
    HcfSymKey *key = nullptr;
    // test api functions
    ret = macObj->init(macObj, key);
    EXPECT_NE(ret, 0);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacInitTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // test api functions
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacUpdateTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    // define input and output data in blob form
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    // test api functions
    ret = macObj->update(macObj, &inBlob);
    EXPECT_NE(ret, 0);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacUpdateTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // cteate key generator and set key text
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // define input and output data in blob form
    HcfBlob *inBlob= nullptr;
    // test api functions
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, inBlob);
    EXPECT_NE(ret, 0);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacUpdateTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a API obj with SHA1
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // cteate key generator and set key text
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output buf
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    // define input and output data in blob form
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    // test api functions
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // set input and output buf
    uint8_t outBuf[20] = {0};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api functions
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_NE(ret, 0);
    // destroy the API obj and blob data
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // cteate key generator and set key text
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    printf("get symkey finish");
    // set input and output buf
    uint8_t outBuf[20] = {0};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};

    // test api functions
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    printf("test init finish");

    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    printf("test dofinal finish");
    PrintfBlobInHex(outBlob.data, outBlob.len);

    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    printf("HcfBlobDataClearAndFree finish");
    HcfObjDestroy(macObj);
    printf("HcfObjDestroy macObj finish");
    HcfObjDestroy(key);
    printf("HcfObjDestroy key finish");
    HcfObjDestroy(generator);
    printf("test finish");
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // cteate key generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output buf
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    uint8_t outBuf[20] = {0};
    // define input and output data in blob form
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api functions
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacDoFinalTest004, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA256", &macObj);
    EXPECT_EQ(ret, 0);
    // cteate key generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output buf
    uint8_t outBuf[20] = {0};
    // define input and output data in blob form
    HcfBlob inBlob= {.data = (uint8_t *)g_testBigData, .len = strnlen(g_testBigData, MAX_MAC_BLOB_LEN)};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api functions
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    PrintfBlobInHex(outBlob.data, outBlob.len);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacLenTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // test api functions
    ret = macObj->getMacLength(macObj);
    EXPECT_EQ(ret, 0);
    HcfObjDestroy(macObj);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacLenTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // cteate key generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // get sym key from preset keyBlob
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // test api functions
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->getMacLength(macObj);
    EXPECT_EQ(ret, 20);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest001, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA1", &macObj);
    EXPECT_EQ(ret, 0);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    uint8_t outBuf[20] = {0};
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api funcitons
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->getMacLength(macObj);
    EXPECT_EQ(ret, 20);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest002, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA224", &macObj);
    EXPECT_EQ(ret, 0);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    uint8_t outBuf[28] = {0};
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api funcitons
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->getMacLength(macObj);
    EXPECT_EQ(ret, 28);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest003, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA256", &macObj);
    EXPECT_EQ(ret, 0);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    uint8_t outBuf[32] = {0};
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api funcitons
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->getMacLength(macObj);
    EXPECT_EQ(ret, 32);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest004, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA384", &macObj);
    EXPECT_EQ(ret, 0);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    uint8_t outBuf[48] = {0};
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api funcitons
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->getMacLength(macObj);
    EXPECT_EQ(ret, 48);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoMacTest, CryptoFrameworkHmacAlgoTest005, TestSize.Level0)
{
    int32_t ret = 0;
    // create a SHA1 obj
    HcfMac *macObj = nullptr;
    ret = (int32_t)HcfMacCreate("SHA512", &macObj);
    EXPECT_EQ(ret, 0);
    // create a symKey generator
    HcfSymKeyGenerator *generator = nullptr;
    ret = (int32_t)HcfSymKeyGeneratorCreate("AES128", &generator);
    EXPECT_EQ(ret, 0);
    // set key data and convert it to key obj
    uint8_t testKey[] = "abcdefghijklmnop";
    uint32_t testKeyLen = 16;
    HcfSymKey *key = nullptr;
    HcfBlob keyMaterialBlob = {.data = (uint8_t *)testKey, .len = testKeyLen};
    generator->convertSymKey(generator, &keyMaterialBlob, &key);
    // set input and output blob
    uint8_t testData[] = "My test data";
    uint32_t testDataLen = 12;
    uint8_t outBuf[64] = {0};
    HcfBlob inBlob= {.data = (uint8_t *)testData, .len = testDataLen};
    HcfBlob outBlob = {.data = (uint8_t *)outBuf, .len = 0};
    // test api funcitons
    ret = macObj->init(macObj, (HcfSymKey *)key);
    EXPECT_EQ(ret, 0);
    ret = macObj->update(macObj, &inBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->doFinal(macObj, &outBlob);
    EXPECT_EQ(ret, 0);
    ret = macObj->getMacLength(macObj);
    EXPECT_EQ(ret, 64);
    // destroy the API obj and blob data
    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(macObj);
    HcfObjDestroy(key);
    HcfObjDestroy(generator);
}
}