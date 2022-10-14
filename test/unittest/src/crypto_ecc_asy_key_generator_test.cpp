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

#include "asy_key_generator.h"
#include "blob.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoEccAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoEccAsyKeyGeneratorTest::SetUpTestCase() {}
void CryptoEccAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoEccAsyKeyGeneratorTest::SetUp() {}
void CryptoEccAsyKeyGeneratorTest::TearDown() {}

const int ECC224_PUB_KEY_LEN = 57;
const int ECC224_PRI_KEY_LEN = 28;
const int ECC256_PUB_KEY_LEN = 65;
const int ECC256_PRI_KEY_LEN = 32;
const int ECC384_PUB_KEY_LEN = 97;
const int ECC384_PRI_KEY_LEN = 48;
const int ECC512_PUB_KEY_LEN = 133;
const int ECC512_PRI_KEY_LEN = 65;

static uint8_t mockEcc224PubKeyBlobData[ECC224_PUB_KEY_LEN] = { 4, 189, 186, 122, 21, 9, 8, 231, 90, 111, 68, 222,
    207, 200, 53, 114, 236, 246, 204, 9, 171, 197, 57, 173, 138, 38, 180, 217, 55, 234, 181, 87, 143, 199, 250, 222,
    101, 120, 193, 184, 132, 9, 139, 177, 112, 246, 97, 25, 57, 43, 252, 212, 33, 181, 114, 89, 151 };

static uint8_t mockEcc224PriKeyBlobData[ECC224_PRI_KEY_LEN] = { 7, 13, 160, 20, 7, 190, 2, 157, 233, 245, 164, 249,
    218, 30, 241, 3, 198, 136, 155, 15, 168, 198, 237, 117, 95, 45, 142, 183 };

static uint8_t mockEcc256PubKeyBlobData[ECC256_PUB_KEY_LEN] = { 4, 15, 195, 182, 51, 78, 219, 41, 100, 231, 64, 119,
    34, 191, 238, 62, 169, 229, 240, 57, 216, 20, 229, 93, 193, 136, 238, 194, 150, 78, 205, 62, 218, 201, 77, 194,
    46, 121, 234, 126, 85, 134, 229, 244, 227, 184, 42, 22, 171, 179, 236, 16, 12, 93, 138, 175, 255, 99, 212, 107,
    83, 128, 49, 194, 215 };

static uint8_t mockEcc256PriKeyBlobData[ECC256_PRI_KEY_LEN] = { 218, 130, 176, 177, 252, 163, 236, 3, 204, 22, 211,
    213, 239, 252, 14, 231, 185, 139, 221, 45, 196, 13, 237, 179, 129, 165, 72, 224, 230, 210, 207, 232 };
static uint8_t mockEcc384PubKeyBlobData[ECC384_PUB_KEY_LEN] = { 4, 246, 111, 226, 33, 39, 150, 111, 50, 96, 228,
    225, 189, 33, 213, 169, 139, 181, 46, 51, 160, 254, 184, 75, 115, 153, 153, 105, 177, 50, 211, 101, 71, 53,
    5, 138, 56, 125, 137, 4, 206, 152, 206, 221, 212, 162, 242, 135, 202, 205, 119, 79, 45, 191, 111, 84, 172,
    34, 159, 112, 149, 197, 102, 56, 235, 212, 171, 234, 162, 11, 188, 146, 137, 203, 180, 46, 241, 44, 235,
    25, 111, 12, 115, 140, 220, 41, 192, 166, 124, 205, 173, 142, 107, 4, 105, 54, 148 };

static uint8_t mockEcc384PriKeyBlobData[ECC384_PRI_KEY_LEN] = { 121, 40, 96, 196, 198, 46, 100, 70, 102, 98, 63, 143,
    8, 224, 229, 57, 236, 161, 224, 204, 85, 49, 99, 205, 104, 90, 98, 9, 79, 171, 189, 5, 194, 117, 225, 203, 127,
    17, 214, 77, 6, 99, 162, 9, 191, 192, 76, 174 };
static uint8_t mockEcc512PubKeyBlobData[ECC512_PUB_KEY_LEN] = { 4, 1, 79, 67, 218, 31, 215, 194, 89, 74, 246, 88,
    151, 232, 47, 159, 60, 56, 23, 159, 12, 123, 12, 239, 81, 75, 92, 15, 118, 101, 27, 69, 147, 76, 151, 91, 59,
    212, 77, 176, 198, 132, 151, 225, 113, 116, 164, 254, 206, 148, 203, 95, 3, 137, 148, 180, 184, 173, 206, 16,
    12, 170, 57, 228, 25, 233, 159, 0, 107, 24, 217, 155, 26, 85, 40, 148, 116, 97, 134, 150, 73, 127, 247, 184,
    132, 188, 2, 165, 236, 146, 150, 103, 213, 206, 185, 124, 13, 166, 213, 238, 39, 18, 10, 164, 226, 139, 86,
    159, 25, 88, 154, 155, 75, 248, 46, 200, 14, 33, 45, 68, 4, 238, 138, 144, 114, 11, 219, 114, 7, 163, 255, 9, 150 };

static uint8_t mockEcc512PriKeyBlobData[ECC512_PRI_KEY_LEN] = { 128, 210, 9, 28, 225, 87, 232, 88, 102, 55, 78, 216,
    162, 210, 219, 218, 26, 33, 206, 253, 165, 172, 111, 60, 157, 206, 77, 145, 123, 95, 92, 21, 254, 159, 145, 104,
    194, 49, 0, 108, 38, 40, 204, 1, 231, 162, 34, 64, 118, 191, 163, 143, 33, 44, 55, 231, 54, 64, 210, 54, 201,
    117, 251, 157, 109 };

static HcfBlob mockEcc224PubKeyBlob = {
    .data = mockEcc224PubKeyBlobData,
    .len = ECC224_PUB_KEY_LEN
};

static HcfBlob mockEcc224PriKeyBlob = {
    .data = mockEcc224PriKeyBlobData,
    .len = ECC224_PRI_KEY_LEN
};

static HcfBlob mockEcc256PubKeyBlob = {
    .data = mockEcc256PubKeyBlobData,
    .len = ECC256_PUB_KEY_LEN
};

static HcfBlob mockEcc256PriKeyBlob = {
    .data = mockEcc256PriKeyBlobData,
    .len = ECC256_PRI_KEY_LEN
};

static HcfBlob mockEcc384PubKeyBlob = {
    .data = mockEcc384PubKeyBlobData,
    .len = ECC384_PUB_KEY_LEN
};

static HcfBlob mockEcc384PriKeyBlob = {
    .data = mockEcc384PriKeyBlobData,
    .len = ECC384_PRI_KEY_LEN
};

static HcfBlob mockEcc512PubKeyBlob = {
    .data = mockEcc512PubKeyBlobData,
    .len = ECC512_PUB_KEY_LEN
};

static HcfBlob mockEcc512PriKeyBlob = {
    .data = mockEcc512PriKeyBlobData,
    .len = ECC512_PRI_KEY_LEN
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

static HcfObjectBase obj = {
    .getClass = GetMockClass,
    .destroy = NULL
};

/**
 * @tc.name: CryptoEccAsyKeyGeneratorTest.CryptoEccAsyKeyGeneratorTest001
 * @tc.desc: Verify that the creation of the ECC224 key pair generator is normal.
 * @tc.type: FUNC
 * @tc.require: I5QWEI
 */
HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest002, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC256", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest003, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC384", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest004, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC512", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest005, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate(nullptr, &generator);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(generator, nullptr);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest006, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"
        "ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD", &generator);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(generator, nullptr);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest007, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC225", &generator);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(generator, nullptr);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest008, TestSize.Level0)
{
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest101, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *className = generator->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest102, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest103, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(NULL);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest104, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&obj);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest105, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgoName(generator);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest106, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgoName(NULL);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest107, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgoName((HcfAsyKeyGenerator *)&obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest201, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest202, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC256", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest203, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC384", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest204, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC512", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest205, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(NULL, NULL, &keyPair);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest206, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair((HcfAsyKeyGenerator *)&obj, NULL, &keyPair);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest207, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generateKeyPair(generator, NULL, NULL);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest301, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest302, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest303, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest304, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest305, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest306, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = NULL;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest307, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest308, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest309, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest310, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(NULL);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest311, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat((HcfKey *)&obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest312, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest313, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(NULL);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest314, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest315, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest316, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded(NULL, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest317, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest318, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), NULL);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest319, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest320, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest321, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest322, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.base.getClass();

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest323, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = NULL;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest324, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest325, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest326, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest327, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(NULL);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest328, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest329, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(&keyPair->priKey->base);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest330, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(NULL);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest331, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm((HcfKey *)&obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest332, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest333, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded(NULL, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest334, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest335, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), NULL);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest401, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest402, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC256", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc256PubKeyBlob, &mockEcc256PriKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest403, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC384", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc384PubKeyBlob, &mockEcc384PriKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest404, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC512", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc512PubKeyBlob, &mockEcc512PriKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest405, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(NULL, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &outKeyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(outKeyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest406, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey((HcfAsyKeyGenerator *)&obj, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob,
        &outKeyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(outKeyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest407, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, NULL, &mockEcc224PriKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest408, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, NULL, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest409, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, NULL, NULL, &outKeyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(outKeyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest410, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, NULL);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest501, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();

    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest502, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest503, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest504, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest505, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest506, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = NULL;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest507, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest508, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest509, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest510, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(NULL);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest511, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat((HcfKey *)&obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest512, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest513, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(NULL);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest514, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest515, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest516, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded(NULL, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest517, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest518, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), NULL);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest519, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest520, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest521, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest522, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.base.getClass();

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest523, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = NULL;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest524, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest525, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest526, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);

    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest527, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(NULL);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest528, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&obj);

    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest529, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(&keyPair->priKey->base);

    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest530, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(NULL);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest531, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm((HcfKey *)&obj);

    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest532, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest533, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded(NULL, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest534, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest535, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->convertKey(generator, NULL, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), NULL);

    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest536, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfBlob outPubKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = outKeyPair->pubKey->base.getEncoded(&(outKeyPair->pubKey->base), &outPubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPubKeyBlob.data, nullptr);
    ASSERT_NE(outPubKeyBlob.len, 0);

    HcfBlob outPriKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = outKeyPair->priKey->base.getEncoded(&(outKeyPair->priKey->base), &outPriKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPriKeyBlob.data, nullptr);
    ASSERT_NE(outPriKeyBlob.len, 0);

    free(pubKeyBlob.data);
    free(priKeyBlob.data);
    free(outPubKeyBlob.data);
    free(outPriKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest537, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, NULL, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_NE(outKeyPair->pubKey, nullptr);
    ASSERT_EQ(outKeyPair->priKey, nullptr);

    HcfBlob outPubKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = outKeyPair->pubKey->base.getEncoded(&(outKeyPair->pubKey->base), &outPubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPubKeyBlob.data, nullptr);
    ASSERT_NE(outPubKeyBlob.len, 0);

    free(pubKeyBlob.data);
    free(outPubKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoEccAsyKeyGeneratorTest, CryptoEccAsyKeyGeneratorTest538, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = NULL;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob priKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = NULL;
    res = generator->convertKey(generator, NULL, NULL, &priKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);
    ASSERT_EQ(outKeyPair->pubKey, nullptr);
    ASSERT_NE(outKeyPair->priKey, nullptr);

    HcfBlob outPriKeyBlob = {
        .data = NULL,
        .len = 0
    };
    res = outKeyPair->priKey->base.getEncoded(&(outKeyPair->priKey->base), &outPriKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPriKeyBlob.data, nullptr);
    ASSERT_NE(outPriKeyBlob.len, 0);

    free(priKeyBlob.data);
    free(outPriKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}
