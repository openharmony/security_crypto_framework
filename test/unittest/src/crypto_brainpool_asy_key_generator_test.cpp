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
#include "securec.h"

#include "asy_key_generator.h"
#include "ecc_asy_key_generator_openssl.h"
#include "blob.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "params_parser.h"
#include "ecc_key_util.h"
#include "key_utils.h"
#include "key_pair.h"
#include "object_base.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoBrainPoolAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoBrainPoolAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoBrainPoolAsyKeyGeneratorTest::SetUp() {}
void CryptoBrainPoolAsyKeyGeneratorTest::TearDown() {}

HcfBlob g_mockECC_BrainPool160r1PriKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockECC_BrainPool160r1PubKeyBlob = {
    .data = nullptr,
    .len = 0
};

static const char *GetMockClass(void)
{
    return "HcfSymKeyGenerator";
}

HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static void ECC_BrainPool160r1KeyBlob(HcfBlob * priblob, HcfBlob *pubblob)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &g_mockECC_BrainPool160r1PriKeyBlob);
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &g_mockECC_BrainPool160r1PubKeyBlob);
}

void CryptoBrainPoolAsyKeyGeneratorTest::SetUpTestCase()
{
    ECC_BrainPool160r1KeyBlob(&g_mockECC_BrainPool160r1PriKeyBlob, &g_mockECC_BrainPool160r1PubKeyBlob);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_2, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_3, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP192r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_4, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP192t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_5, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP224r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_6, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP224t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_7, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP256r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_8, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP256t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_9, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP320r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_10, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP320t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_11, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP384r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_12, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP384t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_13, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP512r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest001_14, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP512t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest002, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *className = generator->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest003, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160t1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);
    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest004, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest005, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&g_obj);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest006, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgoName(generator);
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest007, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgoName(nullptr);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest008, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    const char *algName = generator->getAlgoName((HcfAsyKeyGenerator *)&g_obj);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest009, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest010, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(nullptr, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest011, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair((HcfAsyKeyGenerator *)&g_obj, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest012, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    res = generator->generateKeyPair(generator, nullptr, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest013, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest014, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest015, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest016, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest017, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest018, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest019, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest020, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest021, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    ASSERT_NE(format, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest022, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest023, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest024, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest025, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest026, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest027, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest028, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest029, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest030, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest031, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest032, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest033, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest034, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.base.getClass();
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest035, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest036, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest037, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest038, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest039, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest040, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest041, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest042, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest043, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest044, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest045, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest046, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest047, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest048, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest049, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(nullptr, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &outKeyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest050, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey((HcfAsyKeyGenerator *)&g_obj, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &outKeyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest051, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(nullptr, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &outKeyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(outKeyPair, nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest052, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &g_mockECC_BrainPool160r1PriKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest053, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, nullptr, &outKeyPair);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(outKeyPair, nullptr);

    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest054, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, nullptr);

    ASSERT_NE(res, HCF_SUCCESS);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest055, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest056, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy((HcfObjectBase *)(&(keyPair->base)));
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest057, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest058, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    keyPair->base.destroy(&g_obj);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest059, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest060, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy((HcfObjectBase *)(&(keyPair->pubKey->base.base)));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest061, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    keyPair->pubKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest062, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    keyPair->pubKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest063, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    ASSERT_NE(format, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest064, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest065, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest066, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_NE(algName, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest067, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest068, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algName, nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest069, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest070, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest071, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest072, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest073, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest074, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest075, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest076, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.base.getClass();
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest077, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy((HcfObjectBase *)(&(keyPair->priKey->base.base)));
    keyPair->priKey = nullptr;

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest078, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest079, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest080, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(&keyPair->priKey->base);
    ASSERT_NE(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest081, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest082, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest083, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(&keyPair->priKey->base);
    ASSERT_NE(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest084, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algName = keyPair->priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest085, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *format = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(format, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest086, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    free(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest087, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest088, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest089, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);

    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    free(blob.data);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest090, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outKeyPair, nullptr);

    HcfBlob outPubKeyBlob = { .data = nullptr, .len = 0 };
    res = outKeyPair->pubKey->base.getEncoded(&(outKeyPair->pubKey->base), &outPubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(outPubKeyBlob.data, nullptr);
    ASSERT_NE(outPubKeyBlob.len, 0);

    HcfBlob outPriKeyBlob = { .data = nullptr, .len = 0 };
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

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest091, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest092, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineGenerateKeyPair((HcfAsyKeyGeneratorSpi *)&g_obj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest093, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = spiObj->engineConvertKey((HcfAsyKeyGeneratorSpi *)&g_obj, nullptr, nullptr, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest094, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);
    spiObj->base.destroy(nullptr);
    HcfObjDestroy(spiObj);
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest095, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_ECC,
        .bits = HCF_ALG_ECC_256,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *spiObj = nullptr;
    int32_t res = HcfAsyKeyGeneratorSpiEccCreate(&params, &spiObj);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(spiObj, nullptr);

    spiObj->base.destroy(&g_obj);
    HcfObjDestroy(spiObj);
}

static void MemoryMallocTestFunc(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPubKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPriKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->priKey->base.getEncoded(&(tmpKeyPair->priKey->base), &tmpPriKeyBlob);
        if (res != HCF_SUCCESS) {
            free(tmpPubKeyBlob.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfKeyPair *tmpOutKeyPair = nullptr;
        res = tmpGenerator->convertKey(tmpGenerator, nullptr, &tmpPubKeyBlob, &tmpPriKeyBlob, &tmpOutKeyPair);
        free(tmpPubKeyBlob.data);
        free(tmpPriKeyBlob.data);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
        if (res == HCF_SUCCESS) {
            HcfObjDestroy(tmpOutKeyPair);
        }
    }
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest096, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    free(pubKeyBlob.data);
    free(priKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFunc(mallocCount);
    EndRecordMallocNum();
}

static void OpensslMockTestFunc(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPubKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPriKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->priKey->base.getEncoded(&(tmpKeyPair->priKey->base), &tmpPriKeyBlob);
        if (res != HCF_SUCCESS) {
            free(tmpPubKeyBlob.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfKeyPair *tmpOutKeyPair = nullptr;
        res = tmpGenerator->convertKey(tmpGenerator, nullptr, &tmpPubKeyBlob, &tmpPriKeyBlob, &tmpOutKeyPair);
        free(tmpPubKeyBlob.data);
        free(tmpPriKeyBlob.data);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
        if (res == HCF_SUCCESS) {
            HcfObjDestroy(tmpOutKeyPair);
        }
    }
}

HWTEST_F(CryptoBrainPoolAsyKeyGeneratorTest, CryptoBrainPoolAsyKeyGeneratorTest097, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    int32_t res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    free(pubKeyBlob.data);
    free(priKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount);
    EndRecordOpensslCallNum();
}
}