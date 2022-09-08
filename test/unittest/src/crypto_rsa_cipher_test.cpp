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
#include "cipher.h"
#include "key_pair.h"
#include "memory.h"
#include "cstring"

using namespace std;
using namespace testing::ext;

class RsaCipherTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void RsaCipherTest::SetUpTestCase() {}
void RsaCipherTest::TearDownTestCase() {}
void RsaCipherTest::SetUp() {}
void RsaCipherTest::TearDown() {}

// HcfCipherCreate correct case: RSAXXX + padding
HWTEST_F(RsaCipherTest, RsaCipherTest100, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest110, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest120, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest130, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest140, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest150, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA512|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest160, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest170, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest180, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_MD5", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest190, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA1|MGF1_SHA512", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest200, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA512|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest210, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA768|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest220, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest230, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA512|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest240, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA768|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest250, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest260, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA512|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest270, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA768|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest280, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    EXPECT_NE(cipher->base.getClass(), nullptr);
    EXPECT_NE(cipher->base.destroy, nullptr);
    EXPECT_NE(cipher->init, nullptr);
    EXPECT_NE(cipher->update, nullptr);
    EXPECT_NE(cipher->doFinal, nullptr);
    OH_HCF_ObjDestroy(cipher);
}


// HcfCipherCreate Incorrect case
HWTEST_F(RsaCipherTest, RsaCipherTest300, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256", NULL);
    EXPECT_NE(res, HCF_SUCCESS);
}

HWTEST_F(RsaCipherTest, RsaCipherTest310, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate(NULL, &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(RsaCipherTest, RsaCipherTest320, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256|2111111111111111111111111111111111111111111111"
        "111111111111123123", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(RsaCipherTest, RsaCipherTest330, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA333", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(RsaCipherTest, RsaCipherTest340, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP111|SHA256|MGF1_SHA333", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(RsaCipherTest, RsaCipherTest350, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2111048|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

HWTEST_F(RsaCipherTest, RsaCipherTest360, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256111|MGF1_SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

// destroyCipher
HWTEST_F(RsaCipherTest, RsaCipherTest400, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA2048|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(cipher, nullptr);
    OH_HCF_ObjDestroy(cipher);
    cipher = NULL;
    OH_HCF_ObjDestroy(cipher);
}

// init correct case
HWTEST_F(RsaCipherTest, RsaCipherTest500, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest510, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(cipher);
}

// init incorrect case
HWTEST_F(RsaCipherTest, RsaCipherTest600, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->priKey, NULL);
    EXPECT_NE(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest610, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_NE(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(cipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest620, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(NULL, DECRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_NE(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(cipher);
}

// incorrect case: use diff class, we ignore it in this version
HWTEST_F(RsaCipherTest, RsaCipherTest630, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *aesCipher = NULL;
    res = HcfCipherCreate("AES128|ECB|PKCS7", &aesCipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(aesCipher, DECRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_NE(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(cipher);
    OH_HCF_ObjDestroy(aesCipher);
}

HWTEST_F(RsaCipherTest, RsaCipherTest640, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, NULL, NULL);
    EXPECT_NE(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);
}

// correct case: update not support
HWTEST_F(RsaCipherTest, RsaCipherTest700, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfResult res = HCF_SUCCESS;
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = NULL, .len = 0};
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->update(cipher, &input, &encoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(encoutput.data, nullptr);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(cipher);
}

// dofinal correct case
HWTEST_F(RsaCipherTest, RsaCipherTest800, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = NULL, .len = 0};
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);

    HcfBlob decoutput = {.data = NULL, .len = 0};
    cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaCipherTest, RsaCipherTest810, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA4096|PRIMES_3", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = NULL, .len = 0};
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);

    HcfBlob decoutput = {.data = NULL, .len = 0};
    cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

HWTEST_F(RsaCipherTest, RsaCipherTest820, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = NULL, .len = 0};
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);

    HcfBlob decoutput = {.data = NULL, .len = 0};
    cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

// incorrect case: algName out of boundary
HWTEST_F(RsaCipherTest, RsaCipherTest830, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan[] = "this is rsa cipher test aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!\0";
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = NULL, .len = 0};
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);

    HcfBlob decoutput = {.data = NULL, .len = 0};
    cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)keyPair->priKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_NE(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);
    EXPECT_STRNE((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);

    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}


// Incorrect case: use OAEP pading without mgf1md
HWTEST_F(RsaCipherTest, RsaCipherTest840, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

// Incorrect case: use OAEP pading without md
HWTEST_F(RsaCipherTest, RsaCipherTest845, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;

    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|MGF1_SHA256", &cipher);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(cipher, nullptr);
}

// Correct case: test genEncoded and convert key
HWTEST_F(RsaCipherTest, RsaCipherTest850, TestSize.Level0)
{
    uint8_t plan[] = "this is rsa cipher test!\0";
    HcfAsyKeyGenerator *generator = NULL;
    HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    HcfBlob pubKeyBlob = {.data = NULL, .len = 0};
    HcfBlob priKeyBlob = {.data = NULL, .len = 0};
    res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *dupKeyPair = NULL;
    res = generator->convertKey(generator, NULL, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(generator);
    OH_HCF_ObjDestroy(keyPair);

    HcfBlob input = {.data = (uint8_t *)plan, .len = strlen((char *)plan)};
    HcfBlob encoutput = {.data = NULL, .len = 0};
    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)dupKeyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input, &encoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);

    HcfBlob decoutput = {.data = NULL, .len = 0};
    cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)dupKeyPair->priKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &encoutput, &decoutput);
    EXPECT_EQ(res, HCF_SUCCESS);
    OH_HCF_ObjDestroy(cipher);
    EXPECT_STREQ((char *)plan, (char *)decoutput.data);

    HcfFree(encoutput.data);
    HcfFree(decoutput.data);
    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    OH_HCF_ObjDestroy(dupKeyPair);
}

// correct case: test OAEP Plaintext boundary:
// RSA_size - (md_result_len * mgf1md_result_len) - 2 = 128 - (32 + 32) - 2 = 62
HWTEST_F(RsaCipherTest, RsaCipherTest860, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan1[] = "00112233445566778899aabbccddeeff0aaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint8_t plan2[] = "00112233445566778899aabbccddeeffaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint8_t plan3[] = "00112233445566778899aabbccddeeff00112233445566778899aaaaaaaaaa";
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1_OAEP|SHA256|MGF1_SHA256", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob encoutput1 = {.data = NULL, .len = 0};
    HcfBlob encoutput2 = {.data = NULL, .len = 0};
    HcfBlob encoutput3 = {.data = NULL, .len = 0};
    HcfBlob input1 = {.data = (uint8_t *)plan1, .len = strlen((char *)plan1)};
    HcfBlob input2 = {.data = (uint8_t *)plan2, .len = strlen((char *)plan2)};
    HcfBlob input3 = {.data = (uint8_t *)plan3, .len = strlen((char *)plan3)};
    res = cipher->doFinal(cipher, &input1, &encoutput1);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input2, &encoutput2);
    EXPECT_NE(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input3, &encoutput2);
    EXPECT_EQ(res, HCF_SUCCESS);


    OH_HCF_ObjDestroy(cipher);
    HcfFree(encoutput1.data);
    HcfFree(encoutput2.data);
    HcfFree(encoutput3.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

// correct case: test nopadding boundary < RSA_size(rsa)
HWTEST_F(RsaCipherTest, RsaCipherTest870, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan1[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "1122334455111111111116";
    uint8_t plan2[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "112233445511111111111611111111111";
    
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|NoPadding", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);


    HcfBlob encoutput1 = {.data = NULL, .len = 0};
    HcfBlob encoutput2 = {.data = NULL, .len = 0};

    HcfBlob input1 = {.data = (uint8_t *)plan1, .len = strlen((char *)plan1)};
    HcfBlob input2 = {.data = (uint8_t *)plan2, .len = strlen((char *)plan2)};

    res = cipher->doFinal(cipher, &input1, &encoutput1);
    EXPECT_NE(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input2, &encoutput2);
    EXPECT_EQ(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(cipher);
    HcfFree(encoutput1.data);
    HcfFree(encoutput2.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}

// correct case: test PKCS1 boundary < RSA_size(rsa) - 11
HWTEST_F(RsaCipherTest, RsaCipherTest880, TestSize.Level0)
{
    HcfResult res = HCF_SUCCESS;
    uint8_t plan1[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "1122334455111111111116";
    uint8_t plan2[] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffasdasdbccddeeff0011223344556600"
        "11223344551111111111161";
    
    HcfAsyKeyGenerator *generator = NULL;
    res = HcfAsyKeyGeneratorCreate("RSA1024|PRIMES_2", &generator);

    HcfKeyPair *keyPair = NULL;
    res = generator->generateKeyPair(generator, NULL, &keyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(keyPair, nullptr);
    EXPECT_NE(keyPair->priKey, nullptr);
    EXPECT_NE(keyPair->pubKey, nullptr);

    HcfCipher *cipher = NULL;
    res = HcfCipherCreate("RSA1024|PKCS1", &cipher);
    EXPECT_EQ(res, HCF_SUCCESS);

    res = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)keyPair->pubKey, NULL);
    EXPECT_EQ(res, HCF_SUCCESS);

    HcfBlob encoutput1 = {.data = NULL, .len = 0};
    HcfBlob encoutput2 = {.data = NULL, .len = 0};

    HcfBlob input1 = {.data = (uint8_t *)plan1, .len = strlen((char *)plan1)};
    HcfBlob input2 = {.data = (uint8_t *)plan2, .len = strlen((char *)plan2)};

    res = cipher->doFinal(cipher, &input1, &encoutput1);
    EXPECT_EQ(res, HCF_SUCCESS);
    res = cipher->doFinal(cipher, &input2, &encoutput2);
    EXPECT_NE(res, HCF_SUCCESS);

    OH_HCF_ObjDestroy(cipher);
    HcfFree(encoutput1.data);
    HcfFree(encoutput2.data);
    OH_HCF_ObjDestroy(keyPair);
    OH_HCF_ObjDestroy(generator);
}
