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
#include <fstream>
#include <iostream>

#include "sym_key_generator.h"
#include "cipher.h"
#include "log.h"
#include "memory.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"


using namespace std;
using namespace testing::ext;
const int32_t FILE_BLOCK_SIZE = 1024;
const int32_t RAND_MAX_NUM = 100;
const bool IS_DEBUG = false;

class AesEncryptTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AesEncryptTest::SetUpTestCase() {}

void AesEncryptTest::TearDownTestCase() {}

void AesEncryptTest::SetUp() // add init here, this will be called before test.
{
}

void AesEncryptTest::TearDown() // add destroy here, this will be called when test case done.
{
}

static void PrintfHex(const char *tag, uint8_t *in, int inLen)
{
    if (!IS_DEBUG) {
        return;
    }
    printf("%s:\n", tag);
    for (int i = 0; i < inLen; i++) {
        printf("%02hhX", in[i]);
    }
    printf("\n");
}

static int32_t GenerateSymKey(const char *algoName, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = NULL;

    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!");
        return ret;
    }

    ret = generator->generateSymKey(generator, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    return ret;
}

static int32_t ConvertSymKey(const char *algoName, HcfSymKey **key)
{
    HcfSymKeyGenerator *generator = NULL;
    uint8_t keyMaterial[] = {
        0xba, 0x3b, 0xc2, 0x71, 0x21, 0x1e, 0x30, 0x56,
        0xad, 0x47, 0xfc, 0x5a, 0x46, 0x39, 0xee, 0x7c
    };
    HcfBlob keyTmpBlob = {.data = (uint8_t *)keyMaterial, .len = 16};

    int32_t ret = HcfSymKeyGeneratorCreate(algoName, &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        return ret;
    }

    ret = generator->convertSymKey(generator, &keyTmpBlob, key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }
    PrintfHex("keybinary", keyTmpBlob.data, keyTmpBlob.len);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    return ret;
}

/* just rand data fill file for test */
static int32_t GeneratorFile(const char *fileName, int32_t genFileSize)
{
    if (genFileSize == 0) {
        return 0;
    }
    uint8_t buffer[FILE_BLOCK_SIZE] = {0};
    std::ifstream file(fileName);
    
    if (file.good()) {
        file.close();
        return 0;
    }
    ofstream outfile(fileName, ios::out|ios::binary|ios::app);
    if (outfile.is_open()) {
        while (genFileSize) {
            for (uint32_t i = 0; i < FILE_BLOCK_SIZE; i++) {
                buffer[i] = (rand() % RAND_MAX_NUM) + 1;
            }
            genFileSize -= FILE_BLOCK_SIZE;
            outfile.write(reinterpret_cast<const char *>(buffer), FILE_BLOCK_SIZE);
        }
        outfile.close();
    }
    return 0;
}

static int32_t CompareFileContent()
{
    int32_t ret = -1;
    ifstream infile1, infile2;
    infile1.open("/data/test_aes.txt", ios::in|ios::binary);
    infile1.seekg (0, infile1.end);
    uint32_t length1 = infile1.tellg();
    infile1.seekg (0, infile1.beg);

    infile2.open("/data/test_aes_new.txt", ios::in|ios::binary);
    infile2.seekg (0, infile2.end);
    uint32_t length2 = infile2.tellg();
    infile2.seekg (0, infile2.beg);
    if (length1 != length2) {
        return ret;
    }
    uint8_t buffer1[FILE_BLOCK_SIZE] = {0};
    uint8_t buffer2[FILE_BLOCK_SIZE] = {0};
    for (uint32_t i = 0; i < length1 / FILE_BLOCK_SIZE; i++) {
        infile1.read(reinterpret_cast<char *>(buffer1), FILE_BLOCK_SIZE);
        infile2.read(reinterpret_cast<char *>(buffer2), FILE_BLOCK_SIZE);
        ret = memcmp(buffer1, buffer2, FILE_BLOCK_SIZE);
        if (ret != 0) {
            goto clearup;
        }
    }
clearup:
    infile1.close();
    infile2.close();
    return ret;
}

static int32_t AesMultiBlockEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params)
{
    HcfBlob output = {};
    ifstream infile;
    ofstream outfile;
    infile.open("/data/test_aes.txt", ios::in|ios::binary);
    infile.seekg (0, infile.end);
    uint32_t length = infile.tellg();
    infile.seekg (0, infile.beg);
    uint8_t buffer[1024] = {0};
    outfile.open("/data/test_aes_enc.txt", ios::out|ios::binary);
    HcfBlob input = {.data = (uint8_t *)buffer, .len = FILE_BLOCK_SIZE};
    uint32_t count = length / FILE_BLOCK_SIZE;

    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        goto clearup;
    }
    for (uint32_t i = 0; i < count; i++) {
        infile.read(reinterpret_cast<char *>(buffer), FILE_BLOCK_SIZE);
        ret = cipher->update(cipher, &input, &output);
        if (ret != 0) {
            LOGE("update failed!");
            goto clearup;
        }
        if (output.data != nullptr && output.len > 0) {
            outfile.write(reinterpret_cast<const char *>(output.data), output.len);
        }
        if (output.data != NULL) {
            HcfFree(output.data);
            output.data = NULL;
        }
    }
    ret = cipher->doFinal(cipher, NULL, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        goto clearup;
    }
    if (output.data != nullptr && output.len > 0) {
        outfile.write((const char *)output.data, output.len);
    }

    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
    }
clearup:
    outfile.close();
    infile.close();

    return ret;
}

static int32_t AesMultiBlockDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params)
{
    HcfBlob output = {};
    ifstream infile;
    ofstream outfile;
    infile.open("/data/test_aes_enc.txt", ios::in|ios::binary);
    infile.seekg (0, infile.end);
    uint32_t length = infile.tellg();
    infile.seekg (0, infile.beg);
    uint8_t buffer[1024] = {0};
    outfile.open("/data/test_aes_new.txt", ios::out|ios::binary);
    HcfBlob input = {.data = (uint8_t *)buffer, .len = FILE_BLOCK_SIZE};

    uint32_t count = length / FILE_BLOCK_SIZE;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        goto clearup;
    }
    for (uint32_t i = 0; i < count; i++) {
        infile.read(reinterpret_cast<char *>(buffer), FILE_BLOCK_SIZE);
        ret = cipher->update(cipher, &input, &output);
        if (ret != 0) {
            LOGE("update failed!");
            goto clearup;
        }
        if (output.data != nullptr && output.len > 0) {
            outfile.write(reinterpret_cast<const char *>(output.data), output.len);
        }
        if (output.data != NULL) {
            HcfFree(output.data);
            output.data = NULL;
        }
    }
    ret = cipher->doFinal(cipher, NULL, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        goto clearup;
    }
    if (output.data != nullptr && output.len > 0) {
        outfile.write((const char *)output.data, output.len);
    }

    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
    }
clearup:
    outfile.close();
    infile.close();

    return ret;
}

static int32_t AesEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
        return ret;
    }
    *cipherTextLen = output.len;
    if (output.len > 0 && output.data != NULL) {
        (void)memcpy_s(cipherText, maxLen, output.data, output.len);
    }
    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
    }
    ret = cipher->doFinal(cipher, NULL, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.len > 0 && output.data != NULL) {
        (void)memcpy_s(cipherText + *cipherTextLen, maxLen - *cipherTextLen, output.data, output.len);
    }
    *cipherTextLen += output.len;
    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
    }
    PrintfHex("ciphertext", cipherText, *cipherTextLen);
    return 0;
}

static int32_t AesDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)cipherText, .len = cipherTextLen};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        return ret;
    }

    ret = cipher->update(cipher, &input, &output);
    if (ret != 0) {
        LOGE("update failed!");
        return ret;
    }
    if (output.len > 0 && output.data != NULL) {
        (void)memcpy_s(cipherText, maxLen, output.data, output.len);
    }
    cipherTextLen = output.len;
    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
        output.len = 0;
    }
    ret = cipher->doFinal(cipher, NULL, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.len > 0 && output.data != NULL) {
        (void)memcpy_s(cipherText + cipherTextLen, maxLen - cipherTextLen, output.data, output.len);
    }
    cipherTextLen += output.len;
    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
        output.len = 0;
    }
    PrintfHex("planText", cipherText, cipherTextLen);
    ret = memcmp(cipherText, plainText, cipherTextLen);
    ret =  ret || (cipherTextLen == sizeof(plainText) - 1) ? 0 : 1;
    return ret;
}

static int32_t AesNoUpdateEncrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int *cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)plainText, .len = 13};
    HcfBlob output = {};
    int32_t maxLen = *cipherTextLen;
    int32_t ret = cipher->init(cipher, ENCRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        return ret;
    }

    *cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.len > 0 && output.data != NULL) {
        (void)memcpy_s(cipherText, maxLen, output.data, output.len);
    }
    *cipherTextLen += output.len;
    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
    }
    PrintfHex("ciphertext", cipherText, *cipherTextLen);
    return 0;
}

static int32_t AesNoUpdateDecrypt(HcfCipher *cipher, HcfSymKey *key, HcfParamsSpec *params,
    uint8_t *cipherText, int cipherTextLen)
{
    uint8_t plainText[] = "this is test!";
    HcfBlob input = {.data = (uint8_t *)cipherText, .len = cipherTextLen};
    HcfBlob output = {};
    int32_t maxLen = cipherTextLen;
    int32_t ret = cipher->init(cipher, DECRYPT_MODE, (HcfKey *)key, params);
    if (ret != 0) {
        LOGE("init failed! %d", ret);
        return ret;
    }

    cipherTextLen = 0;
    ret = cipher->doFinal(cipher, &input, &output);
    if (ret != 0) {
        LOGE("doFinal failed!");
        return ret;
    }
    if (output.len > 0 && output.data != NULL) {
        (void)memcpy_s(cipherText, maxLen, output.data, output.len);
    }
    cipherTextLen += output.len;
    if (output.data != NULL) {
        HcfFree(output.data);
        output.data = NULL;
        output.len = 0;
    }
    PrintfHex("planText", cipherText, cipherTextLen);
    ret = memcmp(cipherText, plainText, cipherTextLen);
    ret =  ret || (cipherTextLen == sizeof(plainText) - 1) ? 0 : 1;
    return ret;
}


HWTEST_F(AesEncryptTest, AesEncryptTest001, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }
clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest002, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }
clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest003, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest004, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CBC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest005, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest006, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CBC|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest007, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CTR|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest008, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CTR|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest009, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CTR|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest010, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|OFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest011, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest012, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|OFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }
clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest013, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest014, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest015, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}


HWTEST_F(AesEncryptTest, AesEncryptTest016, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB1|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest017, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB1|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest018, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB1|PKCS7", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest019, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|NoPadding", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest020, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS5", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest021, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS7", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest022, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|NoPadding", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest023, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS5", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest024, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS7", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest025, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed, ret:%d!", ret);
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    PrintfHex("gcm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed, ret:%d!", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest026, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|GCM|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed, ret:%d!", ret);
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    PrintfHex("gcm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed, ret:%d!", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest027, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|GCM|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed, ret:%d!", ret);
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    PrintfHex("gcm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 16;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed, ret:%d!", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest028, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed!");
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    PrintfHex("ccm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 12;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest029, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CCM|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed!");
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    PrintfHex("ccm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 12;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}


HWTEST_F(AesEncryptTest, AesEncryptTest030, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CCM|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed!");
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    PrintfHex("ccm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 12;

    ret = AesDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest031, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    uint8_t codeCipherText[] = {
        0xF5, 0x12, 0xA0, 0x33, 0xCD, 0xCF, 0x0D, 0x32,
        0x3E, 0xFF, 0x80, 0x53, 0x89, 0xB6, 0xE4, 0xFE
    };

    ret = ConvertSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = memcmp(cipherText, codeCipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("cipherText cpmpare failed!");
        goto clearup;
    }

    ret = AesDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest032, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest033, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest034, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest035, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CBC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_NE(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest036, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CBC|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest037, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CBC|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest038, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CTR|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest039, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CTR|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest040, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CTR|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest041, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|OFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest042, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|OFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest043, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|OFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest044, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest045, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest046, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}


HWTEST_F(AesEncryptTest, AesEncryptTest047, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB1|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest048, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB1|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest049, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB1|PKCS7", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest050, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|NoPadding", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest051, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS5", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest052, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB8|PKCS7", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest053, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|NoPadding", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest054, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS5", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest055, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfIvParamsSpec ivSpec = {};
    HcfSymKeyGenerator *generator = NULL;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = HcfSymKeyGeneratorCreate("AES128", &generator);
    if (ret != 0) {
        LOGE("HcfSymKeyGeneratorCreate failed!%d", ret);
        goto clearup;
    }

    ret = generator->generateSymKey(generator, &key);
    if (ret != 0) {
        LOGE("generateSymKey failed!");
    }

    ret = HcfCipherCreate("AES128|CFB128|PKCS7", &cipher);// CFB1/CFB8/CFB128 bit
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    OH_HCF_ObjDestroy((HcfObjectBase *)generator);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest056, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|GCM|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed, ret:%d!", ret);
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    PrintfHex("gcm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 16;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed, ret:%d!", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest057, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|GCM|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed, ret:%d!", ret);
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    PrintfHex("gcm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 16;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed, ret:%d!", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest058, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[16] = {0};
    uint8_t iv[12] = {0}; // openssl only support nonce 12 bytes, tag 16bytes
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    HcfGcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|GCM|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed, ret:%d!", ret);
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 16, cipherText + cipherTextLen - 16, 16);
    PrintfHex("gcm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 16;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed, ret:%d!", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest059, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CCM|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed!");
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    PrintfHex("ccm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 12;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest060, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CCM|PKCS5", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed!");
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    PrintfHex("ccm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 12;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}


HWTEST_F(AesEncryptTest, AesEncryptTest061, TestSize.Level0)
{
    int ret = 0;
    uint8_t aad[8] = {0};
    uint8_t tag[12] = {0};
    uint8_t iv[7] = {0};
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    HcfCcmParamsSpec spec = {};
    spec.aad.data = aad;
    spec.aad.len = sizeof(aad);
    spec.tag.data = tag;
    spec.tag.len = sizeof(tag);
    spec.iv.data = iv;
    spec.iv.len = sizeof(iv);

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("GenerateSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CCM|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed!");
        goto clearup;
    }

    (void)memcpy_s(spec.tag.data, 12, cipherText + cipherTextLen - 12, 12);
    PrintfHex("ccm tag", spec.tag.data, spec.tag.len);
    cipherTextLen -= 12;

    ret = AesNoUpdateDecrypt(cipher, key, (HcfParamsSpec *)&spec, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest062, TestSize.Level0)
{
    int ret = 0;
    uint8_t cipherText[128] = {0};
    int cipherTextLen = 128;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    uint8_t codeCipherText[] = {
        0xF5, 0x12, 0xA0, 0x33, 0xCD, 0xCF, 0x0D, 0x32,
        0x3E, 0xFF, 0x80, 0x53, 0x89, 0xB6, 0xE4, 0xFE
    };

    ret = ConvertSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("ConvertSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|PKCS7", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesNoUpdateEncrypt(cipher, key, NULL, cipherText, &cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = memcmp(cipherText, codeCipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("cipherText cpmpare failed!");
        goto clearup;
    }

    ret = AesNoUpdateDecrypt(cipher, key, NULL, cipherText, cipherTextLen);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest063, TestSize.Level0)
{
    int ret = 0;
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    ret = GeneratorFile("/data/test_aes.txt", 10 * FILE_BLOCK_SIZE);
    if (ret != 0) {
        LOGE("GeneratorFile failed!");
        goto clearup;
    }
    ret = ConvertSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("ConvertSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|ECB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesMultiBlockEncrypt(cipher, key, NULL);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesMultiBlockDecrypt(cipher, key, NULL);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
    ret = CompareFileContent();
    if (ret != 0) {
        LOGE("CompareFileContent failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest064, TestSize.Level0)
{
    int ret = 0;
    HcfIvParamsSpec ivSpec = {};
    uint8_t iv[16] = {0};
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;

    ret = GeneratorFile("/data/test_aes.txt", 10 * FILE_BLOCK_SIZE);
    if (ret != 0) {
        LOGE("GeneratorFile failed!");
        goto clearup;
    }

    ret = ConvertSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("ConvertSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CBC|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }

    ret = AesMultiBlockEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesMultiBlockDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
    ret = CompareFileContent();
    if (ret != 0) {
        LOGE("CompareFileContent failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest065, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = ConvertSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("ConvertSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CTR|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = GeneratorFile("/data/test_aes.txt", 10 * FILE_BLOCK_SIZE);
    if (ret != 0) {
        LOGE("GeneratorFile failed!");
        goto clearup;
    }

    ret = AesMultiBlockEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesMultiBlockDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
    ret = CompareFileContent();
    if (ret != 0) {
        LOGE("CompareFileContent failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest066, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("ConvertSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|OFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = GeneratorFile("/data/test_aes.txt", 10 * FILE_BLOCK_SIZE);
    if (ret != 0) {
        LOGE("GeneratorFile failed!");
        goto clearup;
    }

    ret = AesMultiBlockEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesMultiBlockDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
    ret = CompareFileContent();
    if (ret != 0) {
        LOGE("CompareFileContent failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(AesEncryptTest, AesEncryptTest067, TestSize.Level0)
{
    int ret = 0;
    uint8_t iv[16] = {0};

    HcfIvParamsSpec ivSpec = {};
    HcfCipher *cipher = NULL;
    HcfSymKey *key = NULL;
    ivSpec.iv.data = iv;
    ivSpec.iv.len = 16;

    ret = GenerateSymKey("AES128", &key);
    if (ret != 0) {
        LOGE("ConvertSymKey failed!");
        goto clearup;
    }

    ret = HcfCipherCreate("AES128|CFB|NoPadding", &cipher);
    if (ret != 0) {
        LOGE("HcfCipherCreate failed!");
        goto clearup;
    }
    ret = GeneratorFile("/data/test_aes.txt", 10 * FILE_BLOCK_SIZE);
    if (ret != 0) {
        LOGE("GeneratorFile failed!");
        goto clearup;
    }

    ret = AesMultiBlockEncrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateEncrypt failed! %d", ret);
        goto clearup;
    }

    ret = AesMultiBlockDecrypt(cipher, key, (HcfParamsSpec *)&ivSpec);
    if (ret != 0) {
        LOGE("AesNoUpdateDecrypt failed! %d", ret);
        goto clearup;
    }
    ret = CompareFileContent();
    if (ret != 0) {
        LOGE("CompareFileContent failed!");
        goto clearup;
    }

clearup:
    OH_HCF_ObjDestroy((HcfObjectBase *)key);
    OH_HCF_ObjDestroy((HcfObjectBase *)cipher);
    EXPECT_EQ(ret, 0);
}
