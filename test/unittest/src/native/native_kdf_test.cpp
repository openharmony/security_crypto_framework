/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "crypto_common.h"
#include "crypto_asym_key.h"
#include "crypto_kdf.h"
#include "log.h"
#include "memory.h"
#include "memory_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class NativeKdfest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NativeKdfest::SetUpTestCase() {}
void NativeKdfest::TearDownTestCase() {}

void NativeKdfest::SetUp() // add init here, this will be called before test.
{
}

void NativeKdfest::TearDown() // add destroy here, this will be called when test case done.
{
}

static const char *g_keyData = "012345678901234567890123456789";
static const char *g_infoData = "infostring";
static const char *g_saltData = "saltstring";
static const char *g_password = "123456";

constexpr uint32_t KEY_NORMAL_LENGTH = 32;

HWTEST_F(NativeKdfest, NativeKdfest001, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("HKDF", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    Crypto_DataBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
        .len = strlen(g_keyData)};
    Crypto_DataBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
        .len = strlen(g_saltData)};
    Crypto_DataBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
        .len = strlen(g_infoData)};
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &key);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SALT_DATABLOB, &salt);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_INFO_DATABLOB, &info);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    ret = OH_CryptoKdf_Create("HKDF|SHA256|EXTRACT_AND_EXPAND", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, params, KEY_NORMAL_LENGTH, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
    OH_CryptoKdfParams_Destroy(params);
}

HWTEST_F(NativeKdfest, NativeKdfest002, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("PBKDF2", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    Crypto_DataBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
        .len = strlen(g_saltData)};
    int iterations = 10000;
    Crypto_DataBlob iterationsData = {.data = reinterpret_cast<uint8_t *>(&iterations), .len = sizeof(int)};

    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &password);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SALT_DATABLOB, &salt);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_ITER_COUNT_INT, &iterationsData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    ret = OH_CryptoKdf_Create("PBKDF2|SHA256", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, params, KEY_NORMAL_LENGTH, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
    OH_CryptoKdfParams_Destroy(params);
}

HWTEST_F(NativeKdfest, NativeKdfest003, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("SCRYPT", &params);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob password = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_password)),
        .len = strlen(g_password)};
    Crypto_DataBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
        .len = strlen(g_saltData)};

    uint64_t n = 1024;
    uint64_t p = 16;
    uint64_t r = 8;
    uint64_t maxMem = 1067008;
    Crypto_DataBlob nData = {.data = reinterpret_cast<uint8_t *>(&n), .len = sizeof(uint64_t)};
    Crypto_DataBlob pData = {.data = reinterpret_cast<uint8_t *>(&p), .len = sizeof(uint64_t)};
    Crypto_DataBlob rData = {.data = reinterpret_cast<uint8_t *>(&r), .len = sizeof(uint64_t)};
    Crypto_DataBlob maxMemData = {.data = reinterpret_cast<uint8_t *>(&maxMem), .len = sizeof(uint64_t)};
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_KEY_DATABLOB, &password);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SALT_DATABLOB, &salt);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_N_UINT64, &nData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_P_UINT64, &pData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_R_UINT64, &rData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_SetParam(params, CRYPTO_KDF_SCRYPT_MAX_MEM_UINT64, &maxMemData);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    ret = OH_CryptoKdf_Create("SCRYPT", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, params, KEY_NORMAL_LENGTH, &out);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
    OH_CryptoKdfParams_Destroy(params);
}

HWTEST_F(NativeKdfest, NativeKdfest004, TestSize.Level0)
{
    OH_CryptoKdfParams *params = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdfParams_Create("SCRYPT", nullptr);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdfParams_Create("XXXX", &params);
    EXPECT_NE(ret, CRYPTO_SUCCESS);
}

HWTEST_F(NativeKdfest, NativeKdfest005, TestSize.Level0)
{
    Crypto_DataBlob out  = {0};
    OH_CryptoKdf *kdfCtx = nullptr;
    OH_Crypto_ErrCode ret = OH_CryptoKdf_Create("HKDF|SHA256|EXTRACT_AND_EXPAND", &kdfCtx);
    EXPECT_EQ(ret, CRYPTO_SUCCESS);
    ret = OH_CryptoKdf_Derive(kdfCtx, nullptr, KEY_NORMAL_LENGTH, &out);
    EXPECT_NE(ret, CRYPTO_SUCCESS);

    OH_Crypto_FreeDataBlob(&out);
    OH_CryptoKdf_Destroy(kdfCtx);
}
}