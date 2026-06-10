/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <unordered_map>
#include "native_api_metrics.h"

using namespace testing::ext;

class NativeApiMetricsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(NativeApiMetricsTest, HistogramApiReport001, TestSize.Level1)
{
    static const std::unordered_map<HcfNativeApiId, const char *> items = {
        { API_CRYPTO_RAND_CREATE, "CryptoArchitectureKit.OH_CryptoRand_Create" },
        { API_CRYPTO_RAND_GENERATE_RANDOM, "CryptoArchitectureKit.OH_CryptoRand_GenerateRandom" },
        { API_CRYPTO_RAND_GET_ALGO_NAME, "CryptoArchitectureKit.OH_CryptoRand_GetAlgoName" },
        { API_CRYPTO_RAND_SET_SEED, "CryptoArchitectureKit.OH_CryptoRand_SetSeed" },
        { API_CRYPTO_RAND_ENABLE_HARDWARE_ENTROPY, "CryptoArchitectureKit.OH_CryptoRand_EnableHardwareEntropy" },
        { API_CRYPTO_RAND_DESTROY, "CryptoArchitectureKit.OH_CryptoRand_Destroy" },
        { API_CRYPTO_DIGEST_DESTROY, "CryptoArchitectureKit.OH_DigestCrypto_Destroy" },
    };

    HistogramApiReport(API_CRYPTO_RAND_CREATE, true, 0);
    for (const auto &iter : items) {
        const char *name = GetApiName(iter.first);
        EXPECT_STREQ(name, iter.second);
    }
}

HWTEST_F(NativeApiMetricsTest, HistogramApiReport002, TestSize.Level1)
{
    static const std::unordered_map<OH_Crypto_ErrCode, int32_t> items = {
        { CRYPTO_SUCCESS, 0 },
        { CRYPTO_INVALID_PARAMS, 1 },
        { CRYPTO_NOT_SUPPORTED, 2 },
        { CRYPTO_MEMORY_ERROR, 3 },
        { CRYPTO_PARAMETER_CHECK_FAILED, 4 },
        { CRYPTO_INVALID_CALL, 5 },
        { CRYPTO_OPERTION_ERROR, 6 },
    };

    HistogramApiReport(API_CRYPTO_RAND_CREATE, true, 0);
    for (const auto &iter : items) {
        int32_t boundary = 0;
        int32_t value = GetCodeValue(iter.first, &boundary);
        EXPECT_EQ(value, iter.second);
        EXPECT_EQ(boundary, 7);
    }
}

HWTEST_F(NativeApiMetricsTest, HistogramApiReport003, TestSize.Level1)
{
    int64_t start = GetTimeMilliseconds();
    int32_t boundary = 0;
    int32_t value = GetCodeValue(CRYPTO_INVALID_CALL, &boundary);
    EXPECT_EQ(value, 5);
    EXPECT_EQ(boundary, 7);

    const char *name = GetApiName(API_CRYPTO_KDF_DERIVE);
    EXPECT_STREQ(name, "CryptoArchitectureKit.OH_CryptoKdf_Derive");

    int64_t time = GetTimeMilliseconds() - start;
    HistogramApiReport(API_CRYPTO_RAND_CREATE, CRYPTO_INVALID_PARAMS, time);
    HistogramApiReport(API_CRYPTO_MAC_GET_LENGTH, true, time);
}
