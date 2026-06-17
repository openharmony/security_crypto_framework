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
#include <string>
#include <vector>
#include <unordered_map>
#include "js_api_metrics.h"

using namespace testing::ext;

namespace {
class CryptoJsApiMetricsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(CryptoJsApiMetricsTest, HistogramApiReport001, TestSize.Level1)
{
    static const std::unordered_map<HcfJsApiId, std::string> items = {
        { API_CREATE_RANDOM, "cryptoFramework.createRandom" },
        { API_RANDOM_GENERATE_RANDOM, "cryptoFramework.Random.generateRandom" },
        { API_RANDOM_GENERATE_RANDOM_SYNC, "cryptoFramework.Random.generateRandomSync" },
        { API_RANDOM_SET_SEED, "cryptoFramework.Random.setSeed" },
        { API_RANDOM_ENABLE_HARDWARE_ENTROPY, "cryptoFramework.Random.enableHardwareEntropy" },
    };

    for (const auto &iter : items) {
        HistogramScopeGuard guard(iter.first);
        std::string name = guard.GetApiName();
        EXPECT_EQ(name, iter.second);
    }
}

HWTEST_F(CryptoJsApiMetricsTest, HistogramApiReport002, TestSize.Level1)
{
    static const std::unordered_map<HcfResult, int32_t> items = {
        { HCF_SUCCESS, 0 },
        { HCF_INVALID_PARAMS, 1 },
        { HCF_NOT_SUPPORT, 2 },
        { HCF_ERR_MALLOC, 3 },
        { HCF_ERR_NAPI, 4 },
        { HCF_ERR_ANI, 4 },
        { HCF_ERR_PARAMETER_CHECK_FAILED, 5 },
        { HCF_ERR_INVALID_CALL, 6 },
        { HCF_ERR_CRYPTO_OPERATION, 7 },
    };

    HistogramScopeGuard guard(API_RANDOM_GENERATE_RANDOM);
    for (const auto &iter : items) {
        auto [value, _] = guard.GetCodeValue(iter.first);
        EXPECT_EQ(value, iter.second);
    }
}

HWTEST_F(CryptoJsApiMetricsTest, HistogramApiReport003, TestSize.Level1)
{
    HistogramScopeGuard guard(API_RANDOM_GENERATE_RANDOM);
    guard.SetErrorCode(HCF_ERR_ANI);
    auto [value, boundary] = guard.GetCodeValue(HCF_ERR_ANI);
    EXPECT_EQ(value, 4);
    EXPECT_EQ(boundary, 8);
    std::string name = guard.GetApiName();
    EXPECT_EQ(name, "cryptoFramework.Random.generateRandom");
    guard.DisableScopeGuard();
    name = guard.GetApiName();
    EXPECT_EQ(name, "");
}
}
