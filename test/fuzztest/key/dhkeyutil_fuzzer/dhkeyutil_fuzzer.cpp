/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "dhkeyutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "dh_key_util.h"
#include "blob.h"
#include "detailed_dh_key_params.h"
#include "result.h"

using namespace std;

namespace OHOS {
    static bool g_testFlag = true;
    static void TestDhKey(void)
    {
        HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
        int32_t res = HcfDhKeyUtilCreate(3072, 512, &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            return;
        }
        FreeDhCommParamsSpec(returnCommonParamSpec);
    }

    bool DhKeyUtilFuzzTest(const uint32_t* pLen, size_t size)
    {
        if (g_testFlag) {
            TestDhKey();
            g_testFlag = false;
        }
        HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
        HcfResult res = HcfDhKeyUtilCreate(*pLen, 0, &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            return false;
        }
        FreeDhCommParamsSpec(returnCommonParamSpec);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint32_t* pLen, size_t size)
{
    /* Run your code on data */
    OHOS::DhKeyUtilFuzzTest(pLen, size);
    return 0;
}
