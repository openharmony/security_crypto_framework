/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "hcfrandcreate_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "blob.h"
#include "rand.h"
#include "result.h"
#include "securec.h"

const uint8_t* g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos = 0;

template<class T>
T GetDate()
{
    T object{};
    size_t objectSize = sizeof(T);
    if (g_baseFuzzData == nullptr || objectSize > g_baseFuzzSize - g_baseFuzzPos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_baseFuzzData + g_baseFuzzPos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objectSize;
    return object;
}

namespace OHOS {
    bool HcfRandCreateFuzzTest(const uint8_t* data, size_t size)
    {
        g_baseFuzzData = data;
        g_baseFuzzSize = size;
        g_baseFuzzPos = 0;
        int32_t numBytes = GetDate<int32_t>();
        HcfRand *randObj = nullptr;
        HcfResult res = HcfRandCreate(&randObj);
        if (res != HCF_SUCCESS) {
            return false;
        }
        struct HcfBlob randomBlob = { 0 };
        (void)randObj->generateRandom(randObj, numBytes, &randomBlob);
        struct HcfBlob seedBlob = { 0 };
        (void)randObj->setSeed(randObj, &seedBlob);
        (void)randObj->getAlgoName(randObj);
        HcfBlobDataFree(&randomBlob);
        HcfBlobDataFree(&seedBlob);
        HcfObjDestroy(randObj);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfRandCreateFuzzTest(data, size);
    return 0;
}

