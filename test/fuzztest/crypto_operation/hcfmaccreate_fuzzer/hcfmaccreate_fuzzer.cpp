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

#include "hcfmaccreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "blob.h"
#include "mac.h"
#include "result.h"
#include "sym_key_generator.h"
#include "detailed_hmac_params.h"

namespace OHOS {
    static const int KEY_LEN = 16;

    static void TestMacConvertSymKey(const uint8_t* data, size_t size)
    {
        HcfHmacParamsSpec params = {};
        params.base.algName = "HMAC";
        params.mdName = "SHA1";
        HcfMac *macObj = nullptr;
        HcfResult res = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfSymKeyGenerator *generator = nullptr;
        (void)HcfSymKeyGeneratorCreate("AES128", &generator);
        HcfSymKey *key = nullptr;
        HcfBlob keyMaterialBlob = {.data = const_cast<uint8_t *>(data), .len = size};
        generator->convertSymKey(generator, &keyMaterialBlob, &key);

        HcfObjDestroy(macObj);
        HcfObjDestroy(key);
        HcfObjDestroy(generator);
    }

    static void TestMac(const uint8_t* data, size_t size)
    {
        HcfHmacParamsSpec params = {};
        params.base.algName = "HMAC";
        params.mdName = "SHA1";
        HcfMac *macObj = nullptr;
        HcfResult res = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfSymKeyGenerator *generator = nullptr;
        (void)HcfSymKeyGeneratorCreate("AES128", &generator);
        char testKey[] = "abcdefghijklmnop";
        uint32_t testKeyLen = KEY_LEN;
        HcfSymKey *key = nullptr;
        HcfBlob keyMaterialBlob = {.data = reinterpret_cast<uint8_t *>(testKey), .len = testKeyLen};
        generator->convertSymKey(generator, &keyMaterialBlob, &key);

        HcfBlob inBlob = {.data = const_cast<uint8_t *>(data), .len = size};
        (void)macObj->init(macObj, key);
        (void)macObj->update(macObj, &inBlob);
        HcfBlob outBlob = { 0 };
        (void)macObj->doFinal(macObj, &outBlob);
        (void)macObj->getAlgoName(macObj);
        (void)macObj->getMacLength(macObj);
        HcfBlobDataClearAndFree(&outBlob);
        HcfObjDestroy(macObj);
        HcfObjDestroy(key);
        HcfObjDestroy(generator);
    }

    bool HcfMacCreateFuzzTest(const uint8_t* data, size_t size)
    {
        HcfHmacParamsSpec params = {};
        params.mdName = "SHA1";
        std::string alg(reinterpret_cast<const char *>(data), size);
        params.base.algName = alg.c_str();
        TestMacConvertSymKey(data, size);
        TestMac(data, size);
        HcfMac *macObj = nullptr;
        HcfResult res = HcfMacCreate((HcfMacParamsSpec *)&params, &macObj);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(macObj);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfMacCreateFuzzTest(data, size);
    return 0;
}
