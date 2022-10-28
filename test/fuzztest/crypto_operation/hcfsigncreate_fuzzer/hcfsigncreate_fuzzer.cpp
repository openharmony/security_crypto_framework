/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hcfsigncreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "asy_key_generator.h"
#include "blob.h"
#include "result.h"
#include "signature.h"

static const char *g_mockMessage = "hello world";
const int INPUT_MSG_LEN = 12;

namespace OHOS {
    static void TestSign(void)
    {
        HcfAsyKeyGenerator *generator = NULL;
        HcfResult res = HcfAsyKeyGeneratorCreate("ECC384", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfKeyPair *ecc384KeyPair = NULL;
        res = generator->generateKeyPair(generator, NULL, &ecc384KeyPair);
        HcfObjDestroy(generator);
        if (res != HCF_SUCCESS) {
            return;
        }

        HcfSign *sign = NULL;
        res = HcfSignCreate("ECC384|SHA384", &sign);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(ecc384KeyPair);
            return;
        }
        static HcfBlob mockInput = {
            .data = (uint8_t *)g_mockMessage,
            .len = INPUT_MSG_LEN
        };
        res = sign->init(sign, NULL, ecc384KeyPair->priKey);
        res = sign->update(sign, &mockInput);
        HcfObjDestroy(ecc384KeyPair);
        HcfObjDestroy(sign);
    }

    bool HcfSignCreateFuzzTest(const uint8_t* data, size_t size)
    {
        TestSign();
        HcfSign *sign = nullptr;
        std::string algoName(reinterpret_cast<const char *>(data), size);
        HcfResult res = HcfSignCreate("ECC384|SHA256", &sign);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(sign);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfSignCreateFuzzTest(data, size);
    return 0;
}
