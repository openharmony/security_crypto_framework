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

#include "hcfkdfcreate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include "securec.h"
#include "detailed_hkdf_params.h"
#include "detailed_pbkdf2_params.h"
#include "object_base.h"
#include "blob.h"
#include "kdf.h"
#include "result.h"

namespace OHOS {
    static const char *g_testKdfAlg[] = { "HKDF|SHA1", "HKDF|SHA224", "HKDF|SHA256", "HKDF|SHA384", "HKDF|SHA512",
        "HKDF|SM3", "PBKDF2|SHA1", "PBKDF2|SHA224", "PBKDF2|SHA256", "PBKDF2|SHA384",
        "PBKDF2|SHA512", "PBKDF2|SM3"};
    static const char *g_keyData = "012345678901234567890123456789";
    static const char *g_infoData = "infostring";
    static const char *g_saltData = "saltstring";
    constexpr uint32_t OUT_PUT_MAX_LENGTH = 128;
    constexpr uint32_t OUT_PUT_NORMAL_LENGTH = 32;
    constexpr uint32_t SALT_NORMAL_LENGTH = 16;

    static void TestHkdfGenerateSecretSalt(const char *kdfAlg, const uint8_t* data, size_t size)
    {
        HcfKdf *generator = nullptr;
        HcfResult ret = HcfKdfCreate(kdfAlg, &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
        HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
        HcfBlob salt = {.data = const_cast<uint8_t *>(data), .len = size};
        HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
            .len = strlen(g_keyData)};
        HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
            .len = strlen(g_infoData)};
        HcfHkdfParamsSpec params = {
            .base = { .algName = "HKDF", },
            .key = key,
            .salt = salt,
            .info = info,
            .output = output,
        };
        if (generator != nullptr) {
            generator->generateSecret(generator, &(params.base));
        }
        HcfObjDestroy(generator);
    }

    static void TestHkdfGenerateSecretKey(const char *kdfAlg, const uint8_t* data, size_t size)
    {
        HcfKdf *generator = nullptr;
        HcfResult ret = HcfKdfCreate(kdfAlg, &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
        HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
        HcfBlob key = {.data = const_cast<uint8_t *>(data), .len = size};
        HcfBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
            .len = strlen(g_saltData)};
        HcfBlob info = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_infoData)),
            .len = strlen(g_infoData)};
        HcfHkdfParamsSpec params = {
            .base = { .algName = "HKDF", },
            .key = key,
            .salt = salt,
            .info = info,
            .output = output,
        };
        if (generator != nullptr) {
            generator->generateSecret(generator, &(params.base));
        }
        HcfObjDestroy(generator);
    }

    static void TestHkdfGenerateSecretInfo(const char *kdfAlg, const uint8_t* data, size_t size)
    {
        HcfKdf *generator = nullptr;
        HcfResult ret = HcfKdfCreate(kdfAlg, &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
        HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
        HcfBlob info = {.data = const_cast<uint8_t *>(data), .len = size};
        HcfBlob key = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_keyData)),
            .len = strlen(g_keyData)};
        HcfBlob salt = {.data = reinterpret_cast<uint8_t *>(const_cast<char *>(g_saltData)),
            .len = strlen(g_saltData)};
        HcfHkdfParamsSpec params = {
            .base = { .algName = "HKDF", },
            .key = key,
            .salt = salt,
            .info = info,
            .output = output,
        };
        if (generator != nullptr) {
            generator->generateSecret(generator, &(params.base));
        }
        HcfObjDestroy(generator);
    }

    static void TestPbkdfGenerateSecretWithoutInfo(const char *kdfAlg, const uint8_t* data, size_t size)
    {
        HcfKdf *generator = nullptr;
        HcfResult ret = HcfKdfCreate(kdfAlg, &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        uint8_t out[OUT_PUT_MAX_LENGTH] = {0};
        uint8_t saltData[SALT_NORMAL_LENGTH] = {0};
        HcfBlob output = {.data = out, .len = OUT_PUT_NORMAL_LENGTH};
        HcfBlob salt = {.data = saltData, .len = SALT_NORMAL_LENGTH};
        HcfBlob password = {.data = const_cast<uint8_t *>(data), .len = size};
        HcfPBKDF2ParamsSpec params = {
            .base = { .algName = "PBKDF2", },
            .password = password,
            .salt = salt,
            .iterations = 10000,
            .output = output,
        };
        ret = generator->generateSecret(generator, &(params.base));
        HcfObjDestroy(generator);
    }

    static void TestGetOneAlgoName(const char *kdfAlg)
    {
        HcfKdf *generator = nullptr;
        HcfResult ret = HcfKdfCreate(kdfAlg, &generator);
        if (ret != HCF_SUCCESS) {
            return;
        }
        if (generator != nullptr) {
            generator->getAlgorithm(generator);
        }
    }

    static void TestGenerateSecret(const char *kdfAlg, const uint8_t* data, size_t size)
    {
        TestHkdfGenerateSecretSalt(kdfAlg, data, size);
        TestHkdfGenerateSecretKey(kdfAlg, data, size);
        TestHkdfGenerateSecretInfo(kdfAlg, data, size);
        TestPbkdfGenerateSecretWithoutInfo(kdfAlg, data, size);
    }

    bool HcfKdfCreateFuzzTest(const uint8_t* data, size_t size)
    {
        std::string kdfData(reinterpret_cast<const char *>(data), size);
        TestGetOneAlgoName(kdfData.c_str());
        for (size_t i = 0; i < sizeof(g_testKdfAlg) / sizeof(g_testKdfAlg[0]); i++) {
            const char *algoName = g_testKdfAlg[i];
            TestGenerateSecret(algoName, data, size);
            HcfKdf *generator = nullptr;
            HcfResult res = HcfKdfCreate(algoName, &generator);
            if (res != HCF_SUCCESS) {
                return false;
            }
            HcfObjDestroy(generator);
        }
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::HcfKdfCreateFuzzTest(data, size);
    return 0;
}
