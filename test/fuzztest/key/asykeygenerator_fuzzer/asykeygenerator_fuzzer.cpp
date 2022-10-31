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

#include "asykeygenerator_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "asy_key_generator.h"
#include "blob.h"
#include "result.h"

static bool g_testFlag = true;

namespace OHOS {
    static const int ECC224_PUB_KEY_LEN = 57;
    static const int ECC224_PRI_KEY_LEN = 28;
    static uint8_t g_mockEcc224PubKeyBlobData[ECC224_PUB_KEY_LEN] = { 4, 189, 186, 122, 21, 9, 8, 231, 90, 111, 68,
        222, 207, 200, 53, 114, 236, 246, 204, 9, 171, 197, 57, 173, 138, 38, 180, 217, 55, 234, 181, 87, 143, 199,
        250, 222, 101, 120, 193, 184, 132, 9, 139, 177, 112, 246, 97, 25, 57, 43, 252, 212, 33, 181, 114, 89, 151 };

    static uint8_t g_mockEcc224PriKeyBlobData[ECC224_PRI_KEY_LEN] = { 7, 13, 160, 20, 7, 190, 2, 157, 233,
        245, 164, 249, 218, 30, 241, 3, 198, 136, 155, 15, 168, 198, 237, 117, 95, 45, 142, 183 };

    static void TestEccKey(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        int32_t res = HcfAsyKeyGeneratorCreate("ECC224", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        (void)generator->getAlgoName(generator);
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfKeyPair *convertKeyPair = nullptr;
        static HcfBlob mockEcc224PubKeyBlob = {
            .data = g_mockEcc224PubKeyBlobData,
            .len = ECC224_PUB_KEY_LEN
        };

        static HcfBlob mockEcc224PriKeyBlob = {
            .data = g_mockEcc224PriKeyBlobData,
            .len = ECC224_PRI_KEY_LEN
        };
        res = generator->convertKey(generator, nullptr, &mockEcc224PubKeyBlob, &mockEcc224PriKeyBlob, &convertKeyPair);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(generator);
        HcfObjDestroy(convertKeyPair);
    }

    static void TestRsaKey(void)
    {
        HcfAsyKeyGenerator *generator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("RSA1024", &generator);
        if (res != HCF_SUCCESS) {
            return;
        }
        HcfKeyPair *keyPair = nullptr;
        res = generator->generateKeyPair(generator, nullptr, &keyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(generator);
            return;
        }
        HcfBlob pubKeyBlob = {.data = nullptr, .len = 0};
        HcfBlob priKeyBlob = {.data = nullptr, .len = 0};
        res = keyPair->pubKey->base.getEncoded((HcfKey *)keyPair->pubKey, &pubKeyBlob);
        res = keyPair->priKey->base.getEncoded((HcfKey *)keyPair->priKey, &priKeyBlob);

        HcfKeyPair *dupKeyPair = nullptr;
        res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &dupKeyPair);
        HcfPubKey *pubkey = dupKeyPair->pubKey;
        (void)pubkey->base.getAlgorithm((HcfKey *)pubkey);
        (void)pubkey->base.getFormat((HcfKey *)pubkey);
        (void)pubkey->base.base.getClass();

        HcfBlobDataFree(&pubKeyBlob);
        HcfBlobDataFree(&priKeyBlob);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        HcfObjDestroy(dupKeyPair);
    }

    bool AsyKeyGeneratorFuzzTest(const uint8_t* data, size_t size)
    {
        if (g_testFlag) {
            TestEccKey();
            TestRsaKey();
            g_testFlag = false;
        }
        HcfAsyKeyGenerator *generator = nullptr;
        std::string algoName(reinterpret_cast<const char *>(data), size);
        HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
        if (res != HCF_SUCCESS) {
            return false;
        }
        HcfObjDestroy(generator);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AsyKeyGeneratorFuzzTest(data, size);
    return 0;
}
