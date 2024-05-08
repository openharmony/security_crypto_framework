/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "random_impl.h"
#include "result.h"
#include "crypto_log.h"

namespace OHOS {
    namespace CryptoFramework {
        RandomImpl::RandomImpl(int32_t* errCode)
        {
            HcfRand *randObj = nullptr;
            HcfResult res = HcfRandCreate(&randObj);
            if (res != HCF_SUCCESS) {
                LOGE("create c randObj failed.");
            }
            *errCode = static_cast<int32_t>(res);
            randObj_ = randObj;
        }

        const char* RandomImpl::GetAlgName()
        {
            HcfRand *rand = randObj_;
            if (rand == nullptr) {
                LOGE("fail to get rand obj!");
                return nullptr;
            }
            const char *algoName = rand->getAlgoName(rand);
            return algoName;
        }

        HcfBlob RandomImpl::GenerateRandom(int32_t numBytes, int32_t* errCode)
        {
            HcfBlob randBlob = { .data = nullptr, .len = 0};
            HcfRand *rand = randObj_;
            if (rand == nullptr) {
                *errCode = HCF_ERR_MALLOC;
                LOGE("fail to get rand obj!");
                return randBlob;
            }
            HcfResult res = rand->generateRandom(rand, numBytes, &randBlob);
            if (res != HCF_SUCCESS) {
                LOGE("generateRandom failed!");
            }
            *errCode = static_cast<int32_t>(res);
            return randBlob;
        }

        void RandomImpl::SetSeed(HcfBlob *seed, int32_t* errCode)
        {
            HcfRand *rand = randObj_;
            if (rand == nullptr) {
                *errCode = HCF_ERR_MALLOC;
                LOGE("fail to get rand obj!");
                return;
            }
            HcfResult res = rand->setSeed(rand, seed);
            if (res != HCF_SUCCESS) {
                LOGE("set seed failed.");
            }
            *errCode = static_cast<int32_t>(res);
        }
    }
}