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
#include "symkey_generator_impl.h"
#include "crypto_log.h"

namespace OHOS {
    namespace CryptoFramework {
        SymKeyGeneratorImpl::SymKeyGeneratorImpl(char* algName, int32_t* errCode)
        {
            HcfSymKeyGenerator *generator = nullptr;
            HcfResult res = HcfSymKeyGeneratorCreate(algName, &generator);
            if (res != HCF_SUCCESS) {
                LOGE("create C generator fail.");
            }
            *errCode = static_cast<int32_t>(res);
            generator_ = generator;
        }

        const char *SymKeyGeneratorImpl::GetAlgName()
        {
            HcfSymKeyGenerator *generator = generator_;
            const char *algo = generator->getAlgoName(generator);
            return algo;
        }


        HcfResult SymKeyGeneratorImpl::GenerateSymKey(HcfSymKey **symKey)
        {
            HcfSymKeyGenerator *generator = generator_;
            HcfResult res = generator->generateSymKey(generator, symKey);
            return res;
        }

        HcfResult SymKeyGeneratorImpl::ConvertKey(const HcfBlob key, HcfSymKey **symKey)
        {
            HcfSymKeyGenerator *generator = generator_;
            HcfResult res = generator->convertSymKey(generator, &key, symKey);
            return res;
        }
    }
}