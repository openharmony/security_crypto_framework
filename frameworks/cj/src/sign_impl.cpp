/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sign_impl.h"
#include "crypto_log.h"
#include "result.h"

namespace OHOS {
    namespace CryptoFramework {
        SignImpl::SignImpl(char* algName, int32_t* errCode)
        {
            HcfSign *signObj = nullptr;
            HcfResult res = HcfSignCreate(algName, &signObj);
            if (res != HCF_SUCCESS) {
                LOGE("create c signObj failed.");
            }
            *errCode = static_cast<int32_t>(res);
            signObj_ = signObj;
        }

    }
}