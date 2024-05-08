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

#include "mac_impl.h"
#include "crypto_log.h"
#include "result.h"

namespace OHOS {
    namespace CryptoFramework {
        MacImpl::MacImpl(char* algName, int32_t* errCode)
        {
            HcfMac *macObj = nullptr;
            HcfResult res = HcfMacCreate(algName, &macObj);
            if (res != HCF_SUCCESS) {
                LOGE("create c macObj failed.");
            }
            *errCode = static_cast<int32_t>(res);
            macObj_ = macObj;
        }

        HcfResult MacImpl::MacInit(HcfSymKey *symKey)
        {
            HcfMac *mac = macObj_;
            HcfResult res = mac->init(mac, symKey);
            return res;
        }

        HcfResult MacImpl::MacUpdate(HcfBlob *input)
        {
            HcfMac *mac = macObj_;
            HcfResult res = mac->update(mac, input);
            return res;
        }

        HcfResult MacImpl::MacDoFinal(HcfBlob *output)
        {
            HcfMac *mac = macObj_;
            HcfResult res = mac->doFinal(mac, output);
            return res;
        }

        uint32_t MacImpl::GetMacLength()
        {
            HcfMac *mac = macObj_;
            uint32_t retLen = mac->getMacLength(mac);
            return retLen;
        }

    }
}