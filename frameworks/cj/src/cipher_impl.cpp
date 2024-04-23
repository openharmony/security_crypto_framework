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
#include "cipher_impl.h"
#include "crypto_log.h"

namespace OHOS {
    namespace CryptoFramework {
        CipherImpl::CipherImpl(HcfCipher *cipher)
        {
            cipher_ = cipher;
        }

        HcfResult CipherImpl::CipherInit(HcfCryptoMode opMode, HcfKey *key, HcfParamsSpec *params)
        {
            HcfCipher *cipher = cipher_;
            HcfResult res = cipher->init(cipher, opMode, key, params);
            return res;
        }

        HcfResult CipherImpl::CipherUpdate(HcfBlob *input, HcfBlob *output)
        {
            HcfCipher *cipher = cipher_;
            HcfResult res = cipher->update(cipher, input, output);
            return res;
        }

        HcfResult CipherImpl::CipherDoFinal(HcfBlob *input, HcfBlob *output)
        {
            HcfCipher *cipher = cipher_;
            HcfResult res = cipher->doFinal(cipher, input, output);
            return res;
        }

        HcfResult CipherImpl::SetCipherSpec(CipherSpecItem item, HcfBlob pSource)
        {
            HcfCipher *cipher = cipher_;
            HcfResult res = cipher->setCipherSpecUint8Array(cipher, item, pSource);
            return res;
        }

        HcfResult CipherImpl::GetCipherSpecString(CipherSpecItem item, char **returnString)
        {
            HcfCipher *cipher = cipher_;
            HcfResult res = cipher->getCipherSpecString(cipher, item, returnString);
            return res;
        }

        HcfResult CipherImpl::GetCipherSpecUint8Array(CipherSpecItem item, HcfBlob *returnUint8Array)
        {
            HcfCipher *cipher = cipher_;
            HcfResult res = cipher->getCipherSpecUint8Array(cipher, item, returnUint8Array);
            return res;
        }

        const char *CipherImpl::GetAlgorithm()
        {
            HcfCipher *cipher = cipher_;
            const char *algo = cipher->getAlgorithm(cipher);
            return algo;
        }
    }
}