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

#include "key_agreement_impl.h"

namespace OHOS {
namespace CryptoFramework {
KeyAgreementImpl::KeyAgreementImpl(HcfKeyAgreement *keyAgreement)
{
    this->keyAgreement_ = keyAgreement;
}

KeyAgreementImpl::~KeyAgreementImpl()
{
    HcfObjDestroy(this->keyAgreement_);
    this->keyAgreement_ = nullptr;
}

HcfKeyAgreement *KeyAgreementImpl::GetKeyAgreement()
{
    return this->keyAgreement_;
}

HcfBlob KeyAgreementImpl::GenerateSecret(HcfPriKey *priKey, HcfPubKey *pubKey, int32_t *errCode)
{
    HcfBlob returnSecret = { .data = nullptr, .len = 0 };
    if (this->keyAgreement_ == nullptr || priKey == nullptr || pubKey == nullptr)  {
        *errCode = HCF_INVALID_PARAMS;
        return returnSecret;
    }
    *errCode = this->keyAgreement_->generateSecret(keyAgreement_, priKey, pubKey, &returnSecret);
    return returnSecret;
}
}
}