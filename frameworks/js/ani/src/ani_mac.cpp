/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "ani_mac.h"
#include "detailed_hmac_params.h"

namespace ANI::CryptoFramework {
MacImpl::MacImpl() {}

MacImpl::MacImpl(HcfMac *mac) : mac_(mac) {}

MacImpl::~MacImpl()
{
    HcfObjDestroy(this->mac_);
    this->mac_ = nullptr;
}

void MacImpl::InitSync(weak::SymKey key)
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return;
    }
    HcfSymKey *obj = reinterpret_cast<HcfSymKey *>(key->GetSymKeyObj());
    HcfResult res = this->mac_->init(this->mac_, obj);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac init failed!");
        return;
    }
}

void MacImpl::UpdateSync(DataBlob const& input)
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return;
    }
    HcfBlob inBlob = { .data = input.data.data(), .len = input.data.size() };
    HcfResult res = this->mac_->update(this->mac_, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac update failed!");
        return;
    }
}

DataBlob MacImpl::DoFinalSync()
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return { array<uint8_t>(nullptr, 0) };
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = this->mac_->doFinal(this->mac_, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac doFinal failed!");
        return { array<uint8_t>(nullptr, 0) };
    }
    array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

int32_t MacImpl::GetMacLength()
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return 0;
    }
    uint32_t length = this->mac_->getMacLength(this->mac_);
    return static_cast<int32_t>(length);
}

string MacImpl::GetAlgName()
{
    if (this->mac_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return "";
    }
    const char *algName = this->mac_->getAlgoName(this->mac_);
    return (algName == nullptr) ? "" : string(algName);
}

Mac CreateMac(string_view algName)
{
    HcfMac *mac = nullptr;
    HcfHmacParamsSpec parmas = { { "HMAC" }, algName.c_str() };
    HcfResult res = HcfMacCreate(reinterpret_cast<HcfMacParamsSpec *>(&parmas), &mac);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C mac obj failed.");
        return make_holder<MacImpl, Mac>();
    }
    return make_holder<MacImpl, Mac>(mac);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateMac(ANI::CryptoFramework::CreateMac);
// NOLINTEND
