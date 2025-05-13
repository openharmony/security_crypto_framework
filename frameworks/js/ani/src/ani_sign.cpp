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

#include "ani_sign.h"

namespace ANI::CryptoFramework {
SignImpl::SignImpl() {}

SignImpl::SignImpl(HcfSign *sign) : sign_(sign) {}

SignImpl::~SignImpl()
{
    HcfObjDestroy(this->sign_);
    this->sign_ = nullptr;
}

void SignImpl::InitSync(weak::PriKey priKey)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "sign obj is nullptr!");
        return;
    }
    HcfPriKey *obj = reinterpret_cast<HcfPriKey *>(priKey->GetPriKeyObj());
    HcfResult res = this->sign_->init(this->sign_, nullptr, obj);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "sign init failed.");
        return;
    }
}

void SignImpl::UpdateSync(DataBlob const& data)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "sign obj is nullptr!");
        return;
    }
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(data.data, inBlob);
    HcfResult res = this->sign_->update(this->sign_, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "sign update failed!");
        return;
    }
}

DataBlob SignImpl::SignSync(OptDataBlob const& data)
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "sign obj is nullptr!");
        return {};
    }
    HcfBlob *inBlob = nullptr;
    HcfBlob dataBlob = {};
    if (data.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(data.get_DATABLOB_ref().data, dataBlob);
        inBlob = &dataBlob;
    }
    HcfBlob outBlob = {};
    HcfResult res = this->sign_->sign(this->sign_, inBlob, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "sign doFinal failed!");
        return {};
    }
    array<uint8_t> out(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { out };
}

void SignImpl::SetSignSpec(SignSpecEnum itemType, OptIntUint8Arr const& itemValue)
{
    TH_THROW(std::runtime_error, "SetSignSpec not implemented");
}

OptStrInt SignImpl::GetSignSpec(SignSpecEnum itemType)
{
    TH_THROW(std::runtime_error, "GetSignSpec not implemented");
}

string SignImpl::GetAlgName()
{
    if (this->sign_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "sign obj is nullptr!");
        return "";
    }
    const char *algName = this->sign_->getAlgoName(this->sign_);
    return string(algName);
}

Sign CreateSign(string_view algName)
{
    HcfSign *sign = nullptr;
    HcfResult res = HcfSignCreate(algName.c_str(), &sign);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create sign obj fail!");
        return make_holder<SignImpl, Sign>();
    }
    return make_holder<SignImpl, Sign>(sign);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateSign(ANI::CryptoFramework::CreateSign);
// NOLINTEND
