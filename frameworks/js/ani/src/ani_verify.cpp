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

#include "ani_verify.h"
#include "ani_pub_key.h"

namespace ANI::CryptoFramework {
VerifyImpl::VerifyImpl() {}

VerifyImpl::VerifyImpl(HcfVerify *verify) : verify_(verify) {}

VerifyImpl::~VerifyImpl()
{
    HcfObjDestroy(this->verify_);
    this->verify_ = nullptr;
}

void VerifyImpl::InitSync(weak::PubKey pubKey)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "verify obj is nullptr!");
        return;
    }
    HcfPubKey *hcfPubKey = reinterpret_cast<HcfPubKey *>(pubKey->GetPubKeyObj());
    HcfResult res = this->verify_->init(this->verify_, nullptr, hcfPubKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify init failed.");
        return;
    }
}

void VerifyImpl::UpdateSync(DataBlob const& input)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "verify obj is nullptr!");
        return;
    }
    HcfBlob inBlob = {};
    ArrayU8ToDataBlob(input.data, inBlob);
    HcfResult res = this->verify_->update(this->verify_, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "verify update failed!");
        return;
    }
}

bool VerifyImpl::VerifySync(OptDataBlob const& data, DataBlob const& signature)
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "verify obj is nullptr!");
        return false;
    }
    HcfBlob *inBlob = nullptr;
    HcfBlob dataBlob = {};
    if (data.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(data.get_DATABLOB_ref().data, dataBlob);
        inBlob = &dataBlob;
    }
    HcfBlob signatureData = {};
    ArrayU8ToDataBlob(signature.data, signatureData);
    bool res = this->verify_->verify(this->verify_, inBlob, &signatureData);
    if (!res) {
        LOGE("verify doFinal failed.");
        return false;
    }
    return true;
}

OptDataBlob VerifyImpl::RecoverSync(DataBlob const& signature)
{
    TH_THROW(std::runtime_error, "RecoverSync not implemented");
}

void VerifyImpl::SetVerifySpec(SignSpecEnum itemType, OptIntUint8Arr const& itemValue)
{
    TH_THROW(std::runtime_error, "SetVerifySpec not implemented");
}

OptStrInt VerifyImpl::GetVerifySpec(SignSpecEnum itemType)
{
    TH_THROW(std::runtime_error, "GetVerifySpec not implemented");
}

string VerifyImpl::GetAlgName()
{
    if (this->verify_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "verify obj is nullptr!");
        return "";
    }
    const char *algName = this->verify_->getAlgoName(this->verify_);
    return (algName == nullptr) ? "" : string(algName);
}

Verify CreateVerify(string_view algName)
{
    HcfVerify *verify = nullptr;
    HcfResult res = HcfVerifyCreate(algName.c_str(), &verify);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create verify obj fail!");
        return make_holder<VerifyImpl, Verify>();
    }
    return make_holder<VerifyImpl, Verify>(verify);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateVerify(ANI::CryptoFramework::CreateVerify);
// NOLINTEND
