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

#include "ani_cipher.h"
#include "detailed_iv_params.h"
#include "detailed_gcm_params.h"
#include "detailed_ccm_params.h"

namespace {
using namespace ANI::CryptoFramework;

const std::string IV_PARAMS_SPEC = "IvParamsSpec";
const std::string GCM_PARAMS_SPEC = "GcmParamsSpec";
const std::string CCM_PARAMS_SPEC = "CcmParamsSpec";

const char *GetIvParamsSpecType()
{
    return IV_PARAMS_SPEC.c_str();
}

const char *GetGcmParamsSpecType()
{
    return GCM_PARAMS_SPEC.c_str();
}

const char *GetCcmParamsSpecType()
{
    return CCM_PARAMS_SPEC.c_str();
}

void SetIvParamsSpecAttribute(const IvParamsSpec &params, HcfIvParamsSpec &ivParamsSpec)
{
    ivParamsSpec.base.getType = GetIvParamsSpecType;
    ArrayU8ToDataBlob(params.iv.data, ivParamsSpec.iv);
}

void SetGcmParamsSpecAttribute(const GcmParamsSpec &params, HcfGcmParamsSpec &gcmParamsSpec)
{
    gcmParamsSpec.base.getType = GetGcmParamsSpecType;
    ArrayU8ToDataBlob(params.iv.data, gcmParamsSpec.iv);
    ArrayU8ToDataBlob(params.aad.data, gcmParamsSpec.aad);
    ArrayU8ToDataBlob(params.authTag.data, gcmParamsSpec.tag);
}

void SetCcmParamsSpecAttribute(const CcmParamsSpec &params, HcfCcmParamsSpec &ccmParamsSpec)
{
    ccmParamsSpec.base.getType = GetCcmParamsSpecType;
    ArrayU8ToDataBlob(params.iv.data, ccmParamsSpec.iv);
    ArrayU8ToDataBlob(params.aad.data, ccmParamsSpec.aad);
    ArrayU8ToDataBlob(params.authTag.data, ccmParamsSpec.tag);
}
} // namespace

namespace ANI::CryptoFramework {
CipherImpl::CipherImpl() {}

CipherImpl::CipherImpl(HcfCipher *cipher) : cipher_(cipher) {}

CipherImpl::~CipherImpl()
{
    HcfObjDestroy(this->cipher_);
    this->cipher_ = nullptr;
}

void CipherImpl::InitSync(CryptoMode opMode, weak::Key key, OptParamsSpec const& params)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "cipher obj is nullptr!");
        return;
    }
    HcfParamsSpec *paramsSpec = nullptr;
    HcfIvParamsSpec ivParamsSpec = {};
    HcfGcmParamsSpec gcmParamsSpec = {};
    HcfCcmParamsSpec ccmParamsSpec = {};
    if (params.get_tag() != OptParamsSpec::tag_t::EMPTY) {
        const OptExtParamsSpec &tmp = params.get_PARAMSSPEC_ref();
        const std::string &algName = tmp.get_PARAMSSPEC_ref().algName.c_str();
        if (tmp.get_tag() == OptExtParamsSpec::tag_t::IVPARAMSSPEC && algName == IV_PARAMS_SPEC) {
            SetIvParamsSpecAttribute(tmp.get_IVPARAMSSPEC_ref(), ivParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&ivParamsSpec);
        } else if (tmp.get_tag() == OptExtParamsSpec::tag_t::GCMPARAMSSPEC && algName == GCM_PARAMS_SPEC) {
            SetGcmParamsSpecAttribute(tmp.get_GCMPARAMSSPEC_ref(), gcmParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&gcmParamsSpec);
        } else if (tmp.get_tag() == OptExtParamsSpec::tag_t::CCMPARAMSSPEC && algName == CCM_PARAMS_SPEC) {
            SetCcmParamsSpecAttribute(tmp.get_CCMPARAMSSPEC_ref(), ccmParamsSpec);
            paramsSpec = reinterpret_cast<HcfParamsSpec *>(&ccmParamsSpec);
        } else {
            ANI_LOGE_THROW(HCF_INVALID_PARAMS, "invalid cipher spec!");
            return;
        }
    }
    HcfKey *hcfKey = reinterpret_cast<HcfKey *>(key->GetKeyObj());
    HcfResult res = this->cipher_->init(this->cipher_, static_cast<HcfCryptoMode>(opMode.get_value()),
        hcfKey, paramsSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "init cipher fail.");
        return;
    }
}

DataBlob CipherImpl::UpdateSync(DataBlob const& input)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "cipher obj is nullptr!");
        return {};
    }
    HcfBlob inBlob = {};
    HcfBlob outBlob = {};
    ArrayU8ToDataBlob(input.data, inBlob);
    HcfResult res = this->cipher_->update(this->cipher_, &inBlob, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "cipher update failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

DataBlob CipherImpl::DoFinalSync(OptDataBlob const& input)
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "cipher obj is nullptr!");
        return {};
    }
    HcfBlob *inBlob = nullptr;
    HcfBlob dataBlob = {};
    if (input.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        ArrayU8ToDataBlob(input.get_DATABLOB_ref().data, dataBlob);
        inBlob = &dataBlob;
    }
    HcfBlob outBlob = {};
    HcfResult res = this->cipher_->doFinal(this->cipher_, inBlob, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "cipher doFinal failed!");
        return {};
    }
    array<uint8_t> data = {};
    DataBlobToArrayU8(outBlob, data);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

void CipherImpl::SetCipherSpec(CipherSpecEnum itemType, array_view<uint8_t> itemValue)
{
    TH_THROW(std::runtime_error, "SetCipherSpec not implemented");
}

OptStrUint8Arr CipherImpl::GetCipherSpec(CipherSpecEnum itemType)
{
    TH_THROW(std::runtime_error, "GetCipherSpec not implemented");
}

string CipherImpl::GetAlgName()
{
    if (this->cipher_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "cipher obj is nullptr!");
        return "";
    }
    const char *algName = this->cipher_->getAlgorithm(this->cipher_);
    return (algName == nullptr) ? "" : string(algName);
}

Cipher CreateCipher(string_view transformation)
{
    HcfCipher *cipher = nullptr;
    HcfResult res = HcfCipherCreate(transformation.c_str(), &cipher);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C cipher obj fail!");
        return make_holder<CipherImpl, Cipher>();
    }
    return make_holder<CipherImpl, Cipher>(cipher);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateCipher(ANI::CryptoFramework::CreateCipher);
// NOLINTEND
