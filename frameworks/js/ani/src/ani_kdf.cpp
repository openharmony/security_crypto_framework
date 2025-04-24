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

#include "ani_kdf.h"
#include "detailed_pbkdf2_params.h"
#include "detailed_hkdf_params.h"
#include "detailed_scrypt_params.h"

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace {
const std::string PBKDF2_ALG_NAME = "PBKDF2";
const std::string HKDF_ALG_NAME = "HKDF";
const std::string SCRYPT_ALG_NAME = "SCRYPT";

void SetPBKDF2ParamsSpecAttribute(const PBKDF2Spec &params, HcfPBKDF2ParamsSpec &pbkdf2Spec, HcfBlob &outBlob)
{
    pbkdf2Spec.base.algName = params.base.algName.c_str();
    if (params.password.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        pbkdf2Spec.password.data = reinterpret_cast<uint8_t *>
            (const_cast<char *>(params.password.get_STRING_ref().c_str()));
        pbkdf2Spec.password.len = params.password.get_STRING_ref().size();
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        pbkdf2Spec.password.data = params.password.get_UINT8ARRAY_ref().data();
        pbkdf2Spec.password.len = params.password.get_UINT8ARRAY_ref().size();
    }
    pbkdf2Spec.salt.data = params.salt.data();
    pbkdf2Spec.salt.len = params.salt.size();
    pbkdf2Spec.iterations = params.iterations;
    int32_t keySize = params.keySize;
    outBlob.data = static_cast<uint8_t *>(HcfMalloc(keySize, 0));
    outBlob.len = (outBlob.data == nullptr) ? 0 : keySize;
    pbkdf2Spec.output = outBlob;
}

void SetHkdfParamsSpecAttribute(const HKDFSpec &params, HcfHkdfParamsSpec &hkdfSpec, HcfBlob &outBlob)
{
    hkdfSpec.base.algName = params.base.algName.c_str();
    if (params.key.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        hkdfSpec.key.data = reinterpret_cast<uint8_t *>(const_cast<char *>(params.key.get_STRING_ref().c_str()));
        hkdfSpec.key.len = params.key.get_STRING_ref().size();
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        hkdfSpec.key.data = params.key.get_UINT8ARRAY_ref().data();
        hkdfSpec.key.len = params.key.get_UINT8ARRAY_ref().size();
    }
    hkdfSpec.salt.data = params.salt.data();
    hkdfSpec.salt.len = params.salt.size();
    hkdfSpec.info.data = params.info.data();
    hkdfSpec.info.len = params.info.size();
    int32_t keySize = params.keySize;
    outBlob.data = static_cast<uint8_t *>(HcfMalloc(keySize, 0));
    outBlob.len = (outBlob.data == nullptr) ? 0 : keySize;
    hkdfSpec.output = outBlob;
}

void SetScryptParamsSpecAttribute(const ScryptSpec &params, HcfScryptParamsSpec &scryptSpec, HcfBlob &outBlob)
{
    scryptSpec.base.algName = params.base.algName.c_str();
    if (params.passphrase.get_tag() == OptStrUint8Arr::tag_t::STRING) {
        scryptSpec.passPhrase.data = reinterpret_cast<uint8_t *>
            (const_cast<char *>(params.passphrase.get_STRING_ref().c_str()));
        scryptSpec.passPhrase.len = params.passphrase.get_STRING_ref().size();
    } else { // OptStrUint8Arr::tag_t::UINT8ARRAY
        scryptSpec.passPhrase.data = params.passphrase.get_UINT8ARRAY_ref().data();
        scryptSpec.passPhrase.len = params.passphrase.get_UINT8ARRAY_ref().size();
    }
    scryptSpec.salt.data = params.salt.data();
    scryptSpec.salt.len = params.salt.size();
    scryptSpec.n = params.n;
    scryptSpec.r = params.r;
    scryptSpec.p = params.p;
    scryptSpec.maxMem = params.maxMemory;
    int32_t keySize = params.keySize;
    outBlob.data = static_cast<uint8_t *>(HcfMalloc(keySize, 0));
    outBlob.len = (outBlob.data == nullptr) ? 0 : keySize;
    scryptSpec.output = outBlob;
}
} // namespace

namespace ANI::CryptoFramework {
KdfImpl::KdfImpl() {}

KdfImpl::KdfImpl(HcfKdf *kdf) : kdf_(kdf) {}

KdfImpl::~KdfImpl()
{
    HcfObjDestroy(this->kdf_);
    this->kdf_ = nullptr;
}

DataBlob KdfImpl::GenerateSecretSync(OptExtKdfSpec const& params)
{
    if (this->kdf_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "kdf obj is nullptr!");
        return { array<uint8_t>(nullptr, 0) };
    }
    HcfKdfParamsSpec *paramsSpec = nullptr;
    HcfPBKDF2ParamsSpec pbkdf2Spec = {};
    HcfHkdfParamsSpec hkdfSpec = {};
    HcfScryptParamsSpec scryptSpec = {};
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    const std::string &algName = params.get_KDFSPEC_ref().algName.c_str();
    if (params.get_tag() == OptExtKdfSpec::tag_t::PBKDF2SPEC && algName == PBKDF2_ALG_NAME) {
        SetPBKDF2ParamsSpecAttribute(params.get_PBKDF2SPEC_ref(), pbkdf2Spec, outBlob);
        paramsSpec = reinterpret_cast<HcfKdfParamsSpec *>(&pbkdf2Spec);
    } else if (params.get_tag() == OptExtKdfSpec::tag_t::HKDFSPEC && algName == HKDF_ALG_NAME) {
        SetHkdfParamsSpecAttribute(params.get_HKDFSPEC_ref(), hkdfSpec, outBlob);
        paramsSpec = reinterpret_cast<HcfKdfParamsSpec *>(&hkdfSpec);
    } else if (params.get_tag() == OptExtKdfSpec::tag_t::SCRYPTSPEC && algName == SCRYPT_ALG_NAME) {
        SetScryptParamsSpecAttribute(params.get_SCRYPTSPEC_ref(), scryptSpec, outBlob);
        paramsSpec = reinterpret_cast<HcfKdfParamsSpec *>(&scryptSpec);
    } else {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "invalid kdf spec!");
        return { array<uint8_t>(nullptr, 0) };
    }
    HcfResult res = this->kdf_->generateSecret(this->kdf_, paramsSpec);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "kdf generateSecret failed!");
        return { array<uint8_t>(nullptr, 0) };
    }
    array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string KdfImpl::GetAlgName()
{
    if (this->kdf_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "kdf obj is nullptr!");
        return "";
    }
    const char *algName = this->kdf_->getAlgorithm(this->kdf_);
    return (algName == nullptr) ? "" : string(algName);
}

Kdf CreateKdf(string_view algName)
{
    HcfKdf *kdf = nullptr;
    HcfResult res = HcfKdfCreate(algName.c_str(), &kdf);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C kdf obj failed.");
        return make_holder<KdfImpl, Kdf>();
    }
    return make_holder<KdfImpl, Kdf>(kdf);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateKdf(CreateKdf);
// NOLINTEND
