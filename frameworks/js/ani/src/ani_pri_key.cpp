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

#include "ani_pri_key.h"

namespace ANI::CryptoFramework {
PriKeyImpl::PriKeyImpl() {}

PriKeyImpl::PriKeyImpl(HcfPriKey *priKey) : priKey_(priKey) {}

PriKeyImpl::~PriKeyImpl()
{
    HcfObjDestroy(this->priKey_);
    this->priKey_ = nullptr;
}

int64_t PriKeyImpl::GetPriKeyObj()
{
    return reinterpret_cast<int64_t>(this->priKey_);
}

void PriKeyImpl::ClearMem()
{
    TH_THROW(std::runtime_error, "ClearMem not implemented");
}

OptKeySpec PriKeyImpl::GetAsyKeySpec(AsyKeySpecEnum itemType)
{
    TH_THROW(std::runtime_error, "GetAsyKeySpec not implemented");
}

DataBlob PriKeyImpl::GetEncodedDer(string_view format)
{
    TH_THROW(std::runtime_error, "GetEncodedDer not implemented");
}

string PriKeyImpl::GetEncodedPem(string_view format, optional_view<KeyEncodingConfig> config)
{
    TH_THROW(std::runtime_error, "GetEncodedPem not implemented");
}

int64_t PriKeyImpl::GetKeyObj()
{
    return reinterpret_cast<int64_t>(&this->priKey_->base);
}

DataBlob PriKeyImpl::GetEncoded()
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return {};
    }
    HcfBlob outBlob = {};
    HcfResult res = this->priKey_->base.getEncoded(&this->priKey_->base, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncoded failed.");
        return {};
    }
    array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string PriKeyImpl::GetFormat()
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return "";
    }
    const char *format = this->priKey_->base.getFormat(&this->priKey_->base);
    return (format == nullptr) ? "" : string(format);
}

string PriKeyImpl::GetAlgName()
{
    if (this->priKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "priKey obj is nullptr!");
        return "";
    }
    const char *algName = this->priKey_->base.getAlgorithm(&this->priKey_->base);
    return (algName == nullptr) ? "" : string(algName);
}
} // namespace ANI::CryptoFramework
