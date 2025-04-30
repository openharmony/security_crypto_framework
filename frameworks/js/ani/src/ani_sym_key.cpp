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

#include "ani_sym_key.h"

namespace ANI::CryptoFramework {
SymKeyImpl::SymKeyImpl() : symKey_(nullptr) {}

SymKeyImpl::SymKeyImpl(HcfSymKey *symKey) : symKey_(symKey) {}

SymKeyImpl::~SymKeyImpl()
{
    HcfObjDestroy(this->symKey_);
    this->symKey_ = nullptr;
}

int64_t SymKeyImpl::GetKeyObj()
{
    return reinterpret_cast<int64_t>(&this->symKey_->key);
}

int64_t SymKeyImpl::GetSymKeyObj()
{
    return reinterpret_cast<int64_t>(this->symKey_);
}

void SymKeyImpl::ClearMem()
{
    TH_THROW(std::runtime_error, "ClearMem not implemented");
}

DataBlob SymKeyImpl::GetEncoded()
{
    if (this->symKey_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "symKey obj is nullptr!");
        return { array<uint8_t>(nullptr, 0) };
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = this->symKey_->key.getEncoded(&this->symKey_->key, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "getEncoded failed.");
        return { array<uint8_t>(nullptr, 0) };
    }
    array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

string SymKeyImpl::GetFormat()
{
    TH_THROW(std::runtime_error, "GetFormat not implemented");
}

string SymKeyImpl::GetAlgName()
{
    TH_THROW(std::runtime_error, "GetAlgName not implemented");
}
} // namespace ANI::CryptoFramework
