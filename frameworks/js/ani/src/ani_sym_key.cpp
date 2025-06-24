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

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace ANI::CryptoFramework {
SymKeyImpl::SymKeyImpl() : symKey(nullptr) {}

SymKeyImpl::SymKeyImpl(HcfSymKey *obj) : symKey(obj) {}

SymKeyImpl::~SymKeyImpl()
{
    HcfObjDestroy(symKey);
    symKey = nullptr;
}

void SymKeyImpl::ClearMem()
{
    TH_THROW(std::runtime_error, "ClearMem not implemented");
}

int64_t SymKeyImpl::GetSymKeyObj()
{
    return reinterpret_cast<int64_t>(symKey);
}

DataBlob SymKeyImpl::GetEncoded()
{
    TH_THROW(std::runtime_error, "GetEncoded not implemented");
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
