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

#include "ani_md.h"

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace ANI::CryptoFramework {
MdImpl::MdImpl() : mdObj(nullptr) {}

MdImpl::MdImpl(HcfMd *obj) : mdObj(obj) {}

MdImpl::~MdImpl() {}

void MdImpl::UpdateSync(DataBlob const& input)
{
    if (mdObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "md obj is nullptr!");
        return;
    }
    HcfBlob inBlob = { .data = input.data.data(), .len = input.data.size() };
    HcfResult res = mdObj->update(mdObj, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "md doFinal failed!");
        return;
    }
}

DataBlob MdImpl::DigestSync()
{
    if (mdObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "md obj is nullptr!");
        return { taihe::array<uint8_t>(nullptr, 0) };
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = mdObj->doFinal(mdObj, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac doFinal failed!");
        return { taihe::array<uint8_t>(nullptr, 0) };
    }
    taihe::array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

int32_t MdImpl::GetMdLength()
{
    if (mdObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "md obj is nullptr!");
        return 0;
    }
    uint32_t length = mdObj->getMdLength(mdObj);
    return static_cast<int32_t>(length);
}

string MdImpl::GetAlgName()
{
    if (mdObj == nullptr) {
        return "";
    }
    const char *algName = mdObj->getAlgoName(mdObj);
    return (algName == nullptr) ? "" : string(algName);
}

Md CreateMd(string_view algName)
{
    HcfMd *mdObj = nullptr;
    HcfResult res = HcfMdCreate(algName.c_str(), &mdObj);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C md obj failed.");
        return make_holder<MdImpl, Md>(nullptr);
    }
    return make_holder<MdImpl, Md>(mdObj);
}
} // namespace ANI::CryptoFramework

TH_EXPORT_CPP_API_CreateMd(CreateMd);
