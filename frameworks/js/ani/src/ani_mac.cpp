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

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace ANI::CryptoFramework {
MacImpl::MacImpl() : macObj(nullptr) {}

MacImpl::MacImpl(HcfMac *obj) : macObj(obj) {}

MacImpl::~MacImpl()
{
    HcfObjDestroy(macObj);
    macObj = nullptr;
}

void MacImpl::InitSync(weak::SymKey key)
{
    if (macObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return;
    }
    HcfSymKey *symKey = reinterpret_cast<HcfSymKey *>(key->GetSymKeyObj());
    HcfResult res = macObj->init(macObj, symKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac init failed!");
        return;
    }
}

void MacImpl::UpdateSync(DataBlob const& input)
{
    if (macObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return;
    }
    HcfBlob inBlob = { .data = input.data.data(), .len = input.data.size() };
    HcfResult res = macObj->update(macObj, &inBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac update failed!");
        return;
    }
}

DataBlob MacImpl::DoFinalSync()
{
    if (macObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return { taihe::array<uint8_t>(nullptr, 0) };
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = macObj->doFinal(macObj, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "mac doFinal failed!");
        return { taihe::array<uint8_t>(nullptr, 0) };
    }
    taihe::array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

int32_t MacImpl::GetMacLength()
{
    if (macObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "mac obj is nullptr!");
        return 0;
    }
    uint32_t length = macObj->getMacLength(macObj);
    return static_cast<int32_t>(length);
}

string MacImpl::GetAlgName()
{
    if (macObj == nullptr) {
        return "";
    }
    const char *algName = macObj->getAlgoName(macObj);
    return (algName == nullptr) ? "" : string(algName);
}

Mac CreateMac(string_view algName)
{
    HcfMac *macObj = nullptr;
    HcfHmacParamsSpec parmas = { { "HMAC" }, algName.c_str() };
    HcfResult res = HcfMacCreate(reinterpret_cast<HcfMacParamsSpec *>(&parmas), &macObj);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C mac obj failed.");
        return make_holder<MacImpl, Mac>(nullptr);
    }
    return make_holder<MacImpl, Mac>(macObj);
}
} // namespace ANI::CryptoFramework

TH_EXPORT_CPP_API_CreateMac(CreateMac);
