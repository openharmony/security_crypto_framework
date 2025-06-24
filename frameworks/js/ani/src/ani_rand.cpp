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

#include "ani_rand.h"

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace ANI::CryptoFramework {
RandomImpl::RandomImpl() : randObj(nullptr) {}

RandomImpl::RandomImpl(HcfRand *obj) : randObj(obj) {}

RandomImpl::~RandomImpl()
{
    HcfObjDestroy(randObj);
    randObj = nullptr;
}

DataBlob RandomImpl::GenerateRandomSync(int32_t len)
{
    if (randObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "rand obj is nullptr!");
        return { taihe::array<uint8_t>(nullptr, 0) };
    }
    HcfBlob outBlob = { .data = nullptr, .len = 0 };
    HcfResult res = randObj->generateRandom(randObj, len, &outBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generateRandom failed!");
        return { taihe::array<uint8_t>(nullptr, 0) };
    }
    taihe::array<uint8_t> data(move_data_t{}, outBlob.data, outBlob.len);
    HcfBlobDataClearAndFree(&outBlob);
    return { data };
}

void RandomImpl::SetSeed(DataBlob const& seed)
{
    if (randObj == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "rand obj is nullptr!");
        return;
    }
    HcfBlob seedBlob = { .data = seed.data.data(), .len = seed.data.size() };
    HcfResult res = randObj->setSeed(randObj, &seedBlob);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "set seed failed.");
        return;
    }
}

string RandomImpl::GetAlgName()
{
    if (randObj == nullptr) {
        return "";
    }
    const char *algName = randObj->getAlgoName(randObj);
    return (algName == nullptr) ? "" : string(algName);
}

Random CreateRandom()
{
    HcfRand *randObj = nullptr;
    HcfResult res = HcfRandCreate(&randObj);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C rand obj failed.");
        return make_holder<RandomImpl, Random>(nullptr);
    }
    return make_holder<RandomImpl, Random>(randObj);
}
} // namespace ANI::CryptoFramework

TH_EXPORT_CPP_API_CreateRandom(CreateRandom);
