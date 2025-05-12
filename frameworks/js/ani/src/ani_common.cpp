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

#include "ani_common.h"
#include <unordered_map>

namespace {
enum ResultCode {
    SUCCESS = 0,
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 17620001,
    ERR_RUNTIME_ERROR = 17620002,
    ERR_CRYPTO_OPERATION = 17630001,
};
} // namespace

namespace ANI::CryptoFramework {
template void ArrayU8ToDataBlob<HcfBlob>(const array<uint8_t> &arr, HcfBlob &blob);
template void ArrayU8ToDataBlob<HcfBigInteger>(const array<uint8_t> &arr, HcfBigInteger &blob);

template<typename T>
void ArrayU8ToDataBlob(const array<uint8_t> &arr, T &blob)
{
    blob.data = arr.empty() ? nullptr : arr.data();
    blob.len = arr.size();
}

void StringToDataBlob(const string &str, HcfBlob &blob)
{
    blob.data = str.empty() ? nullptr : reinterpret_cast<uint8_t *>(const_cast<char *>(str.c_str()));
    blob.len = str.size();
}

int ConvertResultCode(HcfResult res)
{
    static std::unordered_map<HcfResult, ResultCode> resCodeMap = {
        { HCF_SUCCESS, SUCCESS },
        { HCF_INVALID_PARAMS, INVALID_PARAMS },
        { HCF_NOT_SUPPORT, NOT_SUPPORT },
        { HCF_ERR_MALLOC, ERR_OUT_OF_MEMORY },
        { HCF_ERR_CRYPTO_OPERATION, ERR_CRYPTO_OPERATION }
    };
    if (resCodeMap.count(res) > 0) {
        return resCodeMap[res];
    }
    return ERR_RUNTIME_ERROR;
}
} // namespace ANI::CryptoFramework
