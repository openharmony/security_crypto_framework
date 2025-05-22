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
using namespace ANI::CryptoFramework;

enum ResultCode {
    SUCCESS = 0,
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 17620001,
    ERR_RUNTIME_ERROR = 17620002,
    ERR_CRYPTO_OPERATION = 17630001,
};

static const std::unordered_map<HcfResult, ResultCode> RESULT_CODE = {
    { HCF_SUCCESS, SUCCESS },
    { HCF_INVALID_PARAMS, INVALID_PARAMS },
    { HCF_NOT_SUPPORT, NOT_SUPPORT },
    { HCF_ERR_MALLOC, ERR_OUT_OF_MEMORY },
    { HCF_ERR_CRYPTO_OPERATION, ERR_CRYPTO_OPERATION },
};

static const std::unordered_map<HcfAsyKeySpecItem, int> ASY_KEY_SPEC_RELATION_MAP = {
    { DSA_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_Q_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_G_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DSA_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_FP_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_A_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_B_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_G_X_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_G_Y_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_N_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_H_INT, SPEC_ITEM_TYPE_NUM },  // warning: ECC_H_NUM in JS
    { ECC_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_PK_X_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_PK_Y_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ECC_FIELD_TYPE_STR, SPEC_ITEM_TYPE_STR },
    { ECC_FIELD_SIZE_INT, SPEC_ITEM_TYPE_NUM },  // warning: ECC_FIELD_SIZE_NUM in JS
    { ECC_CURVE_NAME_STR, SPEC_ITEM_TYPE_STR },
    { RSA_N_BN, SPEC_ITEM_TYPE_BIG_INT },
    { RSA_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { RSA_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_P_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_G_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_L_NUM, SPEC_ITEM_TYPE_NUM },
    { DH_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { DH_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ED25519_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { ED25519_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { X25519_SK_BN, SPEC_ITEM_TYPE_BIG_INT },
    { X25519_PK_BN, SPEC_ITEM_TYPE_BIG_INT },
};

static const std::unordered_map<HcfSignSpecItem, int> SIGN_SPEC_RELATION_MAP = {
    { PSS_MD_NAME_STR, SPEC_ITEM_TYPE_STR },
    { PSS_MGF_NAME_STR, SPEC_ITEM_TYPE_STR },
    { PSS_MGF1_MD_STR, SPEC_ITEM_TYPE_STR },
    { PSS_SALT_LEN_INT, SPEC_ITEM_TYPE_NUM },  // warning: PSS_SALT_LEN_NUM in JS
    { PSS_TRAILER_FIELD_INT, SPEC_ITEM_TYPE_NUM },  // warning: PSS_TRAILER_FIELD_NUM in JS
    { SM2_USER_ID_UINT8ARR, SPEC_ITEM_TYPE_UINT8ARR },
};
} // namespace

namespace ANI::CryptoFramework {
int ConvertResultCode(HcfResult res)
{
    if (RESULT_CODE.count(res) > 0) {
        return RESULT_CODE.at(res);
    }
    return ERR_RUNTIME_ERROR;
}

template void ArrayU8ToDataBlob<HcfBlob>(const array<uint8_t> &arr, HcfBlob &blob);
template void ArrayU8ToDataBlob<HcfBigInteger>(const array<uint8_t> &arr, HcfBigInteger &blob);

template<typename T>
void ArrayU8ToDataBlob(const array<uint8_t> &arr, T &blob)
{
    blob.data = arr.empty() ? nullptr : arr.data();
    blob.len = arr.size();
}

template<>
void DataBlobToArrayU8<HcfBlob>(const HcfBlob &blob, array<uint8_t> &arr)
{
    arr = array<uint8_t>(move_data_t{}, blob.data, blob.len);
}

template<>
void DataBlobToArrayU8<HcfBigInteger>(const HcfBigInteger &blob, array<uint8_t> &arr)
{
    arr = array<uint8_t>(blob.len + 1);
    std::copy(blob.data, blob.data + blob.len, arr.data());
    // 0x00 is the sign bit of big integer, it's always a positive number in this implementation
    arr[blob.len] = 0x00;
}

void StringToDataBlob(const string &str, HcfBlob &blob)
{
    blob.data = str.empty() ? nullptr : reinterpret_cast<uint8_t *>(const_cast<char *>(str.c_str()));
    blob.len = str.size();
}

int GetAsyKeySpecType(HcfAsyKeySpecItem item)
{
    if (ASY_KEY_SPEC_RELATION_MAP.count(item) > 0) {
        return ASY_KEY_SPEC_RELATION_MAP.at(item);
    }
    return -1;
}

int GetSignSpecType(HcfSignSpecItem item)
{
    if (SIGN_SPEC_RELATION_MAP.count(item) > 0) {
        return SIGN_SPEC_RELATION_MAP.at(item);
    }
    return -1;
}
} // namespace ANI::CryptoFramework
