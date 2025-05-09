/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "native_common.h"

OH_Crypto_ErrCode GetOhCryptoErrCode(HcfResult errCode)
{
    switch (errCode) {
        case HCF_SUCCESS:
            return CRYPTO_SUCCESS;
        case HCF_INVALID_PARAMS:
            return CRYPTO_INVALID_PARAMS;
        case HCF_NOT_SUPPORT:
            return CRYPTO_NOT_SUPPORTED;
        case HCF_ERR_MALLOC:
            return CRYPTO_MEMORY_ERROR;
        default:
            return CRYPTO_OPERTION_ERROR;
    }
}

OH_Crypto_ErrCode GetOhCryptoErrCodeNew(HcfResult errCode)
{
    switch (errCode) {
        case HCF_SUCCESS:
            return CRYPTO_SUCCESS;
        case HCF_INVALID_PARAMS:
            return CRYPTO_PARAMETER_CHECK_FAILED;
        case HCF_NOT_SUPPORT:
            return CRYPTO_NOT_SUPPORTED;
        case HCF_ERR_MALLOC:
            return CRYPTO_MEMORY_ERROR;
        default:
            return CRYPTO_OPERTION_ERROR;
    }
}