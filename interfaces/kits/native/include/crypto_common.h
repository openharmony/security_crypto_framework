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

#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

/**
 * @addtogroup CryptoCommonApi
 * @{
 *
 * @brief Describe OpenHarmony common interfaces Provide for applications.
 *
 * @syscap SystemCapability.Security.CryptoFramework
 * @since 12
 * @version 1.0
 */

/**
 * @file crypto_common.h
 *
 * @brief Defines the CryptoCommon APIs.
 *
 * @kit Crypto Architecture Kit
 * @since 12
 * @version 1.0
 */

#include <stdint.h>
#include <stddef.h>

typedef struct Crypto_DataBlob {
    uint8_t *data;
    size_t len;
} Crypto_DataBlob;

typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_INVALID_PARAMS = -10001,
    CRYPTO_NOT_SUPPORT = -10002,
    CRYPTO_ERR_MALLOC = -20001,
    CRYPTO_CRYPTO_OPERTION = -30001,
} Crypto_Result;

typedef enum {
    CRYPTO_ENCRYPT_MODE = 0,
    CRYPTO_DECRYPT_MODE = 1,
} Crypto_CipherMode;

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_COMMON_H */