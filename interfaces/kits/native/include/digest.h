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

#ifndef DIGEST_H
#define DIGEST_H

/**
 * @addtogroup CryptoDigestApi
 * @{
 *
 * @brief Describe OpenHarmony encryption features, including key generation,
 *      encryption and decryption, signature verification, and digest interfaces
 *      Provide for applications.
 *
 * @syscap SystemCapability.Security.CryptoFramework
 * @since 12
 * @version 1.0
 */

/**
 * @file digest.h
 *
 * @brief Defines the Digest APIs.
 *
 * @kit Crypto Architecture Kit
 * @since 12
 * @version 1.0
 */

#include "crypto_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OH_CryptoDigest OH_CryptoDigest;

/**
 * @brief Create the Digest generater.
 *
 * @param algoName Indicates the algorithm name for generating the generator.
 * @param md Indicates the pointer to the md instance.
 * @return {@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} 401 - If paramSet is invalid.
 *         {@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORT} 801 - If algorithm name not support.
 *         {@link OH_Crypto_ErrCode#CRYPTO_ERR_MALLOC} 17620001 - If malloc failed.
 *         {@link OH_Crypto_ErrCode#CRYPTO_CRYPTO_OPERTION} 401 - If crypto opertion failed.
 * @since 12
 * @version 1.0
 */
Crypto_Result OH_CryptoDigest_Create(const char *algoName, OH_CryptoDigest **md);

/**
 * @brief Update md with DataBlob.
 *
 * @param md Indicates the pointer to the md instance.
 * @param in Indicates the DataBlob.
 * @return {@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} 401 - If paramSet is invalid.
 *         {@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORT} 801 - If algorithm name not support.
 *         {@link OH_Crypto_ErrCode#CRYPTO_ERR_MALLOC} 17620001 - If malloc failed.
 *         {@link OH_Crypto_ErrCode#CRYPTO_CRYPTO_OPERTION} 401 - If crypto opertion failed.
 * @since 12
 * @version 1.0
 */
Crypto_Result OH_CryptoDigest_Update(OH_CryptoDigest *ctx, Crypto_DataBlob *in);

/**
 * @brief Update md with DataBlob.
 *
 * @param md Indicates the pointer to the md instance.
 * @param out Return the result as DataBlob.
 * @return {@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} 401 - If paramSet is invalid.
 *         {@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORT} 801 - If algorithm name not support.
 *         {@link OH_Crypto_ErrCode#CRYPTO_ERR_MALLOC} 17620001 - If malloc failed.
 *         {@link OH_Crypto_ErrCode#CRYPTO_CRYPTO_OPERTION} 401 - If crypto opertion failed.
 * @since 12
 * @version 1.0
 */
Crypto_Result OH_CryptoDigest_Final(OH_CryptoDigest *ctx, Crypto_DataBlob *out);

/**
 * @brief Get digest length.
 *
 * @param md Indicates the pointer to the md instance.
 * @return {@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} 401 - If paramSet is invalid.
 *         {@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORT} 801 - If algorithm name not support.
 *         {@link OH_Crypto_ErrCode#CRYPTO_ERR_MALLOC} 17620001 - If malloc failed.
 *         {@link OH_Crypto_ErrCode#CRYPTO_CRYPTO_OPERTION} 401 - If crypto opertion failed.
 * @since 12
 * @version 1.0
 */
uint32_t OH_CryptoDigest_GetLength(OH_CryptoDigest *ctx);

/**
 * @brief Get digest algoName.
 *
 * @param md Indicates the pointer to the md instance.
 * @return {@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} 401 - If paramSet is invalid.
 *         {@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORT} 801 - If algorithm name not support.
 *         {@link OH_Crypto_ErrCode#CRYPTO_ERR_MALLOC} 17620001 - If malloc failed.
 *         {@link OH_Crypto_ErrCode#CRYPTO_CRYPTO_OPERTION} 401 - If crypto opertion failed.
 * @since 12
 * @version 1.0
 */
const char *OH_CryptoDigest_GetAlgoName(OH_CryptoDigest *ctx);

/**
 * @brief Destroy digest pointer.
 *
 * @param md Indicates the pointer to the md instance.
 * @return {@link OH_Crypto_ErrCode#CRYPTO_SUCCESS} 0 - If the operation is successful.
 *         {@link OH_Crypto_ErrCode#CRYPTO_INVALID_PARAMS} 401 - If paramSet is invalid.
 *         {@link OH_Crypto_ErrCode#CRYPTO_NOT_SUPPORT} 801 - If algorithm name not support.
 *         {@link OH_Crypto_ErrCode#CRYPTO_ERR_MALLOC} 17620001 - If malloc failed.
 *         {@link OH_Crypto_ErrCode#CRYPTO_CRYPTO_OPERTION} 401 - If crypto opertion failed.
 * @since 12
 * @version 1.0
 */
void OH_DigestCrypto_Destroy(OH_CryptoDigest *ctx);

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* DIGEST_H */