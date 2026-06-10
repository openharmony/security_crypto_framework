/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "native_api_metrics.h"
#include <string>
#include <unordered_map>

#ifdef CRYPTO_FRAMEWORK_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

#define HCF "CryptoArchitectureKit.OH_Crypto"

static const std::unordered_map<HcfNativeApiId, const char *> API_NAMES = {
    /* crypto_common */
    { API_CRYPTO_FREE_DATA_BLOB, HCF "_FreeDataBlob" },
    /* crypto_digest */
    { API_CRYPTO_DIGEST_CREATE, HCF "Digest_Create" },
    { API_CRYPTO_DIGEST_UPDATE, HCF "Digest_Update" },
    { API_CRYPTO_DIGEST_FINAL, HCF "Digest_Final" },
    { API_CRYPTO_DIGEST_GET_LENGTH, HCF "Digest_GetLength" },
    { API_CRYPTO_DIGEST_GET_ALGO_NAME, HCF "Digest_GetAlgoName" },
    { API_CRYPTO_DIGEST_DESTROY, "CryptoArchitectureKit.OH_DigestCrypto_Destroy" },
    /* crypto_mac */
    { API_CRYPTO_MAC_CREATE, HCF "Mac_Create" },
    { API_CRYPTO_MAC_SET_PARAM, HCF "Mac_SetParam" },
    { API_CRYPTO_MAC_INIT, HCF "Mac_Init" },
    { API_CRYPTO_MAC_UPDATE, HCF "Mac_Update" },
    { API_CRYPTO_MAC_FINAL, HCF "Mac_Final" },
    { API_CRYPTO_MAC_GET_LENGTH, HCF "Mac_GetLength" },
    { API_CRYPTO_MAC_DESTROY, HCF "Mac_Destroy" },
    /* crypto_sym_key */
    { API_CRYPTO_SYM_KEY_GENERATOR_CREATE, HCF "SymKeyGenerator_Create" },
    { API_CRYPTO_SYM_KEY_GENERATOR_GENERATE, HCF "SymKeyGenerator_Generate" },
    { API_CRYPTO_SYM_KEY_GENERATOR_CONVERT, HCF "SymKeyGenerator_Convert" },
    { API_CRYPTO_SYM_KEY_GENERATOR_GET_ALGO_NAME, HCF "SymKeyGenerator_GetAlgoName" },
    { API_CRYPTO_SYM_KEY_GENERATOR_DESTROY, HCF "SymKeyGenerator_Destroy" },
    { API_CRYPTO_SYM_KEY_GET_ALGO_NAME, HCF "SymKey_GetAlgoName" },
    { API_CRYPTO_SYM_KEY_GET_KEY_DATA, HCF "SymKey_GetKeyData" },
    { API_CRYPTO_SYM_KEY_DESTROY, HCF "SymKey_Destroy" },
    /* crypto_sym_cipher */
    { API_CRYPTO_SYM_CIPHER_PARAMS_CREATE, HCF "SymCipherParams_Create" },
    { API_CRYPTO_SYM_CIPHER_PARAMS_SET_PARAM, HCF "SymCipherParams_SetParam" },
    { API_CRYPTO_SYM_CIPHER_PARAMS_DESTROY, HCF "SymCipherParams_Destroy" },
    { API_CRYPTO_SYM_CIPHER_CREATE, HCF "SymCipher_Create" },
    { API_CRYPTO_SYM_CIPHER_INIT, HCF "SymCipher_Init" },
    { API_CRYPTO_SYM_CIPHER_UPDATE, HCF "SymCipher_Update" },
    { API_CRYPTO_SYM_CIPHER_FINAL, HCF "SymCipher_Final" },
    { API_CRYPTO_SYM_CIPHER_GET_ALGO_NAME, HCF "SymCipher_GetAlgoName" },
    { API_CRYPTO_SYM_CIPHER_DESTROY, HCF "SymCipher_Destroy" },
    /* crypto_asym_key */
    { API_CRYPTO_ASYM_KEY_GENERATOR_CREATE, HCF "AsymKeyGenerator_Create" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_GENERATE, HCF "AsymKeyGenerator_Generate" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_CONVERT, HCF "AsymKeyGenerator_Convert" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_GET_ALGO_NAME, HCF "AsymKeyGenerator_GetAlgoName" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_DESTROY, HCF "AsymKeyGenerator_Destroy" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_SET_PASSWORD, HCF "AsymKeyGenerator_SetPassword" },
    { API_CRYPTO_KEY_PAIR_DESTROY, HCF "KeyPair_Destroy" },
    { API_CRYPTO_KEY_PAIR_GET_PUB_KEY, HCF "KeyPair_GetPubKey" },
    { API_CRYPTO_KEY_PAIR_GET_PRIV_KEY, HCF "KeyPair_GetPrivKey" },
    { API_CRYPTO_PUB_KEY_ENCODE, HCF "PubKey_Encode" },
    { API_CRYPTO_PUB_KEY_GET_PARAM, HCF "PubKey_GetParam" },
    { API_CRYPTO_PRIV_KEY_ENCODING_PARAMS_CREATE, HCF "PrivKeyEncodingParams_Create" },
    { API_CRYPTO_PRIV_KEY_ENCODING_PARAMS_SET_PARAM, HCF "PrivKeyEncodingParams_SetParam" },
    { API_CRYPTO_PRIV_KEY_ENCODING_PARAMS_DESTROY, HCF "PrivKeyEncodingParams_Destroy" },
    { API_CRYPTO_PRIV_KEY_ENCODE, HCF "PrivKey_Encode" },
    { API_CRYPTO_PRIV_KEY_GET_PARAM, HCF "PrivKey_GetParam" },
    { API_CRYPTO_ASYM_KEY_SPEC_GEN_EC_COMMON_PARAMS_SPEC, HCF "AsymKeySpec_GenEcCommonParamsSpec" },
    { API_CRYPTO_ASYM_KEY_SPEC_GEN_DH_COMMON_PARAMS_SPEC, HCF "AsymKeySpec_GenDhCommonParamsSpec" },
    { API_CRYPTO_ASYM_KEY_SPEC_CREATE, HCF "AsymKeySpec_Create" },
    { API_CRYPTO_ASYM_KEY_SPEC_SET_PARAM, HCF "AsymKeySpec_SetParam" },
    { API_CRYPTO_ASYM_KEY_SPEC_SET_COMMON_PARAMS_SPEC, HCF "AsymKeySpec_SetCommonParamsSpec" },
    { API_CRYPTO_ASYM_KEY_SPEC_GET_PARAM, HCF "AsymKeySpec_GetParam" },
    { API_CRYPTO_ASYM_KEY_SPEC_DESTROY, HCF "AsymKeySpec_Destroy" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_WITH_SPEC_CREATE, HCF "AsymKeyGeneratorWithSpec_Create" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_WITH_SPEC_GEN_KEY_PAIR, HCF "AsymKeyGeneratorWithSpec_GenKeyPair" },
    { API_CRYPTO_ASYM_KEY_GENERATOR_WITH_SPEC_DESTROY, HCF "AsymKeyGeneratorWithSpec_Destroy" },
    { API_CRYPTO_EC_POINT_CREATE, HCF "EcPoint_Create" },
    { API_CRYPTO_EC_POINT_GET_COORDINATE, HCF "EcPoint_GetCoordinate" },
    { API_CRYPTO_EC_POINT_SET_COORDINATE, HCF "EcPoint_SetCoordinate" },
    { API_CRYPTO_EC_POINT_ENCODE, HCF "EcPoint_Encode" },
    { API_CRYPTO_EC_POINT_DESTROY, HCF "EcPoint_Destroy" },
    /* crypto_signature */
    { API_CRYPTO_VERIFY_CREATE, HCF "Verify_Create" },
    { API_CRYPTO_VERIFY_INIT, HCF "Verify_Init" },
    { API_CRYPTO_VERIFY_UPDATE, HCF "Verify_Update" },
    { API_CRYPTO_VERIFY_FINAL, HCF "Verify_Final" },
    { API_CRYPTO_VERIFY_RECOVER, HCF "Verify_Recover" },
    { API_CRYPTO_VERIFY_GET_ALGO_NAME, HCF "Verify_GetAlgoName" },
    { API_CRYPTO_VERIFY_SET_PARAM, HCF "Verify_SetParam" },
    { API_CRYPTO_VERIFY_GET_PARAM, HCF "Verify_GetParam" },
    { API_CRYPTO_VERIFY_DESTROY, HCF "Verify_Destroy" },
    { API_CRYPTO_SIGN_CREATE, HCF "Sign_Create" },
    { API_CRYPTO_SIGN_INIT, HCF "Sign_Init" },
    { API_CRYPTO_SIGN_UPDATE, HCF "Sign_Update" },
    { API_CRYPTO_SIGN_FINAL, HCF "Sign_Final" },
    { API_CRYPTO_SIGN_GET_ALGO_NAME, HCF "Sign_GetAlgoName" },
    { API_CRYPTO_SIGN_SET_PARAM, HCF "Sign_SetParam" },
    { API_CRYPTO_SIGN_GET_PARAM, HCF "Sign_GetParam" },
    { API_CRYPTO_SIGN_DESTROY, HCF "Sign_Destroy" },
    { API_CRYPTO_ECC_SIGNATURE_SPEC_CREATE, HCF "EccSignatureSpec_Create" },
    { API_CRYPTO_ECC_SIGNATURE_SPEC_GET_R_AND_S, HCF "EccSignatureSpec_GetRAndS" },
    { API_CRYPTO_ECC_SIGNATURE_SPEC_SET_R_AND_S, HCF "EccSignatureSpec_SetRAndS" },
    { API_CRYPTO_ECC_SIGNATURE_SPEC_ENCODE, HCF "EccSignatureSpec_Encode" },
    { API_CRYPTO_ECC_SIGNATURE_SPEC_DESTROY, HCF "EccSignatureSpec_Destroy" },
    /* crypto_rand */
    { API_CRYPTO_RAND_CREATE, HCF "Rand_Create" },
    { API_CRYPTO_RAND_GENERATE_RANDOM, HCF "Rand_GenerateRandom" },
    { API_CRYPTO_RAND_GET_ALGO_NAME, HCF "Rand_GetAlgoName" },
    { API_CRYPTO_RAND_SET_SEED, HCF "Rand_SetSeed" },
    { API_CRYPTO_RAND_ENABLE_HARDWARE_ENTROPY, HCF "Rand_EnableHardwareEntropy" },
    { API_CRYPTO_RAND_DESTROY, HCF "Rand_Destroy" },
    /* crypto_key_agreement */
    { API_CRYPTO_KEY_AGREEMENT_CREATE, HCF "KeyAgreement_Create" },
    { API_CRYPTO_KEY_AGREEMENT_GENERATE_SECRET, HCF "KeyAgreement_GenerateSecret" },
    { API_CRYPTO_KEY_AGREEMENT_DESTROY, HCF "KeyAgreement_Destroy" },
    /* crypto_kdf */
    { API_CRYPTO_KDF_PARAMS_CREATE, HCF "KdfParams_Create" },
    { API_CRYPTO_KDF_PARAMS_SET_PARAM, HCF "KdfParams_SetParam" },
    { API_CRYPTO_KDF_PARAMS_DESTROY, HCF "KdfParams_Destroy" },
    { API_CRYPTO_KDF_CREATE, HCF "Kdf_Create" },
    { API_CRYPTO_KDF_DERIVE, HCF "Kdf_Derive" },
    { API_CRYPTO_KDF_DESTROY, HCF "Kdf_Destroy" },
    /* crypto_asym_cipher */
    { API_CRYPTO_ASYM_CIPHER_CREATE, HCF "AsymCipher_Create" },
    { API_CRYPTO_ASYM_CIPHER_INIT, HCF "AsymCipher_Init" },
    { API_CRYPTO_ASYM_CIPHER_FINAL, HCF "AsymCipher_Final" },
    { API_CRYPTO_ASYM_CIPHER_DESTROY, HCF "AsymCipher_Destroy" },
    { API_CRYPTO_SM2_CIPHERTEXT_SPEC_CREATE, HCF "Sm2CiphertextSpec_Create" },
    { API_CRYPTO_SM2_CIPHERTEXT_SPEC_GET_ITEM, HCF "Sm2CiphertextSpec_GetItem" },
    { API_CRYPTO_SM2_CIPHERTEXT_SPEC_SET_ITEM, HCF "Sm2CiphertextSpec_SetItem" },
    { API_CRYPTO_SM2_CIPHERTEXT_SPEC_ENCODE, HCF "Sm2CiphertextSpec_Encode" },
    { API_CRYPTO_SM2_CIPHERTEXT_SPEC_DESTROY, HCF "Sm2CiphertextSpec_Destroy" },
};

static const std::unordered_map<OH_Crypto_ErrCode, int32_t> ERROR_CODES = {
    { CRYPTO_SUCCESS, 0 },                /* 0 */
    { CRYPTO_INVALID_PARAMS, 1 },         /* 401 */
    { CRYPTO_NOT_SUPPORTED, 2 },          /* 801 */
    { CRYPTO_MEMORY_ERROR, 3 },           /* 17620001 */
    { CRYPTO_PARAMETER_CHECK_FAILED, 4 }, /* 17620003 */
    { CRYPTO_INVALID_CALL, 5 },           /* 17620004 */
    { CRYPTO_OPERTION_ERROR, 6 },         /* 17630001 */
};

const char *GetApiName(HcfNativeApiId id)
{
    auto it = API_NAMES.find(id);
    if (it != API_NAMES.end()) {
        return it->second;
    }
    return nullptr;
}

int32_t GetCodeValue(OH_Crypto_ErrCode code, int32_t *boundary)
{
    *boundary = static_cast<int32_t>(ERROR_CODES.size());
    auto it = ERROR_CODES.find(code);
    if (it != ERROR_CODES.end()) {
        return it->second;
    }
    return -1;
}

int64_t GetTimeMilliseconds(void)
{
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

void HistogramApiReportCode(HcfNativeApiId id, OH_Crypto_ErrCode code, int64_t time)
{
#ifdef CRYPTO_FRAMEWORK_API_METRICS_ENABLE
    int32_t boundary = 0;
    int32_t value = GetCodeValue(code, &boundary);
    const char *name = GetApiName(id);
    if (name != nullptr) {
        HISTOGRAM_BOOLEAN((std::string(name) + ".call").c_str(), code == CRYPTO_SUCCESS);
        HISTOGRAM_TIMES((std::string(name) + ".time").c_str(), static_cast<int32_t>(time));
        if (value >= 0) {
            HISTOGRAM_ENUMERATION((std::string(name) + ".errcode").c_str(), value, boundary);
        }
    }
#endif
}

void HistogramApiReportBool(HcfNativeApiId id, bool success, int64_t time)
{
#ifdef CRYPTO_FRAMEWORK_API_METRICS_ENABLE
    const char *name = GetApiName(id);
    if (name != nullptr) {
        HISTOGRAM_BOOLEAN((std::string(name) + ".call").c_str(), success);
        HISTOGRAM_TIMES((std::string(name) + ".time").c_str(), static_cast<int32_t>(time));
    }
#endif
}
