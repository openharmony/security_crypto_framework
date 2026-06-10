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

#ifndef JS_API_METRICS_H
#define JS_API_METRICS_H

#include <chrono>
#include <string>
#include "result.h"

enum HcfJsApiId {
    /* SymKey */
    API_SYMKEY_GET_ENCODED,
    API_SYMKEY_GET_KEY_SIZE,
    API_SYMKEY_CLEAR_MEM,
    /* PriKey */
    API_PRIKEY_GET_ENCODED,
    API_PRIKEY_GET_KEY_SIZE,
    API_PRIKEY_CLEAR_MEM,
    API_PRIKEY_GET_ASY_KEY_SPEC,
    API_PRIKEY_GET_ENCODED_DER,
    API_PRIKEY_GET_ENCODED_PEM,
    API_PRIKEY_GET_PUB_KEY,
    API_PRIKEY_GET_PUB_KEY_SYNC,
    API_PRIKEY_GET_KEY_DATA,
    API_PRIKEY_GET_KEY_DATA_SYNC,
    /* PubKey */
    API_PUBKEY_GET_ENCODED,
    API_PUBKEY_GET_KEY_SIZE,
    API_PUBKEY_GET_ASY_KEY_SPEC,
    API_PUBKEY_GET_ENCODED_DER,
    API_PUBKEY_GET_ENCODED_PEM,
    API_PUBKEY_GET_KEY_DATA,
    API_PUBKEY_GET_KEY_DATA_SYNC,
    /* Random */
    API_CREATE_RANDOM,
    API_RANDOM_GENERATE_RANDOM,
    API_RANDOM_GENERATE_RANDOM_SYNC,
    API_RANDOM_SET_SEED,
    API_RANDOM_ENABLE_HARDWARE_ENTROPY,
    /* AsyKeyGenerator */
    API_CREATE_ASY_KEY_GENERATOR,
    API_ASY_KEY_GENERATOR_GENERATE_KEY_PAIR,
    API_ASY_KEY_GENERATOR_GENERATE_KEY_PAIR_SYNC,
    API_ASY_KEY_GENERATOR_CONVERT_KEY,
    API_ASY_KEY_GENERATOR_CONVERT_KEY_SYNC,
    API_ASY_KEY_GENERATOR_CONVERT_PEM_KEY,
    API_ASY_KEY_GENERATOR_CONVERT_PEM_KEY_SYNC,
    /* SymKeyGenerator */
    API_CREATE_SYM_KEY_GENERATOR,
    API_SYM_KEY_GENERATOR_GENERATE_SYM_KEY,
    API_SYM_KEY_GENERATOR_GENERATE_SYM_KEY_SYNC,
    API_SYM_KEY_GENERATOR_CONVERT_KEY,
    API_SYM_KEY_GENERATOR_CONVERT_KEY_SYNC,
    /* Mac */
    API_CREATE_MAC,
    API_MAC_INIT,
    API_MAC_INIT_SYNC,
    API_MAC_UPDATE,
    API_MAC_UPDATE_SYNC,
    API_MAC_DO_FINAL,
    API_MAC_DO_FINAL_SYNC,
    API_MAC_GET_MAC_LENGTH,
    /* Md */
    API_CREATE_MD,
    API_MD_UPDATE,
    API_MD_UPDATE_SYNC,
    API_MD_DIGEST,
    API_MD_DIGEST_SYNC,
    API_MD_GET_MD_LENGTH,
    /* Cipher */
    API_CREATE_CIPHER,
    API_CIPHER_INIT,
    API_CIPHER_INIT_SYNC,
    API_CIPHER_UPDATE,
    API_CIPHER_UPDATE_SYNC,
    API_CIPHER_DO_FINAL,
    API_CIPHER_DO_FINAL_SYNC,
    API_CIPHER_SET_CIPHER_SPEC,
    API_CIPHER_GET_CIPHER_SPEC,
    /* Sign */
    API_CREATE_SIGN,
    API_SIGN_INIT,
    API_SIGN_INIT_SYNC,
    API_SIGN_UPDATE,
    API_SIGN_UPDATE_SYNC,
    API_SIGN_SIGN,
    API_SIGN_SIGN_SYNC,
    API_SIGN_SET_SIGN_SPEC,
    API_SIGN_GET_SIGN_SPEC,
    /* Verify */
    API_CREATE_VERIFY,
    API_VERIFY_INIT,
    API_VERIFY_INIT_SYNC,
    API_VERIFY_UPDATE,
    API_VERIFY_UPDATE_SYNC,
    API_VERIFY_VERIFY,
    API_VERIFY_VERIFY_SYNC,
    API_VERIFY_RECOVER,
    API_VERIFY_RECOVER_SYNC,
    API_VERIFY_SET_VERIFY_SPEC,
    API_VERIFY_GET_VERIFY_SPEC,
    /* KeyAgreement */
    API_CREATE_KEY_AGREEMENT,
    API_KEY_AGREEMENT_GENERATE_SECRET,
    API_KEY_AGREEMENT_GENERATE_SECRET_SYNC,
    /* ECCKeyUtil */
    API_ECC_KEY_UTIL_GEN_ECC_COMMON_PARAMS_SPEC,
    API_ECC_KEY_UTIL_CONVERT_POINT,
    API_ECC_KEY_UTIL_GET_ENCODED_POINT,
    /* DHKeyUtil */
    API_DH_KEY_UTIL_GEN_DH_COMMON_PARAMS_SPEC,
    /* AsyKeyGeneratorBySpec */
    API_CREATE_ASY_KEY_GENERATOR_BY_SPEC,
    API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_KEY_PAIR,
    API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_KEY_PAIR_SYNC,
    API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PRI_KEY,
    API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PRI_KEY_SYNC,
    API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PUB_KEY,
    API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PUB_KEY_SYNC,
    /* Kdf */
    API_CREATE_KDF,
    API_KDF_GENERATE_SECRET,
    API_KDF_GENERATE_SECRET_SYNC,
    /* SM2CryptoUtil */
    API_SM2_CRYPTO_UTIL_GEN_CIPHER_TEXT_BY_SPEC,
    API_SM2_CRYPTO_UTIL_GET_CIPHER_TEXT_SPEC,
    /* SignatureUtils */
    API_SIGNATURE_UTILS_GEN_ECC_SIGNATURE_SPEC,
    API_SIGNATURE_UTILS_GEN_ECC_SIGNATURE,
    /* Kem */
    API_CREATE_KEM,
    API_KEM_ENCAPSULATE,
    API_KEM_ENCAPSULATE_SYNC,
    API_KEM_DECAPSULATE,
    API_KEM_DECAPSULATE_SYNC,
};

class HistogramScopeGuard {
public:
    explicit HistogramScopeGuard(HcfJsApiId id);
    ~HistogramScopeGuard();
    void DisableScopeGuard();
    void SetErrorCode(HcfResult code);
    std::pair<int32_t, int32_t> GetCodeValue(HcfResult code) const;
    std::string GetApiName() const; // for self-validation only

    HistogramScopeGuard(const HistogramScopeGuard &) = delete;
    HistogramScopeGuard &operator=(const HistogramScopeGuard &) = delete;

private:
    static void HistogramApiReport(const std::string &name, bool success, int32_t time,
        int32_t value, int32_t boundary);

    std::string name_;
    HcfResult code_;
    std::chrono::steady_clock::time_point start_;
};

#endif /* JS_API_METRICS_H */
