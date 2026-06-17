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

#include "js_api_metrics.h"
#include <chrono>
#include <string>
#include <unordered_map>

#ifdef CRYPTO_FRAMEWORK_API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

#define HCF "cryptoFramework."

static const std::unordered_map<HcfJsApiId, std::string> API_NAMES = {
    /* SymKey */
    { API_SYMKEY_GET_ENCODED, HCF "SymKey.getEncoded" },
    { API_SYMKEY_GET_KEY_SIZE, HCF "SymKey.getKeySize" },
    { API_SYMKEY_CLEAR_MEM, HCF "SymKey.clearMem" },
    /* PriKey */
    { API_PRIKEY_GET_ENCODED, HCF "PriKey.getEncoded" },
    { API_PRIKEY_GET_KEY_SIZE, HCF "PriKey.getKeySize" },
    { API_PRIKEY_CLEAR_MEM, HCF "PriKey.clearMem" },
    { API_PRIKEY_GET_ASY_KEY_SPEC, HCF "PriKey.getAsyKeySpec" },
    { API_PRIKEY_GET_ENCODED_DER, HCF "PriKey.getEncodedDer" },
    { API_PRIKEY_GET_ENCODED_PEM, HCF "PriKey.getEncodedPem" },
    { API_PRIKEY_GET_PUB_KEY, HCF "PriKey.getPubKey" },
    { API_PRIKEY_GET_PUB_KEY_SYNC, HCF "PriKey.getPubKeySync" },
    { API_PRIKEY_GET_KEY_DATA, HCF "PriKey.getKeyData" },
    { API_PRIKEY_GET_KEY_DATA_SYNC, HCF "PriKey.getKeyDataSync" },
    /* PubKey */
    { API_PUBKEY_GET_ENCODED, HCF "PubKey.getEncoded" },
    { API_PUBKEY_GET_KEY_SIZE, HCF "PubKey.getKeySize" },
    { API_PUBKEY_GET_ASY_KEY_SPEC, HCF "PubKey.getAsyKeySpec" },
    { API_PUBKEY_GET_ENCODED_DER, HCF "PubKey.getEncodedDer" },
    { API_PUBKEY_GET_ENCODED_PEM, HCF "PubKey.getEncodedPem" },
    { API_PUBKEY_GET_KEY_DATA, HCF "PubKey.getKeyData" },
    { API_PUBKEY_GET_KEY_DATA_SYNC, HCF "PubKey.getKeyDataSync" },
    /* Random */
    { API_CREATE_RANDOM, HCF "createRandom" },
    { API_RANDOM_GENERATE_RANDOM, HCF "Random.generateRandom" },
    { API_RANDOM_GENERATE_RANDOM_SYNC, HCF "Random.generateRandomSync" },
    { API_RANDOM_SET_SEED, HCF "Random.setSeed" },
    { API_RANDOM_ENABLE_HARDWARE_ENTROPY, HCF "Random.enableHardwareEntropy" },
    /* AsyKeyGenerator */
    { API_CREATE_ASY_KEY_GENERATOR, HCF "createAsyKeyGenerator" },
    { API_ASY_KEY_GENERATOR_GENERATE_KEY_PAIR, HCF "AsyKeyGenerator.generateKeyPair" },
    { API_ASY_KEY_GENERATOR_GENERATE_KEY_PAIR_SYNC, HCF "AsyKeyGenerator.generateKeyPairSync" },
    { API_ASY_KEY_GENERATOR_CONVERT_KEY, HCF "AsyKeyGenerator.convertKey" },
    { API_ASY_KEY_GENERATOR_CONVERT_KEY_SYNC, HCF "AsyKeyGenerator.convertKeySync" },
    { API_ASY_KEY_GENERATOR_CONVERT_PEM_KEY, HCF "AsyKeyGenerator.convertPemKey" },
    { API_ASY_KEY_GENERATOR_CONVERT_PEM_KEY_SYNC, HCF "AsyKeyGenerator.convertPemKeySync" },
    /* SymKeyGenerator */
    { API_CREATE_SYM_KEY_GENERATOR, HCF "createSymKeyGenerator" },
    { API_SYM_KEY_GENERATOR_GENERATE_SYM_KEY, HCF "SymKeyGenerator.generateSymKey" },
    { API_SYM_KEY_GENERATOR_GENERATE_SYM_KEY_SYNC, HCF "SymKeyGenerator.generateSymKeySync" },
    { API_SYM_KEY_GENERATOR_CONVERT_KEY, HCF "SymKeyGenerator.convertKey" },
    { API_SYM_KEY_GENERATOR_CONVERT_KEY_SYNC, HCF "SymKeyGenerator.convertKeySync" },
    /* Mac */
    { API_CREATE_MAC, HCF "createMac" },
    { API_MAC_INIT, HCF "Mac.init" },
    { API_MAC_INIT_SYNC, HCF "Mac.initSync" },
    { API_MAC_UPDATE, HCF "Mac.update" },
    { API_MAC_UPDATE_SYNC, HCF "Mac.updateSync" },
    { API_MAC_DO_FINAL, HCF "Mac.doFinal" },
    { API_MAC_DO_FINAL_SYNC, HCF "Mac.doFinalSync" },
    { API_MAC_GET_MAC_LENGTH, HCF "Mac.getMacLength" },
    /* Md */
    { API_CREATE_MD, HCF "createMd" },
    { API_MD_UPDATE, HCF "Md.update" },
    { API_MD_UPDATE_SYNC, HCF "Md.updateSync" },
    { API_MD_DIGEST, HCF "Md.digest" },
    { API_MD_DIGEST_SYNC, HCF "Md.digestSync" },
    { API_MD_GET_MD_LENGTH, HCF "Md.getMdLength" },
    /* Cipher */
    { API_CREATE_CIPHER, HCF "createCipher" },
    { API_CIPHER_INIT, HCF "Cipher.init" },
    { API_CIPHER_INIT_SYNC, HCF "Cipher.initSync" },
    { API_CIPHER_UPDATE, HCF "Cipher.update" },
    { API_CIPHER_UPDATE_SYNC, HCF "Cipher.updateSync" },
    { API_CIPHER_DO_FINAL, HCF "Cipher.doFinal" },
    { API_CIPHER_DO_FINAL_SYNC, HCF "Cipher.doFinalSync" },
    { API_CIPHER_SET_CIPHER_SPEC, HCF "Cipher.setCipherSpec" },
    { API_CIPHER_GET_CIPHER_SPEC, HCF "Cipher.getCipherSpec" },
    /* Sign */
    { API_CREATE_SIGN, HCF "createSign" },
    { API_SIGN_INIT, HCF "Sign.init" },
    { API_SIGN_INIT_SYNC, HCF "Sign.initSync" },
    { API_SIGN_UPDATE, HCF "Sign.update" },
    { API_SIGN_UPDATE_SYNC, HCF "Sign.updateSync" },
    { API_SIGN_SIGN, HCF "Sign.sign" },
    { API_SIGN_SIGN_SYNC, HCF "Sign.signSync" },
    { API_SIGN_SET_SIGN_SPEC, HCF "Sign.setSignSpec" },
    { API_SIGN_GET_SIGN_SPEC, HCF "Sign.getSignSpec" },
    /* Verify */
    { API_CREATE_VERIFY, HCF "createVerify" },
    { API_VERIFY_INIT, HCF "Verify.init" },
    { API_VERIFY_INIT_SYNC, HCF "Verify.initSync" },
    { API_VERIFY_UPDATE, HCF "Verify.update" },
    { API_VERIFY_UPDATE_SYNC, HCF "Verify.updateSync" },
    { API_VERIFY_VERIFY, HCF "Verify.verify" },
    { API_VERIFY_VERIFY_SYNC, HCF "Verify.verifySync" },
    { API_VERIFY_RECOVER, HCF "Verify.recover" },
    { API_VERIFY_RECOVER_SYNC, HCF "Verify.recoverSync" },
    { API_VERIFY_SET_VERIFY_SPEC, HCF "Verify.setVerifySpec" },
    { API_VERIFY_GET_VERIFY_SPEC, HCF "Verify.getVerifySpec" },
    /* KeyAgreement */
    { API_CREATE_KEY_AGREEMENT, HCF "createKeyAgreement" },
    { API_KEY_AGREEMENT_GENERATE_SECRET, HCF "KeyAgreement.generateSecret" },
    { API_KEY_AGREEMENT_GENERATE_SECRET_SYNC, HCF "KeyAgreement.generateSecretSync" },
    /* ECCKeyUtil */
    { API_ECC_KEY_UTIL_GEN_ECC_COMMON_PARAMS_SPEC, HCF "ECCKeyUtil.genECCCommonParamsSpec" },
    { API_ECC_KEY_UTIL_CONVERT_POINT, HCF "ECCKeyUtil.convertPoint" },
    { API_ECC_KEY_UTIL_GET_ENCODED_POINT, HCF "ECCKeyUtil.getEncodedPoint" },
    /* DHKeyUtil */
    { API_DH_KEY_UTIL_GEN_DH_COMMON_PARAMS_SPEC, HCF "DHKeyUtil.genDHCommonParamsSpec" },
    /* AsyKeyGeneratorBySpec */
    { API_CREATE_ASY_KEY_GENERATOR_BY_SPEC, HCF "createAsyKeyGeneratorBySpec" },
    { API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_KEY_PAIR, HCF "AsyKeyGeneratorBySpec.generateKeyPair" },
    { API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_KEY_PAIR_SYNC, HCF "AsyKeyGeneratorBySpec.generateKeyPairSync" },
    { API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PRI_KEY, HCF "AsyKeyGeneratorBySpec.generatePriKey" },
    { API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PRI_KEY_SYNC, HCF "AsyKeyGeneratorBySpec.generatePriKeySync" },
    { API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PUB_KEY, HCF "AsyKeyGeneratorBySpec.generatePubKey" },
    { API_ASY_KEY_GENERATOR_BY_SPEC_GENERATE_PUB_KEY_SYNC, HCF "AsyKeyGeneratorBySpec.generatePubKeySync" },
    /* Kdf */
    { API_CREATE_KDF, HCF "createKdf" },
    { API_KDF_GENERATE_SECRET, HCF "Kdf.generateSecret" },
    { API_KDF_GENERATE_SECRET_SYNC, HCF "Kdf.generateSecretSync" },
    /* SM2CryptoUtil */
    { API_SM2_CRYPTO_UTIL_GEN_CIPHER_TEXT_BY_SPEC, HCF "SM2CryptoUtil.genCipherTextBySpec" },
    { API_SM2_CRYPTO_UTIL_GET_CIPHER_TEXT_SPEC, HCF "SM2CryptoUtil.getCipherTextSpec" },
    /* SignatureUtils */
    { API_SIGNATURE_UTILS_GEN_ECC_SIGNATURE_SPEC, HCF "SignatureUtils.genEccSignatureSpec" },
    { API_SIGNATURE_UTILS_GEN_ECC_SIGNATURE, HCF "SignatureUtils.genEccSignature" },
    /* Kem */
    { API_CREATE_KEM, HCF "createKem" },
    { API_KEM_ENCAPSULATE, HCF "Kem.encapsulate" },
    { API_KEM_ENCAPSULATE_SYNC, HCF "Kem.encapsulateSync" },
    { API_KEM_DECAPSULATE, HCF "Kem.decapsulate" },
    { API_KEM_DECAPSULATE_SYNC, HCF "Kem.decapsulateSync" },
};

static const std::unordered_map<HcfResult, int32_t> ERROR_CODES = {
    { HCF_SUCCESS, 0 },                     /* 0 */
    { HCF_INVALID_PARAMS, 1 },              /* 401 */
    { HCF_NOT_SUPPORT, 2 },                 /* 801 */
    { HCF_ERR_MALLOC, 3 },                  /* 17620001 */
    { HCF_ERR_NAPI, 4 },                    /* 17620002 */
    { HCF_ERR_ANI, 4 },                     /* 17620002 */
    { HCF_ERR_PARAMETER_CHECK_FAILED, 5 },  /* 17620003 */
    { HCF_ERR_INVALID_CALL, 6 },            /* 17620004 */
    { HCF_ERR_CRYPTO_OPERATION, 7 },        /* 17630001 */
};

HistogramScopeGuard::HistogramScopeGuard(HcfJsApiId id)
    : name_(""), code_(HCF_SUCCESS), start_(std::chrono::steady_clock::now())
{
    auto it = API_NAMES.find(id);
    if (it != API_NAMES.end()) {
        name_ = it->second;
    }
}

HistogramScopeGuard::~HistogramScopeGuard()
{
    bool success = (code_ == HCF_SUCCESS);
    auto [value, boundary] = GetCodeValue(code_);
    int32_t time = static_cast<int32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_).count());
    HistogramApiReport(name_, success, time, value, boundary);
}

void HistogramScopeGuard::DisableScopeGuard()
{
     // clear name, skip report when name is empty in function called
    name_.clear();
}

void HistogramScopeGuard::SetErrorCode(HcfResult code)
{
    code_ = code;
}

std::pair<int32_t, int32_t> HistogramScopeGuard::GetCodeValue(HcfResult code) const
{
    int32_t boundary = static_cast<int32_t>(ERROR_CODES.size());
    int32_t value = -1;
    auto it = ERROR_CODES.find(code);
    if (it != ERROR_CODES.end()) {
        value = it->second;
    }
    return { value, boundary };
}

std::string HistogramScopeGuard::GetApiName() const
{
    return name_;
}

void HistogramScopeGuard::HistogramApiReport(const std::string &name, bool success, int32_t time,
    int32_t value, int32_t boundary)
{
#ifdef CRYPTO_FRAMEWORK_API_METRICS_ENABLE
    if (!name.empty()) {
        HISTOGRAM_BOOLEAN((name + ".call").c_str(), success);
        HISTOGRAM_TIMES((name + ".time").c_str(), time);
        if (value >= 0) {
            HISTOGRAM_ENUMERATION((name + ".errcode").c_str(), value, boundary);
        }
    }
#endif
}
