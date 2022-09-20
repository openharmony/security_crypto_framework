/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "securec.h"
#include "log.h"
#include "memory.h"

#include "napi_x509_certificate.h"
#include "napi_asy_key_generator.h"
#include "napi_sym_key_generator.h"
#include "napi_cipher.h"
#include "napi_cert_chain_validator.h"
#include "napi_key_pair.h"
#include "napi_pri_key.h"
#include "napi_pub_key.h"
#include "napi_sign.h"
#include "napi_verify.h"
#include "napi_key_agreement.h"
#include "napi_mac.h"
#include "napi_md.h"
#include "napi_rand.h"
#include "napi_sym_key.h"
#include "napi_key.h"
#include "napi_utils.h"
#include "napi_x509_crl_entry.h"
#include "napi_x509_crl.h"
#include "napi_crypto_framework_defines.h"

namespace OHOS {
namespace CryptoFramework {
static napi_value CreateEncodingFormat(napi_env env)
{
    napi_value encodingFormat = nullptr;
    napi_create_object(env, &encodingFormat);

    AddUint32Property(env, encodingFormat, "FORMAT_DER", HCF_FORMAT_DER);
    AddUint32Property(env, encodingFormat, "FORMAT_PEM", HCF_FORMAT_PEM);

    return encodingFormat;
}

static void DefineEncodingFormatProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("EncodingFormat", CreateEncodingFormat(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateCryptoMode(napi_env env)
{
    napi_value cryptoMode = nullptr;
    napi_create_object(env, &cryptoMode);

    AddUint32Property(env, cryptoMode, "ENCRYPT_MODE", ENCRYPT_MODE);
    AddUint32Property(env, cryptoMode, "DECRYPT_MODE", DECRYPT_MODE);
    return cryptoMode;
}

static void DefineCryptoModeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CryptoMode", CreateCryptoMode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

static napi_value CreateResultCode(napi_env env)
{
    napi_value resultCode = nullptr;
    napi_create_object(env, &resultCode);

    AddUint32Property(env, resultCode, "INVALID_PARAMS", JS_ERR_INVALID_PARAMS);
    AddUint32Property(env, resultCode, "NOT_SUPPORT", JS_ERR_NOT_SUPPORT);
    AddUint32Property(env, resultCode, "ERR_OUT_OF_MEMORY", JS_ERR_OUT_OF_MEMORY);
    AddUint32Property(env, resultCode, "ERR_INTERNAL_ERROR", JS_ERR_INTERNAL_ERROR);
    AddUint32Property(env, resultCode, "ERR_CRYPTO_OPERATION", JS_ERR_CRYPTO_OPERATION);
    AddUint32Property(env, resultCode, "ERR_CERT_SIGNATURE_FAILURE", JS_ERR_CERT_SIGNATURE_FAILURE);
    AddUint32Property(env, resultCode, "ERR_CERT_NOT_YET_VALID", JS_ERR_CERT_NOT_YET_VALID);
    AddUint32Property(env, resultCode, "ERR_CERT_HAS_EXPIRED", JS_ERR_CERT_HAS_EXPIRED);
    AddUint32Property(env, resultCode, "ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
        JS_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
    AddUint32Property(env, resultCode, "ERR_KEYUSAGE_NO_CERTSIGN", JS_ERR_KEYUSAGE_NO_CERTSIGN);
    AddUint32Property(env, resultCode, "ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE", JS_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE);

    return resultCode;
}

static void DefineResultCodeProperties(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("Result", CreateResultCode(env)),
    };
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

/***********************************************
 * Module export and register
 ***********************************************/
static napi_value ModuleExport(napi_env env, napi_value exports)
{
    LOGI("module init start.");

    DefineEncodingFormatProperties(env, exports);
    DefineCryptoModeProperties(env, exports);
    DefineResultCodeProperties(env, exports);
    NapiAsyKeyGenerator::DefineAsyKeyGeneratorJSClass(env, exports);
    NapiKeyPair::DefineKeyPairJSClass(env);
    NapiPubKey::DefinePubKeyJSClass(env);
    NapiPriKey::DefinePriKeyJSClass(env);

    NapiSign::DefineSignJSClass(env, exports);
    NapiVerify::DefineVerifyJSClass(env, exports);
    NapiKeyAgreement::DefineKeyAgreementJSClass(env, exports);
    // NapiCertFactory::DefineCertFactoryJSClass(env, exports);
    NapiCertChainValidator::DefineCertChainValidatorJSClass(env, exports);
    NapiMac::DefineMacJSClass(env, exports);
    NapiMd::DefineMdJSClass(env, exports);
    NapiPubKey::DefinePubKeyJSClass(env);
    NapiRand::DefineRandJSClass(env, exports);
    NapiSymKeyGenerator::DefineSymKeyGeneratorJSClass(env, exports);
    NapiCipher::DefineCipherJSClass(env, exports);
    NapiSymKey::DefineSymKeyJSClass(env);
    NapiKey::DefineHcfKeyJSClass(env);
    NapiX509Certificate::DefineX509CertJSClass(env, exports);
    NapiX509CrlEntry::DefineX509CrlEntryJSClass(env);
    NapiX509Crl::DefineX509CrlJSClass(env, exports);
    LOGI("module init end.");
    return exports;
}

static napi_module cryptoFrameworkModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = ModuleExport,
    .nm_modname = "security.cryptoFramework",
    .nm_priv = ((void*)0),
    .reserved = { 0 },
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&cryptoFrameworkModule);
}
}  // namespace CryptoFramework
}  // namespace OHOS
