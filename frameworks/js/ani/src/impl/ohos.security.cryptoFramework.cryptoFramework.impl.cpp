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

#include "ohos.security.cryptoFramework.cryptoFramework.proj.hpp"
#include "ohos.security.cryptoFramework.cryptoFramework.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;

namespace {
// To be implemented.

class MdImpl {
public:
    MdImpl() {
        // Don't forget to implement the constructor.
    }

    void UpdateSync(DataBlob const& input) {
        TH_THROW(std::runtime_error, "UpdateSync not implemented");
    }

    DataBlob DigestSync() {
        TH_THROW(std::runtime_error, "DigestSync not implemented");
    }

    int32_t GetMdLength() {
        TH_THROW(std::runtime_error, "GetMdLength not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class RandomImpl {
public:
    RandomImpl() {
        // Don't forget to implement the constructor.
    }

    DataBlob GenerateRandomSync(int32_t len) {
        TH_THROW(std::runtime_error, "GenerateRandomSync not implemented");
    }

    void SetSeed(DataBlob const& seed) {
        TH_THROW(std::runtime_error, "SetSeed not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class MacImpl {
public:
    MacImpl() {
        // Don't forget to implement the constructor.
    }

    void InitSync(weak::SymKey key) {
        TH_THROW(std::runtime_error, "InitSync not implemented");
    }

    void UpdateSync(DataBlob const& input) {
        TH_THROW(std::runtime_error, "UpdateSync not implemented");
    }

    DataBlob DoFinalSync() {
        TH_THROW(std::runtime_error, "DoFinalSync not implemented");
    }

    int32_t GetMacLength() {
        TH_THROW(std::runtime_error, "GetMacLength not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class KeyImpl {
public:
    KeyImpl() {
        // Don't forget to implement the constructor.
    }

    int64_t GetKeyObj() {
        TH_THROW(std::runtime_error, "GetKeyObj not implemented");
    }

    DataBlob GetEncoded() {
        TH_THROW(std::runtime_error, "GetEncoded not implemented");
    }

    string GetFormat() {
        TH_THROW(std::runtime_error, "GetFormat not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class PriKeyImpl {
public:
    PriKeyImpl() {
        // Don't forget to implement the constructor.
    }

    int64_t GetPriKeyObj() {
        TH_THROW(std::runtime_error, "GetPriKeyObj not implemented");
    }

    void ClearMem() {
        TH_THROW(std::runtime_error, "ClearMem not implemented");
    }

    OptKeySpec GetAsyKeySpec(AsyKeySpecEnum itemType) {
        TH_THROW(std::runtime_error, "GetAsyKeySpec not implemented");
    }

    DataBlob GetEncodedDer(string_view format) {
        TH_THROW(std::runtime_error, "GetEncodedDer not implemented");
    }

    string GetEncodedPem(string_view format) {
        TH_THROW(std::runtime_error, "GetEncodedPem not implemented");
    }

    string GetEncodedPemEx(string_view format, KeyEncodingConfig const& config) {
        TH_THROW(std::runtime_error, "GetEncodedPemEx not implemented");
    }

    int64_t GetKeyObj() {
        TH_THROW(std::runtime_error, "GetKeyObj not implemented");
    }

    DataBlob GetEncoded() {
        TH_THROW(std::runtime_error, "GetEncoded not implemented");
    }

    string GetFormat() {
        TH_THROW(std::runtime_error, "GetFormat not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class PubKeyImpl {
public:
    PubKeyImpl() {
        // Don't forget to implement the constructor.
    }

    int64_t GetPubKeyObj() {
        TH_THROW(std::runtime_error, "GetPubKeyObj not implemented");
    }

    OptKeySpec GetAsyKeySpec(AsyKeySpecEnum itemType) {
        TH_THROW(std::runtime_error, "GetAsyKeySpec not implemented");
    }

    DataBlob GetEncodedDer(string_view format) {
        TH_THROW(std::runtime_error, "GetEncodedDer not implemented");
    }

    string GetEncodedPem(string_view format) {
        TH_THROW(std::runtime_error, "GetEncodedPem not implemented");
    }

    int64_t GetKeyObj() {
        TH_THROW(std::runtime_error, "GetKeyObj not implemented");
    }

    DataBlob GetEncoded() {
        TH_THROW(std::runtime_error, "GetEncoded not implemented");
    }

    string GetFormat() {
        TH_THROW(std::runtime_error, "GetFormat not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class KeyPairImpl {
public:
    KeyPairImpl() {
        // Don't forget to implement the constructor.
    }

    PriKey GetPriKey() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<PriKeyImpl, PriKey>();
    }

    PubKey GetPubKey() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<PubKeyImpl, PubKey>();
    }
};

class SymKeyImpl {
public:
    SymKeyImpl() {
        // Don't forget to implement the constructor.
    }

    int64_t GetSymKeyObj() {
        TH_THROW(std::runtime_error, "GetSymKeyObj not implemented");
    }

    void ClearMem() {
        TH_THROW(std::runtime_error, "ClearMem not implemented");
    }

    int64_t GetKeyObj() {
        TH_THROW(std::runtime_error, "GetKeyObj not implemented");
    }

    DataBlob GetEncoded() {
        TH_THROW(std::runtime_error, "GetEncoded not implemented");
    }

    string GetFormat() {
        TH_THROW(std::runtime_error, "GetFormat not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class SymKeyGeneratorImpl {
public:
    SymKeyGeneratorImpl() {
        // Don't forget to implement the constructor.
    }

    SymKey GenerateSymKeySync() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<SymKeyImpl, SymKey>();
    }

    SymKey ConvertKeySync(DataBlob const& key) {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<SymKeyImpl, SymKey>();
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class AsyKeyGeneratorImpl {
public:
    AsyKeyGeneratorImpl() {
        // Don't forget to implement the constructor.
    }

    KeyPair GenerateKeyPairSync() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<KeyPairImpl, KeyPair>();
    }

    KeyPair ConvertKeySync(OptDataBlob const& pubKey, OptDataBlob const& priKey) {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<KeyPairImpl, KeyPair>();
    }

    KeyPair ConvertPemKeySync(OptString const& pubKey, OptString const& priKey) {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<KeyPairImpl, KeyPair>();
    }

    KeyPair ConvertPemKeySyncEx(OptString const& pubKey, OptString const& priKey, string_view password) {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<KeyPairImpl, KeyPair>();
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class KdfImpl {
public:
    KdfImpl() {
        // Don't forget to implement the constructor.
    }

    DataBlob GenerateSecretSync(OptExtKdfSpec const& params) {
        TH_THROW(std::runtime_error, "GenerateSecretSync not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class CipherImpl {
public:
    CipherImpl() {
        // Don't forget to implement the constructor.
    }

    void InitSync(CryptoMode opMode, weak::Key key, OptParamsSpec const& params) {
        TH_THROW(std::runtime_error, "InitSync not implemented");
    }

    DataBlob UpdateSync(DataBlob const& input) {
        TH_THROW(std::runtime_error, "UpdateSync not implemented");
    }

    DataBlob DoFinalSync(OptDataBlob const& input) {
        TH_THROW(std::runtime_error, "DoFinalSync not implemented");
    }

    void SetCipherSpec(CipherSpecEnum itemType, array_view<uint8_t> itemValue) {
        TH_THROW(std::runtime_error, "SetCipherSpec not implemented");
    }

    OptStrUint8Arr GetCipherSpec(CipherSpecEnum itemType) {
        TH_THROW(std::runtime_error, "GetCipherSpec not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class VerifyImpl {
public:
    VerifyImpl() {
        // Don't forget to implement the constructor.
    }

    void InitSync(weak::PubKey pubKey) {
        TH_THROW(std::runtime_error, "InitSync not implemented");
    }

    void UpdateSync(DataBlob const& input) {
        TH_THROW(std::runtime_error, "UpdateSync not implemented");
    }

    bool VerifySync(OptDataBlob const& data, DataBlob const& signature) {
        TH_THROW(std::runtime_error, "VerifySync not implemented");
    }

    OptDataBlob RecoverSync(DataBlob const& signature) {
        TH_THROW(std::runtime_error, "RecoverSync not implemented");
    }

    void SetVerifySpec(SignSpecEnum itemType, OptIntUint8Arr const& itemValue) {
        TH_THROW(std::runtime_error, "SetVerifySpec not implemented");
    }

    OptStrInt GetVerifySpec(SignSpecEnum itemType) {
        TH_THROW(std::runtime_error, "GetVerifySpec not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class SignImpl {
public:
    SignImpl() {
        // Don't forget to implement the constructor.
    }

    void InitSync(weak::PriKey priKey) {
        TH_THROW(std::runtime_error, "InitSync not implemented");
    }

    void UpdateSync(DataBlob const& data) {
        TH_THROW(std::runtime_error, "UpdateSync not implemented");
    }

    DataBlob SignSync(OptDataBlob const& data) {
        TH_THROW(std::runtime_error, "SignSync not implemented");
    }

    void SetSignSpec(SignSpecEnum itemType, OptIntUint8Arr const& itemValue) {
        TH_THROW(std::runtime_error, "SetSignSpec not implemented");
    }

    OptStrInt GetSignSpec(SignSpecEnum itemType) {
        TH_THROW(std::runtime_error, "GetSignSpec not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class AsyKeyGeneratorBySpecImpl {
public:
    AsyKeyGeneratorBySpecImpl() {
        // Don't forget to implement the constructor.
    }

    KeyPair GenerateKeyPairSync() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<KeyPairImpl, KeyPair>();
    }

    PriKey GeneratePriKeySync() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<PriKeyImpl, PriKey>();
    }

    PubKey GeneratePubKeySync() {
        // The parameters in the make_holder function should be of the same type
        // as the parameters in the constructor of the actual implementation class.
        return make_holder<PubKeyImpl, PubKey>();
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class KeyAgreementImpl {
public:
    KeyAgreementImpl() {
        // Don't forget to implement the constructor.
    }

    DataBlob GenerateSecretSync(weak::PriKey priKey, weak::PubKey pubKey) {
        TH_THROW(std::runtime_error, "GenerateSecretSync not implemented");
    }

    string GetAlgName() {
        TH_THROW(std::runtime_error, "GetAlgName not implemented");
    }
};

class DHKeyUtilImpl {
public:
    DHKeyUtilImpl() {
        // Don't forget to implement the constructor.
    }
};

class ECCKeyUtilImpl {
public:
    ECCKeyUtilImpl() {
        // Don't forget to implement the constructor.
    }
};

class SM2CryptoUtilImpl {
public:
    SM2CryptoUtilImpl() {
        // Don't forget to implement the constructor.
    }
};

Md CreateMd(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<MdImpl, Md>();
}

Random CreateRandom() {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<RandomImpl, Random>();
}

Mac CreateMac(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<MacImpl, Mac>();
}

Mac CreateMacBySpec(OptExtMacSpec const& macSpec) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<MacImpl, Mac>();
}

SymKeyGenerator CreateSymKeyGenerator(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<SymKeyGeneratorImpl, SymKeyGenerator>();
}

AsyKeyGenerator CreateAsyKeyGenerator(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<AsyKeyGeneratorImpl, AsyKeyGenerator>();
}

Kdf CreateKdf(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<KdfImpl, Kdf>();
}

Cipher CreateCipher(string_view transformation) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<CipherImpl, Cipher>();
}

Verify CreateVerify(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<VerifyImpl, Verify>();
}

Sign CreateSign(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<SignImpl, Sign>();
}

AsyKeyGeneratorBySpec CreateAsyKeyGeneratorBySpec(OptAsyKeySpec const& asyKeySpec) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>();
}

KeyAgreement CreateKeyAgreement(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<KeyAgreementImpl, KeyAgreement>();
}

DHCommonParamsSpec GenDHCommonParamsSpec(int32_t pLen, optional_view<int32_t> skLen) {
    TH_THROW(std::runtime_error, "GenDHCommonParamsSpec not implemented");
}

ECCCommonParamsSpec GenECCCommonParamsSpec(string_view curveName) {
    TH_THROW(std::runtime_error, "GenECCCommonParamsSpec not implemented");
}

Point ConvertPoint(string_view curveName, array_view<uint8_t> encodedPoint) {
    TH_THROW(std::runtime_error, "ConvertPoint not implemented");
}

array<uint8_t> GetEncodedPoint(string_view curveName, Point const& point, string_view format) {
    TH_THROW(std::runtime_error, "GetEncodedPoint not implemented");
}

DataBlob GenCipherTextBySpec(SM2CipherTextSpec const& spec, optional_view<string> mode) {
    TH_THROW(std::runtime_error, "GenCipherTextBySpec not implemented");
}

SM2CipherTextSpec GetCipherTextSpec(DataBlob const& cipherText, optional_view<string> mode) {
    TH_THROW(std::runtime_error, "GetCipherTextSpec not implemented");
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateMd(CreateMd);
TH_EXPORT_CPP_API_CreateRandom(CreateRandom);
TH_EXPORT_CPP_API_CreateMac(CreateMac);
TH_EXPORT_CPP_API_CreateMacBySpec(CreateMacBySpec);
TH_EXPORT_CPP_API_CreateSymKeyGenerator(CreateSymKeyGenerator);
TH_EXPORT_CPP_API_CreateAsyKeyGenerator(CreateAsyKeyGenerator);
TH_EXPORT_CPP_API_CreateKdf(CreateKdf);
TH_EXPORT_CPP_API_CreateCipher(CreateCipher);
TH_EXPORT_CPP_API_CreateVerify(CreateVerify);
TH_EXPORT_CPP_API_CreateSign(CreateSign);
TH_EXPORT_CPP_API_CreateAsyKeyGeneratorBySpec(CreateAsyKeyGeneratorBySpec);
TH_EXPORT_CPP_API_CreateKeyAgreement(CreateKeyAgreement);
TH_EXPORT_CPP_API_GenDHCommonParamsSpec(GenDHCommonParamsSpec);
TH_EXPORT_CPP_API_GenECCCommonParamsSpec(GenECCCommonParamsSpec);
TH_EXPORT_CPP_API_ConvertPoint(ConvertPoint);
TH_EXPORT_CPP_API_GetEncodedPoint(GetEncodedPoint);
TH_EXPORT_CPP_API_GenCipherTextBySpec(GenCipherTextBySpec);
TH_EXPORT_CPP_API_GetCipherTextSpec(GetCipherTextSpec);
// NOLINTEND
