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

class SymKeyImpl {
public:
    SymKeyImpl() {
        // Don't forget to implement the constructor.
    }

    void ClearMem() {
        TH_THROW(std::runtime_error, "ClearMem not implemented");
    }

    int64_t GetSymKeyObj() {
        TH_THROW(std::runtime_error, "GetSymKeyObj not implemented");
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

SymKeyGenerator CreateSymKeyGenerator(string_view algName) {
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<SymKeyGeneratorImpl, SymKeyGenerator>();
}
}  // namespace

TH_EXPORT_CPP_API_CreateMd(CreateMd);
TH_EXPORT_CPP_API_CreateRandom(CreateRandom);
TH_EXPORT_CPP_API_CreateMac(CreateMac);
TH_EXPORT_CPP_API_CreateSymKeyGenerator(CreateSymKeyGenerator);
