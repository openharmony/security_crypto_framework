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

#include "ani_sym_key_generator.h"
#include "ani_sym_key.h"

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace ANI::CryptoFramework {
SymKeyGeneratorImpl::SymKeyGeneratorImpl() : generator(nullptr) {}

SymKeyGeneratorImpl::SymKeyGeneratorImpl(HcfSymKeyGenerator *obj) : generator(obj) {}

SymKeyGeneratorImpl::~SymKeyGeneratorImpl()
{
    HcfObjDestroy(generator);
    generator = nullptr;
}

SymKey SymKeyGeneratorImpl::GenerateSymKeySync()
{
    return make_holder<SymKeyImpl, SymKey>(nullptr);
}

SymKey SymKeyGeneratorImpl::ConvertKeySync(DataBlob const& key)
{
    if (generator == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return make_holder<SymKeyImpl, SymKey>(nullptr);
    }
    HcfSymKey *symKey = nullptr;
    HcfBlob keyData = { .data = key.data.data(), .len = key.data.size() };
    HcfResult res = generator->convertSymKey(generator, &keyData, &symKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "convertSymKey key failed!");
        return make_holder<SymKeyImpl, SymKey>(nullptr);
    }
    return make_holder<SymKeyImpl, SymKey>(symKey);
}

string SymKeyGeneratorImpl::GetAlgName()
{
    if (generator == nullptr) {
        return "";
    }
    const char *algName = generator->getAlgoName(generator);
    return (algName == nullptr) ? "" : string(algName);
}

SymKeyGenerator CreateSymKeyGenerator(string_view algName)
{
    HcfSymKeyGenerator *generator = nullptr;
    HcfResult res = HcfSymKeyGeneratorCreate(algName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C generator obj fail.");
        return make_holder<SymKeyGeneratorImpl, SymKeyGenerator>(nullptr);
    }
    return make_holder<SymKeyGeneratorImpl, SymKeyGenerator>(generator);
}
} // namespace ANI::CryptoFramework

TH_EXPORT_CPP_API_CreateSymKeyGenerator(CreateSymKeyGenerator);
