/*
 * Copyright (c)2025-2025 Huawei Device Co., Ltd.
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

#include "ani_asy_key_generator.h"
#include "ani_key_pair.h"

using namespace taihe;
using namespace ohos::security::cryptoFramework::cryptoFramework;
using namespace ANI::CryptoFramework;

namespace ANI::CryptoFramework {
AsyKeyGeneratorImpl::AsyKeyGeneratorImpl() {}

AsyKeyGeneratorImpl::AsyKeyGeneratorImpl(HcfAsyKeyGenerator *generator) : generator_(generator) {}

AsyKeyGeneratorImpl::~AsyKeyGeneratorImpl()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

KeyPair AsyKeyGeneratorImpl::GenerateKeyPairSync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = this->generator_->generateKeyPair(this->generator_, nullptr, &(keyPair));
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generate key pair fail.");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}

KeyPair AsyKeyGeneratorImpl::ConvertKeySync(OptDataBlob const& pubKey, OptDataBlob const& priKey)
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfBlob *pubKeyBlob = nullptr;
    HcfBlob *priKeyBlob = nullptr;
    HcfBlob skBlob = { .data = nullptr, .len = 0 };
    HcfBlob pkBlob = { .data = nullptr, .len = 0 };
    if (pubKey.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        pkBlob.data = pubKey.get_DATABLOB_ref().data.data();
        pkBlob.len = pubKey.get_DATABLOB_ref().data.size();
        pubKeyBlob = &pkBlob;
    }
    if (priKey.get_tag() == OptDataBlob::tag_t::DATABLOB) {
        skBlob.data = priKey.get_DATABLOB_ref().data.data();
        skBlob.len = priKey.get_DATABLOB_ref().data.size();
        priKeyBlob = &skBlob;
    }
    HcfResult res = this->generator_->convertKey(this->generator_, nullptr, pubKeyBlob, priKeyBlob, &(keyPair));
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "convert key fail.");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}

KeyPair AsyKeyGeneratorImpl::ConvertPemKeySync(OptString const& pubKey,
    OptString const& priKey, optional_view<string> password)
{
    // The parameters in the make_holder function should be of the same type
    // as the parameters in the constructor of the actual implementation class.
    return make_holder<KeyPairImpl, KeyPair>();
}

string AsyKeyGeneratorImpl::GetAlgName()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return "";
    }
    const char *algName = this->generator_->getAlgoName(this->generator_);
    return (algName == nullptr) ? "" : string(algName);
}

AsyKeyGenerator CreateAsyKeyGenerator(string_view algName)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create C generator obj fail!");
        return make_holder<AsyKeyGeneratorImpl, AsyKeyGenerator>();
    }
    return make_holder<AsyKeyGeneratorImpl, AsyKeyGenerator>(generator);
}
} // namespace ANI::CryptoFramework

TH_EXPORT_CPP_API_CreateAsyKeyGenerator(CreateAsyKeyGenerator);
