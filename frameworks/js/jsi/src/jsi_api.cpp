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

#include "jsi_api.h"
#include "jsi_list.h"
#include "jsi.h"
#include "cipher.h"

namespace OHOS {
namespace ACELite {

static JSIValue CreateCryptoMode(void)
{
    JSIValue cryptoMode = JSI::CreateObject();
    JSI::SetNumberProperty(cryptoMode, "ENCRYPT_MODE", (double)ENCRYPT_MODE);
    JSI::SetNumberProperty(cryptoMode, "DECRYPT_MODE", (double)DECRYPT_MODE);
    return cryptoMode;
}

void InitCryptoFrameworkModule(JSIValue exports)
{
    JSI::SetModuleAPI(exports, "createMd", CryptoFrameworkLiteModule::CreateMd);
    JSI::SetModuleAPI(exports, "createMac", CryptoFrameworkLiteModule::CreateMac);
    JSI::SetModuleAPI(exports, "createRandom", CryptoFrameworkLiteModule::CreateRandom);
    JSI::SetModuleAPI(exports, "createSymKeyGenerator", CryptoFrameworkLiteModule::CreateSymKeyGenerator);
    JSI::SetModuleAPI(exports, "createCipher", CryptoFrameworkLiteModule::CreateCipher);
    JSIValue cryptoMode = CreateCryptoMode();
    JSI::SetNamedProperty(exports, "CryptoMode", cryptoMode);
    JSI::ReleaseValue(cryptoMode);
    JSI::SetOnDestroy(exports, CryptoFrameworkLiteModule::OnDestroy);
    ListObjInit(JSI_ALG_MD);
    ListObjInit(JSI_ALG_MAC);
    ListObjInit(JSI_ALG_RAND);
    ListObjInit(JSI_ALG_SYM_KEY);
    ListObjInit(JSI_ALG_CIPHER);
}

void CryptoFrameworkLiteModule::OnDestroy(void)
{
    CipherDestroy();
    SymKeyDestroy();
    RandomDestroy();
    MacDestroy();
    MdDestroy();
}

} // ACELite
} // OHOS
