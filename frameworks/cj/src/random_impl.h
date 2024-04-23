/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef RANDOM_IMPL_H
#define RANDOM_IMPL_H

#include "ffi_remote_data.h"
#include "rand.h"
#include "blob.h"

namespace OHOS {
namespace CryptoFramework {
class RandomImpl : public OHOS::FFI::FFIData {
public:
    explicit RandomImpl(int32_t* errCode);
    const char *GetAlgName();
    HcfBlob GenerateRandom(int32_t numBytes, int32_t* errCode);
    void SetSeed(HcfBlob *seed, int32_t* errCode);
    OHOS::FFI::RuntimeType *GetRuntimeType() override { return GetClassType(); }

private:
    friend class OHOS::FFI::RuntimeType;
    friend class OHOS::FFI::TypeBase;
    static OHOS::FFI::RuntimeType *GetClassType()
    {
        static OHOS::FFI::RuntimeType runtimeType =
            OHOS::FFI::RuntimeType::Create<OHOS::FFI::FFIData>("RandomImpl");
        return &runtimeType;
    }
    HcfRand *randObj_ = nullptr;
};
}
}

#endif