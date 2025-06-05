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

#include "ani_signature_utils.h"

namespace ANI::CryptoFramework {
EccSignatureSpec GenEccSignatureSpec(array_view<uint8_t> data)
{
    TH_THROW(std::runtime_error, "GenEccSignatureSpec not implemented");
}

array<uint8_t> GenEccSignature(EccSignatureSpec const& spec)
{
    TH_THROW(std::runtime_error, "GenEccSignature not implemented");
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_GenEccSignatureSpec(ANI::CryptoFramework::GenEccSignatureSpec);
TH_EXPORT_CPP_API_GenEccSignature(ANI::CryptoFramework::GenEccSignature);
// NOLINTEND
