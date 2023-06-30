/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef HCF_CIPHER_SM2_OPENSSL_H
#define HCF_CIPHER_SM2_OPENSSL_H

#include "cipher_factory_spi.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfCipherSm2CipherSpiCreate(CipherAttr *params, HcfCipherGeneratorSpi **generator);

#ifdef __cplusplus
}
#endif
#endif