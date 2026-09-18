/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef HCF_MBEDTLS_SYM_KEY_H
#define HCF_MBEDTLS_SYM_KEY_H

#include "sym_key_factory_spi.h"
#include "sym_key.h"
#include "params_parser.h"

#define MBEDTLS_SYM_GENERATOR_CLASS "MBEDTLS.SYM.KEYGENERATOR"
#define MBEDTLS_SYM_KEY_CLASS "MBEDTLS.SYM.KEY"

typedef struct {
    HcfAlgValue algo;
    int keySize;
} SymKeyAttr;

typedef struct {
    HcfSymKey key;
    char *algoName;
    HcfBlob keyMaterial;
} SymKeyImpl;

#ifdef __cplusplus
extern "C" {
#endif

HcfResult MbedtlsSymKeyGeneratorSpiCreate(SymKeyAttr *attr, HcfSymKeyGeneratorSpi **generator);

#ifdef __cplusplus
}
#endif
#endif // HCF_MBEDTLS_SYM_KEY_H
