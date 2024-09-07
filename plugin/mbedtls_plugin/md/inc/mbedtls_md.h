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
#ifndef HCF_MBEDTLS_MD_H
#define HCF_MBEDTLS_MD_H

#include "md_spi.h"

#define HCF_MBEDTLS_INVALID_MD_LEN 0

#ifdef __cplusplus
extern "C" {
#endif

HcfResult MbedtlsMdSpiCreate(const char *mbedtlsAlgoName, HcfMdSpi **spiObj);

#ifdef __cplusplus
}
#endif
#endif
