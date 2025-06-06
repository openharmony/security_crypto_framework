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

#ifndef HCF_DH_KEY_UTIL_H
#define HCF_DH_KEY_UTIL_H

#include <stdint.h>
#include "result.h"
#include "detailed_dh_key_params.h"

#ifdef __cplusplus
extern "C" {
#endif

HcfResult HcfDhKeyUtilCreate(int32_t pLen, int32_t skLen, HcfDhCommParamsSpec **returnCommonParamSpec);

#ifdef __cplusplus
}
#endif

#endif
