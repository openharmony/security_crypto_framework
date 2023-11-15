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

#include "ecc_key_util.h"
#include <securec.h>
#include "ecc_key_util_spi.h"
#include "config.h"
#include "ecc_common_param_spec_generator_openssl.h"
#include "key_utils.h"
#include "params_parser.h"
#include "log.h"
#include "memory.h"
#include "utils.h"

typedef HcfResult (*HcfEccCommParamsSpecCreateFunc)(HcfAsyKeyGenParams *, HcfEccCommParamsSpecSpi **);

typedef struct {
    HcfAlgValue algo;

    HcfEccCommParamsSpecCreateFunc createSpiFunc;
} HcfEccCommParamsSpecAbility;

static const HcfEccCommParamsSpecAbility ASY_KEY_GEN_ABILITY_SET[] = {
    { HCF_ALG_ECC, HcfECCCommonParamSpecCreate },
};

static HcfEccCommParamsSpecCreateFunc FindAbility(HcfAsyKeyGenParams *params)
{
    if (params == NULL) {
        LOGE("params is null");
        return NULL;
    }
    for (uint32_t i = 0; i < sizeof(ASY_KEY_GEN_ABILITY_SET) / sizeof(ASY_KEY_GEN_ABILITY_SET[0]); i++) {
        if (ASY_KEY_GEN_ABILITY_SET[i].algo == params->algo) {
            return ASY_KEY_GEN_ABILITY_SET[i].createSpiFunc;
        }
    }
    LOGE("Algo not support! [Algo]: %d", params->algo);
    return NULL;
}


HcfResult HcfEccKeyUtilCreate(const char *algName, HcfEccCommParamsSpec **returnCommonParamSpec)
{
    if ((!IsStrValid(algName, HCF_MAX_ALGO_NAME_LEN)) || (returnCommonParamSpec == NULL)) {
        LOGE("Failed to parser parmas!");
        return HCF_INVALID_PARAMS;
    }
    HcfAsyKeyGenParams params = { 0 };
    if (ParseCurveNameToParams(algName, &params) != HCF_SUCCESS) {
        LOGE("Failed to parser parmas!");
        return HCF_INVALID_PARAMS;
    }

    HcfEccCommParamsSpecCreateFunc createSpiFunc = FindAbility(&params);
    if (createSpiFunc == NULL) {
        LOGE("Failed to find ability!");
        return HCF_NOT_SUPPORT;
    }

    HcfEccCommParamsSpecSpi *spiInstance = NULL;
    HcfResult ret = createSpiFunc(&params, &spiInstance);
    if (ret != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        return ret;
    }
    if (CreateEccCommonSpecImpl(&(spiInstance->paramsSpec), returnCommonParamSpec) != HCF_SUCCESS) {
        LOGE("Failed to create spi object!");
        FreeEccCommParamsSpec(&(spiInstance->paramsSpec));
        HcfFree(spiInstance);
        return ret;
    }
    FreeEccCommParamsSpec(&(spiInstance->paramsSpec));
    HcfFree(spiInstance);
    return HCF_SUCCESS;
}