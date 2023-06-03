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

#include "asy_key_params.h"

#include <stdio.h>
#include <string.h>
#include <securec.h>

#include "big_integer.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "memory.h"
#include "log.h"

#define ALG_NAME_DSA "DSA"
#define ALG_NAME_ECC "ECC"
#define ALG_NAME_RSA "RSA"

void FreeDsaCommParamsSpec(HcfDsaCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->base.algName);
    spec->base.algName = NULL;
    HcfFree(spec->p.data);
    spec->p.data = NULL;
    HcfFree(spec->q.data);
    spec->q.data = NULL;
    HcfFree(spec->g.data);
    spec->g.data = NULL;
}

static void DestroyDsaCommParamsSpec(HcfDsaCommParamsSpec *spec)
{
    FreeDsaCommParamsSpec(spec);
    HcfFree(spec);
}

void DestroyDsaPubKeySpec(HcfDsaPubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeDsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    HcfFree(spec);
}

void DestroyDsaKeyPairSpec(HcfDsaKeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeDsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
    HcfFree(spec->sk.data);
    spec->sk.data = NULL;
    HcfFree(spec);
}

static void FreeEcFieldMem(HcfECField **field)
{
    HcfFree((*field)->fieldType);
    (*field)->fieldType = NULL;
    HcfFree(((HcfECFieldFp *)(*field))->p.data);
    ((HcfECFieldFp *)(*field))->p.data = NULL;
    HcfFree(*field);
    *field = NULL;
}

static void FreeEcPointMem(HcfPoint *point)
{
    HcfFree(point->x.data);
    point->x.data = NULL;
    HcfFree(point->y.data);
    point->y.data = NULL;
}

void FreeEccCommParamsSpec(HcfEccCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->base.algName);
    spec->base.algName = NULL;
    HcfFree(spec->a.data);
    spec->a.data = NULL;
    HcfFree(spec->b.data);
    spec->b.data = NULL;
    HcfFree(spec->n.data);
    spec->n.data = NULL;
    FreeEcFieldMem(&(spec->field));
    spec->field = NULL;
    FreeEcPointMem(&(spec->g));
}

static void DestroyEccCommParamsSpec(HcfEccCommParamsSpec *spec)
{
    FreeEccCommParamsSpec(spec);
    HcfFree(spec);
}

void DestroyEccPubKeySpec(HcfEccPubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeEccCommParamsSpec(&(spec->base));
    FreeEcPointMem(&(spec->pk));
    HcfFree(spec);
}

void DestroyEccPriKeySpec(HcfEccPriKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeEccCommParamsSpec(&(spec->base));
    (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
    HcfFree(spec->sk.data);
    spec->sk.data = NULL;
    HcfFree(spec);
}

void DestroyEccKeyPairSpec(HcfEccKeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeEccCommParamsSpec(&(spec->base));
    FreeEcPointMem(&(spec->pk));
    (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
    HcfFree(spec->sk.data);
    spec->sk.data = NULL;
    HcfFree(spec);
}

void FreeRsaCommParamsSpec(HcfRsaCommParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    HcfFree(spec->base.algName);
    spec->base.algName = NULL;
    HcfFree(spec->n.data);
    spec->n.data = NULL;
}

static void DestroyRsaCommParamsSpec(HcfRsaCommParamsSpec *spec)
{
    FreeRsaCommParamsSpec(spec);
    HcfFree(spec);
}

void DestroyRsaPubKeySpec(HcfRsaPubKeyParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeRsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    HcfFree(spec);
}

void DestroyRsaKeyPairSpec(HcfRsaKeyPairParamsSpec *spec)
{
    if (spec == NULL) {
        return;
    }
    FreeRsaCommParamsSpec(&(spec->base));
    HcfFree(spec->pk.data);
    spec->pk.data = NULL;
    (void)memset_s(spec->sk.data, spec->sk.len, 0, spec->sk.len);
    HcfFree(spec->sk.data);
    spec->sk.data = NULL;
    HcfFree(spec);
}

static void DestroyDsaParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            DestroyDsaCommParamsSpec((HcfDsaCommParamsSpec *)spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            DestroyDsaPubKeySpec((HcfDsaPubKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyDsaKeyPairSpec((HcfDsaKeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching DSA key params spec type.");
            break;
    }
}

static void DestroyEccParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            DestroyEccCommParamsSpec((HcfEccCommParamsSpec *)spec);
            break;
        case HCF_PRIVATE_KEY_SPEC:
            DestroyEccPriKeySpec((HcfEccPriKeyParamsSpec *)spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            DestroyEccPubKeySpec((HcfEccPubKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyEccKeyPairSpec((HcfEccKeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching ECC key params spec type.");
            break;
    }
}

static void DestroyRsaParamsSpec(HcfAsyKeyParamsSpec *spec)
{
    switch (spec->specType) {
        case HCF_COMMON_PARAMS_SPEC:
            DestroyRsaCommParamsSpec((HcfRsaCommParamsSpec *)spec);
            break;
        case HCF_PUBLIC_KEY_SPEC:
            DestroyRsaPubKeySpec((HcfRsaPubKeyParamsSpec *)spec);
            break;
        case HCF_KEY_PAIR_SPEC:
            DestroyRsaKeyPairSpec((HcfRsaKeyPairParamsSpec *)spec);
            break;
        default:
            LOGE("No matching RSA key params spec type.");
            break;
    }
}

void FreeAsyKeySpec(HcfAsyKeyParamsSpec *spec)
{
    if (spec == NULL || spec->algName == NULL) {
        return;
    }
    if (strcmp(spec->algName, ALG_NAME_DSA) == 0) {
        return DestroyDsaParamsSpec(spec);
    } else if (strcmp(spec->algName, ALG_NAME_ECC) == 0) {
        return DestroyEccParamsSpec(spec);
    } else if (strcmp(spec->algName, ALG_NAME_RSA) == 0) {
        return DestroyRsaParamsSpec(spec);
    } else {
        LOGE("No matching key params spec alg name.");
    }
}