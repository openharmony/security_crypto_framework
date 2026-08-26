/*
* Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef HCF_PARCEL_H
#define HCF_PARCEL_H

#include <stdint.h>
#include <stdbool.h>
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HCF_PARCEL_DEFAULT_LENGTH 0
#define HCF_PARCEL_DEFAULT_ALLOC_UNIT 0

    typedef struct {
        char *data;
        unsigned int beginPos;
        unsigned int endPos;
        unsigned int length;
        unsigned int allocUnit;
    } HcfParcel;

    HcfParcel HcfCreateParcel(uint32_t size, uint32_t allocUnit);
    void HcfDeleteParcel(HcfParcel *parcel);
    bool HcfParcelWrite(HcfParcel *parcel, const void *src, uint32_t dataSize);
    uint32_t HcfGetParcelDataSize(const HcfParcel *parcel);
    const char *HcfGetParcelData(const HcfParcel *parcel);

    bool HcfParcelWriteInt8(HcfParcel *parcel, char src);
    bool HcfParcelPopBack(HcfParcel *parcel, uint32_t size);

#ifdef __cplusplus
}
#endif
#endif
