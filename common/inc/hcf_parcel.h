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

#ifndef HC_PARCEL_H
#define HC_PARCEL_H

#include <stdint.h>
#include <stdbool.h>
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PARCEL_DEFAULT_LENGTH 0
#define PARCEL_DEFAULT_ALLOC_UNIT 0

    typedef struct {
        char *data;
        unsigned int beginPos;
        unsigned int endPos;
        unsigned int length;
        unsigned int allocUnit;
    } HcParcel;

    HcParcel CreateParcel(uint32_t size, uint32_t allocUnit);
    void DeleteParcel(HcParcel *parcel);
    void ClearParcel(HcParcel *parcel);
    void ResetParcel(HcParcel *parcel, uint32_t size, uint32_t allocUnit);
    bool ParcelReadWithoutPopData(HcParcel *parcel, void *dst, uint32_t dataSize);
    bool ParcelRead(HcParcel *parcel, void *dst, uint32_t dataSize);
    bool ParcelWrite(HcParcel *parcel, const void *src, uint32_t dataSize);
    bool ParcelReadRevert(HcParcel *parcel, void *dst, uint32_t dataSize);
    bool ParcelWriteRevert(HcParcel *parcel, const void *src, uint32_t dataSize);
    uint32_t GetParcelDataSize(const HcParcel *parcel);
    const char *GetParcelData(const HcParcel *parcel);
    const char* GetParcelLastChar(const HcParcel *parcel);

    bool ParcelReadInt32(HcParcel *parcel, int *dst);
    bool ParcelReadUint32(HcParcel *parcel, uint32_t *dst);
    bool ParcelReadInt16(HcParcel *parcel, short *dst);
    bool ParcelReadUint16(HcParcel *parcel, uint16_t *dst);
    bool ParcelReadInt8(HcParcel *parcel, char *dst);
    bool ParcelReadUint8(HcParcel *parcel, uint8_t *dst);
    bool ParcelReadUint64(HcParcel *parcel, uint64_t *dst);
    bool ParcelReadInt64(HcParcel *parcel, int64_t *dst);
    bool ParcelWriteInt32(HcParcel *parcel, int src);
    bool ParcelWriteUint32(HcParcel *parcel, uint32_t src);
    bool ParcelWriteInt16(HcParcel *parcel, short src);
    bool ParcelWriteUint16(HcParcel *parcel, uint16_t src);
    bool ParcelWriteInt8(HcParcel *parcel, char src);
    bool ParcelWriteUint8(HcParcel *parcel, uint8_t src);
    bool ParcelWriteUint64(HcParcel *parcel, uint64_t src);
    bool ParcelWriteInt64(HcParcel *parcel, int64_t src);
    bool ParcelWriteString(HcParcel *parcel, const char *str);
    bool ParcelReadString(HcParcel *parcel, char **str);
    bool ParcelReadParcel(HcParcel *src, HcParcel *dst, uint32_t size, bool copy);
    bool ParcelCopy(HcParcel *src, HcParcel *dst);

    bool ParcelReadInt32Revert(HcParcel *parcel, int32_t *dst);
    bool ParcelReadUint32Revert(HcParcel *parcel, uint32_t *dst);
    bool ParcelReadInt16Revert(HcParcel *parcel, short *dst);
    bool ParcelReadUint16Revert(HcParcel *parcel, uint16_t *dst);
    bool ParcelReadInt8Revert(HcParcel *parcel, char *dst);
    bool ParcelReadUint8Revert(HcParcel *parcel, uint8_t *dst);
    bool ParcelReadUint64Revert(HcParcel *parcel, uint64_t *dst);
    bool ParcelReadInt64Revert(HcParcel *parcel, int64_t *dst);
    bool ParcelWriteInt32Revert(HcParcel *parcel, int src);
    bool ParcelWriteUint32Revert(HcParcel *parcel, uint32_t src);
    bool ParcelWriteInt16Revert(HcParcel *parcel, short src);
    bool ParcelWriteUint16Revert(HcParcel *parcel, uint16_t src);
    bool ParcelWriteInt8Revert(HcParcel *parcel, char src);
    bool ParcelWriteUint8Revert(HcParcel *parcel, uint8_t src);
    bool ParcelWriteUint64Revert(HcParcel *parcel, uint64_t src);
    bool ParcelWriteInt64Revert(HcParcel *parcel, int64_t src);

    void DataRevert(void *data, uint32_t length);
    bool ParcelPopBack(HcParcel *parcel, uint32_t size);
    bool ParcelPopFront(HcParcel *parcel, uint32_t size);

#ifdef __cplusplus
}
#endif
#endif
