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

#include "hcf_parcel.h"
#include "securec.h"
#include "memory.h"

const int PARCEL_DEFAULT_INCREASE_STEP = 16;
const uint32_t PARCEL_UINT_MAX = 0xffffffffU;
const int HALF_LEN = 2;

HcParcel CreateParcel(uint32_t size, uint32_t allocUnit)
{
    HcParcel parcel;
    (void)memset_s(&parcel, sizeof(parcel), 0, sizeof(parcel));
    parcel.allocUnit = allocUnit;
    if (parcel.allocUnit == 0) {
        parcel.allocUnit = PARCEL_DEFAULT_INCREASE_STEP;
    }
    if (size > 0) {
        parcel.data = (char *)HcfMalloc(size, 0);
        if (parcel.data != NULL) {
            parcel.length = size;
        }
    }
    return parcel;
}

void DeleteParcel(HcParcel *parcel)
{
    if (parcel == NULL) {
        return;
    }

    if (parcel->data != NULL) {
        HcfFree(parcel->data);
        parcel->data = 0;
    }
    parcel->length = 0;
    parcel->beginPos = 0;
    parcel->endPos = 0;
}

void ClearParcel(HcParcel *parcel)
{
    if (parcel != NULL) {
        parcel->beginPos = 0;
        parcel->endPos = 0;
    }
}

void ResetParcel(HcParcel *parcel, uint32_t size, uint32_t allocUnit)
{
    if (parcel != NULL) {
        DeleteParcel(parcel);
        HcParcel newParcel = CreateParcel(size, allocUnit);
        (void)memcpy_s(parcel, sizeof(HcParcel), &newParcel, sizeof(HcParcel));
    }
}

uint32_t GetParcelDataSize(const HcParcel *parcel)
{
    if (parcel == NULL) {
        return 0;
    }
    if (parcel->endPos >= parcel->beginPos) {
        return parcel->endPos - parcel->beginPos;
    }
    return 0;
}

const char *GetParcelData(const HcParcel *parcel)
{
    if (parcel == NULL) {
        return NULL;
    }
    return parcel->data + parcel->beginPos;
}

const char *GetParcelLastChar(const HcParcel *parcel)
{
    if (parcel == NULL || GetParcelDataSize(parcel) == 0) {
        return NULL;
    }
    return parcel->data + parcel->endPos - 1;
}

bool ParcelReadWithoutPopData(HcParcel *parcel, void *dst, uint32_t dataSize)
{
#ifdef IS_BIG_ENDIAN
    bool ret = ParcelReadRevert(parcel, dst, dataSize);
#else
    bool ret = ParcelRead(parcel, dst, dataSize);
#endif
    if (ret == true) {
        parcel->beginPos -= dataSize;
    }
    return ret;
}

bool ParcelRead(HcParcel *parcel, void *dst, uint32_t dataSize)
{
    errno_t rc;
    if (parcel == NULL || dst == NULL || dataSize == 0) {
        return false;
    }
    if (parcel->beginPos > PARCEL_UINT_MAX - dataSize) {
        return false;
    }
    if (parcel->beginPos + dataSize > parcel->endPos) {
        return false;
    }
    rc = memmove_s(dst, dataSize, parcel->data + parcel->beginPos, dataSize);
    if (rc != EOK) {
        return false;
    }
    parcel->beginPos += dataSize;
    return true;
}

bool ParcelReadRevert(HcParcel *parcel, void *dst, uint32_t dataSize)
{
    if (ParcelRead(parcel, dst, dataSize)) {
        DataRevert(dst, dataSize);
        return true;
    } else {
        return false;
    }
}

bool ParcelWriteRevert(HcParcel *parcel, const void *src, uint32_t dataSize)
{
    errno_t rc;
    void *srcCopy = HcfMalloc(dataSize, 0);
    if (srcCopy == NULL) {
        return false;
    }
    rc = memmove_s(srcCopy, dataSize, src, dataSize);
    if (rc != EOK) {
        HcfFree(srcCopy);
        return false;
    }
    DataRevert(srcCopy, dataSize);
    bool ret = ParcelWrite(parcel, srcCopy, dataSize);
    HcfFree(srcCopy);
    return ret;
}

bool ParcelReadInt32(HcParcel *parcel, int *dst)
{
    return ParcelRead(parcel, dst, sizeof(int));
}

bool ParcelReadUint32(HcParcel *parcel, uint32_t *dst)
{
    return ParcelRead(parcel, dst, sizeof(uint32_t));
}

bool ParcelReadInt16(HcParcel *parcel, short *dst)
{
    return ParcelRead(parcel, dst, sizeof(short));
}

bool ParcelReadUint16(HcParcel *parcel, uint16_t *dst)
{
    return ParcelRead(parcel, dst, sizeof(uint16_t));
}

bool ParcelReadInt8(HcParcel *parcel, char *dst)
{
    return ParcelRead(parcel, dst, sizeof(char));
}

bool ParcelReadUint8(HcParcel *parcel, uint8_t *dst)
{
    return ParcelRead(parcel, dst, sizeof(uint8_t));
}

bool ParcelReadUint64(HcParcel *parcel, uint64_t *dst)
{
    return ParcelRead(parcel, dst, sizeof(uint64_t));
}

bool ParcelReadInt64(HcParcel *parcel, int64_t *dst)
{
    return ParcelRead(parcel, dst, sizeof(int64_t));
}

static bool ParcelRealloc(HcParcel *parcel, uint32_t size)
{
    if (parcel->length >= size) {
        return false;
    }
    char *newData = (char *)HcfMalloc(size, 0);
    if (newData == NULL) {
        return false;
    }
    if (memcpy_s(newData, size, parcel->data, parcel->length) != EOK) {
        HcfFree(newData);
        return false;
    }
    HcfFree(parcel->data);
    parcel->data = newData;
    parcel->length = size;
    return true;
}

static bool ParcelIncrease(HcParcel *parcel, uint32_t size)
{
    if (parcel == NULL || size == 0) {
        return false;
    }
    if (parcel->data == NULL) {
        if (parcel->length != 0) {
            return false;
        }
        *parcel = CreateParcel(size, parcel->allocUnit);
        if (parcel->data == NULL) {
            return false;
        } else {
            return true;
        }
    } else {
        return ParcelRealloc(parcel, size);
    }
}

static void ParcelRecycle(HcParcel *parcel)
{
    if (parcel == NULL) {
        return;
    }
    if (parcel->data == NULL || parcel->beginPos < parcel->allocUnit) {
        return;
    }

    uint32_t contentSize = parcel->endPos - parcel->beginPos;
    if (contentSize > 0) {
        if (memmove_s(parcel->data, parcel->endPos - parcel->beginPos,
            parcel->data + parcel->beginPos, parcel->endPos - parcel->beginPos) != EOK) {
        }
    }
    parcel->beginPos = 0;
    parcel->endPos = contentSize;
}

static uint32_t GetParcelIncreaseSize(HcParcel *parcel, uint32_t newSize)
{
    if (parcel == NULL || parcel->allocUnit == 0) {
        return 0;
    }
    if (newSize % parcel->allocUnit) {
        return (newSize / parcel->allocUnit + 1) * parcel->allocUnit;
    } else {
        return (newSize / parcel->allocUnit) * parcel->allocUnit;
    }
}

bool ParcelWrite(HcParcel *parcel, const void *src, uint32_t dataSize)
{
    errno_t rc;
    if (parcel == NULL || src == NULL || dataSize == 0) {
        return false;
    }
    if (parcel->endPos > PARCEL_UINT_MAX - dataSize) {
        return false;
    }
    if (parcel->endPos + dataSize > parcel->length) {
        ParcelRecycle(parcel);
        if (parcel->endPos + dataSize > parcel->length) {
            uint32_t newSize = GetParcelIncreaseSize(parcel, parcel->endPos + dataSize);
            if (!ParcelIncrease(parcel, newSize)) {
                return false;
            }
        }
    }
    rc = memmove_s(parcel->data + parcel->endPos, dataSize, src, dataSize);
    if (rc != EOK) {
        return false;
    }
    parcel->endPos += dataSize;
    return true;
}

bool ParcelWriteInt32(HcParcel *parcel, int src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelWriteUint32(HcParcel *parcel, uint32_t src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelWriteInt16(HcParcel *parcel, short src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelWriteUint16(HcParcel *parcel, uint16_t src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelWriteInt8(HcParcel *parcel, char src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelWriteUint8(HcParcel *parcel, uint8_t src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelWriteUint64(HcParcel *parcel, uint64_t src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelWriteInt64(HcParcel *parcel, int64_t src)
{
    return ParcelWrite(parcel, &src, sizeof(src));
}

bool ParcelReadParcel(HcParcel *src, HcParcel *dst, uint32_t size, bool copy)
{
    if (src == NULL || dst == NULL) {
        return false;
    }
    if (GetParcelDataSize(src) < size) {
        return false;
    }
    if (!ParcelWrite(dst, (void *)GetParcelData(src), size)) {
        return false;
    }

    if (!copy) {
        src->beginPos += size;
    }
    return true;
}

bool ParcelCopy(HcParcel *src, HcParcel *dst)
{
    if (src == NULL || dst == NULL) {
        return false;
    }
    if (GetParcelDataSize(src) == 0) {
        return true;
    }
    return ParcelReadParcel(src, dst, GetParcelDataSize(src), true);
}

void DataRevert(void *data, uint32_t length)
{
    if (data != NULL) {
        uint8_t *pc = (uint8_t *)data;
        uint32_t i = 0;
        for (; i < length / HALF_LEN; ++i) { /* half of the length */
                                      /* swap p[i] and p[length-i-1] */
            pc[i] ^= pc[length - i - 1];
            pc[length - i - 1] ^= pc[i];
            pc[i] ^= pc[length - i - 1];
        }
    }
}

bool ParcelReadInt32Revert(HcParcel *parcel, int32_t *dst)
{
    bool ret = ParcelRead(parcel, dst, sizeof(int));
    if (ret) {
        DataRevert(dst, sizeof(int));
    }
    return ret;
}

bool ParcelReadUint32Revert(HcParcel *parcel, uint32_t *dst)
{
    bool ret = ParcelRead(parcel, dst, sizeof(uint32_t));
    if (ret) {
        DataRevert(dst, sizeof(uint32_t));
    }
    return ret;
}

bool ParcelReadInt16Revert(HcParcel *parcel, short *dst)
{
    bool ret = ParcelRead(parcel, dst, sizeof(short));
    if (ret) {
        DataRevert(dst, sizeof(short));
    }
    return ret;
}

bool ParcelReadUint16Revert(HcParcel *parcel, uint16_t *dst)
{
    if (parcel == NULL || dst == NULL) {
        return false;
    }
    bool ret = ParcelRead(parcel, dst, sizeof(uint16_t));
    if (ret) {
        DataRevert(dst, sizeof(uint16_t));
    }
    return ret;
}

bool ParcelReadInt8Revert(HcParcel *parcel, char *dst)
{
    return ParcelRead(parcel, dst, sizeof(char));
}

bool ParcelReadUint8Revert(HcParcel *parcel, uint8_t *dst)
{
    return ParcelRead(parcel, dst, sizeof(uint8_t));
}

bool ParcelReadUint64Revert(HcParcel *parcel, uint64_t *dst)
{
    bool ret = ParcelRead(parcel, dst, sizeof(uint64_t));
    if (ret) {
        DataRevert(dst, sizeof(uint64_t));
    }
    return ret;
}

bool ParcelReadInt64Revert(HcParcel *parcel, int64_t *dst)
{
    bool ret = ParcelRead(parcel, dst, sizeof(int64_t));
    if (ret) {
        DataRevert(dst, sizeof(int64_t));
    }
    return ret;
}

bool ParcelWriteInt32Revert(HcParcel *parcel, int src)
{
    DataRevert(&src, sizeof(src));
    return ParcelWriteInt32(parcel, src);
}

bool ParcelWriteUint32Revert(HcParcel *parcel, uint32_t src)
{
    DataRevert(&src, sizeof(src));
    return ParcelWriteUint32(parcel, src);
}

bool ParcelWriteInt16Revert(HcParcel *parcel, short src)
{
    DataRevert(&src, sizeof(src));
    return ParcelWriteInt16(parcel, src);
}

bool ParcelWriteUint16Revert(HcParcel *parcel, uint16_t src)
{
    DataRevert(&src, sizeof(src));
    return ParcelWriteUint16(parcel, src);
}

bool ParcelWriteInt8Revert(HcParcel *parcel, char src)
{
    return ParcelWriteInt8(parcel, src);
}

bool ParcelWriteUint8Revert(HcParcel *parcel, uint8_t src)
{
    return ParcelWriteUint8(parcel, src);
}

bool ParcelWriteUint64Revert(HcParcel *parcel, uint64_t src)
{
    DataRevert(&src, sizeof(src));
    return ParcelWriteUint64(parcel, src);
}

bool ParcelWriteInt64Revert(HcParcel *parcel, int64_t src)
{
    DataRevert(&src, sizeof(src));
    return ParcelWriteInt64(parcel, src);
}

bool ParcelPopBack(HcParcel *parcel, uint32_t size)
{
    if (parcel != NULL && size > 0 && GetParcelDataSize(parcel) >= size) {
        parcel->endPos -= size;
        return true;
    }
    return false;
}

bool ParcelPopFront(HcParcel *parcel, uint32_t size)
{
    if ((parcel != NULL) && (size > 0) && (GetParcelDataSize(parcel) >= size)) {
        parcel->beginPos += size;
        return true;
    }
    return false;
}
