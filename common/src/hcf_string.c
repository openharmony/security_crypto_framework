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

#include <string.h>
#include "hcf_string.h"
#include "log.h"

const uint32_t HCF_STRING_ALLOC_SIZE = 10;
const uint32_t HCF_STRING_END_CHAR_LENGTH = 1;
const char HCF_STRING_END_CHAR = '\0';
#define MAX_INT 0x7FFFFFFF
#define MAX_UINT 0xFFFFFFFF

/*
* Append string pointer
* Notice: It will add '\0' automatically.
* @param self: self pointer.
* @param str: string pointer.
* @return true (ok), false (error)
*/
bool HcfStringAppendPointer(HcfString *self, const char *str)
{
    if (self != NULL && str != NULL) {
        HcfParcelPopBack(&self->parcel, HCF_STRING_END_CHAR_LENGTH);
        return HcfParcelWrite(&self->parcel, (void *)str, strlen(str) + 1);
    }
    LOGE("Self or str is null");
    return false;
}

/*
* Assign a value to the HcfString
* Notice: It will add '\0' automatically.
* @param self: self pointer.
* @param str: assign value of string pointer.
* @return true (ok), false (error)
*/
bool HcfStringSetPointer(HcfString *self, const char *str)
{
    if (self != NULL) {
        HcfDeleteParcel(&self->parcel);
        return HcfStringAppendPointer(self, str);
    }
    LOGE("Self is null when setting string pointer");
    return false;
}

/*
* Assign a value to the HcfString with fixed length
* Notice: It will add '\0' automatically.
* @param self: self pointer.
* @param str: assign value of string pointer.
* @param len: the length of string.
* @return true (ok), false (error)
*/
bool HcfStringSetPointerWithLength(HcfString* self, const char *str, uint32_t len)
{
    if (self == NULL || str == NULL) {
        LOGE("Self or str is null");
        return false;
    }
    uint32_t strLen = strlen(str);
    if (strLen < len) {
        LOGD("String length is less than requested length");
        return false;
    }
    HcfDeleteParcel(&self->parcel);
    if (len > 0) {
        if (false == HcfParcelWrite(&self->parcel, str, len)) {
            LOGE("Failed to write string data to parcel");
            return false;
        }
    }
    return HcfParcelWriteInt8(&self->parcel, (uint32_t)HCF_STRING_END_CHAR);
}

/*
* Get the string pointer data
* @param self: self pointer.
* @return the pointer data of the string
*/
const char *HcfStringGet(const HcfString *self)
{
    if (self == NULL) {
        LOGE("Self is null when getting string");
        return NULL;
    }

    return HcfGetParcelData(&self->parcel);
}

/*
* Get the length of the string
* @param self: self pointer.
* @return the length of the string
*/
uint32_t HcfStringLength(const HcfString *self)
{
    if (self == NULL) {
        return 0;
    } else {
        uint32_t length = HcfGetParcelDataSize(&self->parcel);
        if (length > 0) {
            return length - HCF_STRING_END_CHAR_LENGTH;
        } else {
            return 0;
        }
    }
}

/*
* Find a char from string
* @param self: self pointer.
* @param c: the char you want find
* @param begin: the position find from
* @return the position of the char
*/
int HcfStringFind(const HcfString *self, char c, uint32_t begin)
{
    if (self == NULL) {
        LOGE("Self is null when finding char in string");
        return -1;
    }
    uint32_t p = begin;
    uint32_t strLen = HcfStringLength(self);
    if (strLen >= MAX_INT) {
        LOGE("String length exceeds MAX_INT");
        return -1;
    }

    const char* curChar = HcfStringGet(self);
    if (curChar == NULL) {
        LOGE("Failed to get string data for char search");
        return -1;
    }

    while (p < strLen) {
        if (*(curChar + p) == c) {
            return p;
        }
        ++p;
    }
    LOGD("Char not found in string");
    return -1;
}

/*
* Get sub string from a string.
* @param self: self pointer.
* @param begin: the begin position of the sub string.
* @param len: the length of the sub string.
* @param dst: the string pointer which saved the sub string content.
* @return the operation result.
*/
bool HcfStringSubString(const HcfString *self, uint32_t begin, uint32_t len, HcfString* dst)
{
    if (self == NULL || dst == NULL) {
        LOGE("Self or dst is null");
        return false;
    }
    if (MAX_UINT - len <= begin) {
        LOGE("Overflow detected in substring operation");
        return false;
    }
    const char* beingPointer = HcfStringGet(self) + begin;
    return HcfStringSetPointerWithLength(dst, beingPointer, len);
}

/*
* Compare the string with another string.
* @param self: self pointer.
* @param dst: the pointer of another string.
* @return the compare result.
*  -1: self is smaller than dst
*   0: self is equal with dst
*   1: self is bigger than dst
*/
int HcfStringCompare(const HcfString *self, const char* dst)
{
    if (self == NULL || dst == NULL) {
        LOGE("Self or dst is null");
        return 0;
    }

    const char* src = HcfStringGet(self);
    if (src == NULL) {
        LOGE("Failed to get string data for comparison");
        return -1;
    }

    do {
        if ((*src) > (*dst)) {
            return 1;
        } else if ((*src) < (*dst)) {
            return -1;
        } else {
            if ((*src) == '\0') {
                return 0;
            }
            ++src;
            ++dst;
        }
    } while (true);
    // should never be here
    return 0;
}

/*
* Create a string.
* Notice: You should delete_string when you don't need the string anymore.
* @return return the created string.
*/
HcfString HcfCreateString(void)
{
    HcfString str;
    str.parcel = HcfCreateParcel(0, HCF_STRING_ALLOC_SIZE);
    HcfParcelWriteInt8(&str.parcel, HCF_STRING_END_CHAR);
    return str;
}

/*
* Delete a string. In fact it will not destroy the string,
* but only free the allocate memory of the string and reset the member's value
* of the string.
* You can continue to use the string if you want.
* Notice: You should delete the string when you don't need it any more to avoid memory leak.
* @param str: The string you want to delete.
*/
void HcfDeleteString(HcfString *str)
{
    if (str != NULL) {
        HcfDeleteParcel(&str->parcel);
    }
}
