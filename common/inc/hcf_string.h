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

#ifndef HCF_STRING_H
#define HCF_STRING_H

#include "hcf_parcel.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct HcfString {
        HcfParcel parcel;
    } HcfString;

    /*
    * Append string pointer
    * Notice: It will add '\0' automatically.
    * @param self: self pointer.
    * @param str: string pointer.
    * @return true (ok), false (error)
    */
    bool HcfStringAppendPointer(HcfString *self, const char *str);

    /*
    * Assign a value to the HcfString
    * Notice: It will add '\0' automatically.
    * @param self: self pointer.
    * @param str: assign value of string pointer.
    * @return true (ok), false (error)
    */
    bool HcfStringSetPointer(HcfString *self, const char *str);

    /*
    * Assign a value to the HcfString with fixed length
    * Notice: It will add '\0' automatically.
    * @param self: self pointer.
    * @param str: assign value of string pointer.
    * @param len: the length of string.
    * @return true (ok), false (error)
    */
    bool HcfStringSetPointerWithLength(HcfString* self, const char *str, uint32_t len);

    /*
    * Get the string pointer data
    * @param self: self pointer.
    * @return the pointer data of the string
    */
    const char* HcfStringGet(const HcfString *self);

    /*
    * Get the length of the string
    * @param self: self pointer.
    * @return the length of the string
    */
    uint32_t HcfStringLength(const HcfString *self);

    /*
    * Find a char from string
    * @param self: self pointer.
    * @param c: the char you want find
    * @param begin: the position find from
    * @return the position of the char
    */
    int HcfStringFind(const HcfString *self, char c, uint32_t begin);

    /*
    * Get sub string from a string.
    * @param self: self pointer.
    * @param begin: the begin position of the sub string.
    * @param len: the length of the sub string.
    * @param dst: the string pointer which saved the sub string content.
    * @return the operation result.
    */
    bool HcfStringSubString(const HcfString *self, uint32_t begin, uint32_t len, HcfString* dst);

    /*
    * Compare the string with another string.
    * @param self: self pointer.
    * @param dst: the pointer of another string.
    * @return the compare result.
    *  -1: self is smaller than dst
    *   0: self is equal with dst
    *   1: self is bigger than dst
    */
    int HcfStringCompare(const HcfString *self, const char* dst);

    /*
    * Create a string.
    * Notice: You should delete string when you don't need the string anymore.
    * @return the created string.
    */
    HcfString HcfCreateString(void);

    /*
    * Delete a string. In fact it will not destroy the string,
    * but only free the allocated memory of the string and reset the member's value
    * of the string. You can continue to use the string if you want.
    * Notice: You should delete the string when you don't need it any more to avoid memory leak.
    * @param str: The string you want to delete.
    */
    void HcfDeleteString(HcfString *str);

#ifdef __cplusplus
}
#endif
#endif
