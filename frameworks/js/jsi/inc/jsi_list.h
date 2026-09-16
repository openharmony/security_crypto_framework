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

#ifndef JSI_LIST_H
#define JSI_LIST_H


#include "jsi_api_common.h"

namespace OHOS {
namespace ACELite {
struct ListNode {
    struct ListNode *prev;
    struct ListNode *next;
};

typedef struct {
    LiteAlgType type;
    ListNode *objListHeader;
} ListInfo;

/*
 * IMPORTANT: listNode MUST remain the first member of ObjList. Never
 * place any other member before it.
 *
 * Why: LOS_DL_LIST_FOR_EACH_ENTRY_SAFE (in jsi_list.cpp, called by
 * ListDeleteObjNode and ListDestroy) terminates traversal by comparing
 * the item pointer back-computed via LOS_DL_LIST_ENTRY / container_of
 * against the list head. With listNode as the first member,
 * offsetof(ObjList, listNode) == 0, so LOS_DL_LIST_ENTRY(head, ObjList,
 * listNode) yields item == head; the termination condition holds and
 * the loop body is skipped on an empty list (and when the cursor wraps
 * back to the head).
 *
 * If listNode were not the first member, offsetof != 0 would make the
 * back-computed item differ from head, the termination would never
 * match, and the loop would be entered on an empty list - causing
 * illegal memory access (NULL deref / out-of-bounds read) on the
 * first iteration.
 */
typedef struct {
    ListNode listNode;  /* must be the first member - see above */
    uint32_t objAddr;
} ObjList;

void ListObjInit(LiteAlgType type);
HcfResult ListAddObjNode(LiteAlgType type, uint32_t addAddr);
void ListDeleteObjNode(LiteAlgType type, uint32_t deleteAddr);
void ListDestroy(LiteAlgType type);

}  // namespace ACELite
}  // namespace OHOS

#endif // JSI_LIST_H
