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

#include "jsi_list.h"
#include "memory.h"
#define CRYPTO_OFFSET_OF(type, member) /* NOLINT(G.PRE.02-CPP)*/ \
    ((size_t)(&(((type *)0)->member)))
#define CRYPTO_CONTAINER_OF(ptr, type, member) /* NOLINT(G.PRE.02-CPP)*/ \
    ((type *)((char*)(ptr) - CRYPTO_OFFSET_OF(type, member)))

/* Safe traversal macro, replacement for LOS_DL_LIST_FOR_EACH_ENTRY_SAFE
 * item:      Pointer to the business structure
 * itemNext:  Pre-store the next node
 * head:      ListNode* Head of the linked list
 * type:      Business structure type (ObjList)
 * member:    Name of the embedded linked list member (listNode)
 * Relies on ObjList::listNode must be the first member; otherwise empty-list traversal is unsafe.
 */
#define LIST_FOR_EACH_ENTRY_SAFE(item, itemNext, head, type, member) /* NOLINT(G.PRE.02-CPP)*/ \
    for ((item) = CRYPTO_CONTAINER_OF(((head)->next), type, member),              \
         (itemNext) = CRYPTO_CONTAINER_OF((item)->member.next, type, member);     \
         (&((item)->member)) != (head);                                         \
         (item) = (itemNext),                                                   \
         (itemNext) = CRYPTO_CONTAINER_OF((item)->member.next, type, member))

namespace OHOS {
namespace ACELite {
static ListNode g_mdObjListHeader = { .prev = nullptr, .next = nullptr };
static ListNode g_randObjListHeader = { .prev = nullptr, .next = nullptr };
static ListNode  g_symKeyObjListHeader = { .prev = nullptr, .next = nullptr };
static ListNode  g_cipherObjListHeader = { .prev = nullptr, .next = nullptr };
static ListNode  g_macObjListHeader = { .prev = nullptr, .next = nullptr };

static inline void ListInit(ListNode *node)
{
    node->next = node;
    node->prev = node;
}

static inline void ListAdd(ListNode *newNode, ListNode *head)
{
    newNode->next = head->next;
    newNode->prev = head;
    head->next->prev = newNode;
    head->next = newNode;
}

static inline void ListDelete(ListNode *node)
{
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = nullptr;
    node->prev = nullptr;
}

ListInfo g_listMap[] = {
    { JSI_ALG_MD, &g_mdObjListHeader },
    { JSI_ALG_RAND, &g_randObjListHeader },
    { JSI_ALG_SYM_KEY, &g_symKeyObjListHeader },
    { JSI_ALG_CIPHER, &g_cipherObjListHeader },
    { JSI_ALG_MAC, &g_macObjListHeader },
};

ListNode *GetListHeader(LiteAlgType type)
{
    for (uint32_t index = 0; index < sizeof(g_listMap) / sizeof(g_listMap[0]); index++) {
        if (type == g_listMap[index].type) {
            return g_listMap[index].objListHeader;
        }
    }

    return nullptr;
}

void ListObjInit(LiteAlgType type)
{
    ListNode *header = GetListHeader(type);
    if (header != nullptr) {
        ListInit(header);
    }
}

HcfResult ListAddObjNode(LiteAlgType type, uint32_t addAddr)
{
    ListNode *header = GetListHeader(type);
    if (header == nullptr) {
        return HCF_INVALID_PARAMS;
    }
    ObjList *obj = static_cast<ObjList *>(HcfMalloc(sizeof(ObjList), 0));
    if (obj == nullptr) {
        return HCF_ERR_MALLOC;
    }
    obj->objAddr = addAddr;

    if (header->next == nullptr) {
        ListInit(header);
    }
    ListAdd(&(obj->listNode), header);
    return HCF_SUCCESS;
}

void ListDeleteObjNode(LiteAlgType type, uint32_t deleteAddr)
{
    ObjList *obj = nullptr;
    ObjList *objNext = nullptr;
    ListNode *header = GetListHeader(type);
    if (header == nullptr || header->next == nullptr) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(obj, objNext, header, ObjList, listNode) {
        if (obj == nullptr) {
            continue;
        }
        if ((obj->objAddr != 0) && (obj->objAddr == deleteAddr)) {
            uint32_t tempAddr = obj->objAddr;
            ListDelete(&(obj->listNode));
            HcfObjDestroy(reinterpret_cast<void *>(tempAddr));
            obj->objAddr = 0;
            HcfFree(obj);
            obj = nullptr;
            break;
        }
    }
}

void ListDestroy(LiteAlgType type)
{
    ObjList *obj = nullptr;
    ObjList *objNext = nullptr;
    ListNode *header = GetListHeader(type);
    if (header == nullptr || header->next == nullptr) {
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(obj, objNext, header, ObjList, listNode) {
        if (obj == nullptr) {
            continue;
        }
        uint32_t tempAddr = obj->objAddr;
        ListDelete(&(obj->listNode));
        HcfObjDestroy(reinterpret_cast<void *>(tempAddr));
        HcfFree(obj);
    }
}

}  // ACELite
}  // OHOS
