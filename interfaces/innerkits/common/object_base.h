/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef HCF_OBJECT_BASE_H
#define HCF_OBJECT_BASE_H

typedef struct HcfObjectBase HcfObjectBase;

struct HcfObjectBase {
    const char *(*getClass)(void);
    void (*destroy)(HcfObjectBase *self);
};

#define OH_HCF_OBJ_DESTROY(base) \
    if ((base) != NULL) { \
        ((HcfObjectBase *)(base))->destroy((HcfObjectBase *)(base)); \
    }

#endif // HCF_OBJECT_BASE_H
