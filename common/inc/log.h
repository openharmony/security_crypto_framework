/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_LOG_H
#define HCF_LOG_H

#ifdef HILOG_ENABLE

#include "hilog/log.h"

#undef LOG_TAG
#define LOG_TAG "HCF"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002F0A /* Security subsystem's domain id */

#define LOGD(fmt, ...) HILOG_DEBUG(LOG_CORE, "[%{public}s] " fmt, __func__, ##__VA_ARGS__)
#define LOGI(fmt, ...) HILOG_INFO(LOG_CORE, "[%{public}s] " fmt, __func__, ##__VA_ARGS__)
#define LOGW(fmt, ...) HILOG_WARN(LOG_CORE, "[%{public}s] " fmt, __func__, ##__VA_ARGS__)
#define LOGE(fmt, ...) HILOG_DEBUG(LOG_CORE, "[%{public}s] " fmt, __func__, ##__VA_ARGS__)

#else

#include <stdio.h>

#define LOGD(fmt, ...) printf("[HCF][D][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGI(fmt, ...) printf("[HCF][I][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[HCF][W][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[HCF][E][%s]: " fmt "\n", __FUNCTION__, ##__VA_ARGS__)

#endif
#endif
