/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vector>
#include <string>
#include <unordered_map>
#include <ani.h>
#include <securec.h>
#include "log.h"
#include "mac.h"
#include "sym_key_generator.h"

namespace {
const std::string CRYPTO_FRAMEWORK_CLASS_NAME = "L@ohos/security/cryptoFramework/cryptoFramework;";
const std::string GENERATOR_CLASS_NAME = "L@ohos/security/cryptoFramework/cryptoFramework/SymKeyGeneratorInner;";
const std::string SYM_KEY_CLASS_NAME = "L@ohos/security/cryptoFramework/cryptoFramework/SymKeyInner;";
const std::string MAC_CLASS_NAME = "L@ohos/security/cryptoFramework/cryptoFramework/MacInner;";
const std::string DATA_BLOB_CLASS_NAME = "L@ohos/security/cryptoFramework/cryptoFramework/DataBlobInner;";

std::string GetStdString(ani_env *env, ani_string str)
{
    ani_size strSize;
    if (env->String_GetUTF8Size(str, &strSize)) {
        LOGE("get utf8 size failed");
        return "";
    }

    std::vector<char> buffer(strSize + 1);
    char *utf8Buffer = buffer.data();
    ani_size length = 0;
    if (env->String_GetUTF8(str, utf8Buffer, strSize + 1, &length) != ANI_OK) {
        LOGE("get utf8 string failed");
        return "";
    }

    utf8Buffer[length] = '\0';
    std::string content = std::string(utf8Buffer);
    return content;
}

bool GetUint8Array(ani_env *env, ani_object object, HcfBlob &blob)
{
    ani_ref buffer;
    if (env->Object_GetFieldByName_Ref(object, "buffer", &buffer) != ANI_OK) {
        LOGE("get buffer ref failed");
        return false;
    }

    uint8_t *data = nullptr;
    size_t length = 0;
    if (env->ArrayBuffer_GetInfo(reinterpret_cast<ani_arraybuffer>(buffer),
        reinterpret_cast<void **>(&data), &length) != ANI_OK) {
        LOGE("get arraybuffer info failed");
        return false;
    }

    blob.data = data;
    blob.len = length;
    return true;
}

template<typename... Args>
ani_object CreateAniObject(ani_env *env, std::string name, const char *signature, Args... args)
{
    ani_class cls;
    if (env->FindClass(name.c_str(), &cls) != ANI_OK) {
        LOGE("not found '%s'", name.c_str());
        return {};
    }

    ani_method ctor;
    if (env->Class_FindMethod(cls, "<ctor>", signature, &ctor) != ANI_OK) {
        LOGE("get ctor failed '%s'", name.c_str());
        return {};
    }

    ani_object obj = {};
    if (env->Object_New(cls, ctor, &obj, args...) != ANI_OK) {
        LOGE("create object failed '%s'", name.c_str());
        return obj;
    }

    LOGI("create object success '%s'", name.c_str());
    return obj;
}

ani_long GetLongValue(ani_env *env, ani_object object, std::string name)
{
    ani_long value;
    if (env->Object_GetFieldByName_Long(object, name.c_str(), &value) != ANI_OK) {
        LOGE("get generator object failed '%s'", name.c_str());
        return 0;
    }
    return value;
}
} // namespace

static ani_object CreateSymKeyGenerator([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object,
    ani_string str)
{
    HcfSymKeyGenerator *generator = nullptr;
    std::string algo = GetStdString(env, str);
    HcfResult ret = HcfSymKeyGeneratorCreate(algo.c_str(), &generator);
    if (ret != HCF_SUCCESS) {
        LOGE("create symkey generator failed");
        return {};
    }

    return CreateAniObject(env, GENERATOR_CLASS_NAME, nullptr, reinterpret_cast<ani_long>(generator));
}

static ani_object ConvertKeySync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_object data)
{
    ani_ref dataRef;
    if (env->Object_CallMethodByName_Ref(data, "<get>data", nullptr, &dataRef) != ANI_OK) {
        LOGE("get datablob failed");
        return {};
    }

    HcfBlob keyData = {};
    if (!GetUint8Array(env, reinterpret_cast<ani_object>(dataRef), keyData)) {
        LOGE("get key data failed");
        return {};
    }

    HcfSymKey *symKey = nullptr;
    ani_long context = GetLongValue(env, object, "generator");
    HcfSymKeyGenerator *generator = reinterpret_cast<HcfSymKeyGenerator *>(context);
    HcfResult ret = generator->convertSymKey(generator, &keyData, &symKey);
    if (ret != HCF_SUCCESS) {
        LOGE("convert symkey failed");
        return {};
    }

    return CreateAniObject(env, SYM_KEY_CLASS_NAME, nullptr, reinterpret_cast<ani_long>(symKey));
}

static ani_object CreateMac([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string str)
{
    HcfMac *macObj = nullptr;
    std::string algo = GetStdString(env, str);
    HcfMacParamsSpec params = { algo.c_str() };
    HcfResult ret = HcfMacCreate(&params, &macObj);
    if (ret != HCF_SUCCESS) {
        LOGE("create mac object failed");
        return {};
    }

    return CreateAniObject(env, MAC_CLASS_NAME, nullptr, reinterpret_cast<ani_long>(macObj));
}

static void InitSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_object key)
{
    ani_long context = GetLongValue(env, object, "macObj");
    HcfMac *macObj = reinterpret_cast<HcfMac *>(context);
    context = GetLongValue(env, key, "symKey");
    HcfSymKey *symKey = reinterpret_cast<HcfSymKey *>(context);
    HcfResult ret = macObj->init(macObj, symKey);
    if (ret != HCF_SUCCESS) {
        LOGE("init failed");
        return;
    }
    LOGI("init success");
}

static void UpdateSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_object input)
{
    ani_ref inputRef;
    if (env->Object_CallMethodByName_Ref(input, "<get>data", nullptr, &inputRef) != ANI_OK) {
        LOGE("get datablob failed");
        return;
    }

    HcfBlob inBlob = {};
    if (!GetUint8Array(env, reinterpret_cast<ani_object>(inputRef), inBlob)) {
        LOGE("get input data failed");
        return;
    }

    ani_long context = GetLongValue(env, object, "macObj");
    HcfMac *macObj = reinterpret_cast<HcfMac *>(context);
    HcfResult ret = macObj->update(macObj, &inBlob);
    if (ret != HCF_SUCCESS) {
        LOGE("update failed");
        return;
    }
    LOGI("update success");
}

static ani_object DoFinalSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object)
{
    ani_long context = GetLongValue(env, object, "macObj");
    HcfMac *macObj = reinterpret_cast<HcfMac *>(context);
    HcfBlob resBlob = { .data = nullptr, .len = 0 };
    HcfResult ret = macObj->doFinal(macObj, &resBlob);
    std::vector<uint8_t> result(resBlob.data, resBlob.data + resBlob.len);
    HcfBlobDataClearAndFree(&resBlob);
    if (ret != HCF_SUCCESS) {
        LOGE("dofinal failed");
        return {};
    }
    LOGI("dofinal success");

    ani_object out = CreateAniObject(env, "Lescompat/Uint8Array;", "I:V", result.size());
    HcfBlob outBlob = {};
    if (!GetUint8Array(env, out, outBlob)) {
        LOGE("get output data failed");
        return {};
    }

    if (memcpy_s(outBlob.data, outBlob.len, result.data(), result.size()) != EOK) {
        LOGE("memcpy_s failed");
        return {};
    }

    return CreateAniObject(env, DATA_BLOB_CLASS_NAME, nullptr, out);
}

static std::unordered_map<std::string, std::vector<ani_native_function>> entrys = {
    {
        CRYPTO_FRAMEWORK_CLASS_NAME,
        {
            ani_native_function {"createSymKeyGenerator", nullptr, reinterpret_cast<void *>(CreateSymKeyGenerator)},
            ani_native_function {"createMac", nullptr, reinterpret_cast<void *>(CreateMac)},
        }
    },
    {
        GENERATOR_CLASS_NAME,
        {
            ani_native_function {"convertKeySync", nullptr, reinterpret_cast<void *>(ConvertKeySync)},
        }
    },
    {
        MAC_CLASS_NAME,
        {
            ani_native_function {"initSync", nullptr, reinterpret_cast<void *>(InitSync)},
            ani_native_function {"updateSync", nullptr, reinterpret_cast<void *>(UpdateSync)},
            ani_native_function {"doFinalSync", nullptr, reinterpret_cast<void *>(DoFinalSync)},
        }
    },
};

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        LOGE("unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }

    for (const auto &entry : entrys) {
        const char *className = entry.first.c_str();
        std::vector<ani_native_function> methods = entry.second;
        ani_class cls;
        if (env->FindClass(className, &cls) != ANI_OK) {
            LOGE("not found '%s'", className);
            return ANI_ERROR;
        }
        if (env->Class_BindNativeMethods(cls, methods.data(), methods.size()) != ANI_OK) {
            LOGE("cannot bind native methods to '%s'", className);
            return ANI_ERROR;
        };
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}

ANI_EXPORT ani_status ANI_Destructor(ani_vm *vm)
{
    return ANI_OK;
}
