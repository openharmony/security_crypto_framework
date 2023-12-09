/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <cstring>

#include "asy_key_generator.h"
#include "blob.h"
#include "dh_key_util.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "dh_asy_key_generator_openssl.h"
#include "detailed_dh_key_params.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "detailed_alg_25519_key_params.h"
#include "dh_common_param_spec_generator_openssl.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
constexpr int SKLEN_DH128 = 128;
constexpr int SKLEN_DH223 = 223;
constexpr int SKLEN_DH255 = 255;
constexpr int SKLEN_DH303 = 303;
constexpr int SKLEN_DH351 = 351;
constexpr int SKLEN_DH399 = 399;
constexpr int SKLEN_DH1024 = 1024;
constexpr int SKLEN_EQZERO = 0;
constexpr int PLEN_DH511 = 511;
constexpr int PLEN_DH512 = 512;
constexpr int PLEN_DH1536 = 1536;
constexpr int PLEN_DH2048 = 2048;
constexpr int PLEN_DH3072 = 3072;
constexpr int PLEN_DH4096 = 4096;
constexpr int PLEN_DH6144 = 6144;
constexpr int PLEN_DH8192 = 8192;
constexpr int PLEN_DH10001 = 10001;
constexpr int PLEN_LTZERO = -1;
constexpr int PLEN_LTSK = 20;

class CryptoDHAsyKeyGeneratorBySpecTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static string g_dh1536AlgoName = "DH_modp1536";
static string g_dh2048AlgoName = "DH_modp2048";
static string g_dh3072AlgoName = "DH_modp3072";
static string g_dh4096AlgoName = "DH_modp4096";
static string g_dh6144AlgoName = "DH_modp6144";
static string g_dh8192AlgoName = "DH_modp8192";
static string g_ed25519AlgoName = "Ed25519";

static string g_dhAlgoName = "DH";
static string g_dhpubkeyformatName = "X.509";
static string g_dhprikeyformatName = "PKCS#8";

HcfDhCommParamsSpec *g_dh1536CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh2048CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh3072CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh4096CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh6144CommSpec = nullptr;
HcfDhCommParamsSpec *g_dh8192CommSpec = nullptr;

HcfDhKeyPairParamsSpec g_dhKeyPairSpec;
HcfDhPriKeyParamsSpec g_dhPriKeySpec;
HcfDhPubKeyParamsSpec g_dhPubKeySpec;

HcfAlg25519KeyPairParamsSpec g_ed25519KeyPairSpec;
HcfAlg25519PriKeyParamsSpec g_ed25519PriKeySpec;
HcfAlg25519PubKeyParamsSpec g_ed25519PubKeySpec;

void CryptoDHAsyKeyGeneratorBySpecTest::SetUp() {}
void CryptoDHAsyKeyGeneratorBySpecTest::TearDown() {}

static const char *GetMockClass(void)
{
    return "HcfEcc";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

static HcfResult ConstructDHKeyCommParamsSpec(int32_t pLen, int32_t skLen, HcfDhCommParamsSpec **spec)
{
    HcfDhCommParamsSpec *dhCommSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(pLen, skLen, &dhCommSpec);
    if (res != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    *spec = dhCommSpec;
    return HCF_SUCCESS;
}

static HcfResult ConstructDHKeyPairParamsCommonSpec(const string &algoName, HcfDhCommParamsSpec *comSpec,
    HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    HcfDhKeyPairParamsSpec *dhKeyPairSpec = &g_dhKeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    dhKeyPairSpec->base.base.algName = comSpec->base.algName;
    dhKeyPairSpec->base.base.specType = HCF_COMMON_PARAMS_SPEC;
    dhKeyPairSpec->base.g = comSpec->g;
    dhKeyPairSpec->base.p = comSpec->p;
    dhKeyPairSpec->base.length = comSpec->length;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    dhKeyPairSpec->pk.data = retBigInt.data;
    dhKeyPairSpec->pk.len = retBigInt.len;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DH_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    dhKeyPairSpec->sk.data = retBigInt.data;
    dhKeyPairSpec->sk.len = retBigInt.len;
    *spec = (HcfAsyKeyParamsSpec *)dhKeyPairSpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructDHKeyPairParamsSpec(const string &algoName, HcfDhCommParamsSpec *comSpec,
    HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    HcfDhKeyPairParamsSpec *dhKeyPairSpec = &g_dhKeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    dhKeyPairSpec->base.base.algName = comSpec->base.algName;
    dhKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    dhKeyPairSpec->base.g = comSpec->g;
    dhKeyPairSpec->base.p = comSpec->p;
    dhKeyPairSpec->base.length = comSpec->length;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    dhKeyPairSpec->pk.data = retBigInt.data;
    dhKeyPairSpec->pk.len = retBigInt.len;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DH_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    dhKeyPairSpec->sk.data = retBigInt.data;
    dhKeyPairSpec->sk.len = retBigInt.len;
    *spec = (HcfAsyKeyParamsSpec *)dhKeyPairSpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructDHPubKeyParamsSpec(const string &algoName, HcfDhCommParamsSpec *comSpec,
    HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    HcfDhPubKeyParamsSpec *dhPubKeySpec = &g_dhPubKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    dhPubKeySpec->base.base.algName = comSpec->base.algName;
    dhPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    dhPubKeySpec->base.g = comSpec->g;
    dhPubKeySpec->base.length = comSpec->length;
    dhPubKeySpec->base.p = comSpec->p;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    dhPubKeySpec->pk.data = retBigInt.data;
    dhPubKeySpec->pk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)dhPubKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructDHPriKeyParamsSpec(const string &algoName, HcfDhCommParamsSpec *comSpec,
    HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    HcfDhPriKeyParamsSpec *dhPriKeySpec = &g_dhPriKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    dhPriKeySpec->base.base.algName = comSpec->base.algName;
    dhPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    dhPriKeySpec->base.g = comSpec->g;
    dhPriKeySpec->base.length = comSpec->length;
    dhPriKeySpec->base.p = comSpec->p;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, DH_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    dhPriKeySpec->sk.data = retBigInt.data;
    dhPriKeySpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)dhPriKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructEd25519KeyPairParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    HcfAlg25519KeyPairParamsSpec *ed25519KeyPairSpec = &g_ed25519KeyPairSpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    ed25519KeyPairSpec->base.algName = g_ed25519AlgoName.data();
    ed25519KeyPairSpec->base.specType = HCF_KEY_PAIR_SPEC;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519KeyPairSpec->pk.data = retBigInt.data;
    ed25519KeyPairSpec->pk.len = retBigInt.len;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519KeyPairSpec->sk.data = retBigInt.data;
    ed25519KeyPairSpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)ed25519KeyPairSpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructEd25519PubKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfAlg25519PubKeyParamsSpec *ed25519PubKeySpec = &g_ed25519PubKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };
    ed25519PubKeySpec->base.algName = g_ed25519AlgoName.data();
    ed25519PubKeySpec->base.specType = HCF_PUBLIC_KEY_SPEC;
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, ED25519_PK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519PubKeySpec->pk.data = retBigInt.data;
    ed25519PubKeySpec->pk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)ed25519PubKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ConstructEd25519PriKeyParamsSpec(const string &algoName, HcfAsyKeyParamsSpec **spec)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName.c_str(), &generator);
    if (res != HCF_SUCCESS) {
        return HCF_INVALID_PARAMS;
    }
    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return HCF_INVALID_PARAMS;
    }

    HcfAlg25519PriKeyParamsSpec *ed25519PriKeySpec = &g_ed25519PriKeySpec;
    HcfBigInteger retBigInt = { .data = nullptr, .len = 0 };

    ed25519PriKeySpec->base.algName = g_ed25519AlgoName.data();
    ed25519PriKeySpec->base.specType = HCF_PRIVATE_KEY_SPEC;
    res = keyPair->priKey->getAsyKeySpecBigInteger(keyPair->priKey, ED25519_SK_BN, &retBigInt);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    ed25519PriKeySpec->sk.data = retBigInt.data;
    ed25519PriKeySpec->sk.len = retBigInt.len;

    *spec = (HcfAsyKeyParamsSpec *)ed25519PriKeySpec;
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);

    return HCF_SUCCESS;
}

void CryptoDHAsyKeyGeneratorBySpecTest::SetUpTestCase()
{
    HcfResult res = ConstructDHKeyCommParamsSpec(PLEN_DH1536, SKLEN_DH1024, &g_dh1536CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH2048, SKLEN_DH1024, &g_dh2048CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH3072, SKLEN_DH1024, &g_dh3072CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH4096, SKLEN_DH1024, &g_dh4096CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH6144, SKLEN_DH1024, &g_dh6144CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ConstructDHKeyCommParamsSpec(PLEN_DH8192, SKLEN_DH1024, &g_dh8192CommSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
}

void CryptoDHAsyKeyGeneratorBySpecTest::TearDownTestCase()
{
    FreeDhCommParamsSpec(g_dh1536CommSpec);
    FreeDhCommParamsSpec(g_dh2048CommSpec);
    FreeDhCommParamsSpec(g_dh3072CommSpec);
    FreeDhCommParamsSpec(g_dh4096CommSpec);
    FreeDhCommParamsSpec(g_dh6144CommSpec);
    FreeDhCommParamsSpec(g_dh8192CommSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_1, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH2048, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_2, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH3072, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_3, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH4096, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_4, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH6144, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_5, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH8192, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest001_6, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH8192, SKLEN_EQZERO, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_1, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_2, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh2048AlgoName, g_dh2048CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_3, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh3072AlgoName, g_dh3072CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_4, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh4096AlgoName, g_dh4096CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_5, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh6144AlgoName, g_dh6144CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest002_6, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh8192AlgoName, g_dh8192CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest003, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *className = returnObj->base.getClass();
    ASSERT_NE(className, NULL);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest004, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    returnObj->base.destroy(&(returnObj->base));
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest005, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char * algName = returnObj->getAlgName(returnObj);
    ASSERT_EQ(algName, g_dhAlgoName);

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest006, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest007, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest008, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest009, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest010, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest011, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(&(keyPair->pubKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    const char *formatName = keyPair->pubKey->base.getFormat(&(keyPair->pubKey->base));
    ASSERT_EQ(formatName, g_dhpubkeyformatName);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest012, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *className = keyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest013, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest014, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(&(keyPair->priKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    const char *formatName = keyPair->priKey->base.getFormat(&(keyPair->priKey->base));
    ASSERT_EQ(formatName, g_dhprikeyformatName);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest015, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest016, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_P_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_G_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    int32_t returnInt = 0;
    res = pubKey->getAsyKeySpecInt(pubKey, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnInt, 0);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest017, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, DH_P_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    res = priKey->getAsyKeySpecBigInteger(priKey, DH_G_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    res = priKey->getAsyKeySpecBigInteger(priKey, DH_SK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnBigInteger.data, nullptr);
    ASSERT_NE(returnBigInteger.len, 0);

    int32_t returnInt = 0;
    res = priKey->getAsyKeySpecInt(priKey, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnInt, 0);

    HcfObjDestroy(priKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest018, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest019, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest020, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest021, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest022, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    const char *algName1 = returnObj->getAlgName(nullptr);
    ASSERT_NE(algName1, g_dhAlgoName.data());

    const char *algName2 = returnObj->getAlgName((HcfAsyKeyGeneratorBySpec *)&g_obj);
    ASSERT_NE(algName2, g_dhAlgoName.data());

    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest023, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(nullptr, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    res = returnObj->generateKeyPair((HcfAsyKeyGeneratorBySpec *)&g_obj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest024, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, NULL);

    algorithmName = keyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName, NULL);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest025, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest026, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *formatName = nullptr;
    formatName = keyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    formatName = keyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest027, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *algorithmName = keyPair->priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, NULL);

    algorithmName = keyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName, NULL);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest028, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = keyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest029, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *formatName = nullptr;
    formatName = keyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    formatName = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest030, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = pubKey->getAsyKeySpecBigInteger(pubKey, DH_PK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = pubKey->getAsyKeySpecBigInteger(pubKey, X25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = pubKey->getAsyKeySpecBigInteger((HcfPubKey *)&g_obj, DH_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = pubKey->getAsyKeySpecInt(pubKey, DH_L_NUM, nullptr);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);

    int32_t returnInt = 0;
    res = pubKey->getAsyKeySpecInt(pubKey, X25519_PK_BN, &returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnInt, 0);

    res = pubKey->getAsyKeySpecInt((HcfPubKey *)&g_obj, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnInt, 0);

    char *returnString = nullptr;
    res = pubKey->getAsyKeySpecString(pubKey, ED25519_SK_BN, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    res = pubKey->getAsyKeySpecString(pubKey, ECC_CURVE_NAME_STR, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    HcfObjDestroy(pubKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest031, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = priKey->getAsyKeySpecBigInteger(priKey, DH_PK_BN, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = priKey->getAsyKeySpecBigInteger(priKey, X25519_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = priKey->getAsyKeySpecBigInteger((HcfPriKey *)&g_obj, DH_PK_BN, &returnBigInteger);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnBigInteger.data, nullptr);
    ASSERT_EQ(returnBigInteger.len, 0);

    res = priKey->getAsyKeySpecInt(priKey, DH_L_NUM, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    int32_t returnInt = 0;
    res = priKey->getAsyKeySpecInt(priKey, X25519_PK_BN, &returnInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnInt, 0);

    res = priKey->getAsyKeySpecInt((HcfPriKey *)&g_obj, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnInt, 0);

    char *returnString = nullptr;
    res = priKey->getAsyKeySpecString(priKey, ED25519_SK_BN, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    res = priKey->getAsyKeySpecString(priKey, ECC_CURVE_NAME_STR, &returnString);
    ASSERT_EQ(res, HCF_NOT_SUPPORT);
    ASSERT_EQ(returnString, nullptr);

    HcfObjDestroy(priKey);
    HcfObjDestroy(returnObj);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest032, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_LTZERO, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreate(PLEN_LTSK, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest033, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPubKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest034, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = returnObj->generatePubKey(returnObj, &pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest035, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHKeyPairParamsCommonSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest036, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    returnSpi->base.destroy(nullptr);
    returnSpi->base.destroy(&g_obj);
    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest037, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHKeyPairParamsCommonSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec((HcfAsyKeyGeneratorSpi *)&g_obj, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    paramSpec = nullptr;
    res = ConstructEd25519KeyPairParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPairBySpec(returnSpi, paramSpec, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest038, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_2048,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPubKeyParamsSpec(g_dh2048AlgoName, g_dh2048CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfPubKey *pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec((HcfAsyKeyGeneratorSpi *)&g_obj, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey, nullptr);

    paramSpec = nullptr;
    res = ConstructEd25519PubKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    pubKey = nullptr;
    res = returnSpi->engineGeneratePubKeyBySpec(returnSpi, paramSpec, &pubKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(pubKey);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest039, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_3072,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    res = ConstructDHPriKeyParamsSpec(g_dh3072AlgoName, g_dh3072CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfPriKey *priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec((HcfAsyKeyGeneratorSpi *)&g_obj, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey, nullptr);

    paramSpec = nullptr;
    res = ConstructEd25519PriKeyParamsSpec(g_ed25519AlgoName, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    priKey = nullptr;
    res = returnSpi->engineGeneratePriKeyBySpec(returnSpi, paramSpec, &priKey);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(priKey, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(priKey);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest040, TestSize.Level0)
{
    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(nullptr, &returnSpi);

    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(returnSpi, nullptr);

    HcfObjDestroy(returnSpi);
}

static void OpensslMockTestFunc(uint32_t mallocCount, HcfAsyKeyParamsSpec *paramSpec)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
        HcfResult res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfKeyPair *keyPair = nullptr;
        res = returnObj->generateKeyPair(returnObj, &keyPair);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfObjDestroy(returnObj);
        HcfObjDestroy(keyPair);
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest041, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHKeyPairParamsCommonSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);
    StartRecordOpensslCallNum();

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnObj->generateKeyPair(returnObj, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(keyPair);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount, paramSpec);

    EndRecordOpensslCallNum();
}

static void OpensslMockTestFunc1(uint32_t mallocCount, HcfDhCommParamsSpec *returnCommonParamSpec)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfResult res = HcfDhKeyUtilCreate(PLEN_DH4096, SKLEN_DH1024, &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        FreeDhCommParamsSpec(returnCommonParamSpec);
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest042, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH4096, SKLEN_DH1024, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc1(mallocCount, returnCommonParamSpec);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest043, TestSize.Level0)
{
    HcfResult res = HcfDhCommonParamSpecCreate(PLEN_DH4096, SKLEN_DH1024, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
}

static void OpensslMockTestFunc2(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
        HcfResult res = HcfDhKeyUtilCreate(PLEN_DH512, SKLEN_DH128, &returnCommonParamSpec);
        if (res != HCF_SUCCESS) {
            continue;
        }
        FreeDhCommParamsSpec(returnCommonParamSpec);
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest044, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH512, SKLEN_DH128, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_SUCCESS);

    FreeDhCommParamsSpec(returnCommonParamSpec);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc2(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest045, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;

    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH2048, SKLEN_DH223, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreate(PLEN_DH3072, SKLEN_DH255, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreate(PLEN_DH4096, SKLEN_DH303, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreate(PLEN_DH6144, SKLEN_DH351, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreate(PLEN_DH8192, SKLEN_DH399, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest046, TestSize.Level0)
{
    HcfAsyKeyParamsSpec *paramSpec = nullptr;
    HcfResult res = ConstructDHPriKeyParamsSpec(g_dh1536AlgoName, g_dh1536CommSpec, &paramSpec);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(paramSpec, nullptr);

    HcfAsyKeyGeneratorBySpec *returnObj = nullptr;
    res = HcfAsyKeyGeneratorBySpecCreate(paramSpec, &returnObj);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnObj, nullptr);

    HcfPriKey *priKey = nullptr;
    res = returnObj->generatePriKey(returnObj, &priKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKey, nullptr);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = priKey->base.getEncoded(&(priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);

    HcfAsyKeyGenerator *generator = nullptr;
    res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->convertKey(generator, nullptr, nullptr, &blob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(returnObj);
    HcfObjDestroy(priKey);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorBySpecTest, CryptoDHAsyKeyGeneratorBySpecTest047, TestSize.Level0)
{
    HcfDhCommParamsSpec *returnCommonParamSpec = nullptr;
    HcfResult res = HcfDhKeyUtilCreate(PLEN_DH10001, SKLEN_EQZERO, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    res = HcfDhKeyUtilCreate(PLEN_DH511, SKLEN_EQZERO, &returnCommonParamSpec);
    ASSERT_EQ(res, HCF_ERR_MALLOC);

    FreeDhCommParamsSpec(returnCommonParamSpec);
}
}