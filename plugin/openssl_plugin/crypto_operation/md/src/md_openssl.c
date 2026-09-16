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

#include "md_openssl.h"

#include "openssl_adapter.h"
#include "openssl_common.h"
#include "securec.h"
#include "log.h"
#include "memory.h"
#include "config.h"
#include "utils.h"

typedef struct {
    HcfMdSpi base;

    EVP_MD_CTX *ctx;

    char opensslAlgoName[HCF_MAX_ALGO_NAME_LEN];

    bool squeezed;
} OpensslMdSpiImpl;

static const char *OpensslGetMdClass(void)
{
    return "OpensslMd";
}

static EVP_MD_CTX *OpensslGetMdCtx(HcfMdSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetMdClass())) {
        LOGE("Class is not match.");
        return NULL;
    }
    return ((OpensslMdSpiImpl *)self)->ctx;
}

static bool OpensslEngineIsXof(HcfMdSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetMdClass())) {
        LOGE("Class is not match.");
        return false;
    }
    OpensslMdSpiImpl *impl = (OpensslMdSpiImpl *)self;
    if (impl->ctx == NULL) {
        LOGE("The CTX is NULL!");
        return false;
    }
    const EVP_MD *md = EVP_MD_CTX_get0_md(impl->ctx);
    if (md == NULL) {
        LOGE("Failed to get EVP_MD from ctx!");
        return false;
    }
    unsigned long flags = OpensslEvpMdGetFlags(md);
    if ((flags & EVP_MD_FLAG_XOF) == EVP_MD_FLAG_XOF) {
        return true;
    }
    return false;
}

static bool OpensslEngineIsSqueezed(HcfMdSpi *self)
{
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetMdClass())) {
        LOGE("Class is not match.");
        return false;
    }
    OpensslMdSpiImpl *impl = (OpensslMdSpiImpl *)self;
    return impl->squeezed;
}

static const EVP_MD *OpensslGetMdAlgoFromString(const char *mdName)
{
    if (strcmp(mdName, "SHA1") == 0) {
        return OpensslEvpSha1();
    } else if (strcmp(mdName, "SHA3-256") == 0) {
        return OpensslEvpSha3256();
    } else if (strcmp(mdName, "SHA3-384") == 0) {
        return OpensslEvpSha3384();
    } else if (strcmp(mdName, "SHA3-512") == 0) {
        return OpensslEvpSha3512();
    } else if (strcmp(mdName, "SHA224") == 0) {
        return OpensslEvpSha224();
    } else if (strcmp(mdName, "SHA256") == 0) {
        return OpensslEvpSha256();
    } else if (strcmp(mdName, "SHA384") == 0) {
        return OpensslEvpSha384();
    } else if (strcmp(mdName, "SHA512") == 0) {
        return OpensslEvpSha512();
    } else if (strcmp(mdName, "MD2") == 0) {
        return OpensslEvpMd2();
    } else if (strcmp(mdName, "MD4") == 0) {
        return OpensslEvpMd4();
    } else if (strcmp(mdName, "RIPEMD160") == 0) {
        return OpensslEvpRipemd160();
    } else if (strcmp(mdName, "MD5") == 0) {
        return OpensslEvpMd5();
    } else if (strcmp(mdName, "SM3") == 0) {
        return OpensslEvpSm3();
    } else if (strcmp(mdName, "SHAKE128") == 0) {
        return OpensslEvpShake128();
    } else if (strcmp(mdName, "SHAKE256") == 0) {
        return OpensslEvpShake256();
    }
    return NULL;
}

static HcfResult OpensslEngineUpdateMd(HcfMdSpi *self, HcfBlob *input)
{
    if (input == NULL) {
        LOGE("The input is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (OpensslEngineIsXof(self) && OpensslEngineIsSqueezed(self)) {
        LOGE("Md has been squeezed, update is not allowed.");
        return HCF_ERR_INVALID_CALL;
    }
    if (OpensslGetMdCtx(self) == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (EVP_DigestUpdate(OpensslGetMdCtx(self), input->data, input->len) != HCF_OPENSSL_SUCCESS) {
        LOGE("EVP_DigestUpdate return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineDoFinalMd(HcfMdSpi *self, HcfBlob *output)
{
    if (output == NULL) {
        LOGE("The output is NULL!");
        return HCF_INVALID_PARAMS;
    }
    if (OpensslEngineIsXof(self)) {
        LOGE("XOF algorithm does not support digest, use squeeze instead.");
        return HCF_ERR_INVALID_CALL;
    }
    if (OpensslEngineIsSqueezed(self)) {
        LOGE("Md has been squeezed, doFinal is not allowed.");
        return HCF_ERR_INVALID_CALL;
    }
    EVP_MD_CTX *localCtx = OpensslGetMdCtx(self);
    if (localCtx == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_ERR_CRYPTO_OPERATION;
    }
    unsigned char outputBuf[EVP_MAX_MD_SIZE];
    uint32_t outputLen;
    int32_t ret = OpensslEvpDigestFinalEx(localCtx, outputBuf, &outputLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("EVP_DigestFinal_ex return error!");
        HcfPrintOpensslError();
        return HCF_ERR_CRYPTO_OPERATION;
    }
    output->data = (uint8_t *)HcfMalloc(outputLen, 0);
    if (output->data == NULL) {
        LOGE("Failed to allocate output->data memory!");
        return HCF_ERR_MALLOC;
    }
    (void)memcpy_s(output->data, outputLen, outputBuf, outputLen);
    output->len = outputLen;
    return HCF_SUCCESS;
}

static bool OpensslCheckXofLength(OpensslMdSpiImpl *impl, int32_t length)
{
    uint32_t minLen = HCF_SHAKE256_MIN_LEN;
    if (strcmp(impl->opensslAlgoName, "SHAKE128") == 0) {
        minLen = HCF_SHAKE128_MIN_LEN;
    }
    if (length < (int32_t)minLen || length > HCF_SHAKE_MAX_LEN) {
        LOGE("Invalid digest length: %{public}d, range [%{public}d, %{public}d]",
            length, (int32_t)minLen, HCF_SHAKE_MAX_LEN);
        return false;
    }
    return true;
}

static HcfResult OpensslSqueezeOutput(OpensslMdSpiImpl *impl, int32_t length, HcfBlob *output)
{
    uint32_t outLen = (uint32_t)length;
    output->data = (uint8_t *)HcfMalloc(outLen, 0);
    if (output->data == NULL) {
        LOGE("Failed to allocate output->data memory!");
        return HCF_ERR_MALLOC;
    }
    int32_t ret = OpensslEvpDigestFinalXof(impl->ctx, output->data, outLen);
    if (ret != HCF_OPENSSL_SUCCESS) {
        LOGE("EVP_DigestFinalXOF return error!");
        HcfPrintOpensslError();
        HcfFree(output->data);
        output->data = NULL;
        output->len = 0;
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    output->len = outLen;
    impl->squeezed = true;
    return HCF_SUCCESS;
}

static HcfResult OpensslEngineSqueeze(HcfMdSpi *self, int32_t length, HcfBlob *output)
{
    if (output == NULL) {
        LOGE("The output is NULL!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (!HcfIsClassMatch((HcfObjectBase *)self, OpensslGetMdClass())) {
        LOGE("Class is not match.");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    OpensslMdSpiImpl *impl = (OpensslMdSpiImpl *)self;
    if (impl->ctx == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    if (impl->squeezed) {
        LOGE("Md has been squeezed, squeeze is not allowed.");
        return HCF_ERR_INVALID_CALL;
    }
    if (!OpensslEngineIsXof(self)) {
        LOGE("Variable-length digest is not supported for this algorithm.");
        return HCF_ERR_INVALID_CALL;
    }
    if (!OpensslCheckXofLength(impl, length)) {
        return HCF_ERR_PARAMETER_CHECK_FAILED;
    }
    return OpensslSqueezeOutput(impl, length, output);
}

static uint32_t OpensslEngineGetMdLength(HcfMdSpi *self)
{
    if (OpensslEngineIsXof(self)) {
        LOGE("XOF algorithm does not support getMdLength.");
        return HCF_OPENSSL_INVALID_MD_LEN;
    }
    if (OpensslGetMdCtx(self) == NULL) {
        LOGE("The CTX is NULL!");
        return HCF_OPENSSL_INVALID_MD_LEN;
    }
    int32_t size = OpensslEvpMdCtxSize(OpensslGetMdCtx(self));
    if (size < 0) {
        LOGE("Get the overflow path length in openssl!");
        return HCF_OPENSSL_INVALID_MD_LEN;
    }
    return size;
}

static void OpensslDestroyMd(HcfObjectBase *self)
{
    if (self == NULL) {
        LOGE("Self ptr is NULL!");
        return;
    }
    if (!HcfIsClassMatch(self, OpensslGetMdClass())) {
        LOGE("Class is not match.");
        return;
    }
    if (OpensslGetMdCtx((HcfMdSpi *)self) != NULL) {
        OpensslEvpMdCtxFree(OpensslGetMdCtx((HcfMdSpi *)self));
    }
    HcfFree(self);
}

static void OpensslInitSpiImpl(OpensslMdSpiImpl *impl)
{
    impl->squeezed = false;
    impl->base.base.getClass = OpensslGetMdClass;
    impl->base.base.destroy = OpensslDestroyMd;
    impl->base.engineUpdateMd = OpensslEngineUpdateMd;
    impl->base.engineDoFinalMd = OpensslEngineDoFinalMd;
    impl->base.engineSqueeze = OpensslEngineSqueeze;
    impl->base.engineIsXof = OpensslEngineIsXof;
    impl->base.engineIsSqueezed = OpensslEngineIsSqueezed;
    impl->base.engineGetMdLength = OpensslEngineGetMdLength;
}

static void OpensslFreeSpiImpl(OpensslMdSpiImpl *impl)
{
    if (impl == NULL) {
        return;
    }
    if (impl->ctx != NULL) {
        OpensslEvpMdCtxFree(impl->ctx);
    }
    HcfFree(impl);
}

HcfResult OpensslMdSpiCreate(const char *opensslAlgoName, HcfMdSpi **spiObj)
{
    if (spiObj == NULL || opensslAlgoName == NULL) {
        LOGE("Invalid input parameter.");
        return HCF_INVALID_PARAMS;
    }
    OpensslMdSpiImpl *returnSpiImpl = (OpensslMdSpiImpl *)HcfMalloc(sizeof(OpensslMdSpiImpl), 0);
    if (returnSpiImpl == NULL) {
        LOGE("Failed to allocate MdSpiImpl memory!");
        return HCF_ERR_MALLOC;
    }
    returnSpiImpl->ctx = OpensslEvpMdCtxNew();
    if (returnSpiImpl->ctx == NULL) {
        LOGE("Failed to create ctx!");
        HcfFree(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_MALLOC;
    }
    const EVP_MD *mdfunc = OpensslGetMdAlgoFromString(opensslAlgoName);
    if (mdfunc == NULL) {
        LOGE("Failed to get MD algorithm from string.");
        OpensslFreeSpiImpl(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (OpensslEvpDigestInitEx(returnSpiImpl->ctx, mdfunc, NULL) != HCF_OPENSSL_SUCCESS) {
        LOGE("Failed to init MD!");
        OpensslFreeSpiImpl(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_CRYPTO_OPERATION;
    }
    if (strcpy_s(returnSpiImpl->opensslAlgoName, HCF_MAX_ALGO_NAME_LEN, opensslAlgoName) != EOK) {
        LOGE("Failed to copy algoName!");
        OpensslFreeSpiImpl(returnSpiImpl);
        returnSpiImpl = NULL;
        return HCF_ERR_MALLOC;
    }
    OpensslInitSpiImpl(returnSpiImpl);
    *spiObj = (HcfMdSpi *)returnSpiImpl;
    return HCF_SUCCESS;
}