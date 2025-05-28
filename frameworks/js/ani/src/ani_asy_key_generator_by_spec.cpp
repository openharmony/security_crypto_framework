/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ani_asy_key_generator_by_spec.h"
#include "ani_key_pair.h"
#include "ani_pri_key.h"
#include "ani_pub_key.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "detailed_dh_key_params.h"

namespace {
using namespace ANI::CryptoFramework;

const std::string DSA_ALG_NAME = "DSA";
const std::string ECC_ALG_NAME = "ECC";
const std::string RSA_ALG_NAME = "RSA";
const std::string DH_ALG_NAME = "DH";
const std::string ED25519_ALG_NAME = "Ed25519";
const std::string X25519_ALG_NAME = "X25519";
const std::string SM2_ALG_NAME = "SM2";

void SetDSAKeyPairParamsSpecAttribute(DSAKeyPairSpec const& dsaParams, HcfDsaKeyPairParamsSpec &dsaKeyPairSpec)
{
    dsaKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dsaParams.base.specType.get_value());
    dsaKeyPairSpec.base.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    ArrayU8ToDataBlob(dsaParams.params.p, dsaKeyPairSpec.base.p);
    ArrayU8ToDataBlob(dsaParams.params.q, dsaKeyPairSpec.base.q);
    ArrayU8ToDataBlob(dsaParams.params.g, dsaKeyPairSpec.base.g);
    ArrayU8ToDataBlob(dsaParams.pk, dsaKeyPairSpec.pk);
    ArrayU8ToDataBlob(dsaParams.sk, dsaKeyPairSpec.sk);
}

void SetDSAPubKeyParamsSpecAttribute(DSAPubKeySpec const& dsaParams, HcfDsaPubKeyParamsSpec &dsaPubKeySpec)
{
    dsaPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dsaParams.base.specType.get_value());
    dsaPubKeySpec.base.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    ArrayU8ToDataBlob(dsaParams.params.p, dsaPubKeySpec.base.p);
    ArrayU8ToDataBlob(dsaParams.params.q, dsaPubKeySpec.base.q);
    ArrayU8ToDataBlob(dsaParams.params.g, dsaPubKeySpec.base.g);
    ArrayU8ToDataBlob(dsaParams.pk, dsaPubKeySpec.pk);
}

void SetDSACommonParamsSpecAttribute(DSACommonParamsSpec const& dsaParams, HcfDsaCommParamsSpec &dsaCommonParamsSpec)
{
    dsaCommonParamsSpec.base.specType = static_cast<HcfAsyKeySpecType>(dsaParams.base.specType.get_value());
    dsaCommonParamsSpec.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    ArrayU8ToDataBlob(dsaParams.p, dsaCommonParamsSpec.p);
    ArrayU8ToDataBlob(dsaParams.q, dsaCommonParamsSpec.q);
    ArrayU8ToDataBlob(dsaParams.g, dsaCommonParamsSpec.g);
}

void SetECCKeyPairParamsSpecAttribute(ECCKeyPairSpec const& eccParams, HcfEccKeyPairParamsSpec &eccKeyPairSpec)
{
    eccKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccKeyPairSpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccKeyPairSpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToDataBlob(eccParams.params.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccKeyPairSpec.base.h = eccParams.params.h;
    ArrayU8ToDataBlob(eccParams.params.a, eccKeyPairSpec.base.a);
    ArrayU8ToDataBlob(eccParams.params.b, eccKeyPairSpec.base.b);
    ArrayU8ToDataBlob(eccParams.params.g.x, eccKeyPairSpec.base.g.x);
    ArrayU8ToDataBlob(eccParams.params.g.y, eccKeyPairSpec.base.g.y);
    ArrayU8ToDataBlob(eccParams.params.n, eccKeyPairSpec.base.n);
    ArrayU8ToDataBlob(eccParams.pk.x, eccKeyPairSpec.pk.x);
    ArrayU8ToDataBlob(eccParams.pk.y, eccKeyPairSpec.pk.y);
    ArrayU8ToDataBlob(eccParams.sk, eccKeyPairSpec.sk);
}

void SetECCPubKeyParamsSpecAttribute(ECCPubKeySpec const& eccParams, HcfEccPubKeyParamsSpec &eccPubKeySpec)
{
    eccPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccPubKeySpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccPubKeySpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToDataBlob(eccParams.params.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccPubKeySpec.base.h = eccParams.params.h;
    ArrayU8ToDataBlob(eccParams.params.a, eccPubKeySpec.base.a);
    ArrayU8ToDataBlob(eccParams.params.b, eccPubKeySpec.base.b);
    ArrayU8ToDataBlob(eccParams.params.g.x, eccPubKeySpec.base.g.x);
    ArrayU8ToDataBlob(eccParams.params.g.y, eccPubKeySpec.base.g.y);
    ArrayU8ToDataBlob(eccParams.params.n, eccPubKeySpec.base.n);
    ArrayU8ToDataBlob(eccParams.pk.x, eccPubKeySpec.pk.x);
    ArrayU8ToDataBlob(eccParams.pk.y, eccPubKeySpec.pk.y);
}

void SetECCPriKeyParamsSpecAttribute(ECCPriKeySpec const& eccParams, HcfEccPriKeyParamsSpec &eccPriKeySpec)
{
    eccPriKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccPriKeySpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccPriKeySpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToDataBlob(eccParams.params.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccPriKeySpec.base.h = eccParams.params.h;
    ArrayU8ToDataBlob(eccParams.params.a, eccPriKeySpec.base.a);
    ArrayU8ToDataBlob(eccParams.params.b, eccPriKeySpec.base.b);
    ArrayU8ToDataBlob(eccParams.params.g.x, eccPriKeySpec.base.g.x);
    ArrayU8ToDataBlob(eccParams.params.g.y, eccPriKeySpec.base.g.y);
    ArrayU8ToDataBlob(eccParams.params.n, eccPriKeySpec.base.n);
    ArrayU8ToDataBlob(eccParams.sk, eccPriKeySpec.sk);
}

void SetECCCommonParamsSpecAttribute(ECCCommonParamsSpec const& eccParams, HcfEccCommParamsSpec &eccCommonParamsSpec)
{
    eccCommonParamsSpec.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccCommonParamsSpec.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccCommonParamsSpec.field->fieldType = const_cast<char *>(eccParams.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccCommonParamsSpec.field);
        fieldFp->base.fieldType = const_cast<char *>(eccParams.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToDataBlob(eccParams.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccCommonParamsSpec.h = eccParams.h;
    ArrayU8ToDataBlob(eccParams.a, eccCommonParamsSpec.a);
    ArrayU8ToDataBlob(eccParams.b, eccCommonParamsSpec.b);
    ArrayU8ToDataBlob(eccParams.g.x, eccCommonParamsSpec.g.x);
    ArrayU8ToDataBlob(eccParams.g.y, eccCommonParamsSpec.g.y);
    ArrayU8ToDataBlob(eccParams.n, eccCommonParamsSpec.n);
}

void SetRSAKeyPairParamsSpecAttribute(RSAKeyPairSpec const& rsaParams, HcfRsaKeyPairParamsSpec &rsaKeyPairSpec)
{
    rsaKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(rsaParams.base.specType.get_value());
    rsaKeyPairSpec.base.base.algName = const_cast<char *>(rsaParams.base.algName.c_str());
    ArrayU8ToDataBlob(rsaParams.params.n, rsaKeyPairSpec.base.n);
    ArrayU8ToDataBlob(rsaParams.pk, rsaKeyPairSpec.pk);
    ArrayU8ToDataBlob(rsaParams.sk, rsaKeyPairSpec.sk);
}

void SetRSAPubKeyParamsSpecAttribute(RSAPubKeySpec const& rsaParams, HcfRsaPubKeyParamsSpec &rsaPubKeySpec)
{
    rsaPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(rsaParams.base.specType.get_value());
    rsaPubKeySpec.base.base.algName = const_cast<char *>(rsaParams.base.algName.c_str());
    ArrayU8ToDataBlob(rsaParams.params.n, rsaPubKeySpec.base.n);
    ArrayU8ToDataBlob(rsaParams.pk, rsaPubKeySpec.pk);
}

void SetEd25519KeyPairParamsSpecAttribute(ED25519KeyPairSpec const& ed25519Params,
    HcfAlg25519KeyPairParamsSpec &ed25519KeyPairSpec)
{
    ed25519KeyPairSpec.base.specType = static_cast<HcfAsyKeySpecType>(ed25519Params.base.specType.get_value());
    ed25519KeyPairSpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ArrayU8ToDataBlob(ed25519Params.pk, ed25519KeyPairSpec.pk);
    ArrayU8ToDataBlob(ed25519Params.sk, ed25519KeyPairSpec.sk);
}

void SetEd25519PubKeyParamsSpecAttribute(ED25519PubKeySpec const& ed25519Params,
    HcfAlg25519PubKeyParamsSpec &ed25519PubKeySpec)
{
    ed25519PubKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(ed25519Params.base.specType.get_value());
    ed25519PubKeySpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ArrayU8ToDataBlob(ed25519Params.pk, ed25519PubKeySpec.pk);
}

void SetEd25519PriKeyParamsSpecAttribute(ED25519PriKeySpec const& ed25519Params,
    HcfAlg25519PriKeyParamsSpec &ed25519PriKeySpec)
{
    ed25519PriKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(ed25519Params.base.specType.get_value());
    ed25519PriKeySpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ArrayU8ToDataBlob(ed25519Params.sk, ed25519PriKeySpec.sk);
}

void SetX25519KeyPairParamsSpecAttribute(X25519KeyPairSpec const& x25519Params,
    HcfAlg25519KeyPairParamsSpec &x25519KeyPairSpec)
{
    x25519KeyPairSpec.base.specType = static_cast<HcfAsyKeySpecType>(x25519Params.base.specType.get_value());
    x25519KeyPairSpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    ArrayU8ToDataBlob(x25519Params.pk, x25519KeyPairSpec.pk);
    ArrayU8ToDataBlob(x25519Params.sk, x25519KeyPairSpec.sk);
}

void SetX25519PubKeyParamsSpecAttribute(X25519PubKeySpec const& x25519Params,
    HcfAlg25519PubKeyParamsSpec &x25519PubKeySpec)
{
    x25519PubKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(x25519Params.base.specType.get_value());
    x25519PubKeySpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    ArrayU8ToDataBlob(x25519Params.pk, x25519PubKeySpec.pk);
}

void SetX25519PriKeyParamsSpecAttribute(X25519PriKeySpec const& x25519Params,
    HcfAlg25519PriKeyParamsSpec &x25519PriKeySpec)
{
    x25519PriKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(x25519Params.base.specType.get_value());
    x25519PriKeySpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    ArrayU8ToDataBlob(x25519Params.sk, x25519PriKeySpec.sk);
}

void SetDhKeyPairParamsSpecAttribute(DHKeyPairSpec const& dhParams, HcfDhKeyPairParamsSpec &dhKeyPairSpec)
{
    dhKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhKeyPairSpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhKeyPairSpec.base.length = dhParams.params.l;
    ArrayU8ToDataBlob(dhParams.params.p, dhKeyPairSpec.base.p);
    ArrayU8ToDataBlob(dhParams.params.g, dhKeyPairSpec.base.g);
    ArrayU8ToDataBlob(dhParams.pk, dhKeyPairSpec.pk);
    ArrayU8ToDataBlob(dhParams.sk, dhKeyPairSpec.sk);
}

void SetDhPubKeyParamsSpecAttribute(DHPubKeySpec const& dhParams, HcfDhPubKeyParamsSpec &dhPubKeySpec)
{
    dhPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhPubKeySpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhPubKeySpec.base.length = dhParams.params.l;
    ArrayU8ToDataBlob(dhParams.params.p, dhPubKeySpec.base.p);
    ArrayU8ToDataBlob(dhParams.params.g, dhPubKeySpec.base.g);
    ArrayU8ToDataBlob(dhParams.pk, dhPubKeySpec.pk);
}

void SetDhPriKeyParamsSpecAttribute(DHPriKeySpec const& dhParams, HcfDhPriKeyParamsSpec &dhPriKeySpec)
{
    dhPriKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhPriKeySpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhPriKeySpec.base.length = dhParams.params.l;
    ArrayU8ToDataBlob(dhParams.params.p, dhPriKeySpec.base.p);
    ArrayU8ToDataBlob(dhParams.params.g, dhPriKeySpec.base.g);
    ArrayU8ToDataBlob(dhParams.sk, dhPriKeySpec.sk);
}

void SetDhCommonParamsSpecAttribute(DHCommonParamsSpec const& dhParams, HcfDhCommParamsSpec &dhCommonParamsSpec)
{
    dhCommonParamsSpec.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhCommonParamsSpec.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhCommonParamsSpec.length = dhParams.l;
    ArrayU8ToDataBlob(dhParams.p, dhCommonParamsSpec.p);
    ArrayU8ToDataBlob(dhParams.g, dhCommonParamsSpec.g);
}

HcfAsyKeyParamsSpec* CreateDSASpec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfDsaKeyPairParamsSpec dsaKeyPairSpec = {};
    static HcfDsaPubKeyParamsSpec dsaPubKeySpec = {};
    static HcfDsaCommParamsSpec dsaCommonParamsSpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSAKEYPAIRSPEC) {
        SetDSAKeyPairParamsSpecAttribute(asyKeySpec.get_DSAKEYPAIRSPEC_ref(), dsaKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSAPUBKEYSPEC) {
        SetDSAPubKeyParamsSpecAttribute(asyKeySpec.get_DSAPUBKEYSPEC_ref(), dsaPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSACOMMONPARAMSSPEC) {
        SetDSACommonParamsSpecAttribute(asyKeySpec.get_DSACOMMONPARAMSSPEC_ref(), dsaCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&dsaCommonParamsSpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateECCSpec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfEccKeyPairParamsSpec eccKeyPairSpec = {};
    static HcfEccPubKeyParamsSpec eccPubKeySpec = {};
    static HcfEccPriKeyParamsSpec eccPriKeySpec = {};
    static HcfEccCommParamsSpec eccCommonParamsSpec = {};
    static HcfECFieldFp ecFieldFp = {};
    static HcfECField* ecField = &ecFieldFp.base;

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCKEYPAIRSPEC) {
        eccKeyPairSpec.base.field = ecField;
        SetECCKeyPairParamsSpecAttribute(asyKeySpec.get_ECCKEYPAIRSPEC_ref(), eccKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&eccKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCPUBKEYSPEC) {
        eccPubKeySpec.base.field = ecField;
        SetECCPubKeyParamsSpecAttribute(asyKeySpec.get_ECCPUBKEYSPEC_ref(), eccPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&eccPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCPRIKEYSPEC) {
        eccPriKeySpec.base.field = ecField;
        SetECCPriKeyParamsSpecAttribute(asyKeySpec.get_ECCPRIKEYSPEC_ref(), eccPriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&eccPriKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCCOMMONPARAMSSPEC) {
        eccCommonParamsSpec.field = ecField;
        SetECCCommonParamsSpecAttribute(asyKeySpec.get_ECCCOMMONPARAMSSPEC_ref(), eccCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&eccCommonParamsSpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateRSASpec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfRsaKeyPairParamsSpec rsaKeyPairSpec = {};
    static HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSAKEYPAIRSPEC) {
        SetRSAKeyPairParamsSpecAttribute(asyKeySpec.get_RSAKEYPAIRSPEC_ref(), rsaKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSAPUBKEYSPEC) {
        SetRSAPubKeyParamsSpecAttribute(asyKeySpec.get_RSAPUBKEYSPEC_ref(), rsaPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&rsaPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSACOMMONPARAMSSPEC) {
        LOGE("RSA not support comm key spec");
        return nullptr;
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateEd25519Spec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfAlg25519KeyPairParamsSpec ed25519KeyPairSpec = {};
    static HcfAlg25519PubKeyParamsSpec ed25519PubKeySpec = {};
    static HcfAlg25519PriKeyParamsSpec ed25519PriKeySpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519KEYPAIRSPEC) {
        SetEd25519KeyPairParamsSpecAttribute(asyKeySpec.get_ED25519KEYPAIRSPEC_ref(), ed25519KeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&ed25519KeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519PUBKEYSPEC) {
        SetEd25519PubKeyParamsSpecAttribute(asyKeySpec.get_ED25519PUBKEYSPEC_ref(), ed25519PubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&ed25519PubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519PRIKEYSPEC) {
        SetEd25519PriKeyParamsSpecAttribute(asyKeySpec.get_ED25519PRIKEYSPEC_ref(), ed25519PriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&ed25519PriKeySpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateX25519Spec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfAlg25519KeyPairParamsSpec x25519KeyPairSpec = {};
    static HcfAlg25519PubKeyParamsSpec x25519PubKeySpec = {};
    static HcfAlg25519PriKeyParamsSpec x25519PriKeySpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519KEYPAIRSPEC) {
        SetX25519KeyPairParamsSpecAttribute(asyKeySpec.get_X25519KEYPAIRSPEC_ref(), x25519KeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&x25519KeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519PUBKEYSPEC) {
        SetX25519PubKeyParamsSpecAttribute(asyKeySpec.get_X25519PUBKEYSPEC_ref(), x25519PubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&x25519PubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519PRIKEYSPEC) {
        SetX25519PriKeyParamsSpecAttribute(asyKeySpec.get_X25519PRIKEYSPEC_ref(), x25519PriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&x25519PriKeySpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateDHSpec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfDhKeyPairParamsSpec dhKeyPairSpec = {};
    static HcfDhPubKeyParamsSpec dhPubKeySpec = {};
    static HcfDhPriKeyParamsSpec dhPriKeySpec = {};
    static HcfDhCommParamsSpec dhCommonParamsSpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHKEYPAIRSPEC) {
        SetDhKeyPairParamsSpecAttribute(asyKeySpec.get_DHKEYPAIRSPEC_ref(), dhKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&dhKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHPUBKEYSPEC) {
        SetDhPubKeyParamsSpecAttribute(asyKeySpec.get_DHPUBKEYSPEC_ref(), dhPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&dhPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHPRIKEYSPEC) {
        SetDhPriKeyParamsSpecAttribute(asyKeySpec.get_DHPRIKEYSPEC_ref(), dhPriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&dhPriKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHCOMMONPARAMSSPEC) {
        SetDhCommonParamsSpecAttribute(asyKeySpec.get_DHCOMMONPARAMSSPEC_ref(), dhCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&dhCommonParamsSpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateParamsSpec(OptAsyKeySpec const& asyKeySpec)
{
    const std::string &algName = asyKeySpec.get_ASYKEYSPEC_ref().algName.c_str();
    if (algName == DSA_ALG_NAME) {
        return CreateDSASpec(asyKeySpec);
    } else if (algName == ECC_ALG_NAME || algName == SM2_ALG_NAME) {
        return CreateECCSpec(asyKeySpec);
    } else if (algName == RSA_ALG_NAME) {
        return CreateRSASpec(asyKeySpec);
    } else if (algName == ED25519_ALG_NAME) {
        return CreateEd25519Spec(asyKeySpec);
    } else if (algName == X25519_ALG_NAME) {
        return CreateX25519Spec(asyKeySpec);
    } else if (algName == DH_ALG_NAME) {
        return CreateDHSpec(asyKeySpec);
    }
    return nullptr;
}
} // namespace

namespace ANI::CryptoFramework {
AsyKeyGeneratorBySpecImpl::AsyKeyGeneratorBySpecImpl() {}

AsyKeyGeneratorBySpecImpl::AsyKeyGeneratorBySpecImpl(HcfAsyKeyGeneratorBySpec *generator) : generator_(generator) {}

AsyKeyGeneratorBySpecImpl::~AsyKeyGeneratorBySpecImpl()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

KeyPair AsyKeyGeneratorBySpecImpl::GenerateKeyPairSync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator spec obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = this->generator_->generateKeyPair(this->generator_, &keyPair);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generateKeyPair failed");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}

PriKey AsyKeyGeneratorBySpecImpl::GeneratePriKeySync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator spec obj is nullptr!");
        return make_holder<PriKeyImpl, PriKey>();
    }
    HcfPriKey *priKey = nullptr;
    HcfResult res = this->generator_->generatePriKey(this->generator_, &priKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generatePriKey failed");
        return make_holder<PriKeyImpl, PriKey>();
    }
    return make_holder<PriKeyImpl, PriKey>(priKey);
}

PubKey AsyKeyGeneratorBySpecImpl::GeneratePubKeySync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator spec obj is nullptr!");
        return make_holder<PubKeyImpl, PubKey>();
    }
    HcfPubKey *pubKey = nullptr;
    HcfResult res = this->generator_->generatePubKey(this->generator_, &pubKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generatePubKey failed");
        return make_holder<PubKeyImpl, PubKey>();
    }
    return make_holder<PubKeyImpl, PubKey>(pubKey);
}

string AsyKeyGeneratorBySpecImpl::GetAlgName()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator spec obj is nullptr!");
        return "";
    }
    const char *algName = this->generator_->getAlgName(this->generator_);
    return (algName == nullptr) ? "" : string(algName);
}

AsyKeyGeneratorBySpec CreateAsyKeyGeneratorBySpec(OptAsyKeySpec const& asyKeySpec)
{
    HcfAsyKeyParamsSpec *spec = CreateParamsSpec(asyKeySpec);
    if (spec == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "invalid asy key spec!");
        return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>();
    }

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(spec, &generator);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create generator spec obj fail!");
        return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>();
    }
    return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>(generator);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateAsyKeyGeneratorBySpec(ANI::CryptoFramework::CreateAsyKeyGeneratorBySpec);
// NOLINTEND
