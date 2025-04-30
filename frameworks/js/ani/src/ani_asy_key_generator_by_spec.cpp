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
    dsaKeyPairSpec.base.base.specType = HCF_KEY_PAIR_SPEC;
    dsaKeyPairSpec.base.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    dsaKeyPairSpec.base.p.data = dsaParams.params.p.data();
    dsaKeyPairSpec.base.p.len = dsaParams.params.p.size();
    dsaKeyPairSpec.base.q.data = dsaParams.params.q.data();
    dsaKeyPairSpec.base.q.len = dsaParams.params.q.size();
    dsaKeyPairSpec.base.g.data = dsaParams.params.g.data();
    dsaKeyPairSpec.base.g.len = dsaParams.params.g.size();
    dsaKeyPairSpec.pk.data = dsaParams.pk.data();
    dsaKeyPairSpec.pk.len = dsaParams.pk.size();
    dsaKeyPairSpec.sk.data = dsaParams.sk.data();
    dsaKeyPairSpec.sk.len = dsaParams.sk.size();
}

void SetDSAPubKeyParamsSpecAttribute(DSAPubKeySpec const& dsaParams, HcfDsaPubKeyParamsSpec &dsaPubKeySpec)
{
    dsaPubKeySpec.base.base.specType = HCF_PUBLIC_KEY_SPEC;
    dsaPubKeySpec.base.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    dsaPubKeySpec.base.p.data = dsaParams.params.p.data();
    dsaPubKeySpec.base.p.len = dsaParams.params.p.size();
    dsaPubKeySpec.base.q.data = dsaParams.params.q.data();
    dsaPubKeySpec.base.q.len = dsaParams.params.q.size();
    dsaPubKeySpec.base.g.data = dsaParams.params.g.data();
    dsaPubKeySpec.base.g.len = dsaParams.params.g.size();
    dsaPubKeySpec.pk.data = dsaParams.pk.data();
    dsaPubKeySpec.pk.len = dsaParams.pk.size();
}

void SetDSACommonParamsSpecAttribute(DSACommonParamsSpec const& dsaParams, HcfDsaCommParamsSpec &dsaCommonParamsSpec)
{
    dsaCommonParamsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    dsaCommonParamsSpec.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    dsaCommonParamsSpec.p.data = dsaParams.p.data();
    dsaCommonParamsSpec.p.len = dsaParams.p.size();
    dsaCommonParamsSpec.q.data = dsaParams.q.data();
    dsaCommonParamsSpec.q.len = dsaParams.q.size();
    dsaCommonParamsSpec.g.data = dsaParams.g.data();
    dsaCommonParamsSpec.g.len = dsaParams.g.size();
}

void SetECCKeyPairParamsSpecAttribute(ECCKeyPairSpec const& eccParams, HcfEccKeyPairParamsSpec &eccKeyPairSpec)
{
    eccKeyPairSpec.base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccKeyPairSpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp*>(eccKeyPairSpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        fieldFp->p.data = eccParams.params.field.get_ECFIELDFP_ref().p.data();
        fieldFp->p.len = eccParams.params.field.get_ECFIELDFP_ref().p.size();
    }
    eccKeyPairSpec.base.a.data = eccParams.params.a.data();
    eccKeyPairSpec.base.a.len = eccParams.params.a.size();
    eccKeyPairSpec.base.b.data = eccParams.params.b.data();
    eccKeyPairSpec.base.b.len = eccParams.params.b.size();
    eccKeyPairSpec.base.g.x.data = eccParams.params.g.x.data();
    eccKeyPairSpec.base.g.x.len = eccParams.params.g.x.size();
    eccKeyPairSpec.base.g.y.data = eccParams.params.g.y.data();
    eccKeyPairSpec.base.g.y.len = eccParams.params.g.y.size();
    eccKeyPairSpec.base.n.data = eccParams.params.n.data();
    eccKeyPairSpec.base.n.len = eccParams.params.n.size();
    eccKeyPairSpec.base.h = eccParams.params.h;
    eccKeyPairSpec.pk.x.data = eccParams.pk.x.data();
    eccKeyPairSpec.pk.x.len = eccParams.pk.x.size();
    eccKeyPairSpec.pk.y.data = eccParams.pk.y.data();
    eccKeyPairSpec.pk.y.len = eccParams.pk.y.size();
    eccKeyPairSpec.sk.data = eccParams.sk.data();
    eccKeyPairSpec.sk.len = eccParams.sk.size();
}

void SetECCPubKeyParamsSpecAttribute(ECCPubKeySpec const& eccParams, HcfEccPubKeyParamsSpec &eccPubKeySpec)
{
    eccPubKeySpec.base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccPubKeySpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp*>(eccPubKeySpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        fieldFp->p.data = eccParams.params.field.get_ECFIELDFP_ref().p.data();
        fieldFp->p.len = eccParams.params.field.get_ECFIELDFP_ref().p.size();
    }
    eccPubKeySpec.base.a.data = eccParams.params.a.data();
    eccPubKeySpec.base.a.len = eccParams.params.a.size();
    eccPubKeySpec.base.b.data = eccParams.params.b.data();
    eccPubKeySpec.base.b.len = eccParams.params.b.size();
    eccPubKeySpec.base.g.x.data = eccParams.params.g.x.data();
    eccPubKeySpec.base.g.x.len = eccParams.params.g.x.size();
    eccPubKeySpec.base.g.y.data = eccParams.params.g.y.data();
    eccPubKeySpec.base.g.y.len = eccParams.params.g.y.size();
    eccPubKeySpec.base.n.data = eccParams.params.n.data();
    eccPubKeySpec.base.n.len = eccParams.params.n.size();
    eccPubKeySpec.base.h = eccParams.params.h;
    eccPubKeySpec.pk.x.data = eccParams.pk.x.data();
    eccPubKeySpec.pk.x.len = eccParams.pk.x.size();
    eccPubKeySpec.pk.y.data = eccParams.pk.y.data();
    eccPubKeySpec.pk.y.len = eccParams.pk.y.size();
}

void SetECCPriKeyParamsSpecAttribute(ECCPriKeySpec const& eccParams, HcfEccPriKeyParamsSpec &eccPriKeySpec)
{
    eccPriKeySpec.base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccPriKeySpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp*>(eccPriKeySpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        fieldFp->p.data = eccParams.params.field.get_ECFIELDFP_ref().p.data();
        fieldFp->p.len = eccParams.params.field.get_ECFIELDFP_ref().p.size();
    }
    eccPriKeySpec.base.a.data = eccParams.params.a.data();
    eccPriKeySpec.base.a.len = eccParams.params.a.size();
    eccPriKeySpec.base.b.data = eccParams.params.b.data();
    eccPriKeySpec.base.b.len = eccParams.params.b.size();
    eccPriKeySpec.base.g.x.data = eccParams.params.g.x.data();
    eccPriKeySpec.base.g.x.len = eccParams.params.g.x.size();
    eccPriKeySpec.base.g.y.data = eccParams.params.g.y.data();
    eccPriKeySpec.base.g.y.len = eccParams.params.g.y.size();
    eccPriKeySpec.base.n.data = eccParams.params.n.data();
    eccPriKeySpec.base.n.len = eccParams.params.n.size();
    eccPriKeySpec.base.h = eccParams.params.h;
    eccPriKeySpec.sk.data = eccParams.sk.data();
    eccPriKeySpec.sk.len = eccParams.sk.size();
}

void SetECCCommonParamsSpecAttribute(ECCCommonParamsSpec const& eccParams, HcfEccCommParamsSpec &eccCommonParamsSpec)
{
    eccCommonParamsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommonParamsSpec.base.algName = const_cast<char *>(eccParams.base.algName.c_str());

    if (eccParams.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccCommonParamsSpec.field->fieldType = const_cast<char *>(eccParams.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp*>(eccCommonParamsSpec.field);
        fieldFp->base.fieldType = const_cast<char *>(eccParams.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        fieldFp->p.data = eccParams.field.get_ECFIELDFP_ref().p.data();
        fieldFp->p.len = eccParams.field.get_ECFIELDFP_ref().p.size();
    }
    eccCommonParamsSpec.a.data = eccParams.a.data();
    eccCommonParamsSpec.a.len = eccParams.a.size();
    eccCommonParamsSpec.b.data = eccParams.b.data();
    eccCommonParamsSpec.b.len = eccParams.b.size();
    eccCommonParamsSpec.g.x.data = eccParams.g.x.data();
    eccCommonParamsSpec.g.x.len = eccParams.g.x.size();
    eccCommonParamsSpec.g.y.data = eccParams.g.y.data();
    eccCommonParamsSpec.g.y.len = eccParams.g.y.size();
    eccCommonParamsSpec.n.data = eccParams.n.data();
    eccCommonParamsSpec.n.len = eccParams.n.size();
    eccCommonParamsSpec.h = eccParams.h;
}

void SetRSAKeyPairParamsSpecAttribute(RSAKeyPairSpec const& rsaParams, HcfRsaKeyPairParamsSpec &rsaKeyPairSpec)
{
    rsaKeyPairSpec.base.base.specType = HCF_KEY_PAIR_SPEC;
    rsaKeyPairSpec.base.base.algName = const_cast<char *>(rsaParams.base.algName.c_str());
    rsaKeyPairSpec.base.n.data = rsaParams.params.n.data();
    rsaKeyPairSpec.base.n.len = rsaParams.params.n.size();
    rsaKeyPairSpec.pk.data = rsaParams.pk.data();
    rsaKeyPairSpec.pk.len = rsaParams.pk.size();
    rsaKeyPairSpec.sk.data = rsaParams.sk.data();
    rsaKeyPairSpec.sk.len = rsaParams.sk.size();
}

void SetRSAPubKeyParamsSpecAttribute(RSAPubKeySpec const& rsaParams, HcfRsaPubKeyParamsSpec &rsaPubKeySpec)
{
    rsaPubKeySpec.base.base.specType = HCF_PUBLIC_KEY_SPEC;
    rsaPubKeySpec.base.base.algName = const_cast<char *>(rsaParams.base.algName.c_str());
    rsaPubKeySpec.base.n.data = rsaParams.params.n.data();
    rsaPubKeySpec.base.n.len = rsaParams.params.n.size();
    rsaPubKeySpec.pk.data = rsaParams.pk.data();
    rsaPubKeySpec.pk.len = rsaParams.pk.size();
}

void SetRSACommonParamsSpecAttribute(RSACommonParamsSpec const& rsaParams, HcfRsaCommParamsSpec &rsaCommonParamsSpec)
{
    rsaCommonParamsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    rsaCommonParamsSpec.base.algName = const_cast<char *>(rsaParams.base.algName.c_str());
    rsaCommonParamsSpec.n.data = rsaParams.n.data();
    rsaCommonParamsSpec.n.len = rsaParams.n.size();
}

void SetEd25519KeyPairParamsSpecAttribute(ED25519KeyPairSpec const& ed25519Params,
    HcfAlg25519KeyPairParamsSpec &ed25519KeyPairSpec)
{
    ed25519KeyPairSpec.base.specType = HCF_KEY_PAIR_SPEC;
    ed25519KeyPairSpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ed25519KeyPairSpec.pk.data = ed25519Params.pk.data();
    ed25519KeyPairSpec.pk.len = ed25519Params.pk.size();
    ed25519KeyPairSpec.sk.data = ed25519Params.sk.data();
    ed25519KeyPairSpec.sk.len = ed25519Params.sk.size();
}

void SetEd25519PubKeyParamsSpecAttribute(ED25519PubKeySpec const& ed25519Params,
    HcfAlg25519PubKeyParamsSpec &ed25519PubKeySpec)
{
    ed25519PubKeySpec.base.specType = HCF_PUBLIC_KEY_SPEC;
    ed25519PubKeySpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ed25519PubKeySpec.pk.data = ed25519Params.pk.data();
    ed25519PubKeySpec.pk.len = ed25519Params.pk.size();
}

void SetEd25519PriKeyParamsSpecAttribute(ED25519PriKeySpec const& ed25519Params,
    HcfAlg25519PriKeyParamsSpec &ed25519PriKeySpec)
{
    ed25519PriKeySpec.base.specType = HCF_PRIVATE_KEY_SPEC;
    ed25519PriKeySpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ed25519PriKeySpec.sk.data = ed25519Params.sk.data();
    ed25519PriKeySpec.sk.len = ed25519Params.sk.size();
}

void SetX25519KeyPairParamsSpecAttribute(X25519KeyPairSpec const& x25519Params,
    HcfAlg25519KeyPairParamsSpec &x25519KeyPairSpec)
{
    x25519KeyPairSpec.base.specType = HCF_KEY_PAIR_SPEC;
    x25519KeyPairSpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    x25519KeyPairSpec.pk.data = x25519Params.pk.data();
    x25519KeyPairSpec.pk.len = x25519Params.pk.size();
    x25519KeyPairSpec.sk.data = x25519Params.sk.data();
    x25519KeyPairSpec.sk.len = x25519Params.sk.size();
}

void SetX25519PubKeyParamsSpecAttribute(X25519PubKeySpec const& x25519Params,
    HcfAlg25519PubKeyParamsSpec &x25519PubKeySpec)
{
    x25519PubKeySpec.base.specType = HCF_PUBLIC_KEY_SPEC;
    x25519PubKeySpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    x25519PubKeySpec.pk.data = x25519Params.pk.data();
    x25519PubKeySpec.pk.len = x25519Params.pk.size();
}

void SetX25519PriKeyParamsSpecAttribute(X25519PriKeySpec const& x25519Params,
    HcfAlg25519PriKeyParamsSpec &x25519PriKeySpec)
{
    x25519PriKeySpec.base.specType = HCF_PRIVATE_KEY_SPEC;
    x25519PriKeySpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    x25519PriKeySpec.sk.data = x25519Params.sk.data();
    x25519PriKeySpec.sk.len = x25519Params.sk.size();
}

void SetDhKeyPairParamsSpecAttribute(DHKeyPairSpec const& dhParams, HcfDhKeyPairParamsSpec &dhKeyPairSpec)
{
    dhKeyPairSpec.base.base.specType = HCF_KEY_PAIR_SPEC;
    dhKeyPairSpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhKeyPairSpec.base.p.data = dhParams.params.p.data();
    dhKeyPairSpec.base.p.len = dhParams.params.p.size();
    dhKeyPairSpec.base.g.data = dhParams.params.g.data();
    dhKeyPairSpec.base.g.len = dhParams.params.g.size();
    dhKeyPairSpec.base.length = dhParams.params.l;
    dhKeyPairSpec.pk.data = dhParams.pk.data();
    dhKeyPairSpec.pk.len = dhParams.pk.size();
    dhKeyPairSpec.sk.data = dhParams.sk.data();
    dhKeyPairSpec.sk.len = dhParams.sk.size();
}

void SetDhPubKeyParamsSpecAttribute(DHPubKeySpec const& dhParams, HcfDhPubKeyParamsSpec &dhPubKeySpec)
{
    dhPubKeySpec.base.base.specType = HCF_PUBLIC_KEY_SPEC;
    dhPubKeySpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhPubKeySpec.base.p.data = dhParams.params.p.data();
    dhPubKeySpec.base.p.len = dhParams.params.p.size();
    dhPubKeySpec.base.g.data = dhParams.params.g.data();
    dhPubKeySpec.base.g.len = dhParams.params.g.size();
    dhPubKeySpec.base.length = dhParams.params.l;
    dhPubKeySpec.pk.data = dhParams.pk.data();
    dhPubKeySpec.pk.len = dhParams.pk.size();
}

void SetDhPriKeyParamsSpecAttribute(DHPriKeySpec const& dhParams, HcfDhPriKeyParamsSpec &dhPriKeySpec)
{
    dhPriKeySpec.base.base.specType = HCF_PRIVATE_KEY_SPEC;
    dhPriKeySpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhPriKeySpec.base.p.data = dhParams.params.p.data();
    dhPriKeySpec.base.p.len = dhParams.params.p.size();
    dhPriKeySpec.base.g.data = dhParams.params.g.data();
    dhPriKeySpec.base.g.len = dhParams.params.g.size();
    dhPriKeySpec.base.length = dhParams.params.l;
    dhPriKeySpec.sk.data = dhParams.sk.data();
    dhPriKeySpec.sk.len = dhParams.sk.size();
}

void SetDhCommonParamsSpecAttribute(DHCommonParamsSpec const& dhParams, HcfDhCommParamsSpec &dhCommonParamsSpec)
{
    dhCommonParamsSpec.base.specType = HCF_COMMON_PARAMS_SPEC;
    dhCommonParamsSpec.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhCommonParamsSpec.p.data = dhParams.p.data();
    dhCommonParamsSpec.p.len = dhParams.p.size();
    dhCommonParamsSpec.g.data = dhParams.g.data();
    dhCommonParamsSpec.g.len = dhParams.g.size();
    dhCommonParamsSpec.length = dhParams.l;
}

static HcfAsyKeyParamsSpec* CreateDSASpec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfDsaKeyPairParamsSpec dsaKeyPairSpec = {};
    static HcfDsaPubKeyParamsSpec dsaPubKeySpec = {};
    static HcfDsaCommParamsSpec dsaCommonParamsSpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSAKEYPAIRSPEC) {
        SetDSAKeyPairParamsSpecAttribute(asyKeySpec.get_DSAKEYPAIRSPEC_ref(), dsaKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&dsaKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSAPUBKEYSPEC) {
        SetDSAPubKeyParamsSpecAttribute(asyKeySpec.get_DSAPUBKEYSPEC_ref(), dsaPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&dsaPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSACOMMONPARAMSSPEC) {
        SetDSACommonParamsSpecAttribute(asyKeySpec.get_DSACOMMONPARAMSSPEC_ref(), dsaCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&dsaCommonParamsSpec);
    }
    return nullptr;
}

static HcfAsyKeyParamsSpec* CreateECCSpec(OptAsyKeySpec const& asyKeySpec)
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
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&eccKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCPUBKEYSPEC) {
        eccPubKeySpec.base.field = ecField;
        SetECCPubKeyParamsSpecAttribute(asyKeySpec.get_ECCPUBKEYSPEC_ref(), eccPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&eccPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCPRIKEYSPEC) {
        eccPriKeySpec.base.field = ecField;
        SetECCPriKeyParamsSpecAttribute(asyKeySpec.get_ECCPRIKEYSPEC_ref(), eccPriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&eccPriKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCCOMMONPARAMSSPEC) {
        eccCommonParamsSpec.field = ecField;
        SetECCCommonParamsSpecAttribute(asyKeySpec.get_ECCCOMMONPARAMSSPEC_ref(), eccCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&eccCommonParamsSpec);
    }
    return nullptr;
}

static HcfAsyKeyParamsSpec* CreateRSASpec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfRsaKeyPairParamsSpec rsaKeyPairSpec = {};
    static HcfRsaPubKeyParamsSpec rsaPubKeySpec = {};
    static HcfRsaCommParamsSpec rsaCommonParamsSpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSAKEYPAIRSPEC) {
        SetRSAKeyPairParamsSpecAttribute(asyKeySpec.get_RSAKEYPAIRSPEC_ref(), rsaKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&rsaKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSAPUBKEYSPEC) {
        SetRSAPubKeyParamsSpecAttribute(asyKeySpec.get_RSAPUBKEYSPEC_ref(), rsaPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&rsaPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSACOMMONPARAMSSPEC) {
        SetRSACommonParamsSpecAttribute(asyKeySpec.get_RSACOMMONPARAMSSPEC_ref(), rsaCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&rsaCommonParamsSpec);
    }
    return nullptr;
}

static HcfAsyKeyParamsSpec* CreateEd25519Spec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfAlg25519KeyPairParamsSpec ed25519KeyPairSpec = {};
    static HcfAlg25519PubKeyParamsSpec ed25519PubKeySpec = {};
    static HcfAlg25519PriKeyParamsSpec ed25519PriKeySpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519KEYPAIRSPEC) {
        SetEd25519KeyPairParamsSpecAttribute(asyKeySpec.get_ED25519KEYPAIRSPEC_ref(), ed25519KeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&ed25519KeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519PUBKEYSPEC) {
        SetEd25519PubKeyParamsSpecAttribute(asyKeySpec.get_ED25519PUBKEYSPEC_ref(), ed25519PubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&ed25519PubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519PRIKEYSPEC) {
        SetEd25519PriKeyParamsSpecAttribute(asyKeySpec.get_ED25519PRIKEYSPEC_ref(), ed25519PriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&ed25519PriKeySpec);
    }
    return nullptr;
}

static HcfAsyKeyParamsSpec* CreateX25519Spec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfAlg25519KeyPairParamsSpec x25519KeyPairSpec = {};
    static HcfAlg25519PubKeyParamsSpec x25519PubKeySpec = {};
    static HcfAlg25519PriKeyParamsSpec x25519PriKeySpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519KEYPAIRSPEC) {
        SetX25519KeyPairParamsSpecAttribute(asyKeySpec.get_X25519KEYPAIRSPEC_ref(), x25519KeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&x25519KeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519PUBKEYSPEC) {
        SetX25519PubKeyParamsSpecAttribute(asyKeySpec.get_X25519PUBKEYSPEC_ref(), x25519PubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&x25519PubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519PRIKEYSPEC) {
        SetX25519PriKeyParamsSpecAttribute(asyKeySpec.get_X25519PRIKEYSPEC_ref(), x25519PriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&x25519PriKeySpec);
    }
    return nullptr;
}

static HcfAsyKeyParamsSpec* CreateDHSpec(OptAsyKeySpec const& asyKeySpec)
{
    static HcfDhKeyPairParamsSpec dhKeyPairSpec = {};
    static HcfDhPubKeyParamsSpec dhPubKeySpec = {};
    static HcfDhPriKeyParamsSpec dhPriKeySpec = {};
    static HcfDhCommParamsSpec dhCommonParamsSpec = {};

    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHKEYPAIRSPEC) {
        SetDhKeyPairParamsSpecAttribute(asyKeySpec.get_DHKEYPAIRSPEC_ref(), dhKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&dhKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHPUBKEYSPEC) {
        SetDhPubKeyParamsSpecAttribute(asyKeySpec.get_DHPUBKEYSPEC_ref(), dhPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&dhPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHPRIKEYSPEC) {
        SetDhPriKeyParamsSpecAttribute(asyKeySpec.get_DHPRIKEYSPEC_ref(), dhPriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&dhPriKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHCOMMONPARAMSSPEC) {
        SetDhCommonParamsSpecAttribute(asyKeySpec.get_DHCOMMONPARAMSSPEC_ref(), dhCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec*>(&dhCommonParamsSpec);
    }
    return nullptr;
}

static HcfAsyKeyParamsSpec* CreateSpec(OptAsyKeySpec const& asyKeySpec, const std::string& algName)
{
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
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfResult result = this->generator_->generateKeyPair(this->generator_, &keyPair);
    if (result != HCF_SUCCESS) {
        ANI_LOGE_THROW(result, "generateKeyPair failed");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}

PriKey AsyKeyGeneratorBySpecImpl::GeneratePriKeySync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return make_holder<PriKeyImpl, PriKey>();
    }
    HcfPriKey *priKey = nullptr;
    HcfResult result = this->generator_->generatePriKey(this->generator_, &priKey);
    if (result != HCF_SUCCESS) {
        ANI_LOGE_THROW(result, "generatePriKey failed");
        return make_holder<PriKeyImpl, PriKey>();
    }
    return make_holder<PriKeyImpl, PriKey>(priKey);
}

PubKey AsyKeyGeneratorBySpecImpl::GeneratePubKeySync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return make_holder<PubKeyImpl, PubKey>();
    }
    HcfPubKey *pubKey = nullptr;
    HcfResult result = this->generator_->generatePubKey(this->generator_, &pubKey);
    if (result != HCF_SUCCESS) {
        ANI_LOGE_THROW(result, "generatePubKey failed");
        return make_holder<PubKeyImpl, PubKey>();
    }
    return make_holder<PubKeyImpl, PubKey>(pubKey);
}

string AsyKeyGeneratorBySpecImpl::GetAlgName()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "generator obj is nullptr!");
        return "";
    }
    const char *algName = this->generator_->getAlgName(this->generator_);
    return (algName == nullptr) ? "" : string(algName);
}

AsyKeyGeneratorBySpec CreateAsyKeyGeneratorBySpec(OptAsyKeySpec const& asyKeySpec)
{
    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    const std::string &algName = asyKeySpec.get_ASYKEYSPEC_ref().algName.c_str();

    HcfAsyKeyParamsSpec *spec = CreateSpec(asyKeySpec, algName);
    if (spec == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "Unsupported algorithm or key type");
        return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>();
    }

    HcfResult result = HcfAsyKeyGeneratorBySpecCreate(spec, &generator);
    if (result != HCF_SUCCESS) {
        ANI_LOGE_THROW(result, "HcfAsyKeyGeneratorBySpecCreate failed");
        return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>();
    }
    return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>(generator);
}
} // namespace ANI::CryptoFramework
// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateAsyKeyGeneratorBySpec(CreateAsyKeyGeneratorBySpec);
// NOLINTEND
