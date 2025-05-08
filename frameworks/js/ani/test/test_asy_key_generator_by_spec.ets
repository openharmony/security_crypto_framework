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

import { BusinessError } from "@ohos.base";
import cryptoFramework from "@ohos.security.cryptoFramework";
import utils from "./test_utils";

function testRsaKeyPairSpec() {
  let rsaCommSpec: cryptoFramework.RSACommonParamsSpec = {
    n: BigInt('18478533428762900543234234052165078897463517255891144687945154912560048989428973394502225231475673469493935673076685067666412374336644121661834634328568716128398010589214210242328473325052801924104401463496007910632384934591085795699377924655299831802536043790200563589400549497200957189436092639854513167455276408048482654440065204807879459064738847828290321155399964745065695320081378543586408514487910074079683525564599260683751683646405712006009189387522266386739458730786983547267804377576955002031599762775938196698277063712871930011053484489532696001735479019329660933285131374020059017332898114690445944576549'),
    algName: "RSA",
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC,
  };
  let rsaKeyPairSpec: cryptoFramework.RSAKeyPairSpec = {
      params: rsaCommSpec,
      sk: BigInt('13443367797579784472906374191268730591149473415683261174245648123593551364374079107625793014808865760593273402148759743980757062361671347127799770055874205659183190363964544152829383091462724002309744989516180102276157076935260650085211862081846405192552335715817353665234496972306343601367818009443948359153845315745091050102576900263842800919302048139131982882174917741979278274761193212951786209086143141198926907682548667292864640458922412016755237410423934679056828519631212431348847746741608018079408263762113939943821319770453677716209206087481504965313847534151150635490465180371871825563931626039033876425137'),
      pk: BigInt('65537'),
      algName: "RSA",
      specType: cryptoFramework.AsyKeySpecType.KEY_PAIR_SPEC,
  };
  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(rsaKeyPairSpec);
    let keyPair = generatorBySpec.generateKeyPairSync();
    if (keyPair !== null) {
      console.info('get rsa key pair result success!');
    } else {
      console.error('get rsa key pair result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testRsaKeyPairSpec: ${err.code} ${err.message}`);
  }
}

function testRsaPubKeySpec() {
  try {
    let nIn = BigInt('18478533428762900543234234052165078897463517255891144687945154912560048989428973394502225231475673469493935673076685067666412374336644121661834634328568716128398010589214210242328473325052801924104401463496007910632384934591085795699377924655299831802536043790200563589400549497200957189436092639854513167455276408048482654440065204807879459064738847828290321155399964745065695320081378543586408514487910074079683525564599260683751683646405712006009189387522266386739458730786983547267804377576955002031599762775938196698277063712871930011053484489532696001735479019329660933285131374020059017332898114690445944576549');
    let eIn = BigInt('65537');
    let rsaCommSpec: cryptoFramework.RSACommonParamsSpec = {
    n: nIn,
    algName: 'RSA',
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC
    };
    let rsaPubKeySpec: cryptoFramework.RSAPubKeySpec = {
        params: rsaCommSpec,
        pk: eIn,
        algName: 'RSA',
        specType: cryptoFramework.AsyKeySpecType.PUBLIC_KEY_SPEC
    };
    let rsaGeneratorSpec = cryptoFramework.createAsyKeyGeneratorBySpec(rsaPubKeySpec);
    let pubKey = rsaGeneratorSpec.generatePubKeySync();
    if (pubKey !== null) {
      console.info('get rsa pub key result success!');
    } else {
      console.error('get rsa pub key result fail!');
    }

  } catch (err: BusinessError) {
    console.error(`[error] testRsaPubKeySpec: ${err.code} ${err.message}`);
  }
}

function testEccCommonSpec() {
  let fieldFp: cryptoFramework.ECFieldFp = {
    fieldType: 'Fp',
    p: BigInt('26959946667150639794667015087019630673557916260026308143510066298881')
  }
  let G: cryptoFramework.Point = {
    x: BigInt('19277929113566293071110308034699488026831934219452440156649784352033'),
    y: BigInt('19926808758034470970197974370888749184205991990603949537637343198772')
  }
  let eccCommonSpec: cryptoFramework.ECCCommonParamsSpec = {
    algName: 'ECC',
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC,
    field: fieldFp,
    a: BigInt('26959946667150639794667015087019630673557916260026308143510066298878'),
    b: BigInt('18958286285566608000408668544493926415504680968679321075787234672564'),
    g: G,
    n: BigInt('26959946667150639794667015087019625940457807714424391721682722368061'),
    h: 1
  }
  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(eccCommonSpec);
    let keyPair = generatorBySpec.generateKeyPairSync(); // Generate an ECC key pair.
    if (keyPair !== null) {
      console.info('get key pair result success!');
    } else {
      console.error('get key pair result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testEccCommonSpec: ${err.code} ${err.message}`);
  }
}

function genEccPriKeySpec(xIn: bigint, yIn: bigint, aIn: bigint, bIn: bigint, pIn: bigint,
  nIn: bigint, skIn: bigint): cryptoFramework.ECCPriKeySpec {
  let field: cryptoFramework.ECFieldFp = {
    fieldType: "Fp",
    p: pIn
  };
  let g: cryptoFramework.Point = {
    x: xIn,
    y: yIn
  };
  let params: cryptoFramework.ECCCommonParamsSpec = {
    field: field,
    a: aIn,
    b: bIn,
    g: g,
    n: nIn,
    h: 1,
    algName: "ECC",
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC
  };

  let eccPriKeySpec: cryptoFramework.ECCPriKeySpec = {
    params: params,
    sk: skIn,
    algName: "ECC",
    specType: cryptoFramework.AsyKeySpecType.PRIVATE_KEY_SPEC
  }

  return eccPriKeySpec;
}

function testEccPriKeySpec() {
  try {
    let a: bigint = BigInt('26959946667150639794667015087019630673557916260026308143510066298878');
    let b: bigint = BigInt('18958286285566608000408668544493926415504680968679321075787234672564');
    let p: bigint = BigInt('26959946667150639794667015087019630673557916260026308143510066298881');
    let gX: bigint = BigInt('19277929113566293071110308034699488026831934219452440156649784352033');
    let gY: bigint = BigInt('19926808758034470970197974370888749184205991990603949537637343198772');
    let n: bigint = BigInt('26959946667150639794667015087019625940457807714424391721682722368061');
    let sk: bigint = BigInt('5958211279885070464920675858557961186290168537951857871398143937432');
    let eccPriKeySpec: cryptoFramework.ECCPriKeySpec = genEccPriKeySpec(gX, gY, a, b, p, n, sk);
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(eccPriKeySpec);
    let priKey = generatorBySpec.generatePriKeySync();
    if (priKey !== null) {
      console.info('get pri key result success!');
    } else {
      console.error('get pri key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testEccPriKeySpec: ${err.code} ${err.message}`);
  }
}

function testSm2KeyPairSpec() {
  let fieldFp: cryptoFramework.ECFieldFp = {
    fieldType: 'Fp',
    p: BigInt('115792089210356248756420345214020892766250353991924191454421193933289684991999')
  }
  let G: cryptoFramework.Point = {
    x: BigInt('22963146547237050559479531362550074578802567295341616970375194840604139615431'),
    y: BigInt('85132369209828568825618990617112496413088388631904505083283536607588877201568')
  };
  let sm2CommonParamsSpec: cryptoFramework.ECCCommonParamsSpec = {
    algName: 'SM2',
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC,
    field: fieldFp,
    a: BigInt('115792089210356248756420345214020892766250353991924191454421193933289684991996'),
    b: BigInt('18505919022281880113072981827955639221458448578012075254857346196103069175443'),
    g: G,
    n: BigInt('115792089210356248756420345214020892766061623724957744567843809356293439045923'),
    h: 1
  };
  let sm2KeyPairSpec: cryptoFramework.ECCKeyPairSpec = {
    algName: "SM2",
    specType: cryptoFramework.AsyKeySpecType.KEY_PAIR_SPEC,
    params: sm2CommonParamsSpec,
    sk: BigInt('44865034034753528279576865928075303946258226058363947036220155068824166297716'),
    pk: {
      x: BigInt('47018839338924435050110785031351759007822306695053504711021879526595239871172'),
      y: BigInt('96133091491756192384849037905113087024675932328759814704074462890629083635825')
    },
  };
  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(sm2KeyPairSpec);
    let keyPair = generatorBySpec.generateKeyPairSync();
    if (keyPair !== null) {
      console.info('get key pair result success!');
    } else {
      console.error('get key pair result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testSm2AsyKeyGeneratorBySpecSync: ${err.code} ${err.message}`);
  }
}

function getDsaCommonParamsSpec() {
  let dsaCommonSpec: cryptoFramework.DSACommonParamsSpec = {
    algName: "DSA",
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC,
    p: BigInt('20216857044408199932376494764599580727974045843915439721502938327198864725169044809813204952147752413624701213316563574475039748055346468178028625826092035313601316397655587341814674633664886284528623285325653023780498382484985239780177599233965758919159102159171718273864148712746797113414042595739717319731696609579150841956081703573371531465350272238016149836326224001841088360384367898447054044508716751610019070103182911963258176168025828573385356097755187338108832184592810352254309012721096301415240345204182050921863355546837078288047550266434252240460770780823402663658159753063957196734025229736568089530267'),
    q: BigInt("867213547744821940284222002039163947454712583963"),
    g: BigInt('5613702672530613039214328932450936898231965110898797142283557379865685939526291625923546497805448201404435739446597666135884235480978009652818140400499199787725528596067079382996609708472937555140407402057536621734502472274147757401975812355605352555485852816071445663853971471514294654628089019755771069636793509413303062371896404562622361502073164175883230960631373093173990688756272270068057277748993274083763062285503458176853646465605466871218985585055660513268314836972803355963121806305145618647016398490455324285041057243421484005529145312291069828934043829252492089834817718429184649225777566648238469211448'),
  }
  return dsaCommonSpec;
}

function testDsaKeyPairSpec() {
  let dsaCommonSpec = getDsaCommonParamsSpec();
  let dsaKeyPairSpec: cryptoFramework.DSAKeyPairSpec = {
    algName: "DSA",
    specType: cryptoFramework.AsyKeySpecType.KEY_PAIR_SPEC,
    params: dsaCommonSpec,
    sk: BigInt("287759317661555678461170451498783134028435263911"),
    pk: BigInt('2974320683131303383593011718103778438067248821010128068603330890682877434550441281827351603361334506610914048116228047158214093207291532728181748676811787843316027859373324322706845202765204260289964362553170484033902517855022371250354897430992714094652148720967777508481265194493537489752556929433399052957551421373353304195295773950194626096020536543310165869112300390873999312126377909122302697760566740696966174036865456319235321580616931347110147760623816495949862659419251353007558185295016129505360845025009080058771674461404631229857893492589646335484050582997233310521320078311463229120799046072712830367694'),
  };
  try {
    let asyKeyPairSpec = cryptoFramework.createAsyKeyGeneratorBySpec(dsaKeyPairSpec);
    let keyPair = asyKeyPairSpec.generateKeyPairSync();
    if (keyPair !== null) {
      console.info('get key pair result success!');
    } else {
      console.error('get key pair result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] getDsaCommonParamsSpec: ${err.code} ${err.message}`);
  }
}

function testDsaPubKeySpec() {
  let dsaCommonSpec = getDsaCommonParamsSpec();
  let dsaPubKeySpec: cryptoFramework.DSAPubKeySpec = {
    algName: "DSA",
    specType: cryptoFramework.AsyKeySpecType.PUBLIC_KEY_SPEC,
    params: dsaCommonSpec,
    pk: BigInt('2974320683131303383593011718103778438067248821010128068603330890682877434550441281827351603361334506610914048116228047158214093207291532728181748676811787843316027859373324322706845202765204260289964362553170484033902517855022371250354897430992714094652148720967777508481265194493537489752556929433399052957551421373353304195295773950194626096020536543310165869112300390873999312126377909122302697760566740696966174036865456319235321580616931347110147760623816495949862659419251353007558185295016129505360845025009080058771674461404631229857893492589646335484050582997233310521320078311463229120799046072712830367694'),
  };
  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(dsaPubKeySpec);
    let pubKey = generatorBySpec.generatePubKeySync();
    if (pubKey !== null) {
      console.info('get pub key result success!');
    } else {
      console.error('get pub key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testDsaPubKeySpec: ${err.code} ${err.message}`);
  }
}

function testX25519Keypair() {
  let X25519CommonParamsSpec: cryptoFramework.X25519KeyPairSpec = {
    algName: 'X25519',
    specType: cryptoFramework.AsyKeySpecType.KEY_PAIR_SPEC,
    sk: BigInt("29134879258262849023515049744816060961199782584720683500454612335506387469072"),
    pk: BigInt("31365230504828109670384793213724615431161708201306102578527937807624152602700")
  };

  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(X25519CommonParamsSpec);
    let keyPair = generatorBySpec.generateKeyPairSync();
    if (keyPair !== null) {
      console.info('get key pair result success!');
      let pkBlob = keyPair.pubKey.getEncoded();
      let skBlob = keyPair.priKey.getEncoded();
      let pkStr = utils.uint8ArrayToHexStr(pkBlob.data);
      let skStr = utils.uint8ArrayToHexStr(skBlob.data);
      console.info('pub key: ' + pkStr);
      console.info('pri key: ' + skStr);
    } else {
      console.error('get key pair result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testX25519Keypair: ${err.code} ${err.message}`);
  }
}

function testX25519PubKeySpec() {
  let X25519CommonParamsSpec: cryptoFramework.X25519PubKeySpec = {
    algName: 'X25519',
    specType: cryptoFramework.AsyKeySpecType.PUBLIC_KEY_SPEC,
    pk: BigInt("31365230504828109670384793213724615431161708201306102578527937807624152602700")
  };

  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(X25519CommonParamsSpec);
    let pubKey = generatorBySpec.generatePubKeySync();
    if (pubKey !== null) {
      console.info('get pub key result success!');
    } else {
      console.error('get pub key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testX25519PubKeySpec: ${err.code} ${err.message}`);
  }
}

function testX25519PriKeySpec() {
  let X25519CommonParamsSpec: cryptoFramework.X25519PriKeySpec = {
    algName: 'X25519',
    specType: cryptoFramework.AsyKeySpecType.PRIVATE_KEY_SPEC,
    sk: BigInt("29134879258262849023515049744816060961199782584720683500454612335506387469072")
  };

  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(X25519CommonParamsSpec);
    let priKey = generatorBySpec.generatePriKeySync();
    if (priKey !== null) {
      console.info('get pri key result success!');
    } else {
      console.error('get pri key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testX25519PriKeySpec: ${err.code} ${err.message}`);
  }
}

function testEd25519Keypair() {
  let ed25519CommonParamsSpec: cryptoFramework.ED25519KeyPairSpec = {
    algName: 'Ed25519',
    specType: cryptoFramework.AsyKeySpecType.KEY_PAIR_SPEC,
    sk: BigInt("43647624700350065415986689228612485845309737963740022737531181108678917972381"),
    pk: BigInt("11904025543770991234575058927481377460341025403748801838533672290029823089367")
  };

  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(ed25519CommonParamsSpec);
    let keyPair = generatorBySpec.generateKeyPairSync();
    if (keyPair !== null) {
      console.info('get key pair result success!');
    } else {
      console.error('get key pair result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testEd25519Keypair: ${err.code} ${err.message}`);
  }
}

function testEd25519PubKeySpec() {
  let ed25519CommonParamsSpec: cryptoFramework.ED25519PubKeySpec = {
    algName: 'Ed25519',
    specType: cryptoFramework.AsyKeySpecType.PUBLIC_KEY_SPEC,
    pk: BigInt("11904025543770991234575058927481377460341025403748801838533672290029823089367")
  };

  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(ed25519CommonParamsSpec);
    let pubKey = generatorBySpec.generatePubKeySync();
    if (pubKey !== null) {
      console.info('get pub key result success!');
    } else {
      console.error('get pub key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testEd25519PubKeySpec: ${err.code} ${err.message}`);
  }
}

function testEd25519PriKeySpec() {
  let ed25519CommonParamsSpec: cryptoFramework.ED25519PriKeySpec = {
    algName: 'Ed25519',
    specType: cryptoFramework.AsyKeySpecType.PRIVATE_KEY_SPEC,
    sk: BigInt("43647624700350065415986689228612485845309737963740022737531181108678917972381")
  };

  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(ed25519CommonParamsSpec);
    let priKey = generatorBySpec.generatePriKeySync();
    if (priKey !== null) {
      console.info('get pri key result success!');
    } else {
      console.error('get pri key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testEd25519PriKeySpec: ${err.code} ${err.message}`);
  }
}

function testDhKeyPairSpec() {
  let dhCommonParamsSpec: cryptoFramework.DHCommonParamsSpec = {
    algName: "DH",
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC,
    p: BigInt("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559"),
    g: BigInt("2"),
    l: 0
  }
  let dhKeyPairSpec: cryptoFramework.DHKeyPairSpec = {
    algName: "DH",
    specType: cryptoFramework.AsyKeySpecType.KEY_PAIR_SPEC,
    params: dhCommonParamsSpec,
    sk: BigInt("9125804188382698099196638873877782224672995953990412992193262858452"),
    pk: BigInt("11186379976064470039868881878113769238712700906887300917098479964653512172113576763135554305151065797508933293770633594570926859095962764040640418979407741972148004696002324963207972460619492683808125462174028180856400991828519744547190389466471420338820024463169406721124154332160520586677979673497445849107467994302619965190756490288108819919869861215042849364387924978117630413281355079408669272089515824403370917658313427949840680278654651434802556809089942821560326598440829155965101298935067032294104326983788672385588749202093591460978545538061369828131252628133733300047966728872928488819485461523493709658652"),
  }
  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(dhKeyPairSpec);
    let keyPair = generatorBySpec.generateKeyPairSync();
    if (keyPair !== null) {
      console.info('get key pair result success!');
    } else {
      console.error('get key pair result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testDhKeyPairSpec: ${err.code} ${err.message}`);
  }
}

function testDhPubKeySpec() {
  let dhCommonParamsSpec: cryptoFramework.DHCommonParamsSpec = {
    algName: "DH",
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC,
    p: BigInt("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559"),
    g: BigInt("2"),
    l: 0
  }
  let dhPubKeySpec: cryptoFramework.DHPubKeySpec = {
    algName: "DH",
    specType: cryptoFramework.AsyKeySpecType.PUBLIC_KEY_SPEC,
    params: dhCommonParamsSpec,
    pk: BigInt("11186379976064470039868881878113769238712700906887300917098479964653512172113576763135554305151065797508933293770633594570926859095962764040640418979407741972148004696002324963207972460619492683808125462174028180856400991828519744547190389466471420338820024463169406721124154332160520586677979673497445849107467994302619965190756490288108819919869861215042849364387924978117630413281355079408669272089515824403370917658313427949840680278654651434802556809089942821560326598440829155965101298935067032294104326983788672385588749202093591460978545538061369828131252628133733300047966728872928488819485461523493709658652"),
  }
  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(dhPubKeySpec);
    let pubKey = generatorBySpec.generatePubKeySync();
    if (pubKey !== null) {
      console.info('get pub key result success!');
    } else {
      console.error('get pub key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testDhPubKeySpec: ${err.code} ${err.message}`);
  }
}

function testDhPriKeySpec() {
  let dhCommonParamsSpec: cryptoFramework.DHCommonParamsSpec = {
    algName: "DH",
    specType: cryptoFramework.AsyKeySpecType.COMMON_PARAMS_SPEC,
    p: BigInt("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559"),
    g: BigInt("2"),
    l: 0
  }
  let dhPriKeySpec: cryptoFramework.DHPriKeySpec = {
    algName: "DH",
    specType: cryptoFramework.AsyKeySpecType.PRIVATE_KEY_SPEC,
    params: dhCommonParamsSpec,
    sk: BigInt("9125804188382698099196638873877782224672995953990412992193262858452"),
  }
  try {
    let generatorBySpec = cryptoFramework.createAsyKeyGeneratorBySpec(dhPriKeySpec);
    let priKey = generatorBySpec.generatePriKeySync();
    if (priKey !== null) {
      console.info('get pri key result success!');
    } else {
      console.error('get pri key result fail!');
    }
  } catch (err: BusinessError) {
    console.error(`[error] testDhPriKeySpec: ${err.code} ${err.message}`);
  }
}

export function testAsyKeyGeneratorBySpec() {
  console.log(">>>>>>>>>>>>>>>>>>>> EccCommonSpec");
  testEccCommonSpec();
  console.log(">>>>>>>>>>>>>>>>>>>> EccPriKeySpec");
  testEccPriKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> Sm2KeyPairSpec");
  testSm2KeyPairSpec();
  console.log(">>>>>>>>>>>>>>>>>>>> DsaKeyPairSpec");
  testDsaKeyPairSpec();
  console.log(">>>>>>>>>>>>>>>>>>>> DsaPubKeySpec");
  testDsaPubKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> RsaKeyPairSpec");
  testRsaKeyPairSpec();
  console.log(">>>>>>>>>>>>>>>>>>>> RsaPubKeySpec");
  testRsaPubKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> X25519Keypair");
  testX25519Keypair();
  console.log(">>>>>>>>>>>>>>>>>>>> X25519PubKeySpec");
  testX25519PubKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> X25519PriKeySpec");
  testX25519PriKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> Ed25519Keypair");
  testEd25519Keypair();
  console.log(">>>>>>>>>>>>>>>>>>>> Ed25519PubKeySpec");
  testEd25519PubKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> Ed25519PriKeySpec");
  testEd25519PriKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> DhKeyPairSpec");
  testDhKeyPairSpec();
  console.log(">>>>>>>>>>>>>>>>>>>> DhPubKeySpec");
  testDhPubKeySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> DhPriKeySpec");
  testDhPriKeySpec();
}
