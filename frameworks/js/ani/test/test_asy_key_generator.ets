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

function testAsyKeyGeneratorSync() {
  try {
    let generator = cryptoFramework.createAsyKeyGenerator('RSA1024|PRIMES_2');
    let keyPair = generator.generateKeyPairSync();
    let pubKey = keyPair.pubKey;
    let priKey = keyPair.priKey;
    let pkBlob = pubKey.getEncoded();
    let skBlob = priKey.getEncoded();
    let pkStr = utils.uint8ArrayToHexStr(pkBlob.data);
    let skStr = utils.uint8ArrayToHexStr(skBlob.data);
    console.log("AsyKeyGenerator algName: " + generator.algName);
    console.log('generateKeyPair pubKey: ' + pkStr);
    console.log('generateKeyPair priKey: ' + skStr);
    priKey.clearMem();
  } catch (err: BusinessError) {
    console.error(`[error] generateKeyPair: ${err.code} ${err.message}`);
  }
}

function testAsyKeyConvertKeySync() {
  try {
    let pubKeyArray = new Uint8Array([
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
      0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x2D, 0x03, 0x42, 0x00, 0x04, 0x5A, 0x03, 0x3A, 0x9D, 0xBE,
      0xF8, 0x4C, 0x07, 0x84, 0xC8, 0x97, 0xD0, 0x70, 0xE6, 0x60, 0x8C, 0x5A, 0xEE, 0xD3, 0x9B, 0x80,
      0x6D, 0xF8, 0x28, 0x53, 0xD6, 0x4E, 0x2A, 0x68, 0x6A, 0x37, 0x94, 0xF9, 0x23, 0x3D, 0x20, 0xDD,
      0x87, 0x8F, 0x64, 0x2D, 0x61, 0xC2, 0xB0, 0x34, 0x49, 0x88, 0xAE, 0x28, 0x46, 0x46, 0x22, 0x67,
      0x67, 0xA1, 0x63, 0x1B, 0xBB, 0x0D, 0xBB, 0x6D, 0xF4, 0x0D, 0x07
    ]);
    let priKeyArray = new Uint8Array([
      0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, 0x36, 0x29, 0xEF, 0xF0, 0x3F, 0xBC, 0x86, 0x71, 0x1F,
      0x66, 0x95, 0xCB, 0xF5, 0x59, 0x0F, 0x0F, 0x2F, 0xCA, 0xAA, 0x3C, 0x26, 0x9A, 0x1C, 0xA9, 0xBD,
      0x64, 0xFB, 0x4C, 0x70, 0xDF, 0x9C, 0x9F, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55,
      0x01, 0x82, 0x2D
    ]);
    let pubKeyBlob: cryptoFramework.DataBlob = {
      data: pubKeyArray
    };
    let priKeyBlob: cryptoFramework.DataBlob = {
      data: priKeyArray
    };
    let generator = cryptoFramework.createAsyKeyGenerator('SM2_256');
    let keyPair = generator.convertKeySync(pubKeyBlob, priKeyBlob);
    let pubKey = keyPair.pubKey;
    let priKey = keyPair.priKey;
    let pkBlob = pubKey.getEncoded();
    let skBlob = priKey.getEncoded();
    let pkStr = utils.uint8ArrayToHexStr(pkBlob.data);
    let skStr = utils.uint8ArrayToHexStr(skBlob.data);
    console.log("AsyKeyGenerator algName: " + generator.algName);
    console.log('convertKey pubKey: ' + pkStr);
    console.log('convertKey priKey: ' + skStr);
    priKey.clearMem();
  } catch (err: BusinessError) {
    console.error(`[error] convertKey: ${err.code} ${err.message}`);
  }
}

function testConvertPemKeySync() {
  try {
    let priKeyPkcs1Str1024: string =
        "-----BEGIN RSA PRIVATE KEY-----\n"
      + "MIICXQIBAAKBgQCwIN3mr21+N96ToxnVnaS+xyK9cNRAHiHGgrbjHw6RAj3V+l+W\n"
      + "Y68IhIe3DudVlzE9oMjeOQwkMkq//HCxNlIlFR6O6pa0mrXSwPRE7YKG97CeKk2g\n"
      + "YOS8YEh8toAvm7xKbiLkXuuMlxrjP2j/mb5iI/UASFSPZiQ/IyxDr0AQaQIDAQAB\n"
      + "AoGAEvBFzBNa+7J4PXnRQlYEK/tvsd0bBZX33ceacMubHl6WVZbphltLq+fMTBPP\n"
      + "LjXmtpC+aJ7Lvmyl+wTi/TsxE9vxW5JnbuRT48rnZ/Xwq0eozDeEeIBRrpsr7Rvr\n"
      + "7ctrgzr4m4yMHq9aDgpxj8IR7oHkfwnmWr0wM3FuiVlj650CQQDineeNZ1hUTkj4\n"
      + "D3O+iCi3mxEVEeJrpqrmSFolRMb+iozrIRKuJlgcOs+Gqi2fHfOTTL7LkpYe8SVg\n"
      + "e3JxUdVLAkEAxvcZXk+byMFoetrnlcMR13VHUpoVeoV9qkv6CAWLlbMdgf7uKmgp\n"
      + "a1Yp3QPDNQQqkPvrqtfR19JWZ4uy1qREmwJALTU3BjyBoH/liqb6fh4HkWk75Som\n"
      + "MzeSjFIOubSYxhq5tgZpBZjcpvUMhV7Zrw54kwASZ+YcUJvmyvKViAm9NQJBAKF7\n"
      + "DyXSKrem8Ws0m1ybM7HQx5As6l3EVhePDmDQT1eyRbKp+xaD74nkJpnwYdB3jyyY\n"
      + "qc7A1tj5J5NmeEFolR0CQQCn76Xp8HCjGgLHw9vg7YyIL28y/XyfFyaZAzzK+Yia\n"
      + "akNwQ6NeGtXSsuGCcyyfpacHp9xy8qXQNKSkw03/5vDO\n"
      + "-----END RSA PRIVATE KEY-----\n";
    let publicPkcs1Str1024: string  =
        "-----BEGIN RSA PUBLIC KEY-----\n"
      + "MIGJAoGBALAg3eavbX433pOjGdWdpL7HIr1w1EAeIcaCtuMfDpECPdX6X5ZjrwiE\n"
      + "h7cO51WXMT2gyN45DCQySr/8cLE2UiUVHo7qlrSatdLA9ETtgob3sJ4qTaBg5Lxg\n"
      + "SHy2gC+bvEpuIuRe64yXGuM/aP+ZvmIj9QBIVI9mJD8jLEOvQBBpAgMBAAE=\n"
      + "-----END RSA PUBLIC KEY-----\n";
    let generator = cryptoFramework.createAsyKeyGenerator('RSA1024');
    let keyPair = generator.convertPemKeySync(publicPkcs1Str1024, priKeyPkcs1Str1024);
    let pubKey = keyPair.pubKey;
    let priKey = keyPair.priKey;
    let pkStr = pubKey.getEncodedPem('X509');
    let skStr = priKey.getEncodedPem('PKCS8');
    console.log("AsyKeyGenerator algName: " + generator.algName);
    console.log('convertPemKey pubKey: ' + pkStr);
    console.log('convertPemKey priKey: ' + skStr);
    priKey.clearMem();
  } catch (err: BusinessError) {
    console.error(`[error] convertPemKey: ${err.code} ${err.message}`);
  }
}

// ERROR: TypeError: Cannot find type 'AsyKeySpecItem'.
/*
function showEccSpecDetailInfo(keyName: string, key: cryptoFramework.PubKey | cryptoFramework.PriKey) {
  console.log('showEccSpecDetailInfo ' + keyName + ':');
  let a = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_A_BN);
  console.log('a: ' + a);
  let b = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_B_BN);
  console.log('b: ' + b);
  let gX = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_G_X_BN);
  console.log('gX: ' + gX);
  let gY = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_G_Y_BN);
  console.log('gY: ' + gY);
  let n = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_N_BN);
  console.log('n: ' + n);
  let h = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_H_NUM);
  console.log('h: ' + h);
  let fieldType = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_FIELD_TYPE_STR);
  console.log('fieldType: ' + fieldType);
  let fieldSize = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_FIELD_SIZE_NUM);
  console.log('fieldSize: ' + fieldSize);
  let curveName = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_CURVE_NAME_STR);
  console.log('curveName: ' + curveName);
  if (keyName === 'pubKey') {
    let pkX = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_PK_X_BN);
    console.log('pkX: ' + pkX);
    let pkY = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_PK_Y_BN);
    console.log('pkY: ' + pkY);
  } else if (keyName === 'priKey') {
    let sk = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_SK_BN);
    console.log('sk: ' + sk);
  }
}
*/

function showPubKeyEccSpecDetailInfo(key: cryptoFramework.PubKey) {
  console.log('showPubKeyEccSpecDetailInfo:');
  let a = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_A_BN);
  console.log('a: ' + a);
  let b = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_B_BN);
  console.log('b: ' + b);
  let gX = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_G_X_BN);
  console.log('gX: ' + gX);
  let gY = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_G_Y_BN);
  console.log('gY: ' + gY);
  let n = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_N_BN);
  console.log('n: ' + n);
  let h = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_H_NUM);
  console.log('h: ' + h);
  let fieldType = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_FIELD_TYPE_STR);
  console.log('fieldType: ' + fieldType);
  let fieldSize = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_FIELD_SIZE_NUM);
  console.log('fieldSize: ' + fieldSize);
  let curveName = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_CURVE_NAME_STR);
  console.log('curveName: ' + curveName);
  let pkX = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_PK_X_BN);
  console.log('pkX: ' + pkX);
  let pkY = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_PK_Y_BN);
  console.log('pkY: ' + pkY);
}

function showPriKeyEccSpecDetailInfo(key: cryptoFramework.PriKey) {
  console.log('showPriKeyEccSpecDetailInfo:');
  let a = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_A_BN);
  console.log('a: ' + a);
  let b = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_B_BN);
  console.log('b: ' + b);
  let gX = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_G_X_BN);
  console.log('gX: ' + gX);
  let gY = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_G_Y_BN);
  console.log('gY: ' + gY);
  let n = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_N_BN);
  console.log('n: ' + n);
  let h = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_H_NUM);
  console.log('h: ' + h);
  let fieldType = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_FIELD_TYPE_STR);
  console.log('fieldType: ' + fieldType);
  let fieldSize = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_FIELD_SIZE_NUM);
  console.log('fieldSize: ' + fieldSize);
  let curveName = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_CURVE_NAME_STR);
  console.log('curveName: ' + curveName);
  let sk = key.getAsyKeySpec(cryptoFramework.AsyKeySpecItem.ECC_SK_BN);
  console.log('sk: ' + sk);
}

function testAsyKeySpec() {
  try {
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
    let generator = cryptoFramework.createAsyKeyGeneratorBySpec(eccCommonSpec);
    let keyPair = generator.generateKeyPairSync();
    let pubKey = keyPair.pubKey;
    let priKey = keyPair.priKey;
    showPubKeyEccSpecDetailInfo(pubKey);
    showPriKeyEccSpecDetailInfo(priKey);
  } catch (err: BusinessError) {
    console.error(`[error] AsyKeySpec: ${err.code} ${err.message}`);
  }
}

export function testAsyKeyGenerator() {
  console.log(">>>>>>>>>>>>>>>>>>>> AsyKeyGeneratorSync");
  testAsyKeyGeneratorSync();
  console.log(">>>>>>>>>>>>>>>>>>>> AsyKeyConvertKeySync");
  testAsyKeyConvertKeySync();
  console.log(">>>>>>>>>>>>>>>>>>>> AsyKeyConvertPemKeySync");
  testConvertPemKeySync();
  console.log(">>>>>>>>>>>>>>>>>>>> AsyKeySpec");
  testAsyKeySpec();
}
