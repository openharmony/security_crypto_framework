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
    let pkBlob = keyPair.pubKey.getEncoded();
    let skBlob = keyPair.priKey.getEncoded();
    let pkStr = utils.uint8ArrayToHexStr(pkBlob.data);
    let skStr = utils.uint8ArrayToHexStr(skBlob.data);
    console.info('generateKeyPair pubKey: ' + pkStr);
    console.info('generateKeyPair priKey: ' + skStr);
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
    let pkBlob = keyPair.pubKey.getEncoded();
    let skBlob = keyPair.priKey.getEncoded();
    let pkStr = utils.uint8ArrayToHexStr(pkBlob.data);
    let skStr = utils.uint8ArrayToHexStr(skBlob.data);
    console.log("AsyKeyGenerator algName: " + generator.algName);
    console.info('convertPemKey pubKey: ' + pkStr);
    console.info('convertPemKey priKey: ' + skStr);
  } catch (err: BusinessError) {
    console.error(`[error] convertPemKey: ${err.code} ${err.message}`);
  }
}

export function testAsyKeyGenerator() {
  console.log(">>>>>>>>>>>>>>>>>>>> AsyKeyGeneratorSync");
  testAsyKeyGeneratorSync();
  console.log(">>>>>>>>>>>>>>>>>>>> AsyKeyConvertKeySync");
  testAsyKeyConvertKeySync();
}
