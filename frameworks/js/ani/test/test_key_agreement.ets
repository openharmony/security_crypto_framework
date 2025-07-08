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

function testKeyAgreementSync()
{
  try {
    let pubKeyArray = new Uint8Array([
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
      0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x53, 0x60, 0x8E, 0x09, 0x56,
      0xD6, 0x7E, 0x6A, 0xF7, 0xE9, 0x5C, 0x7D, 0x04, 0x80, 0x8A, 0x69, 0xF6, 0xA2, 0xD7, 0x47, 0x51,
      0x3A, 0xCA, 0x79, 0x1A, 0x69, 0xD3, 0x37, 0x82, 0x2D, 0xEC, 0x8F, 0x37, 0x10, 0xF8, 0x4B, 0xA7,
      0xA0, 0xA7, 0x6A, 0x02, 0x98, 0xF3, 0x2C, 0x44, 0x42, 0x00, 0xA7, 0x63, 0x5C, 0xEB, 0xD7, 0x9F,
      0xEF, 0x1C, 0x6A, 0x7C, 0xAB, 0x22, 0x91, 0x7C, 0xAE, 0x39, 0x5C
    ]);
    let priKeyArray = new Uint8Array([
      0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, 0x73, 0x38, 0x89, 0x23, 0xCF, 0x00, 0x3C, 0xBF, 0x5A,
      0x3D, 0x88, 0x69, 0xD2, 0x10, 0x1B, 0x04, 0xAB, 0x39, 0x0A, 0x3D, 0x7B, 0x28, 0xBD, 0x1C, 0x22,
      0xCF, 0xEC, 0x16, 0x2D, 0xDF, 0x0A, 0xBD, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
      0x03, 0x01, 0x07
    ]);
    let generator = cryptoFramework.createAsyKeyGenerator('ECC256');
    let keyPairA = generator.convertKeySync({ data: pubKeyArray }, { data: priKeyArray });
    let keyPairB = generator.generateKeyPairSync();
    let keyAgreement = cryptoFramework.createKeyAgreement('ECC256');
    console.println("KeyAgreement algName: " + keyAgreement.algName);
    let secret1 = keyAgreement.generateSecretSync(keyPairA.priKey, keyPairB.pubKey);
    let secret2 = keyAgreement.generateSecretSync(keyPairB.priKey, keyPairA.pubKey);
    if (secret1.data.toString() === secret2.data.toString()) {
      console.println('KeyAgreement ecdh result success');
      console.println('KeyAgreement ecdh secret.data: ' + utils.uint8ArrayToHexStr(secret1.data));
    } else {
      console.println('KeyAgreement ecdh result failed');
    }
  } catch (err: BusinessError) {
    console.println(`[error] KeyAgreement: ${err.code} ${err.message}`);
  }
}

export function testKeyAgreement()
{
  console.println(">>>>>>>>>>>>>>>>>>>> KeyAgreementSync");
  testKeyAgreementSync();
}
