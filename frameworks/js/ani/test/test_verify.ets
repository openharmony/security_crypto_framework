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

import cryptoFramework from "@ohos.security.cryptoFramework";
import utils from "./test_utils";

function testVerifySync() {
  try {
    let keyGenAlg = "SM2_256";
    let pubKeyArray =
      new Uint8Array([48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 129, 28, 207, 85, 1, 130, 45, 3, 66,
        0, 4, 90, 3, 58, 157, 190, 248, 76, 7, 132, 200, 151, 208, 112, 230, 96, 140, 90, 238, 211, 155, 128, 109, 248,
        40, 83, 214, 78, 42, 104, 106, 55, 148, 249, 35, 61, 32, 221, 135, 143, 100, 45, 97, 194, 176, 52, 73, 136, 174,
        40, 70, 70, 34, 103, 103, 161, 99, 27, 187, 13, 187, 109, 244, 13, 7]);
    let priKeyArray =
      new Uint8Array([48, 49, 2, 1, 1, 4, 32, 54, 41, 239, 240, 63, 188, 134, 113, 31, 102, 149, 203, 245, 89, 15, 15,
        47, 202, 170, 60, 38, 154, 28, 169, 189, 100, 251, 76, 112, 223, 156, 159, 160, 10, 6, 8, 42, 129, 28, 207, 85,
        1, 130, 45]);
    let pubKeyBlob: cryptoFramework.DataBlob = {
      data: pubKeyArray
    };
    let priKeyBlob: cryptoFramework.DataBlob = {
      data: priKeyArray
    };
    let generator = cryptoFramework.createAsyKeyGenerator(keyGenAlg);
    let keyPair = generator.convertKeySync(pubKeyBlob, priKeyBlob);
    let signData = 
      new Uint8Array([48, 69, 2, 32, 97, 0, 41, 250, 12, 72, 62, 173, 60, 144, 101, 117, 249, 72, 50, 121, 191, 216,
        82, 82, 195, 87, 92, 109, 197, 93, 104, 15, 195, 247, 20, 85, 2, 33, 0, 164, 22, 34, 175, 112, 161, 170, 50,
        165, 253, 248, 248, 121, 16, 83, 214, 68, 188, 158, 130, 54, 89, 250, 143, 31, 226, 26, 121, 162, 153, 102, 28])
    let signDataBytes: cryptoFramework.DataBlob = {
      data: signData
    };

    let input = new Uint8Array([72,101,108,108,111,32,87,111,114,108,100]);
    let inputData: cryptoFramework.DataBlob = {
      data: input
    };
    let verify = cryptoFramework.createVerify("SM2_256|SM3");
    verify.initSync(keyPair.pubKey);
    verify.updateSync(inputData);
    let res = verify.verifySync(null, signDataBytes)
    if (res === true) {
        console.info('verify success');
    } else {
      console.error('verify failed');
    }
  } catch (err) {
    console.log("[error] verify: " + err);
  }
}

export function testVerify() {
  console.log(">>>>>>>>>>>>>>>>>>>> VerifySync");
  testVerifySync();
}
