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

function testGenCipherTextBySpec() {
  try {
    let spec: cryptoFramework.SM2CipherTextSpec = {
      xCoordinate: BigInt('20625015362595980457695435345498579729138244358573902431560627260141789922999'),
      yCoordinate: BigInt('48563164792857017065725892921053777369510340820930241057309844352421738767712'),
      cipherTextData: new Uint8Array([
        0x64, 0xE3, 0x4E, 0xC3, 0xF9, 0xB3, 0x2B, 0x46, 0xF2, 0x45, 0xA9, 0x0A, 0x41, 0x7B
      ]),
      hashData: new Uint8Array([
        0x57, 0xA7, 0xA7, 0xF7, 0x58, 0x92, 0xCB, 0xEA, 0x53, 0x7E, 0x75, 0x81, 0x34, 0x8E, 0x52, 0x36,
        0x98, 0xE2, 0xC9, 0x6F, 0x8F, 0x73, 0xA9, 0x7D, 0x80, 0x2A, 0x9D, 0x1F, 0x72, 0xC6, 0x6D, 0xF4
      ])
    }
    let cipherText = cryptoFramework.SM2CryptoUtil.genCipherTextBySpec(spec, 'C1C3C2');
    console.log("SM2CryptoUtil.genCipherTextBySpec:");
    console.log("CipherText cipherText.data: " + cipherText.data);
  }
  catch (err: BusinessError) {
    console.error(`[error] SM2CryptoUtil.genCipherTextBySpec: ${err.code} ${err.message}`);
  }
}

function testGetCipherTextSpec() {
  try {
    let cipherTextArray = new Uint8Array([
      0x30, 0x76, 0x02, 0x20, 0x2D, 0x99, 0x58, 0x52, 0x68, 0xDD, 0xE2, 0x2B, 0xAE, 0x15, 0x7A, 0xF8,
      0x05, 0xE8, 0x69, 0x29, 0x5C, 0x5F, 0x66, 0xE0, 0xD8, 0x95, 0x55, 0xEC, 0x6E, 0x06, 0x40, 0xBC,
      0x95, 0x46, 0x46, 0xB7, 0x02, 0x20, 0x6B, 0x5D, 0xC6, 0xF7, 0x77, 0x12, 0x28, 0x6E, 0x5A, 0x9C,
      0xC1, 0x9E, 0xCD, 0x71, 0xAA, 0x80, 0x92, 0x6D, 0x4B, 0x11, 0xB5, 0x6D, 0x6E, 0x5B, 0x95, 0x05,
      0x6E, 0xE9, 0xD1, 0x4E, 0xE5, 0x60, 0x04, 0x20, 0x57, 0xA7, 0xA7, 0xF7, 0x58, 0x92, 0xCB, 0xEA,
      0x53, 0x7E, 0x75, 0x81, 0x34, 0x8E, 0x52, 0x36, 0x98, 0xE2, 0xC9, 0x6F, 0x8F, 0x73, 0xA9, 0x7D,
      0x80, 0x2A, 0x9D, 0x1F, 0x72, 0xC6, 0x6D, 0xF4, 0x04, 0x0E, 0x64, 0xE3, 0x4E, 0xC3, 0xF9, 0xB3,
      0x2B, 0x46, 0xF2, 0x45, 0xA9, 0x0A, 0x41, 0x7B
    ]);
    let cipherText: cryptoFramework.DataBlob = {
      data: cipherTextArray
    };
    let spec: cryptoFramework.SM2CipherTextSpec = cryptoFramework.SM2CryptoUtil.getCipherTextSpec(cipherText, 'C1C3C2');
    console.log("SM2CryptoUtil.getCipherTextSpec:");
    console.log("SM2CipherTextSpec spec.xCoordinate: " + spec.xCoordinate);
    console.log("SM2CipherTextSpec spec.yCoordinate: " + spec.yCoordinate);
    console.log("SM2CipherTextSpec spec.cipherTextData: " + utils.uint8ArrayToHexStr(spec.cipherTextData));
    console.log("SM2CipherTextSpec spec.hashData: " + utils.uint8ArrayToHexStr(spec.hashData));
  }
  catch (err: BusinessError) {
    console.error(`[error] SM2CryptoUtil.getCipherTextSpec: ${err.code} ${err.message}`);
  }
}

export function testSM2CryptoUtil() {
  console.log(">>>>>>>>>>>>>>>>>>>> GenCipherTextBySpec");
  testGenCipherTextBySpec();
  console.log(">>>>>>>>>>>>>>>>>>>> GetCipherTextSpec");
  testGetCipherTextSpec();
}
