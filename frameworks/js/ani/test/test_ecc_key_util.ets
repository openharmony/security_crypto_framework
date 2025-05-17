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

function testGenECCCommonParamsSpec() {
  try {
    let spec = cryptoFramework.ECCKeyUtil.genECCCommonParamsSpec('NID_brainpoolP256r1');
    let ecFiledFp = spec.field as cryptoFramework.ECFieldFp;
    console.log("ECCKeyUtil.genECCCommonParamsSpec:");
    console.log("ECCCommonParamsSpec spec.algName: " + spec.algName);
    console.log("ECCCommonParamsSpec spec.specType: " + spec.specType);
    console.log("ECCCommonParamsSpec spec.field.fieldType: " + ecFiledFp.fieldType);
    console.log("ECCCommonParamsSpec spec.field.p: " + ecFiledFp.p);
    console.log("ECCCommonParamsSpec spec.a: " + spec.a);
    console.log("ECCCommonParamsSpec spec.b: " + spec.b);
    console.log("ECCCommonParamsSpec spec.g.x: " + spec.g.x);
    console.log("ECCCommonParamsSpec spec.g.y: " + spec.g.y);
    console.log("ECCCommonParamsSpec spec.n: " + spec.n);
    console.log("ECCCommonParamsSpec spec.h: " + spec.h);
  } catch (err: BusinessError) {
    console.error(`[error] ECCKeyUtil.genECCCommonParamsSpec: ${err.code} ${err.message}`);
  }
}

function testConvertPoint() {
  try {
    let pkData = new Uint8Array([
      0x04, 0x8F, 0x27, 0x39, 0xF9, 0x91, 0x32, 0x3F, 0xDE, 0x23, 0x46, 0xB2, 0x79, 0xCA, 0x9A, 0x15,
      0x92, 0x81, 0x4B, 0x4C, 0x3F, 0x08, 0xC3, 0x9D, 0x6F, 0x28, 0xD9, 0xD7, 0x94, 0x78, 0xE0, 0xCD,
      0x52, 0x53, 0x5C, 0xB9, 0x15, 0xD3, 0xB8, 0x05, 0x13, 0x72, 0x21, 0x56, 0x55, 0xE4, 0x7B, 0xF2,
      0xCE, 0xC8, 0x62, 0xB2, 0xB8, 0x82, 0x23, 0xE8, 0x2D, 0x05, 0xCA, 0xBD, 0x0B, 0x2E, 0xA3, 0x9C,
      0x98
    ]);
    let point = cryptoFramework.ECCKeyUtil.convertPoint('NID_brainpoolP256r1', pkData);
    console.log("ECCKeyUtil.convertPoint:");
    console.log("Point point.x: " + point.x);
    console.log("Point point.y: " + point.y);
  } catch (err: BusinessError) {
    console.error(`[error] ECCKeyUtil.convertPoint: ${err.code} ${err.message}`);
  }
}

function testGetEncodedPoint() {
  try {
    let point: cryptoFramework.Point = {
      x: BigInt('64750044510792891439269945828433327517677381559622384455951527515863444933970'),
      y: BigInt('37705793773900352766227640862738381713868374157045352837992005507978837073048')
    };
    let encoded = cryptoFramework.ECCKeyUtil.getEncodedPoint('NID_brainpoolP256r1', point, 'COMPRESSED');
    console.log("ECCKeyUtil.getEncodedPoint:");
    console.log("Uint8Array encoded: " + encoded);
  } catch (err: BusinessError) {
    console.error(`[error] ECCKeyUtil.getEncodedPoint: ${err.code} ${err.message}`);
  }
}

export function testECCKeyUtil() {
  console.log(">>>>>>>>>>>>>>>>>>>> GenECCCommonParamsSpec");
  testGenECCCommonParamsSpec();
  console.log(">>>>>>>>>>>>>>>>>>>> ConvertPoint");
  testConvertPoint();
  console.log(">>>>>>>>>>>>>>>>>>>> GetEncodedPoint");
  testGetEncodedPoint();
}
