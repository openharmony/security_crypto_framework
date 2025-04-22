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

function testMacSync() {
  try {
    let key = "1234567890";
    let data = "Hello World";
    let keyBytes = utils.hexStrToUint8Array(key);
    let dataBytes = utils.stringToUint8Array(data);
    let generator = cryptoFramework.createSymKeyGenerator("HMAC");
    let symKey = generator.convertKeySync({
      data: keyBytes
    });
    let mac = cryptoFramework.createMac("SHA256");
    mac.initSync(symKey);
    mac.updateSync({
      data: dataBytes
    });
    let output = mac.doFinalSync();
    let str = utils.uint8ArrayToHexStr(output.data);
    console.log("HMAC algName: " + mac.algName);
    console.log("HMAC-SHA256: " + str);
  }
  catch (err) {
    console.error("[error] HMAC-SHA256: " + err);
  }
}

function testMacAsync() {
  try {
    let key = "1234567890";
    let data = "Hello World";
    let keyBytes = utils.hexStrToUint8Array(key);
    let dataBytes = utils.stringToUint8Array(data);;
    let generator = cryptoFramework.createSymKeyGenerator("HMAC");
    let symKey = await generator.convertKey({
      data: keyBytes
    });
    let mac = cryptoFramework.createMac("SHA256");
    await mac.init(symKey);
    await mac.update({
      data: dataBytes
    });
    let output = await mac.doFinal();
    let str = utils.uint8ArrayToHexStr(output.data);
    console.log("HMAC algName: " + mac.algName);
    console.log("HMAC-SHA256: " + str);
  }
  catch (err) {
    console.error("[error] HMAC-SHA256: " + err);
  }
}

export function testMac() {
  console.log(">>>>>>>>>>>>>>>>>>>> MacSync");
  testMacSync();
  console.log(">>>>>>>>>>>>>>>>>>>> MacAsync");
  testMacAsync();
}
