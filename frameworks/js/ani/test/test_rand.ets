
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

function testRandomSync() {
  try {
    let data = "Hello World";
    let dataBytes = utils.stringToUint8Array(data);
    let random = cryptoFramework.createRandom();
    random.setSeed({
      data: dataBytes
    });
    let output = random.generateRandomSync(16);
    let str = utils.uint8ArrayToHexStr(output.data);
    console.log("Random: " + str);
  } catch (err) {
    console.error("[error] Random: " + err);
  }
}

export function testRandom() {
  console.log(">>>>>>>>>>>>>>>>>>>> RandomSync");
  testRandomSync();
}
