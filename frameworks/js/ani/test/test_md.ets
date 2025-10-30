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

function testMdSync() {
  try {
    let data = "Hello World";
    let dataBytes = utils.stringToUint8Array(data);
    let md = cryptoFramework.createMd("MD5");
    md.updateSync({
      data: dataBytes
    });
    let output = md.digestSync();
    let str = utils.uint8ArrayToHexStr(output.data);
    console.println("MD5 algName: " + md.algName);
    console.println("MD5: " + str);
    let length = md.getMdLength();
    console.println("MD5 length: " + length);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println(`[error] MD5: ${err.code} ${err.message}`);
  }
}

function testMdAsync() {
  try {
    let data = "Hello World";
    let dataBytes = utils.stringToUint8Array(data);
    let md = cryptoFramework.createMd("MD5");
    await md.update({
      data: dataBytes
    });
    let output = await md.digest();
    let str = utils.uint8ArrayToHexStr(output.data);
    console.println("MD5: " + str);
    let length = md.getMdLength();
    console.println("MD5 length: " + length);
  } catch (err) {
    if (!(err instanceof BusinessError)) {
      throw err;
    }
    console.println(`[error] MD5: ${err.code} ${err.message}`);
  }
}

export function testMd() {
  console.println(">>>>>>>>>>>>>>>>>>>> MdSync");
  testMdSync();
  console.println(">>>>>>>>>>>>>>>>>>>> MdAsync");
  testMdAsync();
}
