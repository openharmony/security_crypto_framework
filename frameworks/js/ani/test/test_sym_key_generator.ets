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

function testSymKeyGeneratorSync() {
  try {
    let generator = cryptoFramework.createSymKeyGenerator('SM4_128');
    let symKey = generator.generateSymKeySync();
    let encodedKey = symKey.getEncoded();
    let str = utils.uint8ArrayToHexStr(encodedKey.data);
    console.log("SymKeyGenerator algName: " + generator.algName);
    console.log("generateSymKey: " + str);
  } catch (err: BusinessError) {
    console.error(`[error] generateSymKey: ${err.code} ${err.message}`);
  }
}

function testSymKeyConvertKeySync() {
  try {
    let keyBlob: cryptoFramework.DataBlob = {
      data: utils.stringToUint8Array('12345678abcdefgh12345678abcdefgh12345678abcdefgh12345678abcdefgh')
    }
    let generator = cryptoFramework.createSymKeyGenerator('HMAC');
    let symKey = generator.convertKeySync(keyBlob);
    let encodedKey = symKey.getEncoded();
    let str = utils.uint8ArrayToHexStr(encodedKey.data);
    console.log("convertKey: " + str);
  } catch (err: BusinessError) {
    console.error(`[error] convertKey: ${err.code} ${err.message}`);
  }
}

export function testSymKeyGenerator() {
  console.log(">>>>>>>>>>>>>>>>>>>> SymKeyGeneratorSync");
  testSymKeyGeneratorSync();
  console.log(">>>>>>>>>>>>>>>>>>>> SymKeyConvertKeySync");
  testSymKeyConvertKeySync();
}
