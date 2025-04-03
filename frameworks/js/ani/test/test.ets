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

// import buffer from "@ohos.buffer"
import cryptoFramework from "@ohos.security.cryptoFramework";

function hexStrToUint8Array(data: string): Uint8Array {
  // return new Uint8Array(buffer.from(data, 'hex').buffer);
  if (data.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const array = new Uint8Array(data.length / 2);
  for (let i = 0; i < data.length; i += 2) {
    array[i / 2] = parseInt(data.substring(i, i + 2), 16);
  }
  return array;
}

function stringToUint8Array(str: string): Uint8Array {
  // return new Uint8Array(buffer.from(str, 'utf-8').buffer);
  const array = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    array[i] = str.charCodeAt(i);
  }
  return array;
}

function uint8ArrayToHexStr(data: Uint8Array): string {
  // return buffer.from(data).toString('hex').toUpperCase();
  let str = '';
  for (let i = 0; i < data.length; i++) {
    let num: Number = new Number(data[i])
    str += num.toString(16).padStart(2, '0');
  }
  return str;
}

function main() {
  let key = "1234567890";
  let data = "Hello World";
  let keyAlgo = "HMAC";
  let macAlgo = "SHA256";
  let keyBytes = hexStrToUint8Array(key);
  let dataBytes = stringToUint8Array(data);
  let symKey = cryptoFramework.createSymKeyGenerator(keyAlgo).convertKeySync({
    data: keyBytes
  });
  let mac = cryptoFramework.createMac(macAlgo);
  mac.initSync(symKey);
  mac.updateSync({
    data: dataBytes
  });
  let output = mac.doFinalSync();
  let str = uint8ArrayToHexStr(output.data);
  console.log(keyAlgo + "-" + macAlgo + ": " + str);
  // HMAC-SHA256: 610654DF0F74D94B02EBCAB2CF6A0D190B0E889F0777AC63C803C60CBC0AB935
}
