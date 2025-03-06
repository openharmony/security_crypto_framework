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

import { cryptoFramework } from "../ets/cryptoframework_ani";

function hexStrToUint8Array(hexStr: string): Uint8Array {
    if (hexStr.length % 2 !== 0) {
        throw new Error("Invalid hex string");
    }
    const array = new Uint8Array(hexStr.length / 2);
    for (let i = 0; i < hexStr.length; i += 2) {
        array[i / 2] = parseInt(hexStr.substring(i, i + 2), 16);
    }
    return array;
}

function stringToUint8Array(str: string): Uint8Array {
    const array = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        array[i] = str.charCodeAt(i);
    }
    return array;
}

function uint8ArrayToHexStr(array: Uint8Array): string {
    let hexStr = '';
    for (let i = 0; i < array.length; i++) {
        let num: Number = new Number(array[i])
        hexStr += num.toString(16).padStart(2, '0');
    }
    return hexStr;
}

function main() {
    let key = "1234567890";
    let data = "Hello World";
    let keyBytes = hexStrToUint8Array(key);
    let dataBytes = stringToUint8Array(data);

    let obj = new cryptoFramework();
    let generator = obj.createSymKeyGenerator("HMAC");
    let symKey = generator.convertKeySync(keyBytes);

    let mac = obj.createMac("SHA256");
    mac.initSync(symKey);
    mac.updateSync(dataBytes);
    let output = mac.doFinalSync();
    let str = uint8ArrayToHexStr(output);
    console.log("[arkts] HMAC-SHA256: " + str);
    // HMAC-SHA256: 610654DF0F74D94B02EBCAB2CF6A0D190B0E889F0777AC63C803C60CBC0AB935
}
