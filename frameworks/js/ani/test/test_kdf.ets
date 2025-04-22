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

function testPBKDF2Sync() {
  try {
    let spec: cryptoFramework.PBKDF2Spec = {
      algName: 'PBKDF2',
      password: utils.stringToUint8Array("123456"),
      salt: utils.stringToUint8Array("0123456789"),
      iterations: 10000,
      keySize: 32,
    };
    let kdf = cryptoFramework.createKdf('PBKDF2|SHA256');
    let secret = kdf.generateSecretSync(spec);
    let str = utils.uint8ArrayToHexStr(secret.data);
    console.log("PBKDF2 algName: " + kdf.algName);
    console.info("PBKDF2: " + str);
  }
  catch (err) {
    console.error("[error] PBKDF2: " + err);
  }
}

function testHKDFSync() {
  try {
    let spec: cryptoFramework.HKDFSpec = {
      algName: 'HKDF',
      key: utils.stringToUint8Array("012345678901234567890123456789"),
      salt: utils.stringToUint8Array("0123456789"),
      info: utils.stringToUint8Array("infostring"),
      keySize: 32,
    };
    let kdf = cryptoFramework.createKdf('HKDF|SHA256|EXTRACT_AND_EXPAND');
    let secret = kdf.generateSecretSync(spec);
    let str = utils.uint8ArrayToHexStr(secret.data);
    console.log("HKDF algName: " + kdf.algName);
    console.info("HKDF: " + str);
  } catch (err) {
    console.error("[error] HKDF: " + err);
  }
}

function testScryptSync() {
  try {
    let spec: cryptoFramework.ScryptSpec = {
      algName: 'SCRYPT',
      passphrase: "123456",
      salt: utils.stringToUint8Array("0123456789"),
      n: 1024,
      p: 16,
      r: 8,
      maxMemory: 1024 * 16 * 8 * 10, // n * p * r * 10
      keySize: 64,
    };
    let kdf = cryptoFramework.createKdf('SCRYPT');
    let secret = kdf.generateSecretSync(spec);
    let str = utils.uint8ArrayToHexStr(secret.data);
    console.log("Scrypt algName: " + kdf.algName);
    console.info("Scrypt: " + str);
  } catch (err) {
    console.error("[error] Scrypt: " + err);
  }
}

export function testKdf() {
  console.log(">>>>>>>>>>>>>>>>>>>> PBKDF2Sync");
  testPBKDF2Sync();
  console.log(">>>>>>>>>>>>>>>>>>>> HKDFSync");
  testHKDFSync();
  console.log(">>>>>>>>>>>>>>>>>>>> ScryptSync");
  testScryptSync();
}
