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

function generateRandom(len: int) {
  let rand = cryptoFramework.createRandom();
  let generater = rand.generateRandomSync(len);
  return generater;
}

function genSymKeyByData(symKeyData: Uint8Array) {
  let symKeyBlob: cryptoFramework.DataBlob = {
    data: symKeyData
  };
  let generator = cryptoFramework.createSymKeyGenerator('AES128');
  let symKey = generator.convertKeySync(symKeyBlob);
  return symKey;
}

function encrypt(algorithm: string, symKey: cryptoFramework.SymKey, data: cryptoFramework.DataBlob,
  params: cryptoFramework.GcmParamsSpec | cryptoFramework.CcmParamsSpec | cryptoFramework.IvParamsSpec | null
): cryptoFramework.DataBlob {
  let cipher = cryptoFramework.createCipher(algorithm);
  cipher.initSync(cryptoFramework.CryptoMode.ENCRYPT_MODE, symKey, params);
  if (algorithm.includes('GCM') || algorithm.includes('CCM')) {
    let encryptData = cipher.updateSync(data);
    if (algorithm.includes('GCM')) {
      (params as cryptoFramework.GcmParamsSpec).authTag = cipher.doFinalSync(null);
    } else if (algorithm.includes('CCM')) {
      (params as cryptoFramework.CcmParamsSpec).authTag = cipher.doFinalSync(null);
    }
    return encryptData;
  } else { // CBC/ECB
    return cipher.doFinalSync(data);
  }
}

function decrypt(algorithm: string, symKey: cryptoFramework.SymKey, data: cryptoFramework.DataBlob,
  params: cryptoFramework.GcmParamsSpec | cryptoFramework.CcmParamsSpec | cryptoFramework.IvParamsSpec | null
): cryptoFramework.DataBlob {
  let decoder = cryptoFramework.createCipher(algorithm);
  decoder.initSync(cryptoFramework.CryptoMode.DECRYPT_MODE, symKey, params);
  if (algorithm.includes('GCM')) {
    let decryptData = decoder.updateSync(data);
    decoder.doFinalSync(null);
    return decryptData;
  } else if (algorithm.includes('CCM')) {
    return decoder.doFinalSync(data);
  } else { // CBC/ECB
    return decoder.doFinalSync(data);
  }
}

function aesCipher(algorithm: string,
  params: cryptoFramework.GcmParamsSpec | cryptoFramework.CcmParamsSpec | cryptoFramework.IvParamsSpec | null) {
  try {
    let keyData = new Uint8Array([83, 217, 231, 76, 28, 113, 23, 219, 250, 71, 209, 210, 205, 97, 32, 159]);
    let symKey = genSymKeyByData(keyData);
    let message = "This is a test";
    let plainText: cryptoFramework.DataBlob = {
      data: utils.stringToUint8Array(message)
    };
    let encryptText = encrypt(algorithm, symKey, plainText, params);
    let decryptText = decrypt(algorithm, symKey, encryptText, params);
    if (plainText.data.toString() === decryptText.data.toString()) {
      console.info(`${algorithm} success`);
    } else {
      console.error(`${algorithm} failed`);
    }
  } catch (err) {
    console.error(`[error] ${algorithm}: ${err}`);
  }
}

function testAesGcmSync() {
  let params: cryptoFramework.GcmParamsSpec = {
    algName: "GcmParamsSpec",
    iv: generateRandom(12),
    aad: generateRandom(8),
    authTag: generateRandom(16),
  };
  aesCipher('AES128|GCM|PKCS7', params);
}

function testAesCcmSync() {
  let params: cryptoFramework.CcmParamsSpec = {
    algName: "CcmParamsSpec",
    iv: generateRandom(7),
    aad: generateRandom(8),
    authTag: generateRandom(12),
  };
  aesCipher('AES128|CCM', params);
}

function testAesCbcSync() {
  let params: cryptoFramework.IvParamsSpec = {
    algName: "IvParamsSpec",
    iv: generateRandom(16),
  };
  aesCipher('AES128|CBC|PKCS7', params);
}

function testAesEcbSync() {
  aesCipher('AES128|ECB|PKCS7', null);
}

export function testCipher() {
  console.log(">>>>>>>>>>>>>>>>>>>> AesGcmSync");
  testAesGcmSync();
  console.log(">>>>>>>>>>>>>>>>>>>> AesCcmSync");
  testAesCcmSync();
  console.log(">>>>>>>>>>>>>>>>>>>> AesCbcSync");
  testAesCbcSync();
  console.log(">>>>>>>>>>>>>>>>>>>> AesEcbSync");
  testAesEcbSync();
}
