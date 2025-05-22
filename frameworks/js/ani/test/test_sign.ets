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

function sign(algName: string, priKey: cryptoFramework.PriKey,
  input1: cryptoFramework.DataBlob, input2: cryptoFramework.DataBlob) {
  let signer = cryptoFramework.createSign(algName);
  signer.initSync(priKey);
  signer.updateSync(input1);
  let signData = signer.signSync(input2);
  console.log("sign algName: " + signer.algName);
  return signData;
}

function verify(algName: string, pubKey: cryptoFramework.PubKey, signData: cryptoFramework.DataBlob,
  input1: cryptoFramework.DataBlob, input2: cryptoFramework.DataBlob) {
  let verifier = cryptoFramework.createVerify(algName);
  verifier.initSync(pubKey);
  verifier.updateSync(input1);
  let res = verifier.verifySync(input2, signData);
  console.log("verify algName: " + verifier.algName);
  return res;
}

function testSignSync() {
  try {
    let algName = "SM2_256|SM3";
    let str1 = "This is Sign test plan1";
    let str2 = "This is Sign test plan2";
    let input1: cryptoFramework.DataBlob = {
      data: utils.stringToUint8Array(str1)
    };
    let input2: cryptoFramework.DataBlob = {
      data: utils.stringToUint8Array(str2)
    };
    let generator = cryptoFramework.createAsyKeyGenerator("SM2_256");
    console.log("AsyKeyGenerator algName: " + generator.algName);
    let keyPair = generator.generateKeyPairSync();
    let signData = sign(algName, keyPair.priKey, input1, input2);
    let res = verify(algName, keyPair.pubKey, signData, input1, input2);
    if (res === true) {
      console.log('Sign success');
    } else {
      console.error('Sign failed');
    }
  } catch (err: BusinessError) {
    console.error(`[error] Sign: ${err.code} ${err.message}`);
  }
}

function testSignSpec() {
  try {
    let signer = cryptoFramework.createSign("RSA|PSS|SHA256|MGF1_SHA256");
    signer.setSignSpec(cryptoFramework.SignSpecItem.PSS_SALT_LEN_NUM, 32);
    let saltLen = signer.getSignSpec(cryptoFramework.SignSpecItem.PSS_SALT_LEN_NUM);
    let mdName = signer.getSignSpec(cryptoFramework.SignSpecItem.PSS_MD_NAME_STR);
    let mgfName = signer.getSignSpec(cryptoFramework.SignSpecItem.PSS_MGF_NAME_STR);
    console.log("SignSpec saltLen: " + saltLen);
    console.log("SignSpec mdName: " + mdName);
    console.log("SignSpec mgfName: " + mgfName);
  } catch (err: BusinessError) {
    console.error(`[error] SignSpec: ${err.code} ${err.message}`);
  }
}

export function testSign() {
  console.log(">>>>>>>>>>>>>>>>>>>> SignSync");
  testSignSync();
  console.log(">>>>>>>>>>>>>>>>>>>> SignSpec");
  testSignSpec();
}
