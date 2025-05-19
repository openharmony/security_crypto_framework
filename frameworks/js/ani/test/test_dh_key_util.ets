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

function testGenDHCommonParamsSpec() {
  try {
    let spec = cryptoFramework.DHKeyUtil.genDHCommonParamsSpec(2048, 1024);
    console.log("DHKeyUtil.genDHCommonParamsSpec:");
    console.log("DHCommonParamsSpec spec.algName: " + spec.algName);
    console.log("DHCommonParamsSpec spec.specType: " + spec.specType);
    console.log("DHCommonParamsSpec spec.p: " + spec.p);
    console.log("DHCommonParamsSpec spec.g: " + spec.g);
    console.log("DHCommonParamsSpec spec.l: " + spec.l);
  } catch (err: BusinessError) {
    console.error(`[error] DHKeyUtil.genDHCommonParamsSpec: ${err.code} ${err.message}`);
  }
}

export function testDHKeyUtil() {
  console.log(">>>>>>>>>>>>>>>>>>>> GenDHCommonParamsSpec");
  testGenDHCommonParamsSpec();
}
