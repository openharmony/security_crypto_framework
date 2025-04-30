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

import { testRandom } from "./test_rand";
import { testMd } from "./test_md";
import { testMac } from "./test_mac";
import { testKdf } from "./test_kdf";
import { testAsyKeyGenerator } from "./test_asy_key_generator";
import { testSymKeyGenerator } from "./test_sym_key_generator";
import { testCipher } from "./test_cipher";
import { testVerify } from "./test_verify";
import { testAsyKeyGeneratorBySpec } from "./test_asy_key_generator_by_spec";

function main() {
  testRandom();
  testMd();
  testMac();
  testKdf();
  testAsyKeyGenerator();
  testSymKeyGenerator();
  testCipher();
  testVerify();
  testAsyKeyGeneratorBySpec();
}
