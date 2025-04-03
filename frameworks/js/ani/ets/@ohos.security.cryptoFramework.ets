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

namespace cryptoFramework {
  loadLibrary("crypto_framework_ani.z");
  native function createSymKeyGenerator(algName: string): SymKeyGenerator;
  native function createMac(algName: string): Mac;

  interface DataBlob {
    data: Uint8Array;
  }

  interface SymKey {
  }

  interface SymKeyGenerator {
    convertKeySync(key: DataBlob): SymKey;
  }

  interface Mac {
    initSync(key: SymKey): void;
    updateSync(input: DataBlob): void;
    doFinalSync(): DataBlob;
  }

  class DataBlobInner implements DataBlob {
    data: Uint8Array;
    constructor(obj: Uint8Array) {
      this.data = obj;
    }
  }

  class SymKeyInner implements SymKey {
    private symKey: long;
    constructor(obj: long) {
      this.symKey = obj;
    }
  }

  class SymKeyGeneratorInner implements SymKeyGenerator {
    native convertKeySync(data: DataBlob): SymKey;

    private generator: long;
    constructor(obj: long) {
      this.generator = obj;
    }
  }

  class MacInner implements Mac {
    native initSync(key: SymKey): void;
    native updateSync(input: DataBlob): void;
    native doFinalSync(): DataBlob;

    private macObj: long;
    constructor(obj: long) {
      this.macObj = obj;
    }
  }
}

export default cryptoFramework;
