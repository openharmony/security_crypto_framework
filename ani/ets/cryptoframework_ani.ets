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

interface SymKey {
}

interface SymKeyGenerator {
    convertKeySync(data: Uint8Array): SymKey;
}

interface Mac {
    initSync(key: SymKey): void;
    updateSync(input: Uint8Array): void;
    doFinalSync(): Uint8Array;
}

class SymKeyInner implements SymKey {
    private symKey: long = 0;
    constructor(obj: long) {
        if(this.symKey == 0){
             this.symKey = obj;
        }
    }
}

class SymKeyGeneratorInner implements SymKeyGenerator {
    native convertKeySync(data: Uint8Array): SymKey;

    private generator: long = 0;
    constructor(obj: long) {
        if(this.generator == 0){
             this.generator = obj;
        }
    }
}

class MacInner implements Mac {
    native initSync(key: SymKey): void;
    native updateSync(input: Uint8Array): void;
    native doFinalSync(): Uint8Array;

    private macObj: long = 0;
    constructor(obj: long) {
        if(this.macObj == 0){
             this.macObj = obj;
        }
    }
}

export class cryptoFramework {
    static { loadLibrary("crypto_framework_ani.z"); }
    native createSymKeyGenerator(algName: string): SymKeyGenerator;
    native createMac(algName: string): Mac;
}
