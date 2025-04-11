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

import type { AsyncCallback, Callback } from './@ohos.base';

declare namespace cryptoFramework {
  enum Result {
    INVALID_PARAMS = 401,
    NOT_SUPPORT = 801,
    ERR_OUT_OF_MEMORY = 17620001,
    ERR_RUNTIME_ERROR = 17620002,
    ERR_CRYPTO_OPERATION = 17630001
  }

  interface DataBlob {
    data: Uint8Array;
  }

  interface ParamsSpec {
    algName: string;
  }

  interface IvParamsSpec extends ParamsSpec {
    iv: DataBlob;
  }

  interface GcmParamsSpec extends ParamsSpec {
    iv: DataBlob;
    aad: DataBlob;
    authTag: DataBlob;
  }

  interface CcmParamsSpec extends ParamsSpec {
    iv: DataBlob;
    aad: DataBlob;
    authTag: DataBlob;
  }

  enum CryptoMode {
    ENCRYPT_MODE = 0,
    DECRYPT_MODE = 1
  }

  interface KeyEncodingConfig {
    password: string;
    cipherName: string;
  }


  interface Key {
    getEncoded(): DataBlob;
    readonly format: string;
    readonly algName: string;
  }

  interface SymKey extends Key {
    clearMem(): void;
  }

  interface PriKey extends Key {
    clearMem(): void;
    getAsyKeySpec(itemType: AsyKeySpecItem): bigint | string | number;
    getEncodedDer(format: string): DataBlob;
    getEncodedPem(format: string): string;
    getEncodedPem(format: string, config: KeyEncodingConfig): string;
  }

  interface PubKey extends Key {
    getAsyKeySpec(itemType: AsyKeySpecItem): bigint | string | number;
    getEncodedDer(format: string): DataBlob;
    getEncodedPem(format: string): string;
  }

  interface KeyPair {
    readonly priKey: PriKey;
    readonly pubKey: PubKey;
  }

  interface Random {
    generateRandom(len: number, callback: AsyncCallback<DataBlob>): void;
    generateRandom(len: number): Promise<DataBlob>;
    generateRandomSync(len: number): DataBlob;
    setSeed(seed: DataBlob): void;
    readonly algName: string;
  }
  function createRandom(): Random;

  interface AsyKeyGenerator {
    generateKeyPair(callback: AsyncCallback<KeyPair>): void;
    generateKeyPair(): Promise<KeyPair>;
    generateKeyPairSync(): KeyPair;
    convertKey(pubKey: DataBlob, priKey: DataBlob, callback: AsyncCallback<KeyPair>): void;
    convertKey(pubKey: DataBlob | null, priKey: DataBlob | null, callback: AsyncCallback<KeyPair>): void;
    convertKey(pubKey: DataBlob, priKey: DataBlob): Promise<KeyPair>;
    convertKey(pubKey: DataBlob | null, priKey: DataBlob | null): Promise<KeyPair>;
    convertKeySync(pubKey: DataBlob | null, priKey: DataBlob | null): KeyPair;
    convertPemKey(pubKey: string | null, priKey: string | null): Promise<KeyPair>;
    convertPemKey(pubKey: string | null, priKey: string | null, password: string): Promise<KeyPair>;
    convertPemKeySync(pubKey: string | null, priKey: string | null): KeyPair;
    convertPemKeySync(pubKey: string | null, priKey: string | null, password: string): KeyPair;
    readonly algName: string;
  }

  interface SymKeyGenerator {
    generateSymKey(callback: AsyncCallback<SymKey>): void;
    generateSymKey(): Promise<SymKey>;
    generateSymKeySync(): SymKey;
    convertKey(key: DataBlob, callback: AsyncCallback<SymKey>): void;
    convertKey(key: DataBlob): Promise<SymKey>;
    convertKeySync(key: DataBlob): SymKey;
    readonly algName: string;
  }

  function createAsyKeyGenerator(algName: string): AsyKeyGenerator;
  function createSymKeyGenerator(algName: string): SymKeyGenerator;

  interface MacSpec {
    algName: string;
  }

  interface HmacSpec extends MacSpec {
    mdName: string;
  }

  interface CmacSpec extends MacSpec {
    cipherName: string;
  }

  interface Mac {
    init(key: SymKey, callback: AsyncCallback<void>): void;
    init(key: SymKey): Promise<void>;
    initSync(key: SymKey): void;
    update(input: DataBlob, callback: AsyncCallback<void>): void;
    update(input: DataBlob): Promise<void>;
    updateSync(input: DataBlob): void;
    doFinal(callback: AsyncCallback<DataBlob>): void;
    doFinal(): Promise<DataBlob>;
    doFinalSync(): DataBlob;
    getMacLength(): number;
    readonly algName: string;
  }
  function createMac(algName: string): Mac;
  function createMac(macSpec: MacSpec): Mac;

  interface Md {
    update(input: DataBlob, callback: AsyncCallback<void>): void;
    update(input: DataBlob): Promise<void>;
    updateSync(input: DataBlob): void;
    digest(callback: AsyncCallback<DataBlob>): void;
    digest(): Promise<DataBlob>;
    digestSync(): DataBlob;
    getMdLength(): number;
    readonly algName: string;
  }
  function createMd(algName: string): Md;

  enum CipherSpecItem {
    OAEP_MD_NAME_STR = 100,
    OAEP_MGF_NAME_STR = 101,
    OAEP_MGF1_MD_STR = 102,
    OAEP_MGF1_PSRC_UINT8ARR = 103,
    SM2_MD_NAME_STR = 104
  }

  enum SignSpecItem {
    PSS_MD_NAME_STR = 100,
    PSS_MGF_NAME_STR = 101,
    PSS_MGF1_MD_STR = 102,
    PSS_SALT_LEN_NUM = 103,
    PSS_TRAILER_FIELD_NUM = 104,
    SM2_USER_ID_UINT8ARR = 105
  }

  interface Cipher {
    init(opMode: CryptoMode, key: Key, params: ParamsSpec, callback: AsyncCallback<void>): void;
    init(opMode: CryptoMode, key: Key, params: ParamsSpec | null, callback: AsyncCallback<void>): void;
    init(opMode: CryptoMode, key: Key, params: ParamsSpec): Promise<void>;
    init(opMode: CryptoMode, key: Key, params: ParamsSpec | null): Promise<void>;
    initSync(opMode: CryptoMode, key: Key, params: ParamsSpec | null): void;
    update(data: DataBlob, callback: AsyncCallback<DataBlob>): void;
    update(data: DataBlob): Promise<DataBlob>;
    updateSync(data: DataBlob): DataBlob;
    doFinal(data: DataBlob, callback: AsyncCallback<DataBlob>): void;
    doFinal(data: DataBlob | null, callback: AsyncCallback<DataBlob>): void;
    doFinal(data: DataBlob): Promise<DataBlob>;
    doFinal(data: DataBlob | null): Promise<DataBlob>;
    doFinalSync(data: DataBlob | null): DataBlob;
    setCipherSpec(itemType: CipherSpecItem, itemValue: Uint8Array): void;
    getCipherSpec(itemType: CipherSpecItem): string | Uint8Array;
    readonly algName: string;
  }
  function createCipher(transformation: string): Cipher;

  interface Sign {
    init(priKey: PriKey, callback: AsyncCallback<void>): void;
    init(priKey: PriKey): Promise<void>;
    initSync(priKey: PriKey): void;
    update(data: DataBlob, callback: AsyncCallback<void>): void;
    update(data: DataBlob): Promise<void>;
    updateSync(data: DataBlob): void;
    sign(data: DataBlob, callback: AsyncCallback<DataBlob>): void;
    sign(data: DataBlob | null, callback: AsyncCallback<DataBlob>): void;
    sign(data: DataBlob): Promise<DataBlob>;
    sign(data: DataBlob | null): Promise<DataBlob>;
    signSync(data: DataBlob | null): DataBlob;
    setSignSpec(itemType: SignSpecItem, itemValue: number): void;
    setSignSpec(itemType: SignSpecItem, itemValue: number | Uint8Array): void;
    getSignSpec(itemType: SignSpecItem): string | number;
    readonly algName: string;
  }

  interface Verify {
    init(pubKey: PubKey, callback: AsyncCallback<void>): void;
    init(pubKey: PubKey): Promise<void>;
    initSync(pubKey: PubKey): void;
    update(data: DataBlob, callback: AsyncCallback<void>): void;
    update(data: DataBlob): Promise<void>;
    updateSync(data: DataBlob): void;
    verify(data: DataBlob, signatureData: DataBlob, callback: AsyncCallback<boolean>): void;
    verify(data: DataBlob | null, signatureData: DataBlob, callback: AsyncCallback<boolean>): void;
    verify(data: DataBlob, signatureData: DataBlob): Promise<boolean>;
    verify(data: DataBlob | null, signatureData: DataBlob): Promise<boolean>;
    verifySync(data: DataBlob | null, signatureData: DataBlob): boolean;
    recover(signatureData: DataBlob): Promise<DataBlob | null>;
    recoverSync(signatureData: DataBlob): DataBlob | null;
    setVerifySpec(itemType: SignSpecItem, itemValue: number): void;
    setVerifySpec(itemType: SignSpecItem, itemValue: number | Uint8Array): void;
    getVerifySpec(itemType: SignSpecItem): string | number;
    readonly algName: string;
  }
  function createSign(algName: string): Sign;
  function createVerify(algName: string): Verify;

  interface KeyAgreement {
    generateSecret(priKey: PriKey, pubKey: PubKey, callback: AsyncCallback<DataBlob>): void;
    generateSecret(priKey: PriKey, pubKey: PubKey): Promise<DataBlob>;
    generateSecretSync(priKey: PriKey, pubKey: PubKey): DataBlob;
    readonly algName: string;
  }
  function createKeyAgreement(algName: string): KeyAgreement;

  enum AsyKeySpecItem {
    DSA_P_BN = 101,
    DSA_Q_BN = 102,
    DSA_G_BN = 103,
    DSA_SK_BN = 104,
    DSA_PK_BN = 105,
    ECC_FP_P_BN = 201,
    ECC_A_BN = 202,
    ECC_B_BN = 203,
    ECC_G_X_BN = 204,
    ECC_G_Y_BN = 205,
    ECC_N_BN = 206,
    ECC_H_NUM = 207,
    ECC_SK_BN = 208,
    ECC_PK_X_BN = 209,
    ECC_PK_Y_BN = 210,
    ECC_FIELD_TYPE_STR = 211,
    ECC_FIELD_SIZE_NUM = 212,
    ECC_CURVE_NAME_STR = 213,
    RSA_N_BN = 301,
    RSA_SK_BN = 302,
    RSA_PK_BN = 303,
    DH_P_BN = 401,
    DH_G_BN = 402,
    DH_L_NUM = 403,
    DH_SK_BN = 404,
    DH_PK_BN = 405,
    ED25519_SK_BN = 501,
    ED25519_PK_BN = 502,
    X25519_SK_BN = 601,
    X25519_PK_BN = 602
  }

  enum AsyKeySpecType {
    COMMON_PARAMS_SPEC = 0,
    PRIVATE_KEY_SPEC = 1,
    PUBLIC_KEY_SPEC = 2,
    KEY_PAIR_SPEC = 3
  }

  interface AsyKeySpec {
    algName: string;
    specType: AsyKeySpecType;
  }

  interface DSACommonParamsSpec extends AsyKeySpec {
    p: bigint;
    q: bigint;
    g: bigint;
  }

  interface DSAPubKeySpec extends AsyKeySpec {
    params: DSACommonParamsSpec;
    pk: bigint;
  }

  interface DSAKeyPairSpec extends AsyKeySpec {
    params: DSACommonParamsSpec;
    sk: bigint;
    pk: bigint;
  }

  interface ECField {
    fieldType: string;
  }

  interface ECFieldFp extends ECField {
    p: bigint;
  }

  interface Point {
    x: bigint;
    y: bigint;
  }

  interface ECCCommonParamsSpec extends AsyKeySpec {
    field: ECField;
    a: bigint;
    b: bigint;
    g: Point;
    n: bigint;
    h: number;
  }

  interface ECCPriKeySpec extends AsyKeySpec {
    params: ECCCommonParamsSpec;
    sk: bigint;
  }

  interface ECCPubKeySpec extends AsyKeySpec {
    params: ECCCommonParamsSpec;
    pk: Point;
  }

  interface ECCKeyPairSpec extends AsyKeySpec {
    params: ECCCommonParamsSpec;
    sk: bigint;
    pk: Point;
  }

  class ECCKeyUtil {
    static genECCCommonParamsSpec(curveName: string): ECCCommonParamsSpec;
    static convertPoint(curveName: string, encodedPoint: Uint8Array): Point;
    static getEncodedPoint(curveName: string, point: Point, format: string): Uint8Array;
  }

  interface DHCommonParamsSpec extends AsyKeySpec {
    p: bigint;
    g: bigint;
    l: number;
  }

  interface DHPriKeySpec extends AsyKeySpec {
    params: DHCommonParamsSpec;
    sk: bigint;
  }

  interface DHPubKeySpec extends AsyKeySpec {
    params: DHCommonParamsSpec;
    pk: bigint;
  }

  interface DHKeyPairSpec extends AsyKeySpec {
    params: DHCommonParamsSpec;
    sk: bigint;
    pk: bigint;
  }

  class DHKeyUtil {
    static genDHCommonParamsSpec(pLen: number, skLen?: number): DHCommonParamsSpec;
  }

  interface ED25519PriKeySpec extends AsyKeySpec {
    sk: bigint;
  }

  interface ED25519PubKeySpec extends AsyKeySpec {
    pk: bigint;
  }

  interface ED25519KeyPairSpec extends AsyKeySpec {
    sk: bigint;
    pk: bigint;
  }

  interface X25519PriKeySpec extends AsyKeySpec {
    sk: bigint;
  }

  interface X25519PubKeySpec extends AsyKeySpec {
    pk: bigint;
  }

  interface X25519KeyPairSpec extends AsyKeySpec {
    sk: bigint;
    pk: bigint;
  }

  interface RSACommonParamsSpec extends AsyKeySpec {
    n: bigint;
  }

  interface RSAPubKeySpec extends AsyKeySpec {
    params: RSACommonParamsSpec;
    pk: bigint;
  }

  interface RSAKeyPairSpec extends AsyKeySpec {
    params: RSACommonParamsSpec;
    sk: bigint;
    pk: bigint;
  }

  interface AsyKeyGeneratorBySpec {
    generateKeyPair(callback: AsyncCallback<KeyPair>): void;
    generateKeyPair(): Promise<KeyPair>;
    generateKeyPairSync(): KeyPair;
    generatePriKey(callback: AsyncCallback<PriKey>): void;
    generatePriKey(): Promise<PriKey>;
    generatePriKeySync(): PriKey;
    generatePubKey(callback: AsyncCallback<PubKey>): void;
    generatePubKey(): Promise<PubKey>;
    generatePubKeySync(): PubKey;
    readonly algName: string;
  }
  function createAsyKeyGeneratorBySpec(asyKeySpec: AsyKeySpec): AsyKeyGeneratorBySpec;

  interface KdfSpec {
    algName: string;
  }

  interface PBKDF2Spec extends KdfSpec {
    password: string | Uint8Array;
    salt: Uint8Array;
    iterations: number;
    keySize: number;
  }

  interface HKDFSpec extends KdfSpec {
    key: string | Uint8Array;
    salt: Uint8Array;
    info: Uint8Array;
    keySize: number;
  }

  interface ScryptSpec extends KdfSpec {
    passphrase: string | Uint8Array;
    salt: Uint8Array;
    n: number;
    r: number;
    p: number;
    maxMemory: number;
    keySize: number;
  }

  interface Kdf {
    generateSecret(params: KdfSpec, callback: AsyncCallback<DataBlob>): void;
    generateSecret(params: KdfSpec): Promise<DataBlob>;
    generateSecretSync(params: KdfSpec): DataBlob;
    readonly algName: string;
  }
  function createKdf(algName: string): Kdf;

  interface SM2CipherTextSpec {
    xCoordinate: bigint;
    yCoordinate: bigint;
    cipherTextData: Uint8Array;
    hashData: Uint8Array;
  }

  class SM2CryptoUtil {
    static genCipherTextBySpec(spec: SM2CipherTextSpec, mode?: string): DataBlob;
    static getCipherTextSpec(cipherText: DataBlob, mode?: string): SM2CipherTextSpec;
  }
}

export default cryptoFramework;
