/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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


import {AsyncCallback, Callback} from './basic';

/**
 * Provides a set of encryption and decryption algorithm library framework, shields the underlying differences,
 * encapsulates the relevant algorithm library, and provides a unified functional interface upward.
 *
 * @sysCap SystemCapability.Security.CryptoFramework.
 * @import import cryptoFramework from '@ohos.security.cryptoFramework'
 * @permission
 * @since 9
 */
declare namespace cryptoFramework {
    /**
     * Enum for result code
     * @since 9
     */
    enum Result {
        /** Indicates that input params is invalid.
         * @since 9
         */
        INVALID_PARAMS = 401,

        /** Indicates that function or algorithm is not supported.
         * @since 9
         */
        NOT_SUPPORT = 801,

        /** Indicates the out of memory error.
         * @since 9
         */
        ERR_OUT_OF_MEMORY = 17620001,

        /** Indicates that internal error.
         * @since 9
         */
        ERR_INTERNAL_ERROR = 17620002,

        /** Indicates that crypto operation has something wrong.
         * @since 9
         */
        ERR_CRYPTO_OPERATION = 17630001,

        /* Indicates that cert signature check fails.
         * @since 9
         */
        ERR_CERT_SIGNATURE_FAILURE = 17630002,

        /* Indicates that cert is not yet valid.
         * @since 9
         */
        ERR_CERT_NOT_YET_VALID = 17630003,

        /* Indicates that cert has expired.
         * @since 9
         */
        ERR_CERT_HAS_EXPIRED = 17630004,

        /* Indicates that we can not get the untrusted cert's issuer.
         * @since 9
         */
        ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 17630005,

        /* Key usage does not include certificate sign.
         * @since 9
         */
        ERR_KEYUSAGE_NO_CERTSIGN = 17630006,

        /* Key usage does not include digital sign.
         * @since 9
         */
        ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 17630007,
    }

    interface DataBlob {
        data : Uint8Array;
    }

    interface DataArray {
        data : Array<Uint8Array>;
    }

    /**
     * Enum for supported cert encoding format
     * @since 9
     */
     enum EncodingFormat {
        /**
         * The value of cert DER format
         * @since 9
         */
        FORMAT_DER = 0,

        /**
         * The value of cert PEM format
         * @since 9
         */
        FORMAT_PEM = 1,
    }

    interface EncodingBlob {
        data : Uint8Array;
        encodingFormat : EncodingFormat;
    }

    interface CertChainData {
        data: Uint8Array;
        count : number;
        encodingFormat: EncodingFormat;
    }

    interface ParamsSpec {
        algoName : string;
    }

    interface IvParamsSpec extends ParamsSpec {
        iv : DataBlob;
    }

    interface GcmParamsSpec extends ParamsSpec {
        iv : DataBlob;
        aad : DataBlob;
        authTag : DataBlob;
    }

    interface CcmParamsSpec extends ParamsSpec {
        iv : DataBlob;
        aad : DataBlob;
        authTag : DataBlob;
    }

    /**
     * Enum for obtain the crypto operation.
     * @since 9
     */
    enum CryptoMode {
        /**
         * The value of aes and 3des encrypt operation
         * @since 9
         */
        ENCRYPT_MODE = 0,

        /**
         * The value of aes and 3des decrypt operation
         * @since 9
         */
        DECRYPT_MODE = 1,
    }

    interface Key {
        getEncoded() : DataBlob;
        readonly format : string;
        readonly algName : string;
    }

    interface SymKey extends Key {
        clearMem() : void;
    }

    interface PriKey extends Key {
        clearMem() : void;
    }

    interface PubKey extends Key {}

    interface KeyPair {
        readonly priKey : PriKey;
        readonly pubKey : PubKey;
    }

    interface Random {
        generateRandom(len : number, callback: AsyncCallback<DataBlob>) : void;
        generateRandom(len : number) : Promise<DataBlob>;
        setSeed(seed : DataBlob, callback : AsyncCallback<void>) : void;
        setSeed(seed : DataBlob) : Promise<void>;
    }

    /**
     * Provides the rand create func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param callback Indicates the callback for the rand create result.
     */
    function createRandom() : Random;

    interface AsyKeyGenerator {
        generateKeyPair(callback : AsyncCallback<KeyPair>) : void;
        generateKeyPair() : Promise<KeyPair>;
        convertKey(pubKey : DataBlob, priKey : DataBlob, callback : AsyncCallback<KeyPair>) : void;
        convertKey(pubKey : DataBlob, priKey : DataBlob) : Promise<KeyPair>;
        readonly algName : string;
    }

    interface SymKeyGenerator {
        generateSymKey(callback : AsyncCallback<SymKey>) : void;
        generateSymKey() : Promise<SymKey>;
        convertKey(key : DataBlob, callback : AsyncCallback<SymKey>) : void;
        convertKey(key : DataBlob) : Promise<SymKey>;
        readonly algName : string;
    }

    /**
     * Provides the asy key generator instance func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algName Indicates the algorithm name.
     */
    function createAsyKeyGenerator(algName : string) : AsyKeyGenerator;

    /**
     * Provides the sym key generator instance func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algName Indicates the algorithm name.
     * @param callback Indicates the callback for get the sym key generator instance result.
     */
    function createSymKeyGenerator(algName : string) : SymKeyGenerator;

    interface Mac {
        init(key : SymKey, callback : AsyncCallback<void>) : void;
        init(key : SymKey) : Promise<void>;
        update(input : DataBlob, callback : AsyncCallback<void>) : void;
        update(input : DataBlob) : Promise<void>;
        doFinal(callback : AsyncCallback<DataBlob>) : void;
        doFinal() : Promise<DataBlob>;
        getMacLength() : number;
        readonly algName : string;
    }

    /**
     * Provides the mac create func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algName Indicates the mac algorithm name.
     * @param callback Indicates the callback for the mac create result.
     */
    function createMac(algName : string) : Mac;

    interface Md {
        update(input : DataBlob, callback : AsyncCallback<void>) : void;
        update(input : DataBlob) : Promise<void>;
        digest(callback : AsyncCallback<DataBlob>) : void;
        digest() : Promise<DataBlob>;
        getMdLength() : number;
        readonly algName : string;
    }

    /**
     * Provides the md create func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algorithm Indicates the md algorithm.
     * @param callback Indicates the callback for the md create result.
     */
    function createMd(algName : string) : Md;

    interface Cipher {
        init(opMode : CryptoMode, key : Key, params : ParamsSpec, callback : AsyncCallback<void>) : void;
        init(opMode : CryptoMode, key : Key, params : ParamsSpec) : Promise<void>;
        update(data : DataBlob, callback : AsyncCallback<DataBlob>) : void;
        update(data : DataBlob) : Promise<DataBlob>;
        doFinal(data : DataBlob, callback : AsyncCallback<DataBlob>) : void;
        doFinal(data : DataBlob) : Promise<DataBlob>;
        readonly algName : string;
    }

    /**
     * Provides the cipher create func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param transformation Indicates the transform type.
     * @param callback Indicates the callback for the cipher create result.
     */
    function createCipher(transformation : string) : Cipher;

    interface Sign {
        init(priKey : PriKey, callback : AsyncCallback<void>) : void;
        init(priKey : PriKey) : Promise<void>;
        update(data : DataBlob, callback : AsyncCallback<void>) : void;
        update(data : DataBlob) : Promise<void>;
        sign(data : DataBlob, callback : AsyncCallback<DataBlob>) : void;
        sign(data : DataBlob) : Promise<DataBlob>;
        readonly algName : string;
    }

    interface Verify {
        init(pubKey : PubKey, callback : AsyncCallback<void>) : void;
        init(pubKey : PubKey) : Promise<void>;
        update(data : DataBlob, callback : AsyncCallback<void>) : void;
        update(data : DataBlob) : Promise<void>;
        verify(data : DataBlob, signatureData : DataBlob, callback : AsyncCallback<boolean>) : void;
        verify(data : DataBlob, signatureData : DataBlob) : Promise<boolean>;
        readonly algName : string;
    }

    /**
     * Provides the sign func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algName Indicates the sign algorithm name.
     */
    function createSign(algName : string) : Sign;

    /**
     * Provides the verify func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algName Indicates the verify algorithm name.
     */
    function createVerify(algName : string) : Verify;

    interface KeyAgreement {
        generateSecret(priKey : PriKey, pubKey : PubKey, callback : AsyncCallback<DataBlob>) : void;
        generateSecret(priKey : PriKey, pubKey : PubKey) : Promise<DataBlob>;
        readonly algName : string;
    }

    /**
     * Provides the key agree func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algName Indicates the key agreement algorithm name.
     */
    function createKeyAgreement(algName : string) : KeyAgreement;

    interface X509Cert {
        verify(key : PubKey, callback : AsyncCallback<void>) : void;
        verify(key : PubKey) : Promise<void>;
        getEncoded(callback : AsyncCallback<EncodingBlob>) : void;
        getEncoded() : Promise<EncodingBlob>;
        getPublicKey(callback : AsyncCallback<PubKey>) : void;
        getPublicKey() : Promise<PubKey>;
        checkValidityWithDate(date: string, callback : AsyncCallback<void>) : void;
        checkValidityWithDate(date: string) : Promise<void>;
        getVersion() : number;
        getSerialNumber() : number;
        getIssuerName() : DataBlob;
        getSubjectName() : DataBlob;
        getNotBeforeTime() : string;
        getNotAfterTime() : string;
        getSignature() : DataBlob;
        getSignatureAlgName() : string;
        getSignatureAlgOid() : string;
        getSignatureAlgParams() : DataBlob;
        getKeyUsage() : DataBlob;
        getExtKeyUsage() : DataArray;
        getBasicConstraints() : number;
        getSubjectAltNames() : DataArray;
        getIssuerAltNames() : DataArray;
    }

    /**
     * Provides the x509 cert func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param inStream Indicates the input cert data.
     * @param callback Indicates the callback for the x509 cert create.
     */
    function createX509Cert(inStream : EncodingBlob, callback : AsyncCallback<X509Cert>) : void;
    function createX509Cert(inStream : EncodingBlob) : Promise<X509Cert>;

    interface X509CrlEntry {
        getEncoded(callback : AsyncCallback<EncodingBlob>) : void;
        getEncoded() : Promise<EncodingBlob>;
        getSerialNumber() : number;
        getCertIssuer(callback : AsyncCallback<DataBlob>) : void;
        getCertIssuer() : Promise<DataBlob>;
        getRevocationDate(callback : AsyncCallback<string>) : void;
        getRevocationDate() : Promise<string>;
    }

    interface X509Crl {
        isRevoked(cert : X509Cert, callback : AsyncCallback<boolean>) : void;
        isRevoked(cert : X509Cert) : Promise<boolean>;
        getType() : string;
        getEncoded(callback : AsyncCallback<EncodingBlob>) : void;
        getEncoded() : Promise<EncodingBlob>;
        verify(key : PubKey, callback : AsyncCallback<void>) : void;
        verify(key : PubKey) : Promise<void>;
        getVersion() : number;
        getIssuerName() : DataBlob;
        getLastUpdate() : string;
        getNextUpdate() : string;
        getRevokedCert(serialNumber : number, callback : AsyncCallback<X509CrlEntry>) : void;
        getRevokedCert(serialNumber : number) : Promise<X509CrlEntry>;
        getRevokedCertWithCert(cert : X509Cert, callback : AsyncCallback<X509CrlEntry>) : void;
        getRevokedCertWithCert(cert : X509Cert) : Promise<X509CrlEntry>;
        getRevokedCerts(callback : AsyncCallback<Array<X509CrlEntry>>) : void;
        getRevokedCerts() : Promise<Array<X509CrlEntry>>;
        getTbsInfo(callback : AsyncCallback<DataBlob>) : void;
        getTbsInfo() : Promise<DataBlob>;
        getSignature() : DataBlob;
        getSignatureAlgName() : string;
        getSignatureAlgOid() : string;
        getSignatureAlgParams() : DataBlob;
    }

    /**
     * Provides the x509 CRL func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param inStream Indicates the input CRL data.
     * @param callback Indicates the callback for the x509 CRL create.
     */
     function createX509Crl(inStream : EncodingBlob, callback : AsyncCallback<X509Crl>) : void;
     function createX509Crl(inStream : EncodingBlob) : Promise<X509Crl>;

    /**
     * Certification chain validator.
     * @since 9
     * @syscap SystemCapability.Security.CryptoFramework
     */

    interface CertChainValidator {
        validate(certChain : CertChainData, callback : AsyncCallback<void>) : void;
        validate(certChain : CertChainData) : Promise<void>;
        readonly algorithm : string;
    }

    /**
     * Provides the cert chain validator func.
     *
     * @sysCap SystemCapability.Security.CryptoFramework.
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @permission
     * @since 9
     * @param algorithm Indicates the cert chain validator type.
     * @param callback Indicates the callback for the cert chain validator result.
     */
    function createCertChainValidator(algorithm :string) : CertChainValidator;
}

export default cryptoFramework;
