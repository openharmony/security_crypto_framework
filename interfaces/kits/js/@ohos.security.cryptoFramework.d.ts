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
 * @syscap SystemCapability.Security.CryptoFramework
 * @import import cryptoFramework from '@ohos.security.cryptoFramework'
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

        /** Indicates that runtime error.
         * @since 9
         */
        ERR_RUNTIME_ERROR = 17620002,

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
        /**
         * Indicates the algorithm name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        algoName : string;
    }

    interface IvParamsSpec extends ParamsSpec {
        /**
         * Indicates the algorithm parameters such as iv.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        iv : DataBlob;
    }

    interface GcmParamsSpec extends ParamsSpec {
        /**
         * Indicates the GCM algorithm parameters such as iv.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        iv : DataBlob;

        /**
         * Indicates the GCM additional message for integrity check.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        aad : DataBlob;

        /**
         * Indicates the GCM Authenticated Data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        authTag : DataBlob;
    }

    interface CcmParamsSpec extends ParamsSpec {
        /**
         * Indicates the GCM algorithm parameters such as iv.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        iv : DataBlob;

        /**
         * Indicates the CCM additional message for integrity check.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        aad : DataBlob;

        /**
         * Indicates the CCM Authenticated Data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
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

    /**
     * The common parents class of key.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     */
    interface Key {
        /**
         * Encode key Object to bin.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         */
        getEncoded() : DataBlob;

        /**
         * Key format.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         */
        readonly format : string;

        /**
         * Key algorithm name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         */
        readonly algName : string;
    }

    interface SymKey extends Key {
        clearMem() : void;
    }

    /**
     * The private key class of asy-key.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     */
    interface PriKey extends Key {

        /**
         * The function used to clear private key mem.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         */
        clearMem() : void;
    }

    /**
     * The public key class of asy-key.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     */
    interface PubKey extends Key {}

    /**
     * The keyPair class of asy-key. Include privateKey and publickey.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     */
    interface KeyPair {

        /**
         * Public key.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         */
        readonly priKey : PriKey;

        /**
         * Private key.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         */
        readonly pubKey : PubKey;
    }

    interface Random {

        /**
         * Generate radom DataBlob by given length
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         * @param len Indicates the length of random DataBlob
         */
        generateRandom(len : number, callback: AsyncCallback<DataBlob>) : void;
        generateRandom(len : number) : Promise<DataBlob>;

        /**
         * set seed by given DataBlob
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         * @param seed Indicates the seed DataBlob
         */
        setSeed(seed : DataBlob, callback : AsyncCallback<void>) : void;
        setSeed(seed : DataBlob) : Promise<void>;
    }

    /**
     * Provides the rand create func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @return Returns the rand create instance.
     */
    function createRandom() : Random;

    /**
     * The generator used to generate asy_key.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     */
    interface AsyKeyGenerator {

        /**
         * Generate keyPair by init params.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return The generated keyPair.
         */
        generateKeyPair(callback : AsyncCallback<KeyPair>) : void;
        generateKeyPair() : Promise<KeyPair>;

        /**
         * Convert keyPair object from privateKey and publicKey binary data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param pubKey The binary data of public key.
         * @param priKey The binary data of private key.
         * @return The Converted key pair.
         */
        convertKey(pubKey : DataBlob, priKey : DataBlob, callback : AsyncCallback<KeyPair>) : void;
        convertKey(pubKey : DataBlob, priKey : DataBlob) : Promise<KeyPair>;

        /**
         * The algorothm name of generator.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         */
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
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algName This algName contains params of generateKeyPair, like bits, primes or ECC_curve;
     * @return The generator object.
     */
    function createAsyKeyGenerator(algName : string) : AsyKeyGenerator;

    /**
     * Provides the sym key generator instance func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algName Indicates the algorithm name.
     * @return Returns the sym key generator instance.
     */
    function createSymKeyGenerator(algName : string) : SymKeyGenerator;

    interface Mac {
         /**
         * Init hmac with given SymKey
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         * @param key Indicates the SymKey
         */
        init(key : SymKey, callback : AsyncCallback<void>) : void;
        init(key : SymKey) : Promise<void>;

        /**
         * Update hmac with DataBlob
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         * @param input Indicates the DataBlob
         */
        update(input : DataBlob, callback : AsyncCallback<void>) : void;
        update(input : DataBlob) : Promise<void>;

        /**
         * Output the result of hmac calculation
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        doFinal(callback : AsyncCallback<DataBlob>) : void;
        doFinal() : Promise<DataBlob>;

        /**
         * Output the length of hmac result
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        getMacLength() : number;

        /**
         * Indicates the algorithm name
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        readonly algName : string;
    }

    /**
     * Provides the mac create func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algName Indicates the mac algorithm name.
     * @return Returns the mac create instance.
     */
    function createMac(algName : string) : Mac;

    interface Md {
        /**
         * Update md with DataBlob
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         * @param input Indicates the DataBlob
         */
        update(input : DataBlob, callback : AsyncCallback<void>) : void;
        update(input : DataBlob) : Promise<void>;

        /**
         * Output the result of md calculation
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        digest(callback : AsyncCallback<DataBlob>) : void;
        digest() : Promise<DataBlob>;

        /**
         * Output the length of md result
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        getMdLength() : number;

        /**
         * Indicates the algorithm name
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        readonly algName : string;
    }

    /**
     * Provides the md create func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algorithm Indicates the md algorithm.
     * @return Returns the md create instances.
     */
    function createMd(algName : string) : Md;

    interface Cipher {
        /**
         * Init cipher with given cipher mode, key and params.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         * @param opMode Indicates the cipher mode.
         * @param key Indicates the SymKey or AsyKey.
         * @param params Indicates the algorithm parameters such as IV.
         */
        init(opMode : CryptoMode, key : Key, params : ParamsSpec, callback : AsyncCallback<void>) : void;
        init(opMode : CryptoMode, key : Key, params : ParamsSpec) : Promise<void>;

        /**
         * Update cipher with DataBlob.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         * @param input Indicates the DataBlob
         */
        update(data : DataBlob, callback : AsyncCallback<DataBlob>) : void;
        update(data : DataBlob) : Promise<DataBlob>;

        /**
         * Output the result of cipher calculation.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        doFinal(data : DataBlob, callback : AsyncCallback<DataBlob>) : void;
        doFinal(data : DataBlob) : Promise<DataBlob>;

        /**
         * Indicates the algorithm name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        readonly algName : string;
    }

    /**
     * Provides the cipher create func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param transformation Indicates the transform type, and contains init params of cipher.
     * @return Returns the cipher create instance.
     */
    function createCipher(transformation : string) : Cipher;

    /**
     * The sign class
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     */
    interface Sign {
        /**
         * This init function used to Initialize environment, must be invoked before update and sign.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param priKey The prikey object.
         */
        init(priKey : PriKey, callback : AsyncCallback<void>) : void;
        init(priKey : PriKey) : Promise<void>;

        /**
         * This function used to update data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param data The data need to update.
         */
        update(data : DataBlob, callback : AsyncCallback<void>) : void;
        update(data : DataBlob) : Promise<void>;

        /**
         * This function used to sign all data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param data The data need to update.
         * @return The sign data.
         */
        sign(data : DataBlob, callback : AsyncCallback<DataBlob>) : void;
        sign(data : DataBlob) : Promise<DataBlob>;
        readonly algName : string;
    }

    /**
     * The verify class
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     */
    interface Verify {
        /**
         * This init function used to Initialize environment, must be invoked before update and verify.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param priKey The prikey object.
         */
        init(pubKey : PubKey, callback : AsyncCallback<void>) : void;
        init(pubKey : PubKey) : Promise<void>;

        /**
         * This function used to update data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param data The data need to update.
         */
        update(data : DataBlob, callback : AsyncCallback<void>) : void;
        update(data : DataBlob) : Promise<void>;

        /**
         * This function used to sign all data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param data The data need to update.
         * @param signatureData The sign data.
         * @return true means verify success.
         */
        verify(data : DataBlob, signatureData : DataBlob, callback : AsyncCallback<boolean>) : void;
        verify(data : DataBlob, signatureData : DataBlob) : Promise<boolean>;
        readonly algName : string;
    }

    /**
     * Provides the sign func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algName Indicates the sign algorithm name, include init detail params.
     */
    function createSign(algName : string) : Sign;

    /**
     * Provides the verify func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algName Indicates the verify algorithm name, include init detail params.
     */
    function createVerify(algName : string) : Verify;

    interface KeyAgreement {
        /**
         * Generate secret by init params.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return The generated secret.
         */
        generateSecret(priKey : PriKey, pubKey : PubKey, callback : AsyncCallback<DataBlob>) : void;
        generateSecret(priKey : PriKey, pubKey : PubKey) : Promise<DataBlob>;

        /**
         * Indicates the algorithm name
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @since 9
         */
        readonly algName : string;
    }

    /**
     * Provides the key agree func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algName Indicates the key agreement algorithm name.
     */
    function createKeyAgreement(algName : string) : KeyAgreement;

    interface X509Cert {
        /**
         * Verify the X509 cert.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param key Indicates the cert chain validator data.
         */
        verify(key : PubKey, callback : AsyncCallback<void>) : void;
        verify(key : PubKey) : Promise<void>;

        /**
         * Get X509 cert encoded data.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert encoded data.
         */
        getEncoded(callback : AsyncCallback<EncodingBlob>) : void;
        getEncoded() : Promise<EncodingBlob>;

        /**
         * Get X509 cert public key.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert pubKey.
         */
        getPublicKey(callback : AsyncCallback<PubKey>) : void;
        getPublicKey() : Promise<PubKey>;

        /**
         * Check the X509 cert validity with date.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param date Indicates the cert date.
         */
        checkValidityWithDate(date: string, callback : AsyncCallback<void>) : void;
        checkValidityWithDate(date: string) : Promise<void>;

        /**
         * Get X509 cert version.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert version.
         */
        getVersion() : number;

        /**
         * Get X509 cert serial number.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert serial number.
         */
        getSerialNumber() : number;

        /**
         * Get X509 cert issuer name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert issuer name.
         */
        getIssuerName() : DataBlob;

        /**
         * Get X509 cert subject name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert subject name.
         */
        getSubjectName() : DataBlob;

        /**
         * Get X509 cert not before time.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert not before time.
         */
        getNotBeforeTime() : string;

        /**
         * Get X509 cert not after time.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert not after time.
         */
        getNotAfterTime() : string;

        /**
         * Get X509 cert signature.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert signature.
         */
        getSignature() : DataBlob;

        /**
         * Get X509 cert signature's algorithm name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert signature's algorithm name.
         */
        getSignatureAlgName() : string;

        /**
         * Get X509 cert signature's algorithm oid.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert signature's algorithm oid.
         */
        getSignatureAlgOid() : string;

        /**
         * Get X509 cert signature's algorithm name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert signature's algorithm name.
         */
        getSignatureAlgParams() : DataBlob;

        /**
         * Get X509 cert key usage.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert key usage.
         */
        getKeyUsage() : DataBlob;

        /**
         * Get X509 cert extended key usage.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert extended key usage.
         */
        getExtKeyUsage() : DataArray;

        /**
         * Get X509 cert basic constraints path len.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert basic constraints path len.
         */
        getBasicConstraints() : number;

        /**
         * Get X509 cert subject alternative name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert subject alternative name.
         */
        getSubjectAltNames() : DataArray;

        /**
         * Get X509 cert issuer alternative name.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns X509 cert issuer alternative name.
         */
        getIssuerAltNames() : DataArray;
    }

    /**
     * Provides the x509 cert func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param inStream Indicates the input cert data.
     * @return Returns X509 cert instance.
     */
    function createX509Cert(inStream : EncodingBlob, callback : AsyncCallback<X509Cert>) : void;
    function createX509Cert(inStream : EncodingBlob) : Promise<X509Cert>;

    /**
     * Interface of X509CrlEntry.
     * @since 9
     * @syscap SystemCapability.Security.CryptoFramework
     */
    interface X509CrlEntry {
        /**
         * Returns the ASN of this CRL entry 1 der coding form, i.e. internal sequence.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns EncodingBlob of crl entry.
         */
        getEncoded(callback : AsyncCallback<EncodingBlob>) : void;
        getEncoded() : Promise<EncodingBlob>;

        /**
         * Get the serial number from this x509crl entry.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns serial number of crl entry.
         */
        getSerialNumber() : number;

        /**
         * Get the issuer of the x509 certificate described by this entry.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns DataBlob of issuer.
         */
        getCertIssuer(callback : AsyncCallback<DataBlob>) : void;
        getCertIssuer() : Promise<DataBlob>;

        /**
         * Get the revocation date from x509crl entry.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns string of revocation date.
         */
        getRevocationDate(callback : AsyncCallback<string>) : void;
        getRevocationDate() : Promise<string>;
    }

    /**
     * Interface of X509Crl.
     * @since 9
     * @syscap SystemCapability.Security.CryptoFramework
     */
    interface X509Crl {
        /**
         * Check if the given certificate is on this CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param X509Cert Input cert data.
         * @return Returns result of Check cert is revoked or not.
         */
        isRevoked(cert : X509Cert, callback : AsyncCallback<boolean>) : void;
        isRevoked(cert : X509Cert) : Promise<boolean>;

        /**
         * Returns the type of this CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns string of crl type.
         */
        getType() : string;

        /**
         * Get the der coding format.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns EncodingBlob of crl.
         */
        getEncoded(callback : AsyncCallback<EncodingBlob>) : void;
        getEncoded() : Promise<EncodingBlob>;

        /**
         * Use the public key to verify the signature of CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param PubKey Input public Key.
         * @return Returns verify result.
         */
        verify(key : PubKey, callback : AsyncCallback<void>) : void;
        verify(key : PubKey) : Promise<void>;

        /**
         * Get version number from CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns version of crl.
         */
        getVersion() : number;

        /**
         * Get the issuer name from CRL. Issuer means the entity that signs and publishes the CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns issuer name of crl.
         */
        getIssuerName() : DataBlob;

        /**
         * Get lastUpdate value from CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns last update of crl.
         */
        getLastUpdate() : string;

        /**
         * Get nextUpdate value from CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns next update of crl.
         */
        getNextUpdate() : string;

        /**
         * This method can be used to find CRL entries in indirect CRLs.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param serialNumber serial number of crl.
         * @return Returns next update of crl.
         */
        getRevokedCert(serialNumber : number, callback : AsyncCallback<X509CrlEntry>) : void;
        getRevokedCert(serialNumber : number) : Promise<X509CrlEntry>;

        /**
         * This method can be used to find CRL entries in indirect cert.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param X509Cert Cert of x509.
         * @return Returns X509CrlEntry instance.
         */
        getRevokedCertWithCert(cert : X509Cert, callback : AsyncCallback<X509CrlEntry>) : void;
        getRevokedCertWithCert(cert : X509Cert) : Promise<X509CrlEntry>;

        /**
         * Get all entries in this CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns Array of X509CrlEntry instance.
         */
        getRevokedCerts(callback : AsyncCallback<Array<X509CrlEntry>>) : void;
        getRevokedCerts() : Promise<Array<X509CrlEntry>>;

        /**
         * Get the CRL information encoded by Der from this CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns DataBlob of tbs info.
         */
        getTbsInfo(callback : AsyncCallback<DataBlob>) : void;
        getTbsInfo() : Promise<DataBlob>;

        /**
         * Get signature value from CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns DataBlob of signature.
         */
        getSignature() : DataBlob;

        /**
         * Get the signature algorithm name of the CRL signature algorithm.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns string of signature algorithm name.
         */
        getSignatureAlgName() : string;

        /**
         * Get the signature algorithm oid string from CRL.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns string of signature algorithm oid.
         */
        getSignatureAlgOid() : string;

        /**
         * Get the der encoded signature algorithm parameters from the CRL signature algorithm.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @return Returns DataBlob of signature algorithm params.
         */
        getSignatureAlgParams() : DataBlob;
    }

    /**
     * Provides the x509 CRL func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param inStream Indicates the input CRL data.
     * @return Returns the x509 CRL instance.
     */
     function createX509Crl(inStream : EncodingBlob, callback : AsyncCallback<X509Crl>) : void;
     function createX509Crl(inStream : EncodingBlob) : Promise<X509Crl>;

    /**
     * Certification chain validator.
     * @since 9
     * @syscap SystemCapability.Security.CryptoFramework
     */
    interface CertChainValidator {
        /**
         * Validate the cert chain.
         *
         * @syscap SystemCapability.Security.CryptoFramework
         * @import import cryptoFramework from '@ohos.security.cryptoFramework'
         * @since 9
         * @param certChain Indicates the cert chain validator data.
         */
        validate(certChain : CertChainData, callback : AsyncCallback<void>) : void;
        validate(certChain : CertChainData) : Promise<void>;
        readonly algorithm : string;
    }

    /**
     * Provides the cert chain validator func.
     *
     * @syscap SystemCapability.Security.CryptoFramework
     * @import import cryptoFramework from '@ohos.security.cryptoFramework'
     * @since 9
     * @param algorithm Indicates the cert chain validator type.
     * @return Returns the cert chain validator instance.
     */
    function createCertChainValidator(algorithm :string) : CertChainValidator;
}

export default cryptoFramework;
