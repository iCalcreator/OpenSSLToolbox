## OpenSSLFactory Class

Wrapper class with static methods for OpenSSL functions

Note: You need to have a valid openssl.cnf installed for this to operate correctly.<br>
Require a Psr\Log logger, provided by LoggerDepot<br>
The class has only static methods.<br>


###### OpenSSLFactory::getCipherIvLength( cipherAlgorithm )
    uses openssl_cipher_iv_length
    
    cipherAlgorithm  
                 string
                   cipher method, one of openssl_get_cipher_methods()
                   
    return int     openssl cipher initialization vector byte length
    throws InvalidArgumentException, RuntimeException on error
    static method


###### OpenSSLFactory::decrypt( raw, cipherAlgorithm, keyHash, opts = 0, initializationVector = '' )
    uses openssl_decrypt
    Takes a raw or base64 encoded string and decrypts it using a given method and key.
   
    raw          string
                   The encrypted message to be decrypted
    cipherAlgorithm
                 string
                   cipher method, one of openssl_get_cipher_methods()
    keyHash      string
                   The key
    opts          int
                    one of OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING
    initializationVector
                 string
                   A non-NULL Initialization Vector
                   
    return string  openssl_decrypted data
    throws InvalidArgumentException, RunTimeException  on error
    static method

###### OpenSSLFactory::getDecryptedString( raw, cipherAlgorithm, keyHash, opts = 0, initializationVector = '' )
    alias of OpenSSLFactory::decrypt
    static method


###### OpenSSLFactory::digest( key, hashAlgorithm, rawOutput = false )
    uses openssl_digest
    
    key          string
                   The data
    hashAlgorithm
                 string
                   digest method to use
                   one of openssl_get_md_methods(), self::getAvailableDigestMethods()
    rawOutput    bool
                   Setting to TRUE will return as raw output data, otherwise binhex encoded
                   
    return string  hashed key
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getDigestHash( key, hashAlgorithm, rawOutput = false )
    alias of OpenSSLFactory::digest
    static method


###### OpenSSLFactory::encrypt( data, cipherAlgorithm, keyHash, opts = 0, initializationVector = '' )
    uses openssl_encrypt
    Encrypts given data with given method and key, returns a raw or base64 encoded string
    
    data         string
                   The plaintext message data to be encrypted
    scipherAlgorithm
                 tring
                   cipher method, one of openssl_get_cipher_methods()
    keyHash      string
                   The key
    opts         int
                   bitwise disjunction of the flags OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING
     initializationVector
                 string
                   A non-NULL Initialization Vector
    
    return string   encrypted data
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getEncryptedString( data, cipherAlgorithm, keyHash, opts = 0, initializationVector = '' )
    alias of OpenSSLFactory::encrypt
    static method


###### OpenSSLFactory::privateDecrypt( data, privateKey, padding = null )
    uses openssl_private_decrypt
    Decrypts data that was previously encrypted via openssl_public_encrypt()
    
    data         string
    privateKey   resource|string|array
                   The private key corresponding that was used to encrypt the data
                   1 key resource
                   2. A string having the format (file://)/path/to/file.pem.
                      The named file must contain a PEM encoded key
                   3. A string, PEM formatted key.
                   4 array(2/3, passPhrase)
    padding     int
                  One of OPENSSL_PKCS1_PADDING (default),
                  OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
                  
    return string   decrypted data using private key
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getprivateKeyDecryptedString( data, privateKey, padding = null )
    alias of OpenSSLFactory::privateDecrypt
    static method


###### OpenSSLFactory::privateEncrypt( data, privateKey, padding = null )
    uses openssl_private_encrypt
    Encrypts data with private key and stores the result into crypted.
    
    data         string
    privateKey   resource|string|array
                   The private key that was used to encrypt the data
                   1 key resource
                   2. A string having the format (file://)/path/to/file.pem.
                      The named file must contain a PEM encoded key
                   3. A string, PEM formatted key.
                   4 array(2/3, passPhrase)
    padding      int
                   One of OPENSSL_PKCS1_PADDING (default), OPENSSL_NO_PADDING
                   
    return string  encrypted data using private key
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getprivateKeyEncryptedString( data, privateKey, padding = null )
    alias of OpenSSLFactory::privateEncrypt
    static method


###### OpenSSLFactory::publicDecrypt( data, publicKey, padding = null )
    uses openssl_public_decrypt
    Decrypts data that was previous encrypted via openssl_private_encrypt()
    
    data         string
                   Encrypted data to decrypt
    publicKey    resource|string
                   The public key corresponding that was used to encrypt the data
                   1 key resource
                   2. A string having the format (file://)/path/to/file.pem.
                      The named file must contain a PEM encoded key
                   3. A string, PEM formatted key.
    padding      int
                   One of OPENSSL_PKCS1_PADDING (default),
                   OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
                   
    return string  decrypted data using public key
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getpublicKeyDecryptedString( data, publicKey, padding = null )
    alias of OpenSSLFactory::publicDecrypt
    static method


###### OpenSSLFactory::publicEncrypt( data, publicKey, padding = null )
    uses openssl_public_encrypt
    Encrypted message can only be read only by owner of the private key
    
    data         string
                   Raw data to encrypt
    publicKey    resource|string
                   The public key that was used to encrypt the data
                   1 key resource
                   2. A string having the format (file://)/path/to/file.pem.
                      The named file must contain a PEM encoded key
                   3. A string, PEM formatted key.
    padding      int
                   One of OPENSSL_PKCS1_PADDING (default),
                   OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
                   
    return string  encrypted data using public key
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getpublicKeyEncryptedString( data, publicKey, padding = null )
    alias of OpenSSLFactory::publicEncrypt
    static method


###### OpenSSLFactory::open( data, envelopeKey, privateKeyId, method = null, initializationVector = null )
    uses openssl_open
    Return opened (decrypted) sealed_data using the private key
    associated with the key identifier priv_key_id and the envelope key,
    and fills open_data with the decrypted data.
    The envelope key is generated when the data are sealed and can only be used by one specific private key.
    
    data         string
                   Encrypted (sealed) data to decrypt
    envelopeKey  string
                   The public key corresponding that was used to encrypt the data
    privateKeyId resource|string|array
                   The private key resource corresponding that was used to encrypt the data
                   1 key resource
                   2. A string having the format (file://)/path/to/file.pem.
                      The named file must contain a PEM encoded key
                   3. A string, PEM formatted key.
                   4. array (2/3, passPhrase)
    cipherAlgorithm
                 string
                   The cipher method, default 'RC4'
    initializationVector
                 string
                   A non-NULL Initialization Vector, PHP >= 7.0.0
                   
    return string  opened sealed data
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getOpenedSealedString(
    alias of OpenSSLFactory::open
    static method


###### OpenSSLFactory::seal( data, publicKeyIds, cipherAlgorithm = 'RC4', initializationVector = null )
    uses openssl_seal
    Seals (encrypts) data by using the given method with a randomly generated secret key.
    The key is encrypted with each of the public keys associated with the identifiers in publicKeyIds
    and each encrypted key is returned in envelopeKeys.
    This means that one can send sealed data to multiple recipients (provided one has obtained their public keys).
    Each recipient must receive both the sealed data and the envelopekey
    that was encrypted with the recipient's public key.
    
    data         string
                   Data to seal
    publicKeyIds array|resource|string
                   (assoc) array/single public key resource identifier(s), each one of
                   1 key resource
                   2. A string having the format (file://)/path/to/file.pem.
                      The named file must contain a PEM encoded key
                   3. A string, PEM formatted key.
    cipherAlgorithm
                 string
                   The cipher method, default 'RC4'
    initializationVector
                 string
                    A non-NULL Initialization Vector, PHP >= 7.0.0
                   
    return array   [ sealedData, envelopeKeys ]   sealed (encrypted) data, envelope keys
                   The array envelopeKeys will have the same keys as publicKeyIds
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::getSealedString( data, publicKeyIds, cipherAlgorithm = 'RC4', initializationVector = null )
    alias of OpenSSLFactory::seal
    static method


###### OpenSSLFactory::sign( data, privateKey, signatureAlgo = OPENSSL_ALGO_SHA1 )
    uses openssl_sign
    Return (computed) signature for the specified data by generating a cryptographic digital signature
    using the private key associated with priv_key_id.
    @see https://www.php.net/manual/en/function.openssl-sign.php
    
    data         string
                   Data to seal
    privateKey   resource|string
                   1. a key, returned by openssl_get_privatekey()
                   2. a PEM formatted key
                   3. file with PEM formatted key content
    signatureAlgo 
                 int|string
                   1. one of https://www.php.net/manual/en/openssl.signature-algos.php
                   2. one of openssl_get_md_methods(), self::getAvailableDigestMethods()
                   default OPENSSL_ALGO_SHA1
                   
    return string  signature
    throws InvalidArgumentException, RuntimeException on error
    static method


###### OpenSSLFactory::getSignature( data, privateKey, signatureAlgo = OPENSSL_ALGO_SHA1 )
    alias of OpenSSLFactory::sign
    static method


###### OpenSSLFactory::verify( data, signature, publicKeyId, signatureAlgo = OPENSSL_ALGO_SHA1 )
    uses openssl_verify
    Verifies that the signature is correct for the specified data using the public key associated with pub_key_id.
    This must be the public key corresponding to the private key used for signing.
    
    data         string
                   The string of data used to generate the signature previously
    signature    string
                    A raw binary string, generated by openssl_sign() or similar means
    publicKeyId  resource|string
                   1. a key (resource), returned by  openssl_get_publickey()
                   2. a PEM formatted key
                   3. file with PEM formatted key
    signatureAlgo
                 int|string
                   1. one of https://www.php.net/manual/en/openssl.signature-algos.php
                   2. one of openssl_get_md_methods(), self::getAvailableDigestMethods()
                   default OPENSSL_ALGO_SHA1
                   
    return bool    true if signature  with publicKey is verified ok
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLFactory::isSignatureOkForPublicKey( data, signature, publicKeyId, signatureAlgo = OPENSSL_ALGO_SHA1 )
    alias of OpenSSLFactory::verify
    static method


###### OpenSSLFactory::getPbkdf2( passWord, salt = null, keyLength = 40, iterations = 10000, algorithm = 'SHA1' )
    uses openssl_pbkdf2
    Return a PKCS5 v2 PBKDF2 (raw binary) string
    Computes PBKDF2 (Password-Based Key Derivation Function 2), a key derivation function defined in PKCS5 v2
    
    passWord     string
                   Password from which the derived key is generated.
    salt         string
                   PBKDF2 recommends a crytographic salt of at least 64 bits (8 bytes).
                   default 64 random bytes
    keyLength    int
                   Length of desired output key, default 40
    iterations   int 
                   The number of iterations desired. NIST recommends at least 10,000.
    algorithm    string
                   Optional hash or digest algorithm from openssl_get_md_methods(), default SHA-1
                   
    return string
    throws InvalidArgumentException on error
    static method


#### Usage and examples

Please review test/OpenSSLFactoryTest.php

    getCipherIvLengthTest11
      OpenSSLFactory::getCipherIvLength

    encryptDecryptTest12
      OpenSSLFactory::getEncryptedString / getDecryptedString

    assertOptsTest13
      OpenSSLCsrFactory::assertOpts - catch exception

    assertPaddingTest14
      OpenSSLCsrFactory::assertPadding - catch exception

    signVerifyTest21
      OpenSSLFactory::getSignature / isSignatureOkForPublicKey

    OpenSSLFactoryTester3x
      OpenSSLFactory::getpublicKeyEncryptedString
      OpenSSLFactory::getprivateKeyDecryptedString
      OpenSSLFactory::getprivateKeyEncryptedString
      OpenSSLFactory::getpublicKeyDecryptedString


[[return to docs](docs.md)][[return to README](../README.md)]
