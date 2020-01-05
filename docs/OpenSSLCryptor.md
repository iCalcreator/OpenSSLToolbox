
## OpenSSLCryptor class
extends OpenSSLBase, implements OpenSSLInterface

Class constants

    FORMAT_RAW
    FORMAT_B64
    FORMAT_HEX


Class properties

    cipherAlgorithm  
                 string
    hashAlgorithm
                 string
    initializationVectorNumBytes
                 int
    format       int


>Class constructor and factory methods

###### OpenSSLCryptor::__construct( [ cipherAlgorithm [, hashAlgorithm [, encryptedEncoding ]]] )
    cipherAlgorithm
                 string
                   The cipher algorithm,         default aes-256-ctr encryption
    hashAlgorithm
                 string
                   Key hashing algorithm,        default sha256 key hashing
    encryptedEncoding
                 int
                   Format of the encrypted data, default base64 encoding
                   one of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
                   
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLCryptor::factory( [ cipherAlgorithm [, hashAlgorithm [, encryptedEncoding ]]] )
    static method
    return static


>Class logic methods

###### OpenSSLCryptor::getDecryptedString( data, decryptKey, dataEncoding = null )
    data         string
                   String to decrypt.
    decryptKey   string
                   Decryption key.
    dataEncoding int
                   Optional override for the input encoding,
                   one of FORMAT_RAW, FORMAT_B64 (default) or FORMAT_HEX
                   
    return string   The decrypted string.
    throws InvalidArgumentException, RuntimeException on error


###### OpenSSLCryptor::getEncryptedString( data, encryptKey [, outputEncoding ] )
    data         string
                   String to encrypt.
    encryptKey   string
                  Encryption key.
    outputEncoding
                 int
                   Optional override for the output encoding
                   one of FORMAT_RAW, FORMAT_B64 (default) or FORMAT_HEX
                   
    return string      The encrypted string.
    throws InvalidArgumentException, RuntimeException on error


>Getters and setters etc

###### OpenSSLCryptor::getCipherAlgorithm()
    return string cipherAlgorithm

###### OpenSSLCryptor::setCipherAlgorithm( cipherAlgorithm )
    cipherAlgorithm  
                 string
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLCryptor::getHashAlgorithm()
    return string   HashAlgorithm

###### OpenSSLCryptor::setHashAlgorithm( hashAlgorithm )
    hashAlgorithm
                 string
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLCryptor::getFormat( [ asText ] )
    asText       bool
                   default false
    
    return int|string  format

###### OpenSSLCryptor::setFormat( format )
    format       int
                   one of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
    
    return static
    throws InvalidArgumentException on error


>Getters and setters etc

###### OpenSSLCryptor::getCipherAlgorithm()
    return string

###### OpenSSLCryptor::setCipherAlgorithm( cipherAlgorithm )
    Set cipherAlgorithm (and initializationVectorNumBytes)
    
    cipherAlgorithm
                 string
    
    return static
    throws InvalidArgumentException


###### OpenSSLCryptor::getHashAlgorithm()
    return string

###### OpenSSLCryptor::setHashAlgorithm( hashAlgorithm )
    hashAlgorithm
                 string
    
    return static
    throws InvalidArgumentException


###### OpenSSLCryptor::getFormatText( format )
    format       int
    
    return string  format text
    static method

###### OpenSSLCryptor::getFormat( asText = false )
    asText       bool 
    
    return int|string

###### OpenSSLCryptor::setFormat( format )
    format       int 
    
    return static
    throws InvalidArgumentException


#### Usage and examples

```php
namespace Kigkonsult\OpenSSLToolbox;

$data = 'some data';
$key  = Workshop::getSalt();

$enCrypted = OpenSSLCryptor::factory()->getEncryptedString( $data, $key );

$deCrypted = OpenSSLCryptor::factory()->getDecryptedString( $enCrypted, $key );

```

>Please review test/OpenSSLCryptorTest.php

    OpenSSLdefaultTest1*
      defaults

    OpenSSLCryptorTest21
      OpenSSLCryptor::factory(+__construct),
      OpenSSLCryptor::getEncryptedString
      OpenSSLCryptor::getDecryptedString

[[return to docs](docs.md)][[return to README](../README.md)]
