## OpenSSLToolbox

provides object-oriented, secure and extended access to PHP OpenSSL functions

#### Conception basics
The OpenSSL pkey functions are assembled in the

* OpenSSLPkeyFactory class

The OpenSSL CSR functions are assembled in the

* OpenSSLCsrFactory class

The OpenSSL x509 functions are assembled in the

* OpenSSLX509Factory class

The OpenSSL pkcs7 functions are assembled in the

* OpenSSLPkcs7Factory class

The OpenSSL pkcs12 functions are assembled in the

* OpenSSLPkcs12Factory class

The OpenSSL spki functions are assembled in the

* OpenSSLSpkiFactory class

Remaining OpenSSL functions are assembled in the

* OpenSSLFactory class

Asserts and convenient salt, base64, hex, pack utility etc methods are assembled in the

* Assert class
* Convert class


#### Methods

All methods have

* argument validation and throws InvalidArgumentException on error
* errorHandler protection and result error evaluation, throws RuntimeException on error

Method names originates from OpenSSL function names

* Ex 'openssl_pkey_export' is encapsulated in method OpenSSLPkeyFactory::export()

Most methods has also more convenient and describable named method alias

* Ex OpenSSLPkeyFactory::getPrivateKeyAsPemString() for 'openssl_pkey_export'

Most methods (ex setters) are chainable (ie return 'static')

The OO-classes, above, has 'factory' methods, support 'one-liners' and
inherit usefull constants defind in the OpenSSLInterface

Supplementary methods for message digest / hmac digest support are assembled in the

  * HashFactory class
  * HmacHashFactory class


#### Example Usage
Generate keys :
``` php
<?php
namespace Kigkonsult\OpenSSLToolbox;

$config = [
    OpenSSLPkeyFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
    OpenSSLPkeyFactory::PRIVATEKEYBITS => 4096,
    OpenSSLPkeyFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
];

$pKeyFactory      = new OpenSSLPkeyFactory( $config );

// Generate a private key
$privateKeyString = $pKeyFactory->getPrivateKeyAsPemString();
// Generate a public key
$publicKeyString  = $pKeyFactory->getPublicKeyAsPemString();
/* 
// or 
list( $privateKeyString, $publicKeyString ) =
    $pKeyFactory->getPrivatePublicKeyPairAsPemStrings();
// or one-liner, all-in-one
list( $privateKeyString, $publicKeyString ) =
    OpenSSLPkeyFactory::factory( $config )
                      ->getPrivatePublicKeyPairAsPemStrings();
// or to files
OpenSSLPkeyFactory::factory( $config )
                  ->savePrivatePublicKeyPairIntoPemFiles( 'priv.pem', 'pub.pem' )
*/

// Distinguished Name or subject fields to be used in the certificate
$DN = [
    OpenSSLCsrFactory::COUNTRYNAME          => "GB",
    OpenSSLCsrFactory::STATEORPROVINCENAME  => "Somerset",
    OpenSSLCsrFactory::LOCALITYNAME         => "Glastonbury",
    OpenSSLCsrFactory::ORGANIZATIONNAME     => "The Brain Room Limited",
    OpenSSLCsrFactory::ORGANIZATIONUNITNAME => "PHP Documentation Team",
    OpenSSLCsrFactory::COMMONNAME           => "Wez Furlong",
    OpenSSLCsrFactory::EMAILADDRESS         => "wez@example.com"
];
// Generate a certificate signing request
$csrFactory       = OpenSSLCsrFactory::factory( $DN, $privateKeyString, $config );
$csrCertString    = $csrFactory->getCSRasPemString();

// Generate a self-signed cert
$x509CertResource = $csrFactory->getX509CertResource( null, $privateKeyString );
$x509Factory      = OpenSSLX509Factory::factory()
                                      ->setX509Resource( $x509CertResource );
$x509CertString   = $x509Factory->getX509CertAsPemString();

/*
// or shorter
$x509CertString   = OpenSSLX509Factory::csrFactory( null, $DN, $privateKeyString, $config )
                                      ->getX509CertAsPemString();
// or save to pem/der-file
OpenSSLX509Factory::csrFactory( null, $DN, $privateKeyString, $config )
                  ->saveX509CertIntoPemFile( 'cert.pem' );
              //  ->saveX509CertIntoDerFile( 'cert.der' )
*/
```

Seal/open
``` php
<?php
...
// Seal data using public key(s)
$data        = implode( array_fill( 0, 100, 'Testing OpenSSL seal/open, !"#¤%&/()=?. '));
$recipientId = 'The Recipient';
$publicKeys  = [ $recipientId => $publicKeyString ];
list( $sealed, $envelopeKeys ) = OpenSSLFactory::getSealedString( $data, $publicKeys );

// Open (decrypted) data using private key
$decrypted   = OpenSSLFactory::getOpenedSealedString(
     $sealed, $envelopeKeys[$recipientId], $privateKeyString
);
```
Encrypt/decrypt
``` php
$data       = implode( array_fill( 0, 100, 'Testing OpenSSL encrypt/decrypt, !"#¤%&/()=?. '));
$cipher     = 'AES-256-ECB';
$passPhrase = Workshop::getSalt();
// encrypt string
$encrypted  = OpenSSLFactory::getEncryptedString( $data, $cipher, $passPhrase );
// decrypt string
$decrypted  = OpenSSLFactory::getDecryptedString( $encrypted, $cipher, $passPhrase );
```
More encrypt/decrypt
``` php
$data      = 'Testing OpenSSL public/private encrypt/decrypt, !"#¤%&/()=?. ';
// Encrypt the data using the PUBLIC key
$encrypted = OpenSSLFactory::getpublicKeyEncryptedString( $data, $publicKeyString );
// Decrypt the data using the PRIVATE key
$decrypted = OpenSSLFactory::getprivateKeyDecryptedString( $encrypted, $privateKeyString );

// Encrypt the data using the PRIVATE key
$encrypted = OpenSSLFactory::getprivateKeyEncryptedString( $data, $privateKeyString );
// Decrypt the data using the PUBLIC key
$decrypted = OpenSSLFactory::getpublicKeyDecryptedString( $encrypted, $publicKeyString );
```

#### Info

You will find 
- class information in [docs](docs/docs.md) folder 
- convenient constants in [src/OpenSSLInterface](src/OpenSSLInterface.php)
- a lot of more examples in the test folder.

#### Installation

###### [Composer]
From the Command Line:

``` php
composer require kigkonsult/openssltoolbox
```

In your `composer.json`:

``` json
{
    "require": {
        "kigkonsult/openssltoolbox": "dev-master"
    }
}
```

Acquire access
``` php
namespace Kigkonsult\OpenSSLToolbox;
...
include 'vendor/autoload.php';
```

###### Or
Download and acquire..

``` php
namepace Kigkonsult\OpenSSLToolbox;
...
include 'pathToSource/OpenSSLToolbox/autoload.php';
```

Run tests
```
cd pathToSource/OpenSSLToolbox
vendor/bin/phpunit
```
Note, it will takes some time, 80% coverage...<br>
But still remain untested parts, help appreciated.

#### Support

For support, please use [Github]/issues.


#### License

This project is licensed under the LGPLv3 License

[Composer]:https://getcomposer.org/
[Github]:https://github.com/iCalcreator/OpenSSLToolbox/issues
