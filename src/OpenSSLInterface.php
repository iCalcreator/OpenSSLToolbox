<?php
/**
 * OpenSSLToolbox   the PHP OpenSSL Toolbox
 *
 * This file is a part of OpenSSLToolbox.
 *
 * Copyright 2020 Kjell-Inge Gustafsson, kigkonsult, All rights reserved
 * author    Kjell-Inge Gustafsson, kigkonsult
 * Link      https://kigkonsult.se
 * Version   0.971
 * License   GNU Lesser General Public License version 3
 *
 *   Subject matter of licence is the software OpenSSLToolbox. The above
 *   copyright, link, package and version notices, this licence notice shall be
 *   included in all copies or substantial portions of the OpenSSLToolbox.
 *
 *   OpenSSLToolbox is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU Lesser General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or (at your
 *   option) any later version.
 *
 *   OpenSSLToolbox is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *   or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 *   License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with OpenSSLToolbox. If not, see <https://www.gnu.org/licenses/>.
 *
 * Disclaimer of rights
 *
 *   Herein may exist software logic (hereafter solution(s)) found on internet
 *   (hereafter originator(s)). The rights of each solution belongs to
 *   respective originator;
 *
 *   Credits and acknowledgements to originators!
 *   Links to originators are found wherever appropriate.
 *
 *   Only OpenSSLToolbox copyright holder works, OpenSSLToolbox author(s) works
 *   and solutions derived works and OpenSSLToolbox collection of solutions are
 *   covered by GNU Lesser General Public License, above.
 */
namespace Kigkonsult\OpenSSLToolbox;

/**
 * Interface OpenSSLInterface
 */
interface OpenSSLInterface
{

    /**
     * @const   PEM types
     * @link https://github.com/openssl/openssl/blob/master/include/openssl/pem.h#L26
     */
    const PEM_X509_OLD      = 'X509 CERTIFICATE';
    const PEM_X509          = 'CERTIFICATE';
    const PEM_X509_TRUSTED  = 'TRUSTED CERTIFICATE';
    const PEM_X509_REQ_OLD  = 'NEW CERTIFICATE REQUEST';
    const PEM_X509_REQ      = 'CERTIFICATE REQUEST';
    const PEM_X509_CRL      = 'X509 CRL';
    const PEM_EVP_PKEY      = 'ANY PRIVATE KEY';
    const PEM_PUBLIC        = 'PUBLIC KEY';
    const PEM_RSA           = 'RSA PRIVATE KEY';
    const PEM_RSA_PUBLIC    = 'RSA PUBLIC KEY';
    const PEM_DSA           = 'DSA PRIVATE KEY';
    const PEM_DSA_PUBLIC    = 'DSA PUBLIC KEY';
    const PEM_PKCS7         = 'PKCS7';
    const PEM_PKCS7_SIGNED  = 'PKCS #7 SIGNED DATA';
    const PEM_PKCS8         = 'ENCRYPTED PRIVATE KEY';
    const PEM_PKCS8INF      = 'PRIVATE KEY';
    const PEM_DHPARAMS      = 'DH PARAMETERS';
    const PEM_DHXPARAMS     = 'X9.42 DH PARAMETERS';
    const PEM_SSL_SESSION   = 'SSL SESSION PARAMETERS';
    const PEM_DSAPARAMS     = 'DSA PARAMETERS';
    const PEM_ECDSA_PUBLIC  = 'ECDSA PUBLIC KEY';
    const PEM_ECPARAMETERS  = 'EC PARAMETERS';
    const PEM_ECPRIVATEKEY  = 'EC PRIVATE KEY';
    const PEM_PARAMETERS    = 'PARAMETERS';
    const PEM_CMS           = 'CMS';

    /**
     * @const  key configargs (not complete list)
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-new.php
     *
     *                                               Configuration overrides
     * configargs key      type     openssl.conf     description
     *                              equivalent
     * digest_alg          string   default_md       Digest method or signature hash, usually one of openssl_get_md_methods()
     * x509_extensions     string   x509_extensions  Selects which extensions should be used when creating an x509 certificate
     * req_extensions      string   req_extensions   Selects which extensions should be used when creating a CSR
     * private_key_bits    integer  default_bits     Specifies how many bits should be used to generate a private key
     * private_key_type    integer  none             Specifies the type of private key to create.
     *                                                 https://www.php.net/manual/en/openssl.key-types.php
     *                                               This can be one of
     *                                                 OPENSSL_KEYTYPE_DSA,
     *                                                 OPENSSL_KEYTYPE_DH,
     *                                                 OPENSSL_KEYTYPE_RSA
     *                                                 OPENSSL_KEYTYPE_EC.
     *                                               The default value is OPENSSL_KEYTYPE_RSA.
     * encrypt_key         boolean  encrypt_key      Should an exported key (with passphrase) be encrypted?
     * encrypt_key_cipher  integer  none             One of cipher constants.
     *                                                 https://www.php.net/manual/en/openssl.ciphers.php
     *                                                 OPENSSL_CIPHER_RC2_40
     *                                                 OPENSSL_CIPHER_RC2_128
     *                                                 OPENSSL_CIPHER_RC2_64
     *                                                 OPENSSL_CIPHER_DES
     *                                                 OPENSSL_CIPHER_3DES
     *                                                 OPENSSL_CIPHER_AES_128_CBC
     *                                                 OPENSSL_CIPHER_AES_192_CBC
     *                                                 OPENSSL_CIPHER_AES_256_CBC
     * curve_name          string 	none             One of openssl_get_curve_names(). (PHP >= 7.1.0)
     * config              string   N/A              Path to your own alternative openssl.conf file.
     */

    const CONFIG           = 'config';
    const CURVENAME        = 'curve_name';
    const DEFAULTMD        = 'default_md';
    const DIGESTALGO       = 'digest_alg';
    const ENCRYPTKEYCIPHER = 'encrypt_key_cipher';
    const EXCRYPTKEY       = 'encrypt_key';
    const PRIVATEKEYBITS   = 'private_key_bits';
    const PRIVATEKEYTYPE   = 'private_key_type';
    const REQEXTENSIONS    = 'req_extensions';
    const X509EXTENSIONS   = 'x509_extensions';

    /**
     * @const  OpenSSLPkeyFactory::getDetails (openssl_pkey_get_details) keys
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-details.php
     */
    const BITS = 'bits';
    const KEY  = 'key';
    const TYPE = 'type';
    /**
     * Type is one of
     * (PHP constants) OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_DSA, OPENSSL_KEYTYPE_DH, OPENSSL_KEYTYPE_EC or -1 meaning unknown
     */

    /**
     * @const  For OPENSSL_KEYTYPE_RSA, RSA key subarray keys
     */
    const RSA       = 'rsa';        // main key, subkeys below
    const N         = 'n'; 	        // modulus
    const E         = 'e'; 	        // public exponent
    const D         = 'd'; 	        // private exponent
    const P         = 'p';          // prime 1
    const Q         = 'q';          // prime 2
    const DMP1      = 'dmp1';       // exponent1, d mod (p-1)
    const DMQ1      = 'dmq1';       // exponent2, d mod (q-1)
    const IQMP      = 'iqmp';       // coefficient, (inverse of q) mod p

    /**
     * @const  For OPENSSL_KEYTYPE_DSA, DSA key subarray keys
     */
    const DSA       = 'dsa';        // main key, subkeys below
//  const P         = 'p';          // prime number (public)                const defined above
//  const Q         = "q"           // 160-bit subprime, q | p-1 (public)   const defined above
    const G         = 'g';          // generator of subgroup (public)
    const PRIVKEY   = 'priv_key';   // private key x
    const PUBKEY    = 'pub_key';    // public key y = g^x

    /**
     * @const  For OPENSSL_KEYTYPE_DH, DH key subarray keys
     */
    const DH        = 'DH';         // main key, subkeys below
//  const P         = 'p';          // prime number (shared)                const defined above
//  const G         = 'g';          // generator of Z_p (shared)            const defined above
//  const PRIVKEY   = 'priv_key';   // private DH value x                   const defined above
//  const PUBKEY    = 'pub_key';    // public DH value g^x                  const defined above

    /**
     * @const  For OPENSSL_KEYTYPE_EC, EC key subarray keys
     */
    const EC        = 'ec';         // main key, subkeys below
//  const CURVENAME = 'curve_name'; // name of curve, see openssl_get_curve_names() (PHP >= 7.1.0)
    const CURVEOID  = 'curve_oid';  // ASN1 Object identifier (OID) for EC curve.
    const X         = 'x';          // x coordinate (public)
    const Y         = 'y';          // y coordinate (public)
//  const D         = 'd';          // private key                          const defined above


    /**
     * @const  CSR  DN (Distinguished Name) or subject fields to be used in the certificate
     *         X509 subject (/issuer) DN keys, long name form
     */
    const COUNTRYNAME          = 'countryName';
    const STATEORPROVINCENAME  = 'stateOrProvinceName';
    const ORGANIZATIONNAME     = 'organizationName';
    const ORGANIZATIONUNITNAME = 'organizationalUnitName';
    const COMMONNAME           = 'commonName';
    const EMAILADDRESS         = 'emailAddress';
    const LOCALITYNAME         = 'localityName';

    /**
     * @const  X509  subject (/issuer) DN keys, short name form
     * Note, no shortname for 'emailAddress'
     */
    const DN_C                 = 'C';   // countryName
    const DN_ST                = 'ST';  // stateOrProvinceName
    const DN_O                 = 'O';   // organizationName
    const DN_OU                = 'OU';  // organizationalUnitName
    const DN_CN                = 'CN';  // commonName
    const DN_L                 = 'L';   // localityName

    /**
     * @const  OpenSSLX509Factory::parse (openssl_x509_parse) keys (not complete list)
     */
    const NAME                 = 'name';
    const SUBJECT              = 'subject';
    const HASH                 = 'hash';
    const ISSUER               = 'issuer';
    const VERSION              = 'version';
    const SERIALNUMBER         = 'serialNumber';
    const SERIALNUMBERHEX      = 'serialNumberHex';
    const VALIDFROM            = 'validFrom';         // UTC ex '190907163312Z'
    const VALIDTO              = 'validTo';           // UTC ex '200906163312Z'
    const VALIDFROMTIMET       = 'validFrom_time_t';  // seconds (time same as VALIDFROM)
    const VALIDTOTIMET         = 'validTo_time_t';    // seconds (time same as VALIDTO)
    const SIGNATURETYPESN      = 'signatureTypeSN';   // ex 'RSA-SHA256',
    const SIGNATURETYPELN      = 'signatureTypeLN';   // ex 'sha256WithRSAEncryption',
    const SIGNATURETYPEID      = 'signatureTypeNID';  // ex 668,
    const PURPOSES             = 'purposes';
    const EXTENSIONS           = 'extensions';

    /**
     * @const  Optional pkcs12 (export) array args (other keys will be ignored)
     */
    const EXTRACERTS           = 'extracerts';    // array of extra certificates
                                                  // or a single certificate to be included in the PKCS#12 file.
    const FRIENDLYNAMES        = 'friendlyname';  // string to be used for the supplied certificate and key
}
