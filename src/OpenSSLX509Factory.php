<?php
/**
 * OpenSSLToolbox   the PHP OpenSSL Toolbox
 *
 * This file is a part of OpenSSLToolbox.
 *
 * @author    Kjell-Inge Gustafsson, kigkonsult <ical@kigkonsult.se>
 * @copyright 2020-21 Kjell-Inge Gustafsson, kigkonsult, All rights reserved
 * @link      https://kigkonsult.se
 * @license   Subject matter of licence is the software Asit. The above
 *            copyright, link, package and version notices, this licence notice shall be
 *            included in all copies or substantial portions of the OpenSSLToolbox.
 *
 *            OpenSSLToolbox is free software: you can redistribute it and/or modify it
 *            under the terms of the GNU Lesser General Public License as published by
 *            the Free Software Foundation, either version 3 of the License, or (at your
 *            option) any later version.
 *
 *            OpenSSLToolbox is distributed in the hope that it will be useful, but
 *            WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *            or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 *            License for more details.
 *
 *            You should have received a copy of the GNU Lesser General Public License
 *            along with OpenSSLToolbox. If not, see <https://www.gnu.org/licenses/>.
 *
 *            Disclaimer of rights
 *
 *            Herein may exist software logic (hereafter solution(s)) found on internet
 *            (hereafter originator(s)). The rights of each solution belongs to
 *            respective originator;
 *
 *            Credits and acknowledgements to originators!
 *            Links to originators are found wherever appropriate.
 *
 *            Only OpenSSLToolbox copyright holder works, OpenSSLToolbox author(s) works
 *            and solutions derived works and OpenSSLToolbox collection of solutions are
 *            covered by GNU Lesser General Public License, above.
 */
declare( strict_types = 1 );
namespace Kigkonsult\OpenSSLToolbox;

use Exception;
use InvalidArgumentException;
use Kigkonsult\LoggerDepot\LoggerDepot;
use Psr\Log\LogLevel;
use RuntimeException;

use function get_class;
use function in_array;
use function is_null;
use function is_resource;
use function is_string;
use function openssl_x509_check_private_key;
use function openssl_x509_checkpurpose;
use function openssl_x509_export_to_file;
use function openssl_x509_export;
use function openssl_x509_fingerprint;
use function openssl_x509_free;
use function openssl_x509_parse;
use function openssl_x509_read;
use function restore_error_handler;
use function set_error_handler;
use function strtoupper;

/**
 * Class OpenSSLX509Factory
 *
 * Wrapper for PHP OpenSSL X509 functions, encapsulates the X509 resource
 * Note: You need to have a valid openssl.cnf installed for this to operate correctly.
 * Require a Psr\Log logger, provided by LoggerDepot
 *
 * @see https://en.wikipedia.org/wiki/X.509
 * @see https://tools.ietf.org/html/rfc5280
 */
class OpenSSLX509Factory extends OpenSSLBaseFactory
{
    /**
     * constants
     */
    const X509RESOURCETYPE  = 'OpenSSL X.509';

    /**
     * @var string|resource
     *
     * 1. An X.509 resource returned from openssl_x509_read()
     * 2. A string having the format (file://)path/to/cert.pem
     *    The named file must contain a (single) PEM encoded certificate
     * 3. A string containing the content of a (single) PEM encoded certificate
     */
    private $x509certData;

    /**
     * @var resource
     */
    private $x509Resource = null;

    /**
     * Class constructor
     *
     * If argument x509certData is set, a new X509 resource is set
     *
     * @param null|string|resource $x509certData
     *                                      1. An X.509 resource returned from openssl_x509_read()
     *                                      2. A string having the format (file://)path/to/cert.pem;
     *                                         the named file must contain a (single) PEM encoded certificate
     *                                      3. A string containing the content of a (single) PEM encoded certificate
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function __construct( $x509certData = null ) {
        $this->logger = LoggerDepot::getLogger( get_class());
        $this->log( LogLevel::INFO, self::initClassStr());
        if( ! empty( $x509certData )) {
            $this->setX509certData( $x509certData );
            $this->read();
        }
    }

    /**
     * Class factory method
     *
     * @param null|string|resource $x509certData
     *                                      1. An X.509 resource returned from openssl_x509_read()
     *                                      2. A string having the format (file://)path/to/cert.pem;
     *                                         the named file must contain a (single) PEM encoded certificate
     *                                      3. A string containing the content of a (single) PEM encoded certificate
     * @return static
     *@throws RunTimeException
     * @throws InvalidArgumentException
     */
    public static function factory( $x509certData = null ) : self
    {
        return new self( $x509certData );
    }

    /**
     * Class factory method, producing a CSR cert 'under the hood'
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-new.php
     * @param resource|string $caCert  The generated certificate will be signed by caCert.
     *                             If caCert is NULL, the generated certificate will be a self-signed certificate.
     *                             1. An X.509 resource returned from openssl_x509_read()
     *                             2. A string having the format (file://)path/to/cert.pem;
     *                                the named file must contain a (single) PEM encoded certificate
     *                             3. A string containing the content of a (single) PEM encoded certificate
     * @param array $dn            The Distinguished Name or subject fields to be used in the certificate.
     *                             Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     * @param resource|string|array $privateKeyId  A private key
     *                             1. private key resource
     *                             2. PEM string
     *                             3. ('file://')fileName with PEM string content
     *                             4. array(2/3, passPhrase)
     * @param null|array $configArgs    Finetuning the CSR signing
     * @param null|array $extraAttribs  Additional configuration options for the CSR
     *                             Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     * @param null|int   $days     Length of time for which the generated certificate will be valid, in days (default 365).
     * @param null|int   $serial   Optional the serial number of issued certificate (default 0)
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @return static
     */
    public static function csrFactory(
        $caCert,
        array $dn,
        $privateKeyId,
        $configArgs = null,
        $extraAttribs = null,
        $days = 365,
        $serial = 0
    ) : self
    {
        $logger      = LoggerDepot::getLogger( get_class());
        $logger->log(
            LogLevel::INFO,
            strtoupper( self::$INIT ) . self::getCm( __METHOD__ )
        );
        $csrFactory  = OpenSSLCsrFactory::factory(
            $dn,
            $privateKeyId,
            $configArgs,
            $extraAttribs
        );
        $csrResource = $csrFactory->getX509CertResource(
            $caCert,
            $privateKeyId,
            $days,
            $configArgs,
            $serial
        );
        $x509String  = self::factory( $csrResource )->getX509CertAsPemString();
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return new self( $x509String );
    }

    /**
     * Return bool true if the private key corresponds to the certificate - uses openssl_x509_check_private_key
     *
     * The function does not check if key is indeed a private key or not.
     * It merely compares the public materials (e.g. exponent and modulus of an RSA key)
     * and/or key parameters (e.g. EC params of an EC key) of a key pair.
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-check-private-key.php
     * @param resource|string|array $key   1. A pkey resource
     *                                     2. A string having the format (file://)path/to/file.pem.
     *                                        The named file must contain a PEM encoded certificate/private key (it may contain both).
     *                                     3. A string, PEM formatted private key.
     *                                     4 array ( 2/3, passPhrase )
     * @param null|string $passPhrase
     * @return bool
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function checkPrivateKey( $key, $passPhrase = null ) : bool
    {
        $this->log(
            LogLevel::DEBUG,
            self::$INIT . self::getCm( __METHOD__ )
        );
        if( ! $this->isX509ResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $key        = OpenSSLPkeyFactory::assertPkey( $key, 1, true );
        $passPhrase = self::assertPassPhrase( $passPhrase, 2 );
        if( ! empty( $passPhrase )) {
            $key = [ $key, $passPhrase ];
        }
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_x509_check_private_key( $this->x509Resource , $key );
        }
        catch( Exception $e ) {
            self::assessCatch(
                self::getCm( __METHOD__ ),
                $e,
                false,
                self::getOpenSSLErrors()
            );
        }
        finally {
            restore_error_handler();
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return (bool) $result;
    }

    /**
     * Return bool true if a certificate can be used for a particular purpose - uses openssl_x509_checkpurpose
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-checkpurpose.php
     * @param int $purpose
     *     X509_PURPOSE_SSL_CLIENT     Can the certificate be used for the client side of an SSL connection?
     *     X509_PURPOSE_SSL_SERVER     Can the certificate be used for the server side of an SSL connection?
     *     X509_PURPOSE_NS_SSL_SERVER  Can the cert be used for Netscape SSL server?
     *     X509_PURPOSE_SMIME_SIGN     Can the cert be used to sign S/MIME email?
     *     X509_PURPOSE_SMIME_ENCRYPT  Can the cert be used to encrypt S/MIME email?
     *     X509_PURPOSE_CRL_SIGN       Can the cert be used to sign a certificate revocation list (CRL)?
     *     X509_PURPOSE_ANY            Can the cert be used for Any/All purposes?
     *     These options are not bitfields - you may specify one only!
     * @param null|array $caInfo     An array containing file and directory names
     *                               that specify the locations of trusted CA files.
     *                               If a directory is specified,
     *                               then it must be a correctly formed hashed directory
     *                               as the openssl command would use.
     * @param null|string $unTrustedFile
     *                               If specified, this should be the name of a (single) PEM encoded file holding certificates
     *                               that can be used to help verify the certificate,
     *                               although no trust is placed in the certificates that come from that file.
     * @return bool
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function checkPurpose(
        int $purpose,
        $caInfo = [],
        $unTrustedFile = null
    ) : bool
    {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isX509ResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        self::assertPurpose( $purpose );
        if( ! empty( $caInfo )) {
            self::assertCaInfo( $caInfo, 2 );
        }
        if( ! empty( $unTrustedFile )) {
            Assert::fileNameRead( $unTrustedFile, 3 );
        }
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            switch( true ) {
                case empty( $caInfo ) ;
                    $result = openssl_x509_checkpurpose( $this->x509Resource, $purpose );
                    break;
                case empty( $unTrustedFile ) ;
                    $result = openssl_x509_checkpurpose(
                        $this->x509Resource,
                        $purpose,
                        $caInfo
                    );
                    break;
                default :
                    $result = openssl_x509_checkpurpose(
                        $this->x509Resource,
                        $purpose,
                        $caInfo,
                        $unTrustedFile
                    );
                    break;
            }
        }
        catch( Exception $e ) {
            self::assessCatch(
                self::getCm( __METHOD__ ),
                $e,
                ( -1 != $result ),
                self::getOpenSSLErrors()
            );
        }
        finally {
            restore_error_handler();
        }
        if( -1 == $result ) {
            self::logAndThrowRuntimeException(
                self::getCm( __METHOD__ ),
                null,
                self::getOpenSSLErrors()
            );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $result;
    }

    /**
     * Return (string) an X509 certificate in a (single) PEM encoded format - uses openssl_x509_export
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-export.php
     * @param null|bool   $noText    optional, affects the verbosity of the output;
     *                          if it is FALSE, then additional human-readable information is included in the output.
     * @return string           an X509 certificate in a PEM encoded format
     * @throws RuntimeException
     */
    public function export( $noText = true ) : string
    {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isX509ResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $result = false;
        $output = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_x509_export(
                $this->x509Resource,
                $output,
                ( $noText ?? true )
            );
        }
        catch( Exception $e ) {
            self::assessCatch(
                self::getCm( __METHOD__ ),
                $e,
                ( false !== $result ),
                self::getOpenSSLErrors()
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException(
                self::getCm( __METHOD__ ),
                null,
                self::getOpenSSLErrors()
            );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $output;
    }

    /**
     * Return (string) an X509 certificate in a (single) PEM encoded format - alias of export
     *
     * @param null|bool $noText optional, affects the verbosity of the output;
     *                          if it is FALSE, then additional human-readable information is included in the output.
     * @return string           an X509 certificate in a PEM encoded format
     * @throws RuntimeException
     */
    public function getX509CertAsPemString( $noText = true ) : string
    {
        return $this->export( $noText );
    }

    /**
     * Return (string) an X509 certificate in a (single) DER encoded format - extends export
     *
     * @return string           an X509 certificate in a DER encoded format
     * @throws RuntimeException
     */
    public function getX509CertAsDerString() : string
    {
        return self::pem2Der( $this->export( true ));
    }

    /**
     * Save ( PEM encoded) information from an X509 certificate to named fileName - uses openssl_x509_export_to_file
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-export-to-file.php
     * @param string $fileName   Path to the output file. (ext pem, crt, cer)
     * @param null|bool $noText  optional, affects the verbosity of the output;
     *                            if it is FALSE, then additional human-readable information is included in the output.
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function exportToFile( string $fileName, $noText = true ) : self
    {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isX509ResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $fileName = Workshop::getFileWithoutProtoPrefix( $fileName );
        Assert::fileNameWrite( $fileName, 1 );
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_x509_export_to_file(
                $this->x509Resource,
                $fileName,
                ( $noText ?? true )
            );
        }
        catch( Exception $e ) {
            self::assessCatch(
                self::getCm( __METHOD__ ),
                $e,
                ( false !== $result ),
                self::getOpenSSLErrors()
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException(
                self::getCm( __METHOD__ ),
                null,
                self::getOpenSSLErrors()
            );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $this;
    }

    /**
     * Save (PEM encoded) information from an X509 certificate to named fileName - alias of exportToFile
     *
     * @param string $fileName  Path to the output file. (ext pem, crt, cer)
     * @param null|bool $noText Optional, affects the verbosity of the output;
     *                          if it is FALSE, then additional human-readable information is included in the output.
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function saveX509CertIntoPemFile( string $fileName, $noText = true ) : self
    {
        return $this->exportToFile( $fileName, $noText );
    }

    /**
     * Save (DER encoded) information from an X509 certificate to named fileName - extends export
     *
     * @param string $fileName  Path to the output file. (ext pem, crt, cer)
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function saveX509CertIntoDerFile( string $fileName ) : self
    {
        Assert::fileNameWrite( $fileName );
        $fileName = Workshop::getFileWithoutProtoPrefix( $fileName );
        Workshop::saveDataToFile( $fileName, self::pem2Der( $this->export( true )));
        return $this;
    }

    /**
     * Return the fingerprint, or digest, of a given X.509 certificate - uses openssl_x509_fingerprint
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-fingerprint.php
     * @param null|string $hashAlgorithm
     *                                The digest method or hash algorithm to use, default "sha1"
     * @param null|bool   $rawOutput  TRUE, outputs raw binary data. FALSE (default) outputs lowercase hexits
     * @return string                 a (hex) string containing the calculated certificate fingerprint
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function fingerprint( $hashAlgorithm = null, $rawOutput = false ) : string
    {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isX509ResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        if( empty( $hashAlgorithm )) {
            $hashAlgorithm = self::$HASHALGORITHMDEFAULT;
        }
        self::assertMdAlgorithm( $hashAlgorithm );
        $output    = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $output = openssl_x509_fingerprint(
                $this->x509Resource,
                $hashAlgorithm,
                ( $rawOutput ?? false )
            );
        }
        catch( Exception $e ) {
            self::assessCatch(
                self::getCm( __METHOD__ ),
                $e,
                ( false !== $output ),
                self::getOpenSSLErrors()
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $output ) {
            self::logAndThrowRuntimeException(
                self::getCm( __METHOD__ ),
                null,
                self::getOpenSSLErrors()
            );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $output;
    }

    /**
     * Return the fingerprint, or digest, of a given X.509 certificate - alias of fingerprint
     *
     * @param null|string $hashAlgorithm
     *                                The digest method or hash algorithm to use, default "sha1"
     * @param null|bool   $rawOutput  When set to TRUE, outputs raw binary data. FALSE outputs lowercase hexits.
     * @return string                 a (hex) string containing the calculated certificate fingerprint
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getDigestHash( $hashAlgorithm = null, $rawOutput = false ) : string
    {
        return $this->fingerprint( $hashAlgorithm, $rawOutput );
    }

    /**
     * Return (array) information from X509 certificate - uses openssl_x509_parse
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-parse.php
     * @param null|bool $shortNames controls how the data is indexed in the array
     *                         if shortNames is TRUE (the default) then fields will be indexed with the short name form,
     *                         otherwise, the long name form will be used - e.g.: CN is the shortName form of commonName.
     * @return array
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function parse( $shortNames = true ) : array
    {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isX509ResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $certArray  = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $certArray = openssl_x509_parse( $this->x509Resource, ( $shortNames ?? true ));
        }
        catch( Exception $e ) {
            self::assessCatch(
                self::getCm( __METHOD__ ),
                $e,
                ( false !== $certArray ),
                self::getOpenSSLErrors()
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $certArray ) {
            self::logAndThrowRuntimeException(
                self::getCm( __METHOD__ ),
                null,
                self::getOpenSSLErrors()
            );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $certArray;
    }

    /**
     * Return (array/string) information from X509 certificate - extends openssl_x509_parse
     *
     * @param null|bool $shortNames
     *                         controls how the data is indexed in the array
     *                         if shortNames is TRUE (the default) then fields will be indexed with the short name form,
     *                         otherwise, the long name form will be used - e.g.: CN is the shortName form of commonName.
     * @param null|string $key certificate information (array-)key, default null
     *                         see OpenSSLInterface constants
     * @param null|string $subKey
     *                         certificate information (array-)key/subKey, default null
     *                         see OpenSSLInterface constants
     * @return array|string    info array or info[key], null on not found
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function getCertInfo( $shortNames = true, $key = null, $subKey = null ) {
        $source = $this->parse( $shortNames );
        return ( is_null( $key ) && is_null( $subKey ))
            ? $source
            : parent::getSource( $this->parse( $shortNames ), $key, $subKey );
    }

    /**
     * Return subject DN (array) information from X509 certificate - extends openssl_x509_parse
     *
     * @param null|bool $shortNames
     *                         controls how the data is indexed in the array
     *                         if shortNames is TRUE (the default) then fields will be indexed with the short name form,
     *                         otherwise, the long name form will be used - e.g.: CN is the shortName form of commonName.
     * @param null|string $key subject DN key, MUST match shortName arg, default null
     *                         see OpenSSLInterface constants
     * @return array|string    subject DN array, or subject[DNkey], null is not found
     *                         see OpenSSLInterface constants
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function getCertSubjectDN( $shortNames = true, $key = null ) {
        return $this->getCertInfo( $shortNames, self::SUBJECT, $key );
    }

    /**
     * Return issuer DN (array) information from X509 certificate - extends openssl_x509_parse
     *
     * @param null|bool $shortNames controls how the data is indexed in the array
     *                         if shortNames is TRUE (the default) then fields will be indexed with the short name form,
     *                         otherwise, the long name form will be used - e.g.: CN is the shortName form of commonName.
     * @param null|string $key      subject issuer DN key, MUST match shortName arg, default null
     *                         see OpenSSLInterface constants
     * @return array|string    subject issuer DN array, or subject[issuerDNkey] value , null is not found
     *                         see OpenSSLInterface constants
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function getCertIssuerDN( $shortNames = true, $key = null ) {
        return $this->getCertInfo( $shortNames, self::ISSUER, $key );
    }

    /*
     * Return bool true if parse certInfoKey (/subkey) is set
     *
     * @param null|bool  $shortNames
     * @param null|string $certInfoKey   see OpenSSLInterface constants
     * @param string $subKey        see OpenSSLInterface constants
     * @return bool                 true if parse array key(/subKey) is set
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function isCertInfoKeySet(
        $shortNames = true,
        $certInfoKey = null,
        $subKey = null
    ) : bool
    {
        static $FMT = 'certInfoKey required';
        if( empty( $certInfoKey )) {
            throw new InvalidArgumentException( $FMT );
        }
        return parent::isSourceKeySet(
            $this->parse( $shortNames ),
            $certInfoKey,
            $subKey
        );
    }

    /**
     * Set resource identifier from a parsed X.509 certificate - uses openssl_x509_read
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-read.php
     * @param null|string $x509certData
     *                              1. An X.509 resource (returned from openssl_x509_read())
     *                              2. A string having the format (file://)path/to/cert.pem;
     *                                 the named file must contain a (single) PEM encoded certificate
     *                              3. A string containing a (single) PEM encoded certificate
     * @return static
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function read( $x509certData = null ) : self
    {
        static $FMTERR1 = 'argument x509certData is required';
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( empty( $x509certData )) {
            $x509certData = $this->getX509certData();
        }
        else {
            $x509certData = self::assertX509( $x509certData );
        }
        if( empty( $x509certData )) {
            throw new InvalidArgumentException( $FMTERR1 );
        }
        $x509Resource = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $x509Resource = openssl_x509_read( $x509certData );
        }
        catch( Exception $e ) {
            self::assessCatch(
                self::getCm( __METHOD__ ),
                $e,
                ( false !== $x509Resource ),
                self::getOpenSSLErrors()
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $x509Resource ) {
            self::logAndThrowRuntimeException(
                self::getCm( __METHOD__ ),
                null,
                self::getOpenSSLErrors()
            );
        }
        $this->setX509Resource( $x509Resource );
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $this;
    }

    /**
     * Set a resource identifier from string containing a PEM encoded certificate, alias of OpenSSLX509Factory::read
     *
     * @param string $x509CertificateString
     *     A string containing the content of a (single) PEM encoded certificate
     * @return static
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function createX509ResourceFromString( string $x509CertificateString ) : self
    {
        self::assertPemString( $x509CertificateString );
        return $this->read( $x509CertificateString );
    }

    /**
     * Set and generate a resource identifier from file containing a (single) PEM encoded certificate,
     * alias of OpenSSLX509Factory::read
     *
     * @param string $x509CertificateFile  A string having the format (file://)path/to/cert.pem;
     *                                     the named file must contain a (single) PEM encoded certificate
     * @return static
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function createX509ResourceFromFile( string $x509CertificateFile ) : self
    {
        Assert::fileNameRead( $x509CertificateFile );
        $this->read( $x509CertificateFile );
        return $this;
    }

    /** ***********************************************************************
     *  Getters and setters etc
     */

    /**
     * @var string fingerprint method algorithm default
     */
    public static $HASHALGORITHMDEFAULT = 'sha1';

    /**
     * Return valid x509
     *
     * @param resource|string $x509  1. An X.509 resource returned from openssl_x509_read()
     *                               2. A string having the format (file://)path/to/cert.pem
     *                                  The named file must contain a (single) PEM encoded certificate
     *                               3. A string containing a (single) PEM encoded certificate
     * @param null|int|string $argIx
     * @param null|bool $fileToString
     * @param null|bool $keyType          true on key, false on cert
     * @return resource|string       if file, 'file://'-prefixed
     * @throws InvalidArgumentException
     */
    public static function assertX509(
        $x509,
        $argIx = null,
        $fileToString = false,
        $keyType = true
    )
    {
        return parent::assertResourceFileStringPem(
            $x509,
            $argIx,
            $fileToString,
            self::X509RESOURCETYPE,
            $keyType
        );
    }

    /**
     * Return bool true if x509 resource is valid
     *
     * @param string|resource $x509
     * @return bool
     */
    public static function isValidX509Resource( $x509 ) : bool
    {
        return parent::isValidResource( $x509, self::X509RESOURCETYPE );
    }

    /**
     * Assert caInfo array contains valid (readable) fileNames or directories
     *
     * @param array $caInfo
     * @param null|int|string $argIx
     * @throws InvalidArgumentException
     */
    public static function assertCaInfo( array $caInfo, $argIx = null )
    {
        if( ! empty( $caInfo )) {
            foreach( $caInfo as $caParameter ) {
                Assert::fileName( $caParameter, $argIx );
            }
        }
    }

    /**
     * Assert check purpose flags
     *
     * @link https://www.php.net/manual/en/openssl.purpose-check.php
     * @param int $purpose
     * @throws InvalidArgumentException
     */
    private static function assertPurpose( $purpose ) {
        static $FMTERR1 = 'Invalid purpose';
        static $ALLOWED =  [ // values as keys
            1 => X509_PURPOSE_SSL_CLIENT,     // Can the certificate be used for the client side of an SSL connection?
            2 => X509_PURPOSE_SSL_SERVER,     // Can the certificate be used for the server side of an SSL connection?
            3 => X509_PURPOSE_NS_SSL_SERVER,  // Can the cert be used for Netscape SSL server?
            4 => X509_PURPOSE_SMIME_SIGN,     // Can the cert be used to sign S/MIME email?
            5 => X509_PURPOSE_SMIME_ENCRYPT,  // Can the cert be used to encrypt S/MIME email?
            6 => X509_PURPOSE_CRL_SIGN,       // Can the cert be used to sign a certificate revocation list (CRL)?
            7 => X509_PURPOSE_ANY,            // Can the cert be used for Any/All purposes?
        ];
        if( ! in_array( $purpose, $ALLOWED )) {
            throw new InvalidArgumentException( $FMTERR1 );
        }
    }

    /**
     * Free certData resource
     *
     * @return static
     */
    public function freeX509certData() : self
    {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( $this->isX509certDataSet()) {
            self::freeResource( $this->x509certData );
        }
        unset( $this->x509certData );
        return $this;
    }

    /**
     * @return string|resource
     */
    public function getX509certData()
    {
        return $this->x509certData;
    }

    /**
     * @return bool
     */
    public function isX509certDataSet() : bool
    {
        if( empty( $this->x509certData )) {
            return false;
        }
        if( is_string( $this->x509certData )) {
            return true;
        }
        if( ! self::isValidX509Resource( $this->x509certData )) {
            $msg = self::getErrRscMsg(
                __METHOD__,
                self::X509RESOURCETYPE,
                $this->x509certData
            );
            $this->log( LogLevel::WARNING, $msg );
            return false;
        }
        return true;
    }

    /**
     * @param string|resource $x509certData 1. An X.509 resource returned from openssl_x509_read()
     *                                      2. A string having the format (file://)path/to/cert.pem;
     *                                         the named file must contain a (single) PEM encoded certificate
     *                                      3. A string containing the content of a (single) PEM encoded certificate,
     * @return static
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function setX509certData( $x509certData ) : self
    {
        $this->x509certData = self::assertX509( $x509certData );
        return $this;
    }

    /**
     * Free x509 resource
     *
     * @return static
     */
    public function freeX509Resource() : self
    {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( $this->isX509ResourceSet()) {
            self::freeResource( $this->x509Resource );
        }
        unset( $this->x509Resource );
        return $this;
    }

    /**
     * Return X509 resource
     *
     * @return resource
     */
    public function getX509Resource() {
        return $this->x509Resource;
    }

    /**
     * @return bool
     */
    public function isX509ResourceSet() : bool
    {
        if( empty( $this->x509Resource )) {
            return false;
        }
        if( ! self::isValidX509Resource( $this->x509Resource )) {
            $msg = self::getErrRscMsg(
                __METHOD__,
                self::X509RESOURCETYPE,
                $this->x509Resource
            );
            $this->log( LogLevel::WARNING, $msg );
            return false;
        }
        return true;
    }

    /**
     * @param resource $x509Resource
     * @return static
     * @throws InvalidArgumentException
     */
    public function setX509Resource( $x509Resource ) : self
    {
        if( ! self::isValidX509Resource( $x509Resource )) {
            $msg = self::getErrRscMsg(
                __METHOD__,
                self::X509RESOURCETYPE,
                $this->x509Resource
            );
            $this->log( LogLevel::ERROR,  $msg );
            throw new InvalidArgumentException( $msg );
        }
        $this->x509Resource = $x509Resource;
        return $this;
    }

    /**
     * Free certificate resource . uses openssl_x509_free
     *
     * @link https://www.php.net/manual/en/function.openssl-x509-free.php
     * @param mixed $resource
     */
    private static function freeResource( $resource ) {
        if( is_resource( $resource )) {
            set_error_handler( self::$ERRORHANDLER );
            try {
                openssl_x509_free( $resource );
            }
            catch( Exception $e ) {}
            finally {
                restore_error_handler();
            }
        }
    }
}
