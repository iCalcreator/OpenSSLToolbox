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

use Exception;
use InvalidArgumentException;
use Kigkonsult\LoggerDepot\LoggerDepot;
use Psr\Log\LogLevel;
use RuntimeException;

use function get_class;
use function is_array;
use function openssl_csr_export;
use function openssl_csr_export_to_file;
use function openssl_csr_get_public_key;
use function openssl_csr_get_subject;
use function openssl_csr_new;
use function openssl_csr_sign;
use function sprintf;

/**
 * Class OpenSSLCsrFactory
 *
 * Wrapper for PHP OpenSSL CSR functions, encapsulates the CSR resource
 * Note: You need to have a valid openssl.cnf installed for this to operate correctly.
 * Require a Psr\Log logger, provided by LoggerDepot
 */
class OpenSSLCsrFactory extends OpenSSLBaseFactory2
{

    /**
     * constant
     */
    const CSRRESOURCETYPE  = 'OpenSSL X.509 CSR';

    /**
     * @var array
     * @access private
     */
    private $dn = [];

    /**
     * @var string|array|resource     A private key
     *                                1. private key resource
     *                                2. fileName
     *                                3. PEM string
     *                                4. array( 2/3, passPhrase )
     * @access private
     */
    private $privateKey = null;

    /**
     * @var array
     * @access private
     */
    private $extraAttribs = [];

    /**
     * @var resource
     * @access private
     */
    private $csrResource = null;

    /**
     * Class constructor
     *
     * If arguments dn and privateKey are set, a new CSR resource are created
     *
     * @param array    $dn            The Distinguished Name or subject fields to be used in the certificate.
     *                                Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     * @param string|array|resource $privateKey  A private key
     *                                1. private key resource
     *                                2. ('file://')fileName
     *                                3. PEM string
     *                                4. array( 2/3, passPhrase )
     * @param array    $configArgs    Finetuning the CSR signing
     * @param array    $extraAttribs  Additional configuration options for the CSR
     *                                Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function __construct( array $dn = null, $privateKey = null, $configArgs = null, $extraAttribs = null ) {
        $this->logger = LoggerDepot::getLogger( get_class() );
        $this->log( LogLevel::INFO, self::initClassStr());
        $setReady = 0;
        if( ! empty( $dn )) {
            $this->setDn( $dn );
            $setReady += 1;
        }
        if( ! empty( $privateKey )) {
            $this->setPrivateKey( $privateKey );
            $setReady += 2;
        }
        if( ! empty( $configArgs )) {
            $this->setConfig( $configArgs );
        }
        if( ! empty( $extraAttribs )) {
            $this->setExtraAttribs( $extraAttribs );
        }
        if( 3 == $setReady ) {
            $this->csrNew();
        }
    }

    /**
     * Class factory method
     *
     * @param array    $dn            The Distinguished Name or subject fields to be used in the certificate.
     *                                Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     * @param string|array|resource $privateKey  A private key
     *                                1. private key resource
     *                                2. ('file://')fileName
     *                                3. PEM string
     *                                4. array( 2/3, passPhrase )
     * @param array    $configArgs    Finetuning the CSR signing, default config from class contruct
     * @param array    $extraAttribs  Additional configuration options for the CSR
     *                                Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     * @return static
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @access static
     */
    public static function factory( array $dn = null, $privateKey = null, $configArgs = null, $extraAttribs = null ) {
        return new self( $dn, $privateKey, $configArgs, $extraAttribs );
    }

    /**
     * Generate and save a CSR resource - uses openssl_csr_new
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-new.php
     * @param array $dn            The Distinguished Name or subject fields to be used in the certificate.
     *                             Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     *                             If null, uses 'instance create'-dn, if set
     * @param string|array|resource $privateKeyId  A private key
     *                             1. private key resource
     *                             2. PEM string
     *                             3. ('file://')fileName with PEM string content
     *                             4. array( 2/3, passPhrase )
     *                             If null, uses 'instance create'-privateKeyId, if set
     * @param array $configArgs    Finetuning the CSR signing, if null, uses 'instance create'-configArgs, if set
     * @param array $extraAttribs  Additional configuration options for the CSR
     *                             Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
     *                             If null, uses 'instance create'-extraAttribs, if set
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function csrNew( array $dn = null, $privateKeyId = null, $configArgs = null, $extraAttribs = null ) {
        static $FMTERR1 = 'Argument dn (#1) is required';
        static $FMTERR2 = 'Argument privateKey (#2) is required';
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( empty( $dn )) {
            $dn = $this->getDn();
        }
        if( empty( $dn )) {
            throw new InvalidArgumentException( $FMTERR1 );
        }
        $privateKeyId = $this->getPrivateKey( $privateKeyId, 2 );
        if( empty( $privateKeyId )) {
            throw new InvalidArgumentException( $FMTERR2 );
        }
        $configArgs   = $this->getConfig( $configArgs );
        $extraAttribs = $this->getExtraAttribs( $extraAttribs );
        if( empty( $extraAttribs )) {
            $extraAttribs = null;
        }
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_csr_new( $dn, $privateKeyId, $configArgs, $extraAttribs );
        }
        catch( Exception $e ) {
            self::assessCatch( __FUNCTION__, $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( __FUNCTION__, null, self::getOpenSSLErrors() );
        }
        $this->setCsrResource( $result );
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $this;
    }

    /**
     * Return the public key of a CSR  - uses openssl_csr_get_public_key
     *
     * Returns extracted public key from csr and prepares it for use by other functions.
     * including fields commonName (CN), organizationName (O), countryName (C) etc.
     * @link https://www.php.net/manual/en/function.openssl-csr-get-subject.php
     * @return resource   type 'OpenSSL key'
     * @throws RuntimeException
     */
    public function getPublicKey() {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isCsrResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_csr_get_public_key( $this->csrResource );
        }
        catch( Exception $e ) {
            self::assessCatch( __FUNCTION__, $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( __FUNCTION__, null, self::getOpenSSLErrors() );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $result;
    }

    /**
     * Return the public key of a CSR  - alias of getPublicKey
     *
     * @return resource   type 'OpenSSL key'
     * @throws RuntimeException
     */
    public function getPublicKeyAsResource() {
        return $this->getPublicKey();
    }

    /**
     * Return the subject (DN array) of a CSR  - uses openssl_csr_get_subject
     *
     * Returns subject distinguished name information encoded in the csr
     * including fields commonName (CN), organizationName (O), countryName (C) etc.
     * @link https://www.php.net/manual/en/function.openssl-csr-get-subject.php
     * @param bool $useShortnames  Controls how the ouput data is indexed in the array,
     *                             if TRUE (the default) then fields will be indexed with the short name form,
     *                             otherwise, long name forms will be used - e.g.: CN shortname form of commonName
     * @return array
     * @throws RuntimeException
     */
    public function getSubject( $useShortnames = true ) {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isCsrResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $useShortnames = Assert::bool( $useShortnames, 1, true );
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_csr_get_subject( $this->csrResource, $useShortnames );
        }
        catch( Exception $e ) {
            self::assessCatch( __FUNCTION__, $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( __FUNCTION__, null, self::getOpenSSLErrors() );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $result;
    }

    /**
     * Return the subject (DN array) of a CSR  - alias of getSubject
     *
     * @param bool $useShortnames  Controls how the ouput data is indexed in the array,
     *                             if TRUE (the default) then fields will be indexed with the short name form,
     *                             otherwise, long name forms will be used - e.g.: CN shortname form of commonName
     * @return array
     * @throws RuntimeException
     */
    public function getDNfromCsrResource( $useShortnames = true ) {
        return $this->getSubject( $useShortnames );
    }

    /**
     * Return (exports) a CSR as a string in PEM format - uses openssl_csr_export
     *
     * @link https://www.php.net/manual/en/function.openssl-csr-export.php
     * @param bool   $noText    Optional, affects the verbosity of the output;
     *                          if it is FALSE, then additional human-readable information is included in the output.
     * @return string
     * @throws RuntimeException
     */
    public function export( $noText = true ) {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isCsrResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $noText = Assert::bool( $noText, 1, true );
        $result = false;
        $output = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_csr_export( $this->csrResource, $output, $noText );
        }
        catch( Exception $e ) {
            self::assessCatch( __FUNCTION__, $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( __FUNCTION__, null, self::getOpenSSLErrors() );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $output;
    }

    /**
     * Return (exports) a CSR as a string in PEM format - alias of export
     *
     * @param bool   $noText    Optional, affects the verbosity of the output;
     *                          if it is FALSE, then additional human-readable information is included in the output.
     * @return string  PEM format
     * @throws RuntimeException
     */
    public function getCSRasPemString( $noText = true ) {
        return $this->export( $noText );
    }

    /**
     * Return (exports) a CSR as a string in DER format - extends export
     *
     * @return string  DER format
     * @throws RuntimeException
     */
    public function getCSRasDerString() {
        return self::pem2Der( $this->export( true ));
    }

    /**
     * Save an Certificate Signing Request into a PEM file - uses openssl_csr_export_to_file
     *
     * Export the Certificate Signing Request represented by csr and saves it in PEM format into file
     * @link https://www.php.net/manual/en/function.openssl-csr-export-to-file.php
     * @param string $fileName  Path to the output file.
     * @param bool   $noText    Optional, affects the verbosity of the output;
     *                          if it is FALSE, then additional human-readable information is included in the output.
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function exportToFile( $fileName, $noText = true ) {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isCsrResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $fileName = Workshop::getFileWithoutProtoPrefix( $fileName );
        Assert::fileNameWrite( $fileName, 1 );
        $noText = Assert::bool( $noText, 2, true );
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_csr_export_to_file( $this->csrResource, $fileName, $noText );
        }
        catch( Exception $e ) {
            self::assessCatch( __FUNCTION__, $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( __FUNCTION__, null, self::getOpenSSLErrors() );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $this;
    }

    /**
     * Save an Certificate Signing Request into a Pem file - alias of exportToFile
     *
     * @param string $fileName  Path to the output file.
     * @param bool   $noText    Optional, affects the verbosity of the output;
     *                          if it is FALSE, then additional human-readable information is included in the output.
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function saveCSRcertIntoPemFile( $fileName, $noText = true ) {
        return $this->exportToFile( $fileName, $noText );
    }

    /**
     * Save an Certificate Signing Request into a Der file - extends export
     *
     * @param string $fileName  Path to the output file. (NO 'file://'-prefix)
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function saveCSRcertIntoDerFile( $fileName ) {
        Assert::fileNameWrite( $fileName );
        Workshop::saveDataToFile( $fileName, self::pem2Der( $this->export( true )));
        return $this;
    }

    /**
     * Return an x509 certificate resource  - uses openssl_csr_sign
     *
     * Sign a CSR with another certificate (or itself) and generate a certificate
     * @link https://www.php.net/manual/en/function.openssl-csr-sign.php
     * @param resource|string $caCert   The generated certificate will be signed by caCert.
     *                           If caCert is NULL, the generated certificate will be a self-signed certificate.
     *                           1. An X.509 resource returned from openssl_x509_read()
     *                           2. A string having the format (file://)path/to/cert.pem;
     *                              the named file must contain a (single) PEM encoded certificate
     *                           3. A string containing the content of a (single) PEM encoded certificate
     * @param string|resource $privateKeyId
     *                           The private key that corresponds to caCert, PEM string or resource
     *                           1. private key resource
     *                           2. fileName, content string PEM string
     *                           3. string PEM string
     *                           4. array( 2/3, passPhrase )
     * @param int   $days        Length of time for which the generated certificate will be valid, in days (default 365).
     * @param array $configArgs  Finetuning the CSR signing, default config from class contruct
     *                           If null, uses 'instance create'-configArgs, if set
     * @param int   $serial      Optional the serial number of issued certificate (default 0)
     * @return resource
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function sign( $caCert, $privateKeyId = null, $days = 365, $configArgs = null, $serial = 0 ) {
        static $PRIVATEKEY = 'privateKey';
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isCsrResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $caCert = ( empty( $caCert )) ? null : OpenSSLX509Factory::assertX509( $caCert );
        $privateKeyId = $this->getPrivateKey( $privateKeyId, 2 );
        if( empty( $privateKeyId )) {
            throw new InvalidArgumentException( sprintf( self::$FMTERR4, $PRIVATEKEY ));
        }
        $days       = Assert::int( $days, 3, 365 );
        $configArgs = $this->getConfig( $configArgs );
        $serial     = Assert::int( $serial, 5, 0 );
        $result     = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_csr_sign( $this->csrResource, $caCert, $privateKeyId, $days, $configArgs, $serial );
        }
        catch( Exception $e ) {
            self::assessCatch( __FUNCTION__, $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( __FUNCTION__, null, self::getOpenSSLErrors() );
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $result;
    }

    /**
     * Return an x509 certificate resource  - alias of sign
     *
     * @param resource|string $caCert  The generated certificate will be signed by caCert.
     *                           If caCert is NULL, the generated certificate will be a self-signed certificate.
     *                           1. An X.509 resource returned from openssl_x509_read()
     *                           2. A string having the format (file://)path/to/cert.pem;
     *                              the named file must contain a (single) PEM encoded certificate
     *                           3. A string containing the content of a (single) PEM encoded certificate
     * @param string|array|resource $privateKeyId  A private key
     *                           1. private key resource
     *                           2. ('file://'+)fileName
     *                           3. PEM string
     *                           4. array( 2/3, passPhrase )
     * @param int   $days        Length of time for which the generated certificate will be valid, in days (default 365).
     * @param array $configArgs  Finetuning the CSR signing, default config from class contruct, if set
     * @param int   $serial      Optional the serial number of issued certificate (default 0)
     * @return resource
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getX509CertResource( $caCert, $privateKeyId = null, $days = 365, $configArgs = null, $serial = 0 ) {
        return $this->sign( $caCert, $privateKeyId, $days, $configArgs, $serial );
    }

    /** ***********************************************************************
     *  Getters and setters etc
     */

    /**
     * Return bool true if CSR resource is valid
     *
     * @param string|resource $csrResource
     * @return bool
     * @static
     */
    public static function isValidCsrResource( $csrResource ) {
        return parent::isValidResource( $csrResource, self::CSRRESOURCETYPE );
    }

    /**
     * @param string $key    see OpenSSLInterface constants
     * @return string|array  null if key is not found
     */
    public function getDn( $key = null ) {
        return parent::getSource( $this->dn, $key );
    }

    /**
     * @param string $key    see OpenSSLInterface constants
     * @return bool          true if DN (key) is set
     */
    public function isDnSet( $key = null ) {
        return parent::isSourceKeySet( $this->dn, $key );
    }

    /**
     * @param string $key    see OpenSSLInterface constants
     * @param mixed  $value
     * @return static
     * @throws InvalidArgumentException
     */
    public function addDn( $key, $value ) {
        Assert::string( $key );
        $this->dn[$key] = $value;
        return $this;
    }

    /**
     * @param array $dn
     * @return static
     */
    public function setDn( array $dn ) {
        foreach( $dn as $key => $value ) {
            $this->addDn( $key, $value );
        }
        return $this;
    }

    /**
     * @param resource|string|array $privateKeyId
     * @param int|string $argIx
     * @return string|resource
     */
    public function getPrivateKey( $privateKeyId = null, $argIx = null ) {
        if( empty( $privateKeyId )) {
            return $this->privateKey;
        }
        return OpenSSLPkeyFactory::assertPkey( $privateKeyId, $argIx );
    }

    /**
     * @return bool
     */
    public function isPrivateKeySet() {
        return ( ! empty( $this->privateKey ));
    }

    /**
     * @param string|resource $privateKey
     * @return static
     * @throws InvalidArgumentException
     */
    public function setPrivateKey( $privateKey ) {
        $this->privateKey = OpenSSLPkeyFactory::assertPkey( $privateKey );
        return $this;
    }

    /**
     * @param string $key
     * @param mixed  $value
     * @return static
     * @throws InvalidArgumentException
     */
    public function addExtraAttribs( $key, $value ) {
        Assert::string( $key );
        $this->extraAttribs[$key] = $value;
        return $this;
    }

    /**
     * @param string|array $keyAttrs
     * @return string|array   null if (key is) not found
     */
    public function getExtraAttribs( $keyAttrs = null ) {
        if( ! empty( $keyAttrs ) && is_array( $keyAttrs )) {
            return $keyAttrs;
        }
        return parent::getSource( $this->extraAttribs, $keyAttrs );
    }

    /**
     * @param string $key
     * @return bool
     */
    public function isExtraAttribsSet( $key = null ) {
        return parent::isSourceKeySet( $this->extraAttribs, $key );
    }

    /**
     * @param array $extraAttribs
     * @return static
     * @throws InvalidArgumentException
     */
    public function setExtraAttribs( array $extraAttribs ) {
        foreach( $extraAttribs as $key => $value ) {
            $this->addExtraAttribs( $key, $value );
        }
        return $this;
    }

    /**
     * @return resource
     */
    public function getCsrResource() {
        return $this->csrResource;
    }

    /**
     * @return bool
     */
    public function isCsrResourceSet() {
        if( empty( $this->csrResource )) {
            return false;
        }
        if( ! self::isValidCsrResource( $this->csrResource )) {
            $msg = self::getErrRscMsg( __METHOD__, self::CSRRESOURCETYPE, $this->csrResource );
            $this->log( LogLevel::WARNING, $msg );
            return false;
        }
        return true;
    }

    /**
     * @param resource $csrResource
     * @return static
     * @throws InvalidArgumentException
     */
    public function setCsrResource( $csrResource ) {
        if( ! self::isValidCsrResource( $csrResource )) {
            $msg = self::getErrRscMsg( __METHOD__, self::CSRRESOURCETYPE, $csrResource );
            $this->log( LogLevel::ERROR,  $msg );
            throw new InvalidArgumentException( $msg );
        }
        $this->csrResource = $csrResource;
        return $this;
    }
}
