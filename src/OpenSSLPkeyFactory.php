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
use function is_null;
use function openssl_pkey_export;
use function openssl_pkey_export_to_file;
use function openssl_pkey_free;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function openssl_pkey_get_private;
use function openssl_pkey_new;
use function restore_error_handler;
use function set_error_handler;

/**
 * Class OpenSSLPkeyFactory
 *
 * Wrapper for PHP OpenSSL PKEY functions, encapsulates the PKEY resource
 * Note: You need to have a valid openssl.cnf installed for this to operate correctly.
 * Require a Psr\Log logger, provided by LoggerDepot
 */
class OpenSSLPkeyFactory extends OpenSSLBaseFactory2
{

    /**
     * constant
     */
    const PKEYRESOURCETYPE  = 'OpenSSL key';

    /**
     * @var resource
     * @access private
     */
    private $pkeyResource = null;

    /**
     * Class constructor
     *
     * If argument configArgs is set, a new CSR (Certificate Signing Request) is set
     *
     * @param array $configArgs           Note, see assertConfig() for valid algos
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function __construct( $configArgs = null ) {
        $this->logger = LoggerDepot::getLogger( get_class());
        $this->log(LogLevel::INFO, self::initClassStr());
        if( ! empty( $configArgs )) {
            $this->setConfig( $configArgs );
            $this->pKeyNew();
        }
    }

    /**
     * Class factory method
     *
     * @param array $configArgs          Note, see assertConfig() for valid algos
     * @throws InvalidArgumentException
     * @return static
     * @access static
     */
    public static function factory( $configArgs = null ) {
        return new self( $configArgs );
    }

    /**
     * Generates a new pKewy resource - uses openssl_pkey_new
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-new.php
     * @param array  $configArgs    If null, uses 'instance create'-configArgs, if set, otherwise from file 'openssl.cnf'
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function pKeyNew( $configArgs = null ) {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        $configArgs = $this->getConfig( $configArgs );
        $result     = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkey_new( $configArgs );
        }
        catch( Exception $e ) {
            self::assessCatch( self::getCm( __METHOD__ ), $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), null, self::getOpenSSLErrors());
        }
        $this->setPkeyResource( $result );
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $this;
    }

    /**
     * Return array( privateKey, publicKey ) with keys as resources - joins export/getPrivate + getDetails + getPublic
     *
     * @param string $passPhrase
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPrivatePublicKeyPairAsResources( $passPhrase = null ) {
        return [
            $this->getPrivateKeyAsResource( $passPhrase ),
            self::getPublic( $this->getDetails()[self::KEY] )
        ];
    }

    /**
     * Return array( privateKey, publicKey ) with keys as PEM strings - joins export + getDetails
     *
     * @param string $passPhrase   opt private key passphrase
     * @param array  configArgs    opt private key config
     *                             If null, uses 'instance create'-configArgs, if set
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPrivatePublicKeyPairAsPemStrings( $passPhrase = null, $configArgs = null ) {
        return [
            $this->export( $passPhrase, $configArgs ),
            $this->getDetails()[self::KEY]
        ];
    }

    /**
     * Return array( privateKey, publicKey ) with keys as DER strings - extends export + getDetails
     *
     * @param string $passPhrase   opt private key passphrase
     * @param array  configArgs    opt private key config
     *                             If null, uses 'instance create'-configArgs, if set
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPrivatePublicKeyPairAsDerStrings( $passPhrase = null, $configArgs = null ) {
        return [
            $this->getPrivateKeyAsPemString( $passPhrase, $configArgs ),
            $this->getPublicKeyAsDerString()
        ];
    }

    /**
     * Saves privateKey and publicKey into PEM files - joins exportToFile + getDetails
     *
     * @param string $privateFile  Path to the output private key file.
     * @param string $publicFile  Path to the output public key file.
     * @param string $passPhrase
     * @param array  configArgs    If null, uses 'instance create'-configArgs, if set
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function savePrivatePublicKeyPairIntoPemFiles( $privateFile, $publicFile, $passPhrase = null, $configArgs = null ) {
        $this->exportToFile( $privateFile, $passPhrase, $configArgs );
        $this->savePublicKeyIntoPemFile( $publicFile );
        return $this;
    }

    /**
     * Saves privateKey and publicKey into DER files - extends exportToFile + getDetails
     *
     * @param string $privateFile  Path to the output private key file.
     * @param string $publicFile  Path to the output public key file.
     * @param string $passPhrase
     * @param array  configArgs    If null, uses 'instance create'-configArgs, if set
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function savePrivatePublicKeyPairIntoDerFiles(
        $privateFile, $publicFile, $passPhrase = null, $configArgs = null
    ) {
        $this->savePrivateKeyIntoDerFile($privateFile, $passPhrase, $configArgs  );
        $this->savePublicKeyIntoDerFile( $publicFile );
        return $this;
    }

    /**
     * Return an exportable string representation of a private key - uses openssl_pkey_export
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export.php
     * @param string $passPhrase
     * @param array  $configArgs    If null, uses 'instance create'-configArgs, if set
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function export( $passPhrase = null, $configArgs = null ) {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isPkeyResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $passPhrase = self::assertPassPhrase( $passPhrase, 1 );
        $configArgs = $this->getConfig( $configArgs );
        $result     = false;
        $output     = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkey_export( $this->pkeyResource, $output, $passPhrase, $configArgs );
        }
        catch( Exception $e ) {
            self::assessCatch( self::getCm( __METHOD__ ), $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), null, self::getOpenSSLErrors());
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $output;
    }

    /**
     * Return string PEM representation of a private key - alias of export
     *
     * @param string $passPhrase
     * @param array  configArgs    If null, uses 'instance create'-configArgs, if set
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPrivateKeyAsPemString( $passPhrase = null, $configArgs = null ) {
        return $this->export( $passPhrase, $configArgs );
    }

    /**
     * Return string DER representation of a private key - extends export
     *
     * @param string $passPhrase
     * @param array  configArgs    If null, uses 'instance create'-configArgs, if set
     * @return string  DER format
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPrivateKeyAsDerString( $passPhrase = null, $configArgs = null ) {
        return self::pem2Der( $this->export( $passPhrase, $configArgs ));
    }

    /**
     * Return private key as resource - join of export/getPrivate
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export.php
     * @param string $passPhrase   Must be used if the specified key is encrypted (protected by a passphrase)
     * @return resource    type 'OpenSSL key'
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPrivateKeyAsResource( $passPhrase = null ) {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        $keyResource = self::getPrivate(
            $this->export( $passPhrase ),
            $passPhrase
        );
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $keyResource;
    }

    /**
     * Save an exportable (string) PEM representation of a private key into a file - uses openssl_pkey_export_to_file
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export-to-file.php
     * @param string $fileName      Path to the output file.
     * @param string $passPhrase
     * @param array  $configArgs    If null, uses 'instance create'-configArgs, if set
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function exportToFile( $fileName, $passPhrase = null, $configArgs = null ) {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isPkeyResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        Assert::fileNameWrite( $fileName, 1 );
        $fileName = Workshop::getFileWithoutProtoPrefix( $fileName );
        $passPhrase = self::assertPassPhrase( $passPhrase, 2 );
        $configArgs = $this->getConfig( $configArgs );
        $result     = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkey_export_to_file( $this->pkeyResource, $fileName, $passPhrase, $configArgs );
        }
        catch( Exception $e ) {
            self::assessCatch( self::getCm( __METHOD__ ), $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), null, self::getOpenSSLErrors());
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $this;
    }

    /**
     * Save an exportable (string) PEM representation of a private key into a file - alias of exportToFile
     *
     * @param string $fileName      Path to the output file.
     * @param string $passPhrase
     * @param array  $configArgs    If null, uses 'instance create'-configArgs, if set
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function savePrivateKeyIntoPemFile( $fileName, $passPhrase = null, $configArgs = null ) {
        return $this->exportToFile( $fileName, $passPhrase, $configArgs );
    }

    /**
     * Save an exportable (string) DER representation of a private key into a file - extends export
     *
     * @param string $fileName      Path to the output file.
     * @param string $passPhrase
     * @param array  $configArgs    If null, uses 'instance create'-configArgs, if set
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function savePrivateKeyIntoDerFile( $fileName, $passPhrase = null, $configArgs = null ) {
        Assert::fileNameWrite( $fileName );
        self::assertPassPhrase( $passPhrase );
        $configArgs = $this->getConfig( $configArgs );
        Workshop::saveDataToFile( $fileName, $this->export( $passPhrase, $configArgs ));
        return $this;
    }

    /**
     * Return private key as resource - uses openssl_pkey_get_private
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-private.php
     * @param resource|string $key   1. A pkey resource
     *                               2. A string having the format (file://)path/to/file.pem.
     *                                  The named file must contain a PEM encoded certificate/private key (it may contain both).
     *                               3. A string, PEM formatted private key.
     * @param string $passPhrase   Must be used if the specified key is encrypted (protected by a passphrase)
     * @return resource     type 'OpenSSL key'
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @static
     */
    public static function getPrivate( $key,  $passPhrase = null ) {
        $logger     = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        $key = self::assertPkey( $key, 1 );
        $passPhrase = self::assertPassPhrase( $passPhrase, 2 );
        $result = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkey_get_private( $key, $passPhrase );
        }
        catch( Exception $e ) {
            self::assessCatch( self::getCm( __METHOD__ ), $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), null, self::getOpenSSLErrors());
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $result;
    }

    /**
     * Returns an array with the key details - uses openssl_pkey_get_details
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-details.php
     * output 'type' constants
     * 0 => OPENSSL_KEYTYPE_RSA
     * 1 => OPENSSL_KEYTYPE_DSA
     * 2 => OPENSSL_KEYTYPE_DH
     * 3 => OPENSSL_KEYTYPE_EC
     * @return array
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getDetails() {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isPkeyResourceSet()) {
            throw new RuntimeException( self::$FMTERR2 );
        }
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkey_get_details( $this->pkeyResource );
        }
        catch( Exception $e ) {
            self::assessCatch( self::getCm( __METHOD__ ), $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), null, self::getOpenSSLErrors());
        }
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $result;
    }

    /*
     * Return bool true if pKey details key (/subkey) is set
     *
     * @param string $key      see OpenSSLInterface constants
     * @param string $subKey   see OpenSSLInterface constants
     * @return bool            true if found
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function isDetailsKeySet( $key = null, $subKey = null ) {
        if( ! $this->isPkeyResourceSet()) {
            return false;
        }
        return parent::isSourceKeySet( $this->getDetails(), $key,  $subKey );
    }

    /*
     * Return pKey details (key(/subkey)), null if not found
     *
     * @param string $key      see OpenSSLInterface constants
     * @param string $subKey   see OpenSSLInterface constants
     * @param bool $toBase64   if key(/subKey) set, true (default) output in Base64, false not
     * @return string|array    null if not found
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function getDetailsKey( $key = null, $subKey = null, $toBase64 = true  ) {
        if( ! $this->isPkeyResourceSet()) {
            return null;
        }
        Assert::bool( $toBase64, 3, true );
        $result = parent::getSource( $this->getDetails(), $key,  $subKey );
        if( is_null( $result )) {
            return null;
        }
        return ( ! is_array( $result ) && $toBase64 ) ? Convert::base64Encode( $result ) : $result;
    }

    /*
     * Return pKey details RSA modulus (details[rsa][n]), null if not found
     *
     * @param bool $toBase64   default true, output in Base64, false binary string
     * @return string          null if not found
     * @throws RunTimeException
     */
    public function getDetailsRsaModulus( $toBase64 = true ) {
        Assert::bool( $toBase64, 1, true );
        $source = $this->isPkeyResourceSet() ? $this->getDetails() : null;
        $result =  parent::getSource( $source, self::RSA,  self::N );
        return ( ! is_null( $result ) && $toBase64 ) ? Convert::base64Encode( $result ) : $result;
    }

    /*
     * Return pKey details RSA public exponent (details[rsa][e]), null if not found
     *
     * @param bool $toBase64   default true, output in Base64, false binary string
     * @return string          null if not found
     * @throws RunTimeException
     */
    public function getDetailsRsaExponent( $toBase64 = true ) {
        Assert::bool( $toBase64, 1, true );
        $source = $this->isPkeyResourceSet() ? $this->getDetails() : null;
        $result = parent::getSource( $source, self::RSA,  self::E );
        return ( ! is_null( $result ) && $toBase64 ) ? Convert::base64Encode( $result ) : $result;
    }


    /**
     * Return PEM string with the public key - extends getDetails
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-public.php#74986
     * @return string  PEM format
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPublicKeyAsPemString() {
        return $this->getDetails()[self::KEY];
    }

    /**
     * Return DER string with the public key - extends getDetails
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-public.php#74986
     * @return string  DER format
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getPublicKeyAsDerString() {
        return self::pem2Der( $this->getDetails()[self::KEY] );
    }

    /**
     * Save public key into PEM file - extends getDetails
     *
     * @param string $fileName
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function savePublicKeyIntoPemFile( $fileName ) {
        Assert::fileNameWrite( $fileName, 1 );
        Workshop::saveDataToFile( $fileName, $this->getDetails()[self::KEY] );
        return $this;
    }

    /**
     * Save public key into DER file - extends getDetails
     *
     * @param string $fileName
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function savePublicKeyIntoDerFile( $fileName ) {
        Assert::fileNameWrite( $fileName, 1 );
        Workshop::saveDataToFile( $fileName, self::pem2Der( $this->getDetails()[self::KEY] ));
        return $this;
    }

    /**
     * Returns public key resource - extends getDetails + getPublic
     *
     * @return resource     with type 'OpenSSL key'
     * @throws InvalidArgumentException
     */
    public function getPublicKeyResource() {
        return self::getPublic( $this->getDetails()[self::KEY] );
    }


    /**
     * Returns extracted public key (i.e. resource) from certificate, prepared for use - uses openssl_pkey_get_public
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-get-public.php
     * @param resource|string $certificate  1. a resource :  X.509 certificate OR public key resource
     *                                      2. a string having the format (file://)path/to/file.pem.
     *                                         The named file must contain a PEM encoded certificate/public key (it may contain both).
     *                                      3. a PEM formatted string : X.509 OR public key
     * @return resource     with type 'OpenSSL key'
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @static
     */
    public static function getPublic( $certificate ) {
        $logger = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        $certificate = ( self::isValidPkeyResource( $certificate ))
            ? self::assertPkey( $certificate )
            : OpenSSLX509Factory::assertX509( $certificate );
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkey_get_public( $certificate );
        }
        catch( Exception $e ) {
            self::assessCatch( self::getCm( __METHOD__ ), $e, ( false !== $result ), self::getOpenSSLErrors());
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), null, self::getOpenSSLErrors());
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $result;
    }

    /**
     * Returns extracted public key (i.e. resource) from certificate, prepared for use - alias of getPublic
     *
     * @param resource|string $certificate  1. a resource :  X.509 certificate OR public key resource
     *                                      2. a string having the format (file://)path/to/file.pem.
     *                                         The named file must contain a PEM encoded certificate/public key (it may contain both).
     *                                      3. a PEM formatted string : X.509 OR public key
     * @return resource     with type 'OpenSSL key'
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @static
     */
    public static function getPublicKeyAsResource( $certificate ) {
        return self::getPublic( $certificate );
    }

    /** ***********************************************************************
     *  Getters and setters etc
     */

    /**
     * Return valid (source) (private/public) key
     *
     * @param resource|string|array $pKey  1. A key resource
     *                                     2. A string having the format (file://)path/to/file.pem,
     *                                        the named file must contain a PEM encoded certificate/private key (it may contain both)
     *                                     3. A string containing the content of a (single) PEM encoded certificate/key
     *                                     4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                       where $key represents a key specified using the file or textual content notation above,
     *                                       and $passphrase represents a string containing the passphrase for that private key
     * @param int|string $argIx
     * @param bool $fileToString
     * @return resource|string|array       if file, 'file://'-prefixed
     * @throws InvalidArgumentException
     * @static
     */
    public static function assertPkey( $pKey, $argIx = null, $fileToString = false ) {
        $passPhrase = null;
        if( is_array( $pKey )) {
            $passPhrase = OpenSSLBaseFactory::assertPassPhrase( end( $pKey ), $argIx );
            $pKey       = reset( $pKey );
        }
        $pKey = parent::assertResourceFileStringPem( $pKey, $argIx, $fileToString, self::PKEYRESOURCETYPE );
        return ( empty( $passPhrase )) ? $pKey : [ $pKey, $passPhrase ];
    }

    /**
     * Return bool true if pkey resource is valid
     *
     * @param string|resource $pkeyResource
     * @return bool
     * @static
     */
    public static function isValidPkeyResource( $pkeyResource ) {
        return parent::isValidResource( $pkeyResource, self::PKEYRESOURCETYPE );
    }

    /**
     * Free pkey resource - uses openssl_pkey_free
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-free.php
     * @return static
     */
    public function freePkeyResource() {
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ )); // test ###
        if( $this->isPkeyResourceSet()) {
            set_error_handler( self::$ERRORHANDLER );
            try {
                openssl_pkey_free( $this->pkeyResource );
            }
            catch( Exception $e ) {}
            finally {
                restore_error_handler();
            }
            unset( $this->pkeyResource );
        }
        return $this;
    }

    /**
     * Return pKey resource
     *
     * @return resource
     */
    public function getPkeyResource() {
        return $this->pkeyResource;
    }

    /**
     * @return bool
     */
    public function isPkeyResourceSet() {
        if( empty( $this->pkeyResource )) {
            return false;
        }
        if( ! self::isValidPkeyResource( $this->pkeyResource )) {
            $this->log(
                LogLevel::WARNING,
                self::getErrRscMsg( __METHOD__, self::PKEYRESOURCETYPE, $this->pkeyResource )
            );
            return false;
        }
        return true;
    }

    /**
     * @param resource pkeyResource
     * @return static
     * @throws InvalidArgumentException
     */
    public function setPkeyResource( $pkeyResource ) {
        if( ! self::isValidPkeyResource( $pkeyResource )) {
            $msg = self::getErrRscMsg( __METHOD__, self::PKEYRESOURCETYPE, $pkeyResource );
            $this->log( LogLevel::ERROR,  $msg );
            throw new InvalidArgumentException( $msg );
        }
        $this->pkeyResource = $pkeyResource;
        $this->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $this;
    }

}
