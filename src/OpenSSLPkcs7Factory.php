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

use function microtime;
use function number_format;
use function openssl_pkcs7_decrypt;
use function openssl_pkcs7_encrypt;
use function openssl_pkcs7_sign;
use function openssl_pkcs7_verify;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function unlink;

/**
 * Class OpenSSLPkcs7Factory
 *
 * Wrappers for PHP OpenSSL pkcs7 functions
 * Note: You need to have a valid openssl.cnf installed for this to operate correctly.
 * Require a Psr\Log logger, provided by LoggerDepot
 *
 * @see https://web.archive.org/web/20140329004600/http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-7-cryptographic-message-syntax-standar.htm
 */
class OpenSSLPkcs7Factory extends OpenSSLBaseFactory
{
    /**
     * @var string
     */
    private static $FMTC  = 'case #%d';

    /**
     * Assert (int, constant) PKCS7 flags
     *
     * PKCS7 flags/constants
     * PKCS7_TEXT     :   1
     * PKCS7_NOCERT   :   2
     * PKCS7_NOSIGS   :   4
     * PKCS7_NOCHAIN  :   8
     * PKCS7_NOINTERN :  16
     * PKCS7_NOVERIFY :  32
     * PKCS7_DETACHED :  64
     * PKCS7_BINARY   : 128
     * PKCS7_NOATTR   : 256
     * @param int        $flags
     * @param int|string $argIx
     * @param int        $valueIfNull
     * @return int
     * @throws InvalidArgumentException
     * @static
     * @todo assert also in conjunction
     */
    public static function assertflags( $flags, $argIx = 1, $valueIfNull = null ) {
        // static $FMTPOPTSERR = 'Invalid flags (arg #%d), %s';
        return Assert::int( $flags, $argIx, $valueIfNull );
        // throw new InvalidArgumentException( sprintf( $FMTPOPTSERR, $argIx, var_export( $cipherId )));
    }

    /**
     * @return string
     * @static
     */
    private static function getUniqueFilenameBase() {
        static $SP0 = '';
        return number_format( microtime( true ), 6,  $SP0, $SP0  ) .
            Workshop::getSalt( 6 );
    }

    /**
     * Decrypts an S/MIME encrypted message - uses openssl_pkcs7_decrypt
     *
     * Decrypts the S/MIME encrypted message contained in the file specified by infilename
     * using the certificate and its associated private key specified by recipcert and recipkey.
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-decrypt.php
     * @param string $infileName   The message to decrypt is stored in the file specified by infilename.
     * @param string $outfileName  The decrypted message is written to the file specified by outfilename.
     * @param resource|string $recipCert
     *                             1. An X.509 resource returned from openssl_x509_read()
     *                             2. A string having the format (file://)path/to/cert.pem
     *                                The named file must contain a PEM encoded certificate
     *                             3. A string containing the content of a PEM encoded certificate
     * @param resource|string|array $recipKey
     *                             1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                             2. A string having the format (file://)path/to/file.pem
     *                                The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                             3. A string containing the content of a PEM encoded certificate/key
     *                             4. For private keys, you may also use the syntax array($key, $passphrase)
     *                                where $key represents a key specified using the file or textual content notation above,
     *                                and $passphrase represents a string containing the passphrase for that private key
     * @return bool
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @static
     * @todo recipCert to PEMstring, due to self-signed cert?
     */
    public static function decrypt( $infileName, $outfileName, $recipCert, $recipKey ) {
        $logger     = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::fileNameRead( $infileName, 1 );
        Assert::fileNameWrite( $outfileName, 2 );
        $recipCert  = OpenSSLX509Factory::assertX509( $recipCert, 3 );
        if( is_resource( $recipCert )) {
            $recipCert = OpenSSLX509Factory::factory( $recipCert )->getX509CertAsPemString();
        }
        $recipKey   = OpenSSLPkeyFactory::assertPkey( $recipKey, 4 );
        $result     = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkcs7_decrypt( $infileName, $outfileName, $recipCert, $recipKey );
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
        return true;
    }

    /**
     * Return decrypted string, wrapper of 'decrypt'
     *
     * @param string $stringToDecrypt
     * @param resource|string $recipCert
     *                             1. An X.509 resource returned from openssl_x509_read()
     *                             2. A string having the format (file://)path/to/cert.pem
     *                                The named file must contain a (single) PEM encoded certificate
     *                             3. A string containing the content of a (single) PEM encoded certificate
     * @param resource|string|array $recipKey
     *                             1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                             2. A string having the format (file://)path/to/file.pem
     *                                The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                             3. A string containing the content of a PEM encoded certificate/key
     *                             4. For private keys, you may also use the syntax array($key, $passphrase)
     *                                where $key represents a key specified using the file or textual content notation above,
     *                                and $passphrase represents a string containing the passphrase for that private key
     * @return string
     * @throws Exception
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @static
     */
    public static function decryptString( $stringToDecrypt, $recipCert, $recipKey = null ) {
        $logger       = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::string( $stringToDecrypt, 1 );
        list( $infileName, $outfileName ) = self::getInOutFiles( $stringToDecrypt, self::getUniqueFilenameBase());
        $outputString = null;
        try {
            self::decrypt( $infileName, $outfileName, $recipCert, $recipKey );
            $outputString = Workshop::getFileContent( $outfileName );
        }
        catch( Exception $e ) {
            throw $e;
        }
        finally {
            if( is_file( $infileName )) {
                unlink( $infileName );
            }
            if( is_file( $outfileName )) {
                unlink( $outfileName );
            }
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $outputString;
    }

    /**
     * Encrypt an S/MIME message - uses openssl_pkcs7_encrypt
     *
     * Encrypts the infile contents using an RC2 40-bit cipher (default)
     * so that they can only be read by the intended recipients specified by recipcerts
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-encrypt.php
     * @param string         $infileName
     * @param string         $outfileName
     * @param resource|array|string $recipCerts  X.509 certificate (below), single/array
     *                                           1. An X.509 resource returned from openssl_x509_read()
     *                                           2. A string having the format (file://)path/to/cert.pem
     *                                              The named file must contain a (single) PEM encoded certificate
     *                                           3. A string containing the content of a (single) PEM encoded certificate
     * @param array          $headers            Headers that will be prepended to the data after it has been encrypted
     *                                           1. an associative array keyed by header name
     *                                           2. an indexed array, where each element contains a single header line.
     * @param int            $flags              Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
     * @param int            $cipherId           One of cipher constants. (https://www.php.net/manual/en/openssl.ciphers.php)
     * @return bool
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @static
     * @todo  assert array $recipCerts, $headers
     */
    public static function encrypt(
        $infileName, $outfileName, $recipCerts, $headers = [], $flags = 0, $cipherId = OPENSSL_CIPHER_RC2_40
    ) {
        $logger = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::fileNameRead( $infileName, 1 );
        Assert::fileNameWrite( $outfileName, 2 );
        if( is_array( $recipCerts )) {
            foreach( $recipCerts as $x => $recipCert ) {
                $recipCerts[$x] = OpenSSLX509Factory::assertX509( $recipCert, 3, true, false );
            }
        }
        else {
            $recipCerts = OpenSSLX509Factory::assertX509( $recipCerts, 3, true, false );
        }
        $flags = self::assertflags( $flags, 5, 0 );
        self::assertCipherId( $cipherId );
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkcs7_encrypt( $infileName, $outfileName, $recipCerts, $headers, $flags, $cipherId );
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
     * Return encrypted string, wrapper of 'encrypt'
     *
     * @param string         $stringToEncrypt
     * @param resource|array|string $recipCerts  1. Either a lone X.509 certificate, or an array of X.509 certificates.
     *                                           2. A string having the format (file://)path/to/cert.pem
     *                                              The named file must contain a (single) PEM encoded certificate
     * @param array          $headers            Headers that will be prepended to the data after it has been encrypted
     *                                           1. an associative array keyed by header name
     *                                           2. an indexed array, where each element contains a single header line.
     * @param int            $flags              Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
     * @param int            $cipherId           One of cipher constants. (https://www.php.net/manual/en/openssl.ciphers.php)
     * @return string
     * @throws Exception
     * @throws InvalidArgumentException
     * @throws RuntimeException
     * @static
     * @todo assert flags (also in conjunction), cipherId
     */
    public static function encryptString(
        $stringToEncrypt, $recipCerts, $headers = [], $flags = 0, $cipherId = OPENSSL_CIPHER_RC2_40
    ) {
        $logger       = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::string( $stringToEncrypt, 1 );
        list( $infileName, $outfileName ) = self::getInOutFiles( $stringToEncrypt, self::getUniqueFilenameBase());
        $outputString = null;
        try {
            self::encrypt( $infileName, $outfileName, $recipCerts, $headers, $flags, $cipherId );
            $outputString = Workshop::getFileContent( $outfileName );
        }
        catch( Exception $e ) {
            throw $e;
        }
        finally {
            if( is_file( $infileName )) {
                unlink( $infileName );
            }
            if( is_file( $outfileName )) {
                unlink( $outfileName );
            }
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $outputString;
    }

    /**
     *  Sign an S/MIME message  - uses openssl_pkcs7_sign
     *
     * Sign infileName content using the certificate and its matching private key specified by signCert and privKey parameters.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-sign.php
     * @param string $infileName     The input file you are intending to digitally sign.
     * @param string $outfileName    The file which the digital signature will be written to.
     * @param resource|string  $signCert The X.509 certificate used to digitally sign $infileName.
     *                               1. An X.509 resource returned from openssl_x509_read()
     *                               2. A string having the format (file://)path/to/cert.pem;
     *                                  The named file must contain a (single) PEM encoded certificate
     *                               3. A string containing the content of a (single) PEM encoded certificate
     * @param resource|string|array  $privKey  The private key corresponding to signCert.
     *                               1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                               2. A string having the format (file://)path/to/file.pem -
     *                                  The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                               3. A string containing the content of a PEM encoded certificate/key
     *                               4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                 where $key represents a key specified using the file or textual content notation above,
     *                                 and $passphrase represents a string containing the passphrase for that private key
     * @param array  $headers        an array of headers that will be prepended to the data after it has been signed
     *                               1. an associative array keyed by header name
     *                               2. an indexed array, where each element contains a single header line
     * @param int    $flags          Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
     *                               default PKCS7_DETACHED
     * @param string $extraCerts     Specifies the name of a file containing a bunch of extra certificates to include in the signature
     *                               which can for example be used to help the recipient to verify the certificate that you used
     * @return bool
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @static
     * @todo assert $headers, $flags (also in conjunction)
     */
    public static function sign(
        $infileName, $outfileName, $signCert, $privKey, $headers = [], $flags = null, $extraCerts = null
    ) {
        $logger       = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::fileNameRead( $infileName, 1 );
        Assert::fileNameWrite( $outfileName, 2 );
        $signCert     = OpenSSLX509Factory::assertX509( $signCert, 3 );
        $privKey      = OpenSSLPkeyFactory::assertPkey( $privKey, 4 );
        if( ! is_resource( $privKey ) && ! is_array( $privKey )) {
            $privKey = [ $privKey, '' ];
        }
        self::assertflags( $flags, 6, PKCS7_DETACHED );
        if( ! empty( $extraCerts )) {
            Assert::fileNameRead( $extraCerts, 7 );
        }
        $result = false;
        $case   = 7;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            switch( true ) {
                case ( empty( $headers ) && empty( $flags ) && empty( $extraCerts )) :
                    $case   = 4;
                    $result = openssl_pkcs7_sign( $infileName, $outfileName, $signCert, $privKey, [] );
                    break;
                case ( empty( $flags ) && empty( $extraCerts )) :
                    $case   = 5;
                    $result = openssl_pkcs7_sign( $infileName, $outfileName, $signCert, $privKey, $headers );
                    break;
                case empty( $extraCerts ) :
                    $case   = 6;
                    $result = openssl_pkcs7_sign( $infileName, $outfileName, $signCert, $privKey, $headers, $flags );
                    break;
                default :
                    $result = openssl_pkcs7_sign(
                        $infileName, $outfileName, $signCert, $privKey, $headers, $flags, $extraCerts
                    );
                    break;
            } // end switch
        }
        catch( Exception $e ) {
            $cond = ( false !== $result );
            $msg2 = sprintf( self::$FMTC, $case );
            self::assessCatch( self::getCm( __METHOD__ ), $e, $cond, self::getOpenSSLErrors(), $msg2 );
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            $msg2 = sprintf( self::$FMTC, $case );
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), $msg2, self::getOpenSSLErrors());
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return true;
    }

    /**
     *  Return an signed S/MIME message  - alias of 'sign'
     *
     * @param string $stringToSign   The string you are intending to digitally sign.
     * @param mixed  $signCert       The X.509 certificate used to digitally sign $infileName.
     *                                 1. An X.509 resource returned from openssl_x509_read()
     *                                 2. A string having the format (file://)path/to/cert.pem;
     *                                    The named file must contain a (single) PEM encoded certificate
     *                                 3. A string containing the content of a (single) PEM encoded certificate
     * @param mixed  $privKey        The private key corresponding to signCert.
     *                                 1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                                 2. A string having the format (file://)path/to/file.pem
     *                                    The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                                 3. A string containing the content of a PEM encoded certificate/key
     *                                 4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                   where $key represents a key specified using the file or textual content notation above,
     *                                   and $passphrase represents a string containing the passphrase for that private key
     * @param array  $headers        an array of headers that will be prepended to the data after it has been signed
     *                                 1. an associative array keyed by header name
     *                                 2. an indexed array, where each element contains a single header line
     * @param int    $flags          Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
     * @param string $extraCerts       Specifies the name of a file containing a bunch of extra certificates to include in the signature
     *                                 which can for example be used to help the recipient to verify the certificate that you used
     * @return string
     * @throws Exception
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @static
     */
    public static function signString(
        $stringToSign, $signCert, $privKey, $headers = [], $flags = PKCS7_DETACHED, $extraCerts = null
    ) {
        $logger       = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::string( $stringToSign, 1 );
        list( $infileName, $outfileName ) = self::getInOutFiles( $stringToSign, self::getUniqueFilenameBase());
        $outputString = null;
        try {
            self::sign(
                $infileName,
                $outfileName,
                $signCert,
                $privKey,
                $headers,
                $flags,
                $extraCerts
            );
            $outputString = Workshop::getFileContent( $outfileName );
        }
        catch( Exception $e ) {
            throw $e;
        }
        finally {
            if( is_file( $infileName )) {
                unlink( $infileName );
            }
            if( is_file( $outfileName )) {
                unlink( $outfileName );
            }
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return $outputString;
    }

    /**
     * Returns bool TRUE if the signature is verified as an S/MIME signed message - uses openssl_pkcs7_verify
     *
     * Reads the S/MIME message contained in the given file and examines the digital signature.
     * @link https://www.php.net/manual/en/function.openssl-pkcs7-verify.php
     * @param string $infileName
     * @param int    $flags         Opt. used to affect how the signature is verified (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
     *                              default PKCS7_DETACHED
     * @param string $outfileName   Opt. string holding the name of a file into which the certificates of the persons that
     *                              signed the messages will be stored in PEM format
     * @param array  $caInfo        An array containing file and directory names
     *                               that specify the locations of trusted CA files.
     *                               If a directory is specified,
     *                               then it must be a correctly formed hashed directory
     *                               as the openssl command would use.
     * @param string $extraCerts    The filename of a file containing a bunch of certificates to use as untrusted CAs
     * @param string $content       filename, Will be filled with the verified data, but with the signature information stripped
     * @return bool
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @static
     * @todo test
     */
    public static function verify(
        $infileName, $flags, $outfileName = null, $caInfo = [], $extraCerts = null, $content = null
    ) {
        $logger = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::fileNameRead( $infileName, 1 );
        $flags  = self::assertFlags( $flags, 2, PKCS7_DETACHED );
        if( ! empty( $outfileName )) {
            Assert::fileNameWrite( $outfileName, 3 );
        }
        if( ! empty( $caInfo )) {
            OpenSSLX509Factory::assertCaInfo( $caInfo, 4 );
        }
        if( ! empty( $extraCerts )) {
            Assert::fileNameRead( $extraCerts, 5 );
        }
        if( ! empty( $content )) {
            Assert::fileNameWrite( $content, 6 );
        }
        $result = false;
        $case   = 6;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            switch( true ) {
                case ( empty( $outfileName ) && empty( $caInfo ) && empty( $extraCerts ) && empty( $content )) :
                    $case   = 2;
                    $result = openssl_pkcs7_verify( $infileName, $flags );
                    break;
                case ( empty( $caInfo ) && empty( $extraCerts ) && empty( $content )) :
                    $case   = 3;
                    $result = openssl_pkcs7_verify( $infileName, $flags, $outfileName );
                    break;
                case ( empty( $extraCerts ) && empty( $content )) :
                    $case   = 4;
                    $result = openssl_pkcs7_verify( $infileName, $flags, $outfileName, $caInfo );
                    break;
                case ( empty( $content )) :
                    $case   = 5;
                    $result = openssl_pkcs7_verify( $infileName, $flags, $outfileName, $caInfo, $extraCerts );
                    break;
                default :
                    $result = openssl_pkcs7_verify( $infileName, $flags, $outfileName, $caInfo, $extraCerts, $content );
                    break;
            } // end switch
        }
        catch( Exception $e ) {
            $cond = ( -1 != $result );
            $msg2 = sprintf( self::$FMTC, $case );
            self::assessCatch( self::getCm( __METHOD__ ), $e, $cond, self::getOpenSSLErrors(), $msg2 );
        }
        finally {
            restore_error_handler();
        }
        if( -1 == $result ) {
            $msg2 = sprintf( self::$FMTC, $case );
            self::logAndThrowRuntimeException( self::getCm( __METHOD__ ), $msg2, self::getOpenSSLErrors());
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return (bool) $result;
    }

    /**
     * Returns array (PEMs, data) if the signature is verified as an S/MIME signed message - alias of 'verify'
     *
     * @param string $stringToVerify
     * @param int    $flags          Opt. used to affect how the signature is verified
     *                               (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
     * @param array  $caInfo        An array containing file and directory names
     *                               that specify the locations of trusted CA files.
     *                               If a directory is specified,
     *                               then it must be a correctly formed hashed directory
     *                               as the openssl command would use.
     * @param string $extraCerts    The filename of a file containing a bunch of certificates to use as untrusted CAs
     * @param bool   $result
     * @return array   [ string signers PEMs, string $content ]
     * @throws Exception
     * @throws InvalidArgumentException
     * @throws RunTimeException
     * @static
     */
    public static function verifyString( $stringToVerify, $flags, $caInfo = [], $extraCerts = null, & $result = false ) {
        static $SIGN      = 'signPems';
        $logger           = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        Assert::string( $stringToVerify, 1 );
        $unique           = self::getUniqueFilenameBase();
        list( $infileName, $contentFileName ) = self::getInOutFiles( $stringToVerify, $unique );
        $contentString    = null;
        $signPemsFileName = Workshop::getNewFileInTmp( $unique . $SIGN ); // pem?
        $signPemsString   = null;
        $result           = false;
        try {
            $result = self::verify( $infileName, $flags, $signPemsFileName, $caInfo, $extraCerts, $contentFileName );
            $signPemsString = Workshop::getFileContent( $signPemsFileName );
            $contentString  = Workshop::getFileContent( $contentFileName );
        }
        catch( Exception $e ) {
            throw $e;
        }
        finally {
            if( is_file( $infileName )) {
                unlink( $infileName );
            }
            if( is_file( $signPemsFileName )) {
                unlink( $signPemsFileName );
            }
            if( is_file( $contentFileName )) {
                unlink( $contentFileName );
            }
        }
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ )); // test ###
        return [ $signPemsString, $contentString ];
    }

    /**
     * Return array(infileName,outfileName), infile loaded with infileContent
     *
     * @param string $infileContent
     * @param string unique
     * @return array  [infilName,outfileName]
     * @throws RuntimeException
     */
    private static function getInOutFiles( $infileContent, $unique ) {
        static $IN   = '-IN';
        static $OUT  = '-OUT';
        static $TXT  = 'txt';
        $infileName  = Workshop::getNewFileInTmp( $unique . $IN, $TXT );
        Workshop::saveDataToFile( $infileName, $infileContent );
        $outfileName = Workshop::getNewFileInTmp( $unique . $OUT, $TXT );
        return [ $infileName, $outfileName ];
    }
}
