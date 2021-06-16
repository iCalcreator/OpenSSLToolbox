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

use function get_called_class;
use function get_class;
use function is_array;
use function is_file;
use function openssl_pkcs12_export;
use function openssl_pkcs12_export_to_file;
use function openssl_pkcs12_read;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function strpos;

/**
 * Class OpenSSLPkcs12Factory
 *
 * Wrapper for PHP OpenSSL pkcs12 functions,
 *   encapsulates the pkcs12 (string) resource : X.509 public key certificates, X.509 private keys, X.509 CRLs, generic data
 * Note: You need to have a valid openssl.cnf installed for this to operate correctly.
 * Require a Psr\Log logger, provided by LoggerDepot
 *
 * @see https://en.wikipedia.org/wiki/PKCS_12
 * @see https://web.archive.org/web/20140401120450/http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs12-personal-information-exchange-syntax-standard.htm
 */
class OpenSSLPkcs12Factory extends OpenSSLBaseFactory
{
    /**
     * @var string
     */
    private static $SP0 = '';

    /**
     * @var resource|string        1. An X.509 resource returned from openssl_x509_read()
     *                             2. A string having the format (file://)path/to/cert.pem
     *                                The named file must contain a (single) PEM encoded certificate
     *                             3. A string containing the content of a (single) PEM encoded certificate
     */
    private $x509 = null;

    /**
     * @var resource|string|array  1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                             2. For public keys only: an X.509 resource
     *                             3. A string having the format (file://)path/to/file.pem
     *                                The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                             4. A string containing the content of a PEM encoded certificate/key
     *                             5 For private keys, you may also use the syntax array($key, $passphrase)
     *                               where $key represents a key specified using the file or textual content notation above,
     *                               and $passphrase represents a string containing the passphrase for that private key
     */
    private $privateKey = null;

    /**
     * $var string                 Encryption password for unlocking the PKCS#12
     */
    private $pkcs12passWord = null;

    /**
     * @var array                  Optional array, other keys will be ignored
     *                               'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
     *                               'friendlyname' string to be used for the supplied certificate and key
     */
    private $args = [];

    /**
     * @var null|string            The pkcs12 (string) resource
     */
    private $pkcs12 = null;

    /**
     * Class constructor
     *
     * If all but 'args' arguments are set, a new string pkcs12 are set ( using export)
     *
     * @param null|resource|string $x509   1. An X.509 resource returned from openssl_x509_read()
     *                                     2. A string having the format (file://)path/to/cert.pem
     *                                        The named file must contain a (single) PEM encoded certificate
     *                                     3. A string containing the content of a (single) PEM encoded certificate
     * @param null|resource|string|array $privateKey
     *                                     1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                                     2. A string having the format (file://)path/to/file.pem
     *                                        The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                                     3. A string containing the content of a PEM encoded certificate/key
     *                                     4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                       where $key represents a key specified using the file or textual content notation above,
     *                                       and $passphrase represents a string containing the passphrase for that private key
     * @param null|string $pkcs12passWord  Encryption password for unlocking the PKCS#12
     * @param null|array  $args            Optional array, other keys will be ignored
     *                                      'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
     *                                      'friendlyname' string to be used for the supplied certificate and key
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function __construct(
        $x509 = null,
        $privateKey = null,
        $pkcs12passWord = null,
        $args = null
    )
    {
        $this->logger = LoggerDepot::getLogger( get_class() );
        $this->log(LogLevel::INFO, self::initClassStr());
        $setReady     = 0;
        if( ! empty( $x509 )) {
            $this->setX509( $x509 );
            $setReady += 1;
        }
        if( ! empty( $privateKey )) {
            $this->setPrivateKey( $privateKey );
            $setReady += 2;
        }
        if( ! empty( $pkcs12passWord )) {
            $this->setPkcs12PassWord( $pkcs12passWord );
        }
        if( ! empty( $args )) {
            $this->setArgs( $args );
        }
        if( 3 == $setReady ) {
            $this->setPkcs12(
                self::export(
                    $this->getX509(),
                    $this->getPrivateKey(),
                    $this->getPkcs12PassWord(),
                    $this->getArgs()
                )
            );
        }
    }

    /**
     * Class factory method
     *
     * @param null|resource|string $x509   1. An X.509 resource returned from openssl_x509_read()
     *                                     2. A string having the format (file://)path/to/cert.pem
     *                                        The named file must contain a (single) PEM encoded certificate
     *                                     3. A string containing the content of a (single) PEM encoded certificate
     * @param null|resource|string|array $privateKey
     *                                     1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                                     2. A string having the format (file://)path/to/file.pem
     *                                        The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                                     3. A string containing the content of a PEM encoded certificate/key
     *                                     4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                       where $key represents a key specified using the file or textual content notation above,
     *                                       and $passphrase represents a string containing the passphrase for that private key
     * @param null|string $pkcs12passWord  Encryption password for unlocking the PKCS#12
     * @param null|array  $args            Optional array, other keys will be ignored
     *                                      'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
     *                                      'friendlyname' string to be used for the supplied certificate and key
     * @return static
     * @throws InvalidArgumentException
     */
    public static function factory(
        $x509 = null,
        $privateKey = null,
        $pkcs12passWord = null,
        $args = null
    ) : self
    {
        return new self( $x509 , $privateKey, $pkcs12passWord, $args );
    }

    /**
     * Save a PKCS#12 Compatible Certificate Store File - exportToFile wrapper
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-export-to-file.php
     * @param string $fileName      Path to the output file (ext p12 or pfx)
     * @return static
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function saveCertificateStoreIntoFile( string $fileName ) : self
    {
        $this->log(
            LogLevel::DEBUG,
            self::$INIT . self::getCm( __METHOD__ )
        );
        Assert::fileNameWrite( $fileName );
        if( ! $this->isX509Set()) {
            throw new RuntimeException( sprintf( self::$FMTERR4, 'x509' ));
        }
        if( ! $this->isPrivateKeySet()) {
            throw new RuntimeException( sprintf( self::$FMTERR4, 'privateKey' ));
        }
        self::exportToFile(
            $this->getX509(),
            $fileName,
            $this->getPrivateKey(),
            $this->getPkcs12PassWord(),
            $this->getArgs()
        );
        return $this;
    }

    /**
     * Return array of parsed PKCS#12 Certificate Store - uses openssl_pkcs12_read
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-read.php
     * @param string $pkcs12          1.  The certificate store content (not file)
     *                                2.  'file://'-prefixed (!!) fileName with certificate store content
     * @param null|string $pkcs12passWord  Encryption password for unlocking the PKCS#12
     * @return array
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public static function read( string $pkcs12, $pkcs12passWord = '' ) : array
    {
        $logger     = LoggerDepot::getLogger( get_called_class() );
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( Workshop::hasFileProtoPrefix( $pkcs12 ) && is_file( $pkcs12 )) {
            $pkcs12 = Workshop::getFileContent( $pkcs12 );
        }
        $pkcs12passWord = Assert::string( $pkcs12passWord, 2, self::$SP0 );
        $result = false;
        $output = [];
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkcs12_read( $pkcs12, $output, $pkcs12passWord );
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
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ ) ); // test ###
        return $output;
    }

    /**
     * Return array of (string PEM) (private) key(s) from parsed PKCS#12 Certificate Store - derived from read
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-read.php
     * @return array
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function getKeys() : array
    {
        static $PRIVATE = 'PRIVATE';
        $output = [];
        foreach( $this->getCertificateStoreAsArray() as $pemString ) {
            if( false !== strpos( $pemString, $PRIVATE )) {
                $output[] = $pemString;
            }
        }
        return $output;
    }

    /**
     * Return array of (string PEM) certificates from parsed PKCS#12 Certificate Store - derived from read
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-read.php
     * @return array
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function getCertificates() : array
    {
        static $CERTIFICATE = 'CERTIFICATE';
        $output = [];
        foreach( $this->getCertificateStoreAsArray() as $pemString ) {
            if( false !== strpos( $pemString, $CERTIFICATE )) {
                $output[] = $pemString;
            }
        }
        return $output;
    }

    /**
     * Return array of parsed PKCS#12 Certificate Store - 'alias' of read
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-read.php
     * @return array
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public function getCertificateStoreAsArray() : array
    {
        static $PKCS12 = 'pkcs12';
        if( ! $this->isPkcs12Set()) {
            throw new RuntimeException( sprintf( self::$FMTERR4, $PKCS12 ));
        }
        return self::read( $this->getPkcs12(), $this->getPkcs12PassWord());
    }

    /**
     * Return a PKCS#12 Compatible Certificate Store in a PKCS#12 string (file) format - uses openssl_pkcs12_export
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-export.php
     * @param resource|string $x509        1. An X.509 resource returned from openssl_x509_read()
     *                                     2. A string having the format (file://)path/to/cert.pem
     *                                        The named file must contain a (single) PEM encoded certificate
     *                                     3. A string containing the content of a (single) PEM encoded certificate
     * @param resource|string|array $privateKey
     *                                     1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                                     2. A string having the format (file://)path/to/file.pem
     *                                        The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                                     3. A string containing the content of a (single) PEM encoded certificate/key
     *                                     4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                       where $key represents a key specified using the file or textual content notation above,
     *                                       and $passphrase represents a string containing the passphrase for that private key
     * @param null|string $pkcs12passWord
     *                                     Encryption password for unlocking the PKCS#12
     * @param null|array  $args            Optional array, other keys will be ignored
     *                                      'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
     *                                      'friendlyname' string to be used for the supplied certificate and key
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function export(
        $x509,
        $privateKey,
        $pkcs12passWord,
        $args = null
    ) : string
    {
        $logger         = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        $x509           = OpenSSLX509Factory::assertX509( $x509, 1 );
        $privateKey     = OpenSSLPkeyFactory::assertPkey( $privateKey, 2 );
        $pkcs12passWord = self::assertPassPhrase( $pkcs12passWord, 3 );
        $args           = self::assertArgs( $args );
        $result         = false;
        $output         = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkcs12_export(
                $x509,
                $output,
                $privateKey,
                ( $pkcs12passWord ?? self::$SP0 ),
                $args
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
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ ) ); // test ###
        return $output;
    }

    /**
     * Exports a PKCS#12 Compatible Certificate Store File - uses openssl_pkcs12_export_to_file
     *
     * Stores x509 into a file named by filename in a PKCS#12 file format.
     *
     * @link https://www.php.net/manual/en/function.openssl-pkcs12-export-to-file.php
     * @param resource|string $x509        1. An X.509 resource returned from openssl_x509_read()
     *                                     2. A string having the format (file://)path/to/cert.pem
     *                                        The named file must contain a (single) PEM encoded certificate
     *                                     3. A string containing the content of a (single) PEM encoded certificate
     * @param string $fileName
     * @param resource|string|array $privateKey
     *                                     1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                                     2. A string having the format (file://)path/to/file.pem
     *                                        The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                                     3. A string containing the content of a PEM encoded certificate/key
     *                                     4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                       where $key represents a key specified using the file or textual content notation above,
     *                                       and $passphrase represents a string containing the passphrase for that private key
     * @param null|string $pkcs12passWord
     *                                     Encryption password for unlocking the PKCS#12
     * @param null|array  $args            Optional array, other keys will be ignored
     *                                      'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
     *                                      'friendlyname' string to be used for the supplied certificate and key
     * @return bool                        true on success
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function exportToFile(
        $x509,
        string $fileName,
        $privateKey,
        $pkcs12passWord,
        $args = null
    ) : bool
    {
        $logger         = LoggerDepot::getLogger( get_called_class());
        $logger->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        $x509           = OpenSSLX509Factory::assertX509( $x509, 1 );
        Assert::fileNameWrite( $fileName, 2 );
        $privateKey     = OpenSSLPkeyFactory::assertPkey( $privateKey, 3 );
        $pkcs12passWord = self::assertPassPhrase( $pkcs12passWord, 4 );
        $args           = self::assertArgs( $args );
        $result         = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pkcs12_export_to_file(
                $x509,
                $fileName,
                $privateKey,
                ( $pkcs12passWord ?? self::$SP0 ),
                $args
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
        $logger->log( LogLevel::DEBUG, self::$PASSED . self::getCm( __METHOD__ ) ); // test ###
        return true;
    }

    /** ***********************************************************************
     *  Getters and setters etc
     */

    /**
     * @return resource|string  x509
     */
    public function getX509()
    {
        return $this->x509;
    }

    /**
     * @return bool
     */
    public function isX509Set() : bool
    {
        return ( ! empty( $this->x509 ));
    }

    /**
     * Set x509, removes any previously set pkcs12
     *
     * @param resource|string $x509        1. An X.509 resource returned from openssl_x509_read()
     *                                     2. A string having the format (file://)path/to/cert.pem
     *                                        The named file must contain a (single) PEM encoded certificate
     *                                     3. A string containing the content of a (single) PEM encoded certificate
     * @return static
     * @throws InvalidArgumentException;
     */
    public function setX509( $x509 ) : self
    {
        $this->x509   = OpenSSLX509Factory::assertX509( $x509 );
        $this->pkcs12 = null;
        return $this;
    }

    /**
     * @return array|resource|string
     */
    public function getPrivateKey()
    {
        return $this->privateKey;
    }

    /**
     * @return bool
     */
    public function isPrivateKeySet() : bool
    {
        return ( ! empty( $this->privateKey ));
    }

    /**
     * Set privateKey, removes any previously set pkcs12
     *
     * @param resource|string|array $privateKey
     *                                     1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
     *                                     2. A string having the format (file://)path/to/file.pem
     *                                        The named file must contain a PEM encoded certificate/private key (it may contain both)
     *                                     3. A string containing the content of a PEM encoded certificate/key
     *                                     4 For private keys, you may also use the syntax array($key, $passphrase)
     *                                       where $key represents a key specified using the file or textual content notation above,
     *                                       and $passphrase represents a string containing the passphrase for that private key
     * @return static
     * @throws InvalidArgumentException
     */
    public function setPrivateKey( $privateKey ) : self
    {
        $this->privateKey = OpenSSLPkeyFactory::assertPkey( $privateKey );
        $this->pkcs12 = null;
        return $this;
    }

    /**
     * @return null|string
     */
    public function getPkcs12PassWord()
    {
        return $this->pkcs12passWord;
    }

    /**
     * @return bool
     */
    public function isPkcs12passWordSet() : bool
    {
        return ( ! empty( $this->pkcs12passWord ));
    }

    /**
     * @param string $pkcs12passWord
     * @return static
     * @throws InvalidArgumentException
     */
    public function setPkcs12PassWord( string $pkcs12passWord ) : self
    {
        if( empty( $pkcs12passWord )) {
            throw new InvalidArgumentException( sprintf( self::$FMTERR4, 'string' ));
        }
        $this->pkcs12 = null;
        return $this;
    }

    /**
     * @return array
     */
    public function getArgs() : array
    {
        return $this->args;
    }

    /**
     * @return bool
     */
    public function isArgsSet() : bool
    {
        return ( ! empty( $this->args ));
    }

    /**
     * @param array $args
     * @return static
     * @throws InvalidArgumentException
     */
    public function setArgs( array $args ) : self
    {
        $this->args   = self::assertArgs( $args );
        $this->pkcs12 = null;
        return $this;
    }

    /**
     * Return the pkcs12 as string
     *
     * If empty and x509 and privateKey (opt pkcs12PassWord and args) properties are set,
     *   a new string pkcs12 are set first ( using export)
     * @return string
     * @throws RuntimeException
     */
    public function getPkcs12() : string
    {
        static $X509       = 'x509';
        static $PRIVATEKEY = 'privateKey';
        if( $this->isPkcs12Set()) {
            return $this->pkcs12;
        }
        $this->log( LogLevel::DEBUG, self::$INIT . self::getCm( __METHOD__ ));
        if( ! $this->isX509Set()) {
            throw new RuntimeException( sprintf( self::$FMTERR4, $X509 ));
        }
        if( ! $this->isPrivateKeySet()) {
            throw new RuntimeException( sprintf( self::$FMTERR4, $PRIVATEKEY ));
        }
        $this->setPkcs12(
            self::export(
                $this->getX509(),
                $this->getPrivateKey(),
                $this->getPkcs12PassWord(),
                $this->getArgs()
            )
        );
        return $this->pkcs12;
    }

    /**
     * @return bool
     */
    public function isPkcs12Set() : bool
    {
        return ( ! empty( $this->pkcs12 ));
    }

    /**
     * Set pkcs12 and, opt, pkcs12password
     *
     * @param string $pkcs12
     * @param null|string $pkcs12passWord
     * @return static
     */
    public function setPkcs12( string $pkcs12, $pkcs12passWord = null ) : self
    {
        $this->pkcs12 = $pkcs12;
        if( ! empty( $pkcs12passWord )) {
            $this->pkcs12passWord = Assert::string( $pkcs12passWord );
        }
        return $this;
    }

    /**
     * Return bool true if args is valid
     *
     * @param null|array $args
     * @return array
     * @throws InvalidArgumentException
     * @todo assert extraArgs (array) string/file
     */
    private static function assertArgs( $args = null ) : array
    {
        static $FMTERR = 'array expected, got %s';
        if( empty( $args )) {
            return [];
        }
        if( ! is_array( $args )) {
            throw new InvalidArgumentException( sprintf( $FMTERR, gettype( $args )));
        }
        $output = [];
        foreach( $args as $key => $value ) {
            switch( $key ) {
                case self::EXTRACERTS :
                    $output[self::EXTRACERTS] = $value;
                    break;
                case self::FRIENDLYNAMES :
                    $output[self::FRIENDLYNAMES] = Assert::string( $value );
                    break;
            }
        }
        return $output;
    }
}
