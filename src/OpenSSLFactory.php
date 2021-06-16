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
use RuntimeException;

use function array_combine;
use function array_keys;
use function in_array;
use function openssl_cipher_iv_length;
use function openssl_decrypt;
use function openssl_digest;
use function openssl_encrypt;
use function openssl_pbkdf2;
use function openssl_private_decrypt;
use function openssl_private_encrypt;
use function openssl_public_decrypt;
use function openssl_public_encrypt;
use function openssl_seal;
use function openssl_sign;
use function openssl_verify;
use function restore_error_handler;
use function set_error_handler;
use function sprintf;
use function strlen;
use function var_export;

/**
 * Class OpenSSLFactory
 *
 * Wrapper class with static methods for OpenSSL functions :
 *   openssl_cipher_iv_length
 *   openssl_decrypt
 *   openssl_digest
 *   openssl_encrypt
 *   openssl_pbkdf2
 *   openssl_private_decrypt
 *   openssl_private_encrypt
 *   openssl_public_decrypt
 *   openssl_public_encrypt
 *   openssl_open
 *   openssl_seal
 *   openssl_sign
 *   openssl_verify
 * Note: You need to have a valid openssl.cnf installed for this to operate correctly.
 * Require a Psr\Log logger, provided by LoggerDepot
 *
 * @todo https://www.php.net/manual/en/function.openssl-private-encrypt.php#119810
 * @todo https://www.php.net/manual/en/function.openssl-dh-compute-key.php ??
 */
class OpenSSLFactory extends OpenSSLBaseFactory
{
    /**
     * @var array  (values as keys)
     */
    private static $OPENSSLPADDINGS4 = [
        1 => OPENSSL_PKCS1_PADDING,
        2 => OPENSSL_SSLV23_PADDING,
        3 => OPENSSL_PKCS1_OAEP_PADDING,
        4 => OPENSSL_NO_PADDING,
    ];

    /**
     * Assert opts
     *
     * @param int $opts
     * @param null|int|string $argIx
     * @throws InvalidArgumentException
     */
    private static function assertOpts( int $opts, $argIx = 1 )
    {
        static $OPTSARR     = [
            0,
            OPENSSL_RAW_DATA,
            OPENSSL_ZERO_PADDING,
            OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING
        ];
        static $FMTPOPTSERR = 'Invalid option arg (#%d), %s';
        if( ! in_array( $opts, $OPTSARR )) {
            throw new InvalidArgumentException(
                sprintf( $FMTPOPTSERR, $argIx, var_export( $opts, true ))
            );
        }
    }

    /**
     * Assert padding
     *
     * @param int $padding
     * @param null|int|string $argIx
     * @param null|int $defaultIfNull
     * @return null|int
     * @throws InvalidArgumentException
     */
    private static function assertPadding(
        $padding = null,
        $argIx = 1,
        $defaultIfNull = null
    ) : int
    {
        static $FMTPADDERR = 'Invalid padding arg (#%d), %s';
        if( null === $padding ) {
            $padding = $defaultIfNull;
        }
        if( ! in_array( $padding, self::$OPENSSLPADDINGS4 )) {
            throw new InvalidArgumentException(
                sprintf( $FMTPADDERR, $argIx, var_export( $padding, true  ))
            );
        }
        return $padding;
    }

    /**
     * Return openssl cipher initialization vector byte length - uses openssl_cipher_iv_length
     *
     * @link https://www.php.net/manual/en/function.openssl-cipher-iv-length.php
     * @param string $cipherAlgorithm cipher method, one of openssl_get_cipher_methods()
     * @return int
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getCipherIvLength( string $cipherAlgorithm ) : int
    {
        $FMTERR2 = ', cipherAlgorithm: %s, ';
        self::assertCipherAlgorithm( $cipherAlgorithm );
        $initializationVectorNumBytes = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $initializationVectorNumBytes = openssl_cipher_iv_length( $cipherAlgorithm );
        }
        catch( Exception $e ) {
            $cond = ( false !== $initializationVectorNumBytes );
            $msg2 = sprintf( $FMTERR2, $cipherAlgorithm );
            self::assessCatch(__FUNCTION__, $e, $cond, self::getOpenSSLErrors(), $msg2 );
        }
        finally {
            restore_error_handler();
        }
        if( false === $initializationVectorNumBytes ) {
            $msg2 = sprintf( $FMTERR2, $cipherAlgorithm );
            self::logAndThrowRuntimeException(
                __FUNCTION__,
                $msg2,
                self::getOpenSSLErrors()
            );
        }
        return $initializationVectorNumBytes;
    }

    /**
     * Return openssl_decrypted data - uses openssl_decrypt
     *
     * Takes a raw or base64 encoded string and decrypts it using a given method and key.
     *
     * @link https://www.php.net/manual/en/function.openssl-decrypt.php
     * @param string $raw               The encrypted message to be decrypted
     * @param string $cipherAlgorithm   cipher method, one of openssl_get_cipher_methods()
     * @param string $keyHash           The key
     * @param null|int    $opts         one of OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING
     * @param null|string $initializationVector
     *                                  A non-NULL Initialization Vector
     * @return string
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public static function decrypt(
        string $raw,
        string $cipherAlgorithm,
        string $keyHash,
        $opts = 0,
        $initializationVector = ''
    ) : string
    {
        static $FMTERR2 = 'cipherAlgorithm: %s, keyHash length: %d, (iv length: %d) ';
        self::assertCipherAlgorithm( $cipherAlgorithm );
        self::assertOpts( $opts, 4 );
        $decrypted = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $decrypted = openssl_decrypt(
                $raw,
                $cipherAlgorithm,
                $keyHash,
                $opts,
                $initializationVector
            );
        }
        catch( Exception $e ) {
            $cond = ( false !== $decrypted );
            $msg2 = sprintf(
                $FMTERR2,
                $cipherAlgorithm,
                strlen( $keyHash ),
                strlen( $initializationVector )
            );
            self::assessCatch(
                __FUNCTION__,
                $e,
                $cond,
                self::getOpenSSLErrors(),
                $msg2
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $decrypted ) {
            $msg2 = sprintf(
                $FMTERR2,
                $cipherAlgorithm,
                strlen( $keyHash ),
                strlen( $initializationVector )
            );
            self::logAndThrowRuntimeException(
                __FUNCTION__,
                $msg2,
                self::getOpenSSLErrors()
            );
        }
        return $decrypted;
    }

    /**
     * Return openssl_decrypted data - alias of 'decrypt'
     *
     * @param string $raw                    The encrypted message to be decrypted
     * @param string $cipherAlgorithm        cipher method, one of openssl_get_cipher_methods()
     * @param string $keyHash                The key
     * @param null|int    $opts              one of OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING
     * @param null|string $initializationVector   A non-NULL Initialization Vector
     * @return string
     * @throws InvalidArgumentException
     * @throws RunTimeException
     */
    public static function getDecryptedString(
        string $raw,
        string $cipherAlgorithm,
        string $keyHash,
        $opts = 0,
        $initializationVector = ''
    ) : string
    {
        return self::decrypt(
            $raw,
            $cipherAlgorithm,
            $keyHash,
            $opts,
            $initializationVector
        );
    }

    /**
     * Return hashed key - uses openssl_digest
     *
     * @link https://www.php.net/manual/en/function.openssl-digest.php
     * @param string $key             The data
     * @param string $hashAlgorithm   digest method to use
     *                                one of openssl_get_md_methods(), self::getAvailableDigestMethods()
     * @param null|bool   $rawOutput  Setting to TRUE will return as raw output data, otherwise binhex encoded
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function digest(
        string $key,
        string $hashAlgorithm,
        $rawOutput = false
    ) : string
    {
        static $FMTERR2 = ', hashAlgorithm: %s ';
        self::assertMdAlgorithm( $hashAlgorithm );
        $keyHash = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $keyHash = openssl_digest( $key, $hashAlgorithm, ( $rawOutput ?? false ));
        }
        catch( Exception $e ) {
            $msg2 = sprintf( $FMTERR2, $hashAlgorithm );
            self::assessCatch(
                __FUNCTION__,
                $e,
                ( false !== $keyHash ),
                self::getOpenSSLErrors(),
                $msg2
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $keyHash ) {
            $msg2 = sprintf( $FMTERR2, $hashAlgorithm );
            self::logAndThrowRuntimeException(
                __FUNCTION__,
                $msg2,
                self::getOpenSSLErrors()
            );
        }
        return $keyHash;
    }

    /**
     * Return hashed key - alias of 'digest'
     *
     * @param string $key             The data
     * @param string $hashAlgorithm   digest method to use
     *                                one of openssl_get_md_methods(), self::getAvailableDigestMethods()
     * @param null|bool   $rawOutput  Setting to TRUE will return as raw output data, otherwise binhex encoded
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getDigestHash(
        string $key,
        string $hashAlgorithm,
        $rawOutput = false
    ) : string
    {
        return self::digest( $key, $hashAlgorithm, $rawOutput );
    }

    /**
     * Return encrypted data - uses openssl_encrypt
     *
     * Encrypts given data with given method and key, returns a raw or base64 encoded string
     *
     * @link https://www.php.net/manual/en/function.openssl-encrypt.php
     * @param string $data               The plaintext message data to be encrypted
     * @param string $cipherAlgorithm    cipher method, one of openssl_get_cipher_methods()
     * @param string $keyHash            The key
     * @param null|int    $opts          bitwise disjunction of the flags OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING
     * @param null|string $initializationVector
     *                                   A non-NULL Initialization Vector
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function encrypt(
        string $data,
        string $cipherAlgorithm,
        string $keyHash,
        $opts = 0,
        $initializationVector = ''
    ) : string
    {
        static $FMTERR2 = 'cipherAlgorithm: %s, keyHash length: %d (iv length: %d) ';
        self::assertCipherAlgorithm( $cipherAlgorithm );
        self::assertOpts( $opts, 4 );
        $encrypted = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $encrypted = openssl_encrypt(
                $data,
                $cipherAlgorithm,
                $keyHash,
                $opts,
                $initializationVector
            );
        }
        catch( Exception $e ) {
            $msg2 = sprintf(
                $FMTERR2,
                $cipherAlgorithm,
                strlen( $keyHash ),
                strlen( $initializationVector ?? '' )
            );
            self::assessCatch(
                __FUNCTION__,
                $e,
                true,
                self::getOpenSSLErrors(),
                $msg2
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $encrypted ) {
            $msg2 = sprintf(
                $FMTERR2,
                $cipherAlgorithm,
                strlen( $keyHash ),
                strlen( $initializationVector ?? '')
            );
            self::logAndThrowRuntimeException( __FUNCTION__, $msg2, self::getOpenSSLErrors());
        }
        return $encrypted;
    }

    /**
     * Return encrypted data - alias of 'encrypt'
     *
     * @param string $data              The plaintext message data to be encrypted
     * @param string $cipherAlgorithm   cipher method, one of openssl_get_cipher_methods()
     * @param string $keyHash           The key
     * @param null|int    $opts         bitwise disjunction of the flags OPENSSL_RAW_DATA and OPENSSL_ZERO_PADDING
     * @param null|string $initializationVector
     *                                  A non-NULL Initialization Vector
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getEncryptedString(
        string $data,
        string $cipherAlgorithm,
        string $keyHash,
        $opts = 0,
        $initializationVector = ''
    ) : string
    {
        return self::encrypt(
            $data,
            $cipherAlgorithm,
            $keyHash,
            $opts,
            $initializationVector
        );
    }

    /**
     * Return decrypted data using private key  - uses openssl_private_decrypt
     *
     * Decrypts data that was previously encrypted via openssl_public_encrypt()
     *
     * @link https://www.php.net/manual/en/function.openssl-private-decrypt.php
     * @param string           $data
     * @param resource|string|array  $privateKey  The private key corresponding that was used to encrypt the data
     *                                      1 key resource
     *                                      2. A string having the format (file://)/path/to/file.pem.
     *                                         The named file must contain a (single) PEM encoded key
     *                                      3. A string, PEM formatted key.
     *                                      4 array(2/3, passPhrase)
     * @param null|int         $padding     One of OPENSSL_PKCS1_PADDING (default),
     *                                      OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function privateDecrypt(
        string $data,
        $privateKey,
        $padding = null
    ) : string
    {
        $privateKey = OpenSSLPkeyFactory::assertPkey( $privateKey, 2, true );
        $padding    = self::assertPadding( $padding, 3, OPENSSL_PKCS1_PADDING );
        $result     = false;
        $decrypted  = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_private_decrypt(
                $data,
                $decrypted,
                $privateKey,
                $padding
            );
        }
        catch( Exception $e ) {
            self::assessCatch(
                __FUNCTION__,
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
                __FUNCTION__,
                null,
                self::getOpenSSLErrors()
            );
        }
        return $decrypted;
    }

    /**
     * Return decrypted data using private key  - alias of 'privateDecrypt'
     *
     * @param string           $data
     * @param resource|string|array  $privateKey  The private key corresponding that was used to encrypt the data
     *                                      1 key resource
     *                                      2. A string having the format (file://)/path/to/file.pem.
     *                                         The named file must contain a (single) PEM encoded key
     *                                      3. A string, PEM formatted key.
     *                                      4 array(2/3, passPhrase)
     * @param null|int         $padding     One of OPENSSL_PKCS1_PADDING (default),
     *                                      OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getprivateKeyDecryptedString(
        string $data,
        $privateKey,
        $padding = null
    ) : string
    {
        return self::privateDecrypt( $data, $privateKey, $padding );
    }

    /**
     * Return encrypted data using private key - uses openssl_private_encrypt
     *
     * Encrypts data with private key and stores the result into crypted.
     * Encrypted data can be decrypted via openssl_public_decrypt().
     * @link https://www.php.net/manual/en/function.openssl-private-encrypt.php
     * @param string           $data
     * @param resource|string|array  $privateKey  The private key that was used to encrypt the data
     *                                      1 key resource
     *                                      2. A string having the format (file://)/path/to/file.pem.
     *                                         The named file must contain a (single) PEM encoded key
     *                                      3. A string, PEM formatted key.
     *                                      4 array(2/3, passPhrase)
     * @param null|int         $padding     One of OPENSSL_PKCS1_PADDING (default), OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function privateEncrypt(
        string $data,
        $privateKey,
        $padding = null
    ) : string
    {
        $privateKey = OpenSSLPkeyFactory::assertPkey( $privateKey, 2, true );
        $padding    = self::assertPadding( $padding, 3, OPENSSL_PKCS1_PADDING );
        $result     = false;
        $encrypted  = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_private_encrypt(
                $data,
                $encrypted,
                $privateKey,
                $padding
            );
        }
        catch( Exception $e ) {
            self::assessCatch(
                __FUNCTION__,
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
                __FUNCTION__,
                null,
                self::getOpenSSLErrors()
            );
        }
        return $encrypted;
    }

    /**
     * Return encrypted data using private key - alias of 'privateEncrypt'
     *
     * @param string           $data
     * @param resource|string  $privateKey  The private key that was used to encrypt the data
     *                                      1 key resource
     *                                      2. A string having the format (file://)/path/to/file.pem.
     *                                         The named file must contain a (single) PEM encoded key
     *                                      3. A string, PEM formatted key.
     *                                      4 array(2/3, passPhrase)
     * @param null|int         $padding     One of OPENSSL_PKCS1_PADDING (default), OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getprivateKeyEncryptedString(
        string $data,
        $privateKey,
        $padding = null
    ) : string
    {
        return self::privateEncrypt( @$data, $privateKey, $padding );
    }

    /**
     * Return decrypted data using public key - uses openssl_public_decrypt
     *
     * Decrypts data that was previous encrypted via openssl_private_encrypt()
     * @link https://www.php.net/manual/en/function.openssl-public-decrypt.php
     * @param string          $data       Encrypted data to decrypt
     * @param resource|string $publicKey  The public key corresponding that was used to encrypt the data
     *                                    1 key resource
     *                                    2. A string having the format (file://)/path/to/file.pem.
     *                                       The named file must contain a (single) PEM encoded key
     *                                    3. A string, PEM formatted key.
     * @param null|int        $padding    One of OPENSSL_PKCS1_PADDING (default),
     *                                    OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function publicDecrypt(
        string $data,
        $publicKey,
        $padding = null
    ) : string
    {
        $publicKey = OpenSSLPkeyFactory::assertPkey( $publicKey, 2, true );
        $padding   = self::assertPadding( $padding, 3, OPENSSL_PKCS1_PADDING );
        $result    = false;
        $decrypted = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_public_decrypt(
                $data,
                $decrypted,
                $publicKey,
                $padding
            );
        }
        catch( Exception $e ) {
            self::assessCatch(
                __FUNCTION__,
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
                __FUNCTION__,
                null,
                self::getOpenSSLErrors()
            );
        }
        return $decrypted;
    }

    /**
     * Return decrypted data using public key - alias of 'publicDecrypt'
     *
     * @param string          $data       Encrypted data to decrypt
     * @param resource|string $publicKey  The public key corresponding that was used to encrypt the data
     *                                    1 key resource
     *                                    2. A string having the format (file://)/path/to/file.pem.
     *                                       The named file must contain a (single) PEM encoded key
     *                                    3. A string, PEM formatted key.
     * @param null|int        $padding    One of OPENSSL_PKCS1_PADDING (default),
     *                                    OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getpublicKeyDecryptedString(
        string $data,
        $publicKey,
        $padding = null
    ) : string
    {
        return self::publicDecrypt( $data, $publicKey, $padding );
    }

    /**
     * Return encrypted data using public key - uses openssl_public_encrypt
     *
     * Encrypted message can only be read only by owner of the private key
     * @link https://www.php.net/manual/en/function.openssl-public-encrypt.php
     * @param string          $data       Raw data to encrypt
     * @param resource|string $publicKey  The public key that was used to encrypt the data
     *                                    1 key resource
     *                                    2. A string having the format (file://)/path/to/file.pem.
     *                                       The named file must contain a (single) PEM encoded key
     *                                    3. A string, PEM formatted key.
     * @param null|int        $padding    One of OPENSSL_PKCS1_PADDING (default),
     *                                    OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function publicEncrypt(
        string $data,
        $publicKey,
        $padding = null
    ) : string
    {
        $publicKey = OpenSSLPkeyFactory::assertPkey( $publicKey, 2, true );
        $padding   = self::assertPadding( $padding, 3, OPENSSL_PKCS1_PADDING );
        $result    = false;
        $encrypted = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_public_encrypt(
                $data,
                $encrypted,
                $publicKey,
                $padding
            );
        }
        catch( Exception $e ) {
            self::assessCatch(
                __FUNCTION__,
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
                __FUNCTION__,
                null,
                self::getOpenSSLErrors()
            );
        }
        return $encrypted;
    }

    /**
     * Return encrypted data using public key - alias of 'publicEncrypt'
     *
     * @param string          $data       Raw data to encrypt
     * @param resource|string $publicKey  The public key that was used to encrypt the data
     *                                    1 key resource
     *                                    2. A string having the format (file://)/path/to/file.pem.
     *                                       The named file must contain a (single) PEM encoded key
     *                                    3. A string, PEM formatted key.
     * @param null|int        $padding    One of OPENSSL_PKCS1_PADDING (default),
     *                                    OPENSSL_SSLV23_PADDING, OPENSSL_PKCS1_OAEP_PADDING, OPENSSL_NO_PADDING
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getpublicKeyEncryptedString(
        string $data,
        $publicKey,
        $padding = null
    ) : string
    {
        return self::publicEncrypt( $data, $publicKey, $padding );
    }

    /**
     * Return opened sealed data - uses openssl_open
     *
     * Return opened (decrypted) sealed_data using the private key
     * associated with the key identifier priv_key_id and the envelope key,
     * and fills open_data with the decrypted data.
     * The envelope key is generated when the data are sealed and can only be used by one specific private key.
     * @link https://www.php.net/manual/en/function.openssl-open.php
     * @param string          $data          Encrypted (sealed) data to decrypt
     * @param string          $envelopeKey   The public key corresponding that was used to encrypt the data
     * @param resource|string|array  $privateKeyId  The private key resource corresponding that was used to encrypt the data
     *                                       1 key resource
     *                                       2. A string having the format (file://)/path/to/file.pem.
     *                                          The named file must contain a (single) PEM encoded key
     *                                       3. A string, PEM formatted key.
     *                                       4. array (2/3, passPhrase)
     * @param null|string     $cipherAlgorithm       The cipher method, default 'RC4'
     * @param null|string     $initializationVector  A non-NULL Initialization Vector, PHP >= 7.0.0
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function open(
        string $data,
        string $envelopeKey,
        $privateKeyId,
        $cipherAlgorithm = null,
        $initializationVector = null
    ) : string
    {
        $privateKeyId = OpenSSLPkeyFactory::assertPkey( $privateKeyId, 3, true );
        if( empty( $cipherAlgorithm )) {
            $cipherAlgorithm = 'RC4';
        }
        self::assertCipherAlgorithm( $cipherAlgorithm );
        $result    = false;
        $decrypted = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            switch( true ) {
                case empty( $method ) :
                    $result = openssl_open(
                        $data,
                        $decrypted,
                        $envelopeKey,
                        $privateKeyId
                    );
                    break;
                case empty( $initializationVector ) :
                    $result = openssl_open(
                        $data,
                        $decrypted,
                        $envelopeKey,
                        $privateKeyId,
                        $cipherAlgorithm
                    );
                    break;
                default :
                    $result = openssl_open(
                        $data,
                        $decrypted,
                        $envelopeKey,
                        $privateKeyId,
                        $cipherAlgorithm,
                        $initializationVector
                    );
                    break;
            }
        }
        catch( Exception $e ) {
            self::assessCatch(
                __FUNCTION__,
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
                __FUNCTION__,
                null,
                self::getOpenSSLErrors()
            );
        }
        return $decrypted;
    }

    /**
     * Return opened sealed data - alias of 'open'
     *
     * @param string          $data          Encrypted (sealed) data to decrypt
     * @param string          $envelopeKey   The public key corresponding that was used to encrypt the data
     * @param resource|string|array  $privateKeyId  The private key resource corresponding that was used to encrypt the data
     *                                       1 key resource
     *                                       2. A string having the format (file://)/path/to/file.pem.
     *                                          The named file must contain a (single) PEM encoded key
     *                                       3. A string, PEM formatted key.
     *                                       4. array (2/3, passPhrase)
     * @param null|string     $cipherAlgorithm       The cipher method, default 'RC4'
     * @param null|string     $initializationVector  A non-NULL Initialization Vector, PHP >= 7.0.0
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getOpenedSealedString(
        string $data,
        string $envelopeKey,
        $privateKeyId,
        $cipherAlgorithm = null,
        $initializationVector = null
    ) : string
    {
        return self::open(
            $data,
            $envelopeKey,
            $privateKeyId,
            $cipherAlgorithm,
            $initializationVector
        );
    }

    /**
     * Return sealed (encrypted) data - uses openssl_seal
     *
     * Seals (encrypts) data by using the given method with a randomly generated secret key.
     * The key is encrypted with each of the public keys associated with the identifiers in publicKeyIds
     * and each encrypted key is returned in envelopeKeys.
     * This means that one can send sealed data to multiple recipients (provided one has obtained their public keys).
     * Each recipient must receive both the sealed data and the envelopekey
     * that was encrypted with the recipient's public key.
     *
     * @link https://www.php.net/manual/en/function.openssl-seal.php
     * @param string                $data            Data to seal
     * @param array|resource|string $publicKeyIds
     *                                               (assoc) array/single public key resource identifier(s), each one of
     *                                               1 key resource
     *                                               2. A string having the format (file://)/path/to/file.pem.
     *                                               The named file must contain a (single) PEM encoded key
     *                                               3. A string, PEM formatted key.
     * @param string                $cipherAlgorithm The cipher method, default 'RC4'
     * @param null                  $iv
     * @return array  [ sealedData, envelopeKeys ]
     *                                               The array envelopeKeys will have the same keys as publicKeyIds
     */
    public static function seal(
        string $data,
        $publicKeyIds,
        $cipherAlgorithm = null,
        & $iv = null
    ) : array
    {
        $publicKeysArr = [];
        foreach( (array) $publicKeyIds as $x => $publicKey ) {
            $publicKeysArr[$x] = OpenSSLPkeyFactory::assertPkey( $publicKey, 2, true );
        }
        if( empty( $cipherAlgorithm ) ) {
            $cipherAlgorithm = 'RC4';
        }
        self::assertCipherAlgorithm( $cipherAlgorithm );
        $result     = false;
        $sealedData = $envelopeKeys = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            switch( true ) {
                case empty( $iv ) :
                    $result = openssl_seal(
                        $data,
                        $sealedData,
                        $envelopeKeys,
                        $publicKeysArr,
                        $cipherAlgorithm
                    );
                    break;
                default :
                    $result = openssl_seal(
                        $data,
                        $sealedData,
                        $envelopeKeys,
                        $publicKeysArr,
                        $cipherAlgorithm,
                        $iv
                    );
                    break;
            } // end switch
        }
        catch( Exception $e ) {
            self::assessCatch(
                __FUNCTION__,
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
                __FUNCTION__,
                null,
                self::getOpenSSLErrors()
            );
        }
        set_error_handler( self::$ERRORHANDLER );
        try {
            $envelopeKeys2 = array_combine(
                array_keys( $publicKeysArr ),
                $envelopeKeys
            );
        }
        catch( Exception $e ) {
            $envelopeKeys2 = $envelopeKeys;
        }
        finally {
            restore_error_handler();
        }
        return [ $sealedData, $envelopeKeys2 ];
    }

    /**
     * Return sealed (encrypted) data - alias of 'seal'
     *
     * @param string $data             Data to seal
     * @param array|resource|string $publicKeyIds
     *                                 (assoc) array/single public key resource identifier(s), each one of
     *                                   1 key resource
     *                                   2. A string having the format (file://)/path/to/file.pem.
     *                                      The named file must contain a (single) PEM encoded key
     *                                   3. A string, PEM formatted key.
     * @param null|string $cipherAlgorithm
     *                                 The cipher method, default 'RC4'
     * @param string $iv               A non-NULL Initialization Vector, PHP >= 7.0.0
     * @return array  [ sealedData, envelopeKeys ]
     *                                 The array envelopeKeys will have the same keys as publicKeyIds
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getSealedString(
        string $data,
        $publicKeyIds,
        $cipherAlgorithm = null,
        & $iv = null
    ) : array
    {
        return self::seal( $data, $publicKeyIds, $cipherAlgorithm, $iv );
    }

    /**
     * Return (string) signature - uses openssl_sign
     *
     * Return (computed) signature for the specified data by generating a cryptographic digital signature
     * using the private key associated with priv_key_id.
     * @link https://www.php.net/manual/en/function.openssl-sign.php
     * @param string          $data           Data to seal
     * @param resource|string $privateKey     1. a key, returned by openssl_get_privatekey()
     *                                        2. a PEM formatted key
     *                                        3. file with PEM formatted key content
     * @param null|int|string $signatureAlgo  1. one of https://www.php.net/manual/en/openssl.signature-algos.php
     *                                        2. one of openssl_get_md_methods(), self::getAvailableDigestMethods()
     *                                        default OPENSSL_ALGO_SHA1
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function sign(
        string $data,
        $privateKey,
        $signatureAlgo = OPENSSL_ALGO_SHA1
    ) : string
    {
        static $FMTERR2 = 'algorithm: %s ';
        $privateKey = OpenSSLPkeyFactory::assertPkey( $privateKey, 2, true );
        if( ! in_array( $signatureAlgo, self::$SIGNATUREALGOS )) {
            self::assertMdAlgorithm( $signatureAlgo );
        }
        $result    = false;
        $signature = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_sign( $data, $signature, $privateKey, $signatureAlgo );
        }
        catch( Exception $e ) {
            $msg2 = sprintf( $FMTERR2, $signatureAlgo );
            self::assessCatch(
                __FUNCTION__,
                $e,
                ( false !== $result ),
                self::getOpenSSLErrors(),
                $msg2
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            $msg2 = sprintf( $FMTERR2, $signatureAlgo );
            self::logAndThrowRuntimeException(
                __FUNCTION__,
                $msg2,
                self::getOpenSSLErrors()
            );
        }
        return $signature;
    }

    /**
     * Return (string) signature - alias of 'sign'
     *
     * @param string          $data           Data to seal
     * @param resource|string $privateKey     1. a key, returned by openssl_get_privatekey()
     *                                        2. a PEM formatted key
     *                                        3. file with PEM formatted key content
     * @param null|int|string $signatureAlgo  1. one of https://www.php.net/manual/en/openssl.signature-algos.php
     *                                        2. one of openssl_get_md_methods(), self::getAvailableDigestMethods()
     *                                        default OPENSSL_ALGO_SHA1
     * @return string
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function getSignature(
        string $data,
        $privateKey,
        $signatureAlgo = OPENSSL_ALGO_SHA1
    ) : string
    {
        return self::sign( $data, $privateKey, $signatureAlgo );
    }

    /**
     * Return bool true if signature  with publicKey is verified ok - uses openssl_verify
     *
     * Verifies that the signature is correct for the specified data using the public key associated with pub_key_id.
     * This must be the public key corresponding to the private key used for signing.
     * @link https://www.php.net/manual/en/function.openssl-verify.php
     * @param string          $data           The string of data used to generate the signature previously
     * @param string          $signature      A raw binary string, generated by openssl_sign() or similar means
     * @param resource|string $publicKeyId    1. a key (resource), returned by  openssl_get_publickey()
     *                                        2. a PEM formatted key
     *                                        3. file with PEM formatted key
     * @param null|int|string $signatureAlgo  1. one of https://www.php.net/manual/en/openssl.signature-algos.php
     *                                        2. one of openssl_get_md_methods(), self::getAvailableDigestMethods()
     *                                        default OPENSSL_ALGO_SHA1
     * @return bool
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function verify(
        string $data,
        string $signature,
        $publicKeyId,
        $signatureAlgo = OPENSSL_ALGO_SHA1
    ) : bool
    {
        $publicKeyId = OpenSSLPkeyFactory::assertPkey( $publicKeyId, 3, true );
        if( ! in_array( $signatureAlgo, self::$SIGNATUREALGOS )) {
            self::assertMdAlgorithm( $signatureAlgo );
        }
        $result = false;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_verify( $data, $signature, $publicKeyId, $signatureAlgo );
        }
        catch( Exception $e ) {
            self::assessCatch(
                __FUNCTION__,
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
                __FUNCTION__,
                null,
                self::getOpenSSLErrors()
            );
        }
        return (bool) $result;
    }

    /**
     * Return bool true if signature  with publicKey is verified ok - alias of 'verify'
     *
     * @param string          $data           The string of data used to generate the signature previously
     * @param string          $signature      A raw binary string, generated by openssl_sign() or similar means
     * @param resource|string $publicKeyId    1. a key (resource), returned by  openssl_get_publickey()
     *                                        2. a PEM formatted key
     *                                        3. file with PEM formatted key
     * @param null|int|string $signatureAlgo  1. one of https://www.php.net/manual/en/openssl.signature-algos.php
     *                                        2. one of openssl_get_md_methods(), self::getAvailableDigestMethods()
     *                                        default OPENSSL_ALGO_SHA1
     * @return bool
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public static function isSignatureOkForPublicKey(
        string $data,
        string $signature,
        $publicKeyId,
        $signatureAlgo = OPENSSL_ALGO_SHA1
    ) : bool
    {
        return self::verify( $data, $signature, $publicKeyId, $signatureAlgo );
    }

    /**
     * Return a PKCS5 v2 PBKDF2 (raw binary) string - uses openssl_pbkdf2
     *
     * Computes PBKDF2 (Password-Based Key Derivation Function 2), a key derivation function defined in PKCS5 v2.
     * @link https://www.php.net/manual/en/function.openssl-pbkdf2.php
     * @param string $passWord    Password from which the derived key is generated.
     * @param null|string $salt        PBKDF2 recommends a crytographic salt of at least 64 bits (8 bytes).
     *                            default 64 random bytes
     * @param null|int    $keyLength   Length of desired output key, default 40
     * @param null|int    $iterations  The number of iterations desired. NIST recommends at least 10,000.
     *                            https://pages.nist.gov/800-63-3/sp800-63b.html#sec5
     * @param null|string $algorithm   Optional hash or digest algorithm from openssl_get_md_methods(). Defaults to SHA-1.
     * @return string
     * @throws InvalidArgumentException
     */
    public static function getPbkdf2(
        string $passWord,
        $salt = null,
        $keyLength = 40,
        $iterations = 10000,
        $algorithm = 'SHA1'
    ) : string
    {
        static $FMTERR2 = 'algorithm: %s ';
        if( empty( $salt )) {
            $salt   = Workshop::getSalt( 64 );
        }
        $length     = Assert::int( $keyLength, 3, 40 );
        $iterations = Assert::int( $iterations, 4, 10000 );
        $algorithm  = self::assertMdAlgorithm( $algorithm ?? 'SHA1' );
        $result     = false;
        $signature  = null;
        self::clearOpenSSLErrors();
        set_error_handler( self::$ERRORHANDLER );
        try {
            $result = openssl_pbkdf2(
                $passWord,
                $salt,
                $length,
                $iterations,
                $algorithm
            );
        }
        catch( Exception $e ) {
            $msg2 = sprintf( $FMTERR2, $algorithm );
            self::assessCatch(
                __FUNCTION__,
                $e,
                ( false !== $result ),
                self::getOpenSSLErrors(),
                $msg2
            );
        }
        finally {
            restore_error_handler();
        }
        if( false === $result ) {
            $msg2 = sprintf( $FMTERR2, $algorithm );
            self::logAndThrowRuntimeException(
                __FUNCTION__,
                $msg2,
                self::getOpenSSLErrors()
            );
        }
        return $result;
    }
}
