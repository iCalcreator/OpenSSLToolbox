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
 * License   Subject matter of licence is the software OpenSSLToolbox.
 *           The above copyright, link, package and version notices,
 *           this licence notice shall be included in all copies or substantial
 *           portions of the OpenSSLToolbox.
 *
 *           OpenSSLToolbox is free software: you can redistribute it and/or modify
 *           it under the terms of the GNU Lesser General Public License as published
 *           by the Free Software Foundation, either version 3 of the License,
 *           or (at your option) any later version.
 *
 *           OpenSSLToolbox is distributed in the hope that it will be useful,
 *           but WITHOUT ANY WARRANTY; without even the implied warranty of
 *           MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *           GNU Lesser General Public License for more details.
 *
 *           You should have received a copy of the GNU Lesser General Public License
 *           along with OpenSSLToolbox. If not, see <https://www.gnu.org/licenses/>.
 *
 * Disclaimer of rights
 *
 *           Substantial portion of software below, originates from
 *             https://github.com/ioncube/php-openssl-cryptor,
 *           available under the MIT License.
 *
 *           copyright  2016 ionCube Ltd.
 *
 *           Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 *           and associated documentation files (the "Software"), to deal in the Software without restriction,
 *           including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *           and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 *           subject to the following conditions:
 *
 *           The above copyright notice and this permission notice shall be included in all copies or substantial
 *           portions of the Software.
 *
 *           THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 *           INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
 *           AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 *           DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *           OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 *
 *           Herein may exist software logic (hereafter solution(s))
 *           found on internet (hereafter originator(s)).
 *           The rights of each solution belongs to respective originator;
 *
 *           Credits and acknowledgements to originators!
 *           Links to originators are found wherever appropriate.
 *
 *           Only OpenSSLToolbox copyright holder works, OpenSSLToolbox author(s) works and solutions derived works
 *           and collection of solutions are covered by GNU Lesser General Public License, above.
 */
namespace Kigkonsult\OpenSSLToolbox;

use InvalidArgumentException;
use Kigkonsult\LoggerDepot\LoggerDepot;
use Psr\Log\LogLevel;
use RuntimeException;

use function is_null;
use function in_array;
use function ltrim;
use function sprintf;
use function strlen;
use function substr;

/**
 * Class OpenSSLCryptor
 *
 * An encrypt/decrypt solution.
 * Wrapper for OpenSSL : openssl_decrypt, openssl_encrypt, openssl_digest, openssl_cipher_iv_length
 * Require a Psr\Log logger, provided by LoggerDepot
 *
 * Simple usage, encrypt
 * <code>
 * $encrypted = OpenSSLCryptor::factory()->getEncryptedString( $data, $cryptKey );
 * </code>
 *
 * Simple usage, decrypt
 * <code>
 * $decrypted = OpenSSLCryptor::factory()->getDecryptedString( $encrypted, $cryptKey );
 * </code>
 */
class OpenSSLCryptor extends OpenSSLBaseFactory
{

    /** ***********************************************************************
     * Software below originates from
     * https://github.com/ioncube/php-openssl-cryptor
     * @copyright 2016 ionCube Ltd.
     * @license MIT - ionCube Ltd
     * @license LGPL - derived works
     ** ******************************************************************** */

    /**
     * Format constants
     */
    const FORMAT_RAW = 0;
    const FORMAT_B64 = 1;
    const FORMAT_HEX = 2;

    /**
     * @var string  defaults
     */
    private static $defaultCipherAlgorithm = 'aes-256-ctr';
    private static $defaultHashAlgorithm   = 'sha256';
    private static $defaultFormat          = self::FORMAT_B64;

    /**
     * @var string
     * @access private
     */
    private $cipherAlgorithm;

    /**
     * @var string
     * @access private
     */
    private $hashAlgorithm;

    /**
     * @var int
     * @access private
     */
    private $initializationVectorNumBytes;

    /**
     * @var int
     * @access private
     */
    private $format;

    /**
     * Class constructor
     *
     * @param string $cipherAlgorithm     The cipher algorithm,         default aes-256-ctr encryption
     * @param string $hashAlgorithm       Key hashing algorithm,        default sha256 key hashing
     * @param int    $encryptedEncoding   Format of the encrypted data, default base64 encoding
     *                                    one of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function __construct( $cipherAlgorithm = null, $hashAlgorithm = null, $encryptedEncoding = null ) {
        static $FMTINITOUT = 'Init %s, %s, cipher: %s, hash: %s, format: %s ';
        $this->logger = LoggerDepot::getLogger( get_class());
        $this->log( LogLevel::INFO, self::initClassStr());
        $this->setCipherAlgorithm( ( empty( $cipherAlgorithm )   ? self::$defaultCipherAlgorithm : $cipherAlgorithm ));
        $this->setHashAlgorithm((    empty( $hashAlgorithm )     ? self::$defaultHashAlgorithm   : $hashAlgorithm ));
        $this->setFormat((           empty( $encryptedEncoding ) ? self::$defaultFormat          : $encryptedEncoding ));
        $this->log(
            LogLevel::INFO,
            sprintf(
                $FMTINITOUT,
                self::getCm( self::class ),
                OPENSSL_VERSION_TEXT,
                $this->cipherAlgorithm,
                $this->hashAlgorithm,
                self::getFormatText( $this->format )
            )
        );

    }

    /**
     * Class factory method
     *
     * @param string  $cipherAlgorithm    The cipher algorithm, default aes256 encryption
     * @param string  $hashAlgorithm      Key hashing algorithm, default sha256 key hashing
     * @param int     $encryptedEncoding  Format of the encrypted data
     *                                    one of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
     * @return static
     * @throws InvalidArgumentException
     * @access static
     */
    public static function factory( $cipherAlgorithm = null, $hashAlgorithm = null, $encryptedEncoding = null ) {
        return new self( $cipherAlgorithm, $hashAlgorithm, $encryptedEncoding );
    }

    /**
     * Class destructor
     */
    public function __destruct() {
        unset(
            $this->cipherAlgorithm,
            $this->initializationVectorNumBytes,
            $this->hashAlgorithm,
            $this->format
        );
    }

    /**
     * Return decrypted string.
     *
     * @param  string $data        String to decrypt.
     * @param  string $decryptKey  Decryption key.
     * @param int $dataEncoding    Optional override for the input encoding,
     *                             one of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
     * @return string              The decrypted string.
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getDecryptedString( $data, $decryptKey, $dataEncoding = null ) {
        static $FMTERR1 = 'Data length (%d) is less than iv length %d';
        $this->log( LogLevel::DEBUG, sprintf( self::$FMTSTART, self::getCm( __METHOD__ ), strlen( $data )));
        $startTime      = microtime( true );
        Assert::string( $data, 1 );
        Assert::string( $decryptKey, 2 );
        if( is_null( $dataEncoding )) {
            $dataEncoding = $this->format;
        }
        else {
            $this->setFormat( $dataEncoding );
        }
        // Restore the encrypted data if encoded
        switch( $dataEncoding ) {
            case self::FORMAT_B64 :
                $raw = Convert::base64Decode( $data );
                break;
            case self::FORMAT_HEX :
                $raw = Convert::Hpack( $data );
                break;
            default :
                $raw = $data;
                break;
        } // end switch
        // and do an integrity check on the size.
        $strlenRaw = strlen( $raw );
        if( $strlenRaw < $this->initializationVectorNumBytes ) {
            throw new RuntimeException( sprintf( $FMTERR1, $strlenRaw, $this->initializationVectorNumBytes ));
        }
        // Extract the initialisation vector and encrypted data
        $initializationVector = substr( $raw, 0, $this->initializationVectorNumBytes );
        $toDecrypt            = substr( $raw, $this->initializationVectorNumBytes );
        $this->log( LogLevel::DEBUG, 3 . self::$FMTIVTXT . strlen( $initializationVector ));
        // Hash the key
        $keyHash = OpenSSLFactory::getDigestHash( $decryptKey, $this->hashAlgorithm, true );
        $this->log( LogLevel::DEBUG, 4 . self::$FMTKHTXT . strlen( $keyHash ));
        // and decrypt
        $result  = OpenSSLFactory::getDecryptedString(
            $toDecrypt, $this->cipherAlgorithm, $keyHash, OPENSSL_RAW_DATA, $initializationVector
        );
        $this->log(
            LogLevel::INFO,
            sprintf(
                self::$FMTEND,
                self::getCm( __METHOD__ ),
                strlen( $data ),
                strlen( $result ),
                self::getExecTime( $startTime )
            )
        );
        return $result;
    }

    /**
     * Return Encrypted string.
     *
     * @param  string $data            String to encrypt.
     * @param  string $encryptKey      Encryption key.
     * @param int $outputEncoding      Optional override for the output encoding
     *                                 one of FORMAT_RAW, FORMAT_B64 or FORMAT_HEX
     * @return string                  The encrypted string.
     * @throws InvalidArgumentException
     * @throws RuntimeException
     */
    public function getEncryptedString( $data, $encryptKey, $outputEncoding = null ) {
        static $FMTERR1 = 'Not a strong key';
        $this->log( LogLevel::DEBUG, sprintf( self::$FMTSTART, self::getCm( __METHOD__ ), strlen( $data )));
        $startTime = microtime( true );
        Assert::string( $data, 1 );
        Assert::string( $encryptKey, 2 );
        if( is_null( $outputEncoding) ) {
            $outputEncoding = $this->format;
        }
        else {
            $this->setFormat( $outputEncoding );
        }
        // Build an initialisation vector
        if( empty( $this->initializationVectorNumBytes )) {
            $initializationVector = '';
        }
        else {
            $initializationVector = Workshop::getRandomPseudoBytes(
                $this->initializationVectorNumBytes,
                $isStrongCrypto
            );
            if( ! $isStrongCrypto ) {
                throw new RuntimeException( $FMTERR1 );
            }
        }
        $this->log( LogLevel::DEBUG, 3 . self::$FMTIVTXT . strlen( $initializationVector ));
        // Hash the key
        $keyHash = OpenSSLFactory::getDigestHash( $encryptKey, $this->hashAlgorithm, true );
        $this->log( LogLevel::DEBUG, 4 . self::$FMTKHTXT . strlen( $keyHash ));
        // and encrypt
        $encrypted = OpenSSLFactory::getEncryptedString(
            $data, $this->cipherAlgorithm, $keyHash, OPENSSL_RAW_DATA, $initializationVector
        );
        // The result comprises the IV and encrypted data
        $result = $initializationVector . $encrypted;
        // and format the result if required.
        switch( $outputEncoding ) {
            case self::FORMAT_B64 :
                $result = Convert::base64Encode( $result );
                break;
            case self::FORMAT_HEX :
                $result = Convert::HunPack( $result );
                break;
        } // end switch
        $this->log(
            LogLevel::INFO,
            sprintf(
                self::$FMTEND,
                self::getCm( __METHOD__ ),
                strlen( $data ),
                strlen( $result ),
                self::getExecTime( $startTime )
            )
        );
        return $result;
    }

    /** ***********************************************************************
     *  Getters and setters etc
     */

    /**
     * @var array
     * @access private
     */
    private static $FORMATS = [ self::FORMAT_RAW => 'raw', self::FORMAT_B64 => 'base64', self::FORMAT_HEX => 'hex' ];

    /**
     * @var string
     * @access private
     * @static
     */
    private static $FMTENCTXT   = ' Set encoding for encrypted data : ';
    private static $FMTCIPHER   = ' Set cipherAlgorithm: ';
    private static $FMTHASHALGO = ' Set hashAlgorithm: ';
    private static $FMTIVTXT    = ' InitializationVector length: ';
    private static $FMTKHTXT    = ' KeyHash length: ';
    private static $FMTSTART    = 'START %s, input data length: %d';
    private static $FMTEND      = 'END %s input/output byte length: %d/%d, time: %01.6f';

    /**
     * Assert format
     *
     * @param int $format
     * @throws InvalidArgumentException
     */
    private static function assertFormat( $format ) {
        $FMTERR2 = 'Invalid format \'%s\'';
        if( ! in_array( $format, array_keys( self::$FORMATS ))) {
            throw new InvalidArgumentException( sprintf( $FMTERR2, $format ));
        }
    }

    /**
     * Return format text
     *
     * @param int $format
     * @return string
     * @static
     */
    public static function getFormatText( $format ) {
        self::assertFormat( $format );
        return self::$FORMATS[$format];
    }

    /**
     * Return cipherAlgorithm
     * @return string
     */
    public function getCipherAlgorithm() {
        return $this->cipherAlgorithm;
    }

    /**
     * Set cipherAlgorithm (and initializationVectorNumBytes)
     *
     * @param string $cipherAlgorithm
     * @return static
     * @throws InvalidArgumentException
     */
    public function setCipherAlgorithm( $cipherAlgorithm ) {
        $this->cipherAlgorithm = self::assertCipherAlgorithm( Assert::string( $cipherAlgorithm ) );
        $this->log( LogLevel::DEBUG, ltrim( self::$FMTCIPHER ) . $this->cipherAlgorithm );
        $this->initializationVectorNumBytes = OpenSSLFactory::getCipherIvLength( $this->cipherAlgorithm );
        $this->log( LogLevel::DEBUG,ltrim( self::$FMTIVTXT ) . $this->initializationVectorNumBytes );
        return $this;
    }

    /**
     * Return HashAlgorithm
     *
     * @return string
     */
    public function getHashAlgorithm() {
        return $this->hashAlgorithm;
    }

    /**
     * Set hashAlgorithm
     *
     * @param string $hashAlgorithm
     * @return static
     * @throws InvalidArgumentException
     */
    public function setHashAlgorithm( $hashAlgorithm ) {
        $this->hashAlgorithm = self::assertMdAlgorithm( Assert::string( $hashAlgorithm ) );
        $this->log( LogLevel::DEBUG, ltrim( self::$FMTHASHALGO ) . $this->hashAlgorithm );
        return $this;
    }

    /**
     * Return format
     *
     * @param bool $asText
     * @return int|string
     */
    public function getFormat( $asText = false ) {
        $asText = Assert::bool( $asText, 1, false );
        return ( $asText ) ? self::getFormatText( $this->format ) : $this->format;
    }

    /**
     * Set format
     *
     * @param int $format
     * @return static
     * @throws InvalidArgumentException
     */
    public function setFormat( $format ) {
        self::assertFormat( $format );
        $this->format = $format;
        $this->log( LogLevel::DEBUG, ltrim( self::$FMTENCTXT ) . self::getFormatText( $format ));
        return $this;
    }

    /**
     * @param float $startTime
     * @return float
     */
    private static function getExecTime( $startTime ) {
        return ( microtime( true ) - $startTime );
    }
}
