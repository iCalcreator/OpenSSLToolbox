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

use InvalidArgumentException;

use function hash_equals;
use function hash_hmac;
use function hexdec;
use function pack;
use function pow;
use function str_pad;
use function strlen;
use function strtolower;
use function substr;
use function time;

/**
 * Class HmacHashFactory
 */
class HmacHashFactory extends BaseFactory
{
    /**
     * List of PHP 7.0.25 registered hashing algorithms (using hash_algos) supporting PHP hash
     * Note, it may exist algorithms in NOT supported by PHP hash_hmac
     *
     * md2, md4, md5, sha1, sha224, sha256, sha384, sha512, ripemd128, ripemd160, ripemd256, ripemd320,
     * whirlpool, tiger128,3, tiger160,3, tiger192,3, tiger128,4, tiger160,4, tiger192,4,
     * snefru, snefru256, gost, gost-crypto, adler32, crc32, crc32b, fnv132, fnv1a32, fnv164, fnv1a64, joaat,
     * haval128,3, haval160,3, haval192,3, haval224,3, haval256,3, haval128,4, haval160,4, haval192,4,
     * haval224,4, haval256,4, haval128,5, haval160,5, haval192,5, haval224,5, haval256,5
     */

    /**
     * Assert algorithm using hash_hmac_algos (if exist), otherwise hash_algos
     *
     * @param string $algorithm
     * @throws InvalidArgumentException
     * @return string
     */
    public static function assertAlgorithm( string $algorithm ) : string
    {
        static $HMACHASHALGOS = 'hash_hmac_algos';
        $algorithms = ( function_exists( $HMACHASHALGOS )) ? $HMACHASHALGOS() : hash_algos();
        return parent::baseAssertAlgorithm( $algorithms, strtolower( $algorithm ), true );
    }

    /**
     * Return a keyed hash value using the HMAC method, applied on (string) argument
     *
     * @link https://www.php.net/manual/en/function.hash-hmac.php
     * @param string $algorithm
     * @param string $data
     * @param string $secret
     * @param null|bool   $rawOutput
     * @return string
     * @throws InvalidArgumentException
     */
    public static function getDigestHash(
        string $algorithm,
        string $data,
        string $secret,
        $rawOutput = false
    ) : string
    {
        $algorithm = self::assertAlgorithm( $algorithm );
        return hash_hmac( $algorithm, $data, $secret, ( $rawOutput ?? false ));
    }


    /**
     * Return a keyed hash value using the HMAC method, applied on contents of a given file
     *
     * @link https://www.php.net/manual/en/function.hash-hmac-file.php
     * @param string $algorithm
     * @param string $fileName   - URL describing location of file to be hashed; Supports fopen wrappers.
     * @param string $secret
     * @param null|bool   $rawOutput
     * @return string
     * @throws InvalidArgumentException
     */
    public static function getDigestHashFromFile(
        string $algorithm,
        string $fileName,
        string $secret,
        $rawOutput = false
    ) : string
    {
        $algorithm = self::assertAlgorithm( $algorithm );
        Assert::fileNameRead( $fileName, 2 );
        return hash_hmac_file( $algorithm, $fileName, $secret, ( $rawOutput ?? false ));
    }

    /**
     * Return bool true if hashes match
     *
     * @param string $expected
     * @param string $actual
     * @return bool
     */
    public static function hashEquals( string $expected, string $actual ) : bool
    {
        return hash_equals( $expected, $actual );
    }

    /**
     * Return HMAC-based One-Time Password (HOTP)
     *
     * @link https://www.php.net/manual/en/function.hash-hmac.php#110288
     * This function implements the algorithm outlined in RFC 6238 for Time-Based One-Time Passwords
     * @link http://tools.ietf.org/html/rfc6238
     *
     * @param string      $key        the string to use for the HMAC key
     * @param null|mixed  $time       a value that reflects a time (unixtime in the example)
     * @param null|int    $digits     the desired length of the OTP
     * @param null|string $algorithm  default 'sha256'
     * @return string the generated OTP
     * @throws InvalidArgumentException
     */
    public static function oauth_totp(
        string $key,
        $time = null,
        $digits = 8,
        $algorithm = null
    ) : string
    {
        static $SHA256 = 'sha256';
        static $NNCAST = 'NNC*';
        static $ZERO   = '0';
        if( empty( $time )) {
            $time = time();
        }
        $digits    = Assert::int( $digits, 3, 8 );
        $algorithm = Assert::string( $algorithm, 4, $SHA256 );
        $algorithm = self::assertAlgorithm( $algorithm );
        $result    = null;
        // Convert counter to binary (64-bit)
        $data = pack( $NNCAST, $time >> 32, $time & 0xFFFFFFFF );
        // Pad to 8 chars (if necessary)
        if( strlen( $data ) < 8 ) {
            $data = str_pad( $data, 8, chr(0 ), STR_PAD_LEFT );
        }
        // Get the hash
        $hash = hash_hmac( $algorithm, $data, $key );
        // Grab the offset
        $offset = 2 * hexdec( substr( $hash, strlen( $hash ) - 1, 1 ));
        // Grab the portion we're interested in
        $binary = hexdec( substr( $hash, $offset, 8 )) & 0x7fffffff;
        // Modulus
        $result = $binary % pow(10, $digits );
        // Pad (if necessary)
        $result = str_pad((string) $result, $digits, $ZERO, STR_PAD_LEFT );
        return $result;
    }
}
