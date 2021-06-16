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
use function hash;

/**
 * Class HashFactory
 */
class HashFactory extends BaseFactory
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
     * Assert algorithm (return found)
     *
     * @param string $algorithm
     * @return string
     * @throws InvalidArgumentException
     */
    public static function assertAlgorithm( string $algorithm ) : string
    {
        return parent::baseAssertAlgorithm( hash_algos(), strtolower( $algorithm ), true );
    }

    /**
     * Return a hash value (message digest), applied on (string) argument
     *
     * @link https://www.php.net/manual/en/function.hash.php
     * @param string     $algorithm
     * @param string     $data
     * @param null|bool  $rawOutput
     * @return string
     * @throws InvalidArgumentException
     */
    public static function getDigestHash(
        string $algorithm,
        string $data,
        $rawOutput = false
    ) : string
    {
        $algorithm = self::assertAlgorithm( $algorithm );
        $data      = Assert::string( $data, 2 );
        $rawOutput = Assert::bool( $rawOutput, 3, false );
        return hash( $algorithm, $data, ( $rawOutput ?? false ));
    }

    /**
     * Return a hash value using the contents of a given file
     *
     * @link https://www.php.net/manual/en/function.hash-file.php
     * @param string     $algorithm
     * @param string     $fileName   - URL describing location of file to be hashed; Supports fopen wrappers.
     * @param null|bool  $rawOutput
     * @return string
     * @throws InvalidArgumentException
     */
    public static function getDigestHashFromFile(
        string $algorithm,
        string $fileName,
        $rawOutput = false
    ) : string
    {
        $algorithm = self::assertAlgorithm( $algorithm );
        Assert::fileNameRead( $fileName, 2 );
        $rawOutput = Assert::bool( $rawOutput, 3, false );
        return hash_file( $algorithm, $fileName, ( $rawOutput ?? false ));
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
     * Return a PBKDF2 key derivation of a supplied password
     *
     * @link https://www.php.net/manual/en/function.hash-pbkdf2.php
     * @link https://en.wikipedia.org/wiki/PKCS
     * @link https://tools.ietf.org/html/rfc8018
     * @param string $algorithm   Name of selected hashing algorithm (https://www.php.net/manual/en/function.hash-algos.php)
     * @param string $passWord    The password to use for the derivation
     * @param null|string $salt   The salt to use for the derivation. This value should be generated randomly.
     *                            default 64 bytes
     * @param null|int $iterations
     *                            The number of internal iterations to perform for the derivation.
     * @param null|int $length    The length of the output string.
     *                            If raw_output is TRUE this corresponds to the byte-length of the derived key,
     *                            if raw_output is FALSE this corresponds to twice the byte-length of the derived key
     *                            (as every byte of the key is returned as two hexits).
     *                            if 0 is passed, the entire output of the supplied algorithm is used.
     * @param null|bool $rawOutput
     *                            TRUE, outputs raw binary data. FALSE outputs lowercase hexits.
     * @return string
     * @throws InvalidArgumentException
     */
    public static function getHashPbkdf2(
        string $algorithm,
        string $passWord,
        $salt = null,
        $iterations = 10000,
        $length = 0,
        $rawOutput = false
    ) : string
    {
        self::assertAlgorithm( $algorithm );
        Assert::string( $passWord, 2 );
        if( empty( $salt )) {
            $salt = Workshop::getSalt( 64 );
        }
        else {
            Assert::string( $salt, 3 );
        }
        $iterations = Assert::int( $iterations, 4, 10000 );
        $length     = Assert::int( $length, 5, 0 );
        return hash_pbkdf2(
            $algorithm,
            $passWord,
            $salt,
            $iterations,
            $length,
            ( $rawOutput ?? false )
        );
    }
}
