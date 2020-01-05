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

use function base64_decode;
use function base64_encode;
use function ceil;
use function chr;
use function dechex;
use function hexdec;
use function is_string;
use function ord;
use function preg_match;
use function rtrim;
use function str_repeat;
use function strlen;
use function strtr;
use function substr;

/**
 * Class Convert
 */
class Convert extends BaseFactory
{
    /** ***********************************************************************
     *  Base64
     ** ******************************************************************** */

    /**
     * @var int
     *         sufficiently small modulo 4 natural
     * @static
     */
    private static $DIVISOR = 256;

    /**
     * @var string
     * @access private
     * @static
     */
    private static $EQ   = '=';

    /**
     * @var string
     * @access private
     * @static
     */
    private static $MU = '-_';
    private static $PS = '+/';

    /**
     * Return bool true if input is a base64 encoded string
     *
     * @param string $data
     * @return bool
     * @static
     * @link http://php.net/manual/en/function.base64-decode.php#81425
     */
    public static function isBase64( $data ) {
        static $PATTERN = '%^[a-zA-Z0-9/+]*={0,2}$%';
        return ( 1 == preg_match($PATTERN, $data ));
    }

    /**
     * Return base64 encoded string
     *
     * @param string $raw
     * @return string
     * @static
     */
    public static function base64Encode( $raw ) {
        $data = Assert::string( $raw );
        return base64_encode( $data );
    }

    /**
     * Return base64 decoded string of arbitrary length
     *
     * @param string $encoded
     * @return string
     * @static
     * @link https://www.php.net/manual/en/function.base64-decode.php#92980
     */
    public static function base64Decode( $encoded ) {
        $decoded      = '';
        $chunksLength = ceil( strlen( $encoded ) / self::$DIVISOR );
        for( $i = 0; $i < $chunksLength; $i++ ) {
            $decoded .= base64_decode( substr( $encoded, ( $i * self::$DIVISOR ), self::$DIVISOR ) );
        }
        return $decoded;
    }
    /**
     * Return base64url encoded string
     *
     * @param string $raw
     * @return string
     * @static
     * @link https://www.php.net/manual/en/function.base64-encode.php#121767
     */
    public static function base64UrlEncode( $raw ) {
        $data = Assert::string( $raw );
        return rtrim( strtr( base64_encode( $data ), self::$PS, self::$MU ), self::$EQ );
    }

    /**
     * Return base64url decoded string
     *
     * @param string $encoded
     * @return string
     * @static
     * @link https://www.php.net/manual/en/function.base64-encode.php#121767
     */
    public static function base64UrlDecode( $encoded ) {
        $multiplier = 3 - ( 3 + strlen( $encoded ) ) % 4;
        return base64_decode( strtr( $encoded, self::$MU, self::$PS ) . str_repeat( self::$EQ, $multiplier ) );
    }

    /** ***********************************************************************
     *  isHex, String to hex and hex to string
     ** ******************************************************************** */

    /**
     * Return bool true if string is in hex
     *
     * @param string $string
     * @return bool
     * @link https://stackoverflow.com/questions/2643157/php-simple-validate-if-string-is-hex
     */
    public static function isHex( $string ) {
        static $PATTERN = "/^[a-f0-9]{2,}$/i";
        return ( is_string( $string ) &&
            ( 1 == @preg_match( $PATTERN, $string ) ) &&
            ! ( strlen( $string ) & 1 )
        );
    }

    /**
     * Return string converted to hex
     *
     * @param string $string
     * @return string
     * @static
     * @link https://stackoverflow.com/questions/14674834/php-convert-string-to-hex-and-hex-to-string
     */
    public static function strToHex( $string ) {
        static $ZERO = '0';
        $string = (string) $string;
        $strlen = strlen( $string );
        $hex    = '';
        for( $i = 0; $i < $strlen; $i++ ) {
            $ord     = ord( $string[$i] );
            $hexCode = dechex( $ord );
            $hex     .= substr( $ZERO . $hexCode, -2 );
        }
        return strToUpper( $hex );
    }

    /**
     * Return string converted from hex
     *
     * @param string $hex
     * @return string
     * @static
     * @link https://stackoverflow.com/questions/14674834/php-convert-string-to-hex-and-hex-to-string
     */
    public static function hexToStr( $hex ) {
        $strlen = strlen( $hex ) - 1;
        $string = '';
        for( $i = 0; $i < $strlen; $i += 2 ) {
            $string .= chr( hexdec( $hex[$i] . $hex[$i + 1] ) );
        }
        return $string;
    }

    /** ***********************************************************************
     *  'H*' - pack/unpack (hex) data
     ** ******************************************************************** */

    private static $HAST = 'H*';

    /**
     * Return binary string from a 'H*' packed hexadecimally encoded (binary) string
     *
     * @param mixed $input
     * @return string
     * @static
     * @link https://www.php.net/manual/en/function.pack.php
     */
    public static function Hpack( $input ) {
        return pack( self::$HAST, $input );
    }

    /**
     * Return (mixed) data from a 'H*' unpacked binary string
     *
     * @param string $binaryData
     * @return mixed
     * @static
     * @link https://www.php.net/manual/en/function.unpack.php
     */
    public static function HunPack( $binaryData ) {
        return unpack( self::$HAST, $binaryData )[1];
    }
}
