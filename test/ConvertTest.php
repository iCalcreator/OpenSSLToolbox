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
 */
namespace Kigkonsult\OpenSSLToolbox;

use Exception;
use Faker;

/**
 * Class ConvertTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\Convert
 *
 * Testing Convert
 *     Base64
 *     isHex, strToHex, hexToStr
 *     pack/unpack
 */
class ConvertTest extends BaseTest
{
    private   static $FMT   = '%s Error in case #%d';

    /**
     * text2XProvider
     *
     * @return array
     */
    public function text2XProvider() {
        $faker   = Faker\Factory::create();
        $dataArr = [];

        $case    = 310;
        for( $x = 0; $x < 3; $x++ ) {
            $dataArr[] =
                [
                    ++$case,
                    $faker->randomNumber( null, true )
                ];
        }

        $case    = 320;
        for( $x = 0; $x < 3; $x++ ) {
            $dataArr[] =
                [
                    ++$case,
                    number_format( $faker->randomFloat(), 6, '.', '' )
                ];
        }

        $dataArr[] =
            [
                331,
                implode( $faker->words( 2 )),
            ];

        $dataArr[] =
            [
                332,
                $faker->paragraphs( 1, true ),
            ];
        $dataArr[] =
            [
                333,
                $faker->paragraphs( 10, true )
            ];

        $dataArr[] =
            [
                334,
                $faker->paragraphs( 100, true )
            ];

        $dataArr[] =
            [
                335,
                $faker->paragraphs( 1000, true )
            ];

        return $dataArr;
    }

    private static $FMT3  = '%s #%d, %s time : %01.6f testing on %d characters string';


    /** ***********************************************************************
     *  Base64
     ** ******************************************************************** */

    /**
     ** Testing Base64
     *
     * @test
     * @dataProvider text2XProvider
     * @param int    $case
     * @param string $string
     */
    public function base64EnDecodeTest24( $case, $string ) {

        $case = 1000 + $case;
        $startTime = microtime( true );
        $encoded   = Convert::base64Encode( $string );
        $time1     = microtime( true ) - $startTime;

        $this->assertTrue(
            Convert::isBase64( $encoded ),
            sprintf( self::$FMT, Convert::getCm( __METHOD__ ), $case . '-1' )
        );

        $startTime = microtime( true );
        $decoded  = Convert::base64Decode( $encoded );
        $time2     = microtime( true ) - $startTime;
        /*
        if( 10000 <= strlen( $string ) ) {
            echo sprintf(
                self::$FMT3, Convert::getCm( __METHOD__ ), $case, 'encode', $time1, strlen( $string )
                ) . PHP_EOL;
            echo sprintf(
                self::$FMT3, Convert::getCm( __METHOD__ ), $case, 'decode', $time2, strlen( $encoded )
                ) . PHP_EOL;
        }
        */
        $this->assertEquals(
            $string,
            $decoded,
            sprintf( self::$FMT, Convert::getCm( __METHOD__ ), $case . '-2' )
        );
    }

    /**
     * @test
     */
    public function base64UrlEnDecodeTest25() {
        $url = Faker\Factory::create()->url;

        $encoded   = Convert::base64UrlEncode( $url );
        $this->assertTrue(
            Convert::isBase64( $encoded ),
            sprintf( self::$FMT, Convert::getCm( __METHOD__ ), 251 )
        );
        $decoded  = Convert::base64UrlDecode( $encoded );

        $this->assertEquals(
            $url,
            $decoded,
            sprintf( self::$FMT, Convert::getCm( __METHOD__ ), 252 )
        );
    }

    /** ***********************************************************************
     * isHex, strToHex, hexToStr
     ** ******************************************************************** */

    /**
     ** Testing isHex, strToHex, hexToStr
     *
     * @test
     * @dataProvider text2XProvider
     * @param int    $case
     * @param string $string
     */
    public function hexTest26( $case, $string ) {
        $case = 2000 + $case;

        $startTime = microtime( true );
        $hex       = Convert::strToHex( $string );
        $time1     = microtime( true ) - $startTime;

        $this->assertTrue(
            Convert::isHex( $hex ),
            sprintf( self::$FMT, Convert::getCm( __METHOD__ ), $case . '-1' )
        );

        $startTime = microtime( true );
        $string2   = Convert::hexToStr( $hex );
        $time2     = microtime( true ) - $startTime;
        /*
        if( 10000 <= strlen( $string ) ) {
            echo sprintf(
                self::$FMT3, Convert::getCm( __METHOD__ ), $case, 'encode', $time1, strlen( $string )
                ) . PHP_EOL;
            echo sprintf(
                self::$FMT3, Convert::getCm( __METHOD__ ), $case, 'decode', $time2, strlen( $hex )
                ) . PHP_EOL;
        }
        */

        if( ! ctype_digit( $string2 )) {
            $this->assertFalse(
                Convert::isHex( $string2 ),
                sprintf( self::$FMT, Convert::getCm( __METHOD__ ), $case . '-2' ) . ' pos1-10: \'' . substr( $string2, 0, 10 ) . '\''
            );
        }

        $this->assertEquals(
            $string,
            $string2,
            sprintf( self::$FMT, Convert::getCm( __METHOD__ ), $case . '3' )
        );

    }

    /** ***********************************************************************
     *  'H*' - pach/unpack data
     ** ******************************************************************** */

    /**
     ** Testing pack/unpack
     *
     * @test
     * @dataProvider text2XProvider
     * @param int    $case
     * @param string $string
     */
    public function packUnpackTest27( $case, $string ) {
        static $FMT1 = ', input: %d, hex: %d, packed: %d, unpacked: %d, result: %d';
        $case = 3000 + $case;
        $hex       = Convert::strToHex( $string );

        $startTime = microtime( true );
        $packed    = Convert::Hpack( $hex );
        $time1     = microtime( true ) - $startTime;

        $startTime = microtime( true );
        $unPacked  = Convert::HunPack( $packed );
        $time2     = microtime( true ) - $startTime;

        $result    = Convert::hexToStr( $unPacked );
        /*
        if( 10000 <= strlen( $string ) ) {
            echo sprintf(
                self::$FMT3, Convert::getCm( __METHOD__ ), $case, 'encode', $time1, strlen( $hex )
                ) . PHP_EOL;
            echo sprintf(
                self::$FMT3, Convert::getCm( __METHOD__ ), $case, 'decode', $time2, strlen( $packed )
                ) . PHP_EOL;
        }
        */
        $this->assertEquals(
            $string,
            $result,
            sprintf(
                self::$FMT,
                Convert::getCm( __METHOD__ ),
                $case ) .
            sprintf( $FMT1, strlen( $string ), strlen( $hex ), strlen( $packed ), strlen( $unPacked ), strlen( $result ))
        );
    }

}
