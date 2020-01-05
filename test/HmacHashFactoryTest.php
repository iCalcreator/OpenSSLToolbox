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
 */
namespace Kigkonsult\OpenSSLToolbox;

use Exception;
use Faker;

/**
 * Class HmacHashFactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\HmacHashFactory
 *
 * Testing HmacHashFactory
 *   getDigestHash
 *   getDigestHashFromFile
 *   hashEquals
 *   assertAlgorithm
 *   getDigestHashFromFile exceptions
 *   oauth_totp
 */
class HmacHashFactoryTest extends BaseTest
{

    protected static $FILES = [];
    private static $phrase  = 'The quick brown fox jumped over the lazy dog.';

    private static function getSecret() {
        static $secret = null;
        if( empty( $secret )) {
            $secret = base64_encode( self::$phrase );
        }
        return $secret;
    }

    /**
     * hmacHashTest dataProvider
     * @return array
     */
    public function hmacHashTestProvider() {
        $dataArr = [];
        $case    = 200;
        foreach( hash_algos() as $algorithm ) {
            if( in_array( $algorithm, [ 'joaat' ] )) { // don't work...
                continue;
            }
            $dataArr[] = [
                ++$case,
                $algorithm
            ];
        }
        return $dataArr;
    }

    /**
     * Testing HmacHashFactory::getDigestHash
     *         HmacHashFactory::getDigestHashFromFile
     *         HmacHashFactory::hashEquals
     * @test
     * @dataProvider hmacHashTestProvider
     * @param int    $case
     * @param string $algorithm
     */
    public function hmacHashTest( $case, $algorithm ) {
        static $FMT = '%s Error in case #%d, algorithm: %s';
        $data       = Faker\Factory::create()->paragraphs( 10, true );
        $secret     = Workshop::getSalt();

        $hash1 = HmacHashFactory::getDigestHash( $algorithm, $data, $secret );

        $file = self::getFileName( __FUNCTION__ . $case );
        file_put_contents( $file, $data );
        $hash2 = HmacHashFactory::getDigestHashFromFile( $algorithm, $file, $secret );
        unlink( $file );

        $this->assertTrue(
            HmacHashFactory::hashEquals( $hash1, $hash2 ),
            sprintf( $FMT, HmacHashFactory::getCm( __METHOD__ ), $case, $algorithm )
        );
    }

    /**
     * testAssertAlgorithm dataProvider
     * @return array
     */
    public function assertAlgorithmProvider() {
        $dataArr = [];

        $dataArr[] = [
            1,
            'ShA512',
            true
        ];

        $dataArr[] = [
            2,
            'noAlgorithm',
            false
        ];

        return $dataArr;
    }

    /**
     * Testing HmacHashFactory::assertAlgorithm
     *
     * @test
     * @dataProvider assertAlgorithmProvider
     * @param int    $case
     * @param string $algorithm
     * @param string $expected
     */
    public function testAssertAlgorithm( $case, $algorithm, $expected ) {
        static $FMT  = '%s Error in case #%d';

        $result  = null;
        $outcome = true;
        try {
            $result = HmacHashFactory::assertAlgorithm( $algorithm );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals( $expected, $outcome, sprintf( $FMT, HmacHashFactory::getCm( __METHOD__ ), $case . '-1' ));
        if( $expected ) {
            $this->assertEquals( strtolower( $algorithm ), $result, sprintf( $FMT, HmacHashFactory::getCm( __METHOD__ ), $case . '-2' ));
        }
    }


    /**
     * testgetDigestHashFromFileExceptionTest dataProvider
     * @return array
     */
    public function getDigestHashFromFileExceptionTestProvider() {
        $dataArr = [];

        $dataArr[] = [
            1,
            'sha256',
            'fileName'
        ];

        return $dataArr;
    }

    /**
     * Testing HmacHashFactory::getDigestHashFromFile exceptions
     *
     * @test
     * @dataProvider getDigestHashFromFileExceptionTestProvider
     * @param int    $case
     * @param string $algorithm
     * @param string $fileName
     */
    public function testgetDigestHashFromFileExceptionTest( $case, $algorithm, $fileName ) {
        static $FMT  = '%s Error in case #%d';
        $result  = null;
        $outcome = true;
        try {
            $result = HmacHashFactory::getDigestHashFromFile( $algorithm, $fileName, 'secret' );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertFalse( $outcome, sprintf( $FMT, HmacHashFactory::getCm( __METHOD__ ), $case ));
    }

    /**
     * testOauthTotp dataProvider
     * @return array
     */
    public function oauthTotpProvider() {
        $dataArr = [];

        $algoHash = [
            'md2'        => '0000000582259851',
            'md4'        => '0000002002753749',
            'md5'        => '0000001000175228',
            'sha1'       => '0000001681981013',
            'sha256'     => '0000001053049589',
            'sha384'     => '0000001466119322',
            'sha512'     => '0000002112887971',
            'ripemd128'  => '0000000854691662',
            'ripemd160'  => '0000001436037858',
            'ripemd256'  => '0000001949176770',
            'ripemd320'  => '0000000431168000',
            'whirlpool'  => '0000001391494533',
            'tiger128,3' => '0000000000000111',
            'tiger160,3' => '0000001570221234',
            'tiger192,3' => '0000000441565498',
            'tiger128,4' => '0000000515646332',
            'tiger160,4' => '0000002088352188',
            'tiger192,4' => '0000001405412832',
            'snefru'     => '0000001661822588',
            'gost'       => '0000002086446154',
            'adler32'    => '0000000000000000',
            'crc32'      => '0000000000000000',
            'crc32b'     => '0000001984903888',
            'haval128,3' => '0000002127729076',
            'haval160,3' => '0000000208786966',
            'haval192,3' => '0000001370849182',
            'haval224,3' => '0000001884673836',
            'haval256,3' => '0000001824628811',
            'haval128,4' => '0000001842114244',
            'haval160,4' => '0000001276770288',
            'haval192,4' => '0000001991363162',
            'haval224,4' => '0000001252128262',
            'haval256,4' => '0000001826511896',
            'haval128,5' => '0000001606893225',
            'haval160,5' => '0000001464791670',
            'haval192,5' => '0000000383802141',
            'haval224,5' => '0000001158646636',
            'haval256,5' => '0000000618153595',
        ];
        $data   = 'hello';
        $case   = 1;
        $time   = 1558286894;
        $digits = 16;
        foreach( $algoHash as $algorithm => $hash ) {
            $dataArr[] = [
                $case++,
                self::$phrase,
                $time,
                $digits,
                $algorithm,
                $hash,
            ];
        }

        return $dataArr;
    }

    /**
     * Testing HmacHashFactory::oauth_totp
     *
     * @test
     * @dataProvider oauthTotpProvider
     * @param int    $case
     * @param string $data
     * @param int    $time
     * @param int    $digits
     * @param string $algorithm
     * @param string $expected
     */
    public function testOauthTotp( $case, $data, $time, $digits, $algorithm, $expected ) {
        static $FMT  = '%s Error in case #%d, algorithm: %s, hash: %s';

        $hash = HmacHashFactory::oauth_totp( $data, $time, $digits, $algorithm );

        $this->assertTrue(
            HmacHashFactory::hashEquals( $expected, $hash ),
            sprintf( $FMT, HmacHashFactory::getCm( __METHOD__ ), $case, $algorithm, $hash )
        );
    }

    /**
     * @test
     */
    public function testOauthTotp2() {
        static $FMT  = '%s Error in case #%d, algorithm: %s, hash: %s';

        $data   = 'hello';
        $time   = 1558286894;
        $digits = 16;
        $sha256 = '0000000952491788';

        $hash   = HmacHashFactory::oauth_totp( $data, $time, $digits );

        $this->assertTrue(
            HmacHashFactory::hashEquals( $sha256, $hash ),
            sprintf( $FMT, HmacHashFactory::getCm( __METHOD__ ), 1, 'sha256', $hash )
        );
    }

}
