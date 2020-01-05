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
 * Class HashFactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\HashFactory
 * 
 * Testing HashFactory
 *   getDigestHash/getDigestHashFromFile
 *   assertAlgorithm - exceptions
 *   getDigestHashFromFile exceptions
 *
 * Testing HashFactory
 *    getHashPbkdf2
 *    getHashPbkdf2 exceptions
 */
class HashFactoryTest1 extends BaseTest
{

    protected static $FILES = [];

    /**
     * hashTest11 dataProvider
     * @return array
     */
    public function hashTest11Provider() {
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
     ** Testing HashFactory::getDigestHash/getDigestHashFromFile
     *
     * @test
     * @dataProvider hashTest11Provider
     * @param int    $case
     * @param string $algorithm
     */
    public function hashTest11( $case, $algorithm ) {
        static $FMT = '%s Error in case #%d, algorithm: %s';
        $data       = Faker\Factory::create()->paragraphs( 10, true );

        $hash1 = HashFactory::getDigestHash( $algorithm, $data );

        $file = self::getFileName( __FUNCTION__ . $case );
        file_put_contents( $file, $data );
        $hash2 = HashFactory::getDigestHashFromFile( $algorithm, $file );
        unlink( $file );

        $this->assertTrue(
            HashFactory::hashEquals( $hash1, $hash2 ),
            sprintf( $FMT, HashFactory::getCm( __METHOD__ ), $case, $algorithm )
        );
    }

    /**
     * assertAlgorithmTest12 dataProvider
     * @return array
     */
    public function assertAlgorithmTest12Provider() {
        $dataArr = [];

        $dataArr[] =
            [
                11,
                'ShA512',
                true
            ];

        $dataArr[] =
            [
                12,
                'noAlgorithm',
                false
            ];

        return $dataArr;
    }

    /**
     ** Testing HashFactory::assertAlgorithm - exceptions
     *
     * @test
     * @dataProvider assertAlgorithmTest12Provider
     * @param int    $case
     * @param string $algorithm
     * @param string $expected
     */
    public function assertAlgorithmTest12( $case, $algorithm, $expected ) {
        static $FMT = '%s Error in case #%d';


        $result  = null;
        $outcome = true;
        try {
            $result = HashFactory::assertAlgorithm( $algorithm );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals( $expected, $outcome, sprintf( $FMT, HashFactory::getCm( __METHOD__ ), $case . '1' ));
        if( $expected ) {
            $this->assertEquals( strtolower( $algorithm ), $result, sprintf( $FMT, HashFactory::getCm( __METHOD__ ), $case . '2' ));
        }
    }

    /**
     * generateFromFileExeptionsTest13 dataProvider
     * @return array
     */
    public function generateFromFileExeptionsTest13Provider() {
        $dataArr = [];

        $dataArr[] = [
            401,
            'sha256',
            'fileName'
        ];

        return $dataArr;
    }

    /**
     ** Testing HashFactory::getDigestHashFromFile exceptions
     *
     * @test
     * @dataProvider generateFromFileExeptionsTest13Provider
     * @param int    $case
     * @param string $algorithm
     * @param string $fileName
     */
    public function generateFromFileExeptionsTest13( $case, $algorithm, $fileName ) {
        static $FMT  = '%s Error in case #%d';
        $result  = null;
        $outcome = true;
        try {
            $result = HashFactory::getDigestHashFromFile( $algorithm, $fileName );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertFalse( $outcome, sprintf( $FMT, HashFactory::getCm( __METHOD__ ), $case ));
    }

    /**
     * pbkdf2Test21 dataProvider
     * @return array
     */
    public function pbkdf2Test21Provider() {
        $dataArr        = [];
        $faker          = Faker\Factory::create();
//        $digestMethods  = OpenSSLFactory::$SIGNATUREALGOS; // NOT accepted here
//          $digestMethods  = OpenSSLFactory::getAvailableDigestMethods( false );
        // all but [DSA, DSA-SHA, SHA, dsaEncryption, dsaWithSHA, ecdsa-with-SHA1, sha] accepted, in total 23
        $digestMethods  = hash_algos();  // all accepted, in total 46
        $case           = 1;
        foreach( $digestMethods as $digestMethod ) {
            $dataArr[] = [
                $case++,
                $digestMethod,
                $faker->paragraphs( 10, true ),
                ( 1 == array_rand( [ 0, 1 ] )) ? null : $faker->words( 10, true ),
                ( 1 == array_rand( [ 0, 1 ] )) ? null : 12345,
                ( 1 == array_rand( [ 0, 1 ] )) ? null : 60
            ];
        }

        return $dataArr;
    }

    /**
     * Testing HashFactory::getHashPbkdf2
     *
     * @test
     * @dataProvider pbkdf2Test21Provider
     * @param int    $case
     * @param string $algorithm
     * @param string $data
     * @param string $salt
     * @param int    $iterations
     * @param int    $keyLength
     */
    public function pbkdf2Test21( $case, $algorithm, $data, $salt, $iterations, $keyLength ) {
        static $FMT = '%s Error in case #%d, algorithm: %s';
        $hash       = null;
        try {
            $hash = HashFactory::getHashPbkdf2( $algorithm, $data, $salt, $iterations, $keyLength );
        }
        catch( Exception $e ) {
            echo $case . ' ' . $algorithm . ' - ' . $e->getMessage() . PHP_EOL; // test ###
        }

        $this->assertTrue(
            ( is_string( $hash ) && ! empty( $hash )),
            sprintf( $FMT, HashFactory::getCm( __METHOD__ ), $case . '-1', $algorithm)
        );
    }

    /**
     * pbkdf2exceptionsTest22 dataProvider
     * @return array
     */
    public function pbkdf2exceptionsTest22Provider() {
        $dataArr = [];

        $dataArr[] = [
            1,
            'noAlgorithm',
            'data',
            'salt',
            8,
            1024
        ];

        $dataArr[] = [
            2,
            'sha256',
            'data',
            'salt',
            -1,
            1024
        ];

        $dataArr[] = [
            3,
            'sha256',
            'data',
            'salt',
            8,
            -1,
        ];

        return $dataArr;
    }

    /**
     * Testing HashFactory::getHashPbkdf2 exceptions
     *
     * @test
     * @dataProvider pbkdf2exceptionsTest22Provider
     * @param int    $case
     * @param string $data
     * @param string $expected
     */
    public function pbkdf2exceptionsTest22( $case, $algorithm, $data, $salt, $iterations, $keyLength ) {
        static $FMT  = '%s Error in case #%d';
        $result  = null;
        $outcome = true;
        try {
            $result = HashFactory::getHashPbkdf2( $algorithm, $data, $salt, $iterations, $keyLength );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertFalse( $outcome, sprintf( $FMT, HashFactory::getCm( __METHOD__ ), $case ));

    }
}
