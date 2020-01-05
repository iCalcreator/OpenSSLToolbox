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
 *   along with OpenSSLToolbox. If not, see <https://www.gnu.org/licenses/>. */
namespace Kigkonsult\OpenSSLToolbox\Traits;

use Exception;
use Kigkonsult\OpenSSLToolbox\OpenSSLFactory;

trait assertMdCipherAlgorithmTrait
{
    /**
     * assertMdAlgorithmTest1a dataProvider
     * @return array
     */
    public function assertMdAlgorithmTest1aProvider() {
        $dataArr = [];

        $hashAlgorithms = OpenSSLFactory::getAvailableDigestMethods( true );
        sort( $hashAlgorithms );
        $case = 100;
        foreach( $hashAlgorithms as $hashAlgorithm ) {
            $dataArr[] =
                [
                    ++$case,
                    $hashAlgorithm,
                    true
                ];
        }

        $dataArr[] =
            [
                199,
                'noAlgorithm',
                false
            ];

        //      sort( $hashAlgorithms );
        //      echo 'openssl_get_md_methods: ' . implode( ',', $hashAlgorithms ) . PHP_EOL;

        return $dataArr;
    }

    /**
     ** Testing OpenSSLBaseFactory::assertMdAlgorithm
     *          BaseFactory::baseAssertAlgorithm
     *
     * @test
     * @dataProvider assertMdAlgorithmTest1aProvider
     * @param int    $case
     * @param string $algorithm
     * @param string $expected
     */
    public function assertMdAlgorithmTest1a( $case, $algorithm, $expected ) {
        static $FMT = '%s Error in case #%d, algorithm: %s, result: %s';

        $result  = null;
        $outcome = true;
        try {
            $result = OpenSSLFactory::assertMdAlgorithm( $algorithm );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals(
            $expected,
            $outcome,
            sprintf( $FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-1', $algorithm, $result )
        );
        if( $expected ) {
            $this->assertEquals(
                strtolower( $algorithm ),
                strtolower( $result ),
                sprintf( $FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-2', $algorithm, $result )
            );
        }
    }

    /**
     * assertCipherAlgorithmTest1b dataProvider
     * @return array
     */
    public function assertCipherAlgorithmTest1bProvider() {
        $dataArr = [];
        $cipherAlgorithms = OpenSSLFactory::getAvailableCipherMethods(true );
        sort( $cipherAlgorithms );
        $case = 200;

        foreach( $cipherAlgorithms as $cipherAlgorithm ) {
            $dataArr[] =
                [
                    ++$case,
                    $cipherAlgorithm,
                    true
                ];
        }

        $dataArr[] =
            [
                299,
                'noAlgorithm',
                false
            ];

        return $dataArr;
    }

    /**
     ** Testing OpenSSLBaseFactory::assertCipherAlgorithm
     *          BaseFactory::baseAssertAlgorithm
     *
     * @test
     * @dataProvider assertCipherAlgorithmTest1bProvider
     * @param int    $case
     * @param string $algorithm
     * @param string $expected
     */
        public function assertCipherAlgorithmTest1b( $case, $algorithm, $expected ) {
        static $FMT1 = '%s Error in case #%d, expected: %s, actual: %s';

        $result  = null;
        $outcome = true;
        try {
            $result = OpenSSLFactory::assertCipherAlgorithm( $algorithm );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals(
            $expected,
            $outcome,
            sprintf( $FMT1, OpenSSLFactory::getCm( __METHOD__ ), $case . '-1', $algorithm, $result )
        );
        if( $expected ) {
            $this->assertEquals(
                strtolower( $algorithm ),
                strtolower( $result ),
                sprintf( $FMT1, OpenSSLFactory::getCm( __METHOD__ ), $case . '-2', $algorithm, $result )
            );
        }
    }

}
