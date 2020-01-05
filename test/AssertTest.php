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

/**
 * Class AssertTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\Assert
 * 
 * Testing Assert
 *     bool
 *     int
 *     string
 *     fileName
 *     fileNameRead
 *     fileNameWrite
 */
class AssertTest extends BaseTest
{

    private   static $FMT   = '%s Error in case #%d';
    protected static $FILES = [];

    /**
     * assertBoolTest11 dataProvider - accepts true/false/1/0
     * @return array
     */
    public function assertBoolTest11Provider() {
        $dataArr = [];

        $dataArr[] =
            [
                101,
                true,
                null,
                true
            ];

        $dataArr[] =
            [
                102,
                false,
                null,
                true
            ];

        $dataArr[] =
            [
                103,
                1,
                null,
                true
            ];

        $dataArr[] =
            [
                104,
                0,
                null,
                true
            ];

        $dataArr[] =
            [
                105,
                null,
                true,
                true
            ];

        $dataArr[] =
            [
                106,
                null,
                false,
                true
            ];

        $dataArr[] =
            [
                107,
                'notBool',
                null,
                false
            ];

        $dataArr[] =
            [
                108,
                null,
                'notBool',
                true
            ];

        $dataArr[] =
            [
                109,
                null,
                null,
                true
            ];

        return $dataArr;
    }

    /**
     ** Testing Assert::bool
     *
     * @test
     * @dataProvider assertBoolTest11Provider
     * @param int    $case
     * @param string $data
     * @param mixed  $valueIfNull
     * @param string $expected
     */
    public function assertBoolTest11( $case, $data, $valueIfNull, $expected ) {

        $outcome = true;
        try {
            Assert::bool( $data, 1, $valueIfNull );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals( $expected, $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case, null ));
    }

    /**
     * assertIntTest12 dataProvider
     * @return array
     */
    public function assertIntTest12Provider() {
        $dataArr = [];

        $dataArr[] =
            [
                101,
                1,
                null,
                true
            ];

        $dataArr[] =
            [
                102,
                '1',
                null,
                true
            ];

        $dataArr[] =
            [
                103,
                '1A',
                null,
                false
            ];

        $dataArr[] =
            [
                104,
                'A',
                null,
                false
            ];

        $dataArr[] =
            [
                105,
                null,
                'notInt',
                true
            ];

        $dataArr[] =
            [
                106,
                null,
                null,
                true
            ];

        return $dataArr;
    }

    /**
     ** Testing Assert::int
     *
     * @test
     * @dataProvider assertIntTest12Provider
     * @param int    $case
     * @param mixed  $valueIfNull
     * @param string $data
     * @param string $expected
     */
    public function assertIntTest12( $case, $data, $valueIfNull, $expected ) {

        $outcome = true;
        try {
            Assert::int( $data, 1, $valueIfNull );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals( $expected, $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case, null ));
    }

    /**
     * assertStringTest13 dataProvider
     * @return array
     */
    public function assertStringTest13Provider() {
        $dataArr = [];

        $dataArr[] =
            [
                101,
                'string',
                null,
                true
            ];

        $dataArr[] =
            [
                102,
                [],
                null,
                false
            ];

        $dataArr[] =
            [
                103,
                null,
                'string',
                true
            ];

        $dataArr[] =
            [
                104,
                null,
                null,
                true
            ];

        return $dataArr;
    }

    /**
     ** Testing Assert::string
     *
     * @test
     * @dataProvider assertStringTest13Provider
     * @param int    $case
     * @param string $data
     * @param mixed  $valueIfNull
     * @param string $expected
     */
    public function assertStringTest13( $case, $data, $valueIfNull, $expected ) {

        $outcome = true;
        try {
            Assert::string( $data, null, $valueIfNull );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals( $expected, $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case, null ));
    }

    /**
     * assertFileNameTest14a dataProvider
     * @return array
     */
    public function assertFileNameTest14aProvider() {
        $dataArr = [];

        $fileName  = self::getFileName( __FUNCTION__ . 101 );
        $dataArr[] =
            [
                101,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = sys_get_temp_dir();
        $dataArr[] =
            [
                102,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = __FUNCTION__ . 103;
        self::$FILES[] = $fileName;
        touch( $fileName );
        $dataArr[] =
            [
                103,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = 'no' . DIRECTORY_SEPARATOR . 'file' . DIRECTORY_SEPARATOR . 'or' . DIRECTORY_SEPARATOR . 'dir';
        $dataArr[] =
            [
                104,
                $fileName,
                $fileName,
                false
            ];

        $fileName  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'no file';
        $dataArr[] =
            [
                105,
                $fileName,
                $fileName,
                true
            ];


        $fileName  = __FUNCTION__ . '121.txt';
        copy( __FILE__, $fileName );
        $test      = fopen( $fileName, 'rb' );
        $dataArr[] =
            [
                121,
                $test, // stream resource
                $fileName,
                true
            ];

        $test      = tmpfile();
        // https://www.php.net/manual/en/function.tmpfile.php#122678
        $fileName  = stream_get_meta_data( $test )['uri'];
        $dataArr[] =
            [
                122,
                $test, // stream resource
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 123);
        $test      = fopen( $fileName, 'wb' );
        $dataArr[] =
            [
                123,
                $test, // stream resource
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 125 );
        $test      = bzopen( $fileName, 'w' );
        $dataArr[] =
            [
                125,
                $test,
                $fileName,
                true
            ];

        return $dataArr;
    }

    /**
     ** Testing Assert::fileName
     *
     * @test
     * @dataProvider assertFileNameTest14aProvider
     * @param int    $case
     * @param string|resource $name
     * @param string $fileName
     * @param string $expected
     */
    public function assertFileNameTest14a( $case, $name, $fileName, $expected ) {

        $outcome = true;
        try {
            Assert::fileName( $name );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        if( is_resource( $name )) {
            if( true !== fclose( $name )) {
                bzclose( $name  );
            }
        }
        if( is_file( $fileName )) {
            @unlink( $fileName );
        }

        $this->assertEquals(
            $expected,
            $outcome,
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . '-1', null )
        );
    }

    /**
     ** Testing Assert::fileName - invalid resource
     *
     * @test
     */
    public function assertFileNameTest14b() {

        $outcome = true;
        try {
            Assert::fileName(
                OpenSSLPkeyFactory::factory( OpenSSLX509FactoryTest::$config )->getPkeyResource()
            );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals( false, $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), 1, null ));
    }

    /**
     * assertFileNameReadTest16 dataProvider
     * @return array
     */
    public function assertFileNameReadTest16Provider() {
        $dataArr = [];

        $fileName  = self::getFileName( __FUNCTION__ . 201 );
        $dataArr[] =
            [
                201,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 202 );
        $dataArr[] =
            [
                202,
                Workshop::$FILEPROTO . $fileName,
                $fileName,
                true
            ];

        $fileName  = 'no' . DIRECTORY_SEPARATOR . 'file' . DIRECTORY_SEPARATOR . 'or' . DIRECTORY_SEPARATOR . 'dir';
        $dataArr[] =
            [
                203,
                $fileName,
                $fileName,
                false
            ];

        $fileName = __FUNCTION__ . '204.txt'; // note extension...
        self::$FILES[] = $fileName;
        touch( $fileName );
        chmod( $fileName, 0755 );
        Workshop::saveDataToFile( $fileName, 'test' );
        $dataArr[] =
            [
                204,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = __FUNCTION__ . 'noFile205.txt'; // note extension...
        $dataArr[] =
            [
                205,
                $fileName,
                $fileName,
                false
            ];

        $fileName  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . __FUNCTION__ . 'noFile206.txt';
        $dataArr[] =
            [
                206,
                $fileName,
                $fileName,
                false
            ];

        $fileName  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . __FUNCTION__ . 'testDir207';
        self::$FILES[] = $fileName;
        @rmdir( $fileName );
        mkdir( $fileName, 0700 );
        $dataArr[] =
            [
                207,
                $fileName,
                $fileName,
                false
            ];

        $fileName = __FUNCTION__ . '221.txt';
        self::$FILES[] = $fileName;
        touch( $fileName );
        copy( __FILE__, $fileName );
        chmod( $fileName, 0755 );
        $test = fopen( $fileName, 'rb' );
        $dataArr[] =
            [
                221,
                $test, // stream resource, file handle
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 222 );
        $test      = fopen( $fileName, 'rb' );
        $dataArr[] =
            [
                222,
                $test, // stream resource
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 223 );
        $test      = fopen( $fileName, 'wb' );
        $dataArr[] =
            [
                223,
                $test, // stream resource
                $fileName,
                false
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 225 );
        $test      = bzopen( $fileName, 'r' );
        $dataArr[] =
            [
                225,
                $test, // no stream resource ??
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 225 );
        $test      = bzopen( $fileName, 'w' );
        $dataArr[] =
            [
                226,
                $test, // no stream resource ??
                $fileName,
                false
            ];

        $test      = OpenSSLPkeyFactory::factory( OpenSSLX509FactoryTest::$config )->getPkeyResource();
        $dataArr[] =
            [
                227,
                $test, // no stream resource !!
                $fileName,
                false
            ];

        return $dataArr;
    }

    /**
     ** Testing Assert::fileNameRead
     *
     * @test
     * @dataProvider assertFileNameReadTest16Provider
     * @param int    $case
     * @param string|resource $file
     * @param string $fileName
     * @param string $expected
     */
    public function assertFileNameReadTest16( $case, $file, $fileName, $expected ) {

        $outcome = true;
        try {
            Assert::fileNameRead( $file );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $mode = null;
        if( is_resource( $file ) && ( 'stream' == get_resource_type( $file ))) {
            $mode = var_export( Workshop::getResourceMetadata( $file ), true );
            if( true !== @fclose( $file )) {
                @bzclose( $file  );
            }
            @unlink( $fileName );
        }
        elseif( @is_dir( $fileName )) {
            $mode = substr( sprintf( '%o', fileperms( $fileName )), -4 );
            @rmdir( $fileName );
            @unlink( $fileName );
        }
        elseif( @is_file( $fileName )) {
            $mode = substr( sprintf( '%o', fileperms( $fileName )), -4 );
            @unlink( $fileName );
        }

        $this->assertEquals( $expected, $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . '-1', $mode ));
    }

    /**
     * assertFileNameWriteTest17 dataProvider
     * @return array
     */
    public function assertFileNameWriteTest17Provider() {
        $dataArr = [];

        $fileName  = self::getFileName( __FUNCTION__ . 301 );
        $dataArr[] =
            [
                301,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 302 );
        $dataArr[] =
            [
                302,
                Workshop::$FILEPROTO . $fileName,
                $fileName,
                true
            ];

        $fileName  = __FUNCTION__ . 'notExist303.file';
        $dataArr[] =
            [
                303,
                Workshop::$FILEPROTO . $fileName,
                $fileName,
                true
            ];

        $fileName  = 'no' . DIRECTORY_SEPARATOR . 'file' . DIRECTORY_SEPARATOR . 'or' . DIRECTORY_SEPARATOR . 'dir';
        $dataArr[] =
            [
                304,
                $fileName,
                $fileName,
                false
            ];

        $fileName  = __FUNCTION__ . '305.txt'; // note extension...
        self::$FILES[] = $fileName;
        touch( $fileName );
        chmod( $fileName, 0755 );
        Workshop::saveDataToFile( $fileName, 'test' );
        $dataArr[] =
            [
                305,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = __FUNCTION__ . 'noFile.txt'; // note extension...
        $dataArr[] =
            [
                306,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . __FUNCTION__ . 'noFile305.txt';
        $dataArr[] =
            [
                307,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'testDir306';
        self::$FILES[] = $fileName;
        @rmdir( $fileName );
        mkdir( $fileName, 0700 );
        $dataArr[] =
            [
                308,
                $fileName,
                $fileName,
                true
            ];

        $fileName  = __FUNCTION__ . '321.txt'; // note extension...
        self::$FILES[] = $fileName;
        touch( $fileName );
        copy( __FILE__, $fileName );
        chmod( $fileName, 0755 );
        $test      = fopen( $fileName, 'wb' );
        $dataArr[] =
            [
                321,
                $test, // stream resource, file handle
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 332 );
        $test      = fopen( $fileName, 'wb' );
        $dataArr[] =
            [
                322,
                $test, // stream resource
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 323 );
        $test      = fopen( $fileName, 'rb' );
        $dataArr[] =
            [
                323,
                $test, // stream resource
                $fileName,
                false
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 325 );
        $test      = bzopen( $fileName, 'w' );
        $dataArr[] =
            [
                325,
                $test, // no stream resource ??
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 325 );
        $test      = bzopen( $fileName, 'r' );
        $dataArr[] =
            [
                326,
                $test, // no stream resource ??
                $fileName,
                false
            ];

        $test      = OpenSSLPkeyFactory::factory( OpenSSLX509FactoryTest::$config )->getPkeyResource();
        $dataArr[] =
            [
                327,
                $test, // no stream resource !!
                $fileName,
                false
            ];

        return $dataArr;
    }

    /**
     ** Testing Assert::fileNameWrite
     *
     * @test
     * @dataProvider assertFileNameWriteTest17Provider
     * @param int    $case
     * @param string|resource $file
     * @param string $fileName
     * @param string $expected
     */
    public function assertFileNameWriteTest17( $case, $file, $fileName, $expected ) {

        $outcome = true;
        try {
            Assert::fileNameWrite( $file );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $mode = null;
        if( is_resource( $file ) && ( 'stream' == get_resource_type( $file ))) {
            $mode = var_export( Workshop::getResourceMetadata( $file ), true );
            if( true !== @fclose( $file )) {
                @bzclose( $file  );
            }
            @unlink( $fileName );
        }
        elseif( @is_dir( $fileName )) {
            $mode = substr( sprintf( '%o', fileperms( $fileName )), -4);
            @rmdir( $fileName );
            @unlink( $fileName );
        }
        elseif( @is_file( $fileName )) {
            $mode = substr( sprintf( '%o', fileperms( $fileName )), -4);
            @unlink( $fileName );
        }

        $this->assertEquals( $expected, $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . '-1', $mode ) );
    }

}
