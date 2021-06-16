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
use Throwable;

/**
 * Class WorkshopTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\Workshop
 *
 * Testing Workshop
 *   saveDataToFileTest11
 *   saveDataToFile + Exception
 *
 *   getFileContentTest12
 *   getFileContent
 *
 * getNewFileInTmp18
 *   getNewFileInTmp
 *
 * testgetRandomPseudoBytes21
 *   getRandomPseudoBytes
 *
 * getSaltTest22
 *   getSalt
 *
 * getAlgorithmFromIdentifierTest23*
 *   getAlgorithmFromIdentifier
 */
class WorkshopTest extends BaseTest
{

    private   static $FMT   = '%s Error in case #%d';
    private   static $FMT2  = '%s Error in case #%d, expected %d, actual %d';
    protected static $FILES = [];

    /**
     ** Testing Workshop::saveDataToFile Exception
     *
     * @test
     */
    public function saveDataToFileTest11a() {
        $fileName  = self::getFileName( __FUNCTION__ . 1 );
        $outcome = true;
        try {
            Workshop::saveDataToFile( Workshop::$FILEPROTO . $fileName, 'data' );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertTrue( $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), 1, null ));
        unlink( $fileName );

        $outcome = true;
        try {
            Workshop::saveDataToFile( null, 'data' );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse( $outcome, sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), 2, null ));
    }

    /**
     ** Testing Workshop::saveDataToFile
     *
     * @test
     */
    public function saveDataToFileTest11b() {
        $fileName = self::getFileName( __FUNCTION__ . '11b.txt' );
        $resource = fopen( $fileName, 'w+' );

        Workshop::saveDataToFile( $resource, __FUNCTION__ );

        @fclose( $resource );
        $this->assertEquals(
            __FUNCTION__,
            Workshop::getFileContent( $fileName ),
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), '11b', null )
        );
        unlink( $fileName );
    }

    /**
     * getFileContentTest12 dataProvider
     * @return array
     */
    public function getFileContentTest12Provider() {
        $dataArr = [];

        $fileName = __FUNCTION__ . '402.txt'; // note extension...
        self::$FILES[] = $fileName;
        touch( $fileName );
        Workshop::saveDataToFile( $fileName, $fileName );
        chmod( $fileName, 0755 );
        $dataArr[] =
            [
                402,
                $fileName,
                $fileName,
                $fileName,
                true
            ];

        $fileName = __FUNCTION__ . '403.txt'; // note extension...
        self::$FILES[] = $fileName;
        touch( $fileName );
        Workshop::saveDataToFile( $fileName, $fileName );
        chmod( $fileName, 0755 );
        $dataArr[] =
            [
                403,
                Workshop::$FILEPROTO . $fileName,
                $fileName,
                $fileName,
                true
            ];

        $fileName = __FUNCTION__ . 'noFile404.txt';
        $dataArr[] =
            [
                404,
                $fileName,
                $fileName,
                null,
                false
            ];

        $fileName  = __FUNCTION__ . '421.txt'; // note extension...
        self::$FILES[] = $fileName;
        touch( $fileName );
        Workshop::saveDataToFile( $fileName, $fileName );
        chmod( $fileName, 0755 );
        $test      = fopen( $fileName, 'rb' );
        $dataArr[] =
            [
                421,
                $test, // stream resource, file handle
                $fileName,
                $fileName,
                true
            ];

        $fileName  = self::getFileName( __FUNCTION__ . 422 );
        touch( $fileName );
        Workshop::saveDataToFile( $fileName, $fileName );
        chmod( $fileName, 0755 );
        $test      = fopen( $fileName, 'rb' );
        $dataArr[] =
            [
                422,
                $test, // stream resource, read
                $fileName,
                $fileName,
                true
            ];

        $fileName = self::getFileName( __FUNCTION__ . 423 );
        touch( $fileName );
        Workshop::saveDataToFile( $fileName, '' );
        chmod( $fileName, 0755 );
        $test = fopen( $fileName, 'wb' );
        $dataArr[] =
            [
                423,
                $test, // stream resource, write
                $fileName,
                null,
                false
            ];

        $test      = OpenSSLPkeyFactory::factory( OpenSSLX509FactoryTest::$config )->getPkeyResource();
        $dataArr[] =
            [
                427,
                $test, // no (file) stream resource !!
                $fileName,
                null,
                false
            ];

        return $dataArr;
    }

    /**
     ** Testing Workshop::getFileContent
     *
     * @test
     * @dataProvider getFileContentTest12Provider
     * @param int    $case
     * @param string|resource $file
     * @param string $fileName
     * @param string $expectedData
     * @param string $expectedOutcome
     */
    public function getFileContentTest12( $case, $file, $fileName, $expectedData, $expectedOutcome ) {

        $outcome = true;
        try {
            $output = Workshop::getFileContent( $file );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        if( $outcome ) {
            $this->assertEquals(
                $expectedData,
                $output,
                sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . '-1', null )
            );
        }
        $mode = null;
        if( Workshop::isFileResource( $file )) {
            if( $expectedOutcome && Workshop::isResourceWritable( $file )) {
                Workshop::saveDataToFile( $file, $case );
            }
            $mode = var_export( Workshop::getResourceMetadata( $file ), true );
            @fclose( $file );
        }
        elseif( @is_file( $file )) {
            if( is_writeable( $file )) {
                Workshop::saveDataToFile( $file, $case );
            }
            $mode = substr( sprintf( '%o', fileperms( $file )), -4);
        }
        @unlink( $fileName );

        $this->assertEquals(
            $expectedOutcome,
            $outcome,
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . '-2', $mode )
        );
    }

    /**
     ** Testing Workshop::getNewFileInTmp
     *
     * @test
     */
    public function getNewFileInTmp18() {

        $file = Workshop::getNewFileInTmp( __FUNCTION__, 'txt', 0600 );

        $this->assertTrue(
            is_file( $file ),
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            is_readable( $file ),
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), 2, null )
        );
        $this->assertTrue(
            is_writable( $file ),
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), 2, null )
        );
        unlink( $file );
    }



    /** ***********************************************************************
     *  Misc
     ** ******************************************************************** */

    /**
     * getRandomPseudoBytes dataProvider
     * @return array
     */
    public function getRandomPseudoBytesProvider() {
        $dataArr = [];

        $dataArr[] =
            [
                201,
                32,
                32
            ];

        $dataArr[] =
            [
                202,
                64,
                64
            ];

        $dataArr[] =
            [
                203,
                128,
                128
            ];

        return $dataArr;
    }

    /**
     * Testing Workshop::getRandomPseudoBytes
     *
     * @test
     * @dataProvider getRandomPseudoBytesProvider
     * @param int   $case
     * @param mixed $byteCnt
     * @param int   $expected
     */
    public function testgetRandomPseudoBytes21( $case, $byteCnt, $expected ) {
        $result = Workshop::getRandomPseudoBytes( $byteCnt );
        $this->assertTrue(
            is_string( $result ),
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . 1 )
        );
        $this->assertTrue(
            ( $byteCnt == strlen( $result )),
            sprintf( self::$FMT2, Workshop::getCm( __METHOD__ ), $case . 2, $expected, strlen( $result ))
        );
    }

    /**
     * testgetSaltTest22 dataProvider
     * @return array
     */
    public function getSaltTest22Provider() {
        $dataArr = [];

        $dataArr[] =
            [
                311,
                null,
                64
            ];

        $dataArr[] =
            [
                312,
                64,
                64
            ];

        $dataArr[] =
            [
                313,
                128,
                128
            ];

        return $dataArr;
    }

    /**
     * Testing Workshop::getSalt
     *
     * @test
     * @dataProvider getSaltTest22Provider
     * @param int   $case
     * @param mixed $byteCnt
     * @param int   $expected
     */
    public function getSaltTest22( $case, $byteCnt, $expected ) {
        $result = Workshop::getSalt( $byteCnt );
        $this->assertTrue(
            is_string( $result ),
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . 1 )
        );
        $this->assertTrue(
            ( $expected == strlen( $result )),
            sprintf( self::$FMT2, Workshop::getCm( __METHOD__ ), $case . 2, $expected, strlen( $result ))
        );
        $this->assertTrue(
            Convert::isHex( $result ),
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), $case . 3 )
        );
    }

    /**
     * getAlgorithmFromIdentifierTest23a dataProvider
     * @return array
     */
    public function getAlgorithmFromIdentifierTest2xProvider() {
        $dataArr = [];

        $case = 200;
        foreach( [
                     'http://www.w3.org/2001/04/xmldsig-more#md5',
                     'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
                     'http://www.w3.org/2001/04/xmldsig-more#hmac-md5',
                     'http://www.w3.org/2001/04/xmldsig-more#rsa-md5',
                     'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
                     'http://www.w3.org/TR/2001/REC-xml-c14n-20010315/',
                     'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
                     'http://www.w3.org/2001/04/xmldsig-more#rawPKCS7signedData'
                 ] as $value ) {
            $dataArr[] = [
                ++$case,
                $value,
            ];

        }

        return $dataArr;
    }

    /**
     ** Testing Workshop::getAlgorithmFromIdentifier
     *
     * @test
     * @dataProvider getAlgorithmFromIdentifierTest2xProvider
     * @param int    $case
     * @param string $identifier
     */
    public function getAlgorithmFromIdentifierTest23a( $case, $identifier ) {
        static $FMT  = '%s Error in case #%d, identifier: %s, got %s';

        $result = Workshop::getAlgorithmFromIdentifier( $identifier );

        $resultLen = strlen( $result );
        $this->assertTrue(
            ( $result == substr( $identifier, ( 0 - $resultLen )) ||
                ( $result == substr( $identifier, ( -1 - $resultLen ), -1 ))
            ),
            sprintf( $FMT, Workshop::getCm( __METHOD__ ), $case, $identifier, $result )
        );
    }

    /**
     ** Testing Workshop::getAlgorithmFromIdentifier Exception
     *
     * @test
     */
    public function getAlgorithmFromIdentifierTest23b() {

        $outcome = true;
        try {
            $result = Workshop::getAlgorithmFromIdentifier( 'grodan boll' );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, Workshop::getCm( __METHOD__ ), 1, null )
        );
    }

}
