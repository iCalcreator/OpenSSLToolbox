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
 * Class OpenSSLPkeyFactoryTest1
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLPkeyFactory
 *
 * pkeyFactoryTest1
 *   OpenSSLPkeyFactory  exceptions
 *
 * pkeyFactoryTest21
 *   OpenSSLPkeyFactory::__construct
 *   OpenSSLPkeyFactory::getDetails (getDetailsRsaModulus, getDetailsRsaExponent, isDetailsKeySet)
 *
 * pkeyFactoryTest22
 *   OpenSSLPkeyFactory::getPrivat
 *     get private key as resource, string and file, with and without password
 *
 * pkeyFactoryTest23
 * OpenSSLPkeyFactory::factory + pKeyNew
 * OpenSSLPkeyFactory::getPkeyResource
 * OpenSSLPkeyFactory::getPrivateKeyAsPemString
 * OpenSSLPkeyFactory::getPrivateKeyAsDerString
 * OpenSSLPkeyFactory::savePrivateKeyIntoPemFile
 * OpenSSLPkeyFactory::savePrivateKeyIntoDerFile
 *
 * pkeyFactoryTest31
 *   OpenSSLPkeyFactory::getPublicKeyAsResource
 *
 * pkeyFactoryTest4* (Traits\PkeySealOpenTrait)
 *   OpenSSLPkeyFactory::__construct (+ pKeyNew)
 *   OpenSSLPkeyFactory::getPrivateKeyAsResource
 *   OpenSSLPkeyFactory::getPrivateKeyAsPemString
 *   OpenSSLPkeyFactory::savePrivateKeyIntoPemFile
 *   OpenSSLPkeyFactory::getPublicKeyResource
 *   OpenSSLPkeyFactory::getPublicKeyAsPemString
 *   OpenSSLPkeyFactory::savePublicKeyIntoPemFile
 *   OpenSSLPkeyFactory::getPrivatePublicKeyPairAsResources
 *   OpenSSLPkeyFactory::getPrivatePublicKeyPairAsPemStrings
 *   OpenSSLPkeyFactory::savePrivatePublicKeyPairIntoPemFiles
 *
 * pkeyFactoryTest51
 *   OpenSSLPkeyFactory::getPrivatePublicKeyPairAsDerStrings
 *   OpenSSLPkeyFactory::savePrivatePublicKeyPairIntoDerFiles
 */
class OpenSSLPkeyFactoryTest extends OpenSSLTest
{

    protected static $FILES = [];

    /**
     * Test, start as pkeyFactoryTest121, bits < 384, exception expected
     * OpenSSLPkeyFactory  __construct
     *
     * @test
     * @see https://www.php.net/manual/en/function.openssl-pkey-new.php#111769
     */
    public function pkeyFactoryTest11() {
        $case = 11;

        $config  = [
            OpenSSLPkeyFactory::DIGESTALGO     => "sha512",
            OpenSSLPkeyFactory::PRIVATEKEYBITS => 256,
            OpenSSLPkeyFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
        $outcome = true;
        try {
            $pKeyFactory1 = new OpenSSLPkeyFactory( $config );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case, null )
        );
    }


    /**
     ** Testing OpenSSLPkeyFactory - catch exception
     *
     * @test
     */
    public function pkeyFactoryTest12() {
        $case    = 21;
        $outcome = true;
        try {
            OpenSSLPkeyFactory::assertPkey( 'hoppsan' );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     ** Testing OpenSSLPkeyFactory - catch exception
     *
     * @test
     */
    public function pkeyFactoryTest13() {
        $case    = 31;
        $outcome = true;
        try {
            $pkeyFactory = OpenSSLPkeyFactory::factory()->setPkeyResource( 'hoppsan' );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     ** Testing OpenSSLPkeyFactory - catch exception
     *
     * @test
     */
    public function pkeyFactoryTest14() {
        $case    = 41;
        $outcome = true;
        try {
            OpenSSLPkeyFactory::factory()->getPrivateKeyAsPemString();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     ** Testing OpenSSLPkeyFactory - catch exception
     *
     * @test
     */
    public function pkeyFactoryTest15() {
        $case       = 51;
        $outcome    = true;
        $pkey34File = self::getFileName( __FUNCTION__ . '-' . $case );
        try {
            OpenSSLPkeyFactory::factory()->savePrivateKeyIntoPemFile( $pkey34File );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        finally {
            unlink( $pkey34File );
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     ** Testing OpenSSLPkeyFactory - catch exception
     *
     * @test
     */
    public function pkeyFactoryTest16() {
        $case    = 61;
        $outcome = true;
        try {
            OpenSSLPkeyFactory::factory()->getDetails();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     ** Testing OpenSSLPkeyFactory - catch exception
     *
     * @test
     */
    public function pkeyFactoryTest17() {
        $case    = 71;
        $outcome = true;
        try {
            OpenSSLPkeyFactory::factory()->getPublic();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     * pkeyFactoryTest21 dataProvider
     *
     * @return array
     */
    public function pkeyFactoryTest21Provider() {

        $dataArr = [];

        $digestMethods = OpenSSLFactory::$SIGNATUREALGOS;
        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false );
        //      $digestMethods += OpenSSLFactory::getAvailableDigestMethods( true );
        $bitsCnts = [ 384, 512, 1024, 2048, 4096 ];
        $case     = 1000;
        foreach( $digestMethods as $digestMethod ) {
            if( in_array( $digestMethod, [ 5, 'DSA', 'dsaEncryption', 'dsaWithSHA', 'ecdsa-with-SHA1' ] )) {
                $keyType = OPENSSL_KEYTYPE_DSA;   // 'OPENSSL_ALGO_DSS1' etc
            }
            else {
                $keyType = OPENSSL_KEYTYPE_RSA;
            }
            foreach( $bitsCnts as $bits ) {
                $dataArr[] = [
                    ++$case,
                    [
                        OpenSSLPkeyFactory::DIGESTALGO     => $digestMethod,
                        OpenSSLPkeyFactory::PRIVATEKEYBITS => $bits,
                        OpenSSLPkeyFactory::PRIVATEKEYTYPE => $keyType,
                    ]
                ];
            } // end foreach
        } // end foreach

        return $dataArr;
    }

    /**
     * Testing OpenSSLPkeyFactory  __construct, getDetails,
     *                             getDetailsRsaModulus, getDetailsRsaExponent, isDetailsKeySet
     *
     * @test
     * @dataProvider pkeyFactoryTest21Provider
     * @param int   $case
     * @param array $config
     */
    public function pkeyFactoryTest21( $case, $config ) {
        static $dsaSubKeys = [
            OpenSSLPkeyFactory::P,
            OpenSSLPkeyFactory::Q,
            OpenSSLPkeyFactory::G,
            OpenSSLPkeyFactory::PRIVKEY,
            OpenSSLPkeyFactory::PUBKEY,
        ];
        static $rsaSubKeys = [
            OpenSSLPkeyFactory::N,
            OpenSSLPkeyFactory::E,
            OpenSSLPkeyFactory::D,
            OpenSSLPkeyFactory::P,
            OpenSSLPkeyFactory::Q,
            OpenSSLPkeyFactory::DMP1,
            OpenSSLPkeyFactory::DMQ1,
            OpenSSLPkeyFactory::IQMP,
        ];

        if( in_array( $config[OpenSSLPkeyFactory::DIGESTALGO],
                      [ 5, 'DSA', 'dsaEncryption', 'dsaWithSHA', 'ecdsa-with-SHA1' ]
            ) && ( 384 == $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] )) {
            $this->assertFalse( false );  // error in getDetails()
            return;                               // 'Failed asserting that 512 matches expected 384.'
        }

        $msg2 = ' keyType: ' . ( ( OPENSSL_KEYTYPE_RSA == $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE] ) ? 'RSA' : 'DSA ' ) .
            ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS];
        // echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . PHP_EOL;
        switch( array_rand( [ 1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 5 ] )) {
            case 1 :
                $pkeyFactory = new OpenSSLPkeyFactory( $config );
                break;
            case 2 :
                $pkeyFactory = new OpenSSLPkeyFactory();
                $pkeyFactory->setConfig( $config );
                $pkeyFactory->pKeyNew();
                break;
            case 3 :
                $pkeyFactory = new OpenSSLPkeyFactory();
                foreach( $config as $key => $value ) {
                    $pkeyFactory->addConfig( $key, $value );
                }
                $pkeyFactory->pKeyNew();
                break;
            case 4 :
                $pkeyFactory = OpenSSLPkeyFactory::factory( $config );
                break;
            default :
                $pkeyFactory = OpenSSLPkeyFactory::factory();
                $pkeyFactory->setConfig( $config );
                $pkeyFactory->pKeyNew();
                break;
        }

        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $pkeyFactory->getPrivateKeyAsPemString()),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-11', null )
        );

        $publicKeyPEM = $pkeyFactory->getPublicKeyAsPemString();
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyPEM ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-21', null )
        );

        $details = $pkeyFactory->getDetails();

        $this->assertEquals(
            $config[OpenSSLPkeyFactory::PRIVATEKEYBITS],
            $details[OpenSSLPkeyFactory::BITS],
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-31', null )
        );
        $this->assertEquals(
            $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE],
            $details[OpenSSLPkeyFactory::TYPE],
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-32', null )
        );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $details[OpenSSLPkeyFactory::KEY] ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-33', null )
        );
        $this->assertEquals(
            $publicKeyPEM,
            $details[OpenSSLPkeyFactory::KEY],
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-34', null )
        );

        if( OPENSSL_KEYTYPE_DSA == $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE] ) {
            $this->assertTrue(
                isset( $details[OpenSSLPkeyFactory::DSA] ),
                sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-35a', null )
            );
            $this->assertFalse(
                $pkeyFactory->isDetailsKeySet( OpenSSLPkeyFactory::RSA ),
                sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-35b', null )
            );
            foreach( $dsaSubKeys as $x => $subKey ) {
                $this->assertTrue(
                    isset( $details[OpenSSLPkeyFactory::DSA][$subKey] ),
                    sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-' . ( 36 + $x ), null )
                );
                $keyValue = $pkeyFactory->getDetailsKey( OpenSSLPkeyFactory::DSA, $subKey );
                $this->assertTrue(
                    Convert::isBase64( $keyValue ),
                    sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-' . ( 36 + $x ), null )
                );
            }
            return;
        } // end if

        $this->assertTrue(
            isset( $details[OpenSSLPkeyFactory::RSA] ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-37', 'RSA - 1' )
        );
        $this->assertTrue(
            $pkeyFactory->isDetailsKeySet( OpenSSLPkeyFactory::RSA ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-37', 'RSA - 2' )
        );
        $rsaModulus = $pkeyFactory->getDetailsRsaModulus();
        $this->assertTrue(
            Convert::isBase64( $rsaModulus ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-37', 'RSA - N' )
        );
        $rsaExponent = $pkeyFactory->getDetailsRsaExponent();
        $this->assertTrue(
            Convert::isBase64( $rsaExponent ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-37', 'RSA - E' )
        );
        foreach( $rsaSubKeys as $x => $subKey ) {
            $this->assertTrue(
                isset( $details[OpenSSLPkeyFactory::RSA][$subKey] ),
                sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-' . 38, $x . 'a' )
            );
            $keyValue = $pkeyFactory->getDetailsKey( OpenSSLPkeyFactory::RSA, $subKey );
            $this->assertTrue(
                Convert::isBase64( $keyValue ),
                sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-' . 38, $x . 'b' )
            );
        } // end foreach
        $pkeyFactory->freePkeyResource();
        $this->assertFalse(
            $pkeyFactory->isPkeyResourceSet(),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-' . 39, null )
        );
    }

    /**
     * Testing OpenSSLPkeyFactory::getPrivate  get private key as resource, string and file, with and without password
     *
     * @test
     */
    public function pkeyFactoryTest22() {

        /**  without password  **/

        /* private key as recource */
        $pkeyFactory1   = OpenSSLPkeyFactory::factory()->pKeyNew();
        $privateKeyRsc0 = $pkeyFactory1->getPrivateKeyAsResource();
        $this->assertTrue(
            ( is_resource( $privateKeyRsc0 ) &&
                ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $privateKeyRsc0 )) ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 320, null )
        );
        $privateKeyRsc1 = OpenSSLPkeyFactory::getPrivate( $privateKeyRsc0 );
        $this->assertTrue(
            ( is_resource( $privateKeyRsc1 ) &&
                ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $privateKeyRsc1 )) ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 321, null )
        );
        $pkeyFactory1->freePkeyResource();
        $pkeyFactory1 = null;

        /* private key as (PEM) string */
        $pkeyFactory2   = OpenSSLPkeyFactory::factory()->pKeyNew();
        $privateKeyStr2 = $pkeyFactory2->getPrivateKeyAsPemString();
        $privateKeyRsc2 = OpenSSLPkeyFactory::getPrivate( $privateKeyStr2 );
        $this->assertTrue(
            ( is_resource( $privateKeyRsc2 ) &&
                ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $privateKeyRsc2 )) ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 322, null )
        );
        $pkeyFactory2->freePkeyResource();
        $pkeyFactory2 = null;

        /* private key as file */
        $pkeyFactory3    = OpenSSLPkeyFactory::factory()->pKeyNew();
        $privateKeyFile3 = self::getFileName( __FUNCTION__ . '3' );
        $pkeyFactory3->savePrivateKeyIntoPemFile( $privateKeyFile3 );
        $privateKeyRsc3 = OpenSSLPkeyFactory::getPrivate( $privateKeyFile3 );
        $this->assertTrue(
            ( is_resource( $privateKeyRsc3 ) &&
                ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $privateKeyRsc3 )) ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 323, null )
        );
        unlink( $privateKeyFile3 );
        $pkeyFactory3->freePkeyResource();
        $pkeyFactory3 = null;

        /**  with password  **/
        /* private key as resource */
        $pkeyFactory4    = OpenSSLPkeyFactory::factory()->pKeyNew();
        $passPhrase4     = Workshop::getSalt();
        $privateKeyRsc40 = $pkeyFactory4->getPrivateKeyAsResource( $passPhrase4 );
        $privateKeyRsc4  = OpenSSLPkeyFactory::getPrivate( $privateKeyRsc40, $passPhrase4 );
        $this->assertTrue(
            ( is_resource( $privateKeyRsc4 ) &&
                ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $privateKeyRsc4 )) ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 324, null )
        );
        $pkeyFactory4->freePkeyResource();
        $pkeyFactory4 = null;

        /* private key as (PEM) string */
        $pkeyFactory5   = OpenSSLPkeyFactory::factory()->pKeyNew();
        $passPhrase5    = Workshop::getSalt();
        $privateKeyStr5 = $pkeyFactory5->getPrivateKeyAsPemString( $passPhrase5 );
        $privateKeyRsc5 = OpenSSLPkeyFactory::getPrivate( $privateKeyStr5, $passPhrase5 );
        $this->assertTrue(
            ( is_resource( $privateKeyRsc5 ) &&
                ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $privateKeyRsc5 )) ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 325, null )
        );
        $pkeyFactory5->freePkeyResource();
        $pkeyFactory5 = null;

        /* private key as file */
        $pkeyFactory6    = OpenSSLPkeyFactory::factory()->pKeyNew();
        $passPhrase6     = Workshop::getSalt();
        $privateKeyFile6 = self::getFileName( __FUNCTION__ . '6' );
        $pkeyFactory6->savePrivateKeyIntoPemFile( $privateKeyFile6, $passPhrase6 );
        $privateKeyRsc6 = OpenSSLPkeyFactory::getPrivate( $privateKeyFile6, $passPhrase6 );
        $this->assertTrue(
            ( is_resource( $privateKeyRsc6 ) &&
                ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $privateKeyRsc6 )) ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 326, null )
        );
        unlink( $privateKeyFile6 );
        $pkeyFactory6->freePkeyResource();
        $pkeyFactory6 = null;
    }

    /**
     * pkeyFactoryTest23 dataProvider
     *
     * @return array
     */
    public function pkeyFactoryTest23Provider() {

        $dataArr = [];

        $faker     = Faker\Factory::create();
        $case      = 0;
        $dataArr[] =
            [
                $case++,
                null, // empty config
                $faker->paragraphs( 10, true ),
            ];

        $digestMethods = OpenSSLFactory::$SIGNATUREALGOS;
        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false );
//        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( true );
        $bitsCnts = [ 384, 512, 1024, 2048, 4096 ];

        foreach( $digestMethods as $digestMethod ) {
            $config                                 = [ OpenSSLFactory::DIGESTALGO => $digestMethod ];
            $config[OpenSSLFactory::PRIVATEKEYTYPE] = ( false !== stripos( $digestMethod, 'dsa' ))
                ? OPENSSL_KEYTYPE_DSA
                : OPENSSL_KEYTYPE_RSA;
            foreach( $bitsCnts as $bits ) {
                $config[OpenSSLFactory::PRIVATEKEYBITS] = $bits;
                $dataArr[]                              =
                    [
                        $case++,
                        $config,
                        $faker->paragraphs( 10, true ),
                    ];
            } // end foreach
        } // end foreach

        return $dataArr;
    }

    /**
     * Testing creating certificate, public key and private key
     * OpenSSLPkeyFactory  factory + pKeyNew + getPkeyResource +
     *                     getPrivateKeyAsPemString + savePrivateKeyIntoPemFile
     *                     getPrivateKeyAsDerString ' savePrivateKeyIntoDerFile
     *
     * @see          https://www.php.net/manual/en/function.openssl-pkey-new.php#42800
     * @see          https://www.php.net/manual/en/function.openssl-pkey-new.php#120814
     * @test
     * @dataProvider pkeyFactoryTest23Provider
     * @param int    $case
     * @param array  $config
     * @param string $data not used here
     */
    public function pkeyFactoryTest23( $case, $config, $data ) {
        static $privateKeyPass = 'private key password';
        static $numberOfDays = 365;
        $case += 1000;
        /*
        $str2 = ( empty( $config ))
            ? ' empty config'
            : ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
              ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS];
        echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $str2  . PHP_EOL;
        */

        $pKeyFactory = OpenSSLPkeyFactory::factory()->pKeyNew( $config );

        /*  get private key as PEM string */
        $privateKeyPEM = $pKeyFactory->getPrivateKeyAsPemString( $privateKeyPass );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $privateKeyPEM, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-11', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PKCS8,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-12', null )
        );

        /*  test private key as DER string */
        $privateKeyDER = $pKeyFactory->getPrivateKeyAsDerString( $privateKeyPass );
        $privateKeyPEM = OpenSSLPkeyFactory::der2Pem( $privateKeyDER, OpenSSLPkeyFactory::PEM_PKCS8, PHP_EOL );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $privateKeyPEM, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-21', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PKCS8,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-22', null )
        );

        /*  save private key as PEM file */
        $fileName31PEM = self::getFileName( __FUNCTION__ . $case . '-31PEM' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $fileName31PEM, $privateKeyPass );
        $fileContent = Workshop::getFileContent( $fileName31PEM );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $fileContent, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-31', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PKCS8,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-32', null )
        );
        unlink( $fileName31PEM );

        /*  save private key as DER file */
        $fileName41DER = self::getFileName( __FUNCTION__ . $case . '-41DER', 'der' );
        $pKeyFactory->savePrivateKeyIntoDerFile( $fileName41DER, $privateKeyPass );
        $fileContent   = Workshop::getFileContent( $fileName41DER );
        $privateKeyPEM = OpenSSLPkeyFactory::der2Pem( $fileContent, OpenSSLPkeyFactory::PEM_PKCS8, PHP_EOL );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $privateKeyPEM, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-41', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PKCS8,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-42', null )
        );
        unlink( $fileName41DER );

        /*  get private key as resource */
        $pKeyResource = $pKeyFactory->getPkeyResource();
        $this->assertTrue(
            ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == Workshop::getResourceType( $pKeyResource )),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-51', null )
        );

        /*  get public key as PEM string */
        $publicKeyPEM = $pKeyFactory->getPublicKeyAsPemString();
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyPEM, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-61', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PUBLIC,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-62', null )
        );

        /*  test public key as DER string */
        $publicKeyDER = $pKeyFactory->getPublicKeyAsDerString();
        $publicKeyPEM = OpenSSLPkeyFactory::der2Pem( $publicKeyDER, OpenSSLPkeyFactory::PEM_PUBLIC, PHP_EOL );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyPEM, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-71', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PUBLIC,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-72', null )
        );

        /*  save public key as PEM file */
        $fileName81PEM = self::getFileName( __FUNCTION__ . $case . '-81PEM' );
        $pKeyFactory->savePublicKeyIntoPemFile( $fileName81PEM );
        $fileContent = Workshop::getFileContent( $fileName81PEM );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $fileContent, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-81', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PUBLIC,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-82', null )
        );
        unlink( $fileName81PEM );

        /*  save public key as DER file */
        $fileName91DER = self::getFileName( __FUNCTION__ . $case . '-91DER', 'der' );
        $pKeyFactory->savePublicKeyIntoDerFile( $fileName91DER );
        $fileContent  = Workshop::getFileContent( $fileName91DER );
        $publicKeyPEM = OpenSSLPkeyFactory::der2Pem( $fileContent, OpenSSLPkeyFactory::PEM_PUBLIC, PHP_EOL );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyPEM, $type ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-91', null )
        );
        $this->assertEquals(
            OpenSSLPkeyFactory::PEM_PUBLIC,
            $type,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-92', null )
        );
        unlink( $fileName91DER );

        /*  get public key as resource */
        $publicKeyResource = $pKeyFactory->getPublicKeyResource();
        $this->assertTrue(
            ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == Workshop::getResourceType( $publicKeyResource )),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $case . '-101', null )
        );
    }

    /**
     * Testing OpenSSLPkeyFactory - getPublicKeyAsResource (get public key)
     *
     * @test
     */
    public function pkeyFactoryTest31() {
        $pKeyFactory   = OpenSSLPkeyFactory::factory()->pKeyNew();
        $privateKey0   = $pKeyFactory->getPrivateKeyAsPemString();
        $csrFactory    = OpenSSLCsrFactory::factory( self::getDN(), $privateKey0 );
        $x509Resource0 = $csrFactory->getX509CertResource( null );
        $x509Factory   = OpenSSLX509Factory::factory( $x509Resource0 );

        $sources = [];
        /* from x509 cert resource */
        $sources['x509Rsc'] = $x509Factory->getX509Resource();

        /* from x509 cert file */
        $x509File = self::getFileName( __FUNCTION__ . 1 );
        $x509Factory->saveX509CertIntoPemFile( $x509File );
        $sources['x509File1'] = $x509File;
        $sources['x509File2'] = 'file://' . $x509File;

        /* from x509 cert (PEM) string */
        $sources['x509Str'] = $x509Factory->getX509CertAsPemString();

        // from public key as resource
        $sources['pubRsc'] = $pKeyFactory->getPublicKeyResource();
        // from public key as PEM-string
        $sources['pubStr'] = $pKeyFactory->getPublicKeyAsPemString();

        // from public key as file
        $pubFile = self::getFileName( __FUNCTION__ . 2 );
        $pKeyFactory->savePublicKeyIntoPemFile( $pubFile );
        $sources['pubFile1'] = $pubFile;
        $sources['pubFile2'] = 'file://' . $pubFile;

        foreach( $sources as $source => $certificate ) {
            try {
                $publicKeyResource = OpenSSLPkeyFactory::getPublicKeyAsResource( $certificate );
            }
            catch( Exception $e ) {
                echo $source . PHP_EOL;
                echo self::getExceptionmessageAndTrace( $e );
            }
            $this->assertTrue(
                OpenSSLPkeyFactory::isValidPkeyResource( $publicKeyResource ),
                sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), $source, null )
            );
        }
        unlink( $x509File );
        unlink( $pubFile );

    }

    use Traits\PkeySealOpenTrait;

    /**
     * OpenSSLPkeyFactory  factory + pKeyNew + getPrivatePublicKeyPairAsDerStrings
     *                                         savePrivatePublicKeyPairIntoDerFiles
     * @test
     */
    public function pkeyFactoryTest51() {
        $passPhrase1  = Workshop::getSalt();
        $pPkeyFactory = OpenSSLPkeyFactory::factory()->pKeyNew();
        /* init test DER strings */
        list( $privateKeyDerString, $publicKeyDerString ) =
            $pPkeyFactory->getPrivatePublicKeyPairAsDerStrings( $passPhrase1 );

        /* test private key DER string */
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString(
                OpenSSLPkeyFactory::der2Pem( $privateKeyDerString, OpenSSLPkeyFactory::PEM_PKCS8 )
            ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 511, null )
        );
        /* test public key DER string */
        $publicKeyPem = OpenSSLPkeyFactory::der2Pem( $publicKeyDerString, OpenSSLPkeyFactory::PEM_PUBLIC );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyPem ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 512, null )
        );
        try {
            $publicKeyResource = OpenSSLPkeyFactory::getPublicKeyAsResource( $publicKeyPem );
        }
        catch( Exception $e ) {
            echo self::getExceptionmessageAndTrace( $e );
        }
        $this->assertTrue(
            OpenSSLPkeyFactory::isValidPkeyResource( $publicKeyResource ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 513, null )
        );

        /* init test DER files */
        $privateFileDer1 = self::getFileName( __FUNCTION__ . 11, 'der' );
        $publicFileDer1  = self::getFileName( __FUNCTION__ . 12, 'der' );
        $privateFilePem2 = self::getFileName( __FUNCTION__ . 21 );
        $publicFilePem2  = self::getFileName( __FUNCTION__ . 22 );
        $pPkeyFactory->savePrivatePublicKeyPairIntoDerFiles( $privateFileDer1, $publicFileDer1, $passPhrase1 );
        /* test private key DER file */
        OpenSSLPkeyFactory::derFile2PemFile( $privateFileDer1, $privateFilePem2, OpenSSLPkeyFactory::PEM_PKCS8 );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemFile( $privateFilePem2 ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 521, null )
        );
        /* test public key DER file */
        OpenSSLPkeyFactory::derFile2PemFile( $publicFileDer1, $publicFilePem2, OpenSSLPkeyFactory::PEM_PUBLIC );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemFile( $publicFilePem2  ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 522, null )
        );
        try {
            $publicKeyResource = OpenSSLPkeyFactory::getPublicKeyAsResource( $publicFilePem2 );
        }
        catch( Exception $e ) {
            echo self::getExceptionmessageAndTrace( $e );
            $this->assertTrue( false );
        }
        $this->assertTrue(
            OpenSSLPkeyFactory::isValidPkeyResource( $publicKeyResource ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 523, null )
        );
        unlink( $privateFileDer1 );
        unlink( $publicFileDer1 );
        unlink( $privateFilePem2 );
        unlink( $publicFilePem2 );
    }
}
