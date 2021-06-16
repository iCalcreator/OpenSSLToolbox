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

/**
 * Class OpenSSLCsrFactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLCsrFactory
 *
 * csrFactoryTest11*
 *   OpenSSLPkeyFactory - property getter/setter methods
 *
 * crsNewTest12*
 *   OpenSSLCsrFactory  exceptions
 *
 * csrResourceTest21
 *   OpenSSLCsrFactory::getCsrResource
 *   OpenSSLCsrFactory::setCsrResource
 *
 * csrX509Test22
 *   OpenSSLCsrFactory::factory
 *   OpenSSLCsrFactory::csrNew
 *   OpenSSLCsrFactory::getPublicKeyAsResource
 *   OpenSSLCsrFactory::getDNfromCsrResource
 *   OpenSSLCsrFactory::getCSRasPemString
 *   OpenSSLCsrFactory::saveCSRcertIntoPemFile
 *   OpenSSLCsrFactory::getX509CertResource
 *
 * csrX509Test24 (Traits\CsrX509Trait)
 *   OpenSSLCsrFactory::factory
 *   OpenSSLCsrFactory::csrNew
 *   OpenSSLCsrFactory::getX509CertResource
 */
class OpenSSLCsrFactoryTest extends OpenSSLTest
{

    protected static $FMT   = '%s Error in case #%s, %s';
    protected static $FILES = [];

    /**
     * Testing OpenSSLPkeyFactory - DN
     *
     * @test
     */
    public function csrFactoryTest11a() {
        $DN = self::getDN();
        $csrFactory = OpenSSLCsrFactory::factory()->setDn( $DN );
        $this->assertEquals(
            $DN,
            $csrFactory->getDn(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, null )
        );
        $flipDn     = array_flip( $DN );
        $firstKey   = reset( $flipDn );
        $firstValue = reset( $DN );
        $this->assertEquals(
            $firstValue,
            $csrFactory->getDn( $firstKey ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 2, null )
        );
        $this->assertTrue(
            $csrFactory->isDnSet( $firstKey ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 2, null )
        );
        $this->assertTrue(
            $csrFactory->isDnSet(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 5, null )
        );

    }

    /**
     * Testing OpenSSLCsrFactory - private key
     *
     * @test
     */
    public function csrFactoryTest11b() {

        /* Create private key sources */
        $pKeyFactory        = OpenSSLPkeyFactory::factory()->pKeyNew();
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString();
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // get private key as file1/2
        $privateKeyFile1    = self::getFileName( __FUNCTION__ . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile1 );
        $privateKeyFile2    = 'file://' . $privateKeyFile1;
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => $privateKeyString,
            'privFile1' => $privateKeyFile1,
            'privFile2' => $privateKeyFile2
        ];
        foreach( $privateSources as $x => $privateSource ) {

            $csrFactory = OpenSSLCsrFactory::factory( null, $privateSource );

            $this->assertTrue(
                $csrFactory->isPrivateKeySet(),
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, $x )
            );
            $this->assertEquals(
                ( 'privFile1' == $x ) ? 'file://' . $privateSource : $privateSource,
                $csrFactory->getPrivateKey(),
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 2, $x )
            );
        }
        unlink( $privateKeyFile1 );
    }

    /**
     * Testing OpenSSLCsrFactory - extraAttribs
     *
     * @test
     */
    public function csrFactoryTest11d() {
        $extraAttribs  = [
            'key1' => 'value1',
            'key2' => 'value2'
        ];
        $extraAttribs2 = [
            'keyA' => 'valueA',
            'keyB' => 'valueB'
        ];
        $csrFactory = OpenSSLCsrFactory::factory( null, null, null, $extraAttribs  );

        $this->assertEquals(
            $extraAttribs,
            $csrFactory->getExtraAttribs(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertEquals(
            'value2',
            $csrFactory->getExtraAttribs( 'key2' ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 2, null )
        );
        $this->assertNull(
            $csrFactory->getExtraAttribs( 'key3' ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 3, null )
        );
        $this->assertEquals(
            $extraAttribs2,
            $csrFactory->getExtraAttribs( $extraAttribs2 ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 4, null )
        );

        $this->assertTrue(
            $csrFactory->isExtraAttribsSet(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 5, null )
        );
        $this->assertTrue(
            $csrFactory->isExtraAttribsSet( 'key1' ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 6, null )
        );
        $this->assertFalse(
            $csrFactory->isExtraAttribsSet( 'key7' ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 7, null )
        );

    }

    /**
     * Testing OpenSSLCsrFactory::creNew - catch exception
     *
     * @test
     */
    public function crsNewTest12a() {
        try {
            OpenSSLCsrFactory::factory()->csrNew( [ 'grodan' => 'boll' ] );
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory::getPublicKeyAsResource - catch exception
     *
     * @test
     */
    public function getPublicKeyAsResourceTest12b() {
        try {
            OpenSSLCsrFactory::factory()->getPublicKeyAsResource();
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory::getDNfromCsrResource - catch exception
     *
     * @test
     */
    public function getDNfromCsrResourceTest12c() {
        try {
            OpenSSLCsrFactory::factory()->getDNfromCsrResource();
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory::getCSRasPemString - catch exception
     *
     * @test
     */
    public function getCSRasStringTest12d() {
        try {
            OpenSSLCsrFactory::factory()->getCSRasPemString();
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory::saveCSRcertIntoPemFile - catch exception
     *
     * @test
     */
    public function saveCSRcertIntoFileTest12e() {
        try {
            OpenSSLCsrFactory::factory()->saveCSRcertIntoPemFile( 'fakeFileName' );
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory::csrNew - catch exception
     *
     * @test
     */
    public function csrNewTest112f() {
        try {
            OpenSSLCsrFactory::factory()->csrNew();
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory::csrNew - catch exception §
     *
     * @test
     */
    public function csrNewTest12g() {
        try {
            OpenSSLCsrFactory::factory( self::getDN() )->csrNew();
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory::getX509CertResource - catch exception
     *
     * @test
     */
    public function getX509CertResourceTest12h() {
        try {
            OpenSSLCsrFactory::factory()->getX509CertResource( 'fakeCaCert');
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     * Testing OpenSSLCsrFactory csrResource; create, set, get
     *                           getCsrResource, setCsrResource
     *
     * @test
     */
    public function csrResourceTest21() {
        $pKeyFactory0    = OpenSSLPkeyFactory::factory()->pKeyNew();
        $privateKey0     = $pKeyFactory0->getPrivateKeyAsPemString();
        $privateResource = $pKeyFactory0->getPrivateKeyAsResource();

        $csrFactory1     = OpenSSLCsrFactory::factory( self::getDN(), $privateKey0 );
        $csrResource1    = $csrFactory1->getCsrResource();
        $this->assertTrue(
            ( is_resource( $csrResource1 ) &&
                ( OpenSSLCsrFactory::CSRRESOURCETYPE == get_resource_type( $csrResource1 ))),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, null )
        );

        $csrFactory2     = new OpenSSLCsrFactory();
        try {
            $csrFactory2->setCsrResource( $privateResource );
        }
        catch( exception $e ) {
            $this->assertFalse( // expected result, wrong resource type
                false,
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }

        $csrFactory2->setCsrResource( $csrResource1 );
        $csrResource2    = $csrFactory2->getCsrResource();
        $this->assertTrue(
            ( is_resource( $csrResource2 ) &&
                ( OpenSSLCsrFactory::CSRRESOURCETYPE == get_resource_type( $csrResource2 ))),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 2, null )
        );
    }

    /**
     * csrX509Test22 dataProvider
     * @return array
     */
    public function csrX509Test22Provider() {

        $dataArr   = [];
        $case      = 1000;
        /*
        $dataArr[] = [
            $case++,
            null
        ];

        $digestMethods  = OpenSSLFactory::$SIGNATUREALGOS;
        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false );
        //      $digestMethods += OpenSSLFactory::getAvailableDigestMethods( true );
        $bitsCnts       = [ 384, 512, 1024, 2048, 4096 ];
        foreach( $digestMethods as $digestMethod ) {
            $config = [ OpenSSLPkeyFactory::DIGESTALGO => $digestMethod ];
            if( in_array( $digestMethod, [ 5, 'DSA', 'dsaEncryption', 'dsaWithSHA', 'ecdsa-with-SHA1' ] )) {
                $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE] = OPENSSL_KEYTYPE_DSA;   // 5='OPENSSL_ALGO_DSS1'
            }
            else {
                $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE] = OPENSSL_KEYTYPE_RSA;
            }
            foreach( $bitsCnts as $bits ) {
                $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] = $bits;
                $dataArr[] = [
                    $case++,
                    $config,
                ];
            } // end foreach
        } // end foreach
        */
        $dataArr[] = [
            1001,
            [
                OpenSSLPkeyFactory::DIGESTALGO     => "sha512",
                OpenSSLPkeyFactory::PRIVATEKEYBITS => 384, // 512, 1024, 2048, 4096
                OpenSSLPkeyFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
            ]
        ];
        return $dataArr;

    }

    /**
     * Using provider (with sets of digest method and bits) to load
     * OpenSSLPkeyFactory  factory, __construct, pKeyNew
     *                     getPrivateKeyAsResource, getPrivateKeyAsPemString, savePrivateKeyIntoPemFile
     * for tests in self::csrFactoryTester22(),
     * i.e. init OpenSSLCsrFactory with all kinds of private key sources
     *
     * @see https://www.php.net/manual/en/function.openssl-pkey-new.php#120814
     * @test
     * @dataProvider csrX509Test22Provider
     * @param int    $case
     * @param array  $config
     */
    public function csrX509Test22( $case, $config = null) {
        $doEcho = false;
        switch( true ) {
            case empty( $config ) :
                $msg2 = ' keyType: --- ';
                break;
            case ( OPENSSL_KEYTYPE_DSA == $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE] ) :
                $msg2 = ' keyType: DSA';
                break;
            default :
                $msg2 = ' keyType: RSA';
                break;
        }
        $msg2 .=
            ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . ( isset( $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] ) ? $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] : ' ---' );
        switch( true ) {
            case ( 'dsaWithSHA' == $config[OpenSSLPkeyFactory::DIGESTALGO] ) :
                $this->assertFalse( false );   // error:0D0C50A1:asn1 encoding routines:ASN1_item_verify:unknown message digest algorithm
                if( $doEcho ) echo OpenSSLCsrFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . ' - skip1' . PHP_EOL;
                return;
                break;
            case ( 'ecdsa-with-SHA1' == $config[OpenSSLPkeyFactory::DIGESTALGO] ) :
                $this->assertFalse( false );   // error:0A07806A:dsa routines:PKEY_DSA_CTRL:invalid digest type
                if( $doEcho ) echo OpenSSLCsrFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . ' - skip2' . PHP_EOL;
                return;
                break;
            case ( 'whirlpool' == $config[OpenSSLPkeyFactory::DIGESTALGO] ) :
                $this->assertFalse( false );   // 384+512 - error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                //         - error:0D0C50C7:asn1 encoding routines:ASN1_item_verify:unknown signature algorithm
                if( $doEcho ) echo OpenSSLCsrFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . ' - skip3' . PHP_EOL;
                return;
                break;
            case ( in_array( $config[OpenSSLPkeyFactory::DIGESTALGO], [ 'md4', 'md5', 'sha' ] )) :
                $this->assertFalse( false );   // error:0D0C50A1:asn1 encoding routines:ASN1_item_verify:unknown message digest algorithm
                if( $doEcho ) echo OpenSSLCsrFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . ' - skip4' . PHP_EOL;
                return;
                break;
            case ( 384 == $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] ) :
                if( in_array( $config[OpenSSLPkeyFactory::DIGESTALGO], [
                    1, 2, 3, 6, 7, 8, 9, 10,  // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                    'dsaWithSHA',             // error:0D0C50A1:asn1 encoding routines:ASN1_item_verify:unknown message digest algorithm
                    'sha224',                 // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                    'sha256',                 // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                    'sha384',                 // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                    'sha512'                  // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                ] )) {
                    if( $doEcho ) echo OpenSSLCsrFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . ' - skip5' . PHP_EOL;
                    $this->assertFalse( false );  //
                    return;
                }
                break;
            case ( 512 == $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] ) :
                if( in_array( $config[OpenSSLPkeyFactory::DIGESTALGO], [
                    'sha384',                 // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                    'sha512'                  // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                ] )) {
                    if( $doEcho ) echo OpenSSLCsrFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . ' - skip6' . PHP_EOL;
                    $this->assertFalse( false );  //
                    return;
                }
                break;
        }
        if( $doEcho ) echo OpenSSLCsrFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . PHP_EOL;

        $pKeyFactory  = OpenSSLPkeyFactory::factory()->pKeyNew( $config );

        // 1a - test with private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        $this->csrFactoryTester22( $case . '-11', $privateKeyResource, $config, $msg2 );

        // 1b - test with private key as resource and passPhrase
        $passPhrase   = 'passPhrase1b';
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource( $passPhrase );
        $privateKeyId = [ $privateKeyResource, $passPhrase ];
        $this->csrFactoryTester22( $case . '-12', $privateKeyId, $config, $msg2 );

        // 2a - test with private key as PEM string
        $privateKey   = $pKeyFactory->getPrivateKeyAsPemString();
        $this->csrFactoryTester22( $case . '-21', $privateKey, $config, $msg2 );

        // 2b - test with private key as PEM string and passPhrase
        $passPhrase   = 'passPhrase2b';
        $privateKey   = $pKeyFactory->getPrivateKeyAsPemString( $passPhrase );
        $privateKeyId = [ $privateKey, $passPhrase ];
        $this->csrFactoryTester22( $case . '-22', $privateKeyId, $config, $msg2 );

        // 3a - test with private key as file
        $privateKeyFile = self::getFileName( __FUNCTION__ . $case . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile );
        $this->csrFactoryTester22( $case . '-31', 'file://' . $privateKeyFile, $config, $msg2 );
        unlink( $privateKeyFile );

        // 3b - test with private key as file and passPhrase
        $privateKeyFile = self::getFileName( __FUNCTION__ .'-3' );
        $passPhrase   = 'passPhrase3b';
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile, $passPhrase );
        $privateKeyId = [ 'file://' . $privateKeyFile, $passPhrase ];
        $this->csrFactoryTester22( $case . '-31', $privateKeyId, $config, $msg2 );
        unlink( $privateKeyFile );

    }

    /**
     * testing OpenSSLCsrFactory  factory   different privateKey sources
     *                            csrNew
     *                            getPublicKeyAsResource
     *                            getDNfromCsrResource
     *                            getCSRasPemString
     *                            saveCSRcertIntoPemFile
     *                            getX509CertResource
     *
     * @param string           $case
     * @param string|array|resource  $privateKeySource
     * @param array            $config
     * @param string           $msg2
     */
    public function csrFactoryTester22( $case, $privateKeySource, $config, $msg2 ) {

        $DN = self::getDN();
        $csrFactory = OpenSSLCsrFactory::factory()->csrNew( $DN, $privateKeySource, $config );

        /* test resource */
        $publicKeyResource = $csrFactory->getPublicKeyAsResource();
        $this->assertTrue(
            is_resource( $publicKeyResource ) &&
            ( OpenSSLPkeyFactory::PKEYRESOURCETYPE == get_resource_type( $publicKeyResource )),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-11', $msg2 )
        );

        /* test DN */
        $subjects = $csrFactory->getDNfromCsrResource( false );
        //   echo $case . ' ' . var_export( $subjects, true ) . PHP_EOL . PHP_EOL; // test ###
        foreach( $DN as $key => $value ) {
            $this->assertTrue(
                isset( $subjects[$key] ),
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-12 ' . $key, $msg2 )
            );
            $this->assertEquals(
                $value,
                $subjects[$key],
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-13 ' . $key, $msg2 )
            );
        }

        /* test pem string, note, type is used below, der-tests */
        $pemString = $csrFactory->getCSRasPemString();
        $this->assertTrue(
            OpenSSLCsrFactory::isPemString( $pemString, $type ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-14', $msg2 )
        );
        /* test der string */
        $derString = $csrFactory->getCSRasDerString();
        $this->assertTrue(
            OpenSSLCsrFactory::isPemString( OpenSSLCsrFactory::der2Pem( $derString, $type, PHP_EOL )),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-14', $msg2 )
        );

        /* test pem file */
        $tmpFile1      = self::getFileName( __FUNCTION__ . $case . '-151' );
        Workshop::saveDataToFile( $tmpFile1, $pemString );
        $tmpFile2      = self::getFileName( __FUNCTION__ . $case . '-152' );
        $csrFactory->saveCSRcertIntoPemFile( $tmpFile2 );
        $this->assertNotEmpty( Workshop::getFileContent( $tmpFile2 )); // test ###
        $this->assertFileEquals(
            $tmpFile1,
            $tmpFile2,
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-15', $msg2 )
        );
        unlink( $tmpFile1 );
        unlink( $tmpFile2 );

        /* test der file */
        $tmpFile3      = self::getFileName( __FUNCTION__ . $case . '-153', 'der' );
        Workshop::saveDataToFile( $tmpFile3, $derString );
        $tmpFile4      = self::getFileName( __FUNCTION__ . $case . '-154' );
        OpenSSLCsrFactory::derFile2PemFile( $tmpFile3, $tmpFile4, $type, PHP_EOL );

        $tmpFile5      = self::getFileName( __FUNCTION__ . $case . '-155' );
        $csrFactory->saveCSRcertIntoDerFile( $tmpFile5 );
        $tmpFile6      = self::getFileName( __FUNCTION__ . $case . '-156', 'der' );
        OpenSSLCsrFactory::derFile2PemFile( $tmpFile5, $tmpFile6, $type, PHP_EOL );

        $this->assertFileEquals(
            $tmpFile4,
            $tmpFile6,
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-16', $msg2 )
        );
        unlink( $tmpFile3 );
        unlink( $tmpFile4 );
        unlink( $tmpFile5 );
        unlink( $tmpFile6 );

        /* test x509resource */
        $x509CertResource = $csrFactory->getX509CertResource( null, $privateKeySource, 365, $config );
        $this->assertTrue(
            ( is_resource( $x509CertResource ) &&
                ( OpenSSLX509Factory::X509RESOURCETYPE == get_resource_type( $x509CertResource ))),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case . '-17', $msg2 )
        );

    }

    use Traits\CsrX509Trait;

}
