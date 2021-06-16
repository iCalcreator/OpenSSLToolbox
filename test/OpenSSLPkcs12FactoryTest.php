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
use Kigkonsult\LoggerDepot\LoggerDepot;
use Throwable;

/**
 * Class OpenSSLPkcs12FactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLPkcs12Factory
 *
 * pkcs12Test1*
 *   OpenSSLPkcs12Factory::factory
 *   OpenSSLPkcs12Factory::setX509
 *   OpenSSLPkcs12Factory::setPrivateKey
 *   OpenSSLPkcs12Factory::setPkcs12PassWord
 *   OpenSSLPkcs12Factory::getPkcs12PassWord
 *   OpenSSLPkcs12Factory::getPkcs12
 *   OpenSSLPkcs12Factory::saveCertificateStoreIntoFile
 *   OpenSSLPkcs12Factory::read
 *   OpenSSLPkcs12Factory::getCertificateStoreAsArray
 *   OpenSSLPkcs12Factory::getCertificates
 *   OpenSSLPkcs12Factory::getKeys
 *
 * pkcs12Test3*
 *   OpenSSLPkcs12Factory  exceptions
 *
 * pkcs12Test35
 *   OpenSSLPkcs12Factory::setArgs
 *   OpenSSLPkcs12Factory::getArgs
 */
class OpenSSLPkcs12FactoryTest extends OpenSSLTest
{
    protected static $FILES = [];

    /**
     * Testing OpenSSLPkcs12Factory - __factory. __construct, export - without passPhrase for privateKey and pkcs12
     *
     * @see https://knowledge.digicert.com/generalinformation/INFO4131.html
     *  Generating PKCS12 Certificate using x509
     *    Save Private Key in a file (cert-privkey.crt)
     *    Save x509 Cert in a file (cert-pickup.crt)
     *    Run Below command to generate PKCS12 Certificate (certificate.pfx)
     *      openssl pkcs12 -export -out certificate.pfx -inkey cert-privkey.crt -in cert-pickup.crt
     * @see https://hotexamples.com/examples/-/-/openssl_pkcs12_export_to_file/php-openssl_pkcs12_export_to_file-function-examples.html
     * @test
     */
    public function pkcs12Test11() {

        /* privateKey without password */
        $pKeyFactory1        = OpenSSLPkeyFactory::factory()->pKeyNew();
        // get private key as PEM-string
        $privateKeyString1   = $pKeyFactory1->getPrivateKeyAsPemString();
        // get private key as resource
        $privateKeyResource1 = $pKeyFactory1->getPrivateKeyAsResource();
        // get private key as file11/12
        $privateKeyFile11    = self::getFileName( __FUNCTION__ . '-11' );
        $pKeyFactory1->savePrivateKeyIntoPemFile( $privateKeyFile11 );
        $privateKeyFile12    = 'file://' . $privateKeyFile11;
        $privateKeysArr      = [
            'privStr'   => $privateKeyString1,
            'privRsc'   => $privateKeyResource1,
            'privFile1' => $privateKeyFile11,
            'privFile2' => $privateKeyFile12
        ];

        /* x509 cert without password */
        $CsrFactory1         = OpenSSLCsrFactory::factory( self::getDN(), $privateKeyString1 );
        $x509Factory1        = OpenSSLX509Factory::factory();
        $x509Factory1->setX509Resource( $CsrFactory1->getX509CertResource( null,  $privateKeyString1 ));
        // get x509 key as PEM-string
        $x509String1         = $x509Factory1->getX509CertAsPemString();
        // get x509 key as resource
        $x509Resource1       = $x509Factory1->getX509Resource();
        // get private key as file13/14
        $x509File13          = self::getFileName( __FUNCTION__ . '-13' );
        $x509Factory1->saveX509CertIntoPemFile( $x509File13 );
        $x509File14          = 'file://' . $x509File13;
        $x509Arr             = [
            'x509Str'   => $x509String1,
            'x509Rsc'   => $x509Resource1,
            'x509File1' => $x509File13,
            'x509File2' => $x509File14
        ];

        $logger = LoggerDepot::getLogger( get_class());

        $caseNo = 100;
        foreach( $x509Arr as $i1 => $x509Source ) {
            foreach( $privateKeysArr as $i2 => $privateSource ) {
                foreach( [ null, Workshop::getSalt() ] as $pkcs12Password ) {
                    $case  = ++$caseNo . ', without passPhrase for ' . $i1 . '/' . $i2;
                    $case .= ( empty( $pkcs12Password )) ? ' and no for pkcs12' : ' and password for pkcs12';
                    $logger->info( ' ----- START ----- ' . $case . ' -----' );
                    $this->pkcs12Tester1x( $case, $x509Source, $privateSource, null, $pkcs12Password, $i1 . $i2 );
                } // end foreach
            } // end foreach
        } // end foreach
        unlink( $privateKeyFile11 );
        unlink( $x509File13 );
    }

    /**
     ** Testing OpenSSLPkcs12Factory - __factory. __construct, export - with passPhrase for privateKey and without/with for pkcs12
     *
     * @see https://knowledge.digicert.com/generalinformation/INFO4131.html
     *  Generating PKCS12 Certificate using x509
     *    Save Private Key in a file (cert-privkey.crt)
     *    Save x509 Cert in a file (cert-pickup.crt)
     *    Run Below command to generate PKCS12 Certificate (certificate.pfx)
     *      openssl pkcs12 -export -out certificate.pfx -inkey cert-privkey.crt -in cert-pickup.crt
     * @see https://hotexamples.com/examples/-/-/openssl_pkcs12_export_to_file/php-openssl_pkcs12_export_to_file-function-examples.html
     * @test
     */
    public function pkcs12Test12() {

        /* privateKey with password */
        $pKeyFactory2        = OpenSSLPkeyFactory::factory()->pKeyNew();
        // get private key as PEM-string
        $passPhrase2         = Workshop::getSalt();
        $privateKeyString2   = $pKeyFactory2->getPrivateKeyAsPemString( $passPhrase2 );
        // get private key as resource
        $privateKeyResource2 = $pKeyFactory2->getPrivateKeyAsResource( $passPhrase2 );
        // get private key as file21/22
        $privateKeyFile21    = self::getFileName( __FUNCTION__ . '-21' );
        $pKeyFactory2->savePrivateKeyIntoPemFile( $privateKeyFile21 );
        $privateKeyFile22    = 'file://' . $privateKeyFile21;
        $privateKeysPwArr    = [
            'privStr'   => $privateKeyString2,
            'privRsc'   => $privateKeyResource2,
            'privFile1' => $privateKeyFile21,
            'privFile2' => $privateKeyFile22
        ];

        /* x509 cert with passWord */
        $privateKeyId2       = [ $privateKeyString2, $passPhrase2 ];
        $CsrFactory2         = OpenSSLCsrFactory::factory( self::getDN(), $privateKeyId2 );
        $x509Factory2        = OpenSSLX509Factory::factory()->setX509Resource( $CsrFactory2->getX509CertResource( null, $privateKeyId2 ));
        // get x509 key as PEM-string
        $x509String2         = $x509Factory2->getX509CertAsPemString();
        // get x509 key as resource
        $x509Resource2       = $x509Factory2->getX509Resource();
        // get private key as file23/24
        $x509File23          = self::getFileName( __FUNCTION__ . '-23' );
        $x509Factory2->saveX509CertIntoPemFile( $x509File23 );
        $x509File24          = 'file://' . $x509File23;
        $x509PwArr           = [
            'x509Str'   => $x509String2,
            'x509Rsc'   => $x509Resource2,
            'x509File1' => $x509File23,
            'x509File2' => $x509File24
        ];

        $logger = LoggerDepot::getLogger( get_class());

        $caseNo = 200;
        foreach( $x509PwArr as $i1 => $x509Source ) {
            foreach( $privateKeysPwArr as $i2 => $privateSource ) {
                foreach( [ null, Workshop::getSalt() ] as $pkcs12Password ) {
                    $case  = ++$caseNo . ', with passPhrase for ' . $i1 . '/' . $i2;
                    $case .= ( empty( $pkcs12Password )) ? ' and no for pkcs12' : ' and password for pkcs12';
                    $logger->info( ' ----- START ----- ' . $case . ' -----' );
                    $this->pkcs12Tester1x( $case, $x509Source, $privateSource, $passPhrase2, $pkcs12Password, $i1 . $i2 );
                }
            } // end foreach
        } // end foreach
        unlink( $privateKeyFile21 );
        unlink( $x509File23 );
    }

    /**
     */
    public function pkcs12Tester1x( $case, $x509Source, $privateSource, $passPhrase2, $pkcs12Password, $fileSuffix ) {
        $doEcho = false;
        /*
        if( OpenSSLPkcs12Factory::isPemString( $privateSource )) {
            echo $case . ', key : ' . substr( $privateSource, 0, 27 ) . PHP_EOL; // test ###
        }
        */
        try {
            $pkcs12Factory1 = OpenSSLPkcs12Factory::factory( $x509Source, [ $privateSource, $passPhrase2 ], $pkcs12Password );
            $this->assertTrue(
                $pkcs12Factory1->isX509Set(),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 11, $case )
            );
            $this->assertTrue(
                (( ! empty($pkcs12Password )) == $pkcs12Factory1->isPkcs12passWordSet()),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 12, $case )
            );
            $this->assertTrue(
                $pkcs12Factory1->isPrivateKeySet(),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 13, $case )
            );
            $this->assertFalse(
                $pkcs12Factory1->isArgsSet(),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 14, $case )
            );
            $this->assertTrue(
                $pkcs12Factory1->isPkcs12Set(),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 15, $case )
            );
            $pkcs12Factory1 = null;

            // testing one-liner
            $pkcs12        = OpenSSLPkcs12Factory::factory( $x509Source, [ $privateSource, $passPhrase2 ], $pkcs12Password )
                                                 ->getPkcs12();
            $this->assertTrue(
                ( is_string( $pkcs12 ) && ! empty( $pkcs12 )),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 16, $case )
            );

            // testing setters
            $pkcs12Factory2 = new OpenSSLPkcs12Factory();
            $pkcs12Factory2->setX509( $x509Source );
            $pkcs12Factory2->setPrivateKey( ( empty( $passPhrase2 ) ? $privateSource : [ $privateSource, $passPhrase2 ] ));
            if( ! empty( $pkcs12Password )) {
                $pkcs12Factory2->setPkcs12PassWord( $pkcs12Password );
            }
            $pkcs12        = $pkcs12Factory2->getPkcs12();
            $this->assertTrue(
                ( is_string( $pkcs12 ) && ! empty( $pkcs12 )),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 16, $case )
            );

            // testing save to file
            $pkcs12File   = self::getFileName( __FUNCTION__ . '-' . $fileSuffix );
            $pkcs12Factory2->saveCertificateStoreIntoFile( $pkcs12File );
            $pkcs12String = Workshop::getFileContent( $pkcs12File );

            $this->assertTrue(
                ( is_string( $pkcs12String ) && ! empty( $pkcs12String )),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 21, $case )
            );
            $pkcs12_2     = $pkcs12Factory2->getPkcs12();
            $pkcs12_pw    = $pkcs12Factory2->getPkcs12PassWord();
            $pkcs12Factory2 = null;


            $this->assertTrue(
                is_array( OpenSSLPkcs12Factory::read( 'file://' . $pkcs12File, $pkcs12_pw )),
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 27, $case )
            );

            unlink( $pkcs12File );

            // testing set (string) pkcs12 (+password) and extract (read) array certs and private key
            $pkcs12Factory3 = new OpenSSLPkcs12Factory();
            $pkcs12Factory3->setPkcs12( $pkcs12_2, $pkcs12_pw );

            foreach( $pkcs12Factory3->getCertificateStoreAsArray() as $x => $value ) {
                $this->assertTrue(
                    OpenSSLFactory::isPemString( $value ),
                    sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 31 . $x, $case )
                );
                // echo ' pkcs12 part #' . $x . ' : ' . substr( $value, 0, 25 ) . '...' . PHP_EOL; // test ###
            }
            // testing get certificates from pkcs12 certificate store
            if( OpenSSLPkcs12Factory::isPemString( $x509Source )) {
                $this->assertEquals(
                    $x509Source,
                    $pkcs12Factory3->getCertificates()[0],
                    sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 32, $case )
                );
            }
            $pkcs12Factory2 = null;

            // testing set (string) pkcs12 (+password) and extract array certs
            if( OpenSSLPkcs12Factory::isPemString( $x509Source )) {
                $this->assertEquals(
                    $x509Source,
                    $pkcs12Factory3->getCertificates()[0],
                    sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 4, $case )
                );
            }

            // testing set (string) pkcs12 (+password) and extract array (private) keys
            foreach( $pkcs12Factory3->getKeys() as $x => $key ) {
                // echo 5 . ' found private key : #' . $x . ', ' . substr( $key, 0, 64 ) . PHP_EOL;
                $this->assertTrue(
                    OpenSSLPkcs12Factory::isPemString( $key ),
                    sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), '5-' . $x, $case )
                );
                $this->assertEquals(
                    '-----BEGIN PRIVATE KEY-----',
                    substr( $key, 0, 27 ),
                    sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), '6-' . $x, $case )
                );
                if( OpenSSLPkcs12Factory::isPemString( $privateSource )) {
                    if( empty( $passPhrase2 ) ) {
                        // foreach( $keys as $key ) {  }
                        $this->assertEquals(
                            $privateSource,
                            $key,
                            sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), '6-' . $x, $case )
                        );
                    }
                }
            } // end foreach
            if( $doEcho ) echo OpenSSLPkcs12Factory::getCm( __METHOD__ ) . ' ' . $case . PHP_EOL;
        }
        catch( Exception $e ) {
            $msg = sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), 8, $case . PHP_EOL . self::getExceptionmessageAndTrace( $e ));
            $this->assertFalse(false, $msg );
        }
    }

    /**
     * pkcs12Test31 provider
     */
    public function pkcs12Test3xProvider() {

            $dataArr = [];
            $case    = 0;

            $dataArr[] = [
            ++$case,
            null,
            null,
            null,
            null
        ];

        $passPhrase   = Workshop::getSalt();
        $privateKey   = OpenSSLPkeyFactory::factory()->pKeyNew()->getPrivateKeyAsPemString( $passPhrase );
        $privateKeyId = [ $privateKey, $passPhrase ];
        $x509Resource = OpenSSLCsrFactory::factory( self::getDN(), $privateKeyId )->getX509CertResource( null );
        $dataArr[]    = [
            ++$case,
            $x509Resource,
            null,
            null,
            null
        ];

        $passPhrase   = Workshop::getSalt();
        $privateKey   = OpenSSLPkeyFactory::factory()->pKeyNew()->getPrivateKeyAsPemString( $passPhrase );
        $privateKeyId = [ $privateKey, $passPhrase ];
        $x509Resource = OpenSSLCsrFactory::factory( self::getDN(), $privateKeyId )->getX509CertResource( null );
        $dataArr[]    = [
            ++$case,
            null,
            $privateKeyId,
            null,
            null,
            false
        ];

        $passPhrase   = Workshop::getSalt();
        $privateKey   = OpenSSLPkeyFactory::factory()->pKeyNew()->getPrivateKeyAsPemString( $passPhrase );
        $privateKeyId = [ $privateKey, $passPhrase ];
        $x509Resource = OpenSSLCsrFactory::factory( self::getDN(), $privateKeyId )->getX509CertResource( null );
        $dataArr[]    = [
            ++$case,
            $x509Resource,
            $privateKeyId,
            null,
            null,
            false
        ];

        return $dataArr;
    }

    /**
     ** Testing OpenSSLPkcs12Factory - catch exceptions
     *
     * @test
     * @dataProvider pkcs12Test3xProvider
     * @param int                   $case
     * @param resource|string       $x509
     * @param resource|string|array $privateKey
     * @param string                $pkcs12passWord
     * @param array                 $args
     */
    public function pkcs12Test31( $case, $x509 , $privateKey, $pkcs12passWord, $args = null ) {
        $case += 500;
        // echo OpenSSLPkcs12Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;

        try {
            $pkcs12Factory = OpenSSLPkcs12Factory::factory( $x509 , $privateKey, $pkcs12passWord, $args );
            $pkcs12        = $pkcs12Factory->getPkcs12();
            $pkcs12Factory = null;

            $pkcs12Factory = OpenSSLPkcs12Factory::factory()->getCertificateStoreAsArray();
        }
        catch( Exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), $case . '-1',  self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     ** Testing OpenSSLPkcs12Factory - catch exceptions
     *
     * @test
     * @dataProvider pkcs12Test3xProvider
     * @param int                   $case
     * @param resource|string       $x509
     * @param resource|string|array $privateKey
     * @param string                $pkcs12passWord
     * @param array                 $args
     */
    public function pkcs12Test32( $case, $x509 , $privateKey, $pkcs12passWord, $args = null ) {
        $case += 600;
        // echo OpenSSLPkcs12Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $privateKey = null;
        $pkcs12File = self::getFileName( __FUNCTION__ . '-' . $case );
        try {
            $pkcs12Factory = OpenSSLPkcs12Factory::factory( $x509 , $privateKey, $pkcs12passWord, $args )
                                                 ->saveCertificateStoreIntoFile( $pkcs12File );
        }
        catch( Exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), $case . '-1', self::getExceptionmessageAndTrace( $e ))
            );
        }
        finally {
            unlink( $pkcs12File );
        }
    }

    /**
     ** Testing OpenSSLPkcs12Factory - catch exception
     *
     * @test
     */
    public function pkcs12Test33() {
        $case = 701;
        // echo OpenSSLPkcs12Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;

        try {
            $pkcs12Factory = OpenSSLPkcs12Factory::factory();
            $pkcs12Factory->setPkcs12PassWord( null );
        }
        catch( Throwable $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), $case . '-1', self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

    /**
     ** Testing OpenSSLPkcs12Factory - setArgs
     *
     * @test
     */
    public function pkcs12Test35() {
        $case = 901;
        // echo OpenSSLPkcs12Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;

        $args = [
            OpenSSLPkcs12Factory::EXTRACERTS    => OpenSSLPkcs12Factory::EXTRACERTS, // todo assert (array) string/file
            OpenSSLPkcs12Factory::FRIENDLYNAMES => OpenSSLPkcs12Factory::FRIENDLYNAMES
        ];
        $pkcs12Factory = OpenSSLPkcs12Factory::factory( null, null, null, $args );
        $this->assertEquals(
            $args,
            $pkcs12Factory->getArgs(),
            sprintf( self::$FMT, OpenSSLPkcs12Factory::getCm( __METHOD__ ), $case, null )
        );
    }

}

