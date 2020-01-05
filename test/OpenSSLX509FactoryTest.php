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
use Kigkonsult\LoggerDepot\LoggerDepot;
use Psr\Log\LogLevel;

/**
 * Class OpenSSLX509FactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLX509Factory
 *
 * certDataTest11
 *   OpenSSLX509Factory::__construct    certData sources
 *
 * csrFactoryTest12
 *   OpenSSLX509Factory::csrFactory (caCert)
 *     create x509 instance, set/create x509 resource from resource/file/string
 *
 * csrFactoryTest13
 *   set/create x509 resource from resource/file/string
 *
 * checkPrivateKeyTest24
 *   OpenSSLX509Factory::__construct
 *   OpenSSLX509Factory::read
 *   OpenSSLX509Factory::checkPrivateKey
 *
 * checkPurposeTest31
 *   OpenSSLX509Factory::checkPurpose
 *
 * exportTest32
 *   OpenSSLX509Factory::getX509CertAsPemString
 *    OpenSSLX509Factory::getX509CertAsDerString
 *
 * saveX509CertIntoFileTest33
 *   OpenSSLX509Factory::saveX509CertIntoPemFile
 *   OpenSSLX509Factory::saveX509CertIntoDerFile
 *
 * fingerprintTest34
 *   OpenSSLX509Factory::getDigestHash (fingerprint)
 *
 * parseTest35
 *   OpenSSLX509Factory::parse
 *
 * csrX509Test24  (Traits\CsrX509Trait)
 *   OpenSSLX509Factory::getCertInfo
 *   OpenSSLX509Factory::getCertName
 *   OpenSSLX509Factory::getCertSubjectDN
 *   OpenSSLX509Factory::getCertIssuerDN
 *
 * *Test4*  - Exception tests
 *
 */
class OpenSSLX509FactoryTest extends OpenSSLTest
{

    protected static $FILES = [];

    public static $config   = [
        OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
        OpenSSLFactory::PRIVATEKEYBITS => 4096,
        OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
    ];

    /**
     * certDataTest11
     * Testing OpenSSLX509Factory::__construct    certData sources
     *  1. An X.509 resource returned from openssl_x509_read()
     *  2. A string having the format (file://(path/to/cert.pem;
     *     the named file must contain a PEM encoded certificate
     *  3. A PEM encoded string containing the content of a certificate
     *
     * @test
     */
    public function certDataTest11() {
        /* private key without password */
        $pKeyFactory1      = new OpenSSLPkeyFactory( self::$config );
        $privateKey1       = $pKeyFactory1->getPrivateKeyAsPemString();
        // Generate a self-signed certificate signing request CSR
        $x509CertResource1 = OpenSSLCsrFactory::factory( self::getDN(), $privateKey1, self::$config )
                                             ->getX509CertResource( null, $privateKey1 ); // i.e. sign

        /* private key with password */
        $pKeyFactory2      = new OpenSSLPkeyFactory( self::$config );
        $passPhrase2       = Workshop::getSalt();
        $privateKey2       = $pKeyFactory2->getPrivateKeyAsPemString( $passPhrase2 );
        $privateKeyId2     = [ $privateKey2, $passPhrase2 ];
        // Generate a self-signed certificate signing request CSR
        $x509CertResource2 = OpenSSLCsrFactory::factory( self::getDN(), $privateKeyId2, self::$config )
                                             ->getX509CertResource( null, $privateKeyId2 ); // i.e. sign

        $case               = 110;
        foreach( [ $x509CertResource1, $x509CertResource2 ] as $x1 => $x509CertResource ) {
            $case          += $x1;
            $x509Factory0   = OpenSSLX509Factory::factory()->setX509Resource( $x509CertResource );
            $x509Resource   = $x509Factory0->getX509Resource();
            $x509CertString = $x509Factory0->getX509CertAsPemString();
            $x509CertFile1  = self::getFileName( __FUNCTION__ . $case );
            $x509Factory0->saveX509CertIntoPemFile( $x509CertFile1 );
            $x509CertFile2  = 'file://' . $x509CertFile1;

            $x509Sources = [
                'rcs'   => $x509Resource,
                'str'   => $x509CertString,
                'file1' => $x509CertFile1,
                'file2' => $x509CertFile2,
            ];
            foreach( $x509Sources as $x2 => $x509Source ) {
                $case         += $x2;
                $x509Factory1  = new OpenSSLX509Factory( $x509Source );
                $this->assertTrue(
                    $x509Factory1->isX509certDataSet(),
                    sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, 1 )
                );
                $x509Resource1 = $x509Factory1->getX509Resource();
                $this->assertTrue(
                    ( OpenSSLX509Factory::X509RESOURCETYPE == get_resource_type( $x509Resource1 )),
                    sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, 1 )
                );
                $certData1 = $x509Factory1->getX509certData();
                if( is_resource( $certData1 ) ) {
                    $this->assertTrue(
                        ( OpenSSLX509Factory::X509RESOURCETYPE == get_resource_type( $certData1 ) ),
                        sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, 2 )
                    );
                }
                else { // PEM or file
                    $this->assertTrue(
                        is_string( $certData1 ),
                        sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, 3 )
                    );
                }
                $x509Factory1->freeX509Resource();
                $this->assertFalse(
                    $x509Factory1->isX509ResourceSet(),
                    sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, 4 )
                );
                $x509Factory1->freeX509certData();
                $this->assertFalse(
                    $x509Factory1->isX509certDataSet(),
                    sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, 5 )
                );
                $x509Factory1 = null;
            } // end foreach
            if( is_file( $x509CertFile1 ) ) {
                unlink( $x509CertFile1 );
            }
        } // end foreach
    }

    /**
     * csrFactoryTest12
     * Testing OpenSSLX509Factory::csrFactory (caCert)
     *    create x509 instance, set/create x509 resource from resource/file/string
     *  1. An X.509 resource returned from openssl_x509_read()
     *  2. A string having the format (file://(path/to/cert.pem;
     *     the named file must contain a PEM encoded certificate
     *  3. A PEM encoded string containing the content of a certificate
     * @test
     */
    public function csrFactoryTest12() {

        $cases = [
            0 > 'rcs',
            1 => 'str',
            2 => 'file1',
            3 => 'file2',
        ];
        $x509CertFile1 = self::getFileName( __FUNCTION__ . '-1' );
        foreach( $cases as $x => $x509Type ) {
            $privateKey = OpenSSLPkeyFactory::factory( self::$config )->getPrivateKeyAsPemString();
            // Generate a self-signed certificate signing request CSR
            $x509Factory0 = OpenSSLX509Factory::csrfactory( null, self::getDN(), $privateKey, self::$config );

            switch( $x ) {
                case 0 :
                    $x509source = $x509Factory0->getX509Resource();
                    break;
                case 1 :
                    $x509source = $x509Factory0->getX509CertAsPemString();
                    break;
                case 1 :
                    $x509Factory0->saveX509CertIntoPemFile( $x509CertFile1 );
                    $x509source = $x509CertFile1;
                    break;
                default :
                    $x509Factory0->saveX509CertIntoPemFile( $x509CertFile1 );
                    $x509source = 'file://' . $x509CertFile1;
            }
            $case = 120 + $x;
            // Generate a NEW semi-signed certificate resource (based on $x509source, above)
            $x509Factory1 = OpenSSLX509Factory::csrfactory( $x509source, self::getDN(), $privateKey, self::$config );
            $this->assertTrue(
                ( OpenSSLX509Factory::X509RESOURCETYPE ==
                    get_resource_type( $x509Factory1->getX509Resource() )
                ),
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, 'resource exists' )
            );
        } // end foreach
        if( is_file( $x509CertFile1 ) ) {
            unlink( $x509CertFile1 );
        }
    }

    /**
     * csrFactoryTest13
     * Test set/create x509 resource from resource/file/string
     * setX509Resource, createX509ResourceFromFile, createX509ResourceFromString
     * Test export resource to new instance
     * isX509certDataSet, isX509ResourceSet, getX509Resource
     *
     * @test
     */
    public function csrFactoryTest13() {
        $privateKey = OpenSSLPkeyFactory::factory( self::$config )->getPrivateKeyAsPemString();
        // Generate a self-signed certificate signing request CSR
        $x509Factory0 = OpenSSLX509Factory::csrfactory( null, self::getDN(), $privateKey, self::$config );

        $x509Resource   = $x509Factory0->getX509Resource();
        $x509CertString = $x509Factory0->getX509CertAsPemString();
        $x509CertFile1  = self::getFileName( __FUNCTION__ . '-1' );
        $x509Factory0->saveX509CertIntoPemFile( $x509CertFile1 );
        $x509Sources = [
            'rcs'   => $x509Resource,
            'str'   => $x509CertString,
            'file1' => $x509CertFile1,
            'file2' => 'file://' . $x509CertFile1,
        ];
        $case        = 1301;
        foreach( $x509Sources as $x => $x509Source ) {
            $case += $x;
            // test create x509 instance, set/create x509 resource from resource/file/string
            $x509Factory2 = new OpenSSLX509Factory();
            if( is_resource( $x509Source )) {
                $x509Factory2->setX509Resource( $x509Source );
            }
            elseif( is_file( $x509Source )) {
                $x509Factory2->createX509ResourceFromFile( $x509Source );
            }
            else {
                $x509Factory2->createX509ResourceFromString( $x509Source );
            }
            $this->assertFalse(
                $x509Factory2->isX509certDataSet(),
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, '2 - no certData set' )
            );
            $this->assertTrue(
                $x509Factory2->isX509ResourceSet(),
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, '3 - x509 resource set' )
            );
            $this->assertTrue(
                ( OpenSSLX509Factory::X509RESOURCETYPE == get_resource_type( $x509Factory2->getX509Resource())),
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, '4 - x509 resource !!' )
            );

            // test export resource to new instance
            // $x509FactoryB = new OpenSSLX509Factory( $x509Factory->getX509Resource());       // same
            // $x509FactoryB = OpenSSLX509Factory::factory( $x509Factory->getX509Resource());  // same
            $x509Factory3 = new OpenSSLX509Factory();
            $x509Factory3->read( $x509Factory2->getX509Resource());                            // same
            $this->assertTrue(
                $x509Factory3->isX509ResourceSet(),
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, '5 - x509 resource is not set' )
            );
            $this->assertTrue(
                ( OpenSSLX509Factory::X509RESOURCETYPE == get_resource_type( $x509Factory3->getX509Resource())),
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, '6 - NOT x509 resource !!' )
            );
            $x509Factory2->freeX509Resource();  // NOTE, resources have NOT persistence, depend on origin
            $this->assertFalse(
                $x509Factory3->isX509ResourceSet(),
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, '7 - x509 resource is not set' )
            );
        }
        if( is_file( $x509CertFile1 )) {
            unlink( $x509CertFile1 );
        }
    }

    /**
     * link https://www.php.net/manual/en/function.openssl-csr-new.php
     * @param string $passPhrase
     * @return array
     */
    public static function getX509CertAndprivateKey( $passPhrase = null ) {

        $pKeyFactory        = new OpenSSLPkeyFactory( self::$config );
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString( $passPhrase );
        // Generate a self-signed certificate signing request CSR
        $privateKeyId       = ( empty( $passPhrase )) ? $privateKeyString : [ $privateKeyString, $passPhrase ];
        $x509CertString     = OpenSSLX509Factory::csrFactory(null, self::getDN(), $privateKeyId, self::$config  )
                                                ->getX509CertAsPemString();
        return [ $x509CertString, $privateKeyString ];
    }

    /**
     * checkPrivateKeyTest24
     * Testing OpenSSLX509Factory  __construct, read, checkPrivateKey
     *  testing private key as string
     *                         string + password
     *                         resource
     *                         resource + password
     *                         file
     *                         file + password
     *                         'file://' . file
     *                         'file://' . file + password
     * @test
     */
    public function checkPrivateKeyTest24() {
        $logger = LoggerDepot::getLogger( get_class() );
        $doEcho = false;
        /* private key as string */
        $case               = 1451;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $privateKey         = OpenSSLPkeyFactory::factory( self::$config )->getPrivateKeyAsPemString();
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $privateKey, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $privateKey ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );

        /* private key as string + password */
        $case               = 1452;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $passPhrase         = 'passPhrase' . $case;
        $privateKey         = OpenSSLPkeyFactory::factory( self::$config )->getPrivateKeyAsPemString( $passPhrase );
        $privateKeyId       = [ $privateKey, $passPhrase ];
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $privateKeyId, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $privateKey, $passPhrase ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );

        /* private key as resource */
        $case               = 1453;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $privateKeyResource = OpenSSLPkeyFactory::factory( self::$config )->getPkeyResource();
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $privateKeyResource, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $privateKeyResource ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );

        /* private key as resource + password */
        $case               = 1454;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $passPhrase         = 'passPhrase' . $case;
        $privateKeyResource = OpenSSLPkeyFactory::factory( self::$config )->getPkeyResource();
        $privateKeyId       = [ $privateKeyResource, $passPhrase ];
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $privateKeyId, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $privateKeyResource, $passPhrase ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );

        /* private key as file */
        $case       = 1455;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $keyFile1           = self::getFileName( __FUNCTION__ . $case );
        OpenSSLPkeyFactory::factory( self::$config )->savePrivateKeyIntoPemFile( $keyFile1 );
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $keyFile1, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $keyFile1 ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );

        /* private key as file + password */
        $case       = 1456;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $passPhrase         = 'passPhrase' . $case;
        $keyFile2           = self::getFileName( __FUNCTION__ . $case );
        OpenSSLPkeyFactory::factory( self::$config )->savePrivateKeyIntoPemFile( $keyFile2, $passPhrase );
        $privateKeyId       = [ $keyFile2, $passPhrase ];
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $privateKeyId, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $keyFile2, $passPhrase ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );

        /* private key as 'file://' . file */
        $case       = 1457;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $keyFile3           = 'file://' . self::getFileName( __FUNCTION__ . $case );
        OpenSSLPkeyFactory::factory( self::$config )->savePrivateKeyIntoPemFile( $keyFile3 );
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $keyFile3, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $keyFile3 ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );

        /* private key as 'file://' . file + password */
        $case       = 1458;
        if( $doEcho ) echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        $keyFile4           = 'file://' . self::getFileName( __FUNCTION__ . $case );
        OpenSSLPkeyFactory::factory( self::$config )->savePrivateKeyIntoPemFile( $keyFile4, $passPhrase );
        $privateKeyId       = [ $keyFile4, $passPhrase ];
        // Generate a self-signed certificate signing request CSR
        $x509Factory        = OpenSSLX509Factory::csrFactory(null, self::getDN(), $privateKeyId, self::$config  );
        $this->assertTrue(
            $x509Factory->checkPrivateKey( $keyFile4, $passPhrase ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case, null )
        );
        if( is_file( $keyFile1 )) {
            unlink( $keyFile1 );
        }
        if( is_file( $keyFile2 )) {
            unlink( $keyFile2 );
        }
        if( is_file( $keyFile3 )) {
            unlink( $keyFile3 );
        }
        if( is_file( $keyFile4 )) {
            unlink( $keyFile4 );
        }

    }

    /**
     * checkPurposeTest31
     * Testing OpenSSLX509Factory  checkPurpose
     * @test
     */
    public function checkPurposeTest31() {
        $case   = 101;
        // echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;

        $logger = LoggerDepot::getLogger( get_class() );
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );
        list( $x509String, $privateKeyString ) = self::getX509CertAndprivateKey();
        $x509   = new OpenSSLX509Factory();
        $x509->setx509certData( $x509String );
        $x509->read();
        $this->assertTrue(
            is_resource( $x509->getX509Resource()),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-10', null )
        );

        $result  = $x509->checkPurpose( X509_PURPOSE_ANY );
        $this->assertTrue(
            is_bool( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-11', null )
        );

        // same as above but one-liner
        $result  = OpenSSLX509Factory::factory( $x509String )
                                     ->checkPurpose( X509_PURPOSE_ANY );
        $this->assertTrue(
            is_bool( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-21', null )
        );

        // one-liner with caInfo
        list( $x509String2, $privateKeyString2 ) = self::getX509CertAndprivateKey();
        $certFile1 = self::getFileName( __FUNCTION__ . $case . '-1' );
        OpenSSLX509Factory::factory( $x509String2 )->saveX509CertIntoPemFile( $certFile1 );


        $result  = OpenSSLX509Factory::factory( $x509String )
                                     ->checkPurpose( X509_PURPOSE_ANY, [ $certFile1 ] );
        $this->assertTrue(
            is_bool( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-31', null )
        );

        // one-liner with caInfo && unTrustedFile
        list( $x509String2, $privateKeyString2 ) = self::getX509CertAndprivateKey();
        $certFile2 = self::getFileName( __FUNCTION__ . $case . '-2' );
        OpenSSLX509Factory::factory( $x509String2 )->saveX509CertIntoPemFile( $certFile2 );
        list( $x509String2, $privateKeyString2 ) = self::getX509CertAndprivateKey();
        $certFile3 = self::getFileName( __FUNCTION__ . $case . '-3' );
        OpenSSLX509Factory::factory( $x509String2 )->saveX509CertIntoPemFile( $certFile3 );

        $result  = OpenSSLX509Factory::factory( $x509String )
                                     ->checkPurpose( X509_PURPOSE_ANY, [ $certFile2 ], $certFile3 );
        $this->assertTrue(
            is_bool( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-41', null )
        );

        if( is_file( $certFile1 )) {
            unlink( $certFile1 );
        }
        if( is_file( $certFile2 )) {
            unlink( $certFile2 );
        }
        if( is_file( $certFile3 )) {
            unlink( $certFile3 );
        }
    }

    /**
     * exportTest32
     * Testing OpenSSLX509Factory  getX509CertAsPemString / getX509CertAsDerString
     *
     * @test
     */
    public function exportTest32() {
        $case   = 201;
        // echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger = LoggerDepot::getLogger( get_class() );
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );

        list( $x509String, $privateKeyString ) = self::getX509CertAndprivateKey();

        $x509          = new OpenSSLX509Factory( $x509String );
        $x509PemString = $x509->getX509CertAsPemString();
        $this->assertEquals(
            $x509String,
            $x509PemString,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-1', null )
        );
        $x509 = null;

        // same again but one-liner
        $this->assertEquals(
            $x509String,
            OpenSSLX509Factory::factory( $x509String )->getX509CertAsPemString(),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-2', null )
        );

        $x509          = new OpenSSLX509Factory( $x509String );
        $x509DerString = $x509->getX509CertAsDerString();
        $this->assertEquals(
            $x509String,
            OpenSSLX509Factory::der2Pem( $x509DerString, OpenSSLX509Factory::PEM_X509, PHP_EOL ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-3', null )
        );
        $x509 = null;

    }

    /**
     * saveX509CertIntoFileTest33
     * Testing OpenSSLX509Factory  saveX509CertIntoPemFile / saveX509CertIntoDerFile
     *
     * @test
     */
    public function saveX509CertIntoFileTest33() {
        $case   = 301;
        // echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case . PHP_EOL;
        $logger = LoggerDepot::getLogger( get_class() );
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );

        list( $x509String, $privateKeyString ) = self::getX509CertAndprivateKey();
        $certFileLocation = self::getFileName( __FUNCTION__ . $case . '-1' );
        file_put_contents( $certFileLocation, $x509String );
        $tmpFile2         = self::getFileName( __FUNCTION__ . $case . '-2' );

        $x509Factory = new OpenSSLX509Factory( $x509String );
        $x509Factory->saveX509CertIntoPemFile( $tmpFile2 );

        $this->assertFileEquals(
            $certFileLocation,
            $tmpFile2,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-3', null )
        );
        unlink( $tmpFile2 );

        // same again but one-liner
        $tmpFile5 = self::getFileName( __FUNCTION__ . $case . '-5' );

        OpenSSLX509Factory::factory( $x509String )->saveX509CertIntoPemFile( $tmpFile5 );

        $this->assertFileEquals(
            $certFileLocation,
            $tmpFile5,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-5', null )
        );
        unlink( $tmpFile5 );

        $x509Factory = new OpenSSLX509Factory( $x509String );
        $tmpFile6    = self::getFileName( __FUNCTION__ . $case . '-6', 'der' );
        $x509Factory->saveX509CertIntoDerFile( $tmpFile6 );

        $tmpFile7    = self::getFileName( __FUNCTION__ . $case . '-7' );
        OpenSSLX509Factory::derFile2PemFile( $tmpFile6, $tmpFile7, OpenSSLX509Factory::PEM_X509, PHP_EOL );
        $this->assertFileEquals(
            $certFileLocation,
            $tmpFile7,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), $case . '-6', null )
        );
        unlink( $tmpFile6 );
        unlink( $tmpFile7 );
        unlink( $certFileLocation );
    }

    /**
     * fingerprintTest34 dataProvider
     * @return array
     */
    public function fingerprintTest34Provider() {

        $dataArr   = [];
        $case      = 301;

        $dataArr[] =
            [
                $case,
                null
            ];

//        $digestMethods  = OpenSSLFactory::$SIGNATUREALGOS; // don't work here
        $digestMethods = OpenSSLFactory::getAvailableDigestMethods( false );
        foreach( $digestMethods as $x =>$digestMethod ) {
            $dataArr[] =
                [
                    ++$case,
                    $digestMethod
                ];
        }

        return $dataArr;
    }

    /**
     * fingerprintTest34
     * Testing OpenSSLX509Factory  getDigestHash (fingerprint)
     *
     * link https://stackoverflow.com/questions/26800272/how-to-sign-x-509-certificate-with-rs256-in-php-not-able-to-get-valid-fingerpri
     *
     * @test
     * @dataProvider fingerprintTest34Provider
     * @param int    $case
     * @param string $digestMethod
     */
    public function fingerprintTest34( $case, $digestMethod ) {
        // echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start ' . $case . ' digestMethod: ' . self::getSIGNATUREALGOStext( $digestMethod ) . PHP_EOL;
        $logger = LoggerDepot::getLogger( get_class() );
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );

        list( $x509String, $privateKeyString ) = self::getX509CertAndprivateKey();
        $certData = Convert::base64Decode( preg_replace( '#-.*-|\r|\n#', '', $x509String ));
        $cert2    = OpenSSLFactory::getDigestHash(
            $certData,
            ( empty( $digestMethod ) ? OpenSSLX509Factory::$HASHALGORITHMDEFAULT : $digestMethod )
        );

        $x509   = new OpenSSLX509Factory( $x509String );
        $result = $x509->getDigestHash( $digestMethod ); // sha1 default
        $this->assertTrue(
            Convert::isHex( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-1', null )
        );
        $this->assertEquals(
            $result,
            $cert2,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-2', null )
        );

        // same again but one-liner
        $result = OpenSSLX509Factory::factory( $x509String )->getDigestHash( $digestMethod ); // sha1 default
        $this->assertTrue(
            Convert::isHex( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-3', null )
        );
        $this->assertEquals(
            $result,
            $cert2,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-4', null )
        );
    }

    /**
     * parseTest35
     * Testing OpenSSLX509Factory  parse
     *
     * @test
     */
    public function parseTest35() {
        $case   = 350;
        // echo OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start '. PHP_EOL;
        $logger = LoggerDepot::getLogger( get_class() );
        $logger->log(LogLevel::INFO, OpenSSLX509Factory::getCm( __METHOD__ ) . ' Start #' . $case );

        list( $x509String, $privateKeyString ) = self::getX509CertAndprivateKey();

        $x509   = new OpenSSLX509Factory( $x509String );
        $result = $x509->getCertInfo();
        $this->assertNotEmpty(
            $result,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-11', null )
        );
        $this->assertTrue(
            is_array( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-12', null )
        );
        // echo 'true  : ' . var_export( $x509->getCertInfo( true ), true ) . PHP_EOL; // test ###
        // echo 'false : ' . var_export( $x509->getCertInfo( false ), true ) . PHP_EOL; // test ###
        $result = $x509->getCertInfo();
        $this->assertTrue(
            ( is_array( $result ) && ! empty( $result )),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-14', null )
        );
        $result = $x509->getCertSubjectDN();
        $this->assertTrue(
            ( is_array( $result ) && ! empty( $result )),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-15', null )
        );
        $this->assertTrue(
            $x509->isCertInfoKeySet( true, OpenSSLX509Factory::SUBJECT ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-16', null )
        );
        $this->assertTrue(
            $x509->isCertInfoKeySet( true, OpenSSLX509Factory::SUBJECT, OpenSSLX509Factory::DN_CN ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-17', null )
        );
        $result = $x509->getCertIssuerDN();
        $this->assertTrue(
            ( is_array( $result ) && ! empty( $result )),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-18', null )
        );
        $this->assertTrue(
            $x509->isCertInfoKeySet( true, OpenSSLX509Factory::ISSUER, OpenSSLX509Factory::DN_CN ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-19', null )
        );
        $this->assertEmpty(
            $x509->getCertSubjectDN( true, 'grodan boll' ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-20', null )
        );

        // same( first part) again but one-liner
        $result = OpenSSLX509Factory::factory( $x509String )->getCertInfo( false );
        $this->assertNotEmpty(
            $result,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-21', null )
        );
        $this->assertTrue(
            is_array( $result ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-22', null )
        );

        $this->assertTrue(
            isset( $result[OpenSSLX509Factory::SUBJECT] ),
            sprintf( self::$FMT, __FUNCTION__, '-23', null )
        );
        $this->assertTrue(
            isset( $result[OpenSSLX509Factory::ISSUER] ),
            sprintf( self::$FMT, __FUNCTION__, '-24', null )
        );
        $x = 0;
        foreach( self::getDN() as $key => $value ) {
            $this->assertTrue(
                isset( $result[OpenSSLX509Factory::SUBJECT][$key] ),
                sprintf( self::$FMT, __FUNCTION__, '-25' . ++$x, null )
            );
            /*
            $this->assertTrue(
                ( $value == $result[OpenSSLX509Factory::SUBJECT][$key] ),
                sprintf( self::$FMT, __FUNCTION__, '-26' . ++$x, null )
            );
            */
            $this->assertTrue(
                isset( $result[OpenSSLX509Factory::ISSUER][$key] ),
                sprintf( self::$FMT, __FUNCTION__, '-27' . ++$x, null )
            );
            /*
            $this->assertTrue(
                ( $value == $result[OpenSSLX509Factory::ISSUER][$key] ),
                sprintf( self::$FMT, __FUNCTION__, '-28' . ++$x, null )
            );
            */
        } // end foreach
    }

    use Traits\CsrX509Trait;

    /**
     * assertX509Test4a
     * Testing OpenSSLX509Factory::assertX509 Exception
     *
     * @test
     */
    public function assertX509Test4a() {

        foreach( [ tmpfile(), 'grodan boll' ] as $x => $source ) {
            $outcome    = true;
            try {
                $result = OpenSSLX509Factory::assertX509( $source );
            }
            catch( Exception $e ) {
                $outcome = false;
            }
            $this->assertEquals( false, $outcome, sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), ($x + 1), null ));
        }
    }

    /**
     * setX509ResourceExceptionTest4b
     * Testing OpenSSLX509Factory::setX509Resource - Exception
     *
     * @test
     */
    public function setX509ResourceExceptionTest4b() {
        $outcome  = true;
        $resource = OpenSSLPkeyFactory::factory( self::$config )->getPkeyResource();
        try {
            OpenSSLX509Factory::factory()->setX509Resource( $resource );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 3, null )
        );
    }

    /**
     * checkPurposeExceptionTest4c
     * Testing OpenSSLX509Factory::checkPurpose - Exception
     *
     * @test
     */
    public function checkPurposeExceptionTest4c() {
        $outcome  = true;
        try {
            OpenSSLX509Factory::factory()->checkPurpose( X509_PURPOSE_ANY );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 3, null )
        );
    }

    /**
     * getX509CertAsStringExceptionTest4d
     * Testing OpenSSLX509Factory::getX509CertAsPemString - Exception
     *
     * @test
     */
    public function getX509CertAsStringExceptionTest4d() {
        $outcome  = true;
        try {
            OpenSSLX509Factory::factory()->getX509CertAsPemString();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 3, null )
        );
    }

    /**
     * saveX509CertIntoFileExceptionTest4e
     * Testing OpenSSLX509Factory::saveX509CertIntoPemFile - Exception
     *
     * @test
     */
    public function saveX509CertIntoFileExceptionTest4e() {
        $outcome = true;
        $file    = self::getFileName( __FUNCTION__ );
        try {
            OpenSSLX509Factory::factory()->saveX509CertIntoPemFile( $file );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 3, null )
        );
        unlink( $file );
    }

    /**
     * fingerprintExceptionTest4f
     * Testing OpenSSLX509Factory::fingerprint - Exception
     *
     * @test
     */
    public function fingerprintExceptionTest4f() {
        $outcome = true;
        try {
            OpenSSLX509Factory::factory()->fingerprint();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 3, null )
        );
    }

    /**
     * parseExceptionTest4g1
     * Testing OpenSSLX509Factory::parse - Exception
     *
     * @test
     */
    public function parseExceptionTest4g1() {
        $outcome = true;
        try {
            OpenSSLX509Factory::factory()->parse();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 41, null )
        );
    }

    /**
     * parseExceptionTest4g2
     * Testing OpenSSLX509Factory::isCertInfoKeySet - Exception
     *
     * @test
     */
    public function parseExceptionTest4g2() {
        $outcome = true;
        try {
            OpenSSLX509Factory::factory()->isCertInfoKeySet();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 42, null )
        );
    }

    /**
     * readExceptionTest4h
     * Testing OpenSSLX509Factory::read - Exception
     *
     * @test
     */
    public function readExceptionTest4h() {
        $outcome = true;
        try {
            OpenSSLX509Factory::factory()->read();
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 3, null )
        );
    }

    /**
     * checkPrivateKeyExceptionTest4i
     * Testing OpenSSLX509Factory::checkPrivateKey - Exception
     *
     * @test
     */
    public function checkPrivateKeyExceptionTest4i() {
        $outcome = true;
        $key     = OpenSSLPkeyFactory::factory( self::$config )->getPrivateKeyAsPemString();
        try {
            OpenSSLX509Factory::factory()->checkPrivateKey( $key );
        }
        catch( Exception $e ) {
            $outcome = false;
        }
        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 1, null )
        );
    }

    /**
     * checkPurposeTest14j
     * Testing checkPurpose - exception purpose + unTrustedFile
     * @test
     */
    public function checkPurposeTest14j() {
        $privateKey       = OpenSSLPkeyFactory::factory( self::$config )->getPrivateKeyAsPemString();
        $x509CertResource = OpenSSLCsrFactory::factory( self::getDN(), $privateKey, self::$config )
                                             ->getX509CertResource( null, $privateKey ); // i.e. sign
        $x509Factory      = OpenSSLX509Factory::factory()->setX509Resource( $x509CertResource );

        try {
            $x509Factory->checkPurpose( 123 );
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }

        try {
            $x509Factory->checkPurpose( X509_PURPOSE_ANY, [], 'fakeFile' );
        }
        catch( exception $e ) {
            $this->assertFalse(
                false,
                sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
            );
        }
    }

}
