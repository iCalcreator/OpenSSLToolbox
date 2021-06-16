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

use Faker;
use Exception;
use Throwable;

/**
 * Class OpenSSLPkcs7FactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLPkcs7Factory
 *
 * OpenSSLPkcs7FactoryTest11
 *   OpenSSLPkcs7Factory exceptions
 *
 * OpenSSLPkcs7FactoryTest2*
 *   OpenSSLPkcs7Factory::encryptString
 *   OpenSSLPkcs7Factory::encrypt
 *   OpenSSLPkcs7Factory::decryptString
 *   OpenSSLPkcs7Factory::decrypt
 *
 * OpenSSLPkcs7FactoryTest3*
 *   OpenSSLPkcs7Factory::signString
 *   OpenSSLPkcs7Factory::sign
 *   OpenSSLPkcs7Factory::verifyString
 *   OpenSSLPkcs7Factory::verify
 * @todo fix test of verify !!
 */
class OpenSSLPkcs7FactoryTest extends OpenSSLTest
{

    private static $config = [
        OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
        OpenSSLFactory::PRIVATEKEYBITS => 4096,
        OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
    ];

    private static function getCipherText( $cipher ) {
        static $CIPHERS = [
            OPENSSL_CIPHER_RC2_40      => 'OPENSSL_CIPHER_RC2_40',
            OPENSSL_CIPHER_RC2_128     => 'OPENSSL_CIPHER_RC2_128',
            OPENSSL_CIPHER_RC2_64      => 'OPENSSL_CIPHER_RC2_64',
            OPENSSL_CIPHER_DES         => 'OPENSSL_CIPHER_DES',
            OPENSSL_CIPHER_3DES        => 'OPENSSL_CIPHER_3DES',
            OPENSSL_CIPHER_AES_128_CBC => 'OPENSSL_CIPHER_AES_128_CBC',
            OPENSSL_CIPHER_AES_192_CBC => 'OPENSSL_CIPHER_AES_192_CBC',
            OPENSSL_CIPHER_AES_256_CBC => 'OPENSSL_CIPHER_AES_256_CBC',
        ];
        return ( isset( $CIPHERS[$cipher] )) ? $CIPHERS[$cipher] . ' (' . $cipher . ')' : ' -default- ';
    }

    /**
     * Testing OpenSSLPkcs7Factory - catch exception
     *
     * @test
     */
    public function OpenSSLPkcs7FactoryTest11() {
        $case    = 12;
        $outcome = true;
        try {
            OpenSSLPkcs7Factory::assertFlags( 'false' );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     * @param mixed $certSource
     * @param mixed $privateSource
     * @param mixed $case
     */
    public function encryptDecryptTester2x( $certSource, $privateSource, $case ) {
        $faker   = Faker\Factory::create();
        $ciphers = [ null ] + OpenSSLFactory::$CIPHERS;

        foreach( $ciphers as $cipher ) {
            $data    = $faker->sentences( 10, true );
            $headers = [
                "To"      => $faker->companyEmail,
                "From"    => $faker->companyEmail,
                "Subject" => $faker->sentence()
            ];
            $cipherText = self::getCipherText( $cipher );
            $flags      = null;
            // echo 'start ' . OpenSSLFactory::getCm( __METHOD__ ) . ' ' . $case . '-' . $cipherText . PHP_EOL;
            $theCert = ( 0 == array_rand( [ 0, 1 ] )) ? $certSource : [ $certSource ];

            // encrypt it
            try {
                $encryptedData = OpenSSLPkcs7Factory::encryptString( $data, $theCert, $headers, $flags, $cipher );
            }
            catch( Exception $e ) {
                $this->assertTrue(
                    false,
                    sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-encrypt1-' . $cipherText, PHP_EOL . self::getExceptionmessageAndTrace( $e ))
                );
            }
            $this->assertTrue(
                is_string( $encryptedData ),
                sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-encrypt2-' . $cipherText, null )
            );
            // decrypt it
            try {
                $decryptedData = OpenSSLPkcs7Factory::decryptString( $encryptedData, $certSource, $privateSource );
            }
            catch( Exception $e ) {
                $this->assertTrue(
                    false,
                    sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-decrypt1-' . $cipherText, PHP_EOL . self::getExceptionmessageAndTrace( $e ))
                );
            }
            $this->assertEquals(
                $data,
                $decryptedData,
                sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-decrypt2-' . $cipherText, null )
            );
        } // end foreach
    }
    
    /**
     * Testing OpenSSLPkcs7Factory : encryptString (encrypt), decryptString (decrypt) without password
     *
     * @test
     * @see https://www.php.net/manual/en/function.openssl-pkcs7-encrypt.php#51006
     */
    public function OpenSSLPkcs7FactoryTest21() {
// load keys
        /* privateKey without password */
        $pKeyFactory        = OpenSSLPkeyFactory::factory()->pKeyNew( self::$config );
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString();
        // get private key as PEM-file
        $privateKeyFile     = self::getFileName( __FUNCTION__ . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile );
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => $privateKeyString,
            'privFile1' => $privateKeyFile,
            'privFile2' => 'file://' . $privateKeyFile,
        ];

        /* x509 cert without password */
        $csrFactory         = new OpenSSLCsrFactory( self::getDN(), $privateKeyString, self::$config );
        $caCertFile         = null;
        $csrX509Resource    = $csrFactory->getX509CertResource( $caCertFile, $privateKeyString, 365, self::$config );
        $x509Factory        = OpenSSLX509Factory::factory()->setX509Resource( $csrX509Resource );
        // get x509 cert as resource
        $x509Resource       = $x509Factory->getX509Resource();
        // get x509 cert as string
        $x509CertString     = $x509Factory->getX509CertAsPemString();
        // get x509 cert as file
        $x509CertFile       = self::getFileName( __FUNCTION__ . '-2' );
        $x509Factory->saveX509CertIntoPemFile( $x509CertFile );
        $certSources        = [
            'certRscArr' => $x509Resource,
            'certStr'    => $x509CertString,
            'certFile1'  => $x509CertFile,
            'certFile2'  => 'file://' . $x509CertFile,
        ];

        $case = 1300;
        foreach( $certSources as $cx => $certSource ) {
            foreach( $privateSources as $px => $privateSource ) {
                $this->encryptDecryptTester2x( $certSource, $privateSource, ++$case . '-'. $cx . '-' . $px );
            }
        }
        if( is_file( $privateKeyFile  )) {
            unlink( $privateKeyFile );
        }
        if( is_file( $x509CertFile  )) {
            unlink( $x509CertFile );
        }
    }

    /**
     * Testing OpenSSLPkcs7Factory : encryptString (encrypt), decryptString (decrypt) with password
     *
     * @test
     * @see https://www.php.net/manual/en/function.openssl-pkcs7-encrypt.php#51006
     */
    public function OpenSSLPkcs7FactoryTest22() {

// load keys
        /* privateKey with password */
        $pKeyFactory        = OpenSSLPkeyFactory::factory()->pKeyNew( self::$config );
        $passPhrase         = Workshop::getSalt();
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString( $passPhrase );
        // get private key as PEM-file
        $privateKeyFile     = self::getFileName( __FUNCTION__ . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile );
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => [ $privateKeyString, $passPhrase ],
            'privFile1' => [ $privateKeyFile, $passPhrase ],
            'privFile2' => [ 'file://' . $privateKeyFile, $passPhrase ],
        ];

        /* x509 cert with password */
        $privateKeyId       = [ $privateKeyString, $passPhrase ];
        $csrFactory         = new OpenSSLCsrFactory( self::getDN(), $privateKeyId, self::$config );
        $caCertFile         = null;
        $csrX509Resource    = $csrFactory->getX509CertResource( $caCertFile, $privateKeyId, 365, self::$config );
        $x509Factory        = OpenSSLX509Factory::factory()->setX509Resource( $csrX509Resource );
        // get x509 cert as resource
        $x509Resource       = $x509Factory->getX509Resource();
        // get x509 cert as string
        $x509CertString     = $x509Factory->getX509CertAsPemString();
        // get x509 cert as file
        $x509CertFile       = self::getFileName( __FUNCTION__ . '-2' );
        $x509Factory->saveX509CertIntoPemFile( $x509CertFile );
        $certSources        = [
            'certRscArr' => $x509Resource,
            'certStr'    => $x509CertString,
            'certfile1'  => $x509CertFile,
            'certfile2'  => 'file://' . $x509CertFile,
        ];

        $case = 1400;
        foreach( $certSources as $cx => $certSource ) {
            foreach( $privateSources as $px => $privateSource ) {
                $this->encryptDecryptTester2x( $certSource, $privateSource, ++$case . '-'. $cx . '-' . $px );
            }
        }
        if( is_file( $privateKeyFile  )) {
            unlink( $privateKeyFile );
        }
        if( is_file( $x509CertFile  )) {
            unlink( $x509CertFile );
        }
    }

    /**
     * Testing sign and verify
     * @param mixed  $certSource
     * @param mixed  $privateSource
     * @param string $case
     * @param array  $caInfo
     * @param string $extraCerts
     * @todo test verify
     */
    public function signVerifyTester3x( $certSource, $privateSource, $case, $caInfo, $extraCerts ) {
        $faker   = Faker\Factory::create();
        $data    = $faker->sentences( 10, true );
        $headers = [
            "To"      => $faker->companyEmail,
            "From"    => $faker->companyEmail,
            "Subject" => $faker->sentence()
        ];

        $flags   = PKCS7_DETACHED;
        // echo 'start ' . OpenSSLPkcs7Factory::getCm( __METHOD__ ) . ' ' . $case . PHP_EOL;
        try {
            $signedData = OpenSSLPkcs7Factory::signString( $data, $certSource, $privateSource, $headers, null );
        }
        catch( Exception $e ) {
            $this->assertTrue(
                false,
                sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), '-sign', PHP_EOL . self::getExceptionmessageAndTrace( $e ))
            );
        }
        $this->assertTrue(
            ( is_string( $signedData ) && ! empty( $signedData )),
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-1', null )
        );
        /*
        $signPemsString = $contentString = null;
        try {
            list ( $signPemsString, $contentString ) =
                OpenSSLPkcs7Factory::verifyString( $signedData, $flags, $caInfo, $extraCerts, $result );
        }
        catch( Exception $e ) {
            $this->assertTrue(
                false,
                sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), '-verify', PHP_EOL . self::getExceptionmessageAndTrace( $e ))
            );
        }
        $this->assertTrue(
            is_bool( $result ), // should test result for 'true' here but it is next @todo
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-3', null )
        );
        $this->assertTrue(
//          OpenSSLPkcs7Factory::isPemString( $signPemsString ), // should work if result true?
            is_string( $signPemsString ),
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-4', null )
        );
        $this->assertTrue(
            is_string( $contentString ),
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case . '-5', null )
        );
        echo '\'result\' : ' . var_export( $result, true ) . PHP_EOL;
        */
    }

    /**
     * Testing OpenSSLPkcs7Factory : signString (sign), verifyString (verify)  without password
     *
     * @test
     * @see https://www.php.net/manual/en/function.openssl-pkcs7-encrypt.php#51006
     */
    public function OpenSSLPkcs7FactoryTest31() {
        /* privateKey without password */
        $pKeyFactory        = OpenSSLPkeyFactory::factory()->pKeyNew( self::$config );
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString();
        // get private key as PEM-file
        $privateKeyFile     = self::getFileName( __FUNCTION__ . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile );
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => $privateKeyString,
            'privFile1' => $privateKeyFile,
            'privFile2' => 'file://' . $privateKeyFile,
        ];

        /* x509 cert without password */
        $x509Factory    = OpenSSLX509Factory::csrFactory( null, self::getDN(), $privateKeyString, self::$config );
        // get x509 cert as resource
        $x509Resource   = $x509Factory->getX509Resource();
        // get x509 cert as string
        $x509CertString = $x509Factory->getX509CertAsPemString();
        // get x509 cert as file
        $x509CertFile       = self::getFileName( __FUNCTION__ . '-2' );
        $x509Factory->saveX509CertIntoPemFile( $x509CertFile );

        $certSources    = [
            'certRsc'   => $x509Resource,
            'certStr'   => $x509CertString,
            'certFile1' => $x509CertFile,
            'certFile2' => 'file://' . $x509CertFile,
        ];

        $bundle             = $privateKeyString . PHP_EOL . $x509CertString;
        $caInfoBundleFile   = self::getFileName( __FUNCTION__ . '-3' );  // caInfo
        file_put_contents( $caInfoBundleFile, $bundle );
        $caInfo             = [ $caInfoBundleFile ]; // 'file://' .

        $extraCertsFile     = self::getFileName( __FUNCTION__ . '-4' );  // extracerts
        file_put_contents( $extraCertsFile, $bundle );
        $extraCerts         = $extraCertsFile; // 'file://' . $extraCertsFile;

        $case = 2100;
        foreach( $certSources as $cx => $certSource ) {
            foreach( $privateSources as $px => $privateSource ) {
                $xx = ++$case . '-'. $cx . '-' . $px;
                $this->signVerifyTester3x( $certSource, $privateSource, ++$xx, $caInfo, $extraCerts );
            }
        }
        if( is_file( $privateKeyFile  )) {
            unlink( $privateKeyFile );
        }
        if( is_file( $x509CertFile  )) {
            unlink( $x509CertFile );
        }
        if( is_file( $caInfoBundleFile  )) {
            unlink( $caInfoBundleFile );
        }
        if( is_file( $extraCertsFile  )) {
            unlink( $extraCertsFile );
        }

    }

    /**
     ** Testing OpenSSLPkcs7Factory : signString (sign), verifyString (verify)  with password
     *
     * @test
     * @see https://www.php.net/manual/en/function.openssl-pkcs7-encrypt.php#51006
     *
     * Ref OpenSSLPkcs12FactoryTest::pkcs12Test1+2, copy ?
     */
    public function OpenSSLPkcs7FactoryTest32() {
        /* privateKey with password */
        $pKeyFactory        = OpenSSLPkeyFactory::factory()->pKeyNew( self::$config );
        $passPhrase         = Workshop::getSalt();
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource( $passPhrase );
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString( $passPhrase );
        // get private key as PEM-file
        $privateKeyFile     = self::getFileName( __FUNCTION__ . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile );
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => [ $privateKeyString, $passPhrase ],
            'privFile1' => [ $privateKeyFile, $passPhrase ],
            'privFile2' => [ 'file://' . $privateKeyFile, $passPhrase ],
        ];

        /* x509 cert with password */
        $privateKeyId       = [ $privateKeyString, $passPhrase ];
        $x509Factory        = OpenSSLX509Factory::csrFactory( null, self::getDN(), $privateKeyId, self::$config );
        // get x509 cert as resource
        $x509Resource       = $x509Factory->getX509Resource();
        // get x509 cert as string
        $x509CertString     = $x509Factory->getX509CertAsPemString();
        // get x509 cert as file
        $x509CertFile       = self::getFileName( __FUNCTION__ . '-2' );
        $x509Factory->saveX509CertIntoPemFile( $x509CertFile );

        $certSources        = [
            'certRsc'   => $x509Resource,
            'certStr'   => $x509CertString,
            'certFile1' => $x509CertFile,
            'certFile2' => 'file://' . $x509CertFile,
        ];

        $bundle             = $privateKeyString . PHP_EOL . $x509CertString;
        $caInfoBundleFile   = self::getFileName( __FUNCTION__ . '-3' );  // caInfo
        file_put_contents( $caInfoBundleFile, $bundle );
        $caInfo             = [ 'file://' . $caInfoBundleFile ];

        $extraCertsFile     = self::getFileName( __FUNCTION__ . '-4' );  // extracerts
        file_put_contents( $extraCertsFile, $bundle );
        $extraCerts         = $extraCertsFile; // 'file://' . $extraCertsFile;

        $case = 2200;
        foreach( $certSources as $cx => $certSource ) {
            foreach( $privateSources as $px => $privateSource ) {
                $xx = ++$case . '-'. $cx . '-' . $px;
                $this->signVerifyTester3x( $certSource, $privateSource, $xx, $caInfo, $extraCerts );
            }
        }
        if( is_file( $privateKeyFile  )) {
            unlink( $privateKeyFile );
        }
        if( is_file( $x509CertFile  )) {
            unlink( $x509CertFile );
        }
        if( is_file( $caInfoBundleFile  )) {
            unlink( $caInfoBundleFile );
        }
        if( is_file( $extraCertsFile  )) {
            unlink( $extraCertsFile );
        }
    }

}
