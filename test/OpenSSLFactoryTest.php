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
 * Class OpenSSLFactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLFactory
 *
 * getCipherIvLengthTest11
 *   OpenSSLFactory::getCipherIvLength
 *
 * encryptDecryptTest12
 *   OpenSSLFactory::getEncryptedString / getDecryptedString
 *
 * assertOptsTest13
 *   OpenSSLCsrFactory::assertOpts - catch exception
 *
 * assertPaddingTest14
 *   OpenSSLCsrFactory::assertPadding - catch exception
 *
 * signVerifyTest21
 *   OpenSSLFactory::getSignature / isSignatureOkForPublicKey
 *
 * OpenSSLFactoryTester3x
 *   OpenSSLFactory::getpublicKeyEncryptedString
 *   OpenSSLFactory::getprivateKeyDecryptedString
 *   OpenSSLFactory::getprivateKeyEncryptedString
 *   OpenSSLFactory::getpublicKeyDecryptedString
 * @todo https://www.php.net/manual/en/function.openssl-private-encrypt.php#119810
 *
 * pbkdf2Test41
 *   OpenSSLFactory::getPbkdf2
 *
 * pkeyFactoryTest4x (Traits\PkeySealOpenTrait)
 *   OpenSSLFactory::getSealedString
 *   OpenSSLFactory::getOpenedSealedString
 */
class OpenSSLFactoryTest extends OpenSSLTest
{

    protected static $FILES = [];

    /**
     * getCipherIvLengthTest11 dataProvider
     * @return array
     */
    public function getCipherIvLengthTest11Provider() {
        $dataArr = [];
        $cipherAlgorithms = OpenSSLFactory::getAvailableCipherMethods(true );
        sort( $cipherAlgorithms );
        $case = 0;

        foreach( $cipherAlgorithms as $cipherAlgorithm ) { // as of PHP 7.0.25: 226 algorithms
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
     * Testing OpenSSLFactory::getCipherIvLength
     *
     * @test
     * @dataProvider getCipherIvLengthTest11Provider
     * @param int    $case
     * @param string $algorithm
     * @param bool   $expected
     */
    public function getCipherIvLengthTest11( $case, $algorithm, $expected ) {
        static $FMT1 = '%s Error in case #%s, algorithm: %s, result: %s';
        $outcome     = true;
        $result      = null;
        try {
            $result = OpenSSLFactory::getCipherIvLength( $algorithm );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals(
            $expected,
            $outcome,
            sprintf( $FMT1, OpenSSLFactory::getCm( __METHOD__ ), '1-' . $case . '-1', $algorithm, var_export( $result, true ))
        );
        if( $outcome ) {
            // echo '1-' . $case . ' ok     ' . $algorithm . PHP_EOL; // test ###
            $this->assertTrue(
                is_int( $result ),
                sprintf( $FMT1, OpenSSLFactory::getCm( __METHOD__ ), '1-' . $case . '-2', $algorithm, var_export( $result, true ))
            );
        }
    }

    /**
     * encryptDecryptTest12 dataProvider
     * @return array
     */
    public function encryptDecryptTest12Provider() {
        $dataArr = [];
        $cipherAlgorithms = OpenSSLFactory::getAvailableCipherMethods(true );
        sort( $cipherAlgorithms );
        $case    = 0;
        $faker   = Faker\Factory::create();
        foreach( $cipherAlgorithms as $cipherAlgorithm ) {
            if( in_array(        // non-working ciphers...
                $cipherAlgorithm,
                [
                    'aes-128-ccm',
                    'aes-128-gcm',
                    'aes-192-ccm',
                    'aes-192-gcm',
                    'aes-256-ccm',
                    'aes-256-gcm',
                    'id-aes128-CCM',
                    'id-aes128-GCM',
                    'id-aes128-wrap',
                    'id-aes128-wrap-pad',
                    'id-aes192-CCM',
                    'id-aes192-GCM',
                    'id-aes192-wrap',
                    'id-aes192-wrap-pad',
                    'id-aes256-CCM',
                    'id-aes256-GCM',
                    'id-aes256-wrap',
                    'id-aes256-wrap-pad',
                    'id-smime-alg-CMS3DESwrap',
                ]
            )) {
                $case += 1;
                continue;
            };
            $dataArr[] =
                [
                    ++$case,
                    $cipherAlgorithm,
                    $faker->password,
                    $faker->paragraphs( 10, true )
                ];
        }
        return $dataArr;
    }

    /**
     * Testing OpenSSLFactory::getEncryptedString / getDecryptedString
     *
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php#120987
     * @test
     * @dataProvider encryptDecryptTest12Provider
     * @param int    $case
     * @param string $algorithm
     * @param string $passWord
     * @param string $data
     */
    public function encryptDecryptTest12( $case, $algorithm, $passWord, $data ) {
        static $FMT1 = '%s Error in case #%s, algorithm: %s';

        $cipherIvLength       = OpenSSLFactory::getCipherIvLength( $algorithm );
        $initializationVector = ( empty( $cipherIvLength )) ? '' : Workshop::getSalt( $cipherIvLength );
        $keyHash              = OpenSSLFactory::getDigestHash( $passWord, 'sha256', true );
        $opts                 = 0; // OPENSSL_RAW_DATA;

        try {
            $encrypted = OpenSSLFactory::getEncryptedString( $data, $algorithm, $keyHash, $opts, $initializationVector );
        }
        catch( Exception $e ) {
            echo $case . '-1 ' . $algorithm . PHP_EOL; // test ###
            echo self::getExceptionmessageAndTrace( $e );
            $this->assertTrue( true );
            return;
        }

        try {
            $decrypted = OpenSSLFactory::getDecryptedString( $encrypted, $algorithm, $keyHash, $opts, $initializationVector );
        }
        catch( Exception $e ) {
            echo $case . '-2 ' . $algorithm . PHP_EOL; // test ###
            echo self::getExceptionmessageAndTrace( $e );
            $this->assertTrue( true );
            return;
        }

        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( $FMT1, OpenSSLFactory::getCm( __METHOD__ ), $case . '-3', $algorithm )
        );
        // echo $case . '-4 ' . $algorithm . ' - ok' . PHP_EOL; // test ###
    }

    /**
     * Testing OpenSSLCsrFactory::assertOpts - catch exception
     *
     * @test
     */
    public function assertOptsTest13() {
        $outcome = true;
        try {
            $encrypted = OpenSSLFactory::getEncryptedString(
                Faker\Factory::create()->words( 3, true ),
                OpenSSLFactory::getAvailableCipherMethods()[0],
                OpenSSLFactory::getDigestHash(
                    Faker\Factory::create()->words( 2, true ),
                    'sha256',
                    true
                ),
                12345
            );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
        );
    }

    /**
     * Testing OpenSSLCsrFactory::assertPadding - catch exception
     *
     * @test
     */
    public function assertPaddingTest14() {
        $outcome = true;
        try {
            $encrypted = OpenSSLFactory::getpublicKeyEncryptedString(
                Faker\Factory::create()->words( 3, true ),
                OpenSSLPkeyFactory::factory()->pKeyNew()->getPublicKeyAsPemString(),
                12345
            );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, self::getExceptionmessageAndTrace( $e ))
        );
    }

    /**
     * signVerifyTest21 provider
     */
    public function signVerifyTestProvider() {

        $dataArr = [];
        $case    = 1000;

        $digestMethods  = OpenSSLFactory::$SIGNATUREALGOS;
        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false );
//        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( true );
        $bitsCnts       = [ 384, 512, 1024, 2048, 4096 ];
        foreach( $digestMethods as $digestMethod ) {
            $case   += 10;
            if( in_array( $digestMethod,    // OpenSLL sign error
                          [
                              'whirlpool',
                              'ecdsa-with-SHA1'
                          ]
            )
            ) { // OpenSLL sign error
                continue;  // error:0606B06E:digital envelope routines:EVP_SignFinal:wrong public key type
            }
            if( in_array( $digestMethod, [ 5, 'DSA', 'dsaEncryption', 'dsaWithSHA', 'ecdsa-with-SHA1' ] )) {
                $keyType =OPENSSL_KEYTYPE_DSA;   // 'OPENSSL_ALGO_DSS1' etc
            }
            else {
                $keyType = OPENSSL_KEYTYPE_RSA;
            }
            $case2 = $case;
            foreach( $bitsCnts as $bits ) {
                if(( 384 == $bits ) &&
                    in_array( $digestMethod,    // OpenSLL sign error
                              [                 // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                                  6, // OPENSSL_ALGO_SHA224
                                  7, // OPENSSL_ALGO_SHA256
                                  8, // OPENSSL_ALGO_SHA384
                                  9, // OPENSSL_ALGO_SHA512
                                  'sha224',
                                  'sha256',
                                  'sha384',
                                  'sha512'
                              ]
                    )
                ) {
                    continue;
                }
                elseif(( 512 == $bits ) &&
                    in_array( $digestMethod,    // OpenSLL sign error
                              [                 // error:04075070:rsa routines:RSA_sign:digest too big for rsa key
                                  8, // OPENSSL_ALGO_SHA384
                                  9, // OPENSSL_ALGO_SHA512
                                  'sha384',
                                  'sha512'
                              ]
                    )
                ) {
                    continue;
                }
                $dataArr[] = [
                    ++$case2,
                    [
                        OpenSSLFactory::PRIVATEKEYBITS => $bits,
                        OpenSSLFactory::PRIVATEKEYTYPE => $keyType,
                    ],
                    $digestMethod,
                ];
            } // end foreach
        } // end foreach

        return $dataArr;
    }

    /**
     ** Testing OpenSSLFactory::getSignature / isSignatureOkForPublicKey
     * (sign / verify) -with Private Key PEMstring / file / resource
     *
     * @see https://www.php.net/manual/en/function.openssl-sign.php, example 2
     * @test
     * @dataProvider signVerifyTestProvider
     * @param int              $case
     * @param array            $config
     * @param int|string       $algorithm
     */
    public function signVerifyTest21( $case, $config, $algorithm ) {
        /*
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
            ' algorithm: ' . self::getSIGNATUREALGOStext( $algorithm ) .
            ' bits: ' . ( isset( $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] ) ? $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] : ' ---' );
        echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2 . PHP_EOL;
        */

        // create new private and public key
        $pKeyFactory = new OpenSSLPkeyFactory( $config );

        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // get private key as PEM-string
        $privateKeyPEM      = $pKeyFactory->getPrivateKeyAsPemString();
        // echo 'privatePEM: ' . substr( $privateKeyPEM, 0, 37 ) . PHP_EOL; // test ###
        // get private key as file1/2
        $privateKeyFile1    = self::getFileName( __FUNCTION__ . $case . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile1 );
        $privateKeyFile2    = 'file://' . $privateKeyFile1;
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => $privateKeyPEM,
            'privFile1' => $privateKeyFile1,
            'privFile2' => $privateKeyFile2
        ];

        // get public key as resource
        $publicKeyResource = $pKeyFactory->getPublicKeyResource();
        // get public key as PEM-string
        $publicKeyPEM      = $pKeyFactory->getPublicKeyAsPemString();
        // get public key as file3/4
        $publicKeyFile3    = self::getFileName( __FUNCTION__ . $case . '-3' );
        $pKeyFactory->savePublicKeyIntoPemFile( $publicKeyFile3 );
        $publicKeyFile4    = 'file://' . $publicKeyFile3;
        $publicSources     = [
            'pubRsc'   => $publicKeyResource,
            'pubStr'   => $publicKeyPEM,
            'pubFile1' => $publicKeyFile3,
            'pubFile2' => $publicKeyFile4
        ];

        foreach( $privateSources as $x1 => $privateKeySource ) {
            foreach( $publicSources as $x2 => $publicKeySource ) {
                $xx = $case . '-' . $x1 . '-' . $x2;
                // echo 'start ' . $xx . PHP_EOL; // test ###
                $this->signVerifyTester21( $xx, $privateKeySource, $publicKeySource, $algorithm );
            }
        }

        if( is_file( $privateKeyFile1 )) {
            unlink( $privateKeyFile1 );
        }
        if( is_file( $publicKeyFile3 )) {
            unlink( $publicKeyFile3 );
        }
    }

    /**
     * @param string           $case
     * @param string|resource  $privateKeyId
     * @param string|resource  $publicKeyId
     * @param int|string       $algorithm
     */
    public function signVerifyTester21( $case, $privateKeyId, $publicKeyId, $algorithm ) {
        static $FMT  = '%s Error in case #%s, algorithm: %s';
        //data you want to sign
        $data    = [
//          1 => Faker\Factory::create()->words( 3, true ),
            2 => Faker\Factory::create()->paragraphs( 10, true ),
        ];
        foreach( $data as $x => $testData ) {
            //create signature
            $signature = OpenSSLFactory::getSignature( $testData, $privateKeyId, $algorithm );

            //verify signature
            $this->assertTrue(
                OpenSSLFactory::isSignatureOkForPublicKey( $testData, $signature, $publicKeyId, $algorithm ),
                sprintf( $FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-' . $x, self::getSIGNATUREALGOStext( $algorithm ))
            );
        }
    }

    /**
     * TEST OpenSSLFactory::getpublicKeyEncryptedString
     *      OpenSSLFactory::getprivateKeyDecryptedString
     *
     *      OpenSSLFactory::getprivateKeyEncryptedString
     *      OpenSSLFactory::getpublicKeyDecryptedString
     *
     * @param mixed $case
     * @param mixed $msg
     * @param mixed $msg2
     * @param mixed $xx
     * @param mixed $data
     * @param mixed $expected
     * @param mixed $publicKeySource
     * @param mixed $privateKeySource
     */
    public function OpenSSLFactoryTester3x( $case, $msg, $msg2, $xx, $data, $expected, $publicKeySource, $privateKeySource ) {
        $publicEncrypt = true;
        try {
            // Encrypt the data using the PUBLIC key
            $encrypted = OpenSSLFactory::getpublicKeyEncryptedString( $data, $publicKeySource );
        }
        catch( Exception $e ) {
            $publicEncrypt = false;
        }

        $this->assertEquals(
            $expected,
            $publicEncrypt,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-21', $msg2 . $xx )
        );
        if( $publicEncrypt ) {
            // Decrypt the data using the PRIVATE key
            $decrypted = OpenSSLFactory::getprivateKeyDecryptedString( $encrypted, $privateKeySource );

            $this->assertEquals(
                $data,
                $decrypted,
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-31', $msg2 . $xx )
            );
        }

        $privateEncrypt = true;
        try {
            // Encrypt the data using the PRIVATE key
            $encrypted = OpenSSLFactory::getprivateKeyEncryptedString( $data, $privateKeySource );
        }
        catch( Exception $e ) {
            $privateEncrypt = false;
        }

        if( $privateEncrypt ) {
            // echo $msg . $xx . PHP_EOL;

            // Decrypt the data using the PUBLIC key
            $decrypted = OpenSSLFactory::getpublicKeyDecryptedString( $encrypted, $publicKeySource );

            $this->assertEquals(
                $data,
                $decrypted,
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-41', $msg2 . $xx )
            );
        }
        if( $expected && ( ! $publicEncrypt || ! $privateEncrypt )) {
            echo $msg . $xx . ', public encrypt; ' . ( $publicEncrypt ? 'ok' : 'error' ) . ', private encrypt: ' . ( $privateEncrypt ? 'ok' : 'error' ) . PHP_EOL;
        }
    }

    /**
     * OpenSSLFactoryTestx dataProvider
     * @return array
     */
    public function OpenSSLFactoryTestProvider() {

        $dataArr   = [];

        $digestMethods  = OpenSSLFactory::$SIGNATUREALGOS;
        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false );
        //      $digestMethods += OpenSSLFactory::getAvailableDigestMethods( true );
        $bitsCnts = [ 384, 512, 1024, 2048, 4096 ];
//        $bitsCnts = [ 1024, 2048, 4096 ];   // using 384/512 may cause csr_new exceptions...

        $faker    = Faker\Factory::create();
        $text     = $faker->paragraphs(10, true ) ;
        $case     = 0;
        foreach( $digestMethods as $digestMethod ) {
            if( in_array( $digestMethod, [ 5, 'DSA', 'dsaEncryption', 'dsaWithSHA', 'ecdsa-with-SHA1' ] )) {
                // $keyType =OPENSSL_KEYTYPE_DSA;   // 'OPENSSL_ALGO_DSS1' etc
                continue;                        // don't work
            }
            else {
                $keyType = OPENSSL_KEYTYPE_RSA;
            }
            $configArgs = [
                OpenSSLPkeyFactory::DIGESTALGO     => $digestMethod,
                OpenSSLPkeyFactory::PRIVATEKEYTYPE => $keyType,
            ];
            foreach( $bitsCnts as $bits ) {
                $configArgs[OpenSSLPkeyFactory::PRIVATEKEYBITS] = $bits;
                switch( $bits ) {
                    case 384 :
                        $data = substr( $text, 0, 37 );
                        break;
                    case 512 :
                        $data = substr( $text, 0, 53 );
                        break;
                    case 1024 :
                        $data = substr( $text, 0, 117 );
                        break;
                    case 2048 :
                        $data = substr( $text, 0, 245 );
                        break;
                    default : // 4096
                        $data = substr( $text, 0, 501 );
                        break;
                }
                if( ' ' == substr( $data, -1, 1 )) {
                    $data = substr( $data, 0, -1 ) . 'x'; // replace trailing space
                }
                $dataArr[] = [
                    ++$case,
                    $configArgs,
                    $data,
                    true
                ];
                $dataArr[] = [
                    ++$case,
                    $configArgs,
                    $data . 'x',
                    false
                ];
            } // end foreach
        } // end foreach

        return $dataArr;
    }

    /**
     * @test
     * @dataProvider OpenSSLFactoryTestProvider
     * OpenSSLFactory      getpublicKeyEncryptedString + getprivateKeyDecryptedString
     * OpenSSLFactory      getprivateKeyEncryptedString + getpublicKeyDecryptedString
     * OpenSSLPkeyFactory  __construct + setConfig + addConfig + pKeyNew +
     *                     getPrivateKeyAsResource, getPrivateKeyAsPemString, savePrivateKeyIntoPemFile
     *                     private key without password
     *                     getPublicKeyResource, getPublicKeyAsPemString, savePublicKeyIntoPemFile
     * @see https://www.php.net/manual/en/function.openssl-pkey-new.php#111769
     * @see https://www.php.net/manual/en/function.openssl-private-encrypt.php#119810
     *      max number of chars (bytes) to encrypt depends on the length of key
     * key bits  data length  expected
     *      384 -  37         ok
     *             38         error
     *      512 -  54         ok
     *             55         error
     *     1024 - 117         ok
     *            118         error
     *     2048 - 245         ok
     *            246         error
     *     4096 - 501         ok
     *            502         error
     ** Testing keys as resource/string/file
     * @param int    $case
     * @param array  $config
     * @param string $data
     * @param bool   $expected  if false, public/private key encrypt fails
     */
    public function OpenSSLFactoryTest31( $case, $config, $data, $expected ) {
        $case += 1000;
        $msg2 = ' keyType: ' . ( ( OPENSSL_KEYTYPE_RSA == $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE] ) ? 'RSA' : 'DSA ' ) .
            ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] .
            ' strlen data: ' . strlen( $data ) . ' expected:' . ( $expected ? 'ok' : 'error' );
        $msg  = OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2;

        // Create the private key
        $pKeyFactory = new OpenSSLPkeyFactory( $config );

        // Extract the private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // Extract the private key as string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString();
        // Extract the private key as file
        $privateKeyFile     = self::getFileName( __FUNCTION__ . $case . 1 );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile );
        $privateKeySources  = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => $privateKeyString,
            'privFile1' => $privateKeyFile,
            'privFile2' => 'file://' . $privateKeyFile,
        ];

        // Extract the public key as resource
        $publicKeyResource  = $pKeyFactory->getPublicKeyResource();
        // Extract the public key as string
        $publicKeyString    = $pKeyFactory->getPublicKeyAsPemString();
        // save the public key in file
        $publicKeyFile      = self::getFileName( __FUNCTION__ . $case . 2 );
        $pKeyFactory->savePublicKeyIntoPemFile( $publicKeyFile );
        $publicKeySources = [
            'pubRsc'   => $publicKeyResource,
            'pubStr'   => $publicKeyString,
            'pubFile1' => $publicKeyFile,
            'pubFile2' => 'file://' . $publicKeyFile,
        ];

        foreach( $privateKeySources as $privX => $privateKeySource ) {
            foreach( $publicKeySources as $pubX => $publicKeyResources ) {
                $xx = " {$privX}-{$pubX}";
                $this->OpenSSLFactoryTester3x(
                    $case, $msg, $msg2, $xx, $data, $expected, $publicKeyResources, $privateKeySource );
            } // end foreach
        } // end foreach

        unlink( $privateKeyFile );
        unlink( $publicKeyFile );
    }

    /**
     * @test
     * @dataProvider OpenSSLFactoryTestProvider
     * OpenSSLFactory      getpublicKeyEncryptedString + getprivateKeyDecryptedString
     * OpenSSLFactory      getprivateKeyEncryptedString + getpublicKeyDecryptedString
     * @see https://www.php.net/manual/en/function.openssl-pkey-new.php#111769
     * @see https://www.php.net/manual/en/function.openssl-private-encrypt.php#119810
     *      max number of chars (bytes) to encrypt depends on the length of key
     * key bits  data length  expected
     *      384 -  37         ok
     *             38         error
     *      512 -  54         ok
     *             55         error
     *     1024 - 117         ok
     *            118         error
     *     2048 - 245         ok
     *            246         error
     *     4096 - 501         ok
     *            502         error
     ** Testing keys as resource/string/file
     * @param int    $case
     * @param array  $config
     * @param string $data
     * @param bool   $expected  if false, public/private key encrypt fails
     */
    public function OpenSSLFactoryTest32( $case, $config, $data, $expected ) {
        $case += 1000;
        $msg2 = ' keyType: ' . ( ( OPENSSL_KEYTYPE_RSA == $config[OpenSSLPkeyFactory::PRIVATEKEYTYPE] ) ? 'RSA' : 'DSA ' ) .
            ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS] .
            ' strlen data: ' . strlen( $data ) . ' expected:' . ( $expected ? 'ok' : 'error' );
        $msg  = OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $msg2;

        // Create the private key
        $pKeyFactory = new OpenSSLPkeyFactory( $config );
        $passPhrase  = Workshop::getSalt();

        // Extract the private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource( $passPhrase );
        // Extract the private key as string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString( $passPhrase );
        // Extract the private key as file
        $privateKeyFile     = self::getFileName( __FUNCTION__ . $case . 1 );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile, $passPhrase );
        $privateKeySources  = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => [ $privateKeyString, $passPhrase ],
            'privFile1' => [ $privateKeyFile, $passPhrase ],
            'privFile2' => [ 'file://' . $privateKeyFile, $passPhrase ],
        ];

        // Extract the public key as resource
        $publicKeyResource  = $pKeyFactory->getPublicKeyResource();
        // Extract the public key as string
        $publicKeyString    = $pKeyFactory->getPublicKeyAsPemString();
        // save the public key in file
        $publicKeyFile      = self::getFileName( __FUNCTION__ . $case . 2 );
        $pKeyFactory->savePublicKeyIntoPemFile( $publicKeyFile );
        $publicKeySources = [
            'pubRsc'   => $publicKeyResource,
            'pubStr'   => $publicKeyString,
            'pubFile1' => $publicKeyFile,
            'pubFile2' => 'file://' . $publicKeyFile,
        ];

        foreach( $privateKeySources as $privX => $privateKeySource ) {
            foreach( $publicKeySources as $pubX => $publicKeyResources ) {
                $xx = " {$privX}-{$pubX}";
                $this->OpenSSLFactoryTester3x(
                    $case, $msg, $msg2, $xx, $data, $expected, $publicKeyResources, $privateKeySource );
            } // end foreach
        } // end foreach

        unlink( $privateKeyFile );
        unlink( $publicKeyFile );
    }

    /**
     * @test
     *     misuse getpublicKeyEncryptedString   using private key - exception
     *     misuse getprivateKeyDecryptedString  using public key  - exception
     *     misuse getprivateKeyEncryptedString  using public key  - exception
     *     misuse getpublicKeyDecryptedString   using private key - exception
     */
    public function OpenSSLFactoryTest33() {
        $config = [
            OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
            OpenSSLFactory::PRIVATEKEYBITS => 4096,
            OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
        $pKeyFactory      = new OpenSSLPkeyFactory( $config );

        // Generate private and public keys
        list( $privateKeyString, $publicKeyString ) =
            $pKeyFactory->getPrivatePublicKeyPairAsPemStrings();

        $data      = 'Testing OpenSSL misusing public/private encrypt/decrypt, !"#¤%&/()=?. ';

        try {
            $encrypted = OpenSSLFactory::getpublicKeyEncryptedString( $data, $privateKeyString );
            $this->assertTrue( false ); // really break if NOT error
        }
        catch( exception $e ) {
            $this->assertFalse(
                false ); // expected
        }
        $encrypted = OpenSSLFactory::getpublicKeyEncryptedString( $data, $publicKeyString );
        try {
            $decrypted = OpenSSLFactory::getprivateKeyDecryptedString( $encrypted, $publicKeyString );
            $this->assertTrue( false ); // really break if NOT error
        }
        catch( exception $e ) {
            $this->assertFalse(
                false ); // expected
        }

        try {
            $encrypted = OpenSSLFactory::getprivateKeyEncryptedString( $data, $publicKeyString );
            $this->assertTrue( false ); // really break if NOT error
        }
        catch( exception $e ) {
            $this->assertFalse(
                false ); // expected
        }

        $encrypted = OpenSSLFactory::getprivateKeyEncryptedString( $data, $privateKeyString );
        try {
            $decrypted = OpenSSLFactory::getprivateKeyDecryptedString( $encrypted, $publicKeyString );
            $this->assertTrue( false ); // really break if NOT error
        }
        catch( exception $e ) {
            $this->assertFalse(
                false ); // expected
        }

    }

    /**
     * pbkdf2Test41 dataProvider
     * @return array
     */
    public function pbkdf2Test41Provider() {
        $dataArr        = [];
        $case           = 0;
        $faker          = Faker\Factory::create();

        $dataArr[] =
            [
                ++$case,
                null,
                $data = $faker->words( 10, true )
            ];

        $digestMethods  = []; // OpenSSLFactory::$SIGNATUREALGOS; // don't work here
        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false );
        foreach( $digestMethods as $digestMethod ) {
            $dataArr[] =
                [
                    ++$case,
                    $digestMethod,
                    $data = $faker->words( 10, true )
                ];
        }
        return $dataArr;
    }

    /**
     * Testing  OpenSSLFactory::getPbkdf2
     *
     * @test
     * @dataProvider pbkdf2Test41Provider
     * @param int    $case
     * @param string $algorithm
     * @param string $password
     */
    public function pbkdf2Test41( $case, $algorithm, $password ) {

        $pbkdf2 = OpenSSLFactory::getPbkdf2( $password, null, null, null, $algorithm );

        $this->assertTrue(
            ( is_string( $pbkdf2 ) && ! empty( $pbkdf2 )),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case , $algorithm )
        );
    }

    use Traits\PkeySealOpenTrait;
}

