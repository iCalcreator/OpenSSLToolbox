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

use Kigkonsult\OpenSSLToolbox\Workshop;
use Exception;
use Faker;
use Kigkonsult\OpenSSLToolbox\OpenSSLFactory;
use Kigkonsult\OpenSSLToolbox\OpenSSLPkeyFactory;

/**
 * Testing OpenSSLFactory
 * Testing OpenSSLPkeyFactory
 *
 * Testing seal/open, one recipient, private key without password, keys as resource/string/file
 * OpenSSLPkeyFactory  __construct + pKeyNew
 *                     + getPrivateKeyAsResource + getPrivateKeyAsPemString + savePrivateKeyIntoPemFile
 *                     + getPublicKeyResource, getPublicKeyAsPemString + savePublicKeyIntoPemFile
 * OpenSSLFactory      getSealedString + getOpenedSealedString
 *
 * Testing seal/open, one recipient, private key with password, keys as resource/string/file
 * OpenSSLPkeyFactory  __construct + pKeyNew
 *                     + getPrivateKeyAsResource + getPrivateKeyAsPemString + savePrivateKeyIntoPemFile
 *                     + getPublicKeyResource, getPublicKeyAsPemString + savePublicKeyIntoPemFile
 * OpenSSLFactory      getSealedString + getOpenedSealedString
 *
 * Testing seal/open, two recipients, private key with password, keys as resources
 * OpenSSLPkeyFactory  factory + pKeyNew + getPrivatePublicKeyPairAsResources
 * OpenSSLFactory      getSealedString + getOpenedSealedString
 *
 * Testing seal/open, two recipients, private key with password, keys as strings
 * OpenSSLPkeyFactory  factory + pKeyNew + getPrivatePublicKeyPairAsPemStrings
 * OpenSSLFactory      getSealedString + getOpenedSealedString
 *
 * Testing seal/open, two recipients, private key with password, keys fetched from files
 * OpenSSLPkeyFactory  factory + pKeyNew + savePrivatePublicKeyPairIntoPemFiles
 * OpenSSLFactory      getSealedString + getOpenedSealedString
 *
 * @todo test with cipherAlgorithm and initializationVector
 */

trait PkeySealOpenTrait
{
    /**
     * pkeyFactoryTest4x dataProvider
     * @return array
     */
    public function pkeyFactoryTest4xProvider() {

        $dataArr   = [];

        $faker     = Faker\Factory::create();
        $case      = 0;
        $dataArr[] =
            [
                $case++,
                null, // empty config
                $faker->paragraphs( 10, true ),
            ];

        $digestMethods  = OpenSSLFactory::$SIGNATUREALGOS;
        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false );
        //        $digestMethods += OpenSSLFactory::getAvailableDigestMethods( true );
        $bitsCnts       = [ 384, 512, 1024, 2048, 4096 ];

        $config = [ OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA ];
        foreach( $digestMethods as $digestMethod ) {
            if( in_array( $digestMethod,  [ 'DSA', 'dsaEncryption', 'dsaWithSHA', 'ecdsa-with-SHA1' ] )) {
                // OpenSLL seal error (#2),
                // 'error:0609806A:digital envelope routines:EVP_PKEY_encrypt_old:public key not rsa'
                continue;
            }
            $config[OpenSSLFactory::DIGESTALGO] = $digestMethod;
            foreach( $bitsCnts as $bits ) {
                $config[OpenSSLFactory::PRIVATEKEYBITS] = $bits;
                $dataArr[] =
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
     * @param int    $case
     * @param string $data
     * @param mixed  $privateKeySource
     */
    public function sealOpenTester( $case, $data, $publicKeySource, $privateKeySource ) {
        try {
            // Seal (encrypt) the data using the public keys
            list( $sealed, $envelopeKeys ) = OpenSSLFactory::getSealedString( $data, $publicKeySource );
            // $envelopeKeys is an array

            $this->assertEquals(
                array_keys( (array) $publicKeySource ),
                array_keys( $envelopeKeys ),
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 1 )
            );

            // Open (decrypt) the data using the private key
            $envelopeKey = reset( $envelopeKeys );
            $decrypted   = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKey, $privateKeySource );

            $this->assertEquals(
                $data,
                $decrypted,
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 2 )
            );
        }
        catch( Exception $e ) {
            $this->assertTrue(
                false,
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, self::getExceptionmessageAndTrace( $e ) )
            );
        }
    }

    /**
     * Testing seal/open, one recipient, private key without password, keys as resource/string/file
     * OpenSSLPkeyFactory  __construct + pKeyNew
     *                     + getPrivateKeyAsResource + getPrivateKeyAsPemString + savePrivateKeyIntoPemFile
     *                     + getPublicKeyResource, getPublicKeyAsPemString + savePublicKeyIntoPemFile
     * OpenSSLFactory      getSealedString + getOpenedSealedString
     *
     * @test
     * @dataProvider pkeyFactoryTest4xProvider
     * @see https://www.php.net/manual/en/function.openssl-pkey-export.php#90658
     * @param int    $case
     * @param array  $config
     * @param string $data
     */
    public function pkeyFactoryTest43( $case, $config, $data ) {
        $case += 3000;
        /*
        $str2 = ( empty( $config ))
            ? ' empty config'
            : ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS];
        echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $str2  . ' strlen data: ' . strlen( $data ) . PHP_EOL;
        */

        /* Create the keypair - private and public key */
        $pKeyFactory = new OpenSSLPkeyFactory( $config );
        if( empty( $config ) ) {
            $pKeyFactory->pKeyNew();
        }
        /* Create private key sources */
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString();
        // get private key as file1/2
        $privateKeyFile1    = self::getFileName( __FUNCTION__ . $case . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile1 );
        $privateKeyFile2    = 'file://' . $privateKeyFile1;
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => $privateKeyString,
            'privFile1' => $privateKeyFile1,
            'privFile2' => $privateKeyFile2
        ];

        /* Create public key sources */
        // get public key as resource
        $publicKeyResource = $pKeyFactory->getPublicKeyResource();
        // get public key as PEM-string
        $publicKeyString   = $pKeyFactory->getPublicKeyAsPemString();
        // get public key as file3/4
        $publicKeyFile3 = self::getFileName( __FUNCTION__ . $case . '-2' );
        $pKeyFactory->savePublicKeyIntoPemFile( $publicKeyFile3 );
        $publicKeyFile4 = 'file://' . $publicKeyFile3;
        $publicSources  = [
            'pubRsc'   => $publicKeyResource,
            'pubStr'   => $publicKeyString,
            'pubFile1' => $publicKeyFile3,
            'pubFile2' => $publicKeyFile4
        ];

        foreach( $privateSources as $x1 => $privateKeySource ) {
            foreach( $publicSources as $x2 => $publicKeySource ) {
                $xx = $case . '-' . $x1 . '-' . $x2;
                $this->sealOpenTester( $xx, $data, $publicKeySource, $privateKeySource );
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
     * Testing seal/open, one recipient, private key with password, keys as resource/string/file
     * OpenSSLPkeyFactory  __construct + pKeyNew
     *                     + getPrivateKeyAsResource + getPrivateKeyAsPemString + savePrivateKeyIntoPemFile
     *                     + getPublicKeyResource, getPublicKeyAsPemString + savePublicKeyIntoPemFile
     * OpenSSLFactory      getSealedString + getOpenedSealedString
     *
     * @test
     * @dataProvider pkeyFactoryTest4xProvider
     * @see https://www.php.net/manual/en/function.openssl-pkey-export.php#90658
     * @param int    $case
     * @param array  $config
     * @param string $data
     */
    public function pkeyFactoryTest44( $case, $config, $data ) {
        $case += 4000;
        /*
        $str2 = ( empty( $config ))
            ? ' empty config'
            : ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS];
        echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $str2  . ' strlen data: ' . strlen( $data ) . PHP_EOL;
        */

        /* Create the keypair - private and public key */
        $pKeyFactory = new OpenSSLPkeyFactory( $config );
        if( empty( $config ) ) {
            $pKeyFactory->pKeyNew();
        }
        /* Create private key sources */
        $passPhrase         = Workshop::getSalt();
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource( $passPhrase );
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString( $passPhrase );
        // get private key as file1/2
        $privateKeyFile1    = self::getFileName( __FUNCTION__ . $case . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile1 );
        $privateKeyFile2    = 'file://' . $privateKeyFile1;
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => [ $privateKeyString, $passPhrase ],
            'privFile1' => [ $privateKeyFile1, $passPhrase ],
            'privFile2' => [ $privateKeyFile2, $passPhrase ]
        ];

        /* Create public key sources */
        // get public key as resource
        $publicKeyResource = $pKeyFactory->getPublicKeyResource();
        // get public key as PEM-string
        $publicKeyString   = $pKeyFactory->getPublicKeyAsPemString();
        // get public key as file3/4
        $publicKeyFile3 = self::getFileName( __FUNCTION__ . $case . '-2' );
        $pKeyFactory->savePublicKeyIntoPemFile( $publicKeyFile3 );
        $publicKeyFile4 = 'file://' . $publicKeyFile3;
        $publicSources  = [
            'pubRsc'   => $publicKeyResource,
            'pubStr'   => $publicKeyString,
            'pubFile1' => $publicKeyFile3,
            'pubFile2' => $publicKeyFile4
        ];

        foreach( $privateSources as $x1 => $privateKeySource ) {
            foreach( $publicSources as $x2 => $publicKeySource ) {
                $this->sealOpenTester( $case . '-' . $x1 . $x2, $data, $publicKeySource, $privateKeySource );
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
     * Testing seal/open, two recipients, private key with password, keys as resources
     * OpenSSLPkeyFactory  factory + pKeyNew + getPrivatePublicKeyPairAsResources
     * OpenSSLFactory      getSealedString + getOpenedSealedString
     *
     * @test
     * @dataProvider pkeyFactoryTest4xProvider
     * @see https://www.php.net/manual/en/function.openssl-pkey-export.php#90658
     * @param int    $case
     * @param array  $config
     * @param string $data
     */
    public function pkeyFactoryTest45( $case, $config, $data ) {
        $case += 5000;
        /*
        $str2 = ( empty( $config ) )
            ? ' empty config'
            : ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS];
        echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $str2  . ' strlen data: ' . strlen( $data ) .  PHP_EOL;
        */

        /* Create the keypair 1 into strings */
        $passPhrase1   = Workshop::getSalt();
        list( $privateKeyResource1, $publicKeyResource1 ) =
            OpenSSLPkeyFactory::factory()
                              ->pKeyNew( $config )
                              ->getPrivatePublicKeyPairAsResources( $passPhrase1 );

        /* Create the keypair 2 into strings */
        $passPhrase2   = Workshop::getSalt();
        list( $privateKeyResource2, $publicKeyResource2 ) =
            OpenSSLPkeyFactory::factory()
                              ->pKeyNew( $config )
                              ->getPrivatePublicKeyPairAsResources( $passPhrase2 );

        $recipientId1 = 'recipient1';
        $recipientId2 = 'recipient2';
        /* Encrypt the data using the public key resources */
        $publicKeys = [ $recipientId1 => $publicKeyResource1, $recipientId2 => $publicKeyResource2 ];
        list( $sealed, $envelopeKeys )  = OpenSSLFactory::getSealedString( $data, $publicKeys );

        /* Decrypt the data using the private key resource 1 */
        $decrypted = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKeys[$recipientId1], $privateKeyResource1 );
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-1', var_export( $config, true ))
        );

        /* Decrypt the data using the private key resource 2 */
        $decrypted = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKeys[$recipientId2], $privateKeyResource2 );
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-2', var_export( $config, true ))
        );
    }

    /**
     * Testing seal/open, two recipients, private key with password, keys as strings
     * OpenSSLPkeyFactory  factory + pKeyNew + getPrivatePublicKeyPairAsPemStrings
     * OpenSSLFactory      getSealedString + getOpenedSealedString
     *
     * @test
     * @dataProvider pkeyFactoryTest4xProvider
     * @see https://www.php.net/manual/en/function.openssl-pkey-export.php#90658
     * @param int    $case
     * @param array  $config
     * @param string $data
     */
    public function pkeyFactoryTest46( $case, $config, $data ) {
        $case += 6000;
        /*
        $str2 = ( empty( $config ) )
            ? ' empty config'
            : ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS];
        echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $str2  . ' strlen data: ' . strlen( $data ) .  PHP_EOL;
        */

        /* Create the keypair 1 into strings */
        $passPhrase1   = Workshop::getSalt();
        list( $privateKeyString1, $publicKeyString1 ) =
            OpenSSLPkeyFactory::factory()
                              ->pKeyNew( $config )
                              ->getPrivatePublicKeyPairAsPemStrings( $passPhrase1 );
        $privateKeyId1 = [ $privateKeyString1, $passPhrase1 ];

        /* Create the keypair 2 into strings */
        $passPhrase2   = Workshop::getSalt();
        list( $privateKeyString2, $publicKeyString2 ) =
            OpenSSLPkeyFactory::factory()
                              ->pKeyNew( $config )
                              ->getPrivatePublicKeyPairAsPemStrings( $passPhrase2 );
        $privateKeyId2 = [ $privateKeyString2, $passPhrase2 ];

        $recipientId1 = 'recipient1';
        $recipientId2 = 'recipient2';
        /* Encrypt the data using the public keys */
        $publicKeys = [ $recipientId1 => $publicKeyString1, $recipientId2 => $publicKeyString2 ];
        list( $sealed, $envelopeKeys )  = OpenSSLFactory::getSealedString( $data, $publicKeys );

        /* Decrypt the data using the private key1 */
        $decrypted = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKeys[$recipientId1], $privateKeyId1 );
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-1', var_export( $config, true ))
        );

        /* Decrypt the data using the private key2 */
        $decrypted = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKeys[$recipientId2], $privateKeyId2 );
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-2', var_export( $config, true ))
        );
    }

    /**
     * Testing seal/open, two recipients, private key with password, keys fetched from files
     * OpenSSLPkeyFactory  factory + pKeyNew + savePrivatePublicKeyPairIntoPemFiles
     * OpenSSLFactory      getSealedString + getOpenedSealedString
     *
     * @test
     * @dataProvider pkeyFactoryTest4xProvider
     * @see https://www.php.net/manual/en/function.openssl-pkey-export.php#90658
     * @param int    $case
     * @param array  $config
     * @param string $data
     */
    public function pkeyFactoryTest47( $case, $config, $data ) {
        $case += 7000;
        /*
        $str2 = ( empty( $config ) )
            ? ' empty config'
            : ' digestAlgo: ' . self::getSIGNATUREALGOStext( $config[OpenSSLPkeyFactory::DIGESTALGO] ) .
            ' bits: ' . $config[OpenSSLPkeyFactory::PRIVATEKEYBITS];
        echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' ' . $str2  . ' strlen data: ' . strlen( $data ) .  PHP_EOL;
        */

        /* Create the keypair 1 into files */
        $passPhrase1     = Workshop::getSalt();
        $privateKeyFile1 = self::getFileName( __FUNCTION__ . $case . '-1' );
        $publicKeyFile1  = self::getFileName( __FUNCTION__ . $case . '-2' );
        OpenSSLPkeyFactory::factory()
                          ->pKeyNew( $config )
                          ->savePrivatePublicKeyPairIntoPemFiles( $privateKeyFile1, $publicKeyFile1, $passPhrase1 );
        $privateKeyId1 = [ $privateKeyFile1, $passPhrase1 ];

        /* Create the keypair 2 into files */
        $passPhrase2     = Workshop::getSalt();
        $privateKeyFile2 = self::getFileName( __FUNCTION__ . $case . '-3' );
        $publicKeyFile2  = self::getFileName( __FUNCTION__ . $case . '-4' );
        OpenSSLPkeyFactory::factory()
                          ->pKeyNew( $config )
                          ->savePrivatePublicKeyPairIntoPemFiles( $privateKeyFile2, $publicKeyFile2, $passPhrase2 );
        $privateKeyId2 = [ $privateKeyFile2, $passPhrase2 ];

        $recipientId1 = 'recipient1';
        $recipientId2 = 'recipient2';
        /* Encrypt the data using the public keys */
        $publicKeys = [ $recipientId1 => $publicKeyFile1, $recipientId2 => $publicKeyFile2 ];
        // The array envelopeKeys will have the same keys as publicKeyIds
        list( $sealed, $envelopeKeys )  = OpenSSLFactory::getSealedString( $data, $publicKeys );

        /* Decrypt the data using the private key1 */
        $decrypted = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKeys[$recipientId1], $privateKeyId1 );
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-1', var_export( $config, true ))
        );

        /* Decrypt the data using the private key2 */
        $decrypted = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKeys[$recipientId2], $privateKeyId2 );
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case . '-2', var_export( $config, true ))
        );
        if( is_file( $privateKeyFile1 )) {
            unlink( $privateKeyFile1 );
        }
        if( is_file( $publicKeyFile1 )) {
            unlink( $publicKeyFile1 );
        }
        if( is_file( $privateKeyFile2 )) {
            unlink( $privateKeyFile2 );
        }
        if( is_file( $publicKeyFile2 )) {
            unlink( $publicKeyFile2 );
        }
    }

}
