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

/**
 * Class OpenSSLDemoTest
 *
 * @coversNothing
 *
 * Testing README.md example, ver 1
 */
class OpenSSLDemoTest extends OpenSSLTest
{

    protected static $FILES = [];

    /**
     * Testing README.md example
     *
     * @test
     */
    public function demoTest1() {
        $config = [
            OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
            OpenSSLFactory::PRIVATEKEYBITS => 4096,
            OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
        $pKeyFactory      = new OpenSSLPkeyFactory( $config );

        // Generate a private key
        $privateKeyString = $pKeyFactory->getPrivateKeyAsPemString();
        // Generate a public key
        $publicKeyString  = $pKeyFactory->getPublicKeyAsPemString();

        // Distinguished Name or subject fields to be used in the certificate
        $DN = [
            OpenSSLFactory::COUNTRYNAME          => "GB",
            OpenSSLFactory::STATEORPROVINCENAME  => "Somerset",
            OpenSSLFactory::LOCALITYNAME         => "Glastonbury",
            OpenSSLFactory::ORGANIZATIONNAME     => "The Brain Room Limited",
            OpenSSLFactory::ORGANIZATIONUNITNAME => "PHP Documentation Team",
            OpenSSLFactory::COMMONNAME           => "Wez Furlong",
            OpenSSLFactory::EMAILADDRESS         => "wez@example.com"
        ];
        // Generate a certificate signing request
        $csrFactory       = OpenSSLCsrFactory::factory( self::getDN(), $privateKeyString, $config );
        $csrCertString    = $csrFactory->getCSRasPemString();

        // Generate a self-signed cert
        $x509CertResource = $csrFactory->getX509CertResource( null, $privateKeyString );
        $x509Factory      = OpenSSLX509Factory::factory()->setX509Resource( $x509CertResource );
        $x509CertString   = $x509Factory->getX509CertAsPemString();

        // tests...
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $privateKeyString ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyString ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            OpenSSLCsrFactory::isPemString( $csrCertString ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            OpenSSLX509Factory::isPemString( $x509CertString ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 1, null )
        );

        $certFile1 = self::getFileName( __FUNCTION__ . 1 );
        Workshop::saveDataToFile( $certFile1, $x509CertString );
        $certFile2 = self::getFileName( __FUNCTION__ . 2 );
        $x509Factory->saveX509CertIntoPemFile( $certFile2 );

        OpenSSLX509Factory::assertPemFile( $certFile2 );
        $this->assertFileEquals( $certFile1, $certFile2 );
        unlink( $certFile1 );
        unlink( $certFile2 );

    }

    /**
     * Testing README.md example, ver 2
     *
     * @test
     */
    public function demoTest2() {
        $config = [
            OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
            OpenSSLFactory::PRIVATEKEYBITS => 4096,
            OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
        $pKeyFactory      = new OpenSSLPkeyFactory( $config );

        // Generate private and public keys
        list( $privateKeyString, $publicKeyString ) =
            $pKeyFactory->getPrivatePublicKeyPairAsPemStrings();

        // Distinguished Name or subject fields to be used in the certificate
        $DN = [
            OpenSSLFactory::COUNTRYNAME          => "GB",
            OpenSSLFactory::STATEORPROVINCENAME  => "Somerset",
            OpenSSLFactory::LOCALITYNAME         => "Glastonbury",
            OpenSSLFactory::ORGANIZATIONNAME     => "The Brain Room Limited",
            OpenSSLFactory::ORGANIZATIONUNITNAME => "PHP Documentation Team",
            OpenSSLFactory::COMMONNAME           => "Wez Furlong",
            OpenSSLFactory::EMAILADDRESS         => "wez@example.com"
        ];

        // Generate a self-signed cert
        $x509CertString   = OpenSSLX509Factory::csrFactory( null, $DN, $privateKeyString, $config  )
                                              ->getX509CertAsPemString();

        // tests...
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $privateKeyString ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyString ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            OpenSSLX509Factory::isPemString( $x509CertString ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 1, null )
        );
    }

    /**
     * Testing README.md example, ver 3
     *
     * @test
     */
    public function demoTest3() {
        $config = [
            OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
            OpenSSLFactory::PRIVATEKEYBITS => 4096,
            OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];

        // Generate private and public keys
        list( $privateKeyString, $publicKeyString ) =
            OpenSSLPkeyFactory::factory( $config )
                              ->getPrivatePublicKeyPairAsPemStrings();

        // Distinguished Name or subject fields to be used in the certificate
        $DN = [
            OpenSSLFactory::COUNTRYNAME          => "GB",
            OpenSSLFactory::STATEORPROVINCENAME  => "Somerset",
            OpenSSLFactory::LOCALITYNAME         => "Glastonbury",
            OpenSSLFactory::ORGANIZATIONNAME     => "The Brain Room Limited",
            OpenSSLFactory::ORGANIZATIONUNITNAME => "PHP Documentation Team",
            OpenSSLFactory::COMMONNAME           => "Wez Furlong",
            OpenSSLFactory::EMAILADDRESS         => "wez@example.com"
        ];

        // Generate a self-signed cert
        $x509CertString   = OpenSSLX509Factory::csrFactory( null, $DN, $privateKeyString, $config  )
                                              ->getX509CertAsPemString();

        // tests...
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $privateKeyString ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            OpenSSLPkeyFactory::isPemString( $publicKeyString ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertTrue(
            OpenSSLX509Factory::isPemString( $x509CertString ),
            sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), 1, null )
        );
    }

    /**
     * Testing README.md example, seal/open tests
     *
     * @test
     */
    public function demoTest4() {
        $config = [
            OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
            OpenSSLFactory::PRIVATEKEYBITS => 4096,
            OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
        $pKeyFactory      = new OpenSSLPkeyFactory( $config );

        // Generate private and public keys
        list( $privateKeyString, $publicKeyString ) =
            $pKeyFactory->getPrivatePublicKeyPairAsPemStrings();


        // Seal data using public key(s)
        $data = implode( array_fill( 0, 100, 'Testing OpenSSL seal/open, !"#¤%&/()=?. '));
        $recipientId = 'The Recipient';
        $publicKeys  = [ $recipientId => $publicKeyString ];
        list( $sealed, $envelopeKeys ) = OpenSSLFactory::getSealedString( $data, $publicKeys );

        // Open (decrypted) data using private key
        $decrypted   = OpenSSLFactory::getOpenedSealedString( $sealed, $envelopeKeys[$recipientId], $privateKeyString );

        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, null )
        );

    }

    /**
     * Testing README.md example, encrypt/decrypt tests
     *
     * @test
     */
    public function demoTest5() {
        $data       = implode( array_fill( 0, 100, 'Testing OpenSSL encrypt/decrypt, !"#¤%&/()=?. ' ));
        $cipher     = 'AES-256-ECB';
        $passPhrase = Workshop::getSalt();
        $encrypted  = OpenSSLFactory::getEncryptedString( $data, $cipher, $passPhrase );
        $decrypted  = OpenSSLFactory::getDecryptedString( $encrypted, $cipher, $passPhrase );

        $this->assertEquals(
            $data,
            $decrypted
        );

    }

    /**
     * Testing README.md example
     *   OpenSSLFactory::getpublicKeyEncryptedString
     *   OpenSSLFactory::getprivateKeyDecryptedString
     *   OpenSSLFactory::getprivateKeyEncryptedString
     *   OpenSSLFactory::getpublicKeyDecryptedString
     * @test
     */
    public function demoTest6() {
        $config = [
            OpenSSLFactory::DIGESTALGO     => OPENSSL_ALGO_SHA512,
            OpenSSLFactory::PRIVATEKEYBITS => 4096,
            OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
        $pKeyFactory      = new OpenSSLPkeyFactory( $config );

        // Generate private and public keys
        list( $privateKeyString, $publicKeyString ) =
            $pKeyFactory->getPrivatePublicKeyPairAsPemStrings();

        $data      = 'Testing OpenSSL public/private encrypt/decrypt, !"#¤%&/()=?. ';

        // Encrypt the data to $encrypted using the PUBLIC key
        $encrypted = OpenSSLFactory::getpublicKeyEncryptedString( $data, $publicKeyString );

        // Decrypt the data using the PRIVATE key and store the results in $decrypted
        $decrypted = OpenSSLFactory::getprivateKeyDecryptedString( $encrypted, $privateKeyString );

        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, 'public encrypt' )
        );

        // Encrypt the data to $encrypted using the PRIVATE key
        $encrypted = OpenSSLFactory::getprivateKeyEncryptedString( $data, $privateKeyString );

        // Decrypt the data using the PUBLIC key and store the results in $decrypted
        $decrypted = OpenSSLFactory::getpublicKeyDecryptedString( $encrypted, $publicKeyString );
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, 'private encrypt' )
        );
    }

}
