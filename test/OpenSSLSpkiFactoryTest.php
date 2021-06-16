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
 * Class OpenSSLSpkiFactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLSpkiFactory
 *
 * OpenSSLSpkiTest1
 *   OpenSSLSpkiFactory exceptions
 *
 * OpenSSLSpkiTest21
 *   OpenSSLSpkiFactory::__construct (+ spkiNew)
 *   OpenSSLSpkiFactory::getSPKACasString
 *   OpenSSLSpkiFactory::getChallengeAsString
 *
 * OpenSSLSpkiTest22
 *   populate spkiFactory from "spkac" string, test exceptions if verify not ok
 */
class OpenSSLSpkiFactoryTest extends OpenSSLTest
{

    protected static $FILES = [];

    /**
     ** Testing OpenSSLSpkiFactory exceptions
     *
     * @test
     */
    public function OpenSSLSpkiTest1() {
        $spkiFactory42 = new OpenSSLSpkiFactory();
        $errorTest    = true;
        try {
            $spkiFactory42->spkiNew( [ 'Grodan Boll' ], 'challenge' );
        }
        catch( Exception $e ) {
            $errorTest = false;
        }
        $this->assertFalse(
            $errorTest,
            sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), 11, null )
        );

        $spkiFactory43 = new OpenSSLSpkiFactory();
        $errorTest    = true;
        try {
            $spkiFactory43->spkiNew(
                OpenSSLPkeyFactory::factory()->pKeyNew()->getPrivateKeyAsResource(),
                'challenge',
                16 // invalid algorithm
            );
        }
        catch( Exception $e ) {
            $errorTest = false;
        }
        $this->assertFalse(
            $errorTest,
            sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), 12, null )
        );

        $spkiFactory44 = new OpenSSLSpkiFactory();
        $errorTest    = true;
        try {
            $spkiFactory44->getSPKACasString();
        }
        catch( Exception $e ) {
            $errorTest = false;
        }
        $this->assertFalse(
            $errorTest,
            sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), 13, null )
        );

        $spkiFactory45 = new OpenSSLSpkiFactory();
        $errorTest    = true;
        try {
            $spkiFactory45->getChallengeAsString();
        }
        catch( Exception $e ) {
            $errorTest = false;
        }
        $this->assertFalse(
            $errorTest,
            sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), 14, null )
        );

    }

    /**
     * OpenSSLSpkiTest2x dataProvider
     * @return array
     */
    public function OpenSSLSpkiTest2xProvider() {

        $dataArr   = [];
        $case     = 0;

        $dataArr[] = [
            $case++,
            null
        ];

        $digestMethods  = OpenSSLFactory::$SIGNATUREALGOS;
        // $digestMethods += OpenSSLFactory::getAvailableDigestMethods( false ); -- don't work with spki
        foreach( $digestMethods as $digestMethod ) {
            $testOk = ( in_array( $digestMethod, [ 2, 3, 5 ] )) ? false : true;  // will not verify ok
            $dataArr[] = [
                ++$case,
                $digestMethod,
                $testOk
            ];
        } // end foreach

        return $dataArr;
    }

    /**
     * OpenSSLSpkiFactory  __construct + spkiNew, getSPKACasString, getChallengeAsString
     *
     * @test
     * @dataProvider OpenSSLSpkiTest2xProvider
     * @see https://www.php.net/manual/en/function.openssl-spki-new.php
     * @see https://www.php.net/manual/en/function.openssl-spki-export.php
     * @see https://www.php.net/manual/en/function.openssl-spki-export-challenge.php
     * @param int    $case
     * @param string $algorithm
     * @param bool   $testOk
     */
    public function OpenSSLSpkiTest21( $case, $algorithm = null, $testOk = true ) {
        $doEcho = false;
            static $config   = [
            OpenSSLPkeyFactory::PRIVATEKEYBITS => 4096,
            OpenSSLPkeyFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
        if( ! empty( $algorithm )) {
            $config[OpenSSLPkeyFactory::DIGESTALGO] = $algorithm; // 1, // OPENSSL_ALGO_SHA1,
        }
        $case += 2100;
        if( $doEcho ) echo OpenSSLPkeyFactory::getCm( __METHOD__ ) . ' Start #' . $case . ' algorithm: ' . self::getSIGNATUREALGOStext( $algorithm ) . PHP_EOL;

        $pkeyFactory     = OpenSSLPkeyFactory::factory()->pKeyNew( $config );

        $pkeyResource    = $pkeyFactory->getPrivateKeyAsResource();
        $pkeyString      = $pkeyFactory->getPrivateKeyAsPemString();
        $privateKeyFile1 = self::getFileName( __FUNCTION__ . $case . '-1' );
        $pkeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile1 );
        $privateSources  = [
            'privRsc'   => $pkeyResource,
            'privStr'   => $pkeyString,
            'privFile1' => $privateKeyFile1,
            'privFile2' => 'file://' . $privateKeyFile1
        ];

        foreach( $privateSources as $x => $privateSource ) {

            $challenge = Faker\Factory::create()->text( 100 );
            try {
                $spkiFactory1 = OpenSSLSpkiFactory::factory( $pkeyString, $challenge, $algorithm );
            }
            catch( Exception $e ) {
                $this->assertFalse(
                    $testOk,
                    sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, $x . '-' . $algorithm . '-1' )
                );
                if( $doEcho ) echo OpenSSLSpkiFactory::getCm( __METHOD__ ) . $case . '-' . $x . '-' . self::getSIGNATUREALGOStext( $algorithm ) . PHP_EOL . self::getExceptionmessageAndTrace( $e ); // test ###
                continue;
            }

            $spkac1 = $spkiFactory1->getSpkac();
            // echo $spkac1 . PHP_EOL; // test ###
            $this->assertTrue(
                is_string( $spkac1 ),
                sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, $x . '-' . $algorithm . '-2' )
            );

            $spkacStr1 = $spkiFactory1->getSPKACasString();
            // echo $spkacStr1 . PHP_EOL; // test ###
            $this->assertTrue(
                OpenSSLSpkiFactory::isPemString( $spkacStr1 ),
                sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, $x . '-' . $algorithm . '-3' )
            );

            $this->assertEquals(
                $challenge,
                $spkiFactory1->getChallengeAsString(),
                sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, $x . '-' . $algorithm . '-4' )
            );
        } // end foreach
        unlink( $privateKeyFile1 );
    }

    /**
     * populate spkiFactory from "spkac" string, test exceptions if verify not ok
     *
     * @test
     * @dataProvider OpenSSLSpkiTest2xProvider
     * @param int    $case
     * @param string $algorithm
     * @param bool   $testOk
     */
    public function OpenSSLSpkiTest22( $case, $algorithm = null, $testOk = true ) {
        $case += 2200;
        $config   = [
            OpenSSLPkeyFactory::DIGESTALGO     => $algorithm, // OPENSSL_ALGO_SHA512,
            OpenSSLPkeyFactory::PRIVATEKEYBITS => 4096,
            OpenSSLPkeyFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
        ];
       $pkeyResource = OpenSSLPkeyFactory::factory()
                                          ->pKeyNew( $config )
                                          ->getPrivateKeyAsResource();
        $challenge    = Faker\Factory::create()->text( 100 );
        try {
            $spkac1 = OpenSSLSpkiFactory::factory( $pkeyResource, $challenge, $algorithm )
                                        ->getSpkac();
        }
        catch( Exception $e ) {
            $this->assertFalse(
                $testOk,
                sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, self::getSIGNATUREALGOStext( $algorithm ) . ' - 1' )
            );
            // echo $case . ' - ' . self::getSIGNATUREALGOStext( $algorithm ) . PHP_EOL; // . self::getExceptionmessageAndTrace( $e ); // test ###
            return;
        }

        $spkiFactory2 = new OpenSSLSpkiFactory();
        $errorTest    = true;
        try {
            $spkiFactory2->setSpkac( $spkac1 );  // includes spki verify
        }
        catch( Exception $e ) {
            $errorTest = false;
        }
        $this->assertEquals(
            $testOk,
            $errorTest,
            sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, self::getSIGNATUREALGOStext( $algorithm ) . ' - 2' )
        );

        $errorTest    = true;
        try {
            $spkacStr2 = $spkiFactory2->getSPKACasString();
            $this->assertTrue(
                OpenSSLSpkiFactory::isPemString( $spkacStr2 ),
                sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, self::getSIGNATUREALGOStext( $algorithm ) . ' - 3' )
            );
        }
        catch( Exception $e ) {
            $errorTest = false;
        }
        $this->assertEquals(
            $testOk,
            $errorTest,
            sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, self::getSIGNATUREALGOStext( $algorithm ) . ' - 4' )
        );

        $errorTest    = true;
        try {
            $this->assertEquals(
                $challenge,
                $spkiFactory2->getChallengeAsString(),
                sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, self::getSIGNATUREALGOStext( $algorithm ) . ' - 5' )
            );
        }
        catch( Exception $e ) {
            $errorTest = false;
        }
        $this->assertEquals(
            $testOk,
            $errorTest,
            sprintf( self::$FMT, OpenSSLSpkiFactory::getCm( __METHOD__ ), $case, self::getSIGNATUREALGOStext( $algorithm ) . ' - 6' )
        );

    }

}
