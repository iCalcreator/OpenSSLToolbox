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

use Throwable;

/**
 * Class OpenSSLBaseFactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\BaseFactory
 *
 * Testing BaseFactory
 *   getCm
 *   initClassStr
 *   getErrArgNoText
 *
 *   PhpErrors2Exception
 */
class BaseFactoryTest extends OpenSSLTest
{

    protected static $FILES = [];

    use Traits\assertMdCipherAlgorithmTrait;

    /**
     * Testing OpenSSLBaseFactory::getCm
     *
     * @test
     */
    public function getCm12( ) {

        $this->assertTrue(
            is_string( OpenSSLFactory::getCm( __METHOD__ )),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, null )
        );

    }

    /**
     * Testing OpenSSLBaseFactory::initClassStr
     *
     * @test
     */
    public function initClassStr13( ) {

        $this->assertTrue(
            is_string( OpenSSLPkeyFactory::initClassStr()),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, null )
        );

    }

    /**
     * Testing BaseFactory::getErrArgNoText
     *
     * @test
     */
    public function getErrArgNoText14( ) {

        $this->assertTrue(
            is_string( OpenSSLPkeyFactory::getErrArgNoText( 1 )),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, null )
        );

    }

    /**
     * Testing BaseFactory::PhpErrors2Exception - catch exception
     *
     * @test
     */
    public function PhpErrors2ExceptionTest15() {
        $case    = 1;
        $outcome = true;
        try {
            PhpErrorException::PhpErrors2Exception( null, 'PhpErrors2Exception error text', 'file.php', 75 );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     * Testing BaseFactory::getSource / isSourceKeySet
     *
     * @test
     */
    public function sourceTest16() {
        $config = [
            OpenSSLPkeyFactory::TYPE => OPENSSL_KEYTYPE_RSA,
        ];

        $pkeyFactory = OpenSSLPkeyFactory::factory();
        $this->assertFalse(
            $pkeyFactory->isDetailsKeySet(),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertNull(
            $pkeyFactory->getDetailsKey(),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 2, null )
        );

        $pkeyFactory->setConfig( $config );
        $pkeyFactory->pKeyNew();

        $this->assertFalse(
            $pkeyFactory->isDetailsKeySet( 'key1' ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 3, null )
        );
        $this->assertNull(
            $pkeyFactory->getDetailsKey( 'key1' ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 4, null )
        );
        $this->assertTrue(
            $pkeyFactory->isDetailsKeySet( OpenSSLPkeyFactory::TYPE ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 5, null )
        );
        $this->assertEquals(
            OPENSSL_KEYTYPE_RSA,
            $pkeyFactory->getDetailsKey( OpenSSLPkeyFactory::TYPE, null, false ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 6, null )
        );

        $this->assertFalse(
            $pkeyFactory->isDetailsKeySet( OpenSSLPkeyFactory::RSA, 'key4' ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 7, null )
        );
        $this->assertNull(
            $pkeyFactory->getDetailsKey( OpenSSLPkeyFactory::RSA, 'key4' ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 8, null )
        );
        $this->assertTrue(
            $pkeyFactory->isDetailsKeySet( OpenSSLPkeyFactory::RSA, OpenSSLPkeyFactory::N ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 9, null )
        );
        $this->assertTrue(
            Convert::isBase64(
                $pkeyFactory->getDetailsKey( OpenSSLPkeyFactory::RSA, OpenSSLPkeyFactory::N )
            ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 10, null )
        );

    }
}
