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
use Throwable;

/**
 * Class OpenSSLBaseFactory2Test
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLBaseFactory2
 *
 *  OpenSSLBaseFactory2::config  methods
 */
class OpenSSLBaseFactory2Test extends OpenSSLTest
{

    protected static $FMT   = '%s Error in case #%s, %s';
    protected static $FILES = [];

    /**
     * Testing OpenSSLCsrFactory - getConfig / setConfig
     *
     * @test
     */
    public function csrFactoryTest11c() {
        $csrFactory0 = OpenSSLCsrFactory::factory();
        $this->assertNull(
            $csrFactory0->getConfig(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 0, null )
        );

        $config = [
            OpenSSLFactory::DIGESTALGO     => 10,
            OpenSSLFactory::PRIVATEKEYTYPE => OPENSSL_KEYTYPE_RSA,
            OpenSSLFactory::PRIVATEKEYBITS => 4096,
        ];
        $csrFactory1 = OpenSSLCsrFactory::factory()->setConfig( $config  );
        $this->assertTrue(
            $csrFactory1->isConfigSet(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 1, null )
        );
        $this->assertEquals(
            $config,
            $csrFactory1->getConfig(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 2, null )
        );
        $this->assertTrue(
            $csrFactory1->isConfigSet( OpenSSLFactory::PRIVATEKEYTYPE ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 3, null )
        );
        $this->assertEquals(
            OPENSSL_KEYTYPE_RSA,
            $csrFactory1->getConfig( OpenSSLFactory::PRIVATEKEYTYPE ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 3, null )
        );

        $csrFactory2 = OpenSSLCsrFactory::factory();
        $this->assertEmpty(
            $csrFactory2->getConfig(),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 4, null )
        );
        $csrFactory2->setConfig( $csrFactory1->getConfig());
        $this->assertEquals(
            $config,
            $csrFactory2->getConfig( $config ),
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 5, null )
        );

        $outcome = true;
        try  {
            $csrFactory2->setConfig( [ OpenSSLFactory::DIGESTALGO => 13 ] );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 6, null )
        );

        $outcome = true;
        try  {
            $csrFactory2->setConfig( [ OpenSSLFactory::ENCRYPTKEYCIPHER => 13 ] );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 7, null )
        );

        $outcome = true;
        try  {
            $csrFactory2->setConfig( [ OpenSSLFactory::PRIVATEKEYBITS => [1024] ] );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 8, null )
        );

        $outcome = true;
        try  {
            $csrFactory2->setConfig( [ OpenSSLFactory::PRIVATEKEYBITS => 'bits1024' ] );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 9, null )
        );

        $outcome = true;
        try  {
            $csrFactory2->setConfig( [ OpenSSLFactory::PRIVATEKEYBITS => 224 ] );
        }
        catch( Throwable $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), 10, null )
        );
    }

}
