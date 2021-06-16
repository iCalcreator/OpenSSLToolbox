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
 * Class PhpErrorExceptionTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\PhpErrorException
 */
class PhpErrorExceptionTest extends OpenSSLTest
{

    protected static $FILES = [];

    /**
     * Testing BaseFactory::PhpErrors2Exception - catch exception
     *
     * @test
     */
    public function PhpErrorExceptionTest() {
        $outcome = true;
        try {
            throw new PhpErrorException(
                'Error text', 123, E_USER_ERROR, 'file.php', 75
            );
        }
        catch( PhpErrorException $pe ) {
            $outcome = false;
            $this->assertEquals(
                'UserError',
                PhpErrorException::getSeverityText( $pe->getSeverity()),
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 1, null )
            );
        }
        catch( exception $e ) {}

        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 2, null )
        );
    }
}
