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
 * Class OpenSSLTest
 *
 */
abstract class OpenSSLTest extends BaseTest
{

    protected static $FMT   = '%s Error in case #%s, %s';

    /**
     * @param int|string $algorithm
     * @return int|string
     * @static
     */
    public static function getSIGNATUREALGOStext( $algorithm ) {
        static $CONSTtexts = [
            5  => 'OPENSSL_ALGO_DSS1',
            1  => 'OPENSSL_ALGO_SHA1',     // Used as default algorithm by openssl_sign() and openssl_verify().
            6  => 'OPENSSL_ALGO_SHA224',
            7  => 'OPENSSL_ALGO_SHA256',
            8  => 'OPENSSL_ALGO_SHA384',
            9  => 'OPENSSL_ALGO_SHA512',
            10 => 'OPENSSL_ALGO_RMD160',
            2  => 'OPENSSL_ALGO_MD5',
            3  => 'OPENSSL_ALGO_MD4',
            4  => 'OPENSSL_ALGO_MD2',
        ];
        if( empty( $algorithm )) {
            return '---';
        }
        if( ! is_int( $algorithm )) {
            return $algorithm;
        }
        if( isset( $CONSTtexts[$algorithm] )) {
            return sprintf( '(%d) %s', $algorithm, $CONSTtexts[$algorithm] );
        }
        return $algorithm;
    }

    /**
     * Return array, Distinguished Name or subject fields to be used when creating certificate.
     *
     * @return array
     * @static
     */
    public static function getDN() {
        static $faker = null;
        if( empty( $faker )) {
            $faker = Faker\Factory::create();
        }
        return [
            OpenSSLFactory::COUNTRYNAME          => $faker->countryCode,
            OpenSSLFactory::STATEORPROVINCENAME  => $faker->state,
            OpenSSLFactory::LOCALITYNAME         => $faker->city,
            OpenSSLFactory::ORGANIZATIONNAME     => $faker->company . ' ' . $faker->companySuffix,
            OpenSSLFactory::ORGANIZATIONUNITNAME => $faker->catchPhrase,
            OpenSSLFactory::COMMONNAME           =>
                $faker->firstName . ' ' . strtoupper( $faker->randomLetter ) . ' ' . $faker->lastName,
            OpenSSLFactory::EMAILADDRESS         => $faker->companyEmail
        ];
    }

}
