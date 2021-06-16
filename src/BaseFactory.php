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
 *
 *            Disclaimer of rights
 *
 *            Herein may exist software logic (hereafter solution(s)) found on internet
 *            (hereafter originator(s)). The rights of each solution belongs to
 *            respective originator;
 *
 *            Credits and acknowledgements to originators!
 *            Links to originators are found wherever appropriate.
 *
 *            Only OpenSSLToolbox copyright holder works, OpenSSLToolbox author(s) works
 *            and solutions derived works and OpenSSLToolbox collection of solutions are
 *            covered by GNU Lesser General Public License, above.
 */
declare( strict_types = 1 );
namespace Kigkonsult\OpenSSLToolbox;

use InvalidArgumentException;

use function in_array;
use function is_null;
use function sprintf;
use function str_pad;
use function strrpos;
use function substr;

abstract class BaseFactory
{
    /**
     * @var callable
     */
    public static $ERRORHANDLER = [ 'Kigkonsult\OpenSSLToolbox\PhpErrorException', 'PhpErrors2Exception' ];

    /**
     * Assert algorithm - matched returned
     *
     * @param array      $algorithms
     * @param string     $algorithm
     * @param null|bool  $strict     if false : anycase search
     * @throws InvalidArgumentException
     * @return string  - found algorithm
     */
    protected static function baseAssertAlgorithm(
        array $algorithms,
        string $algorithm,
        $strict = false
    ) : string
    {
        static $FMTERR = 'Algorithm %s is not found';
        if( in_array( $algorithm, $algorithms, true )) {
            return $algorithm;
        }
        $strict = Assert::bool( $strict, 3, false );
        if( ! $strict ) {
            foreach( $algorithms as $supported ) {
                if( 0 == strcasecmp( $algorithm, $supported )) {
                    return $supported;
                }
            }
        }
        throw new InvalidArgumentException( sprintf( $FMTERR, $algorithm ));
    }

    /**
     * Return class(+method) from FQCN
     *
     * @param string $method
     * @return string
     */
    public static function getCm( string $method ) : string
    {
        static $DB = '\\';
        return substr( $method, ( strrpos( $method,  $DB ) + 1 ));
    }

    /**
     * @return string
     */
    public static function initClassStr() : string
    {
        static $FMTINIT = 'INIT %s, %s';
        static $PAD     = ' -';
        return str_pad(
            sprintf( $FMTINIT, self::getCm( get_called_class()), OPENSSL_VERSION_TEXT ),
            80,
            $PAD
        );
    }

    /**
     * Return string with (error) argument number
     *
     * @param null|int|string $argIx
     * @return string
     */
    public static function getErrArgNoText( $argIx = null ) : string
    {
        static $FMTARG = ' (argument #%s)';
        return ( empty( $argIx )) ? '' : sprintf( $FMTARG, $argIx );
    }

    /** ***********************************************************************
     *  Array properties operations; config, DN etc
     *
     * @param array $source
     * @param null  $key
     * @param null  $subKey
     * @return array|mixed|null
     */

    /*
     * Return source (key(/subkey)) value, null on not found
     *
     * @param array $source
     * @param null|string $key      see OpenSSLInterface constants
     * @param null|string $subKey   see OpenSSLInterface constants
     * @return null|array|string    null on not found
     * @throws InvalidArgumentException
     */
    protected static function getSource( array $source, $key = null, $subKey = null )
    {
        if( empty( $source )) {
            return null;
        }
        if( empty( $key )) {
            return $source;
        }
        Assert::string( $key );
        if( ! isset( $source[$key] )) {
            return null;
        }
        if( ! empty( $subKey )) {
            Assert::string( $subKey );
            return ( isset( $source[$key][$subKey] )) ? $source[$key][$subKey] : null;
        }
        return $source[$key];
    }

    /*
     * Return bool true if array key (/subkey) is set
     *
     * @param array $source
     * @param null|string $key      see OpenSSLInterface constants
     * @param null|string $subKey   see OpenSSLInterface constants
     * @return bool                 true if found
     * @throws InvalidArgumentException
     */
    protected static function isSourceKeySet(
        array $source,
        $key = null,
        $subKey = null
    ) : bool
    {
        return ( ! is_null( self::getSource( $source, $key, $subKey )));
    }
}
