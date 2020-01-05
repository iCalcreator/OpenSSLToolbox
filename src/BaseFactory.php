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
 *   along with OpenSSLToolbox. If not, see <https://www.gnu.org/licenses/>.
 *
 * Disclaimer of rights
 *
 *   Herein may exist software logic (hereafter solution(s)) found on internet
 *   (hereafter originator(s)). The rights of each solution belongs to
 *   respective originator;
 *
 *   Credits and acknowledgements to originators!
 *   Links to originators are found wherever appropriate.
 *
 *   Only OpenSSLToolbox copyright holder works, OpenSSLToolbox author(s) works
 *   and solutions derived works and OpenSSLToolbox collection of solutions are
 *   covered by GNU Lesser General Public License, above.
 */
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
     * @static
     */
    public static $ERRORHANDLER = [ 'Kigkonsult\OpenSSLToolbox\PhpErrorException', 'PhpErrors2Exception' ];

    /**
     * Assert algorithm - matched returned
     *
     * @param array  $algorithms
     * @param string $algorithm
     * @param bool   $strict     -  if false : anycase search
     * @throws InvalidArgumentException
     * @return string  - found algorithm
     * @access protected
     * @static
     */
    protected static function baseAssertAlgorithm( array $algorithms, $algorithm, $strict = false ) {
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
     * @param $method
     * @return string
     * @static
     */
    public static function getCm( $method ) {
        static $DB = '\\';
        return substr( $method, ( strrpos( $method,  $DB ) + 1 ));
    }

    /**
     * @return string
     * @static
     */
    public static function initClassStr() {
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
     * @param int|string $argIx
     * @return string
     * @static
     */
    public static function getErrArgNoText( $argIx = null ) {
        static $FMTARG = ' (argument #%s)';
        return ( empty( $argIx )) ? null : sprintf( $FMTARG, $argIx );
    }

    /** ***********************************************************************
     *  Array properties operations; config, DN etc
     */

    /*
     * Return source (key(/subkey)) value, null on not found
     *
     * @param array $source
     * @param string $key      see OpenSSLInterface constants
     * @param string $subKey   see OpenSSLInterface constants
     * @return array|string    null on not found
     * @throws InvalidArgumentException
     * @access protected
     * @static
     */
    protected static function getSource( $source, $key = null, $subKey = null ) {
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
     * @param string $key      see OpenSSLInterface constants
     * @param string $subKey   see OpenSSLInterface constants
     * @return bool            true if found
     * @throws InvalidArgumentException
     * @access protected
     * @static
     */
    protected static function isSourceKeySet( $source, $key = null, $subKey = null ) {
        return ( ! is_null( self::getSource( $source, $key, $subKey )));
    }

}
