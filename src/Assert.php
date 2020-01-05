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

use function clearstatcache;
use function dirname;
use function is_dir;
use function is_file;
use function var_export;
use function is_null;
use function is_resource;
use function is_writeable;
use function sprintf;

/**
 * Class Assert . more general asserts
 */
class Assert
{

    /**
     * $var string
     * @access private
     * @static
     */
    private static $FMT4  = 'Resource not stream';

    /**
     * Assert data is a boolean and return bool, accepts true/false/1/0
     *
     * @param mixed $data
     * @param int|string $argIx
     * @param bool $valueIfNull
     * @return bool
     * @throws InvalidArgumentException
     * @static
     */
    public static function bool( $data, $argIx = null, $valueIfNull = null ) {
        static $FMT2 = 'bool expected%s, got \'%s\'';
        switch( true ) {
            case is_bool( $data ) :
                break;
            case ( 1 === $data ) :
                $data = true;
                break;
            case ( 0 === $data ) :
                $data = false;
                break;
            case ( is_null( $data )) :
                $data = $valueIfNull;
                break;
            default :
                throw new InvalidArgumentException(
                    sprintf( $FMT2, BaseFactory::getErrArgNoText( $argIx ), var_export( $data, true ))
                );
                break;
        }
        return $data;
    }

    /**
     * Assert data is an positiv integer (scalar) and return int
     *
     * @param mixed $data
     * @param int|string $argIx
     * @param int $valueIfNull
     * @return int
     * @static
     *@throws InvalidArgumentException
     */
    public static function int( $data, $argIx = null, $valueIfNull = null ) {
        static $FMT2 = 'Int expected%s, got \'%s\'';
        if( is_null( $data )) {
            return $valueIfNull;
        }
        if( ! ctype_digit( (string) $data ) || ( 0 > $data )) {
            throw new InvalidArgumentException(
                sprintf( $FMT2, BaseFactory::getErrArgNoText( $argIx ), var_export( $data, true ))
            );
        }
        return intval( $data );
    }

    /**
     * Assert data is a string (i.e. is a scalar) and return string
     *
     * @param mixed      $data
     * @param int|string $argIx
     * @param string     $valueIfNull
     * @return string
     * @static
     *@throws InvalidArgumentException
     */
    public static function string( $data, $argIx = null, $valueIfNull = null ) {
        static $FMT2 = 'String expected%s, got \'%s\'';
        if( is_null( $data )) {
            return $valueIfNull;
        }
        if( ! is_scalar( $data )) {
            throw new InvalidArgumentException(
                sprintf( $FMT2, BaseFactory::getErrArgNoText( $argIx ), var_export( $data, true ))
            );
        }
        return (string) $data;
    }

    /**
     * Assert (path/)fileName is a (local) file or file resource
     *
     * @param string|resource $fileName
     * @param int|string $argIx
     * @throws InvalidArgumentException
     * @static
     * @todo traverse pathinfo until existing path is found...
     */
    public static function fileName( $fileName, $argIx = null ) {
        static $FMT1 = '%s is no file';
        switch( true ) {
            case ( ! is_resource( $fileName )) :
                break;
            case ( ! Workshop::isFileResource( $fileName )) :
                throw new InvalidArgumentException( self::$FMT4 . BaseFactory::getErrArgNoText( $argIx ));
                break;
            default :
                return;
                break;
        } // end switch
        self::string( $fileName, $argIx );
        switch( true ) {
            case  @is_file( $fileName ) : // but may not yet exist...
                break;
            case  @is_dir( dirname( $fileName )) :
                break;
            default :
                throw new InvalidArgumentException(
                    sprintf( $FMT1, $fileName ) . BaseFactory::getErrArgNoText( $argIx )
                );
                break;
        }
        clearstatcache( $fileName );
    }

    /**
     * Assert (path/)fileName is a readable (local) file (resource)
     *
     * @param string|resource $fileName
     * @param int|string $argIx
     * @throws InvalidArgumentException
     */
    public static function fileNameRead( $fileName, $argIx = null ) {
        static $FMT2 = 'Resource (type %s) is not readable';
        static $FMT7 = 'File expected, got directory %s';
        static $FMT8 = 'File %s is not readable';
        switch( true ) {
            case ( ! is_resource( $fileName )) :
                break;
            case ( ! Workshop::isFileResource( $fileName )) :
                throw new InvalidArgumentException( self::$FMT4 . BaseFactory::getErrArgNoText( $argIx ));
                break;
            case Workshop::isResourceReadable( $fileName ) :
                return;
                break;
            default;
                throw new InvalidArgumentException(
                    sprintf( $FMT2, Workshop::getResourceType( $fileName ) . BaseFactory::getErrArgNoText( $argIx ))
                );
                break;
        } // end if
        self::string( $fileName, $argIx );
        $fileName = Workshop::getFileWithoutProtoPrefix( $fileName );
        switch( true ) {
            case @is_dir( $fileName ) :
                throw new InvalidArgumentException(
                    sprintf( $FMT7, $fileName ). BaseFactory::getErrArgNoText( $argIx )
                );
                break;
            case @is_readable( $fileName ) :
                break;
            default :
                throw new InvalidArgumentException(
                    sprintf( $FMT8, $fileName ). BaseFactory::getErrArgNoText( $argIx )
                );
                break;
        }
        clearstatcache( true, $fileName );
    }

    /**
     * Assert (path/)fileName is a writable (local) file (resource)
     *
     * @param string|resource $fileName
     * @param int|string $argIx
     * @throws InvalidArgumentException
     * @todo check path top level and down, file may not yet exist
     */
    public static function fileNameWrite( $fileName, $argIx = null ) {
        static $FMT1 = 'Resource not readable';
        static $FMT2 = 'file %s is not writeable';
        switch( true ) {
            case ( ! is_resource( $fileName )) :
                break;
            case ( ! Workshop::isFileResource( $fileName )) :
                throw new InvalidArgumentException( self::$FMT4 . BaseFactory::getErrArgNoText( $argIx ));
                break;
            case ( ! Workshop::isResourceWritable( $fileName )) :
                throw new InvalidArgumentException( $FMT1 . BaseFactory::getErrArgNoText( $argIx ));
                break;
            default :
                return;
                break;
        } // end switch
        self::string( $fileName, $argIx );
        $fileName = Workshop::getFileWithoutProtoPrefix( $fileName );
        if( ! is_writeable( $fileName ) && ! is_writeable( dirName( $fileName ))) {
            throw new InvalidArgumentException(
                sprintf( $FMT2, $fileName ) . BaseFactory::getErrArgNoText( $argIx )
            );
        }
        clearstatcache( $fileName );
    }

}
