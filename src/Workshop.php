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
use RuntimeException;

use function bin2hex;
use function file_get_contents;
use function file_put_contents;
use function fseek;
use function get_resource_type;
use function gettype;
use function is_null;
use function is_resource;
use function openssl_random_pseudo_bytes;
use function sprintf;
use function stream_get_contents;
use function stream_get_meta_data;
use function strpbrk;
use function strpos;
use function sys_get_temp_dir;
use function substr;

/**
 * Class Workshop
 */
class Workshop extends BaseFactory
{
    /**
     * $var string
     * @static
     */
    public static $FILEPROTO = 'file://';

    /**
     * $var string  file resource type
     * @access private
     * @static
     */
    private static $STREAM = 'stream';

    /** ***********************************************************************
     *  Resource methods
     ** ******************************************************************** */

    /**
     * Return (key) metadata from streams/file pointers
     *
     * @param resource $resource
     * @param string $key
     * @return array|string (null if key if not found)
     * @static
     */
    public static function getResourceMetadata( $resource, $key = null ) {
        $metaData = stream_get_meta_data( $resource );
        if( empty( $key )) {
            return $metaData;
        }
        return ( isset( $metaData[$key] )) ? $metaData[$key] : null;
    }

    /**
     * Return resource type
     *
     * @param string|resource $resource
     * @return string
     * @static
     */
    public static function getResourceType( $resource ) {
        switch( true ) {
            case ( is_null( $resource )) :
                return null;
                break;
            case ( is_resource( $resource )) :
                return get_resource_type( $resource );
                break;
            default :
                return gettype( $resource );
        }
    }

    /**
     * Return bool true if resource is a file resource
     *
     * @param resource $resource
     * @return bool
     * @static
     */
    public static function isFileResource( $resource ) {
        return ( self::$STREAM == self::getResourceType( $resource ));
    }

    /**
     * Return bool true if resource is readable
     *
     * @param resource $resource
     * @return bool
     * @static
     */
    public static function isResourceReadable( $resource ) {
        static $MODE  = 'mode';
        static $READC = 'r+';
        return ( false !== strpbrk( self::getResourceMetadata( $resource, $MODE ), $READC ));
    }

    /**
     * Return bool true if resource is writeable
     * @param resource $resource
     * @return bool
     * @static
     */
    public static function isResourceWritable( $resource ) {
        static $MODE   = 'mode';
        static $WRITEC = 'waxc+';
        return ( false !== strpbrk( self::getResourceMetadata( $resource, $MODE ), $WRITEC ));
    }

    /**
     * Return resource contents
     *
     * @param resource $resource
     * @param int|string $argIx
     * @return string
     * @throws RuntimeException
     * @static
     */
    public static function getResourceContents( $resource, $argIx = null ) {
        static $FMTERR1 = 'Resource is not readable';
        static $FMTERR2 = 'Resource seek error';
        static $FMTERR3 = 'Resource read content error';
        if( ! self::isResourceReadable( $resource )) {
            throw new RuntimeException( $FMTERR1 . self::getErrArgNoText( $argIx ));
        }
        if( -1 == fseek( $resource, 0, SEEK_SET )) {
            throw new RuntimeException( $FMTERR3 . self::getErrArgNoText( $argIx ));
        }
        $data = stream_get_contents( $resource );
        if( false === $data ) {
            throw new RuntimeException( $FMTERR2, self::getErrArgNoText( $argIx ));
        }
        return $data;
    }

    /**
     * Write data into (file) resource
     *
     * @param resource $resource
     * @param string   $data
     * @throws RuntimeException
     * @static
     */
    public static function writeToResource( $resource, $data ) {
        static $FMT = 'File resource write error (#%d)';
        $result     = null;
        if( ! self::isResourceReadable( $resource )) {
            $result = 1;
        }
        elseif( false === rewind( $resource ) ) {
            $result = 2;
        }
        elseif( empty( fwrite( $resource, $data ) ) ) {
            $result = 3;
        }
        if( ! empty( $result )) {
            throw new RuntimeException( sprintf( $FMT, $result ));
        }
    }

    /** ***********************************************************************
     *  File/Resource  methods
     ** ******************************************************************** */

    /**
     * Return file (resource) content
     *
     * @param string|resource $fileName
     * @param int|string $argIx
     * @return string
     * @throws InvalidArgumentException
     * @static
     */
    public static function getFileContent( $fileName, $argIx = null ) {
        static $FMT = 'Can\'t read \'%s\'%s';
        if( is_resource( $fileName )) {
            return self::getResourceContents( $fileName );
        }
        Assert::fileNameRead( $fileName, $argIx );
        $fileName = self::getFileWithoutProtoPrefix( $fileName );
        $content = file_get_contents( $fileName );
        if( false === $content ) {
            throw new InvalidArgumentException( sprintf( $FMT, $fileName, self::getErrArgNoText( $argIx )));
        }
        return $content;
    }

    /**
     * Save data into file (resource)
     *
     * @param string|resource $fileName
     * @param string $data
     * @param int    $flags
     * @param resource $context
     * @throws RuntimeException
     * @static
     * @todo https://www.php.net/manual/en/function.file-put-contents.php#123657
     */
    public static function saveDataToFile( $fileName, $data, $flags = null, $context = null ) {
        static $FMT = 'File write error ($%d) : %s';
        if( self::isFileResource( $fileName )) {
            self::writeToResource( $fileName, $data );
            return;
        }
        $result = null;
        switch( true ) {
            case ( empty( $flags ) && empty( $context )) :
                if( false === file_put_contents( $fileName, $data )) {
                    $result = 3;
                }
                break;
            case  empty( $context ) :
                if( false === file_put_contents( $fileName, $data, $flags )) {
                    $result = 4;
                }
                break;
            default :
                if( false === file_put_contents( $fileName, $data, $flags, $context )) {
                    $result = 5;
                }
                break;
        } // end switch
        if( ! empty( $result )) {
            throw new RuntimeException( sprintf( $FMT, $result, $fileName ));
        }
    }

    /** ***********************************************************************
     *  File  methods
     ** ******************************************************************** */

    /**
     * Return a new (and touched file), opt with ext, mode default 0600, if exists, it's cleared
     *
     * @param string $unique
     * @param string $ext
     * @param int    $mode (oct)  default 0600
     * @return string
     * @static
     */
    public static function getNewFileInTmp( $unique, $ext = null, $mode = 0600 ) {
        static $DOT = '.';
        $fileName   = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $unique;
        if( ! empty( $ext )) {
            $fileName .= $DOT . $ext;
        }
        touch( $fileName );
        chmod( $fileName, $mode );
        self::saveDataToFile( $fileName, null );
        return $fileName;
    }

    /**
     * Return fileName without 'file://'-prefix
     *
     * @param string $fileName
     * @return bool
     * @static
     */
    public static function getFileWithoutProtoPrefix( $fileName ) {
        return self::hasFileProtoPrefix( $fileName ) ? substr( $fileName, 7 ) : $fileName;
    }

    /**
     * Return bool true if file has 'file://'-prefix
     *
     * @param string $fileName
     * @return bool
     * @static
     */
    public static function hasFileProtoPrefix( $fileName ) {
        return ( 0 == strcasecmp( self::$FILEPROTO, substr( $fileName, 0, 7 )));
    }

    /** ***********************************************************************
     *  Misc
     ** ******************************************************************** */

    /**
     * Return cryptographically strong arg byteCnt bytes - uses openssl_random_pseudo_bytes
     *
     * @param int $byteCnt
     * @param bool $cStrong
     * @return string
     * @static
     */
    public static function getRandomPseudoBytes( $byteCnt, & $cStrong = false ) {
        static $MAX = 10;
        $cnt = 0;
        do {
            $bytes = openssl_random_pseudo_bytes( $byteCnt, $cStrong );
            $cnt += 1;
        } while(( $MAX > $cnt ) && ( false === $cStrong ));
        return $bytes;
    }

    /**
     * Return (hex) cryptographically strong salt, default 64 bytes
     *
     * @param int $byteCnt
     * @return string
     * @static
     */
    public static function getSalt( $byteCnt = null ) {
        if( empty( $byteCnt )) {
            $byteCnt = 64;
        }
        $byteCnt2 = (int) floor( $byteCnt / 2 );
        return bin2hex( self::getRandomPseudoBytes( $byteCnt2 ));
    }

    /**
     * Return (trailing)) algorithm from (URI) identifier
     *
     * @param string $identifier
     * @return string
     * @throws InvalidArgumentException
     * @static
     */
    public static function getAlgorithmFromIdentifier( $identifier ) {
        static $HASH  = '#';
        static $SLASH = '/';
        static $FMT   = 'Algorithm not found in \'%s\'';
        if( $SLASH == substr( $identifier, -1 )) {
            $identifier = substr( $identifier, 0, -1 );
        }
        if( false !== ( $pos = strpos( $identifier, $HASH ))) {
            return substr( $identifier, ( $pos + 1 ));
        }
        if( false !== ( $pos = strrpos( $identifier, $SLASH ))) {
            return substr( $identifier, ( $pos + 1 ));
        }
        throw new InvalidArgumentException( sprintf( $FMT, $identifier ));
    }
}
