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
 */
namespace Kigkonsult\OpenSSLToolbox;

use Exception;
use Katzgrau\KLogger\Logger as KLogger;
use Kigkonsult\LoggerDepot\LoggerDepot;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;
use Psr\Log\NullLogger;

/**
 * Class BaseTest
 */
abstract class BaseTest extends TestCase
{

    protected static $FILES = [];


    public static function getBasePath() {
        $dir0 = $dir = __DIR__;
        $level = 6;
        while( ! is_dir( $dir . DIRECTORY_SEPARATOR . 'test' )) {
            $dir = realpath( $dir . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR );
            if( false == $dir ) {
                $dir = $dir0;
                break;
            }
            $level -= 1;
            if( empty( $level )) {
                $dir = $dir0;
                break;
            }
        } // end while
        return $dir . DIRECTORY_SEPARATOR;
    }

    public static function setUpBeforeClass() {
        if( defined( 'LOG' ) && ( false !== LOG )) {
            $basePath = self::getBasePath() . LOG;
            if( ! is_dir( $basePath )) {
                mkdir( $basePath );
            }
            $basePath .= DIRECTORY_SEPARATOR . 'logs';
            if( ! is_dir( $basePath )) {
                mkdir( $basePath );
            }
            $fileName = OpenSSLFactory::getCm( get_called_class()) . '.log';
            $pathFile = $basePath . DIRECTORY_SEPARATOR . $fileName;
            touch( $pathFile );
            file_put_contents( $pathFile, '' ); // clear content (if exists)
            $logger   = new KLogger(
                $basePath,
                LogLevel::DEBUG,
                [ 'filename' => $fileName ]
            );
        }
        else {
            $logger = new NullLogger();
        }
        LoggerDepot::registerLogger( __NAMESPACE__, $logger );
    }

    public static function tearDownAfterClass() {
        foreach( LoggerDepot::getLoggerKeys() as $key ) {
            LoggerDepot::unregisterLogger( $key );
        }
        $class = get_called_class();
        foreach( $class::$FILES as $file ) {
            if( is_file( $file )) {
                unlink( $file );
            }
            elseif( is_dir( $file )) {
                rmdir( $file );
            }
        }
        $class::$FILES = [];
    }

    public static function getExceptionmessageAndTrace( Exception $e ) {
        static $DB = '\\';
        $name = get_class( $e );
        $msg  = ( false === strpos( $name, $DB )) ? $name . ' ' : '(' . substr( $name, ( strrpos( $name, $DB ) + 1 )) . ') ';
        $msg .= $e->getMessage() . PHP_EOL .$e->getTraceAsString() . PHP_EOL;
        $prev = $e->getPrevious();
        if( ! empty( $prev )) {
            $name = get_class( $prev );
            $msg  = ( false === strpos( $name, $DB )) ? $name . ' ' : '(' . substr( $name, ( strrpos( $name, $DB ) + 1 )) . ') ';
            $msg .= $prev->getMessage() . PHP_EOL . $prev->getTraceAsString() . PHP_EOL;
        }
        return $msg;
    }

    public static function getFileName( $unique, $ext = 'pem' ) {
        $fileName = Workshop::getNewFileInTmp( $unique, $ext, 0755 );
        $class    = get_called_class();
        array_push( $class::$FILES, $fileName );
        return $fileName;
    }

}
