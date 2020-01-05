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

use Exception;

/**
 * Class PhpErrorException
 *
 * @see https://www.php.net/manual/en/class.errorexception.php#89132
 */
class PhpErrorException extends Exception
{
    /**
     * Throw PHP errors as PhpErrorException
     *
     * @param int    $errno
     * @param string $errstr
     * @param string $errfile
     * @param int    $errline
     * @throws PhpErrorException
     * @static
     */
    public static function PhpErrors2Exception( $errno, $errstr, $errfile, $errline ) {
        static $FMT = '%s, %s, %s:%d';
        $message = sprintf( $FMT, PhpErrorException::getSeverityText( $errno ), $errstr, $errfile, $errline );
        throw new PhpErrorException( $message, 0, $errno, $errfile, $errline );
    }

    /**
     * @var int
     * @access protected
     */
    protected $severity;

    /**
     * @var array
     * @access private
     */
    private static $errorTexts = [
        E_ERROR             => 'ErrorException',
        E_WARNING           => 'Warning',
        E_PARSE             => 'Parse',
        E_NOTICE            => 'Notice',
        E_CORE_ERROR        => 'CoreError',
        E_CORE_WARNING      => 'CoreWarning',
        E_COMPILE_ERROR     => 'CompileError',
        E_COMPILE_WARNING   => 'CoreWarning',
        E_USER_ERROR        => 'UserError',
        E_USER_WARNING      => 'UserWarning',
        E_USER_NOTICE       => 'UserNotice',
        E_STRICT            => 'Strict',
        E_RECOVERABLE_ERROR => 'RecoverableError',
        E_DEPRECATED        => 'Deprecated',
        E_USER_DEPRECATED   => 'UserDeprecated',
    ];

    /**
     * Class constructor
     *
     * @param string $message
     * @param int    $code
     * @param int    $severity
     * @param string $filename
     * @param int    $lineno
     */
    public function __construct( $message, $code, $severity, $filename, $lineno ) {
        $this->message  = $message;
        $this->code     = $code;
        $this->severity = $severity;
        $this->file     = $filename;
        $this->line     = $lineno;
    }

    /**
     * Return severity
     *
     * @return int
     */
    public function getSeverity() {
        return $this->severity;
    }

    /**
     * Return severity text
     *
     * @param int $errorNo
     * @return string
     * @static
     */
    public static function getSeverityText( $errorNo ) {
        static $unknown = 'Unknown error';
        return ( isset( self::$errorTexts[$errorNo] )) ? self::$errorTexts[$errorNo] : $unknown;
    }
}
