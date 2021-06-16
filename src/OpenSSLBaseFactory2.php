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

use function intval;
use function is_scalar;
use function is_array;
use function sprintf;
use function var_export;

/**
 * Class OpenSSLBaseFactory2
 *
 * Manages configArgs for CsrFactory and PkeyFactory
 */
abstract class OpenSSLBaseFactory2 extends OpenSSLBaseFactory
{
    /**
     * Assert algorithm and config[bits] >= 384
     *
     * Algorithms in 'OpenSSLFactory::$SIGNATUREALGOS' or openssl_get_md_methods()
     * Ciphers in 'OpenSSLFactory::$CIPHERS
     *
     * @link https://www.php.net/manual/en/function.openssl-pkey-new.php#116765
     * @link https://www.php.net/manual/en/function.openssl-pkey-new.php#102392
     * @param array $configArgs
     * @throws InvalidArgumentException
     */
    protected static function assertConfig( array $configArgs )
    {
        static $FMT = 'The minimum number of bits is (int) 384, now %s';
        if( isset( $configArgs[self::DIGESTALGO] )) {
            if( ! isset( self::$SIGNATUREALGOS[$configArgs[self::DIGESTALGO]] )) {
                self::assertMdAlgorithm( $configArgs[self::DIGESTALGO] );
            }
        }
        if( isset( $configArgs[self::ENCRYPTKEYCIPHER] )) {
            self::assertCipherId( $configArgs[self::ENCRYPTKEYCIPHER] );
        }
        if( ! isset( $configArgs[self::PRIVATEKEYBITS] )) {
            return;
        }
        if( ! is_scalar( $configArgs[self::PRIVATEKEYBITS] )) {
            throw new InvalidArgumentException(
                sprintf( $FMT, var_export( $configArgs[self::PRIVATEKEYBITS], true ))
            );
        }
        $keyBits = intval( $configArgs[self::PRIVATEKEYBITS] );
        if( empty( $keyBits )) {
            throw new InvalidArgumentException(
                sprintf( $FMT, var_export( $configArgs[self::PRIVATEKEYBITS], true  ))
            );
        }
        if( 384 > $keyBits ) {
            throw new InvalidArgumentException(
                sprintf( $FMT, $configArgs[self::PRIVATEKEYBITS] )
            );
        }
    }

    /**
     * @var array
     */
    protected $config = [];

    /**
     * @param string|array  $config    If null, return 'instance create'-configArgs, if set
     *                                 if string, see OpenSSLInterface constants
     * @return bool|string|array       null if (key is) not found
     * @throws InvalidArgumentException
     */
    public function getConfig( $config = null )
    {
        if( ! empty( $config ) && is_array( $config )) {
            return $config;
        }
        return parent::getSource( $this->config, $config );
    }

    /**
     * @param null|string $key      see OpenSSLInterface constants
     * @return bool
     */
    public function isConfigSet( $key = null ) : bool
    {
        return parent::isSourceKeySet( $this->config, $key );
    }

    /**
     * @param string $key  see OpenSSLInterface constants
     * @param mixed  $value
     * @return static
     * @throws InvalidArgumentException
     */
    public function addConfig( string $key, $value ) : self
    {
        Assert::string( $key );
        self::assertConfig( [ $key => $value ] );
        if( self::PRIVATEKEYBITS == $key ) {
            $value = intval( $value );
        }
        $this->config[$key] = $value;
        return $this;
    }

    /**
     * @param array $config
     * @return static
     * @throws InvalidArgumentException
     */
    public function setConfig( array $config ) : self
    {
        foreach( $config as $key => $value ) {
            $this->addConfig( $key, $value );
        }
        return $this;
    }
}
