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
 * Class OpenSSLCryptorTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLCryptor
 *
 * OpenSSLdefaultTest1*
 *   defaults
 *
 * OpenSSLCryptorTest21
 *   OpenSSLCryptor::factory(+__construct),
 *   OpenSSLCryptor::getEncryptedString
 *   OpenSSLCryptor::getDecryptedString
 */
class OpenSSLCryptorTest extends BaseTest
{

    protected static $FILES = [];

    /**
     * @var string  aggregates working (or not) cipher and md algorythms combinations in files
     */
    private static $cipherAndMdOk       = null;
    private static $cipherEncryptErrors = null;
    private static $cipherDecryptErrors = null;

    public static function setUpBeforeClass() {
        parent::setUpBeforeClass();
        if( defined( 'LOG' ) && ( false !== LOG )) {
            $basePath = self::getBasePath() . LOG . DIRECTORY_SEPARATOR;
            if( ! is_dir( $basePath )) {
                mkdir( $basePath );
            }
            $basePath .= 'logs' . DIRECTORY_SEPARATOR;
            if( ! is_dir( $basePath )) {
                mkdir( $basePath );
            }

            self::$cipherAndMdOk = $basePath . 'OpenSSLCryptorCipherAndMdOk.txt';
            file_put_contents( self::$cipherAndMdOk, '' );

            self::$cipherEncryptErrors = $basePath . 'OpenSSLCryptorCipherEncryptErrors.txt';
            file_put_contents( self::$cipherEncryptErrors, '' );

            self::$cipherDecryptErrors = $basePath . 'OpenSSLCryptorCipherDecryptErrors.txt';
            file_put_contents( self::$cipherDecryptErrors, '' );
        }
    }

    /**
     ** Testing OpenSSLCryptor defaults
     *
     * @test
     */
    public function OpenSSLdefaultTest11() {
        $testCryptor     = new OpenSSLCryptor();

        $this->assertEquals(
            $testCryptor->getCipherAlgorithm(),
            'aes-256-ctr',
            '#11, default cipher algo not \'aes-256-ctr\''
        );
        $this->assertEquals(
            $testCryptor->getHashAlgorithm(),
            'sha256',
            '#12, default hash algo not \'sha256\''
        );
        $this->assertEquals(
            $testCryptor->getFormat( true ),
            'base64',
            '#11, default format not \'base64\''
        );
        $testCryptor     = null;

    }

    /**
     ** Testing OpenSSLCryptor factory, getEncryptedString, getDecryptedString with DEFAULT cipher+ md
     *
     * @test
     */
    public function OpenSSLdefaultTest12() {
        $data      = Faker\Factory::create()->paragraphs( 10, true );
        $cryptKey  = Workshop::getSalt();
        $encrypted = OpenSSLCryptor::factory()->getEncryptedString( $data, $cryptKey );
        $decrypted = OpenSSLCryptor::factory()->getDecryptedString( $encrypted, $cryptKey );
        $this->assertEquals(
            $data,
            $decrypted,
            '#12, encrypt/decrypt error, default cipher/md'
        );
    }

    /**
     ** Testing OpenSSLCryptor constructor, getEncryptedString, getDecryptedString with DEFAULT cipher+ md
     *
     * @test
     */
    public function OpenSSLdefaultTest13() {
        $data            = Faker\Factory::create()->paragraphs( 10, true );
        $cryptKey        = Workshop::getSalt();

        $enCryptor       = new OpenSSLCryptor();
        $encrypted       = $enCryptor->getEncryptedString( $data, $cryptKey );
        $enCryptor       = null;


        $deCryptor       = new OpenSSLCryptor();
        $decrypted       = $deCryptor->getDecryptedString( $encrypted, $cryptKey );
        $deCryptor       = null;

        $this->assertEquals(
            $data,
            $decrypted,
            '#13, encrypt/decrypt error, default cipher/md'
        );
    }

    /**
     * OpenSSLCryptorTest21 dataProvider
     *
     * @return array
     */
    public function OpenSSLCryptorTest21Provider() {
        $dataArr = [];
        $case    = 21000;

        $cipherAlgosWithout = openssl_get_cipher_methods();               // without aliases
        sort( $cipherAlgosWithout );
        $cipherAlgosWith    = openssl_get_cipher_methods( true );  // with aliases
        sort( $cipherAlgosWith );

        $mdAlgosWithout     = openssl_get_md_methods();                   // without aliases
        sort( $mdAlgosWithout);
        $mdAlgosWith        = openssl_get_md_methods( true );      // with aliases
        sort( $mdAlgosWith );

        $openSLLmode = 0;

        switch( $openSLLmode ) {
            case 1 :
                $cipherAlgos = [ 'aes-256-ctr' ];    // default
                $mdAlgos     = $mdAlgosWithout;      // without aliases
                break;
            case 2 :
                $cipherAlgos = [ 'aes-256-ctr' ];    // default
                $mdAlgos     = $mdAlgosWith;         // with aliases
                break;
            case 3 :
                $cipherAlgos = $cipherAlgosWithout;  // without aliases
                $mdAlgos     = [ 'sha256' ];         // default
                break;
            case 4 :
                $cipherAlgos = $cipherAlgosWithout;  // without aliases
                $mdAlgos     = $mdAlgosWithout;      // without aliases
                break;
            case 5 :
                $cipherAlgos = $cipherAlgosWithout;  // without aliases
                $mdAlgos     = $mdAlgosWith;         // with aliases
                break;
            case 6 :
                $cipherAlgos = $cipherAlgosWith;     // with aliases
                $mdAlgos     = [ 'sha256' ];         // default
                break;
            case 7 :
                $cipherAlgos = $cipherAlgosWith;     // with aliases
                $mdAlgos     = $mdAlgosWithout;      // without aliases
                break;
            case 8 :
                $cipherAlgos = $cipherAlgosWith;     // with aliases
                $mdAlgos     = $mdAlgosWith;         // with aliases
                break;
            case 10 :
                $cipherAlgos = array_chunk( $cipherAlgosWithout, (int) floor(count( $cipherAlgosWithout ) / 8 ))[7];
                $mdAlgos     = [ 'sha256' ];         // default
                break;
            case 0 :
                // fall through
            default :
                $cipherAlgos = [ 'aes-256-ctr' ];    // default
                $mdAlgos     = [ 'sha256' ];         // default
                break;
        }
        $formats = [ OpenSSLCryptor::FORMAT_RAW, OpenSSLCryptor::FORMAT_B64, OpenSSLCryptor::FORMAT_HEX ];
        foreach( $cipherAlgos as $cipherAlgorithm ) {
            foreach( $mdAlgos as $hashAlgorithm ) {
                $dataArr[] = [
                    ++$case,
                    $cipherAlgorithm,
                    $hashAlgorithm,
                    array_rand( $formats ),
                ];
            } // end foreach
        } // end foreach

        return $dataArr;
    }

    /**
     ** Testing OpenSSLCryptor constructor, factory, getEncryptedString, getDecryptedString
     *
     * @test
     * @dataProvider OpenSSLCryptorTest21Provider
     * @param int    $case
     * @param string $cipherAlgorithm
     * @param string $hashAlgorithm
     * @param int    $fmt
     */
    public function OpenSSLCryptorTest21( $case, $cipherAlgorithm, $hashAlgorithm, $fmt ) {
        static $FMTSTART = '%s = START #%04d, cipherAlgorithm; %s, hashAlgorithm; %s, format: %s, %s';
        static $FMTDSP   = '%s %s #%04d, cipherAlgorithm; %s, hashAlgorithm; %s, format: %s, time: %01.6f, %d/%d chars%s';
        static $FMTERR   = 'Encrypt/decrypt ERROR, cipherAlgorithm: %s, hasdAlgorithm: %s, format %s, data input/output length %d/%d';
        static $cipherEncryptErrors = [];
        static $cipherDecryptErrors = [];
        $doEcho = false;

        if( ( in_array(
            $cipherAlgorithm, [
            'aes-128-ccm',
            'aes-128-gcm',
            'aes-192-ccm',
            'aes-192-gcm',
            'aes-256-ccm',
            'aes-256-gcm',
            'des-cfb1',
            'des-cfb8',
            'des-ecb',
            'des-ede',
            'des-ede-cbc',
            'des-ede-cfb',
            'des-ede-ofb',
            'des-ede3',
            'des-ede3-cbc',
            'des-ede3-cfb',
            'des-ede3-cfb1',
            'des-ede3-cfb8',
            'des-ede3-ofb',
            'des-ofb',
            'desx-cbc',
            'id-aes128-CCM',
            'id-aes128-GCM',
            'id-aes128-wrap',
            'id-aes128-wrap-pad',
            'id-aes192-CCM',
            'id-aes192-GCM',
            'id-aes192-wrap',
            'id-aes192-wrap-pad',
            'id-aes256-CCM',
            'id-aes256-GCM',
            'id-aes256-wrap',
            'id-aes256-wrap-pad',
            'id-smime-alg-CMS3DESwrap',
        ] ))) { // skipped, not working...
            if( $doEcho ) echo ' skip ' . $cipherAlgorithm . PHP_EOL;
            $this->assertTrue( true );
            return;
        }

        $data            = Faker\Factory::create()->paragraphs( 10, true );
        $dataInputStrlen = strlen( $data );
        $key             = Workshop::getSalt();
        $isCipherAlias   =
            ( ! empty( $cipherAlgorithm ) && ! in_array( $cipherAlgorithm, openssl_get_cipher_methods()))
                ? ' (alias) '
                : null;
        $isHashAlias     =
            ( ! empty( $hashAlgorithm ) && ! in_array( $hashAlgorithm, openssl_get_md_methods()))
                ? ' (alias) '
                : null;

        // E N C R Y P T - - - - -
        if( $doEcho ) echo sprintf( $FMTSTART, OpenSSLCryptor::getCm( __METHOD__ ), $case, $cipherAlgorithm, $hashAlgorithm, OpenSSLCryptor::getFormatText( $fmt ), PHP_EOL );
        $enCryptor = OpenSSLCryptor::factory();
        if( ! empty( $cipherAlgorithm )) {
            $enCryptor->setCipherAlgorithm( $cipherAlgorithm );
        }
        if( ! empty( $hashAlgorithm )) {
            $enCryptor->setHashAlgorithm( $hashAlgorithm );
        }
        if( null !== $fmt ) {
            $enCryptor->setFormat( $fmt );
        }

        $startTime = microtime( true );
        try {
            $encrypted       = $enCryptor->getEncryptedString( $data, $key );
            $time            = microtime( true ) - $startTime;
            $encryptedStrlen = strlen( $encrypted );
            if( $doEcho ) echo sprintf(
                $FMTDSP,
                OpenSSLCryptor::getCm( __METHOD__ ),
                'encrypt',
                $case,
                $enCryptor->getCipherAlgorithm(),
                $enCryptor->getHashAlgorithm(),
                $enCryptor->getFormat( true ),
                $time, $dataInputStrlen, $encryptedStrlen, PHP_EOL
            );
        } // end try
        catch( Exception $e ) {
            $exMsg = self::getExceptionmessageAndTrace( $e );
            if( ! empty( self::$cipherEncryptErrors ) &&
              ( ! isset( $cipherEncryptErrors[$cipherAlgorithm] ) ||
                ! in_array( $exMsg, $cipherEncryptErrors[$cipherAlgorithm] ))) {
                $msg = $cipherAlgorithm . ' ' . $case . ' ' . $isCipherAlias . $exMsg . PHP_EOL;
                file_put_contents( self::$cipherEncryptErrors, $msg, FILE_APPEND );
                $cipherEncryptErrors[$cipherAlgorithm][] = $exMsg;
            }
            if( $doEcho ) echo $exMsg;
            $this->assertTrue( true );
            $enCryptor = null;
            return; // continue when error...
        } // end catch
        $enCryptor = null;

            // D E C R Y P T - - - - -
        $decryptedStrlen = 0;
        $deCryptor       = new OpenSSLCryptor();
        if( ! empty( $cipherAlgorithm )) {
            $deCryptor->setCipherAlgorithm( $cipherAlgorithm );
        }
        if( ! empty( $hashAlgorithm )) {
            $deCryptor->setHashAlgorithm( $hashAlgorithm );
        }
        if( null !== $fmt ) {
            $deCryptor->setFormat( $fmt );
        }
        $startTime = microtime( true );
        try {
            $decrypted       = $deCryptor->getDecryptedString( $encrypted, $key );
            $time            = microtime( true ) - $startTime;
            $decryptedStrlen = strlen( $decrypted );
            if( $doEcho ) echo sprintf(
                $FMTDSP,
                OpenSSLCryptor::getCm( __METHOD__ ),
                'decrypt',
                $case,
                $deCryptor->getCipherAlgorithm(),
                $deCryptor->getHashAlgorithm(),
                $deCryptor->getFormat( true ),
                $time, $encryptedStrlen, $decryptedStrlen, PHP_EOL
            );
        } // end try
        catch( Exception $e ) {
            $exMsg = self::getExceptionmessageAndTrace( $e );
            if( ! empty( self::$cipherDecryptErrors ) &&
              ( ! isset( $cipherDecryptErrors[$cipherAlgorithm] ) ||
                ! in_array( $exMsg, $cipherDecryptErrors[$cipherAlgorithm] ))) {
                $msg = $cipherAlgorithm . ' ' . ' ' . $case . ' ' . $isCipherAlias . $exMsg . PHP_EOL;
                file_put_contents( self::$cipherDecryptErrors, $msg, FILE_APPEND );
                $cipherDecryptErrors[$cipherAlgorithm][] = $exMsg;
            }
            if( $doEcho ) echo $exMsg . PHP_EOL;
            $this->assertTrue( true );
            $deCryptor       = null;
            return; // continue when error...
        } // end catch
        $cipherAlgorithm = $deCryptor->getCipherAlgorithm();
        $hashAlgorithm   = $deCryptor->getHashAlgorithm();
        $format          = $deCryptor->getFormat( true );
        $deCryptor       = null;

        // Evaluate result
        $this->assertEquals(
            $data,
            $decrypted,
            sprintf(
                $FMTERR,
                $cipherAlgorithm,
                $hashAlgorithm,
                $format,
                $dataInputStrlen,
                $decryptedStrlen,
                PHP_EOL
            )
        );
            // record successful cipher and hash algorithms
        if(( $data == $decrypted ) && ! empty( self::$cipherAndMdOk )) {
            $msg = $cipherAlgorithm . ' ' . $isCipherAlias . ' - ' . $hashAlgorithm . $isHashAlias . PHP_EOL;
            file_put_contents( self::$cipherAndMdOk, $msg, FILE_APPEND );
        } // end if
    }


}

