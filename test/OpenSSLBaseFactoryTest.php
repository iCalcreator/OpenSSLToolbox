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
use Kigkonsult\LoggerDepot\LoggerDepot;
use Psr\Log\NullLogger;

/**
 * Class OpenSSLBaseFactoryTest
 *
 * @covers \Kigkonsult\OpenSSLToolbox\OpenSSLBaseFactory
 *
 * isPemTest11                    -  isPemString/getStringPemType/isPemFile/getFilePemType
 * assertPemTest12                -  assertPemString/assertPemFile
 * pem2Der2PemTest13a             -  pem2Der/der2Pem
 * pem2DerTest13b                 -  pem2Der - catch exception
 * der2PemTest13c                 -  der2Pem - catch exception
 * pem2DerASN1Test14              -  pem2DerASN1
 * assertPassPhraseTest15         -  assertPassPhrase
 * assertResourceFileStringPemTest16  -  Testing assertResourceFileStringPem
 * assertMdAlgorithmTest1a        -  assertMdAlgorithm/assertCipherAlgorithm
 *                                   (Traits\assertMdCipherAlgorithmTrait)
 * assertCipherIdTest17           -  assertCipherId - catch exception
 * getOpenSSLErrorsTest18         -  Testing getOpenSSLErrors
 * assessCatchTest19              -  assessCatch
 * logAndThrowRuntimeException20  -  logAndThrowRuntimeException
 */
class OpenSSLBaseFactoryTest extends OpenSSLTest
{

    protected static $FILES = [];

    protected static $privateKeyString1 = '-----BEGIN PRIVATE KEY-----
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
PvcEFpVXVHj0vJP7S3ZW/G7ddvxJR6fs
-----END PRIVATE KEY-----
';
    protected static $privateKeyString2 = '-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIIxeh8wgkhyMCAggA
MBQGCCqGSIb3DQMHBAj3vywgjYGiBQSCBMjTDJsvsaovLleIwD5SssgnU2EGFx4w
b3LSp+hQmB/Q8iFFUib6gsi75OplzGXmg9mTJXbe8StslD3P6O0/CFAe7TvPgwX3
vpMG2A4jTfY2ruRJg24vpjm0GEOKPnyrKodB8g07lW+XRT+kcWyyiS68NA1TY5eM
+EsyDrv3F3qOwKerByU2r8ggYnbad0OwEkwQb5DUx0safDpMSOCpw0NDingrfX7h
Fo7jtJrxt9djH0erHxIm3/VJm+qIVbF+PC0mLTIuSKYK6bk0a54ItxQ6jb+as5O/
vYsJVRaRB7Ti+NwoaM8K9Nj14D7GurUlZDSghgIZxymdmoW33AYX3B2zdzGwvF5J
o1EZhy5hWGYlRLuNMnil9Ug6VmEsImFK3RmTplDoM/uDat5+zDe9EROS4KUNtIAV
9iLRyi4wWrDfHjwB22Q37fgcXV+itdSRiHT/FIZXiz3wVcbaAH4ziqxX5J6w6S3P
NMSyVVm3zBTf4TSVLF2HVoFQRKUrnlNxzcUN3b8nhbCOnJe5hpXHK4JEdwkQoRn5
5dTo1E4foaijSZaR/E4dpz43PixlVwbXUN+s1DqtijwJaFZ/9nakkR3OXJsB0+8E
mxe/wtAoImWwTKEp13hkJfazBp3lq1NGHPjgvZC1N3FSrlK88Y/mN5TxgVASU6B4
AhH9svo40iixfkcIZEAXi+MWH1wjh8UWn48fEAt1bKZbYlBexllfag9mIzf+XkEr
XLjIOsaPckTjW1R6lFKZx0O7YRpjY26+C2rx8qgl5Mz/+byNfVbQbdiN+UN9qiQo
gNZUwC62iAbPSS/P7faQSda17N6Jz4iBwx+i/1Y/5xzpnLgryog9mDWTUTbItS+4
iX3RdGmULTEbD4Trq6NQkffCy8nTDYwbXGbj9fy2Swml2PaYUCxb639UKCr7aMRm
IKLP+jYcL9Etjurfj1HsOlXls3TqI0JCeIPKfOBC7py1kviiFzJL14affdJtKO2X
dWAmxM2HksYYSOX9sPae2GvDNb8xxGci5QpwpfhyKL0Xp2aS2ADxg0u24dQhNDPS
IYNsYitWuFDmdmaTlLzWAeCkdv9leKj/scB/foIAdidq/K6+pUCamgRFHcdcJfV8
DvL+1Tme5hSzVZ8BLYTC+wCba4lPVBZ5VtFGxx1HJ/l3YZK+rpWORvcb/gdvPoto
Q+c0zRS71MkXGJUHI6jGkcXph+18yEWaUyBMemF3kjuPellg4iHWvJHTxk4T9YyG
aDf4DgrdIFmBzfTdHqZ4OxDCjJNOgRkR854RzVOdXQga36QdnrGb/t0UkmwI4Z2P
2MZJVS5pEKQRP9qH+i2mSbURuAjtzatTHkVgFyZXVlh2itAvJX8Vk+2Y3OASTFcS
Sra0b6RbY7xilwkf0mFnY9G9sSvVmqf4GQXeFUXZurvjhn2rJOslC+qytmSvbyEE
861+HIOS3EtSC9iTjNeabFkddybU/766BPZKDUO6XDlnYvTW0/JNt0d2ZwbqFIQ7
sa9+r+Q2+oL5w7KhizBmoO35OxtG1fyJo5YNXQe0ps5AQ5f5DSoyNOi7B1YYDt8s
YCdEX0kNTAID7v0H2cZ1p+iYdECFpC/cleMfnlQkkpkQQySKtoQeJoWk7Y18iSC6
xQU=
-----END ENCRYPTED PRIVATE KEY-----
';

    protected static $publicKeyString = '-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA/UXvqRNOGEj/ZqQIuwBy
7FM/y2kwSTHNa5BvIAqlEmwI7FyrOSgS4gRF4fkOJvol7RV7BWhnKUVJ7cbyQhLL
f97jNkjntZoGBTSyDT77ZDpFAKWxxQ3VGj4eF7fd2TLl6eotUKqmVor5/f90wEDD
vpxAzWaDJJnHGPg41z5p852L/bPTQbd+izYb7qlheuWkguQxyHaBkHwfgNBgGNTr
761/Agqo9Vmkug2MC+FLcNxo3az/vQ+e2neksmlbL0B4wRwACQtExAN1/XNeEclL
VbBDXYMmwP0ukzQ43WpKCPm0d34AbikGj5xEYaAUixt2LZ9zoB4mE4lP4LFThE0h
ETSU1tNPAGgI7A5Yiz1ijgRFO1RmZIXqey0agb89IT0Th7W/aAbAlUI10UMJtm2c
xzb0OnZjJdHpcWLbZDjx04SgiPYbZx8+IM3KoEJU6qTv852dBb7TUM+dV3HoAuMv
s0fQheNQeIjbdHxhD2mXqlHEmHsu82otQ7RcLj8BJfbnlSutivqikspztheK7fv8
CgjRIgIhPxMomz47uGmnhaL0w+94+MRAEmJVga5Janvg5G4+4tCzkJ89/aR9B7uA
4NetvFvU6umGjdMAsNh8Y3k3IBte7dxrRcJD/pJhDSPghRxHqS7b6u9flziBV4QX
aHkMuIX9qc1FvFEx/K9hSncCAwEAAQ==
-----END PUBLIC KEY-----
';
    protected static $certString1 = '-----BEGIN CERTIFICATE-----
MIIGZzCCBE+gAwIBAgIBADANBgkqhkiG9w0BAQsFADCBzTELMAkGA1UEBhMCQlEx
ETAPBgNVBAgMCE9rbGFob21hMRcwFQYDVQQHDA5FYXN0IENheWxhdmlldzEdMBsG
A1UECgwUQ2Fycm9sbCBMdGQgYW5kIFNvbnMxMzAxBgNVBAsMKlRlYW0tb3JpZW50
ZWQgb2JqZWN0LW9yaWVudGVkIGluc3RhbGxhdGlvbjEZMBcGA1UEAwwQTW9oYW1t
YWQgVSBCb3lsZTEjMCEGCSqGSIb3DQEJARYUbW9zZXMzNkBnb29kd2luLmluZm8w
HhcNMTkwODIzMTA1NTA0WhcNMjAwODIyMTA1NTA0WjCBzTELMAkGA1UEBhMCQlEx
ETAPBgNVBAgMCE9rbGFob21hMRcwFQYDVQQHDA5FYXN0IENheWxhdmlldzEdMBsG
A1UECgwUQ2Fycm9sbCBMdGQgYW5kIFNvbnMxMzAxBgNVBAsMKlRlYW0tb3JpZW50
ZWQgb2JqZWN0LW9yaWVudGVkIGluc3RhbGxhdGlvbjEZMBcGA1UEAwwQTW9oYW1t
YWQgVSBCb3lsZTEjMCEGCSqGSIb3DQEJARYUbW9zZXMzNkBnb29kd2luLmluZm8w
ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDDgs+k8/5vPazGVcJ6A4Or
jQc5WtKe5BOrUd0/B+v6QB5oVaKKhHAUxH4xjxYS/ShdxIEo+pQPhFZtA0p8O1g1
7KKwnyOFNE42rVsqccytodNGK3cgLv5yEZ4jdv2SWkO64SrLgOKSLlwijySbPrzl
LDNMUU/j6rKfwiD8KdlODgjwSNESNy+IBl5Wyl4C/dgKDGDIeGdAC8H4ikvbh2SX
D9UWVEzPvmGWUdN3ggwj6wjd4tcaZovMLYiXGiwLh9mlqgC6rEj6PL3idukfE+M0
fW0uQOzL9myYvc4PeSZZ/49ubePDo0KBZvP1X1AJ0yiC632ggvh4VSSj81AB4wWf
T6MbLj97yiYVWU0oECT4n6NNsBgf6DIETiujcJ7kg0E3Tp//oMoufUr4M8krP9At
TyQjmSoBsaO72shLazpvTEOxncGF9cNv1aRJjL8MM5ah61Fs6t3zLaTjzIgr8Lrx
o3fn3xZVopTraEcqO5Xd1PJXmf0onnAdzzfUHUy+Ie9M9Iz09e1xZCOQBjjtT6vQ
1jeW7YFD7069YWyT/nKJ4DRjM6Dmv6eh4rDiBc+P/C5oHK9kdDqLxrjpoLk+CCuq
+VhFay+8VoGkX8Tqe/KUkhV4tZGklZRu1iZEa+HpzVqndD+zq1x9WwKsC5qQeUEq
JeKQxq+xPMxGqzZkLnyIJwIDAQABo1AwTjAdBgNVHQ4EFgQUCxb7ir4OTrGZBlwM
2awRYj2c6qAwHwYDVR0jBBgwFoAUCxb7ir4OTrGZBlwM2awRYj2c6qAwDAYDVR0T
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAmz2ReUbPo1dVZqdzQnijdnVL8sos
82IBNPNBZNy1t4DDlxLyXvc1twkMQ2QftES1BBgcDHQb+VLrfYTDFJOQy4zg1saS
/FbftHUYtqYxwecejK4KWXp3SXr5BMqdRBnhbZPOdpl3hc6VmzCEzCTuiVmD45W4
Wncsi561oF2IgvSzyv6KyfA+78B/R3PUOyIcw9oXRo1g5KW7B9fsGSKPOijH05A8
MByC5lLHstg7+umzjVXLUtyEeHNos2dGFjK9Too4nkVTiV88lxFWsx3k7inc2LN+
BFLcsY8qqtTodpTbdQJeaca4Q9QYoC2owl+V+sCAWUvoK0wYVqRwtKLArEx+/dQe
PveXINUQhudGoVz1x0SPu3FRi1IK+sE/51p6G+5G28/eW3URpFjaVJ669A49KxCj
Anx2bKV+nO3iwFfBxYjdMrK59a0eywhZki3zwJcfUXtAbH1GZHtQg+Vv68WJecc9
G8TXNvfJBmT4Q28ufVauBj/KWsUqw3fvgDhOAI0dxjinU7efbEGLrY3al4vko2Zb
WE2QTJ/3xX0T6VuP2xyB/7kaRo9qUXgaDRhAf6rj2/mcC9jfg3DZfpABHVDvRpDv
QbJXBpeTMIXKkh4YODrOdnunQGN9qnTl/W5fr+jTarPSLiE0PTjXmlAT/ZSj0kPO
/pARCTWcRlJNaSg=
-----END CERTIFICATE-----
';
    protected static $certString2 = '-----BEGIN CERTIFICATE-----
MIIGUTCCBDmgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBwjELMAkGA1UEBhMCTlUx
FTATBgNVBAgMDFJob2RlIElzbGFuZDEVMBMGA1UEBwwMQmVybmllY2ViZXJnMRQw
EgYDVQQKDAtUb3kgSW5jIEluYzEoMCYGA1UECwwfUHJvZml0LWZvY3VzZWQgbW9k
dWxhciBmdW5jdGlvbjEYMBYGA1UEAwwPR29yZG9uIEcgTWFnZ2lvMSswKQYJKoZI
hvcNAQkBFhxlbGxpb3Qub2tlZWZlQHdpbnRoZWlzZXIuY29tMB4XDTE5MDgyMzEw
NTUwNloXDTIwMDgyMjEwNTUwNlowgcIxCzAJBgNVBAYTAk5VMRUwEwYDVQQIDAxS
aG9kZSBJc2xhbmQxFTATBgNVBAcMDEJlcm5pZWNlYmVyZzEUMBIGA1UECgwLVG95
IEluYyBJbmMxKDAmBgNVBAsMH1Byb2ZpdC1mb2N1c2VkIG1vZHVsYXIgZnVuY3Rp
b24xGDAWBgNVBAMMD0dvcmRvbiBHIE1hZ2dpbzErMCkGCSqGSIb3DQEJARYcZWxs
aW90Lm9rZWVmZUB3aW50aGVpc2VyLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
ADCCAgoCggIBAMiRcnCc3caBb1D3oj6avW9feO72v26UfhNuS5uaHbkqYRRszrCA
XpMCfo7mY7RBJWYjeVYxMUiNgWDFz18IqbJGrxspFvi0c8kVhi5hQ3EKD+E/qQfr
rf2mx9XBP7xkAjCPylDEyUbNI2wqjvQ89Z1Fqv5AdbkedK3y+jdbBJ3+ip5D+19y
sCjoU1OLH5jOgJA/1GPGiONmhQLiX/DpLNSkywj933YwuZtXex28Qp7uUT5YLjoK
PSn7l5hBzbUlRd3eyYl9ZCk86SkNj/KMuRDPrJ2hVzmg8HYia70Z2xAqsj7dYyoP
WwKcyBE11EVQNCZI9FU1t3ulSv8Bdm9YmuJsoZGKrHyEGgbS9hzy3njnJcJh8sXz
bGhl2syQGgLcWIB3fbLvaux4R88mWqFi2eRKIV6dxIQYcwpGT60OO9j0JCrINSM8
pj2e2ON9fP3C7cPrypf23tlaZXGocjG9PHSZnzOEDseH6/4YpzDPusJV/KhwmsRo
Xe/1HcR1RKYZUaJdfHor19uDTlxLIaS5w31wTxg3TQwDDPuA8xCYgRtYL50JDHp/
7AkX+ZgZLbyT9uWc2L4lZs3juLvC+ZrkYCRCuytSScv77z9Vn0tfOHydCWpIRY/k
hXV5FE9qRlxiJMXQErSeeTWxNHNpbK1MGlP9TIuk+sI/byOtWzT8ioxNAgMBAAGj
UDBOMB0GA1UdDgQWBBSsknfJ026sIKhYAKwQZqMx6xMSUDAfBgNVHSMEGDAWgBSs
knfJ026sIKhYAKwQZqMx6xMSUDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4ICAQCvZff/nLRCOJDM+PdgyAUP64S0bbgMSs873H2OuscbIwO987BUHpsNqwh0
21kfDbpeuMekY8rA197kJpOY8esrH2OOgAI675f7S5ZKEGzxTqDeHQmQ3K/2Q/lu
fXXwxyrZtHVH8h7We3Wo7Zkff6jWe9dExf1xcO0oVu/BG49T7w2CGar/dExdRrKb
rmxGCqjEm4ogHv8ZwRuk416aXIS0Fh1IyxtHgDzpj3vyvSaZnM/hf5clM1uSRWlc
uiZAJhtQN82Q1aKhO6l4IoDVkxmr9YpDQidrze34oarmeAW+OquFFnf+n78KwvJq
vLICKh+N+slVBgBgHxlP9Xvd6BJsPOa+CJbnIp+WtKzAPwKWpEGzUuufbrbS7l8x
nICwyFLKP3CH9z7AaRGWAViMJjhrrD/k2VEMEi6aLsACN34A+noSxt6LT04g7woQ
19X+E11aaVCINTgCOF57pMG3ndwd2iwQPAZxZzReLERrbLT+P+yywVqeYV+HGGq8
4t5Kmn2GkmH+RSyI8EKVXJHl2rqpf6qALzCNni5OxmyvWxJKYhh/AkYs4pOWWhBt
WAZdJSbOX2JUoXs/RLMJz++203lBNSMDaS1JeHUvkRgIr0abj/nVJk3GxOeE/Xg2
SX+KN+yR40WVThEjlJysOv3kj4Fbe75p/sVNqz2qo6fIj+kZ2Q==
-----END CERTIFICATE-----
';

    /**
     * assertPemTest12 dataProvider
     *
     * @return array
     */
    public function assertPemTest12Provider() {
        $dataArr = [];

        $dataArr[] =
            [
                1,
                str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, self::$privateKeyString1 ),
                'PRIVATE KEY'
            ];

        $dataArr[] =
            [
                2,
                str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, self::$privateKeyString2 ),
                'ENCRYPTED PRIVATE KEY'
            ];

        $dataArr[] =
            [
                3,
                str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, self::$publicKeyString ),
                'PUBLIC KEY'
            ];

        $dataArr[] =
            [
                4,
                str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, self::$certString1 ),
                'CERTIFICATE'
            ];

        $dataArr[] =
            [
                5,
                str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, self::$privateKeyString1 . self::$certString2 ),
                false
            ];

        $dataArr[] =
            [
                6,
                '',
                false
            ];

        $dataArr[] =
            [
                7,
                's0fQheNQeIjbdHxhD2mXqlHEmHsu82otQ7RcLj8BJfbnlSutivqikspztheK7fv8',
                false
            ];

        return $dataArr;
    }

    /**
     * Testing OpenSSLBaseFactory::isPemString/getStringPemType/isPemFile/getFilePemType
     *
     * @test
     * @dataProvider assertPemTest12Provider
     * @param int    $case
     * @param string $string
     * @param string $expected
     */
    public function isPemTest11( $case, $string, $expected ) {
        $case += 110;
        $this->assertEquals(
            ! ( false === $expected ),
            OpenSSLFactory::isPemString( $string, $type ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 1 )
        );
        if( false !== $expected ) {
            $this->assertEquals(
                $expected,
                $type,
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 2 )
            );
            $this->assertEquals(
                $expected,
                OpenSSLFactory::getStringPemType( $string ),
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 2 )
            );
        }

        $file = self::getFileName( __FUNCTION__ . $case );
        Workshop::saveDataToFile( $file, $string );
        $this->assertEquals(
            ! ( false === $expected ),
            OpenSSLFactory::isPemFile( $file, $type ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 3 )
        );
        if( false !== $expected ) {
            $this->assertEquals(
                $expected,
                $type,
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 2 )
            );
            $this->assertEquals(
                $expected,
                OpenSSLFactory::getFilePemType( $file ),
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 2 )
            );
        }
        unlink( $file );
    }

    /**
     * Testing OpenSSLBaseFactory::assertPemString/assertPemFile
     *
     * @test
     * @dataProvider assertPemTest12Provider
     * @param int    $case
     * @param string $string
     * @param string $expected
     */
    public function assertPemTest12( $case, $string, $expected ) {
        $case   += 120;
        $outcome = false;
        try {
            OpenSSLFactory::assertPemString( $string );
        }
        catch( Exception $e ) {
            $outcome = true;
        }
        $this->assertEquals(
            ( false === $expected ),
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 1 )
        );

        $file    = self::getFileName( __FUNCTION__ . $case );
        Workshop::saveDataToFile( $file, $string );
        $outcome = false;
        try {
            OpenSSLFactory::assertPemFile( $file );
        }
        catch( Exception $e ) {
            $outcome = true;
        }
        $this->assertEquals(
            ( false === $expected ),
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, 2 )
        );
        unlink( $file );

    }

    /**
     * Testing OpenSSLBaseFactory::pem2Der/der2Pem
     *
     * @test
     */
    public function pem2Der2PemTest13a( ) {
        $pems = [
            self::$certString1       => OpenSSLFactory::PEM_X509,
            self::$certString2       => OpenSSLFactory::PEM_X509,
            self::$privateKeyString1 => OpenSSLFactory::PEM_PKCS8INF,
            self::$privateKeyString2 => OpenSSLFactory::PEM_PKCS8INF,
            self::$publicKeyString   => OpenSSLFactory::PEM_PUBLIC
        ];
        $x = 0;
        foreach( $pems as $pem => $type ) {
            $x   += 1;
            $pem  = str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, $pem );
            $pem2 = OpenSSLFactory::der2Pem( OpenSSLFactory::pem2Der( $pem, $type ), $type );
            $this->assertEquals(
                $pem,
                $pem2,
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), ( 131 + $x ), null )
            );

            $pemFile1 = self::getFileName( __FUNCTION__ . 1 );
            $derFile  = self::getFileName( __FUNCTION__ . 2, 'der' );

            Workshop::saveDataToFile( $pemFile1, $pem2 );
            $type     = OpenSSLFactory::getFilePemType( $pemFile1 );
            OpenSSLFactory::pemFile2DerFile( $pemFile1, $derFile );

            $pemFile3 = self::getFileName( __FUNCTION__ . 3 );
            OpenSSLFactory::derFile2PemFile( $derFile, $pemFile3, $type );
            $this->assertEquals(
                $pem,
                Workshop::getFileContent( $pemFile3 ),
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), ( 132 + $x ), null )
            );

            unlink( $pemFile1 );
            unlink( $derFile );
            unlink( $pemFile3 );
        }
    }

    /**
     * Testing OpenSSLBaseFactory::pem2Der - catch exception
     *
     * @test
     */
    public function pem2DerTest13b() {
        $case    = 138;
        $outcome = true;
        try {
            $der = OpenSSLFactory::pem2Der( 'grodan boll' );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, null )
        );
    }
    /**
     * Testing OpenSSLBaseFactory::der2Pem - catch exception
     *
     * @test
     */
    public function der2PemTest13c() {
        $case    = 139;
        $outcome = true;
        try {
            $der = OpenSSLFactory::der2pem( self::$privateKeyString1, 'grodan boll' );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     * Testing OpenSSLBaseFactory::pem2DerASN1
     *
     * @test
     * @todo assert result
     */
    public function pem2DerASN1Test14() {
        $pems = [
            self::$certString1,
            self::$certString2,
            self::$privateKeyString1,
            self::$privateKeyString2,
            self::$publicKeyString
        ];
        foreach( $pems as $x => $pem ) {
            $pem = str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, $pem );
            $this->assertTrue(
                is_string( OpenSSLFactory::pem2DerASN1( $pem, $type )),
                sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), ( 141 ), $x )
            );
        }

        $fakePem = '-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA/UXvqRNOGEj/ZqQIuwBy
aHkMuIX9qc1FvFEx/K9hSncCAwEAAQ==
-----END PUBLIC KEY-----
';
        $pem = str_replace( PHP_EOL, OpenSSLX509Factory::$PEMEOL, $fakePem );
        $this->assertTrue(
            is_string( OpenSSLFactory::pem2DerASN1( $pem, $type )),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), ( 141 ), 9 )
        );
    }

    /**
     * Testing OpenSSLBaseFactory::assertPassPhrase
     *
     * @test
     */
    public function assertPassPhraseTest15( ) {

        $passPhrase = 'passPhrase';
        $this->assertTrue(
            is_string( OpenSSLPkeyFactory::assertPassPhrase( $passPhrase )),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );

        $passPhrase = null;
        $this->assertNull(
            OpenSSLPkeyFactory::assertPassPhrase( $passPhrase ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );

        $passPhrase = '';
        $this->assertNull(
            OpenSSLPkeyFactory::assertPassPhrase( $passPhrase ),
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );

    }

    /**
     * Testing OpenSSLBaseFactory::assertResourceFileStringPem
     *
     * @test
     */
    public function assertResourceFileStringPemTest16() {

        $outcome = true;
        try {
            OpenSSLPkeyFactory::assertPkey( [] );
        }
        catch( Exception $e ) {
            $outcome = false;
        }

        $this->assertEquals(
            false,
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 1, null )
        );

        $pKeyFactory        = OpenSSLPkeyFactory::factory()->pKeyNew();
        // get private key as resource
        $privateKeyResource = $pKeyFactory->getPrivateKeyAsResource();
        // get private key as PEM-string
        $privateKeyString   = $pKeyFactory->getPrivateKeyAsPemString();
        // get private key as PEM-file
        $privateKeyFile     = self::getFileName( __FUNCTION__ . '-1' );
        $pKeyFactory->savePrivateKeyIntoPemFile( $privateKeyFile );
        $privateSources     = [
            'privRsc'   => $privateKeyResource,
            'privStr'   => $privateKeyString,
            'privFile1' => $privateKeyFile,
            'privFile2' => 'file://' . $privateKeyFile,
        ];

        foreach( $privateSources as $x => $privateSource ) {
            $this->assertNotFalse(
                OpenSSLPkeyFactory::assertPkey( $privateSource,  1, true  ),
                sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), ( 150 + $x ), null )
            );
        }

        $outcome = true;
        try {
            OpenSSLPkeyFactory::assertResourceFileStringPem(
                $privateKeyResource, 1, null, OpenSSLX509Factory::X509RESOURCETYPE
            );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 154, null )
        );

        $pem = self::$privateKeyString1 . self::$certString1;
        $this->assertEquals(
            $pem,
            OpenSSLPkeyFactory::assertPkey( $pem ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 155, null )
        );
        $outcome = true;
        try {
            $pem = OpenSSLPkeyFactory::assertPkey( 'grodan boll' . self::$privateKeyString1 );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), 156, null )
        );

        $this->assertNotFalse(
            OpenSSLPkeyFactory::assertPkey( $privateKeyFile,  1, false  ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), ( 157 ), null )
        );
        $this->assertNotFalse(
            OpenSSLPkeyFactory::assertPkey( 'file://' . $privateKeyFile,  1, false  ),
            sprintf( self::$FMT, OpenSSLFactory::getCm( __METHOD__ ), ( 158 ), null )
        );
        if( is_file( $privateKeyFile )) {
            unlink( $privateKeyFile );
        }

    }

    use Traits\assertMdCipherAlgorithmTrait;

    /**
     * Testing OpenSSLBaseFactory::assertCipherId - catch exception
     *
     * @test
     */
    public function assertCipherIdTest17() {
        $case    = 161;
        $outcome = true;
        try {
            OpenSSLPkcs7Factory::assertCipherId( 13 );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case, null )
        );

        $case    = 162;
        $outcome = true;
        try {
            OpenSSLPkcs7Factory::assertCipherId( 5 );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertTrue(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), $case, null )
        );
    }

    /**
     * Testing OpenSSLBaseFactory::getOpenSSLErrors
     *
     * @test
     */
    public function getOpenSSLErrorsTest18() {
        $getOpenSSLErrors = null;
        OpenSSLFactory::clearOpenSSLErrors();
        set_error_handler( OpenSSLFactory::$ERRORHANDLER );
        $x = 'Grodan boll';
        try {
            $result = openssl_open( $x, $decrypted, $x, $x, $x, $x );
        }
        catch( Exception $e ) {
            $getOpenSSLErrors = OpenSSLFactory::getOpenSSLErrors();
            try {
                $result = openssl_open( $x, $decrypted, $x, $x, $x, $x );
            }
            catch( Exception $e ) {
                OpenSSLFactory::clearOpenSSLErrors();
            }
        }
        finally {
            restore_error_handler();
        }
        $this->assertNotNull(
            $getOpenSSLErrors,
            sprintf( self::$FMT, OpenSSLPkcs7Factory::getCm( __METHOD__ ), 171, null )
        );
    }

    /**
     * Testing OpenSSLBaseFactory::assessCatch
     *
     * @test
     */
    public function assessCatchTest19() {
        LoggerDepot::registerLogger( __NAMESPACE__, new NullLogger());

        $outcome = true;
        try {
            OpenSSLPkeyFactory::assessCatch(
                __METHOD__,
                new PhpErrorException( 'errorMessage', 123, E_USER_ERROR, 'file.php', 13 ),
                //                new Exception( 'errorMessage' ),
                true,
                'OpenSSLErrors',
                'msg2'
            );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertTrue(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 181, null )
        );

        $outcome = true;
        try {
            OpenSSLPkeyFactory::assessCatch(
                __METHOD__,
                new PhpErrorException( 'errorMessage', 123, E_USER_ERROR, 'file.php', 13 ),
                //                new Exception( 'errorMessage' ),
                false,
                'OpenSSLErrors',
                'msg2'
            );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 182, null )
        );

    }

    /**
     * Testing OpenSSLBaseFactory::logAndThrowRuntimeException
     *
     * @test
     */
    public function logAndThrowRuntimeException20() {
        $outcome = true;
        try {
            OpenSSLPkeyFactory::logAndThrowRuntimeException( __METHOD__, 'msg2', 'OpenSSLErrors' );
        }
        catch( exception $e ) {
            $outcome = false;
        }
        $this->assertFalse(
            $outcome,
            sprintf( self::$FMT, OpenSSLPkeyFactory::getCm( __METHOD__ ), 191, null )
        );
    }

}
