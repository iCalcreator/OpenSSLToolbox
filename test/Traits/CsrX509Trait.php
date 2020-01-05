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
namespace Kigkonsult\OpenSSLToolbox\Traits;

use Kigkonsult\OpenSSLToolbox\OpenSSLCsrFactory;
use Kigkonsult\OpenSSLToolbox\OpenSSLPkeyFactory;
use Kigkonsult\OpenSSLToolbox\OpenSSLX509Factory;

trait CsrX509Trait
{
    /**
     * Testing
     *
     * OpenSSLCsrFactory  factory, csrNew, getX509CertResource, sign using another cert
     * OpenSSLX509Factory  (parse) getCertInfo, getCertName, getCertSubjectDN, getCertIssuerDN
     *   extends OpenSSLX509FactoryTest3::parseTest35
     *
     * @test
     */
    public function csrX509Test24() {
        $case         = 2400;

        /* get private key */
        $privateKey   = OpenSSLPkeyFactory::factory()
                                          ->pKeyNew()
                                          ->getPrivateKeyAsPemString();
        /* create a (self-signed) certificate, x509 instance */
        $DN1          = self::getDN(); // a set of DN
        $x509Factory  = OpenSSLX509Factory::csrFactory( null, $DN1, $privateKey );
        /* get caCert as x509 resource */
        $x509Resource = $x509Factory->getX509Resource();
        /* get caCert as string */
        $x509String   = $x509Factory->getX509CertAsPemString();
        /* get caCert as file */
        $x509File     = self::getFileName( __FUNCTION__ .'-1' );
        $x509Factory->saveX509CertIntoPemFile( $x509File );
        $certArr      = [
            'x509Rcs'   => $x509Resource,
            'x509Str'   => $x509String,
            'x509File1' => $x509File,
            'x509File2' => 'file://' . $x509File
        ];

        foreach( $certArr as $x => $caCertSource ) {
            $days = $case += 1;
            $DN2  = self::getDN(); // another set of DN
            $csrFactory       = OpenSSLCsrFactory::factory( $DN2, $privateKey );
            /* create (sign) a new certificate, base on caCertSource+privateKey, get a x509 resource */
            $x509CertResource = $csrFactory->getX509CertResource( $caCertSource, $privateKey, $days );
            $this->assertTrue(
                ( is_resource( $x509CertResource ) &&
                    ( OpenSSLX509Factory::X509RESOURCETYPE == get_resource_type( $x509CertResource ))),
                sprintf( self::$FMT, OpenSSLCsrFactory::getCm( __METHOD__ ), $case, $x )
            );
            /* initate another x509resource */
            $x509Factory2 = OpenSSLX509Factory::factory( $x509CertResource );
            $this->assertTrue(
                is_array( $x509Factory2->getCertInfo()),
                sprintf( self::$FMT, __FUNCTION__, $case .'-10', null )
            );
            $this->assertTrue(
                $x509Factory2->isCertInfoKeySet( false, OpenSSLX509Factory::SERIALNUMBER ),
                sprintf( self::$FMT, __FUNCTION__, $case .'-11', null )
            );

            /* check subject values */
            foreach( $DN2 as $key => $value ) {
                $this->assertTrue(
                    $x509Factory2->isCertInfoKeySet( false, OpenSSLX509Factory::SUBJECT, $key ),
                    sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-21', null )
                );
                $this->assertEquals(
                    $value,
                    $x509Factory2->getCertSubjectDN( false, $key ),
                    sprintf( self::$FMT, __FUNCTION__, $case .'-22', $key )
                );
            } // end foreach

            /* check issuer values */
            foreach( $DN1 as $key => $value ) {
                $this->assertTrue(
                    $x509Factory2->isCertInfoKeySet( false, OpenSSLX509Factory::ISSUER, $key ),
                    sprintf( self::$FMT, OpenSSLX509Factory::getCm( __METHOD__ ), '-31', null )
                );
                $this->assertEquals(
                    $value,
                    $x509Factory2->getCertIssuerDN( false, $key ),
                    sprintf( self::$FMT, __FUNCTION__, $case .'-32', $key )
                );
            } // end foreach
        } // end foreach

        if( is_file( $x509File )) {
            unlink( $x509File );
        }

    }

}
