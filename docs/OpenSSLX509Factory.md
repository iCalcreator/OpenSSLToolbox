## OpenSSLX509Factory class
extends OpenSSLBase, implements OpenSSLInterface

Wrapper for PHP OpenSSL X509 functions, encapsulates the X509 resource.<br>
Note: You need to have a valid openssl.cnf installed for this to operate correctly.<br>
You will find convenient constants in OpenSSLInterface.<br>
Require a Psr\Log logger, provided by LoggerDepot.<br>


Class constants

    X509RESOURCETYPE


Class properties

    x509certData  string/resource
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    x509Resource resource
                   x509 resource, type 'OpenSSL X.509'


>Class constructor and factory methods

###### OpenSSLX509Factory::__construct( [ x509certData ] )
     If argument x509certData is set, a new X509 resource is set
     
     x509certData  string|resource
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem;
                      the named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
                   
     throws InvalidArgumentException, RunTimeException on error

###### OpenSSLX509Factory::factory( [ x509certData ] )
     x509certData  string|resource
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem;
                      the named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
                   
    throws InvalidArgumentException, RunTimeException on error
    return static
    static method

###### OpenSSLX509Factory::csrFactory( caCert, array dn, privateKeyId [, configArgs [, extraAttribs [, days [, serial ]]]] )
    Class factory method, producing a CSR cert 'under the hood'
    
    caCert        resource|string
                    The generated certificate will be signed by caCert.
                    If caCert is NULL, the generated certificate will be a self-signed certificate.
                    1. An X.509 resource returned from openssl_x509_read()
                    2. A string having the format (file://)path/to/cert.pem;
                       the named file must contain a PEM encoded certificate
                    3. A string containing the content of a PEM encoded certificate
    dn            array
                    The Distinguished Name or subject fields to be used in the certificate.
                    Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
    privateKeyId  string|array|resource
                    A private key
                    1. private key resource
                    2. PEM string
                    3. ('file://')fileName with PEM string content
                    4. array( 2/3, passPhrase )
     configArgs   array
                    Finetuning the CSR signing
     extraAttribs array
                    Additional configuration options for the CSR
                    Assoc array whose keys are converted to OIDs and applied to the relevant part of the request.
    days          int
                    Length of time for which the generated certificate will be valid, in days (default 365).
    serial        int
                    Optional the serial number of issued certificate (default 0)
    
    return static
    throws InvalidArgumentException, RunTimeException on error
    static method


>Class logic methods

###### OpenSSLX509Factory::checkPrivateKey( key [, passPhrase ] )
    uses openssl_x509_check_private_key
    The function does not check if key is indeed a private key or not.
    It merely compares the public materials (e.g. exponent and modulus of an RSA key)
    and/or key parameters (e.g. EC params of an EC key) of a key pair.
    
    key         resource|string
                   1. A pkey resource
                   2. A string having the format (file://)path/to/file.pem.
                      The named file must contain a PEM encoded certificate/private key (it may contain both).
                   3. A string, PEM formatted private key.
    passPhrase  string
    
    return bool    true if the (private) key corresponds to the certificate
    throws InvalidArgumentException, RuntimeException on error


###### OpenSSLX509Factory::checkPurpose( purpose [, caInfo [, unTrustedFile ]]  )
    uses openssl_x509_checkpurpose
    
    purpose        int
                     (https://www.php.net/manual/en/openssl.purpose-check.php)
    caInfo         array
                     an array containing file and directory names
                     that specify the locations of trusted CA files.
                     If a directory is specified,
                     then it must be a correctly formed hashed directory
                     as the openssl command would use.
    unTrustedFile  string
                     If specified, this should be the name of a PEM encoded file holding certificates
                     that can be used to help verify the certificate,
                     although no trust is placed in the certificates that come from that file.
                   
    return bool   true if a certificate can be used for a particular purpose
    throws InvalidArgumentException, RunTimeException on error


###### OpenSSLX509Factory::export( [ noText ] )
    uses openssl_x509_export
    
    noText       bool   
                   optional, default true, affects the verbosity of the output;
                   if it is FALSE, then additional human-readable information is included in the output.
                   
    return string  an X509 certificate in a PEM encoded format
    throws RuntimeException on error

###### OpenSSLX509Factory::getX509CertAsPemString( [ noText ] )
    alias of OpenSSLX509Factory::export
    return string  an X509 certificate in a PEM encoded format

###### OpenSSLX509Factory::getX509CertAsDerString()
    extends OpenSSLX509Factory::export
    return string  an X509 certificate in a DER encoded format


###### OpenSSLX509Factory::getX509CertAsDerString()
    extends OpenSSLX509Factory::export
    return string  an X509 certificate in a DER encoded format


###### OpenSSLX509Factory::exportToFile( fileName [, noText ] )
    uses openssl_x509_export_to_file
    Save (PEM encoded) information from an X509 certificate to named fileName
    
    fileName  string
                    Path to the output file. (ext: pem, crt, cer)
    noText    bool  
                    optional, default true, affects the verbosity of the output;
                    if it is FALSE, then additional human-readable information is included in the output.
                   
    return static
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLX509Factory::saveX509CertIntoPemFile( fileName[, noText ] )
    alias of OpenSSLX509Factory::exportToFile
    Save (PEM encoded) information from an X509 certificate to named fileName

###### OpenSSLX509Factory::saveX509CertIntoDerFile( fileName )
    extends OpenSSLX509Factory::export
    Save (DER encoded) information from an X509 certificate to named fileName

    fileName  string
    noText    bool  
                    optional, default true, affects the verbosity of the output;
                    if it is FALSE, then additional human-readable information is included in the output.


###### OpenSSLX509Factory::fingerprint( [ hashAlgorithm [, rawOutput ]] )
    uses openssl_x509_fingerprint
    Return the fingerprint, or digest, of a given X.509 certificate -
    
    hashAlgorithm  string
                     The digest method or hash algorithm to use, default "sha1"
    rawOutput      bool
                     TRUE, outputs raw binary data. FALSE (default) outputs lowercase hexits
                     
    return string  a string containing the calculated certificate fingerprint
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLX509Factory::getDigestHash( [ hashAlgorithm [, rawOutput ]] )
    alias of OpenSSLX509Factory::fingerprint


###### OpenSSLX509Factory::parse( [ shortNames ] )
    uses openssl_x509_parse
    Return (array) information from X509 certificate
    
    shortNames   bool
                   controls how the data is indexed in the array
                   if shortNames is TRUE (the default) then fields will be indexed with the short name form,
                   otherwise, the long name form will be used - e.g.: CN is the shortName form of commonName.
                   
    return array
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLX509Factory::getCertInfo( [ shortNames [, key [, subKey  ]]] )
    extends OpenSSLX509Factory::parse
    
    shortNames   bool
                   default true
    key          string
                   certificate information (array-)key, default null
                   see OpenSSLInterface constants
    subKey       string  certificate information (array-)key/subKey, default null
                   see OpenSSLInterface constants
                   
    return array|string  cert info array(key/subKey)
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLX509Factory::getCertSubjectDN( [ shortNames [, key ]] )
    extends OpenSSLX509Factory::parse
    
    shortNames   bool
                   default true
    key          string
                   opt. subject DN subKey (see OpenSSLInterface constants)
                   
    return array|string  (parsed) subject DN information from X509 certificate
                   null if subject DN key not found
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLX509Factory::getCertIssuerDN( [ shortNames [, key ] ] )
    extends OpenSSLX509Factory::parse
    
    shortNames   bool
                   default true
    key         string
                   opt. issuer DN subKey (see OpenSSLInterface constants)
                   
    return array|string  (parsed) issuer DN information from X509 certificate
                   null if issuer DN key not found
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLX509Factory::isCertInfoKeySet( [ shortNames [, key [, subKey ]]] )
    extends OpenSSLX509Factory::parse
    
    shortNames   bool
                   default true
    key          string
                   certificate information (array-)key, default null
                   see OpenSSLInterface constants
    subKey       string  
                   certificate information (array-)key/subKey, default null
                   see OpenSSLInterface constants
                   
    return bool    true if parse array key(/subKey) is set
    throws InvalidArgumentException, RunTimeException on error


###### OpenSSLX509Factory::read( [ x509certData] )
    uses openssl_x509_read
    Set resource identifier from a parsed X.509 certificate
    
    x509certData string
                   1. An X.509 resource (returned from openssl_x509_read())
                   2. A string having the format (file://)path/to/cert.pem;
                   the named file must contain a PEM encoded certificate
                   3. A string containing a PEM encoded certificate
                   
    return static
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLX509Factory::createX509ResourceFromString( x509CertificateString )
    alias of OpenSSLX509Factory::read

###### OpenSSLX509Factory::createX509ResourceFromFile( x509CertificateFile )
    alias of OpenSSLX509Factory::read


>Getters and setters etc

###### OpenSSLX509Factory::assertCaInfo( array caInfo, argIx = null )
    Assert caInfo array contains valid (readable) fileNames or directories
    
    caInfo       array
    argIx        int|string
    
    throws InvalidArgumentException on error
    static method


###### OpenSSLX509Factory::freeX509certData()
    uses openssl_x509_free
    return static

###### OpenSSLX509Factory::getX509certData()
    return string|resource

###### OpenSSLX509Factory::isX509certDataSet()
    return bool  true is x509Certdata is set

###### OpenSSLX509Factory::setX509certData( x509certData )
    x509certData string|resource
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem;
                      the named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate,
                   
    return static
    throws InvalidArgumentException on error


###### OpenSSLX509Factory::assertX509( x509, argIx = null, fileToString = false )
    x509         resource|string
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing a PEM encoded certificate
    argIx        int|string
    fileToString bool
                   if true and x509 is file, return file content
                   
    return resource|string       if file, 'file://'-prefixed
    throws InvalidArgumentException on error
    static method

###### OpenSSLX509Factory::isValidX509Resource( x509 )

    x509         string|resource
    return bool  true if x509 resource is valid
    static method

###### OpenSSLX509Factory::freeX509Resource()
    uses openssl_x509_free
    return static

###### OpenSSLX509Factory::getX509Resource()
    return x509 resource

###### OpenSSLX509Factory::isX509ResourceSet()
    return bool   true is x509Resource is set

###### OpenSSLX509Factory::setX509Resource( x509Resource )
    x509Resource  resource
    
    return static
    throws InvalidArgumentException on error


#### Usage and examples

Please review test/OpenSSLX509FactoryTest.php

    certDataTest11
      __construct    certData sources

    csrFactoryTest12
      csrFactory (caCert)
        create x509 instance, set/create x509 resource from resource/file/string

    csrFactoryTest13
      set/create x509 resource from resource/file/string

    checkPrivateKeyTest24
      __construct
      read
      checkPrivateKey

    checkPurposeTest31
      checkPurpose

    exportTest32
      getX509CertAsPemString
      getX509CertAsDerString

    saveX509CertIntoFileTest33
      saveX509CertIntoPemFile
      saveX509CertIntoDerFile

    fingerprintTest34
      getDigestHash (fingerprint)

    parseTest35
      parse

    csrX509Test24  (Traits\CsrX509Trait)
      getCertInfo
      getCertName
      getCertSubjectDN
      getCertIssuerDN

    *Test4*
      Exception tests


[[return to docs](docs.md)][[return to README](../README.md)]
