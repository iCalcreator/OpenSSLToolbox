## OpenSSLCsrFactory class
extends OpenSSLBase, implements OpenSSLInterface

Wrapper for PHP OpenSSL CSR functions, encapsulates the CSR resource<br>
Note: You need to have a valid openssl.cnf installed for this to operate correctly.<br>
You will find convenient constants in OpenSSLInterface.<br>
Require a Psr\Log logger, provided by LoggerDepot<br>


Class constant

    CSRRESOURCETYPE


Class properties

    dn           array
    privateKey   string|array|resource
                   A private key
                   1. private key resource
                   2. fileName
                   3. PEM string
                   4. array( 2/3, passPhrase )
    config       array
                    configArgs
    extraAttribs array
    csrResource  resource
                   type 'OpenSSL X.509 CSR'


>Class constructor and factory methods

###### OpenSSLCsrFactory::__construct( [ array dn [, privateKey [, configArgs [, extraAttribs ]]] )
    If arguments dn and privateKey are set, a new CSR resource are set
    
    dn           array
                   The Distinguished Name or subject fields to be used in the certificate.
                   Assoc array whose keys are converted to OIDs
                   and applied to the relevant part of the request.
    privateKey   string|array|resource
                   A private key
                   1. private key resource
                   2. ('file://')fileName
                   3. PEM string
                   4. array( 2/3, passPhrase )
    configArgs   array
                   Finetuning the CSR signing
    extraAttribs array
                   Additional configuration options for the CSR
                   Assoc array whose keys are converted to OIDs
                   and applied to the relevant part of the request.
                   
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLCsrFactory::factory( [ array dn [, privateKey [, configArgs [, extraAttribs ]]] )
    static method
    return static


>Class logic methods

###### OpenSSLCsrFactory::csrNew( [ array dn [, privateKeyId, [ configArgs, [ extraAttribs ]]]] )
    uses openssl_csr_new
    Generate and save a CSR resource
    
    dn           array
                   The Distinguished Name or subject fields to be used in the certificate.
                   Assoc array whose keys are converted to OIDs
                   and applied to the relevant part of the request.
                   If null, uses 'instance create'-dn, if set
    privateKeyId string|array|resource
                   A private key
                   1. private key resource
                   2. PEM string
                   3. ('file://')fileName with PEM string content
                   4. array( 2/3, passPhrase )
                   If null, uses 'instance create'-privateKeyId, if set
    configArgs   array
                   Finetuning the CSR signing,
                   if null, uses 'instance create'-configArgs, if set
    extraAttribs array
                   Additional configuration options for the CSR
                   Assoc array whose keys are converted to OIDs
                   and applied to the relevant part of the request.
                   If null, uses 'instance create'-extraAttribs, if set
                    
    return static
    throws InvalidArgumentException, RuntimeException on error


###### OpenSSLCsrFactory::getPublicKey()
    uses openssl_csr_get_public_key
    return resource   extracted public key from csr and prepares it for use by other functions.
                      including fields commonName (CN), organizationName (O), countryName (C) etc.
    throws RuntimeException on error

###### OpenSSLCsrFactory::getPublicKeyAsResource()
    alias of OpenSSLCsrFactory::getPublicKey


###### OpenSSLCsrFactory::getSubject( [ useShortnames ] )
    uses openssl_csr_get_subject
    
    useShortnames  
                 bool
                   Controls how the ouput data is indexed in the array,
                   if TRUE (the default) then fields will be indexed with the short name form,
                   otherwise, long name forms will be used - e.g.: CN shortname form of commonName
                          
    return array          subject distinguished name information encoded in the csr
                          including fields commonName (CN), organizationName (O), countryName (C) etc.
    throws RuntimeException on error

###### OpenSSLCsrFactory::getDNfromCsrResource( [ useShortnames ] )
    alias of OpenSSLCsrFactory::getSubject


###### OpenSSLCsrFactory::export( [ noText ] )
    uses openssl_csr_export
    
    noText       bool
                   Optional, default true, affects the verbosity of the output;
                   if it is FALSE, then additional human-readable information is included in the output.
                    
    return string   a CSR as a string in PEM format
    throws RuntimeException on error

###### OpenSSLCsrFactory::getCSRasPemString( [ noText ] )
    alias of OpenSSLCsrFactory::export
    return string   a CSR as a string in PEM format

###### OpenSSLCsrFactory::getCSRasDerString()
    extends OpenSSLCsrFactory::export
    return string   a CSR as a string in DER format


###### OpenSSLCsrFactory::exportToFile( fileName [, noText ] )
    uses openssl_csr_export_to_file
    Export the Certificate Signing Request represented by csr and saves it in PEM format into file
    
    fileName     string
                   Path to the output file.
    noText       bool
                   Optional, default true, affects the verbosity of the output;
                   if it is FALSE, then additional human-readable information is included in the output.
                       
    return static
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLCsrFactory::saveCSRcertIntoPemFile( fileName[, noText ] )
    alias of OpenSSLCsrFactory::exportToFile
    Export the Certificate Signing Request represented by csr and saves it in PEM format into file

###### OpenSSLCsrFactory::saveCSRcertIntoDerFile( fileName )
    extends OpenSSLCsrFactory::export
    Export the Certificate Signing Request represented by csr and saves it in DER format into file
    
    fileName     string
                   Path to the output file. (NO 'file://'-prefix)


###### OpenSSLCsrFactory::sign( caCert , privateKeyId [, days [, configArgs [, serial ]]] )
    uses openssl_csr_sign
    Sign a CSR with another certificate (or itself) and generate a certificate
    
    caCert       resource|string
                   The generated certificate will be signed by caCert.
                   If caCert is NULL, the generated certificate will be a self-signed certificate.
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem;
                      the named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    privateKeyId string|resource
                   The private key that corresponds to caCert, PEM string or resource
                   1. private key resource
                   2. fileName or string PEM string
                   3. array( PEM-string, passPhrase )
    days         int
                   Length of time for which the generated certificate will be valid,
                   in days (default 365).
    configArgs   array
                   Finetuning the CSR signing, default config from class contruct
                   If null, uses 'instance create'-configArgs, if set
    serial       int
                   Optional the serial number of issued certificate (default 0)
    
    return resource   an x509 certificate resource
    throws InvalidArgumentException, RuntimeException  on error

###### OpenSSLCsrFactory::getX509CertResource( caCert , privateKeyId [, days [, configArgs [, serial ]]] )
    alias of OpenSSLCsrFactory::sign


>Getters and setters etc

###### OpenSSLPkeyFactory::getConfig( [ key ] )
    key          string
                   see OpenSSLInterface constants
    
    return bool|string|array
                   bool false if config[key] is not found, otherwise if empty key null
    throws InvalidArgumentException

###### OpenSSLPkeyFactory::isConfigSet( [ key ] )
    key          string
                   see OpenSSLInterface constants
    
    return bool    true if config/config[key] is found

###### OpenSSLPkeyFactory::addConfig( key, value )
    if OpenSSLPkeyFactory::DIGESTALGO == key, validates algorithm
    if OpenSSLPkeyFactory::PRIVATEKEYBITS == key, validates values >= 384
    
    key          string
                   see OpenSSLInterface constants
    value         mixed
    
    return static
    throws InvalidArgumentException on error

###### OpenSSLPkeyFactory::setConfig( array config )
    if OpenSSLPkeyFactory::DIGESTALGO == (config) key, validates (config) algorithm
    if OpenSSLPkeyFactory::PRIVATEKEYBITS == (config) key, validates (config) value >= 384
    
    config       array
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLCsrFactory::getDn( [ key ] )
    key          string
                   see OpenSSLInterface constants
    
    return bool|string|array   return bool false if DN[key] is not found

###### OpenSSLCsrFactory::isDnSet( [ key ] )
    key          string
                   see OpenSSLInterface constants
    
    return bool   true if DN / DN[key] is set

###### OpenSSLCsrFactory::addDn( key, value )
    key          string
                   see OpenSSLInterface constants
    
    mixed  value
    return static
    throws InvalidArgumentException on error

###### OpenSSLCsrFactory::setDn( array dn )
    dn           array
    
    return static


###### OpenSSLCsrFactory::getPrivateKey()
    return string|resource

###### OpenSSLCsrFactory::isPrivateKeySet()
    return bool   true if privateKey is set

###### OpenSSLCsrFactory::setPrivateKey( privateKey )
    privateKey   string|resource
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLCsrFactory::addExtraAttribs( key, value )
    key          string
    value        mixed
    
    return static
    throws InvalidArgumentException on error

###### OpenSSLCsrFactory::getExtraAttribs( [ keyAttrs ] )
    keyAttrs     string|array
    
    return bool|string|array   return bool false if extraAttribs[key] is not found

###### OpenSSLCsrFactory::isExtraAttribsSet( [ key ] )
    key          string
    
    return bool  true if extraAttribs / extraAttribs[key] is set

###### OpenSSLCsrFactory::setExtraAttribs( array extraAttribs )
    extraAttribs array
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLCsrFactory::isValidCsrResource( csrResource )
    csrResource  string|resource
    
    return bool    true if CSR resource is valid
    static

###### OpenSSLCsrFactory::getCsrResource()
    return resource

###### OpenSSLCsrFactory::isCsrResourceSet()
    return bool   true if csrResource is set

###### OpenSSLCsrFactory::setCsrResource( csrResource )
    csrResource  resource
    
    return static
    throws InvalidArgumentException on error


#### Usage and examples

Please review test/OpenSSLCsrFactoryTest2.php

    csrFactoryTest11*
      OpenSSLPkeyFactory - property getter/setter methods

    crsNewTest12*
      OpenSSLCsrFactory  exceptions

    csrResourceTest21
      OpenSSLCsrFactory::getCsrResource
      OpenSSLCsrFactory::setCsrResource

    csrX509Test22
      OpenSSLCsrFactory::factory
      OpenSSLCsrFactory::csrNew
      OpenSSLCsrFactory::getPublicKeyAsResource
      OpenSSLCsrFactory::getDNfromCsrResource
      OpenSSLCsrFactory::getCSRasPemString
      OpenSSLCsrFactory::saveCSRcertIntoPemFile
      OpenSSLCsrFactory::getX509CertResource

    csrX509Test24 (Traits\CsrX509Trait)
      OpenSSLCsrFactory::factory
      OpenSSLCsrFactory::csrNew
      OpenSSLCsrFactory::getX509CertResource


[[return to docs](docs.md)][[return to README](../README.md)]
