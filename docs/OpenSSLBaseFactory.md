
## OpenSSLBaseFactory class
abstract, implements OpenSSLInterface


>Class logic static methods, inherited by all OpenSSL* classes

###### OpenSSLBaseFactory::assertPemString( pem [, argIx ] )
    Assert PEM string
    
    pem          string
    argIx        int|string
    
    throws InvalidArgumentException on error
    static method

###### OpenSSLBaseFactory::isPemString( pem [, type ] )
    A standard PEM has a begin line, an end line
    and inbetween is a base64 encoding of the DER representation of the certificate.
    PEM requires that linefeeds ("\r\n") be present every 64 characters.
    
    pem          string
    type         string
                   contains PEM type (see OpenSSLInterface) on success
    
    return bool    true if pem is a (single) PEM string,
    static method

###### OpenSSLBaseFactory::isPemFile( pem [, type ] )
    pem          string
    type         string
                   contains PEM type (see OpenSSLInterface) on success
    
    return bool    true if file content is a (single) PEM string,
    static method


###### OpenSSLBaseFactory::pem2Der( pem [, type ] )
    pem          string
    type         string
                   contains PEM type (see OpenSSLInterface) on success
    
    return string  PEM string converted to DER format
    throws InvalidArgumentException on error
    static method

###### OpenSSLBaseFactory::pemFile2DerFile( inputPemFile, outputDerFile [, type ] )
    converts PEM certificate/key file into DER file
    
    inputPemFile string
    outputDerFile 
                 string
    type         string
                   contains PEM type (see OpenSSLInterface) on success
    
    throws InvalidArgumentException on error
    static method

###### OpenSSLBaseFactory::pem2DerASN1( pem [, type] )
    pem          string
    type         string
                   contains PEM type (see OpenSSLInterface) on success
    
    return string  PEM string converted to DER format with extra ASN.1 wrapping
    throws InvalidArgumentException on error
    static method

###### OpenSSLBaseFactory::der2Pem( der, type [, eol ] )
    der          string     (without ASN.1)
    type         string
                   PEM type (see OpenSSLInterface constants)
    eol          string
                   default "\r\n", may be set to PHP_EOL
    
    return string  PEM certificate/key etc converted from DER
                   Note, NO type<->content check
    throws InvalidArgumentException on error
    static method

###### OpenSSLBaseFactory::derFile2PemFile( derFile, pemFile, type [, eol ] )
    converts DER file into PEM certificate/key file
                   Note, NO type<->content check
                   
    derFile      string 
                   input der file (without ASN.1)
    pemFile      string 
                   output pem file
    type         string
                   PEM type (see OpenSSLInterface constants)
    eol          string
                   default "\r\n", may be set to PHP_EOL
    
    throws InvalidArgumentException on error
    static method


###### OpenSSLBaseFactory::assertPassPhrase( passPhrase [, argIx ] )
    Assert passPhrase
    
    passPhrase   mixed
    argIx        int|string
    
    return null|string  null or passPhrase
    throws InvalidArgumentException
    static method


###### OpenSSLBaseFactory::assertCipherAlgorithm( algorithm )
    algorithm    string
    
    return string   found algorithm (exact case), uses self::getAvailableCipherMethods()
    throws InvalidArgumentException  on error
    static method

###### OpenSSLBaseFactory::getAvailableCipherMethods( [ aliases ] )
    uses openssl_get_cipher_methods
    
    aliases      bool  
                   default false, no aliases
    
    return array   available cipher methods
    static method


###### OpenSSLBaseFactory::assertMdAlgorithm( algorithm )
    algorithm    string
    
    return string  found algorithm (exact case), uses self::getAvailableDigestMethods()
    throws InvalidArgumentException
    static method

###### OpenSSLBaseFactory::getAvailableDigestMethods( [ aliases ] )
    uses openssl_get_md_methods
    
    aliases      bool  
                   default false, no aliases
    
    return array   available digest (md) methods
    static method


[[return to docs](docs.md)][[return to README](../README.md)]
