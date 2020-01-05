## OpenSSLBase class, abstract, implements OpenSSLInterface


> Class logic static methods, inherited by all OpenSSL* classes

###### OpenSSLBase::assertPemString( pem [, argIx ] )
    Assert PEM string
    
    pem         string
    argIx       int|string
    
    throws InvalidArgumentException on error
    static method

###### OpenSSLBase::assertPemFile( file [, argIx ] )
    Assert File with PEM string content
    
    file         string
    argIx        int|string
    
    throws InvalidArgumentException on error
    static method


###### OpenSSLBase::isPemString( pem )
    A standard PEM has a begin line, an end line
    and inbetween is a base64 encoding of the DER representation of the certificate.
    PEM requires that linefeeds ("\r\n") be present every 64 characters.
    
    pem          string
    
    return bool    true if pem is a (single) PEM string
    static method

###### OpenSSLBase::isPemFile( file )
    file         string
    
    return bool  true if file content is a (single) PEM string
    static method


###### OpenSSLBase::assertPassPhrase( passPhrase [, argIx ] )
    Assert passPhrase
    
    passPhrase   mixed
    argIx        int|string
    
    return null|string  null or passPhrase
    throws InvalidArgumentException
    static method


###### OpenSSLBase::assertCipherAlgorithm( algorithm )
    algorithm    string
    
    return string   found algorithm (exact case)
    throws InvalidArgumentException  on error
    static method

###### OpenSSLBase::getAvailableCipherMethods( [ aliases ] )
    aliases      bool  
                   default false, no aliases
    
    return array   available cipher methods
    static method


###### OpenSSLBase::assertMdAlgorithm( algorithm )
    algorithm    string
    
    return string  found algorithm (exact case)
    throws InvalidArgumentException
    static method

###### OpenSSLBase::getAvailableDigestMethods( [ aliases ] )
    aliases      bool
                   default false, no aliases
    
    return array   available digest (md) methods
    static method



#### Usage and examples

Please review test/OpenSSLBaseFactoryTest.php

    isPemTest11                    -  isPemString/getStringPemType/isPemFile/getFilePemType
    assertPemTest12                -  assertPemString/assertPemFile
    pem2Der2PemTest13a             -  pem2Der/der2Pem
    pem2DerTest13b                 -  pem2Der - catch exception
    der2PemTest13c                 -  der2Pem - catch exception
    pem2DerASN1Test14              -  pem2DerASN1
    assertPassPhraseTest15         -  assertPassPhrase
    assertResourceFileStringPemTest16 - Testing assertResourceFileStringPem
    assertMdAlgorithmTest1a        -  assertMdAlgorithm/assertCipherAlgorithm
                                      (Traits\assertMdCipherAlgorithmTrait)
    assertCipherIdTest17           -  assertCipherId - catch exception
    getOpenSSLErrorsTest18         -  Testing getOpenSSLErrors
    assessCatchTest19              -  assessCatch
    logAndThrowRuntimeException20  -  logAndThrowRuntimeException

[[return to docs](docs.md)][[return to README](../README.md)]
