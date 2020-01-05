###### OpenSSLPkcs7Factory class, extends OpenSSLBase, implements OpenSSLInterface

Wrapper for PHP OpenSSL pkcs12 functions, encapsulates the pkcs12 (string) resource<br>
Note: You need to have a valid openssl.cnf installed for this to operate correctly.<br>
You will find convenient constants in OpenSSLInterface.<br>
Require a Psr\Log logger, provided by LoggerDepot<br>

The class has only static methods.<br>


###### OpenSSLPkcs7Factory::assertCipherId( cipherId [ argIx] )
    cipherId     int
    argIx        int|string  default 1
    
    throws InvalidArgumentException on error
    static method

###### OpenSSLPkcs7Factory::assertflags( flags [, argIx [, valueIfNull] )
    Assert (int, constant) PKCS7 flags
    
    flags        int
    argIx        int|string  default 1
    valueIfNull  int
    
    return int
    throws InvalidArgumentException on error
    static method


###### OpenSSLPkcs7Factory::decrypt( infileName, outfileName, recipCert [, recipKey ] )
    uses openssl_pkcs7_decrypt
    Decrypts an S/MIME encrypted message contained in the file specified by infilename
    using the certificate and its associated private key specified by recipcert and recipkey.
    
    infileName   string
                   The message to decrypt is stored in the file specified by infilename.
    outfileName  string
                   The decrypted message is written to the file specified by outfilename.
    recipCert    resource|string
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                   The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    recipKey     resource|string|array
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4. For private keys, you may also use the syntax array($key, $passphrase)
                      where $key represents a key specified using the file or textual content notation above,
                      and $passphrase represents a string containing the passphrase for that private key
                      
    return bool  true on successfull decrypt
    throws InvalidArgumentException, RunTimeException on error
    static method

###### OpenSSLPkcs7Factory::decryptString( stringToDecrypt, recipCert [, recipKey ] )
    extends OpenSSLPkcs7Factory::decrypt
    
    stringToDecrypt
                 string
    recipCert    resource|string
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                   The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    recipKey     resource|string|array
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4. For private keys, you may also use the syntax array($key, $passphrase)
                      where $key represents a key specified using the file or textual content notation above,
                      and $passphrase represents a string containing the passphrase for that private key
                      
    return string  decrypted string
    throws Exception, InvalidArgumentException, RunTimeException on error
    static method


###### OpenSSLPkcs7Factory::encrypt( infileName, outfileName, recipCerts, headers = [], flags = 0, cipherId =
    uses openssl_pkcs7_encrypt
    Encrypts the infile (S/MIME message) contents using an RC2 40-bit cipher
    so that they can only be read by the intended recipients specified by recipcerts
    
    infileName   string
    outfileName  string
    recipCerts   resource|array|string
                   X.509 certificate (below), single/array
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    headers      array  default []
                   Headers that will be prepended to the data after it has been encrypted
                   1. an associative array keyed by header name
                   2. an indexed array, where each element contains a single header line.
    flags        int    default 0
                   Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
    cipherId     int    default OPENSSL_CIPHER_RC2_40
                   One of cipher constants. (https://www.php.net/manual/en/openssl.ciphers.php)
                   
    return bool
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLPkcs7Factory::encryptString( stringToEncrypt, recipCerts [, headers [, flags [, cipherId ]]] )
    extends OpenSSLPkcs7Factory::encrypt
    
    stringToEncrypt
                 string
    recipCerts   resource|array|string
                   1. Either a lone X.509 certificate, or an array of X.509 certificates.
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
    headers      array
                   default []
                   Headers that will be prepended to the data after it has been encrypted
                   1. an associative array keyed by header name
                   2. an indexed array, where each element contains a single header line.
    flags        int
                   default 0
                   Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
    cipherId     int
                   default OPENSSL_CIPHER_RC2_40
                   One of cipher constants. (https://www.php.net/manual/en/openssl.ciphers.php)
                   
    return string  encrypted
    throws Exception, InvalidArgumentException, RuntimeException  on error
    static method


###### OpenSSLPkcs7Factory::sign( infileName, outfileName, signCert, privKey [, headers [, flags [, extraCerts ]]] )
    uses openssl_pkcs7_sign
    Sign infileName (S/MIME message) content
    using the certificate and its matching private key specified by signCert and privKey parameters.
    
    infileName   string
                   The input file you are intending to digitally sign.
    outfileName  string
                   The file which the digital signature will be written to.
    signCert     resource|string
                   The X.509 certificate used to digitally sign $infileName.
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem;
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    privKey      resource|string|array
                   The private key corresponding to signCert.
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem -
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4 For private keys, you may also use the syntax array($key, $passphrase)
                     where $key represents a key specified using the file or textual content notation above,
                     and $passphrase represents a string containing the passphrase for that private key
    headers      array
                   default []
                   an array of headers that will be prepended to the data after it has been signed
                   1. an associative array keyed by header name
                   2. an indexed array, where each element contains a single header line
    flags        int
                   default PKCS7_DETACHED
                   Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
    extraCerts   string
                   Specifies the name of a file containing a bunch of extra certificates to include in the signature
                   which can for example be used to help the recipient to verify the certificate that you used
                   
    return bool    true on success
    throws InvalidArgumentException, RunTimeException on error
    static method

###### OpenSSLPkcs7Factory::signString( stringToSign, signCert, privKey, [ headers [, flags [, extraCerts ]]] )
    alias of OpenSSLPkcs7Factory::sign
    Return an signed S/MIME message
    
    stringToSign   
                 string
                   The string you are intending to digitally sign.
    signCert     resource|string
                   The X.509 certificate used to digitally sign $infileName.
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem;
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    privKey      resource|string|array
                   The private key corresponding to signCert.
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem -
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4 For private keys, you may also use the syntax array($key, $passphrase)
                     where $key represents a key specified using the file or textual content notation above,
                     and $passphrase represents a string containing the passphrase for that private key
    headers      array
                   default []
                   an array of headers that will be prepended to the data after it has been signed
                   1. an associative array keyed by header name
                   2. an indexed array, where each element contains a single header line
    flags        int
                   default PKCS7_DETACHED
                   Opt. options that affect the encoding process (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
    extraCerts   string
                   Specifies the name of a file containing a bunch of extra certificates to include in the signature
                   which can for example be used to help the recipient to verify the certificate that you used
                   
    return string  signed
    throws Exception, InvalidArgumentException, RunTimeException on error
    static method


###### OpenSSLPkcs7Factory::verify( infileName, flags [, outfileName [, caInfo [, extraCerts [, content ]]]] )
    uses openssl_pkcs7_verify
    Reads the S/MIME message contained in the given file and examines the digital signature.
    
    infileName   string
    flags        int
                   Opt. used to affect how the signature is verified
                   (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
    outfileName  string
                   Opt. string holding the name of a file into which the certificates of the persons that
                   signed the messages will be stored in PEM format
    caInfo       array
                   default []
                   An array containing file and directory names
                   that specify the locations of trusted CA files.
                   If a directory is specified,
                   then it must be a correctly formed hashed directory
                   as the openssl command would use.
    extraCerts   string 
                   default null
                   The filename of a file containing a bunch of certificates to use as untrusted CAs
    content      string default null
                   filename, Will be filled with the verified data, but with the signature information stripped
                   
    return bool    TRUE if the signature is verified as an S/MIME signed message
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLPkcs7Factory::verifyString( stringToVerify, flags, caInfo = [], extraCerts = null,  result = false )
    extends OpenSSLPkcs7Factory::verify
    Returns array (PEMs, data) if the signature is verified as an S/MIME signed message
    
    stringToVerify
                 string
    flags        int
                   Opt. used to affect how the signature is verified
                   (https://www.php.net/manual/en/openssl.pkcs7.flags.php)
    caInfo       array  
                   default []
                   An array containing file and directory names
                   that specify the locations of trusted CA files.
                   If a directory is specified,
                   then it must be a correctly formed hashed directory
                   as the openssl command would use.
    extraCerts   string 
                   default null
                   The filename of a file containing a bunch of certificates to use as untrusted CAs
                   
    result  bool   true if verify ok
    return array   [ string signers PEMs, string content ]
    throws Exception, InvalidArgumentException, RunTimeException on error


#### Usage and examples

Please review test/OpenSSLPkcs7FactoryTest.php

    OpenSSLPkcs7FactoryTest11
      OpenSSLPkcs7Factory exceptions

    OpenSSLPkcs7FactoryTest2*
      OpenSSLPkcs7Factory::encryptString
      OpenSSLPkcs7Factory::encrypt
      OpenSSLPkcs7Factory::decryptString
      OpenSSLPkcs7Factory::decrypt

    OpenSSLPkcs7FactoryTest3*
      OpenSSLPkcs7Factory::signString
      OpenSSLPkcs7Factory::sign


[[return to docs](docs.md)][[return to README](../README.md)]
