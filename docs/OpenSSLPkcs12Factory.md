## OpenSSLPkcs12Factory class
extends OpenSSLBase, implements OpenSSLInterface

Wrapper for PHP OpenSSL pkcs12 functions, encapsulates the pkcs12 (string) resource<br>
Note: You need to have a valid openssl.cnf installed for this to operate correctly.<br>
You will find convenient constants in OpenSSLInterface.<br>
Require a Psr\Log logger, provided by LoggerDepot<br>


>Class properties

    x509         resource|string
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate

    privateKey   resource|string|array
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. For public keys only: an X.509 resource
                   3. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   4. A string containing the content of a PEM encoded certificate/key
                   5 For private keys, you may also use the syntax array(key, passphrase)
                     where key represents a key specified using the file or textual content notation above,
                     and passphrase represents a string containing the passphrase for that private key

    pkcs12passWord string
                   Encryption password for unlocking the PKCS#12

    args         array
                   Optional array, other keys will be ignored
                   'extracerts'   array of extra certificates or
                                  a single certificate to be included in the PKCS#12 file.
                   'friendlyname' string to be used for the supplied certificate and key

    pkcs12       string
                   The pkcs12 (string) resource


>Class constructor and factory methods

###### OpenSSLPkcs12Factory::__construct( [ x509 [, privateKey [, pkcs12passWord [, args ]]]] )
    If all but 'args' arguments are set, a new string pkcs12 are set ( using export)
    
    x509         resource|string x509
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    privateKey   resource|string|array
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4 For private keys, you may also use the syntax array(key, passphrase)
                     where key represents a key specified using the file or textual content notation above,
                     and passphrase represents a string containing the passphrase for that private key
    pkcs12passWord string
                   Encryption password for unlocking the PKCS#12
    args         array
                   Optional array, other keys will be ignored
                   'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
                   'friendlyname' string to be used for the supplied certificate and key
                   
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLPkcs12Factory::factory( [ x509 [, privateKey [, pkcs12passWord [, args ]]]] )
    If all but 'args' arguments are set, a new string pkcs12 are set ( using export)
    
    x509         resource|string x509
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    privateKey   resource|string|array
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4 For private keys, you may also use the syntax array(key, passphrase)
                     where key represents a key specified using the file or textual content notation above,
                     and passphrase represents a string containing the passphrase for that private key
    pkcs12passWord string
                   Encryption password for unlocking the PKCS#12
    args         array
                   Optional array, other keys will be ignored
                   'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
                   'friendlyname' string to be used for the supplied certificate and key
                   
    throws InvalidArgumentException, RunTimeException on error
    return static
    static method


>Class logic methods

###### OpenSSLPkcs12Factory::read( pkcs12 [, pkcs12passWord ] )
    pkcs12       string
                   1.  The certificate store content (not file)
                   2.  'file://'-prefixed (!!) fileName with certificate store content
    pkcs12passWord string
                   Encryption password for unlocking the PKCS#12
                   
    return array   parsed PKCS#12 Certificate Store - uses openssl_pkcs12_read
    throws InvalidArgumentException, RunTimeException on error
    static method

###### OpenSSLPkcs12Factory::getCertificateStoreAsArray()
    'alias' of read
    return array  array of parsed PKCS#12 Certificate Store
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLPkcs12Factory::getCertificates()
    derived from read
    return array   array of (string PEM) certificates from parsed PKCS#12 Certificate Store
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLPkcs12Factory::getKeys()
    derived from read
    return array   array of (string PEM) (private) key(s)
                   from parsed PKCS#12 Certificate Store
    throws InvalidArgumentException, RunTimeException on error


###### OpenSSLPkcs12Factory::export( x509, privateKey, pkcs12passWord [, args ] )
    uses openssl_pkcs12_export
    
    x509         resource|string
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    privateKey   resource|string|array
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4 For private keys, you may also use the syntax array(key, passphrase)
                     where key represents a key specified using the file or textual content notation above,
                     and passphrase represents a string containing the passphrase for that private key
    pkcs12passWord string
                   Encryption password for unlocking the PKCS#12
    args         array
                   Optional array, other keys will be ignored
                   'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
                   'friendlyname' string to be used for the supplied certificate and key
                   
    return string  a PKCS#12 Compatible Certificate Store in a PKCS#12 string (file) format
    throws InvalidArgumentException, RuntimeException on error
    static method


###### OpenSSLPkcs12Factory::exportToFile( x509, fileName, privateKey, pkcs12passWord [, args ] )
    uses openssl_pkcs12_export_to_file
    Stores x509 into a file named by filename in a PKCS#12 file format.
    
    x509         resource|string
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
    fileName     string
    privateKey   resource|string|array
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4 For private keys, you may also use the syntax array(key, passphrase)
                     where key represents a key specified using the file or textual content notation above,
                     and passphrase represents a string containing the passphrase for that private key
    pkcs12passWord string
                   Encryption password for unlocking the PKCS#12
    args         array   Optional array, other keys will be ignored
                   'extracerts'   array of extra certificates or a single certificate to be included in the PKCS#12 file.
                   'friendlyname' string to be used for the supplied certificate and key
                   
    return bool   true on success
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLPkcs12Factory::saveCertificateStoreIntoFile( fileName )
    exportToFile wrapper
    Save a PKCS#12 Compatible Certificate Store File
    
    fileName     string
                   Path to the output file.
                   
    return static
    throws InvalidArgumentException, RuntimeException on error


>Getters and setters etc

###### OpenSSLPkcs12Factory::function getX509()
    return resource|string  x509

###### OpenSSLPkcs12Factory::isX509Set()
    return bool  true if x509 is set

###### OpenSSLPkcs12Factory::setX509( x509 )
    Set x509, removes any previously set pkcs12
    
    x509         resource|string
                   1. An X.509 resource returned from openssl_x509_read()
                   2. A string having the format (file://)path/to/cert.pem
                      The named file must contain a PEM encoded certificate
                   3. A string containing the content of a PEM encoded certificate
                   
    return static
    throws InvalidArgumentException on error


###### OpenSSLPkcs12Factory::getPrivateKey()
    return array|resource|string

###### OpenSSLPkcs12Factory::isPrivateKeySet()
    return bool  true if privateKey is set

###### OpenSSLPkcs12Factory::setPrivateKey( privateKey )
    Set privateKey, removes any previously set pkcs12
    
    privateKey   array|resource|string
                   1. A key resource returned from openssl_get_publickey() or openssl_get_privatekey()
                   2. For public keys only: an X.509 resource
                   3. A string having the format (file://)path/to/file.pem
                      The named file must contain a PEM encoded certificate/private key (it may contain both)
                   4. A string containing the content of a PEM encoded certificate/key
                   5 For private keys, you may also use the syntax array(key, passphrase)
                     where key represents a key specified using the file or textual content notation above,
                     and passphrase represents a string containing the passphrase for that private key
                     
    return static
    throws InvalidArgumentException on error


###### OpenSSLPkcs12Factory::getPkcs12PassWord()
     return string

###### OpenSSLPkcs12Factory::isPkcs12passWordSet()
    return bool  if pkcs12passWord is set

###### OpenSSLPkcs12Factory::setPkcs12PassWord( pkcs12passWord )
    pkcs12passWord  string
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLPkcs12Factory::getArgs()
    return array

###### OpenSSLPkcs12Factory::isArgsSet()
    return bool  true if args is set

###### OpenSSLPkcs12Factory::setArgs( args )
    args         array
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLPkcs12Factory::getPkcs12()
    If empty pkcs12 and x509 and privateKey (opt pkcs12PassWord and args) properties are set,
      a new string pkcs12 are set first ( using export)
    return string  the pkcs12 as string
    throws RuntimeException on error

###### OpenSSLPkcs12Factory::isPkcs12Set()
    return bool   true if pkcs12 is set

###### OpenSSLPkcs12Factory::setPkcs12( pkcs12 [, pkcs12passWord ] )
    pkcs12          string
    pkcs12passWord  string
    
    return static
    throws InvalidArgumentException on error


#### Usage and examples

Please review test/OpenSSLPkcs12FactoryTest.php

    pkcs12Test1*
      factory
      setX509
      setPrivateKey
      setPkcs12PassWord
      getPkcs12PassWord
      getPkcs12
      saveCertificateStoreIntoFile
      read
      getCertificateStoreAsArray
      getCertificates
      getKeys

    pkcs12Test3*
      exceptions

    pkcs12Test35
      setArgs
      getArgs


[[return to docs](docs.md)][[return to README](../README.md)]
