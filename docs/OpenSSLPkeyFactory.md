## OpenSSLPkeyFactory class
extends OpenSSLBase, implements OpenSSLInterface

Wrapper for PHP OpenSSL PKEY functions, encapsulates the PKEY resource<br>
Note: You need to have a valid openssl.cnf installed for this to operate correctly.<br>
You will find convenient constants in OpenSSLInterface.<br>
Require a Psr\Log logger, provided by LoggerDepot<br>


Class constant

    PKEYRESOURCETYPE


Class properties

    pkeyResource  resource
                   pkey resource, type 'OpenSSL key'
    config        array
                   configArgs


>Class constructor and factory methods

###### OpenSSLPkeyFactory::__construct( [ configArgs ] )
    If argument configArgs is set, a new CSR (Certificate Signing Request) is set
    
    configArgs   array
                   Note, see setConfig(), below, for valid algos
                   
    throws InvalidArgumentException, RunTimeException on error

###### OpenSSLPkeyFactory::factory( [ configArgs ] )
    If argument configArgs is set, a new CSR (Certificate Signing Request) is set
    
    configArgs   array
                   Note, see setConfig(), below, for valid algos
                   
    throws InvalidArgumentException, RunTimeException on error
    static method
    return static


>Class logic methods

###### OpenSSLPkeyFactory::pKeyNew( [ configArgs ] )
    uses openssl_pkey_new
    Generates a new pKewy resource
    
    configArgs   array
                   If null, uses 'instance create'-configArgs, if set, otherwise from file 'openssl.cnf'
                   
    return static
    throws InvalidArgumentException, RuntimeException on error


###### OpenSSLPkeyFactory::getPrivatePublicKeyPairAsResources( [ passPhrase ] )
    joins getPrivateKeyAsResource, getDetails and getPublic
    
    passPhrase   string
    
    return array( privateKeyResource, publicKeyResource ), resource type 'OpenSSL key'
    throws InvalidArgumentException, throws RuntimeException on error

###### OpenSSLPkeyFactory::getPrivatePublicKeyPairAsPemStrings( [ $passPhrase [, $configArgs ] )
    joins export + getDetails
    
    passPhrase   string
                   opt private key passphrase
    configArgs array
                   opt private key config
                   If null, uses 'instance create'-configArgs, if set
                   
    return array( privateKeyString, publicKeyString )
    throws InvalidArgumentException, throws RuntimeException on error

###### OpenSSLPkeyFactory::savePrivatePublicKeyPairIntoPemFiles( privateFile, publicFile, [ passPhrase [, $configArgs ]])
    joins exportToFile + getDetails
    Saves privateKey and publicKey into PEM files
    
    privateFile  string
                   Path to the output private key file
    publicFile   string
                   Path to the output public key file
    passPhrase   string
    configArgs   array
                   If null, uses 'instance create'-configArgs, if set
                   
    return static
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::savePrivatePublicKeyPairIntoDerFiles( privateFile, publicFile, [ passPhrase [, $configArgs ]])
    extends exportToFile + getDetails
    Saves privateKey and publicKey into DER files
    
    privateFile  string
                   Path to the output private key file
    publicFile   string
                   Path to the output public key file
    passPhrase   string
    configArgs   array
                   If null, uses 'instance create'-configArgs, if set
                   
    return static
    throws InvalidArgumentException, RuntimeException on error


###### OpenSSLPkeyFactory::export( [ passPhrase [, configArgs ]] )
    uses openssl_pkey_export
    Return an exportable string representation of a private key
    
    passPhrase   string
    configArgs   array
                   If null, uses 'instance create'-configArgs, if set
                   
    return string  PEM format
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::getPrivateKeyAsPemString( [ passPhrase [, configArgs ]] )
    alias of export
    return string  PEM format

###### OpenSSLPkeyFactory::getPrivateKeyAsDerString( [ passPhrase [, configArgs ]] )
    extends export
    return string  DER format

###### OpenSSLPkeyFactory::getPrivateKeyAsResource( [ passPhrase ] )
    join of getPrivate/export
    
    passPhrase   string
                   Must be used if the specified key is encrypted (protected by a passphrase)
                   
    return resource
                   private key, type 'OpenSSL key'
    throws InvalidArgumentException, RuntimeException on error


###### OpenSSLPkeyFactory::exportToFile( fileName [, passPhrase [, configArgs]] )
    uses openssl_pkey_export_to_file
    Saves privateKey into PEM file
    
    fileName     string
                   Path to the output file.
    passPhrase   string
    configArgs   array
                   If null, uses 'instance create'-configArgs, if set
                   
    return static
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::savePrivateKeyIntoPemFile( fileName [, passPhrase [, configArgs]] )
    alias of OpenSSLPkeyFactory::exportToFile
    Saves privateKey into PEM file

###### OpenSSLPkeyFactory::savePrivateKeyIntoDerFile( fileName [, passPhrase [, configArgs]] )
    extends OpenSSLPkeyFactory::export
    Saves privateKey into DER file


###### OpenSSLPkeyFactory::getPrivate( key [, passPhrase ] )
    uses openssl_pkey_get_private
    
    key          resource|string
                   1. A pkey resource
                   2. A string having the format (file://)path/to/file.pem.
                   The named file must contain a PEM encoded certificate/private key (it may contain both).
                   3. A string, PEM formatted private key.
    passPhrase   string
                   Must be used if the specified key is encrypted (protected by a passphrase)
                   
    return resource
                   private key as resource, type 'OpenSSL key'
    throws InvalidArgumentException, RuntimeException on error
    static method


###### OpenSSLPkeyFactory::getDetails()
    uses openssl_pkey_get_details
    return array   the key details
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::isDetailsKeySet( [ key [, subKey ] )
    extends OpenSSLPkeyFactory::getDetails
    
    key          string
                   see OpenSSLInterface constants
    subKey       string
                   see OpenSSLInterface constants
    
    return bool    true if pKey details key (/subkey) is set
    throws InvalidArgumentException, RunTimeException

###### OpenSSLPkeyFactory::getDetailsKey( [ key [, subKey [, toBase64 ] ] )
    extends OpenSSLPkeyFactory::getDetails
    
    key          string
                   see OpenSSLInterface constants
    subKey       string  
                   see OpenSSLInterface constants
    toBase64     bool  
                   if key(/subKey) set, true (default) output in Base64, false not
    
    return string|array  null if not found
    throws InvalidArgumentException, RunTimeException

###### OpenSSLPkeyFactory::getDetailsRsaModulus( [ toBase64 ] )
    extends OpenSSLPkeyFactory::getDetails
    
    toBase64     bool
                   default true, output in Base64, false binary string
    
    return string  pKey details RSA modulus, null if not found
    throws RunTimeException

###### OpenSSLPkeyFactory::getDetailsRsaExponent( [ toBase64 ] )
    extends OpenSSLPkeyFactory::getDetails
    
    toBase64     bool
                   default true, output in Base64, false binary string
    
    return string  pKey details RSA public exponent, null if not found
    throws RunTimeException

###### OpenSSLPkeyFactory::getPublicKeyAsPemString()
    extends OpenSSLPkeyFactory::getDetails
    return string  PEM format
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::getPublicKeyAsDerString()
    extends OpenSSLPkeyFactory::getDetails
    return string  DER format
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::savePublicKeyintoPemFile( fileName )
    extends OpenSSLPkeyFactory::getDetails
    Saves publicKey into PEM file
    
    fileName     string
                   Path to the output file
                   
    return static
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::savePublicKeyintoDerFile( fileName )
    extends OpenSSLPkeyFactory::getDetails
    Save publicKey into DER file
    
    fileName     string
                   Path to the output file
                   
    return static
    throws InvalidArgumentException, RuntimeException on error

###### OpenSSLPkeyFactory::getPublicKeyResource()
    extends OpenSSLPkeyFactory::getDetails + OpenSSLPkeyFactory::getPublic
    return resource
                   public key as resource, type 'OpenSSL key'
    throws InvalidArgumentException, RuntimeException on error


###### OpenSSLPkeyFactory::getPublic( certificate )
    uses openssl_pkey_get_public
    Returns extracted public key (i.e. resource) from certificate, prepared for use
    
    certificate  resource|string
                   1. a resource :  X.509 certificate OR public key resource
                   2. a string having the format (file://)path/to/file.pem.
                      The named file must contain a PEM encoded certificate/public key (it may contain both).
                   3. a PEM formatted string : X.509 OR public key
                   
    return resource
                   public key as resource, type 'OpenSSL key'
    throws InvalidArgumentException, RuntimeException on error
    static method

###### OpenSSLPkeyFactory::getPublicKeyAsResource( certificate )
    alias of OpenSSLPkeyFactory::getPublic
    static method


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
      (openssl-get-md-methods or https://www.php.net/manual/en/openssl.signature-algos.php)
    if OpenSSLPkeyFactory::PRIVATEKEYBITS == key, validates values >= 384
    
    key          string
                   see OpenSSLInterface constants
    value        mixed
    
    return static
    throws InvalidArgumentException on error

###### OpenSSLPkeyFactory::setConfig( array config )
    if OpenSSLPkeyFactory::DIGESTALGO == (config) key, validates (config) algorithm
      (openssl-get-md-methods or https://www.php.net/manual/en/openssl.signature-algos.php)
    if OpenSSLPkeyFactory::PRIVATEKEYBITS == (config) key, validates (config) value >= 384
    
    config       array
    
    return static
    throws InvalidArgumentException on error


###### OpenSSLPkeyFactory::assertPkey( pKey [, argIx [, fileToString ]] )
    Return valid (source) (private/public) key
    
    pKey         resource|string|array
                   1. A key resource
                   2. A string having the format (file://)path/to/file.pem,
                      the named file must contain a PEM encoded certificate/private key (it may contain both)
                   3. A string containing the content of a PEM encoded certificate/key
                   4 For private keys, you may also use the syntax array(key, passphrase)
                     where key represents a key specified using the file or textual content notation above,
                     and passphrase represents a string containing the passphrase for that private key
    argIx        int|string
    fileToString bool
                   default false
                   
    return resource|string|array       if file, 'file://'-prefixed
    throws InvalidArgumentException on error
    static method

###### OpenSSLPkeyFactory::isValidPkeyResource( pkeyResource )
    pkeyResource string|resource
    
    return bool    true if pkeyResource is valid
    static method

###### OpenSSLPkeyFactory::freePkeyResource()
    uses openssl_pkey_free
    return static

###### OpenSSLPkeyFactory::getPkeyResource()
    return pKey resource

###### OpenSSLPkeyFactory::isPkeyResourceSet()
    return bool    true if pKeyResource is set

###### OpenSSLPkeyFactory::setPkeyResource( pkeyResource )
    pkeyResource  resource
    
    return static
    throws InvalidArgumentException on error


#### Usage and examples

Please review test/OpenSSLPkeyFactoryTest.php

    pkeyFactoryTest1
      exceptions

    pkeyFactoryTest21
      __construct
      getDetails
      getDetailsRsaModulus, getDetailsRsaExponent, isDetailsKeySet

    pkeyFactoryTest22
      getPrivat
        get private key as resource, string and file, with and without password

    pkeyFactoryTest23
      factory + pKeyNew
      getPkeyResource
      getPrivateKeyAsPemString
      getPrivateKeyAsDerString
      savePrivateKeyIntoPemFile
      savePrivateKeyIntoDerFile

    pkeyFactoryTest31
      getPublicKeyAsResource

    pkeyFactoryTest4* (Traits\PkeySealOpenTrait)
      __construct (+ pKeyNew)
      getPrivateKeyAsResource
      getPrivateKeyAsPemString
      savePrivateKeyIntoPemFile
      getPublicKeyResource
      getPublicKeyAsPemString
      savePublicKeyIntoPemFile
      getPrivatePublicKeyPairAsResources
      getPrivatePublicKeyPairAsPemStrings
      savePrivatePublicKeyPairIntoPemFiles

    pkeyFactoryTest51
      getPrivatePublicKeyPairAsDerStrings
      savePrivatePublicKeyPairIntoDerFiles


[[return to docs](docs.md)][[return to README](../README.md)]
