
## HashFactory Class

The class has only static methods.

###### HashFactory::assertAlgorithm( algorithm )
    Assert algorithm
    
    algorithm    string
    
    throws InvalidArgumentException
    return string  found, exact case
    static method

###### HashFactory::getDigestHash( algorithm, data [, rawOutput ] )
    Return a hash value (message digest), applied on (string) argument
    
    algorithm    string
    data         string
    rawOutput    bool
                   default false
    
    return string
    throws InvalidArgumentException
    static method

###### HashFactory::getDigestHashFromFile( algorithm, fileName [, rawOutput ] )
    Return a hash value using the contents of a given file
    
    algorithm    string
    fileName     string
                   URL describing location of file to be hashed; Supports fopen wrappers.
    rawOutput    bool
                   default false
    
    return string
    throws InvalidArgumentException
    static method

###### HashFactory::hashEquals( expected, actual )
    expected     string 
    actual       string
    
    return bool   true if hashes match
    static method


###### HashFactory::getHashPbkdf2( algo, passWord [, salt [, iterations [, length [, rawOutput ]]] )
    Return a PBKDF2 key derivation of a supplied password
    
    algo         string
                   Name of selected hashing algorithm (https://www.php.net/manual/en/function.hash-algos.php)
    passWord     string
                   The password to use for the derivation
    salt         string
                   The salt to use for the derivation. This value should be generated randomly.
                   default 64 bytes salt
    iterations   int
                   The number of internal iterations to perform for the derivation.
                   default 10000
    length       int
                   The length of the output string.
                   If raw_output is TRUE this corresponds to the byte-length of the derived key,
                   if raw_output is FALSE this corresponds to twice the byte-length of the derived key
                   (as every byte of the key is returned as two hexits).
                   if 0 is passed, DEFAULT, the entire output of the supplied algorithm is used.
    rawOutput    bool
                   true, outputs raw binary data. false (DEFAULT), outputs lowercase hexits.
    
    return string
    throws InvalidArgumentException
    static method
    


#### Usage and examples

Please review test/HashFactoryTest.php

    getDigestHash/getDigestHashFromFile
    assertAlgorithm - exceptions
    getDigestHashFromFile exceptions

    getHashPbkdf2
    getHashPbkdf2 exceptions

[[return to docs](docs.md)][[return to README](../README.md)]
