## HmacHashFactory Class

The class has only static methods.


###### HmacHashFactory::assertAlgorithm( algorithm )
    Assert algorithm using 1. hash_hmac_algos (if exist), 2. hash_algos
    
    algorithm    string
    
    throws InvalidArgumentException on error
    return string
    static method

###### HmacHashFactory::getDigestHash( algorithm, data, secret, rawOutput = false )
    Return a keyed hash value using the HMAC method, applied on (string) argument
    
    algorithm    string
    data         string
    secret       string
    rawOutput    bool
                   default false
    
    return string     keyed hash value using the HMAC method, applied on (string) argument
    throws InvalidArgumentException on error
    static method

##### HmacHashFactory::getDigestHashFromFile( algorithm, fileName, secret, rawOutput = false )
    Return a keyed hash value using the HMAC method, applied on contents of a given file
    
    algorithm    string
    fileName     string  
                   URL describing location of file to be hashed; Supports fopen wrappers.
    secret       string
    rawOutput    bool
                   default false
    
    return string
    throws InvalidArgumentException on error
    static method

###### HmacHashFactory::hashEquals( expected, actual )
    expected     string 
    actual       string 
    
    return bool    true if hashes match
    static method

###### HmacHashFactory::oauth_totp( key [, time [, digits [, algorithm ]]] )
    Return HMAC-based One-Time Password (HOTP)
    This function implements the algorithm outlined in RFC 6238 for Time-Based One-Time Passwords
    
    key          string
                   the string to use for the HMAC key
    time         mixed
                   a value that reflects a time, default (unix) time()
    digits       int
                   the desired length of the OTP, default 8
    algorithm    string
                   default 'sha256'
    
    return string       the generated OTP
    throws InvalidArgumentException on error
    static method


#### Usage and examples

Please review test/HmacHashFactoryTest.php

    getDigestHash
    getDigestHashFromFile
    hashEquals
    assertAlgorithm
    getDigestHashFromFile exceptions
    oauth_totp

[[return to docs](docs.md)][[return to README](../README.md)]
