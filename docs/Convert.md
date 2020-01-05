## Convert Class

The class has only static methods.
    
<br>

>Base64

###### Convert::isBase64( string )
    string       string
    
    return bool   true if string is in base64

###### Convert::base64Encode( raw )
    raw          string
    
    return string   base64 encoded
    static method

###### Convert::base64Decode( encoded )
    encoded      string
    
    return string   base64 decoded string of arbitrary length
    static method

###### Convert::base64UrlEncode( raw )
    raw          string
    
    return string   base64url encoded
    static method

###### Convert::base64UrlDecode( encoded )
    encoded      string
    
    return string   base64url decoded
    static method

    
<br>

>isHex, String to hex and hex to string

###### Convert::isHex( string )
    string       string
    
    return bool   true if string is in hex

###### Convert::strToHex( string )
    string       string
    
    return string   hex converted from string
    static method

###### Convert::hexToStr( hex )
    hex          string
    
    return string  converted from hex
    static method
    
<br>

>'H*' - pack/unpack (hex) data

###### Convert::Hpack( input )
    input        mixed
    
    return string   binary string from a 'H*' packed hexadecimally encoded (binary) string
    static method

###### Convert::HunPack( binaryData )
    binaryData   string
    
    return mixed   (mixed) data from a 'H*' unpacked binary string
    static method


#### Usage and examples

    Please review test/ConvertTest.php

[[return to docs](docs.md)][[return to README](../README.md)]
