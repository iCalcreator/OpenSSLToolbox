
## Assert Class

The class has only static methods.


###### Assert::bool( data, argIx = null, valueIfNull = null )
    Assert data is a boolean and return bool, accepts true/false/1/0
    
    data         mixed
    argIx        int/string
    valueIfNull  bool
    
    return bool
    throws InvalidArgumentException on error
    static method

###### Assert::int( data, argIx = null, valueIfNull = null ) 
    Assert data is an positiv integer (scalar) and return int
    
    data         mixed
    argIx        int|string
    valueIfNull  int
    
    throws InvalidArgumentException on error
    return int
    static method

###### Assert::string( data, argIx = null, valueIfNull = null )
    Assert data is a string (i.e. is a scalar) and return string
    
    data         mixed
    argIx        int|string
    valueIfNull  string
    
    throws InvalidArgumentException on error
    return string
    static method

###### Assert::fileName( fileName, argIx = null )
    Assert (path/)fileName is a (local) file or file resource
    
    fileName     string|resource
    argIx        int|string
    
    throws InvalidArgumentException on error
    static method

###### Assert::fileNameRead( fileName, argIx = null )
    Assert (path/)fileName is a readable (local) file (resource)
    
    fileName     string|resource
    argIx        int|string
    
    throws InvalidArgumentException on error

###### Assert::fileNameWrite( fileName, argIx = null )
    Assert (path/)fileName is a writable (local) file (resource)
    
    fileName     string|resource
    argIx        int|string
    
    throws InvalidArgumentException on error


#### Usage and examples
    Please review test/AssertTest.php


[[return to docs](docs.md)][[return to README](../README.md)]
