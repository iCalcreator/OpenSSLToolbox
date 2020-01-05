## Workshop Class

The class has only static methods.

>Resource methods

###### Workshop::getResourceMetadata( resource, key = null )
    Return (key) metadata from streams/file pointers
    
    resource  resource
    key       string
    
    return array|string    (null if key if not found)
    static method

###### Workshop::isFileResource( resource )
    resource  resource
    
    return bool   true if resource is a file resource
    static method

###### Workshop::isResourceReadable( resource )
    resource  resource
    
    return bool   true if resource is readable
    static method

###### Workshop::isResourceWritable( resource )
    resource  resource
    
    return bool    true if resource is writeable
    static method

###### Workshop::getResourceContents( resource, argIx = null )
    resource  resource
    argIx     int|string
    
    return string   resource contents
    throws RuntimeException on error
    static method

###### Workshop::writeToResource( $resource, $data )
     Write data into (file) resource
     
    resource resource
    data     string
    
    throws RuntimeException on error
    static method


>File/Resource  methods

###### Workshop::getFileContent( fileName, argIx = null )
    fileName  string|resource
    argIx     int|string
    
    return string  file (resource) content
    throws InvalidArgumentException on error
    static method

###### Workshop::saveDataToFile( fileName, data )
    Save data into file (resource)
    
    fileName  string|resource
    data      string
    
    throws RuntimeException
    static method

>File  methods

###### Workshop::getNewFileInTmp( unique, ext = null, mode = 0600 )
    unique  string
    ext     string
    mode    int (oct)
    
    return string   filename, a new (and touched file),
                    opt with ext, mode default 0600, if exists, it's made empty
    static method

>Misc

###### Workshop::getRandomPseudoBytes( byteCnt, & cStrong = false )
    byteCnt  int
    cStrong  bool
    
    return string   cryptographically strong arg byteCnt bytes
    static method

###### Workshop::getSalt( byteCnt = null )
    byteCnt  int
    
    return string   (hex) cryptographically strong salt, default 64 bytes
    static method

###### Workshop::getAlgorithmFromIdentifier( identifier )
    identifier  string
    
    return string   (trailing)) algorithm from (URI) identifier
    throws InvalidArgumentException on error
    static method


#### Usage and examples

Please review test/WorkshopTest.php

    saveDataToFileTest11
      saveDataToFile + Exception

    getFileContentTest12
      getFileContent
 
    getNewFileInTmp18
      getNewFileInTmp

    testgetRandomPseudoBytes21
      getRandomPseudoBytes

    getSaltTest22
      getSalt

    getAlgorithmFromIdentifierTest23*
      getAlgorithmFromIdentifier
