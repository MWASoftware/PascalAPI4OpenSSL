const
  openssl_lib_info = '';

  {$IFNDEF OPENSSL_NO_MIN_VERSION}
  min_supported_ssl_version =  ((((((byte(OPENSSL_VERSION_MAJOR) shl 8) + byte(OPENSSL_VERSION_MINOR)) shl 8) + byte (0)) shl 8) + byte(0)) shl 4; 
  {$ELSE}
  min_supported_ssl_version = 0;
  {$ENDIF}
  
