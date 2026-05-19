const
  openssl_lib_info = 'With Legacy Support for Indy use of OpenSSL 1.0.2 and 1.1.0';

  {$IFNDEF OPENSSL_NO_MIN_VERSION}
  min_supported_ssl_version =  ((((((byte(1) shl 8) + byte(0)) shl 8) + byte (2)) shl 8) + byte(0)) shl 4; {1.0.2}
  {$ELSE}
  min_supported_ssl_version = 0;
  {$ENDIF}

