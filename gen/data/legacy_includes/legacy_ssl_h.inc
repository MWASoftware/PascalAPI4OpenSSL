const
  SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE =220;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
type
    TOpenSSL_Version = (sslUnknown,sslvSSLv2, sslvSSLv23, sslvSSLv3, sslvTLSv1,sslvTLSv1_1,
                      sslvTLSv1_2, sslvTLSv1_3);

  procedure OpenSSL_SetMethod(aMethod: TOpenSSL_Version); {used for pre 1.1.0 OpenSSL}
  function IsOpenSSL_SSLv2_Available : Boolean;
  function IsOpenSSL_SSLv3_Available : Boolean;
  function IsOpenSSL_SSLv23_Available : Boolean;
  function IsOpenSSL_TLSv1_0_Available : Boolean;
  function IsOpenSSL_TLSv1_1_Available : Boolean;
  function IsOpenSSL_TLSv1_2_Available : Boolean;
  function HasTLS_method: boolean;
{$ENDIF}
{$ENDIF}
  
