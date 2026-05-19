{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License"), and as
    a derived work of the OpenSSL Project (see below for the original licence text).

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.
}

{$include openssl_defines.inc}

unit openssl_fips_names;

{
  Generated from OpenSSL 4.0.0 Header File fips_names.h - Tue 19 May 14:32:43 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_fips_names.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_core_names;


{* Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_FIPS_NAMES_H}
  {$define OPENSSL_FIPS_NAMES_H}

const
  
  {* Parameter names that the FIPS Provider defines
  * All parameters are of type: OSSL_PARAM_UTF8_STRING
  }
  { The following 4 Parameters are used for FIPS Self Testing }
  { The calculated MAC of the module file }
  OSSL_PROV_FIPS_PARAM_MODULE_MAC = 'module-mac';
  { The Version number for the fips install process }
  OSSL_PROV_FIPS_PARAM_INSTALL_VERSION = 'install-version';
  { The calculated MAC of the install status indicator }
  OSSL_PROV_FIPS_PARAM_INSTALL_MAC = 'install-mac';
  { The install status indicator }
  OSSL_PROV_FIPS_PARAM_INSTALL_STATUS = 'install-status';
  
  {* A boolean that determines if the FIPS conditional test errors result in
  * the module entering an error state.
  * Type: OSSL_PARAM_UTF8_STRING
  }
  OSSL_PROV_FIPS_PARAM_CONDITIONAL_ERRORS = 'conditional-errors';
  
  {* A boolean that determines if all the FIPS conditional self-test are executed
  * at module startup or deferred and run only when an algorithm is invoked
  }
  OSSL_PROV_FIPS_PARAM_DEFER_TESTS = 'defer-tests';
  { The following are provided for backwards compatibility }
  OSSL_PROV_FIPS_PARAM_SECURITY_CHECKS = OSSL_PROV_PARAM_SECURITY_CHECKS;
  OSSL_PROV_FIPS_PARAM_TLS1_PRF_EMS_CHECK = OSSL_PROV_PARAM_TLS1_PRF_EMS_CHECK;
  OSSL_PROV_FIPS_PARAM_DRBG_TRUNC_DIGEST = OSSL_PROV_PARAM_DRBG_TRUNC_DIGEST;
{$endif}
{ OPENSSL_FIPS_NAMES_H }

implementation

uses Sysutils, variants
  {$ifdef OPENSSL_INTERNAL_NEED_THREADS}
   {$IFNDEF FPC}
     ,System.SyncObjs
     {$IFDEF POSIX}
       ,Posix.Pthread
     {$ELSE}
       ,Windows
     {$ENDIF}
   {$ELSE}
     ,SyncObjs
   {$ENDIF}
  {$endif}
  ,Classes, OpenSSLExceptionHandlers;

  {$if not declared(__FILE__)}
  const
    {$ifdef FPC}
    __FILE__ = {$include %FILE%};
    {$else}
    __FILE__ = '$(INPUTFILENAME)';
    {$endif}
  {$ifend}
  {$if not declared(__LINE__)}
  const
    __LINE__ = 0;
  {$ifend}
  {$if not declared(OPENSSL_FILE)}
  const
    OPENSSL_FILE = __FILE__;
  {$ifend}
  {$if not declared(OPENSSL_LINE)}
  const
    OPENSSL_LINE  = 0;
  {$ifend}

{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
end;

{$endif} {OPENSSL_STATIC_LINK_MODEL}

initialization

{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef EMPTY_LOAD_FUNCTION}
Register_SSLloader(@Load);
{$endif}
Register_SSLUnloader(@Unload);
{$endif}
{$if declared(LegacySupport_Initialization)}
LegacySupport_Initialization;
{$ifend}

finalization

{$if declared(LegacySupport_Finalization)}
LegacySupport_Finalization;
{$ifend}

end.



