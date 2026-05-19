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

unit openssl_dtls1;

{
  Generated from OpenSSL 4.0.0 Header File dtls1.h - Tue 19 May 14:32:26 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_dtls1.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_prov_ssl;


{* Copyright 2005-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_DTLS1_H}
  {$define OPENSSL_DTLS1_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_DTLS1_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  { DTLS*_VERSION constants are defined in prov_ssl.h }
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  DTLS_MIN_VERSION = DTLS1_VERSION;
  DTLS_MAX_VERSION = DTLS1_2_VERSION;
  {$endif}

const
  DTLS1_VERSION_MAJOR = $FE;
  { Special value for method supporting multiple versions }
  DTLS_ANY_VERSION = $1FFFF;
  { lengths of messages }
  DTLS1_COOKIE_LENGTH = 255;
  DTLS1_RT_HEADER_LENGTH = 13;
  DTLS1_HM_HEADER_LENGTH = 12;
  DTLS1_HM_BAD_FRAGMENT = -(2);
  DTLS1_HM_FRAGMENT_RETRY = -(3);
  DTLS1_CCS_HEADER_LENGTH = 1;
  DTLS1_AL_HEADER_LENGTH = 2;
  DTLS1_TMO_ALERT_COUNT = 12;
{$endif}

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



