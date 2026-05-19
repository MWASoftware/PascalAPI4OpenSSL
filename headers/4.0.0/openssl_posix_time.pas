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

unit openssl_posix_time;

{
  Generated from OpenSSL 4.0.0 Header File posix_time.h - Tue 19 May 14:33:05 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_posix_time.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_HEADER_POSIX_TIME_H}
  {$define OPENSSL_HEADER_POSIX_TIME_H}


  
  {* OPENSSL_posix_to_tm converts a int64_t POSIX time value in |time|,
  * which must be in the range of year 0000 to 9999, to a broken out
  * time value in |tm|. It returns one on success and zero on error.
  }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OPENSSL_posix_to_tm(time: TOpenSSL_C_LONG; out_tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_posix_to_tm';
  
  {* OPENSSL_tm_to_posix converts a time value between the years 0 and
  * 9999 in |tm| to a POSIX time value in |out|. One is returned on
  * success, zero is returned on failure. It is a failure if |tm|
  * contains out of range values.
  }
  function OPENSSL_tm_to_posix(tm: POpenSSL_C_TM; out_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_tm_to_posix';
  
  {* OPENSSL_timegm converts a time value between the years 0 and 9999
  * in |tm| to a time_t value in |out|. One is returned on success,
  * zero is returned on failure. It is a failure if the converted time
  * can not be represented in a time_t, or if the tm contains out of
  * range values.
  }
  function OPENSSL_timegm(tm: POpenSSL_C_TM; out_: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_timegm';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OPENSSL_posix_to_tm}
  {$EXTERNALSYM OPENSSL_tm_to_posix}
  {$EXTERNALSYM OPENSSL_timegm}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OPENSSL_posix_to_tm(time: TOpenSSL_C_LONG; out_tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_tm_to_posix(tm: POpenSSL_C_TM; out_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_timegm(tm: POpenSSL_C_TM; out_: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;

var
  OPENSSL_posix_to_tm: function(time: TOpenSSL_C_LONG; out_tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl = Load_OPENSSL_posix_to_tm;
  
  {* OPENSSL_tm_to_posix converts a time value between the years 0 and
  * 9999 in |tm| to a POSIX time value in |out|. One is returned on
  * success, zero is returned on failure. It is a failure if |tm|
  * contains out of range values.
  }
  OPENSSL_tm_to_posix: function(tm: POpenSSL_C_TM; out_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_OPENSSL_tm_to_posix;
  
  {* OPENSSL_timegm converts a time value between the years 0 and 9999
  * in |tm| to a time_t value in |out|. One is returned on success,
  * zero is returned on failure. It is a failure if the converted time
  * can not be represented in a time_t, or if the tm contains out of
  * range values.
  }
  OPENSSL_timegm: function(tm: POpenSSL_C_TM; out_: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_OPENSSL_timegm;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}
{ OPENSSL_HEADER_POSIX_TIME_H }

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
function Load_OPENSSL_posix_to_tm(time: TOpenSSL_C_LONG; out_tm: POpenSSL_C_TM): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_posix_to_tm := LoadLibCryptoFunction('OPENSSL_posix_to_tm');
  if not assigned(OPENSSL_posix_to_tm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_posix_to_tm');
  Result := OPENSSL_posix_to_tm(time, out_tm);
end;

function Load_OPENSSL_tm_to_posix(tm: POpenSSL_C_TM; out_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_tm_to_posix := LoadLibCryptoFunction('OPENSSL_tm_to_posix');
  if not assigned(OPENSSL_tm_to_posix) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_tm_to_posix');
  Result := OPENSSL_tm_to_posix(tm, out_);
end;

function Load_OPENSSL_timegm(tm: POpenSSL_C_TM; out_: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_timegm := LoadLibCryptoFunction('OPENSSL_timegm');
  if not assigned(OPENSSL_timegm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_timegm');
  Result := OPENSSL_timegm(tm, out_);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OPENSSL_posix_to_tm := Load_OPENSSL_posix_to_tm;
  OPENSSL_tm_to_posix := Load_OPENSSL_tm_to_posix;
  OPENSSL_timegm := Load_OPENSSL_timegm;
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



