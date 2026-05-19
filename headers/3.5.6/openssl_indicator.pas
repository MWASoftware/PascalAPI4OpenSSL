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

unit openssl_indicator;

{
  Generated from OpenSSL 3.5.6 Header File indicator.h - Tue 19 May 14:27:51 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_indicator.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_params;


{* Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_INDICATOR_H}
  {$define OPENSSL_INDICATOR_H}

type
  {Auto-generated forward references}
  POSSL_INDICATOR_CALLBACK = ^TOSSL_INDICATOR_CALLBACK;
  PPOSSL_INDICATOR_CALLBACK = ^POSSL_INDICATOR_CALLBACK;
  {end of auto-generated forward references}

  TOSSL_INDICATOR_CALLBACK = function(type_: PAnsiChar; desc: PAnsiChar; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OSSL_INDICATOR_set_callback(libctx: POSSL_LIB_CTX; cb: POSSL_INDICATOR_CALLBACK); cdecl; external CLibCrypto name 'OSSL_INDICATOR_set_callback';
  procedure OSSL_INDICATOR_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl; external CLibCrypto name 'OSSL_INDICATOR_get_callback';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_INDICATOR_set_callback}
  {$EXTERNALSYM OSSL_INDICATOR_get_callback}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OSSL_INDICATOR_set_callback(libctx: POSSL_LIB_CTX; cb: POSSL_INDICATOR_CALLBACK); cdecl;
  procedure Load_OSSL_INDICATOR_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl;

var
  OSSL_INDICATOR_set_callback: procedure(libctx: POSSL_LIB_CTX; cb: POSSL_INDICATOR_CALLBACK); cdecl = Load_OSSL_INDICATOR_set_callback;
  OSSL_INDICATOR_get_callback: procedure(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl = Load_OSSL_INDICATOR_get_callback;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}
{ OPENSSL_INDICATOR_H }

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
procedure Load_OSSL_INDICATOR_set_callback(libctx: POSSL_LIB_CTX; cb: POSSL_INDICATOR_CALLBACK); cdecl;
begin
  OSSL_INDICATOR_set_callback := LoadLibCryptoFunction('OSSL_INDICATOR_set_callback');
  if not assigned(OSSL_INDICATOR_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_INDICATOR_set_callback');
  OSSL_INDICATOR_set_callback(libctx, cb);
end;

procedure Load_OSSL_INDICATOR_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl;
begin
  OSSL_INDICATOR_get_callback := LoadLibCryptoFunction('OSSL_INDICATOR_get_callback');
  if not assigned(OSSL_INDICATOR_get_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_INDICATOR_get_callback');
  OSSL_INDICATOR_get_callback(libctx, cb);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_INDICATOR_set_callback := Load_OSSL_INDICATOR_set_callback;
  OSSL_INDICATOR_get_callback := Load_OSSL_INDICATOR_get_callback;
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



