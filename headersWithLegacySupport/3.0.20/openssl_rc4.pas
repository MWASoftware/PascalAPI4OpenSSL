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

unit openssl_rc4;

{
  Generated from OpenSSL 3.0.20 Header File rc4.h - Tue 19 May 14:25:31 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_rc4.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_RC4_H}
  {$define OPENSSL_RC4_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_RC4_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_RC4}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  Prc4_key_st = ^Trc4_key_st;
  PPrc4_key_st = ^Prc4_key_st;
  PRC4_KEY = ^TRC4_KEY;
  PPRC4_KEY = ^PRC4_KEY;
  {end of auto-generated forward references}

  Trc4_key_st = record 
    x: TOpenSSL_C_UINT;
    y: TOpenSSL_C_UINT;
    data: array[0..255] of TOpenSSL_C_UINT;
  end;
  TRC4_KEY = Trc4_key_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RC4_options: PAnsiChar; cdecl; external CLibCrypto name 'RC4_options'; deprecated 'Since OpenSSL 3.0';
  procedure RC4_set_key(key: PRC4_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl; external CLibCrypto name 'RC4_set_key'; deprecated 'Since OpenSSL 3.0';
  procedure RC4(key: PRC4_KEY; len: TOpenSSL_C_SIZET; indata: Pbyte; outdata: Pbyte); cdecl; external CLibCrypto name 'RC4'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM RC4_options}
  {$EXTERNALSYM RC4_set_key}
  {$EXTERNALSYM RC4}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RC4_options: PAnsiChar; cdecl;
  procedure Load_RC4_set_key(key: PRC4_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl;
  procedure Load_RC4(key: PRC4_KEY; len: TOpenSSL_C_SIZET; indata: Pbyte; outdata: Pbyte); cdecl;

var
  RC4_options: function: PAnsiChar; cdecl = Load_RC4_options;
  RC4_set_key: procedure(key: PRC4_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl = Load_RC4_set_key;
  RC4: procedure(key: PRC4_KEY; len: TOpenSSL_C_SIZET; indata: Pbyte; outdata: Pbyte); cdecl = Load_RC4;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}
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
{$ifndef  OPENSSL_NO_RC4}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_RC4_options: PAnsiChar; cdecl;
begin
  RC4_options := LoadLibCryptoFunction('RC4_options');
  if not assigned(RC4_options) then
    {$if declared(LEGACY_RC4_options)}
    RC4_options := @LEGACY_RC4_options;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC4_options');
    {$ifend}
  Result := RC4_options;
end;

procedure Load_RC4_set_key(key: PRC4_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl;
begin
  RC4_set_key := LoadLibCryptoFunction('RC4_set_key');
  if not assigned(RC4_set_key) then
    {$if declared(LEGACY_RC4_set_key)}
    RC4_set_key := @LEGACY_RC4_set_key;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC4_set_key');
    {$ifend}
  RC4_set_key(key, len, data);
end;

procedure Load_RC4(key: PRC4_KEY; len: TOpenSSL_C_SIZET; indata: Pbyte; outdata: Pbyte); cdecl;
begin
  RC4 := LoadLibCryptoFunction('RC4');
  if not assigned(RC4) then
    {$if declared(LEGACY_RC4)}
    RC4 := @LEGACY_RC4;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC4');
    {$ifend}
  RC4(key, len, indata, outdata);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RC4}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_RC4}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  RC4_options := Load_RC4_options;
  RC4_set_key := Load_RC4_set_key;
  RC4 := Load_RC4;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RC4}
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



