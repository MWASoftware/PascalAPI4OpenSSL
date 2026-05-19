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

unit openssl_blowfish;

{
  Generated from OpenSSL 3.5.6 Header File blowfish.h - Tue 19 May 14:27:05 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_blowfish.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2;


{* Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_BLOWFISH_H}
  {$define OPENSSL_BLOWFISH_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_BLOWFISH_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_BF}

const
  BF_BLOCK = 8;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  BF_ENCRYPT_ = 1;
  BF_DECRYPT_ = 0;

type
  {Auto-generated forward references}
  PBF_LONG = ^TBF_LONG;
  PPBF_LONG = ^PBF_LONG;
  {end of auto-generated forward references}

      {-
      * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      * ! BF_LONG has to be at least 32 bits wide.                     !
      * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      }
  TBF_LONG = TOpenSSL_C_UINT;

const
  BF_ROUNDS = 16;

type
  {Auto-generated forward references}
  Pbf_key_st = ^Tbf_key_st;
  PPbf_key_st = ^Pbf_key_st;
  PBF_KEY = ^TBF_KEY;
  PPBF_KEY = ^PBF_KEY;
  {end of auto-generated forward references}

  Tbf_key_st = record 
    P: array[0..(16+2)-1] of TOpenSSL_C_UINT;
    S: array[0..(4*256)-1] of TOpenSSL_C_UINT;
  end;
  TBF_KEY = Tbf_key_st;
    {$endif}
    { OPENSSL_NO_DEPRECATED_3_0 }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl; external CLibCrypto name 'BF_set_key'; deprecated 'Since OpenSSL 3.0';
  procedure BF_encrypt(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl; external CLibCrypto name 'BF_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure BF_decrypt(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl; external CLibCrypto name 'BF_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure BF_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'BF_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure BF_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'BF_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure BF_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'BF_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure BF_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'BF_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  function BF_options: PAnsiChar; cdecl; external CLibCrypto name 'BF_options'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM BF_set_key}
  {$EXTERNALSYM BF_encrypt}
  {$EXTERNALSYM BF_decrypt}
  {$EXTERNALSYM BF_ecb_encrypt}
  {$EXTERNALSYM BF_cbc_encrypt}
  {$EXTERNALSYM BF_cfb64_encrypt}
  {$EXTERNALSYM BF_ofb64_encrypt}
  {$EXTERNALSYM BF_options}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl;
  procedure Load_BF_encrypt(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl;
  procedure Load_BF_decrypt(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl;
  procedure Load_BF_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_BF_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_BF_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_BF_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
  function Load_BF_options: PAnsiChar; cdecl;

var
  BF_set_key: procedure(key: PBF_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl = Load_BF_set_key;
  BF_encrypt: procedure(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl = Load_BF_encrypt;
  BF_decrypt: procedure(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl = Load_BF_decrypt;
  BF_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl = Load_BF_ecb_encrypt;
  BF_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_BF_cbc_encrypt;
  BF_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_BF_cfb64_encrypt;
  BF_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl = Load_BF_ofb64_encrypt;
  BF_options: function: PAnsiChar; cdecl = Load_BF_options;
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
{$ifndef  OPENSSL_NO_BF}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl;
begin
  BF_set_key := LoadLibCryptoFunction('BF_set_key');
  if not assigned(BF_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_set_key');
  BF_set_key(key, len, data);
end;

procedure Load_BF_encrypt(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl;
begin
  BF_encrypt := LoadLibCryptoFunction('BF_encrypt');
  if not assigned(BF_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_encrypt');
  BF_encrypt(data, key);
end;

procedure Load_BF_decrypt(data: POpenSSL_C_UINT; key: PBF_KEY); cdecl;
begin
  BF_decrypt := LoadLibCryptoFunction('BF_decrypt');
  if not assigned(BF_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_decrypt');
  BF_decrypt(data, key);
end;

procedure Load_BF_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  BF_ecb_encrypt := LoadLibCryptoFunction('BF_ecb_encrypt');
  if not assigned(BF_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_ecb_encrypt');
  BF_ecb_encrypt(in_, out_, key, enc);
end;

procedure Load_BF_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  BF_cbc_encrypt := LoadLibCryptoFunction('BF_cbc_encrypt');
  if not assigned(BF_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_cbc_encrypt');
  BF_cbc_encrypt(in_, out_, length, schedule, ivec, enc);
end;

procedure Load_BF_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  BF_cfb64_encrypt := LoadLibCryptoFunction('BF_cfb64_encrypt');
  if not assigned(BF_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_cfb64_encrypt');
  BF_cfb64_encrypt(in_, out_, length, schedule, ivec, num, enc);
end;

procedure Load_BF_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PBF_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  BF_ofb64_encrypt := LoadLibCryptoFunction('BF_ofb64_encrypt');
  if not assigned(BF_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_ofb64_encrypt');
  BF_ofb64_encrypt(in_, out_, length, schedule, ivec, num);
end;

function Load_BF_options: PAnsiChar; cdecl;
begin
  BF_options := LoadLibCryptoFunction('BF_options');
  if not assigned(BF_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BF_options');
  Result := BF_options;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_BF}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_BF}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  BF_set_key := Load_BF_set_key;
  BF_encrypt := Load_BF_encrypt;
  BF_decrypt := Load_BF_decrypt;
  BF_ecb_encrypt := Load_BF_ecb_encrypt;
  BF_cbc_encrypt := Load_BF_cbc_encrypt;
  BF_cfb64_encrypt := Load_BF_cfb64_encrypt;
  BF_ofb64_encrypt := Load_BF_ofb64_encrypt;
  BF_options := Load_BF_options;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_BF}
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



