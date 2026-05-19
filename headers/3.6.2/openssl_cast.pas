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

unit openssl_cast;

{
  Generated from OpenSSL 3.6.2 Header File cast.h - Tue 19 May 14:29:28 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_cast.obj}
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
{$ifndef  OPENSSL_CAST_H}
  {$define OPENSSL_CAST_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_CAST_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_CAST}

const
  CAST_BLOCK = 8;
  CAST_KEY_LENGTH = 16;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  CAST_ENCRYPT_ = 1;
  CAST_DECRYPT_ = 0;

type
  {Auto-generated forward references}
  PCAST_LONG = ^TCAST_LONG;
  PPCAST_LONG = ^PCAST_LONG;
  Pcast_key_st = ^Tcast_key_st;
  PPcast_key_st = ^Pcast_key_st;
  PCAST_KEY = ^TCAST_KEY;
  PPCAST_KEY = ^PCAST_KEY;
  {end of auto-generated forward references}

  TCAST_LONG = TOpenSSL_C_UINT;
  Tcast_key_st = record 
    data: array[0..31] of TOpenSSL_C_UINT;
    short_key: TOpenSSL_C_INT; { Use reduced rounds for short key }
  end;
  TCAST_KEY = Tcast_key_st;
    {$endif}
    { OPENSSL_NO_DEPRECATED_3_0 }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure CAST_set_key(key: PCAST_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl; external CLibCrypto name 'CAST_set_key'; deprecated 'Since OpenSSL 3.0';
  procedure CAST_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PCAST_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'CAST_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure CAST_encrypt(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl; external CLibCrypto name 'CAST_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure CAST_decrypt(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl; external CLibCrypto name 'CAST_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure CAST_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PCAST_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'CAST_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure CAST_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'CAST_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure CAST_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'CAST_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM CAST_set_key}
  {$EXTERNALSYM CAST_ecb_encrypt}
  {$EXTERNALSYM CAST_encrypt}
  {$EXTERNALSYM CAST_decrypt}
  {$EXTERNALSYM CAST_cbc_encrypt}
  {$EXTERNALSYM CAST_cfb64_encrypt}
  {$EXTERNALSYM CAST_ofb64_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_CAST_set_key(key: PCAST_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl;
  procedure Load_CAST_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PCAST_KEY; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_CAST_encrypt(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl;
  procedure Load_CAST_decrypt(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl;
  procedure Load_CAST_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PCAST_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_CAST_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_CAST_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;

var
  CAST_set_key: procedure(key: PCAST_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl = Load_CAST_set_key;
  CAST_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PCAST_KEY; enc: TOpenSSL_C_INT); cdecl = Load_CAST_ecb_encrypt;
  CAST_encrypt: procedure(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl = Load_CAST_encrypt;
  CAST_decrypt: procedure(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl = Load_CAST_decrypt;
  CAST_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PCAST_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_CAST_cbc_encrypt;
  CAST_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_CAST_cfb64_encrypt;
  CAST_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl = Load_CAST_ofb64_encrypt;
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
{$ifndef  OPENSSL_NO_CAST}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_CAST_set_key(key: PCAST_KEY; len: TOpenSSL_C_INT; data: Pbyte); cdecl;
begin
  CAST_set_key := LoadLibCryptoFunction('CAST_set_key');
  if not assigned(CAST_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_set_key');
  CAST_set_key(key, len, data);
end;

procedure Load_CAST_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PCAST_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  CAST_ecb_encrypt := LoadLibCryptoFunction('CAST_ecb_encrypt');
  if not assigned(CAST_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_ecb_encrypt');
  CAST_ecb_encrypt(in_, out_, key, enc);
end;

procedure Load_CAST_encrypt(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl;
begin
  CAST_encrypt := LoadLibCryptoFunction('CAST_encrypt');
  if not assigned(CAST_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_encrypt');
  CAST_encrypt(data, key);
end;

procedure Load_CAST_decrypt(data: POpenSSL_C_UINT; key: PCAST_KEY); cdecl;
begin
  CAST_decrypt := LoadLibCryptoFunction('CAST_decrypt');
  if not assigned(CAST_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_decrypt');
  CAST_decrypt(data, key);
end;

procedure Load_CAST_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PCAST_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  CAST_cbc_encrypt := LoadLibCryptoFunction('CAST_cbc_encrypt');
  if not assigned(CAST_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_cbc_encrypt');
  CAST_cbc_encrypt(in_, out_, length, ks, iv, enc);
end;

procedure Load_CAST_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  CAST_cfb64_encrypt := LoadLibCryptoFunction('CAST_cfb64_encrypt');
  if not assigned(CAST_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_cfb64_encrypt');
  CAST_cfb64_encrypt(in_, out_, length, schedule, ivec, num, enc);
end;

procedure Load_CAST_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PCAST_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  CAST_ofb64_encrypt := LoadLibCryptoFunction('CAST_ofb64_encrypt');
  if not assigned(CAST_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_ofb64_encrypt');
  CAST_ofb64_encrypt(in_, out_, length, schedule, ivec, num);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_CAST}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_CAST}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  CAST_set_key := Load_CAST_set_key;
  CAST_ecb_encrypt := Load_CAST_ecb_encrypt;
  CAST_encrypt := Load_CAST_encrypt;
  CAST_decrypt := Load_CAST_decrypt;
  CAST_cbc_encrypt := Load_CAST_cbc_encrypt;
  CAST_cfb64_encrypt := Load_CAST_cfb64_encrypt;
  CAST_ofb64_encrypt := Load_CAST_ofb64_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_CAST}
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



