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

unit openssl_aes;

{
  Generated from OpenSSL 3.5.6 Header File aes.h - Tue 19 May 14:27:00 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_aes.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 2002-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_AES_H}
  {$define OPENSSL_AES_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_AES_H}
  {$endif}
  {$include openssl_opensslconf.inc}

const
  AES_BLOCK_SIZE = 16;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  AES_ENCRYPT_ = 1;
  AES_DECRYPT_ = 0;
  AES_MAXNR = 14;

type
  {Auto-generated forward references}
  Paes_key_st = ^Taes_key_st;
  PPaes_key_st = ^Paes_key_st;
  PAES_KEY = ^TAES_KEY;
  PPAES_KEY = ^PAES_KEY;
  {end of auto-generated forward references}

    { This should be a hidden type, but EVP requires that the size be known }
  Taes_key_st = record 
    {$ifdef AES_LONG}
      rd_key: array[0..(4*(14+1))-1] of TOpenSSL_C_UINT;
    {$else}
      rd_key: array[0..(4*(14+1))-1] of TOpenSSL_C_UINT;
    {$endif}
    rounds: TOpenSSL_C_INT;
  end;
  TAES_KEY = Taes_key_st;
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function AES_options: PAnsiChar; cdecl; external CLibCrypto name 'AES_options'; deprecated 'Since OpenSSL 3.0';
  function AES_set_encrypt_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'AES_set_encrypt_key'; deprecated 'Since OpenSSL 3.0';
  function AES_set_decrypt_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'AES_set_decrypt_key'; deprecated 'Since OpenSSL 3.0';
  procedure AES_encrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl; external CLibCrypto name 'AES_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure AES_decrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl; external CLibCrypto name 'AES_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure AES_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure AES_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure AES_cfb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_cfb128_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure AES_cfb1_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_cfb1_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure AES_cfb8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_cfb8_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure AES_ofb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_ofb128_encrypt'; deprecated 'Since OpenSSL 3.0';
  { NB: the IV is _two_ blocks long }
  procedure AES_ige_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_ige_encrypt'; deprecated 'Since OpenSSL 3.0';
  { NB: the IV is _four_ blocks long }
  procedure AES_bi_ige_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'AES_bi_ige_encrypt'; deprecated 'Since OpenSSL 3.0';
  function AES_wrap_key(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'AES_wrap_key'; deprecated 'Since OpenSSL 3.0';
  function AES_unwrap_key(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'AES_unwrap_key'; deprecated 'Since OpenSSL 3.0';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM AES_options}
  {$EXTERNALSYM AES_set_encrypt_key}
  {$EXTERNALSYM AES_set_decrypt_key}
  {$EXTERNALSYM AES_encrypt}
  {$EXTERNALSYM AES_decrypt}
  {$EXTERNALSYM AES_ecb_encrypt}
  {$EXTERNALSYM AES_cbc_encrypt}
  {$EXTERNALSYM AES_cfb128_encrypt}
  {$EXTERNALSYM AES_cfb1_encrypt}
  {$EXTERNALSYM AES_cfb8_encrypt}
  {$EXTERNALSYM AES_ofb128_encrypt}
  {$EXTERNALSYM AES_ige_encrypt}
  {$EXTERNALSYM AES_bi_ige_encrypt}
  {$EXTERNALSYM AES_wrap_key}
  {$EXTERNALSYM AES_unwrap_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_AES_options: PAnsiChar; cdecl;
  function Load_AES_set_encrypt_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl;
  function Load_AES_set_decrypt_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl;
  procedure Load_AES_encrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl;
  procedure Load_AES_decrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl;
  procedure Load_AES_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_AES_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_AES_cfb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_AES_cfb1_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_AES_cfb8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_AES_ofb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
  procedure Load_AES_ige_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_AES_bi_ige_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  function Load_AES_wrap_key(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_AES_unwrap_key(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

var
  AES_options: function: PAnsiChar; cdecl = Load_AES_options;
  AES_set_encrypt_key: function(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl = Load_AES_set_encrypt_key;
  AES_set_decrypt_key: function(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl = Load_AES_set_decrypt_key;
  AES_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl = Load_AES_encrypt;
  AES_decrypt: procedure(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl = Load_AES_decrypt;
  AES_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PAES_KEY; enc: TOpenSSL_C_INT); cdecl = Load_AES_ecb_encrypt;
  AES_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_AES_cbc_encrypt;
  AES_cfb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_AES_cfb128_encrypt;
  AES_cfb1_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_AES_cfb1_encrypt;
  AES_cfb8_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_AES_cfb8_encrypt;
  AES_ofb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl = Load_AES_ofb128_encrypt;
  { NB: the IV is _two_ blocks long }
  AES_ige_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_AES_ige_encrypt;
  { NB: the IV is _four_ blocks long }
  AES_bi_ige_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_AES_bi_ige_encrypt;
  AES_wrap_key: function(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_AES_wrap_key;
  AES_unwrap_key: function(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_AES_unwrap_key;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
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
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_AES_options: PAnsiChar; cdecl;
begin
  AES_options := LoadLibCryptoFunction('AES_options');
  if not assigned(AES_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_options');
  Result := AES_options;
end;

function Load_AES_set_encrypt_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl;
begin
  AES_set_encrypt_key := LoadLibCryptoFunction('AES_set_encrypt_key');
  if not assigned(AES_set_encrypt_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_set_encrypt_key');
  Result := AES_set_encrypt_key(userKey, bits, key);
end;

function Load_AES_set_decrypt_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PAES_KEY): TOpenSSL_C_INT; cdecl;
begin
  AES_set_decrypt_key := LoadLibCryptoFunction('AES_set_decrypt_key');
  if not assigned(AES_set_decrypt_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_set_decrypt_key');
  Result := AES_set_decrypt_key(userKey, bits, key);
end;

procedure Load_AES_encrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl;
begin
  AES_encrypt := LoadLibCryptoFunction('AES_encrypt');
  if not assigned(AES_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_encrypt');
  AES_encrypt(in_, out_, key);
end;

procedure Load_AES_decrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY); cdecl;
begin
  AES_decrypt := LoadLibCryptoFunction('AES_decrypt');
  if not assigned(AES_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_decrypt');
  AES_decrypt(in_, out_, key);
end;

procedure Load_AES_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PAES_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  AES_ecb_encrypt := LoadLibCryptoFunction('AES_ecb_encrypt');
  if not assigned(AES_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_ecb_encrypt');
  AES_ecb_encrypt(in_, out_, key, enc);
end;

procedure Load_AES_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  AES_cbc_encrypt := LoadLibCryptoFunction('AES_cbc_encrypt');
  if not assigned(AES_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cbc_encrypt');
  AES_cbc_encrypt(in_, out_, length, key, ivec, enc);
end;

procedure Load_AES_cfb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  AES_cfb128_encrypt := LoadLibCryptoFunction('AES_cfb128_encrypt');
  if not assigned(AES_cfb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cfb128_encrypt');
  AES_cfb128_encrypt(in_, out_, length, key, ivec, num, enc);
end;

procedure Load_AES_cfb1_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  AES_cfb1_encrypt := LoadLibCryptoFunction('AES_cfb1_encrypt');
  if not assigned(AES_cfb1_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cfb1_encrypt');
  AES_cfb1_encrypt(in_, out_, length, key, ivec, num, enc);
end;

procedure Load_AES_cfb8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  AES_cfb8_encrypt := LoadLibCryptoFunction('AES_cfb8_encrypt');
  if not assigned(AES_cfb8_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cfb8_encrypt');
  AES_cfb8_encrypt(in_, out_, length, key, ivec, num, enc);
end;

procedure Load_AES_ofb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  AES_ofb128_encrypt := LoadLibCryptoFunction('AES_ofb128_encrypt');
  if not assigned(AES_ofb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_ofb128_encrypt');
  AES_ofb128_encrypt(in_, out_, length, key, ivec, num);
end;

procedure Load_AES_ige_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  AES_ige_encrypt := LoadLibCryptoFunction('AES_ige_encrypt');
  if not assigned(AES_ige_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_ige_encrypt');
  AES_ige_encrypt(in_, out_, length, key, ivec, enc);
end;

procedure Load_AES_bi_ige_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PAES_KEY; key2: PAES_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  AES_bi_ige_encrypt := LoadLibCryptoFunction('AES_bi_ige_encrypt');
  if not assigned(AES_bi_ige_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_bi_ige_encrypt');
  AES_bi_ige_encrypt(in_, out_, length, key, key2, ivec, enc);
end;

function Load_AES_wrap_key(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  AES_wrap_key := LoadLibCryptoFunction('AES_wrap_key');
  if not assigned(AES_wrap_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_wrap_key');
  Result := AES_wrap_key(key, iv, out_, in_, inlen);
end;

function Load_AES_unwrap_key(key: PAES_KEY; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  AES_unwrap_key := LoadLibCryptoFunction('AES_unwrap_key');
  if not assigned(AES_unwrap_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('AES_unwrap_key');
  Result := AES_unwrap_key(key, iv, out_, in_, inlen);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  AES_options := Load_AES_options;
  AES_set_encrypt_key := Load_AES_set_encrypt_key;
  AES_set_decrypt_key := Load_AES_set_decrypt_key;
  AES_encrypt := Load_AES_encrypt;
  AES_decrypt := Load_AES_decrypt;
  AES_ecb_encrypt := Load_AES_ecb_encrypt;
  AES_cbc_encrypt := Load_AES_cbc_encrypt;
  AES_cfb128_encrypt := Load_AES_cfb128_encrypt;
  AES_cfb1_encrypt := Load_AES_cfb1_encrypt;
  AES_cfb8_encrypt := Load_AES_cfb8_encrypt;
  AES_ofb128_encrypt := Load_AES_ofb128_encrypt;
  AES_ige_encrypt := Load_AES_ige_encrypt;
  AES_bi_ige_encrypt := Load_AES_bi_ige_encrypt;
  AES_wrap_key := Load_AES_wrap_key;
  AES_unwrap_key := Load_AES_unwrap_key;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
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



