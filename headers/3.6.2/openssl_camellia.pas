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

unit openssl_camellia;

{
  Generated from OpenSSL 3.6.2 Header File camellia.h - Tue 19 May 14:29:28 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_camellia.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 2006-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CAMELLIA_H}
  {$define OPENSSL_CAMELLIA_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_CAMELLIA_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_CAMELLIA}

const
  CAMELLIA_BLOCK_SIZE = 16;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  CAMELLIA_ENCRYPT_ = 1;
  CAMELLIA_DECRYPT_ = 0;
      
      {* Because array size can't be a const in C, the following two are macros.
      * Both sizes are in bytes.
      }
      { This should be a hidden type, but EVP requires that the size be known }
  CAMELLIA_TABLE_BYTE_LEN = 272;
  CAMELLIA_TABLE_WORD_LEN = CAMELLIA_TABLE_BYTE_LEN/4;

type
  {Auto-generated forward references}
  PKEY_TABLE_TYPE = ^TKEY_TABLE_TYPE;
  PPKEY_TABLE_TYPE = ^PKEY_TABLE_TYPE;
  Pcamellia_key_st = ^Tcamellia_key_st;
  PPcamellia_key_st = ^Pcamellia_key_st;
  PCAMELLIA_KEY = ^TCAMELLIA_KEY;
  PPCAMELLIA_KEY = ^PCAMELLIA_KEY;
  {end of auto-generated forward references}

  TKEY_TABLE_TYPE = array[0..(272 div 4)-1] of TOpenSSL_C_UINT;
      { to match
      * with WORD }
  Tcamellia_key_st = record 
    u: record 
      case integer of 
        0: (d: TOpenSSL_C_DOUBLE); { ensures 64-bit align }
        1: (rd_key: TKEY_TABLE_TYPE);
    end;
    grand_rounds: TOpenSSL_C_INT;
  end;
  TCAMELLIA_KEY = Tcamellia_key_st;
    {$endif}
    { OPENSSL_NO_DEPRECATED_3_0 }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function Camellia_set_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'Camellia_set_key'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_encrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl; external CLibCrypto name 'Camellia_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_decrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl; external CLibCrypto name 'Camellia_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'Camellia_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'Camellia_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_cfb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'Camellia_cfb128_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_cfb1_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'Camellia_cfb1_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_cfb8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'Camellia_cfb8_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_ofb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'Camellia_ofb128_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure Camellia_ctr128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT); cdecl; external CLibCrypto name 'Camellia_ctr128_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM Camellia_set_key}
  {$EXTERNALSYM Camellia_encrypt}
  {$EXTERNALSYM Camellia_decrypt}
  {$EXTERNALSYM Camellia_ecb_encrypt}
  {$EXTERNALSYM Camellia_cbc_encrypt}
  {$EXTERNALSYM Camellia_cfb128_encrypt}
  {$EXTERNALSYM Camellia_cfb1_encrypt}
  {$EXTERNALSYM Camellia_cfb8_encrypt}
  {$EXTERNALSYM Camellia_ofb128_encrypt}
  {$EXTERNALSYM Camellia_ctr128_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_Camellia_set_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl;
  procedure Load_Camellia_encrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl;
  procedure Load_Camellia_decrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl;
  procedure Load_Camellia_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_Camellia_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_Camellia_cfb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_Camellia_cfb1_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_Camellia_cfb8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_Camellia_ofb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
  procedure Load_Camellia_ctr128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT); cdecl;

var
  Camellia_set_key: function(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl = Load_Camellia_set_key;
  Camellia_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl = Load_Camellia_encrypt;
  Camellia_decrypt: procedure(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl = Load_Camellia_decrypt;
  Camellia_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY; enc: TOpenSSL_C_INT); cdecl = Load_Camellia_ecb_encrypt;
  Camellia_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cbc_encrypt;
  Camellia_cfb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cfb128_encrypt;
  Camellia_cfb1_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cfb1_encrypt;
  Camellia_cfb8_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_Camellia_cfb8_encrypt;
  Camellia_ofb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl = Load_Camellia_ofb128_encrypt;
  Camellia_ctr128_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT); cdecl = Load_Camellia_ctr128_encrypt;
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
{$ifndef  OPENSSL_NO_CAMELLIA}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_Camellia_set_key(userKey: Pbyte; bits: TOpenSSL_C_INT; key: PCAMELLIA_KEY): TOpenSSL_C_INT; cdecl;
begin
  Camellia_set_key := LoadLibCryptoFunction('Camellia_set_key');
  if not assigned(Camellia_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_set_key');
  Result := Camellia_set_key(userKey, bits, key);
end;

procedure Load_Camellia_encrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl;
begin
  Camellia_encrypt := LoadLibCryptoFunction('Camellia_encrypt');
  if not assigned(Camellia_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_encrypt');
  Camellia_encrypt(in_, out_, key);
end;

procedure Load_Camellia_decrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY); cdecl;
begin
  Camellia_decrypt := LoadLibCryptoFunction('Camellia_decrypt');
  if not assigned(Camellia_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_decrypt');
  Camellia_decrypt(in_, out_, key);
end;

procedure Load_Camellia_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PCAMELLIA_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_ecb_encrypt := LoadLibCryptoFunction('Camellia_ecb_encrypt');
  if not assigned(Camellia_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_ecb_encrypt');
  Camellia_ecb_encrypt(in_, out_, key, enc);
end;

procedure Load_Camellia_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cbc_encrypt := LoadLibCryptoFunction('Camellia_cbc_encrypt');
  if not assigned(Camellia_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cbc_encrypt');
  Camellia_cbc_encrypt(in_, out_, length, key, ivec, enc);
end;

procedure Load_Camellia_cfb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cfb128_encrypt := LoadLibCryptoFunction('Camellia_cfb128_encrypt');
  if not assigned(Camellia_cfb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cfb128_encrypt');
  Camellia_cfb128_encrypt(in_, out_, length, key, ivec, num, enc);
end;

procedure Load_Camellia_cfb1_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cfb1_encrypt := LoadLibCryptoFunction('Camellia_cfb1_encrypt');
  if not assigned(Camellia_cfb1_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cfb1_encrypt');
  Camellia_cfb1_encrypt(in_, out_, length, key, ivec, num, enc);
end;

procedure Load_Camellia_cfb8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  Camellia_cfb8_encrypt := LoadLibCryptoFunction('Camellia_cfb8_encrypt');
  if not assigned(Camellia_cfb8_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_cfb8_encrypt');
  Camellia_cfb8_encrypt(in_, out_, length, key, ivec, num, enc);
end;

procedure Load_Camellia_ofb128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  Camellia_ofb128_encrypt := LoadLibCryptoFunction('Camellia_ofb128_encrypt');
  if not assigned(Camellia_ofb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_ofb128_encrypt');
  Camellia_ofb128_encrypt(in_, out_, length, key, ivec, num);
end;

procedure Load_Camellia_ctr128_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: PCAMELLIA_KEY; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT); cdecl;
begin
  Camellia_ctr128_encrypt := LoadLibCryptoFunction('Camellia_ctr128_encrypt');
  if not assigned(Camellia_ctr128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('Camellia_ctr128_encrypt');
  Camellia_ctr128_encrypt(in_, out_, length, key, ivec, ecount_buf, num);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_CAMELLIA}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_CAMELLIA}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  Camellia_set_key := Load_Camellia_set_key;
  Camellia_encrypt := Load_Camellia_encrypt;
  Camellia_decrypt := Load_Camellia_decrypt;
  Camellia_ecb_encrypt := Load_Camellia_ecb_encrypt;
  Camellia_cbc_encrypt := Load_Camellia_cbc_encrypt;
  Camellia_cfb128_encrypt := Load_Camellia_cfb128_encrypt;
  Camellia_cfb1_encrypt := Load_Camellia_cfb1_encrypt;
  Camellia_cfb8_encrypt := Load_Camellia_cfb8_encrypt;
  Camellia_ofb128_encrypt := Load_Camellia_ofb128_encrypt;
  Camellia_ctr128_encrypt := Load_Camellia_ctr128_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_CAMELLIA}
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



