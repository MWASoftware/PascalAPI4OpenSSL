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

unit openssl_rc5;

{
  Generated from OpenSSL 4.0.0 Header File rc5.h - Tue 19 May 14:33:10 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_rc5.obj}
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
{$ifndef  OPENSSL_RC5_H}
  {$define OPENSSL_RC5_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_RC5_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_RC5}

const
  RC5_32_BLOCK = 8;
  RC5_32_KEY_LENGTH = 16;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  RC5_ENCRYPT = 1;
  RC5_DECRYPT = 0;

type
  {Auto-generated forward references}
  PRC5_32_INT = ^TRC5_32_INT;
  PPRC5_32_INT = ^PRC5_32_INT;
  {end of auto-generated forward references}

  TRC5_32_INT = TOpenSSL_C_UINT;

const
      
      {* This are the only values supported.  Tweak the code if you want more The
      * most supported modes will be RC5-32/12/16 RC5-32/16/8
      }
  RC5_8_ROUNDS = 8;
  RC5_12_ROUNDS = 12;
  RC5_16_ROUNDS = 16;

type
  {Auto-generated forward references}
  Prc5_key_st = ^Trc5_key_st;
  PPrc5_key_st = ^Prc5_key_st;
  PRC5_32_KEY = ^TRC5_32_KEY;
  PPRC5_32_KEY = ^PRC5_32_KEY;
  {end of auto-generated forward references}

  Trc5_key_st = record 
 { Number of rounds }
    rounds: TOpenSSL_C_INT;
    data: array[0..(2*(16+1))-1] of TRC5_32_INT;
  end;
  TRC5_32_KEY = Trc5_key_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RC5_32_set_key(key: PRC5_32_KEY; len: TOpenSSL_C_INT; data: Pbyte; rounds: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RC5_32_set_key'; deprecated 'Since OpenSSL 3.0';
  procedure RC5_32_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PRC5_32_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RC5_32_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC5_32_encrypt(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl; external CLibCrypto name 'RC5_32_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC5_32_decrypt(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl; external CLibCrypto name 'RC5_32_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC5_32_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC5_32_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RC5_32_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC5_32_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RC5_32_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC5_32_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'RC5_32_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM RC5_32_set_key}
  {$EXTERNALSYM RC5_32_ecb_encrypt}
  {$EXTERNALSYM RC5_32_encrypt}
  {$EXTERNALSYM RC5_32_decrypt}
  {$EXTERNALSYM RC5_32_cbc_encrypt}
  {$EXTERNALSYM RC5_32_cfb64_encrypt}
  {$EXTERNALSYM RC5_32_ofb64_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RC5_32_set_key(key: PRC5_32_KEY; len: TOpenSSL_C_INT; data: Pbyte; rounds: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_RC5_32_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PRC5_32_KEY; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_RC5_32_encrypt(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl;
  procedure Load_RC5_32_decrypt(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl;
  procedure Load_RC5_32_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC5_32_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_RC5_32_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_RC5_32_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;

var
  RC5_32_set_key: function(key: PRC5_32_KEY; len: TOpenSSL_C_INT; data: Pbyte; rounds: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RC5_32_set_key;
  RC5_32_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PRC5_32_KEY; enc: TOpenSSL_C_INT); cdecl = Load_RC5_32_ecb_encrypt;
  RC5_32_encrypt: procedure(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl = Load_RC5_32_encrypt;
  RC5_32_decrypt: procedure(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl = Load_RC5_32_decrypt;
  RC5_32_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC5_32_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_RC5_32_cbc_encrypt;
  RC5_32_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_RC5_32_cfb64_encrypt;
  RC5_32_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl = Load_RC5_32_ofb64_encrypt;
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
{$ifndef  OPENSSL_NO_RC5}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_RC5_32_set_key(key: PRC5_32_KEY; len: TOpenSSL_C_INT; data: Pbyte; rounds: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RC5_32_set_key := LoadLibCryptoFunction('RC5_32_set_key');
  if not assigned(RC5_32_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC5_32_set_key');
  Result := RC5_32_set_key(key, len, data, rounds);
end;

procedure Load_RC5_32_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PRC5_32_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  RC5_32_ecb_encrypt := LoadLibCryptoFunction('RC5_32_ecb_encrypt');
  if not assigned(RC5_32_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC5_32_ecb_encrypt');
  RC5_32_ecb_encrypt(in_, out_, key, enc);
end;

procedure Load_RC5_32_encrypt(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl;
begin
  RC5_32_encrypt := LoadLibCryptoFunction('RC5_32_encrypt');
  if not assigned(RC5_32_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC5_32_encrypt');
  RC5_32_encrypt(data, key);
end;

procedure Load_RC5_32_decrypt(data: POpenSSL_C_UINT; key: PRC5_32_KEY); cdecl;
begin
  RC5_32_decrypt := LoadLibCryptoFunction('RC5_32_decrypt');
  if not assigned(RC5_32_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC5_32_decrypt');
  RC5_32_decrypt(data, key);
end;

procedure Load_RC5_32_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC5_32_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  RC5_32_cbc_encrypt := LoadLibCryptoFunction('RC5_32_cbc_encrypt');
  if not assigned(RC5_32_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC5_32_cbc_encrypt');
  RC5_32_cbc_encrypt(in_, out_, length, ks, iv, enc);
end;

procedure Load_RC5_32_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  RC5_32_cfb64_encrypt := LoadLibCryptoFunction('RC5_32_cfb64_encrypt');
  if not assigned(RC5_32_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC5_32_cfb64_encrypt');
  RC5_32_cfb64_encrypt(in_, out_, length, schedule, ivec, num, enc);
end;

procedure Load_RC5_32_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC5_32_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  RC5_32_ofb64_encrypt := LoadLibCryptoFunction('RC5_32_ofb64_encrypt');
  if not assigned(RC5_32_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC5_32_ofb64_encrypt');
  RC5_32_ofb64_encrypt(in_, out_, length, schedule, ivec, num);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RC5}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_RC5}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  RC5_32_set_key := Load_RC5_32_set_key;
  RC5_32_ecb_encrypt := Load_RC5_32_ecb_encrypt;
  RC5_32_encrypt := Load_RC5_32_encrypt;
  RC5_32_decrypt := Load_RC5_32_decrypt;
  RC5_32_cbc_encrypt := Load_RC5_32_cbc_encrypt;
  RC5_32_cfb64_encrypt := Load_RC5_32_cfb64_encrypt;
  RC5_32_ofb64_encrypt := Load_RC5_32_ofb64_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RC5}
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



