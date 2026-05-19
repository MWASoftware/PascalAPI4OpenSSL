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

unit openssl_rc2;

{
  Generated from OpenSSL 3.0.20 Header File rc2.h - Tue 19 May 14:16:26 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_rc2.obj}
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
{$ifndef  OPENSSL_RC2_H}
  {$define OPENSSL_RC2_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_RC2_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_RC2}

const
  RC2_BLOCK = 8;
  RC2_KEY_LENGTH = 16;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PRC2_INT = ^TRC2_INT;
  PPRC2_INT = ^PRC2_INT;
  {end of auto-generated forward references}

  TRC2_INT = TOpenSSL_C_UINT;

const
  RC2_ENCRYPT_ = 1;
  RC2_DECRYPT_ = 0;

type
  {Auto-generated forward references}
  Prc2_key_st = ^Trc2_key_st;
  PPrc2_key_st = ^Prc2_key_st;
  PRC2_KEY = ^TRC2_KEY;
  PPRC2_KEY = ^PRC2_KEY;
  {end of auto-generated forward references}

  Trc2_key_st = record 
    data: array[0..63] of TRC2_INT;
  end;
  TRC2_KEY = Trc2_key_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure RC2_set_key(key: PRC2_KEY; len: TOpenSSL_C_INT; data: Pbyte; bits: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RC2_set_key'; deprecated 'Since OpenSSL 3.0';
  procedure RC2_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PRC2_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RC2_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC2_encrypt(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl; external CLibCrypto name 'RC2_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC2_decrypt(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl; external CLibCrypto name 'RC2_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC2_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC2_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RC2_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RC2_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RC2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'RC2_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM RC2_set_key}
  {$EXTERNALSYM RC2_ecb_encrypt}
  {$EXTERNALSYM RC2_encrypt}
  {$EXTERNALSYM RC2_decrypt}
  {$EXTERNALSYM RC2_cbc_encrypt}
  {$EXTERNALSYM RC2_cfb64_encrypt}
  {$EXTERNALSYM RC2_ofb64_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_RC2_set_key(key: PRC2_KEY; len: TOpenSSL_C_INT; data: Pbyte; bits: TOpenSSL_C_INT); cdecl;
  procedure Load_RC2_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PRC2_KEY; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_RC2_encrypt(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl;
  procedure Load_RC2_decrypt(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl;
  procedure Load_RC2_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC2_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_RC2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_RC2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;

var
  RC2_set_key: procedure(key: PRC2_KEY; len: TOpenSSL_C_INT; data: Pbyte; bits: TOpenSSL_C_INT); cdecl = Load_RC2_set_key;
  RC2_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; key: PRC2_KEY; enc: TOpenSSL_C_INT); cdecl = Load_RC2_ecb_encrypt;
  RC2_encrypt: procedure(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl = Load_RC2_encrypt;
  RC2_decrypt: procedure(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl = Load_RC2_decrypt;
  RC2_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC2_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_RC2_cbc_encrypt;
  RC2_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_RC2_cfb64_encrypt;
  RC2_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl = Load_RC2_ofb64_encrypt;
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
{$ifndef  OPENSSL_NO_RC2}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_RC2_set_key(key: PRC2_KEY; len: TOpenSSL_C_INT; data: Pbyte; bits: TOpenSSL_C_INT); cdecl;
begin
  RC2_set_key := LoadLibCryptoFunction('RC2_set_key');
  if not assigned(RC2_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC2_set_key');
  RC2_set_key(key, len, data, bits);
end;

procedure Load_RC2_ecb_encrypt(in_: Pbyte; out_: Pbyte; key: PRC2_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  RC2_ecb_encrypt := LoadLibCryptoFunction('RC2_ecb_encrypt');
  if not assigned(RC2_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC2_ecb_encrypt');
  RC2_ecb_encrypt(in_, out_, key, enc);
end;

procedure Load_RC2_encrypt(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl;
begin
  RC2_encrypt := LoadLibCryptoFunction('RC2_encrypt');
  if not assigned(RC2_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC2_encrypt');
  RC2_encrypt(data, key);
end;

procedure Load_RC2_decrypt(data: POpenSSL_C_UINT; key: PRC2_KEY); cdecl;
begin
  RC2_decrypt := LoadLibCryptoFunction('RC2_decrypt');
  if not assigned(RC2_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC2_decrypt');
  RC2_decrypt(data, key);
end;

procedure Load_RC2_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PRC2_KEY; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  RC2_cbc_encrypt := LoadLibCryptoFunction('RC2_cbc_encrypt');
  if not assigned(RC2_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC2_cbc_encrypt');
  RC2_cbc_encrypt(in_, out_, length, ks, iv, enc);
end;

procedure Load_RC2_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  RC2_cfb64_encrypt := LoadLibCryptoFunction('RC2_cfb64_encrypt');
  if not assigned(RC2_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC2_cfb64_encrypt');
  RC2_cfb64_encrypt(in_, out_, length, schedule, ivec, num, enc);
end;

procedure Load_RC2_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PRC2_KEY; ivec: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  RC2_ofb64_encrypt := LoadLibCryptoFunction('RC2_ofb64_encrypt');
  if not assigned(RC2_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RC2_ofb64_encrypt');
  RC2_ofb64_encrypt(in_, out_, length, schedule, ivec, num);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RC2}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_RC2}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  RC2_set_key := Load_RC2_set_key;
  RC2_ecb_encrypt := Load_RC2_ecb_encrypt;
  RC2_encrypt := Load_RC2_encrypt;
  RC2_decrypt := Load_RC2_decrypt;
  RC2_cbc_encrypt := Load_RC2_cbc_encrypt;
  RC2_cfb64_encrypt := Load_RC2_cfb64_encrypt;
  RC2_ofb64_encrypt := Load_RC2_ofb64_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RC2}
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



