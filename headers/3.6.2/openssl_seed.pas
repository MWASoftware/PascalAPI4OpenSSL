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

unit openssl_seed;

{
  Generated from OpenSSL 3.6.2 Header File seed.h - Tue 19 May 14:30:39 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_seed.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2,openssl_crypto;


{* Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}

{* Copyright (c) 2007 KISA(Korea Information Security Agency). All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Neither the name of author nor the names of its contributors may
*    be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
}
{$ifndef  OPENSSL_SEED_H}
  {$define OPENSSL_SEED_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_SEED_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_SEED}

const
  SEED_BLOCK_SIZE = 16;
  SEED_KEY_LENGTH = 16;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
      { look whether we need 'long' to get 32 bits }
      {$ifdef AES_LONG}
        {$ifndef  SEED_LONG}

const
  SEED_LONG = 1;
        {$endif}
      {$endif}

type
  {Auto-generated forward references}
  Pseed_key_st = ^Tseed_key_st;
  PPseed_key_st = ^Pseed_key_st;
  PSEED_KEY_SCHEDULE = ^TSEED_KEY_SCHEDULE;
  PPSEED_KEY_SCHEDULE = ^PSEED_KEY_SCHEDULE;
  {end of auto-generated forward references}

  Tseed_key_st = record 
    {$if declared(TSEED_LONG)}
      data: array[0..31] of TOpenSSL_C_UINT;
    {$else}
      data: array[0..31] of TOpenSSL_C_UINT;
    {$endif}
  end;
  TSEED_KEY_SCHEDULE = Tseed_key_st;
    {$endif}
    { OPENSSL_NO_DEPRECATED_3_0 }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure SEED_set_key(rawkey: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl; external CLibCrypto name 'SEED_set_key'; deprecated 'Since OpenSSL 3.0';
  procedure SEED_encrypt(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl; external CLibCrypto name 'SEED_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure SEED_decrypt(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl; external CLibCrypto name 'SEED_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure SEED_ecb_encrypt(in_: Pbyte; out_: Pbyte; ks: PSEED_KEY_SCHEDULE; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'SEED_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure SEED_cbc_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'SEED_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure SEED_cfb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'SEED_cfb128_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure SEED_ofb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'SEED_ofb128_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM SEED_set_key}
  {$EXTERNALSYM SEED_encrypt}
  {$EXTERNALSYM SEED_decrypt}
  {$EXTERNALSYM SEED_ecb_encrypt}
  {$EXTERNALSYM SEED_cbc_encrypt}
  {$EXTERNALSYM SEED_cfb128_encrypt}
  {$EXTERNALSYM SEED_ofb128_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_SEED_set_key(rawkey: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl;
  procedure Load_SEED_encrypt(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl;
  procedure Load_SEED_decrypt(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl;
  procedure Load_SEED_ecb_encrypt(in_: Pbyte; out_: Pbyte; ks: PSEED_KEY_SCHEDULE; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_SEED_cbc_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_SEED_cfb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_SEED_ofb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT); cdecl;

var
  SEED_set_key: procedure(rawkey: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl = Load_SEED_set_key;
  SEED_encrypt: procedure(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl = Load_SEED_encrypt;
  SEED_decrypt: procedure(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl = Load_SEED_decrypt;
  SEED_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; ks: PSEED_KEY_SCHEDULE; enc: TOpenSSL_C_INT); cdecl = Load_SEED_ecb_encrypt;
  SEED_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; enc: TOpenSSL_C_INT); cdecl = Load_SEED_cbc_encrypt;
  SEED_cfb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_SEED_cfb128_encrypt;
  SEED_ofb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT); cdecl = Load_SEED_ofb128_encrypt;
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
{$ifndef  OPENSSL_NO_SEED}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_SEED_set_key(rawkey: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl;
begin
  SEED_set_key := LoadLibCryptoFunction('SEED_set_key');
  if not assigned(SEED_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SEED_set_key');
  SEED_set_key(rawkey, ks);
end;

procedure Load_SEED_encrypt(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl;
begin
  SEED_encrypt := LoadLibCryptoFunction('SEED_encrypt');
  if not assigned(SEED_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SEED_encrypt');
  SEED_encrypt(s, d, ks);
end;

procedure Load_SEED_decrypt(s: array of byte; d: array of byte; ks: PSEED_KEY_SCHEDULE); cdecl;
begin
  SEED_decrypt := LoadLibCryptoFunction('SEED_decrypt');
  if not assigned(SEED_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SEED_decrypt');
  SEED_decrypt(s, d, ks);
end;

procedure Load_SEED_ecb_encrypt(in_: Pbyte; out_: Pbyte; ks: PSEED_KEY_SCHEDULE; enc: TOpenSSL_C_INT); cdecl;
begin
  SEED_ecb_encrypt := LoadLibCryptoFunction('SEED_ecb_encrypt');
  if not assigned(SEED_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SEED_ecb_encrypt');
  SEED_ecb_encrypt(in_, out_, ks, enc);
end;

procedure Load_SEED_cbc_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; enc: TOpenSSL_C_INT); cdecl;
begin
  SEED_cbc_encrypt := LoadLibCryptoFunction('SEED_cbc_encrypt');
  if not assigned(SEED_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SEED_cbc_encrypt');
  SEED_cbc_encrypt(in_, out_, len, ks, ivec, enc);
end;

procedure Load_SEED_cfb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  SEED_cfb128_encrypt := LoadLibCryptoFunction('SEED_cfb128_encrypt');
  if not assigned(SEED_cfb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SEED_cfb128_encrypt');
  SEED_cfb128_encrypt(in_, out_, len, ks, ivec, num, enc);
end;

procedure Load_SEED_ofb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; ks: PSEED_KEY_SCHEDULE; ivec: array of byte; num: POpenSSL_C_INT); cdecl;
begin
  SEED_ofb128_encrypt := LoadLibCryptoFunction('SEED_ofb128_encrypt');
  if not assigned(SEED_ofb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SEED_ofb128_encrypt');
  SEED_ofb128_encrypt(in_, out_, len, ks, ivec, num);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_SEED}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_SEED}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  SEED_set_key := Load_SEED_set_key;
  SEED_encrypt := Load_SEED_encrypt;
  SEED_decrypt := Load_SEED_decrypt;
  SEED_ecb_encrypt := Load_SEED_ecb_encrypt;
  SEED_cbc_encrypt := Load_SEED_cbc_encrypt;
  SEED_cfb128_encrypt := Load_SEED_cfb128_encrypt;
  SEED_ofb128_encrypt := Load_SEED_ofb128_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_SEED}
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



