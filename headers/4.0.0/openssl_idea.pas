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

unit openssl_idea;

{
  Generated from OpenSSL 4.0.0 Header File idea.h - Tue 19 May 14:32:46 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_idea.obj}
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
{$ifndef  OPENSSL_IDEA_H}
  {$define OPENSSL_IDEA_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_IDEA_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_IDEA}

const
  IDEA_BLOCK = 8;
  IDEA_KEY_LENGTH = 16;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PIDEA_INT = ^TIDEA_INT;
  PPIDEA_INT = ^PIDEA_INT;
  {end of auto-generated forward references}

  TIDEA_INT = TOpenSSL_C_UINT;

const
  IDEA_ENCRYPT_ = 1;
  IDEA_DECRYPT = 0;

type
  {Auto-generated forward references}
  Pidea_key_st = ^Tidea_key_st;
  PPidea_key_st = ^Pidea_key_st;
  PIDEA_KEY_SCHEDULE = ^TIDEA_KEY_SCHEDULE;
  PPIDEA_KEY_SCHEDULE = ^PIDEA_KEY_SCHEDULE;
  {end of auto-generated forward references}

  Tidea_key_st = record 
    data: array[0..8] of TIDEA_INT;
  end;
  TIDEA_KEY_SCHEDULE = Tidea_key_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function IDEA_options: PAnsiChar; cdecl; external CLibCrypto name 'IDEA_options'; deprecated 'Since OpenSSL 3.0';
  procedure IDEA_ecb_encrypt(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure IDEA_set_encrypt_key(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_set_encrypt_key'; deprecated 'Since OpenSSL 3.0';
  procedure IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_set_decrypt_key'; deprecated 'Since OpenSSL 3.0';
  procedure IDEA_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'IDEA_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure IDEA_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'IDEA_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure IDEA_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'IDEA_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure IDEA_encrypt(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM IDEA_options}
  {$EXTERNALSYM IDEA_ecb_encrypt}
  {$EXTERNALSYM IDEA_set_encrypt_key}
  {$EXTERNALSYM IDEA_set_decrypt_key}
  {$EXTERNALSYM IDEA_cbc_encrypt}
  {$EXTERNALSYM IDEA_cfb64_encrypt}
  {$EXTERNALSYM IDEA_ofb64_encrypt}
  {$EXTERNALSYM IDEA_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_IDEA_options: PAnsiChar; cdecl;
  procedure Load_IDEA_ecb_encrypt(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
  procedure Load_IDEA_set_encrypt_key(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
  procedure Load_IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
  procedure Load_IDEA_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_IDEA_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_IDEA_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl;
  procedure Load_IDEA_encrypt(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl;

var
  IDEA_options: function: PAnsiChar; cdecl = Load_IDEA_options;
  IDEA_ecb_encrypt: procedure(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_ecb_encrypt;
  IDEA_set_encrypt_key: procedure(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_set_encrypt_key;
  IDEA_set_decrypt_key: procedure(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_set_decrypt_key;
  IDEA_cbc_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_IDEA_cbc_encrypt;
  IDEA_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_IDEA_cfb64_encrypt;
  IDEA_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl = Load_IDEA_ofb64_encrypt;
  IDEA_encrypt: procedure(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_IDEA_encrypt;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function idea_options_: PAnsiChar; cdecl; external CLibCrypto name 'IDEA_options'; deprecated 'Since OpenSSL 3.0';
  procedure idea_ecb_encrypt_(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure idea_set_encrypt_key_(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_set_encrypt_key'; deprecated 'Since OpenSSL 3.0';
  procedure idea_set_decrypt_key_(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_set_decrypt_key'; deprecated 'Since OpenSSL 3.0';
  procedure idea_cbc_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'IDEA_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure idea_cfb64_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'IDEA_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure idea_ofb64_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'IDEA_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure idea_encrypt__(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto name 'IDEA_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM idea_options_}
  {$EXTERNALSYM idea_ecb_encrypt_}
  {$EXTERNALSYM idea_set_encrypt_key_}
  {$EXTERNALSYM idea_set_decrypt_key_}
  {$EXTERNALSYM idea_cbc_encrypt_}
  {$EXTERNALSYM idea_cfb64_encrypt_}
  {$EXTERNALSYM idea_ofb64_encrypt_}
  {$EXTERNALSYM idea_encrypt__}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_idea_options_: PAnsiChar; cdecl;
  procedure Load_idea_ecb_encrypt_(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
  procedure Load_idea_set_encrypt_key_(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
  procedure Load_idea_set_decrypt_key_(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
  procedure Load_idea_cbc_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_idea_cfb64_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_idea_ofb64_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl;
  procedure Load_idea_encrypt__(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl;

var
  idea_options_: function: PAnsiChar; cdecl = Load_idea_options_;
  idea_ecb_encrypt_: procedure(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_idea_ecb_encrypt_;
  idea_set_encrypt_key_: procedure(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_idea_set_encrypt_key_;
  idea_set_decrypt_key_: procedure(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl = Load_idea_set_decrypt_key_;
  idea_cbc_encrypt_: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl = Load_idea_cbc_encrypt_;
  idea_cfb64_encrypt_: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_idea_cfb64_encrypt_;
  idea_ofb64_encrypt_: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl = Load_idea_ofb64_encrypt_;
  idea_encrypt__: procedure(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl = Load_idea_encrypt__;
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
{$ifndef  OPENSSL_NO_IDEA}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_IDEA_options: PAnsiChar; cdecl;
begin
  IDEA_options := LoadLibCryptoFunction('IDEA_options');
  if not assigned(IDEA_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_options');
  Result := IDEA_options;
end;

procedure Load_IDEA_ecb_encrypt(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_ecb_encrypt := LoadLibCryptoFunction('IDEA_ecb_encrypt');
  if not assigned(IDEA_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ecb_encrypt');
  IDEA_ecb_encrypt(in_, out_, ks);
end;

procedure Load_IDEA_set_encrypt_key(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_set_encrypt_key := LoadLibCryptoFunction('IDEA_set_encrypt_key');
  if not assigned(IDEA_set_encrypt_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_encrypt_key');
  IDEA_set_encrypt_key(key, ks);
end;

procedure Load_IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_set_decrypt_key := LoadLibCryptoFunction('IDEA_set_decrypt_key');
  if not assigned(IDEA_set_decrypt_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_decrypt_key');
  IDEA_set_decrypt_key(ek, dk);
end;

procedure Load_IDEA_cbc_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  IDEA_cbc_encrypt := LoadLibCryptoFunction('IDEA_cbc_encrypt');
  if not assigned(IDEA_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cbc_encrypt');
  IDEA_cbc_encrypt(in_, out_, length, ks, iv, enc);
end;

procedure Load_IDEA_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  IDEA_cfb64_encrypt := LoadLibCryptoFunction('IDEA_cfb64_encrypt');
  if not assigned(IDEA_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cfb64_encrypt');
  IDEA_cfb64_encrypt(in_, out_, length, ks, iv, num, enc);
end;

procedure Load_IDEA_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  IDEA_ofb64_encrypt := LoadLibCryptoFunction('IDEA_ofb64_encrypt');
  if not assigned(IDEA_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ofb64_encrypt');
  IDEA_ofb64_encrypt(in_, out_, length, ks, iv, num);
end;

procedure Load_IDEA_encrypt(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  IDEA_encrypt := LoadLibCryptoFunction('IDEA_encrypt');
  if not assigned(IDEA_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_encrypt');
  IDEA_encrypt(in_, ks);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
function Load_idea_options_: PAnsiChar; cdecl;
begin
  idea_options_ := LoadLibCryptoFunction('IDEA_options');
  if not assigned(idea_options_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_options');
  Result := idea_options_;
end;

procedure Load_idea_ecb_encrypt_(in_: Pbyte; out_: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  idea_ecb_encrypt_ := LoadLibCryptoFunction('IDEA_ecb_encrypt');
  if not assigned(idea_ecb_encrypt_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ecb_encrypt');
  idea_ecb_encrypt_(in_, out_, ks);
end;

procedure Load_idea_set_encrypt_key_(key: Pbyte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  idea_set_encrypt_key_ := LoadLibCryptoFunction('IDEA_set_encrypt_key');
  if not assigned(idea_set_encrypt_key_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_encrypt_key');
  idea_set_encrypt_key_(key, ks);
end;

procedure Load_idea_set_decrypt_key_(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
begin
  idea_set_decrypt_key_ := LoadLibCryptoFunction('IDEA_set_decrypt_key');
  if not assigned(idea_set_decrypt_key_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_decrypt_key');
  idea_set_decrypt_key_(ek, dk);
end;

procedure Load_idea_cbc_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; enc: TOpenSSL_C_INT); cdecl;
begin
  idea_cbc_encrypt_ := LoadLibCryptoFunction('IDEA_cbc_encrypt');
  if not assigned(idea_cbc_encrypt_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cbc_encrypt');
  idea_cbc_encrypt_(in_, out_, length, ks, iv, enc);
end;

procedure Load_idea_cfb64_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  idea_cfb64_encrypt_ := LoadLibCryptoFunction('IDEA_cfb64_encrypt');
  if not assigned(idea_cfb64_encrypt_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cfb64_encrypt');
  idea_cfb64_encrypt_(in_, out_, length, ks, iv, num, enc);
end;

procedure Load_idea_ofb64_encrypt_(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks: PIDEA_KEY_SCHEDULE; iv: Pbyte; num: POpenSSL_C_INT); cdecl;
begin
  idea_ofb64_encrypt_ := LoadLibCryptoFunction('IDEA_ofb64_encrypt');
  if not assigned(idea_ofb64_encrypt_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ofb64_encrypt');
  idea_ofb64_encrypt_(in_, out_, length, ks, iv, num);
end;

procedure Load_idea_encrypt__(in_: POpenSSL_C_UINT; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  idea_encrypt__ := LoadLibCryptoFunction('IDEA_encrypt');
  if not assigned(idea_encrypt__) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_encrypt');
  idea_encrypt__(in_, ks);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$endif} { OPENSSL_NO_IDEA}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_IDEA}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  IDEA_options := Load_IDEA_options;
  IDEA_ecb_encrypt := Load_IDEA_ecb_encrypt;
  IDEA_set_encrypt_key := Load_IDEA_set_encrypt_key;
  IDEA_set_decrypt_key := Load_IDEA_set_decrypt_key;
  IDEA_cbc_encrypt := Load_IDEA_cbc_encrypt;
  IDEA_cfb64_encrypt := Load_IDEA_cfb64_encrypt;
  IDEA_ofb64_encrypt := Load_IDEA_ofb64_encrypt;
  IDEA_encrypt := Load_IDEA_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  idea_options_ := Load_idea_options_;
  idea_ecb_encrypt_ := Load_idea_ecb_encrypt_;
  idea_set_encrypt_key_ := Load_idea_set_encrypt_key_;
  idea_set_decrypt_key_ := Load_idea_set_decrypt_key_;
  idea_cbc_encrypt_ := Load_idea_cbc_encrypt_;
  idea_cfb64_encrypt_ := Load_idea_cfb64_encrypt_;
  idea_ofb64_encrypt_ := Load_idea_ofb64_encrypt_;
  idea_encrypt__ := Load_idea_encrypt__;
    {$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$endif} { OPENSSL_NO_IDEA}
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



