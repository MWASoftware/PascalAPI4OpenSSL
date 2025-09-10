(* This unit was generated from the source file aes.h2pas 
It should not be modified directly. All changes should be made to aes.h2pas
and this file regenerated *)

{$i OpenSSLDefines.inc}

{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License").

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.

    This file includes software copied from the Indy (Internet Direct) project, and which is offered
    under the dual-licensing agreement described on the Indy website. (https://www.indyproject.org/license/)
    }


unit OpenSSL_aes;


interface

// Headers for OpenSSL 1.1.1
// aes.h


uses
  OpenSSLAPI;

const
// Added '_CONST' to avoid name clashes
  AES_ENCRYPT_CONST = 1;
// Added '_CONST' to avoid name clashes
  AES_DECRYPT_CONST = 0;
  AES_MAXNR = 14;
  AES_BLOCK_SIZE = 16;

type
  aes_key_st = record
  // in old IdSSLOpenSSLHeaders.pas it was also TOpenSSL_C_UINT ¯\_(ツ)_/¯
//    {$IFDEF AES_LONG}
//    rd_key: array[0..(4 * (AES_MAXNR + 1))] of TOpenSSL_C_ULONG;
//    {$ELSE}
    rd_key: array[0..(4 * (AES_MAXNR + 1))] of TOpenSSL_C_UINT;
//    {$ENDIF}
    rounds: TOpenSSL_C_INT;
  end;
  AES_KEY = aes_key_st;
  PAES_KEY = ^AES_KEY;

  
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

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function AES_options: PAnsiChar; cdecl; external CLibCrypto;
function AES_set_encrypt_key(const userKey: PByte; const bits: TOpenSSL_C_INT; const key: PAES_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function AES_set_decrypt_key(const userKey: PByte; const bits: TOpenSSL_C_INT; const key: PAES_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure AES_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl; external CLibCrypto;
procedure AES_decrypt(const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl; external CLibCrypto;
procedure AES_ecb_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure AES_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure AES_cfb128_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure AES_cfb1_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure AES_cfb8_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure AES_ofb128_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;
procedure AES_ige_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure AES_bi_ige_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; const key2: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function AES_wrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function AES_unwrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  AES_options: function : PAnsiChar; cdecl = nil;
  AES_set_encrypt_key: function (const userKey: PByte; const bits: TOpenSSL_C_INT; const key: PAES_KEY): TOpenSSL_C_INT; cdecl = nil;
  AES_set_decrypt_key: function (const userKey: PByte; const bits: TOpenSSL_C_INT; const key: PAES_KEY): TOpenSSL_C_INT; cdecl = nil;
  AES_encrypt: procedure (const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl = nil;
  AES_decrypt: procedure (const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl = nil;
  AES_ecb_encrypt: procedure (const in_: PByte; out_: PByte; const key: PAES_KEY; const enc: TOpenSSL_C_INT); cdecl = nil;
  AES_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl = nil;
  AES_cfb128_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl = nil;
  AES_cfb1_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl = nil;
  AES_cfb8_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl = nil;
  AES_ofb128_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl = nil;
  AES_ige_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl = nil;
  AES_bi_ige_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; const key2: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl = nil;
  AES_wrap_key: function (key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  AES_unwrap_key: function (key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
{$ENDIF}

implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_AES_options: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_options');
end;

function ERROR_AES_set_encrypt_key(const userKey: PByte; const bits: TOpenSSL_C_INT; const key: PAES_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_set_encrypt_key');
end;

function ERROR_AES_set_decrypt_key(const userKey: PByte; const bits: TOpenSSL_C_INT; const key: PAES_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_set_decrypt_key');
end;

procedure ERROR_AES_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_encrypt');
end;

procedure ERROR_AES_decrypt(const in_: PByte; out_: PByte; const key: PAES_KEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_decrypt');
end;

procedure ERROR_AES_ecb_encrypt(const in_: PByte; out_: PByte; const key: PAES_KEY; const enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_ecb_encrypt');
end;

procedure ERROR_AES_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cbc_encrypt');
end;

procedure ERROR_AES_cfb128_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cfb128_encrypt');
end;

procedure ERROR_AES_cfb1_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cfb1_encrypt');
end;

procedure ERROR_AES_cfb8_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT; const enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_cfb8_encrypt');
end;

procedure ERROR_AES_ofb128_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_ofb128_encrypt');
end;

procedure ERROR_AES_ige_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_ige_encrypt');
end;

procedure ERROR_AES_bi_ige_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_SIZET; const key: PAES_KEY; const key2: PAES_KEY; ivec: PByte; const enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_bi_ige_encrypt');
end;

function ERROR_AES_wrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_wrap_key');
end;

function ERROR_AES_unwrap_key(key: PAES_KEY; const iv: PByte; out_: PByte; const in_: PByte; inlen: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('AES_unwrap_key');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  AES_options := LoadLibCryptoFunction('AES_options');
  FuncLoadError := not assigned(AES_options);
  if FuncLoadError then
  begin
    AES_options :=  @ERROR_AES_options;
  end;

  AES_set_encrypt_key := LoadLibCryptoFunction('AES_set_encrypt_key');
  FuncLoadError := not assigned(AES_set_encrypt_key);
  if FuncLoadError then
  begin
    AES_set_encrypt_key :=  @ERROR_AES_set_encrypt_key;
  end;

  AES_set_decrypt_key := LoadLibCryptoFunction('AES_set_decrypt_key');
  FuncLoadError := not assigned(AES_set_decrypt_key);
  if FuncLoadError then
  begin
    AES_set_decrypt_key :=  @ERROR_AES_set_decrypt_key;
  end;

  AES_encrypt := LoadLibCryptoFunction('AES_encrypt');
  FuncLoadError := not assigned(AES_encrypt);
  if FuncLoadError then
  begin
    AES_encrypt :=  @ERROR_AES_encrypt;
  end;

  AES_decrypt := LoadLibCryptoFunction('AES_decrypt');
  FuncLoadError := not assigned(AES_decrypt);
  if FuncLoadError then
  begin
    AES_decrypt :=  @ERROR_AES_decrypt;
  end;

  AES_ecb_encrypt := LoadLibCryptoFunction('AES_ecb_encrypt');
  FuncLoadError := not assigned(AES_ecb_encrypt);
  if FuncLoadError then
  begin
    AES_ecb_encrypt :=  @ERROR_AES_ecb_encrypt;
  end;

  AES_cbc_encrypt := LoadLibCryptoFunction('AES_cbc_encrypt');
  FuncLoadError := not assigned(AES_cbc_encrypt);
  if FuncLoadError then
  begin
    AES_cbc_encrypt :=  @ERROR_AES_cbc_encrypt;
  end;

  AES_cfb128_encrypt := LoadLibCryptoFunction('AES_cfb128_encrypt');
  FuncLoadError := not assigned(AES_cfb128_encrypt);
  if FuncLoadError then
  begin
    AES_cfb128_encrypt :=  @ERROR_AES_cfb128_encrypt;
  end;

  AES_cfb1_encrypt := LoadLibCryptoFunction('AES_cfb1_encrypt');
  FuncLoadError := not assigned(AES_cfb1_encrypt);
  if FuncLoadError then
  begin
    AES_cfb1_encrypt :=  @ERROR_AES_cfb1_encrypt;
  end;

  AES_cfb8_encrypt := LoadLibCryptoFunction('AES_cfb8_encrypt');
  FuncLoadError := not assigned(AES_cfb8_encrypt);
  if FuncLoadError then
  begin
    AES_cfb8_encrypt :=  @ERROR_AES_cfb8_encrypt;
  end;

  AES_ofb128_encrypt := LoadLibCryptoFunction('AES_ofb128_encrypt');
  FuncLoadError := not assigned(AES_ofb128_encrypt);
  if FuncLoadError then
  begin
    AES_ofb128_encrypt :=  @ERROR_AES_ofb128_encrypt;
  end;

  AES_ige_encrypt := LoadLibCryptoFunction('AES_ige_encrypt');
  FuncLoadError := not assigned(AES_ige_encrypt);
  if FuncLoadError then
  begin
    AES_ige_encrypt :=  @ERROR_AES_ige_encrypt;
  end;

  AES_bi_ige_encrypt := LoadLibCryptoFunction('AES_bi_ige_encrypt');
  FuncLoadError := not assigned(AES_bi_ige_encrypt);
  if FuncLoadError then
  begin
    AES_bi_ige_encrypt :=  @ERROR_AES_bi_ige_encrypt;
  end;

  AES_wrap_key := LoadLibCryptoFunction('AES_wrap_key');
  FuncLoadError := not assigned(AES_wrap_key);
  if FuncLoadError then
  begin
    AES_wrap_key :=  @ERROR_AES_wrap_key;
  end;

  AES_unwrap_key := LoadLibCryptoFunction('AES_unwrap_key');
  FuncLoadError := not assigned(AES_unwrap_key);
  if FuncLoadError then
  begin
    AES_unwrap_key :=  @ERROR_AES_unwrap_key;
  end;

end;

procedure UnLoad;
begin
  AES_options := nil;
  AES_set_encrypt_key := nil;
  AES_set_decrypt_key := nil;
  AES_encrypt := nil;
  AES_decrypt := nil;
  AES_ecb_encrypt := nil;
  AES_cbc_encrypt := nil;
  AES_cfb128_encrypt := nil;
  AES_cfb1_encrypt := nil;
  AES_cfb8_encrypt := nil;
  AES_ofb128_encrypt := nil;
  AES_ige_encrypt := nil;
  AES_bi_ige_encrypt := nil;
  AES_wrap_key := nil;
  AES_unwrap_key := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
