(* This unit was generated from the source file blowfish.h2pas 
It should not be modified directly. All changes should be made to blowfish.h2pas
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


unit OpenSSL_blowfish;


interface

// Headers for OpenSSL 1.1.1
// blowfish.h


uses
  OpenSSLAPI;

const
  // Added '_CONST' to avoid name clashes
  BF_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  BF_DECRYPT_CONST = 0;

  BF_ROUNDS = 16;
  BF_BLOCK  = 8;

type
  BF_LONG = TOpenSSL_C_UINT;
  PBF_LONG = ^BF_LONG;

  bf_key_st = record
    p: array[0 .. BF_ROUNDS + 2 - 1] of BF_LONG;
    s: array[0 .. 4 * 256 - 1] of BF_LONG;
  end;
  BF_KEY = bf_key_st;
  PBF_KEY = ^BF_KEY;

  
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

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; const data: PByte); cdecl; external CLibCrypto;
procedure BF_encrypt(data: PBF_LONG; const key: PBF_KEY); cdecl; external CLibCrypto;
procedure BF_decrypt(data: PBF_LONG; const key: PBF_KEY); cdecl; external CLibCrypto;
procedure BF_ecb_encrypt(const in_: PByte; out_: PByte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure BF_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure BF_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure BF_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;
function BF_options: PAnsiChar; cdecl; external CLibCrypto;

{$ELSE}
var
  BF_set_key: procedure (key: PBF_KEY; len: TOpenSSL_C_INT; const data: PByte); cdecl = nil;
  BF_encrypt: procedure (data: PBF_LONG; const key: PBF_KEY); cdecl = nil;
  BF_decrypt: procedure (data: PBF_LONG; const key: PBF_KEY); cdecl = nil;
  BF_ecb_encrypt: procedure (const in_: PByte; out_: PByte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl = nil;
  BF_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; enc: TOpenSSL_C_INT); cdecl = nil;
  BF_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = nil;
  BF_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl = nil;
  BF_options: function : PAnsiChar; cdecl = nil;
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
procedure ERROR_BF_set_key(key: PBF_KEY; len: TOpenSSL_C_INT; const data: PByte); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_set_key');
end;

procedure ERROR_BF_encrypt(data: PBF_LONG; const key: PBF_KEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_encrypt');
end;

procedure ERROR_BF_decrypt(data: PBF_LONG; const key: PBF_KEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_decrypt');
end;

procedure ERROR_BF_ecb_encrypt(const in_: PByte; out_: PByte; key: PBF_KEY; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_ecb_encrypt');
end;

procedure ERROR_BF_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_cbc_encrypt');
end;

procedure ERROR_BF_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_cfb64_encrypt');
end;

procedure ERROR_BF_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; schedule: PBF_KEY; ivec: PByte; num: POpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_ofb64_encrypt');
end;

function ERROR_BF_options: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BF_options');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  BF_set_key := LoadLibCryptoFunction('BF_set_key');
  FuncLoadError := not assigned(BF_set_key);
  if FuncLoadError then
  begin
    BF_set_key :=  @ERROR_BF_set_key;
  end;

  BF_encrypt := LoadLibCryptoFunction('BF_encrypt');
  FuncLoadError := not assigned(BF_encrypt);
  if FuncLoadError then
  begin
    BF_encrypt :=  @ERROR_BF_encrypt;
  end;

  BF_decrypt := LoadLibCryptoFunction('BF_decrypt');
  FuncLoadError := not assigned(BF_decrypt);
  if FuncLoadError then
  begin
    BF_decrypt :=  @ERROR_BF_decrypt;
  end;

  BF_ecb_encrypt := LoadLibCryptoFunction('BF_ecb_encrypt');
  FuncLoadError := not assigned(BF_ecb_encrypt);
  if FuncLoadError then
  begin
    BF_ecb_encrypt :=  @ERROR_BF_ecb_encrypt;
  end;

  BF_cbc_encrypt := LoadLibCryptoFunction('BF_cbc_encrypt');
  FuncLoadError := not assigned(BF_cbc_encrypt);
  if FuncLoadError then
  begin
    BF_cbc_encrypt :=  @ERROR_BF_cbc_encrypt;
  end;

  BF_cfb64_encrypt := LoadLibCryptoFunction('BF_cfb64_encrypt');
  FuncLoadError := not assigned(BF_cfb64_encrypt);
  if FuncLoadError then
  begin
    BF_cfb64_encrypt :=  @ERROR_BF_cfb64_encrypt;
  end;

  BF_ofb64_encrypt := LoadLibCryptoFunction('BF_ofb64_encrypt');
  FuncLoadError := not assigned(BF_ofb64_encrypt);
  if FuncLoadError then
  begin
    BF_ofb64_encrypt :=  @ERROR_BF_ofb64_encrypt;
  end;

  BF_options := LoadLibCryptoFunction('BF_options');
  FuncLoadError := not assigned(BF_options);
  if FuncLoadError then
  begin
    BF_options :=  @ERROR_BF_options;
  end;

end;

procedure UnLoad;
begin
  BF_set_key := nil;
  BF_encrypt := nil;
  BF_decrypt := nil;
  BF_ecb_encrypt := nil;
  BF_cbc_encrypt := nil;
  BF_cfb64_encrypt := nil;
  BF_ofb64_encrypt := nil;
  BF_options := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
