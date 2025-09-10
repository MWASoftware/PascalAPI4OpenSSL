(* This unit was generated from the source file idea.h2pas 
It should not be modified directly. All changes should be made to idea.h2pas
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


unit OpenSSL_idea;


interface

// Headers for OpenSSL 1.1.1
// idea.h


uses
  OpenSSLAPI;

const
  // Added '_CONST' to avoid name clashes
  IDEA_ENCRYPT_CONST = 1;
  // Added '_CONST' to avoid name clashes
  IDEA_DECRYPT_CONST = 0;

  IDEA_BLOCK      = 8;
  IDEA_KEY_LENGTH = 16;

type
  IDEA_INT = type TOpenSSL_C_INT;

  idea_key_st = record
    data: array[0..8, 0..5] of IDEA_INT;
  end;
  IDEA_KEY_SCHEDULE = idea_key_st;
  PIDEA_KEY_SCHEDULE = ^IDEA_KEY_SCHEDULE;

  
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

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function IDEA_options: PAnsiChar; cdecl; external CLibCrypto;
procedure IDEA_ecb_encrypt(const in_: PByte; out_: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;
procedure IDEA_set_encrypt_key(const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;
procedure IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;
procedure IDEA_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure IDEA_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure IDEA_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;
procedure IDEA_encrypt(in_: POpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl; external CLibCrypto;

{$ELSE}
var
  IDEA_options: function : PAnsiChar; cdecl = nil;
  IDEA_ecb_encrypt: procedure (const in_: PByte; out_: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
  IDEA_set_encrypt_key: procedure (const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
  IDEA_set_decrypt_key: procedure (ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl = nil;
  IDEA_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TOpenSSL_C_INT); cdecl = nil;
  IDEA_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = nil;
  IDEA_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT); cdecl = nil;
  IDEA_encrypt: procedure (in_: POpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl = nil;
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
function ERROR_IDEA_options: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_options');
end;

procedure ERROR_IDEA_ecb_encrypt(const in_: PByte; out_: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ecb_encrypt');
end;

procedure ERROR_IDEA_set_encrypt_key(const key: PByte; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_encrypt_key');
end;

procedure ERROR_IDEA_set_decrypt_key(ek: PIDEA_KEY_SCHEDULE; dk: PIDEA_KEY_SCHEDULE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_set_decrypt_key');
end;

procedure ERROR_IDEA_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cbc_encrypt');
end;

procedure ERROR_IDEA_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_cfb64_encrypt');
end;

procedure ERROR_IDEA_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE; iv: PByte; num: POpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_ofb64_encrypt');
end;

procedure ERROR_IDEA_encrypt(in_: POpenSSL_C_LONG; ks: PIDEA_KEY_SCHEDULE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('IDEA_encrypt');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  IDEA_options := LoadLibCryptoFunction('IDEA_options');
  FuncLoadError := not assigned(IDEA_options);
  if FuncLoadError then
  begin
    IDEA_options :=  @ERROR_IDEA_options;
  end;

  IDEA_ecb_encrypt := LoadLibCryptoFunction('IDEA_ecb_encrypt');
  FuncLoadError := not assigned(IDEA_ecb_encrypt);
  if FuncLoadError then
  begin
    IDEA_ecb_encrypt :=  @ERROR_IDEA_ecb_encrypt;
  end;

  IDEA_set_encrypt_key := LoadLibCryptoFunction('IDEA_set_encrypt_key');
  FuncLoadError := not assigned(IDEA_set_encrypt_key);
  if FuncLoadError then
  begin
    IDEA_set_encrypt_key :=  @ERROR_IDEA_set_encrypt_key;
  end;

  IDEA_set_decrypt_key := LoadLibCryptoFunction('IDEA_set_decrypt_key');
  FuncLoadError := not assigned(IDEA_set_decrypt_key);
  if FuncLoadError then
  begin
    IDEA_set_decrypt_key :=  @ERROR_IDEA_set_decrypt_key;
  end;

  IDEA_cbc_encrypt := LoadLibCryptoFunction('IDEA_cbc_encrypt');
  FuncLoadError := not assigned(IDEA_cbc_encrypt);
  if FuncLoadError then
  begin
    IDEA_cbc_encrypt :=  @ERROR_IDEA_cbc_encrypt;
  end;

  IDEA_cfb64_encrypt := LoadLibCryptoFunction('IDEA_cfb64_encrypt');
  FuncLoadError := not assigned(IDEA_cfb64_encrypt);
  if FuncLoadError then
  begin
    IDEA_cfb64_encrypt :=  @ERROR_IDEA_cfb64_encrypt;
  end;

  IDEA_ofb64_encrypt := LoadLibCryptoFunction('IDEA_ofb64_encrypt');
  FuncLoadError := not assigned(IDEA_ofb64_encrypt);
  if FuncLoadError then
  begin
    IDEA_ofb64_encrypt :=  @ERROR_IDEA_ofb64_encrypt;
  end;

  IDEA_encrypt := LoadLibCryptoFunction('IDEA_encrypt');
  FuncLoadError := not assigned(IDEA_encrypt);
  if FuncLoadError then
  begin
    IDEA_encrypt :=  @ERROR_IDEA_encrypt;
  end;

end;

procedure UnLoad;
begin
  IDEA_options := nil;
  IDEA_ecb_encrypt := nil;
  IDEA_set_encrypt_key := nil;
  IDEA_set_decrypt_key := nil;
  IDEA_cbc_encrypt := nil;
  IDEA_cfb64_encrypt := nil;
  IDEA_ofb64_encrypt := nil;
  IDEA_encrypt := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
