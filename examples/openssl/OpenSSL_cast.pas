(* This unit was generated from the source file cast.h2pas 
It should not be modified directly. All changes should be made to cast.h2pas
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


unit OpenSSL_cast;


interface

// Headers for OpenSSL 1.1.1
// cast.h


uses
  OpenSSLAPI;

const
  CAST_ENCRYPT_CONST =  1;
  CAST_DECRYPT_CONST =  0;
  CAST_BLOCK =  8;
  CAST_KEY_LENGTH = 16;

type
  CAST_LONG = type TOpenSSL_C_UINT;
  PCAST_LONG = ^CAST_LONG;

  cast_key_st = record
    data: array of CAST_LONG;
    short_key: TOpenSSL_C_INT;              //* Use reduced rounds for short key */
  end;

  CAST_KEY = cast_key_st;
  PCAST_KEY = ^CAST_KEY;

  
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

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure CAST_set_key(key: PCast_Key; len: TOpenSSL_C_INT; const data: PByte); cdecl; external CLibCrypto;
procedure CAST_ecb_encrypt(const in_: PByte; out_: PByte; const key: PCast_Key; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CAST_encrypt(data: PCAST_LONG; const key: PCast_Key); cdecl; external CLibCrypto;
procedure CAST_decrypt(data: PCAST_LONG; const key: PCast_Key); cdecl; external CLibCrypto;
procedure CAST_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const ks: PCast_Key; iv: PByte; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CAST_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CAST_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT); cdecl; external CLibCrypto;

{$ELSE}
var
  CAST_set_key: procedure (key: PCast_Key; len: TOpenSSL_C_INT; const data: PByte); cdecl = nil;
  CAST_ecb_encrypt: procedure (const in_: PByte; out_: PByte; const key: PCast_Key; enc: TOpenSSL_C_INT); cdecl = nil;
  CAST_encrypt: procedure (data: PCAST_LONG; const key: PCast_Key); cdecl = nil;
  CAST_decrypt: procedure (data: PCAST_LONG; const key: PCast_Key); cdecl = nil;
  CAST_cbc_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const ks: PCast_Key; iv: PByte; enc: TOpenSSL_C_INT); cdecl = nil;
  CAST_cfb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = nil;
  CAST_ofb64_encrypt: procedure (const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT); cdecl = nil;
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
procedure ERROR_CAST_set_key(key: PCast_Key; len: TOpenSSL_C_INT; const data: PByte); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_set_key');
end;

procedure ERROR_CAST_ecb_encrypt(const in_: PByte; out_: PByte; const key: PCast_Key; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_ecb_encrypt');
end;

procedure ERROR_CAST_encrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_encrypt');
end;

procedure ERROR_CAST_decrypt(data: PCAST_LONG; const key: PCast_Key); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_decrypt');
end;

procedure ERROR_CAST_cbc_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const ks: PCast_Key; iv: PByte; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_cbc_encrypt');
end;

procedure ERROR_CAST_cfb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_cfb64_encrypt');
end;

procedure ERROR_CAST_ofb64_encrypt(const in_: PByte; out_: PByte; length: TOpenSSL_C_LONG; const schedule: PCast_Key; ivec: PByte; num: POpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CAST_ofb64_encrypt');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  CAST_set_key := LoadLibCryptoFunction('CAST_set_key');
  FuncLoadError := not assigned(CAST_set_key);
  if FuncLoadError then
  begin
    CAST_set_key :=  @ERROR_CAST_set_key;
  end;

  CAST_ecb_encrypt := LoadLibCryptoFunction('CAST_ecb_encrypt');
  FuncLoadError := not assigned(CAST_ecb_encrypt);
  if FuncLoadError then
  begin
    CAST_ecb_encrypt :=  @ERROR_CAST_ecb_encrypt;
  end;

  CAST_encrypt := LoadLibCryptoFunction('CAST_encrypt');
  FuncLoadError := not assigned(CAST_encrypt);
  if FuncLoadError then
  begin
    CAST_encrypt :=  @ERROR_CAST_encrypt;
  end;

  CAST_decrypt := LoadLibCryptoFunction('CAST_decrypt');
  FuncLoadError := not assigned(CAST_decrypt);
  if FuncLoadError then
  begin
    CAST_decrypt :=  @ERROR_CAST_decrypt;
  end;

  CAST_cbc_encrypt := LoadLibCryptoFunction('CAST_cbc_encrypt');
  FuncLoadError := not assigned(CAST_cbc_encrypt);
  if FuncLoadError then
  begin
    CAST_cbc_encrypt :=  @ERROR_CAST_cbc_encrypt;
  end;

  CAST_cfb64_encrypt := LoadLibCryptoFunction('CAST_cfb64_encrypt');
  FuncLoadError := not assigned(CAST_cfb64_encrypt);
  if FuncLoadError then
  begin
    CAST_cfb64_encrypt :=  @ERROR_CAST_cfb64_encrypt;
  end;

  CAST_ofb64_encrypt := LoadLibCryptoFunction('CAST_ofb64_encrypt');
  FuncLoadError := not assigned(CAST_ofb64_encrypt);
  if FuncLoadError then
  begin
    CAST_ofb64_encrypt :=  @ERROR_CAST_ofb64_encrypt;
  end;

end;

procedure UnLoad;
begin
  CAST_set_key := nil;
  CAST_ecb_encrypt := nil;
  CAST_encrypt := nil;
  CAST_decrypt := nil;
  CAST_cbc_encrypt := nil;
  CAST_cfb64_encrypt := nil;
  CAST_ofb64_encrypt := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
