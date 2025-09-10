(* This unit was generated from the source file cmac.h2pas 
It should not be modified directly. All changes should be made to cmac.h2pas
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


unit OpenSSL_cmac;


interface

// Headers for OpenSSL 1.1.1
// cmac.h


uses
  OpenSSLAPI,
  OpenSSL_evp,
  OpenSSL_ossl_typ;

//* Opaque */

type
  CMAC_CTX_st = type Pointer;
  CMAC_CTX = CMAC_CTX_st;
  PCMAC_CTX = ^CMAC_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CMAC_CTX_new}
{$EXTERNALSYM CMAC_CTX_cleanup}
{$EXTERNALSYM CMAC_CTX_free}
{$EXTERNALSYM CMAC_CTX_get0_cipher_ctx}
{$EXTERNALSYM CMAC_CTX_copy}
{$EXTERNALSYM CMAC_Init}
{$EXTERNALSYM CMAC_Update}
{$EXTERNALSYM CMAC_Final}
{$EXTERNALSYM CMAC_resume}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CMAC_CTX_new: PCMAC_CTX; cdecl; external CLibCrypto;
procedure CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl; external CLibCrypto;
procedure CMAC_CTX_free(ctx: PCMAC_CTX); cdecl; external CLibCrypto;
function CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl; external CLibCrypto;
function CMAC_CTX_copy(out_: PCMAC_CTX; const in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_Init(ctx: PCMAC_CTX; const key: Pointer; keylen: TOpenSSL_C_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_Update(ctx: PCMAC_CTX; const data: Pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_Final(ctx: PCMAC_CTX; out_: PByte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  CMAC_CTX_new: function : PCMAC_CTX; cdecl = nil;
  CMAC_CTX_cleanup: procedure (ctx: PCMAC_CTX); cdecl = nil;
  CMAC_CTX_free: procedure (ctx: PCMAC_CTX); cdecl = nil;
  CMAC_CTX_get0_cipher_ctx: function (ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl = nil;
  CMAC_CTX_copy: function (out_: PCMAC_CTX; const in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl = nil;
  CMAC_Init: function (ctx: PCMAC_CTX; const key: Pointer; keylen: TOpenSSL_C_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TOpenSSL_C_INT; cdecl = nil;
  CMAC_Update: function (ctx: PCMAC_CTX; const data: Pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  CMAC_Final: function (ctx: PCMAC_CTX; out_: PByte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  CMAC_resume: function (ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl = nil;
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
function ERROR_CMAC_CTX_new: PCMAC_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_new');
end;

procedure ERROR_CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_cleanup');
end;

procedure ERROR_CMAC_CTX_free(ctx: PCMAC_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_free');
end;

function ERROR_CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_get0_cipher_ctx');
end;

function ERROR_CMAC_CTX_copy(out_: PCMAC_CTX; const in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_copy');
end;

function ERROR_CMAC_Init(ctx: PCMAC_CTX; const key: Pointer; keylen: TOpenSSL_C_SIZET; const cipher: PEVP_Cipher; impl: PENGINe): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Init');
end;

function ERROR_CMAC_Update(ctx: PCMAC_CTX; const data: Pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Update');
end;

function ERROR_CMAC_Final(ctx: PCMAC_CTX; out_: PByte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Final');
end;

function ERROR_CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_resume');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  CMAC_CTX_new := LoadLibCryptoFunction('CMAC_CTX_new');
  FuncLoadError := not assigned(CMAC_CTX_new);
  if FuncLoadError then
  begin
    CMAC_CTX_new :=  @ERROR_CMAC_CTX_new;
  end;

  CMAC_CTX_cleanup := LoadLibCryptoFunction('CMAC_CTX_cleanup');
  FuncLoadError := not assigned(CMAC_CTX_cleanup);
  if FuncLoadError then
  begin
    CMAC_CTX_cleanup :=  @ERROR_CMAC_CTX_cleanup;
  end;

  CMAC_CTX_free := LoadLibCryptoFunction('CMAC_CTX_free');
  FuncLoadError := not assigned(CMAC_CTX_free);
  if FuncLoadError then
  begin
    CMAC_CTX_free :=  @ERROR_CMAC_CTX_free;
  end;

  CMAC_CTX_get0_cipher_ctx := LoadLibCryptoFunction('CMAC_CTX_get0_cipher_ctx');
  FuncLoadError := not assigned(CMAC_CTX_get0_cipher_ctx);
  if FuncLoadError then
  begin
    CMAC_CTX_get0_cipher_ctx :=  @ERROR_CMAC_CTX_get0_cipher_ctx;
  end;

  CMAC_CTX_copy := LoadLibCryptoFunction('CMAC_CTX_copy');
  FuncLoadError := not assigned(CMAC_CTX_copy);
  if FuncLoadError then
  begin
    CMAC_CTX_copy :=  @ERROR_CMAC_CTX_copy;
  end;

  CMAC_Init := LoadLibCryptoFunction('CMAC_Init');
  FuncLoadError := not assigned(CMAC_Init);
  if FuncLoadError then
  begin
    CMAC_Init :=  @ERROR_CMAC_Init;
  end;

  CMAC_Update := LoadLibCryptoFunction('CMAC_Update');
  FuncLoadError := not assigned(CMAC_Update);
  if FuncLoadError then
  begin
    CMAC_Update :=  @ERROR_CMAC_Update;
  end;

  CMAC_Final := LoadLibCryptoFunction('CMAC_Final');
  FuncLoadError := not assigned(CMAC_Final);
  if FuncLoadError then
  begin
    CMAC_Final :=  @ERROR_CMAC_Final;
  end;

  CMAC_resume := LoadLibCryptoFunction('CMAC_resume');
  FuncLoadError := not assigned(CMAC_resume);
  if FuncLoadError then
  begin
    CMAC_resume :=  @ERROR_CMAC_resume;
  end;

end;

procedure UnLoad;
begin
  CMAC_CTX_new := nil;
  CMAC_CTX_cleanup := nil;
  CMAC_CTX_free := nil;
  CMAC_CTX_get0_cipher_ctx := nil;
  CMAC_CTX_copy := nil;
  CMAC_Init := nil;
  CMAC_Update := nil;
  CMAC_Final := nil;
  CMAC_resume := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
