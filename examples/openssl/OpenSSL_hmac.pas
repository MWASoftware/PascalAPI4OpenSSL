(* This unit was generated from the source file hmac.h2pas 
It should not be modified directly. All changes should be made to hmac.h2pas
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


unit OpenSSL_hmac;


interface

// Headers for OpenSSL 1.1.1
// hmac.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_evp;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM HMAC_size}
{$EXTERNALSYM HMAC_CTX_new}
{$EXTERNALSYM HMAC_CTX_reset}
{$EXTERNALSYM HMAC_CTX_free}
{$EXTERNALSYM HMAC_Init_ex}
{$EXTERNALSYM HMAC_Update}
{$EXTERNALSYM HMAC_Final}
{$EXTERNALSYM HMAC}
{$EXTERNALSYM HMAC_CTX_copy}
{$EXTERNALSYM HMAC_CTX_set_flags}
{$EXTERNALSYM HMAC_CTX_get_md}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function HMAC_CTX_new: PHMAC_CTX; cdecl; external CLibCrypto;
function HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure HMAC_CTX_free(ctx: PHMAC_CTX); cdecl; external CLibCrypto;
function HMAC_Init_ex(ctx: PHMAC_CTX; const key: Pointer; len: TOpenSSL_C_INT; const md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function HMAC_Update(ctx: PHMAC_CTX; const data: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function HMAC_Final(ctx: PHMAC_CTX; md: PByte; len: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function HMAC(const evp_md: PEVP_MD; const key: Pointer; key_len: TOpenSSL_C_INT; const d: PByte; n: TOpenSSL_C_SIZET; md: PByte; md_len: POpenSSL_C_INT): PByte; cdecl; external CLibCrypto;
function HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function HMAC_CTX_get_md(const ctx: PHMAC_CTX): PEVP_MD; cdecl; external CLibCrypto;

{$ELSE}
var
  HMAC_size: function (const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl = nil;
  HMAC_CTX_new: function : PHMAC_CTX; cdecl = nil;
  HMAC_CTX_reset: function (ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl = nil;
  HMAC_CTX_free: procedure (ctx: PHMAC_CTX); cdecl = nil;
  HMAC_Init_ex: function (ctx: PHMAC_CTX; const key: Pointer; len: TOpenSSL_C_INT; const md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  HMAC_Update: function (ctx: PHMAC_CTX; const data: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  HMAC_Final: function (ctx: PHMAC_CTX; md: PByte; len: PByte): TOpenSSL_C_INT; cdecl = nil;
  HMAC: function (const evp_md: PEVP_MD; const key: Pointer; key_len: TOpenSSL_C_INT; const d: PByte; n: TOpenSSL_C_SIZET; md: PByte; md_len: POpenSSL_C_INT): PByte; cdecl = nil;
  HMAC_CTX_copy: function (dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl = nil;
  HMAC_CTX_set_flags: procedure (ctx: PHMAC_CTX; flags: TOpenSSL_C_ULONG); cdecl = nil;
  HMAC_CTX_get_md: function (const ctx: PHMAC_CTX): PEVP_MD; cdecl = nil;
{$ENDIF}
const
  HMAC_CTX_init_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  HMAC_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_reset_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_cleanup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  HMAC_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  HMAC_CTX_get_md_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  HMAC_CTX_init: procedure (ctx : PHMAC_CTX); cdecl = nil; {removed 1.1.0}
  HMAC_CTX_cleanup: procedure (ctx : PHMAC_CTX); cdecl = nil; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  HMAC_MAX_MD_CBLOCK = 128; {largest known is SHA512}

type
 _PHMAC_CTX = ^HMAC_CTX;
 HMAC_CTX = record
   md: EVP_MD;
   md_ctx: EVP_MD_CTX;
   i_ctx: EVP_MD_CTX;
   o_ctx: EVP_MD_CTX;
   key_length: TOpenSSL_C_UINT;
   key: array [0..HMAC_MAX_MD_CBLOCK] of char;
 end;



{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_HMAC_CTX_new: PHMAC_CTX; cdecl;

begin
  Result := AllocMem(SizeOf(HMAC_CTX));
  HMAC_CTX_init(Result);
end;



procedure COMPAT_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;

begin
  HMAC_CTX_cleanup(ctx);
  FreeMem(ctx,SizeOf(HMAC_CTX));
end;

(*
typedef struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX md_ctx;
    EVP_MD_CTX i_ctx;
    EVP_MD_CTX o_ctx;
    unsigned int key_length;
    unsigned char key[HMAC_MAX_MD_CBLOCK];
} HMAC_CTX;
*)


function COMPAT_HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl;

var EVP_MD_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_size := LoadLibCryptoFunction('EVP_MD_size');
  if not assigned(EVP_MD_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_size');
  Result := EVP_MD_size(_PHMAC_CTX(e)^.md);
end;







{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
procedure ERROR_HMAC_CTX_init(ctx : PHMAC_CTX); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_init');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_size');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_HMAC_CTX_new: PHMAC_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_new');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_reset');
end;

procedure ERROR_HMAC_CTX_cleanup(ctx : PHMAC_CTX); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_cleanup');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_HMAC_Init_ex(ctx: PHMAC_CTX; const key: Pointer; len: TOpenSSL_C_INT; const md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Init_ex');
end;

function ERROR_HMAC_Update(ctx: PHMAC_CTX; const data: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Update');
end;

function ERROR_HMAC_Final(ctx: PHMAC_CTX; md: PByte; len: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Final');
end;

function ERROR_HMAC(const evp_md: PEVP_MD; const key: Pointer; key_len: TOpenSSL_C_INT; const d: PByte; n: TOpenSSL_C_SIZET; md: PByte; md_len: POpenSSL_C_INT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC');
end;

function ERROR_HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_copy');
end;

procedure ERROR_HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_set_flags');
end;

function ERROR_HMAC_CTX_get_md(const ctx: PHMAC_CTX): PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_get_md');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  HMAC_CTX_init := LoadLibCryptoFunction('HMAC_CTX_init');
  FuncLoadError := not assigned(HMAC_CTX_init);
  if FuncLoadError then
  begin
    if HMAC_CTX_init_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_init');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  HMAC_size := LoadLibCryptoFunction('HMAC_size');
  FuncLoadError := not assigned(HMAC_size);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    HMAC_size := @COMPAT_HMAC_size;
{$ELSE}
    HMAC_size :=  @ERROR_HMAC_size;
{$ENDIF}
  end;

  HMAC_CTX_new := LoadLibCryptoFunction('HMAC_CTX_new');
  FuncLoadError := not assigned(HMAC_CTX_new);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    HMAC_CTX_new := @COMPAT_HMAC_CTX_new;
{$ELSE}
    HMAC_CTX_new :=  @ERROR_HMAC_CTX_new;
{$ENDIF}
  end;

  HMAC_CTX_reset := LoadLibCryptoFunction('HMAC_CTX_reset');
  FuncLoadError := not assigned(HMAC_CTX_reset);
  if FuncLoadError then
  begin
    HMAC_CTX_reset :=  @ERROR_HMAC_CTX_reset;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  HMAC_CTX_cleanup := LoadLibCryptoFunction('HMAC_CTX_cleanup');
  FuncLoadError := not assigned(HMAC_CTX_cleanup);
  if FuncLoadError then
  begin
    if HMAC_CTX_cleanup_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('HMAC_CTX_cleanup');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  HMAC_CTX_free := LoadLibCryptoFunction('HMAC_CTX_free');
  FuncLoadError := not assigned(HMAC_CTX_free);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    HMAC_CTX_free := @COMPAT_HMAC_CTX_free;
{$ELSE}
    HMAC_CTX_free :=  @ERROR_HMAC_CTX_free;
{$ENDIF}
  end;

  HMAC_Init_ex := LoadLibCryptoFunction('HMAC_Init_ex');
  FuncLoadError := not assigned(HMAC_Init_ex);
  if FuncLoadError then
  begin
    HMAC_Init_ex :=  @ERROR_HMAC_Init_ex;
  end;

  HMAC_Update := LoadLibCryptoFunction('HMAC_Update');
  FuncLoadError := not assigned(HMAC_Update);
  if FuncLoadError then
  begin
    HMAC_Update :=  @ERROR_HMAC_Update;
  end;

  HMAC_Final := LoadLibCryptoFunction('HMAC_Final');
  FuncLoadError := not assigned(HMAC_Final);
  if FuncLoadError then
  begin
    HMAC_Final :=  @ERROR_HMAC_Final;
  end;

  HMAC := LoadLibCryptoFunction('HMAC');
  FuncLoadError := not assigned(HMAC);
  if FuncLoadError then
  begin
    HMAC :=  @ERROR_HMAC;
  end;

  HMAC_CTX_copy := LoadLibCryptoFunction('HMAC_CTX_copy');
  FuncLoadError := not assigned(HMAC_CTX_copy);
  if FuncLoadError then
  begin
    HMAC_CTX_copy :=  @ERROR_HMAC_CTX_copy;
  end;

  HMAC_CTX_set_flags := LoadLibCryptoFunction('HMAC_CTX_set_flags');
  FuncLoadError := not assigned(HMAC_CTX_set_flags);
  if FuncLoadError then
  begin
    HMAC_CTX_set_flags :=  @ERROR_HMAC_CTX_set_flags;
  end;

  HMAC_CTX_get_md := LoadLibCryptoFunction('HMAC_CTX_get_md');
  FuncLoadError := not assigned(HMAC_CTX_get_md);
  if FuncLoadError then
  begin
    HMAC_CTX_get_md :=  @ERROR_HMAC_CTX_get_md;
  end;

end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  HMAC_CTX_init := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  HMAC_size := nil;
  HMAC_CTX_new := nil;
  HMAC_CTX_reset := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  HMAC_CTX_cleanup := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  HMAC_CTX_free := nil;
  HMAC_Init_ex := nil;
  HMAC_Update := nil;
  HMAC_Final := nil;
  HMAC := nil;
  HMAC_CTX_copy := nil;
  HMAC_CTX_set_flags := nil;
  HMAC_CTX_get_md := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
