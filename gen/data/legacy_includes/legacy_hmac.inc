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
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}

procedure Load_HMAC_CTX_init(ctx : PHMAC_CTX); cdecl; forward;
procedure Load_HMAC_CTX_cleanup(ctx : PHMAC_CTX); cdecl; forward;

var
  HMAC_CTX_init: procedure (ctx : PHMAC_CTX); cdecl = Load_HMAC_CTX_init; {removed 1.1.0}
  HMAC_CTX_cleanup: procedure (ctx : PHMAC_CTX); cdecl = Load_HMAC_CTX_cleanup; {removed 1.1.0}
  
procedure Load_HMAC_CTX_init(ctx : PHMAC_CTX); cdecl;
begin
  HMAC_CTX_init := LoadLibCryptoFunction('HMAC_CTX_init');
  if not assigned(HMAC_CTX_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_init');
  HMAC_CTX_init(ctx);
end;

procedure Load_HMAC_CTX_cleanup(ctx : PHMAC_CTX); cdecl;
begin
  HMAC_CTX_cleanup := LoadLibCryptoFunction('HMAC_CTX_cleanup');
  if not assigned(HMAC_CTX_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_cleanup');
  HMAC_CTX_cleanup(ctx);
end;

function LEGACY_HMAC_CTX_new: PHMAC_CTX;
begin
  Result := AllocMem(SizeOf(THMAC_CTX));
  HMAC_CTX_init(Result);
end;

procedure LEGACY_HMAC_CTX_free(ctx: PHMAC_CTX);
begin
  HMAC_CTX_cleanup(ctx);
  FreeMem(ctx,SizeOf(PHMAC_CTX));
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

type
 _PHMAC_CTX = ^_HMAC_CTX;
 _HMAC_CTX = record
   md: PEVP_MD;
   md_ctx: TEVP_MD_CTX;
   i_ctx: TEVP_MD_CTX;
   o_ctx: TEVP_MD_CTX;
   key_length: TOpenSSL_C_UINT;
   key: array [0..HMAC_MAX_MD_CBLOCK] of char;
 end;


function LEGACY_HMAC_size(const e: PHMAC_CTX): TOpenSSL_C_SIZET;
var EVP_MD_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_size := LoadLibCryptoFunction('EVP_MD_size');
  if not assigned(EVP_MD_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_size');
  Result := EVP_MD_size(_PHMAC_CTX(e)^.md);
end;
{$endif}
{$endif}
