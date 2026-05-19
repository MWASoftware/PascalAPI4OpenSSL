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

unit openssl_cmac;

{
  Generated from OpenSSL 4.0.0 Header File cmac.h - Tue 19 May 14:32:01 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_cmac.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_evp;


{* Copyright 2010-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CMAC_H}
  {$define OPENSSL_CMAC_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_CMAC_H}
  {$endif}
  {$ifndef  OPENSSL_NO_CMAC}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PCMAC_CTX_st = ^TCMAC_CTX;
  PPCMAC_CTX_st = ^PCMAC_CTX_st;
  PCMAC_CTX = ^TCMAC_CTX;
  PPCMAC_CTX = ^PCMAC_CTX;
  {end of auto-generated forward references}

      { Opaque }
  TCMAC_CTX_st = record end;
  TCMAC_CTX = TCMAC_CTX_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function CMAC_CTX_new: PCMAC_CTX; cdecl; external CLibCrypto name 'CMAC_CTX_new'; deprecated 'Since OpenSSL 3.0';
  procedure CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl; external CLibCrypto name 'CMAC_CTX_cleanup'; deprecated 'Since OpenSSL 3.0';
  procedure CMAC_CTX_free(ctx: PCMAC_CTX); cdecl; external CLibCrypto name 'CMAC_CTX_free'; deprecated 'Since OpenSSL 3.0';
  function CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl; external CLibCrypto name 'CMAC_CTX_get0_cipher_ctx'; deprecated 'Since OpenSSL 3.0';
  function CMAC_CTX_copy(out_: PCMAC_CTX; in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CMAC_CTX_copy'; deprecated 'Since OpenSSL 3.0';
  { must be NULL }
  function CMAC_Init(ctx: PCMAC_CTX; key: pointer; keylen: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CMAC_Init'; deprecated 'Since OpenSSL 3.0';
  function CMAC_Update(ctx: PCMAC_CTX; data: pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CMAC_Update'; deprecated 'Since OpenSSL 3.0';
  function CMAC_Final(ctx: PCMAC_CTX; out_: Pbyte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CMAC_Final'; deprecated 'Since OpenSSL 3.0';
  function CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CMAC_resume'; deprecated 'Since OpenSSL 3.0';
      {$else}
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
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_CMAC_CTX_new: PCMAC_CTX; cdecl;
  procedure Load_CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl;
  procedure Load_CMAC_CTX_free(ctx: PCMAC_CTX); cdecl;
  function Load_CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl;
  function Load_CMAC_CTX_copy(out_: PCMAC_CTX; in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
  function Load_CMAC_Init(ctx: PCMAC_CTX; key: pointer; keylen: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER; impl: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_CMAC_Update(ctx: PCMAC_CTX; data: pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CMAC_Final(ctx: PCMAC_CTX; out_: Pbyte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl;

var
  CMAC_CTX_new: function: PCMAC_CTX; cdecl = Load_CMAC_CTX_new;
  CMAC_CTX_cleanup: procedure(ctx: PCMAC_CTX); cdecl = Load_CMAC_CTX_cleanup;
  CMAC_CTX_free: procedure(ctx: PCMAC_CTX); cdecl = Load_CMAC_CTX_free;
  CMAC_CTX_get0_cipher_ctx: function(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl = Load_CMAC_CTX_get0_cipher_ctx;
  CMAC_CTX_copy: function(out_: PCMAC_CTX; in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl = Load_CMAC_CTX_copy;
  { must be NULL }
  CMAC_Init: function(ctx: PCMAC_CTX; key: pointer; keylen: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER; impl: PENGINE): TOpenSSL_C_INT; cdecl = Load_CMAC_Init;
  CMAC_Update: function(ctx: PCMAC_CTX; data: pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMAC_Update;
  CMAC_Final: function(ctx: PCMAC_CTX; out_: Pbyte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CMAC_Final;
  CMAC_resume: function(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl = Load_CMAC_resume;
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
{$ifndef  OPENSSL_NO_CMAC}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_CMAC_CTX_new: PCMAC_CTX; cdecl;
begin
  CMAC_CTX_new := LoadLibCryptoFunction('CMAC_CTX_new');
  if not assigned(CMAC_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_new');
  Result := CMAC_CTX_new;
end;

procedure Load_CMAC_CTX_cleanup(ctx: PCMAC_CTX); cdecl;
begin
  CMAC_CTX_cleanup := LoadLibCryptoFunction('CMAC_CTX_cleanup');
  if not assigned(CMAC_CTX_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_cleanup');
  CMAC_CTX_cleanup(ctx);
end;

procedure Load_CMAC_CTX_free(ctx: PCMAC_CTX); cdecl;
begin
  CMAC_CTX_free := LoadLibCryptoFunction('CMAC_CTX_free');
  if not assigned(CMAC_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_free');
  CMAC_CTX_free(ctx);
end;

function Load_CMAC_CTX_get0_cipher_ctx(ctx: PCMAC_CTX): PEVP_CIPHER_CTX; cdecl;
begin
  CMAC_CTX_get0_cipher_ctx := LoadLibCryptoFunction('CMAC_CTX_get0_cipher_ctx');
  if not assigned(CMAC_CTX_get0_cipher_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_get0_cipher_ctx');
  Result := CMAC_CTX_get0_cipher_ctx(ctx);
end;

function Load_CMAC_CTX_copy(out_: PCMAC_CTX; in_: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  CMAC_CTX_copy := LoadLibCryptoFunction('CMAC_CTX_copy');
  if not assigned(CMAC_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_CTX_copy');
  Result := CMAC_CTX_copy(out_, in_);
end;

function Load_CMAC_Init(ctx: PCMAC_CTX; key: pointer; keylen: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  CMAC_Init := LoadLibCryptoFunction('CMAC_Init');
  if not assigned(CMAC_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Init');
  Result := CMAC_Init(ctx, key, keylen, cipher, impl);
end;

function Load_CMAC_Update(ctx: PCMAC_CTX; data: pointer; dlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMAC_Update := LoadLibCryptoFunction('CMAC_Update');
  if not assigned(CMAC_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Update');
  Result := CMAC_Update(ctx, data, dlen);
end;

function Load_CMAC_Final(ctx: PCMAC_CTX; out_: Pbyte; poutlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CMAC_Final := LoadLibCryptoFunction('CMAC_Final');
  if not assigned(CMAC_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_Final');
  Result := CMAC_Final(ctx, out_, poutlen);
end;

function Load_CMAC_resume(ctx: PCMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  CMAC_resume := LoadLibCryptoFunction('CMAC_resume');
  if not assigned(CMAC_resume) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CMAC_resume');
  Result := CMAC_resume(ctx);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_CMAC}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_CMAC}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  CMAC_CTX_new := Load_CMAC_CTX_new;
  CMAC_CTX_cleanup := Load_CMAC_CTX_cleanup;
  CMAC_CTX_free := Load_CMAC_CTX_free;
  CMAC_CTX_get0_cipher_ctx := Load_CMAC_CTX_get0_cipher_ctx;
  CMAC_CTX_copy := Load_CMAC_CTX_copy;
  CMAC_Init := Load_CMAC_Init;
  CMAC_Update := Load_CMAC_Update;
  CMAC_Final := Load_CMAC_Final;
  CMAC_resume := Load_CMAC_resume;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_CMAC}
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



