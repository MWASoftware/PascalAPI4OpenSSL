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

unit openssl_hmac;

{
  Generated from OpenSSL 3.5.6 Header File hmac.h - Tue 19 May 14:27:49 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_hmac.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_evp;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_HMAC_H}
  {$define OPENSSL_HMAC_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_HMAC_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  HMAC_MAX_MD_CBLOCK = 200;
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function HMAC_size(e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'HMAC_size'; deprecated 'Since OpenSSL 3.0';
  function HMAC_CTX_new: PHMAC_CTX; cdecl; external CLibCrypto name 'HMAC_CTX_new'; deprecated 'Since OpenSSL 3.0';
  function HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'HMAC_CTX_reset'; deprecated 'Since OpenSSL 3.0';
  procedure HMAC_CTX_free(ctx: PHMAC_CTX); cdecl; external CLibCrypto name 'HMAC_CTX_free'; deprecated 'Since OpenSSL 3.0';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM HMAC_size}
  {$EXTERNALSYM HMAC_CTX_new}
  {$EXTERNALSYM HMAC_CTX_reset}
  {$EXTERNALSYM HMAC_CTX_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_HMAC_size(e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl;
  function Load_HMAC_CTX_new: PHMAC_CTX; cdecl;
  function Load_HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;

var
  HMAC_size: function(e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl = Load_HMAC_size;
  HMAC_CTX_new: function: PHMAC_CTX; cdecl = Load_HMAC_CTX_new;
  HMAC_CTX_reset: function(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl = Load_HMAC_CTX_reset;
  HMAC_CTX_free: procedure(ctx: PHMAC_CTX); cdecl = Load_HMAC_CTX_free;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function HMAC_Init(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'HMAC_Init'; deprecated 'Since OpenSSL 1.1.0';
    {$else}
  {$EXTERNALSYM HMAC_Init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_HMAC_Init(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD): TOpenSSL_C_INT; cdecl;

var
  HMAC_Init: function(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_HMAC_Init;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function HMAC_Init_ex(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'HMAC_Init_ex'; deprecated 'Since OpenSSL 3.0';
  function HMAC_Update(ctx: PHMAC_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'HMAC_Update'; deprecated 'Since OpenSSL 3.0';
  function HMAC_Final(ctx: PHMAC_CTX; md: Pbyte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'HMAC_Final'; deprecated 'Since OpenSSL 3.0';
  function HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'HMAC_CTX_copy'; deprecated 'Since OpenSSL 3.0';
  procedure HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_UINT); cdecl; external CLibCrypto name 'HMAC_CTX_set_flags'; deprecated 'Since OpenSSL 3.0';
  function HMAC_CTX_get_md(ctx: PHMAC_CTX): PEVP_MD; cdecl; external CLibCrypto name 'HMAC_CTX_get_md'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM HMAC_Init_ex}
  {$EXTERNALSYM HMAC_Update}
  {$EXTERNALSYM HMAC_Final}
  {$EXTERNALSYM HMAC_CTX_copy}
  {$EXTERNALSYM HMAC_CTX_set_flags}
  {$EXTERNALSYM HMAC_CTX_get_md}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_HMAC_Init_ex(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_HMAC_Update(ctx: PHMAC_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_HMAC_Final(ctx: PHMAC_CTX; md: Pbyte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_UINT); cdecl;
  function Load_HMAC_CTX_get_md(ctx: PHMAC_CTX): PEVP_MD; cdecl;

var
  HMAC_Init_ex: function(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = Load_HMAC_Init_ex;
  HMAC_Update: function(ctx: PHMAC_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_HMAC_Update;
  HMAC_Final: function(ctx: PHMAC_CTX; md: Pbyte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_HMAC_Final;
  HMAC_CTX_copy: function(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl = Load_HMAC_CTX_copy;
  HMAC_CTX_set_flags: procedure(ctx: PHMAC_CTX; flags: TOpenSSL_C_UINT); cdecl = Load_HMAC_CTX_set_flags;
  HMAC_CTX_get_md: function(ctx: PHMAC_CTX): PEVP_MD; cdecl = Load_HMAC_CTX_get_md;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function HMAC(evp_md: PEVP_MD; key: pointer; key_len: TOpenSSL_C_INT; data: Pbyte; data_len: TOpenSSL_C_SIZET; md: Pbyte; md_len: POpenSSL_C_UINT): Pbyte; cdecl; external CLibCrypto name 'HMAC';
  {$else}
  {$EXTERNALSYM HMAC}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_HMAC(evp_md: PEVP_MD; key: pointer; key_len: TOpenSSL_C_INT; data: Pbyte; data_len: TOpenSSL_C_SIZET; md: Pbyte; md_len: POpenSSL_C_UINT): Pbyte; cdecl;

var
  HMAC: function(evp_md: PEVP_MD; key: pointer; key_len: TOpenSSL_C_INT; data: Pbyte; data_len: TOpenSSL_C_SIZET; md: Pbyte; md_len: POpenSSL_C_UINT): Pbyte; cdecl = Load_HMAC;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
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
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_HMAC_size(e: PHMAC_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  HMAC_size := LoadLibCryptoFunction('HMAC_size');
  if not assigned(HMAC_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_size');
  Result := HMAC_size(e);
end;

function Load_HMAC_CTX_new: PHMAC_CTX; cdecl;
begin
  HMAC_CTX_new := LoadLibCryptoFunction('HMAC_CTX_new');
  if not assigned(HMAC_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_new');
  Result := HMAC_CTX_new;
end;

function Load_HMAC_CTX_reset(ctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  HMAC_CTX_reset := LoadLibCryptoFunction('HMAC_CTX_reset');
  if not assigned(HMAC_CTX_reset) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_reset');
  Result := HMAC_CTX_reset(ctx);
end;

procedure Load_HMAC_CTX_free(ctx: PHMAC_CTX); cdecl;
begin
  HMAC_CTX_free := LoadLibCryptoFunction('HMAC_CTX_free');
  if not assigned(HMAC_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_free');
  HMAC_CTX_free(ctx);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
function Load_HMAC_Init(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  HMAC_Init := LoadLibCryptoFunction('HMAC_Init');
  if not assigned(HMAC_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Init');
  Result := HMAC_Init(ctx, key, len, md);
end;

{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_HMAC_Init_ex(ctx: PHMAC_CTX; key: pointer; len: TOpenSSL_C_INT; md: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  HMAC_Init_ex := LoadLibCryptoFunction('HMAC_Init_ex');
  if not assigned(HMAC_Init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Init_ex');
  Result := HMAC_Init_ex(ctx, key, len, md, impl);
end;

function Load_HMAC_Update(ctx: PHMAC_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  HMAC_Update := LoadLibCryptoFunction('HMAC_Update');
  if not assigned(HMAC_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Update');
  Result := HMAC_Update(ctx, data, len);
end;

function Load_HMAC_Final(ctx: PHMAC_CTX; md: Pbyte; len: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  HMAC_Final := LoadLibCryptoFunction('HMAC_Final');
  if not assigned(HMAC_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_Final');
  Result := HMAC_Final(ctx, md, len);
end;

function Load_HMAC_CTX_copy(dctx: PHMAC_CTX; sctx: PHMAC_CTX): TOpenSSL_C_INT; cdecl;
begin
  HMAC_CTX_copy := LoadLibCryptoFunction('HMAC_CTX_copy');
  if not assigned(HMAC_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_copy');
  Result := HMAC_CTX_copy(dctx, sctx);
end;

procedure Load_HMAC_CTX_set_flags(ctx: PHMAC_CTX; flags: TOpenSSL_C_UINT); cdecl;
begin
  HMAC_CTX_set_flags := LoadLibCryptoFunction('HMAC_CTX_set_flags');
  if not assigned(HMAC_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_set_flags');
  HMAC_CTX_set_flags(ctx, flags);
end;

function Load_HMAC_CTX_get_md(ctx: PHMAC_CTX): PEVP_MD; cdecl;
begin
  HMAC_CTX_get_md := LoadLibCryptoFunction('HMAC_CTX_get_md');
  if not assigned(HMAC_CTX_get_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC_CTX_get_md');
  Result := HMAC_CTX_get_md(ctx);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_HMAC(evp_md: PEVP_MD; key: pointer; key_len: TOpenSSL_C_INT; data: Pbyte; data_len: TOpenSSL_C_SIZET; md: Pbyte; md_len: POpenSSL_C_UINT): Pbyte; cdecl;
begin
  HMAC := LoadLibCryptoFunction('HMAC');
  if not assigned(HMAC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('HMAC');
  Result := HMAC(evp_md, key, key_len, data, data_len, md, md_len);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  HMAC_size := Load_HMAC_size;
  HMAC_CTX_new := Load_HMAC_CTX_new;
  HMAC_CTX_reset := Load_HMAC_CTX_reset;
  HMAC_CTX_free := Load_HMAC_CTX_free;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  HMAC_Init := Load_HMAC_Init;
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  HMAC_Init_ex := Load_HMAC_Init_ex;
  HMAC_Update := Load_HMAC_Update;
  HMAC_Final := Load_HMAC_Final;
  HMAC_CTX_copy := Load_HMAC_CTX_copy;
  HMAC_CTX_set_flags := Load_HMAC_CTX_set_flags;
  HMAC_CTX_get_md := Load_HMAC_CTX_get_md;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  HMAC := Load_HMAC;
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



