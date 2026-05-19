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

unit openssl_comp;

{
  Generated from OpenSSL 3.0.20 Header File comp.h - Tue 19 May 14:15:39 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_comp.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_crypto,openssl_comperr;


{* Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_COMP_H}
  {$define OPENSSL_COMP_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_COMP_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_COMP}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl; external CLibCrypto name 'COMP_CTX_new';
  function COMP_CTX_get_method(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl; external CLibCrypto name 'COMP_CTX_get_method';
  function COMP_CTX_get_type(comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'COMP_CTX_get_type';
  function COMP_get_type(meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'COMP_get_type';
  function COMP_get_name(meth: PCOMP_METHOD): PAnsiChar; cdecl; external CLibCrypto name 'COMP_get_name';
  procedure COMP_CTX_free(ctx: PCOMP_CTX); cdecl; external CLibCrypto name 'COMP_CTX_free';
  function COMP_compress_block(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'COMP_compress_block';
  function COMP_expand_block(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'COMP_expand_block';
  function COMP_zlib: PCOMP_METHOD; cdecl; external CLibCrypto name 'COMP_zlib';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM COMP_CTX_new}
  {$EXTERNALSYM COMP_CTX_get_method}
  {$EXTERNALSYM COMP_CTX_get_type}
  {$EXTERNALSYM COMP_get_type}
  {$EXTERNALSYM COMP_get_name}
  {$EXTERNALSYM COMP_CTX_free}
  {$EXTERNALSYM COMP_compress_block}
  {$EXTERNALSYM COMP_expand_block}
  {$EXTERNALSYM COMP_zlib}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl;
  function Load_COMP_CTX_get_method(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl;
  function Load_COMP_CTX_get_type(comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_COMP_get_type(meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_COMP_get_name(meth: PCOMP_METHOD): PAnsiChar; cdecl;
  procedure Load_COMP_CTX_free(ctx: PCOMP_CTX); cdecl;
  function Load_COMP_compress_block(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_COMP_expand_block(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_COMP_zlib: PCOMP_METHOD; cdecl;

var
  COMP_CTX_new: function(meth: PCOMP_METHOD): PCOMP_CTX; cdecl = Load_COMP_CTX_new;
  COMP_CTX_get_method: function(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl = Load_COMP_CTX_get_method;
  COMP_CTX_get_type: function(comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl = Load_COMP_CTX_get_type;
  COMP_get_type: function(meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl = Load_COMP_get_type;
  COMP_get_name: function(meth: PCOMP_METHOD): PAnsiChar; cdecl = Load_COMP_get_name;
  COMP_CTX_free: procedure(ctx: PCOMP_CTX); cdecl = Load_COMP_CTX_free;
  COMP_compress_block: function(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_COMP_compress_block;
  COMP_expand_block: function(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_COMP_expand_block;
  COMP_zlib: function: PCOMP_METHOD; cdecl = Load_COMP_zlib;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{# define  COMP_zlib_cleanup() while (0) continue}
    {$endif}
    {$ifdef OPENSSL_BIO_H}
      {$ifdef ZLIB}


        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function BIO_f_zlib: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_zlib';
        {$else}
  {$EXTERNALSYM BIO_f_zlib}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_BIO_f_zlib: PBIO_METHOD; cdecl;

var
  BIO_f_zlib: function: PBIO_METHOD; cdecl = Load_BIO_f_zlib;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}
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
{$ifndef  OPENSSL_NO_COMP}
function Load_COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl;
begin
  COMP_CTX_new := LoadLibCryptoFunction('COMP_CTX_new');
  if not assigned(COMP_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_new');
  Result := COMP_CTX_new(meth);
end;

function Load_COMP_CTX_get_method(ctx: PCOMP_CTX): PCOMP_METHOD; cdecl;
begin
  COMP_CTX_get_method := LoadLibCryptoFunction('COMP_CTX_get_method');
  if not assigned(COMP_CTX_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_get_method');
  Result := COMP_CTX_get_method(ctx);
end;

function Load_COMP_CTX_get_type(comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl;
begin
  COMP_CTX_get_type := LoadLibCryptoFunction('COMP_CTX_get_type');
  if not assigned(COMP_CTX_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_get_type');
  Result := COMP_CTX_get_type(comp);
end;

function Load_COMP_get_type(meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl;
begin
  COMP_get_type := LoadLibCryptoFunction('COMP_get_type');
  if not assigned(COMP_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_get_type');
  Result := COMP_get_type(meth);
end;

function Load_COMP_get_name(meth: PCOMP_METHOD): PAnsiChar; cdecl;
begin
  COMP_get_name := LoadLibCryptoFunction('COMP_get_name');
  if not assigned(COMP_get_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_get_name');
  Result := COMP_get_name(meth);
end;

procedure Load_COMP_CTX_free(ctx: PCOMP_CTX); cdecl;
begin
  COMP_CTX_free := LoadLibCryptoFunction('COMP_CTX_free');
  if not assigned(COMP_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_free');
  COMP_CTX_free(ctx);
end;

function Load_COMP_compress_block(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  COMP_compress_block := LoadLibCryptoFunction('COMP_compress_block');
  if not assigned(COMP_compress_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_compress_block');
  Result := COMP_compress_block(ctx, out_, olen, in_, ilen);
end;

function Load_COMP_expand_block(ctx: PCOMP_CTX; out_: Pbyte; olen: TOpenSSL_C_INT; in_: Pbyte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  COMP_expand_block := LoadLibCryptoFunction('COMP_expand_block');
  if not assigned(COMP_expand_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_expand_block');
  Result := COMP_expand_block(ctx, out_, olen, in_, ilen);
end;

function Load_COMP_zlib: PCOMP_METHOD; cdecl;
begin
  COMP_zlib := LoadLibCryptoFunction('COMP_zlib');
  if not assigned(COMP_zlib) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_zlib');
  Result := COMP_zlib;
end;

    {$ifdef OPENSSL_BIO_H}
        {$ifdef ZLIB}
function Load_BIO_f_zlib: PBIO_METHOD; cdecl;
begin
  BIO_f_zlib := LoadLibCryptoFunction('BIO_f_zlib');
  if not assigned(BIO_f_zlib) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_zlib');
  Result := BIO_f_zlib;
end;

        {$endif} {ZLIB}
    {$endif} {OPENSSL_BIO_H}
{$endif} { OPENSSL_NO_COMP}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_COMP}
  COMP_CTX_new := Load_COMP_CTX_new;
  COMP_CTX_get_method := Load_COMP_CTX_get_method;
  COMP_CTX_get_type := Load_COMP_CTX_get_type;
  COMP_get_type := Load_COMP_get_type;
  COMP_get_name := Load_COMP_get_name;
  COMP_CTX_free := Load_COMP_CTX_free;
  COMP_compress_block := Load_COMP_compress_block;
  COMP_expand_block := Load_COMP_expand_block;
  COMP_zlib := Load_COMP_zlib;
    {$ifdef OPENSSL_BIO_H}
        {$ifdef ZLIB}
  BIO_f_zlib := Load_BIO_f_zlib;
        {$endif} {ZLIB}
    {$endif} {OPENSSL_BIO_H}
{$endif} { OPENSSL_NO_COMP}
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



