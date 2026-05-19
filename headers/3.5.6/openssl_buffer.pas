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

unit openssl_buffer;

{
  Generated from OpenSSL 3.5.6 Header File buffer.h - Tue 19 May 14:27:07 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_buffer.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_crypto,openssl_buffererr;


{* Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_BUFFER_H}
  {$define OPENSSL_BUFFER_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_BUFFER_H}
  {$endif}
  {$ifndef  OPENSSL_CRYPTO_H}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  BUF_strdup(s) OPENSSL_strdup(s)} {Macro Return Type unknown at line no 34}
{# define  BUF_strndup(s,size) OPENSSL_strndup(s, size)} {Macro Return Type unknown at line no 35}
{# define  BUF_memdup(data,size) OPENSSL_memdup(data, size)} {Macro Return Type unknown at line no 36}
{# define  BUF_strlcpy(dst,src,size) OPENSSL_strlcpy(dst, src, size)} {Macro Return Type unknown at line no 37}
{# define  BUF_strlcat(dst,src,size) OPENSSL_strlcat(dst, src, size)} {Macro Return Type unknown at line no 38}
{# define  BUF_strnlen(str,maxlen) OPENSSL_strnlen(str, maxlen)} {Macro Return Type unknown at line no 39}
  {$endif}

type
  {Auto-generated forward references}
  Pbuf_mem_st = ^Tbuf_mem_st;
  PPbuf_mem_st = ^Pbuf_mem_st;
  {end of auto-generated forward references}

  Tbuf_mem_st = record 
    length: TOpenSSL_C_SIZET; { current number of bytes }
    data: PAnsiChar;
    max: TOpenSSL_C_SIZET; { size of buffer }
    flags: TOpenSSL_C_UINT;
  end;

const
  BUF_MEM_FLAG_SECURE = $01;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function BUF_MEM_new: PBUF_MEM; cdecl; external CLibCrypto name 'BUF_MEM_new';
  function BUF_MEM_new_ex(flags: TOpenSSL_C_UINT): PBUF_MEM; cdecl; external CLibCrypto name 'BUF_MEM_new_ex';
  procedure BUF_MEM_free(a: PBUF_MEM); cdecl; external CLibCrypto name 'BUF_MEM_free';
  function BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'BUF_MEM_grow';
  function BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'BUF_MEM_grow_clean';
  procedure BUF_reverse(out_: Pbyte; in_: Pbyte; siz: TOpenSSL_C_SIZET); cdecl; external CLibCrypto name 'BUF_reverse';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM BUF_MEM_new}
  {$EXTERNALSYM BUF_MEM_new_ex}
  {$EXTERNALSYM BUF_MEM_free}
  {$EXTERNALSYM BUF_MEM_grow}
  {$EXTERNALSYM BUF_MEM_grow_clean}
  {$EXTERNALSYM BUF_reverse}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_BUF_MEM_new: PBUF_MEM; cdecl;
  function Load_BUF_MEM_new_ex(flags: TOpenSSL_C_UINT): PBUF_MEM; cdecl;
  procedure Load_BUF_MEM_free(a: PBUF_MEM); cdecl;
  function Load_BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
  function Load_BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
  procedure Load_BUF_reverse(out_: Pbyte; in_: Pbyte; siz: TOpenSSL_C_SIZET); cdecl;

var
  BUF_MEM_new: function: PBUF_MEM; cdecl = Load_BUF_MEM_new;
  BUF_MEM_new_ex: function(flags: TOpenSSL_C_UINT): PBUF_MEM; cdecl = Load_BUF_MEM_new_ex;
  BUF_MEM_free: procedure(a: PBUF_MEM); cdecl = Load_BUF_MEM_free;
  BUF_MEM_grow: function(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_BUF_MEM_grow;
  BUF_MEM_grow_clean: function(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_BUF_MEM_grow_clean;
  BUF_reverse: procedure(out_: Pbyte; in_: Pbyte; siz: TOpenSSL_C_SIZET); cdecl = Load_BUF_reverse;
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
function Load_BUF_MEM_new: PBUF_MEM; cdecl;
begin
  BUF_MEM_new := LoadLibCryptoFunction('BUF_MEM_new');
  if not assigned(BUF_MEM_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_new');
  Result := BUF_MEM_new;
end;

function Load_BUF_MEM_new_ex(flags: TOpenSSL_C_UINT): PBUF_MEM; cdecl;
begin
  BUF_MEM_new_ex := LoadLibCryptoFunction('BUF_MEM_new_ex');
  if not assigned(BUF_MEM_new_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_new_ex');
  Result := BUF_MEM_new_ex(flags);
end;

procedure Load_BUF_MEM_free(a: PBUF_MEM); cdecl;
begin
  BUF_MEM_free := LoadLibCryptoFunction('BUF_MEM_free');
  if not assigned(BUF_MEM_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_free');
  BUF_MEM_free(a);
end;

function Load_BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  BUF_MEM_grow := LoadLibCryptoFunction('BUF_MEM_grow');
  if not assigned(BUF_MEM_grow) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_grow');
  Result := BUF_MEM_grow(str, len);
end;

function Load_BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  BUF_MEM_grow_clean := LoadLibCryptoFunction('BUF_MEM_grow_clean');
  if not assigned(BUF_MEM_grow_clean) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_grow_clean');
  Result := BUF_MEM_grow_clean(str, len);
end;

procedure Load_BUF_reverse(out_: Pbyte; in_: Pbyte; siz: TOpenSSL_C_SIZET); cdecl;
begin
  BUF_reverse := LoadLibCryptoFunction('BUF_reverse');
  if not assigned(BUF_reverse) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_reverse');
  BUF_reverse(out_, in_, siz);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  BUF_MEM_new := Load_BUF_MEM_new;
  BUF_MEM_new_ex := Load_BUF_MEM_new_ex;
  BUF_MEM_free := Load_BUF_MEM_free;
  BUF_MEM_grow := Load_BUF_MEM_grow;
  BUF_MEM_grow_clean := Load_BUF_MEM_grow_clean;
  BUF_reverse := Load_BUF_reverse;
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



