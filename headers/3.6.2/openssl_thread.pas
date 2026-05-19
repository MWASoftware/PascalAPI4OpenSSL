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

unit openssl_thread;

{
  Generated from OpenSSL 3.6.2 Header File thread.h - Tue 19 May 14:30:54 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_thread.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types;


{* Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
* Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_THREAD_H}
  {$define OPENSSL_THREAD_H}

const
  OSSL_THREAD_SUPPORT_FLAG_THREAD_POOL = 1 shl 0;
  OSSL_THREAD_SUPPORT_FLAG_DEFAULT_SPAWN = 1 shl 1;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_get_thread_support_flags: TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'OSSL_get_thread_support_flags';
  function OSSL_set_max_threads(ctx: POSSL_LIB_CTX; max_threads: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_set_max_threads';
  function OSSL_get_max_threads(ctx: POSSL_LIB_CTX): TOpenSSL_C_UINT64; cdecl; external CLibCrypto name 'OSSL_get_max_threads';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_get_thread_support_flags}
  {$EXTERNALSYM OSSL_set_max_threads}
  {$EXTERNALSYM OSSL_get_max_threads}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_get_thread_support_flags: TOpenSSL_C_UINT; cdecl;
  function Load_OSSL_set_max_threads(ctx: POSSL_LIB_CTX; max_threads: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_get_max_threads(ctx: POSSL_LIB_CTX): TOpenSSL_C_UINT64; cdecl;

var
  OSSL_get_thread_support_flags: function: TOpenSSL_C_UINT; cdecl = Load_OSSL_get_thread_support_flags;
  OSSL_set_max_threads: function(ctx: POSSL_LIB_CTX; max_threads: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_OSSL_set_max_threads;
  OSSL_get_max_threads: function(ctx: POSSL_LIB_CTX): TOpenSSL_C_UINT64; cdecl = Load_OSSL_get_max_threads;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}
{ OPENSSL_THREAD_H }

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
function Load_OSSL_get_thread_support_flags: TOpenSSL_C_UINT; cdecl;
begin
  OSSL_get_thread_support_flags := LoadLibCryptoFunction('OSSL_get_thread_support_flags');
  if not assigned(OSSL_get_thread_support_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_get_thread_support_flags');
  Result := OSSL_get_thread_support_flags;
end;

function Load_OSSL_set_max_threads(ctx: POSSL_LIB_CTX; max_threads: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  OSSL_set_max_threads := LoadLibCryptoFunction('OSSL_set_max_threads');
  if not assigned(OSSL_set_max_threads) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_set_max_threads');
  Result := OSSL_set_max_threads(ctx, max_threads);
end;

function Load_OSSL_get_max_threads(ctx: POSSL_LIB_CTX): TOpenSSL_C_UINT64; cdecl;
begin
  OSSL_get_max_threads := LoadLibCryptoFunction('OSSL_get_max_threads');
  if not assigned(OSSL_get_max_threads) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_get_max_threads');
  Result := OSSL_get_max_threads(ctx);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_get_thread_support_flags := Load_OSSL_get_thread_support_flags;
  OSSL_set_max_threads := Load_OSSL_set_max_threads;
  OSSL_get_max_threads := Load_OSSL_get_max_threads;
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



