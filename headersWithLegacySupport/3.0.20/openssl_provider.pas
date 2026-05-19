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

unit openssl_provider;

{
  Generated from OpenSSL 3.0.20 Header File provider.h - Tue 19 May 14:25:29 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_provider.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_core;


{* Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_PROVIDER_H}
  {$define OPENSSL_PROVIDER_H}


  { Set the default provider search path }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_PROVIDER_set_default_search_path(_param1: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_set_default_search_path';
  { Load and unload a provider }
  function OSSL_PROVIDER_load(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_PROVIDER_load';
  function OSSL_PROVIDER_try_load(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_PROVIDER_try_load';
  function OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_unload';
  function OSSL_PROVIDER_available(_param1: POSSL_LIB_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_available';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_PROVIDER_set_default_search_path}
  {$EXTERNALSYM OSSL_PROVIDER_load}
  {$EXTERNALSYM OSSL_PROVIDER_try_load}
  {$EXTERNALSYM OSSL_PROVIDER_unload}
  {$EXTERNALSYM OSSL_PROVIDER_available}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_PROVIDER_set_default_search_path(_param1: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_load(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl;
  function Load_OSSL_PROVIDER_try_load(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl;
  function Load_OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_available(_param1: POSSL_LIB_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  OSSL_PROVIDER_set_default_search_path: function(_param1: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_set_default_search_path;
  { Load and unload a provider }
  OSSL_PROVIDER_load: function(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_load;
  OSSL_PROVIDER_try_load: function(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_try_load;
  OSSL_PROVIDER_unload: function(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_unload;
  OSSL_PROVIDER_available: function(_param1: POSSL_LIB_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_available;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = function(provider: POSSL_PROVIDER; cbdata: pointer): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_PROVIDER_do_all(ctx: POSSL_LIB_CTX; cb: TFuncType000; cbdata: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_do_all';
  function OSSL_PROVIDER_gettable_params(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PROVIDER_gettable_params';
  function OSSL_PROVIDER_get_params(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_get_params';
  function OSSL_PROVIDER_self_test(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_self_test';
  function OSSL_PROVIDER_get_capabilities(prov: POSSL_PROVIDER; capability: PAnsiChar; cb: POSSL_CALLBACK; arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_get_capabilities';
  function OSSL_PROVIDER_query_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; no_cache: POpenSSL_C_INT): POSSL_ALGORITHM; cdecl; external CLibCrypto name 'OSSL_PROVIDER_query_operation';
  procedure OSSL_PROVIDER_unquery_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; algs: POSSL_ALGORITHM); cdecl; external CLibCrypto name 'OSSL_PROVIDER_unquery_operation';
  function OSSL_PROVIDER_get0_provider_ctx(prov: POSSL_PROVIDER): pointer; cdecl; external CLibCrypto name 'OSSL_PROVIDER_get0_provider_ctx';
  function OSSL_PROVIDER_get0_dispatch(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl; external CLibCrypto name 'OSSL_PROVIDER_get0_dispatch';
  { Add a built in providers }
  function OSSL_PROVIDER_add_builtin(_param1: POSSL_LIB_CTX; name: PAnsiChar; init_fn: POSSL_provider_init_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_add_builtin';
  { Information }
  function OSSL_PROVIDER_get0_name(prov: POSSL_PROVIDER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_PROVIDER_get0_name';
  {$else}
  {$EXTERNALSYM OSSL_PROVIDER_do_all}
  {$EXTERNALSYM OSSL_PROVIDER_gettable_params}
  {$EXTERNALSYM OSSL_PROVIDER_get_params}
  {$EXTERNALSYM OSSL_PROVIDER_self_test}
  {$EXTERNALSYM OSSL_PROVIDER_get_capabilities}
  {$EXTERNALSYM OSSL_PROVIDER_query_operation}
  {$EXTERNALSYM OSSL_PROVIDER_unquery_operation}
  {$EXTERNALSYM OSSL_PROVIDER_get0_provider_ctx}
  {$EXTERNALSYM OSSL_PROVIDER_get0_dispatch}
  {$EXTERNALSYM OSSL_PROVIDER_add_builtin}
  {$EXTERNALSYM OSSL_PROVIDER_get0_name}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_PROVIDER_do_all(ctx: POSSL_LIB_CTX; cb: TFuncType000; cbdata: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_gettable_params(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl;
  function Load_OSSL_PROVIDER_get_params(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_self_test(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_get_capabilities(prov: POSSL_PROVIDER; capability: PAnsiChar; cb: POSSL_CALLBACK; arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_query_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; no_cache: POpenSSL_C_INT): POSSL_ALGORITHM; cdecl;
  procedure Load_OSSL_PROVIDER_unquery_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; algs: POSSL_ALGORITHM); cdecl;
  function Load_OSSL_PROVIDER_get0_provider_ctx(prov: POSSL_PROVIDER): pointer; cdecl;
  function Load_OSSL_PROVIDER_get0_dispatch(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl;
  function Load_OSSL_PROVIDER_add_builtin(_param1: POSSL_LIB_CTX; name: PAnsiChar; init_fn: POSSL_provider_init_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_get0_name(prov: POSSL_PROVIDER): PAnsiChar; cdecl;

var
  OSSL_PROVIDER_do_all: function(ctx: POSSL_LIB_CTX; cb: TFuncType000; cbdata: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_do_all;
  OSSL_PROVIDER_gettable_params: function(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl = Load_OSSL_PROVIDER_gettable_params;
  OSSL_PROVIDER_get_params: function(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_get_params;
  OSSL_PROVIDER_self_test: function(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_self_test;
  OSSL_PROVIDER_get_capabilities: function(prov: POSSL_PROVIDER; capability: PAnsiChar; cb: POSSL_CALLBACK; arg: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_get_capabilities;
  OSSL_PROVIDER_query_operation: function(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; no_cache: POpenSSL_C_INT): POSSL_ALGORITHM; cdecl = Load_OSSL_PROVIDER_query_operation;
  OSSL_PROVIDER_unquery_operation: procedure(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; algs: POSSL_ALGORITHM); cdecl = Load_OSSL_PROVIDER_unquery_operation;
  OSSL_PROVIDER_get0_provider_ctx: function(prov: POSSL_PROVIDER): pointer; cdecl = Load_OSSL_PROVIDER_get0_provider_ctx;
  OSSL_PROVIDER_get0_dispatch: function(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl = Load_OSSL_PROVIDER_get0_dispatch;
  { Add a built in providers }
  OSSL_PROVIDER_add_builtin: function(_param1: POSSL_LIB_CTX; name: PAnsiChar; init_fn: POSSL_provider_init_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_add_builtin;
  { Information }
  OSSL_PROVIDER_get0_name: function(prov: POSSL_PROVIDER): PAnsiChar; cdecl = Load_OSSL_PROVIDER_get0_name;
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
function Load_OSSL_PROVIDER_set_default_search_path(_param1: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_set_default_search_path := LoadLibCryptoFunction('OSSL_PROVIDER_set_default_search_path');
  if not assigned(OSSL_PROVIDER_set_default_search_path) then
    {$if declared(LEGACY_OSSL_PROVIDER_set_default_search_path)}
    OSSL_PROVIDER_set_default_search_path := @LEGACY_OSSL_PROVIDER_set_default_search_path;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_set_default_search_path');
    {$ifend}
  Result := OSSL_PROVIDER_set_default_search_path(_param1, path);
end;

function Load_OSSL_PROVIDER_load(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_load := LoadLibCryptoFunction('OSSL_PROVIDER_load');
  if not assigned(OSSL_PROVIDER_load) then
    {$if declared(LEGACY_OSSL_PROVIDER_load)}
    OSSL_PROVIDER_load := @LEGACY_OSSL_PROVIDER_load;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_load');
    {$ifend}
  Result := OSSL_PROVIDER_load(_param1, name);
end;

function Load_OSSL_PROVIDER_try_load(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_try_load := LoadLibCryptoFunction('OSSL_PROVIDER_try_load');
  if not assigned(OSSL_PROVIDER_try_load) then
    {$if declared(LEGACY_OSSL_PROVIDER_try_load)}
    OSSL_PROVIDER_try_load := @LEGACY_OSSL_PROVIDER_try_load;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_try_load');
    {$ifend}
  Result := OSSL_PROVIDER_try_load(_param1, name, retain_fallbacks);
end;

function Load_OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_unload := LoadLibCryptoFunction('OSSL_PROVIDER_unload');
  if not assigned(OSSL_PROVIDER_unload) then
    {$if declared(LEGACY_OSSL_PROVIDER_unload)}
    OSSL_PROVIDER_unload := @LEGACY_OSSL_PROVIDER_unload;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unload');
    {$ifend}
  Result := OSSL_PROVIDER_unload(prov);
end;

function Load_OSSL_PROVIDER_available(_param1: POSSL_LIB_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_available := LoadLibCryptoFunction('OSSL_PROVIDER_available');
  if not assigned(OSSL_PROVIDER_available) then
    {$if declared(LEGACY_OSSL_PROVIDER_available)}
    OSSL_PROVIDER_available := @LEGACY_OSSL_PROVIDER_available;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_available');
    {$ifend}
  Result := OSSL_PROVIDER_available(_param1, name);
end;

function Load_OSSL_PROVIDER_do_all(ctx: POSSL_LIB_CTX; cb: TFuncType000; cbdata: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_do_all := LoadLibCryptoFunction('OSSL_PROVIDER_do_all');
  if not assigned(OSSL_PROVIDER_do_all) then
    {$if declared(LEGACY_OSSL_PROVIDER_do_all)}
    OSSL_PROVIDER_do_all := @LEGACY_OSSL_PROVIDER_do_all;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_do_all');
    {$ifend}
  Result := OSSL_PROVIDER_do_all(ctx, cb, cbdata);
end;

function Load_OSSL_PROVIDER_gettable_params(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl;
begin
  OSSL_PROVIDER_gettable_params := LoadLibCryptoFunction('OSSL_PROVIDER_gettable_params');
  if not assigned(OSSL_PROVIDER_gettable_params) then
    {$if declared(LEGACY_OSSL_PROVIDER_gettable_params)}
    OSSL_PROVIDER_gettable_params := @LEGACY_OSSL_PROVIDER_gettable_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_gettable_params');
    {$ifend}
  Result := OSSL_PROVIDER_gettable_params(prov);
end;

function Load_OSSL_PROVIDER_get_params(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_get_params := LoadLibCryptoFunction('OSSL_PROVIDER_get_params');
  if not assigned(OSSL_PROVIDER_get_params) then
    {$if declared(LEGACY_OSSL_PROVIDER_get_params)}
    OSSL_PROVIDER_get_params := @LEGACY_OSSL_PROVIDER_get_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_params');
    {$ifend}
  Result := OSSL_PROVIDER_get_params(prov, params);
end;

function Load_OSSL_PROVIDER_self_test(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_self_test := LoadLibCryptoFunction('OSSL_PROVIDER_self_test');
  if not assigned(OSSL_PROVIDER_self_test) then
    {$if declared(LEGACY_OSSL_PROVIDER_self_test)}
    OSSL_PROVIDER_self_test := @LEGACY_OSSL_PROVIDER_self_test;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_self_test');
    {$ifend}
  Result := OSSL_PROVIDER_self_test(prov);
end;

function Load_OSSL_PROVIDER_get_capabilities(prov: POSSL_PROVIDER; capability: PAnsiChar; cb: POSSL_CALLBACK; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_get_capabilities := LoadLibCryptoFunction('OSSL_PROVIDER_get_capabilities');
  if not assigned(OSSL_PROVIDER_get_capabilities) then
    {$if declared(LEGACY_OSSL_PROVIDER_get_capabilities)}
    OSSL_PROVIDER_get_capabilities := @LEGACY_OSSL_PROVIDER_get_capabilities;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_capabilities');
    {$ifend}
  Result := OSSL_PROVIDER_get_capabilities(prov, capability, cb, arg);
end;

function Load_OSSL_PROVIDER_query_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; no_cache: POpenSSL_C_INT): POSSL_ALGORITHM; cdecl;
begin
  OSSL_PROVIDER_query_operation := LoadLibCryptoFunction('OSSL_PROVIDER_query_operation');
  if not assigned(OSSL_PROVIDER_query_operation) then
    {$if declared(LEGACY_OSSL_PROVIDER_query_operation)}
    OSSL_PROVIDER_query_operation := @LEGACY_OSSL_PROVIDER_query_operation;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_query_operation');
    {$ifend}
  Result := OSSL_PROVIDER_query_operation(prov, operation_id, no_cache);
end;

procedure Load_OSSL_PROVIDER_unquery_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; algs: POSSL_ALGORITHM); cdecl;
begin
  OSSL_PROVIDER_unquery_operation := LoadLibCryptoFunction('OSSL_PROVIDER_unquery_operation');
  if not assigned(OSSL_PROVIDER_unquery_operation) then
    {$if declared(LEGACY_OSSL_PROVIDER_unquery_operation)}
    OSSL_PROVIDER_unquery_operation := @LEGACY_OSSL_PROVIDER_unquery_operation;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unquery_operation');
    {$ifend}
  OSSL_PROVIDER_unquery_operation(prov, operation_id, algs);
end;

function Load_OSSL_PROVIDER_get0_provider_ctx(prov: POSSL_PROVIDER): pointer; cdecl;
begin
  OSSL_PROVIDER_get0_provider_ctx := LoadLibCryptoFunction('OSSL_PROVIDER_get0_provider_ctx');
  if not assigned(OSSL_PROVIDER_get0_provider_ctx) then
    {$if declared(LEGACY_OSSL_PROVIDER_get0_provider_ctx)}
    OSSL_PROVIDER_get0_provider_ctx := @LEGACY_OSSL_PROVIDER_get0_provider_ctx;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_provider_ctx');
    {$ifend}
  Result := OSSL_PROVIDER_get0_provider_ctx(prov);
end;

function Load_OSSL_PROVIDER_get0_dispatch(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl;
begin
  OSSL_PROVIDER_get0_dispatch := LoadLibCryptoFunction('OSSL_PROVIDER_get0_dispatch');
  if not assigned(OSSL_PROVIDER_get0_dispatch) then
    {$if declared(LEGACY_OSSL_PROVIDER_get0_dispatch)}
    OSSL_PROVIDER_get0_dispatch := @LEGACY_OSSL_PROVIDER_get0_dispatch;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_dispatch');
    {$ifend}
  Result := OSSL_PROVIDER_get0_dispatch(prov);
end;

function Load_OSSL_PROVIDER_add_builtin(_param1: POSSL_LIB_CTX; name: PAnsiChar; init_fn: POSSL_provider_init_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_add_builtin := LoadLibCryptoFunction('OSSL_PROVIDER_add_builtin');
  if not assigned(OSSL_PROVIDER_add_builtin) then
    {$if declared(LEGACY_OSSL_PROVIDER_add_builtin)}
    OSSL_PROVIDER_add_builtin := @LEGACY_OSSL_PROVIDER_add_builtin;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_add_builtin');
    {$ifend}
  Result := OSSL_PROVIDER_add_builtin(_param1, name, init_fn);
end;

function Load_OSSL_PROVIDER_get0_name(prov: POSSL_PROVIDER): PAnsiChar; cdecl;
begin
  OSSL_PROVIDER_get0_name := LoadLibCryptoFunction('OSSL_PROVIDER_get0_name');
  if not assigned(OSSL_PROVIDER_get0_name) then
    {$if declared(LEGACY_OSSL_PROVIDER_get0_name)}
    OSSL_PROVIDER_get0_name := @LEGACY_OSSL_PROVIDER_get0_name;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_name');
    {$ifend}
  Result := OSSL_PROVIDER_get0_name(prov);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_PROVIDER_set_default_search_path := Load_OSSL_PROVIDER_set_default_search_path;
  OSSL_PROVIDER_load := Load_OSSL_PROVIDER_load;
  OSSL_PROVIDER_try_load := Load_OSSL_PROVIDER_try_load;
  OSSL_PROVIDER_unload := Load_OSSL_PROVIDER_unload;
  OSSL_PROVIDER_available := Load_OSSL_PROVIDER_available;
  OSSL_PROVIDER_do_all := Load_OSSL_PROVIDER_do_all;
  OSSL_PROVIDER_gettable_params := Load_OSSL_PROVIDER_gettable_params;
  OSSL_PROVIDER_get_params := Load_OSSL_PROVIDER_get_params;
  OSSL_PROVIDER_self_test := Load_OSSL_PROVIDER_self_test;
  OSSL_PROVIDER_get_capabilities := Load_OSSL_PROVIDER_get_capabilities;
  OSSL_PROVIDER_query_operation := Load_OSSL_PROVIDER_query_operation;
  OSSL_PROVIDER_unquery_operation := Load_OSSL_PROVIDER_unquery_operation;
  OSSL_PROVIDER_get0_provider_ctx := Load_OSSL_PROVIDER_get0_provider_ctx;
  OSSL_PROVIDER_get0_dispatch := Load_OSSL_PROVIDER_get0_dispatch;
  OSSL_PROVIDER_add_builtin := Load_OSSL_PROVIDER_add_builtin;
  OSSL_PROVIDER_get0_name := Load_OSSL_PROVIDER_get0_name;
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



