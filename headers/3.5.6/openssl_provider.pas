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
  Generated from OpenSSL 3.5.6 Header File provider.h - Tue 19 May 14:28:10 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_provider.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_core;


{* Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_PROVIDER_H}
  {$define OPENSSL_PROVIDER_H}


  { Set and Get a library context search path }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_PROVIDER_set_default_search_path(_param1: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_set_default_search_path';
  function OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_PROVIDER_get0_default_search_path';
  { Load and unload a provider }
  function OSSL_PROVIDER_load(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_PROVIDER_load';
  function OSSL_PROVIDER_load_ex(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_PROVIDER_load_ex';
  function OSSL_PROVIDER_try_load(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_PROVIDER_try_load';
  function OSSL_PROVIDER_try_load_ex(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_PROVIDER_try_load_ex';
  function OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_unload';
  function OSSL_PROVIDER_available(_param1: POSSL_LIB_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_available';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_PROVIDER_set_default_search_path}
  {$EXTERNALSYM OSSL_PROVIDER_get0_default_search_path}
  {$EXTERNALSYM OSSL_PROVIDER_load}
  {$EXTERNALSYM OSSL_PROVIDER_load_ex}
  {$EXTERNALSYM OSSL_PROVIDER_try_load}
  {$EXTERNALSYM OSSL_PROVIDER_try_load_ex}
  {$EXTERNALSYM OSSL_PROVIDER_unload}
  {$EXTERNALSYM OSSL_PROVIDER_available}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_PROVIDER_set_default_search_path(_param1: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl;
  function Load_OSSL_PROVIDER_load(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl;
  function Load_OSSL_PROVIDER_load_ex(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl;
  function Load_OSSL_PROVIDER_try_load(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl;
  function Load_OSSL_PROVIDER_try_load_ex(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl;
  function Load_OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_available(_param1: POSSL_LIB_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  OSSL_PROVIDER_set_default_search_path: function(_param1: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_set_default_search_path;
  OSSL_PROVIDER_get0_default_search_path: function(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl = Load_OSSL_PROVIDER_get0_default_search_path;
  { Load and unload a provider }
  OSSL_PROVIDER_load: function(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_load;
  OSSL_PROVIDER_load_ex: function(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_load_ex;
  OSSL_PROVIDER_try_load: function(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_try_load;
  OSSL_PROVIDER_try_load_ex: function(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl = Load_OSSL_PROVIDER_try_load_ex;
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
  {-
  * Provider configuration parameters are normally set in the configuration file,
  * but can also be set early in the main program before a provider is in use by
  * multiple threads.
  *
  * Only UTF8-string values are supported.
  }
  function OSSL_PROVIDER_add_conf_parameter(prov: POSSL_PROVIDER; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_add_conf_parameter';
  
  {* Retrieves any of the requested configuration parameters for the given
  * provider that were set in the configuration file or via the above
  * OSSL_PROVIDER_add_parameter() function.
  *
  * The |params| array elements MUST have type OSSL_PARAM_UTF8_PTR, values are
  * returned by reference, not as copies.
  }
  function OSSL_PROVIDER_get_conf_parameters(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_get_conf_parameters';
  
  {* Parse a provider configuration parameter as a boolean value,
  * or return a default value if unable to retrieve the parameter.
  * Values like "1", "yes", "true", ... are true (nonzero).
  * Values like "0", "no", "false", ... are false (zero).
  }
  function OSSL_PROVIDER_conf_get_bool(prov: POSSL_PROVIDER; name: PAnsiChar; defval: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PROVIDER_conf_get_bool';
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
  {$EXTERNALSYM OSSL_PROVIDER_add_conf_parameter}
  {$EXTERNALSYM OSSL_PROVIDER_get_conf_parameters}
  {$EXTERNALSYM OSSL_PROVIDER_conf_get_bool}
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
  function Load_OSSL_PROVIDER_add_conf_parameter(prov: POSSL_PROVIDER; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_get_conf_parameters(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PROVIDER_conf_get_bool(prov: POSSL_PROVIDER; name: PAnsiChar; defval: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
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
  {-
  * Provider configuration parameters are normally set in the configuration file,
  * but can also be set early in the main program before a provider is in use by
  * multiple threads.
  *
  * Only UTF8-string values are supported.
  }
  OSSL_PROVIDER_add_conf_parameter: function(prov: POSSL_PROVIDER; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_add_conf_parameter;
  
  {* Retrieves any of the requested configuration parameters for the given
  * provider that were set in the configuration file or via the above
  * OSSL_PROVIDER_add_parameter() function.
  *
  * The |params| array elements MUST have type OSSL_PARAM_UTF8_PTR, values are
  * returned by reference, not as copies.
  }
  OSSL_PROVIDER_get_conf_parameters: function(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_get_conf_parameters;
  
  {* Parse a provider configuration parameter as a boolean value,
  * or return a default value if unable to retrieve the parameter.
  * Values like "1", "yes", "true", ... are true (nonzero).
  * Values like "0", "no", "false", ... are false (zero).
  }
  OSSL_PROVIDER_conf_get_bool: function(prov: POSSL_PROVIDER; name: PAnsiChar; defval: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PROVIDER_conf_get_bool;
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
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_set_default_search_path');
  Result := OSSL_PROVIDER_set_default_search_path(_param1, path);
end;

function Load_OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl;
begin
  OSSL_PROVIDER_get0_default_search_path := LoadLibCryptoFunction('OSSL_PROVIDER_get0_default_search_path');
  if not assigned(OSSL_PROVIDER_get0_default_search_path) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_default_search_path');
  Result := OSSL_PROVIDER_get0_default_search_path(libctx);
end;

function Load_OSSL_PROVIDER_load(_param1: POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_load := LoadLibCryptoFunction('OSSL_PROVIDER_load');
  if not assigned(OSSL_PROVIDER_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_load');
  Result := OSSL_PROVIDER_load(_param1, name);
end;

function Load_OSSL_PROVIDER_load_ex(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_load_ex := LoadLibCryptoFunction('OSSL_PROVIDER_load_ex');
  if not assigned(OSSL_PROVIDER_load_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_load_ex');
  Result := OSSL_PROVIDER_load_ex(_param1, name, params);
end;

function Load_OSSL_PROVIDER_try_load(_param1: POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_try_load := LoadLibCryptoFunction('OSSL_PROVIDER_try_load');
  if not assigned(OSSL_PROVIDER_try_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_try_load');
  Result := OSSL_PROVIDER_try_load(_param1, name, retain_fallbacks);
end;

function Load_OSSL_PROVIDER_try_load_ex(_param1: POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM; retain_fallbacks: TOpenSSL_C_INT): POSSL_PROVIDER; cdecl;
begin
  OSSL_PROVIDER_try_load_ex := LoadLibCryptoFunction('OSSL_PROVIDER_try_load_ex');
  if not assigned(OSSL_PROVIDER_try_load_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_try_load_ex');
  Result := OSSL_PROVIDER_try_load_ex(_param1, name, params, retain_fallbacks);
end;

function Load_OSSL_PROVIDER_unload(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_unload := LoadLibCryptoFunction('OSSL_PROVIDER_unload');
  if not assigned(OSSL_PROVIDER_unload) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unload');
  Result := OSSL_PROVIDER_unload(prov);
end;

function Load_OSSL_PROVIDER_available(_param1: POSSL_LIB_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_available := LoadLibCryptoFunction('OSSL_PROVIDER_available');
  if not assigned(OSSL_PROVIDER_available) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_available');
  Result := OSSL_PROVIDER_available(_param1, name);
end;

function Load_OSSL_PROVIDER_do_all(ctx: POSSL_LIB_CTX; cb: TFuncType000; cbdata: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_do_all := LoadLibCryptoFunction('OSSL_PROVIDER_do_all');
  if not assigned(OSSL_PROVIDER_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_do_all');
  Result := OSSL_PROVIDER_do_all(ctx, cb, cbdata);
end;

function Load_OSSL_PROVIDER_gettable_params(prov: POSSL_PROVIDER): POSSL_PARAM; cdecl;
begin
  OSSL_PROVIDER_gettable_params := LoadLibCryptoFunction('OSSL_PROVIDER_gettable_params');
  if not assigned(OSSL_PROVIDER_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_gettable_params');
  Result := OSSL_PROVIDER_gettable_params(prov);
end;

function Load_OSSL_PROVIDER_get_params(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_get_params := LoadLibCryptoFunction('OSSL_PROVIDER_get_params');
  if not assigned(OSSL_PROVIDER_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_params');
  Result := OSSL_PROVIDER_get_params(prov, params);
end;

function Load_OSSL_PROVIDER_self_test(prov: POSSL_PROVIDER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_self_test := LoadLibCryptoFunction('OSSL_PROVIDER_self_test');
  if not assigned(OSSL_PROVIDER_self_test) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_self_test');
  Result := OSSL_PROVIDER_self_test(prov);
end;

function Load_OSSL_PROVIDER_get_capabilities(prov: POSSL_PROVIDER; capability: PAnsiChar; cb: POSSL_CALLBACK; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_get_capabilities := LoadLibCryptoFunction('OSSL_PROVIDER_get_capabilities');
  if not assigned(OSSL_PROVIDER_get_capabilities) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_capabilities');
  Result := OSSL_PROVIDER_get_capabilities(prov, capability, cb, arg);
end;

function Load_OSSL_PROVIDER_add_conf_parameter(prov: POSSL_PROVIDER; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_add_conf_parameter := LoadLibCryptoFunction('OSSL_PROVIDER_add_conf_parameter');
  if not assigned(OSSL_PROVIDER_add_conf_parameter) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_add_conf_parameter');
  Result := OSSL_PROVIDER_add_conf_parameter(prov, name, value);
end;

function Load_OSSL_PROVIDER_get_conf_parameters(prov: POSSL_PROVIDER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_get_conf_parameters := LoadLibCryptoFunction('OSSL_PROVIDER_get_conf_parameters');
  if not assigned(OSSL_PROVIDER_get_conf_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_conf_parameters');
  Result := OSSL_PROVIDER_get_conf_parameters(prov, params);
end;

function Load_OSSL_PROVIDER_conf_get_bool(prov: POSSL_PROVIDER; name: PAnsiChar; defval: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_conf_get_bool := LoadLibCryptoFunction('OSSL_PROVIDER_conf_get_bool');
  if not assigned(OSSL_PROVIDER_conf_get_bool) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_conf_get_bool');
  Result := OSSL_PROVIDER_conf_get_bool(prov, name, defval);
end;

function Load_OSSL_PROVIDER_query_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; no_cache: POpenSSL_C_INT): POSSL_ALGORITHM; cdecl;
begin
  OSSL_PROVIDER_query_operation := LoadLibCryptoFunction('OSSL_PROVIDER_query_operation');
  if not assigned(OSSL_PROVIDER_query_operation) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_query_operation');
  Result := OSSL_PROVIDER_query_operation(prov, operation_id, no_cache);
end;

procedure Load_OSSL_PROVIDER_unquery_operation(prov: POSSL_PROVIDER; operation_id: TOpenSSL_C_INT; algs: POSSL_ALGORITHM); cdecl;
begin
  OSSL_PROVIDER_unquery_operation := LoadLibCryptoFunction('OSSL_PROVIDER_unquery_operation');
  if not assigned(OSSL_PROVIDER_unquery_operation) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unquery_operation');
  OSSL_PROVIDER_unquery_operation(prov, operation_id, algs);
end;

function Load_OSSL_PROVIDER_get0_provider_ctx(prov: POSSL_PROVIDER): pointer; cdecl;
begin
  OSSL_PROVIDER_get0_provider_ctx := LoadLibCryptoFunction('OSSL_PROVIDER_get0_provider_ctx');
  if not assigned(OSSL_PROVIDER_get0_provider_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_provider_ctx');
  Result := OSSL_PROVIDER_get0_provider_ctx(prov);
end;

function Load_OSSL_PROVIDER_get0_dispatch(prov: POSSL_PROVIDER): POSSL_DISPATCH; cdecl;
begin
  OSSL_PROVIDER_get0_dispatch := LoadLibCryptoFunction('OSSL_PROVIDER_get0_dispatch');
  if not assigned(OSSL_PROVIDER_get0_dispatch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_dispatch');
  Result := OSSL_PROVIDER_get0_dispatch(prov);
end;

function Load_OSSL_PROVIDER_add_builtin(_param1: POSSL_LIB_CTX; name: PAnsiChar; init_fn: POSSL_provider_init_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PROVIDER_add_builtin := LoadLibCryptoFunction('OSSL_PROVIDER_add_builtin');
  if not assigned(OSSL_PROVIDER_add_builtin) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_add_builtin');
  Result := OSSL_PROVIDER_add_builtin(_param1, name, init_fn);
end;

function Load_OSSL_PROVIDER_get0_name(prov: POSSL_PROVIDER): PAnsiChar; cdecl;
begin
  OSSL_PROVIDER_get0_name := LoadLibCryptoFunction('OSSL_PROVIDER_get0_name');
  if not assigned(OSSL_PROVIDER_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_name');
  Result := OSSL_PROVIDER_get0_name(prov);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_PROVIDER_set_default_search_path := Load_OSSL_PROVIDER_set_default_search_path;
  OSSL_PROVIDER_get0_default_search_path := Load_OSSL_PROVIDER_get0_default_search_path;
  OSSL_PROVIDER_load := Load_OSSL_PROVIDER_load;
  OSSL_PROVIDER_load_ex := Load_OSSL_PROVIDER_load_ex;
  OSSL_PROVIDER_try_load := Load_OSSL_PROVIDER_try_load;
  OSSL_PROVIDER_try_load_ex := Load_OSSL_PROVIDER_try_load_ex;
  OSSL_PROVIDER_unload := Load_OSSL_PROVIDER_unload;
  OSSL_PROVIDER_available := Load_OSSL_PROVIDER_available;
  OSSL_PROVIDER_do_all := Load_OSSL_PROVIDER_do_all;
  OSSL_PROVIDER_gettable_params := Load_OSSL_PROVIDER_gettable_params;
  OSSL_PROVIDER_get_params := Load_OSSL_PROVIDER_get_params;
  OSSL_PROVIDER_self_test := Load_OSSL_PROVIDER_self_test;
  OSSL_PROVIDER_get_capabilities := Load_OSSL_PROVIDER_get_capabilities;
  OSSL_PROVIDER_add_conf_parameter := Load_OSSL_PROVIDER_add_conf_parameter;
  OSSL_PROVIDER_get_conf_parameters := Load_OSSL_PROVIDER_get_conf_parameters;
  OSSL_PROVIDER_conf_get_bool := Load_OSSL_PROVIDER_conf_get_bool;
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



