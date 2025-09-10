(* This unit was generated from the source file provider.h2pas 
It should not be modified directly. All changes should be made to provider.h2pas
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


unit OpenSSL_provider;


interface

{
  Automatically converted by H2Pas 1.0.0 from provider.h
  The following command line parameters were used:
    provider.h
}

uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_core;

{$IFDEF FPC}
{$PACKRECORDS C}
{$ENDIF}

type
    POSSL_ALGORITHM  = ^OSSL_ALGORITHM;
    POSSL_CALLBACK  = ^OSSL_CALLBACK;
    POSSL_DISPATCH  = ^OSSL_DISPATCH;
    POSSL_PARAM  = ^OSSL_PARAM;
    POSSL_PROVIDER  = pointer;
    POSSL_provider_init_fn  = ^OSSL_provider_init_fn;

    TDo_AllCallback = function (provider:POSSL_PROVIDER; cbdata:pointer):TOpenSSL_C_LONG; cdecl;

  {
   * Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
   *
   * Licensed under the Apache License 2.0 (the "License").  You may not use
   * this file except in compliance with the License.  You can obtain a copy
   * in the file LICENSE in the source distribution or at
   * https://www.openssl.org/source/license.html
    }
  { Set and Get a library context search path  }
    
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM OSSL_PROVIDER_set_default_search_path}
{$EXTERNALSYM OSSL_PROVIDER_load}
{$EXTERNALSYM OSSL_PROVIDER_try_load}
{$EXTERNALSYM OSSL_PROVIDER_unload}
{$EXTERNALSYM OSSL_PROVIDER_available}
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
{$IFDEF OPENSSL_3_2_ORLATER}
{$EXTERNALSYM OSSL_PROVIDER_get0_default_search_path}
{$EXTERNALSYM OSSL_PROVIDER_try_load_ex}
{$EXTERNALSYM OSSL_PROVIDER_load_ex}
{$ENDIF}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function OSSL_PROVIDER_set_default_search_path(ctx: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OSSL_PROVIDER_load(_para1:POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl; external CLibCrypto;
function OSSL_PROVIDER_try_load(_para1:POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl; external CLibCrypto;
function OSSL_PROVIDER_unload(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_available(_para1:POSSL_LIB_CTX; name:PAnsiChar): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_do_all(ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_gettable_params(prov:POSSL_PROVIDER): POSSL_PARAM; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get_params(prov:POSSL_PROVIDER; params:POSSL_PARAM): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_self_test(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get_capabilities(prov:POSSL_PROVIDER; capability:PAnsiChar; cb:POSSL_CALLBACK; arg:pointer): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_query_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; no_cache:POpenSSL_C_LONG): POSSL_ALGORITHM; cdecl; external CLibCrypto;
procedure OSSL_PROVIDER_unquery_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; algs:POSSL_ALGORITHM); cdecl; external CLibCrypto;
function OSSL_PROVIDER_get0_provider_ctx(prov:POSSL_PROVIDER): pointer; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get0_dispatch(prov:POSSL_PROVIDER): POSSL_DISPATCH; cdecl; external CLibCrypto;
function OSSL_PROVIDER_add_builtin(_para1:POSSL_LIB_CTX; name:PAnsiChar; init_fn:POSSL_provider_init_fn): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function OSSL_PROVIDER_get0_name(prov:POSSL_PROVIDER): PAnsiChar; cdecl; external CLibCrypto;
{$IFDEF OPENSSL_3_2_ORLATER}
{$IFDEF OPENSSL_3_2_ORLATER}
    
function OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl; {introduced 3.2.0 } external CLibCrypto;
function OSSL_PROVIDER_try_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params:POSSL_PARAM; retain_fallbacks:TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl; {introduced 3.2.0 } external CLibCrypto;
function OSSL_PROVIDER_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl; {introduced 3.2.0 } external CLibCrypto;
{$ENDIF}
{$ENDIF}



{$ELSE}
var
  OSSL_PROVIDER_set_default_search_path: function (ctx: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  OSSL_PROVIDER_load: function (_para1:POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl = nil;
  OSSL_PROVIDER_try_load: function (_para1:POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl = nil;
  OSSL_PROVIDER_unload: function (prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl = nil;
  OSSL_PROVIDER_available: function (_para1:POSSL_LIB_CTX; name:PAnsiChar): TOpenSSL_C_LONG; cdecl = nil;
  OSSL_PROVIDER_do_all: function (ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer): TOpenSSL_C_LONG; cdecl = nil;
  OSSL_PROVIDER_gettable_params: function (prov:POSSL_PROVIDER): POSSL_PARAM; cdecl = nil;
  OSSL_PROVIDER_get_params: function (prov:POSSL_PROVIDER; params:POSSL_PARAM): TOpenSSL_C_LONG; cdecl = nil;
  OSSL_PROVIDER_self_test: function (prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl = nil;
  OSSL_PROVIDER_get_capabilities: function (prov:POSSL_PROVIDER; capability:PAnsiChar; cb:POSSL_CALLBACK; arg:pointer): TOpenSSL_C_LONG; cdecl = nil;
  OSSL_PROVIDER_query_operation: function (prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; no_cache:POpenSSL_C_LONG): POSSL_ALGORITHM; cdecl = nil;
  OSSL_PROVIDER_unquery_operation: procedure (prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; algs:POSSL_ALGORITHM); cdecl = nil;
  OSSL_PROVIDER_get0_provider_ctx: function (prov:POSSL_PROVIDER): pointer; cdecl = nil;
  OSSL_PROVIDER_get0_dispatch: function (prov:POSSL_PROVIDER): POSSL_DISPATCH; cdecl = nil;
  OSSL_PROVIDER_add_builtin: function (_para1:POSSL_LIB_CTX; name:PAnsiChar; init_fn:POSSL_provider_init_fn): TOpenSSL_C_LONG; cdecl = nil;
  OSSL_PROVIDER_get0_name: function (prov:POSSL_PROVIDER): PAnsiChar; cdecl = nil;
{$IFDEF OPENSSL_3_2_ORLATER}
{$IFDEF OPENSSL_3_2_ORLATER}
    
  OSSL_PROVIDER_get0_default_search_path: function (libctx: POSSL_LIB_CTX): PAnsiChar; cdecl = nil; {introduced 3.2.0 }
  OSSL_PROVIDER_try_load_ex: function (_para1:POSSL_LIB_CTX; name: PAnsiChar; params:POSSL_PARAM; retain_fallbacks:TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl = nil; {introduced 3.2.0 }
  OSSL_PROVIDER_load_ex: function (_para1:POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl = nil; {introduced 3.2.0 }
{$ENDIF}
{$ENDIF}


{$ENDIF}
const
  OSSL_PROVIDER_set_default_search_path_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_load_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_try_load_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_unload_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_available_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_do_all_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_gettable_params_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get_params_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_self_test_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get_capabilities_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_query_operation_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_unquery_operation_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_provider_ctx_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_dispatch_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_add_builtin_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_name_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  OSSL_PROVIDER_get0_default_search_path_introduced = ((((((byte(3) shl 8) or byte(2)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.2.0}
  OSSL_PROVIDER_try_load_ex_introduced = ((((((byte(3) shl 8) or byte(2)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.2.0}
  OSSL_PROVIDER_load_ex_introduced = ((((((byte(3) shl 8) or byte(2)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.2.0}


implementation


uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$IFDEF OPENSSL_3_2_ORLATER}
{$ENDIF}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_OSSL_PROVIDER_set_default_search_path(ctx: POSSL_LIB_CTX; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_set_default_search_path');
end;

function ERROR_OSSL_PROVIDER_load(_para1:POSSL_LIB_CTX; name: PAnsiChar): POSSL_PROVIDER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_load');
end;

function ERROR_OSSL_PROVIDER_try_load(_para1:POSSL_LIB_CTX; name: PAnsiChar; retain_fallbacks: TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_try_load');
end;

function ERROR_OSSL_PROVIDER_unload(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unload');
end;

function ERROR_OSSL_PROVIDER_available(_para1:POSSL_LIB_CTX; name:PAnsiChar): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_available');
end;

function ERROR_OSSL_PROVIDER_do_all(ctx:POSSL_LIB_CTX; cb:TDo_AllCallback; cbdata:pointer): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_do_all');
end;

function ERROR_OSSL_PROVIDER_gettable_params(prov:POSSL_PROVIDER): POSSL_PARAM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_gettable_params');
end;

function ERROR_OSSL_PROVIDER_get_params(prov:POSSL_PROVIDER; params:POSSL_PARAM): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_params');
end;

function ERROR_OSSL_PROVIDER_self_test(prov:POSSL_PROVIDER): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_self_test');
end;

function ERROR_OSSL_PROVIDER_get_capabilities(prov:POSSL_PROVIDER; capability:PAnsiChar; cb:POSSL_CALLBACK; arg:pointer): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get_capabilities');
end;

function ERROR_OSSL_PROVIDER_query_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; no_cache:POpenSSL_C_LONG): POSSL_ALGORITHM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_query_operation');
end;

procedure ERROR_OSSL_PROVIDER_unquery_operation(prov:POSSL_PROVIDER; operation_id:TOpenSSL_C_LONG; algs:POSSL_ALGORITHM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_unquery_operation');
end;

function ERROR_OSSL_PROVIDER_get0_provider_ctx(prov:POSSL_PROVIDER): pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_provider_ctx');
end;

function ERROR_OSSL_PROVIDER_get0_dispatch(prov:POSSL_PROVIDER): POSSL_DISPATCH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_dispatch');
end;

function ERROR_OSSL_PROVIDER_add_builtin(_para1:POSSL_LIB_CTX; name:PAnsiChar; init_fn:POSSL_provider_init_fn): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_add_builtin');
end;

function ERROR_OSSL_PROVIDER_get0_name(prov:POSSL_PROVIDER): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_name');
end;

{$IFDEF OPENSSL_3_2_ORLATER}
function ERROR_OSSL_PROVIDER_get0_default_search_path(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl; {introduced 3.2.0 }
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_get0_default_search_path');
end;

function ERROR_OSSL_PROVIDER_try_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params:POSSL_PARAM; retain_fallbacks:TOpenSSL_C_LONG): POSSL_PROVIDER; cdecl; {introduced 3.2.0 }
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_try_load_ex');
end;

function ERROR_OSSL_PROVIDER_load_ex(_para1:POSSL_LIB_CTX; name: PAnsiChar; params: POSSL_PARAM): POSSL_PROVIDER; cdecl; {introduced 3.2.0 }
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PROVIDER_load_ex');
end;

{$ENDIF}
{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  OSSL_PROVIDER_set_default_search_path := LoadLibCryptoFunction('OSSL_PROVIDER_set_default_search_path');
  FuncLoadError := not assigned(OSSL_PROVIDER_set_default_search_path);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_set_default_search_path :=  @ERROR_OSSL_PROVIDER_set_default_search_path;
  end;

  OSSL_PROVIDER_load := LoadLibCryptoFunction('OSSL_PROVIDER_load');
  FuncLoadError := not assigned(OSSL_PROVIDER_load);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_load :=  @ERROR_OSSL_PROVIDER_load;
  end;

  OSSL_PROVIDER_try_load := LoadLibCryptoFunction('OSSL_PROVIDER_try_load');
  FuncLoadError := not assigned(OSSL_PROVIDER_try_load);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_try_load :=  @ERROR_OSSL_PROVIDER_try_load;
  end;

  OSSL_PROVIDER_unload := LoadLibCryptoFunction('OSSL_PROVIDER_unload');
  FuncLoadError := not assigned(OSSL_PROVIDER_unload);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_unload :=  @ERROR_OSSL_PROVIDER_unload;
  end;

  OSSL_PROVIDER_available := LoadLibCryptoFunction('OSSL_PROVIDER_available');
  FuncLoadError := not assigned(OSSL_PROVIDER_available);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_available :=  @ERROR_OSSL_PROVIDER_available;
  end;

  OSSL_PROVIDER_do_all := LoadLibCryptoFunction('OSSL_PROVIDER_do_all');
  FuncLoadError := not assigned(OSSL_PROVIDER_do_all);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_do_all :=  @ERROR_OSSL_PROVIDER_do_all;
  end;

  OSSL_PROVIDER_gettable_params := LoadLibCryptoFunction('OSSL_PROVIDER_gettable_params');
  FuncLoadError := not assigned(OSSL_PROVIDER_gettable_params);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_gettable_params :=  @ERROR_OSSL_PROVIDER_gettable_params;
  end;

  OSSL_PROVIDER_get_params := LoadLibCryptoFunction('OSSL_PROVIDER_get_params');
  FuncLoadError := not assigned(OSSL_PROVIDER_get_params);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_get_params :=  @ERROR_OSSL_PROVIDER_get_params;
  end;

  OSSL_PROVIDER_self_test := LoadLibCryptoFunction('OSSL_PROVIDER_self_test');
  FuncLoadError := not assigned(OSSL_PROVIDER_self_test);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_self_test :=  @ERROR_OSSL_PROVIDER_self_test;
  end;

  OSSL_PROVIDER_get_capabilities := LoadLibCryptoFunction('OSSL_PROVIDER_get_capabilities');
  FuncLoadError := not assigned(OSSL_PROVIDER_get_capabilities);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_get_capabilities :=  @ERROR_OSSL_PROVIDER_get_capabilities;
  end;

  OSSL_PROVIDER_query_operation := LoadLibCryptoFunction('OSSL_PROVIDER_query_operation');
  FuncLoadError := not assigned(OSSL_PROVIDER_query_operation);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_query_operation :=  @ERROR_OSSL_PROVIDER_query_operation;
  end;

  OSSL_PROVIDER_unquery_operation := LoadLibCryptoFunction('OSSL_PROVIDER_unquery_operation');
  FuncLoadError := not assigned(OSSL_PROVIDER_unquery_operation);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_unquery_operation :=  @ERROR_OSSL_PROVIDER_unquery_operation;
  end;

  OSSL_PROVIDER_get0_provider_ctx := LoadLibCryptoFunction('OSSL_PROVIDER_get0_provider_ctx');
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_provider_ctx);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_get0_provider_ctx :=  @ERROR_OSSL_PROVIDER_get0_provider_ctx;
  end;

  OSSL_PROVIDER_get0_dispatch := LoadLibCryptoFunction('OSSL_PROVIDER_get0_dispatch');
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_dispatch);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_get0_dispatch :=  @ERROR_OSSL_PROVIDER_get0_dispatch;
  end;

  OSSL_PROVIDER_add_builtin := LoadLibCryptoFunction('OSSL_PROVIDER_add_builtin');
  FuncLoadError := not assigned(OSSL_PROVIDER_add_builtin);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_add_builtin :=  @ERROR_OSSL_PROVIDER_add_builtin;
  end;

  OSSL_PROVIDER_get0_name := LoadLibCryptoFunction('OSSL_PROVIDER_get0_name');
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_name);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_get0_name :=  @ERROR_OSSL_PROVIDER_get0_name;
  end;

{$IFDEF OPENSSL_3_2_ORLATER}
  OSSL_PROVIDER_get0_default_search_path := LoadLibCryptoFunction('OSSL_PROVIDER_get0_default_search_path');
  FuncLoadError := not assigned(OSSL_PROVIDER_get0_default_search_path);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_get0_default_search_path :=  @ERROR_OSSL_PROVIDER_get0_default_search_path;
    if LibVersion < OSSL_PROVIDER_get0_default_search_path_introduced then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_get0_default_search_path');
  end;

  OSSL_PROVIDER_try_load_ex := LoadLibCryptoFunction('OSSL_PROVIDER_try_load_ex');
  FuncLoadError := not assigned(OSSL_PROVIDER_try_load_ex);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_try_load_ex :=  @ERROR_OSSL_PROVIDER_try_load_ex;
    if LibVersion < OSSL_PROVIDER_try_load_ex_introduced then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_try_load_ex');
  end;

  OSSL_PROVIDER_load_ex := LoadLibCryptoFunction('OSSL_PROVIDER_load_ex');
  FuncLoadError := not assigned(OSSL_PROVIDER_load_ex);
  if FuncLoadError then
  begin
    OSSL_PROVIDER_load_ex :=  @ERROR_OSSL_PROVIDER_load_ex;
    if LibVersion < OSSL_PROVIDER_load_ex_introduced then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OSSL_PROVIDER_load_ex');
  end;

{$ENDIF}
end;

procedure UnLoad;
begin
  OSSL_PROVIDER_set_default_search_path := nil;
  OSSL_PROVIDER_load := nil;
  OSSL_PROVIDER_try_load := nil;
  OSSL_PROVIDER_unload := nil;
  OSSL_PROVIDER_available := nil;
  OSSL_PROVIDER_do_all := nil;
  OSSL_PROVIDER_gettable_params := nil;
  OSSL_PROVIDER_get_params := nil;
  OSSL_PROVIDER_self_test := nil;
  OSSL_PROVIDER_get_capabilities := nil;
  OSSL_PROVIDER_query_operation := nil;
  OSSL_PROVIDER_unquery_operation := nil;
  OSSL_PROVIDER_get0_provider_ctx := nil;
  OSSL_PROVIDER_get0_dispatch := nil;
  OSSL_PROVIDER_add_builtin := nil;
  OSSL_PROVIDER_get0_name := nil;
{$IFDEF OPENSSL_3_2_ORLATER}
  OSSL_PROVIDER_get0_default_search_path := nil;
  OSSL_PROVIDER_try_load_ex := nil;
  OSSL_PROVIDER_load_ex := nil;
{$ENDIF}
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
