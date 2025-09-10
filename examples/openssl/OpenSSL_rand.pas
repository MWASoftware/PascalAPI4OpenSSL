(* This unit was generated from the source file rand.h2pas 
It should not be modified directly. All changes should be made to rand.h2pas
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


unit OpenSSL_rand;


interface

// Headers for OpenSSL 1.1.1
// rand.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ;

type
  rand_meth_st_seed = function (const buf: Pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  rand_meth_st_bytes = function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  rand_meth_st_cleanup = procedure; cdecl;
  rand_meth_st_add = function (const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
  rand_meth_st_pseudorand = function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  rand_meth_st_status = function: TOpenSSL_C_INT; cdecl;

  rand_meth_st = record
    seed: rand_meth_st_seed;
    bytes: rand_meth_st_bytes;
    cleanup: rand_meth_st_cleanup;
    add: rand_meth_st_add;
    pseudorand: rand_meth_st_pseudorand;
    status: rand_meth_st_status;
  end;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM RAND_set_rand_method}
{$EXTERNALSYM RAND_get_rand_method}
{$EXTERNALSYM RAND_set_rand_engine}
{$EXTERNALSYM RAND_OpenSSL}
{$EXTERNALSYM RAND_bytes}
{$EXTERNALSYM RAND_priv_bytes}
{$EXTERNALSYM RAND_seed}
{$EXTERNALSYM RAND_keep_random_devices_open}
{$EXTERNALSYM RAND_add}
{$EXTERNALSYM RAND_load_file}
{$EXTERNALSYM RAND_write_file}
{$EXTERNALSYM RAND_status}
{$EXTERNALSYM RAND_query_egd_bytes}
{$EXTERNALSYM RAND_egd}
{$EXTERNALSYM RAND_egd_bytes}
{$EXTERNALSYM RAND_poll}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function RAND_set_rand_method(const meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_get_rand_method: PRAND_METHOD; cdecl; external CLibCrypto;
function RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_OpenSSL: PRAND_METHOD; cdecl; external CLibCrypto;
function RAND_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_priv_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RAND_seed(const buf: Pointer; num: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure RAND_add(const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl; external CLibCrypto;
function RAND_load_file(const file_: PAnsiChar; max_bytes: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_write_file(const file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_status: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_query_egd_bytes(const path: PAnsiChar; buf: PByte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_egd(const path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_egd_bytes(const path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RAND_poll: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  RAND_set_rand_method: function (const meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl = nil;
  RAND_get_rand_method: function : PRAND_METHOD; cdecl = nil;
  RAND_set_rand_engine: function (engine: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  RAND_OpenSSL: function : PRAND_METHOD; cdecl = nil;
  RAND_bytes: function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RAND_priv_bytes: function (buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RAND_seed: procedure (const buf: Pointer; num: TOpenSSL_C_INT); cdecl = nil;
  RAND_keep_random_devices_open: procedure (keep: TOpenSSL_C_INT); cdecl = nil;
  RAND_add: procedure (const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl = nil;
  RAND_load_file: function (const file_: PAnsiChar; max_bytes: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  RAND_write_file: function (const file_: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  RAND_status: function : TOpenSSL_C_INT; cdecl = nil;
  RAND_query_egd_bytes: function (const path: PAnsiChar; buf: PByte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RAND_egd: function (const path: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  RAND_egd_bytes: function (const path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RAND_poll: function : TOpenSSL_C_INT; cdecl = nil;
{$ENDIF}

implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_RAND_set_rand_method(const meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_rand_method');
end;

function ERROR_RAND_get_rand_method: PRAND_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_get_rand_method');
end;

function ERROR_RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_rand_engine');
end;

function ERROR_RAND_OpenSSL: PRAND_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_OpenSSL');
end;

function ERROR_RAND_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_bytes');
end;

function ERROR_RAND_priv_bytes(buf: PByte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_priv_bytes');
end;

procedure ERROR_RAND_seed(const buf: Pointer; num: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_seed');
end;

procedure ERROR_RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_keep_random_devices_open');
end;

procedure ERROR_RAND_add(const buf: Pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_add');
end;

function ERROR_RAND_load_file(const file_: PAnsiChar; max_bytes: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_load_file');
end;

function ERROR_RAND_write_file(const file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_write_file');
end;

function ERROR_RAND_status: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_status');
end;

function ERROR_RAND_query_egd_bytes(const path: PAnsiChar; buf: PByte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_query_egd_bytes');
end;

function ERROR_RAND_egd(const path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_egd');
end;

function ERROR_RAND_egd_bytes(const path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_egd_bytes');
end;

function ERROR_RAND_poll: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_poll');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  RAND_set_rand_method := LoadLibCryptoFunction('RAND_set_rand_method');
  FuncLoadError := not assigned(RAND_set_rand_method);
  if FuncLoadError then
  begin
    RAND_set_rand_method :=  @ERROR_RAND_set_rand_method;
  end;

  RAND_get_rand_method := LoadLibCryptoFunction('RAND_get_rand_method');
  FuncLoadError := not assigned(RAND_get_rand_method);
  if FuncLoadError then
  begin
    RAND_get_rand_method :=  @ERROR_RAND_get_rand_method;
  end;

  RAND_set_rand_engine := LoadLibCryptoFunction('RAND_set_rand_engine');
  FuncLoadError := not assigned(RAND_set_rand_engine);
  if FuncLoadError then
  begin
    RAND_set_rand_engine :=  @ERROR_RAND_set_rand_engine;
  end;

  RAND_OpenSSL := LoadLibCryptoFunction('RAND_OpenSSL');
  FuncLoadError := not assigned(RAND_OpenSSL);
  if FuncLoadError then
  begin
    RAND_OpenSSL :=  @ERROR_RAND_OpenSSL;
  end;

  RAND_bytes := LoadLibCryptoFunction('RAND_bytes');
  FuncLoadError := not assigned(RAND_bytes);
  if FuncLoadError then
  begin
    RAND_bytes :=  @ERROR_RAND_bytes;
  end;

  RAND_priv_bytes := LoadLibCryptoFunction('RAND_priv_bytes');
  FuncLoadError := not assigned(RAND_priv_bytes);
  if FuncLoadError then
  begin
    RAND_priv_bytes :=  @ERROR_RAND_priv_bytes;
  end;

  RAND_seed := LoadLibCryptoFunction('RAND_seed');
  FuncLoadError := not assigned(RAND_seed);
  if FuncLoadError then
  begin
    RAND_seed :=  @ERROR_RAND_seed;
  end;

  RAND_keep_random_devices_open := LoadLibCryptoFunction('RAND_keep_random_devices_open');
  FuncLoadError := not assigned(RAND_keep_random_devices_open);
  if FuncLoadError then
  begin
    RAND_keep_random_devices_open :=  @ERROR_RAND_keep_random_devices_open;
  end;

  RAND_add := LoadLibCryptoFunction('RAND_add');
  FuncLoadError := not assigned(RAND_add);
  if FuncLoadError then
  begin
    RAND_add :=  @ERROR_RAND_add;
  end;

  RAND_load_file := LoadLibCryptoFunction('RAND_load_file');
  FuncLoadError := not assigned(RAND_load_file);
  if FuncLoadError then
  begin
    RAND_load_file :=  @ERROR_RAND_load_file;
  end;

  RAND_write_file := LoadLibCryptoFunction('RAND_write_file');
  FuncLoadError := not assigned(RAND_write_file);
  if FuncLoadError then
  begin
    RAND_write_file :=  @ERROR_RAND_write_file;
  end;

  RAND_status := LoadLibCryptoFunction('RAND_status');
  FuncLoadError := not assigned(RAND_status);
  if FuncLoadError then
  begin
    RAND_status :=  @ERROR_RAND_status;
  end;

  RAND_query_egd_bytes := LoadLibCryptoFunction('RAND_query_egd_bytes');
  FuncLoadError := not assigned(RAND_query_egd_bytes);
  if FuncLoadError then
  begin
    RAND_query_egd_bytes :=  @ERROR_RAND_query_egd_bytes;
  end;

  RAND_egd := LoadLibCryptoFunction('RAND_egd');
  FuncLoadError := not assigned(RAND_egd);
  if FuncLoadError then
  begin
    RAND_egd :=  @ERROR_RAND_egd;
  end;

  RAND_egd_bytes := LoadLibCryptoFunction('RAND_egd_bytes');
  FuncLoadError := not assigned(RAND_egd_bytes);
  if FuncLoadError then
  begin
    RAND_egd_bytes :=  @ERROR_RAND_egd_bytes;
  end;

  RAND_poll := LoadLibCryptoFunction('RAND_poll');
  FuncLoadError := not assigned(RAND_poll);
  if FuncLoadError then
  begin
    RAND_poll :=  @ERROR_RAND_poll;
  end;

end;

procedure UnLoad;
begin
  RAND_set_rand_method := nil;
  RAND_get_rand_method := nil;
  RAND_set_rand_engine := nil;
  RAND_OpenSSL := nil;
  RAND_bytes := nil;
  RAND_priv_bytes := nil;
  RAND_seed := nil;
  RAND_keep_random_devices_open := nil;
  RAND_add := nil;
  RAND_load_file := nil;
  RAND_write_file := nil;
  RAND_status := nil;
  RAND_query_egd_bytes := nil;
  RAND_egd := nil;
  RAND_egd_bytes := nil;
  RAND_poll := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
