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

unit openssl_rand;

{
  Generated from OpenSSL 3.0.20 Header File rand.h - Tue 19 May 14:25:31 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_rand.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_e_os2,openssl_randerr,openssl_evp;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_RAND_H}
  {$define OPENSSL_RAND_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_RAND_H}
  {$endif}

const
  
  {* Default security strength (in the sense of [NIST SP 800-90Ar1])
  *
  * NIST SP 800-90Ar1 supports the strength of the DRBG being smaller than that
  * of the cipher by collecting less entropy. The current DRBG implementation
  * does not take RAND_DRBG_STRENGTH into account and sets the strength of the
  * DRBG to that of the cipher.
  }
  RAND_DRBG_STRENGTH = 256;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  PFuncType003 = ^TFuncType003;
  PPFuncType003 = ^PFuncType003;
  PFuncType004 = ^TFuncType004;
  PPFuncType004 = ^PFuncType004;
  PFuncType005 = ^TFuncType005;
  PPFuncType005 = ^PFuncType005;
  Prand_meth_st = ^Trand_meth_st;
  PPrand_meth_st = ^Prand_meth_st;
  {end of auto-generated forward references}

  TFuncType000 = function(buf: pointer; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TFuncType001 = function(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TFuncType002 = procedure; cdecl;
  TFuncType003 = function(buf: pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
  TFuncType004 = function(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TFuncType005 = function: TOpenSSL_C_INT; cdecl;
  Trand_meth_st = record 
    seed: TFuncType000;
    bytes: TFuncType001;
    cleanup: TFuncType002;
    add: TFuncType003;
    pseudorand: TFuncType004;
    status: TFuncType005;
  end;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_set_rand_method(meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_set_rand_method'; deprecated 'Since OpenSSL 3.0';
  function RAND_get_rand_method: PRAND_METHOD; cdecl; external CLibCrypto name 'RAND_get_rand_method'; deprecated 'Since OpenSSL 3.0';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM RAND_set_rand_method}
  {$EXTERNALSYM RAND_get_rand_method}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_set_rand_method(meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_RAND_get_rand_method: PRAND_METHOD; cdecl;

var
  RAND_set_rand_method: function(meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl = Load_RAND_set_rand_method;
  RAND_get_rand_method: function: PRAND_METHOD; cdecl = Load_RAND_get_rand_method;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_ENGINE}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_set_rand_engine'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM RAND_set_rand_engine}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl;

var
  RAND_set_rand_engine: function(engine: PENGINE): TOpenSSL_C_INT; cdecl = Load_RAND_set_rand_engine;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_OpenSSL: PRAND_METHOD; cdecl; external CLibCrypto name 'RAND_OpenSSL'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RAND_OpenSSL}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_OpenSSL: PRAND_METHOD; cdecl;

var
  RAND_OpenSSL: function: PRAND_METHOD; cdecl = Load_RAND_OpenSSL;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  { OPENSSL_NO_DEPRECATED_3_0 }
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{# define  RAND_cleanup() while (0) continue}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_bytes';
  function RAND_priv_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_priv_bytes';
  
  {* Equivalent of RAND_priv_bytes() but additionally taking an OSSL_LIB_CTX and
  * a strength.
  }
  function RAND_priv_bytes_ex(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_priv_bytes_ex';
  
  {* Equivalent of RAND_bytes() but additionally taking an OSSL_LIB_CTX and
  * a strength.
  }
  function RAND_bytes_ex(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_bytes_ex';
  {$else}
  {$EXTERNALSYM RAND_bytes}
  {$EXTERNALSYM RAND_priv_bytes}
  {$EXTERNALSYM RAND_priv_bytes_ex}
  {$EXTERNALSYM RAND_bytes_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RAND_priv_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RAND_priv_bytes_ex(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_RAND_bytes_ex(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

var
  RAND_bytes: function(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_bytes;
  RAND_priv_bytes: function(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_priv_bytes;
  
  {* Equivalent of RAND_priv_bytes() but additionally taking an OSSL_LIB_CTX and
  * a strength.
  }
  RAND_priv_bytes_ex: function(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_RAND_priv_bytes_ex;
  
  {* Equivalent of RAND_bytes() but additionally taking an OSSL_LIB_CTX and
  * a strength.
  }
  RAND_bytes_ex: function(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_RAND_bytes_ex;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_pseudo_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_pseudo_bytes'; deprecated 'Since OpenSSL 1.1.0';
    {$else}
  {$EXTERNALSYM RAND_pseudo_bytes}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_pseudo_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  RAND_pseudo_bytes: function(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_pseudo_bytes;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_get0_primary(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl; external CLibCrypto name 'RAND_get0_primary';
  function RAND_get0_public(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl; external CLibCrypto name 'RAND_get0_public';
  function RAND_get0_private(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl; external CLibCrypto name 'RAND_get0_private';
  function RAND_set_DRBG_type(ctx: POSSL_LIB_CTX; drbg: PAnsiChar; propq: PAnsiChar; cipher: PAnsiChar; digest: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_set_DRBG_type';
  function RAND_set_seed_source_type(ctx: POSSL_LIB_CTX; seed: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_set_seed_source_type';
  procedure RAND_seed(buf: pointer; num: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RAND_seed';
  procedure RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RAND_keep_random_devices_open';
  {$else}
  {$EXTERNALSYM RAND_get0_primary}
  {$EXTERNALSYM RAND_get0_public}
  {$EXTERNALSYM RAND_get0_private}
  {$EXTERNALSYM RAND_set_DRBG_type}
  {$EXTERNALSYM RAND_set_seed_source_type}
  {$EXTERNALSYM RAND_seed}
  {$EXTERNALSYM RAND_keep_random_devices_open}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_get0_primary(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
  function Load_RAND_get0_public(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
  function Load_RAND_get0_private(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
  function Load_RAND_set_DRBG_type(ctx: POSSL_LIB_CTX; drbg: PAnsiChar; propq: PAnsiChar; cipher: PAnsiChar; digest: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_RAND_set_seed_source_type(ctx: POSSL_LIB_CTX; seed: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  procedure Load_RAND_seed(buf: pointer; num: TOpenSSL_C_INT); cdecl;
  procedure Load_RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl;

var
  RAND_get0_primary: function(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl = Load_RAND_get0_primary;
  RAND_get0_public: function(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl = Load_RAND_get0_public;
  RAND_get0_private: function(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl = Load_RAND_get0_private;
  RAND_set_DRBG_type: function(ctx: POSSL_LIB_CTX; drbg: PAnsiChar; propq: PAnsiChar; cipher: PAnsiChar; digest: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RAND_set_DRBG_type;
  RAND_set_seed_source_type: function(ctx: POSSL_LIB_CTX; seed: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RAND_set_seed_source_type;
  RAND_seed: procedure(buf: pointer; num: TOpenSSL_C_INT); cdecl = Load_RAND_seed;
  RAND_keep_random_devices_open: procedure(keep: TOpenSSL_C_INT); cdecl = Load_RAND_keep_random_devices_open;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$if  defined(__ANDROID__)  and defined(__NDK_FPABI__)}
    {__NDK_FPABI__ /* __attribute__((pcs("aapcs"))) on ARM */}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure RAND_add(buf: pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl; external CLibCrypto name 'RAND_add';
  function RAND_load_file(file_: PAnsiChar; max_bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_load_file';
  function RAND_write_file(file_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_write_file';
  function RAND_file_name(file_: PAnsiChar; num: TOpenSSL_C_SIZET): PAnsiChar; cdecl; external CLibCrypto name 'RAND_file_name';
  function RAND_status: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_status';
  {$else}
  {$EXTERNALSYM RAND_add}
  {$EXTERNALSYM RAND_load_file}
  {$EXTERNALSYM RAND_write_file}
  {$EXTERNALSYM RAND_file_name}
  {$EXTERNALSYM RAND_status}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_RAND_add(buf: pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl;
  function Load_RAND_load_file(file_: PAnsiChar; max_bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RAND_write_file(file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_RAND_file_name(file_: PAnsiChar; num: TOpenSSL_C_SIZET): PAnsiChar; cdecl;
  function Load_RAND_status: TOpenSSL_C_INT; cdecl;

var
  RAND_add: procedure(buf: pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl = Load_RAND_add;
  RAND_load_file: function(file_: PAnsiChar; max_bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_load_file;
  RAND_write_file: function(file_: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RAND_write_file;
  RAND_file_name: function(file_: PAnsiChar; num: TOpenSSL_C_SIZET): PAnsiChar; cdecl = Load_RAND_file_name;
  RAND_status: function: TOpenSSL_C_INT; cdecl = Load_RAND_status;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_EGD}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_query_egd_bytes(path: PAnsiChar; buf: Pbyte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_query_egd_bytes';
  function RAND_egd(path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_egd';
  function RAND_egd_bytes(path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_egd_bytes';
    {$else}
  {$EXTERNALSYM RAND_query_egd_bytes}
  {$EXTERNALSYM RAND_egd}
  {$EXTERNALSYM RAND_egd_bytes}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_query_egd_bytes(path: PAnsiChar; buf: Pbyte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RAND_egd(path: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_RAND_egd_bytes(path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  RAND_query_egd_bytes: function(path: PAnsiChar; buf: Pbyte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_query_egd_bytes;
  RAND_egd: function(path: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RAND_egd;
  RAND_egd_bytes: function(path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RAND_egd_bytes;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RAND_poll: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_poll';
  {$else}
  {$EXTERNALSYM RAND_poll}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RAND_poll: TOpenSSL_C_INT; cdecl;

var
  RAND_poll: function: TOpenSSL_C_INT; cdecl = Load_RAND_poll;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$if  defined(_WIN32)  and  (defined(BASETYPES)  or defined(_WINDEF_H))}
    { application has to include <windows.h> in order to use these }
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure RAND_screen; cdecl; external CLibCrypto name 'RAND_screen'; deprecated 'Since OpenSSL 1.1.0';
  function RAND_event(_param1: TOpenSSL_C_UINT; _param2: TWPARAM; _param3: TLPARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RAND_event'; deprecated 'Since OpenSSL 1.1.0';
      {$else}
  {$EXTERNALSYM RAND_screen}
  {$EXTERNALSYM RAND_event}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_RAND_screen; cdecl;
  function Load_RAND_event(_param1: TOpenSSL_C_UINT; _param2: TWPARAM; _param3: TLPARAM): TOpenSSL_C_INT; cdecl;

var
  RAND_screen: procedure; cdecl = Load_RAND_screen;
  RAND_event: function(_param1: TOpenSSL_C_UINT; _param2: TWPARAM; _param3: TLPARAM): TOpenSSL_C_INT; cdecl = Load_RAND_event;
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
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_RAND_set_rand_method(meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
begin
  RAND_set_rand_method := LoadLibCryptoFunction('RAND_set_rand_method');
  if not assigned(RAND_set_rand_method) then
    {$if declared(LEGACY_RAND_set_rand_method)}
    RAND_set_rand_method := @LEGACY_RAND_set_rand_method;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_rand_method');
    {$ifend}
  Result := RAND_set_rand_method(meth);
end;

function Load_RAND_get_rand_method: PRAND_METHOD; cdecl;
begin
  RAND_get_rand_method := LoadLibCryptoFunction('RAND_get_rand_method');
  if not assigned(RAND_get_rand_method) then
    {$if declared(LEGACY_RAND_get_rand_method)}
    RAND_get_rand_method := @LEGACY_RAND_get_rand_method;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_get_rand_method');
    {$ifend}
  Result := RAND_get_rand_method;
end;

    {$ifndef  OPENSSL_NO_ENGINE}
function Load_RAND_set_rand_engine(engine: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  RAND_set_rand_engine := LoadLibCryptoFunction('RAND_set_rand_engine');
  if not assigned(RAND_set_rand_engine) then
    {$if declared(LEGACY_RAND_set_rand_engine)}
    RAND_set_rand_engine := @LEGACY_RAND_set_rand_engine;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_rand_engine');
    {$ifend}
  Result := RAND_set_rand_engine(engine);
end;

    {$endif} { OPENSSL_NO_ENGINE}
function Load_RAND_OpenSSL: PRAND_METHOD; cdecl;
begin
  RAND_OpenSSL := LoadLibCryptoFunction('RAND_OpenSSL');
  if not assigned(RAND_OpenSSL) then
    {$if declared(LEGACY_RAND_OpenSSL)}
    RAND_OpenSSL := @LEGACY_RAND_OpenSSL;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_OpenSSL');
    {$ifend}
  Result := RAND_OpenSSL;
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_RAND_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_bytes := LoadLibCryptoFunction('RAND_bytes');
  if not assigned(RAND_bytes) then
    {$if declared(LEGACY_RAND_bytes)}
    RAND_bytes := @LEGACY_RAND_bytes;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_bytes');
    {$ifend}
  Result := RAND_bytes(buf, num);
end;

function Load_RAND_priv_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_priv_bytes := LoadLibCryptoFunction('RAND_priv_bytes');
  if not assigned(RAND_priv_bytes) then
    {$if declared(LEGACY_RAND_priv_bytes)}
    RAND_priv_bytes := @LEGACY_RAND_priv_bytes;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_priv_bytes');
    {$ifend}
  Result := RAND_priv_bytes(buf, num);
end;

function Load_RAND_priv_bytes_ex(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  RAND_priv_bytes_ex := LoadLibCryptoFunction('RAND_priv_bytes_ex');
  if not assigned(RAND_priv_bytes_ex) then
    {$if declared(LEGACY_RAND_priv_bytes_ex)}
    RAND_priv_bytes_ex := @LEGACY_RAND_priv_bytes_ex;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_priv_bytes_ex');
    {$ifend}
  Result := RAND_priv_bytes_ex(ctx, buf, num, strength);
end;

function Load_RAND_bytes_ex(ctx: POSSL_LIB_CTX; buf: Pbyte; num: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  RAND_bytes_ex := LoadLibCryptoFunction('RAND_bytes_ex');
  if not assigned(RAND_bytes_ex) then
    {$if declared(LEGACY_RAND_bytes_ex)}
    RAND_bytes_ex := @LEGACY_RAND_bytes_ex;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_bytes_ex');
    {$ifend}
  Result := RAND_bytes_ex(ctx, buf, num, strength);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
function Load_RAND_pseudo_bytes(buf: Pbyte; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_pseudo_bytes := LoadLibCryptoFunction('RAND_pseudo_bytes');
  if not assigned(RAND_pseudo_bytes) then
    {$if declared(LEGACY_RAND_pseudo_bytes)}
    RAND_pseudo_bytes := @LEGACY_RAND_pseudo_bytes;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_pseudo_bytes');
    {$ifend}
  Result := RAND_pseudo_bytes(buf, num);
end;

{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
function Load_RAND_get0_primary(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
begin
  RAND_get0_primary := LoadLibCryptoFunction('RAND_get0_primary');
  if not assigned(RAND_get0_primary) then
    {$if declared(LEGACY_RAND_get0_primary)}
    RAND_get0_primary := @LEGACY_RAND_get0_primary;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_get0_primary');
    {$ifend}
  Result := RAND_get0_primary(ctx);
end;

function Load_RAND_get0_public(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
begin
  RAND_get0_public := LoadLibCryptoFunction('RAND_get0_public');
  if not assigned(RAND_get0_public) then
    {$if declared(LEGACY_RAND_get0_public)}
    RAND_get0_public := @LEGACY_RAND_get0_public;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_get0_public');
    {$ifend}
  Result := RAND_get0_public(ctx);
end;

function Load_RAND_get0_private(ctx: POSSL_LIB_CTX): PEVP_RAND_CTX; cdecl;
begin
  RAND_get0_private := LoadLibCryptoFunction('RAND_get0_private');
  if not assigned(RAND_get0_private) then
    {$if declared(LEGACY_RAND_get0_private)}
    RAND_get0_private := @LEGACY_RAND_get0_private;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_get0_private');
    {$ifend}
  Result := RAND_get0_private(ctx);
end;

function Load_RAND_set_DRBG_type(ctx: POSSL_LIB_CTX; drbg: PAnsiChar; propq: PAnsiChar; cipher: PAnsiChar; digest: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RAND_set_DRBG_type := LoadLibCryptoFunction('RAND_set_DRBG_type');
  if not assigned(RAND_set_DRBG_type) then
    {$if declared(LEGACY_RAND_set_DRBG_type)}
    RAND_set_DRBG_type := @LEGACY_RAND_set_DRBG_type;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_DRBG_type');
    {$ifend}
  Result := RAND_set_DRBG_type(ctx, drbg, propq, cipher, digest);
end;

function Load_RAND_set_seed_source_type(ctx: POSSL_LIB_CTX; seed: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RAND_set_seed_source_type := LoadLibCryptoFunction('RAND_set_seed_source_type');
  if not assigned(RAND_set_seed_source_type) then
    {$if declared(LEGACY_RAND_set_seed_source_type)}
    RAND_set_seed_source_type := @LEGACY_RAND_set_seed_source_type;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_set_seed_source_type');
    {$ifend}
  Result := RAND_set_seed_source_type(ctx, seed, propq);
end;

procedure Load_RAND_seed(buf: pointer; num: TOpenSSL_C_INT); cdecl;
begin
  RAND_seed := LoadLibCryptoFunction('RAND_seed');
  if not assigned(RAND_seed) then
    {$if declared(LEGACY_RAND_seed)}
    RAND_seed := @LEGACY_RAND_seed;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_seed');
    {$ifend}
  RAND_seed(buf, num);
end;

procedure Load_RAND_keep_random_devices_open(keep: TOpenSSL_C_INT); cdecl;
begin
  RAND_keep_random_devices_open := LoadLibCryptoFunction('RAND_keep_random_devices_open');
  if not assigned(RAND_keep_random_devices_open) then
    {$if declared(LEGACY_RAND_keep_random_devices_open)}
    RAND_keep_random_devices_open := @LEGACY_RAND_keep_random_devices_open;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_keep_random_devices_open');
    {$ifend}
  RAND_keep_random_devices_open(keep);
end;

procedure Load_RAND_add(buf: pointer; num: TOpenSSL_C_INT; randomness: TOpenSSL_C_DOUBLE); cdecl;
begin
  RAND_add := LoadLibCryptoFunction('RAND_add');
  if not assigned(RAND_add) then
    {$if declared(LEGACY_RAND_add)}
    RAND_add := @LEGACY_RAND_add;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_add');
    {$ifend}
  RAND_add(buf, num, randomness);
end;

function Load_RAND_load_file(file_: PAnsiChar; max_bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_load_file := LoadLibCryptoFunction('RAND_load_file');
  if not assigned(RAND_load_file) then
    {$if declared(LEGACY_RAND_load_file)}
    RAND_load_file := @LEGACY_RAND_load_file;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_load_file');
    {$ifend}
  Result := RAND_load_file(file_, max_bytes);
end;

function Load_RAND_write_file(file_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RAND_write_file := LoadLibCryptoFunction('RAND_write_file');
  if not assigned(RAND_write_file) then
    {$if declared(LEGACY_RAND_write_file)}
    RAND_write_file := @LEGACY_RAND_write_file;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_write_file');
    {$ifend}
  Result := RAND_write_file(file_);
end;

function Load_RAND_file_name(file_: PAnsiChar; num: TOpenSSL_C_SIZET): PAnsiChar; cdecl;
begin
  RAND_file_name := LoadLibCryptoFunction('RAND_file_name');
  if not assigned(RAND_file_name) then
    {$if declared(LEGACY_RAND_file_name)}
    RAND_file_name := @LEGACY_RAND_file_name;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_file_name');
    {$ifend}
  Result := RAND_file_name(file_, num);
end;

function Load_RAND_status: TOpenSSL_C_INT; cdecl;
begin
  RAND_status := LoadLibCryptoFunction('RAND_status');
  if not assigned(RAND_status) then
    {$if declared(LEGACY_RAND_status)}
    RAND_status := @LEGACY_RAND_status;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_status');
    {$ifend}
  Result := RAND_status;
end;

{$ifndef  OPENSSL_NO_EGD}
function Load_RAND_query_egd_bytes(path: PAnsiChar; buf: Pbyte; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_query_egd_bytes := LoadLibCryptoFunction('RAND_query_egd_bytes');
  if not assigned(RAND_query_egd_bytes) then
    {$if declared(LEGACY_RAND_query_egd_bytes)}
    RAND_query_egd_bytes := @LEGACY_RAND_query_egd_bytes;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_query_egd_bytes');
    {$ifend}
  Result := RAND_query_egd_bytes(path, buf, bytes);
end;

function Load_RAND_egd(path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RAND_egd := LoadLibCryptoFunction('RAND_egd');
  if not assigned(RAND_egd) then
    {$if declared(LEGACY_RAND_egd)}
    RAND_egd := @LEGACY_RAND_egd;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_egd');
    {$ifend}
  Result := RAND_egd(path);
end;

function Load_RAND_egd_bytes(path: PAnsiChar; bytes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RAND_egd_bytes := LoadLibCryptoFunction('RAND_egd_bytes');
  if not assigned(RAND_egd_bytes) then
    {$if declared(LEGACY_RAND_egd_bytes)}
    RAND_egd_bytes := @LEGACY_RAND_egd_bytes;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_egd_bytes');
    {$ifend}
  Result := RAND_egd_bytes(path, bytes);
end;

{$endif} { OPENSSL_NO_EGD}
function Load_RAND_poll: TOpenSSL_C_INT; cdecl;
begin
  RAND_poll := LoadLibCryptoFunction('RAND_poll');
  if not assigned(RAND_poll) then
    {$if declared(LEGACY_RAND_poll)}
    RAND_poll := @LEGACY_RAND_poll;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_poll');
    {$ifend}
  Result := RAND_poll;
end;

{$if  defined(_WIN32)  and  (defined(BASETYPES)  or defined(_WINDEF_H))}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
procedure Load_RAND_screen; cdecl;
begin
  RAND_screen := LoadLibCryptoFunction('RAND_screen');
  if not assigned(RAND_screen) then
    {$if declared(LEGACY_RAND_screen)}
    RAND_screen := @LEGACY_RAND_screen;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_screen');
    {$ifend}
  RAND_screen;
end;

function Load_RAND_event(_param1: TOpenSSL_C_UINT; _param2: TWPARAM; _param3: TLPARAM): TOpenSSL_C_INT; cdecl;
begin
  RAND_event := LoadLibCryptoFunction('RAND_event');
  if not assigned(RAND_event) then
    {$if declared(LEGACY_RAND_event)}
    RAND_event := @LEGACY_RAND_event;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('RAND_event');
    {$ifend}
  Result := RAND_event(_param1, _param2, _param3);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$endif} { defined(_WIN32)  and  (defined(BASETYPES)  or  defined(_WINDEF_H))}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  RAND_set_rand_method := Load_RAND_set_rand_method;
  RAND_get_rand_method := Load_RAND_get_rand_method;
    {$ifndef  OPENSSL_NO_ENGINE}
  RAND_set_rand_engine := Load_RAND_set_rand_engine;
    {$endif} { OPENSSL_NO_ENGINE}
  RAND_OpenSSL := Load_RAND_OpenSSL;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  RAND_bytes := Load_RAND_bytes;
  RAND_priv_bytes := Load_RAND_priv_bytes;
  RAND_priv_bytes_ex := Load_RAND_priv_bytes_ex;
  RAND_bytes_ex := Load_RAND_bytes_ex;
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  RAND_pseudo_bytes := Load_RAND_pseudo_bytes;
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
  RAND_get0_primary := Load_RAND_get0_primary;
  RAND_get0_public := Load_RAND_get0_public;
  RAND_get0_private := Load_RAND_get0_private;
  RAND_set_DRBG_type := Load_RAND_set_DRBG_type;
  RAND_set_seed_source_type := Load_RAND_set_seed_source_type;
  RAND_seed := Load_RAND_seed;
  RAND_keep_random_devices_open := Load_RAND_keep_random_devices_open;
  RAND_add := Load_RAND_add;
  RAND_load_file := Load_RAND_load_file;
  RAND_write_file := Load_RAND_write_file;
  RAND_file_name := Load_RAND_file_name;
  RAND_status := Load_RAND_status;
{$ifndef  OPENSSL_NO_EGD}
  RAND_query_egd_bytes := Load_RAND_query_egd_bytes;
  RAND_egd := Load_RAND_egd;
  RAND_egd_bytes := Load_RAND_egd_bytes;
{$endif} { OPENSSL_NO_EGD}
  RAND_poll := Load_RAND_poll;
{$if  defined(_WIN32)  and  (defined(BASETYPES)  or defined(_WINDEF_H))}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  RAND_screen := Load_RAND_screen;
  RAND_event := Load_RAND_event;
    {$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$endif} { defined(_WIN32)  and  (defined(BASETYPES)  or  defined(_WINDEF_H))}
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



