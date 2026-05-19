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

unit openssl_param_build;

{
  Generated from OpenSSL 4.0.0 Header File param_build.h - Tue 19 May 14:32:57 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_param_build.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_params,openssl_types;


{* Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
* Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_PARAM_BUILD_H}
  {$define OPENSSL_PARAM_BUILD_H}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_PARAM_BLD_new: POSSL_PARAM_BLD; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_new';
  function OSSL_PARAM_BLD_to_param(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_to_param';
  procedure OSSL_PARAM_BLD_free(bld: POSSL_PARAM_BLD); cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_free';
  function OSSL_PARAM_BLD_push_int(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_int';
  function OSSL_PARAM_BLD_push_uint(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_uint';
  function OSSL_PARAM_BLD_push_long(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_long';
  function OSSL_PARAM_BLD_push_ulong(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_ulong';
  function OSSL_PARAM_BLD_push_int32(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_int32';
  function OSSL_PARAM_BLD_push_uint32(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_uint32';
  function OSSL_PARAM_BLD_push_int64(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_int64';
  function OSSL_PARAM_BLD_push_uint64(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_uint64';
  function OSSL_PARAM_BLD_push_size_t(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_size_t';
  function OSSL_PARAM_BLD_push_time_t(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_time_t';
  function OSSL_PARAM_BLD_push_double(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_double';
  function OSSL_PARAM_BLD_push_BN(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_BN';
  function OSSL_PARAM_BLD_push_BN_pad(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM; sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_BN_pad';
  function OSSL_PARAM_BLD_push_utf8_string(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_utf8_string';
  function OSSL_PARAM_BLD_push_utf8_ptr(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_utf8_ptr';
  function OSSL_PARAM_BLD_push_octet_string(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_octet_string';
  function OSSL_PARAM_BLD_push_octet_ptr(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_BLD_push_octet_ptr';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_PARAM_BLD_new}
  {$EXTERNALSYM OSSL_PARAM_BLD_to_param}
  {$EXTERNALSYM OSSL_PARAM_BLD_free}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_int}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_uint}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_long}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_ulong}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_int32}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_uint32}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_int64}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_uint64}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_size_t}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_time_t}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_double}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_BN}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_BN_pad}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_utf8_string}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_utf8_ptr}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_octet_string}
  {$EXTERNALSYM OSSL_PARAM_BLD_push_octet_ptr}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_PARAM_BLD_new: POSSL_PARAM_BLD; cdecl;
  function Load_OSSL_PARAM_BLD_to_param(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl;
  procedure Load_OSSL_PARAM_BLD_free(bld: POSSL_PARAM_BLD); cdecl;
  function Load_OSSL_PARAM_BLD_push_int(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_uint(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_long(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_ulong(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_int32(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_uint32(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_int64(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_uint64(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_size_t(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_time_t(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_double(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_BN(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_BN_pad(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM; sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_utf8_string(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_utf8_ptr(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_octet_string(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_BLD_push_octet_ptr(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

var
  OSSL_PARAM_BLD_new: function: POSSL_PARAM_BLD; cdecl = Load_OSSL_PARAM_BLD_new;
  OSSL_PARAM_BLD_to_param: function(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl = Load_OSSL_PARAM_BLD_to_param;
  OSSL_PARAM_BLD_free: procedure(bld: POSSL_PARAM_BLD); cdecl = Load_OSSL_PARAM_BLD_free;
  OSSL_PARAM_BLD_push_int: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_int;
  OSSL_PARAM_BLD_push_uint: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_uint;
  OSSL_PARAM_BLD_push_long: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_long;
  OSSL_PARAM_BLD_push_ulong: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_ulong;
  OSSL_PARAM_BLD_push_int32: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_int32;
  OSSL_PARAM_BLD_push_uint32: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_uint32;
  OSSL_PARAM_BLD_push_int64: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_int64;
  OSSL_PARAM_BLD_push_uint64: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_uint64;
  OSSL_PARAM_BLD_push_size_t: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_size_t;
  OSSL_PARAM_BLD_push_time_t: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_time_t;
  OSSL_PARAM_BLD_push_double: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_double;
  OSSL_PARAM_BLD_push_BN: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_BN;
  OSSL_PARAM_BLD_push_BN_pad: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM; sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_BN_pad;
  OSSL_PARAM_BLD_push_utf8_string: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_utf8_string;
  OSSL_PARAM_BLD_push_utf8_ptr: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_utf8_ptr;
  OSSL_PARAM_BLD_push_octet_string: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_octet_string;
  OSSL_PARAM_BLD_push_octet_ptr: function(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_BLD_push_octet_ptr;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}
{ OPENSSL_PARAM_BUILD_H }

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
function Load_OSSL_PARAM_BLD_new: POSSL_PARAM_BLD; cdecl;
begin
  OSSL_PARAM_BLD_new := LoadLibCryptoFunction('OSSL_PARAM_BLD_new');
  if not assigned(OSSL_PARAM_BLD_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_new');
  Result := OSSL_PARAM_BLD_new;
end;

function Load_OSSL_PARAM_BLD_to_param(bld: POSSL_PARAM_BLD): POSSL_PARAM; cdecl;
begin
  OSSL_PARAM_BLD_to_param := LoadLibCryptoFunction('OSSL_PARAM_BLD_to_param');
  if not assigned(OSSL_PARAM_BLD_to_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_to_param');
  Result := OSSL_PARAM_BLD_to_param(bld);
end;

procedure Load_OSSL_PARAM_BLD_free(bld: POSSL_PARAM_BLD); cdecl;
begin
  OSSL_PARAM_BLD_free := LoadLibCryptoFunction('OSSL_PARAM_BLD_free');
  if not assigned(OSSL_PARAM_BLD_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_free');
  OSSL_PARAM_BLD_free(bld);
end;

function Load_OSSL_PARAM_BLD_push_int(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_int := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_int');
  if not assigned(OSSL_PARAM_BLD_push_int) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_int');
  Result := OSSL_PARAM_BLD_push_int(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_uint(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_uint := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_uint');
  if not assigned(OSSL_PARAM_BLD_push_uint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_uint');
  Result := OSSL_PARAM_BLD_push_uint(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_long(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_long := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_long');
  if not assigned(OSSL_PARAM_BLD_push_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_long');
  Result := OSSL_PARAM_BLD_push_long(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_ulong(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_ulong := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_ulong');
  if not assigned(OSSL_PARAM_BLD_push_ulong) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_ulong');
  Result := OSSL_PARAM_BLD_push_ulong(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_int32(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_int32 := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_int32');
  if not assigned(OSSL_PARAM_BLD_push_int32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_int32');
  Result := OSSL_PARAM_BLD_push_int32(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_uint32(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_uint32 := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_uint32');
  if not assigned(OSSL_PARAM_BLD_push_uint32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_uint32');
  Result := OSSL_PARAM_BLD_push_uint32(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_int64(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_int64 := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_int64');
  if not assigned(OSSL_PARAM_BLD_push_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_int64');
  Result := OSSL_PARAM_BLD_push_int64(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_uint64(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_uint64 := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_uint64');
  if not assigned(OSSL_PARAM_BLD_push_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_uint64');
  Result := OSSL_PARAM_BLD_push_uint64(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_size_t(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_size_t := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_size_t');
  if not assigned(OSSL_PARAM_BLD_push_size_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_size_t');
  Result := OSSL_PARAM_BLD_push_size_t(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_time_t(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_time_t := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_time_t');
  if not assigned(OSSL_PARAM_BLD_push_time_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_time_t');
  Result := OSSL_PARAM_BLD_push_time_t(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_double(bld: POSSL_PARAM_BLD; key: PAnsiChar; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_double := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_double');
  if not assigned(OSSL_PARAM_BLD_push_double) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_double');
  Result := OSSL_PARAM_BLD_push_double(bld, key, val);
end;

function Load_OSSL_PARAM_BLD_push_BN(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_BN := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_BN');
  if not assigned(OSSL_PARAM_BLD_push_BN) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_BN');
  Result := OSSL_PARAM_BLD_push_BN(bld, key, bn);
end;

function Load_OSSL_PARAM_BLD_push_BN_pad(bld: POSSL_PARAM_BLD; key: PAnsiChar; bn: PBIGNUM; sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_BN_pad := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_BN_pad');
  if not assigned(OSSL_PARAM_BLD_push_BN_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_BN_pad');
  Result := OSSL_PARAM_BLD_push_BN_pad(bld, key, bn, sz);
end;

function Load_OSSL_PARAM_BLD_push_utf8_string(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_utf8_string := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_utf8_string');
  if not assigned(OSSL_PARAM_BLD_push_utf8_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_utf8_string');
  Result := OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, bsize);
end;

function Load_OSSL_PARAM_BLD_push_utf8_ptr(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_utf8_ptr := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_utf8_ptr');
  if not assigned(OSSL_PARAM_BLD_push_utf8_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_utf8_ptr');
  Result := OSSL_PARAM_BLD_push_utf8_ptr(bld, key, buf, bsize);
end;

function Load_OSSL_PARAM_BLD_push_octet_string(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_octet_string := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_octet_string');
  if not assigned(OSSL_PARAM_BLD_push_octet_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_octet_string');
  Result := OSSL_PARAM_BLD_push_octet_string(bld, key, buf, bsize);
end;

function Load_OSSL_PARAM_BLD_push_octet_ptr(bld: POSSL_PARAM_BLD; key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_BLD_push_octet_ptr := LoadLibCryptoFunction('OSSL_PARAM_BLD_push_octet_ptr');
  if not assigned(OSSL_PARAM_BLD_push_octet_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_BLD_push_octet_ptr');
  Result := OSSL_PARAM_BLD_push_octet_ptr(bld, key, buf, bsize);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_PARAM_BLD_new := Load_OSSL_PARAM_BLD_new;
  OSSL_PARAM_BLD_to_param := Load_OSSL_PARAM_BLD_to_param;
  OSSL_PARAM_BLD_free := Load_OSSL_PARAM_BLD_free;
  OSSL_PARAM_BLD_push_int := Load_OSSL_PARAM_BLD_push_int;
  OSSL_PARAM_BLD_push_uint := Load_OSSL_PARAM_BLD_push_uint;
  OSSL_PARAM_BLD_push_long := Load_OSSL_PARAM_BLD_push_long;
  OSSL_PARAM_BLD_push_ulong := Load_OSSL_PARAM_BLD_push_ulong;
  OSSL_PARAM_BLD_push_int32 := Load_OSSL_PARAM_BLD_push_int32;
  OSSL_PARAM_BLD_push_uint32 := Load_OSSL_PARAM_BLD_push_uint32;
  OSSL_PARAM_BLD_push_int64 := Load_OSSL_PARAM_BLD_push_int64;
  OSSL_PARAM_BLD_push_uint64 := Load_OSSL_PARAM_BLD_push_uint64;
  OSSL_PARAM_BLD_push_size_t := Load_OSSL_PARAM_BLD_push_size_t;
  OSSL_PARAM_BLD_push_time_t := Load_OSSL_PARAM_BLD_push_time_t;
  OSSL_PARAM_BLD_push_double := Load_OSSL_PARAM_BLD_push_double;
  OSSL_PARAM_BLD_push_BN := Load_OSSL_PARAM_BLD_push_BN;
  OSSL_PARAM_BLD_push_BN_pad := Load_OSSL_PARAM_BLD_push_BN_pad;
  OSSL_PARAM_BLD_push_utf8_string := Load_OSSL_PARAM_BLD_push_utf8_string;
  OSSL_PARAM_BLD_push_utf8_ptr := Load_OSSL_PARAM_BLD_push_utf8_ptr;
  OSSL_PARAM_BLD_push_octet_string := Load_OSSL_PARAM_BLD_push_octet_string;
  OSSL_PARAM_BLD_push_octet_ptr := Load_OSSL_PARAM_BLD_push_octet_ptr;
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



