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

unit openssl_params;

{
  Generated from OpenSSL 3.5.6 Header File params.h - Tue 19 May 14:28:02 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_params.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_core,openssl_bn;


{* Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
* Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_PARAMS_H}
  {$define OPENSSL_PARAMS_H}


  function OSSL_PARAM_UNMODIFIED: TOpenSSL_C_SIZET; inline;
  (*# define  OSSL_PARAM_END { NULL, 0, NULL, 0, 0 }*)
  (*# define  OSSL_PARAM_DEFN(key,type,addr,sz) { (key), (type), (addr), (sz), OSSL_PARAM_UNMODIFIED }*)
  {# define  OSSL_PARAM_int(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int))} {Macro Return Type unknown at line no 30}
  {# define  OSSL_PARAM_uint(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(unsigned int))} {Macro Return Type unknown at line no 32}
  {# define  OSSL_PARAM_long(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(long int))} {Macro Return Type unknown at line no 35}
  {# define  OSSL_PARAM_ulong(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(unsigned long int))} {Macro Return Type unknown at line no 37}
  {# define  OSSL_PARAM_int32(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int32_t))} {Macro Return Type unknown at line no 40}
  {# define  OSSL_PARAM_uint32(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(uint32_t))} {Macro Return Type unknown at line no 42}
  {# define  OSSL_PARAM_int64(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(int64_t))} {Macro Return Type unknown at line no 45}
  {# define  OSSL_PARAM_uint64(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(uint64_t))} {Macro Return Type unknown at line no 47}
  {# define  OSSL_PARAM_size_t(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t))} {Macro Return Type unknown at line no 50}
  {# define  OSSL_PARAM_time_t(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_INTEGER, (addr), sizeof(time_t))} {Macro Return Type unknown at line no 52}
  {# define  OSSL_PARAM_double(key,addr) OSSL_PARAM_DEFN((key), OSSL_PARAM_REAL, (addr), sizeof(double))} {Macro Return Type unknown at line no 54}
  {# define  OSSL_PARAM_BN(key,bn,sz) OSSL_PARAM_DEFN((key), OSSL_PARAM_UNSIGNED_INTEGER, (bn), (sz))} {Macro Return Type unknown at line no 57}
  {# define  OSSL_PARAM_utf8_string(key,addr,sz) OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_STRING, (addr), sz)} {Macro Return Type unknown at line no 59}
  {# define  OSSL_PARAM_octet_string(key,addr,sz) OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_STRING, (addr), sz)} {Macro Return Type unknown at line no 61}
  {# define  OSSL_PARAM_utf8_ptr(key,addr,sz) OSSL_PARAM_DEFN((key), OSSL_PARAM_UTF8_PTR, (addr), sz)} {Macro Return Type unknown at line no 64}
  {# define  OSSL_PARAM_octet_ptr(key,addr,sz) OSSL_PARAM_DEFN((key), OSSL_PARAM_OCTET_PTR, (addr), sz)} {Macro Return Type unknown at line no 66}
  { Basic parameter types without return sizes }
  { Search an OSSL_PARAM array for a matching name }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_PARAM_locate(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_locate';
  function OSSL_PARAM_locate_const(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_locate_const';
  { Basic parameter type run-time construction }
  function OSSL_PARAM_construct_int(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_int';
  function OSSL_PARAM_construct_uint(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_uint';
  function OSSL_PARAM_construct_long(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_long';
  function OSSL_PARAM_construct_ulong(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_ulong';
  function OSSL_PARAM_construct_int32(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_int32';
  function OSSL_PARAM_construct_uint32(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_uint32';
  function OSSL_PARAM_construct_int64(key: PAnsiChar; buf: POpenSSL_C_LONG): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_int64';
  function OSSL_PARAM_construct_uint64(key: PAnsiChar; buf: POpenSSL_C_UINT64): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_uint64';
  function OSSL_PARAM_construct_size_t(key: PAnsiChar; buf: POpenSSL_C_SIZET): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_size_t';
  function OSSL_PARAM_construct_time_t(key: PAnsiChar; buf: POpenSSL_C_TIMET): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_time_t';
  function OSSL_PARAM_construct_BN(key: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_BN';
  function OSSL_PARAM_construct_double(key: PAnsiChar; buf: POpenSSL_C_DOUBLE): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_double';
  function OSSL_PARAM_construct_utf8_string(key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_utf8_string';
  function OSSL_PARAM_construct_utf8_ptr(key: PAnsiChar; buf: PPAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_utf8_ptr';
  function OSSL_PARAM_construct_octet_string(key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_octet_string';
  function OSSL_PARAM_construct_octet_ptr(key: PAnsiChar; buf: Ppointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_octet_ptr';
  function OSSL_PARAM_construct_end: TOSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_construct_end';
  function OSSL_PARAM_allocate_from_text(to_: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PAnsiChar; value: PAnsiChar; value_n: TOpenSSL_C_SIZET; found: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_allocate_from_text';
  function OSSL_PARAM_print_to_bio(params: POSSL_PARAM; bio: PBIO; print_values: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_print_to_bio';
  function OSSL_PARAM_get_int(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_int';
  function OSSL_PARAM_get_uint(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_uint';
  function OSSL_PARAM_get_long(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_long';
  function OSSL_PARAM_get_ulong(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_ulong';
  function OSSL_PARAM_get_int32(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_int32';
  function OSSL_PARAM_get_uint32(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_uint32';
  function OSSL_PARAM_get_int64(p: POSSL_PARAM; val: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_int64';
  function OSSL_PARAM_get_uint64(p: POSSL_PARAM; val: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_uint64';
  function OSSL_PARAM_get_size_t(p: POSSL_PARAM; val: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_size_t';
  function OSSL_PARAM_get_time_t(p: POSSL_PARAM; val: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_time_t';
  function OSSL_PARAM_set_int(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_int';
  function OSSL_PARAM_set_uint(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_uint';
  function OSSL_PARAM_set_long(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_long';
  function OSSL_PARAM_set_ulong(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_ulong';
  function OSSL_PARAM_set_int32(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_int32';
  function OSSL_PARAM_set_uint32(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_uint32';
  function OSSL_PARAM_set_int64(p: POSSL_PARAM; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_int64';
  function OSSL_PARAM_set_uint64(p: POSSL_PARAM; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_uint64';
  function OSSL_PARAM_set_size_t(p: POSSL_PARAM; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_size_t';
  function OSSL_PARAM_set_time_t(p: POSSL_PARAM; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_time_t';
  function OSSL_PARAM_get_double(p: POSSL_PARAM; val: POpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_double';
  function OSSL_PARAM_set_double(p: POSSL_PARAM; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_double';
  function OSSL_PARAM_get_BN(p: POSSL_PARAM; val: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_BN';
  function OSSL_PARAM_set_BN(p: POSSL_PARAM; val: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_BN';
  function OSSL_PARAM_get_utf8_string(p: POSSL_PARAM; val: PPAnsiChar; max_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_utf8_string';
  function OSSL_PARAM_set_utf8_string(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_utf8_string';
  function OSSL_PARAM_get_octet_string(p: POSSL_PARAM; val: Ppointer; max_len: TOpenSSL_C_SIZET; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_octet_string';
  function OSSL_PARAM_set_octet_string(p: POSSL_PARAM; val: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_octet_string';
  function OSSL_PARAM_get_utf8_ptr(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_utf8_ptr';
  function OSSL_PARAM_set_utf8_ptr(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_utf8_ptr';
  function OSSL_PARAM_get_octet_ptr(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_octet_ptr';
  function OSSL_PARAM_set_octet_ptr(p: POSSL_PARAM; val: pointer; used_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_set_octet_ptr';
  function OSSL_PARAM_get_utf8_string_ptr(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_utf8_string_ptr';
  function OSSL_PARAM_get_octet_string_ptr(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_get_octet_string_ptr';
  function OSSL_PARAM_modified(p: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_PARAM_modified';
  procedure OSSL_PARAM_set_all_unmodified(p: POSSL_PARAM); cdecl; external CLibCrypto name 'OSSL_PARAM_set_all_unmodified';
  function OSSL_PARAM_dup(p: POSSL_PARAM): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_dup';
  function OSSL_PARAM_merge(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_PARAM_merge';
  procedure OSSL_PARAM_free(p: POSSL_PARAM); cdecl; external CLibCrypto name 'OSSL_PARAM_free';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_PARAM_locate}
  {$EXTERNALSYM OSSL_PARAM_locate_const}
  {$EXTERNALSYM OSSL_PARAM_construct_int}
  {$EXTERNALSYM OSSL_PARAM_construct_uint}
  {$EXTERNALSYM OSSL_PARAM_construct_long}
  {$EXTERNALSYM OSSL_PARAM_construct_ulong}
  {$EXTERNALSYM OSSL_PARAM_construct_int32}
  {$EXTERNALSYM OSSL_PARAM_construct_uint32}
  {$EXTERNALSYM OSSL_PARAM_construct_int64}
  {$EXTERNALSYM OSSL_PARAM_construct_uint64}
  {$EXTERNALSYM OSSL_PARAM_construct_size_t}
  {$EXTERNALSYM OSSL_PARAM_construct_time_t}
  {$EXTERNALSYM OSSL_PARAM_construct_BN}
  {$EXTERNALSYM OSSL_PARAM_construct_double}
  {$EXTERNALSYM OSSL_PARAM_construct_utf8_string}
  {$EXTERNALSYM OSSL_PARAM_construct_utf8_ptr}
  {$EXTERNALSYM OSSL_PARAM_construct_octet_string}
  {$EXTERNALSYM OSSL_PARAM_construct_octet_ptr}
  {$EXTERNALSYM OSSL_PARAM_construct_end}
  {$EXTERNALSYM OSSL_PARAM_allocate_from_text}
  {$EXTERNALSYM OSSL_PARAM_print_to_bio}
  {$EXTERNALSYM OSSL_PARAM_get_int}
  {$EXTERNALSYM OSSL_PARAM_get_uint}
  {$EXTERNALSYM OSSL_PARAM_get_long}
  {$EXTERNALSYM OSSL_PARAM_get_ulong}
  {$EXTERNALSYM OSSL_PARAM_get_int32}
  {$EXTERNALSYM OSSL_PARAM_get_uint32}
  {$EXTERNALSYM OSSL_PARAM_get_int64}
  {$EXTERNALSYM OSSL_PARAM_get_uint64}
  {$EXTERNALSYM OSSL_PARAM_get_size_t}
  {$EXTERNALSYM OSSL_PARAM_get_time_t}
  {$EXTERNALSYM OSSL_PARAM_set_int}
  {$EXTERNALSYM OSSL_PARAM_set_uint}
  {$EXTERNALSYM OSSL_PARAM_set_long}
  {$EXTERNALSYM OSSL_PARAM_set_ulong}
  {$EXTERNALSYM OSSL_PARAM_set_int32}
  {$EXTERNALSYM OSSL_PARAM_set_uint32}
  {$EXTERNALSYM OSSL_PARAM_set_int64}
  {$EXTERNALSYM OSSL_PARAM_set_uint64}
  {$EXTERNALSYM OSSL_PARAM_set_size_t}
  {$EXTERNALSYM OSSL_PARAM_set_time_t}
  {$EXTERNALSYM OSSL_PARAM_get_double}
  {$EXTERNALSYM OSSL_PARAM_set_double}
  {$EXTERNALSYM OSSL_PARAM_get_BN}
  {$EXTERNALSYM OSSL_PARAM_set_BN}
  {$EXTERNALSYM OSSL_PARAM_get_utf8_string}
  {$EXTERNALSYM OSSL_PARAM_set_utf8_string}
  {$EXTERNALSYM OSSL_PARAM_get_octet_string}
  {$EXTERNALSYM OSSL_PARAM_set_octet_string}
  {$EXTERNALSYM OSSL_PARAM_get_utf8_ptr}
  {$EXTERNALSYM OSSL_PARAM_set_utf8_ptr}
  {$EXTERNALSYM OSSL_PARAM_get_octet_ptr}
  {$EXTERNALSYM OSSL_PARAM_set_octet_ptr}
  {$EXTERNALSYM OSSL_PARAM_get_utf8_string_ptr}
  {$EXTERNALSYM OSSL_PARAM_get_octet_string_ptr}
  {$EXTERNALSYM OSSL_PARAM_modified}
  {$EXTERNALSYM OSSL_PARAM_set_all_unmodified}
  {$EXTERNALSYM OSSL_PARAM_dup}
  {$EXTERNALSYM OSSL_PARAM_merge}
  {$EXTERNALSYM OSSL_PARAM_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_PARAM_locate(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_locate_const(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_int(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_uint(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_long(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_ulong(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_int32(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_uint32(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_int64(key: PAnsiChar; buf: POpenSSL_C_LONG): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_uint64(key: PAnsiChar; buf: POpenSSL_C_UINT64): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_size_t(key: PAnsiChar; buf: POpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_time_t(key: PAnsiChar; buf: POpenSSL_C_TIMET): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_BN(key: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_double(key: PAnsiChar; buf: POpenSSL_C_DOUBLE): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_utf8_string(key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_utf8_ptr(key: PAnsiChar; buf: PPAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_octet_string(key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_octet_ptr(key: PAnsiChar; buf: Ppointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_construct_end: TOSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_allocate_from_text(to_: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PAnsiChar; value: PAnsiChar; value_n: TOpenSSL_C_SIZET; found: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_print_to_bio(params: POSSL_PARAM; bio: PBIO; print_values: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_int(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_uint(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_long(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_ulong(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_int32(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_uint32(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_int64(p: POSSL_PARAM; val: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_uint64(p: POSSL_PARAM; val: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_size_t(p: POSSL_PARAM; val: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_time_t(p: POSSL_PARAM; val: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_int(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_uint(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_long(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_ulong(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_int32(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_uint32(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_int64(p: POSSL_PARAM; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_uint64(p: POSSL_PARAM; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_size_t(p: POSSL_PARAM; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_time_t(p: POSSL_PARAM; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_double(p: POSSL_PARAM; val: POpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_double(p: POSSL_PARAM; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_BN(p: POSSL_PARAM; val: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_BN(p: POSSL_PARAM; val: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_utf8_string(p: POSSL_PARAM; val: PPAnsiChar; max_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_utf8_string(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_octet_string(p: POSSL_PARAM; val: Ppointer; max_len: TOpenSSL_C_SIZET; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_octet_string(p: POSSL_PARAM; val: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_utf8_ptr(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_utf8_ptr(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_octet_ptr(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_set_octet_ptr(p: POSSL_PARAM; val: pointer; used_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_utf8_string_ptr(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_get_octet_string_ptr(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_PARAM_modified(p: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_PARAM_set_all_unmodified(p: POSSL_PARAM); cdecl;
  function Load_OSSL_PARAM_dup(p: POSSL_PARAM): POSSL_PARAM; cdecl;
  function Load_OSSL_PARAM_merge(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl;
  procedure Load_OSSL_PARAM_free(p: POSSL_PARAM); cdecl;

var
  OSSL_PARAM_locate: function(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl = Load_OSSL_PARAM_locate;
  OSSL_PARAM_locate_const: function(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl = Load_OSSL_PARAM_locate_const;
  { Basic parameter type run-time construction }
  OSSL_PARAM_construct_int: function(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_int;
  OSSL_PARAM_construct_uint: function(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_uint;
  OSSL_PARAM_construct_long: function(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_long;
  OSSL_PARAM_construct_ulong: function(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_ulong;
  OSSL_PARAM_construct_int32: function(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_int32;
  OSSL_PARAM_construct_uint32: function(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_uint32;
  OSSL_PARAM_construct_int64: function(key: PAnsiChar; buf: POpenSSL_C_LONG): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_int64;
  OSSL_PARAM_construct_uint64: function(key: PAnsiChar; buf: POpenSSL_C_UINT64): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_uint64;
  OSSL_PARAM_construct_size_t: function(key: PAnsiChar; buf: POpenSSL_C_SIZET): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_size_t;
  OSSL_PARAM_construct_time_t: function(key: PAnsiChar; buf: POpenSSL_C_TIMET): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_time_t;
  OSSL_PARAM_construct_BN: function(key: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_BN;
  OSSL_PARAM_construct_double: function(key: PAnsiChar; buf: POpenSSL_C_DOUBLE): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_double;
  OSSL_PARAM_construct_utf8_string: function(key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_utf8_string;
  OSSL_PARAM_construct_utf8_ptr: function(key: PAnsiChar; buf: PPAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_utf8_ptr;
  OSSL_PARAM_construct_octet_string: function(key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_octet_string;
  OSSL_PARAM_construct_octet_ptr: function(key: PAnsiChar; buf: Ppointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_octet_ptr;
  OSSL_PARAM_construct_end: function: TOSSL_PARAM; cdecl = Load_OSSL_PARAM_construct_end;
  OSSL_PARAM_allocate_from_text: function(to_: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PAnsiChar; value: PAnsiChar; value_n: TOpenSSL_C_SIZET; found: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_allocate_from_text;
  OSSL_PARAM_print_to_bio: function(params: POSSL_PARAM; bio: PBIO; print_values: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_print_to_bio;
  OSSL_PARAM_get_int: function(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_int;
  OSSL_PARAM_get_uint: function(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_uint;
  OSSL_PARAM_get_long: function(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_long;
  OSSL_PARAM_get_ulong: function(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_ulong;
  OSSL_PARAM_get_int32: function(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_int32;
  OSSL_PARAM_get_uint32: function(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_uint32;
  OSSL_PARAM_get_int64: function(p: POSSL_PARAM; val: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_int64;
  OSSL_PARAM_get_uint64: function(p: POSSL_PARAM; val: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_uint64;
  OSSL_PARAM_get_size_t: function(p: POSSL_PARAM; val: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_size_t;
  OSSL_PARAM_get_time_t: function(p: POSSL_PARAM; val: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_time_t;
  OSSL_PARAM_set_int: function(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_int;
  OSSL_PARAM_set_uint: function(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_uint;
  OSSL_PARAM_set_long: function(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_long;
  OSSL_PARAM_set_ulong: function(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_ulong;
  OSSL_PARAM_set_int32: function(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_int32;
  OSSL_PARAM_set_uint32: function(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_uint32;
  OSSL_PARAM_set_int64: function(p: POSSL_PARAM; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_int64;
  OSSL_PARAM_set_uint64: function(p: POSSL_PARAM; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_uint64;
  OSSL_PARAM_set_size_t: function(p: POSSL_PARAM; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_size_t;
  OSSL_PARAM_set_time_t: function(p: POSSL_PARAM; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_time_t;
  OSSL_PARAM_get_double: function(p: POSSL_PARAM; val: POpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_double;
  OSSL_PARAM_set_double: function(p: POSSL_PARAM; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_double;
  OSSL_PARAM_get_BN: function(p: POSSL_PARAM; val: PPBIGNUM): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_BN;
  OSSL_PARAM_set_BN: function(p: POSSL_PARAM; val: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_BN;
  OSSL_PARAM_get_utf8_string: function(p: POSSL_PARAM; val: PPAnsiChar; max_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_utf8_string;
  OSSL_PARAM_set_utf8_string: function(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_utf8_string;
  OSSL_PARAM_get_octet_string: function(p: POSSL_PARAM; val: Ppointer; max_len: TOpenSSL_C_SIZET; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_octet_string;
  OSSL_PARAM_set_octet_string: function(p: POSSL_PARAM; val: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_octet_string;
  OSSL_PARAM_get_utf8_ptr: function(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_utf8_ptr;
  OSSL_PARAM_set_utf8_ptr: function(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_utf8_ptr;
  OSSL_PARAM_get_octet_ptr: function(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_octet_ptr;
  OSSL_PARAM_set_octet_ptr: function(p: POSSL_PARAM; val: pointer; used_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_set_octet_ptr;
  OSSL_PARAM_get_utf8_string_ptr: function(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_utf8_string_ptr;
  OSSL_PARAM_get_octet_string_ptr: function(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_get_octet_string_ptr;
  OSSL_PARAM_modified: function(p: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_PARAM_modified;
  OSSL_PARAM_set_all_unmodified: procedure(p: POSSL_PARAM); cdecl = Load_OSSL_PARAM_set_all_unmodified;
  OSSL_PARAM_dup: function(p: POSSL_PARAM): POSSL_PARAM; cdecl = Load_OSSL_PARAM_dup;
  OSSL_PARAM_merge: function(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl = Load_OSSL_PARAM_merge;
  OSSL_PARAM_free: procedure(p: POSSL_PARAM); cdecl = Load_OSSL_PARAM_free;
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


{# define  OSSL_PARAM_UNMODIFIED ((size_t)-1)}

function OSSL_PARAM_UNMODIFIED: TOpenSSL_C_SIZET;
begin
  Result := TOpenSSL_C_SIZET(TOpenSSL_C_SIZET(-(1)));
end;
{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_OSSL_PARAM_locate(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl;
begin
  OSSL_PARAM_locate := LoadLibCryptoFunction('OSSL_PARAM_locate');
  if not assigned(OSSL_PARAM_locate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_locate');
  Result := OSSL_PARAM_locate(p, key);
end;

function Load_OSSL_PARAM_locate_const(p: POSSL_PARAM; key: PAnsiChar): POSSL_PARAM; cdecl;
begin
  OSSL_PARAM_locate_const := LoadLibCryptoFunction('OSSL_PARAM_locate_const');
  if not assigned(OSSL_PARAM_locate_const) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_locate_const');
  Result := OSSL_PARAM_locate_const(p, key);
end;

function Load_OSSL_PARAM_construct_int(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_int := LoadLibCryptoFunction('OSSL_PARAM_construct_int');
  if not assigned(OSSL_PARAM_construct_int) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_int');
  Result := OSSL_PARAM_construct_int(key, buf);
end;

function Load_OSSL_PARAM_construct_uint(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_uint := LoadLibCryptoFunction('OSSL_PARAM_construct_uint');
  if not assigned(OSSL_PARAM_construct_uint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_uint');
  Result := OSSL_PARAM_construct_uint(key, buf);
end;

function Load_OSSL_PARAM_construct_long(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_long := LoadLibCryptoFunction('OSSL_PARAM_construct_long');
  if not assigned(OSSL_PARAM_construct_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_long');
  Result := OSSL_PARAM_construct_long(key, buf);
end;

function Load_OSSL_PARAM_construct_ulong(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_ulong := LoadLibCryptoFunction('OSSL_PARAM_construct_ulong');
  if not assigned(OSSL_PARAM_construct_ulong) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_ulong');
  Result := OSSL_PARAM_construct_ulong(key, buf);
end;

function Load_OSSL_PARAM_construct_int32(key: PAnsiChar; buf: POpenSSL_C_INT): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_int32 := LoadLibCryptoFunction('OSSL_PARAM_construct_int32');
  if not assigned(OSSL_PARAM_construct_int32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_int32');
  Result := OSSL_PARAM_construct_int32(key, buf);
end;

function Load_OSSL_PARAM_construct_uint32(key: PAnsiChar; buf: POpenSSL_C_UINT): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_uint32 := LoadLibCryptoFunction('OSSL_PARAM_construct_uint32');
  if not assigned(OSSL_PARAM_construct_uint32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_uint32');
  Result := OSSL_PARAM_construct_uint32(key, buf);
end;

function Load_OSSL_PARAM_construct_int64(key: PAnsiChar; buf: POpenSSL_C_LONG): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_int64 := LoadLibCryptoFunction('OSSL_PARAM_construct_int64');
  if not assigned(OSSL_PARAM_construct_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_int64');
  Result := OSSL_PARAM_construct_int64(key, buf);
end;

function Load_OSSL_PARAM_construct_uint64(key: PAnsiChar; buf: POpenSSL_C_UINT64): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_uint64 := LoadLibCryptoFunction('OSSL_PARAM_construct_uint64');
  if not assigned(OSSL_PARAM_construct_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_uint64');
  Result := OSSL_PARAM_construct_uint64(key, buf);
end;

function Load_OSSL_PARAM_construct_size_t(key: PAnsiChar; buf: POpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_size_t := LoadLibCryptoFunction('OSSL_PARAM_construct_size_t');
  if not assigned(OSSL_PARAM_construct_size_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_size_t');
  Result := OSSL_PARAM_construct_size_t(key, buf);
end;

function Load_OSSL_PARAM_construct_time_t(key: PAnsiChar; buf: POpenSSL_C_TIMET): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_time_t := LoadLibCryptoFunction('OSSL_PARAM_construct_time_t');
  if not assigned(OSSL_PARAM_construct_time_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_time_t');
  Result := OSSL_PARAM_construct_time_t(key, buf);
end;

function Load_OSSL_PARAM_construct_BN(key: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_BN := LoadLibCryptoFunction('OSSL_PARAM_construct_BN');
  if not assigned(OSSL_PARAM_construct_BN) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_BN');
  Result := OSSL_PARAM_construct_BN(key, buf, bsize);
end;

function Load_OSSL_PARAM_construct_double(key: PAnsiChar; buf: POpenSSL_C_DOUBLE): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_double := LoadLibCryptoFunction('OSSL_PARAM_construct_double');
  if not assigned(OSSL_PARAM_construct_double) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_double');
  Result := OSSL_PARAM_construct_double(key, buf);
end;

function Load_OSSL_PARAM_construct_utf8_string(key: PAnsiChar; buf: PAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_utf8_string := LoadLibCryptoFunction('OSSL_PARAM_construct_utf8_string');
  if not assigned(OSSL_PARAM_construct_utf8_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_utf8_string');
  Result := OSSL_PARAM_construct_utf8_string(key, buf, bsize);
end;

function Load_OSSL_PARAM_construct_utf8_ptr(key: PAnsiChar; buf: PPAnsiChar; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_utf8_ptr := LoadLibCryptoFunction('OSSL_PARAM_construct_utf8_ptr');
  if not assigned(OSSL_PARAM_construct_utf8_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_utf8_ptr');
  Result := OSSL_PARAM_construct_utf8_ptr(key, buf, bsize);
end;

function Load_OSSL_PARAM_construct_octet_string(key: PAnsiChar; buf: pointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_octet_string := LoadLibCryptoFunction('OSSL_PARAM_construct_octet_string');
  if not assigned(OSSL_PARAM_construct_octet_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_octet_string');
  Result := OSSL_PARAM_construct_octet_string(key, buf, bsize);
end;

function Load_OSSL_PARAM_construct_octet_ptr(key: PAnsiChar; buf: Ppointer; bsize: TOpenSSL_C_SIZET): TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_octet_ptr := LoadLibCryptoFunction('OSSL_PARAM_construct_octet_ptr');
  if not assigned(OSSL_PARAM_construct_octet_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_octet_ptr');
  Result := OSSL_PARAM_construct_octet_ptr(key, buf, bsize);
end;

function Load_OSSL_PARAM_construct_end: TOSSL_PARAM; cdecl;
begin
  OSSL_PARAM_construct_end := LoadLibCryptoFunction('OSSL_PARAM_construct_end');
  if not assigned(OSSL_PARAM_construct_end) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_construct_end');
  Result := OSSL_PARAM_construct_end;
end;

function Load_OSSL_PARAM_allocate_from_text(to_: POSSL_PARAM; paramdefs: POSSL_PARAM; key: PAnsiChar; value: PAnsiChar; value_n: TOpenSSL_C_SIZET; found: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_allocate_from_text := LoadLibCryptoFunction('OSSL_PARAM_allocate_from_text');
  if not assigned(OSSL_PARAM_allocate_from_text) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_allocate_from_text');
  Result := OSSL_PARAM_allocate_from_text(to_, paramdefs, key, value, value_n, found);
end;

function Load_OSSL_PARAM_print_to_bio(params: POSSL_PARAM; bio: PBIO; print_values: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_print_to_bio := LoadLibCryptoFunction('OSSL_PARAM_print_to_bio');
  if not assigned(OSSL_PARAM_print_to_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_print_to_bio');
  Result := OSSL_PARAM_print_to_bio(params, bio, print_values);
end;

function Load_OSSL_PARAM_get_int(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_int := LoadLibCryptoFunction('OSSL_PARAM_get_int');
  if not assigned(OSSL_PARAM_get_int) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_int');
  Result := OSSL_PARAM_get_int(p, val);
end;

function Load_OSSL_PARAM_get_uint(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_uint := LoadLibCryptoFunction('OSSL_PARAM_get_uint');
  if not assigned(OSSL_PARAM_get_uint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_uint');
  Result := OSSL_PARAM_get_uint(p, val);
end;

function Load_OSSL_PARAM_get_long(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_long := LoadLibCryptoFunction('OSSL_PARAM_get_long');
  if not assigned(OSSL_PARAM_get_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_long');
  Result := OSSL_PARAM_get_long(p, val);
end;

function Load_OSSL_PARAM_get_ulong(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_ulong := LoadLibCryptoFunction('OSSL_PARAM_get_ulong');
  if not assigned(OSSL_PARAM_get_ulong) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_ulong');
  Result := OSSL_PARAM_get_ulong(p, val);
end;

function Load_OSSL_PARAM_get_int32(p: POSSL_PARAM; val: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_int32 := LoadLibCryptoFunction('OSSL_PARAM_get_int32');
  if not assigned(OSSL_PARAM_get_int32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_int32');
  Result := OSSL_PARAM_get_int32(p, val);
end;

function Load_OSSL_PARAM_get_uint32(p: POSSL_PARAM; val: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_uint32 := LoadLibCryptoFunction('OSSL_PARAM_get_uint32');
  if not assigned(OSSL_PARAM_get_uint32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_uint32');
  Result := OSSL_PARAM_get_uint32(p, val);
end;

function Load_OSSL_PARAM_get_int64(p: POSSL_PARAM; val: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_int64 := LoadLibCryptoFunction('OSSL_PARAM_get_int64');
  if not assigned(OSSL_PARAM_get_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_int64');
  Result := OSSL_PARAM_get_int64(p, val);
end;

function Load_OSSL_PARAM_get_uint64(p: POSSL_PARAM; val: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_uint64 := LoadLibCryptoFunction('OSSL_PARAM_get_uint64');
  if not assigned(OSSL_PARAM_get_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_uint64');
  Result := OSSL_PARAM_get_uint64(p, val);
end;

function Load_OSSL_PARAM_get_size_t(p: POSSL_PARAM; val: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_size_t := LoadLibCryptoFunction('OSSL_PARAM_get_size_t');
  if not assigned(OSSL_PARAM_get_size_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_size_t');
  Result := OSSL_PARAM_get_size_t(p, val);
end;

function Load_OSSL_PARAM_get_time_t(p: POSSL_PARAM; val: POpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_time_t := LoadLibCryptoFunction('OSSL_PARAM_get_time_t');
  if not assigned(OSSL_PARAM_get_time_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_time_t');
  Result := OSSL_PARAM_get_time_t(p, val);
end;

function Load_OSSL_PARAM_set_int(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_int := LoadLibCryptoFunction('OSSL_PARAM_set_int');
  if not assigned(OSSL_PARAM_set_int) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_int');
  Result := OSSL_PARAM_set_int(p, val);
end;

function Load_OSSL_PARAM_set_uint(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_uint := LoadLibCryptoFunction('OSSL_PARAM_set_uint');
  if not assigned(OSSL_PARAM_set_uint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_uint');
  Result := OSSL_PARAM_set_uint(p, val);
end;

function Load_OSSL_PARAM_set_long(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_long := LoadLibCryptoFunction('OSSL_PARAM_set_long');
  if not assigned(OSSL_PARAM_set_long) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_long');
  Result := OSSL_PARAM_set_long(p, val);
end;

function Load_OSSL_PARAM_set_ulong(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_ulong := LoadLibCryptoFunction('OSSL_PARAM_set_ulong');
  if not assigned(OSSL_PARAM_set_ulong) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_ulong');
  Result := OSSL_PARAM_set_ulong(p, val);
end;

function Load_OSSL_PARAM_set_int32(p: POSSL_PARAM; val: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_int32 := LoadLibCryptoFunction('OSSL_PARAM_set_int32');
  if not assigned(OSSL_PARAM_set_int32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_int32');
  Result := OSSL_PARAM_set_int32(p, val);
end;

function Load_OSSL_PARAM_set_uint32(p: POSSL_PARAM; val: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_uint32 := LoadLibCryptoFunction('OSSL_PARAM_set_uint32');
  if not assigned(OSSL_PARAM_set_uint32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_uint32');
  Result := OSSL_PARAM_set_uint32(p, val);
end;

function Load_OSSL_PARAM_set_int64(p: POSSL_PARAM; val: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_int64 := LoadLibCryptoFunction('OSSL_PARAM_set_int64');
  if not assigned(OSSL_PARAM_set_int64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_int64');
  Result := OSSL_PARAM_set_int64(p, val);
end;

function Load_OSSL_PARAM_set_uint64(p: POSSL_PARAM; val: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_uint64 := LoadLibCryptoFunction('OSSL_PARAM_set_uint64');
  if not assigned(OSSL_PARAM_set_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_uint64');
  Result := OSSL_PARAM_set_uint64(p, val);
end;

function Load_OSSL_PARAM_set_size_t(p: POSSL_PARAM; val: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_size_t := LoadLibCryptoFunction('OSSL_PARAM_set_size_t');
  if not assigned(OSSL_PARAM_set_size_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_size_t');
  Result := OSSL_PARAM_set_size_t(p, val);
end;

function Load_OSSL_PARAM_set_time_t(p: POSSL_PARAM; val: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_time_t := LoadLibCryptoFunction('OSSL_PARAM_set_time_t');
  if not assigned(OSSL_PARAM_set_time_t) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_time_t');
  Result := OSSL_PARAM_set_time_t(p, val);
end;

function Load_OSSL_PARAM_get_double(p: POSSL_PARAM; val: POpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_double := LoadLibCryptoFunction('OSSL_PARAM_get_double');
  if not assigned(OSSL_PARAM_get_double) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_double');
  Result := OSSL_PARAM_get_double(p, val);
end;

function Load_OSSL_PARAM_set_double(p: POSSL_PARAM; val: TOpenSSL_C_DOUBLE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_double := LoadLibCryptoFunction('OSSL_PARAM_set_double');
  if not assigned(OSSL_PARAM_set_double) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_double');
  Result := OSSL_PARAM_set_double(p, val);
end;

function Load_OSSL_PARAM_get_BN(p: POSSL_PARAM; val: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_BN := LoadLibCryptoFunction('OSSL_PARAM_get_BN');
  if not assigned(OSSL_PARAM_get_BN) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_BN');
  Result := OSSL_PARAM_get_BN(p, val);
end;

function Load_OSSL_PARAM_set_BN(p: POSSL_PARAM; val: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_BN := LoadLibCryptoFunction('OSSL_PARAM_set_BN');
  if not assigned(OSSL_PARAM_set_BN) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_BN');
  Result := OSSL_PARAM_set_BN(p, val);
end;

function Load_OSSL_PARAM_get_utf8_string(p: POSSL_PARAM; val: PPAnsiChar; max_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_utf8_string := LoadLibCryptoFunction('OSSL_PARAM_get_utf8_string');
  if not assigned(OSSL_PARAM_get_utf8_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_utf8_string');
  Result := OSSL_PARAM_get_utf8_string(p, val, max_len);
end;

function Load_OSSL_PARAM_set_utf8_string(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_utf8_string := LoadLibCryptoFunction('OSSL_PARAM_set_utf8_string');
  if not assigned(OSSL_PARAM_set_utf8_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_utf8_string');
  Result := OSSL_PARAM_set_utf8_string(p, val);
end;

function Load_OSSL_PARAM_get_octet_string(p: POSSL_PARAM; val: Ppointer; max_len: TOpenSSL_C_SIZET; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_octet_string := LoadLibCryptoFunction('OSSL_PARAM_get_octet_string');
  if not assigned(OSSL_PARAM_get_octet_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_octet_string');
  Result := OSSL_PARAM_get_octet_string(p, val, max_len, used_len);
end;

function Load_OSSL_PARAM_set_octet_string(p: POSSL_PARAM; val: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_octet_string := LoadLibCryptoFunction('OSSL_PARAM_set_octet_string');
  if not assigned(OSSL_PARAM_set_octet_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_octet_string');
  Result := OSSL_PARAM_set_octet_string(p, val, len);
end;

function Load_OSSL_PARAM_get_utf8_ptr(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_utf8_ptr := LoadLibCryptoFunction('OSSL_PARAM_get_utf8_ptr');
  if not assigned(OSSL_PARAM_get_utf8_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_utf8_ptr');
  Result := OSSL_PARAM_get_utf8_ptr(p, val);
end;

function Load_OSSL_PARAM_set_utf8_ptr(p: POSSL_PARAM; val: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_utf8_ptr := LoadLibCryptoFunction('OSSL_PARAM_set_utf8_ptr');
  if not assigned(OSSL_PARAM_set_utf8_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_utf8_ptr');
  Result := OSSL_PARAM_set_utf8_ptr(p, val);
end;

function Load_OSSL_PARAM_get_octet_ptr(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_octet_ptr := LoadLibCryptoFunction('OSSL_PARAM_get_octet_ptr');
  if not assigned(OSSL_PARAM_get_octet_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_octet_ptr');
  Result := OSSL_PARAM_get_octet_ptr(p, val, used_len);
end;

function Load_OSSL_PARAM_set_octet_ptr(p: POSSL_PARAM; val: pointer; used_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_set_octet_ptr := LoadLibCryptoFunction('OSSL_PARAM_set_octet_ptr');
  if not assigned(OSSL_PARAM_set_octet_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_octet_ptr');
  Result := OSSL_PARAM_set_octet_ptr(p, val, used_len);
end;

function Load_OSSL_PARAM_get_utf8_string_ptr(p: POSSL_PARAM; val: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_utf8_string_ptr := LoadLibCryptoFunction('OSSL_PARAM_get_utf8_string_ptr');
  if not assigned(OSSL_PARAM_get_utf8_string_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_utf8_string_ptr');
  Result := OSSL_PARAM_get_utf8_string_ptr(p, val);
end;

function Load_OSSL_PARAM_get_octet_string_ptr(p: POSSL_PARAM; val: Ppointer; used_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_get_octet_string_ptr := LoadLibCryptoFunction('OSSL_PARAM_get_octet_string_ptr');
  if not assigned(OSSL_PARAM_get_octet_string_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_get_octet_string_ptr');
  Result := OSSL_PARAM_get_octet_string_ptr(p, val, used_len);
end;

function Load_OSSL_PARAM_modified(p: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_PARAM_modified := LoadLibCryptoFunction('OSSL_PARAM_modified');
  if not assigned(OSSL_PARAM_modified) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_modified');
  Result := OSSL_PARAM_modified(p);
end;

procedure Load_OSSL_PARAM_set_all_unmodified(p: POSSL_PARAM); cdecl;
begin
  OSSL_PARAM_set_all_unmodified := LoadLibCryptoFunction('OSSL_PARAM_set_all_unmodified');
  if not assigned(OSSL_PARAM_set_all_unmodified) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_set_all_unmodified');
  OSSL_PARAM_set_all_unmodified(p);
end;

function Load_OSSL_PARAM_dup(p: POSSL_PARAM): POSSL_PARAM; cdecl;
begin
  OSSL_PARAM_dup := LoadLibCryptoFunction('OSSL_PARAM_dup');
  if not assigned(OSSL_PARAM_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_dup');
  Result := OSSL_PARAM_dup(p);
end;

function Load_OSSL_PARAM_merge(p1: POSSL_PARAM; p2: POSSL_PARAM): POSSL_PARAM; cdecl;
begin
  OSSL_PARAM_merge := LoadLibCryptoFunction('OSSL_PARAM_merge');
  if not assigned(OSSL_PARAM_merge) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_merge');
  Result := OSSL_PARAM_merge(p1, p2);
end;

procedure Load_OSSL_PARAM_free(p: POSSL_PARAM); cdecl;
begin
  OSSL_PARAM_free := LoadLibCryptoFunction('OSSL_PARAM_free');
  if not assigned(OSSL_PARAM_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_PARAM_free');
  OSSL_PARAM_free(p);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_PARAM_locate := Load_OSSL_PARAM_locate;
  OSSL_PARAM_locate_const := Load_OSSL_PARAM_locate_const;
  OSSL_PARAM_construct_int := Load_OSSL_PARAM_construct_int;
  OSSL_PARAM_construct_uint := Load_OSSL_PARAM_construct_uint;
  OSSL_PARAM_construct_long := Load_OSSL_PARAM_construct_long;
  OSSL_PARAM_construct_ulong := Load_OSSL_PARAM_construct_ulong;
  OSSL_PARAM_construct_int32 := Load_OSSL_PARAM_construct_int32;
  OSSL_PARAM_construct_uint32 := Load_OSSL_PARAM_construct_uint32;
  OSSL_PARAM_construct_int64 := Load_OSSL_PARAM_construct_int64;
  OSSL_PARAM_construct_uint64 := Load_OSSL_PARAM_construct_uint64;
  OSSL_PARAM_construct_size_t := Load_OSSL_PARAM_construct_size_t;
  OSSL_PARAM_construct_time_t := Load_OSSL_PARAM_construct_time_t;
  OSSL_PARAM_construct_BN := Load_OSSL_PARAM_construct_BN;
  OSSL_PARAM_construct_double := Load_OSSL_PARAM_construct_double;
  OSSL_PARAM_construct_utf8_string := Load_OSSL_PARAM_construct_utf8_string;
  OSSL_PARAM_construct_utf8_ptr := Load_OSSL_PARAM_construct_utf8_ptr;
  OSSL_PARAM_construct_octet_string := Load_OSSL_PARAM_construct_octet_string;
  OSSL_PARAM_construct_octet_ptr := Load_OSSL_PARAM_construct_octet_ptr;
  OSSL_PARAM_construct_end := Load_OSSL_PARAM_construct_end;
  OSSL_PARAM_allocate_from_text := Load_OSSL_PARAM_allocate_from_text;
  OSSL_PARAM_print_to_bio := Load_OSSL_PARAM_print_to_bio;
  OSSL_PARAM_get_int := Load_OSSL_PARAM_get_int;
  OSSL_PARAM_get_uint := Load_OSSL_PARAM_get_uint;
  OSSL_PARAM_get_long := Load_OSSL_PARAM_get_long;
  OSSL_PARAM_get_ulong := Load_OSSL_PARAM_get_ulong;
  OSSL_PARAM_get_int32 := Load_OSSL_PARAM_get_int32;
  OSSL_PARAM_get_uint32 := Load_OSSL_PARAM_get_uint32;
  OSSL_PARAM_get_int64 := Load_OSSL_PARAM_get_int64;
  OSSL_PARAM_get_uint64 := Load_OSSL_PARAM_get_uint64;
  OSSL_PARAM_get_size_t := Load_OSSL_PARAM_get_size_t;
  OSSL_PARAM_get_time_t := Load_OSSL_PARAM_get_time_t;
  OSSL_PARAM_set_int := Load_OSSL_PARAM_set_int;
  OSSL_PARAM_set_uint := Load_OSSL_PARAM_set_uint;
  OSSL_PARAM_set_long := Load_OSSL_PARAM_set_long;
  OSSL_PARAM_set_ulong := Load_OSSL_PARAM_set_ulong;
  OSSL_PARAM_set_int32 := Load_OSSL_PARAM_set_int32;
  OSSL_PARAM_set_uint32 := Load_OSSL_PARAM_set_uint32;
  OSSL_PARAM_set_int64 := Load_OSSL_PARAM_set_int64;
  OSSL_PARAM_set_uint64 := Load_OSSL_PARAM_set_uint64;
  OSSL_PARAM_set_size_t := Load_OSSL_PARAM_set_size_t;
  OSSL_PARAM_set_time_t := Load_OSSL_PARAM_set_time_t;
  OSSL_PARAM_get_double := Load_OSSL_PARAM_get_double;
  OSSL_PARAM_set_double := Load_OSSL_PARAM_set_double;
  OSSL_PARAM_get_BN := Load_OSSL_PARAM_get_BN;
  OSSL_PARAM_set_BN := Load_OSSL_PARAM_set_BN;
  OSSL_PARAM_get_utf8_string := Load_OSSL_PARAM_get_utf8_string;
  OSSL_PARAM_set_utf8_string := Load_OSSL_PARAM_set_utf8_string;
  OSSL_PARAM_get_octet_string := Load_OSSL_PARAM_get_octet_string;
  OSSL_PARAM_set_octet_string := Load_OSSL_PARAM_set_octet_string;
  OSSL_PARAM_get_utf8_ptr := Load_OSSL_PARAM_get_utf8_ptr;
  OSSL_PARAM_set_utf8_ptr := Load_OSSL_PARAM_set_utf8_ptr;
  OSSL_PARAM_get_octet_ptr := Load_OSSL_PARAM_get_octet_ptr;
  OSSL_PARAM_set_octet_ptr := Load_OSSL_PARAM_set_octet_ptr;
  OSSL_PARAM_get_utf8_string_ptr := Load_OSSL_PARAM_get_utf8_string_ptr;
  OSSL_PARAM_get_octet_string_ptr := Load_OSSL_PARAM_get_octet_string_ptr;
  OSSL_PARAM_modified := Load_OSSL_PARAM_modified;
  OSSL_PARAM_set_all_unmodified := Load_OSSL_PARAM_set_all_unmodified;
  OSSL_PARAM_dup := Load_OSSL_PARAM_dup;
  OSSL_PARAM_merge := Load_OSSL_PARAM_merge;
  OSSL_PARAM_free := Load_OSSL_PARAM_free;
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



