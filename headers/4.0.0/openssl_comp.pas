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
  Generated from OpenSSL 4.0.0 Header File comp.h - Tue 19 May 14:32:10 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_comp.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_stack,openssl_crypto,openssl_comperr;


{* Copyright 2015-2024 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{ clang-format off }
{ clang-format on }
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
  function COMP_zlib_oneshot: PCOMP_METHOD; cdecl; external CLibCrypto name 'COMP_zlib_oneshot';
  function COMP_brotli: PCOMP_METHOD; cdecl; external CLibCrypto name 'COMP_brotli';
  function COMP_brotli_oneshot: PCOMP_METHOD; cdecl; external CLibCrypto name 'COMP_brotli_oneshot';
  function COMP_zstd: PCOMP_METHOD; cdecl; external CLibCrypto name 'COMP_zstd';
  function COMP_zstd_oneshot: PCOMP_METHOD; cdecl; external CLibCrypto name 'COMP_zstd_oneshot';
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
  {$EXTERNALSYM COMP_zlib_oneshot}
  {$EXTERNALSYM COMP_brotli}
  {$EXTERNALSYM COMP_brotli_oneshot}
  {$EXTERNALSYM COMP_zstd}
  {$EXTERNALSYM COMP_zstd_oneshot}
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
  function Load_COMP_zlib_oneshot: PCOMP_METHOD; cdecl;
  function Load_COMP_brotli: PCOMP_METHOD; cdecl;
  function Load_COMP_brotli_oneshot: PCOMP_METHOD; cdecl;
  function Load_COMP_zstd: PCOMP_METHOD; cdecl;
  function Load_COMP_zstd_oneshot: PCOMP_METHOD; cdecl;

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
  COMP_zlib_oneshot: function: PCOMP_METHOD; cdecl = Load_COMP_zlib_oneshot;
  COMP_brotli: function: PCOMP_METHOD; cdecl = Load_COMP_brotli;
  COMP_brotli_oneshot: function: PCOMP_METHOD; cdecl = Load_COMP_brotli_oneshot;
  COMP_zstd: function: PCOMP_METHOD; cdecl = Load_COMP_zstd;
  COMP_zstd_oneshot: function: PCOMP_METHOD; cdecl = Load_COMP_zstd_oneshot;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{# define  COMP_zlib_cleanup() while (0) continue}
    {$endif}
    {$ifdef OPENSSL_BIO_H}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function BIO_f_zlib: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_zlib';
  function BIO_f_brotli: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_brotli';
  function BIO_f_zstd: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_zstd';
      {$else}
  {$EXTERNALSYM BIO_f_zlib}
  {$EXTERNALSYM BIO_f_brotli}
  {$EXTERNALSYM BIO_f_zstd}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_BIO_f_zlib: PBIO_METHOD; cdecl;
  function Load_BIO_f_brotli: PBIO_METHOD; cdecl;
  function Load_BIO_f_zstd: PBIO_METHOD; cdecl;

var
  BIO_f_zlib: function: PBIO_METHOD; cdecl = Load_BIO_f_zlib;
  BIO_f_brotli: function: PBIO_METHOD; cdecl = Load_BIO_f_brotli;
  BIO_f_zstd: function: PBIO_METHOD; cdecl = Load_BIO_f_zstd;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}

type
  {Auto-generated forward references}
  Pssl_comp_st = ^TSSL_COMP;
  PPssl_comp_st = ^Pssl_comp_st;
  PSSL_COMP = ^TSSL_COMP;
  PPSSL_COMP = ^PSSL_COMP;
  Pstack_st_SSL_COMP = ^Tstack_st_SSL_COMP;
  PPstack_st_SSL_COMP = ^Pstack_st_SSL_COMP;
  Psk_SSL_COMP_compfunc = ^Tsk_SSL_COMP_compfunc;
  PPsk_SSL_COMP_compfunc = ^Psk_SSL_COMP_compfunc;
  Psk_SSL_COMP_freefunc = ^Tsk_SSL_COMP_freefunc;
  PPsk_SSL_COMP_freefunc = ^Psk_SSL_COMP_freefunc;
  Psk_SSL_COMP_copyfunc = ^Tsk_SSL_COMP_copyfunc;
  PPsk_SSL_COMP_copyfunc = ^Psk_SSL_COMP_copyfunc;
  {end of auto-generated forward references}

  Tssl_comp_st = record end;
  TSSL_COMP = Tssl_comp_st;
  { clang-format off }
  Tstack_st_SSL_COMP = record 
  end;
  Tsk_SSL_COMP_compfunc = function(a: PPSSL_COMP; b: PPSSL_COMP): TOpenSSL_C_INT; cdecl;
  Tsk_SSL_COMP_freefunc = procedure(a: PSSL_COMP); cdecl;
  Tsk_SSL_COMP_copyfunc = function(a: PSSL_COMP): PSSL_COMP; cdecl;


  procedure sk_SSL_COMP_freefunc_thunk(freefunc_arg: TOPENSSL_sk_freefunc; ptr: pointer); inline;

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = function(_param1: pointer; _param2: pointer): TOpenSSL_C_INT;


  function sk_SSL_COMP_cmpfunc_thunk(cmp: TFuncType000; a: pointer; b: pointer): TOpenSSL_C_INT; inline;
  function ossl_check_SSL_COMP_type(ptr: PSSL_COMP): PSSL_COMP{Has C Attribute: unused}; inline;
  function ossl_check_const_SSL_COMP_sk_type(sk: Pstack_st_SSL_COMP): POPENSSL_STACK{Has C Attribute: unused}; inline;
  function ossl_check_SSL_COMP_sk_type(sk: Pstack_st_SSL_COMP): POPENSSL_STACK{Has C Attribute: unused}; inline;
  function ossl_check_SSL_COMP_compfunc_type(cmp: Tsk_SSL_COMP_compfunc): TOPENSSL_sk_compfunc{Has C Attribute: unused}; inline;
  function ossl_check_SSL_COMP_copyfunc_type(cpy: Tsk_SSL_COMP_copyfunc): TOPENSSL_sk_copyfunc{Has C Attribute: unused}; inline;
  function ossl_check_SSL_COMP_freefunc_type(fr: Tsk_SSL_COMP_freefunc): TOPENSSL_sk_freefunc{Has C Attribute: unused}; inline;
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function sk_SSL_COMP_num(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  function sk_SSL_COMP_value(_para: Pstack_st_SSL_COMP; _para2: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  function sk_SSL_COMP_new(cmp: Tsk_SSL_COMP_compfunc): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  function sk_SSL_COMP_new_null: Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  function sk_SSL_COMP_new_reserve(cmp: Tsk_SSL_COMP_compfunc; n: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_new_reserve';
  function sk_SSL_COMP_reserve(_para: Pstack_st_SSL_COMP; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_reserve';
  function sk_SSL_COMP_free(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  function sk_SSL_COMP_zero(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_zero';
  function sk_SSL_COMP_delete(st: Pstack_st_SSL_COMP; loc: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_delete';
  function sk_SSL_COMP_delete_ptr(st: Pstack_st_SSL_COMP; ptr: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_delete_ptr';
  function sk_SSL_COMP_push(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  function sk_SSL_COMP_unshift(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_unshift';
  function sk_SSL_COMP_pop(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_pop';
  function sk_SSL_COMP_shift(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_shift';
  procedure sk_SSL_COMP_pop_free(st: Pstack_st_SSL_COMP; func: Tsk_SSL_COMP_freefunc); cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  function sk_SSL_COMP_insert(st: Pstack_st_SSL_COMP; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_insert';
  function sk_SSL_COMP_set(st: Pstack_st_SSL_COMP; i: TOpenSSL_C_INT; data: pointer): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_set';
  function sk_SSL_COMP_find(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  function sk_SSL_COMP_find_ex(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find_ex';
  function sk_SSL_COMP_find_all(st: Pstack_st_SSL_COMP; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find_all';
  function sk_SSL_COMP_sort(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_sort';
  function sk_SSL_COMP_is_sorted(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_is_sorted';
  function sk_SSL_COMP_dup(st: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  function sk_SSL_COMP_deep_copy(st: Pstack_st_SSL_COMP; c: Tsk_SSL_COMP_compfunc; f: Tsk_SSL_COMP_freefunc): Pstack_st_SSL_COMP; cdecl; external CLibCrypto name 'OPENSSL_sk_deep_copy';
  function sk_SSL_COMP_set_cmp_func(st: Pstack_st_SSL_COMP; cmp: Tsk_SSL_COMP_compfunc): Tsk_SSL_COMP_compfunc; cdecl; external CLibCrypto name 'OPENSSL_sk_set_cmp_func';
  { clang-format on }
  {$else}
  {$EXTERNALSYM sk_SSL_COMP_num}
  {$EXTERNALSYM sk_SSL_COMP_value}
  {$EXTERNALSYM sk_SSL_COMP_new}
  {$EXTERNALSYM sk_SSL_COMP_new_null}
  {$EXTERNALSYM sk_SSL_COMP_new_reserve}
  {$EXTERNALSYM sk_SSL_COMP_reserve}
  {$EXTERNALSYM sk_SSL_COMP_free}
  {$EXTERNALSYM sk_SSL_COMP_zero}
  {$EXTERNALSYM sk_SSL_COMP_delete}
  {$EXTERNALSYM sk_SSL_COMP_delete_ptr}
  {$EXTERNALSYM sk_SSL_COMP_push}
  {$EXTERNALSYM sk_SSL_COMP_unshift}
  {$EXTERNALSYM sk_SSL_COMP_pop}
  {$EXTERNALSYM sk_SSL_COMP_shift}
  {$EXTERNALSYM sk_SSL_COMP_pop_free}
  {$EXTERNALSYM sk_SSL_COMP_insert}
  {$EXTERNALSYM sk_SSL_COMP_set}
  {$EXTERNALSYM sk_SSL_COMP_find}
  {$EXTERNALSYM sk_SSL_COMP_find_ex}
  {$EXTERNALSYM sk_SSL_COMP_find_all}
  {$EXTERNALSYM sk_SSL_COMP_sort}
  {$EXTERNALSYM sk_SSL_COMP_is_sorted}
  {$EXTERNALSYM sk_SSL_COMP_dup}
  {$EXTERNALSYM sk_SSL_COMP_deep_copy}
  {$EXTERNALSYM sk_SSL_COMP_set_cmp_func}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_sk_SSL_COMP_num(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_value(_para: Pstack_st_SSL_COMP; _para2: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_new(cmp: Tsk_SSL_COMP_compfunc): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_new_null: Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_new_reserve(cmp: Tsk_SSL_COMP_compfunc; n: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_reserve(_para: Pstack_st_SSL_COMP; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_free(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_zero(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_delete(st: Pstack_st_SSL_COMP; loc: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_delete_ptr(st: Pstack_st_SSL_COMP; ptr: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_push(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_unshift(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_pop(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_shift(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
  procedure Load_sk_SSL_COMP_pop_free(st: Pstack_st_SSL_COMP; func: Tsk_SSL_COMP_freefunc); cdecl;
  function Load_sk_SSL_COMP_insert(st: Pstack_st_SSL_COMP; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_set(st: Pstack_st_SSL_COMP; i: TOpenSSL_C_INT; data: pointer): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_find(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_find_ex(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_find_all(st: Pstack_st_SSL_COMP; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_sort(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_is_sorted(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
  function Load_sk_SSL_COMP_dup(st: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_deep_copy(st: Pstack_st_SSL_COMP; c: Tsk_SSL_COMP_compfunc; f: Tsk_SSL_COMP_freefunc): Pstack_st_SSL_COMP; cdecl;
  function Load_sk_SSL_COMP_set_cmp_func(st: Pstack_st_SSL_COMP; cmp: Tsk_SSL_COMP_compfunc): Tsk_SSL_COMP_compfunc; cdecl;

var
  sk_SSL_COMP_num: function(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_num;
  sk_SSL_COMP_value: function(_para: Pstack_st_SSL_COMP; _para2: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_value;
  sk_SSL_COMP_new: function(cmp: Tsk_SSL_COMP_compfunc): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_new;
  sk_SSL_COMP_new_null: function: Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_new_null;
  sk_SSL_COMP_new_reserve: function(cmp: Tsk_SSL_COMP_compfunc; n: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_new_reserve;
  sk_SSL_COMP_reserve: function(_para: Pstack_st_SSL_COMP; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_reserve;
  sk_SSL_COMP_free: function(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_free;
  sk_SSL_COMP_zero: function(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_zero;
  sk_SSL_COMP_delete: function(st: Pstack_st_SSL_COMP; loc: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_delete;
  sk_SSL_COMP_delete_ptr: function(st: Pstack_st_SSL_COMP; ptr: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_delete_ptr;
  sk_SSL_COMP_push: function(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_push;
  sk_SSL_COMP_unshift: function(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_unshift;
  sk_SSL_COMP_pop: function(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_pop;
  sk_SSL_COMP_shift: function(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_shift;
  sk_SSL_COMP_pop_free: procedure(st: Pstack_st_SSL_COMP; func: Tsk_SSL_COMP_freefunc); cdecl = Load_sk_SSL_COMP_pop_free;
  sk_SSL_COMP_insert: function(st: Pstack_st_SSL_COMP; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_insert;
  sk_SSL_COMP_set: function(st: Pstack_st_SSL_COMP; i: TOpenSSL_C_INT; data: pointer): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_set;
  sk_SSL_COMP_find: function(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_find;
  sk_SSL_COMP_find_ex: function(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_find_ex;
  sk_SSL_COMP_find_all: function(st: Pstack_st_SSL_COMP; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_find_all;
  sk_SSL_COMP_sort: function(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_sort;
  sk_SSL_COMP_is_sorted: function(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl = Load_sk_SSL_COMP_is_sorted;
  sk_SSL_COMP_dup: function(st: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_dup;
  sk_SSL_COMP_deep_copy: function(st: Pstack_st_SSL_COMP; c: Tsk_SSL_COMP_compfunc; f: Tsk_SSL_COMP_freefunc): Pstack_st_SSL_COMP; cdecl = Load_sk_SSL_COMP_deep_copy;
  sk_SSL_COMP_set_cmp_func: function(st: Pstack_st_SSL_COMP; cmp: Tsk_SSL_COMP_compfunc): Tsk_SSL_COMP_compfunc; cdecl = Load_sk_SSL_COMP_set_cmp_func;
  { clang-format on }
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

procedure sk_SSL_COMP_freefunc_thunk(freefunc_arg: TOPENSSL_sk_freefunc; ptr: pointer); inline;
begin
  raise Exception.Create('Unable to translate C Function "sk_SSL_COMP_freefunc_thunk"');

{Error: Line 69: Syntax Error parsing " sk_SSL_COMP_freefunc freefunc = (sk_SSL_COMP_freefunc)freefunc_arg; freefunc((SSL_COMP *)ptr); 
"

 sk_SSL_COMP_freefunc freefunc = (sk_SSL_COMP_freefunc)freefunc_arg; freefunc((SSL_COMP *)ptr); }
end;

function sk_SSL_COMP_cmpfunc_thunk(cmp: TFuncType000; a: pointer; b: pointer): TOpenSSL_C_INT; inline;
begin
  raise Exception.Create('Unable to translate C Function "sk_SSL_COMP_cmpfunc_thunk"');

{Error: Line 69: Syntax Error parsing " int (*realcmp)(const SSL_COMP *const *a, const SSL_COMP *const *b) = (int (*)(const SSL_COMP 
*const *a, const SSL_COMP *const *b))(cmp); const SSL_COMP *const *at = (const SSL_COMP *const *)a; const SSL_COMP *const *bt = 
(const SSL_COMP *const *)b; return realcmp(at, bt); "

 int (*realcmp)(const SSL_COMP *const *a, const SSL_COMP *const *b) = (int (*)(const SSL_COMP *const *a, const SSL_COMP *const 
*b))(cmp); const SSL_COMP *const *at = (const SSL_COMP *const *)a; const SSL_COMP *const *bt = (const SSL_COMP *const *)b; return 
realcmp(at, bt); }
end;

function ossl_check_SSL_COMP_type(ptr: PSSL_COMP): PSSL_COMP{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_SSL_COMP_sk_type(sk: Pstack_st_SSL_COMP): POPENSSL_STACK{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STACK(sk);
end;

function ossl_check_SSL_COMP_sk_type(sk: Pstack_st_SSL_COMP): POPENSSL_STACK{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STACK(sk);
end;

function ossl_check_SSL_COMP_compfunc_type(cmp: Tsk_SSL_COMP_compfunc): TOPENSSL_sk_compfunc{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_sk_compfunc(cmp);
end;

function ossl_check_SSL_COMP_copyfunc_type(cpy: Tsk_SSL_COMP_copyfunc): TOPENSSL_sk_copyfunc{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_sk_copyfunc(cpy);
end;

function ossl_check_SSL_COMP_freefunc_type(fr: Tsk_SSL_COMP_freefunc): TOPENSSL_sk_freefunc{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_sk_freefunc(fr);
end;

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

function Load_COMP_zlib_oneshot: PCOMP_METHOD; cdecl;
begin
  COMP_zlib_oneshot := LoadLibCryptoFunction('COMP_zlib_oneshot');
  if not assigned(COMP_zlib_oneshot) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_zlib_oneshot');
  Result := COMP_zlib_oneshot;
end;

function Load_COMP_brotli: PCOMP_METHOD; cdecl;
begin
  COMP_brotli := LoadLibCryptoFunction('COMP_brotli');
  if not assigned(COMP_brotli) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_brotli');
  Result := COMP_brotli;
end;

function Load_COMP_brotli_oneshot: PCOMP_METHOD; cdecl;
begin
  COMP_brotli_oneshot := LoadLibCryptoFunction('COMP_brotli_oneshot');
  if not assigned(COMP_brotli_oneshot) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_brotli_oneshot');
  Result := COMP_brotli_oneshot;
end;

function Load_COMP_zstd: PCOMP_METHOD; cdecl;
begin
  COMP_zstd := LoadLibCryptoFunction('COMP_zstd');
  if not assigned(COMP_zstd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_zstd');
  Result := COMP_zstd;
end;

function Load_COMP_zstd_oneshot: PCOMP_METHOD; cdecl;
begin
  COMP_zstd_oneshot := LoadLibCryptoFunction('COMP_zstd_oneshot');
  if not assigned(COMP_zstd_oneshot) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_zstd_oneshot');
  Result := COMP_zstd_oneshot;
end;

    {$ifdef OPENSSL_BIO_H}
function Load_BIO_f_zlib: PBIO_METHOD; cdecl;
begin
  BIO_f_zlib := LoadLibCryptoFunction('BIO_f_zlib');
  if not assigned(BIO_f_zlib) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_zlib');
  Result := BIO_f_zlib;
end;

function Load_BIO_f_brotli: PBIO_METHOD; cdecl;
begin
  BIO_f_brotli := LoadLibCryptoFunction('BIO_f_brotli');
  if not assigned(BIO_f_brotli) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_brotli');
  Result := BIO_f_brotli;
end;

function Load_BIO_f_zstd: PBIO_METHOD; cdecl;
begin
  BIO_f_zstd := LoadLibCryptoFunction('BIO_f_zstd');
  if not assigned(BIO_f_zstd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_zstd');
  Result := BIO_f_zstd;
end;

    {$endif} {OPENSSL_BIO_H}
{$endif} { OPENSSL_NO_COMP}
function Load_sk_SSL_COMP_num(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_num := LoadLibCryptoFunction('OPENSSL_sk_num');
  if not assigned(sk_SSL_COMP_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_num');
  Result := sk_SSL_COMP_num(_para);
end;

function Load_sk_SSL_COMP_value(_para: Pstack_st_SSL_COMP; _para2: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_value := LoadLibCryptoFunction('OPENSSL_sk_value');
  if not assigned(sk_SSL_COMP_value) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_value');
  Result := sk_SSL_COMP_value(_para, _para2);
end;

function Load_sk_SSL_COMP_new(cmp: Tsk_SSL_COMP_compfunc): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_new := LoadLibCryptoFunction('OPENSSL_sk_new');
  if not assigned(sk_SSL_COMP_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new');
  Result := sk_SSL_COMP_new(cmp);
end;

function Load_sk_SSL_COMP_new_null: Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_new_null := LoadLibCryptoFunction('OPENSSL_sk_new_null');
  if not assigned(sk_SSL_COMP_new_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_null');
  Result := sk_SSL_COMP_new_null;
end;

function Load_sk_SSL_COMP_new_reserve(cmp: Tsk_SSL_COMP_compfunc; n: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_new_reserve := LoadLibCryptoFunction('OPENSSL_sk_new_reserve');
  if not assigned(sk_SSL_COMP_new_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_reserve');
  Result := sk_SSL_COMP_new_reserve(cmp, n);
end;

function Load_sk_SSL_COMP_reserve(_para: Pstack_st_SSL_COMP; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_reserve := LoadLibCryptoFunction('OPENSSL_sk_reserve');
  if not assigned(sk_SSL_COMP_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_reserve');
  Result := sk_SSL_COMP_reserve(_para, n);
end;

function Load_sk_SSL_COMP_free(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_free := LoadLibCryptoFunction('OPENSSL_sk_free');
  if not assigned(sk_SSL_COMP_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_free');
  Result := sk_SSL_COMP_free(_para);
end;

function Load_sk_SSL_COMP_zero(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_zero := LoadLibCryptoFunction('OPENSSL_sk_zero');
  if not assigned(sk_SSL_COMP_zero) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_zero');
  Result := sk_SSL_COMP_zero(_para);
end;

function Load_sk_SSL_COMP_delete(st: Pstack_st_SSL_COMP; loc: TOpenSSL_C_INT): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_delete := LoadLibCryptoFunction('OPENSSL_sk_delete');
  if not assigned(sk_SSL_COMP_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete');
  Result := sk_SSL_COMP_delete(st, loc);
end;

function Load_sk_SSL_COMP_delete_ptr(st: Pstack_st_SSL_COMP; ptr: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_delete_ptr := LoadLibCryptoFunction('OPENSSL_sk_delete_ptr');
  if not assigned(sk_SSL_COMP_delete_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete_ptr');
  Result := sk_SSL_COMP_delete_ptr(st, ptr);
end;

function Load_sk_SSL_COMP_push(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_push := LoadLibCryptoFunction('OPENSSL_sk_push');
  if not assigned(sk_SSL_COMP_push) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_push');
  Result := sk_SSL_COMP_push(st, data);
end;

function Load_sk_SSL_COMP_unshift(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_unshift := LoadLibCryptoFunction('OPENSSL_sk_unshift');
  if not assigned(sk_SSL_COMP_unshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_unshift');
  Result := sk_SSL_COMP_unshift(st, data);
end;

function Load_sk_SSL_COMP_pop(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_pop := LoadLibCryptoFunction('OPENSSL_sk_pop');
  if not assigned(sk_SSL_COMP_pop) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop');
  Result := sk_SSL_COMP_pop(_para);
end;

function Load_sk_SSL_COMP_shift(_para: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_shift := LoadLibCryptoFunction('OPENSSL_sk_shift');
  if not assigned(sk_SSL_COMP_shift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_shift');
  Result := sk_SSL_COMP_shift(_para);
end;

procedure Load_sk_SSL_COMP_pop_free(st: Pstack_st_SSL_COMP; func: Tsk_SSL_COMP_freefunc); cdecl;
begin
  sk_SSL_COMP_pop_free := LoadLibCryptoFunction('OPENSSL_sk_pop_free');
  if not assigned(sk_SSL_COMP_pop_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop_free');
  sk_SSL_COMP_pop_free(st, func);
end;

function Load_sk_SSL_COMP_insert(st: Pstack_st_SSL_COMP; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_insert := LoadLibCryptoFunction('OPENSSL_sk_insert');
  if not assigned(sk_SSL_COMP_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_insert');
  Result := sk_SSL_COMP_insert(st, data, where);
end;

function Load_sk_SSL_COMP_set(st: Pstack_st_SSL_COMP; i: TOpenSSL_C_INT; data: pointer): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_set := LoadLibCryptoFunction('OPENSSL_sk_set');
  if not assigned(sk_SSL_COMP_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set');
  Result := sk_SSL_COMP_set(st, i, data);
end;

function Load_sk_SSL_COMP_find(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_find := LoadLibCryptoFunction('OPENSSL_sk_find');
  if not assigned(sk_SSL_COMP_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find');
  Result := sk_SSL_COMP_find(st, data);
end;

function Load_sk_SSL_COMP_find_ex(st: Pstack_st_SSL_COMP; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_find_ex := LoadLibCryptoFunction('OPENSSL_sk_find_ex');
  if not assigned(sk_SSL_COMP_find_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find_ex');
  Result := sk_SSL_COMP_find_ex(st, data);
end;

function Load_sk_SSL_COMP_find_all(st: Pstack_st_SSL_COMP; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_find_all := LoadLibCryptoFunction('OPENSSL_sk_find_all');
  if not assigned(sk_SSL_COMP_find_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find_all');
  Result := sk_SSL_COMP_find_all(st, data, pnum);
end;

function Load_sk_SSL_COMP_sort(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_sort := LoadLibCryptoFunction('OPENSSL_sk_sort');
  if not assigned(sk_SSL_COMP_sort) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_sort');
  Result := sk_SSL_COMP_sort(_para);
end;

function Load_sk_SSL_COMP_is_sorted(_para: Pstack_st_SSL_COMP): TOpenSSL_C_INT; cdecl;
begin
  sk_SSL_COMP_is_sorted := LoadLibCryptoFunction('OPENSSL_sk_is_sorted');
  if not assigned(sk_SSL_COMP_is_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_is_sorted');
  Result := sk_SSL_COMP_is_sorted(_para);
end;

function Load_sk_SSL_COMP_dup(st: Pstack_st_SSL_COMP): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_dup := LoadLibCryptoFunction('OPENSSL_sk_dup');
  if not assigned(sk_SSL_COMP_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_dup');
  Result := sk_SSL_COMP_dup(st);
end;

function Load_sk_SSL_COMP_deep_copy(st: Pstack_st_SSL_COMP; c: Tsk_SSL_COMP_compfunc; f: Tsk_SSL_COMP_freefunc): Pstack_st_SSL_COMP; cdecl;
begin
  sk_SSL_COMP_deep_copy := LoadLibCryptoFunction('OPENSSL_sk_deep_copy');
  if not assigned(sk_SSL_COMP_deep_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_deep_copy');
  Result := sk_SSL_COMP_deep_copy(st, c, f);
end;

function Load_sk_SSL_COMP_set_cmp_func(st: Pstack_st_SSL_COMP; cmp: Tsk_SSL_COMP_compfunc): Tsk_SSL_COMP_compfunc; cdecl;
begin
  sk_SSL_COMP_set_cmp_func := LoadLibCryptoFunction('OPENSSL_sk_set_cmp_func');
  if not assigned(sk_SSL_COMP_set_cmp_func) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set_cmp_func');
  Result := sk_SSL_COMP_set_cmp_func(st, cmp);
end;

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
  COMP_zlib_oneshot := Load_COMP_zlib_oneshot;
  COMP_brotli := Load_COMP_brotli;
  COMP_brotli_oneshot := Load_COMP_brotli_oneshot;
  COMP_zstd := Load_COMP_zstd;
  COMP_zstd_oneshot := Load_COMP_zstd_oneshot;
    {$ifdef OPENSSL_BIO_H}
  BIO_f_zlib := Load_BIO_f_zlib;
  BIO_f_brotli := Load_BIO_f_brotli;
  BIO_f_zstd := Load_BIO_f_zstd;
    {$endif} {OPENSSL_BIO_H}
{$endif} { OPENSSL_NO_COMP}
  sk_SSL_COMP_num := Load_sk_SSL_COMP_num;
  sk_SSL_COMP_value := Load_sk_SSL_COMP_value;
  sk_SSL_COMP_new := Load_sk_SSL_COMP_new;
  sk_SSL_COMP_new_null := Load_sk_SSL_COMP_new_null;
  sk_SSL_COMP_new_reserve := Load_sk_SSL_COMP_new_reserve;
  sk_SSL_COMP_reserve := Load_sk_SSL_COMP_reserve;
  sk_SSL_COMP_free := Load_sk_SSL_COMP_free;
  sk_SSL_COMP_zero := Load_sk_SSL_COMP_zero;
  sk_SSL_COMP_delete := Load_sk_SSL_COMP_delete;
  sk_SSL_COMP_delete_ptr := Load_sk_SSL_COMP_delete_ptr;
  sk_SSL_COMP_push := Load_sk_SSL_COMP_push;
  sk_SSL_COMP_unshift := Load_sk_SSL_COMP_unshift;
  sk_SSL_COMP_pop := Load_sk_SSL_COMP_pop;
  sk_SSL_COMP_shift := Load_sk_SSL_COMP_shift;
  sk_SSL_COMP_pop_free := Load_sk_SSL_COMP_pop_free;
  sk_SSL_COMP_insert := Load_sk_SSL_COMP_insert;
  sk_SSL_COMP_set := Load_sk_SSL_COMP_set;
  sk_SSL_COMP_find := Load_sk_SSL_COMP_find;
  sk_SSL_COMP_find_ex := Load_sk_SSL_COMP_find_ex;
  sk_SSL_COMP_find_all := Load_sk_SSL_COMP_find_all;
  sk_SSL_COMP_sort := Load_sk_SSL_COMP_sort;
  sk_SSL_COMP_is_sorted := Load_sk_SSL_COMP_is_sorted;
  sk_SSL_COMP_dup := Load_sk_SSL_COMP_dup;
  sk_SSL_COMP_deep_copy := Load_sk_SSL_COMP_deep_copy;
  sk_SSL_COMP_set_cmp_func := Load_sk_SSL_COMP_set_cmp_func;
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



