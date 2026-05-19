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

unit openssl_stack;

{
  Generated from OpenSSL 3.0.20 Header File stack.h - Tue 19 May 14:16:39 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_stack.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_STACK_H}
  {$define OPENSSL_STACK_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_STACK_H}
  {$endif}

type
  {Auto-generated forward references}
  Pstack_st = ^TOPENSSL_STACK;
  PPstack_st = ^Pstack_st;
  POPENSSL_STACK = ^TOPENSSL_STACK;
  PPOPENSSL_STACK = ^POPENSSL_STACK;
  POPENSSL_sk_compfunc = ^TOPENSSL_sk_compfunc;
  PPOPENSSL_sk_compfunc = ^POPENSSL_sk_compfunc;
  POPENSSL_sk_freefunc = ^TOPENSSL_sk_freefunc;
  PPOPENSSL_sk_freefunc = ^POPENSSL_sk_freefunc;
  POPENSSL_sk_copyfunc = ^TOPENSSL_sk_copyfunc;
  PPOPENSSL_sk_copyfunc = ^POPENSSL_sk_copyfunc;
  {end of auto-generated forward references}

  Tstack_st = record end;
  TOPENSSL_STACK = Tstack_st;
  { Use STACK_OF(...) instead }
  TOPENSSL_sk_compfunc = function(_param1: pointer; _param2: pointer): TOpenSSL_C_INT; cdecl;
  TOPENSSL_sk_freefunc = procedure(_param1: pointer); cdecl;
  TOPENSSL_sk_copyfunc = function(_param1: pointer): pointer; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OPENSSL_sk_num(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  function OPENSSL_sk_value(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  function OPENSSL_sk_set(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_set';
  function OPENSSL_sk_new(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  function OPENSSL_sk_new_null: POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  function OPENSSL_sk_new_reserve(c: TOPENSSL_sk_compfunc; n: TOpenSSL_C_INT): POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_new_reserve';
  function OPENSSL_sk_reserve(st: POPENSSL_STACK; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_reserve';
  procedure OPENSSL_sk_free(_param1: POPENSSL_STACK); cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OPENSSL_sk_num}
  {$EXTERNALSYM OPENSSL_sk_value}
  {$EXTERNALSYM OPENSSL_sk_set}
  {$EXTERNALSYM OPENSSL_sk_new}
  {$EXTERNALSYM OPENSSL_sk_new_null}
  {$EXTERNALSYM OPENSSL_sk_new_reserve}
  {$EXTERNALSYM OPENSSL_sk_reserve}
  {$EXTERNALSYM OPENSSL_sk_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OPENSSL_sk_num(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_sk_value(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl;
  function Load_OPENSSL_sk_set(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl;
  function Load_OPENSSL_sk_new(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
  function Load_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;
  function Load_OPENSSL_sk_new_reserve(c: TOPENSSL_sk_compfunc; n: TOpenSSL_C_INT): POPENSSL_STACK; cdecl;
  function Load_OPENSSL_sk_reserve(st: POPENSSL_STACK; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_OPENSSL_sk_free(_param1: POPENSSL_STACK); cdecl;

var
  OPENSSL_sk_num: function(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_num;
  OPENSSL_sk_value: function(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl = Load_OPENSSL_sk_value;
  OPENSSL_sk_set: function(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl = Load_OPENSSL_sk_set;
  OPENSSL_sk_new: function(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_new;
  OPENSSL_sk_new_null: function: POPENSSL_STACK; cdecl = Load_OPENSSL_sk_new_null;
  OPENSSL_sk_new_reserve: function(c: TOPENSSL_sk_compfunc; n: TOpenSSL_C_INT): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_new_reserve;
  OPENSSL_sk_reserve: function(st: POPENSSL_STACK; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_reserve;
  OPENSSL_sk_free: procedure(_param1: POPENSSL_STACK); cdecl = Load_OPENSSL_sk_free;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = procedure(_param1: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OPENSSL_sk_pop_free(st: POPENSSL_STACK; func: TFuncType000); cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  function OPENSSL_sk_deep_copy(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_deep_copy';
  function OPENSSL_sk_insert(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_insert';
  function OPENSSL_sk_delete(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_delete';
  function OPENSSL_sk_delete_ptr(st: POPENSSL_STACK; p: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_delete_ptr';
  function OPENSSL_sk_find(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  function OPENSSL_sk_find_ex(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find_ex';
  function OPENSSL_sk_find_all(st: POPENSSL_STACK; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find_all';
  function OPENSSL_sk_push(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  function OPENSSL_sk_unshift(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_unshift';
  function OPENSSL_sk_shift(st: POPENSSL_STACK): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_shift';
  function OPENSSL_sk_pop(st: POPENSSL_STACK): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_pop';
  procedure OPENSSL_sk_zero(st: POPENSSL_STACK); cdecl; external CLibCrypto name 'OPENSSL_sk_zero';
  function OPENSSL_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl; external CLibCrypto name 'OPENSSL_sk_set_cmp_func';
  function OPENSSL_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  procedure OPENSSL_sk_sort(st: POPENSSL_STACK); cdecl; external CLibCrypto name 'OPENSSL_sk_sort';
  function OPENSSL_sk_is_sorted(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_is_sorted';
  {$else}
  {$EXTERNALSYM OPENSSL_sk_pop_free}
  {$EXTERNALSYM OPENSSL_sk_deep_copy}
  {$EXTERNALSYM OPENSSL_sk_insert}
  {$EXTERNALSYM OPENSSL_sk_delete}
  {$EXTERNALSYM OPENSSL_sk_delete_ptr}
  {$EXTERNALSYM OPENSSL_sk_find}
  {$EXTERNALSYM OPENSSL_sk_find_ex}
  {$EXTERNALSYM OPENSSL_sk_find_all}
  {$EXTERNALSYM OPENSSL_sk_push}
  {$EXTERNALSYM OPENSSL_sk_unshift}
  {$EXTERNALSYM OPENSSL_sk_shift}
  {$EXTERNALSYM OPENSSL_sk_pop}
  {$EXTERNALSYM OPENSSL_sk_zero}
  {$EXTERNALSYM OPENSSL_sk_set_cmp_func}
  {$EXTERNALSYM OPENSSL_sk_dup}
  {$EXTERNALSYM OPENSSL_sk_sort}
  {$EXTERNALSYM OPENSSL_sk_is_sorted}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OPENSSL_sk_pop_free(st: POPENSSL_STACK; func: TFuncType000); cdecl;
  function Load_OPENSSL_sk_deep_copy(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
  function Load_OPENSSL_sk_insert(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_sk_delete(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl;
  function Load_OPENSSL_sk_delete_ptr(st: POPENSSL_STACK; p: pointer): pointer; cdecl;
  function Load_OPENSSL_sk_find(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_sk_find_ex(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_sk_find_all(st: POPENSSL_STACK; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_sk_push(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_sk_unshift(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_sk_shift(st: POPENSSL_STACK): pointer; cdecl;
  function Load_OPENSSL_sk_pop(st: POPENSSL_STACK): pointer; cdecl;
  procedure Load_OPENSSL_sk_zero(st: POPENSSL_STACK); cdecl;
  function Load_OPENSSL_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
  function Load_OPENSSL_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl;
  procedure Load_OPENSSL_sk_sort(st: POPENSSL_STACK); cdecl;
  function Load_OPENSSL_sk_is_sorted(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;

var
  OPENSSL_sk_pop_free: procedure(st: POPENSSL_STACK; func: TFuncType000); cdecl = Load_OPENSSL_sk_pop_free;
  OPENSSL_sk_deep_copy: function(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_deep_copy;
  OPENSSL_sk_insert: function(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_insert;
  OPENSSL_sk_delete: function(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl = Load_OPENSSL_sk_delete;
  OPENSSL_sk_delete_ptr: function(st: POPENSSL_STACK; p: pointer): pointer; cdecl = Load_OPENSSL_sk_delete_ptr;
  OPENSSL_sk_find: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_find;
  OPENSSL_sk_find_ex: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_find_ex;
  OPENSSL_sk_find_all: function(st: POPENSSL_STACK; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_find_all;
  OPENSSL_sk_push: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_push;
  OPENSSL_sk_unshift: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_unshift;
  OPENSSL_sk_shift: function(st: POPENSSL_STACK): pointer; cdecl = Load_OPENSSL_sk_shift;
  OPENSSL_sk_pop: function(st: POPENSSL_STACK): pointer; cdecl = Load_OPENSSL_sk_pop;
  OPENSSL_sk_zero: procedure(st: POPENSSL_STACK); cdecl = Load_OPENSSL_sk_zero;
  OPENSSL_sk_set_cmp_func: function(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl = Load_OPENSSL_sk_set_cmp_func;
  OPENSSL_sk_dup: function(st: POPENSSL_STACK): POPENSSL_STACK; cdecl = Load_OPENSSL_sk_dup;
  OPENSSL_sk_sort: procedure(st: POPENSSL_STACK); cdecl = Load_OPENSSL_sk_sort;
  OPENSSL_sk_is_sorted: function(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl = Load_OPENSSL_sk_is_sorted;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

type
  {Auto-generated forward references}
  P_STACK = ^T_STACK;
  PP_STACK = ^P_STACK;
  {end of auto-generated forward references}

  T_STACK = TOPENSSL_STACK;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function sk_num(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_num';
  function sk_value(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_value';
  function sk_set(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_set';
  function sk_new(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_new';
  function sk_new_null: POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_new_null';
  procedure sk_free(_param1: POPENSSL_STACK); cdecl; external CLibCrypto name 'OPENSSL_sk_free';
  procedure sk_pop_free(st: POPENSSL_STACK; func: TFuncType000); cdecl; external CLibCrypto name 'OPENSSL_sk_pop_free';
  function sk_deep_copy(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_deep_copy';
  function sk_insert(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_insert';
  function sk_delete(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_delete';
  function sk_delete_ptr(st: POPENSSL_STACK; p: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_delete_ptr';
  function sk_find(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find';
  function sk_find_ex(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_find_ex';
  function sk_push(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_push';
  function sk_unshift(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_unshift';
  function sk_shift(st: POPENSSL_STACK): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_shift';
  function sk_pop(st: POPENSSL_STACK): pointer; cdecl; external CLibCrypto name 'OPENSSL_sk_pop';
  procedure sk_zero(st: POPENSSL_STACK); cdecl; external CLibCrypto name 'OPENSSL_sk_zero';
  function sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl; external CLibCrypto name 'OPENSSL_sk_set_cmp_func';
  function sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl; external CLibCrypto name 'OPENSSL_sk_dup';
  procedure sk_sort(st: POPENSSL_STACK); cdecl; external CLibCrypto name 'OPENSSL_sk_sort';
  function sk_is_sorted(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_sk_is_sorted';
    {$else}
  {$EXTERNALSYM sk_num}
  {$EXTERNALSYM sk_value}
  {$EXTERNALSYM sk_set}
  {$EXTERNALSYM sk_new}
  {$EXTERNALSYM sk_new_null}
  {$EXTERNALSYM sk_free}
  {$EXTERNALSYM sk_pop_free}
  {$EXTERNALSYM sk_deep_copy}
  {$EXTERNALSYM sk_insert}
  {$EXTERNALSYM sk_delete}
  {$EXTERNALSYM sk_delete_ptr}
  {$EXTERNALSYM sk_find}
  {$EXTERNALSYM sk_find_ex}
  {$EXTERNALSYM sk_push}
  {$EXTERNALSYM sk_unshift}
  {$EXTERNALSYM sk_shift}
  {$EXTERNALSYM sk_pop}
  {$EXTERNALSYM sk_zero}
  {$EXTERNALSYM sk_set_cmp_func}
  {$EXTERNALSYM sk_dup}
  {$EXTERNALSYM sk_sort}
  {$EXTERNALSYM sk_is_sorted}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_sk_num(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
  function Load_sk_value(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl;
  function Load_sk_set(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl;
  function Load_sk_new(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
  function Load_sk_new_null: POPENSSL_STACK; cdecl;
  procedure Load_sk_free(_param1: POPENSSL_STACK); cdecl;
  procedure Load_sk_pop_free(st: POPENSSL_STACK; func: TFuncType000); cdecl;
  function Load_sk_deep_copy(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
  function Load_sk_insert(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_sk_delete(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl;
  function Load_sk_delete_ptr(st: POPENSSL_STACK; p: pointer): pointer; cdecl;
  function Load_sk_find(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_find_ex(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_push(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_unshift(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_sk_shift(st: POPENSSL_STACK): pointer; cdecl;
  function Load_sk_pop(st: POPENSSL_STACK): pointer; cdecl;
  procedure Load_sk_zero(st: POPENSSL_STACK); cdecl;
  function Load_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
  function Load_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl;
  procedure Load_sk_sort(st: POPENSSL_STACK); cdecl;
  function Load_sk_is_sorted(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;

var
  sk_num: function(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl = Load_sk_num;
  sk_value: function(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl = Load_sk_value;
  sk_set: function(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl = Load_sk_set;
  sk_new: function(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl = Load_sk_new;
  sk_new_null: function: POPENSSL_STACK; cdecl = Load_sk_new_null;
  sk_free: procedure(_param1: POPENSSL_STACK); cdecl = Load_sk_free;
  sk_pop_free: procedure(st: POPENSSL_STACK; func: TFuncType000); cdecl = Load_sk_pop_free;
  sk_deep_copy: function(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl = Load_sk_deep_copy;
  sk_insert: function(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_sk_insert;
  sk_delete: function(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl = Load_sk_delete;
  sk_delete_ptr: function(st: POPENSSL_STACK; p: pointer): pointer; cdecl = Load_sk_delete_ptr;
  sk_find: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_find;
  sk_find_ex: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_find_ex;
  sk_push: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_push;
  sk_unshift: function(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl = Load_sk_unshift;
  sk_shift: function(st: POPENSSL_STACK): pointer; cdecl = Load_sk_shift;
  sk_pop: function(st: POPENSSL_STACK): pointer; cdecl = Load_sk_pop;
  sk_zero: procedure(st: POPENSSL_STACK); cdecl = Load_sk_zero;
  sk_set_cmp_func: function(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl = Load_sk_set_cmp_func;
  sk_dup: function(st: POPENSSL_STACK): POPENSSL_STACK; cdecl = Load_sk_dup;
  sk_sort: procedure(st: POPENSSL_STACK); cdecl = Load_sk_sort;
  sk_is_sorted: function(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl = Load_sk_is_sorted;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
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
function Load_OPENSSL_sk_num(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_num := LoadLibCryptoFunction('OPENSSL_sk_num');
  if not assigned(OPENSSL_sk_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_num');
  Result := OPENSSL_sk_num(_param1);
end;

function Load_OPENSSL_sk_value(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl;
begin
  OPENSSL_sk_value := LoadLibCryptoFunction('OPENSSL_sk_value');
  if not assigned(OPENSSL_sk_value) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_value');
  Result := OPENSSL_sk_value(_param1, _param2);
end;

function Load_OPENSSL_sk_set(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl;
begin
  OPENSSL_sk_set := LoadLibCryptoFunction('OPENSSL_sk_set');
  if not assigned(OPENSSL_sk_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set');
  Result := OPENSSL_sk_set(st, i, data);
end;

function Load_OPENSSL_sk_new(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_new := LoadLibCryptoFunction('OPENSSL_sk_new');
  if not assigned(OPENSSL_sk_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new');
  Result := OPENSSL_sk_new(cmp);
end;

function Load_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_new_null := LoadLibCryptoFunction('OPENSSL_sk_new_null');
  if not assigned(OPENSSL_sk_new_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_null');
  Result := OPENSSL_sk_new_null;
end;

function Load_OPENSSL_sk_new_reserve(c: TOPENSSL_sk_compfunc; n: TOpenSSL_C_INT): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_new_reserve := LoadLibCryptoFunction('OPENSSL_sk_new_reserve');
  if not assigned(OPENSSL_sk_new_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_reserve');
  Result := OPENSSL_sk_new_reserve(c, n);
end;

function Load_OPENSSL_sk_reserve(st: POPENSSL_STACK; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_reserve := LoadLibCryptoFunction('OPENSSL_sk_reserve');
  if not assigned(OPENSSL_sk_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_reserve');
  Result := OPENSSL_sk_reserve(st, n);
end;

procedure Load_OPENSSL_sk_free(_param1: POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_free := LoadLibCryptoFunction('OPENSSL_sk_free');
  if not assigned(OPENSSL_sk_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_free');
  OPENSSL_sk_free(_param1);
end;

procedure Load_OPENSSL_sk_pop_free(st: POPENSSL_STACK; func: TFuncType000); cdecl;
begin
  OPENSSL_sk_pop_free := LoadLibCryptoFunction('OPENSSL_sk_pop_free');
  if not assigned(OPENSSL_sk_pop_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop_free');
  OPENSSL_sk_pop_free(st, func);
end;

function Load_OPENSSL_sk_deep_copy(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_deep_copy := LoadLibCryptoFunction('OPENSSL_sk_deep_copy');
  if not assigned(OPENSSL_sk_deep_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_deep_copy');
  Result := OPENSSL_sk_deep_copy(_param1, c, f);
end;

function Load_OPENSSL_sk_insert(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_insert := LoadLibCryptoFunction('OPENSSL_sk_insert');
  if not assigned(OPENSSL_sk_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_insert');
  Result := OPENSSL_sk_insert(sk, data, where);
end;

function Load_OPENSSL_sk_delete(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl;
begin
  OPENSSL_sk_delete := LoadLibCryptoFunction('OPENSSL_sk_delete');
  if not assigned(OPENSSL_sk_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete');
  Result := OPENSSL_sk_delete(st, loc);
end;

function Load_OPENSSL_sk_delete_ptr(st: POPENSSL_STACK; p: pointer): pointer; cdecl;
begin
  OPENSSL_sk_delete_ptr := LoadLibCryptoFunction('OPENSSL_sk_delete_ptr');
  if not assigned(OPENSSL_sk_delete_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete_ptr');
  Result := OPENSSL_sk_delete_ptr(st, p);
end;

function Load_OPENSSL_sk_find(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_find := LoadLibCryptoFunction('OPENSSL_sk_find');
  if not assigned(OPENSSL_sk_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find');
  Result := OPENSSL_sk_find(st, data);
end;

function Load_OPENSSL_sk_find_ex(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_find_ex := LoadLibCryptoFunction('OPENSSL_sk_find_ex');
  if not assigned(OPENSSL_sk_find_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find_ex');
  Result := OPENSSL_sk_find_ex(st, data);
end;

function Load_OPENSSL_sk_find_all(st: POPENSSL_STACK; data: pointer; pnum: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_find_all := LoadLibCryptoFunction('OPENSSL_sk_find_all');
  if not assigned(OPENSSL_sk_find_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find_all');
  Result := OPENSSL_sk_find_all(st, data, pnum);
end;

function Load_OPENSSL_sk_push(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_push := LoadLibCryptoFunction('OPENSSL_sk_push');
  if not assigned(OPENSSL_sk_push) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_push');
  Result := OPENSSL_sk_push(st, data);
end;

function Load_OPENSSL_sk_unshift(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_unshift := LoadLibCryptoFunction('OPENSSL_sk_unshift');
  if not assigned(OPENSSL_sk_unshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_unshift');
  Result := OPENSSL_sk_unshift(st, data);
end;

function Load_OPENSSL_sk_shift(st: POPENSSL_STACK): pointer; cdecl;
begin
  OPENSSL_sk_shift := LoadLibCryptoFunction('OPENSSL_sk_shift');
  if not assigned(OPENSSL_sk_shift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_shift');
  Result := OPENSSL_sk_shift(st);
end;

function Load_OPENSSL_sk_pop(st: POPENSSL_STACK): pointer; cdecl;
begin
  OPENSSL_sk_pop := LoadLibCryptoFunction('OPENSSL_sk_pop');
  if not assigned(OPENSSL_sk_pop) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop');
  Result := OPENSSL_sk_pop(st);
end;

procedure Load_OPENSSL_sk_zero(st: POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_zero := LoadLibCryptoFunction('OPENSSL_sk_zero');
  if not assigned(OPENSSL_sk_zero) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_zero');
  OPENSSL_sk_zero(st);
end;

function Load_OPENSSL_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
begin
  OPENSSL_sk_set_cmp_func := LoadLibCryptoFunction('OPENSSL_sk_set_cmp_func');
  if not assigned(OPENSSL_sk_set_cmp_func) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set_cmp_func');
  Result := OPENSSL_sk_set_cmp_func(sk, cmp);
end;

function Load_OPENSSL_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl;
begin
  OPENSSL_sk_dup := LoadLibCryptoFunction('OPENSSL_sk_dup');
  if not assigned(OPENSSL_sk_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_dup');
  Result := OPENSSL_sk_dup(st);
end;

procedure Load_OPENSSL_sk_sort(st: POPENSSL_STACK); cdecl;
begin
  OPENSSL_sk_sort := LoadLibCryptoFunction('OPENSSL_sk_sort');
  if not assigned(OPENSSL_sk_sort) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_sort');
  OPENSSL_sk_sort(st);
end;

function Load_OPENSSL_sk_is_sorted(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_sk_is_sorted := LoadLibCryptoFunction('OPENSSL_sk_is_sorted');
  if not assigned(OPENSSL_sk_is_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_is_sorted');
  Result := OPENSSL_sk_is_sorted(st);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
function Load_sk_num(_param1: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
begin
  sk_num := LoadLibCryptoFunction('OPENSSL_sk_num');
  if not assigned(sk_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_num');
  Result := sk_num(_param1);
end;

function Load_sk_value(_param1: POPENSSL_STACK; _param2: TOpenSSL_C_INT): pointer; cdecl;
begin
  sk_value := LoadLibCryptoFunction('OPENSSL_sk_value');
  if not assigned(sk_value) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_value');
  Result := sk_value(_param1, _param2);
end;

function Load_sk_set(st: POPENSSL_STACK; i: TOpenSSL_C_INT; data: pointer): pointer; cdecl;
begin
  sk_set := LoadLibCryptoFunction('OPENSSL_sk_set');
  if not assigned(sk_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set');
  Result := sk_set(st, i, data);
end;

function Load_sk_new(cmp: TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
begin
  sk_new := LoadLibCryptoFunction('OPENSSL_sk_new');
  if not assigned(sk_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new');
  Result := sk_new(cmp);
end;

function Load_sk_new_null: POPENSSL_STACK; cdecl;
begin
  sk_new_null := LoadLibCryptoFunction('OPENSSL_sk_new_null');
  if not assigned(sk_new_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_null');
  Result := sk_new_null;
end;

procedure Load_sk_free(_param1: POPENSSL_STACK); cdecl;
begin
  sk_free := LoadLibCryptoFunction('OPENSSL_sk_free');
  if not assigned(sk_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_free');
  sk_free(_param1);
end;

procedure Load_sk_pop_free(st: POPENSSL_STACK; func: TFuncType000); cdecl;
begin
  sk_pop_free := LoadLibCryptoFunction('OPENSSL_sk_pop_free');
  if not assigned(sk_pop_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop_free');
  sk_pop_free(st, func);
end;

function Load_sk_deep_copy(_param1: POPENSSL_STACK; c: TOPENSSL_sk_copyfunc; f: TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
begin
  sk_deep_copy := LoadLibCryptoFunction('OPENSSL_sk_deep_copy');
  if not assigned(sk_deep_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_deep_copy');
  Result := sk_deep_copy(_param1, c, f);
end;

function Load_sk_insert(sk: POPENSSL_STACK; data: pointer; where: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  sk_insert := LoadLibCryptoFunction('OPENSSL_sk_insert');
  if not assigned(sk_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_insert');
  Result := sk_insert(sk, data, where);
end;

function Load_sk_delete(st: POPENSSL_STACK; loc: TOpenSSL_C_INT): pointer; cdecl;
begin
  sk_delete := LoadLibCryptoFunction('OPENSSL_sk_delete');
  if not assigned(sk_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete');
  Result := sk_delete(st, loc);
end;

function Load_sk_delete_ptr(st: POPENSSL_STACK; p: pointer): pointer; cdecl;
begin
  sk_delete_ptr := LoadLibCryptoFunction('OPENSSL_sk_delete_ptr');
  if not assigned(sk_delete_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete_ptr');
  Result := sk_delete_ptr(st, p);
end;

function Load_sk_find(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_find := LoadLibCryptoFunction('OPENSSL_sk_find');
  if not assigned(sk_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find');
  Result := sk_find(st, data);
end;

function Load_sk_find_ex(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_find_ex := LoadLibCryptoFunction('OPENSSL_sk_find_ex');
  if not assigned(sk_find_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find_ex');
  Result := sk_find_ex(st, data);
end;

function Load_sk_push(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_push := LoadLibCryptoFunction('OPENSSL_sk_push');
  if not assigned(sk_push) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_push');
  Result := sk_push(st, data);
end;

function Load_sk_unshift(st: POPENSSL_STACK; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  sk_unshift := LoadLibCryptoFunction('OPENSSL_sk_unshift');
  if not assigned(sk_unshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_unshift');
  Result := sk_unshift(st, data);
end;

function Load_sk_shift(st: POPENSSL_STACK): pointer; cdecl;
begin
  sk_shift := LoadLibCryptoFunction('OPENSSL_sk_shift');
  if not assigned(sk_shift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_shift');
  Result := sk_shift(st);
end;

function Load_sk_pop(st: POPENSSL_STACK): pointer; cdecl;
begin
  sk_pop := LoadLibCryptoFunction('OPENSSL_sk_pop');
  if not assigned(sk_pop) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop');
  Result := sk_pop(st);
end;

procedure Load_sk_zero(st: POPENSSL_STACK); cdecl;
begin
  sk_zero := LoadLibCryptoFunction('OPENSSL_sk_zero');
  if not assigned(sk_zero) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_zero');
  sk_zero(st);
end;

function Load_sk_set_cmp_func(sk: POPENSSL_STACK; cmp: TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
begin
  sk_set_cmp_func := LoadLibCryptoFunction('OPENSSL_sk_set_cmp_func');
  if not assigned(sk_set_cmp_func) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set_cmp_func');
  Result := sk_set_cmp_func(sk, cmp);
end;

function Load_sk_dup(st: POPENSSL_STACK): POPENSSL_STACK; cdecl;
begin
  sk_dup := LoadLibCryptoFunction('OPENSSL_sk_dup');
  if not assigned(sk_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_dup');
  Result := sk_dup(st);
end;

procedure Load_sk_sort(st: POPENSSL_STACK); cdecl;
begin
  sk_sort := LoadLibCryptoFunction('OPENSSL_sk_sort');
  if not assigned(sk_sort) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_sort');
  sk_sort(st);
end;

function Load_sk_is_sorted(st: POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
begin
  sk_is_sorted := LoadLibCryptoFunction('OPENSSL_sk_is_sorted');
  if not assigned(sk_is_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_is_sorted');
  Result := sk_is_sorted(st);
end;

{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OPENSSL_sk_num := Load_OPENSSL_sk_num;
  OPENSSL_sk_value := Load_OPENSSL_sk_value;
  OPENSSL_sk_set := Load_OPENSSL_sk_set;
  OPENSSL_sk_new := Load_OPENSSL_sk_new;
  OPENSSL_sk_new_null := Load_OPENSSL_sk_new_null;
  OPENSSL_sk_new_reserve := Load_OPENSSL_sk_new_reserve;
  OPENSSL_sk_reserve := Load_OPENSSL_sk_reserve;
  OPENSSL_sk_free := Load_OPENSSL_sk_free;
  OPENSSL_sk_pop_free := Load_OPENSSL_sk_pop_free;
  OPENSSL_sk_deep_copy := Load_OPENSSL_sk_deep_copy;
  OPENSSL_sk_insert := Load_OPENSSL_sk_insert;
  OPENSSL_sk_delete := Load_OPENSSL_sk_delete;
  OPENSSL_sk_delete_ptr := Load_OPENSSL_sk_delete_ptr;
  OPENSSL_sk_find := Load_OPENSSL_sk_find;
  OPENSSL_sk_find_ex := Load_OPENSSL_sk_find_ex;
  OPENSSL_sk_find_all := Load_OPENSSL_sk_find_all;
  OPENSSL_sk_push := Load_OPENSSL_sk_push;
  OPENSSL_sk_unshift := Load_OPENSSL_sk_unshift;
  OPENSSL_sk_shift := Load_OPENSSL_sk_shift;
  OPENSSL_sk_pop := Load_OPENSSL_sk_pop;
  OPENSSL_sk_zero := Load_OPENSSL_sk_zero;
  OPENSSL_sk_set_cmp_func := Load_OPENSSL_sk_set_cmp_func;
  OPENSSL_sk_dup := Load_OPENSSL_sk_dup;
  OPENSSL_sk_sort := Load_OPENSSL_sk_sort;
  OPENSSL_sk_is_sorted := Load_OPENSSL_sk_is_sorted;
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  sk_num := Load_sk_num;
  sk_value := Load_sk_value;
  sk_set := Load_sk_set;
  sk_new := Load_sk_new;
  sk_new_null := Load_sk_new_null;
  sk_free := Load_sk_free;
  sk_pop_free := Load_sk_pop_free;
  sk_deep_copy := Load_sk_deep_copy;
  sk_insert := Load_sk_insert;
  sk_delete := Load_sk_delete;
  sk_delete_ptr := Load_sk_delete_ptr;
  sk_find := Load_sk_find;
  sk_find_ex := Load_sk_find_ex;
  sk_push := Load_sk_push;
  sk_unshift := Load_sk_unshift;
  sk_shift := Load_sk_shift;
  sk_pop := Load_sk_pop;
  sk_zero := Load_sk_zero;
  sk_set_cmp_func := Load_sk_set_cmp_func;
  sk_dup := Load_sk_dup;
  sk_sort := Load_sk_sort;
  sk_is_sorted := Load_sk_is_sorted;
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
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



