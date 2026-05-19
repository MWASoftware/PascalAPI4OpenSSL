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

unit openssl_lhash;

{
  Generated from OpenSSL 3.0.20 Header File lhash.h - Tue 19 May 14:16:09 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_lhash.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_safestack,openssl_e_os2,openssl_bio;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{ clang-format off }
{ clang-format on }

{* Header for dynamic hash table routines Author - Eric Young
}
{$ifndef  OPENSSL_LHASH_H}
  {$define OPENSSL_LHASH_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_LHASH_H}
  {$endif}

type
  {Auto-generated forward references}
  Plhash_node_st = ^TOPENSSL_LH_NODE;
  PPlhash_node_st = ^Plhash_node_st;
  POPENSSL_LH_NODE = ^TOPENSSL_LH_NODE;
  PPOPENSSL_LH_NODE = ^POPENSSL_LH_NODE;
  POPENSSL_LH_COMPFUNC = ^TOPENSSL_LH_COMPFUNC;
  PPOPENSSL_LH_COMPFUNC = ^POPENSSL_LH_COMPFUNC;
  POPENSSL_LH_HASHFUNC = ^TOPENSSL_LH_HASHFUNC;
  PPOPENSSL_LH_HASHFUNC = ^POPENSSL_LH_HASHFUNC;
  POPENSSL_LH_DOALL_FUNC = ^TOPENSSL_LH_DOALL_FUNC;
  PPOPENSSL_LH_DOALL_FUNC = ^POPENSSL_LH_DOALL_FUNC;
  POPENSSL_LH_DOALL_FUNCARG = ^TOPENSSL_LH_DOALL_FUNCARG;
  PPOPENSSL_LH_DOALL_FUNCARG = ^POPENSSL_LH_DOALL_FUNCARG;
  Plhash_st = ^TOPENSSL_LHASH;
  PPlhash_st = ^Plhash_st;
  POPENSSL_LHASH = ^TOPENSSL_LHASH;
  PPOPENSSL_LHASH = ^POPENSSL_LHASH;
  {end of auto-generated forward references}

  Tlhash_node_st = record end;
  TOPENSSL_LH_NODE = Tlhash_node_st;
  TOPENSSL_LH_COMPFUNC = function(_param1: pointer; _param2: pointer): TOpenSSL_C_INT; cdecl;
  TOPENSSL_LH_HASHFUNC = function(_param1: pointer): TOpenSSL_C_UINT; cdecl;
  TOPENSSL_LH_DOALL_FUNC = procedure(_param1: pointer); cdecl;
  TOPENSSL_LH_DOALL_FUNCARG = procedure(_param1: pointer; _param2: pointer); cdecl;
  Tlhash_st = record end;
  TOPENSSL_LHASH = Tlhash_st;
  {# define  DECLARE_LHASH_HASH_FN(name,o_type) unsigned long name ##_LHASH_HASH(const void *);}
  (*# define  IMPLEMENT_LHASH_HASH_FN(name,o_type) unsigned long name ##_LHASH_HASH(const void *arg) { const o_type *a = arg; return 
name ##_hash(a); }*)
  {# define  LHASH_HASH_FN(name) name ##_LHASH_HASH}
  {# define  DECLARE_LHASH_COMP_FN(name,o_type) int name ##_LHASH_COMP(const void *, const void *);}
  (*# define  IMPLEMENT_LHASH_COMP_FN(name,o_type) int name ##_LHASH_COMP(const void *arg1, const void *arg2) { const o_type *a = 
arg1; const o_type *b = arg2; return name ##_cmp(a, b); }*)
  {# define  LHASH_COMP_FN(name) name ##_LHASH_COMP}
  {# define  DECLARE_LHASH_DOALL_ARG_FN(name,o_type,a_type) void name ##_LHASH_DOALL_ARG(void *, void *);}
  (*# define  IMPLEMENT_LHASH_DOALL_ARG_FN(name,o_type,a_type) void name ##_LHASH_DOALL_ARG(void *arg1, void *arg2) { o_type *a = 
arg1; a_type *b = arg2; name ##_doall_arg(a, b); }*)
  {# define  LHASH_DOALL_ARG_FN(name) name ##_LHASH_DOALL_ARG}

const
  
  {* Macros for declaring and implementing type-safe wrappers for LHASH
  * callbacks. This way, callbacks can be provided to LHASH structures without
  * function pointer casting and the macro-defined callbacks provide
  * per-variable casting before deferring to the underlying type-specific
  * callbacks. NB: It is possible to place a "static" in front of both the
  * DECLARE and IMPLEMENT macros if the functions are strictly internal.
  }
  { First: "hash" functions }
  { Second: "compare" functions }
  { Fourth: "doall_arg" functions }
  LH_LOAD_MULT = 256;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OPENSSL_LH_error(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_LH_error';
  function OPENSSL_LH_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl; external CLibCrypto name 'OPENSSL_LH_new';
  procedure OPENSSL_LH_free(lh: POPENSSL_LHASH); cdecl; external CLibCrypto name 'OPENSSL_LH_free';
  procedure OPENSSL_LH_flush(lh: POPENSSL_LHASH); cdecl; external CLibCrypto name 'OPENSSL_LH_flush';
  function OPENSSL_LH_insert(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_LH_insert';
  function OPENSSL_LH_delete(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_LH_delete';
  function OPENSSL_LH_retrieve(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_LH_retrieve';
  procedure OPENSSL_LH_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl; external CLibCrypto name 'OPENSSL_LH_doall';
  procedure OPENSSL_LH_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl; external CLibCrypto name 'OPENSSL_LH_doall_arg';
  function OPENSSL_LH_strhash(c: PAnsiChar): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'OPENSSL_LH_strhash';
  function OPENSSL_LH_num_items(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'OPENSSL_LH_num_items';
  function OPENSSL_LH_get_down_load(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'OPENSSL_LH_get_down_load';
  procedure OPENSSL_LH_set_down_load(lh: POPENSSL_LHASH; down_load: TOpenSSL_C_UINT); cdecl; external CLibCrypto name 'OPENSSL_LH_set_down_load';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OPENSSL_LH_error}
  {$EXTERNALSYM OPENSSL_LH_new}
  {$EXTERNALSYM OPENSSL_LH_free}
  {$EXTERNALSYM OPENSSL_LH_flush}
  {$EXTERNALSYM OPENSSL_LH_insert}
  {$EXTERNALSYM OPENSSL_LH_delete}
  {$EXTERNALSYM OPENSSL_LH_retrieve}
  {$EXTERNALSYM OPENSSL_LH_doall}
  {$EXTERNALSYM OPENSSL_LH_doall_arg}
  {$EXTERNALSYM OPENSSL_LH_strhash}
  {$EXTERNALSYM OPENSSL_LH_num_items}
  {$EXTERNALSYM OPENSSL_LH_get_down_load}
  {$EXTERNALSYM OPENSSL_LH_set_down_load}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OPENSSL_LH_error(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl;
  function Load_OPENSSL_LH_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl;
  procedure Load_OPENSSL_LH_free(lh: POPENSSL_LHASH); cdecl;
  procedure Load_OPENSSL_LH_flush(lh: POPENSSL_LHASH); cdecl;
  function Load_OPENSSL_LH_insert(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
  function Load_OPENSSL_LH_delete(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
  function Load_OPENSSL_LH_retrieve(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
  procedure Load_OPENSSL_LH_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl;
  procedure Load_OPENSSL_LH_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl;
  function Load_OPENSSL_LH_strhash(c: PAnsiChar): TOpenSSL_C_UINT; cdecl;
  function Load_OPENSSL_LH_num_items(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl;
  function Load_OPENSSL_LH_get_down_load(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl;
  procedure Load_OPENSSL_LH_set_down_load(lh: POPENSSL_LHASH; down_load: TOpenSSL_C_UINT); cdecl;

var
  OPENSSL_LH_error: function(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl = Load_OPENSSL_LH_error;
  OPENSSL_LH_new: function(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl = Load_OPENSSL_LH_new;
  OPENSSL_LH_free: procedure(lh: POPENSSL_LHASH); cdecl = Load_OPENSSL_LH_free;
  OPENSSL_LH_flush: procedure(lh: POPENSSL_LHASH); cdecl = Load_OPENSSL_LH_flush;
  OPENSSL_LH_insert: function(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl = Load_OPENSSL_LH_insert;
  OPENSSL_LH_delete: function(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl = Load_OPENSSL_LH_delete;
  OPENSSL_LH_retrieve: function(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl = Load_OPENSSL_LH_retrieve;
  OPENSSL_LH_doall: procedure(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl = Load_OPENSSL_LH_doall;
  OPENSSL_LH_doall_arg: procedure(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl = Load_OPENSSL_LH_doall_arg;
  OPENSSL_LH_strhash: function(c: PAnsiChar): TOpenSSL_C_UINT; cdecl = Load_OPENSSL_LH_strhash;
  OPENSSL_LH_num_items: function(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl = Load_OPENSSL_LH_num_items;
  OPENSSL_LH_get_down_load: function(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl = Load_OPENSSL_LH_get_down_load;
  OPENSSL_LH_set_down_load: procedure(lh: POPENSSL_LHASH; down_load: TOpenSSL_C_UINT); cdecl = Load_OPENSSL_LH_set_down_load;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_STDIO}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OPENSSL_LH_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; external CLibCrypto name 'OPENSSL_LH_stats';
  procedure OPENSSL_LH_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; external CLibCrypto name 'OPENSSL_LH_node_stats';
  procedure OPENSSL_LH_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; external CLibCrypto name 'OPENSSL_LH_node_usage_stats';
    {$else}
  {$EXTERNALSYM OPENSSL_LH_stats}
  {$EXTERNALSYM OPENSSL_LH_node_stats}
  {$EXTERNALSYM OPENSSL_LH_node_usage_stats}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OPENSSL_LH_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
  procedure Load_OPENSSL_LH_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
  procedure Load_OPENSSL_LH_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;

var
  OPENSSL_LH_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = Load_OPENSSL_LH_stats;
  OPENSSL_LH_node_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = Load_OPENSSL_LH_node_stats;
  OPENSSL_LH_node_usage_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = Load_OPENSSL_LH_node_usage_stats;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OPENSSL_LH_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl; external CLibCrypto name 'OPENSSL_LH_stats_bio';
  procedure OPENSSL_LH_node_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl; external CLibCrypto name 'OPENSSL_LH_node_stats_bio';
  procedure OPENSSL_LH_node_usage_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl; external CLibCrypto name 'OPENSSL_LH_node_usage_stats_bio';
  {$else}
  {$EXTERNALSYM OPENSSL_LH_stats_bio}
  {$EXTERNALSYM OPENSSL_LH_node_stats_bio}
  {$EXTERNALSYM OPENSSL_LH_node_usage_stats_bio}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OPENSSL_LH_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
  procedure Load_OPENSSL_LH_node_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
  procedure Load_OPENSSL_LH_node_usage_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;

var
  OPENSSL_LH_stats_bio: procedure(lh: POPENSSL_LHASH; out_: PBIO); cdecl = Load_OPENSSL_LH_stats_bio;
  OPENSSL_LH_node_stats_bio: procedure(lh: POPENSSL_LHASH; out_: PBIO); cdecl = Load_OPENSSL_LH_node_stats_bio;
  OPENSSL_LH_node_usage_stats_bio: procedure(lh: POPENSSL_LHASH; out_: PBIO); cdecl = Load_OPENSSL_LH_node_usage_stats_bio;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

type
  {Auto-generated forward references}
  P_LHASH = ^T_LHASH;
  PP_LHASH = ^P_LHASH;
  PLHASH_NODE = ^TLHASH_NODE;
  PPLHASH_NODE = ^PLHASH_NODE;
  {end of auto-generated forward references}

  T_LHASH = TOPENSSL_LHASH;
  TLHASH_NODE = TOPENSSL_LH_NODE;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function lh_error(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OPENSSL_LH_error';
  function lh_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl; external CLibCrypto name 'OPENSSL_LH_new';
  procedure lh_free(lh: POPENSSL_LHASH); cdecl; external CLibCrypto name 'OPENSSL_LH_free';
  function lh_insert(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_LH_insert';
  function lh_delete(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_LH_delete';
  function lh_retrieve(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl; external CLibCrypto name 'OPENSSL_LH_retrieve';
  procedure lh_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl; external CLibCrypto name 'OPENSSL_LH_doall';
  procedure lh_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl; external CLibCrypto name 'OPENSSL_LH_doall_arg';
  function lh_strhash(c: PAnsiChar): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'OPENSSL_LH_strhash';
  function lh_num_items(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'OPENSSL_LH_num_items';
    {$else}
  {$EXTERNALSYM lh_error}
  {$EXTERNALSYM lh_new}
  {$EXTERNALSYM lh_free}
  {$EXTERNALSYM lh_insert}
  {$EXTERNALSYM lh_delete}
  {$EXTERNALSYM lh_retrieve}
  {$EXTERNALSYM lh_doall}
  {$EXTERNALSYM lh_doall_arg}
  {$EXTERNALSYM lh_strhash}
  {$EXTERNALSYM lh_num_items}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_lh_error(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl;
  function Load_lh_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl;
  procedure Load_lh_free(lh: POPENSSL_LHASH); cdecl;
  function Load_lh_insert(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
  function Load_lh_delete(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
  function Load_lh_retrieve(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
  procedure Load_lh_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl;
  procedure Load_lh_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl;
  function Load_lh_strhash(c: PAnsiChar): TOpenSSL_C_UINT; cdecl;
  function Load_lh_num_items(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl;

var
  lh_error: function(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl = Load_lh_error;
  lh_new: function(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl = Load_lh_new;
  lh_free: procedure(lh: POPENSSL_LHASH); cdecl = Load_lh_free;
  lh_insert: function(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl = Load_lh_insert;
  lh_delete: function(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl = Load_lh_delete;
  lh_retrieve: function(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl = Load_lh_retrieve;
  lh_doall: procedure(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl = Load_lh_doall;
  lh_doall_arg: procedure(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl = Load_lh_doall_arg;
  lh_strhash: function(c: PAnsiChar): TOpenSSL_C_UINT; cdecl = Load_lh_strhash;
  lh_num_items: function(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl = Load_lh_num_items;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_STDIO}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure lh_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; external CLibCrypto name 'OPENSSL_LH_stats';
  procedure lh_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; external CLibCrypto name 'OPENSSL_LH_node_stats';
  procedure lh_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl; external CLibCrypto name 'OPENSSL_LH_node_usage_stats';
      {$else}
  {$EXTERNALSYM lh_stats}
  {$EXTERNALSYM lh_node_stats}
  {$EXTERNALSYM lh_node_usage_stats}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_lh_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
  procedure Load_lh_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
  procedure Load_lh_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;

var
  lh_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = Load_lh_stats;
  lh_node_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = Load_lh_node_stats;
  lh_node_usage_stats: procedure(lh: POPENSSL_LHASH; fp: PFILE); cdecl = Load_lh_node_usage_stats;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure lh_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl; external CLibCrypto name 'OPENSSL_LH_stats_bio';
  procedure lh_node_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl; external CLibCrypto name 'OPENSSL_LH_node_stats_bio';
  procedure lh_node_usage_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl; external CLibCrypto name 'OPENSSL_LH_node_usage_stats_bio';
    {$else}
  {$EXTERNALSYM lh_stats_bio}
  {$EXTERNALSYM lh_node_stats_bio}
  {$EXTERNALSYM lh_node_usage_stats_bio}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_lh_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
  procedure Load_lh_node_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
  procedure Load_lh_node_usage_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;

var
  lh_stats_bio: procedure(lh: POPENSSL_LHASH; out_: PBIO); cdecl = Load_lh_stats_bio;
  lh_node_stats_bio: procedure(lh: POPENSSL_LHASH; out_: PBIO); cdecl = Load_lh_node_stats_bio;
  lh_node_usage_stats_bio: procedure(lh: POPENSSL_LHASH; out_: PBIO); cdecl = Load_lh_node_usage_stats_bio;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
{# define  LHASH_OF(type) struct lhash_st_ ##type}
(*# define  DEFINE_LHASH_OF_INTERNAL(type) LHASH_OF(type) { union lh_ ##type ##_dummy { void *d1; unsigned long d2; int d3; } dummy; 
}; typedef int ( *lh_ ##type ##_compfunc)(const type *a, const type *b); typedef unsigned long ( *lh_ ##type ##_hashfunc)(const 
type *a); typedef void ( *lh_ ##type ##_doallfunc)(type * a); static ossl_unused ossl_inline type *ossl_check_ ##type ##_lh_plain_type(type 
*ptr) { return ptr; } static ossl_unused ossl_inline const type *ossl_check_const_ ##type ##_lh_plain_type(const type *ptr) { return 
ptr; } static ossl_unused ossl_inline const OPENSSL_LHASH *ossl_check_const_ ##type ##_lh_type(const LHASH_OF(type) *lh) { return 
(const OPENSSL_LHASH * )lh; } static ossl_unused ossl_inline OPENSSL_LHASH *ossl_check_ ##type ##_lh_type(LHASH_OF(type) *lh) { 
return (OPENSSL_LHASH * )lh; } static ossl_unused ossl_inline OPENSSL_LH_COMPFUNC ossl_check_ ##type ##_lh_compfunc_type(lh_ ##type 
##_compfunc cmp) { return (OPENSSL_LH_COMPFUNC)cmp; } static ossl_unused ossl_inline OPENSSL_LH_HASHFUNC ossl_check_ ##type ##_lh_hashfunc_type(lh_ 
##type ##_hashfunc hfn) { return (OPENSSL_LH_HASHFUNC)hfn; } static ossl_unused ossl_inline OPENSSL_LH_DOALL_FUNC ossl_check_ ##type 
##_lh_doallfunc_type(lh_ ##type ##_doallfunc dfn) { return (OPENSSL_LH_DOALL_FUNC)dfn; } LHASH_OF(type)*)
(*# define  DEFINE_LHASH_OF(type) LHASH_OF(type) { union lh_ ##type ##_dummy { void *d1; unsigned long d2; int d3; } dummy; }; static 
ossl_unused ossl_inline LHASH_OF(type) *lh_ ##type ##_new(unsigned long ( *hfn)(const type * ), int ( *cfn)(const type *, const 
type * )) { return (LHASH_OF(type) * ) OPENSSL_LH_new((OPENSSL_LH_HASHFUNC)hfn, (OPENSSL_LH_COMPFUNC)cfn); } static ossl_unused 
ossl_inline void lh_ ##type ##_free(LHASH_OF(type) *lh) { OPENSSL_LH_free((OPENSSL_LHASH * )lh); } static ossl_unused ossl_inline 
void lh_ ##type ##_flush(LHASH_OF(type) *lh) { OPENSSL_LH_flush((OPENSSL_LHASH * )lh); } static ossl_unused ossl_inline type *lh_ 
##type ##_insert(LHASH_OF(type) *lh, type *d) { return (type * )OPENSSL_LH_insert((OPENSSL_LHASH * )lh, d); } static ossl_unused 
ossl_inline type *lh_ ##type ##_delete(LHASH_OF(type) *lh, const type *d) { return (type * )OPENSSL_LH_delete((OPENSSL_LHASH * )lh,
 d); } static ossl_unused ossl_inline type *lh_ ##type ##_retrieve(LHASH_OF(type) *lh, const type *d) { return (type * )OPENSSL_LH_retrieve((OPENSSL_LHASH 
* )lh, d); } static ossl_unused ossl_inline int lh_ ##type ##_error(LHASH_OF(type) *lh) { return OPENSSL_LH_error((OPENSSL_LHASH 
* )lh); } static ossl_unused ossl_inline unsigned long lh_ ##type ##_num_items(LHASH_OF(type) *lh) { return OPENSSL_LH_num_items((OPENSSL_LHASH 
* )lh); } static ossl_unused ossl_inline void lh_ ##type ##_node_stats_bio(const LHASH_OF(type) *lh, BIO *out) { OPENSSL_LH_node_stats_bio((const 
OPENSSL_LHASH * )lh, out); } static ossl_unused ossl_inline void lh_ ##type ##_node_usage_stats_bio(const LHASH_OF(type) *lh, BIO 
*out) { OPENSSL_LH_node_usage_stats_bio((const OPENSSL_LHASH * )lh, out); } static ossl_unused ossl_inline void lh_ ##type ##_stats_bio(const 
LHASH_OF(type) *lh, BIO *out) { OPENSSL_LH_stats_bio((const OPENSSL_LHASH * )lh, out); } static ossl_unused ossl_inline unsigned 
long lh_ ##type ##_get_down_load(LHASH_OF(type) *lh) { return OPENSSL_LH_get_down_load((OPENSSL_LHASH * )lh); } static ossl_unused 
ossl_inline void lh_ ##type ##_set_down_load(LHASH_OF(type) *lh, unsigned long dl) { OPENSSL_LH_set_down_load((OPENSSL_LHASH * )lh,
 dl); } static ossl_unused ossl_inline void lh_ ##type ##_doall(LHASH_OF(type) *lh, void ( *doall)(type * )) { OPENSSL_LH_doall((OPENSSL_LHASH 
* )lh, (OPENSSL_LH_DOALL_FUNC)doall); } static ossl_unused ossl_inline void lh_ ##type ##_doall_arg(LHASH_OF(type) *lh, void ( *doallarg)(type 
*, void * ), void *arg) { OPENSSL_LH_doall_arg((OPENSSL_LHASH * )lh, (OPENSSL_LH_DOALL_FUNCARG)doallarg, arg); } LHASH_OF(type)*)
{# define  IMPLEMENT_LHASH_DOALL_ARG_CONST(type,argtype) int_implement_lhash_doall(type, argtype, const type)}
{# define  IMPLEMENT_LHASH_DOALL_ARG(type,argtype) int_implement_lhash_doall(type, argtype, type)} { Blacklisted Macro}
(*# define  int_implement_lhash_doall(type,argtype,cbargtype) static ossl_unused ossl_inline void lh_ ##type ##_doall_ ##argtype(LHASH_OF(type) 
*lh, void ( *fn)(cbargtype *, argtype * ), argtype *arg) { OPENSSL_LH_doall_arg((OPENSSL_LHASH * )lh, (OPENSSL_LH_DOALL_FUNCARG)fn,
 (void * )arg); } LHASH_OF(type)*)

type
  {Auto-generated forward references}
  Plh_OPENSSL_STRING_dummy = ^Tlh_OPENSSL_STRING_dummy;
  PPlh_OPENSSL_STRING_dummy = ^Plh_OPENSSL_STRING_dummy;
  Plhash_st_OPENSSL_STRING = ^Tlhash_st_OPENSSL_STRING;
  PPlhash_st_OPENSSL_STRING = ^Plhash_st_OPENSSL_STRING;
  Plh_OPENSSL_STRING_compfunc = ^Tlh_OPENSSL_STRING_compfunc;
  PPlh_OPENSSL_STRING_compfunc = ^Plh_OPENSSL_STRING_compfunc;
  Plh_OPENSSL_STRING_hashfunc = ^Tlh_OPENSSL_STRING_hashfunc;
  PPlh_OPENSSL_STRING_hashfunc = ^Plh_OPENSSL_STRING_hashfunc;
  Plh_OPENSSL_STRING_doallfunc = ^Tlh_OPENSSL_STRING_doallfunc;
  PPlh_OPENSSL_STRING_doallfunc = ^Plh_OPENSSL_STRING_doallfunc;
  {end of auto-generated forward references}

  { Type checking... }
  { Helper macro for internal use }
  { clang-format off }
  Tlh_OPENSSL_STRING_dummy = record 
    case integer of 
      0: (d1: pointer);
      1: (d2: TOpenSSL_C_UINT);
      2: (d3: TOpenSSL_C_INT);
  end;
  Tlhash_st_OPENSSL_STRING = record 
    dummy: Tlh_OPENSSL_STRING_dummy;
  end;
  Tlh_OPENSSL_STRING_compfunc = function(a: POPENSSL_STRING; b: POPENSSL_STRING): TOpenSSL_C_INT; cdecl;
  Tlh_OPENSSL_STRING_hashfunc = function(a: POPENSSL_STRING): TOpenSSL_C_UINT; cdecl;
  Tlh_OPENSSL_STRING_doallfunc = procedure(a: POPENSSL_STRING); cdecl;


  function ossl_check_OPENSSL_STRING_lh_plain_type(ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
  function ossl_check_const_OPENSSL_STRING_lh_plain_type(ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
  function ossl_check_const_OPENSSL_STRING_lh_type(lh: Plhash_st_OPENSSL_STRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_STRING_lh_type(lh: Plhash_st_OPENSSL_STRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_STRING_lh_compfunc_type(cmp: Tlh_OPENSSL_STRING_compfunc): TOPENSSL_LH_COMPFUNC{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_STRING_lh_hashfunc_type(hfn: Tlh_OPENSSL_STRING_hashfunc): TOPENSSL_LH_HASHFUNC{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_STRING_lh_doallfunc_type(dfn: Tlh_OPENSSL_STRING_doallfunc): TOPENSSL_LH_DOALL_FUNC{Has C Attribute: unused}; inline;
  {# define  lh_OPENSSL_STRING_new(hfn,cmp) ((LHASH_OF(OPENSSL_STRING) *)OPENSSL_LH_new(ossl_check_OPENSSL_STRING_lh_hashfunc_type(hfn),
 ossl_check_OPENSSL_STRING_lh_compfunc_type(cmp)))}
  procedure lh_OPENSSL_STRING_free(lh:Plhash_st_OPENSSL_STRING); inline;
  procedure lh_OPENSSL_STRING_flush(lh:Plhash_st_OPENSSL_STRING); inline;
  {# define  lh_OPENSSL_STRING_insert(lh,ptr) ((OPENSSL_STRING *)OPENSSL_LH_insert(ossl_check_OPENSSL_STRING_lh_type(lh), ossl_check_OPENSSL_STRING_lh_plain_type(ptr)))}
  {# define  lh_OPENSSL_STRING_delete(lh,ptr) ((OPENSSL_STRING *)OPENSSL_LH_delete(ossl_check_OPENSSL_STRING_lh_type(lh), ossl_check_const_OPENSSL_STRING_lh_plain_type(ptr)))}
  {# define  lh_OPENSSL_STRING_retrieve(lh,ptr) ((OPENSSL_STRING *)OPENSSL_LH_retrieve(ossl_check_OPENSSL_STRING_lh_type(lh), ossl_check_const_OPENSSL_STRING_lh_plain_type(ptr)))}
  function lh_OPENSSL_STRING_error(lh:Plhash_st_OPENSSL_STRING): TOpenSSL_C_INT; inline;
  function lh_OPENSSL_STRING_num_items(lh:Plhash_st_OPENSSL_STRING): TOpenSSL_C_UINT; inline;
  {# define  lh_OPENSSL_STRING_node_stats_bio(lh,out) OPENSSL_LH_node_stats_bio(ossl_check_const_OPENSSL_STRING_lh_type(lh), out)} {Function argument out of range at line no 156}
  {# define  lh_OPENSSL_STRING_node_usage_stats_bio(lh,out) OPENSSL_LH_node_usage_stats_bio(ossl_check_const_OPENSSL_STRING_lh_type(lh),
 out)} {Function argument out of range at line no 157}
  {# define  lh_OPENSSL_STRING_stats_bio(lh,out) OPENSSL_LH_stats_bio(ossl_check_const_OPENSSL_STRING_lh_type(lh), out)} {Function argument out of range at line no 158}
  function lh_OPENSSL_STRING_get_down_load(lh:Plhash_st_OPENSSL_STRING): TOpenSSL_C_UINT; inline;
  {# define  lh_OPENSSL_STRING_set_down_load(lh,dl) OPENSSL_LH_set_down_load(ossl_check_OPENSSL_STRING_lh_type(lh), dl)} {Function argument out of range at line no 160}
  procedure lh_OPENSSL_STRING_doall(lh:Plhash_st_OPENSSL_STRING; dfn:Tlh_OPENSSL_STRING_doallfunc); inline;

type
  {Auto-generated forward references}
  Plh_OPENSSL_CSTRING_dummy = ^Tlh_OPENSSL_CSTRING_dummy;
  PPlh_OPENSSL_CSTRING_dummy = ^Plh_OPENSSL_CSTRING_dummy;
  Plhash_st_OPENSSL_CSTRING = ^Tlhash_st_OPENSSL_CSTRING;
  PPlhash_st_OPENSSL_CSTRING = ^Plhash_st_OPENSSL_CSTRING;
  Plh_OPENSSL_CSTRING_compfunc = ^Tlh_OPENSSL_CSTRING_compfunc;
  PPlh_OPENSSL_CSTRING_compfunc = ^Plh_OPENSSL_CSTRING_compfunc;
  Plh_OPENSSL_CSTRING_hashfunc = ^Tlh_OPENSSL_CSTRING_hashfunc;
  PPlh_OPENSSL_CSTRING_hashfunc = ^Plh_OPENSSL_CSTRING_hashfunc;
  Plh_OPENSSL_CSTRING_doallfunc = ^Tlh_OPENSSL_CSTRING_doallfunc;
  PPlh_OPENSSL_CSTRING_doallfunc = ^Plh_OPENSSL_CSTRING_doallfunc;
  {end of auto-generated forward references}

  Tlh_OPENSSL_CSTRING_dummy = record 
    case integer of 
      0: (d1: pointer);
      1: (d2: TOpenSSL_C_UINT);
      2: (d3: TOpenSSL_C_INT);
  end;
  Tlhash_st_OPENSSL_CSTRING = record 
    dummy: Tlh_OPENSSL_CSTRING_dummy;
  end;
  Tlh_OPENSSL_CSTRING_compfunc = function(a: POPENSSL_CSTRING; b: POPENSSL_CSTRING): TOpenSSL_C_INT; cdecl;
  Tlh_OPENSSL_CSTRING_hashfunc = function(a: POPENSSL_CSTRING): TOpenSSL_C_UINT; cdecl;
  Tlh_OPENSSL_CSTRING_doallfunc = procedure(a: POPENSSL_CSTRING); cdecl;


  function ossl_check_OPENSSL_CSTRING_lh_plain_type(ptr: POPENSSL_CSTRING): POPENSSL_CSTRING{Has C Attribute: unused}; inline;
  function ossl_check_const_OPENSSL_CSTRING_lh_plain_type(ptr: POPENSSL_CSTRING): POPENSSL_CSTRING{Has C Attribute: unused}; inline;
  function ossl_check_const_OPENSSL_CSTRING_lh_type(lh: Plhash_st_OPENSSL_CSTRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_CSTRING_lh_type(lh: Plhash_st_OPENSSL_CSTRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_CSTRING_lh_compfunc_type(cmp: Tlh_OPENSSL_CSTRING_compfunc): TOPENSSL_LH_COMPFUNC{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_CSTRING_lh_hashfunc_type(hfn: Tlh_OPENSSL_CSTRING_hashfunc): TOPENSSL_LH_HASHFUNC{Has C Attribute: unused}; inline;
  function ossl_check_OPENSSL_CSTRING_lh_doallfunc_type(dfn: Tlh_OPENSSL_CSTRING_doallfunc): TOPENSSL_LH_DOALL_FUNC{Has C Attribute: unused}; inline;
  {# define  lh_OPENSSL_CSTRING_new(hfn,cmp) ((LHASH_OF(OPENSSL_CSTRING) *)OPENSSL_LH_new(ossl_check_OPENSSL_CSTRING_lh_hashfunc_type(hfn),
 ossl_check_OPENSSL_CSTRING_lh_compfunc_type(cmp)))}
  procedure lh_OPENSSL_CSTRING_free(lh:Plhash_st_OPENSSL_CSTRING); inline;
  procedure lh_OPENSSL_CSTRING_flush(lh:Plhash_st_OPENSSL_CSTRING); inline;
  {# define  lh_OPENSSL_CSTRING_insert(lh,ptr) ((OPENSSL_CSTRING *)OPENSSL_LH_insert(ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_check_OPENSSL_CSTRING_lh_plain_type(ptr)))}
  {# define  lh_OPENSSL_CSTRING_delete(lh,ptr) ((OPENSSL_CSTRING *)OPENSSL_LH_delete(ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_check_const_OPENSSL_CSTRING_lh_plain_type(ptr)))}
  {# define  lh_OPENSSL_CSTRING_retrieve(lh,ptr) ((OPENSSL_CSTRING *)OPENSSL_LH_retrieve(ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_check_const_OPENSSL_CSTRING_lh_plain_type(ptr)))}
  function lh_OPENSSL_CSTRING_error(lh:Plhash_st_OPENSSL_CSTRING): TOpenSSL_C_INT; inline;
  function lh_OPENSSL_CSTRING_num_items(lh:Plhash_st_OPENSSL_CSTRING): TOpenSSL_C_UINT; inline;
  {# define  lh_OPENSSL_CSTRING_node_stats_bio(lh,out) OPENSSL_LH_node_stats_bio(ossl_check_const_OPENSSL_CSTRING_lh_type(lh), out)} {Function argument out of range at line no 171}
  {# define  lh_OPENSSL_CSTRING_node_usage_stats_bio(lh,out) OPENSSL_LH_node_usage_stats_bio(ossl_check_const_OPENSSL_CSTRING_lh_type(lh),
 out)} {Function argument out of range at line no 172}
  {# define  lh_OPENSSL_CSTRING_stats_bio(lh,out) OPENSSL_LH_stats_bio(ossl_check_const_OPENSSL_CSTRING_lh_type(lh), out)} {Function argument out of range at line no 173}
  function lh_OPENSSL_CSTRING_get_down_load(lh:Plhash_st_OPENSSL_CSTRING): TOpenSSL_C_UINT; inline;
  {# define  lh_OPENSSL_CSTRING_set_down_load(lh,dl) OPENSSL_LH_set_down_load(ossl_check_OPENSSL_CSTRING_lh_type(lh), dl)} {Function argument out of range at line no 175}
  procedure lh_OPENSSL_CSTRING_doall(lh:Plhash_st_OPENSSL_CSTRING; dfn:Tlh_OPENSSL_CSTRING_doallfunc); inline;
  { clang-format on }
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

function ossl_check_OPENSSL_STRING_lh_plain_type(ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_OPENSSL_STRING_lh_plain_type(ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_OPENSSL_STRING_lh_type(lh: Plhash_st_OPENSSL_STRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_LHASH(lh);
end;

function ossl_check_OPENSSL_STRING_lh_type(lh: Plhash_st_OPENSSL_STRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_LHASH(lh);
end;

function ossl_check_OPENSSL_STRING_lh_compfunc_type(cmp: Tlh_OPENSSL_STRING_compfunc): TOPENSSL_LH_COMPFUNC{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_LH_COMPFUNC(cmp);
end;

function ossl_check_OPENSSL_STRING_lh_hashfunc_type(hfn: Tlh_OPENSSL_STRING_hashfunc): TOPENSSL_LH_HASHFUNC{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_LH_HASHFUNC(hfn);
end;

function ossl_check_OPENSSL_STRING_lh_doallfunc_type(dfn: Tlh_OPENSSL_STRING_doallfunc): TOPENSSL_LH_DOALL_FUNC{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_LH_DOALL_FUNC(dfn);
end;


{# define  lh_OPENSSL_STRING_free(lh) OPENSSL_LH_free(ossl_check_OPENSSL_STRING_lh_type(lh))}

procedure lh_OPENSSL_STRING_free(lh:Plhash_st_OPENSSL_STRING);
begin
  OPENSSL_LH_free(ossl_check_OPENSSL_STRING_lh_type(lh));
end;

{# define  lh_OPENSSL_STRING_flush(lh) OPENSSL_LH_flush(ossl_check_OPENSSL_STRING_lh_type(lh))}

procedure lh_OPENSSL_STRING_flush(lh:Plhash_st_OPENSSL_STRING);
begin
  OPENSSL_LH_flush(ossl_check_OPENSSL_STRING_lh_type(lh));
end;

{# define  lh_OPENSSL_STRING_error(lh) OPENSSL_LH_error(ossl_check_OPENSSL_STRING_lh_type(lh))}

function lh_OPENSSL_STRING_error(lh:Plhash_st_OPENSSL_STRING): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_LH_error(ossl_check_OPENSSL_STRING_lh_type(lh)));
end;

{# define  lh_OPENSSL_STRING_num_items(lh) OPENSSL_LH_num_items(ossl_check_OPENSSL_STRING_lh_type(lh))}

function lh_OPENSSL_STRING_num_items(lh:Plhash_st_OPENSSL_STRING): TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(OPENSSL_LH_num_items(ossl_check_OPENSSL_STRING_lh_type(lh)));
end;

{# define  lh_OPENSSL_STRING_get_down_load(lh) OPENSSL_LH_get_down_load(ossl_check_OPENSSL_STRING_lh_type(lh))}

function lh_OPENSSL_STRING_get_down_load(lh:Plhash_st_OPENSSL_STRING): TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(OPENSSL_LH_get_down_load(ossl_check_OPENSSL_STRING_lh_type(lh)));
end;

{# define  lh_OPENSSL_STRING_doall(lh,dfn) OPENSSL_LH_doall(ossl_check_OPENSSL_STRING_lh_type(lh), ossl_check_OPENSSL_STRING_lh_doallfunc_type(dfn))}

procedure lh_OPENSSL_STRING_doall(lh:Plhash_st_OPENSSL_STRING; dfn:Tlh_OPENSSL_STRING_doallfunc);
begin
  OPENSSL_LH_doall(ossl_check_OPENSSL_STRING_lh_type(lh),ossl_check_OPENSSL_STRING_lh_doallfunc_type(dfn));
end;
function ossl_check_OPENSSL_CSTRING_lh_plain_type(ptr: POPENSSL_CSTRING): POPENSSL_CSTRING{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_OPENSSL_CSTRING_lh_plain_type(ptr: POPENSSL_CSTRING): POPENSSL_CSTRING{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_OPENSSL_CSTRING_lh_type(lh: Plhash_st_OPENSSL_CSTRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_LHASH(lh);
end;

function ossl_check_OPENSSL_CSTRING_lh_type(lh: Plhash_st_OPENSSL_CSTRING): POPENSSL_LHASH{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_LHASH(lh);
end;

function ossl_check_OPENSSL_CSTRING_lh_compfunc_type(cmp: Tlh_OPENSSL_CSTRING_compfunc): TOPENSSL_LH_COMPFUNC{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_LH_COMPFUNC(cmp);
end;

function ossl_check_OPENSSL_CSTRING_lh_hashfunc_type(hfn: Tlh_OPENSSL_CSTRING_hashfunc): TOPENSSL_LH_HASHFUNC{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_LH_HASHFUNC(hfn);
end;

function ossl_check_OPENSSL_CSTRING_lh_doallfunc_type(dfn: Tlh_OPENSSL_CSTRING_doallfunc): TOPENSSL_LH_DOALL_FUNC{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_LH_DOALL_FUNC(dfn);
end;


{# define  lh_OPENSSL_CSTRING_free(lh) OPENSSL_LH_free(ossl_check_OPENSSL_CSTRING_lh_type(lh))}

procedure lh_OPENSSL_CSTRING_free(lh:Plhash_st_OPENSSL_CSTRING);
begin
  OPENSSL_LH_free(ossl_check_OPENSSL_CSTRING_lh_type(lh));
end;

{# define  lh_OPENSSL_CSTRING_flush(lh) OPENSSL_LH_flush(ossl_check_OPENSSL_CSTRING_lh_type(lh))}

procedure lh_OPENSSL_CSTRING_flush(lh:Plhash_st_OPENSSL_CSTRING);
begin
  OPENSSL_LH_flush(ossl_check_OPENSSL_CSTRING_lh_type(lh));
end;

{# define  lh_OPENSSL_CSTRING_error(lh) OPENSSL_LH_error(ossl_check_OPENSSL_CSTRING_lh_type(lh))}

function lh_OPENSSL_CSTRING_error(lh:Plhash_st_OPENSSL_CSTRING): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_LH_error(ossl_check_OPENSSL_CSTRING_lh_type(lh)));
end;

{# define  lh_OPENSSL_CSTRING_num_items(lh) OPENSSL_LH_num_items(ossl_check_OPENSSL_CSTRING_lh_type(lh))}

function lh_OPENSSL_CSTRING_num_items(lh:Plhash_st_OPENSSL_CSTRING): TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(OPENSSL_LH_num_items(ossl_check_OPENSSL_CSTRING_lh_type(lh)));
end;

{# define  lh_OPENSSL_CSTRING_get_down_load(lh) OPENSSL_LH_get_down_load(ossl_check_OPENSSL_CSTRING_lh_type(lh))}

function lh_OPENSSL_CSTRING_get_down_load(lh:Plhash_st_OPENSSL_CSTRING): TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(OPENSSL_LH_get_down_load(ossl_check_OPENSSL_CSTRING_lh_type(lh)));
end;

{# define  lh_OPENSSL_CSTRING_doall(lh,dfn) OPENSSL_LH_doall(ossl_check_OPENSSL_CSTRING_lh_type(lh), ossl_check_OPENSSL_CSTRING_lh_doallfunc_type(dfn))}

procedure lh_OPENSSL_CSTRING_doall(lh:Plhash_st_OPENSSL_CSTRING; dfn:Tlh_OPENSSL_CSTRING_doallfunc);
begin
  OPENSSL_LH_doall(ossl_check_OPENSSL_CSTRING_lh_type(lh),ossl_check_OPENSSL_CSTRING_lh_doallfunc_type(dfn));
end;
{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_OPENSSL_LH_error(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl;
begin
  OPENSSL_LH_error := LoadLibCryptoFunction('OPENSSL_LH_error');
  if not assigned(OPENSSL_LH_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_error');
  Result := OPENSSL_LH_error(lh);
end;

function Load_OPENSSL_LH_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl;
begin
  OPENSSL_LH_new := LoadLibCryptoFunction('OPENSSL_LH_new');
  if not assigned(OPENSSL_LH_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_new');
  Result := OPENSSL_LH_new(h, c);
end;

procedure Load_OPENSSL_LH_free(lh: POPENSSL_LHASH); cdecl;
begin
  OPENSSL_LH_free := LoadLibCryptoFunction('OPENSSL_LH_free');
  if not assigned(OPENSSL_LH_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_free');
  OPENSSL_LH_free(lh);
end;

procedure Load_OPENSSL_LH_flush(lh: POPENSSL_LHASH); cdecl;
begin
  OPENSSL_LH_flush := LoadLibCryptoFunction('OPENSSL_LH_flush');
  if not assigned(OPENSSL_LH_flush) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_flush');
  OPENSSL_LH_flush(lh);
end;

function Load_OPENSSL_LH_insert(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
begin
  OPENSSL_LH_insert := LoadLibCryptoFunction('OPENSSL_LH_insert');
  if not assigned(OPENSSL_LH_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_insert');
  Result := OPENSSL_LH_insert(lh, data);
end;

function Load_OPENSSL_LH_delete(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
begin
  OPENSSL_LH_delete := LoadLibCryptoFunction('OPENSSL_LH_delete');
  if not assigned(OPENSSL_LH_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_delete');
  Result := OPENSSL_LH_delete(lh, data);
end;

function Load_OPENSSL_LH_retrieve(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
begin
  OPENSSL_LH_retrieve := LoadLibCryptoFunction('OPENSSL_LH_retrieve');
  if not assigned(OPENSSL_LH_retrieve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_retrieve');
  Result := OPENSSL_LH_retrieve(lh, data);
end;

procedure Load_OPENSSL_LH_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl;
begin
  OPENSSL_LH_doall := LoadLibCryptoFunction('OPENSSL_LH_doall');
  if not assigned(OPENSSL_LH_doall) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_doall');
  OPENSSL_LH_doall(lh, func);
end;

procedure Load_OPENSSL_LH_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl;
begin
  OPENSSL_LH_doall_arg := LoadLibCryptoFunction('OPENSSL_LH_doall_arg');
  if not assigned(OPENSSL_LH_doall_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_doall_arg');
  OPENSSL_LH_doall_arg(lh, func, arg);
end;

function Load_OPENSSL_LH_strhash(c: PAnsiChar): TOpenSSL_C_UINT; cdecl;
begin
  OPENSSL_LH_strhash := LoadLibCryptoFunction('OPENSSL_LH_strhash');
  if not assigned(OPENSSL_LH_strhash) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_strhash');
  Result := OPENSSL_LH_strhash(c);
end;

function Load_OPENSSL_LH_num_items(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl;
begin
  OPENSSL_LH_num_items := LoadLibCryptoFunction('OPENSSL_LH_num_items');
  if not assigned(OPENSSL_LH_num_items) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_num_items');
  Result := OPENSSL_LH_num_items(lh);
end;

function Load_OPENSSL_LH_get_down_load(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl;
begin
  OPENSSL_LH_get_down_load := LoadLibCryptoFunction('OPENSSL_LH_get_down_load');
  if not assigned(OPENSSL_LH_get_down_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_get_down_load');
  Result := OPENSSL_LH_get_down_load(lh);
end;

procedure Load_OPENSSL_LH_set_down_load(lh: POPENSSL_LHASH; down_load: TOpenSSL_C_UINT); cdecl;
begin
  OPENSSL_LH_set_down_load := LoadLibCryptoFunction('OPENSSL_LH_set_down_load');
  if not assigned(OPENSSL_LH_set_down_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_set_down_load');
  OPENSSL_LH_set_down_load(lh, down_load);
end;

{$ifndef  OPENSSL_NO_STDIO}
procedure Load_OPENSSL_LH_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
begin
  OPENSSL_LH_stats := LoadLibCryptoFunction('OPENSSL_LH_stats');
  if not assigned(OPENSSL_LH_stats) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_stats');
  OPENSSL_LH_stats(lh, fp);
end;

procedure Load_OPENSSL_LH_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
begin
  OPENSSL_LH_node_stats := LoadLibCryptoFunction('OPENSSL_LH_node_stats');
  if not assigned(OPENSSL_LH_node_stats) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_stats');
  OPENSSL_LH_node_stats(lh, fp);
end;

procedure Load_OPENSSL_LH_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
begin
  OPENSSL_LH_node_usage_stats := LoadLibCryptoFunction('OPENSSL_LH_node_usage_stats');
  if not assigned(OPENSSL_LH_node_usage_stats) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_usage_stats');
  OPENSSL_LH_node_usage_stats(lh, fp);
end;

{$endif} { OPENSSL_NO_STDIO}
procedure Load_OPENSSL_LH_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
begin
  OPENSSL_LH_stats_bio := LoadLibCryptoFunction('OPENSSL_LH_stats_bio');
  if not assigned(OPENSSL_LH_stats_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_stats_bio');
  OPENSSL_LH_stats_bio(lh, out_);
end;

procedure Load_OPENSSL_LH_node_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
begin
  OPENSSL_LH_node_stats_bio := LoadLibCryptoFunction('OPENSSL_LH_node_stats_bio');
  if not assigned(OPENSSL_LH_node_stats_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_stats_bio');
  OPENSSL_LH_node_stats_bio(lh, out_);
end;

procedure Load_OPENSSL_LH_node_usage_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
begin
  OPENSSL_LH_node_usage_stats_bio := LoadLibCryptoFunction('OPENSSL_LH_node_usage_stats_bio');
  if not assigned(OPENSSL_LH_node_usage_stats_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_usage_stats_bio');
  OPENSSL_LH_node_usage_stats_bio(lh, out_);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
function Load_lh_error(lh: POPENSSL_LHASH): TOpenSSL_C_INT; cdecl;
begin
  lh_error := LoadLibCryptoFunction('OPENSSL_LH_error');
  if not assigned(lh_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_error');
  Result := lh_error(lh);
end;

function Load_lh_new(h: TOPENSSL_LH_HASHFUNC; c: TOPENSSL_LH_COMPFUNC): POPENSSL_LHASH; cdecl;
begin
  lh_new := LoadLibCryptoFunction('OPENSSL_LH_new');
  if not assigned(lh_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_new');
  Result := lh_new(h, c);
end;

procedure Load_lh_free(lh: POPENSSL_LHASH); cdecl;
begin
  lh_free := LoadLibCryptoFunction('OPENSSL_LH_free');
  if not assigned(lh_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_free');
  lh_free(lh);
end;

function Load_lh_insert(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
begin
  lh_insert := LoadLibCryptoFunction('OPENSSL_LH_insert');
  if not assigned(lh_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_insert');
  Result := lh_insert(lh, data);
end;

function Load_lh_delete(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
begin
  lh_delete := LoadLibCryptoFunction('OPENSSL_LH_delete');
  if not assigned(lh_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_delete');
  Result := lh_delete(lh, data);
end;

function Load_lh_retrieve(lh: POPENSSL_LHASH; data: pointer): pointer; cdecl;
begin
  lh_retrieve := LoadLibCryptoFunction('OPENSSL_LH_retrieve');
  if not assigned(lh_retrieve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_retrieve');
  Result := lh_retrieve(lh, data);
end;

procedure Load_lh_doall(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNC); cdecl;
begin
  lh_doall := LoadLibCryptoFunction('OPENSSL_LH_doall');
  if not assigned(lh_doall) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_doall');
  lh_doall(lh, func);
end;

procedure Load_lh_doall_arg(lh: POPENSSL_LHASH; func: TOPENSSL_LH_DOALL_FUNCARG; arg: pointer); cdecl;
begin
  lh_doall_arg := LoadLibCryptoFunction('OPENSSL_LH_doall_arg');
  if not assigned(lh_doall_arg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_doall_arg');
  lh_doall_arg(lh, func, arg);
end;

function Load_lh_strhash(c: PAnsiChar): TOpenSSL_C_UINT; cdecl;
begin
  lh_strhash := LoadLibCryptoFunction('OPENSSL_LH_strhash');
  if not assigned(lh_strhash) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_strhash');
  Result := lh_strhash(c);
end;

function Load_lh_num_items(lh: POPENSSL_LHASH): TOpenSSL_C_UINT; cdecl;
begin
  lh_num_items := LoadLibCryptoFunction('OPENSSL_LH_num_items');
  if not assigned(lh_num_items) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_num_items');
  Result := lh_num_items(lh);
end;

    {$ifndef  OPENSSL_NO_STDIO}
procedure Load_lh_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
begin
  lh_stats := LoadLibCryptoFunction('OPENSSL_LH_stats');
  if not assigned(lh_stats) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_stats');
  lh_stats(lh, fp);
end;

procedure Load_lh_node_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
begin
  lh_node_stats := LoadLibCryptoFunction('OPENSSL_LH_node_stats');
  if not assigned(lh_node_stats) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_stats');
  lh_node_stats(lh, fp);
end;

procedure Load_lh_node_usage_stats(lh: POPENSSL_LHASH; fp: PFILE); cdecl;
begin
  lh_node_usage_stats := LoadLibCryptoFunction('OPENSSL_LH_node_usage_stats');
  if not assigned(lh_node_usage_stats) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_usage_stats');
  lh_node_usage_stats(lh, fp);
end;

    {$endif} { OPENSSL_NO_STDIO}
procedure Load_lh_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
begin
  lh_stats_bio := LoadLibCryptoFunction('OPENSSL_LH_stats_bio');
  if not assigned(lh_stats_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_stats_bio');
  lh_stats_bio(lh, out_);
end;

procedure Load_lh_node_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
begin
  lh_node_stats_bio := LoadLibCryptoFunction('OPENSSL_LH_node_stats_bio');
  if not assigned(lh_node_stats_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_stats_bio');
  lh_node_stats_bio(lh, out_);
end;

procedure Load_lh_node_usage_stats_bio(lh: POPENSSL_LHASH; out_: PBIO); cdecl;
begin
  lh_node_usage_stats_bio := LoadLibCryptoFunction('OPENSSL_LH_node_usage_stats_bio');
  if not assigned(lh_node_usage_stats_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_LH_node_usage_stats_bio');
  lh_node_usage_stats_bio(lh, out_);
end;

{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OPENSSL_LH_error := Load_OPENSSL_LH_error;
  OPENSSL_LH_new := Load_OPENSSL_LH_new;
  OPENSSL_LH_free := Load_OPENSSL_LH_free;
  OPENSSL_LH_flush := Load_OPENSSL_LH_flush;
  OPENSSL_LH_insert := Load_OPENSSL_LH_insert;
  OPENSSL_LH_delete := Load_OPENSSL_LH_delete;
  OPENSSL_LH_retrieve := Load_OPENSSL_LH_retrieve;
  OPENSSL_LH_doall := Load_OPENSSL_LH_doall;
  OPENSSL_LH_doall_arg := Load_OPENSSL_LH_doall_arg;
  OPENSSL_LH_strhash := Load_OPENSSL_LH_strhash;
  OPENSSL_LH_num_items := Load_OPENSSL_LH_num_items;
  OPENSSL_LH_get_down_load := Load_OPENSSL_LH_get_down_load;
  OPENSSL_LH_set_down_load := Load_OPENSSL_LH_set_down_load;
{$ifndef  OPENSSL_NO_STDIO}
  OPENSSL_LH_stats := Load_OPENSSL_LH_stats;
  OPENSSL_LH_node_stats := Load_OPENSSL_LH_node_stats;
  OPENSSL_LH_node_usage_stats := Load_OPENSSL_LH_node_usage_stats;
{$endif} { OPENSSL_NO_STDIO}
  OPENSSL_LH_stats_bio := Load_OPENSSL_LH_stats_bio;
  OPENSSL_LH_node_stats_bio := Load_OPENSSL_LH_node_stats_bio;
  OPENSSL_LH_node_usage_stats_bio := Load_OPENSSL_LH_node_usage_stats_bio;
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  lh_error := Load_lh_error;
  lh_new := Load_lh_new;
  lh_free := Load_lh_free;
  lh_insert := Load_lh_insert;
  lh_delete := Load_lh_delete;
  lh_retrieve := Load_lh_retrieve;
  lh_doall := Load_lh_doall;
  lh_doall_arg := Load_lh_doall_arg;
  lh_strhash := Load_lh_strhash;
  lh_num_items := Load_lh_num_items;
    {$ifndef  OPENSSL_NO_STDIO}
  lh_stats := Load_lh_stats;
  lh_node_stats := Load_lh_node_stats;
  lh_node_usage_stats := Load_lh_node_usage_stats;
    {$endif} { OPENSSL_NO_STDIO}
  lh_stats_bio := Load_lh_stats_bio;
  lh_node_stats_bio := Load_lh_node_stats_bio;
  lh_node_usage_stats_bio := Load_lh_node_usage_stats_bio;
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



