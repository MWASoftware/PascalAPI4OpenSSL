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

unit openssl_objects;

{
  Generated from OpenSSL 3.6.2 Header File objects.h - Tue 19 May 14:30:17 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_objects.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_obj_mac,openssl_bio,openssl_asn1,
     openssl_objectserr;


{* Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_OBJECTS_H}
  {$define OPENSSL_OBJECTS_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_OBJECTS_H}
  {$endif}

const
  OBJ_NAME_TYPE_UNDEF = $00;
  OBJ_NAME_TYPE_MD_METH = $01;
  OBJ_NAME_TYPE_CIPHER_METH = $02;
  OBJ_NAME_TYPE_PKEY_METH = $03;
  OBJ_NAME_TYPE_COMP_METH = $04;
  OBJ_NAME_TYPE_MAC_METH = $05;
  OBJ_NAME_TYPE_KDF_METH = $06;
  OBJ_NAME_TYPE_NUM = $07;
  OBJ_NAME_ALIAS = $8000;
  OBJ_BSEARCH_VALUE_ON_NOMATCH = $01;
  OBJ_BSEARCH_FIRST_VALUE_ON_MATCH = $02;

type
  {Auto-generated forward references}
  Pobj_name_st = ^Tobj_name_st;
  PPobj_name_st = ^Pobj_name_st;
  POBJ_NAME = ^TOBJ_NAME;
  PPOBJ_NAME = ^POBJ_NAME;
  {end of auto-generated forward references}

  Tobj_name_st = record 
    type_: TOpenSSL_C_INT;
    alias: TOpenSSL_C_INT;
    name: PAnsiChar;
    data: PAnsiChar;
  end;
  TOBJ_NAME = Tobj_name_st;


  function OBJ_create_and_add_object(a:PAnsiChar; b:PAnsiChar; c:PAnsiChar): TOpenSSL_C_INT; inline;
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OBJ_NAME_init: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_NAME_init';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OBJ_NAME_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OBJ_NAME_init: TOpenSSL_C_INT; cdecl;

var
  OBJ_NAME_init: function: TOpenSSL_C_INT; cdecl = Load_OBJ_NAME_init;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  {end of auto-generated forward references}

  TFuncType000 = function(_param1: PAnsiChar): TOpenSSL_C_UINT; cdecl;
  TFuncType001 = function(_param1: PAnsiChar; _param2: PAnsiChar): TOpenSSL_C_INT; cdecl;
  TFuncType002 = procedure(_param1: PAnsiChar; _param2: TOpenSSL_C_INT; _param3: PAnsiChar); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OBJ_NAME_new_index(hash_func: TFuncType000; cmp_func: TFuncType001; free_func: TFuncType002): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_NAME_new_index';
  function OBJ_NAME_get(name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OBJ_NAME_get';
  function OBJ_NAME_add(name: PAnsiChar; type_: TOpenSSL_C_INT; data: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_NAME_add';
  function OBJ_NAME_remove(name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_NAME_remove';
  procedure OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'OBJ_NAME_cleanup';
  { -1 for everything }
  {$else}
  {$EXTERNALSYM OBJ_NAME_new_index}
  {$EXTERNALSYM OBJ_NAME_get}
  {$EXTERNALSYM OBJ_NAME_add}
  {$EXTERNALSYM OBJ_NAME_remove}
  {$EXTERNALSYM OBJ_NAME_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OBJ_NAME_new_index(hash_func: TFuncType000; cmp_func: TFuncType001; free_func: TFuncType002): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_NAME_get(name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
  function Load_OBJ_NAME_add(name: PAnsiChar; type_: TOpenSSL_C_INT; data: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_NAME_remove(name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl;

var
  OBJ_NAME_new_index: function(hash_func: TFuncType000; cmp_func: TFuncType001; free_func: TFuncType002): TOpenSSL_C_INT; cdecl = Load_OBJ_NAME_new_index;
  OBJ_NAME_get: function(name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OBJ_NAME_get;
  OBJ_NAME_add: function(name: PAnsiChar; type_: TOpenSSL_C_INT; data: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_NAME_add;
  OBJ_NAME_remove: function(name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_NAME_remove;
  OBJ_NAME_cleanup: procedure(type_: TOpenSSL_C_INT); cdecl = Load_OBJ_NAME_cleanup;
  { -1 for everything }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType003 = ^TFuncType003;
  PPFuncType003 = ^PFuncType003;
  {end of auto-generated forward references}

  TFuncType003 = procedure(_param1: POBJ_NAME; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OBJ_NAME_do_all(type_: TOpenSSL_C_INT; fn: TFuncType003; arg: pointer); cdecl; external CLibCrypto name 'OBJ_NAME_do_all';
  {$else}
  {$EXTERNALSYM OBJ_NAME_do_all}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OBJ_NAME_do_all(type_: TOpenSSL_C_INT; fn: TFuncType003; arg: pointer); cdecl;

var
  OBJ_NAME_do_all: procedure(type_: TOpenSSL_C_INT; fn: TFuncType003; arg: pointer); cdecl = Load_OBJ_NAME_do_all;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType004 = ^TFuncType004;
  PPFuncType004 = ^PFuncType004;
  {end of auto-generated forward references}

  TFuncType004 = procedure(_param1: POBJ_NAME; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OBJ_NAME_do_all_sorted(type_: TOpenSSL_C_INT; fn: TFuncType004; arg: pointer); cdecl; external CLibCrypto name 'OBJ_NAME_do_all_sorted';
  function OBJ_dup(a: PASN1_OBJECT): PASN1_OBJECT; cdecl; external CLibCrypto name 'OBJ_dup';
  function OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl; external CLibCrypto name 'OBJ_nid2obj';
  function OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OBJ_nid2ln';
  function OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OBJ_nid2sn';
  function OBJ_obj2nid(o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_obj2nid';
  function OBJ_txt2obj(s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl; external CLibCrypto name 'OBJ_txt2obj';
  function OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_obj2txt';
  function OBJ_txt2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_txt2nid';
  function OBJ_ln2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_ln2nid';
  function OBJ_sn2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_sn2nid';
  function OBJ_cmp(a: PASN1_OBJECT; b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_cmp';
  {$else}
  {$EXTERNALSYM OBJ_NAME_do_all_sorted}
  {$EXTERNALSYM OBJ_dup}
  {$EXTERNALSYM OBJ_nid2obj}
  {$EXTERNALSYM OBJ_nid2ln}
  {$EXTERNALSYM OBJ_nid2sn}
  {$EXTERNALSYM OBJ_obj2nid}
  {$EXTERNALSYM OBJ_txt2obj}
  {$EXTERNALSYM OBJ_obj2txt}
  {$EXTERNALSYM OBJ_txt2nid}
  {$EXTERNALSYM OBJ_ln2nid}
  {$EXTERNALSYM OBJ_sn2nid}
  {$EXTERNALSYM OBJ_cmp}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OBJ_NAME_do_all_sorted(type_: TOpenSSL_C_INT; fn: TFuncType004; arg: pointer); cdecl;
  function Load_OBJ_dup(a: PASN1_OBJECT): PASN1_OBJECT; cdecl;
  function Load_OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
  function Load_OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
  function Load_OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
  function Load_OBJ_obj2nid(o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_txt2obj(s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
  function Load_OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_txt2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_ln2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_sn2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_cmp(a: PASN1_OBJECT; b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;

var
  OBJ_NAME_do_all_sorted: procedure(type_: TOpenSSL_C_INT; fn: TFuncType004; arg: pointer); cdecl = Load_OBJ_NAME_do_all_sorted;
  OBJ_dup: function(a: PASN1_OBJECT): PASN1_OBJECT; cdecl = Load_OBJ_dup;
  OBJ_nid2obj: function(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl = Load_OBJ_nid2obj;
  OBJ_nid2ln: function(n: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OBJ_nid2ln;
  OBJ_nid2sn: function(n: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OBJ_nid2sn;
  OBJ_obj2nid: function(o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_OBJ_obj2nid;
  OBJ_txt2obj: function(s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl = Load_OBJ_txt2obj;
  OBJ_obj2txt: function(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_obj2txt;
  OBJ_txt2nid: function(s: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_txt2nid;
  OBJ_ln2nid: function(s: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_ln2nid;
  OBJ_sn2nid: function(s: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_sn2nid;
  OBJ_cmp: function(a: PASN1_OBJECT; b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_OBJ_cmp;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType005 = ^TFuncType005;
  PPFuncType005 = ^PFuncType005;
  {end of auto-generated forward references}

  TFuncType005 = function(_param1: pointer; _param2: pointer): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OBJ_bsearch_(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType005): pointer; cdecl; external CLibCrypto name 'OBJ_bsearch_';
  {$else}
  {$EXTERNALSYM OBJ_bsearch_}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OBJ_bsearch_(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType005): pointer; cdecl;

var
  OBJ_bsearch_: function(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType005): pointer; cdecl = Load_OBJ_bsearch_;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType006 = ^TFuncType006;
  PPFuncType006 = ^PFuncType006;
  {end of auto-generated forward references}

  TFuncType006 = function(_param1: pointer; _param2: pointer): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OBJ_bsearch_ex_(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType006; flags: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'OBJ_bsearch_ex_';
  {$else}
  {$EXTERNALSYM OBJ_bsearch_ex_}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OBJ_bsearch_ex_(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType006; flags: TOpenSSL_C_INT): pointer; cdecl;

var
  OBJ_bsearch_ex_: function(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType006; flags: TOpenSSL_C_INT): pointer; cdecl = Load_OBJ_bsearch_ex_;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {# define  _DECLARE_OBJ_BSEARCH_CMP_FN(scope,type1,type2,nm) static int nm ##_cmp_BSEARCH_CMP_FN(const void *, const void *); static 
int nm ##_cmp(type1 const *, type2 const *); scope type2 *OBJ_bsearch_ ##nm(type1 *key, type2 const *base, int num)}
  {# define  DECLARE_OBJ_BSEARCH_CMP_FN(type1,type2,cmp) _DECLARE_OBJ_BSEARCH_CMP_FN(static, type1, type2, cmp)} { Blacklisted Macro}
  {# define  DECLARE_OBJ_BSEARCH_GLOBAL_CMP_FN(type1,type2,nm) type2 *OBJ_bsearch_ ##nm(type1 *key, type2 const *base, int num)}
  (*# define  IMPLEMENT_OBJ_BSEARCH_CMP_FN(type1,type2,nm) static int nm ##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_) { type1 
const *a = a_; type2 const *b = b_; return nm ##_cmp(a, b); } static type2 *OBJ_bsearch_ ##nm(type1 *key, type2 const *base, int 
num) { return (type2 * )OBJ_bsearch_(key, base, num, sizeof(type2), nm ##_cmp_BSEARCH_CMP_FN); } extern void dummy_prototype(void)*)
  (*# define  IMPLEMENT_OBJ_BSEARCH_GLOBAL_CMP_FN(type1,type2,nm) static int nm ##_cmp_BSEARCH_CMP_FN(const void *a_, const void *b_) 
{ type1 const *a = a_; type2 const *b = b_; return nm ##_cmp(a, b); } type2 *OBJ_bsearch_ ##nm(type1 *key, type2 const *base, int 
num) { return (type2 * )OBJ_bsearch_(key, base, num, sizeof(type2), nm ##_cmp_BSEARCH_CMP_FN); } extern void dummy_prototype(void)*)
  {# define  OBJ_bsearch(type1,key,type2,base,num,cmp) ((type2 *)OBJ_bsearch_(CHECKED_PTR_OF(type1, key), CHECKED_PTR_OF(type2, base),
 num, sizeof(type2), ((void)CHECKED_PTR_OF(type1, cmp ##_type_1), (void)CHECKED_PTR_OF(type2, cmp ##_type_2), cmp ##_BSEARCH_CMP_FN)))}
  {# define  OBJ_bsearch_ex(type1,key,type2,base,num,cmp,flags) ((type2 *)OBJ_bsearch_ex_(CHECKED_PTR_OF(type1, key), CHECKED_PTR_OF(type2,
 base), num, sizeof(type2), ((void)CHECKED_PTR_OF(type1, cmp ##_type_1), (void)type_2 = CHECKED_PTR_OF(type2, cmp ##_type_2), cmp 
##_BSEARCH_CMP_FN)), flags)}


  {-
  * Unsolved problem: if a type is actually a pointer type, like
  * nid_triple is, then its impossible to get a const where you need
  * it. Consider:
  *
  * typedef int nid_triple[3];
  * const void *a_;
  * const nid_triple const *a = a_;
  *
  * The assignment discards a const because what you really want is:
  *
  * const int const * const *a = a_;
  *
  * But if you do that, you lose the fact that a is an array of 3 ints,
  * which breaks comparison functions.
  *
  * Thus we end up having to cast, sadly, or unpack the
  * declarations. Or, as I finally did in this case, declare nid_triple
  * to be a struct, which it should have been in the first place.
  *
  * Ben, August 2008.
  *
  * Also, strictly speaking not all types need be const, but handling
  * the non-constness means a lot of complication, and in practice
  * comparison routines do always not touch their arguments.
  }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_new_nid';
  function OBJ_add_object(obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_add_object';
  function OBJ_create(oid: PAnsiChar; sn: PAnsiChar; ln: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_create';
  {$else}
  {$EXTERNALSYM OBJ_new_nid}
  {$EXTERNALSYM OBJ_add_object}
  {$EXTERNALSYM OBJ_create}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_add_object(obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_create(oid: PAnsiChar; sn: PAnsiChar; ln: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  OBJ_new_nid: function(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_new_nid;
  OBJ_add_object: function(obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_OBJ_add_object;
  OBJ_create: function(oid: PAnsiChar; sn: PAnsiChar; ln: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OBJ_create;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{# define  OBJ_cleanup() while (0) continue}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_create_objects';
  function OBJ_length(obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'OBJ_length';
  function OBJ_get0_data(obj: PASN1_OBJECT): Pbyte; cdecl; external CLibCrypto name 'OBJ_get0_data';
  function OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_find_sigid_algs';
  function OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_find_sigid_by_algs';
  function OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OBJ_add_sigid';
  procedure OBJ_sigid_free; cdecl; external CLibCrypto name 'OBJ_sigid_free';
  {$else}
  {$EXTERNALSYM OBJ_create_objects}
  {$EXTERNALSYM OBJ_length}
  {$EXTERNALSYM OBJ_get0_data}
  {$EXTERNALSYM OBJ_find_sigid_algs}
  {$EXTERNALSYM OBJ_find_sigid_by_algs}
  {$EXTERNALSYM OBJ_add_sigid}
  {$EXTERNALSYM OBJ_sigid_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_length(obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl;
  function Load_OBJ_get0_data(obj: PASN1_OBJECT): Pbyte; cdecl;
  function Load_OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_OBJ_sigid_free; cdecl;

var
  OBJ_create_objects: function(in_: PBIO): TOpenSSL_C_INT; cdecl = Load_OBJ_create_objects;
  OBJ_length: function(obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl = Load_OBJ_length;
  OBJ_get0_data: function(obj: PASN1_OBJECT): Pbyte; cdecl = Load_OBJ_get0_data;
  OBJ_find_sigid_algs: function(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_find_sigid_algs;
  OBJ_find_sigid_by_algs: function(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_find_sigid_by_algs;
  OBJ_add_sigid: function(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OBJ_add_sigid;
  OBJ_sigid_free: procedure; cdecl = Load_OBJ_sigid_free;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  SN_ac_auditEntity = SN_ac_auditIdentity;
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


{# define  OBJ_create_and_add_object(a,b,c) OBJ_create(a, b, c)}

function OBJ_create_and_add_object(a:PAnsiChar; b:PAnsiChar; c:PAnsiChar): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OBJ_create(a,b,c));
end;
{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_OBJ_NAME_init: TOpenSSL_C_INT; cdecl;
begin
  OBJ_NAME_init := LoadLibCryptoFunction('OBJ_NAME_init');
  if not assigned(OBJ_NAME_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_init');
  Result := OBJ_NAME_init;
end;

function Load_OBJ_NAME_new_index(hash_func: TFuncType000; cmp_func: TFuncType001; free_func: TFuncType002): TOpenSSL_C_INT; cdecl;
begin
  OBJ_NAME_new_index := LoadLibCryptoFunction('OBJ_NAME_new_index');
  if not assigned(OBJ_NAME_new_index) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_new_index');
  Result := OBJ_NAME_new_index(hash_func, cmp_func, free_func);
end;

function Load_OBJ_NAME_get(name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OBJ_NAME_get := LoadLibCryptoFunction('OBJ_NAME_get');
  if not assigned(OBJ_NAME_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_get');
  Result := OBJ_NAME_get(name, type_);
end;

function Load_OBJ_NAME_add(name: PAnsiChar; type_: TOpenSSL_C_INT; data: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_NAME_add := LoadLibCryptoFunction('OBJ_NAME_add');
  if not assigned(OBJ_NAME_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_add');
  Result := OBJ_NAME_add(name, type_, data);
end;

function Load_OBJ_NAME_remove(name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_NAME_remove := LoadLibCryptoFunction('OBJ_NAME_remove');
  if not assigned(OBJ_NAME_remove) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_remove');
  Result := OBJ_NAME_remove(name, type_);
end;

procedure Load_OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl;
begin
  OBJ_NAME_cleanup := LoadLibCryptoFunction('OBJ_NAME_cleanup');
  if not assigned(OBJ_NAME_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_cleanup');
  OBJ_NAME_cleanup(type_);
end;

procedure Load_OBJ_NAME_do_all(type_: TOpenSSL_C_INT; fn: TFuncType003; arg: pointer); cdecl;
begin
  OBJ_NAME_do_all := LoadLibCryptoFunction('OBJ_NAME_do_all');
  if not assigned(OBJ_NAME_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_do_all');
  OBJ_NAME_do_all(type_, fn, arg);
end;

procedure Load_OBJ_NAME_do_all_sorted(type_: TOpenSSL_C_INT; fn: TFuncType004; arg: pointer); cdecl;
begin
  OBJ_NAME_do_all_sorted := LoadLibCryptoFunction('OBJ_NAME_do_all_sorted');
  if not assigned(OBJ_NAME_do_all_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_do_all_sorted');
  OBJ_NAME_do_all_sorted(type_, fn, arg);
end;

function Load_OBJ_dup(a: PASN1_OBJECT): PASN1_OBJECT; cdecl;
begin
  OBJ_dup := LoadLibCryptoFunction('OBJ_dup');
  if not assigned(OBJ_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_dup');
  Result := OBJ_dup(a);
end;

function Load_OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
begin
  OBJ_nid2obj := LoadLibCryptoFunction('OBJ_nid2obj');
  if not assigned(OBJ_nid2obj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2obj');
  Result := OBJ_nid2obj(n);
end;

function Load_OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OBJ_nid2ln := LoadLibCryptoFunction('OBJ_nid2ln');
  if not assigned(OBJ_nid2ln) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2ln');
  Result := OBJ_nid2ln(n);
end;

function Load_OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OBJ_nid2sn := LoadLibCryptoFunction('OBJ_nid2sn');
  if not assigned(OBJ_nid2sn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2sn');
  Result := OBJ_nid2sn(n);
end;

function Load_OBJ_obj2nid(o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_obj2nid := LoadLibCryptoFunction('OBJ_obj2nid');
  if not assigned(OBJ_obj2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_obj2nid');
  Result := OBJ_obj2nid(o);
end;

function Load_OBJ_txt2obj(s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
begin
  OBJ_txt2obj := LoadLibCryptoFunction('OBJ_txt2obj');
  if not assigned(OBJ_txt2obj) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_txt2obj');
  Result := OBJ_txt2obj(s, no_name);
end;

function Load_OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_obj2txt := LoadLibCryptoFunction('OBJ_obj2txt');
  if not assigned(OBJ_obj2txt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_obj2txt');
  Result := OBJ_obj2txt(buf, buf_len, a, no_name);
end;

function Load_OBJ_txt2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_txt2nid := LoadLibCryptoFunction('OBJ_txt2nid');
  if not assigned(OBJ_txt2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_txt2nid');
  Result := OBJ_txt2nid(s);
end;

function Load_OBJ_ln2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_ln2nid := LoadLibCryptoFunction('OBJ_ln2nid');
  if not assigned(OBJ_ln2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_ln2nid');
  Result := OBJ_ln2nid(s);
end;

function Load_OBJ_sn2nid(s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_sn2nid := LoadLibCryptoFunction('OBJ_sn2nid');
  if not assigned(OBJ_sn2nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_sn2nid');
  Result := OBJ_sn2nid(s);
end;

function Load_OBJ_cmp(a: PASN1_OBJECT; b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_cmp := LoadLibCryptoFunction('OBJ_cmp');
  if not assigned(OBJ_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_cmp');
  Result := OBJ_cmp(a, b);
end;

function Load_OBJ_bsearch_(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType005): pointer; cdecl;
begin
  OBJ_bsearch_ := LoadLibCryptoFunction('OBJ_bsearch_');
  if not assigned(OBJ_bsearch_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_bsearch_');
  Result := OBJ_bsearch_(key, base, num, size, cmp);
end;

function Load_OBJ_bsearch_ex_(key: pointer; base: pointer; num: TOpenSSL_C_INT; size: TOpenSSL_C_INT; cmp: TFuncType006; flags: TOpenSSL_C_INT): pointer; cdecl;
begin
  OBJ_bsearch_ex_ := LoadLibCryptoFunction('OBJ_bsearch_ex_');
  if not assigned(OBJ_bsearch_ex_) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_bsearch_ex_');
  Result := OBJ_bsearch_ex_(key, base, num, size, cmp, flags);
end;

function Load_OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_new_nid := LoadLibCryptoFunction('OBJ_new_nid');
  if not assigned(OBJ_new_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_new_nid');
  Result := OBJ_new_nid(num);
end;

function Load_OBJ_add_object(obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_add_object := LoadLibCryptoFunction('OBJ_add_object');
  if not assigned(OBJ_add_object) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_add_object');
  Result := OBJ_add_object(obj);
end;

function Load_OBJ_create(oid: PAnsiChar; sn: PAnsiChar; ln: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OBJ_create := LoadLibCryptoFunction('OBJ_create');
  if not assigned(OBJ_create) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_create');
  Result := OBJ_create(oid, sn, ln);
end;

function Load_OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  OBJ_create_objects := LoadLibCryptoFunction('OBJ_create_objects');
  if not assigned(OBJ_create_objects) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_create_objects');
  Result := OBJ_create_objects(in_);
end;

function Load_OBJ_length(obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl;
begin
  OBJ_length := LoadLibCryptoFunction('OBJ_length');
  if not assigned(OBJ_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_length');
  Result := OBJ_length(obj);
end;

function Load_OBJ_get0_data(obj: PASN1_OBJECT): Pbyte; cdecl;
begin
  OBJ_get0_data := LoadLibCryptoFunction('OBJ_get0_data');
  if not assigned(OBJ_get0_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_get0_data');
  Result := OBJ_get0_data(obj);
end;

function Load_OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_find_sigid_algs := LoadLibCryptoFunction('OBJ_find_sigid_algs');
  if not assigned(OBJ_find_sigid_algs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_find_sigid_algs');
  Result := OBJ_find_sigid_algs(signid, pdig_nid, ppkey_nid);
end;

function Load_OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_find_sigid_by_algs := LoadLibCryptoFunction('OBJ_find_sigid_by_algs');
  if not assigned(OBJ_find_sigid_by_algs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_find_sigid_by_algs');
  Result := OBJ_find_sigid_by_algs(psignid, dig_nid, pkey_nid);
end;

function Load_OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OBJ_add_sigid := LoadLibCryptoFunction('OBJ_add_sigid');
  if not assigned(OBJ_add_sigid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_add_sigid');
  Result := OBJ_add_sigid(signid, dig_id, pkey_id);
end;

procedure Load_OBJ_sigid_free; cdecl;
begin
  OBJ_sigid_free := LoadLibCryptoFunction('OBJ_sigid_free');
  if not assigned(OBJ_sigid_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_sigid_free');
  OBJ_sigid_free;
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OBJ_NAME_init := Load_OBJ_NAME_init;
  OBJ_NAME_new_index := Load_OBJ_NAME_new_index;
  OBJ_NAME_get := Load_OBJ_NAME_get;
  OBJ_NAME_add := Load_OBJ_NAME_add;
  OBJ_NAME_remove := Load_OBJ_NAME_remove;
  OBJ_NAME_cleanup := Load_OBJ_NAME_cleanup;
  OBJ_NAME_do_all := Load_OBJ_NAME_do_all;
  OBJ_NAME_do_all_sorted := Load_OBJ_NAME_do_all_sorted;
  OBJ_dup := Load_OBJ_dup;
  OBJ_nid2obj := Load_OBJ_nid2obj;
  OBJ_nid2ln := Load_OBJ_nid2ln;
  OBJ_nid2sn := Load_OBJ_nid2sn;
  OBJ_obj2nid := Load_OBJ_obj2nid;
  OBJ_txt2obj := Load_OBJ_txt2obj;
  OBJ_obj2txt := Load_OBJ_obj2txt;
  OBJ_txt2nid := Load_OBJ_txt2nid;
  OBJ_ln2nid := Load_OBJ_ln2nid;
  OBJ_sn2nid := Load_OBJ_sn2nid;
  OBJ_cmp := Load_OBJ_cmp;
  OBJ_bsearch_ := Load_OBJ_bsearch_;
  OBJ_bsearch_ex_ := Load_OBJ_bsearch_ex_;
  OBJ_new_nid := Load_OBJ_new_nid;
  OBJ_add_object := Load_OBJ_add_object;
  OBJ_create := Load_OBJ_create;
  OBJ_create_objects := Load_OBJ_create_objects;
  OBJ_length := Load_OBJ_length;
  OBJ_get0_data := Load_OBJ_get0_data;
  OBJ_find_sigid_algs := Load_OBJ_find_sigid_algs;
  OBJ_find_sigid_by_algs := Load_OBJ_find_sigid_by_algs;
  OBJ_add_sigid := Load_OBJ_add_sigid;
  OBJ_sigid_free := Load_OBJ_sigid_free;
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



