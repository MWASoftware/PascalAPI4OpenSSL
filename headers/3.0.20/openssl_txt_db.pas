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

unit openssl_txt_db;

{
  Generated from OpenSSL 3.0.20 Header File txt_db.h - Tue 19 May 14:16:50 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_txt_db.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_stack,openssl_bio,openssl_safestack,
     openssl_lhash;


{* Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_TXT_DB_H}
  {$define OPENSSL_TXT_DB_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_TXT_DB_H}
  {$endif}
  {$include openssl_opensslconf.inc}

const
  DB_ERROR_OK = 0;
  DB_ERROR_MALLOC = 1;
  DB_ERROR_INDEX_CLASH = 2;
  DB_ERROR_INDEX_OUT_OF_RANGE = 3;
  DB_ERROR_NO_INDEX = 4;
  DB_ERROR_INSERT_INDEX_CLASH = 5;
  DB_ERROR_WRONG_NUM_FIELDS = 6;

type
  {Auto-generated forward references}
  POPENSSL_PSTRING = ^TOPENSSL_PSTRING;
  PPOPENSSL_PSTRING = ^POPENSSL_PSTRING;
  Pstack_st_OPENSSL_PSTRING = ^Tstack_st_OPENSSL_PSTRING;
  PPstack_st_OPENSSL_PSTRING = ^Pstack_st_OPENSSL_PSTRING;
  Psk_OPENSSL_PSTRING_compfunc = ^Tsk_OPENSSL_PSTRING_compfunc;
  PPsk_OPENSSL_PSTRING_compfunc = ^Psk_OPENSSL_PSTRING_compfunc;
  Psk_OPENSSL_PSTRING_freefunc = ^Tsk_OPENSSL_PSTRING_freefunc;
  PPsk_OPENSSL_PSTRING_freefunc = ^Psk_OPENSSL_PSTRING_freefunc;
  Psk_OPENSSL_PSTRING_copyfunc = ^Tsk_OPENSSL_PSTRING_copyfunc;
  PPsk_OPENSSL_PSTRING_copyfunc = ^Psk_OPENSSL_PSTRING_copyfunc;
  {end of auto-generated forward references}

  TOPENSSL_PSTRING = POPENSSL_STRING;
  Tstack_st_OPENSSL_PSTRING = record 
  end;
  Tsk_OPENSSL_PSTRING_compfunc = function(a: PPOPENSSL_STRING; b: PPOPENSSL_STRING): TOpenSSL_C_INT; cdecl;
  Tsk_OPENSSL_PSTRING_freefunc = procedure(a: POPENSSL_STRING); cdecl;
  Tsk_OPENSSL_PSTRING_copyfunc = function(a: POPENSSL_STRING): POPENSSL_STRING; cdecl;


  function sk_OPENSSL_PSTRING_num(sk: Pstack_st_OPENSSL_PSTRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_value(sk: Pstack_st_OPENSSL_PSTRING; idx: TOpenSSL_C_INT): POPENSSL_STRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_new(compare: Tsk_OPENSSL_PSTRING_compfunc): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_new_null: Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_new_reserve(compare: Tsk_OPENSSL_PSTRING_compfunc; n: TOpenSSL_C_INT): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_reserve(sk: Pstack_st_OPENSSL_PSTRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  procedure sk_OPENSSL_PSTRING_free(sk: Pstack_st_OPENSSL_PSTRING){Has C Attribute: unused}; inline;
  procedure sk_OPENSSL_PSTRING_zero(sk: Pstack_st_OPENSSL_PSTRING){Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_delete(sk: Pstack_st_OPENSSL_PSTRING; i: TOpenSSL_C_INT): POPENSSL_STRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_delete_ptr(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_push(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_unshift(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_pop(sk: Pstack_st_OPENSSL_PSTRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_shift(sk: Pstack_st_OPENSSL_PSTRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
  procedure sk_OPENSSL_PSTRING_pop_free(sk: Pstack_st_OPENSSL_PSTRING; freefunc: Tsk_OPENSSL_PSTRING_freefunc){Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_insert(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING; idx: TOpenSSL_C_INT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_set(sk: Pstack_st_OPENSSL_PSTRING; idx: TOpenSSL_C_INT; ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_find(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_find_ex(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_find_all(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING; pnum: POpenSSL_C_INT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  procedure sk_OPENSSL_PSTRING_sort(sk: Pstack_st_OPENSSL_PSTRING){Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_is_sorted(sk: Pstack_st_OPENSSL_PSTRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_dup(sk: Pstack_st_OPENSSL_PSTRING): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_deep_copy(sk: Pstack_st_OPENSSL_PSTRING; copyfunc: Tsk_OPENSSL_PSTRING_copyfunc; freefunc: Tsk_OPENSSL_PSTRING_freefunc): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
  function sk_OPENSSL_PSTRING_set_cmp_func(sk: Pstack_st_OPENSSL_PSTRING; compare: Tsk_OPENSSL_PSTRING_compfunc): Tsk_OPENSSL_PSTRING_compfunc{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  Ptxt_db_st = ^Ttxt_db_st;
  PPtxt_db_st = ^Ptxt_db_st;
  PTXT_DB = ^TTXT_DB;
  PPTXT_DB = ^PTXT_DB;
  {end of auto-generated forward references}

  TFuncType000 = function(_param1: POPENSSL_STRING): TOpenSSL_C_INT; cdecl;
  Ttxt_db_st = record 
    num_fields: TOpenSSL_C_INT;
    data: Pstack_st_OPENSSL_PSTRING;
    index: PPlhash_st_OPENSSL_STRING;
    qual: TFuncType000;
    error: TOpenSSL_C_INT;
    arg1: TOpenSSL_C_INT;
    arg2: TOpenSSL_C_INT;
    arg_row: POPENSSL_STRING;
  end;
  TTXT_DB = Ttxt_db_st;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TXT_DB_read(in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl; external CLibCrypto name 'TXT_DB_read';
  function TXT_DB_write(out_: PBIO; db: PTXT_DB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TXT_DB_write';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM TXT_DB_read}
  {$EXTERNALSYM TXT_DB_write}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TXT_DB_read(in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl;
  function Load_TXT_DB_write(out_: PBIO; db: PTXT_DB): TOpenSSL_C_INT; cdecl;

var
  TXT_DB_read: function(in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl = Load_TXT_DB_read;
  TXT_DB_write: function(out_: PBIO; db: PTXT_DB): TOpenSSL_C_INT; cdecl = Load_TXT_DB_write;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = function(_param1: POPENSSL_STRING): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TXT_DB_create_index(db: PTXT_DB; field: TOpenSSL_C_INT; qual: TFuncType001; hash: TOPENSSL_LH_HASHFUNC; cmp: TOPENSSL_LH_COMPFUNC): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TXT_DB_create_index';
  procedure TXT_DB_free(db: PTXT_DB); cdecl; external CLibCrypto name 'TXT_DB_free';
  function TXT_DB_get_by_index(db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl; external CLibCrypto name 'TXT_DB_get_by_index';
  function TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TXT_DB_insert';
  {$else}
  {$EXTERNALSYM TXT_DB_create_index}
  {$EXTERNALSYM TXT_DB_free}
  {$EXTERNALSYM TXT_DB_get_by_index}
  {$EXTERNALSYM TXT_DB_insert}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TXT_DB_create_index(db: PTXT_DB; field: TOpenSSL_C_INT; qual: TFuncType001; hash: TOPENSSL_LH_HASHFUNC; cmp: TOPENSSL_LH_COMPFUNC): TOpenSSL_C_INT; cdecl;
  procedure Load_TXT_DB_free(db: PTXT_DB); cdecl;
  function Load_TXT_DB_get_by_index(db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl;
  function Load_TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl;

var
  TXT_DB_create_index: function(db: PTXT_DB; field: TOpenSSL_C_INT; qual: TFuncType001; hash: TOPENSSL_LH_HASHFUNC; cmp: TOPENSSL_LH_COMPFUNC): TOpenSSL_C_INT; cdecl = Load_TXT_DB_create_index;
  TXT_DB_free: procedure(db: PTXT_DB); cdecl = Load_TXT_DB_free;
  TXT_DB_get_by_index: function(db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl = Load_TXT_DB_get_by_index;
  TXT_DB_insert: function(db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl = Load_TXT_DB_insert;
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

function sk_OPENSSL_PSTRING_num(sk: Pstack_st_OPENSSL_PSTRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_PSTRING_value(sk: Pstack_st_OPENSSL_PSTRING; idx: TOpenSSL_C_INT): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STRING(OPENSSL_sk_value(POPENSSL_STACK(sk),idx));
end;

function sk_OPENSSL_PSTRING_new(compare: Tsk_OPENSSL_PSTRING_compfunc): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
begin
   Result := Pstack_st_OPENSSL_PSTRING(OPENSSL_sk_new(TOPENSSL_sk_compfunc(compare)));
end;

function sk_OPENSSL_PSTRING_new_null: Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
begin
   Result := Pstack_st_OPENSSL_PSTRING(OPENSSL_sk_new_null);
end;

function sk_OPENSSL_PSTRING_new_reserve(compare: Tsk_OPENSSL_PSTRING_compfunc; n: TOpenSSL_C_INT): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
begin
   Result := Pstack_st_OPENSSL_PSTRING(OPENSSL_sk_new_reserve(TOPENSSL_sk_compfunc(compare),n));
end;

function sk_OPENSSL_PSTRING_reserve(sk: Pstack_st_OPENSSL_PSTRING; n: TOpenSSL_C_INT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk),n);
end;

procedure sk_OPENSSL_PSTRING_free(sk: Pstack_st_OPENSSL_PSTRING){Has C Attribute: unused}; inline;
begin
    OPENSSL_sk_free(POPENSSL_STACK(sk));
end;

procedure sk_OPENSSL_PSTRING_zero(sk: Pstack_st_OPENSSL_PSTRING){Has C Attribute: unused}; inline;
begin
    OPENSSL_sk_zero(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_PSTRING_delete(sk: Pstack_st_OPENSSL_PSTRING; i: TOpenSSL_C_INT): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STRING(OPENSSL_sk_delete(POPENSSL_STACK(sk),i));
end;

function sk_OPENSSL_PSTRING_delete_ptr(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STRING(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk),pointer(ptr)));
end;

function sk_OPENSSL_PSTRING_push(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk),pointer(ptr));
end;

function sk_OPENSSL_PSTRING_unshift(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk),pointer(ptr));
end;

function sk_OPENSSL_PSTRING_pop(sk: Pstack_st_OPENSSL_PSTRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STRING(OPENSSL_sk_pop(POPENSSL_STACK(sk)));
end;

function sk_OPENSSL_PSTRING_shift(sk: Pstack_st_OPENSSL_PSTRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STRING(OPENSSL_sk_shift(POPENSSL_STACK(sk)));
end;

procedure sk_OPENSSL_PSTRING_pop_free(sk: Pstack_st_OPENSSL_PSTRING; freefunc: Tsk_OPENSSL_PSTRING_freefunc){Has C Attribute: unused}; inline;
begin
    OPENSSL_sk_pop_free(POPENSSL_STACK(sk), TOPENSSL_sk_freefunc(freefunc));
end;

function sk_OPENSSL_PSTRING_insert(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING; idx: TOpenSSL_C_INT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk),pointer(ptr),idx);
end;

function sk_OPENSSL_PSTRING_set(sk: Pstack_st_OPENSSL_PSTRING; idx: TOpenSSL_C_INT; ptr: POPENSSL_STRING): POPENSSL_STRING{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STRING(OPENSSL_sk_set(POPENSSL_STACK(sk),idx,pointer(ptr)));
end;

function sk_OPENSSL_PSTRING_find(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk),pointer(ptr));
end;

function sk_OPENSSL_PSTRING_find_ex(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk),pointer(ptr));
end;

function sk_OPENSSL_PSTRING_find_all(sk: Pstack_st_OPENSSL_PSTRING; ptr: POPENSSL_STRING; pnum: POpenSSL_C_INT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk),pointer(ptr),pnum);
end;

procedure sk_OPENSSL_PSTRING_sort(sk: Pstack_st_OPENSSL_PSTRING){Has C Attribute: unused}; inline;
begin
    OPENSSL_sk_sort(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_PSTRING_is_sorted(sk: Pstack_st_OPENSSL_PSTRING): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk));
end;

function sk_OPENSSL_PSTRING_dup(sk: Pstack_st_OPENSSL_PSTRING): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
begin
   Result := Pstack_st_OPENSSL_PSTRING(OPENSSL_sk_dup(POPENSSL_STACK(sk)));
end;

function sk_OPENSSL_PSTRING_deep_copy(sk: Pstack_st_OPENSSL_PSTRING; copyfunc: Tsk_OPENSSL_PSTRING_copyfunc; freefunc: Tsk_OPENSSL_PSTRING_freefunc): Pstack_st_OPENSSL_PSTRING{Has C Attribute: unused}; inline;
begin
   Result := Pstack_st_OPENSSL_PSTRING(OPENSSL_sk_deep_copy(POPENSSL_STACK(sk),TOPENSSL_sk_copyfunc(copyfunc),TOPENSSL_sk_freefunc(freefunc)));
end;

function sk_OPENSSL_PSTRING_set_cmp_func(sk: Pstack_st_OPENSSL_PSTRING; compare: Tsk_OPENSSL_PSTRING_compfunc): Tsk_OPENSSL_PSTRING_compfunc{Has C Attribute: unused}; inline;
begin
   Result := Tsk_OPENSSL_PSTRING_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk),TOPENSSL_sk_compfunc(compare)));
end;

{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_TXT_DB_read(in_: PBIO; num: TOpenSSL_C_INT): PTXT_DB; cdecl;
begin
  TXT_DB_read := LoadLibCryptoFunction('TXT_DB_read');
  if not assigned(TXT_DB_read) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_read');
  Result := TXT_DB_read(in_, num);
end;

function Load_TXT_DB_write(out_: PBIO; db: PTXT_DB): TOpenSSL_C_INT; cdecl;
begin
  TXT_DB_write := LoadLibCryptoFunction('TXT_DB_write');
  if not assigned(TXT_DB_write) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_write');
  Result := TXT_DB_write(out_, db);
end;

function Load_TXT_DB_create_index(db: PTXT_DB; field: TOpenSSL_C_INT; qual: TFuncType001; hash: TOPENSSL_LH_HASHFUNC; cmp: TOPENSSL_LH_COMPFUNC): TOpenSSL_C_INT; cdecl;
begin
  TXT_DB_create_index := LoadLibCryptoFunction('TXT_DB_create_index');
  if not assigned(TXT_DB_create_index) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_create_index');
  Result := TXT_DB_create_index(db, field, qual, hash, cmp);
end;

procedure Load_TXT_DB_free(db: PTXT_DB); cdecl;
begin
  TXT_DB_free := LoadLibCryptoFunction('TXT_DB_free');
  if not assigned(TXT_DB_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_free');
  TXT_DB_free(db);
end;

function Load_TXT_DB_get_by_index(db: PTXT_DB; idx: TOpenSSL_C_INT; value: POPENSSL_STRING): POPENSSL_STRING; cdecl;
begin
  TXT_DB_get_by_index := LoadLibCryptoFunction('TXT_DB_get_by_index');
  if not assigned(TXT_DB_get_by_index) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_get_by_index');
  Result := TXT_DB_get_by_index(db, idx, value);
end;

function Load_TXT_DB_insert(db: PTXT_DB; value: POPENSSL_STRING): TOpenSSL_C_INT; cdecl;
begin
  TXT_DB_insert := LoadLibCryptoFunction('TXT_DB_insert');
  if not assigned(TXT_DB_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TXT_DB_insert');
  Result := TXT_DB_insert(db, value);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  TXT_DB_read := Load_TXT_DB_read;
  TXT_DB_write := Load_TXT_DB_write;
  TXT_DB_create_index := Load_TXT_DB_create_index;
  TXT_DB_free := Load_TXT_DB_free;
  TXT_DB_get_by_index := Load_TXT_DB_get_by_index;
  TXT_DB_insert := Load_TXT_DB_insert;
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



