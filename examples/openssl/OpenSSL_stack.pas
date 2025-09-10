(* This unit was generated from the source file stack.h2pas 
It should not be modified directly. All changes should be made to stack.h2pas
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

unit OpenSSL_stack;


interface

uses
    OpenSSLAPI;


{
  Automatically converted by H2Pas 1.0.0 from stack.h
  The following command line parameters were used:
  -p
  -t
    stack.h
}

 {
   * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
   *
   * Licensed under the OpenSSL license (the "License").  You may not use
   * this file except in compliance with the License.  You can obtain a copy
   * in the file LICENSE in the source distribution or at
   * https://www.openssl.org/source/license.html
    }

  
type
  POPENSSL_STACK  = pointer;

  TOPENSSL_sk_compfunc = function (_para1:pointer; _para2:pointer):longint;cdecl;
  TOPENSSL_sk_freefunc = procedure (_para1:pointer);cdecl;
  TOPENSSL_sk_copyfunc = function (_para1:pointer):pointer;cdecl;

  
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
{$EXTERNALSYM OPENSSL_sk_pop_free}
{$EXTERNALSYM OPENSSL_sk_deep_copy}
{$EXTERNALSYM OPENSSL_sk_insert}
{$EXTERNALSYM OPENSSL_sk_delete}
{$EXTERNALSYM OPENSSL_sk_delete_ptr}
{$EXTERNALSYM OPENSSL_sk_find}
{$EXTERNALSYM OPENSSL_sk_find_ex}
{$EXTERNALSYM OPENSSL_sk_push}
{$EXTERNALSYM OPENSSL_sk_unshift}
{$EXTERNALSYM OPENSSL_sk_shift}
{$EXTERNALSYM OPENSSL_sk_pop}
{$EXTERNALSYM OPENSSL_sk_zero}
{$EXTERNALSYM OPENSSL_sk_set_cmp_func}
{$EXTERNALSYM OPENSSL_sk_dup}
{$EXTERNALSYM OPENSSL_sk_sort}
{$EXTERNALSYM OPENSSL_sk_is_sorted}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function OPENSSL_sk_num(_para1:POPENSSL_STACK): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_new_null: POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl; external CLibCrypto;
procedure OPENSSL_sk_free(_para1:POPENSSL_STACK); cdecl; external CLibCrypto;
procedure OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl; external CLibCrypto;
function OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl; external CLibCrypto;
function OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl; external CLibCrypto;
function OPENSSL_sk_shift(st:POPENSSL_STACK): pointer; cdecl; external CLibCrypto;
function OPENSSL_sk_pop(st:POPENSSL_STACK): pointer; cdecl; external CLibCrypto;
procedure OPENSSL_sk_zero(st:POPENSSL_STACK); cdecl; external CLibCrypto;
function OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl; external CLibCrypto;
function OPENSSL_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl; external CLibCrypto;
procedure OPENSSL_sk_sort(st:POPENSSL_STACK); cdecl; external CLibCrypto;
function OPENSSL_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl; external CLibCrypto;

{$ELSE}
var
  OPENSSL_sk_num: function (_para1:POPENSSL_STACK): longint; cdecl = nil;
  OPENSSL_sk_value: function (_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl = nil;
  OPENSSL_sk_set: function (st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl = nil;
  OPENSSL_sk_new: function (cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl = nil;
  OPENSSL_sk_new_null: function : POPENSSL_STACK; cdecl = nil;
  OPENSSL_sk_new_reserve: function (c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl = nil;
  OPENSSL_sk_reserve: function (st:POPENSSL_STACK; n:longint): longint; cdecl = nil;
  OPENSSL_sk_free: procedure (_para1:POPENSSL_STACK); cdecl = nil;
  OPENSSL_sk_pop_free: procedure (st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl = nil;
  OPENSSL_sk_deep_copy: function (_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl = nil;
  OPENSSL_sk_insert: function (sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl = nil;
  OPENSSL_sk_delete: function (st:POPENSSL_STACK; loc:longint): pointer; cdecl = nil;
  OPENSSL_sk_delete_ptr: function (st:POPENSSL_STACK; p:pointer): pointer; cdecl = nil;
  OPENSSL_sk_find: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil;
  OPENSSL_sk_find_ex: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil;
  OPENSSL_sk_push: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil;
  OPENSSL_sk_unshift: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil;
  OPENSSL_sk_shift: function (st:POPENSSL_STACK): pointer; cdecl = nil;
  OPENSSL_sk_pop: function (st:POPENSSL_STACK): pointer; cdecl = nil;
  OPENSSL_sk_zero: procedure (st:POPENSSL_STACK); cdecl = nil;
  OPENSSL_sk_set_cmp_func: function (sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl = nil;
  OPENSSL_sk_dup: function (st:POPENSSL_STACK): POPENSSL_STACK; cdecl = nil;
  OPENSSL_sk_sort: procedure (st:POPENSSL_STACK); cdecl = nil;
  OPENSSL_sk_is_sorted: function (st:POPENSSL_STACK): longint; cdecl = nil;
{$ENDIF}
const
  OPENSSL_sk_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_value_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_set_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_new_null_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_new_reserve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_reserve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_pop_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_deep_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_insert_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_delete_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_delete_ptr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_find_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_find_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_push_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_unshift_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_shift_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_pop_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_zero_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_set_cmp_func_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_sort_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_sk_is_sorted_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  sk_num_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_value_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_set_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_new_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_new_null_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_new_reserve_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  sk_reserve_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  sk_free_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_pop_free_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_deep_copy_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_insert_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_delete_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_delete_ptr_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_find_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_find_ex_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_push_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_unshift_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_shift_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_pop_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_zero_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_set_cmp_func_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_dup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_sort_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  sk_is_sorted_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}


implementation


uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  sk_num: function (_para1:POPENSSL_STACK): longint; cdecl = nil; {removed 1.1.0}
  sk_value: function (_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl = nil; {removed 1.1.0}
  sk_set: function (st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl = nil; {removed 1.1.0}
  sk_new: function (cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_new_null: function : POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_new_reserve: function (c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl = nil; {removed 1.0.0}
  sk_reserve: function (st:POPENSSL_STACK; n:longint): longint; cdecl = nil; {removed 1.0.0}
  sk_free: procedure (_para1:POPENSSL_STACK); cdecl = nil; {removed 1.1.0}
  sk_pop_free: procedure (st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl = nil; {removed 1.1.0}
  sk_deep_copy: function (_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_insert: function (sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl = nil; {removed 1.1.0}
  sk_delete: function (st:POPENSSL_STACK; loc:longint): pointer; cdecl = nil; {removed 1.1.0}
  sk_delete_ptr: function (st:POPENSSL_STACK; p:pointer): pointer; cdecl = nil; {removed 1.1.0}
  sk_find: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil; {removed 1.1.0}
  sk_find_ex: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil; {removed 1.1.0}
  sk_push: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil; {removed 1.1.0}
  sk_unshift: function (st:POPENSSL_STACK; data:pointer): longint; cdecl = nil; {removed 1.1.0}
  sk_shift: function (st:POPENSSL_STACK): pointer; cdecl = nil; {removed 1.1.0}
  sk_pop: function (st:POPENSSL_STACK): pointer; cdecl = nil; {removed 1.1.0}
  sk_zero: procedure (st:POPENSSL_STACK); cdecl = nil; {removed 1.1.0}
  sk_set_cmp_func: function (sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl = nil; {removed 1.1.0}
  sk_dup: function (st:POPENSSL_STACK): POPENSSL_STACK; cdecl = nil; {removed 1.1.0}
  sk_sort: procedure (st:POPENSSL_STACK); cdecl = nil; {removed 1.1.0}
  sk_is_sorted: function (st:POPENSSL_STACK): longint; cdecl = nil; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_OPENSSL_sk_num(_para1:POPENSSL_STACK): longint; cdecl;

begin
  Result := sk_num(_para1);
end;



function COMPAT_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl;

begin
  Result := sk_value(_para1,_para2);
end;



function COMPAT_OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl;

begin
  Result := sk_set(st,i,data);
end;



function COMPAT_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;

begin
  Result := sk_new(cmp);
end;



function COMPAT_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;

begin
  Result := sk_new_null;
end;



function COMPAT_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl;

begin
  Result := sk_new_reserve(c,n);
end;



function COMPAT_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl;

begin
  Result := sk_reserve(st,n);
end;



procedure COMPAT_OPENSSL_sk_free(_para1:POPENSSL_STACK); cdecl;

begin
  sk_free(_para1);
end;



procedure COMPAT_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;

begin
  sk_pop_free(st, func);
end;



function COMPAT_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;

begin
  Result := sk_deep_copy(_para1,c,f);
end;



function COMPAT_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl;

begin
  Result := sk_insert(sk,data,where);
end;



function COMPAT_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl;

begin
  Result := sk_delete(st,loc);
end;



function COMPAT_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;

begin
  Result := sk_delete_ptr(st,p);
end;



function COMPAT_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_find(st,data);
end;



function COMPAT_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_find_ex(st,data);
end;



function COMPAT_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_push(st,data);
end;



function COMPAT_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl;

begin
  Result := sk_unshift(st,data);
end;



function COMPAT_OPENSSL_sk_shift(st:POPENSSL_STACK): pointer; cdecl;

begin
  Result := sk_shift(st);
end;



function COMPAT_OPENSSL_sk_pop(st:POPENSSL_STACK): pointer; cdecl;

begin
  Result := sk_pop(st);
end;



procedure COMPAT_OPENSSL_sk_zero(st:POPENSSL_STACK); cdecl;

begin
  OPENSSL_sk_zero(st);
end;



function COMPAT_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;

begin
  Result := sk_set_cmp_func(sk,cmp);
end;



function COMPAT_OPENSSL_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;

begin
  Result := sk_dup(st);
end;



procedure COMPAT_OPENSSL_sk_sort(st:POPENSSL_STACK); cdecl;

begin
  OPENSSL_sk_sort(st);
end;



function COMPAT_OPENSSL_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl;

begin
  Result := sk_is_sorted(st);
end;






{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_num(_para1:POPENSSL_STACK): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_num');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_value');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_new_null: POPENSSL_STACK; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_null');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_new_reserve');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_reserve');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_sk_free(_para1:POPENSSL_STACK); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_deep_copy');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_insert');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_delete_ptr');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_find_ex');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_push');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_unshift');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_shift(st:POPENSSL_STACK): pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_shift');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_pop(st:POPENSSL_STACK): pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_pop');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_sk_zero(st:POPENSSL_STACK); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_zero');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_set_cmp_func');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_dup');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_sk_sort(st:POPENSSL_STACK); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_sort');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_sk_is_sorted');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_sk_num(_para1:POPENSSL_STACK): longint; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_num');
end;

function ERROR_sk_value(_para1:POPENSSL_STACK; _para2:longint): pointer; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_value');
end;

function ERROR_sk_set(st:POPENSSL_STACK; i:longint; data:pointer): pointer; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_set');
end;

function ERROR_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new');
end;

function ERROR_sk_new_null: POPENSSL_STACK; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new_null');
end;

function ERROR_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:longint): POPENSSL_STACK; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new_reserve');
end;

function ERROR_sk_reserve(st:POPENSSL_STACK; n:longint): longint; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_reserve');
end;

procedure ERROR_sk_free(_para1:POPENSSL_STACK); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_free');
end;

procedure ERROR_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_pop_free');
end;

function ERROR_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_deep_copy');
end;

function ERROR_sk_insert(sk:POPENSSL_STACK; data:pointer; where:longint): longint; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_insert');
end;

function ERROR_sk_delete(st:POPENSSL_STACK; loc:longint): pointer; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_delete');
end;

function ERROR_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_delete_ptr');
end;

function ERROR_sk_find(st:POPENSSL_STACK; data:pointer): longint; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_find');
end;

function ERROR_sk_find_ex(st:POPENSSL_STACK; data:pointer): longint; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_find_ex');
end;

function ERROR_sk_push(st:POPENSSL_STACK; data:pointer): longint; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_push');
end;

function ERROR_sk_unshift(st:POPENSSL_STACK; data:pointer): longint; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_unshift');
end;

function ERROR_sk_shift(st:POPENSSL_STACK): pointer; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_shift');
end;

function ERROR_sk_pop(st:POPENSSL_STACK): pointer; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_pop');
end;

procedure ERROR_sk_zero(st:POPENSSL_STACK); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_zero');
end;

function ERROR_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_set_cmp_func');
end;

function ERROR_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_dup');
end;

procedure ERROR_sk_sort(st:POPENSSL_STACK); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_sort');
end;

function ERROR_sk_is_sorted(st:POPENSSL_STACK): longint; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('sk_is_sorted');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  OPENSSL_sk_num := LoadLibCryptoFunction('OPENSSL_sk_num');
  FuncLoadError := not assigned(OPENSSL_sk_num);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_num := @COMPAT_OPENSSL_sk_num;
{$ELSE}
    OPENSSL_sk_num :=  @ERROR_OPENSSL_sk_num;
{$ENDIF}
  end;

  OPENSSL_sk_value := LoadLibCryptoFunction('OPENSSL_sk_value');
  FuncLoadError := not assigned(OPENSSL_sk_value);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_value := @COMPAT_OPENSSL_sk_value;
{$ELSE}
    OPENSSL_sk_value :=  @ERROR_OPENSSL_sk_value;
{$ENDIF}
  end;

  OPENSSL_sk_set := LoadLibCryptoFunction('OPENSSL_sk_set');
  FuncLoadError := not assigned(OPENSSL_sk_set);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_set := @COMPAT_OPENSSL_sk_set;
{$ELSE}
    OPENSSL_sk_set :=  @ERROR_OPENSSL_sk_set;
{$ENDIF}
  end;

  OPENSSL_sk_new := LoadLibCryptoFunction('OPENSSL_sk_new');
  FuncLoadError := not assigned(OPENSSL_sk_new);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_new := @COMPAT_OPENSSL_sk_new;
{$ELSE}
    OPENSSL_sk_new :=  @ERROR_OPENSSL_sk_new;
{$ENDIF}
  end;

  OPENSSL_sk_new_null := LoadLibCryptoFunction('OPENSSL_sk_new_null');
  FuncLoadError := not assigned(OPENSSL_sk_new_null);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_new_null := @COMPAT_OPENSSL_sk_new_null;
{$ELSE}
    OPENSSL_sk_new_null :=  @ERROR_OPENSSL_sk_new_null;
{$ENDIF}
  end;

  OPENSSL_sk_new_reserve := LoadLibCryptoFunction('OPENSSL_sk_new_reserve');
  FuncLoadError := not assigned(OPENSSL_sk_new_reserve);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_new_reserve := @COMPAT_OPENSSL_sk_new_reserve;
{$ELSE}
    OPENSSL_sk_new_reserve :=  @ERROR_OPENSSL_sk_new_reserve;
{$ENDIF}
  end;

  OPENSSL_sk_reserve := LoadLibCryptoFunction('OPENSSL_sk_reserve');
  FuncLoadError := not assigned(OPENSSL_sk_reserve);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_reserve := @COMPAT_OPENSSL_sk_reserve;
{$ELSE}
    OPENSSL_sk_reserve :=  @ERROR_OPENSSL_sk_reserve;
{$ENDIF}
  end;

  OPENSSL_sk_free := LoadLibCryptoFunction('OPENSSL_sk_free');
  FuncLoadError := not assigned(OPENSSL_sk_free);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_free := @COMPAT_OPENSSL_sk_free;
{$ELSE}
    OPENSSL_sk_free :=  @ERROR_OPENSSL_sk_free;
{$ENDIF}
  end;

  OPENSSL_sk_pop_free := LoadLibCryptoFunction('OPENSSL_sk_pop_free');
  FuncLoadError := not assigned(OPENSSL_sk_pop_free);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_pop_free := @COMPAT_OPENSSL_sk_pop_free;
{$ELSE}
    OPENSSL_sk_pop_free :=  @ERROR_OPENSSL_sk_pop_free;
{$ENDIF}
  end;

  OPENSSL_sk_deep_copy := LoadLibCryptoFunction('OPENSSL_sk_deep_copy');
  FuncLoadError := not assigned(OPENSSL_sk_deep_copy);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_deep_copy := @COMPAT_OPENSSL_sk_deep_copy;
{$ELSE}
    OPENSSL_sk_deep_copy :=  @ERROR_OPENSSL_sk_deep_copy;
{$ENDIF}
  end;

  OPENSSL_sk_insert := LoadLibCryptoFunction('OPENSSL_sk_insert');
  FuncLoadError := not assigned(OPENSSL_sk_insert);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_insert := @COMPAT_OPENSSL_sk_insert;
{$ELSE}
    OPENSSL_sk_insert :=  @ERROR_OPENSSL_sk_insert;
{$ENDIF}
  end;

  OPENSSL_sk_delete := LoadLibCryptoFunction('OPENSSL_sk_delete');
  FuncLoadError := not assigned(OPENSSL_sk_delete);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_delete := @COMPAT_OPENSSL_sk_delete;
{$ELSE}
    OPENSSL_sk_delete :=  @ERROR_OPENSSL_sk_delete;
{$ENDIF}
  end;

  OPENSSL_sk_delete_ptr := LoadLibCryptoFunction('OPENSSL_sk_delete_ptr');
  FuncLoadError := not assigned(OPENSSL_sk_delete_ptr);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_delete_ptr := @COMPAT_OPENSSL_sk_delete_ptr;
{$ELSE}
    OPENSSL_sk_delete_ptr :=  @ERROR_OPENSSL_sk_delete_ptr;
{$ENDIF}
  end;

  OPENSSL_sk_find := LoadLibCryptoFunction('OPENSSL_sk_find');
  FuncLoadError := not assigned(OPENSSL_sk_find);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_find := @COMPAT_OPENSSL_sk_find;
{$ELSE}
    OPENSSL_sk_find :=  @ERROR_OPENSSL_sk_find;
{$ENDIF}
  end;

  OPENSSL_sk_find_ex := LoadLibCryptoFunction('OPENSSL_sk_find_ex');
  FuncLoadError := not assigned(OPENSSL_sk_find_ex);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_find_ex := @COMPAT_OPENSSL_sk_find_ex;
{$ELSE}
    OPENSSL_sk_find_ex :=  @ERROR_OPENSSL_sk_find_ex;
{$ENDIF}
  end;

  OPENSSL_sk_push := LoadLibCryptoFunction('OPENSSL_sk_push');
  FuncLoadError := not assigned(OPENSSL_sk_push);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_push := @COMPAT_OPENSSL_sk_push;
{$ELSE}
    OPENSSL_sk_push :=  @ERROR_OPENSSL_sk_push;
{$ENDIF}
  end;

  OPENSSL_sk_unshift := LoadLibCryptoFunction('OPENSSL_sk_unshift');
  FuncLoadError := not assigned(OPENSSL_sk_unshift);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_unshift := @COMPAT_OPENSSL_sk_unshift;
{$ELSE}
    OPENSSL_sk_unshift :=  @ERROR_OPENSSL_sk_unshift;
{$ENDIF}
  end;

  OPENSSL_sk_shift := LoadLibCryptoFunction('OPENSSL_sk_shift');
  FuncLoadError := not assigned(OPENSSL_sk_shift);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_shift := @COMPAT_OPENSSL_sk_shift;
{$ELSE}
    OPENSSL_sk_shift :=  @ERROR_OPENSSL_sk_shift;
{$ENDIF}
  end;

  OPENSSL_sk_pop := LoadLibCryptoFunction('OPENSSL_sk_pop');
  FuncLoadError := not assigned(OPENSSL_sk_pop);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_pop := @COMPAT_OPENSSL_sk_pop;
{$ELSE}
    OPENSSL_sk_pop :=  @ERROR_OPENSSL_sk_pop;
{$ENDIF}
  end;

  OPENSSL_sk_zero := LoadLibCryptoFunction('OPENSSL_sk_zero');
  FuncLoadError := not assigned(OPENSSL_sk_zero);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_zero := @COMPAT_OPENSSL_sk_zero;
{$ELSE}
    OPENSSL_sk_zero :=  @ERROR_OPENSSL_sk_zero;
{$ENDIF}
  end;

  OPENSSL_sk_set_cmp_func := LoadLibCryptoFunction('OPENSSL_sk_set_cmp_func');
  FuncLoadError := not assigned(OPENSSL_sk_set_cmp_func);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_set_cmp_func := @COMPAT_OPENSSL_sk_set_cmp_func;
{$ELSE}
    OPENSSL_sk_set_cmp_func :=  @ERROR_OPENSSL_sk_set_cmp_func;
{$ENDIF}
  end;

  OPENSSL_sk_dup := LoadLibCryptoFunction('OPENSSL_sk_dup');
  FuncLoadError := not assigned(OPENSSL_sk_dup);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_dup := @COMPAT_OPENSSL_sk_dup;
{$ELSE}
    OPENSSL_sk_dup :=  @ERROR_OPENSSL_sk_dup;
{$ENDIF}
  end;

  OPENSSL_sk_sort := LoadLibCryptoFunction('OPENSSL_sk_sort');
  FuncLoadError := not assigned(OPENSSL_sk_sort);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_sort := @COMPAT_OPENSSL_sk_sort;
{$ELSE}
    OPENSSL_sk_sort :=  @ERROR_OPENSSL_sk_sort;
{$ENDIF}
  end;

  OPENSSL_sk_is_sorted := LoadLibCryptoFunction('OPENSSL_sk_is_sorted');
  FuncLoadError := not assigned(OPENSSL_sk_is_sorted);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_sk_is_sorted := @COMPAT_OPENSSL_sk_is_sorted;
{$ELSE}
    OPENSSL_sk_is_sorted :=  @ERROR_OPENSSL_sk_is_sorted;
{$ENDIF}
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  sk_num := LoadLibCryptoFunction('sk_num');
  FuncLoadError := not assigned(sk_num);
  if FuncLoadError then
  begin
    if sk_num_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_num');
  end;

  sk_value := LoadLibCryptoFunction('sk_value');
  FuncLoadError := not assigned(sk_value);
  if FuncLoadError then
  begin
    if sk_value_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_value');
  end;

  sk_set := LoadLibCryptoFunction('sk_set');
  FuncLoadError := not assigned(sk_set);
  if FuncLoadError then
  begin
    if sk_set_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_set');
  end;

  sk_new := LoadLibCryptoFunction('sk_new');
  FuncLoadError := not assigned(sk_new);
  if FuncLoadError then
  begin
    if sk_new_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_new');
  end;

  sk_new_null := LoadLibCryptoFunction('sk_new_null');
  FuncLoadError := not assigned(sk_new_null);
  if FuncLoadError then
  begin
    if sk_new_null_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_new_null');
  end;

  sk_new_reserve := LoadLibCryptoFunction('sk_new_reserve');
  FuncLoadError := not assigned(sk_new_reserve);
  if FuncLoadError then
  begin
    if sk_new_reserve_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_new_reserve');
  end;

  sk_reserve := LoadLibCryptoFunction('sk_reserve');
  FuncLoadError := not assigned(sk_reserve);
  if FuncLoadError then
  begin
    if sk_reserve_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_reserve');
  end;

  sk_free := LoadLibCryptoFunction('sk_free');
  FuncLoadError := not assigned(sk_free);
  if FuncLoadError then
  begin
    if sk_free_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_free');
  end;

  sk_pop_free := LoadLibCryptoFunction('sk_pop_free');
  FuncLoadError := not assigned(sk_pop_free);
  if FuncLoadError then
  begin
    if sk_pop_free_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_pop_free');
  end;

  sk_deep_copy := LoadLibCryptoFunction('sk_deep_copy');
  FuncLoadError := not assigned(sk_deep_copy);
  if FuncLoadError then
  begin
    if sk_deep_copy_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_deep_copy');
  end;

  sk_insert := LoadLibCryptoFunction('sk_insert');
  FuncLoadError := not assigned(sk_insert);
  if FuncLoadError then
  begin
    if sk_insert_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_insert');
  end;

  sk_delete := LoadLibCryptoFunction('sk_delete');
  FuncLoadError := not assigned(sk_delete);
  if FuncLoadError then
  begin
    if sk_delete_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_delete');
  end;

  sk_delete_ptr := LoadLibCryptoFunction('sk_delete_ptr');
  FuncLoadError := not assigned(sk_delete_ptr);
  if FuncLoadError then
  begin
    if sk_delete_ptr_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_delete_ptr');
  end;

  sk_find := LoadLibCryptoFunction('sk_find');
  FuncLoadError := not assigned(sk_find);
  if FuncLoadError then
  begin
    if sk_find_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_find');
  end;

  sk_find_ex := LoadLibCryptoFunction('sk_find_ex');
  FuncLoadError := not assigned(sk_find_ex);
  if FuncLoadError then
  begin
    if sk_find_ex_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_find_ex');
  end;

  sk_push := LoadLibCryptoFunction('sk_push');
  FuncLoadError := not assigned(sk_push);
  if FuncLoadError then
  begin
    if sk_push_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_push');
  end;

  sk_unshift := LoadLibCryptoFunction('sk_unshift');
  FuncLoadError := not assigned(sk_unshift);
  if FuncLoadError then
  begin
    if sk_unshift_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_unshift');
  end;

  sk_shift := LoadLibCryptoFunction('sk_shift');
  FuncLoadError := not assigned(sk_shift);
  if FuncLoadError then
  begin
    if sk_shift_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_shift');
  end;

  sk_pop := LoadLibCryptoFunction('sk_pop');
  FuncLoadError := not assigned(sk_pop);
  if FuncLoadError then
  begin
    if sk_pop_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_pop');
  end;

  sk_zero := LoadLibCryptoFunction('sk_zero');
  FuncLoadError := not assigned(sk_zero);
  if FuncLoadError then
  begin
    if sk_zero_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_zero');
  end;

  sk_set_cmp_func := LoadLibCryptoFunction('sk_set_cmp_func');
  FuncLoadError := not assigned(sk_set_cmp_func);
  if FuncLoadError then
  begin
    if sk_set_cmp_func_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_set_cmp_func');
  end;

  sk_dup := LoadLibCryptoFunction('sk_dup');
  FuncLoadError := not assigned(sk_dup);
  if FuncLoadError then
  begin
    if sk_dup_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_dup');
  end;

  sk_sort := LoadLibCryptoFunction('sk_sort');
  FuncLoadError := not assigned(sk_sort);
  if FuncLoadError then
  begin
    if sk_sort_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_sort');
  end;

  sk_is_sorted := LoadLibCryptoFunction('sk_is_sorted');
  FuncLoadError := not assigned(sk_is_sorted);
  if FuncLoadError then
  begin
    if sk_is_sorted_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('sk_is_sorted');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;

procedure UnLoad;
begin
  OPENSSL_sk_num := nil;
  OPENSSL_sk_value := nil;
  OPENSSL_sk_set := nil;
  OPENSSL_sk_new := nil;
  OPENSSL_sk_new_null := nil;
  OPENSSL_sk_new_reserve := nil;
  OPENSSL_sk_reserve := nil;
  OPENSSL_sk_free := nil;
  OPENSSL_sk_pop_free := nil;
  OPENSSL_sk_deep_copy := nil;
  OPENSSL_sk_insert := nil;
  OPENSSL_sk_delete := nil;
  OPENSSL_sk_delete_ptr := nil;
  OPENSSL_sk_find := nil;
  OPENSSL_sk_find_ex := nil;
  OPENSSL_sk_push := nil;
  OPENSSL_sk_unshift := nil;
  OPENSSL_sk_shift := nil;
  OPENSSL_sk_pop := nil;
  OPENSSL_sk_zero := nil;
  OPENSSL_sk_set_cmp_func := nil;
  OPENSSL_sk_dup := nil;
  OPENSSL_sk_sort := nil;
  OPENSSL_sk_is_sorted := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  sk_num := nil;
  sk_value := nil;
  sk_set := nil;
  sk_new := nil;
  sk_new_null := nil;
  sk_new_reserve := nil;
  sk_reserve := nil;
  sk_free := nil;
  sk_pop_free := nil;
  sk_deep_copy := nil;
  sk_insert := nil;
  sk_delete := nil;
  sk_delete_ptr := nil;
  sk_find := nil;
  sk_find_ex := nil;
  sk_push := nil;
  sk_unshift := nil;
  sk_shift := nil;
  sk_pop := nil;
  sk_zero := nil;
  sk_set_cmp_func := nil;
  sk_dup := nil;
  sk_sort := nil;
  sk_is_sorted := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
