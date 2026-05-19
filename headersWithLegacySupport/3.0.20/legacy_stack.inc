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
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}

  function Legacy_Load_sk_num(_para1:POPENSSL_STACK):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_value(_para1:POPENSSL_STACK; _para2:TOpenSSL_C_INT):pointer; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_set(st:POPENSSL_STACK; i:TOpenSSL_C_INT; data:pointer):pointer; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_new_null:POPENSSL_STACK; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:TOpenSSL_C_INT):POPENSSL_STACK; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_reserve(st:POPENSSL_STACK; n:TOpenSSL_C_INT):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}
  procedure Legacy_Load_sk_free(_para1:POPENSSL_STACK); cdecl; forward; {introduced 1.1.0}
  procedure Legacy_Load_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_insert(sk:POPENSSL_STACK; data:pointer; where:TOpenSSL_C_INT):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_delete(st:POPENSSL_STACK; loc:TOpenSSL_C_INT):pointer; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_find(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_find_ex(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_push(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_unshift(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_shift(st:POPENSSL_STACK):pointer; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_pop(st:POPENSSL_STACK):pointer; cdecl; forward; {introduced 1.1.0}
  procedure Legacy_Load_sk_zero(st:POPENSSL_STACK); cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc; cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_dup(st:POPENSSL_STACK):POPENSSL_STACK; cdecl; forward; {introduced 1.1.0}
  procedure Legacy_Load_sk_sort(st:POPENSSL_STACK); cdecl; forward; {introduced 1.1.0}
  function Legacy_Load_sk_is_sorted(st:POPENSSL_STACK):TOpenSSL_C_INT; cdecl; forward; {introduced 1.1.0}

var
  Legacy_sk_num: function (_para1:POPENSSL_STACK): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_num; {removed 1.1.0}
  Legacy_sk_value: function (_para1:POPENSSL_STACK; _para2:TOpenSSL_C_INT): pointer; cdecl = Legacy_Load_sk_value; {removed 1.1.0}
  Legacy_sk_set: function (st:POPENSSL_STACK; i:TOpenSSL_C_INT; data:pointer): pointer; cdecl = Legacy_Load_sk_set; {removed 1.1.0}
  Legacy_sk_new: function (cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl = Legacy_Load_sk_new; {removed 1.1.0}
  Legacy_sk_new_null: function : POPENSSL_STACK; cdecl = Legacy_Load_sk_new_null; {removed 1.1.0}
  Legacy_sk_new_reserve: function (c:TOPENSSL_sk_compfunc; n:TOpenSSL_C_INT): POPENSSL_STACK; cdecl = Legacy_Load_sk_new_reserve; {removed 1.0.0}
  Legacy_sk_reserve: function (st:POPENSSL_STACK; n:TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_reserve; {removed 1.0.0}
  Legacy_sk_free: procedure (_para1:POPENSSL_STACK); cdecl = Legacy_Load_sk_free; {removed 1.1.0}
  Legacy_sk_pop_free: procedure (st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl = Legacy_Load_sk_pop_free; {removed 1.1.0}
  Legacy_sk_deep_copy: function (_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl = Legacy_Load_sk_deep_copy; {removed 1.1.0}
  Legacy_sk_insert: function (sk:POPENSSL_STACK; data:pointer; where:TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_insert; {removed 1.1.0}
  Legacy_sk_delete: function (st:POPENSSL_STACK; loc:TOpenSSL_C_INT): pointer; cdecl = Legacy_Load_sk_delete; {removed 1.1.0}
  Legacy_sk_delete_ptr: function (st:POPENSSL_STACK; p:pointer): pointer; cdecl = Legacy_Load_sk_delete_ptr; {removed 1.1.0}
  Legacy_sk_find: function (st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_find; {removed 1.1.0}
  Legacy_sk_find_ex: function (st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_find_ex; {removed 1.1.0}
  Legacy_sk_push: function (st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_push; {removed 1.1.0}
  Legacy_sk_unshift: function (st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_unshift; {removed 1.1.0}
  Legacy_sk_shift: function (st:POPENSSL_STACK): pointer; cdecl = Legacy_Load_sk_shift; {removed 1.1.0}
  Legacy_sk_pop: function (st:POPENSSL_STACK): pointer; cdecl = Legacy_Load_sk_pop; {removed 1.1.0}
  Legacy_sk_zero: procedure (st:POPENSSL_STACK); cdecl = Legacy_Load_sk_zero; {removed 1.1.0}
  Legacy_sk_set_cmp_func: function (sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl = Legacy_Load_sk_set_cmp_func; {removed 1.1.0}
  Legacy_sk_dup: function (st:POPENSSL_STACK): POPENSSL_STACK; cdecl = Legacy_Load_sk_dup; {removed 1.1.0}
  Legacy_sk_sort: procedure (st:POPENSSL_STACK); cdecl = Legacy_Load_sk_sort; {removed 1.1.0}
  Legacy_sk_is_sorted: function (st:POPENSSL_STACK): TOpenSSL_C_INT; cdecl = Legacy_Load_sk_is_sorted; {removed 1.1.0}
  
function Legacy_Load_sk_num(_para1:POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_num := LoadLibCryptoFunction('sk_num');
  if not assigned(Legacy_sk_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_num');
  Result := Legacy_sk_num(_para1);
end;

function Legacy_Load_sk_value(_para1:POPENSSL_STACK; _para2:TOpenSSL_C_INT): pointer; cdecl;
begin
  Legacy_sk_value := LoadLibCryptoFunction('sk_value');
  if not assigned(Legacy_sk_value) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_value');
  Result := Legacy_sk_value(_para1,_para2);
end;

function Legacy_Load_sk_set(st:POPENSSL_STACK; i:TOpenSSL_C_INT; data:pointer): pointer; cdecl;
begin
  Legacy_sk_set := LoadLibCryptoFunction('sk_set');
  if not assigned(Legacy_sk_set) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_set');
  Result := Legacy_sk_set(st,i,data);
end;

function Legacy_Load_sk_new(cmp:TOPENSSL_sk_compfunc): POPENSSL_STACK; cdecl;
begin
  Legacy_sk_new := LoadLibCryptoFunction('sk_new');
  if not assigned(Legacy_sk_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new');
  Result := Legacy_sk_new(cmp);
end;

function Legacy_Load_sk_new_null: POPENSSL_STACK; cdecl;
begin
  Legacy_sk_new_null := LoadLibCryptoFunction('sk_new_null');
  if not assigned(Legacy_sk_new_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new_null');
  Result := Legacy_sk_new_null();
end;

function Legacy_Load_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:TOpenSSL_C_INT): POPENSSL_STACK; cdecl;
begin
  Legacy_sk_new_reserve := LoadLibCryptoFunction('sk_new_reserve');
  if not assigned(Legacy_sk_new_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_new_reserve');
  Result := Legacy_sk_new_reserve(c,n);
end;

function Legacy_Load_sk_reserve(st:POPENSSL_STACK; n:TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_reserve := LoadLibCryptoFunction('sk_reserve');
  if not assigned(Legacy_sk_reserve) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_reserve');
  Result := Legacy_sk_reserve(st,n);
end;

procedure Legacy_Load_sk_free(_para1:POPENSSL_STACK); cdecl;
begin
  Legacy_sk_free := LoadLibCryptoFunction('sk_free');
  if not assigned(Legacy_sk_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_free');
  Legacy_sk_free(_para1);
end;

procedure Legacy_Load_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc); cdecl;
begin
  Legacy_sk_pop_free := LoadLibCryptoFunction('sk_pop_free');
  if not assigned(Legacy_sk_pop_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_pop_free');
  Legacy_sk_pop_free(st,func);
end;

function Legacy_Load_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc): POPENSSL_STACK; cdecl;
begin
  Legacy_sk_deep_copy := LoadLibCryptoFunction('sk_deep_copy');
  if not assigned(Legacy_sk_deep_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_deep_copy');
  Result := Legacy_sk_deep_copy(_para1,c,f);
end;

function Legacy_Load_sk_insert(sk:POPENSSL_STACK; data:pointer; where:TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_insert := LoadLibCryptoFunction('sk_insert');
  if not assigned(Legacy_sk_insert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_insert');
  Result := Legacy_sk_insert(sk,data,where);
end;

function Legacy_Load_sk_delete(st:POPENSSL_STACK; loc:TOpenSSL_C_INT): pointer; cdecl;
begin
  Legacy_sk_delete := LoadLibCryptoFunction('sk_delete');
  if not assigned(Legacy_sk_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_delete');
  Result := Legacy_sk_delete(st,loc);
end;

function Legacy_Load_sk_delete_ptr(st:POPENSSL_STACK; p:pointer): pointer; cdecl;
begin
  Legacy_sk_delete_ptr := LoadLibCryptoFunction('sk_delete_ptr');
  if not assigned(Legacy_sk_delete_ptr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_delete_ptr');
  Result := Legacy_sk_delete_ptr(st,p);
end;

function Legacy_Load_sk_find(st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_find := LoadLibCryptoFunction('sk_find');
  if not assigned(Legacy_sk_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_find');
  Result := Legacy_sk_find(st,data);
end;

function Legacy_Load_sk_find_ex(st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_find_ex := LoadLibCryptoFunction('sk_find_ex');
  if not assigned(Legacy_sk_find_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_find_ex');
  Result := Legacy_sk_find_ex(st,data);
end;

function Legacy_Load_sk_push(st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_push := LoadLibCryptoFunction('sk_push');
  if not assigned(Legacy_sk_push) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_push');
  Result := Legacy_sk_push(st,data);
end;

function Legacy_Load_sk_unshift(st:POPENSSL_STACK; data:pointer): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_unshift := LoadLibCryptoFunction('sk_unshift');
  if not assigned(Legacy_sk_unshift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_unshift');
  Result := Legacy_sk_unshift(st,data);
end;

function Legacy_Load_sk_shift(st:POPENSSL_STACK): pointer; cdecl;
begin
  Legacy_sk_shift := LoadLibCryptoFunction('sk_shift');
  if not assigned(Legacy_sk_shift) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_shift');
  Result := Legacy_sk_shift(st);
end;

function Legacy_Load_sk_pop(st:POPENSSL_STACK): pointer; cdecl;
begin
  Legacy_sk_pop := LoadLibCryptoFunction('sk_pop');
  if not assigned(Legacy_sk_pop) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_pop');
  Result := Legacy_sk_pop(st);
end;

procedure Legacy_Load_sk_zero(st:POPENSSL_STACK); cdecl;
begin
  Legacy_sk_zero := LoadLibCryptoFunction('sk_zero');
  if not assigned(Legacy_sk_zero) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_zero');
  Legacy_sk_zero(st);
end;

function Legacy_Load_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc): TOPENSSL_sk_compfunc; cdecl;
begin
  Legacy_sk_set_cmp_func := LoadLibCryptoFunction('sk_set_cmp_func');
  if not assigned(Legacy_sk_set_cmp_func) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_set_cmp_func');
  Result := Legacy_sk_set_cmp_func(sk,cmp);
end;

function Legacy_Load_sk_dup(st:POPENSSL_STACK): POPENSSL_STACK; cdecl;
begin
  Legacy_sk_dup := LoadLibCryptoFunction('sk_dup');
  if not assigned(Legacy_sk_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_dup');
  Result := Legacy_sk_dup(st);
end;

procedure Legacy_Load_sk_sort(st:POPENSSL_STACK); cdecl;
begin
  Legacy_sk_sort := LoadLibCryptoFunction('sk_sort');
  if not assigned(Legacy_sk_sort) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_sort');
  Legacy_sk_sort(st);
end;

function Legacy_Load_sk_is_sorted(st:POPENSSL_STACK): TOpenSSL_C_INT; cdecl;
begin
  Legacy_sk_is_sorted := LoadLibCryptoFunction('sk_is_sorted');
  if not assigned(Legacy_sk_is_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('sk_is_sorted');
  Result := Legacy_sk_is_sorted(st);
end;

function LEGACY_OPENSSL_sk_num(_para1:POPENSSL_STACK):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_num(_para1);
end;

function LEGACY_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:TOpenSSL_C_INT):pointer;
begin
  Result := Legacy_sk_value(_para1,_para2);
end;

function LEGACY_OPENSSL_sk_set(st:POPENSSL_STACK; i:TOpenSSL_C_INT; data:pointer):pointer;
begin
  Result := Legacy_sk_set(st,i,data);
end;

function LEGACY_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK;
begin
  Result := Legacy_sk_new(cmp);
end;

function LEGACY_OPENSSL_Legacy_sk_new_null:POPENSSL_STACK;
begin
  Result := sk_new_null;
end;

function LEGACY_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:TOpenSSL_C_INT):POPENSSL_STACK;
begin
  Result := Legacy_sk_new_reserve(c,n);
end;

function LEGACY_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:TOpenSSL_C_INT):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_reserve(st,n);
end;

procedure LEGACY_OPENSSL_sk_free(_para1:POPENSSL_STACK);
begin
  Legacy_sk_free(_para1);
end;

procedure LEGACY_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc);
begin
  Legacy_sk_pop_free(st, func);
end;

function LEGACY_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK;
begin
  Result := Legacy_sk_deep_copy(_para1,c,f);
end;

function LEGACY_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:TOpenSSL_C_INT):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_insert(sk,data,where);
end;

function LEGACY_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:TOpenSSL_C_INT):pointer;
begin
  Result := Legacy_sk_delete(st,loc);
end;

function LEGACY_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer;
begin
  Result := Legacy_sk_delete_ptr(st,p);
end;

function LEGACY_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_find(st,data);
end;

function LEGACY_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_find_ex(st,data);
end;

function LEGACY_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_push(st,data);
end;

function LEGACY_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_unshift(st,data);
end;

function LEGACY_OPENSSL_sk_shift(st:POPENSSL_STACK):pointer;
begin
  Result := Legacy_sk_shift(st);
end;

function LEGACY_OPENSSL_sk_pop(st:POPENSSL_STACK):pointer;
begin
  Result := Legacy_sk_pop(st);
end;

procedure LEGACY_OPENSSL_sk_zero(st:POPENSSL_STACK);
begin
  OPENSSL_sk_zero(st);
end;

function LEGACY_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc;
begin
  Result := Legacy_sk_set_cmp_func(sk,cmp);
end;

function LEGACY_OPENSSL_sk_dup(st:POPENSSL_STACK):POPENSSL_STACK;
begin
  Result := Legacy_sk_dup(st);
end;

procedure LEGACY_OPENSSL_sk_sort(st:POPENSSL_STACK);
begin
  OPENSSL_sk_sort(st);
end;

function LEGACY_OPENSSL_sk_is_sorted(st:POPENSSL_STACK):TOpenSSL_C_INT;
begin
  Result := Legacy_sk_is_sorted(st);
end;

  
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}

