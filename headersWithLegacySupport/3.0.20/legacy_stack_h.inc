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
function LEGACY_OPENSSL_sk_num(_para1:POPENSSL_STACK):TOpenSSL_C_INT;
function LEGACY_OPENSSL_sk_value(_para1:POPENSSL_STACK; _para2:TOpenSSL_C_INT):pointer;
function LEGACY_OPENSSL_sk_set(st:POPENSSL_STACK; i:TOpenSSL_C_INT; data:pointer):pointer;
function LEGACY_OPENSSL_sk_new(cmp:TOPENSSL_sk_compfunc):POPENSSL_STACK;
function LEGACY_OPENSSL_Legacy_sk_new_null:POPENSSL_STACK;
function LEGACY_OPENSSL_sk_new_reserve(c:TOPENSSL_sk_compfunc; n:TOpenSSL_C_INT):POPENSSL_STACK;
function LEGACY_OPENSSL_sk_reserve(st:POPENSSL_STACK; n:TOpenSSL_C_INT):TOpenSSL_C_INT;
procedure LEGACY_OPENSSL_sk_free(_para1:POPENSSL_STACK);
procedure LEGACY_OPENSSL_sk_pop_free(st:POPENSSL_STACK; func:TOPENSSL_sk_freefunc);
function LEGACY_OPENSSL_sk_deep_copy(_para1:POPENSSL_STACK; c:TOPENSSL_sk_copyfunc; f:TOPENSSL_sk_freefunc):POPENSSL_STACK;
function LEGACY_OPENSSL_sk_insert(sk:POPENSSL_STACK; data:pointer; where:TOpenSSL_C_INT):TOpenSSL_C_INT;
function LEGACY_OPENSSL_sk_delete(st:POPENSSL_STACK; loc:TOpenSSL_C_INT):pointer;
function LEGACY_OPENSSL_sk_delete_ptr(st:POPENSSL_STACK; p:pointer):pointer;
function LEGACY_OPENSSL_sk_find(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
function LEGACY_OPENSSL_sk_find_ex(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
function LEGACY_OPENSSL_sk_push(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
function LEGACY_OPENSSL_sk_unshift(st:POPENSSL_STACK; data:pointer):TOpenSSL_C_INT;
function LEGACY_OPENSSL_sk_shift(st:POPENSSL_STACK):pointer;
function LEGACY_OPENSSL_sk_pop(st:POPENSSL_STACK):pointer;
procedure LEGACY_OPENSSL_sk_zero(st:POPENSSL_STACK);
function LEGACY_OPENSSL_sk_set_cmp_func(sk:POPENSSL_STACK; cmp:TOPENSSL_sk_compfunc):TOPENSSL_sk_compfunc;
function LEGACY_OPENSSL_sk_dup(st:POPENSSL_STACK):POPENSSL_STACK;
procedure LEGACY_OPENSSL_sk_sort(st:POPENSSL_STACK);
function LEGACY_OPENSSL_sk_is_sorted(st:POPENSSL_STACK):TOpenSSL_C_INT;

{$ENDIF}
{$ENDIF}  
