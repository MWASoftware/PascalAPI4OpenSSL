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

unit openssl_core_dispatch;

{
  Generated from OpenSSL 4.0.0 Header File core_dispatch.h - Tue 19 May 14:32:14 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_core_dispatch.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_core,openssl_indicator;


{* Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CORE_NUMBERS_H}
  {$define OPENSSL_CORE_NUMBERS_H}

type
  {Auto-generated forward references}
  POSSL_FUNC = ^TOSSL_FUNC;
  PPOSSL_FUNC = ^POSSL_FUNC;
  {end of auto-generated forward references}

  
  {* Generic function pointer for provider method arrays, or other contexts where
  * functions of various signatures must occupy a common slot in an array of
  * structures.
  }
  TOSSL_FUNC = procedure; cdecl;
  (*# define  OSSL_CORE_MAKE_FUNC(type,name,args) typedef type(OSSL_FUNC_ ##name ##_fn) args; static ossl_unused ossl_inline OSSL_FUNC_ 
##name ##_fn * OSSL_FUNC_ ##name(const OSSL_DISPATCH *opf) { return (OSSL_FUNC_ ##name ##_fn * )opf->function; }*)

const
  {-
  * Identities
  * ----------
  *
  * All series start with 1, to allow 0 to be an array terminator.
  * For any FUNC identity, we also provide a function signature typedef
  * and a static inline function to extract a function pointer from a
  * OSSL_DISPATCH element in a type safe manner.
  *
  * Names:
  * for any function base name 'foo' (uppercase form 'FOO'), we will have
  * the following:
  * - a macro for the identity with the name OSSL_FUNC_'FOO' or derivatives
  *   thereof (to be specified further down)
  * - a function signature typedef with the name OSSL_FUNC_'foo'_fn
  * - a function pointer extractor function with the name OSSL_FUNC_'foo'
  }
  
  {* Helper macro to create the function signature typedef and the extractor
  * |type| is the return-type of the function, |name| is the name of the
  * function to fetch, and |args| is a parenthesized list of parameters
  * for the function (that is, it is |name|'s function signature).
  * Note: This is considered a "reserved" internal macro. Applications should
  * not use this or assume its existence.
  }
  
  {* Core function identities, for the two OSSL_DISPATCH tables being passed
  * in the OSSL_provider_init call.
  *
  * 0 serves as a marker for the end of the OSSL_DISPATCH array, and must
  * therefore NEVER be used as a function identity.
  }
  { Functions provided by the Core to the provider, reserved numbers 1-1023 }
  OSSL_FUNC_CORE_GETTABLE_PARAMS_ = 1;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_gettable_params_fn = ^TOSSL_FUNC_core_gettable_params_fn;
  PPOSSL_FUNC_core_gettable_params_fn = ^POSSL_FUNC_core_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_gettable_params_fn = function(prov: POSSL_CORE_HANDLE): POSSL_PARAM; cdecl;


  function OSSL_FUNC_core_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_core_gettable_params_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_GET_PARAMS_ = 2;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_get_params_fn = ^TOSSL_FUNC_core_get_params_fn;
  PPOSSL_FUNC_core_get_params_fn = ^POSSL_FUNC_core_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_get_params_fn = function(prov: POSSL_CORE_HANDLE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_core_get_params_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_THREAD_START_ = 3;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_thread_start_fn = ^TOSSL_FUNC_core_thread_start_fn;
  PPOSSL_FUNC_core_thread_start_fn = ^POSSL_FUNC_core_thread_start_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_thread_start_fn = function(prov: POSSL_CORE_HANDLE; handfn: TOSSL_thread_stop_handler_fn; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_thread_start(opf: POSSL_DISPATCH): POSSL_FUNC_core_thread_start_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_GET_LIBCTX_ = 4;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_get_libctx_fn = ^TOSSL_FUNC_core_get_libctx_fn;
  PPOSSL_FUNC_core_get_libctx_fn = ^POSSL_FUNC_core_get_libctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_get_libctx_fn = function(prov: POSSL_CORE_HANDLE): POPENSSL_CORE_CTX; cdecl;


  function OSSL_FUNC_core_get_libctx(opf: POSSL_DISPATCH): POSSL_FUNC_core_get_libctx_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_NEW_ERROR_ = 5;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_new_error_fn = ^TOSSL_FUNC_core_new_error_fn;
  PPOSSL_FUNC_core_new_error_fn = ^POSSL_FUNC_core_new_error_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_new_error_fn = procedure(prov: POSSL_CORE_HANDLE); cdecl;


  function OSSL_FUNC_core_new_error(opf: POSSL_DISPATCH): POSSL_FUNC_core_new_error_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_SET_ERROR_DEBUG_ = 6;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_set_error_debug_fn = ^TOSSL_FUNC_core_set_error_debug_fn;
  PPOSSL_FUNC_core_set_error_debug_fn = ^POSSL_FUNC_core_set_error_debug_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_set_error_debug_fn = procedure(prov: POSSL_CORE_HANDLE; file_: PAnsiChar; line: TOpenSSL_C_INT; func: PAnsiChar); cdecl;


  function OSSL_FUNC_core_set_error_debug(opf: POSSL_DISPATCH): POSSL_FUNC_core_set_error_debug_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_VSET_ERROR_ = 7;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_vset_error_fn = ^TOSSL_FUNC_core_vset_error_fn;
  PPOSSL_FUNC_core_vset_error_fn = ^POSSL_FUNC_core_vset_error_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_vset_error_fn = procedure(prov: POSSL_CORE_HANDLE; reason: TOpenSSL_C_UINT; fmt: PAnsiChar; args: array of const); cdecl;


  function OSSL_FUNC_core_vset_error(opf: POSSL_DISPATCH): POSSL_FUNC_core_vset_error_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_SET_ERROR_MARK_ = 8;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_set_error_mark_fn = ^TOSSL_FUNC_core_set_error_mark_fn;
  PPOSSL_FUNC_core_set_error_mark_fn = ^POSSL_FUNC_core_set_error_mark_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_set_error_mark_fn = function(prov: POSSL_CORE_HANDLE): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_set_error_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_set_error_mark_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK_ = 9;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_clear_last_error_mark_fn = ^TOSSL_FUNC_core_clear_last_error_mark_fn;
  PPOSSL_FUNC_core_clear_last_error_mark_fn = ^POSSL_FUNC_core_clear_last_error_mark_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_clear_last_error_mark_fn = function(prov: POSSL_CORE_HANDLE): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_clear_last_error_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_clear_last_error_mark_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CORE_POP_ERROR_TO_MARK_ = 10;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_pop_error_to_mark_fn = ^TOSSL_FUNC_core_pop_error_to_mark_fn;
  PPOSSL_FUNC_core_pop_error_to_mark_fn = ^POSSL_FUNC_core_pop_error_to_mark_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_pop_error_to_mark_fn = function(prov: POSSL_CORE_HANDLE): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_pop_error_to_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_pop_error_to_mark_fn{Has C Attribute: unused}; inline;

const
  { Functions to access the OBJ database }
  OSSL_FUNC_CORE_OBJ_ADD_SIGID_ = 11;
  OSSL_FUNC_CORE_OBJ_CREATE_ = 12;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_obj_add_sigid_fn = ^TOSSL_FUNC_core_obj_add_sigid_fn;
  PPOSSL_FUNC_core_obj_add_sigid_fn = ^POSSL_FUNC_core_obj_add_sigid_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_obj_add_sigid_fn = function(prov: POSSL_CORE_HANDLE; sign_name: PAnsiChar; digest_name: PAnsiChar; pkey_name: PAnsiChar): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_obj_add_sigid(opf: POSSL_DISPATCH): POSSL_FUNC_core_obj_add_sigid_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_obj_create_fn = ^TOSSL_FUNC_core_obj_create_fn;
  PPOSSL_FUNC_core_obj_create_fn = ^POSSL_FUNC_core_obj_create_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_obj_create_fn = function(prov: POSSL_CORE_HANDLE; oid: PAnsiChar; sn: PAnsiChar; ln: PAnsiChar): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_obj_create(opf: POSSL_DISPATCH): POSSL_FUNC_core_obj_create_fn{Has C Attribute: unused}; inline;

const
  { Memory allocation, freeing, clearing. }
  OSSL_FUNC_CRYPTO_MALLOC_ = 20;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_malloc_fn = ^TOSSL_FUNC_CRYPTO_malloc_fn;
  PPOSSL_FUNC_CRYPTO_malloc_fn = ^POSSL_FUNC_CRYPTO_malloc_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_malloc_fn = function(num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT): pointer; cdecl;


  function OSSL_FUNC_CRYPTO_malloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_malloc_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_ZALLOC_ = 21;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_zalloc_fn = ^TOSSL_FUNC_CRYPTO_zalloc_fn;
  PPOSSL_FUNC_CRYPTO_zalloc_fn = ^POSSL_FUNC_CRYPTO_zalloc_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_zalloc_fn = function(num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT): pointer; cdecl;


  function OSSL_FUNC_CRYPTO_zalloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_zalloc_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_FREE_ = 22;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_free_fn = ^TOSSL_FUNC_CRYPTO_free_fn;
  PPOSSL_FUNC_CRYPTO_free_fn = ^POSSL_FUNC_CRYPTO_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_free_fn = procedure(ptr: pointer; file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;


  function OSSL_FUNC_CRYPTO_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_free_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_CLEAR_FREE_ = 23;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_clear_free_fn = ^TOSSL_FUNC_CRYPTO_clear_free_fn;
  PPOSSL_FUNC_CRYPTO_clear_free_fn = ^POSSL_FUNC_CRYPTO_clear_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_clear_free_fn = procedure(ptr: pointer; num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;


  function OSSL_FUNC_CRYPTO_clear_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_clear_free_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_REALLOC_ = 24;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_realloc_fn = ^TOSSL_FUNC_CRYPTO_realloc_fn;
  PPOSSL_FUNC_CRYPTO_realloc_fn = ^POSSL_FUNC_CRYPTO_realloc_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_realloc_fn = function(addr: pointer; num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT): pointer; cdecl;


  function OSSL_FUNC_CRYPTO_realloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_realloc_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_CLEAR_REALLOC_ = 25;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_clear_realloc_fn = ^TOSSL_FUNC_CRYPTO_clear_realloc_fn;
  PPOSSL_FUNC_CRYPTO_clear_realloc_fn = ^POSSL_FUNC_CRYPTO_clear_realloc_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_clear_realloc_fn = function(addr: pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT): pointer; cdecl;


  function OSSL_FUNC_CRYPTO_clear_realloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_clear_realloc_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_SECURE_MALLOC_ = 26;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_secure_malloc_fn = ^TOSSL_FUNC_CRYPTO_secure_malloc_fn;
  PPOSSL_FUNC_CRYPTO_secure_malloc_fn = ^POSSL_FUNC_CRYPTO_secure_malloc_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_secure_malloc_fn = function(num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT): pointer; cdecl;


  function OSSL_FUNC_CRYPTO_secure_malloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_malloc_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_SECURE_ZALLOC_ = 27;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_secure_zalloc_fn = ^TOSSL_FUNC_CRYPTO_secure_zalloc_fn;
  PPOSSL_FUNC_CRYPTO_secure_zalloc_fn = ^POSSL_FUNC_CRYPTO_secure_zalloc_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_secure_zalloc_fn = function(num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT): pointer; cdecl;


  function OSSL_FUNC_CRYPTO_secure_zalloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_zalloc_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_SECURE_FREE_ = 28;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_secure_free_fn = ^TOSSL_FUNC_CRYPTO_secure_free_fn;
  PPOSSL_FUNC_CRYPTO_secure_free_fn = ^POSSL_FUNC_CRYPTO_secure_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_secure_free_fn = procedure(ptr: pointer; file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;


  function OSSL_FUNC_CRYPTO_secure_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_free_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE_ = 29;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_secure_clear_free_fn = ^TOSSL_FUNC_CRYPTO_secure_clear_free_fn;
  PPOSSL_FUNC_CRYPTO_secure_clear_free_fn = ^POSSL_FUNC_CRYPTO_secure_clear_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_secure_clear_free_fn = procedure(ptr: pointer; num: TOpenSSL_C_SIZET; file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;


  function OSSL_FUNC_CRYPTO_secure_clear_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_clear_free_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_CRYPTO_SECURE_ALLOCATED_ = 30;

type
  {Auto-generated forward references}
  POSSL_FUNC_CRYPTO_secure_allocated_fn = ^TOSSL_FUNC_CRYPTO_secure_allocated_fn;
  PPOSSL_FUNC_CRYPTO_secure_allocated_fn = ^POSSL_FUNC_CRYPTO_secure_allocated_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_CRYPTO_secure_allocated_fn = function(ptr: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_CRYPTO_secure_allocated(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_allocated_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_OPENSSL_CLEANSE_ = 31;

type
  {Auto-generated forward references}
  POSSL_FUNC_OPENSSL_cleanse_fn = ^TOSSL_FUNC_OPENSSL_cleanse_fn;
  PPOSSL_FUNC_OPENSSL_cleanse_fn = ^POSSL_FUNC_OPENSSL_cleanse_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_OPENSSL_cleanse_fn = procedure(ptr: pointer; len: TOpenSSL_C_SIZET); cdecl;


  function OSSL_FUNC_OPENSSL_cleanse(opf: POSSL_DISPATCH): POSSL_FUNC_OPENSSL_cleanse_fn{Has C Attribute: unused}; inline;

const
  { Bio functions provided by the core }
  OSSL_FUNC_BIO_NEW_FILE_ = 40;
  OSSL_FUNC_BIO_NEW_MEMBUF_ = 41;
  OSSL_FUNC_BIO_READ_EX_ = 42;
  OSSL_FUNC_BIO_WRITE_EX_ = 43;
  OSSL_FUNC_BIO_UP_REF_ = 44;
  OSSL_FUNC_BIO_FREE_ = 45;
  OSSL_FUNC_BIO_VPRINTF_ = 46;
  OSSL_FUNC_BIO_VSNPRINTF_ = 47;
  OSSL_FUNC_BIO_PUTS_ = 48;
  OSSL_FUNC_BIO_GETS_ = 49;
  OSSL_FUNC_BIO_CTRL_ = 50;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_new_file_fn = ^TOSSL_FUNC_BIO_new_file_fn;
  PPOSSL_FUNC_BIO_new_file_fn = ^POSSL_FUNC_BIO_new_file_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_new_file_fn = function(filename: PAnsiChar; mode: PAnsiChar): POSSL_CORE_BIO; cdecl;


  function OSSL_FUNC_BIO_new_file(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_new_file_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_new_membuf_fn = ^TOSSL_FUNC_BIO_new_membuf_fn;
  PPOSSL_FUNC_BIO_new_membuf_fn = ^POSSL_FUNC_BIO_new_membuf_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_new_membuf_fn = function(buf: pointer; len: TOpenSSL_C_INT): POSSL_CORE_BIO; cdecl;


  function OSSL_FUNC_BIO_new_membuf(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_new_membuf_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_read_ex_fn = ^TOSSL_FUNC_BIO_read_ex_fn;
  PPOSSL_FUNC_BIO_read_ex_fn = ^POSSL_FUNC_BIO_read_ex_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_read_ex_fn = function(bio: POSSL_CORE_BIO; data: pointer; data_len: TOpenSSL_C_SIZET; bytes_read: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_read_ex(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_read_ex_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_write_ex_fn = ^TOSSL_FUNC_BIO_write_ex_fn;
  PPOSSL_FUNC_BIO_write_ex_fn = ^POSSL_FUNC_BIO_write_ex_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_write_ex_fn = function(bio: POSSL_CORE_BIO; data: pointer; data_len: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_write_ex(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_write_ex_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_gets_fn = ^TOSSL_FUNC_BIO_gets_fn;
  PPOSSL_FUNC_BIO_gets_fn = ^POSSL_FUNC_BIO_gets_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_gets_fn = function(bio: POSSL_CORE_BIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_gets(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_gets_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_puts_fn = ^TOSSL_FUNC_BIO_puts_fn;
  PPOSSL_FUNC_BIO_puts_fn = ^POSSL_FUNC_BIO_puts_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_puts_fn = function(bio: POSSL_CORE_BIO; str: PAnsiChar): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_puts(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_puts_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_up_ref_fn = ^TOSSL_FUNC_BIO_up_ref_fn;
  PPOSSL_FUNC_BIO_up_ref_fn = ^POSSL_FUNC_BIO_up_ref_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_up_ref_fn = function(bio: POSSL_CORE_BIO): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_up_ref(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_up_ref_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_free_fn = ^TOSSL_FUNC_BIO_free_fn;
  PPOSSL_FUNC_BIO_free_fn = ^POSSL_FUNC_BIO_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_free_fn = function(bio: POSSL_CORE_BIO): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_free(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_free_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_vprintf_fn = ^TOSSL_FUNC_BIO_vprintf_fn;
  PPOSSL_FUNC_BIO_vprintf_fn = ^POSSL_FUNC_BIO_vprintf_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_vprintf_fn = function(bio: POSSL_CORE_BIO; format: PAnsiChar; args: array of const): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_vprintf(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_vprintf_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_vsnprintf_fn = ^TOSSL_FUNC_BIO_vsnprintf_fn;
  PPOSSL_FUNC_BIO_vsnprintf_fn = ^POSSL_FUNC_BIO_vsnprintf_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_vsnprintf_fn = function(buf: PAnsiChar; n: TOpenSSL_C_SIZET; fmt: PAnsiChar; args: array of const): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_vsnprintf(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_vsnprintf_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_BIO_ctrl_fn = ^TOSSL_FUNC_BIO_ctrl_fn;
  PPOSSL_FUNC_BIO_ctrl_fn = ^POSSL_FUNC_BIO_ctrl_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_BIO_ctrl_fn = function(bio: POSSL_CORE_BIO; cmd: TOpenSSL_C_INT; num: TOpenSSL_C_INT; ptr: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_BIO_ctrl(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_ctrl_fn{Has C Attribute: unused}; inline;

const
  { New seeding functions prototypes with the 101-104 series }
  OSSL_FUNC_CLEANUP_USER_ENTROPY_ = 96;
  OSSL_FUNC_CLEANUP_USER_NONCE_ = 97;
  OSSL_FUNC_GET_USER_ENTROPY_ = 98;
  OSSL_FUNC_GET_USER_NONCE_ = 99;
  OSSL_FUNC_INDICATOR_CB_ = 95;

type
  {Auto-generated forward references}
  POSSL_FUNC_indicator_cb_fn = ^TOSSL_FUNC_indicator_cb_fn;
  PPOSSL_FUNC_indicator_cb_fn = ^POSSL_FUNC_indicator_cb_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_indicator_cb_fn = procedure(ctx: POPENSSL_CORE_CTX; cb: PPOSSL_INDICATOR_CALLBACK); cdecl;


  function OSSL_FUNC_indicator_cb(opf: POSSL_DISPATCH): POSSL_FUNC_indicator_cb_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_SELF_TEST_CB_ = 100;

type
  {Auto-generated forward references}
  POSSL_FUNC_self_test_cb_fn = ^TOSSL_FUNC_self_test_cb_fn;
  PPOSSL_FUNC_self_test_cb_fn = ^POSSL_FUNC_self_test_cb_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_self_test_cb_fn = procedure(ctx: POPENSSL_CORE_CTX; cb: PPOSSL_CALLBACK; cbarg: Ppointer); cdecl;


  function OSSL_FUNC_self_test_cb(opf: POSSL_DISPATCH): POSSL_FUNC_self_test_cb_fn{Has C Attribute: unused}; inline;

const
  { Functions to get seed material from the operating system }
  OSSL_FUNC_GET_ENTROPY_ = 101;
  OSSL_FUNC_CLEANUP_ENTROPY_ = 102;
  OSSL_FUNC_GET_NONCE_ = 103;
  OSSL_FUNC_CLEANUP_NONCE_ = 104;

type
  {Auto-generated forward references}
  POSSL_FUNC_get_entropy_fn = ^TOSSL_FUNC_get_entropy_fn;
  PPOSSL_FUNC_get_entropy_fn = ^POSSL_FUNC_get_entropy_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_get_entropy_fn = function(handle: POSSL_CORE_HANDLE; pout: PPbyte; entropy: TOpenSSL_C_INT; min_len: TOpenSSL_C_SIZET; max_len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;


  function OSSL_FUNC_get_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_get_entropy_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_get_user_entropy_fn = ^TOSSL_FUNC_get_user_entropy_fn;
  PPOSSL_FUNC_get_user_entropy_fn = ^POSSL_FUNC_get_user_entropy_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_get_user_entropy_fn = function(handle: POSSL_CORE_HANDLE; pout: PPbyte; entropy: TOpenSSL_C_INT; min_len: TOpenSSL_C_SIZET; max_len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;


  function OSSL_FUNC_get_user_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_get_user_entropy_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cleanup_entropy_fn = ^TOSSL_FUNC_cleanup_entropy_fn;
  PPOSSL_FUNC_cleanup_entropy_fn = ^POSSL_FUNC_cleanup_entropy_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cleanup_entropy_fn = procedure(handle: POSSL_CORE_HANDLE; buf: Pbyte; len: TOpenSSL_C_SIZET); cdecl;


  function OSSL_FUNC_cleanup_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_entropy_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cleanup_user_entropy_fn = ^TOSSL_FUNC_cleanup_user_entropy_fn;
  PPOSSL_FUNC_cleanup_user_entropy_fn = ^POSSL_FUNC_cleanup_user_entropy_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cleanup_user_entropy_fn = procedure(handle: POSSL_CORE_HANDLE; buf: Pbyte; len: TOpenSSL_C_SIZET); cdecl;


  function OSSL_FUNC_cleanup_user_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_user_entropy_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_get_nonce_fn = ^TOSSL_FUNC_get_nonce_fn;
  PPOSSL_FUNC_get_nonce_fn = ^POSSL_FUNC_get_nonce_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_get_nonce_fn = function(handle: POSSL_CORE_HANDLE; pout: PPbyte; min_len: TOpenSSL_C_SIZET; max_len: TOpenSSL_C_SIZET; salt: pointer; salt_len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;


  function OSSL_FUNC_get_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_get_nonce_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_get_user_nonce_fn = ^TOSSL_FUNC_get_user_nonce_fn;
  PPOSSL_FUNC_get_user_nonce_fn = ^POSSL_FUNC_get_user_nonce_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_get_user_nonce_fn = function(handle: POSSL_CORE_HANDLE; pout: PPbyte; min_len: TOpenSSL_C_SIZET; max_len: TOpenSSL_C_SIZET; salt: pointer; salt_len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;


  function OSSL_FUNC_get_user_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_get_user_nonce_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cleanup_nonce_fn = ^TOSSL_FUNC_cleanup_nonce_fn;
  PPOSSL_FUNC_cleanup_nonce_fn = ^POSSL_FUNC_cleanup_nonce_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cleanup_nonce_fn = procedure(handle: POSSL_CORE_HANDLE; buf: Pbyte; len: TOpenSSL_C_SIZET); cdecl;


  function OSSL_FUNC_cleanup_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_nonce_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cleanup_user_nonce_fn = ^TOSSL_FUNC_cleanup_user_nonce_fn;
  PPOSSL_FUNC_cleanup_user_nonce_fn = ^POSSL_FUNC_cleanup_user_nonce_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cleanup_user_nonce_fn = procedure(handle: POSSL_CORE_HANDLE; buf: Pbyte; len: TOpenSSL_C_SIZET); cdecl;


  function OSSL_FUNC_cleanup_user_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_user_nonce_fn{Has C Attribute: unused}; inline;

const
  { Functions to access the core's providers }
  OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB_ = 105;
  OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB_ = 106;
  OSSL_FUNC_PROVIDER_NAME_ = 107;
  OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX_ = 108;
  OSSL_FUNC_PROVIDER_GET0_DISPATCH_ = 109;
  OSSL_FUNC_PROVIDER_UP_REF_ = 110;
  OSSL_FUNC_PROVIDER_FREE_ = 111;

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  POSSL_FUNC_provider_register_child_cb_fn = ^TOSSL_FUNC_provider_register_child_cb_fn;
  PPOSSL_FUNC_provider_register_child_cb_fn = ^POSSL_FUNC_provider_register_child_cb_fn;
  {end of auto-generated forward references}

  TFuncType000 = function(provider: POSSL_CORE_HANDLE; cbdata: pointer): TOpenSSL_C_INT; cdecl;
  TFuncType001 = function(provider: POSSL_CORE_HANDLE; cbdata: pointer): TOpenSSL_C_INT; cdecl;
  TFuncType002 = function(props: PAnsiChar; cbdata: pointer): TOpenSSL_C_INT; cdecl;
  TOSSL_FUNC_provider_register_child_cb_fn = function(handle: POSSL_CORE_HANDLE; create_cb: TFuncType000; remove_cb: TFuncType001; global_props_cb: TFuncType002; cbdata: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_provider_register_child_cb(opf: POSSL_DISPATCH): POSSL_FUNC_provider_register_child_cb_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_deregister_child_cb_fn = ^TOSSL_FUNC_provider_deregister_child_cb_fn;
  PPOSSL_FUNC_provider_deregister_child_cb_fn = ^POSSL_FUNC_provider_deregister_child_cb_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_deregister_child_cb_fn = procedure(handle: POSSL_CORE_HANDLE); cdecl;


  function OSSL_FUNC_provider_deregister_child_cb(opf: POSSL_DISPATCH): POSSL_FUNC_provider_deregister_child_cb_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_name_fn = ^TOSSL_FUNC_provider_name_fn;
  PPOSSL_FUNC_provider_name_fn = ^POSSL_FUNC_provider_name_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_name_fn = function(prov: POSSL_CORE_HANDLE): PAnsiChar; cdecl;


  function OSSL_FUNC_provider_name(opf: POSSL_DISPATCH): POSSL_FUNC_provider_name_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_get0_provider_ctx_fn = ^TOSSL_FUNC_provider_get0_provider_ctx_fn;
  PPOSSL_FUNC_provider_get0_provider_ctx_fn = ^POSSL_FUNC_provider_get0_provider_ctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_get0_provider_ctx_fn = function(prov: POSSL_CORE_HANDLE): pointer; cdecl;


  function OSSL_FUNC_provider_get0_provider_ctx(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get0_provider_ctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_get0_dispatch_fn = ^TOSSL_FUNC_provider_get0_dispatch_fn;
  PPOSSL_FUNC_provider_get0_dispatch_fn = ^POSSL_FUNC_provider_get0_dispatch_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_get0_dispatch_fn = function(prov: POSSL_CORE_HANDLE): POSSL_DISPATCH; cdecl;


  function OSSL_FUNC_provider_get0_dispatch(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get0_dispatch_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_up_ref_fn = ^TOSSL_FUNC_provider_up_ref_fn;
  PPOSSL_FUNC_provider_up_ref_fn = ^POSSL_FUNC_provider_up_ref_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_up_ref_fn = function(prov: POSSL_CORE_HANDLE; activate: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_provider_up_ref(opf: POSSL_DISPATCH): POSSL_FUNC_provider_up_ref_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_free_fn = ^TOSSL_FUNC_provider_free_fn;
  PPOSSL_FUNC_provider_free_fn = ^POSSL_FUNC_provider_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_free_fn = function(prov: POSSL_CORE_HANDLE; deactivate: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_provider_free(opf: POSSL_DISPATCH): POSSL_FUNC_provider_free_fn{Has C Attribute: unused}; inline;

const
  { Additional error functions provided by the core }
  OSSL_FUNC_CORE_COUNT_TO_MARK_ = 120;

type
  {Auto-generated forward references}
  POSSL_FUNC_core_count_to_mark_fn = ^TOSSL_FUNC_core_count_to_mark_fn;
  PPOSSL_FUNC_core_count_to_mark_fn = ^POSSL_FUNC_core_count_to_mark_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_core_count_to_mark_fn = function(prov: POSSL_CORE_HANDLE): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_core_count_to_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_count_to_mark_fn{Has C Attribute: unused}; inline;

const
  { Functions provided by the provider to the Core, reserved numbers 1024-1535 }
  OSSL_FUNC_PROVIDER_TEARDOWN_ = 1024;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_teardown_fn = ^TOSSL_FUNC_provider_teardown_fn;
  PPOSSL_FUNC_provider_teardown_fn = ^POSSL_FUNC_provider_teardown_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_teardown_fn = procedure(provctx: pointer); cdecl;


  function OSSL_FUNC_provider_teardown(opf: POSSL_DISPATCH): POSSL_FUNC_provider_teardown_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_GETTABLE_PARAMS_ = 1025;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_gettable_params_fn = ^TOSSL_FUNC_provider_gettable_params_fn;
  PPOSSL_FUNC_provider_gettable_params_fn = ^POSSL_FUNC_provider_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_provider_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_provider_gettable_params_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_GET_PARAMS_ = 1026;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_get_params_fn = ^TOSSL_FUNC_provider_get_params_fn;
  PPOSSL_FUNC_provider_get_params_fn = ^POSSL_FUNC_provider_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_get_params_fn = function(provctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_provider_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get_params_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_QUERY_OPERATION_ = 1027;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_query_operation_fn = ^TOSSL_FUNC_provider_query_operation_fn;
  PPOSSL_FUNC_provider_query_operation_fn = ^POSSL_FUNC_provider_query_operation_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_query_operation_fn = function(provctx: pointer; operation_id: TOpenSSL_C_INT; no_store: POpenSSL_C_INT): POSSL_ALGORITHM; cdecl;


  function OSSL_FUNC_provider_query_operation(opf: POSSL_DISPATCH): POSSL_FUNC_provider_query_operation_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_UNQUERY_OPERATION_ = 1028;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_unquery_operation_fn = ^TOSSL_FUNC_provider_unquery_operation_fn;
  PPOSSL_FUNC_provider_unquery_operation_fn = ^POSSL_FUNC_provider_unquery_operation_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_unquery_operation_fn = procedure(provctx: pointer; operation_id: TOpenSSL_C_INT; _param3: POSSL_ALGORITHM); cdecl;


  function OSSL_FUNC_provider_unquery_operation(opf: POSSL_DISPATCH): POSSL_FUNC_provider_unquery_operation_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_GET_REASON_STRINGS_ = 1029;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_get_reason_strings_fn = ^TOSSL_FUNC_provider_get_reason_strings_fn;
  PPOSSL_FUNC_provider_get_reason_strings_fn = ^POSSL_FUNC_provider_get_reason_strings_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_get_reason_strings_fn = function(provctx: pointer): POSSL_ITEM; cdecl;


  function OSSL_FUNC_provider_get_reason_strings(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get_reason_strings_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_GET_CAPABILITIES_ = 1030;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_get_capabilities_fn = ^TOSSL_FUNC_provider_get_capabilities_fn;
  PPOSSL_FUNC_provider_get_capabilities_fn = ^POSSL_FUNC_provider_get_capabilities_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_get_capabilities_fn = function(provctx: pointer; capability: PAnsiChar; cb: POSSL_CALLBACK; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_provider_get_capabilities(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get_capabilities_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_SELF_TEST_ = 1031;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_self_test_fn = ^TOSSL_FUNC_provider_self_test_fn;
  PPOSSL_FUNC_provider_self_test_fn = ^POSSL_FUNC_provider_self_test_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_self_test_fn = function(provctx: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_provider_self_test(opf: POSSL_DISPATCH): POSSL_FUNC_provider_self_test_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_PROVIDER_RANDOM_BYTES_ = 1032;

type
  {Auto-generated forward references}
  POSSL_FUNC_provider_random_bytes_fn = ^TOSSL_FUNC_provider_random_bytes_fn;
  PPOSSL_FUNC_provider_random_bytes_fn = ^POSSL_FUNC_provider_random_bytes_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_provider_random_bytes_fn = function(provctx: pointer; which: TOpenSSL_C_INT; buf: pointer; n: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_provider_random_bytes(opf: POSSL_DISPATCH): POSSL_FUNC_provider_random_bytes_fn{Has C Attribute: unused}; inline;

const
  { Libssl related functions }
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND_ = 2001;

type
  {Auto-generated forward references}
  POSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn = ^TOSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn;
  PPOSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn = ^POSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn = function(s: PSSL; buf: Pbyte; buf_len: TOpenSSL_C_SIZET; consumed: POpenSSL_C_SIZET; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_SSL_QUIC_TLS_crypto_send(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD_ = 2002;

type
  {Auto-generated forward references}
  POSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn = ^TOSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn;
  PPOSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn = ^POSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn = function(s: PSSL; buf: PPbyte; bytes_read: POpenSSL_C_SIZET; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD_ = 2003;

type
  {Auto-generated forward references}
  POSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn = ^TOSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn;
  PPOSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn = ^POSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn = function(s: PSSL; bytes_read: TOpenSSL_C_SIZET; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET_ = 2004;

type
  {Auto-generated forward references}
  POSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn = ^TOSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn;
  PPOSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn = ^POSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn = function(s: PSSL; prot_level: TOpenSSL_C_UINT; direction: TOpenSSL_C_INT; secret: Pbyte; secret_len: TOpenSSL_C_SIZET; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_SSL_QUIC_TLS_yield_secret(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS_ = 2005;

type
  {Auto-generated forward references}
  POSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn = ^TOSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn;
  PPOSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn = ^POSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn = function(s: PSSL; params: Pbyte; params_len: TOpenSSL_C_SIZET; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_SSL_QUIC_TLS_got_transport_params(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_SSL_QUIC_TLS_ALERT_ = 2006;

type
  {Auto-generated forward references}
  POSSL_FUNC_SSL_QUIC_TLS_alert_fn = ^TOSSL_FUNC_SSL_QUIC_TLS_alert_fn;
  PPOSSL_FUNC_SSL_QUIC_TLS_alert_fn = ^POSSL_FUNC_SSL_QUIC_TLS_alert_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_SSL_QUIC_TLS_alert_fn = function(s: PSSL; alert_code: byte; arg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_SSL_QUIC_TLS_alert(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_alert_fn{Has C Attribute: unused}; inline;

const
  { Operations }
  OSSL_OP_DIGEST = 1;
  OSSL_OP_CIPHER = 2;
  OSSL_OP_MAC = 3;
  OSSL_OP_KDF = 4;
  OSSL_OP_RAND = 5;
  OSSL_OP_KEYMGMT = 10;
  OSSL_OP_KEYEXCH = 11;
  OSSL_OP_SIGNATURE = 12;
  OSSL_OP_ASYM_CIPHER = 13;
  OSSL_OP_KEM = 14;
  OSSL_OP_SKEYMGMT = 15;
  { New section for non-EVP operations }
  OSSL_OP_ENCODER = 20;
  OSSL_OP_DECODER = 21;
  OSSL_OP_STORE = 22;
  { Highest known operation number }
  OSSL_OP__HIGHEST = 22;
  { Digests }
  OSSL_FUNC_DIGEST_NEWCTX_ = 1;
  OSSL_FUNC_DIGEST_INIT_ = 2;
  OSSL_FUNC_DIGEST_UPDATE_ = 3;
  OSSL_FUNC_DIGEST_FINAL_ = 4;
  OSSL_FUNC_DIGEST_DIGEST_ = 5;
  OSSL_FUNC_DIGEST_FREECTX_ = 6;
  OSSL_FUNC_DIGEST_DUPCTX_ = 7;
  OSSL_FUNC_DIGEST_GET_PARAMS_ = 8;
  OSSL_FUNC_DIGEST_SET_CTX_PARAMS_ = 9;
  OSSL_FUNC_DIGEST_GET_CTX_PARAMS_ = 10;
  OSSL_FUNC_DIGEST_GETTABLE_PARAMS_ = 11;
  OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS_ = 12;
  OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS_ = 13;
  OSSL_FUNC_DIGEST_SQUEEZE_ = 14;
  OSSL_FUNC_DIGEST_COPYCTX_ = 15;
  OSSL_FUNC_DIGEST_SERIALIZE_ = 16;
  OSSL_FUNC_DIGEST_DESERIALIZE_ = 17;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_newctx_fn = ^TOSSL_FUNC_digest_newctx_fn;
  PPOSSL_FUNC_digest_newctx_fn = ^POSSL_FUNC_digest_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_digest_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_init_fn = ^TOSSL_FUNC_digest_init_fn;
  PPOSSL_FUNC_digest_init_fn = ^POSSL_FUNC_digest_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_init_fn = function(dctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_init(opf: POSSL_DISPATCH): POSSL_FUNC_digest_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_update_fn = ^TOSSL_FUNC_digest_update_fn;
  PPOSSL_FUNC_digest_update_fn = ^POSSL_FUNC_digest_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_update_fn = function(dctx: pointer; in_: Pbyte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_update(opf: POSSL_DISPATCH): POSSL_FUNC_digest_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_final_fn = ^TOSSL_FUNC_digest_final_fn;
  PPOSSL_FUNC_digest_final_fn = ^POSSL_FUNC_digest_final_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_final_fn = function(dctx: pointer; out_: Pbyte; outl: POpenSSL_C_SIZET; outsz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_final(opf: POSSL_DISPATCH): POSSL_FUNC_digest_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_squeeze_fn = ^TOSSL_FUNC_digest_squeeze_fn;
  PPOSSL_FUNC_digest_squeeze_fn = ^POSSL_FUNC_digest_squeeze_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_squeeze_fn = function(dctx: pointer; out_: Pbyte; outl: POpenSSL_C_SIZET; outsz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_squeeze(opf: POSSL_DISPATCH): POSSL_FUNC_digest_squeeze_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_digest_fn = ^TOSSL_FUNC_digest_digest_fn;
  PPOSSL_FUNC_digest_digest_fn = ^POSSL_FUNC_digest_digest_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_digest_fn = function(provctx: pointer; in_: Pbyte; inl: TOpenSSL_C_SIZET; out_: Pbyte; outl: POpenSSL_C_SIZET; outsz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_digest(opf: POSSL_DISPATCH): POSSL_FUNC_digest_digest_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_freectx_fn = ^TOSSL_FUNC_digest_freectx_fn;
  PPOSSL_FUNC_digest_freectx_fn = ^POSSL_FUNC_digest_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_freectx_fn = procedure(dctx: pointer); cdecl;


  function OSSL_FUNC_digest_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_dupctx_fn = ^TOSSL_FUNC_digest_dupctx_fn;
  PPOSSL_FUNC_digest_dupctx_fn = ^POSSL_FUNC_digest_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_dupctx_fn = function(dctx: pointer): pointer; cdecl;


  function OSSL_FUNC_digest_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_copyctx_fn = ^TOSSL_FUNC_digest_copyctx_fn;
  PPOSSL_FUNC_digest_copyctx_fn = ^POSSL_FUNC_digest_copyctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_copyctx_fn = procedure(outctx: pointer; inctx: pointer); cdecl;


  function OSSL_FUNC_digest_copyctx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_copyctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_get_params_fn = ^TOSSL_FUNC_digest_get_params_fn;
  PPOSSL_FUNC_digest_get_params_fn = ^POSSL_FUNC_digest_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_get_params_fn = function(params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_set_ctx_params_fn = ^TOSSL_FUNC_digest_set_ctx_params_fn;
  PPOSSL_FUNC_digest_set_ctx_params_fn = ^POSSL_FUNC_digest_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_set_ctx_params_fn = function(vctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_get_ctx_params_fn = ^TOSSL_FUNC_digest_get_ctx_params_fn;
  PPOSSL_FUNC_digest_get_ctx_params_fn = ^POSSL_FUNC_digest_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_get_ctx_params_fn = function(vctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_gettable_params_fn = ^TOSSL_FUNC_digest_gettable_params_fn;
  PPOSSL_FUNC_digest_gettable_params_fn = ^POSSL_FUNC_digest_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_digest_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_settable_ctx_params_fn = ^TOSSL_FUNC_digest_settable_ctx_params_fn;
  PPOSSL_FUNC_digest_settable_ctx_params_fn = ^POSSL_FUNC_digest_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_settable_ctx_params_fn = function(dctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_digest_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_gettable_ctx_params_fn = ^TOSSL_FUNC_digest_gettable_ctx_params_fn;
  PPOSSL_FUNC_digest_gettable_ctx_params_fn = ^POSSL_FUNC_digest_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_gettable_ctx_params_fn = function(dctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_digest_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_serialize_fn = ^TOSSL_FUNC_digest_serialize_fn;
  PPOSSL_FUNC_digest_serialize_fn = ^POSSL_FUNC_digest_serialize_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_serialize_fn = function(dctx: pointer; out_: Pbyte; outl: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_serialize(opf: POSSL_DISPATCH): POSSL_FUNC_digest_serialize_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_digest_deserialize_fn = ^TOSSL_FUNC_digest_deserialize_fn;
  PPOSSL_FUNC_digest_deserialize_fn = ^POSSL_FUNC_digest_deserialize_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_digest_deserialize_fn = function(dctx: pointer; in_: Pbyte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_digest_deserialize(opf: POSSL_DISPATCH): POSSL_FUNC_digest_deserialize_fn{Has C Attribute: unused}; inline;

const
  { Symmetric Ciphers }
  OSSL_FUNC_CIPHER_NEWCTX_ = 1;
  OSSL_FUNC_CIPHER_ENCRYPT_INIT_ = 2;
  OSSL_FUNC_CIPHER_DECRYPT_INIT_ = 3;
  OSSL_FUNC_CIPHER_UPDATE_ = 4;
  OSSL_FUNC_CIPHER_FINAL_ = 5;
  OSSL_FUNC_CIPHER_CIPHER_ = 6;
  OSSL_FUNC_CIPHER_FREECTX_ = 7;
  OSSL_FUNC_CIPHER_DUPCTX_ = 8;
  OSSL_FUNC_CIPHER_GET_PARAMS_ = 9;
  OSSL_FUNC_CIPHER_GET_CTX_PARAMS_ = 10;
  OSSL_FUNC_CIPHER_SET_CTX_PARAMS_ = 11;
  OSSL_FUNC_CIPHER_GETTABLE_PARAMS_ = 12;
  OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS_ = 13;
  OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS_ = 14;
  OSSL_FUNC_CIPHER_PIPELINE_ENCRYPT_INIT_ = 15;
  OSSL_FUNC_CIPHER_PIPELINE_DECRYPT_INIT_ = 16;
  OSSL_FUNC_CIPHER_PIPELINE_UPDATE_ = 17;
  OSSL_FUNC_CIPHER_PIPELINE_FINAL_ = 18;
  OSSL_FUNC_CIPHER_ENCRYPT_SKEY_INIT_ = 19;
  OSSL_FUNC_CIPHER_DECRYPT_SKEY_INIT_ = 20;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_newctx_fn = ^TOSSL_FUNC_cipher_newctx_fn;
  PPOSSL_FUNC_cipher_newctx_fn = ^POSSL_FUNC_cipher_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_cipher_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_encrypt_init_fn = ^TOSSL_FUNC_cipher_encrypt_init_fn;
  PPOSSL_FUNC_cipher_encrypt_init_fn = ^POSSL_FUNC_cipher_encrypt_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_encrypt_init_fn = function(cctx: pointer; key: Pbyte; keylen: TOpenSSL_C_SIZET; iv: Pbyte; ivlen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_encrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_encrypt_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_decrypt_init_fn = ^TOSSL_FUNC_cipher_decrypt_init_fn;
  PPOSSL_FUNC_cipher_decrypt_init_fn = ^POSSL_FUNC_cipher_decrypt_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_decrypt_init_fn = function(cctx: pointer; key: Pbyte; keylen: TOpenSSL_C_SIZET; iv: Pbyte; ivlen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_decrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_decrypt_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_update_fn = ^TOSSL_FUNC_cipher_update_fn;
  PPOSSL_FUNC_cipher_update_fn = ^POSSL_FUNC_cipher_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_update_fn = function(cctx: pointer; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET; in_: Pbyte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_update(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_final_fn = ^TOSSL_FUNC_cipher_final_fn;
  PPOSSL_FUNC_cipher_final_fn = ^POSSL_FUNC_cipher_final_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_final_fn = function(cctx: pointer; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_final(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_cipher_fn = ^TOSSL_FUNC_cipher_cipher_fn;
  PPOSSL_FUNC_cipher_cipher_fn = ^POSSL_FUNC_cipher_cipher_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_cipher_fn = function(cctx: pointer; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET; in_: Pbyte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_cipher(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_cipher_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_pipeline_encrypt_init_fn = ^TOSSL_FUNC_cipher_pipeline_encrypt_init_fn;
  PPOSSL_FUNC_cipher_pipeline_encrypt_init_fn = ^POSSL_FUNC_cipher_pipeline_encrypt_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_pipeline_encrypt_init_fn = function(cctx: pointer; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_pipeline_encrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_encrypt_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_pipeline_decrypt_init_fn = ^TOSSL_FUNC_cipher_pipeline_decrypt_init_fn;
  PPOSSL_FUNC_cipher_pipeline_decrypt_init_fn = ^POSSL_FUNC_cipher_pipeline_decrypt_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_pipeline_decrypt_init_fn = function(cctx: pointer; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_pipeline_decrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_decrypt_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_pipeline_update_fn = ^TOSSL_FUNC_cipher_pipeline_update_fn;
  PPOSSL_FUNC_cipher_pipeline_update_fn = ^POSSL_FUNC_cipher_pipeline_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_pipeline_update_fn = function(cctx: pointer; numpipes: TOpenSSL_C_SIZET; out_: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET; in_: PPbyte; inl: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_pipeline_update(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_pipeline_final_fn = ^TOSSL_FUNC_cipher_pipeline_final_fn;
  PPOSSL_FUNC_cipher_pipeline_final_fn = ^POSSL_FUNC_cipher_pipeline_final_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_pipeline_final_fn = function(cctx: pointer; numpipes: TOpenSSL_C_SIZET; out_: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_pipeline_final(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_freectx_fn = ^TOSSL_FUNC_cipher_freectx_fn;
  PPOSSL_FUNC_cipher_freectx_fn = ^POSSL_FUNC_cipher_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_freectx_fn = procedure(cctx: pointer); cdecl;


  function OSSL_FUNC_cipher_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_dupctx_fn = ^TOSSL_FUNC_cipher_dupctx_fn;
  PPOSSL_FUNC_cipher_dupctx_fn = ^POSSL_FUNC_cipher_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_dupctx_fn = function(cctx: pointer): pointer; cdecl;


  function OSSL_FUNC_cipher_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_get_params_fn = ^TOSSL_FUNC_cipher_get_params_fn;
  PPOSSL_FUNC_cipher_get_params_fn = ^POSSL_FUNC_cipher_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_get_params_fn = function(params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_get_ctx_params_fn = ^TOSSL_FUNC_cipher_get_ctx_params_fn;
  PPOSSL_FUNC_cipher_get_ctx_params_fn = ^POSSL_FUNC_cipher_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_get_ctx_params_fn = function(cctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_set_ctx_params_fn = ^TOSSL_FUNC_cipher_set_ctx_params_fn;
  PPOSSL_FUNC_cipher_set_ctx_params_fn = ^POSSL_FUNC_cipher_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_set_ctx_params_fn = function(cctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_gettable_params_fn = ^TOSSL_FUNC_cipher_gettable_params_fn;
  PPOSSL_FUNC_cipher_gettable_params_fn = ^POSSL_FUNC_cipher_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_cipher_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_settable_ctx_params_fn = ^TOSSL_FUNC_cipher_settable_ctx_params_fn;
  PPOSSL_FUNC_cipher_settable_ctx_params_fn = ^POSSL_FUNC_cipher_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_settable_ctx_params_fn = function(cctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_cipher_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_gettable_ctx_params_fn = ^TOSSL_FUNC_cipher_gettable_ctx_params_fn;
  PPOSSL_FUNC_cipher_gettable_ctx_params_fn = ^POSSL_FUNC_cipher_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_gettable_ctx_params_fn = function(cctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_cipher_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_encrypt_skey_init_fn = ^TOSSL_FUNC_cipher_encrypt_skey_init_fn;
  PPOSSL_FUNC_cipher_encrypt_skey_init_fn = ^POSSL_FUNC_cipher_encrypt_skey_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_encrypt_skey_init_fn = function(cctx: pointer; skeydata: pointer; iv: Pbyte; ivlen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_encrypt_skey_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_encrypt_skey_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_cipher_decrypt_skey_init_fn = ^TOSSL_FUNC_cipher_decrypt_skey_init_fn;
  PPOSSL_FUNC_cipher_decrypt_skey_init_fn = ^POSSL_FUNC_cipher_decrypt_skey_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_cipher_decrypt_skey_init_fn = function(cctx: pointer; skeydata: pointer; iv: Pbyte; ivlen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_cipher_decrypt_skey_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_decrypt_skey_init_fn{Has C Attribute: unused}; inline;

const
  { MACs }
  OSSL_FUNC_MAC_NEWCTX_ = 1;
  OSSL_FUNC_MAC_DUPCTX_ = 2;
  OSSL_FUNC_MAC_FREECTX_ = 3;
  OSSL_FUNC_MAC_INIT_ = 4;
  OSSL_FUNC_MAC_UPDATE_ = 5;
  OSSL_FUNC_MAC_FINAL_ = 6;
  OSSL_FUNC_MAC_GET_PARAMS_ = 7;
  OSSL_FUNC_MAC_GET_CTX_PARAMS_ = 8;
  OSSL_FUNC_MAC_SET_CTX_PARAMS_ = 9;
  OSSL_FUNC_MAC_GETTABLE_PARAMS_ = 10;
  OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS_ = 11;
  OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS_ = 12;
  OSSL_FUNC_MAC_INIT_SKEY_ = 13;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_newctx_fn = ^TOSSL_FUNC_mac_newctx_fn;
  PPOSSL_FUNC_mac_newctx_fn = ^POSSL_FUNC_mac_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_mac_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_mac_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_dupctx_fn = ^TOSSL_FUNC_mac_dupctx_fn;
  PPOSSL_FUNC_mac_dupctx_fn = ^POSSL_FUNC_mac_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_dupctx_fn = function(src: pointer): pointer; cdecl;


  function OSSL_FUNC_mac_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_mac_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_freectx_fn = ^TOSSL_FUNC_mac_freectx_fn;
  PPOSSL_FUNC_mac_freectx_fn = ^POSSL_FUNC_mac_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_freectx_fn = procedure(mctx: pointer); cdecl;


  function OSSL_FUNC_mac_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_mac_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_init_fn = ^TOSSL_FUNC_mac_init_fn;
  PPOSSL_FUNC_mac_init_fn = ^POSSL_FUNC_mac_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_init_fn = function(mctx: pointer; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_mac_init(opf: POSSL_DISPATCH): POSSL_FUNC_mac_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_update_fn = ^TOSSL_FUNC_mac_update_fn;
  PPOSSL_FUNC_mac_update_fn = ^POSSL_FUNC_mac_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_update_fn = function(mctx: pointer; in_: Pbyte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_mac_update(opf: POSSL_DISPATCH): POSSL_FUNC_mac_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_final_fn = ^TOSSL_FUNC_mac_final_fn;
  PPOSSL_FUNC_mac_final_fn = ^POSSL_FUNC_mac_final_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_final_fn = function(mctx: pointer; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_mac_final(opf: POSSL_DISPATCH): POSSL_FUNC_mac_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_gettable_params_fn = ^TOSSL_FUNC_mac_gettable_params_fn;
  PPOSSL_FUNC_mac_gettable_params_fn = ^POSSL_FUNC_mac_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_mac_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_gettable_ctx_params_fn = ^TOSSL_FUNC_mac_gettable_ctx_params_fn;
  PPOSSL_FUNC_mac_gettable_ctx_params_fn = ^POSSL_FUNC_mac_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_gettable_ctx_params_fn = function(mctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_mac_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_settable_ctx_params_fn = ^TOSSL_FUNC_mac_settable_ctx_params_fn;
  PPOSSL_FUNC_mac_settable_ctx_params_fn = ^POSSL_FUNC_mac_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_settable_ctx_params_fn = function(mctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_mac_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_get_params_fn = ^TOSSL_FUNC_mac_get_params_fn;
  PPOSSL_FUNC_mac_get_params_fn = ^POSSL_FUNC_mac_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_get_params_fn = function(params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_mac_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_get_ctx_params_fn = ^TOSSL_FUNC_mac_get_ctx_params_fn;
  PPOSSL_FUNC_mac_get_ctx_params_fn = ^POSSL_FUNC_mac_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_get_ctx_params_fn = function(mctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_mac_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_set_ctx_params_fn = ^TOSSL_FUNC_mac_set_ctx_params_fn;
  PPOSSL_FUNC_mac_set_ctx_params_fn = ^POSSL_FUNC_mac_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_set_ctx_params_fn = function(mctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_mac_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_mac_init_skey_fn = ^TOSSL_FUNC_mac_init_skey_fn;
  PPOSSL_FUNC_mac_init_skey_fn = ^POSSL_FUNC_mac_init_skey_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_mac_init_skey_fn = function(mctx: pointer; key: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_mac_init_skey(opf: POSSL_DISPATCH): POSSL_FUNC_mac_init_skey_fn{Has C Attribute: unused}; inline;

const
  {-
  * Symmetric key management
  *
  * The Key Management takes care of provider side of symmetric key objects, and
  * includes essentially everything that manipulates the keys  themselves and
  * their parameters.
  *
  * The key objects are commonly referred to as |keydata|, and it MUST be able
  * to contain parameters if the key has any, and the secret key.
  *
  * Key objects are created with OSSL_FUNC_skeymgmt_import() (there is no
  * dedicated memory allocation function), exported with
  * OSSL_FUNC_skeymgmt_export() and destroyed with OSSL_FUNC_keymgmt_free().
  *
  }
  { Key data subset selection - individual bits }
  OSSL_SKEYMGMT_SELECT_PARAMETERS = $01;
  OSSL_SKEYMGMT_SELECT_SECRET_KEY = $02;
  { Key data subset selection - combinations }
  OSSL_SKEYMGMT_SELECT_ALL = OSSL_SKEYMGMT_SELECT_PARAMETERS or OSSL_SKEYMGMT_SELECT_SECRET_KEY;
  OSSL_FUNC_SKEYMGMT_FREE_ = 1;
  OSSL_FUNC_SKEYMGMT_IMPORT_ = 2;
  OSSL_FUNC_SKEYMGMT_EXPORT_ = 3;
  OSSL_FUNC_SKEYMGMT_GENERATE_ = 4;
  OSSL_FUNC_SKEYMGMT_GET_KEY_ID_ = 5;
  OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS_ = 6;
  OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS_ = 7;

type
  {Auto-generated forward references}
  POSSL_FUNC_skeymgmt_free_fn = ^TOSSL_FUNC_skeymgmt_free_fn;
  PPOSSL_FUNC_skeymgmt_free_fn = ^POSSL_FUNC_skeymgmt_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_skeymgmt_free_fn = procedure(keydata: pointer); cdecl;


  function OSSL_FUNC_skeymgmt_free(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_free_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_skeymgmt_imp_settable_params_fn = ^TOSSL_FUNC_skeymgmt_imp_settable_params_fn;
  PPOSSL_FUNC_skeymgmt_imp_settable_params_fn = ^POSSL_FUNC_skeymgmt_imp_settable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_skeymgmt_imp_settable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_skeymgmt_imp_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_imp_settable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_skeymgmt_import_fn = ^TOSSL_FUNC_skeymgmt_import_fn;
  PPOSSL_FUNC_skeymgmt_import_fn = ^POSSL_FUNC_skeymgmt_import_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_skeymgmt_import_fn = function(provctx: pointer; selection: TOpenSSL_C_INT; params: POSSL_PARAM): pointer; cdecl;


  function OSSL_FUNC_skeymgmt_import(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_import_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_skeymgmt_export_fn = ^TOSSL_FUNC_skeymgmt_export_fn;
  PPOSSL_FUNC_skeymgmt_export_fn = ^POSSL_FUNC_skeymgmt_export_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_skeymgmt_export_fn = function(keydata: pointer; selection: TOpenSSL_C_INT; param_cb: POSSL_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_skeymgmt_export(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_export_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_skeymgmt_gen_settable_params_fn = ^TOSSL_FUNC_skeymgmt_gen_settable_params_fn;
  PPOSSL_FUNC_skeymgmt_gen_settable_params_fn = ^POSSL_FUNC_skeymgmt_gen_settable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_skeymgmt_gen_settable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_skeymgmt_gen_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_gen_settable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_skeymgmt_generate_fn = ^TOSSL_FUNC_skeymgmt_generate_fn;
  PPOSSL_FUNC_skeymgmt_generate_fn = ^POSSL_FUNC_skeymgmt_generate_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_skeymgmt_generate_fn = function(provctx: pointer; params: POSSL_PARAM): pointer; cdecl;


  function OSSL_FUNC_skeymgmt_generate(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_generate_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_skeymgmt_get_key_id_fn = ^TOSSL_FUNC_skeymgmt_get_key_id_fn;
  PPOSSL_FUNC_skeymgmt_get_key_id_fn = ^POSSL_FUNC_skeymgmt_get_key_id_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_skeymgmt_get_key_id_fn = function(keydata: pointer): PAnsiChar; cdecl;


  function OSSL_FUNC_skeymgmt_get_key_id(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_get_key_id_fn{Has C Attribute: unused}; inline;

const
  { KDFs and PRFs }
  OSSL_FUNC_KDF_NEWCTX_ = 1;
  OSSL_FUNC_KDF_DUPCTX_ = 2;
  OSSL_FUNC_KDF_FREECTX_ = 3;
  OSSL_FUNC_KDF_RESET_ = 4;
  OSSL_FUNC_KDF_DERIVE_ = 5;
  OSSL_FUNC_KDF_GETTABLE_PARAMS_ = 6;
  OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS_ = 7;
  OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS_ = 8;
  OSSL_FUNC_KDF_GET_PARAMS_ = 9;
  OSSL_FUNC_KDF_GET_CTX_PARAMS_ = 10;
  OSSL_FUNC_KDF_SET_CTX_PARAMS_ = 11;
  OSSL_FUNC_KDF_SET_SKEY_ = 12;
  OSSL_FUNC_KDF_DERIVE_SKEY_ = 13;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_newctx_fn = ^TOSSL_FUNC_kdf_newctx_fn;
  PPOSSL_FUNC_kdf_newctx_fn = ^POSSL_FUNC_kdf_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_kdf_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_dupctx_fn = ^TOSSL_FUNC_kdf_dupctx_fn;
  PPOSSL_FUNC_kdf_dupctx_fn = ^POSSL_FUNC_kdf_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_dupctx_fn = function(src: pointer): pointer; cdecl;


  function OSSL_FUNC_kdf_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_freectx_fn = ^TOSSL_FUNC_kdf_freectx_fn;
  PPOSSL_FUNC_kdf_freectx_fn = ^POSSL_FUNC_kdf_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_freectx_fn = procedure(kctx: pointer); cdecl;


  function OSSL_FUNC_kdf_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_reset_fn = ^TOSSL_FUNC_kdf_reset_fn;
  PPOSSL_FUNC_kdf_reset_fn = ^POSSL_FUNC_kdf_reset_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_reset_fn = procedure(kctx: pointer); cdecl;


  function OSSL_FUNC_kdf_reset(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_reset_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_derive_fn = ^TOSSL_FUNC_kdf_derive_fn;
  PPOSSL_FUNC_kdf_derive_fn = ^POSSL_FUNC_kdf_derive_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_derive_fn = function(kctx: pointer; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kdf_derive(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_derive_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_gettable_params_fn = ^TOSSL_FUNC_kdf_gettable_params_fn;
  PPOSSL_FUNC_kdf_gettable_params_fn = ^POSSL_FUNC_kdf_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_kdf_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_gettable_ctx_params_fn = ^TOSSL_FUNC_kdf_gettable_ctx_params_fn;
  PPOSSL_FUNC_kdf_gettable_ctx_params_fn = ^POSSL_FUNC_kdf_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_gettable_ctx_params_fn = function(kctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_kdf_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_settable_ctx_params_fn = ^TOSSL_FUNC_kdf_settable_ctx_params_fn;
  PPOSSL_FUNC_kdf_settable_ctx_params_fn = ^POSSL_FUNC_kdf_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_settable_ctx_params_fn = function(kctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_kdf_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_get_params_fn = ^TOSSL_FUNC_kdf_get_params_fn;
  PPOSSL_FUNC_kdf_get_params_fn = ^POSSL_FUNC_kdf_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_get_params_fn = function(params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kdf_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_get_ctx_params_fn = ^TOSSL_FUNC_kdf_get_ctx_params_fn;
  PPOSSL_FUNC_kdf_get_ctx_params_fn = ^POSSL_FUNC_kdf_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_get_ctx_params_fn = function(kctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kdf_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_set_ctx_params_fn = ^TOSSL_FUNC_kdf_set_ctx_params_fn;
  PPOSSL_FUNC_kdf_set_ctx_params_fn = ^POSSL_FUNC_kdf_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_set_ctx_params_fn = function(kctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kdf_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_set_skey_fn = ^TOSSL_FUNC_kdf_set_skey_fn;
  PPOSSL_FUNC_kdf_set_skey_fn = ^POSSL_FUNC_kdf_set_skey_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_set_skey_fn = function(kctx: pointer; skeydata: pointer; paramname: PAnsiChar): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kdf_set_skey(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_set_skey_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kdf_derive_skey_fn = ^TOSSL_FUNC_kdf_derive_skey_fn;
  PPOSSL_FUNC_kdf_derive_skey_fn = ^POSSL_FUNC_kdf_derive_skey_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kdf_derive_skey_fn = function(ctx: pointer; key_type: PAnsiChar; provctx: pointer; import: POSSL_FUNC_skeymgmt_import_fn; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): pointer; cdecl;


  function OSSL_FUNC_kdf_derive_skey(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_derive_skey_fn{Has C Attribute: unused}; inline;

const
  { RAND }
  OSSL_FUNC_RAND_NEWCTX_ = 1;
  OSSL_FUNC_RAND_FREECTX_ = 2;
  OSSL_FUNC_RAND_INSTANTIATE_ = 3;
  OSSL_FUNC_RAND_UNINSTANTIATE_ = 4;
  OSSL_FUNC_RAND_GENERATE_ = 5;
  OSSL_FUNC_RAND_RESEED_ = 6;
  OSSL_FUNC_RAND_NONCE_ = 7;
  OSSL_FUNC_RAND_ENABLE_LOCKING_ = 8;
  OSSL_FUNC_RAND_LOCK_ = 9;
  OSSL_FUNC_RAND_UNLOCK_ = 10;
  OSSL_FUNC_RAND_GETTABLE_PARAMS_ = 11;
  OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS_ = 12;
  OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS_ = 13;
  OSSL_FUNC_RAND_GET_PARAMS_ = 14;
  OSSL_FUNC_RAND_GET_CTX_PARAMS_ = 15;
  OSSL_FUNC_RAND_SET_CTX_PARAMS_ = 16;
  OSSL_FUNC_RAND_VERIFY_ZEROIZATION_ = 17;
  OSSL_FUNC_RAND_GET_SEED_ = 18;
  OSSL_FUNC_RAND_CLEAR_SEED_ = 19;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_newctx_fn = ^TOSSL_FUNC_rand_newctx_fn;
  PPOSSL_FUNC_rand_newctx_fn = ^POSSL_FUNC_rand_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_newctx_fn = function(provctx: pointer; parent: pointer; parent_calls: POSSL_DISPATCH): pointer; cdecl;


  function OSSL_FUNC_rand_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_rand_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_freectx_fn = ^TOSSL_FUNC_rand_freectx_fn;
  PPOSSL_FUNC_rand_freectx_fn = ^POSSL_FUNC_rand_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_freectx_fn = procedure(vctx: pointer); cdecl;


  function OSSL_FUNC_rand_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_rand_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_instantiate_fn = ^TOSSL_FUNC_rand_instantiate_fn;
  PPOSSL_FUNC_rand_instantiate_fn = ^POSSL_FUNC_rand_instantiate_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_instantiate_fn = function(vdrbg: pointer; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; pstr: Pbyte; pstr_len: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_instantiate(opf: POSSL_DISPATCH): POSSL_FUNC_rand_instantiate_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_uninstantiate_fn = ^TOSSL_FUNC_rand_uninstantiate_fn;
  PPOSSL_FUNC_rand_uninstantiate_fn = ^POSSL_FUNC_rand_uninstantiate_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_uninstantiate_fn = function(vdrbg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_uninstantiate(opf: POSSL_DISPATCH): POSSL_FUNC_rand_uninstantiate_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_generate_fn = ^TOSSL_FUNC_rand_generate_fn;
  PPOSSL_FUNC_rand_generate_fn = ^POSSL_FUNC_rand_generate_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_generate_fn = function(vctx: pointer; out_: Pbyte; outlen: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_generate(opf: POSSL_DISPATCH): POSSL_FUNC_rand_generate_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_reseed_fn = ^TOSSL_FUNC_rand_reseed_fn;
  PPOSSL_FUNC_rand_reseed_fn = ^POSSL_FUNC_rand_reseed_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_reseed_fn = function(vctx: pointer; prediction_resistance: TOpenSSL_C_INT; ent: Pbyte; ent_len: TOpenSSL_C_SIZET; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_reseed(opf: POSSL_DISPATCH): POSSL_FUNC_rand_reseed_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_nonce_fn = ^TOSSL_FUNC_rand_nonce_fn;
  PPOSSL_FUNC_rand_nonce_fn = ^POSSL_FUNC_rand_nonce_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_nonce_fn = function(vctx: pointer; out_: Pbyte; strength: TOpenSSL_C_UINT; min_noncelen: TOpenSSL_C_SIZET; max_noncelen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;


  function OSSL_FUNC_rand_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_rand_nonce_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_enable_locking_fn = ^TOSSL_FUNC_rand_enable_locking_fn;
  PPOSSL_FUNC_rand_enable_locking_fn = ^POSSL_FUNC_rand_enable_locking_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_enable_locking_fn = function(vctx: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_enable_locking(opf: POSSL_DISPATCH): POSSL_FUNC_rand_enable_locking_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_lock_fn = ^TOSSL_FUNC_rand_lock_fn;
  PPOSSL_FUNC_rand_lock_fn = ^POSSL_FUNC_rand_lock_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_lock_fn = function(vctx: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_lock(opf: POSSL_DISPATCH): POSSL_FUNC_rand_lock_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_unlock_fn = ^TOSSL_FUNC_rand_unlock_fn;
  PPOSSL_FUNC_rand_unlock_fn = ^POSSL_FUNC_rand_unlock_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_unlock_fn = procedure(vctx: pointer); cdecl;


  function OSSL_FUNC_rand_unlock(opf: POSSL_DISPATCH): POSSL_FUNC_rand_unlock_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_gettable_params_fn = ^TOSSL_FUNC_rand_gettable_params_fn;
  PPOSSL_FUNC_rand_gettable_params_fn = ^POSSL_FUNC_rand_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_rand_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_gettable_ctx_params_fn = ^TOSSL_FUNC_rand_gettable_ctx_params_fn;
  PPOSSL_FUNC_rand_gettable_ctx_params_fn = ^POSSL_FUNC_rand_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_gettable_ctx_params_fn = function(vctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_rand_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_settable_ctx_params_fn = ^TOSSL_FUNC_rand_settable_ctx_params_fn;
  PPOSSL_FUNC_rand_settable_ctx_params_fn = ^POSSL_FUNC_rand_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_settable_ctx_params_fn = function(vctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_rand_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_get_params_fn = ^TOSSL_FUNC_rand_get_params_fn;
  PPOSSL_FUNC_rand_get_params_fn = ^POSSL_FUNC_rand_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_get_params_fn = function(params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_get_ctx_params_fn = ^TOSSL_FUNC_rand_get_ctx_params_fn;
  PPOSSL_FUNC_rand_get_ctx_params_fn = ^POSSL_FUNC_rand_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_get_ctx_params_fn = function(vctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_set_ctx_params_fn = ^TOSSL_FUNC_rand_set_ctx_params_fn;
  PPOSSL_FUNC_rand_set_ctx_params_fn = ^POSSL_FUNC_rand_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_set_ctx_params_fn = function(vctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_set_callbacks_fn = ^TOSSL_FUNC_rand_set_callbacks_fn;
  PPOSSL_FUNC_rand_set_callbacks_fn = ^POSSL_FUNC_rand_set_callbacks_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_set_callbacks_fn = procedure(vctx: pointer; get_entropy: POSSL_INOUT_CALLBACK; cleanup_entropy: POSSL_CALLBACK; get_nonce: POSSL_INOUT_CALLBACK; cleanup_nonce: POSSL_CALLBACK; arg: pointer); cdecl;


  function OSSL_FUNC_rand_set_callbacks(opf: POSSL_DISPATCH): POSSL_FUNC_rand_set_callbacks_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_verify_zeroization_fn = ^TOSSL_FUNC_rand_verify_zeroization_fn;
  PPOSSL_FUNC_rand_verify_zeroization_fn = ^POSSL_FUNC_rand_verify_zeroization_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_verify_zeroization_fn = function(vctx: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_rand_verify_zeroization(opf: POSSL_DISPATCH): POSSL_FUNC_rand_verify_zeroization_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_get_seed_fn = ^TOSSL_FUNC_rand_get_seed_fn;
  PPOSSL_FUNC_rand_get_seed_fn = ^POSSL_FUNC_rand_get_seed_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_get_seed_fn = function(vctx: pointer; buffer: PPbyte; entropy: TOpenSSL_C_INT; min_len: TOpenSSL_C_SIZET; max_len: TOpenSSL_C_SIZET; prediction_resistance: TOpenSSL_C_INT; adin: Pbyte; adin_len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;


  function OSSL_FUNC_rand_get_seed(opf: POSSL_DISPATCH): POSSL_FUNC_rand_get_seed_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_rand_clear_seed_fn = ^TOSSL_FUNC_rand_clear_seed_fn;
  PPOSSL_FUNC_rand_clear_seed_fn = ^POSSL_FUNC_rand_clear_seed_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_rand_clear_seed_fn = procedure(vctx: pointer; buffer: Pbyte; b_len: TOpenSSL_C_SIZET); cdecl;


  function OSSL_FUNC_rand_clear_seed(opf: POSSL_DISPATCH): POSSL_FUNC_rand_clear_seed_fn{Has C Attribute: unused}; inline;

const
  {-
  * Key management
  *
  * The Key Management takes care of provider side key objects, and includes
  * all current functionality to create them, destroy them, set parameters
  * and key material, etc, essentially everything that manipulates the keys
  * themselves and their parameters.
  *
  * The key objects are commonly referred to as |keydata|, and it MUST be able
  * to contain parameters if the key has any, the public key and the private
  * key.  All parts are optional, but their presence determines what can be
  * done with the key object in terms of encryption, signature, and so on.
  * The assumption from libcrypto is that the key object contains any of the
  * following data combinations:
  *
  * - parameters only
  * - public key only
  * - public key + private key
  * - parameters + public key
  * - parameters + public key + private key
  *
  * What "parameters", "public key" and "private key" means in detail is left
  * to the implementation.  In the case of DH and DSA, they would typically
  * include domain parameters, while for certain variants of RSA, they would
  * typically include PSS or OAEP parameters.
  *
  * Key objects are created with OSSL_FUNC_keymgmt_new() and destroyed with
  * OSSL_FUNC_keymgmt_free().  Key objects can have data filled in with
  * OSSL_FUNC_keymgmt_import().
  *
  * Three functions are made available to check what selection of data is
  * present in a key object: OSSL_FUNC_keymgmt_has_parameters(),
  * OSSL_FUNC_keymgmt_has_public_key(), and OSSL_FUNC_keymgmt_has_private_key(),
  }
  { Key data subset selection - individual bits }
  OSSL_KEYMGMT_SELECT_PRIVATE_KEY = $01;
  OSSL_KEYMGMT_SELECT_PUBLIC_KEY = $02;
  OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS = $04;
  OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS = $80;
  { Key data subset selection - combinations }
  OSSL_KEYMGMT_SELECT_ALL_PARAMETERS = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS or OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
  OSSL_KEYMGMT_SELECT_KEYPAIR = OSSL_KEYMGMT_SELECT_PRIVATE_KEY or OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
  OSSL_KEYMGMT_SELECT_ALL = OSSL_KEYMGMT_SELECT_KEYPAIR or OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
  OSSL_KEYMGMT_VALIDATE_FULL_CHECK = 0;
  OSSL_KEYMGMT_VALIDATE_QUICK_CHECK = 1;
  { Basic key object creation }
  OSSL_FUNC_KEYMGMT_NEW_ = 1;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_new_fn = ^TOSSL_FUNC_keymgmt_new_fn;
  PPOSSL_FUNC_keymgmt_new_fn = ^POSSL_FUNC_keymgmt_new_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_new_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_keymgmt_new(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_new_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_KEYMGMT_NEW_EX_ = 17;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_new_ex_fn = ^TOSSL_FUNC_keymgmt_new_ex_fn;
  PPOSSL_FUNC_keymgmt_new_ex_fn = ^POSSL_FUNC_keymgmt_new_ex_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_new_ex_fn = function(provctx: pointer; params: POSSL_PARAM): pointer; cdecl;


  function OSSL_FUNC_keymgmt_new_ex(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_new_ex_fn{Has C Attribute: unused}; inline;

const
  { Generation, a more complex constructor }
  OSSL_FUNC_KEYMGMT_GEN_INIT_ = 2;
  OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE_ = 3;
  OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS_ = 4;
  OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS_ = 5;
  OSSL_FUNC_KEYMGMT_GEN_ = 6;
  OSSL_FUNC_KEYMGMT_GEN_CLEANUP_ = 7;
  OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS_ = 15;
  OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS_ = 16;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_init_fn = ^TOSSL_FUNC_keymgmt_gen_init_fn;
  PPOSSL_FUNC_keymgmt_gen_init_fn = ^POSSL_FUNC_keymgmt_gen_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_init_fn = function(provctx: pointer; selection: TOpenSSL_C_INT; params: POSSL_PARAM): pointer; cdecl;


  function OSSL_FUNC_keymgmt_gen_init(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_set_template_fn = ^TOSSL_FUNC_keymgmt_gen_set_template_fn;
  PPOSSL_FUNC_keymgmt_gen_set_template_fn = ^POSSL_FUNC_keymgmt_gen_set_template_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_set_template_fn = function(genctx: pointer; templ: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_gen_set_template(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_set_template_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_set_params_fn = ^TOSSL_FUNC_keymgmt_gen_set_params_fn;
  PPOSSL_FUNC_keymgmt_gen_set_params_fn = ^POSSL_FUNC_keymgmt_gen_set_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_set_params_fn = function(genctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_gen_set_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_set_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_settable_params_fn = ^TOSSL_FUNC_keymgmt_gen_settable_params_fn;
  PPOSSL_FUNC_keymgmt_gen_settable_params_fn = ^POSSL_FUNC_keymgmt_gen_settable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_settable_params_fn = function(genctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_gen_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_settable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_get_params_fn = ^TOSSL_FUNC_keymgmt_gen_get_params_fn;
  PPOSSL_FUNC_keymgmt_gen_get_params_fn = ^POSSL_FUNC_keymgmt_gen_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_get_params_fn = function(genctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_gen_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_gettable_params_fn = ^TOSSL_FUNC_keymgmt_gen_gettable_params_fn;
  PPOSSL_FUNC_keymgmt_gen_gettable_params_fn = ^POSSL_FUNC_keymgmt_gen_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_gettable_params_fn = function(genctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_gen_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_fn = ^TOSSL_FUNC_keymgmt_gen_fn;
  PPOSSL_FUNC_keymgmt_gen_fn = ^POSSL_FUNC_keymgmt_gen_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_fn = function(genctx: pointer; cb: POSSL_CALLBACK; cbarg: pointer): pointer; cdecl;


  function OSSL_FUNC_keymgmt_gen(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gen_cleanup_fn = ^TOSSL_FUNC_keymgmt_gen_cleanup_fn;
  PPOSSL_FUNC_keymgmt_gen_cleanup_fn = ^POSSL_FUNC_keymgmt_gen_cleanup_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gen_cleanup_fn = procedure(genctx: pointer); cdecl;


  function OSSL_FUNC_keymgmt_gen_cleanup(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_cleanup_fn{Has C Attribute: unused}; inline;

const
  { Key loading by object reference }
  OSSL_FUNC_KEYMGMT_LOAD_ = 8;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_load_fn = ^TOSSL_FUNC_keymgmt_load_fn;
  PPOSSL_FUNC_keymgmt_load_fn = ^POSSL_FUNC_keymgmt_load_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_load_fn = function(reference: pointer; reference_sz: TOpenSSL_C_SIZET): pointer; cdecl;


  function OSSL_FUNC_keymgmt_load(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_load_fn{Has C Attribute: unused}; inline;

const
  { Basic key object destruction }
  OSSL_FUNC_KEYMGMT_FREE_ = 10;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_free_fn = ^TOSSL_FUNC_keymgmt_free_fn;
  PPOSSL_FUNC_keymgmt_free_fn = ^POSSL_FUNC_keymgmt_free_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_free_fn = procedure(keydata: pointer); cdecl;


  function OSSL_FUNC_keymgmt_free(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_free_fn{Has C Attribute: unused}; inline;

const
  { Key object information, with discovery }
  OSSL_FUNC_KEYMGMT_GET_PARAMS_ = 11;
  OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS_ = 12;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_get_params_fn = ^TOSSL_FUNC_keymgmt_get_params_fn;
  PPOSSL_FUNC_keymgmt_get_params_fn = ^POSSL_FUNC_keymgmt_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_get_params_fn = function(keydata: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_gettable_params_fn = ^TOSSL_FUNC_keymgmt_gettable_params_fn;
  PPOSSL_FUNC_keymgmt_gettable_params_fn = ^POSSL_FUNC_keymgmt_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gettable_params_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_KEYMGMT_SET_PARAMS_ = 13;
  OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS_ = 14;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_set_params_fn = ^TOSSL_FUNC_keymgmt_set_params_fn;
  PPOSSL_FUNC_keymgmt_set_params_fn = ^POSSL_FUNC_keymgmt_set_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_set_params_fn = function(keydata: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_set_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_set_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_settable_params_fn = ^TOSSL_FUNC_keymgmt_settable_params_fn;
  PPOSSL_FUNC_keymgmt_settable_params_fn = ^POSSL_FUNC_keymgmt_settable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_settable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_settable_params_fn{Has C Attribute: unused}; inline;

const
  { Key checks - discovery of supported operations }
  OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME_ = 20;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_query_operation_name_fn = ^TOSSL_FUNC_keymgmt_query_operation_name_fn;
  PPOSSL_FUNC_keymgmt_query_operation_name_fn = ^POSSL_FUNC_keymgmt_query_operation_name_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_query_operation_name_fn = function(operation_id: TOpenSSL_C_INT): PAnsiChar; cdecl;


  function OSSL_FUNC_keymgmt_query_operation_name(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_query_operation_name_fn{Has C Attribute: unused}; inline;

const
  { Key checks - key data content checks }
  OSSL_FUNC_KEYMGMT_HAS_ = 21;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_has_fn = ^TOSSL_FUNC_keymgmt_has_fn;
  PPOSSL_FUNC_keymgmt_has_fn = ^POSSL_FUNC_keymgmt_has_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_has_fn = function(keydata: pointer; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_has(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_has_fn{Has C Attribute: unused}; inline;

const
  { Key checks - validation }
  OSSL_FUNC_KEYMGMT_VALIDATE_ = 22;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_validate_fn = ^TOSSL_FUNC_keymgmt_validate_fn;
  PPOSSL_FUNC_keymgmt_validate_fn = ^POSSL_FUNC_keymgmt_validate_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_validate_fn = function(keydata: pointer; selection: TOpenSSL_C_INT; checktype: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_validate(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_validate_fn{Has C Attribute: unused}; inline;

const
  { Key checks - matching }
  OSSL_FUNC_KEYMGMT_MATCH_ = 23;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_match_fn = ^TOSSL_FUNC_keymgmt_match_fn;
  PPOSSL_FUNC_keymgmt_match_fn = ^POSSL_FUNC_keymgmt_match_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_match_fn = function(keydata1: pointer; keydata2: pointer; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_match(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_match_fn{Has C Attribute: unused}; inline;

const
  { Import and export functions, with discovery }
  OSSL_FUNC_KEYMGMT_IMPORT_ = 40;
  OSSL_FUNC_KEYMGMT_IMPORT_TYPES_ = 41;
  OSSL_FUNC_KEYMGMT_EXPORT_ = 42;
  OSSL_FUNC_KEYMGMT_EXPORT_TYPES_ = 43;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_import_fn = ^TOSSL_FUNC_keymgmt_import_fn;
  PPOSSL_FUNC_keymgmt_import_fn = ^POSSL_FUNC_keymgmt_import_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_import_fn = function(keydata: pointer; selection: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_import(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_import_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_import_types_fn = ^TOSSL_FUNC_keymgmt_import_types_fn;
  PPOSSL_FUNC_keymgmt_import_types_fn = ^POSSL_FUNC_keymgmt_import_types_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_import_types_fn = function(selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_import_types(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_import_types_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_export_fn = ^TOSSL_FUNC_keymgmt_export_fn;
  PPOSSL_FUNC_keymgmt_export_fn = ^POSSL_FUNC_keymgmt_export_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_export_fn = function(keydata: pointer; selection: TOpenSSL_C_INT; param_cb: POSSL_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keymgmt_export(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_export_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_export_types_fn = ^TOSSL_FUNC_keymgmt_export_types_fn;
  PPOSSL_FUNC_keymgmt_export_types_fn = ^POSSL_FUNC_keymgmt_export_types_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_export_types_fn = function(selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_export_types(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_export_types_fn{Has C Attribute: unused}; inline;

const
  { Dup function, constructor }
  OSSL_FUNC_KEYMGMT_DUP_ = 44;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_dup_fn = ^TOSSL_FUNC_keymgmt_dup_fn;
  PPOSSL_FUNC_keymgmt_dup_fn = ^POSSL_FUNC_keymgmt_dup_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_dup_fn = function(keydata_from: pointer; selection: TOpenSSL_C_INT): pointer; cdecl;


  function OSSL_FUNC_keymgmt_dup(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_dup_fn{Has C Attribute: unused}; inline;

const
  { Extended import and export functions }
  OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX_ = 45;
  OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX_ = 46;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_import_types_ex_fn = ^TOSSL_FUNC_keymgmt_import_types_ex_fn;
  PPOSSL_FUNC_keymgmt_import_types_ex_fn = ^POSSL_FUNC_keymgmt_import_types_ex_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_import_types_ex_fn = function(provctx: pointer; selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_import_types_ex(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_import_types_ex_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keymgmt_export_types_ex_fn = ^TOSSL_FUNC_keymgmt_export_types_ex_fn;
  PPOSSL_FUNC_keymgmt_export_types_ex_fn = ^POSSL_FUNC_keymgmt_export_types_ex_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keymgmt_export_types_ex_fn = function(provctx: pointer; selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keymgmt_export_types_ex(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_export_types_ex_fn{Has C Attribute: unused}; inline;

const
  { Key Exchange }
  OSSL_FUNC_KEYEXCH_NEWCTX_ = 1;
  OSSL_FUNC_KEYEXCH_INIT_ = 2;
  OSSL_FUNC_KEYEXCH_DERIVE_ = 3;
  OSSL_FUNC_KEYEXCH_SET_PEER_ = 4;
  OSSL_FUNC_KEYEXCH_FREECTX_ = 5;
  OSSL_FUNC_KEYEXCH_DUPCTX_ = 6;
  OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS_ = 7;
  OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS_ = 8;
  OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS_ = 9;
  OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS_ = 10;
  OSSL_FUNC_KEYEXCH_DERIVE_SKEY_ = 11;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_newctx_fn = ^TOSSL_FUNC_keyexch_newctx_fn;
  PPOSSL_FUNC_keyexch_newctx_fn = ^POSSL_FUNC_keyexch_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_keyexch_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_init_fn = ^TOSSL_FUNC_keyexch_init_fn;
  PPOSSL_FUNC_keyexch_init_fn = ^POSSL_FUNC_keyexch_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keyexch_init(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_derive_fn = ^TOSSL_FUNC_keyexch_derive_fn;
  PPOSSL_FUNC_keyexch_derive_fn = ^POSSL_FUNC_keyexch_derive_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_derive_fn = function(ctx: pointer; secret: Pbyte; secretlen: POpenSSL_C_SIZET; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keyexch_derive(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_derive_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_set_peer_fn = ^TOSSL_FUNC_keyexch_set_peer_fn;
  PPOSSL_FUNC_keyexch_set_peer_fn = ^POSSL_FUNC_keyexch_set_peer_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_set_peer_fn = function(ctx: pointer; provkey: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keyexch_set_peer(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_set_peer_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_freectx_fn = ^TOSSL_FUNC_keyexch_freectx_fn;
  PPOSSL_FUNC_keyexch_freectx_fn = ^POSSL_FUNC_keyexch_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_freectx_fn = procedure(ctx: pointer); cdecl;


  function OSSL_FUNC_keyexch_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_dupctx_fn = ^TOSSL_FUNC_keyexch_dupctx_fn;
  PPOSSL_FUNC_keyexch_dupctx_fn = ^POSSL_FUNC_keyexch_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_dupctx_fn = function(ctx: pointer): pointer; cdecl;


  function OSSL_FUNC_keyexch_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_set_ctx_params_fn = ^TOSSL_FUNC_keyexch_set_ctx_params_fn;
  PPOSSL_FUNC_keyexch_set_ctx_params_fn = ^POSSL_FUNC_keyexch_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_set_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keyexch_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_settable_ctx_params_fn = ^TOSSL_FUNC_keyexch_settable_ctx_params_fn;
  PPOSSL_FUNC_keyexch_settable_ctx_params_fn = ^POSSL_FUNC_keyexch_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_settable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keyexch_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_get_ctx_params_fn = ^TOSSL_FUNC_keyexch_get_ctx_params_fn;
  PPOSSL_FUNC_keyexch_get_ctx_params_fn = ^POSSL_FUNC_keyexch_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_get_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_keyexch_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_gettable_ctx_params_fn = ^TOSSL_FUNC_keyexch_gettable_ctx_params_fn;
  PPOSSL_FUNC_keyexch_gettable_ctx_params_fn = ^POSSL_FUNC_keyexch_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_gettable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_keyexch_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_keyexch_derive_skey_fn = ^TOSSL_FUNC_keyexch_derive_skey_fn;
  PPOSSL_FUNC_keyexch_derive_skey_fn = ^POSSL_FUNC_keyexch_derive_skey_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_keyexch_derive_skey_fn = function(ctx: pointer; key_type: PAnsiChar; provctx: pointer; import: POSSL_FUNC_skeymgmt_import_fn; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): pointer; cdecl;


  function OSSL_FUNC_keyexch_derive_skey(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_derive_skey_fn{Has C Attribute: unused}; inline;

const
  { Signature }
  OSSL_FUNC_SIGNATURE_NEWCTX_ = 1;
  OSSL_FUNC_SIGNATURE_SIGN_INIT_ = 2;
  OSSL_FUNC_SIGNATURE_SIGN_ = 3;
  OSSL_FUNC_SIGNATURE_VERIFY_INIT_ = 4;
  OSSL_FUNC_SIGNATURE_VERIFY_ = 5;
  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT_ = 6;
  OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_ = 7;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT_ = 8;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE_ = 9;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL_ = 10;
  OSSL_FUNC_SIGNATURE_DIGEST_SIGN_ = 11;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT_ = 12;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE_ = 13;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL_ = 14;
  OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_ = 15;
  OSSL_FUNC_SIGNATURE_FREECTX_ = 16;
  OSSL_FUNC_SIGNATURE_DUPCTX_ = 17;
  OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS_ = 18;
  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS_ = 19;
  OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS_ = 20;
  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS_ = 21;
  OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS_ = 22;
  OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS_ = 23;
  OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS_ = 24;
  OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS_ = 25;
  OSSL_FUNC_SIGNATURE_QUERY_KEY_TYPES_ = 26;
  OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT_ = 27;
  OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE_ = 28;
  OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL_ = 29;
  OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT_ = 30;
  OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE_ = 31;
  OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL_ = 32;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_newctx_fn = ^TOSSL_FUNC_signature_newctx_fn;
  PPOSSL_FUNC_signature_newctx_fn = ^POSSL_FUNC_signature_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_newctx_fn = function(provctx: pointer; propq: PAnsiChar): pointer; cdecl;


  function OSSL_FUNC_signature_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_signature_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_sign_init_fn = ^TOSSL_FUNC_signature_sign_init_fn;
  PPOSSL_FUNC_signature_sign_init_fn = ^POSSL_FUNC_signature_sign_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_sign_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_sign_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_sign_fn = ^TOSSL_FUNC_signature_sign_fn;
  PPOSSL_FUNC_signature_sign_fn = ^POSSL_FUNC_signature_sign_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_sign_fn = function(ctx: pointer; sig: Pbyte; siglen: POpenSSL_C_SIZET; sigsize: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_sign(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_sign_message_init_fn = ^TOSSL_FUNC_signature_sign_message_init_fn;
  PPOSSL_FUNC_signature_sign_message_init_fn = ^POSSL_FUNC_signature_sign_message_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_sign_message_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_sign_message_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_message_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_sign_message_update_fn = ^TOSSL_FUNC_signature_sign_message_update_fn;
  PPOSSL_FUNC_signature_sign_message_update_fn = ^POSSL_FUNC_signature_sign_message_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_sign_message_update_fn = function(ctx: pointer; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_sign_message_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_message_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_sign_message_final_fn = ^TOSSL_FUNC_signature_sign_message_final_fn;
  PPOSSL_FUNC_signature_sign_message_final_fn = ^POSSL_FUNC_signature_sign_message_final_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_sign_message_final_fn = function(ctx: pointer; sig: Pbyte; siglen: POpenSSL_C_SIZET; sigsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_sign_message_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_message_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_verify_init_fn = ^TOSSL_FUNC_signature_verify_init_fn;
  PPOSSL_FUNC_signature_verify_init_fn = ^POSSL_FUNC_signature_verify_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_verify_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_verify_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_verify_fn = ^TOSSL_FUNC_signature_verify_fn;
  PPOSSL_FUNC_signature_verify_fn = ^POSSL_FUNC_signature_verify_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_verify_fn = function(ctx: pointer; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_verify(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_verify_message_init_fn = ^TOSSL_FUNC_signature_verify_message_init_fn;
  PPOSSL_FUNC_signature_verify_message_init_fn = ^POSSL_FUNC_signature_verify_message_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_verify_message_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_verify_message_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_message_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_verify_message_update_fn = ^TOSSL_FUNC_signature_verify_message_update_fn;
  PPOSSL_FUNC_signature_verify_message_update_fn = ^POSSL_FUNC_signature_verify_message_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_verify_message_update_fn = function(ctx: pointer; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_verify_message_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_message_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_verify_message_final_fn = ^TOSSL_FUNC_signature_verify_message_final_fn;
  PPOSSL_FUNC_signature_verify_message_final_fn = ^POSSL_FUNC_signature_verify_message_final_fn;
  {end of auto-generated forward references}

  
  {* signature_verify_final requires that the signature to be verified against
  * is specified via an OSSL_PARAM.
  }
  TOSSL_FUNC_signature_verify_message_final_fn = function(ctx: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_verify_message_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_message_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_verify_recover_init_fn = ^TOSSL_FUNC_signature_verify_recover_init_fn;
  PPOSSL_FUNC_signature_verify_recover_init_fn = ^POSSL_FUNC_signature_verify_recover_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_verify_recover_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_verify_recover_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_recover_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_verify_recover_fn = ^TOSSL_FUNC_signature_verify_recover_fn;
  PPOSSL_FUNC_signature_verify_recover_fn = ^POSSL_FUNC_signature_verify_recover_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_verify_recover_fn = function(ctx: pointer; rout: Pbyte; routlen: POpenSSL_C_SIZET; routsize: TOpenSSL_C_SIZET; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_verify_recover(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_recover_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_sign_init_fn = ^TOSSL_FUNC_signature_digest_sign_init_fn;
  PPOSSL_FUNC_signature_digest_sign_init_fn = ^POSSL_FUNC_signature_digest_sign_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_sign_init_fn = function(ctx: pointer; mdname: PAnsiChar; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_sign_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_sign_update_fn = ^TOSSL_FUNC_signature_digest_sign_update_fn;
  PPOSSL_FUNC_signature_digest_sign_update_fn = ^POSSL_FUNC_signature_digest_sign_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_sign_update_fn = function(ctx: pointer; data: Pbyte; datalen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_sign_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_sign_final_fn = ^TOSSL_FUNC_signature_digest_sign_final_fn;
  PPOSSL_FUNC_signature_digest_sign_final_fn = ^POSSL_FUNC_signature_digest_sign_final_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_sign_final_fn = function(ctx: pointer; sig: Pbyte; siglen: POpenSSL_C_SIZET; sigsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_sign_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_sign_fn = ^TOSSL_FUNC_signature_digest_sign_fn;
  PPOSSL_FUNC_signature_digest_sign_fn = ^POSSL_FUNC_signature_digest_sign_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_sign_fn = function(ctx: pointer; sigret: Pbyte; siglen: POpenSSL_C_SIZET; sigsize: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_sign(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_verify_init_fn = ^TOSSL_FUNC_signature_digest_verify_init_fn;
  PPOSSL_FUNC_signature_digest_verify_init_fn = ^POSSL_FUNC_signature_digest_verify_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_verify_init_fn = function(ctx: pointer; mdname: PAnsiChar; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_verify_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_verify_update_fn = ^TOSSL_FUNC_signature_digest_verify_update_fn;
  PPOSSL_FUNC_signature_digest_verify_update_fn = ^POSSL_FUNC_signature_digest_verify_update_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_verify_update_fn = function(ctx: pointer; data: Pbyte; datalen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_verify_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_update_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_verify_final_fn = ^TOSSL_FUNC_signature_digest_verify_final_fn;
  PPOSSL_FUNC_signature_digest_verify_final_fn = ^POSSL_FUNC_signature_digest_verify_final_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_verify_final_fn = function(ctx: pointer; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_verify_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_final_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_digest_verify_fn = ^TOSSL_FUNC_signature_digest_verify_fn;
  PPOSSL_FUNC_signature_digest_verify_fn = ^POSSL_FUNC_signature_digest_verify_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_digest_verify_fn = function(ctx: pointer; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_digest_verify(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_freectx_fn = ^TOSSL_FUNC_signature_freectx_fn;
  PPOSSL_FUNC_signature_freectx_fn = ^POSSL_FUNC_signature_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_freectx_fn = procedure(ctx: pointer); cdecl;


  function OSSL_FUNC_signature_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_signature_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_dupctx_fn = ^TOSSL_FUNC_signature_dupctx_fn;
  PPOSSL_FUNC_signature_dupctx_fn = ^POSSL_FUNC_signature_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_dupctx_fn = function(ctx: pointer): pointer; cdecl;


  function OSSL_FUNC_signature_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_signature_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_get_ctx_params_fn = ^TOSSL_FUNC_signature_get_ctx_params_fn;
  PPOSSL_FUNC_signature_get_ctx_params_fn = ^POSSL_FUNC_signature_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_get_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_gettable_ctx_params_fn = ^TOSSL_FUNC_signature_gettable_ctx_params_fn;
  PPOSSL_FUNC_signature_gettable_ctx_params_fn = ^POSSL_FUNC_signature_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_gettable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_signature_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_set_ctx_params_fn = ^TOSSL_FUNC_signature_set_ctx_params_fn;
  PPOSSL_FUNC_signature_set_ctx_params_fn = ^POSSL_FUNC_signature_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_set_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_settable_ctx_params_fn = ^TOSSL_FUNC_signature_settable_ctx_params_fn;
  PPOSSL_FUNC_signature_settable_ctx_params_fn = ^POSSL_FUNC_signature_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_settable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_signature_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_get_ctx_md_params_fn = ^TOSSL_FUNC_signature_get_ctx_md_params_fn;
  PPOSSL_FUNC_signature_get_ctx_md_params_fn = ^POSSL_FUNC_signature_get_ctx_md_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_get_ctx_md_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_get_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_get_ctx_md_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_gettable_ctx_md_params_fn = ^TOSSL_FUNC_signature_gettable_ctx_md_params_fn;
  PPOSSL_FUNC_signature_gettable_ctx_md_params_fn = ^POSSL_FUNC_signature_gettable_ctx_md_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_gettable_ctx_md_params_fn = function(ctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_signature_gettable_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_gettable_ctx_md_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_set_ctx_md_params_fn = ^TOSSL_FUNC_signature_set_ctx_md_params_fn;
  PPOSSL_FUNC_signature_set_ctx_md_params_fn = ^POSSL_FUNC_signature_set_ctx_md_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_set_ctx_md_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_signature_set_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_set_ctx_md_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_settable_ctx_md_params_fn = ^TOSSL_FUNC_signature_settable_ctx_md_params_fn;
  PPOSSL_FUNC_signature_settable_ctx_md_params_fn = ^POSSL_FUNC_signature_settable_ctx_md_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_settable_ctx_md_params_fn = function(ctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_signature_settable_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_settable_ctx_md_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_signature_query_key_types_fn = ^TOSSL_FUNC_signature_query_key_types_fn;
  PPOSSL_FUNC_signature_query_key_types_fn = ^POSSL_FUNC_signature_query_key_types_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_signature_query_key_types_fn = function: PPAnsiChar; cdecl;


  function OSSL_FUNC_signature_query_key_types(opf: POSSL_DISPATCH): POSSL_FUNC_signature_query_key_types_fn{Has C Attribute: unused}; inline;

const
  { Asymmetric Ciphers }
  OSSL_FUNC_ASYM_CIPHER_NEWCTX_ = 1;
  OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT_ = 2;
  OSSL_FUNC_ASYM_CIPHER_ENCRYPT_ = 3;
  OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT_ = 4;
  OSSL_FUNC_ASYM_CIPHER_DECRYPT_ = 5;
  OSSL_FUNC_ASYM_CIPHER_FREECTX_ = 6;
  OSSL_FUNC_ASYM_CIPHER_DUPCTX_ = 7;
  OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS_ = 8;
  OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS_ = 9;
  OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS_ = 10;
  OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS_ = 11;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_newctx_fn = ^TOSSL_FUNC_asym_cipher_newctx_fn;
  PPOSSL_FUNC_asym_cipher_newctx_fn = ^POSSL_FUNC_asym_cipher_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_asym_cipher_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_encrypt_init_fn = ^TOSSL_FUNC_asym_cipher_encrypt_init_fn;
  PPOSSL_FUNC_asym_cipher_encrypt_init_fn = ^POSSL_FUNC_asym_cipher_encrypt_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_encrypt_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_asym_cipher_encrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_encrypt_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_encrypt_fn = ^TOSSL_FUNC_asym_cipher_encrypt_fn;
  PPOSSL_FUNC_asym_cipher_encrypt_fn = ^POSSL_FUNC_asym_cipher_encrypt_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_encrypt_fn = function(ctx: pointer; out_: Pbyte; outlen: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_asym_cipher_encrypt(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_encrypt_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_decrypt_init_fn = ^TOSSL_FUNC_asym_cipher_decrypt_init_fn;
  PPOSSL_FUNC_asym_cipher_decrypt_init_fn = ^POSSL_FUNC_asym_cipher_decrypt_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_decrypt_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_asym_cipher_decrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_decrypt_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_decrypt_fn = ^TOSSL_FUNC_asym_cipher_decrypt_fn;
  PPOSSL_FUNC_asym_cipher_decrypt_fn = ^POSSL_FUNC_asym_cipher_decrypt_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_decrypt_fn = function(ctx: pointer; out_: Pbyte; outlen: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_asym_cipher_decrypt(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_decrypt_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_freectx_fn = ^TOSSL_FUNC_asym_cipher_freectx_fn;
  PPOSSL_FUNC_asym_cipher_freectx_fn = ^POSSL_FUNC_asym_cipher_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_freectx_fn = procedure(ctx: pointer); cdecl;


  function OSSL_FUNC_asym_cipher_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_dupctx_fn = ^TOSSL_FUNC_asym_cipher_dupctx_fn;
  PPOSSL_FUNC_asym_cipher_dupctx_fn = ^POSSL_FUNC_asym_cipher_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_dupctx_fn = function(ctx: pointer): pointer; cdecl;


  function OSSL_FUNC_asym_cipher_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_get_ctx_params_fn = ^TOSSL_FUNC_asym_cipher_get_ctx_params_fn;
  PPOSSL_FUNC_asym_cipher_get_ctx_params_fn = ^POSSL_FUNC_asym_cipher_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_get_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_asym_cipher_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_gettable_ctx_params_fn = ^TOSSL_FUNC_asym_cipher_gettable_ctx_params_fn;
  PPOSSL_FUNC_asym_cipher_gettable_ctx_params_fn = ^POSSL_FUNC_asym_cipher_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_gettable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_asym_cipher_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_set_ctx_params_fn = ^TOSSL_FUNC_asym_cipher_set_ctx_params_fn;
  PPOSSL_FUNC_asym_cipher_set_ctx_params_fn = ^POSSL_FUNC_asym_cipher_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_set_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_asym_cipher_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_asym_cipher_settable_ctx_params_fn = ^TOSSL_FUNC_asym_cipher_settable_ctx_params_fn;
  PPOSSL_FUNC_asym_cipher_settable_ctx_params_fn = ^POSSL_FUNC_asym_cipher_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_asym_cipher_settable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_asym_cipher_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_settable_ctx_params_fn{Has C Attribute: unused}; inline;

const
  { Asymmetric Key encapsulation }
  OSSL_FUNC_KEM_NEWCTX_ = 1;
  OSSL_FUNC_KEM_ENCAPSULATE_INIT_ = 2;
  OSSL_FUNC_KEM_ENCAPSULATE_ = 3;
  OSSL_FUNC_KEM_DECAPSULATE_INIT_ = 4;
  OSSL_FUNC_KEM_DECAPSULATE_ = 5;
  OSSL_FUNC_KEM_FREECTX_ = 6;
  OSSL_FUNC_KEM_DUPCTX_ = 7;
  OSSL_FUNC_KEM_GET_CTX_PARAMS_ = 8;
  OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS_ = 9;
  OSSL_FUNC_KEM_SET_CTX_PARAMS_ = 10;
  OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS_ = 11;
  OSSL_FUNC_KEM_AUTH_ENCAPSULATE_INIT_ = 12;
  OSSL_FUNC_KEM_AUTH_DECAPSULATE_INIT_ = 13;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_newctx_fn = ^TOSSL_FUNC_kem_newctx_fn;
  PPOSSL_FUNC_kem_newctx_fn = ^POSSL_FUNC_kem_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_kem_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_kem_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_encapsulate_init_fn = ^TOSSL_FUNC_kem_encapsulate_init_fn;
  PPOSSL_FUNC_kem_encapsulate_init_fn = ^POSSL_FUNC_kem_encapsulate_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_encapsulate_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_encapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_encapsulate_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_auth_encapsulate_init_fn = ^TOSSL_FUNC_kem_auth_encapsulate_init_fn;
  PPOSSL_FUNC_kem_auth_encapsulate_init_fn = ^POSSL_FUNC_kem_auth_encapsulate_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_auth_encapsulate_init_fn = function(ctx: pointer; provkey: pointer; authprivkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_auth_encapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_auth_encapsulate_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_encapsulate_fn = ^TOSSL_FUNC_kem_encapsulate_fn;
  PPOSSL_FUNC_kem_encapsulate_fn = ^POSSL_FUNC_kem_encapsulate_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_encapsulate_fn = function(ctx: pointer; out_: Pbyte; outlen: POpenSSL_C_SIZET; secret: Pbyte; secretlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_encapsulate(opf: POSSL_DISPATCH): POSSL_FUNC_kem_encapsulate_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_decapsulate_init_fn = ^TOSSL_FUNC_kem_decapsulate_init_fn;
  PPOSSL_FUNC_kem_decapsulate_init_fn = ^POSSL_FUNC_kem_decapsulate_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_decapsulate_init_fn = function(ctx: pointer; provkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_decapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_decapsulate_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_auth_decapsulate_init_fn = ^TOSSL_FUNC_kem_auth_decapsulate_init_fn;
  PPOSSL_FUNC_kem_auth_decapsulate_init_fn = ^POSSL_FUNC_kem_auth_decapsulate_init_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_auth_decapsulate_init_fn = function(ctx: pointer; provkey: pointer; authpubkey: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_auth_decapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_auth_decapsulate_init_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_decapsulate_fn = ^TOSSL_FUNC_kem_decapsulate_fn;
  PPOSSL_FUNC_kem_decapsulate_fn = ^POSSL_FUNC_kem_decapsulate_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_decapsulate_fn = function(ctx: pointer; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_decapsulate(opf: POSSL_DISPATCH): POSSL_FUNC_kem_decapsulate_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_freectx_fn = ^TOSSL_FUNC_kem_freectx_fn;
  PPOSSL_FUNC_kem_freectx_fn = ^POSSL_FUNC_kem_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_freectx_fn = procedure(ctx: pointer); cdecl;


  function OSSL_FUNC_kem_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_kem_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_dupctx_fn = ^TOSSL_FUNC_kem_dupctx_fn;
  PPOSSL_FUNC_kem_dupctx_fn = ^POSSL_FUNC_kem_dupctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_dupctx_fn = function(ctx: pointer): pointer; cdecl;


  function OSSL_FUNC_kem_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_kem_dupctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_get_ctx_params_fn = ^TOSSL_FUNC_kem_get_ctx_params_fn;
  PPOSSL_FUNC_kem_get_ctx_params_fn = ^POSSL_FUNC_kem_get_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_get_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_get_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_gettable_ctx_params_fn = ^TOSSL_FUNC_kem_gettable_ctx_params_fn;
  PPOSSL_FUNC_kem_gettable_ctx_params_fn = ^POSSL_FUNC_kem_gettable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_gettable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_kem_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_gettable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_set_ctx_params_fn = ^TOSSL_FUNC_kem_set_ctx_params_fn;
  PPOSSL_FUNC_kem_set_ctx_params_fn = ^POSSL_FUNC_kem_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_set_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_kem_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_kem_settable_ctx_params_fn = ^TOSSL_FUNC_kem_settable_ctx_params_fn;
  PPOSSL_FUNC_kem_settable_ctx_params_fn = ^POSSL_FUNC_kem_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_kem_settable_ctx_params_fn = function(ctx: pointer; provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_kem_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_settable_ctx_params_fn{Has C Attribute: unused}; inline;

const
  { Encoders and decoders }
  OSSL_FUNC_ENCODER_NEWCTX_ = 1;
  OSSL_FUNC_ENCODER_FREECTX_ = 2;
  OSSL_FUNC_ENCODER_GET_PARAMS_ = 3;
  OSSL_FUNC_ENCODER_GETTABLE_PARAMS_ = 4;
  OSSL_FUNC_ENCODER_SET_CTX_PARAMS_ = 5;
  OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS_ = 6;
  OSSL_FUNC_ENCODER_DOES_SELECTION_ = 10;
  OSSL_FUNC_ENCODER_ENCODE_ = 11;
  OSSL_FUNC_ENCODER_IMPORT_OBJECT_ = 20;
  OSSL_FUNC_ENCODER_FREE_OBJECT_ = 21;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_newctx_fn = ^TOSSL_FUNC_encoder_newctx_fn;
  PPOSSL_FUNC_encoder_newctx_fn = ^POSSL_FUNC_encoder_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_encoder_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_freectx_fn = ^TOSSL_FUNC_encoder_freectx_fn;
  PPOSSL_FUNC_encoder_freectx_fn = ^POSSL_FUNC_encoder_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_freectx_fn = procedure(ctx: pointer); cdecl;


  function OSSL_FUNC_encoder_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_get_params_fn = ^TOSSL_FUNC_encoder_get_params_fn;
  PPOSSL_FUNC_encoder_get_params_fn = ^POSSL_FUNC_encoder_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_get_params_fn = function(params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_encoder_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_gettable_params_fn = ^TOSSL_FUNC_encoder_gettable_params_fn;
  PPOSSL_FUNC_encoder_gettable_params_fn = ^POSSL_FUNC_encoder_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_encoder_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_set_ctx_params_fn = ^TOSSL_FUNC_encoder_set_ctx_params_fn;
  PPOSSL_FUNC_encoder_set_ctx_params_fn = ^POSSL_FUNC_encoder_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_set_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_encoder_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_settable_ctx_params_fn = ^TOSSL_FUNC_encoder_settable_ctx_params_fn;
  PPOSSL_FUNC_encoder_settable_ctx_params_fn = ^POSSL_FUNC_encoder_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_settable_ctx_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_encoder_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_does_selection_fn = ^TOSSL_FUNC_encoder_does_selection_fn;
  PPOSSL_FUNC_encoder_does_selection_fn = ^POSSL_FUNC_encoder_does_selection_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_does_selection_fn = function(provctx: pointer; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_encoder_does_selection(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_does_selection_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_encode_fn = ^TOSSL_FUNC_encoder_encode_fn;
  PPOSSL_FUNC_encoder_encode_fn = ^POSSL_FUNC_encoder_encode_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_encode_fn = function(ctx: pointer; out_: POSSL_CORE_BIO; obj_raw: pointer; obj_abstract: POSSL_PARAM; selection: TOpenSSL_C_INT; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_encoder_encode(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_encode_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_import_object_fn = ^TOSSL_FUNC_encoder_import_object_fn;
  PPOSSL_FUNC_encoder_import_object_fn = ^POSSL_FUNC_encoder_import_object_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_import_object_fn = function(ctx: pointer; selection: TOpenSSL_C_INT; params: POSSL_PARAM): pointer; cdecl;


  function OSSL_FUNC_encoder_import_object(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_import_object_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_encoder_free_object_fn = ^TOSSL_FUNC_encoder_free_object_fn;
  PPOSSL_FUNC_encoder_free_object_fn = ^POSSL_FUNC_encoder_free_object_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_encoder_free_object_fn = procedure(obj: pointer); cdecl;


  function OSSL_FUNC_encoder_free_object(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_free_object_fn{Has C Attribute: unused}; inline;

const
  OSSL_FUNC_DECODER_NEWCTX_ = 1;
  OSSL_FUNC_DECODER_FREECTX_ = 2;
  OSSL_FUNC_DECODER_GET_PARAMS_ = 3;
  OSSL_FUNC_DECODER_GETTABLE_PARAMS_ = 4;
  OSSL_FUNC_DECODER_SET_CTX_PARAMS_ = 5;
  OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS_ = 6;
  OSSL_FUNC_DECODER_DOES_SELECTION_ = 10;
  OSSL_FUNC_DECODER_DECODE_ = 11;
  OSSL_FUNC_DECODER_EXPORT_OBJECT_ = 20;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_newctx_fn = ^TOSSL_FUNC_decoder_newctx_fn;
  PPOSSL_FUNC_decoder_newctx_fn = ^POSSL_FUNC_decoder_newctx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_newctx_fn = function(provctx: pointer): pointer; cdecl;


  function OSSL_FUNC_decoder_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_newctx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_freectx_fn = ^TOSSL_FUNC_decoder_freectx_fn;
  PPOSSL_FUNC_decoder_freectx_fn = ^POSSL_FUNC_decoder_freectx_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_freectx_fn = procedure(ctx: pointer); cdecl;


  function OSSL_FUNC_decoder_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_freectx_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_get_params_fn = ^TOSSL_FUNC_decoder_get_params_fn;
  PPOSSL_FUNC_decoder_get_params_fn = ^POSSL_FUNC_decoder_get_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_get_params_fn = function(params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_decoder_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_get_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_gettable_params_fn = ^TOSSL_FUNC_decoder_gettable_params_fn;
  PPOSSL_FUNC_decoder_gettable_params_fn = ^POSSL_FUNC_decoder_gettable_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_gettable_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_decoder_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_gettable_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_set_ctx_params_fn = ^TOSSL_FUNC_decoder_set_ctx_params_fn;
  PPOSSL_FUNC_decoder_set_ctx_params_fn = ^POSSL_FUNC_decoder_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_set_ctx_params_fn = function(ctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_decoder_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_settable_ctx_params_fn = ^TOSSL_FUNC_decoder_settable_ctx_params_fn;
  PPOSSL_FUNC_decoder_settable_ctx_params_fn = ^POSSL_FUNC_decoder_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_settable_ctx_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_decoder_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_does_selection_fn = ^TOSSL_FUNC_decoder_does_selection_fn;
  PPOSSL_FUNC_decoder_does_selection_fn = ^POSSL_FUNC_decoder_does_selection_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_does_selection_fn = function(provctx: pointer; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_decoder_does_selection(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_does_selection_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_decode_fn = ^TOSSL_FUNC_decoder_decode_fn;
  PPOSSL_FUNC_decoder_decode_fn = ^POSSL_FUNC_decoder_decode_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_decode_fn = function(ctx: pointer; in_: POSSL_CORE_BIO; selection: TOpenSSL_C_INT; data_cb: POSSL_CALLBACK; data_cbarg: pointer; pw_cb: POSSL_PASSPHRASE_CALLBACK; pw_cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_decoder_decode(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_decode_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_decoder_export_object_fn = ^TOSSL_FUNC_decoder_export_object_fn;
  PPOSSL_FUNC_decoder_export_object_fn = ^POSSL_FUNC_decoder_export_object_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_decoder_export_object_fn = function(ctx: pointer; objref: pointer; objref_sz: TOpenSSL_C_SIZET; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_decoder_export_object(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_export_object_fn{Has C Attribute: unused}; inline;

const
  {-
  * Store
  *
  * Objects are scanned by using the 'open', 'load', 'eof' and 'close'
  * functions, which implement an OSSL_STORE loader.
  *
  * store_load() works in a way that's very similar to the decoders, in
  * that they pass an abstract object through a callback, either as a DER
  * octet string or as an object reference, which libcrypto will have to
  * deal with.
  }
  OSSL_FUNC_STORE_OPEN_ = 1;
  OSSL_FUNC_STORE_ATTACH_ = 2;
  OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS_ = 3;
  OSSL_FUNC_STORE_SET_CTX_PARAMS_ = 4;
  OSSL_FUNC_STORE_LOAD_ = 5;
  OSSL_FUNC_STORE_EOF_ = 6;
  OSSL_FUNC_STORE_CLOSE_ = 7;
  OSSL_FUNC_STORE_EXPORT_OBJECT_ = 8;
  OSSL_FUNC_STORE_DELETE_ = 9;
  OSSL_FUNC_STORE_OPEN_EX_ = 10;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_open_fn = ^TOSSL_FUNC_store_open_fn;
  PPOSSL_FUNC_store_open_fn = ^POSSL_FUNC_store_open_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_open_fn = function(provctx: pointer; uri: PAnsiChar): pointer; cdecl;


  function OSSL_FUNC_store_open(opf: POSSL_DISPATCH): POSSL_FUNC_store_open_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_attach_fn = ^TOSSL_FUNC_store_attach_fn;
  PPOSSL_FUNC_store_attach_fn = ^POSSL_FUNC_store_attach_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_attach_fn = function(provctx: pointer; in_: POSSL_CORE_BIO): pointer; cdecl;


  function OSSL_FUNC_store_attach(opf: POSSL_DISPATCH): POSSL_FUNC_store_attach_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_settable_ctx_params_fn = ^TOSSL_FUNC_store_settable_ctx_params_fn;
  PPOSSL_FUNC_store_settable_ctx_params_fn = ^POSSL_FUNC_store_settable_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_settable_ctx_params_fn = function(provctx: pointer): POSSL_PARAM; cdecl;


  function OSSL_FUNC_store_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_store_settable_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_set_ctx_params_fn = ^TOSSL_FUNC_store_set_ctx_params_fn;
  PPOSSL_FUNC_store_set_ctx_params_fn = ^POSSL_FUNC_store_set_ctx_params_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_set_ctx_params_fn = function(loaderctx: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_store_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_store_set_ctx_params_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_load_fn = ^TOSSL_FUNC_store_load_fn;
  PPOSSL_FUNC_store_load_fn = ^POSSL_FUNC_store_load_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_load_fn = function(loaderctx: pointer; object_cb: POSSL_CALLBACK; object_cbarg: pointer; pw_cb: POSSL_PASSPHRASE_CALLBACK; pw_cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_store_load(opf: POSSL_DISPATCH): POSSL_FUNC_store_load_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_eof_fn = ^TOSSL_FUNC_store_eof_fn;
  PPOSSL_FUNC_store_eof_fn = ^POSSL_FUNC_store_eof_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_eof_fn = function(loaderctx: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_store_eof(opf: POSSL_DISPATCH): POSSL_FUNC_store_eof_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_close_fn = ^TOSSL_FUNC_store_close_fn;
  PPOSSL_FUNC_store_close_fn = ^POSSL_FUNC_store_close_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_close_fn = function(loaderctx: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_store_close(opf: POSSL_DISPATCH): POSSL_FUNC_store_close_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_export_object_fn = ^TOSSL_FUNC_store_export_object_fn;
  PPOSSL_FUNC_store_export_object_fn = ^POSSL_FUNC_store_export_object_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_export_object_fn = function(loaderctx: pointer; objref: pointer; objref_sz: TOpenSSL_C_SIZET; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_store_export_object(opf: POSSL_DISPATCH): POSSL_FUNC_store_export_object_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_delete_fn = ^TOSSL_FUNC_store_delete_fn;
  PPOSSL_FUNC_store_delete_fn = ^POSSL_FUNC_store_delete_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_delete_fn = function(provctx: pointer; uri: PAnsiChar; params: POSSL_PARAM; pw_cb: POSSL_PASSPHRASE_CALLBACK; pw_cbarg: pointer): TOpenSSL_C_INT; cdecl;


  function OSSL_FUNC_store_delete(opf: POSSL_DISPATCH): POSSL_FUNC_store_delete_fn{Has C Attribute: unused}; inline;

type
  {Auto-generated forward references}
  POSSL_FUNC_store_open_ex_fn = ^TOSSL_FUNC_store_open_ex_fn;
  PPOSSL_FUNC_store_open_ex_fn = ^POSSL_FUNC_store_open_ex_fn;
  {end of auto-generated forward references}

  TOSSL_FUNC_store_open_ex_fn = function(provctx: pointer; uri: PAnsiChar; params: POSSL_PARAM; pw_cb: POSSL_PASSPHRASE_CALLBACK; pw_cbarg: pointer): pointer; cdecl;


  function OSSL_FUNC_store_open_ex(opf: POSSL_DISPATCH): POSSL_FUNC_store_open_ex_fn{Has C Attribute: unused}; inline;
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

function OSSL_FUNC_core_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_core_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_gettable_params"');

{Error: Line 65: Syntax Error parsing " return (OSSL_FUNC_core_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_core_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_core_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_core_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_get_params"');

{Error: Line 68: Syntax Error parsing " return (OSSL_FUNC_core_get_params_fn *)opf->function; "

 return (OSSL_FUNC_core_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_core_thread_start(opf: POSSL_DISPATCH): POSSL_FUNC_core_thread_start_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_thread_start"');

{Error: Line 70: Syntax Error parsing " return (OSSL_FUNC_core_thread_start_fn *)opf->function; "

 return (OSSL_FUNC_core_thread_start_fn *)opf->function; }
end;

function OSSL_FUNC_core_get_libctx(opf: POSSL_DISPATCH): POSSL_FUNC_core_get_libctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_get_libctx"');

{Error: Line 72: Syntax Error parsing " return (OSSL_FUNC_core_get_libctx_fn *)opf->function; "

 return (OSSL_FUNC_core_get_libctx_fn *)opf->function; }
end;

function OSSL_FUNC_core_new_error(opf: POSSL_DISPATCH): POSSL_FUNC_core_new_error_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_new_error"');

{Error: Line 75: Syntax Error parsing " return (OSSL_FUNC_core_new_error_fn *)opf->function; "

 return (OSSL_FUNC_core_new_error_fn *)opf->function; }
end;

function OSSL_FUNC_core_set_error_debug(opf: POSSL_DISPATCH): POSSL_FUNC_core_set_error_debug_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_set_error_debug"');

{Error: Line 77: Syntax Error parsing " return (OSSL_FUNC_core_set_error_debug_fn *)opf->function; "

 return (OSSL_FUNC_core_set_error_debug_fn *)opf->function; }
end;

function OSSL_FUNC_core_vset_error(opf: POSSL_DISPATCH): POSSL_FUNC_core_vset_error_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_vset_error"');

{Error: Line 81: Syntax Error parsing " return (OSSL_FUNC_core_vset_error_fn *)opf->function; "

 return (OSSL_FUNC_core_vset_error_fn *)opf->function; }
end;

function OSSL_FUNC_core_set_error_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_set_error_mark_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_set_error_mark"');

{Error: Line 85: Syntax Error parsing " return (OSSL_FUNC_core_set_error_mark_fn *)opf->function; "

 return (OSSL_FUNC_core_set_error_mark_fn *)opf->function; }
end;

function OSSL_FUNC_core_clear_last_error_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_clear_last_error_mark_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_clear_last_error_mark"');

{Error: Line 87: Syntax Error parsing " return (OSSL_FUNC_core_clear_last_error_mark_fn *)opf->function; "

 return (OSSL_FUNC_core_clear_last_error_mark_fn *)opf->function; }
end;

function OSSL_FUNC_core_pop_error_to_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_pop_error_to_mark_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_pop_error_to_mark"');

{Error: Line 90: Syntax Error parsing " return (OSSL_FUNC_core_pop_error_to_mark_fn *)opf->function; "

 return (OSSL_FUNC_core_pop_error_to_mark_fn *)opf->function; }
end;

function OSSL_FUNC_core_obj_add_sigid(opf: POSSL_DISPATCH): POSSL_FUNC_core_obj_add_sigid_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_obj_add_sigid"');

{Error: Line 97: Syntax Error parsing " return (OSSL_FUNC_core_obj_add_sigid_fn *)opf->function; "

 return (OSSL_FUNC_core_obj_add_sigid_fn *)opf->function; }
end;

function OSSL_FUNC_core_obj_create(opf: POSSL_DISPATCH): POSSL_FUNC_core_obj_create_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_obj_create"');

{Error: Line 100: Syntax Error parsing " return (OSSL_FUNC_core_obj_create_fn *)opf->function; "

 return (OSSL_FUNC_core_obj_create_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_malloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_malloc_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_malloc"');

{Error: Line 106: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_malloc_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_malloc_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_zalloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_zalloc_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_zalloc"');

{Error: Line 109: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_zalloc_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_zalloc_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_free"');

{Error: Line 112: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_free_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_free_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_clear_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_clear_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_clear_free"');

{Error: Line 115: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_clear_free_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_clear_free_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_realloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_realloc_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_realloc"');

{Error: Line 118: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_realloc_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_realloc_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_clear_realloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_clear_realloc_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_clear_realloc"');

{Error: Line 121: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_clear_realloc_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_clear_realloc_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_secure_malloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_malloc_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_secure_malloc"');

{Error: Line 124: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_secure_malloc_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_secure_malloc_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_secure_zalloc(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_zalloc_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_secure_zalloc"');

{Error: Line 127: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_secure_zalloc_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_secure_zalloc_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_secure_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_secure_free"');

{Error: Line 130: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_secure_free_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_secure_free_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_secure_clear_free(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_clear_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_secure_clear_free"');

{Error: Line 133: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_secure_clear_free_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_secure_clear_free_fn *)opf->function; }
end;

function OSSL_FUNC_CRYPTO_secure_allocated(opf: POSSL_DISPATCH): POSSL_FUNC_CRYPTO_secure_allocated_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_CRYPTO_secure_allocated"');

{Error: Line 136: Syntax Error parsing " return (OSSL_FUNC_CRYPTO_secure_allocated_fn *)opf->function; "

 return (OSSL_FUNC_CRYPTO_secure_allocated_fn *)opf->function; }
end;

function OSSL_FUNC_OPENSSL_cleanse(opf: POSSL_DISPATCH): POSSL_FUNC_OPENSSL_cleanse_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_OPENSSL_cleanse"');

{Error: Line 139: Syntax Error parsing " return (OSSL_FUNC_OPENSSL_cleanse_fn *)opf->function; "

 return (OSSL_FUNC_OPENSSL_cleanse_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_new_file(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_new_file_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_new_file"');

{Error: Line 155: Syntax Error parsing " return (OSSL_FUNC_BIO_new_file_fn *)opf->function; "

 return (OSSL_FUNC_BIO_new_file_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_new_membuf(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_new_membuf_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_new_membuf"');

{Error: Line 156: Syntax Error parsing " return (OSSL_FUNC_BIO_new_membuf_fn *)opf->function; "

 return (OSSL_FUNC_BIO_new_membuf_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_read_ex(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_read_ex_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_read_ex"');

{Error: Line 157: Syntax Error parsing " return (OSSL_FUNC_BIO_read_ex_fn *)opf->function; "

 return (OSSL_FUNC_BIO_read_ex_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_write_ex(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_write_ex_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_write_ex"');

{Error: Line 158: Syntax Error parsing " return (OSSL_FUNC_BIO_write_ex_fn *)opf->function; "

 return (OSSL_FUNC_BIO_write_ex_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_gets(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_gets_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_gets"');

{Error: Line 159: Syntax Error parsing " return (OSSL_FUNC_BIO_gets_fn *)opf->function; "

 return (OSSL_FUNC_BIO_gets_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_puts(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_puts_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_puts"');

{Error: Line 160: Syntax Error parsing " return (OSSL_FUNC_BIO_puts_fn *)opf->function; "

 return (OSSL_FUNC_BIO_puts_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_up_ref(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_up_ref_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_up_ref"');

{Error: Line 161: Syntax Error parsing " return (OSSL_FUNC_BIO_up_ref_fn *)opf->function; "

 return (OSSL_FUNC_BIO_up_ref_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_free(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_free"');

{Error: Line 162: Syntax Error parsing " return (OSSL_FUNC_BIO_free_fn *)opf->function; "

 return (OSSL_FUNC_BIO_free_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_vprintf(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_vprintf_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_vprintf"');

{Error: Line 163: Syntax Error parsing " return (OSSL_FUNC_BIO_vprintf_fn *)opf->function; "

 return (OSSL_FUNC_BIO_vprintf_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_vsnprintf(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_vsnprintf_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_vsnprintf"');

{Error: Line 164: Syntax Error parsing " return (OSSL_FUNC_BIO_vsnprintf_fn *)opf->function; "

 return (OSSL_FUNC_BIO_vsnprintf_fn *)opf->function; }
end;

function OSSL_FUNC_BIO_ctrl(opf: POSSL_DISPATCH): POSSL_FUNC_BIO_ctrl_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_BIO_ctrl"');

{Error: Line 166: Syntax Error parsing " return (OSSL_FUNC_BIO_ctrl_fn *)opf->function; "

 return (OSSL_FUNC_BIO_ctrl_fn *)opf->function; }
end;

function OSSL_FUNC_indicator_cb(opf: POSSL_DISPATCH): POSSL_FUNC_indicator_cb_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_indicator_cb"');

{Error: Line 175: Syntax Error parsing " return (OSSL_FUNC_indicator_cb_fn *)opf->function; "

 return (OSSL_FUNC_indicator_cb_fn *)opf->function; }
end;

function OSSL_FUNC_self_test_cb(opf: POSSL_DISPATCH): POSSL_FUNC_self_test_cb_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_self_test_cb"');

{Error: Line 177: Syntax Error parsing " return (OSSL_FUNC_self_test_cb_fn *)opf->function; "

 return (OSSL_FUNC_self_test_cb_fn *)opf->function; }
end;

function OSSL_FUNC_get_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_get_entropy_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_get_entropy"');

{Error: Line 184: Syntax Error parsing " return (OSSL_FUNC_get_entropy_fn *)opf->function; "

 return (OSSL_FUNC_get_entropy_fn *)opf->function; }
end;

function OSSL_FUNC_get_user_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_get_user_entropy_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_get_user_entropy"');

{Error: Line 185: Syntax Error parsing " return (OSSL_FUNC_get_user_entropy_fn *)opf->function; "

 return (OSSL_FUNC_get_user_entropy_fn *)opf->function; }
end;

function OSSL_FUNC_cleanup_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_entropy_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cleanup_entropy"');

{Error: Line 186: Syntax Error parsing " return (OSSL_FUNC_cleanup_entropy_fn *)opf->function; "

 return (OSSL_FUNC_cleanup_entropy_fn *)opf->function; }
end;

function OSSL_FUNC_cleanup_user_entropy(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_user_entropy_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cleanup_user_entropy"');

{Error: Line 187: Syntax Error parsing " return (OSSL_FUNC_cleanup_user_entropy_fn *)opf->function; "

 return (OSSL_FUNC_cleanup_user_entropy_fn *)opf->function; }
end;

function OSSL_FUNC_get_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_get_nonce_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_get_nonce"');

{Error: Line 188: Syntax Error parsing " return (OSSL_FUNC_get_nonce_fn *)opf->function; "

 return (OSSL_FUNC_get_nonce_fn *)opf->function; }
end;

function OSSL_FUNC_get_user_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_get_user_nonce_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_get_user_nonce"');

{Error: Line 189: Syntax Error parsing " return (OSSL_FUNC_get_user_nonce_fn *)opf->function; "

 return (OSSL_FUNC_get_user_nonce_fn *)opf->function; }
end;

function OSSL_FUNC_cleanup_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_nonce_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cleanup_nonce"');

{Error: Line 190: Syntax Error parsing " return (OSSL_FUNC_cleanup_nonce_fn *)opf->function; "

 return (OSSL_FUNC_cleanup_nonce_fn *)opf->function; }
end;

function OSSL_FUNC_cleanup_user_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_cleanup_user_nonce_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cleanup_user_nonce"');

{Error: Line 191: Syntax Error parsing " return (OSSL_FUNC_cleanup_user_nonce_fn *)opf->function; "

 return (OSSL_FUNC_cleanup_user_nonce_fn *)opf->function; }
end;

function OSSL_FUNC_provider_register_child_cb(opf: POSSL_DISPATCH): POSSL_FUNC_provider_register_child_cb_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_register_child_cb"');

{Error: Line 202: Syntax Error parsing " return (OSSL_FUNC_provider_register_child_cb_fn *)opf->function; "

 return (OSSL_FUNC_provider_register_child_cb_fn *)opf->function; }
end;

function OSSL_FUNC_provider_deregister_child_cb(opf: POSSL_DISPATCH): POSSL_FUNC_provider_deregister_child_cb_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_deregister_child_cb"');

{Error: Line 208: Syntax Error parsing " return (OSSL_FUNC_provider_deregister_child_cb_fn *)opf->function; "

 return (OSSL_FUNC_provider_deregister_child_cb_fn *)opf->function; }
end;

function OSSL_FUNC_provider_name(opf: POSSL_DISPATCH): POSSL_FUNC_provider_name_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_name"');

{Error: Line 210: Syntax Error parsing " return (OSSL_FUNC_provider_name_fn *)opf->function; "

 return (OSSL_FUNC_provider_name_fn *)opf->function; }
end;

function OSSL_FUNC_provider_get0_provider_ctx(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get0_provider_ctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_get0_provider_ctx"');

{Error: Line 212: Syntax Error parsing " return (OSSL_FUNC_provider_get0_provider_ctx_fn *)opf->function; "

 return (OSSL_FUNC_provider_get0_provider_ctx_fn *)opf->function; }
end;

function OSSL_FUNC_provider_get0_dispatch(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get0_dispatch_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_get0_dispatch"');

{Error: Line 214: Syntax Error parsing " return (OSSL_FUNC_provider_get0_dispatch_fn *)opf->function; "

 return (OSSL_FUNC_provider_get0_dispatch_fn *)opf->function; }
end;

function OSSL_FUNC_provider_up_ref(opf: POSSL_DISPATCH): POSSL_FUNC_provider_up_ref_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_up_ref"');

{Error: Line 216: Syntax Error parsing " return (OSSL_FUNC_provider_up_ref_fn *)opf->function; "

 return (OSSL_FUNC_provider_up_ref_fn *)opf->function; }
end;

function OSSL_FUNC_provider_free(opf: POSSL_DISPATCH): POSSL_FUNC_provider_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_free"');

{Error: Line 218: Syntax Error parsing " return (OSSL_FUNC_provider_free_fn *)opf->function; "

 return (OSSL_FUNC_provider_free_fn *)opf->function; }
end;

function OSSL_FUNC_core_count_to_mark(opf: POSSL_DISPATCH): POSSL_FUNC_core_count_to_mark_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_core_count_to_mark"');

{Error: Line 223: Syntax Error parsing " return (OSSL_FUNC_core_count_to_mark_fn *)opf->function; "

 return (OSSL_FUNC_core_count_to_mark_fn *)opf->function; }
end;

function OSSL_FUNC_provider_teardown(opf: POSSL_DISPATCH): POSSL_FUNC_provider_teardown_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_teardown"');

{Error: Line 227: Syntax Error parsing " return (OSSL_FUNC_provider_teardown_fn *)opf->function; "

 return (OSSL_FUNC_provider_teardown_fn *)opf->function; }
end;

function OSSL_FUNC_provider_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_provider_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_gettable_params"');

{Error: Line 229: Syntax Error parsing " return (OSSL_FUNC_provider_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_provider_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_provider_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_get_params"');

{Error: Line 232: Syntax Error parsing " return (OSSL_FUNC_provider_get_params_fn *)opf->function; "

 return (OSSL_FUNC_provider_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_provider_query_operation(opf: POSSL_DISPATCH): POSSL_FUNC_provider_query_operation_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_query_operation"');

{Error: Line 234: Syntax Error parsing " return (OSSL_FUNC_provider_query_operation_fn *)opf->function; "

 return (OSSL_FUNC_provider_query_operation_fn *)opf->function; }
end;

function OSSL_FUNC_provider_unquery_operation(opf: POSSL_DISPATCH): POSSL_FUNC_provider_unquery_operation_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_unquery_operation"');

{Error: Line 237: Syntax Error parsing " return (OSSL_FUNC_provider_unquery_operation_fn *)opf->function; "

 return (OSSL_FUNC_provider_unquery_operation_fn *)opf->function; }
end;

function OSSL_FUNC_provider_get_reason_strings(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get_reason_strings_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_get_reason_strings"');

{Error: Line 240: Syntax Error parsing " return (OSSL_FUNC_provider_get_reason_strings_fn *)opf->function; "

 return (OSSL_FUNC_provider_get_reason_strings_fn *)opf->function; }
end;

function OSSL_FUNC_provider_get_capabilities(opf: POSSL_DISPATCH): POSSL_FUNC_provider_get_capabilities_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_get_capabilities"');

{Error: Line 243: Syntax Error parsing " return (OSSL_FUNC_provider_get_capabilities_fn *)opf->function; "

 return (OSSL_FUNC_provider_get_capabilities_fn *)opf->function; }
end;

function OSSL_FUNC_provider_self_test(opf: POSSL_DISPATCH): POSSL_FUNC_provider_self_test_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_self_test"');

{Error: Line 245: Syntax Error parsing " return (OSSL_FUNC_provider_self_test_fn *)opf->function; "

 return (OSSL_FUNC_provider_self_test_fn *)opf->function; }
end;

function OSSL_FUNC_provider_random_bytes(opf: POSSL_DISPATCH): POSSL_FUNC_provider_random_bytes_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_provider_random_bytes"');

{Error: Line 247: Syntax Error parsing " return (OSSL_FUNC_provider_random_bytes_fn *)opf->function; "

 return (OSSL_FUNC_provider_random_bytes_fn *)opf->function; }
end;

function OSSL_FUNC_SSL_QUIC_TLS_crypto_send(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_SSL_QUIC_TLS_crypto_send"');

{Error: Line 251: Syntax Error parsing " return (OSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn *)opf->function; "

 return (OSSL_FUNC_SSL_QUIC_TLS_crypto_send_fn *)opf->function; }
end;

function OSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd"');

{Error: Line 255: Syntax Error parsing " return (OSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn *)opf->function; "

 return (OSSL_FUNC_SSL_QUIC_TLS_crypto_recv_rcd_fn *)opf->function; }
end;

function OSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd"');

{Error: Line 259: Syntax Error parsing " return (OSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn *)opf->function; "

 return (OSSL_FUNC_SSL_QUIC_TLS_crypto_release_rcd_fn *)opf->function; }
end;

function OSSL_FUNC_SSL_QUIC_TLS_yield_secret(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_SSL_QUIC_TLS_yield_secret"');

{Error: Line 262: Syntax Error parsing " return (OSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn *)opf->function; "

 return (OSSL_FUNC_SSL_QUIC_TLS_yield_secret_fn *)opf->function; }
end;

function OSSL_FUNC_SSL_QUIC_TLS_got_transport_params(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_SSL_QUIC_TLS_got_transport_params"');

{Error: Line 266: Syntax Error parsing " return (OSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn *)opf->function; "

 return (OSSL_FUNC_SSL_QUIC_TLS_got_transport_params_fn *)opf->function; }
end;

function OSSL_FUNC_SSL_QUIC_TLS_alert(opf: POSSL_DISPATCH): POSSL_FUNC_SSL_QUIC_TLS_alert_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_SSL_QUIC_TLS_alert"');

{Error: Line 270: Syntax Error parsing " return (OSSL_FUNC_SSL_QUIC_TLS_alert_fn *)opf->function; "

 return (OSSL_FUNC_SSL_QUIC_TLS_alert_fn *)opf->function; }
end;

function OSSL_FUNC_digest_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_newctx"');

{Error: Line 313: Syntax Error parsing " return (OSSL_FUNC_digest_newctx_fn *)opf->function; "

 return (OSSL_FUNC_digest_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_digest_init(opf: POSSL_DISPATCH): POSSL_FUNC_digest_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_init"');

{Error: Line 314: Syntax Error parsing " return (OSSL_FUNC_digest_init_fn *)opf->function; "

 return (OSSL_FUNC_digest_init_fn *)opf->function; }
end;

function OSSL_FUNC_digest_update(opf: POSSL_DISPATCH): POSSL_FUNC_digest_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_update"');

{Error: Line 315: Syntax Error parsing " return (OSSL_FUNC_digest_update_fn *)opf->function; "

 return (OSSL_FUNC_digest_update_fn *)opf->function; }
end;

function OSSL_FUNC_digest_final(opf: POSSL_DISPATCH): POSSL_FUNC_digest_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_final"');

{Error: Line 317: Syntax Error parsing " return (OSSL_FUNC_digest_final_fn *)opf->function; "

 return (OSSL_FUNC_digest_final_fn *)opf->function; }
end;

function OSSL_FUNC_digest_squeeze(opf: POSSL_DISPATCH): POSSL_FUNC_digest_squeeze_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_squeeze"');

{Error: Line 320: Syntax Error parsing " return (OSSL_FUNC_digest_squeeze_fn *)opf->function; "

 return (OSSL_FUNC_digest_squeeze_fn *)opf->function; }
end;

function OSSL_FUNC_digest_digest(opf: POSSL_DISPATCH): POSSL_FUNC_digest_digest_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_digest"');

{Error: Line 323: Syntax Error parsing " return (OSSL_FUNC_digest_digest_fn *)opf->function; "

 return (OSSL_FUNC_digest_digest_fn *)opf->function; }
end;

function OSSL_FUNC_digest_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_freectx"');

{Error: Line 327: Syntax Error parsing " return (OSSL_FUNC_digest_freectx_fn *)opf->function; "

 return (OSSL_FUNC_digest_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_digest_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_dupctx"');

{Error: Line 328: Syntax Error parsing " return (OSSL_FUNC_digest_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_digest_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_digest_copyctx(opf: POSSL_DISPATCH): POSSL_FUNC_digest_copyctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_copyctx"');

{Error: Line 329: Syntax Error parsing " return (OSSL_FUNC_digest_copyctx_fn *)opf->function; "

 return (OSSL_FUNC_digest_copyctx_fn *)opf->function; }
end;

function OSSL_FUNC_digest_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_get_params"');

{Error: Line 331: Syntax Error parsing " return (OSSL_FUNC_digest_get_params_fn *)opf->function; "

 return (OSSL_FUNC_digest_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_digest_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_set_ctx_params"');

{Error: Line 332: Syntax Error parsing " return (OSSL_FUNC_digest_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_digest_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_digest_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_get_ctx_params"');

{Error: Line 334: Syntax Error parsing " return (OSSL_FUNC_digest_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_digest_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_digest_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_gettable_params"');

{Error: Line 336: Syntax Error parsing " return (OSSL_FUNC_digest_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_digest_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_digest_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_settable_ctx_params"');

{Error: Line 338: Syntax Error parsing " return (OSSL_FUNC_digest_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_digest_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_digest_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_digest_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_gettable_ctx_params"');

{Error: Line 340: Syntax Error parsing " return (OSSL_FUNC_digest_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_digest_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_digest_serialize(opf: POSSL_DISPATCH): POSSL_FUNC_digest_serialize_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_serialize"');

{Error: Line 342: Syntax Error parsing " return (OSSL_FUNC_digest_serialize_fn *)opf->function; "

 return (OSSL_FUNC_digest_serialize_fn *)opf->function; }
end;

function OSSL_FUNC_digest_deserialize(opf: POSSL_DISPATCH): POSSL_FUNC_digest_deserialize_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_digest_deserialize"');

{Error: Line 344: Syntax Error parsing " return (OSSL_FUNC_digest_deserialize_fn *)opf->function; "

 return (OSSL_FUNC_digest_deserialize_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_newctx"');

{Error: Line 370: Syntax Error parsing " return (OSSL_FUNC_cipher_newctx_fn *)opf->function; "

 return (OSSL_FUNC_cipher_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_encrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_encrypt_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_encrypt_init"');

{Error: Line 371: Syntax Error parsing " return (OSSL_FUNC_cipher_encrypt_init_fn *)opf->function; "

 return (OSSL_FUNC_cipher_encrypt_init_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_decrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_decrypt_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_decrypt_init"');

{Error: Line 372: Syntax Error parsing " return (OSSL_FUNC_cipher_decrypt_init_fn *)opf->function; "

 return (OSSL_FUNC_cipher_decrypt_init_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_update(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_update"');

{Error: Line 373: Syntax Error parsing " return (OSSL_FUNC_cipher_update_fn *)opf->function; "

 return (OSSL_FUNC_cipher_update_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_final(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_final"');

{Error: Line 377: Syntax Error parsing " return (OSSL_FUNC_cipher_final_fn *)opf->function; "

 return (OSSL_FUNC_cipher_final_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_cipher(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_cipher_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_cipher"');

{Error: Line 380: Syntax Error parsing " return (OSSL_FUNC_cipher_cipher_fn *)opf->function; "

 return (OSSL_FUNC_cipher_cipher_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_pipeline_encrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_encrypt_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_pipeline_encrypt_init"');

{Error: Line 384: Syntax Error parsing " return (OSSL_FUNC_cipher_pipeline_encrypt_init_fn *)opf->function; "

 return (OSSL_FUNC_cipher_pipeline_encrypt_init_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_pipeline_decrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_decrypt_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_pipeline_decrypt_init"');

{Error: Line 389: Syntax Error parsing " return (OSSL_FUNC_cipher_pipeline_decrypt_init_fn *)opf->function; "

 return (OSSL_FUNC_cipher_pipeline_decrypt_init_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_pipeline_update(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_pipeline_update"');

{Error: Line 394: Syntax Error parsing " return (OSSL_FUNC_cipher_pipeline_update_fn *)opf->function; "

 return (OSSL_FUNC_cipher_pipeline_update_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_pipeline_final(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_pipeline_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_pipeline_final"');

{Error: Line 398: Syntax Error parsing " return (OSSL_FUNC_cipher_pipeline_final_fn *)opf->function; "

 return (OSSL_FUNC_cipher_pipeline_final_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_freectx"');

{Error: Line 401: Syntax Error parsing " return (OSSL_FUNC_cipher_freectx_fn *)opf->function; "

 return (OSSL_FUNC_cipher_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_dupctx"');

{Error: Line 402: Syntax Error parsing " return (OSSL_FUNC_cipher_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_cipher_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_get_params"');

{Error: Line 403: Syntax Error parsing " return (OSSL_FUNC_cipher_get_params_fn *)opf->function; "

 return (OSSL_FUNC_cipher_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_get_ctx_params"');

{Error: Line 404: Syntax Error parsing " return (OSSL_FUNC_cipher_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_cipher_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_set_ctx_params"');

{Error: Line 405: Syntax Error parsing " return (OSSL_FUNC_cipher_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_cipher_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_gettable_params"');

{Error: Line 406: Syntax Error parsing " return (OSSL_FUNC_cipher_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_cipher_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_settable_ctx_params"');

{Error: Line 408: Syntax Error parsing " return (OSSL_FUNC_cipher_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_cipher_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_gettable_ctx_params"');

{Error: Line 410: Syntax Error parsing " return (OSSL_FUNC_cipher_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_cipher_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_encrypt_skey_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_encrypt_skey_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_encrypt_skey_init"');

{Error: Line 412: Syntax Error parsing " return (OSSL_FUNC_cipher_encrypt_skey_init_fn *)opf->function; "

 return (OSSL_FUNC_cipher_encrypt_skey_init_fn *)opf->function; }
end;

function OSSL_FUNC_cipher_decrypt_skey_init(opf: POSSL_DISPATCH): POSSL_FUNC_cipher_decrypt_skey_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_cipher_decrypt_skey_init"');

{Error: Line 413: Syntax Error parsing " return (OSSL_FUNC_cipher_decrypt_skey_init_fn *)opf->function; "

 return (OSSL_FUNC_cipher_decrypt_skey_init_fn *)opf->function; }
end;

function OSSL_FUNC_mac_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_mac_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_newctx"');

{Error: Line 431: Syntax Error parsing " return (OSSL_FUNC_mac_newctx_fn *)opf->function; "

 return (OSSL_FUNC_mac_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_mac_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_mac_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_dupctx"');

{Error: Line 432: Syntax Error parsing " return (OSSL_FUNC_mac_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_mac_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_mac_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_mac_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_freectx"');

{Error: Line 433: Syntax Error parsing " return (OSSL_FUNC_mac_freectx_fn *)opf->function; "

 return (OSSL_FUNC_mac_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_mac_init(opf: POSSL_DISPATCH): POSSL_FUNC_mac_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_init"');

{Error: Line 434: Syntax Error parsing " return (OSSL_FUNC_mac_init_fn *)opf->function; "

 return (OSSL_FUNC_mac_init_fn *)opf->function; }
end;

function OSSL_FUNC_mac_update(opf: POSSL_DISPATCH): POSSL_FUNC_mac_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_update"');

{Error: Line 435: Syntax Error parsing " return (OSSL_FUNC_mac_update_fn *)opf->function; "

 return (OSSL_FUNC_mac_update_fn *)opf->function; }
end;

function OSSL_FUNC_mac_final(opf: POSSL_DISPATCH): POSSL_FUNC_mac_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_final"');

{Error: Line 437: Syntax Error parsing " return (OSSL_FUNC_mac_final_fn *)opf->function; "

 return (OSSL_FUNC_mac_final_fn *)opf->function; }
end;

function OSSL_FUNC_mac_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_gettable_params"');

{Error: Line 440: Syntax Error parsing " return (OSSL_FUNC_mac_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_mac_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_mac_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_gettable_ctx_params"');

{Error: Line 441: Syntax Error parsing " return (OSSL_FUNC_mac_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_mac_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_mac_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_settable_ctx_params"');

{Error: Line 443: Syntax Error parsing " return (OSSL_FUNC_mac_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_mac_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_mac_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_get_params"');

{Error: Line 445: Syntax Error parsing " return (OSSL_FUNC_mac_get_params_fn *)opf->function; "

 return (OSSL_FUNC_mac_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_mac_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_get_ctx_params"');

{Error: Line 446: Syntax Error parsing " return (OSSL_FUNC_mac_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_mac_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_mac_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_mac_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_set_ctx_params"');

{Error: Line 448: Syntax Error parsing " return (OSSL_FUNC_mac_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_mac_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_mac_init_skey(opf: POSSL_DISPATCH): POSSL_FUNC_mac_init_skey_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_mac_init_skey"');

{Error: Line 450: Syntax Error parsing " return (OSSL_FUNC_mac_init_skey_fn *)opf->function; "

 return (OSSL_FUNC_mac_init_skey_fn *)opf->function; }
end;

function OSSL_FUNC_skeymgmt_free(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_skeymgmt_free"');

{Error: Line 484: Syntax Error parsing " return (OSSL_FUNC_skeymgmt_free_fn *)opf->function; "

 return (OSSL_FUNC_skeymgmt_free_fn *)opf->function; }
end;

function OSSL_FUNC_skeymgmt_imp_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_imp_settable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_skeymgmt_imp_settable_params"');

{Error: Line 485: Syntax Error parsing " return (OSSL_FUNC_skeymgmt_imp_settable_params_fn *)opf->function; "

 return (OSSL_FUNC_skeymgmt_imp_settable_params_fn *)opf->function; }
end;

function OSSL_FUNC_skeymgmt_import(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_import_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_skeymgmt_import"');

{Error: Line 487: Syntax Error parsing " return (OSSL_FUNC_skeymgmt_import_fn *)opf->function; "

 return (OSSL_FUNC_skeymgmt_import_fn *)opf->function; }
end;

function OSSL_FUNC_skeymgmt_export(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_export_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_skeymgmt_export"');

{Error: Line 488: Syntax Error parsing " return (OSSL_FUNC_skeymgmt_export_fn *)opf->function; "

 return (OSSL_FUNC_skeymgmt_export_fn *)opf->function; }
end;

function OSSL_FUNC_skeymgmt_gen_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_gen_settable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_skeymgmt_gen_settable_params"');

{Error: Line 491: Syntax Error parsing " return (OSSL_FUNC_skeymgmt_gen_settable_params_fn *)opf->function; "

 return (OSSL_FUNC_skeymgmt_gen_settable_params_fn *)opf->function; }
end;

function OSSL_FUNC_skeymgmt_generate(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_generate_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_skeymgmt_generate"');

{Error: Line 493: Syntax Error parsing " return (OSSL_FUNC_skeymgmt_generate_fn *)opf->function; "

 return (OSSL_FUNC_skeymgmt_generate_fn *)opf->function; }
end;

function OSSL_FUNC_skeymgmt_get_key_id(opf: POSSL_DISPATCH): POSSL_FUNC_skeymgmt_get_key_id_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_skeymgmt_get_key_id"');

{Error: Line 494: Syntax Error parsing " return (OSSL_FUNC_skeymgmt_get_key_id_fn *)opf->function; "

 return (OSSL_FUNC_skeymgmt_get_key_id_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_newctx"');

{Error: Line 512: Syntax Error parsing " return (OSSL_FUNC_kdf_newctx_fn *)opf->function; "

 return (OSSL_FUNC_kdf_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_dupctx"');

{Error: Line 513: Syntax Error parsing " return (OSSL_FUNC_kdf_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_kdf_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_freectx"');

{Error: Line 514: Syntax Error parsing " return (OSSL_FUNC_kdf_freectx_fn *)opf->function; "

 return (OSSL_FUNC_kdf_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_reset(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_reset_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_reset"');

{Error: Line 515: Syntax Error parsing " return (OSSL_FUNC_kdf_reset_fn *)opf->function; "

 return (OSSL_FUNC_kdf_reset_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_derive(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_derive_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_derive"');

{Error: Line 516: Syntax Error parsing " return (OSSL_FUNC_kdf_derive_fn *)opf->function; "

 return (OSSL_FUNC_kdf_derive_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_gettable_params"');

{Error: Line 517: Syntax Error parsing " return (OSSL_FUNC_kdf_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_kdf_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_gettable_ctx_params"');

{Error: Line 518: Syntax Error parsing " return (OSSL_FUNC_kdf_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kdf_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_settable_ctx_params"');

{Error: Line 520: Syntax Error parsing " return (OSSL_FUNC_kdf_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kdf_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_get_params"');

{Error: Line 522: Syntax Error parsing " return (OSSL_FUNC_kdf_get_params_fn *)opf->function; "

 return (OSSL_FUNC_kdf_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_get_ctx_params"');

{Error: Line 523: Syntax Error parsing " return (OSSL_FUNC_kdf_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kdf_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_set_ctx_params"');

{Error: Line 525: Syntax Error parsing " return (OSSL_FUNC_kdf_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kdf_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_set_skey(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_set_skey_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_set_skey"');

{Error: Line 527: Syntax Error parsing " return (OSSL_FUNC_kdf_set_skey_fn *)opf->function; "

 return (OSSL_FUNC_kdf_set_skey_fn *)opf->function; }
end;

function OSSL_FUNC_kdf_derive_skey(opf: POSSL_DISPATCH): POSSL_FUNC_kdf_derive_skey_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kdf_derive_skey"');

{Error: Line 529: Syntax Error parsing " return (OSSL_FUNC_kdf_derive_skey_fn *)opf->function; "

 return (OSSL_FUNC_kdf_derive_skey_fn *)opf->function; }
end;

function OSSL_FUNC_rand_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_rand_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_newctx"');

{Error: Line 553: Syntax Error parsing " return (OSSL_FUNC_rand_newctx_fn *)opf->function; "

 return (OSSL_FUNC_rand_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_rand_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_rand_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_freectx"');

{Error: Line 556: Syntax Error parsing " return (OSSL_FUNC_rand_freectx_fn *)opf->function; "

 return (OSSL_FUNC_rand_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_rand_instantiate(opf: POSSL_DISPATCH): POSSL_FUNC_rand_instantiate_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_instantiate"');

{Error: Line 557: Syntax Error parsing " return (OSSL_FUNC_rand_instantiate_fn *)opf->function; "

 return (OSSL_FUNC_rand_instantiate_fn *)opf->function; }
end;

function OSSL_FUNC_rand_uninstantiate(opf: POSSL_DISPATCH): POSSL_FUNC_rand_uninstantiate_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_uninstantiate"');

{Error: Line 562: Syntax Error parsing " return (OSSL_FUNC_rand_uninstantiate_fn *)opf->function; "

 return (OSSL_FUNC_rand_uninstantiate_fn *)opf->function; }
end;

function OSSL_FUNC_rand_generate(opf: POSSL_DISPATCH): POSSL_FUNC_rand_generate_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_generate"');

{Error: Line 563: Syntax Error parsing " return (OSSL_FUNC_rand_generate_fn *)opf->function; "

 return (OSSL_FUNC_rand_generate_fn *)opf->function; }
end;

function OSSL_FUNC_rand_reseed(opf: POSSL_DISPATCH): POSSL_FUNC_rand_reseed_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_reseed"');

{Error: Line 567: Syntax Error parsing " return (OSSL_FUNC_rand_reseed_fn *)opf->function; "

 return (OSSL_FUNC_rand_reseed_fn *)opf->function; }
end;

function OSSL_FUNC_rand_nonce(opf: POSSL_DISPATCH): POSSL_FUNC_rand_nonce_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_nonce"');

{Error: Line 571: Syntax Error parsing " return (OSSL_FUNC_rand_nonce_fn *)opf->function; "

 return (OSSL_FUNC_rand_nonce_fn *)opf->function; }
end;

function OSSL_FUNC_rand_enable_locking(opf: POSSL_DISPATCH): POSSL_FUNC_rand_enable_locking_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_enable_locking"');

{Error: Line 574: Syntax Error parsing " return (OSSL_FUNC_rand_enable_locking_fn *)opf->function; "

 return (OSSL_FUNC_rand_enable_locking_fn *)opf->function; }
end;

function OSSL_FUNC_rand_lock(opf: POSSL_DISPATCH): POSSL_FUNC_rand_lock_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_lock"');

{Error: Line 575: Syntax Error parsing " return (OSSL_FUNC_rand_lock_fn *)opf->function; "

 return (OSSL_FUNC_rand_lock_fn *)opf->function; }
end;

function OSSL_FUNC_rand_unlock(opf: POSSL_DISPATCH): POSSL_FUNC_rand_unlock_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_unlock"');

{Error: Line 576: Syntax Error parsing " return (OSSL_FUNC_rand_unlock_fn *)opf->function; "

 return (OSSL_FUNC_rand_unlock_fn *)opf->function; }
end;

function OSSL_FUNC_rand_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_gettable_params"');

{Error: Line 577: Syntax Error parsing " return (OSSL_FUNC_rand_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_rand_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_rand_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_gettable_ctx_params"');

{Error: Line 578: Syntax Error parsing " return (OSSL_FUNC_rand_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_rand_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_rand_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_settable_ctx_params"');

{Error: Line 580: Syntax Error parsing " return (OSSL_FUNC_rand_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_rand_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_rand_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_get_params"');

{Error: Line 582: Syntax Error parsing " return (OSSL_FUNC_rand_get_params_fn *)opf->function; "

 return (OSSL_FUNC_rand_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_rand_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_get_ctx_params"');

{Error: Line 583: Syntax Error parsing " return (OSSL_FUNC_rand_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_rand_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_rand_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_rand_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_set_ctx_params"');

{Error: Line 585: Syntax Error parsing " return (OSSL_FUNC_rand_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_rand_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_rand_set_callbacks(opf: POSSL_DISPATCH): POSSL_FUNC_rand_set_callbacks_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_set_callbacks"');

{Error: Line 587: Syntax Error parsing " return (OSSL_FUNC_rand_set_callbacks_fn *)opf->function; "

 return (OSSL_FUNC_rand_set_callbacks_fn *)opf->function; }
end;

function OSSL_FUNC_rand_verify_zeroization(opf: POSSL_DISPATCH): POSSL_FUNC_rand_verify_zeroization_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_verify_zeroization"');

{Error: Line 592: Syntax Error parsing " return (OSSL_FUNC_rand_verify_zeroization_fn *)opf->function; "

 return (OSSL_FUNC_rand_verify_zeroization_fn *)opf->function; }
end;

function OSSL_FUNC_rand_get_seed(opf: POSSL_DISPATCH): POSSL_FUNC_rand_get_seed_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_get_seed"');

{Error: Line 594: Syntax Error parsing " return (OSSL_FUNC_rand_get_seed_fn *)opf->function; "

 return (OSSL_FUNC_rand_get_seed_fn *)opf->function; }
end;

function OSSL_FUNC_rand_clear_seed(opf: POSSL_DISPATCH): POSSL_FUNC_rand_clear_seed_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_rand_clear_seed"');

{Error: Line 599: Syntax Error parsing " return (OSSL_FUNC_rand_clear_seed_fn *)opf->function; "

 return (OSSL_FUNC_rand_clear_seed_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_new(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_new_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_new"');

{Error: Line 657: Syntax Error parsing " return (OSSL_FUNC_keymgmt_new_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_new_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_new_ex(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_new_ex_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_new_ex"');

{Error: Line 659: Syntax Error parsing " return (OSSL_FUNC_keymgmt_new_ex_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_new_ex_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen_init(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen_init"');

{Error: Line 671: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_init_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_init_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen_set_template(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_set_template_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen_set_template"');

{Error: Line 673: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_set_template_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_set_template_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen_set_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_set_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen_set_params"');

{Error: Line 675: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_set_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_set_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_settable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen_settable_params"');

{Error: Line 677: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_settable_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_settable_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen_get_params"');

{Error: Line 680: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_get_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen_gettable_params"');

{Error: Line 682: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen"');

{Error: Line 684: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gen_cleanup(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gen_cleanup_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gen_cleanup"');

{Error: Line 686: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gen_cleanup_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gen_cleanup_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_load(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_load_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_load"');

{Error: Line 690: Syntax Error parsing " return (OSSL_FUNC_keymgmt_load_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_load_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_free(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_free_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_free"');

{Error: Line 695: Syntax Error parsing " return (OSSL_FUNC_keymgmt_free_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_free_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_get_params"');

{Error: Line 700: Syntax Error parsing " return (OSSL_FUNC_keymgmt_get_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_gettable_params"');

{Error: Line 702: Syntax Error parsing " return (OSSL_FUNC_keymgmt_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_set_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_set_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_set_params"');

{Error: Line 707: Syntax Error parsing " return (OSSL_FUNC_keymgmt_set_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_set_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_settable_params(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_settable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_settable_params"');

{Error: Line 709: Syntax Error parsing " return (OSSL_FUNC_keymgmt_settable_params_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_settable_params_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_query_operation_name(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_query_operation_name_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_query_operation_name"');

{Error: Line 714: Syntax Error parsing " return (OSSL_FUNC_keymgmt_query_operation_name_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_query_operation_name_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_has(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_has_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_has"');

{Error: Line 719: Syntax Error parsing " return (OSSL_FUNC_keymgmt_has_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_has_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_validate(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_validate_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_validate"');

{Error: Line 723: Syntax Error parsing " return (OSSL_FUNC_keymgmt_validate_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_validate_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_match(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_match_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_match"');

{Error: Line 727: Syntax Error parsing " return (OSSL_FUNC_keymgmt_match_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_match_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_import(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_import_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_import"');

{Error: Line 736: Syntax Error parsing " return (OSSL_FUNC_keymgmt_import_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_import_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_import_types(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_import_types_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_import_types"');

{Error: Line 738: Syntax Error parsing " return (OSSL_FUNC_keymgmt_import_types_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_import_types_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_export(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_export_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_export"');

{Error: Line 740: Syntax Error parsing " return (OSSL_FUNC_keymgmt_export_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_export_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_export_types(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_export_types_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_export_types"');

{Error: Line 743: Syntax Error parsing " return (OSSL_FUNC_keymgmt_export_types_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_export_types_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_dup(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_dup_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_dup"');

{Error: Line 748: Syntax Error parsing " return (OSSL_FUNC_keymgmt_dup_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_dup_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_import_types_ex(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_import_types_ex_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_import_types_ex"');

{Error: Line 754: Syntax Error parsing " return (OSSL_FUNC_keymgmt_import_types_ex_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_import_types_ex_fn *)opf->function; }
end;

function OSSL_FUNC_keymgmt_export_types_ex(opf: POSSL_DISPATCH): POSSL_FUNC_keymgmt_export_types_ex_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keymgmt_export_types_ex"');

{Error: Line 756: Syntax Error parsing " return (OSSL_FUNC_keymgmt_export_types_ex_fn *)opf->function; "

 return (OSSL_FUNC_keymgmt_export_types_ex_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_newctx"');

{Error: Line 773: Syntax Error parsing " return (OSSL_FUNC_keyexch_newctx_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_init(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_init"');

{Error: Line 774: Syntax Error parsing " return (OSSL_FUNC_keyexch_init_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_init_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_derive(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_derive_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_derive"');

{Error: Line 775: Syntax Error parsing " return (OSSL_FUNC_keyexch_derive_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_derive_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_set_peer(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_set_peer_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_set_peer"');

{Error: Line 776: Syntax Error parsing " return (OSSL_FUNC_keyexch_set_peer_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_set_peer_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_freectx"');

{Error: Line 777: Syntax Error parsing " return (OSSL_FUNC_keyexch_freectx_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_dupctx"');

{Error: Line 778: Syntax Error parsing " return (OSSL_FUNC_keyexch_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_set_ctx_params"');

{Error: Line 779: Syntax Error parsing " return (OSSL_FUNC_keyexch_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_settable_ctx_params"');

{Error: Line 780: Syntax Error parsing " return (OSSL_FUNC_keyexch_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_get_ctx_params"');

{Error: Line 782: Syntax Error parsing " return (OSSL_FUNC_keyexch_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_gettable_ctx_params"');

{Error: Line 783: Syntax Error parsing " return (OSSL_FUNC_keyexch_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_keyexch_derive_skey(opf: POSSL_DISPATCH): POSSL_FUNC_keyexch_derive_skey_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_keyexch_derive_skey"');

{Error: Line 785: Syntax Error parsing " return (OSSL_FUNC_keyexch_derive_skey_fn *)opf->function; "

 return (OSSL_FUNC_keyexch_derive_skey_fn *)opf->function; }
end;

function OSSL_FUNC_signature_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_signature_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_newctx"');

{Error: Line 822: Syntax Error parsing " return (OSSL_FUNC_signature_newctx_fn *)opf->function; "

 return (OSSL_FUNC_signature_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_signature_sign_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_sign_init"');

{Error: Line 823: Syntax Error parsing " return (OSSL_FUNC_signature_sign_init_fn *)opf->function; "

 return (OSSL_FUNC_signature_sign_init_fn *)opf->function; }
end;

function OSSL_FUNC_signature_sign(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_sign"');

{Error: Line 824: Syntax Error parsing " return (OSSL_FUNC_signature_sign_fn *)opf->function; "

 return (OSSL_FUNC_signature_sign_fn *)opf->function; }
end;

function OSSL_FUNC_signature_sign_message_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_message_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_sign_message_init"');

{Error: Line 825: Syntax Error parsing " return (OSSL_FUNC_signature_sign_message_init_fn *)opf->function; "

 return (OSSL_FUNC_signature_sign_message_init_fn *)opf->function; }
end;

function OSSL_FUNC_signature_sign_message_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_message_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_sign_message_update"');

{Error: Line 827: Syntax Error parsing " return (OSSL_FUNC_signature_sign_message_update_fn *)opf->function; "

 return (OSSL_FUNC_signature_sign_message_update_fn *)opf->function; }
end;

function OSSL_FUNC_signature_sign_message_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_sign_message_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_sign_message_final"');

{Error: Line 829: Syntax Error parsing " return (OSSL_FUNC_signature_sign_message_final_fn *)opf->function; "

 return (OSSL_FUNC_signature_sign_message_final_fn *)opf->function; }
end;

function OSSL_FUNC_signature_verify_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_verify_init"');

{Error: Line 832: Syntax Error parsing " return (OSSL_FUNC_signature_verify_init_fn *)opf->function; "

 return (OSSL_FUNC_signature_verify_init_fn *)opf->function; }
end;

function OSSL_FUNC_signature_verify(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_verify"');

{Error: Line 833: Syntax Error parsing " return (OSSL_FUNC_signature_verify_fn *)opf->function; "

 return (OSSL_FUNC_signature_verify_fn *)opf->function; }
end;

function OSSL_FUNC_signature_verify_message_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_message_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_verify_message_init"');

{Error: Line 834: Syntax Error parsing " return (OSSL_FUNC_signature_verify_message_init_fn *)opf->function; "

 return (OSSL_FUNC_signature_verify_message_init_fn *)opf->function; }
end;

function OSSL_FUNC_signature_verify_message_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_message_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_verify_message_update"');

{Error: Line 836: Syntax Error parsing " return (OSSL_FUNC_signature_verify_message_update_fn *)opf->function; "

 return (OSSL_FUNC_signature_verify_message_update_fn *)opf->function; }
end;

function OSSL_FUNC_signature_verify_message_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_message_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_verify_message_final"');

{Error: Line 842: Syntax Error parsing " return (OSSL_FUNC_signature_verify_message_final_fn *)opf->function; "

 return (OSSL_FUNC_signature_verify_message_final_fn *)opf->function; }
end;

function OSSL_FUNC_signature_verify_recover_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_recover_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_verify_recover_init"');

{Error: Line 843: Syntax Error parsing " return (OSSL_FUNC_signature_verify_recover_init_fn *)opf->function; "

 return (OSSL_FUNC_signature_verify_recover_init_fn *)opf->function; }
end;

function OSSL_FUNC_signature_verify_recover(opf: POSSL_DISPATCH): POSSL_FUNC_signature_verify_recover_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_verify_recover"');

{Error: Line 845: Syntax Error parsing " return (OSSL_FUNC_signature_verify_recover_fn *)opf->function; "

 return (OSSL_FUNC_signature_verify_recover_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_sign_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_sign_init"');

{Error: Line 848: Syntax Error parsing " return (OSSL_FUNC_signature_digest_sign_init_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_sign_init_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_sign_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_sign_update"');

{Error: Line 851: Syntax Error parsing " return (OSSL_FUNC_signature_digest_sign_update_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_sign_update_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_sign_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_sign_final"');

{Error: Line 853: Syntax Error parsing " return (OSSL_FUNC_signature_digest_sign_final_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_sign_final_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_sign(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_sign_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_sign"');

{Error: Line 856: Syntax Error parsing " return (OSSL_FUNC_signature_digest_sign_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_sign_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_verify_init(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_verify_init"');

{Error: Line 859: Syntax Error parsing " return (OSSL_FUNC_signature_digest_verify_init_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_verify_init_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_verify_update(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_update_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_verify_update"');

{Error: Line 862: Syntax Error parsing " return (OSSL_FUNC_signature_digest_verify_update_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_verify_update_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_verify_final(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_final_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_verify_final"');

{Error: Line 864: Syntax Error parsing " return (OSSL_FUNC_signature_digest_verify_final_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_verify_final_fn *)opf->function; }
end;

function OSSL_FUNC_signature_digest_verify(opf: POSSL_DISPATCH): POSSL_FUNC_signature_digest_verify_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_digest_verify"');

{Error: Line 866: Syntax Error parsing " return (OSSL_FUNC_signature_digest_verify_fn *)opf->function; "

 return (OSSL_FUNC_signature_digest_verify_fn *)opf->function; }
end;

function OSSL_FUNC_signature_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_signature_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_freectx"');

{Error: Line 869: Syntax Error parsing " return (OSSL_FUNC_signature_freectx_fn *)opf->function; "

 return (OSSL_FUNC_signature_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_signature_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_signature_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_dupctx"');

{Error: Line 870: Syntax Error parsing " return (OSSL_FUNC_signature_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_signature_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_signature_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_get_ctx_params"');

{Error: Line 871: Syntax Error parsing " return (OSSL_FUNC_signature_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_gettable_ctx_params"');

{Error: Line 873: Syntax Error parsing " return (OSSL_FUNC_signature_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_set_ctx_params"');

{Error: Line 875: Syntax Error parsing " return (OSSL_FUNC_signature_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_settable_ctx_params"');

{Error: Line 877: Syntax Error parsing " return (OSSL_FUNC_signature_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_get_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_get_ctx_md_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_get_ctx_md_params"');

{Error: Line 879: Syntax Error parsing " return (OSSL_FUNC_signature_get_ctx_md_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_get_ctx_md_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_gettable_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_gettable_ctx_md_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_gettable_ctx_md_params"');

{Error: Line 881: Syntax Error parsing " return (OSSL_FUNC_signature_gettable_ctx_md_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_gettable_ctx_md_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_set_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_set_ctx_md_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_set_ctx_md_params"');

{Error: Line 883: Syntax Error parsing " return (OSSL_FUNC_signature_set_ctx_md_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_set_ctx_md_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_settable_ctx_md_params(opf: POSSL_DISPATCH): POSSL_FUNC_signature_settable_ctx_md_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_settable_ctx_md_params"');

{Error: Line 885: Syntax Error parsing " return (OSSL_FUNC_signature_settable_ctx_md_params_fn *)opf->function; "

 return (OSSL_FUNC_signature_settable_ctx_md_params_fn *)opf->function; }
end;

function OSSL_FUNC_signature_query_key_types(opf: POSSL_DISPATCH): POSSL_FUNC_signature_query_key_types_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_signature_query_key_types"');

{Error: Line 887: Syntax Error parsing " return (OSSL_FUNC_signature_query_key_types_fn *)opf->function; "

 return (OSSL_FUNC_signature_query_key_types_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_newctx"');

{Error: Line 903: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_newctx_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_encrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_encrypt_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_encrypt_init"');

{Error: Line 904: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_encrypt_init_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_encrypt_init_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_encrypt(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_encrypt_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_encrypt"');

{Error: Line 905: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_encrypt_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_encrypt_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_decrypt_init(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_decrypt_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_decrypt_init"');

{Error: Line 906: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_decrypt_init_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_decrypt_init_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_decrypt(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_decrypt_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_decrypt"');

{Error: Line 907: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_decrypt_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_decrypt_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_freectx"');

{Error: Line 908: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_freectx_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_dupctx"');

{Error: Line 909: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_get_ctx_params"');

{Error: Line 910: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_gettable_ctx_params"');

{Error: Line 912: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_set_ctx_params"');

{Error: Line 914: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_asym_cipher_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_asym_cipher_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_asym_cipher_settable_ctx_params"');

{Error: Line 916: Syntax Error parsing " return (OSSL_FUNC_asym_cipher_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_asym_cipher_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kem_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_kem_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_newctx"');

{Error: Line 934: Syntax Error parsing " return (OSSL_FUNC_kem_newctx_fn *)opf->function; "

 return (OSSL_FUNC_kem_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_kem_encapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_encapsulate_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_encapsulate_init"');

{Error: Line 935: Syntax Error parsing " return (OSSL_FUNC_kem_encapsulate_init_fn *)opf->function; "

 return (OSSL_FUNC_kem_encapsulate_init_fn *)opf->function; }
end;

function OSSL_FUNC_kem_auth_encapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_auth_encapsulate_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_auth_encapsulate_init"');

{Error: Line 936: Syntax Error parsing " return (OSSL_FUNC_kem_auth_encapsulate_init_fn *)opf->function; "

 return (OSSL_FUNC_kem_auth_encapsulate_init_fn *)opf->function; }
end;

function OSSL_FUNC_kem_encapsulate(opf: POSSL_DISPATCH): POSSL_FUNC_kem_encapsulate_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_encapsulate"');

{Error: Line 937: Syntax Error parsing " return (OSSL_FUNC_kem_encapsulate_fn *)opf->function; "

 return (OSSL_FUNC_kem_encapsulate_fn *)opf->function; }
end;

function OSSL_FUNC_kem_decapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_decapsulate_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_decapsulate_init"');

{Error: Line 938: Syntax Error parsing " return (OSSL_FUNC_kem_decapsulate_init_fn *)opf->function; "

 return (OSSL_FUNC_kem_decapsulate_init_fn *)opf->function; }
end;

function OSSL_FUNC_kem_auth_decapsulate_init(opf: POSSL_DISPATCH): POSSL_FUNC_kem_auth_decapsulate_init_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_auth_decapsulate_init"');

{Error: Line 939: Syntax Error parsing " return (OSSL_FUNC_kem_auth_decapsulate_init_fn *)opf->function; "

 return (OSSL_FUNC_kem_auth_decapsulate_init_fn *)opf->function; }
end;

function OSSL_FUNC_kem_decapsulate(opf: POSSL_DISPATCH): POSSL_FUNC_kem_decapsulate_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_decapsulate"');

{Error: Line 940: Syntax Error parsing " return (OSSL_FUNC_kem_decapsulate_fn *)opf->function; "

 return (OSSL_FUNC_kem_decapsulate_fn *)opf->function; }
end;

function OSSL_FUNC_kem_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_kem_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_freectx"');

{Error: Line 941: Syntax Error parsing " return (OSSL_FUNC_kem_freectx_fn *)opf->function; "

 return (OSSL_FUNC_kem_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_kem_dupctx(opf: POSSL_DISPATCH): POSSL_FUNC_kem_dupctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_dupctx"');

{Error: Line 942: Syntax Error parsing " return (OSSL_FUNC_kem_dupctx_fn *)opf->function; "

 return (OSSL_FUNC_kem_dupctx_fn *)opf->function; }
end;

function OSSL_FUNC_kem_get_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_get_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_get_ctx_params"');

{Error: Line 943: Syntax Error parsing " return (OSSL_FUNC_kem_get_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kem_get_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kem_gettable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_gettable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_gettable_ctx_params"');

{Error: Line 944: Syntax Error parsing " return (OSSL_FUNC_kem_gettable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kem_gettable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kem_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_set_ctx_params"');

{Error: Line 946: Syntax Error parsing " return (OSSL_FUNC_kem_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kem_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_kem_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_kem_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_kem_settable_ctx_params"');

{Error: Line 948: Syntax Error parsing " return (OSSL_FUNC_kem_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_kem_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_newctx"');

{Error: Line 962: Syntax Error parsing " return (OSSL_FUNC_encoder_newctx_fn *)opf->function; "

 return (OSSL_FUNC_encoder_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_freectx"');

{Error: Line 963: Syntax Error parsing " return (OSSL_FUNC_encoder_freectx_fn *)opf->function; "

 return (OSSL_FUNC_encoder_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_get_params"');

{Error: Line 964: Syntax Error parsing " return (OSSL_FUNC_encoder_get_params_fn *)opf->function; "

 return (OSSL_FUNC_encoder_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_gettable_params"');

{Error: Line 965: Syntax Error parsing " return (OSSL_FUNC_encoder_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_encoder_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_set_ctx_params"');

{Error: Line 967: Syntax Error parsing " return (OSSL_FUNC_encoder_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_encoder_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_settable_ctx_params"');

{Error: Line 969: Syntax Error parsing " return (OSSL_FUNC_encoder_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_encoder_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_does_selection(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_does_selection_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_does_selection"');

{Error: Line 972: Syntax Error parsing " return (OSSL_FUNC_encoder_does_selection_fn *)opf->function; "

 return (OSSL_FUNC_encoder_does_selection_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_encode(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_encode_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_encode"');

{Error: Line 974: Syntax Error parsing " return (OSSL_FUNC_encoder_encode_fn *)opf->function; "

 return (OSSL_FUNC_encoder_encode_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_import_object(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_import_object_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_import_object"');

{Error: Line 980: Syntax Error parsing " return (OSSL_FUNC_encoder_import_object_fn *)opf->function; "

 return (OSSL_FUNC_encoder_import_object_fn *)opf->function; }
end;

function OSSL_FUNC_encoder_free_object(opf: POSSL_DISPATCH): POSSL_FUNC_encoder_free_object_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_encoder_free_object"');

{Error: Line 982: Syntax Error parsing " return (OSSL_FUNC_encoder_free_object_fn *)opf->function; "

 return (OSSL_FUNC_encoder_free_object_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_newctx(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_newctx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_newctx"');

{Error: Line 993: Syntax Error parsing " return (OSSL_FUNC_decoder_newctx_fn *)opf->function; "

 return (OSSL_FUNC_decoder_newctx_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_freectx(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_freectx_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_freectx"');

{Error: Line 994: Syntax Error parsing " return (OSSL_FUNC_decoder_freectx_fn *)opf->function; "

 return (OSSL_FUNC_decoder_freectx_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_get_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_get_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_get_params"');

{Error: Line 995: Syntax Error parsing " return (OSSL_FUNC_decoder_get_params_fn *)opf->function; "

 return (OSSL_FUNC_decoder_get_params_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_gettable_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_gettable_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_gettable_params"');

{Error: Line 996: Syntax Error parsing " return (OSSL_FUNC_decoder_gettable_params_fn *)opf->function; "

 return (OSSL_FUNC_decoder_gettable_params_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_set_ctx_params"');

{Error: Line 998: Syntax Error parsing " return (OSSL_FUNC_decoder_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_decoder_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_settable_ctx_params"');

{Error: Line 1000: Syntax Error parsing " return (OSSL_FUNC_decoder_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_decoder_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_does_selection(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_does_selection_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_does_selection"');

{Error: Line 1003: Syntax Error parsing " return (OSSL_FUNC_decoder_does_selection_fn *)opf->function; "

 return (OSSL_FUNC_decoder_does_selection_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_decode(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_decode_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_decode"');

{Error: Line 1005: Syntax Error parsing " return (OSSL_FUNC_decoder_decode_fn *)opf->function; "

 return (OSSL_FUNC_decoder_decode_fn *)opf->function; }
end;

function OSSL_FUNC_decoder_export_object(opf: POSSL_DISPATCH): POSSL_FUNC_decoder_export_object_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_decoder_export_object"');

{Error: Line 1009: Syntax Error parsing " return (OSSL_FUNC_decoder_export_object_fn *)opf->function; "

 return (OSSL_FUNC_decoder_export_object_fn *)opf->function; }
end;

function OSSL_FUNC_store_open(opf: POSSL_DISPATCH): POSSL_FUNC_store_open_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_open"');

{Error: Line 1035: Syntax Error parsing " return (OSSL_FUNC_store_open_fn *)opf->function; "

 return (OSSL_FUNC_store_open_fn *)opf->function; }
end;

function OSSL_FUNC_store_attach(opf: POSSL_DISPATCH): POSSL_FUNC_store_attach_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_attach"');

{Error: Line 1036: Syntax Error parsing " return (OSSL_FUNC_store_attach_fn *)opf->function; "

 return (OSSL_FUNC_store_attach_fn *)opf->function; }
end;

function OSSL_FUNC_store_settable_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_store_settable_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_settable_ctx_params"');

{Error: Line 1037: Syntax Error parsing " return (OSSL_FUNC_store_settable_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_store_settable_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_store_set_ctx_params(opf: POSSL_DISPATCH): POSSL_FUNC_store_set_ctx_params_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_set_ctx_params"');

{Error: Line 1039: Syntax Error parsing " return (OSSL_FUNC_store_set_ctx_params_fn *)opf->function; "

 return (OSSL_FUNC_store_set_ctx_params_fn *)opf->function; }
end;

function OSSL_FUNC_store_load(opf: POSSL_DISPATCH): POSSL_FUNC_store_load_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_load"');

{Error: Line 1041: Syntax Error parsing " return (OSSL_FUNC_store_load_fn *)opf->function; "

 return (OSSL_FUNC_store_load_fn *)opf->function; }
end;

function OSSL_FUNC_store_eof(opf: POSSL_DISPATCH): POSSL_FUNC_store_eof_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_eof"');

{Error: Line 1045: Syntax Error parsing " return (OSSL_FUNC_store_eof_fn *)opf->function; "

 return (OSSL_FUNC_store_eof_fn *)opf->function; }
end;

function OSSL_FUNC_store_close(opf: POSSL_DISPATCH): POSSL_FUNC_store_close_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_close"');

{Error: Line 1046: Syntax Error parsing " return (OSSL_FUNC_store_close_fn *)opf->function; "

 return (OSSL_FUNC_store_close_fn *)opf->function; }
end;

function OSSL_FUNC_store_export_object(opf: POSSL_DISPATCH): POSSL_FUNC_store_export_object_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_export_object"');

{Error: Line 1047: Syntax Error parsing " return (OSSL_FUNC_store_export_object_fn *)opf->function; "

 return (OSSL_FUNC_store_export_object_fn *)opf->function; }
end;

function OSSL_FUNC_store_delete(opf: POSSL_DISPATCH): POSSL_FUNC_store_delete_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_delete"');

{Error: Line 1050: Syntax Error parsing " return (OSSL_FUNC_store_delete_fn *)opf->function; "

 return (OSSL_FUNC_store_delete_fn *)opf->function; }
end;

function OSSL_FUNC_store_open_ex(opf: POSSL_DISPATCH): POSSL_FUNC_store_open_ex_fn{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "OSSL_FUNC_store_open_ex"');

{Error: Line 1053: Syntax Error parsing " return (OSSL_FUNC_store_open_ex_fn *)opf->function; "

 return (OSSL_FUNC_store_open_ex_fn *)opf->function; }
end;

{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
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



