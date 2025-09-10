(* This unit was generated from the source file crypto.h2pas 
It should not be modified directly. All changes should be made to crypto.h2pas
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


unit OpenSSL_crypto;


interface

// Headers for OpenSSL 1.1.1
// crypto.h

{$J+}
{$J+}

uses
  OpenSSLAPI,
  OpenSSL_bio,
  OpenSSL_ossl_typ,
  OpenSSL_evp,
  OpenSSL_provider,
  Types;

{$MINENUMSIZE 4}

const
  CRYPTO_MEM_CHECK_OFF = $0;   //* Control only */
  CRYPTO_MEM_CHECK_ON = $1;   //* Control and mode bit */
  CRYPTO_MEM_CHECK_ENABLE = $2;   //* Control and mode bit */
  CRYPTO_MEM_CHECK_DISABLE = $3;   //* Control only */

  CRYPTO_EX_INDEX_SSL = 0;
  CRYPTO_EX_INDEX_SSL_CTX = 1;
  CRYPTO_EX_INDEX_SSL_SESSION = 2;
  CRYPTO_EX_INDEX_X509 = 3;
  CRYPTO_EX_INDEX_X509_STORE = 4;
  CRYPTO_EX_INDEX_X509_STORE_CTX = 5;
  CRYPTO_EX_INDEX_DH = 6;
  CRYPTO_EX_INDEX_DSA = 7;
  CRYPTO_EX_INDEX_EC_KEY = 8;
  CRYPTO_EX_INDEX_RSA = 9;
  CRYPTO_EX_INDEX_ENGINE = 10;
  CRYPTO_EX_INDEX_UI = 11;
  CRYPTO_EX_INDEX_BIO = 12;
  CRYPTO_EX_INDEX_APP = 13;
  CRYPTO_EX_INDEX_UI_METHOD = 14;
  CRYPTO_EX_INDEX_DRBG = 15;
  CRYPTO_EX_INDEX__COUNT = 16;
  
  // Added _CONST to prevent nameclashes
  OPENSSL_VERSION_CONST = 0;
  OPENSSL_CFLAGS = 1;
  OPENSSL_BUILT_ON = 2;
  OPENSSL_PLATFORM = 3;
  OPENSSL_DIR = 4;
  OPENSSL_ENGINES_DIR = 5;
  SSLEAY_VERSION_CONST = OPENSSL_VERSION_CONST;

  (*
   * These defines where used in combination with the old locking callbacks,
   * they are not called anymore, but old code that's not called might still
   * use them.
   *)
  CRYPTO_LOCK = 1;
  CRYPTO_UNLOCK = 2;
  CRYPTO_READ = 4;
  CRYPTO_WRITE = 8;

  (* Standard initialisation options *)
  OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS = TOpenSSL_C_Long($00000001);
  OPENSSL_INIT_LOAD_CRYPTO_STRINGS = TOpenSSL_C_Long($00000002);
  OPENSSL_INIT_ADD_ALL_CIPHERS = TOpenSSL_C_Long($00000004);
  OPENSSL_INIT_ADD_ALL_DIGESTS = TOpenSSL_C_Long($00000008);
  OPENSSL_INIT_NO_ADD_ALL_CIPHERS = TOpenSSL_C_Long($00000010);
  OPENSSL_INIT_NO_ADD_ALL_DIGESTS = TOpenSSL_C_Long($00000020);
  OPENSSL_INIT_LOAD_CONFIG = TOpenSSL_C_Long($00000040);
  OPENSSL_INIT_NO_LOAD_CONFIG = TOpenSSL_C_Long($00000080);
  OPENSSL_INIT_ASYNC = TOpenSSL_C_Long($00000100);
  OPENSSL_INIT_ENGINE_RDRAND = TOpenSSL_C_Long($00000200);
  OPENSSL_INIT_ENGINE_DYNAMIC = TOpenSSL_C_Long($00000400);
  OPENSSL_INIT_ENGINE_OPENSSL = TOpenSSL_C_Long($00000800);
  OPENSSL_INIT_ENGINE_CRYPTODEV = TOpenSSL_C_Long($00001000);
  OPENSSL_INIT_ENGINE_CAPI = TOpenSSL_C_Long($00002000);
  OPENSSL_INIT_ENGINE_PADLOCK = TOpenSSL_C_Long($00004000);
  OPENSSL_INIT_ENGINE_AFALG = TOpenSSL_C_Long($00008000);
  (* OPENSSL_INIT_ZLIB = TOpenSSL_C_Long($00010000); *)
  OPENSSL_INIT_ATFORK = TOpenSSL_C_Long(00020000);
  (* OPENSSL_INIT_BASE_ONLY = TOpenSSL_C_Long(00040000); *)
  OPENSSL_INIT_NO_ATEXIT = TOpenSSL_C_Long(00080000);
  (* OPENSSL_INIT flag range 0xfff00000 reserved for OPENSSL_init_ssl() *)
  (* Max OPENSSL_INIT flag value is 0x80000000 *)

  (* openssl and dasync not counted as builtin *)
  OPENSSL_INIT_ENGINE_ALL_BUILTIN = OPENSSL_INIT_ENGINE_RDRAND
    or OPENSSL_INIT_ENGINE_DYNAMIC or OPENSSL_INIT_ENGINE_CRYPTODEV
    or OPENSSL_INIT_ENGINE_CAPI or OPENSSL_INIT_ENGINE_PADLOCK;

  CRYPTO_ONCE_STATIC_INIT = 0;

type
  CRYPTO_THREADID = record {1.0.x only}
    ptr : Pointer;
    val : TOpenSSL_C_ULONG;
  end;
  PCRYPTO_THREADID = ^CRYPTO_THREADID;
  CRYPTO_RWLOCK = type Pointer;
  PCRYPTO_RWLOCK = ^CRYPTO_RWLOCK;
  //crypto_ex_data_st = record
  //  sk: PStackOfVoid;
  //end;
  //DEFINE_STACK_OF(void)

  Tthreadid_func = procedure (id : PCRYPTO_THREADID) cdecl;    


  // CRYPTO_EX_new = procedure(parent: Pointer; ptr: Pointer; CRYPTO_EX_DATA *ad; idx: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; argp: Pointer);
  //  CRYPTO_EX_free = procedure(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
  //                             int idx, long argl, void *argp);
  //typedef int CRYPTO_EX_dup (CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
  //                           void *from_d, int idx, long argl, void *argp);
  //__owur int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
  //                            CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
  //                            CRYPTO_EX_free *free_func);

  CRYPTO_mem_leaks_cb_cb = function(const str: PAnsiChar; len: TOpenSSL_C_SIZET; u: Pointer): TOpenSSL_C_INT; cdecl;
  CRYPTO_THREAD_run_once_init = procedure; cdecl;

  CRYPTO_THREAD_LOCAL = type DWORD;
  PCRYPTO_THREAD_LOCAL = ^CRYPTO_THREAD_LOCAL;
  CRYPTO_THREAD_ID = type DWORD;
  CRYPTO_ONCE = type TOpenSSL_C_LONG;
  PCRYPTO_ONCE = ^CRYPTO_ONCE;

  CRYPTO_set_mem_functions_m = function(size: TOpenSSL_C_SIZET; const filename: PAnsiChar; linenumber: TOpenSSL_C_INT): Pointer; cdecl;
  CRYPTO_set_mem_functions_r = function(buffer: Pointer; size: TOpenSSL_C_SIZET; const filename: PAnsiChar; linenumber: TOpenSSL_C_INT): Pointer; cdecl;
  CRYPTO_set_mem_functions_f = procedure(buffer: Pointer; const filename: PAnsiChar; const linenumber: TOpenSSL_C_INT); cdecl;
  TIdSslIdCallback = function: TOpenSSL_C_ULONG; cdecl;
  TIdSslLockingCallback = procedure (mode, n : TOpenSSL_C_INT; Afile : PAnsiChar; line : TOpenSSL_C_INT); cdecl;



procedure SetLegacyCallbacks;
procedure RemoveLegacyCallbacks;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CRYPTO_THREAD_lock_new}
{$EXTERNALSYM CRYPTO_THREAD_read_lock}
{$EXTERNALSYM CRYPTO_THREAD_write_lock}
{$EXTERNALSYM CRYPTO_THREAD_unlock}
{$EXTERNALSYM CRYPTO_THREAD_lock_free}
{$EXTERNALSYM CRYPTO_atomic_add}
{$EXTERNALSYM OPENSSL_strlcpy}
{$EXTERNALSYM OPENSSL_strlcat}
{$EXTERNALSYM OPENSSL_strnlen}
{$EXTERNALSYM OPENSSL_buf2hexstr}
{$EXTERNALSYM OPENSSL_hexstr2buf}
{$EXTERNALSYM OPENSSL_hexchar2int}
{$EXTERNALSYM OpenSSL_version_num}
{$EXTERNALSYM OpenSSL_version}
{$EXTERNALSYM OPENSSL_issetugid}
{$EXTERNALSYM CRYPTO_new_ex_data}
{$EXTERNALSYM CRYPTO_dup_ex_data}
{$EXTERNALSYM CRYPTO_free_ex_data}
{$EXTERNALSYM CRYPTO_set_ex_data}
{$EXTERNALSYM CRYPTO_get_ex_data}
{$EXTERNALSYM CRYPTO_set_mem_functions}
{$EXTERNALSYM CRYPTO_malloc}
{$EXTERNALSYM CRYPTO_zalloc}
{$EXTERNALSYM CRYPTO_memdup}
{$EXTERNALSYM CRYPTO_strdup}
{$EXTERNALSYM CRYPTO_strndup}
{$EXTERNALSYM CRYPTO_free}
{$EXTERNALSYM CRYPTO_clear_free}
{$EXTERNALSYM CRYPTO_realloc}
{$EXTERNALSYM CRYPTO_clear_realloc}
{$EXTERNALSYM CRYPTO_secure_malloc_init}
{$EXTERNALSYM CRYPTO_secure_malloc_done}
{$EXTERNALSYM CRYPTO_secure_malloc}
{$EXTERNALSYM CRYPTO_secure_zalloc}
{$EXTERNALSYM CRYPTO_secure_free}
{$EXTERNALSYM CRYPTO_secure_clear_free}
{$EXTERNALSYM CRYPTO_secure_allocated}
{$EXTERNALSYM CRYPTO_secure_malloc_initialized}
{$EXTERNALSYM CRYPTO_secure_actual_size}
{$EXTERNALSYM CRYPTO_secure_used}
{$EXTERNALSYM OPENSSL_cleanse}
{$EXTERNALSYM OPENSSL_isservice}
{$EXTERNALSYM OPENSSL_init}
{$EXTERNALSYM CRYPTO_memcmp}
{$EXTERNALSYM OPENSSL_cleanup}
{$EXTERNALSYM OPENSSL_init_crypto}
{$EXTERNALSYM OPENSSL_thread_stop}
{$EXTERNALSYM OPENSSL_INIT_new}
{$EXTERNALSYM OPENSSL_INIT_free}
{$EXTERNALSYM CRYPTO_THREAD_run_once}
{$EXTERNALSYM CRYPTO_THREAD_get_local}
{$EXTERNALSYM CRYPTO_THREAD_set_local}
{$EXTERNALSYM CRYPTO_THREAD_cleanup_local}
{$EXTERNALSYM CRYPTO_THREAD_get_current_id}
{$EXTERNALSYM CRYPTO_THREAD_compare_id}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl; external CLibCrypto;
function CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK); cdecl; external CLibCrypto;
function CRYPTO_atomic_add(val: POpenSSL_C_INT; amount: TOpenSSL_C_INT; ret: POpenSSL_C_INT; lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OPENSSL_strlcpy(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OPENSSL_strlcat(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OPENSSL_strnlen(const str: PAnsiChar; maxlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OPENSSL_buf2hexstr(const buffer: PByte; len: TOpenSSL_C_LONG): PAnsiChar; cdecl; external CLibCrypto;
function OPENSSL_hexstr2buf(const str: PAnsiChar; len: POpenSSL_C_LONG): PByte; cdecl; external CLibCrypto;
function OPENSSL_hexchar2int(c: Byte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OpenSSL_version_num: TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function OpenSSL_version(type_: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OPENSSL_issetugid: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_new_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_dup_ex_data(class_index: TOpenSSL_C_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CRYPTO_free_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl; external CLibCrypto;
function CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT; val: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_get_ex_data(const ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_set_mem_functions(m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_memdup(const str: Pointer; siz: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_strdup(const str: PAnsiChar; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function CRYPTO_strndup(const str: PAnsiChar; s: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
procedure CRYPTO_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CRYPTO_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function CRYPTO_realloc(addr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc_init(sz: TOpenSSL_C_SIZET; minsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc_done: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function CRYPTO_secure_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
procedure CRYPTO_secure_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CRYPTO_secure_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function CRYPTO_secure_allocated(const ptr: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_malloc_initialized: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function CRYPTO_secure_used: TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
procedure OPENSSL_cleanse(ptr: Pointer; len: TOpenSSL_C_SIZET); cdecl; external CLibCrypto;
function OPENSSL_isservice: TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_init; cdecl; external CLibCrypto;
function CRYPTO_memcmp(const in_a: Pointer; const in_b: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_cleanup; cdecl; external CLibCrypto;
function OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_thread_stop; cdecl; external CLibCrypto;
function OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl; external CLibCrypto;
procedure OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS); cdecl; external CLibCrypto;
function CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl; external CLibCrypto;
function CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CRYPTO_THREAD_get_current_id: CRYPTO_THREAD_ID; cdecl; external CLibCrypto;
function CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TOpenSSL_C_INT; cdecl; external CLibCrypto;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
procedure OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); {removed 1.0.0}
procedure OPENSSL_free(addr: Pointer); {removed 1.0.0}
function OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_strdup(const str: PAnsiChar): PAnsiChar; {removed 1.0.0}
function OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; {removed 1.0.0}
function OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
function OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer; {removed 1.0.0}
procedure OPENSSL_secure_free(addr: Pointer); {removed 1.0.0}
procedure OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); {removed 1.0.0}
function OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; {removed 1.0.0}
function FIPS_mode: TOpenSSL_C_INT; {removed 3.0.0}
function FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  CRYPTO_THREAD_lock_new: function : PCRYPTO_RWLOCK; cdecl = nil;
  CRYPTO_THREAD_read_lock: function (lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_THREAD_write_lock: function (lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_THREAD_unlock: function (lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_THREAD_lock_free: procedure (lock: PCRYPTO_RWLOCK); cdecl = nil;
  CRYPTO_atomic_add: function (val: POpenSSL_C_INT; amount: TOpenSSL_C_INT; ret: POpenSSL_C_INT; lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl = nil;
  OPENSSL_strlcpy: function (dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  OPENSSL_strlcat: function (dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  OPENSSL_strnlen: function (const str: PAnsiChar; maxlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  OPENSSL_buf2hexstr: function (const buffer: PByte; len: TOpenSSL_C_LONG): PAnsiChar; cdecl = nil;
  OPENSSL_hexstr2buf: function (const str: PAnsiChar; len: POpenSSL_C_LONG): PByte; cdecl = nil;
  OPENSSL_hexchar2int: function (c: Byte): TOpenSSL_C_INT; cdecl = nil;
  OpenSSL_version_num: function : TOpenSSL_C_ULONG; cdecl = nil;
  OpenSSL_version: function (type_: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  OPENSSL_issetugid: function : TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_new_ex_data: function (class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_dup_ex_data: function (class_index: TOpenSSL_C_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_free_ex_data: procedure (class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl = nil;
  CRYPTO_set_ex_data: function (ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT; val: Pointer): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_get_ex_data: function (const ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_set_mem_functions: function (m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_malloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_zalloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_memdup: function (const str: Pointer; siz: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_strdup: function (const str: PAnsiChar; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  CRYPTO_strndup: function (const str: PAnsiChar; s: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  CRYPTO_free: procedure (ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = nil;
  CRYPTO_clear_free: procedure (ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = nil;
  CRYPTO_realloc: function (addr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_clear_realloc: function (addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_secure_malloc_init: function (sz: TOpenSSL_C_SIZET; minsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_secure_malloc_done: function : TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_secure_malloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_secure_zalloc: function (num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl = nil;
  CRYPTO_secure_free: procedure (ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = nil;
  CRYPTO_secure_clear_free: procedure (ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = nil;
  CRYPTO_secure_allocated: function (const ptr: Pointer): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_secure_malloc_initialized: function : TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_secure_actual_size: function (ptr: Pointer): TOpenSSL_C_SIZET; cdecl = nil;
  CRYPTO_secure_used: function : TOpenSSL_C_SIZET; cdecl = nil;
  OPENSSL_cleanse: procedure (ptr: Pointer; len: TOpenSSL_C_SIZET); cdecl = nil;
  OPENSSL_isservice: function : TOpenSSL_C_INT; cdecl = nil;
  OPENSSL_init: procedure ; cdecl = nil;
  CRYPTO_memcmp: function (const in_a: Pointer; const in_b: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  OPENSSL_cleanup: procedure ; cdecl = nil;
  OPENSSL_init_crypto: function (opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl = nil;
  OPENSSL_thread_stop: procedure ; cdecl = nil;
  OPENSSL_INIT_new: function : POPENSSL_INIT_SETTINGS; cdecl = nil;
  OPENSSL_INIT_free: procedure (settings: POPENSSL_INIT_SETTINGS); cdecl = nil;
  CRYPTO_THREAD_run_once: function (once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_THREAD_get_local: function (key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl = nil;
  CRYPTO_THREAD_set_local: function (key: PCRYPTO_THREAD_LOCAL; val: Pointer): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_THREAD_cleanup_local: function (key: PCRYPTO_THREAD_LOCAL): TOpenSSL_C_INT; cdecl = nil;
  CRYPTO_THREAD_get_current_id: function : CRYPTO_THREAD_ID; cdecl = nil;
  CRYPTO_THREAD_compare_id: function (a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TOpenSSL_C_INT; cdecl = nil;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  OPENSSL_malloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  OPENSSL_zalloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  OPENSSL_realloc: function (addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  OPENSSL_clear_realloc: function (addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  OPENSSL_clear_free: procedure (addr: Pointer; num: TOpenSSL_C_SIZET); cdecl = nil; {removed 1.0.0}
  OPENSSL_free: procedure (addr: Pointer); cdecl = nil; {removed 1.0.0}
  OPENSSL_memdup: function (const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  OPENSSL_strdup: function (const str: PAnsiChar): PAnsiChar; cdecl = nil; {removed 1.0.0}
  OPENSSL_strndup: function (const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; cdecl = nil; {removed 1.0.0}
  OPENSSL_secure_malloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  OPENSSL_secure_zalloc: function (num: TOpenSSL_C_SIZET): Pointer; cdecl = nil; {removed 1.0.0}
  OPENSSL_secure_free: procedure (addr: Pointer); cdecl = nil; {removed 1.0.0}
  OPENSSL_secure_clear_free: procedure (addr: Pointer; num: TOpenSSL_C_SIZET); cdecl = nil; {removed 1.0.0}
  OPENSSL_secure_actual_size: function (ptr: Pointer): TOpenSSL_C_SIZET; cdecl = nil; {removed 1.0.0}
  FIPS_mode: function : TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  FIPS_mode_set: function (r: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  OPENSSL_malloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_zalloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_realloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_clear_realloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_clear_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_memdup_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_strdup_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_strndup_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_malloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_zalloc_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_clear_free_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  OPENSSL_secure_actual_size_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  CRYPTO_THREAD_lock_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_read_lock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_write_lock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_unlock_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_lock_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_atomic_add_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_mem_ctrl_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  OPENSSL_strlcpy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_strlcat_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_strnlen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_buf2hexstr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_hexstr2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_hexchar2int_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OpenSSL_version_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OpenSSL_version_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_num_locks_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_set_locking_callback_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_THREADID_set_numeric_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_THREADID_set_callback_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_set_id_callback_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  CRYPTO_set_mem_debug_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_set_mem_debug_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  CRYPTO_zalloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_memdup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_strndup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_clear_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_clear_realloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_done_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_zalloc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_clear_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_allocated_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_malloc_initialized_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_actual_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_secure_used_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  FIPS_mode_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  FIPS_mode_set_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  OPENSSL_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_init_crypto_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_thread_stop_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_INIT_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OPENSSL_INIT_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_run_once_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_get_local_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_set_local_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_cleanup_local_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_get_current_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  CRYPTO_THREAD_compare_id_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSLeay_version_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  SSLeay_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}


implementation

uses SyncObjs,  Sysutils
   {$IFNDEF FPC}
     {$IFDEF WINDOWS}
       ,Windows
     {$ELSE}
       ,Posix.Pthread
     {$ENDIF}
   {$ENDIF},
Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

// OPENSSL_FILE = __FILE__ = C preprocessor macro
// OPENSSL_LINE = __LINE__ = C preprocessor macro
// FPC hase an equivalent with {$I %FILE%} and {$I %LINENUM%}, see https://www.freepascal.org/docs-html/prog/progsu41.html#x47-460001.1.41
// Delphi has nothing :(

//# define OPENSSL_malloc(num) CRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$J+}
var
  CRYPTO_mem_ctrl: function (mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  CRYPTO_num_locks: function : TOpenSSL_C_INT; cdecl = nil; {removed 1.1.0}
  CRYPTO_set_locking_callback: procedure (func: TIdSslLockingCallback); cdecl = nil; {removed 1.1.0}
  CRYPTO_THREADID_set_numeric: procedure (id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl = nil; {removed 1.1.0}
  CRYPTO_THREADID_set_callback: procedure (threadid_func: Tthreadid_func); cdecl = nil; {removed 1.1.0}
  CRYPTO_set_id_callback: procedure (func: TIdSslIdCallback); cdecl = nil; {removed 1.1.0}
  CRYPTO_set_mem_debug: function (flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  SSLeay_version: function (type_ : TOpenSSL_C_INT): PAnsiChar; cdecl = nil; {removed 1.1.0}
  SSLeay: function : TOpenSSL_C_ULONG; cdecl = nil; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
var fips_provider: POSSL_PROVIDER;
    base_provider: POSSL_PROVIDER;



{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$if declared(CRYPTO_num_locks)}
type

  { TOpenSSLLegacyCallbacks }

  TOpenSSLLegacyCallbacks = class(TThreadList)
  private
    procedure PrepareOpenSSLLocking;
    class var FCallbackList: TOpenSSLLegacyCallbacks;
  public
    constructor Create;
    destructor Destroy; override;
  end;

procedure TOpenSSLLegacyCallbacks.PrepareOpenSSLLocking;
var
  i: integer;
  Lock: TCriticalSection;
begin
  LockList;
  try
    for i := 0 to CRYPTO_num_locks - 1 do
    begin
      Lock := TCriticalSection.Create;
      try
        Add(Lock);
      except
        Lock.Free;
        raise;
      end;
    end;
  finally
    UnlockList;
  end;
end;

procedure OpenSSLSetCurrentThreadID(id : PCRYPTO_THREADID); cdecl;
begin
  CRYPTO_THREADID_set_numeric(id, TOpenSSL_C_ULONG(GetCurrentThreadId));
end;

procedure OpenSSLLockingCallback(mode, n: TOpenSSL_C_INT; Afile: PAnsiChar;
  line: TOpenSSL_C_INT); cdecl;
var
  Lock: TCriticalSection;
  LList: TList;
begin
  Assert(TOpenSSLLegacyCallbacks.FCallbackList <> nil);
  Lock := nil;

  LList := TOpenSSLLegacyCallbacks.FCallbackList.LockList;
  try
    if n < LList.Count then
      Lock := TCriticalSection(LList[n]);
  finally
    TOpenSSLLegacyCallbacks.FCallbackList.UnlockList;
  end;
  Assert(Lock <> nil);
  if (mode and CRYPTO_LOCK) = CRYPTO_LOCK then
    Lock.Acquire
  else
    Lock.Release;
end;

constructor TOpenSSLLegacyCallbacks.Create;
begin
  Assert(FCallbackList = nil);
  inherited Create;
  FCallbackList := self;
  PrepareOpenSSLLocking;
  CRYPTO_set_locking_callback(@OpenSSLLockingCallback);
  CRYPTO_THREADID_set_callback(@OpenSSLSetCurrentThreadID);
end;

destructor TOpenSSLLegacyCallbacks.Destroy;
var i: integer;
    LList: TList;
begin
  CRYPTO_set_locking_callback(nil);
  LList := LockList;

  try
    for i := 0 to LList.Count - 1 do
      TCriticalSection(LList[i]).Free;
    Clear;
  finally
    UnlockList;
  end;
  inherited Destroy;
  FCallbackList := nil;
end;
{$IFEND}
{$ENDIF}


procedure SetLegacyCallbacks;
begin
  {$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  {$if declared(CRYPTO_num_locks)}
  if TOpenSSLLegacyCallbacks.FCallbackList = nil then
    TOpenSSLLegacyCallbacks.Create;
  {$ifend}
  {$ENDIF}
end;

procedure RemoveLegacyCallbacks;
begin
  {$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  {$if declared(CRYPTO_num_locks)}
  if TOpenSSLLegacyCallbacks.FCallbackList <> nil then
    FreeAndNil(TOpenSSLLegacyCallbacks.FCallbackList);
    {$ifend}
  {$ENDIF}
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_zalloc(num) CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_realloc(addr, num) CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_realloc(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_realloc(addr, old_num, num) CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_clear_realloc(addr, old_num, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_free(addr, num) CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET);

begin
  CRYPTO_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_free(addr) CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_free(addr: Pointer);

begin
  CRYPTO_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_memdup(str, s) CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_memdup(str, s, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strdup(str) CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_strdup(const str: PAnsiChar): PAnsiChar;

begin
  Result := CRYPTO_strdup(str, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strndup(str, n) CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar;

begin
  Result := CRYPTO_strndup(str, n, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_malloc(num) CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_secure_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_zalloc(num) CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer;

begin
  Result := CRYPTO_secure_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_free(addr) CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_secure_free(addr: Pointer);

begin
  CRYPTO_secure_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_clear_free(addr, num) CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET);

begin
  CRYPTO_secure_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_actual_size(ptr) CRYPTO_secure_actual_size(ptr)


function OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET;

begin
  Result := CRYPTO_secure_actual_size(ptr);
end;



function FIPS_mode: TOpenSSL_C_INT;

begin
  Result := OSSL_PROVIDER_available(nil,PAnsiChar(AnsiString('fips')));
end;


function FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT;

begin
  if r = 0 then
  begin
    if base_provider <> nil then
    begin
      OSSL_PROVIDER_unload(base_provider);
      base_provider := nil;
    end;

    if fips_provider <> nil then
    begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
    end;
    Result := 1;
  end
  else
  begin
     Result := 0;
     fips_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('fips')));
     if fips_provider = nil then
       Exit;
     base_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('base')));
     if base_provider = nil then
     begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
       Exit;
     end;
     Result := 1;
  end;
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_zalloc(num) CRYPTO_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_realloc(addr, num) CRYPTO_realloc(addr, num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_realloc(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_realloc(addr, old_num, num) CRYPTO_clear_realloc(addr, old_num, num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_clear_realloc(addr, old_num, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_clear_free(addr, num) CRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;

begin
  CRYPTO_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_free(addr) CRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_free(addr: Pointer); cdecl;

begin
  CRYPTO_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_memdup(str, s) CRYPTO_memdup((str), s, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_memdup(str, s, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strdup(str) CRYPTO_strdup(str, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_strdup(const str: PAnsiChar): PAnsiChar; cdecl;

begin
  Result := CRYPTO_strdup(str, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_strndup(str, n) CRYPTO_strndup(str, n, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; cdecl;

begin
  Result := CRYPTO_strndup(str, n, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_malloc(num) CRYPTO_secure_malloc(num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_secure_malloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_zalloc(num) CRYPTO_secure_zalloc(num, OPENSSL_FILE, OPENSSL_LINE)


function COMPAT_OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl;

begin
  Result := CRYPTO_secure_zalloc(num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_free(addr) CRYPTO_secure_free(addr, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_secure_free(addr: Pointer); cdecl;

begin
  CRYPTO_secure_free(addr, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_clear_free(addr, num) CRYPTO_secure_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)


procedure COMPAT_OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl;

begin
  CRYPTO_secure_clear_free(addr, num, {$IFNDEF FPC}''{$ELSE}{$I %FILE%}{$ENDIF}, {$IFNDEF FPC}-1{$ELSE}{$I %LINENUM%}{$ENDIF});
end;

//# define OPENSSL_secure_actual_size(ptr) CRYPTO_secure_actual_size(ptr)


function COMPAT_OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl;

begin
  Result := CRYPTO_secure_actual_size(ptr);
end;



function COMPAT_OpenSSL_version(type_ : TOpenSSL_C_INT): PAnsiChar; cdecl;

begin
  Result := SSLeay_version(type_);
end;



function COMPAT_OpenSSL_version_num: TOpenSSL_C_ULONG; cdecl;

begin
  Result := SSLeay;
end;



function COMPAT_FIPS_mode: TOpenSSL_C_INT; cdecl;

begin
  Result := OSSL_PROVIDER_available(nil,PAnsiChar(AnsiString('fips')));
end;


function COMPAT_FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

begin
  if r = 0 then
  begin
    if base_provider <> nil then
    begin
      OSSL_PROVIDER_unload(base_provider);
      base_provider := nil;
    end;

    if fips_provider <> nil then
    begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
    end;
    Result := 1;
  end
  else
  begin
     Result := 0;
     fips_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('fips')));
     if fips_provider = nil then
       Exit;
     base_provider := OSSL_PROVIDER_load(nil, PAnsiChar(AnsiString('base')));
     if base_provider = nil then
     begin
       OSSL_PROVIDER_unload(fips_provider);
       fips_provider := nil;
       Exit;
     end;
     Result := 1;
  end;
end;




function COMPAT_OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;

var OpenSSL_add_all_ciphers: procedure; cdecl;
    OpenSSL_add_all_digests: procedure; cdecl;
begin
  Result := 0;
  if opts and OPENSSL_INIT_ADD_ALL_CIPHERS <> 0 then
  begin
    OpenSSL_add_all_ciphers := LoadLibCryptoFunction('OpenSSL_add_all_ciphers');
    if not assigned(OpenSSL_add_all_ciphers) then
      EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_ciphers');
    OpenSSL_add_all_ciphers;
  end;
  if opts and OPENSSL_INIT_ADD_ALL_DIGESTS <> 0 then
  begin
    OpenSSL_add_all_digests := LoadLibCryptoFunction('OpenSSL_add_all_digests');
    if not assigned(OpenSSL_add_all_digests) then
      EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_digests');
    OpenSSL_add_all_digests;
  end;
  Result := 1;
end;



procedure COMPAT_OPENSSL_cleanup; cdecl;

begin
 {nothing to do}
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$J+}
{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_malloc');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_zalloc');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_realloc(addr: Pointer; num: TOpenSSL_C_SIZET): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_realloc');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_clear_realloc');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_clear_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_free(addr: Pointer); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_memdup(const str: Pointer; s: TOpenSSL_C_SIZET): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_memdup');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_strdup(const str: PAnsiChar): PAnsiChar; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strdup');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_strndup(const str: PAnsiChar; n: TOpenSSL_C_SIZET): PAnsiChar; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strndup');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_secure_malloc(num: TOpenSSL_C_SIZET): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_secure_malloc');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_secure_zalloc(num: TOpenSSL_C_SIZET): Pointer; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_secure_zalloc');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_secure_free(addr: Pointer); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_secure_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_secure_clear_free(addr: Pointer; num: TOpenSSL_C_SIZET); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_secure_clear_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_secure_actual_size');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_CRYPTO_THREAD_lock_new: PCRYPTO_RWLOCK; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_lock_new');
end;

function ERROR_CRYPTO_THREAD_read_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_read_lock');
end;

function ERROR_CRYPTO_THREAD_write_lock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_write_lock');
end;

function ERROR_CRYPTO_THREAD_unlock(lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_unlock');
end;

procedure ERROR_CRYPTO_THREAD_lock_free(lock: PCRYPTO_RWLOCK); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_lock_free');
end;

function ERROR_CRYPTO_atomic_add(val: POpenSSL_C_INT; amount: TOpenSSL_C_INT; ret: POpenSSL_C_INT; lock: PCRYPTO_RWLOCK): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_atomic_add');
end;

function ERROR_CRYPTO_mem_ctrl(mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_mem_ctrl');
end;

function ERROR_OPENSSL_strlcpy(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strlcpy');
end;

function ERROR_OPENSSL_strlcat(dst: PAnsiChar; const src: PAnsiChar; siz: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strlcat');
end;

function ERROR_OPENSSL_strnlen(const str: PAnsiChar; maxlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_strnlen');
end;

function ERROR_OPENSSL_buf2hexstr(const buffer: PByte; len: TOpenSSL_C_LONG): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_buf2hexstr');
end;

function ERROR_OPENSSL_hexstr2buf(const str: PAnsiChar; len: POpenSSL_C_LONG): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_hexstr2buf');
end;

function ERROR_OPENSSL_hexchar2int(c: Byte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_hexchar2int');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OpenSSL_version_num: TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_version_num');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OpenSSL_version(type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_version');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_OPENSSL_issetugid: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_issetugid');
end;

function ERROR_CRYPTO_new_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_new_ex_data');
end;

function ERROR_CRYPTO_dup_ex_data(class_index: TOpenSSL_C_INT; to_: PCRYPTO_EX_DATA; const from: PCRYPTO_EX_DATA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_dup_ex_data');
end;

procedure ERROR_CRYPTO_free_ex_data(class_index: TOpenSSL_C_INT; obj: Pointer; ad: PCRYPTO_EX_DATA); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_free_ex_data');
end;

function ERROR_CRYPTO_set_ex_data(ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT; val: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_ex_data');
end;

function ERROR_CRYPTO_get_ex_data(const ad: PCRYPTO_EX_DATA; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_get_ex_data');
end;

function ERROR_CRYPTO_num_locks: TOpenSSL_C_INT; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_num_locks');
end;

procedure ERROR_CRYPTO_set_locking_callback(func: TIdSslLockingCallback); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_locking_callback');
end;

procedure ERROR_CRYPTO_THREADID_set_numeric(id : PCRYPTO_THREADID; val: TOpenSSL_C_ULONG); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREADID_set_numeric');
end;

procedure ERROR_CRYPTO_THREADID_set_callback(threadid_func: Tthreadid_func); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREADID_set_callback');
end;

procedure ERROR_CRYPTO_set_id_callback(func: TIdSslIdCallback); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_id_callback');
end;

function ERROR_CRYPTO_set_mem_functions(m: CRYPTO_set_mem_functions_m; r: CRYPTO_set_mem_functions_r; f: CRYPTO_set_mem_functions_f): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_mem_functions');
end;

function ERROR_CRYPTO_set_mem_debug(flag: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_set_mem_debug');
end;

function ERROR_CRYPTO_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_malloc');
end;

function ERROR_CRYPTO_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_zalloc');
end;

function ERROR_CRYPTO_memdup(const str: Pointer; siz: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_memdup');
end;

function ERROR_CRYPTO_strdup(const str: PAnsiChar; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_strdup');
end;

function ERROR_CRYPTO_strndup(const str: PAnsiChar; s: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_strndup');
end;

procedure ERROR_CRYPTO_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_free');
end;

procedure ERROR_CRYPTO_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_clear_free');
end;

function ERROR_CRYPTO_realloc(addr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_realloc');
end;

function ERROR_CRYPTO_clear_realloc(addr: Pointer; old_num: TOpenSSL_C_SIZET; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_clear_realloc');
end;

function ERROR_CRYPTO_secure_malloc_init(sz: TOpenSSL_C_SIZET; minsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc_init');
end;

function ERROR_CRYPTO_secure_malloc_done: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc_done');
end;

function ERROR_CRYPTO_secure_malloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc');
end;

function ERROR_CRYPTO_secure_zalloc(num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_zalloc');
end;

procedure ERROR_CRYPTO_secure_free(ptr: Pointer; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_free');
end;

procedure ERROR_CRYPTO_secure_clear_free(ptr: Pointer; num: TOpenSSL_C_SIZET; const file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_clear_free');
end;

function ERROR_CRYPTO_secure_allocated(const ptr: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_allocated');
end;

function ERROR_CRYPTO_secure_malloc_initialized: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_malloc_initialized');
end;

function ERROR_CRYPTO_secure_actual_size(ptr: Pointer): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_actual_size');
end;

function ERROR_CRYPTO_secure_used: TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_secure_used');
end;

procedure ERROR_OPENSSL_cleanse(ptr: Pointer; len: TOpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_cleanse');
end;

function ERROR_OPENSSL_isservice: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_isservice');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_FIPS_mode: TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('FIPS_mode');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_FIPS_mode_set(r: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('FIPS_mode_set');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

procedure ERROR_OPENSSL_init; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_init');
end;

function ERROR_CRYPTO_memcmp(const in_a: Pointer; const in_b: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_memcmp');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OPENSSL_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_cleanup');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_OPENSSL_init_crypto(opts: TOpenSSL_C_UINT64; const settings: POPENSSL_INIT_SETTINGS): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_init_crypto');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

procedure ERROR_OPENSSL_thread_stop; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_thread_stop');
end;

function ERROR_OPENSSL_INIT_new: POPENSSL_INIT_SETTINGS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_INIT_new');
end;

procedure ERROR_OPENSSL_INIT_free(settings: POPENSSL_INIT_SETTINGS); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_INIT_free');
end;

function ERROR_CRYPTO_THREAD_run_once(once: PCRYPTO_ONCE; init: CRYPTO_THREAD_run_once_init): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_run_once');
end;

function ERROR_CRYPTO_THREAD_get_local(key: PCRYPTO_THREAD_LOCAL): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_get_local');
end;

function ERROR_CRYPTO_THREAD_set_local(key: PCRYPTO_THREAD_LOCAL; val: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_set_local');
end;

function ERROR_CRYPTO_THREAD_cleanup_local(key: PCRYPTO_THREAD_LOCAL): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_cleanup_local');
end;

function ERROR_CRYPTO_THREAD_get_current_id: CRYPTO_THREAD_ID; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_get_current_id');
end;

function ERROR_CRYPTO_THREAD_compare_id(a: CRYPTO_THREAD_ID; b: CRYPTO_THREAD_ID): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_THREAD_compare_id');
end;

function ERROR_SSLeay_version(type_ : TOpenSSL_C_INT): PAnsiChar; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSLeay_version');
end;

function ERROR_SSLeay: TOpenSSL_C_ULONG; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSLeay');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$J+}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_malloc := LoadLibCryptoFunction('OPENSSL_malloc');
  FuncLoadError := not assigned(OPENSSL_malloc);
  if FuncLoadError then
  begin
    OPENSSL_malloc := @COMPAT_OPENSSL_malloc;
    if OPENSSL_malloc_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_malloc');
  end;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_zalloc := LoadLibCryptoFunction('OPENSSL_zalloc');
  FuncLoadError := not assigned(OPENSSL_zalloc);
  if FuncLoadError then
  begin
    OPENSSL_zalloc := @COMPAT_OPENSSL_zalloc;
    if OPENSSL_zalloc_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_zalloc');
  end;

  OPENSSL_realloc := LoadLibCryptoFunction('OPENSSL_realloc');
  FuncLoadError := not assigned(OPENSSL_realloc);
  if FuncLoadError then
  begin
    OPENSSL_realloc := @COMPAT_OPENSSL_realloc;
    if OPENSSL_realloc_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_realloc');
  end;

  OPENSSL_clear_realloc := LoadLibCryptoFunction('OPENSSL_clear_realloc');
  FuncLoadError := not assigned(OPENSSL_clear_realloc);
  if FuncLoadError then
  begin
    OPENSSL_clear_realloc := @COMPAT_OPENSSL_clear_realloc;
    if OPENSSL_clear_realloc_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_clear_realloc');
  end;

  OPENSSL_clear_free := LoadLibCryptoFunction('OPENSSL_clear_free');
  FuncLoadError := not assigned(OPENSSL_clear_free);
  if FuncLoadError then
  begin
    OPENSSL_clear_free := @COMPAT_OPENSSL_clear_free;
    if OPENSSL_clear_free_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_clear_free');
  end;

  OPENSSL_free := LoadLibCryptoFunction('OPENSSL_free');
  FuncLoadError := not assigned(OPENSSL_free);
  if FuncLoadError then
  begin
    OPENSSL_free := @COMPAT_OPENSSL_free;
    if OPENSSL_free_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_free');
  end;

  OPENSSL_memdup := LoadLibCryptoFunction('OPENSSL_memdup');
  FuncLoadError := not assigned(OPENSSL_memdup);
  if FuncLoadError then
  begin
    OPENSSL_memdup := @COMPAT_OPENSSL_memdup;
    if OPENSSL_memdup_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_memdup');
  end;

  OPENSSL_strdup := LoadLibCryptoFunction('OPENSSL_strdup');
  FuncLoadError := not assigned(OPENSSL_strdup);
  if FuncLoadError then
  begin
    OPENSSL_strdup := @COMPAT_OPENSSL_strdup;
    if OPENSSL_strdup_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_strdup');
  end;

  OPENSSL_strndup := LoadLibCryptoFunction('OPENSSL_strndup');
  FuncLoadError := not assigned(OPENSSL_strndup);
  if FuncLoadError then
  begin
    OPENSSL_strndup := @COMPAT_OPENSSL_strndup;
    if OPENSSL_strndup_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_strndup');
  end;

  OPENSSL_secure_malloc := LoadLibCryptoFunction('OPENSSL_secure_malloc');
  FuncLoadError := not assigned(OPENSSL_secure_malloc);
  if FuncLoadError then
  begin
    OPENSSL_secure_malloc := @COMPAT_OPENSSL_secure_malloc;
    if OPENSSL_secure_malloc_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_malloc');
  end;

  OPENSSL_secure_zalloc := LoadLibCryptoFunction('OPENSSL_secure_zalloc');
  FuncLoadError := not assigned(OPENSSL_secure_zalloc);
  if FuncLoadError then
  begin
    OPENSSL_secure_zalloc := @COMPAT_OPENSSL_secure_zalloc;
    if OPENSSL_secure_zalloc_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_zalloc');
  end;

  OPENSSL_secure_free := LoadLibCryptoFunction('OPENSSL_secure_free');
  FuncLoadError := not assigned(OPENSSL_secure_free);
  if FuncLoadError then
  begin
    OPENSSL_secure_free := @COMPAT_OPENSSL_secure_free;
    if OPENSSL_secure_free_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_free');
  end;

  OPENSSL_secure_clear_free := LoadLibCryptoFunction('OPENSSL_secure_clear_free');
  FuncLoadError := not assigned(OPENSSL_secure_clear_free);
  if FuncLoadError then
  begin
    OPENSSL_secure_clear_free := @COMPAT_OPENSSL_secure_clear_free;
    if OPENSSL_secure_clear_free_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_clear_free');
  end;

  OPENSSL_secure_actual_size := LoadLibCryptoFunction('OPENSSL_secure_actual_size');
  FuncLoadError := not assigned(OPENSSL_secure_actual_size);
  if FuncLoadError then
  begin
    OPENSSL_secure_actual_size := @COMPAT_OPENSSL_secure_actual_size;
    if OPENSSL_secure_actual_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OPENSSL_secure_actual_size');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_THREAD_lock_new := LoadLibCryptoFunction('CRYPTO_THREAD_lock_new');
  FuncLoadError := not assigned(CRYPTO_THREAD_lock_new);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_lock_new :=  @ERROR_CRYPTO_THREAD_lock_new;
  end;

  CRYPTO_THREAD_read_lock := LoadLibCryptoFunction('CRYPTO_THREAD_read_lock');
  FuncLoadError := not assigned(CRYPTO_THREAD_read_lock);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_read_lock :=  @ERROR_CRYPTO_THREAD_read_lock;
  end;

  CRYPTO_THREAD_write_lock := LoadLibCryptoFunction('CRYPTO_THREAD_write_lock');
  FuncLoadError := not assigned(CRYPTO_THREAD_write_lock);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_write_lock :=  @ERROR_CRYPTO_THREAD_write_lock;
  end;

  CRYPTO_THREAD_unlock := LoadLibCryptoFunction('CRYPTO_THREAD_unlock');
  FuncLoadError := not assigned(CRYPTO_THREAD_unlock);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_unlock :=  @ERROR_CRYPTO_THREAD_unlock;
  end;

  CRYPTO_THREAD_lock_free := LoadLibCryptoFunction('CRYPTO_THREAD_lock_free');
  FuncLoadError := not assigned(CRYPTO_THREAD_lock_free);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_lock_free :=  @ERROR_CRYPTO_THREAD_lock_free;
  end;

  CRYPTO_atomic_add := LoadLibCryptoFunction('CRYPTO_atomic_add');
  FuncLoadError := not assigned(CRYPTO_atomic_add);
  if FuncLoadError then
  begin
    CRYPTO_atomic_add :=  @ERROR_CRYPTO_atomic_add;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_mem_ctrl := LoadLibCryptoFunction('CRYPTO_mem_ctrl');
  FuncLoadError := not assigned(CRYPTO_mem_ctrl);
  if FuncLoadError then
  begin
    if CRYPTO_mem_ctrl_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('CRYPTO_mem_ctrl');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  OPENSSL_strlcpy := LoadLibCryptoFunction('OPENSSL_strlcpy');
  FuncLoadError := not assigned(OPENSSL_strlcpy);
  if FuncLoadError then
  begin
    OPENSSL_strlcpy :=  @ERROR_OPENSSL_strlcpy;
  end;

  OPENSSL_strlcat := LoadLibCryptoFunction('OPENSSL_strlcat');
  FuncLoadError := not assigned(OPENSSL_strlcat);
  if FuncLoadError then
  begin
    OPENSSL_strlcat :=  @ERROR_OPENSSL_strlcat;
  end;

  OPENSSL_strnlen := LoadLibCryptoFunction('OPENSSL_strnlen');
  FuncLoadError := not assigned(OPENSSL_strnlen);
  if FuncLoadError then
  begin
    OPENSSL_strnlen :=  @ERROR_OPENSSL_strnlen;
  end;

  OPENSSL_buf2hexstr := LoadLibCryptoFunction('OPENSSL_buf2hexstr');
  FuncLoadError := not assigned(OPENSSL_buf2hexstr);
  if FuncLoadError then
  begin
    OPENSSL_buf2hexstr :=  @ERROR_OPENSSL_buf2hexstr;
  end;

  OPENSSL_hexstr2buf := LoadLibCryptoFunction('OPENSSL_hexstr2buf');
  FuncLoadError := not assigned(OPENSSL_hexstr2buf);
  if FuncLoadError then
  begin
    OPENSSL_hexstr2buf :=  @ERROR_OPENSSL_hexstr2buf;
  end;

  OPENSSL_hexchar2int := LoadLibCryptoFunction('OPENSSL_hexchar2int');
  FuncLoadError := not assigned(OPENSSL_hexchar2int);
  if FuncLoadError then
  begin
    OPENSSL_hexchar2int :=  @ERROR_OPENSSL_hexchar2int;
  end;

  OpenSSL_version_num := LoadLibCryptoFunction('OpenSSL_version_num');
  FuncLoadError := not assigned(OpenSSL_version_num);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OpenSSL_version_num := @COMPAT_OpenSSL_version_num;
{$ELSE}
    OpenSSL_version_num :=  @ERROR_OpenSSL_version_num;
{$ENDIF}
  end;

  OpenSSL_version := LoadLibCryptoFunction('OpenSSL_version');
  FuncLoadError := not assigned(OpenSSL_version);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OpenSSL_version := @COMPAT_OpenSSL_version;
{$ELSE}
    OpenSSL_version :=  @ERROR_OpenSSL_version;
{$ENDIF}
  end;

  OPENSSL_issetugid := LoadLibCryptoFunction('OPENSSL_issetugid');
  FuncLoadError := not assigned(OPENSSL_issetugid);
  if FuncLoadError then
  begin
    OPENSSL_issetugid :=  @ERROR_OPENSSL_issetugid;
  end;

  CRYPTO_new_ex_data := LoadLibCryptoFunction('CRYPTO_new_ex_data');
  FuncLoadError := not assigned(CRYPTO_new_ex_data);
  if FuncLoadError then
  begin
    CRYPTO_new_ex_data :=  @ERROR_CRYPTO_new_ex_data;
  end;

  CRYPTO_dup_ex_data := LoadLibCryptoFunction('CRYPTO_dup_ex_data');
  FuncLoadError := not assigned(CRYPTO_dup_ex_data);
  if FuncLoadError then
  begin
    CRYPTO_dup_ex_data :=  @ERROR_CRYPTO_dup_ex_data;
  end;

  CRYPTO_free_ex_data := LoadLibCryptoFunction('CRYPTO_free_ex_data');
  FuncLoadError := not assigned(CRYPTO_free_ex_data);
  if FuncLoadError then
  begin
    CRYPTO_free_ex_data :=  @ERROR_CRYPTO_free_ex_data;
  end;

  CRYPTO_set_ex_data := LoadLibCryptoFunction('CRYPTO_set_ex_data');
  FuncLoadError := not assigned(CRYPTO_set_ex_data);
  if FuncLoadError then
  begin
    CRYPTO_set_ex_data :=  @ERROR_CRYPTO_set_ex_data;
  end;

  CRYPTO_get_ex_data := LoadLibCryptoFunction('CRYPTO_get_ex_data');
  FuncLoadError := not assigned(CRYPTO_get_ex_data);
  if FuncLoadError then
  begin
    CRYPTO_get_ex_data :=  @ERROR_CRYPTO_get_ex_data;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_num_locks := LoadLibCryptoFunction('CRYPTO_num_locks');
  FuncLoadError := not assigned(CRYPTO_num_locks);
  if FuncLoadError then
  begin
    if CRYPTO_num_locks_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('CRYPTO_num_locks');
  end;

  CRYPTO_set_locking_callback := LoadLibCryptoFunction('CRYPTO_set_locking_callback');
  FuncLoadError := not assigned(CRYPTO_set_locking_callback);
  if FuncLoadError then
  begin
    if CRYPTO_set_locking_callback_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_locking_callback');
  end;

  CRYPTO_THREADID_set_numeric := LoadLibCryptoFunction('CRYPTO_THREADID_set_numeric');
  FuncLoadError := not assigned(CRYPTO_THREADID_set_numeric);
  if FuncLoadError then
  begin
    if CRYPTO_THREADID_set_numeric_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREADID_set_numeric');
  end;

  CRYPTO_THREADID_set_callback := LoadLibCryptoFunction('CRYPTO_THREADID_set_callback');
  FuncLoadError := not assigned(CRYPTO_THREADID_set_callback);
  if FuncLoadError then
  begin
    if CRYPTO_THREADID_set_callback_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('CRYPTO_THREADID_set_callback');
  end;

  CRYPTO_set_id_callback := LoadLibCryptoFunction('CRYPTO_set_id_callback');
  FuncLoadError := not assigned(CRYPTO_set_id_callback);
  if FuncLoadError then
  begin
    if CRYPTO_set_id_callback_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_id_callback');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_set_mem_functions := LoadLibCryptoFunction('CRYPTO_set_mem_functions');
  FuncLoadError := not assigned(CRYPTO_set_mem_functions);
  if FuncLoadError then
  begin
    CRYPTO_set_mem_functions :=  @ERROR_CRYPTO_set_mem_functions;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_set_mem_debug := LoadLibCryptoFunction('CRYPTO_set_mem_debug');
  FuncLoadError := not assigned(CRYPTO_set_mem_debug);
  if FuncLoadError then
  begin
    if CRYPTO_set_mem_debug_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('CRYPTO_set_mem_debug');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_malloc := LoadLibCryptoFunction('CRYPTO_malloc');
  FuncLoadError := not assigned(CRYPTO_malloc);
  if FuncLoadError then
  begin
    CRYPTO_malloc :=  @ERROR_CRYPTO_malloc;
  end;

  CRYPTO_zalloc := LoadLibCryptoFunction('CRYPTO_zalloc');
  FuncLoadError := not assigned(CRYPTO_zalloc);
  if FuncLoadError then
  begin
    CRYPTO_zalloc :=  @ERROR_CRYPTO_zalloc;
  end;

  CRYPTO_memdup := LoadLibCryptoFunction('CRYPTO_memdup');
  FuncLoadError := not assigned(CRYPTO_memdup);
  if FuncLoadError then
  begin
    CRYPTO_memdup :=  @ERROR_CRYPTO_memdup;
  end;

  CRYPTO_strdup := LoadLibCryptoFunction('CRYPTO_strdup');
  FuncLoadError := not assigned(CRYPTO_strdup);
  if FuncLoadError then
  begin
    CRYPTO_strdup :=  @ERROR_CRYPTO_strdup;
  end;

  CRYPTO_strndup := LoadLibCryptoFunction('CRYPTO_strndup');
  FuncLoadError := not assigned(CRYPTO_strndup);
  if FuncLoadError then
  begin
    CRYPTO_strndup :=  @ERROR_CRYPTO_strndup;
  end;

  CRYPTO_free := LoadLibCryptoFunction('CRYPTO_free');
  FuncLoadError := not assigned(CRYPTO_free);
  if FuncLoadError then
  begin
    CRYPTO_free :=  @ERROR_CRYPTO_free;
  end;

  CRYPTO_clear_free := LoadLibCryptoFunction('CRYPTO_clear_free');
  FuncLoadError := not assigned(CRYPTO_clear_free);
  if FuncLoadError then
  begin
    CRYPTO_clear_free :=  @ERROR_CRYPTO_clear_free;
  end;

  CRYPTO_realloc := LoadLibCryptoFunction('CRYPTO_realloc');
  FuncLoadError := not assigned(CRYPTO_realloc);
  if FuncLoadError then
  begin
    CRYPTO_realloc :=  @ERROR_CRYPTO_realloc;
  end;

  CRYPTO_clear_realloc := LoadLibCryptoFunction('CRYPTO_clear_realloc');
  FuncLoadError := not assigned(CRYPTO_clear_realloc);
  if FuncLoadError then
  begin
    CRYPTO_clear_realloc :=  @ERROR_CRYPTO_clear_realloc;
  end;

  CRYPTO_secure_malloc_init := LoadLibCryptoFunction('CRYPTO_secure_malloc_init');
  FuncLoadError := not assigned(CRYPTO_secure_malloc_init);
  if FuncLoadError then
  begin
    CRYPTO_secure_malloc_init :=  @ERROR_CRYPTO_secure_malloc_init;
  end;

  CRYPTO_secure_malloc_done := LoadLibCryptoFunction('CRYPTO_secure_malloc_done');
  FuncLoadError := not assigned(CRYPTO_secure_malloc_done);
  if FuncLoadError then
  begin
    CRYPTO_secure_malloc_done :=  @ERROR_CRYPTO_secure_malloc_done;
  end;

  CRYPTO_secure_malloc := LoadLibCryptoFunction('CRYPTO_secure_malloc');
  FuncLoadError := not assigned(CRYPTO_secure_malloc);
  if FuncLoadError then
  begin
    CRYPTO_secure_malloc :=  @ERROR_CRYPTO_secure_malloc;
  end;

  CRYPTO_secure_zalloc := LoadLibCryptoFunction('CRYPTO_secure_zalloc');
  FuncLoadError := not assigned(CRYPTO_secure_zalloc);
  if FuncLoadError then
  begin
    CRYPTO_secure_zalloc :=  @ERROR_CRYPTO_secure_zalloc;
  end;

  CRYPTO_secure_free := LoadLibCryptoFunction('CRYPTO_secure_free');
  FuncLoadError := not assigned(CRYPTO_secure_free);
  if FuncLoadError then
  begin
    CRYPTO_secure_free :=  @ERROR_CRYPTO_secure_free;
  end;

  CRYPTO_secure_clear_free := LoadLibCryptoFunction('CRYPTO_secure_clear_free');
  FuncLoadError := not assigned(CRYPTO_secure_clear_free);
  if FuncLoadError then
  begin
    CRYPTO_secure_clear_free :=  @ERROR_CRYPTO_secure_clear_free;
  end;

  CRYPTO_secure_allocated := LoadLibCryptoFunction('CRYPTO_secure_allocated');
  FuncLoadError := not assigned(CRYPTO_secure_allocated);
  if FuncLoadError then
  begin
    CRYPTO_secure_allocated :=  @ERROR_CRYPTO_secure_allocated;
  end;

  CRYPTO_secure_malloc_initialized := LoadLibCryptoFunction('CRYPTO_secure_malloc_initialized');
  FuncLoadError := not assigned(CRYPTO_secure_malloc_initialized);
  if FuncLoadError then
  begin
    CRYPTO_secure_malloc_initialized :=  @ERROR_CRYPTO_secure_malloc_initialized;
  end;

  CRYPTO_secure_actual_size := LoadLibCryptoFunction('CRYPTO_secure_actual_size');
  FuncLoadError := not assigned(CRYPTO_secure_actual_size);
  if FuncLoadError then
  begin
    CRYPTO_secure_actual_size :=  @ERROR_CRYPTO_secure_actual_size;
  end;

  CRYPTO_secure_used := LoadLibCryptoFunction('CRYPTO_secure_used');
  FuncLoadError := not assigned(CRYPTO_secure_used);
  if FuncLoadError then
  begin
    CRYPTO_secure_used :=  @ERROR_CRYPTO_secure_used;
  end;

  OPENSSL_cleanse := LoadLibCryptoFunction('OPENSSL_cleanse');
  FuncLoadError := not assigned(OPENSSL_cleanse);
  if FuncLoadError then
  begin
    OPENSSL_cleanse :=  @ERROR_OPENSSL_cleanse;
  end;

  OPENSSL_isservice := LoadLibCryptoFunction('OPENSSL_isservice');
  FuncLoadError := not assigned(OPENSSL_isservice);
  if FuncLoadError then
  begin
    OPENSSL_isservice :=  @ERROR_OPENSSL_isservice;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  FIPS_mode := LoadLibCryptoFunction('FIPS_mode');
  FuncLoadError := not assigned(FIPS_mode);
  if FuncLoadError then
  begin
    FIPS_mode := @COMPAT_FIPS_mode;
    if FIPS_mode_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('FIPS_mode');
  end;

  FIPS_mode_set := LoadLibCryptoFunction('FIPS_mode_set');
  FuncLoadError := not assigned(FIPS_mode_set);
  if FuncLoadError then
  begin
    FIPS_mode_set := @COMPAT_FIPS_mode_set;
    if FIPS_mode_set_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('FIPS_mode_set');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  OPENSSL_init := LoadLibCryptoFunction('OPENSSL_init');
  FuncLoadError := not assigned(OPENSSL_init);
  if FuncLoadError then
  begin
    OPENSSL_init :=  @ERROR_OPENSSL_init;
  end;

  CRYPTO_memcmp := LoadLibCryptoFunction('CRYPTO_memcmp');
  FuncLoadError := not assigned(CRYPTO_memcmp);
  if FuncLoadError then
  begin
    CRYPTO_memcmp :=  @ERROR_CRYPTO_memcmp;
  end;

  OPENSSL_cleanup := LoadLibCryptoFunction('OPENSSL_cleanup');
  FuncLoadError := not assigned(OPENSSL_cleanup);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_cleanup := @COMPAT_OPENSSL_cleanup;
{$ELSE}
    OPENSSL_cleanup :=  @ERROR_OPENSSL_cleanup;
{$ENDIF}
  end;

  OPENSSL_init_crypto := LoadLibCryptoFunction('OPENSSL_init_crypto');
  FuncLoadError := not assigned(OPENSSL_init_crypto);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    OPENSSL_init_crypto := @COMPAT_OPENSSL_init_crypto;
{$ELSE}
    OPENSSL_init_crypto :=  @ERROR_OPENSSL_init_crypto;
{$ENDIF}
  end;

  OPENSSL_thread_stop := LoadLibCryptoFunction('OPENSSL_thread_stop');
  FuncLoadError := not assigned(OPENSSL_thread_stop);
  if FuncLoadError then
  begin
    OPENSSL_thread_stop :=  @ERROR_OPENSSL_thread_stop;
  end;

  OPENSSL_INIT_new := LoadLibCryptoFunction('OPENSSL_INIT_new');
  FuncLoadError := not assigned(OPENSSL_INIT_new);
  if FuncLoadError then
  begin
    OPENSSL_INIT_new :=  @ERROR_OPENSSL_INIT_new;
  end;

  OPENSSL_INIT_free := LoadLibCryptoFunction('OPENSSL_INIT_free');
  FuncLoadError := not assigned(OPENSSL_INIT_free);
  if FuncLoadError then
  begin
    OPENSSL_INIT_free :=  @ERROR_OPENSSL_INIT_free;
  end;

  CRYPTO_THREAD_run_once := LoadLibCryptoFunction('CRYPTO_THREAD_run_once');
  FuncLoadError := not assigned(CRYPTO_THREAD_run_once);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_run_once :=  @ERROR_CRYPTO_THREAD_run_once;
  end;

  CRYPTO_THREAD_get_local := LoadLibCryptoFunction('CRYPTO_THREAD_get_local');
  FuncLoadError := not assigned(CRYPTO_THREAD_get_local);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_get_local :=  @ERROR_CRYPTO_THREAD_get_local;
  end;

  CRYPTO_THREAD_set_local := LoadLibCryptoFunction('CRYPTO_THREAD_set_local');
  FuncLoadError := not assigned(CRYPTO_THREAD_set_local);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_set_local :=  @ERROR_CRYPTO_THREAD_set_local;
  end;

  CRYPTO_THREAD_cleanup_local := LoadLibCryptoFunction('CRYPTO_THREAD_cleanup_local');
  FuncLoadError := not assigned(CRYPTO_THREAD_cleanup_local);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_cleanup_local :=  @ERROR_CRYPTO_THREAD_cleanup_local;
  end;

  CRYPTO_THREAD_get_current_id := LoadLibCryptoFunction('CRYPTO_THREAD_get_current_id');
  FuncLoadError := not assigned(CRYPTO_THREAD_get_current_id);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_get_current_id :=  @ERROR_CRYPTO_THREAD_get_current_id;
  end;

  CRYPTO_THREAD_compare_id := LoadLibCryptoFunction('CRYPTO_THREAD_compare_id');
  FuncLoadError := not assigned(CRYPTO_THREAD_compare_id);
  if FuncLoadError then
  begin
    CRYPTO_THREAD_compare_id :=  @ERROR_CRYPTO_THREAD_compare_id;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLeay_version := LoadLibCryptoFunction('SSLeay_version');
  FuncLoadError := not assigned(SSLeay_version);
  if FuncLoadError then
  begin
    if SSLeay_version_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSLeay_version');
  end;

  SSLeay := LoadLibCryptoFunction('SSLeay');
  FuncLoadError := not assigned(SSLeay);
  if FuncLoadError then
  begin
    if SSLeay_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSLeay');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;

procedure UnLoad;
begin
{$J+}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_malloc := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OPENSSL_zalloc := nil;
  OPENSSL_realloc := nil;
  OPENSSL_clear_realloc := nil;
  OPENSSL_clear_free := nil;
  OPENSSL_free := nil;
  OPENSSL_memdup := nil;
  OPENSSL_strdup := nil;
  OPENSSL_strndup := nil;
  OPENSSL_secure_malloc := nil;
  OPENSSL_secure_zalloc := nil;
  OPENSSL_secure_free := nil;
  OPENSSL_secure_clear_free := nil;
  OPENSSL_secure_actual_size := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_THREAD_lock_new := nil;
  CRYPTO_THREAD_read_lock := nil;
  CRYPTO_THREAD_write_lock := nil;
  CRYPTO_THREAD_unlock := nil;
  CRYPTO_THREAD_lock_free := nil;
  CRYPTO_atomic_add := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_mem_ctrl := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  OPENSSL_strlcpy := nil;
  OPENSSL_strlcat := nil;
  OPENSSL_strnlen := nil;
  OPENSSL_buf2hexstr := nil;
  OPENSSL_hexstr2buf := nil;
  OPENSSL_hexchar2int := nil;
  OpenSSL_version_num := nil;
  OpenSSL_version := nil;
  OPENSSL_issetugid := nil;
  CRYPTO_new_ex_data := nil;
  CRYPTO_dup_ex_data := nil;
  CRYPTO_free_ex_data := nil;
  CRYPTO_set_ex_data := nil;
  CRYPTO_get_ex_data := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_num_locks := nil;
  CRYPTO_set_locking_callback := nil;
  CRYPTO_THREADID_set_numeric := nil;
  CRYPTO_THREADID_set_callback := nil;
  CRYPTO_set_id_callback := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_set_mem_functions := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  CRYPTO_set_mem_debug := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  CRYPTO_malloc := nil;
  CRYPTO_zalloc := nil;
  CRYPTO_memdup := nil;
  CRYPTO_strdup := nil;
  CRYPTO_strndup := nil;
  CRYPTO_free := nil;
  CRYPTO_clear_free := nil;
  CRYPTO_realloc := nil;
  CRYPTO_clear_realloc := nil;
  CRYPTO_secure_malloc_init := nil;
  CRYPTO_secure_malloc_done := nil;
  CRYPTO_secure_malloc := nil;
  CRYPTO_secure_zalloc := nil;
  CRYPTO_secure_free := nil;
  CRYPTO_secure_clear_free := nil;
  CRYPTO_secure_allocated := nil;
  CRYPTO_secure_malloc_initialized := nil;
  CRYPTO_secure_actual_size := nil;
  CRYPTO_secure_used := nil;
  OPENSSL_cleanse := nil;
  OPENSSL_isservice := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  FIPS_mode := nil;
  FIPS_mode_set := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  OPENSSL_init := nil;
  CRYPTO_memcmp := nil;
  OPENSSL_cleanup := nil;
  OPENSSL_init_crypto := nil;
  OPENSSL_thread_stop := nil;
  OPENSSL_INIT_new := nil;
  OPENSSL_INIT_free := nil;
  CRYPTO_THREAD_run_once := nil;
  CRYPTO_THREAD_get_local := nil;
  CRYPTO_THREAD_set_local := nil;
  CRYPTO_THREAD_cleanup_local := nil;
  CRYPTO_THREAD_get_current_id := nil;
  CRYPTO_THREAD_compare_id := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLeay_version := nil;
  SSLeay := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization


  {$if declared(CRYPTO_num_locks)}
  TOpenSSLLegacyCallbacks.FCallbackList := nil;
  {$ifend}


{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}

finalization


  RemoveLegacyCallbacks;




end.
