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

unit openssl_kdf;

{
  Generated from OpenSSL 3.0.20 Header File kdf.h - Tue 19 May 14:25:13 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_kdf.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_evp,openssl_types,openssl_core;


{* Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_KDF_H}
  {$define OPENSSL_KDF_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_KDF_H}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_KDF_up_ref(kdf: PEVP_KDF): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KDF_up_ref';
  procedure EVP_KDF_free(kdf: PEVP_KDF); cdecl; external CLibCrypto name 'EVP_KDF_free';
  function EVP_KDF_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KDF; cdecl; external CLibCrypto name 'EVP_KDF_fetch';
  function EVP_KDF_CTX_new(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl; external CLibCrypto name 'EVP_KDF_CTX_new';
  procedure EVP_KDF_CTX_free(ctx: PEVP_KDF_CTX); cdecl; external CLibCrypto name 'EVP_KDF_CTX_free';
  function EVP_KDF_CTX_dup(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl; external CLibCrypto name 'EVP_KDF_CTX_dup';
  function EVP_KDF_get0_description(kdf: PEVP_KDF): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KDF_get0_description';
  function EVP_KDF_is_a(kdf: PEVP_KDF; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KDF_is_a';
  function EVP_KDF_get0_name(kdf: PEVP_KDF): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KDF_get0_name';
  function EVP_KDF_get0_provider(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_KDF_get0_provider';
  function EVP_KDF_CTX_kdf(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl; external CLibCrypto name 'EVP_KDF_CTX_kdf';
  procedure EVP_KDF_CTX_reset(ctx: PEVP_KDF_CTX); cdecl; external CLibCrypto name 'EVP_KDF_CTX_reset';
  function EVP_KDF_CTX_get_kdf_size(ctx: PEVP_KDF_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EVP_KDF_CTX_get_kdf_size';
  function EVP_KDF_derive(ctx: PEVP_KDF_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KDF_derive';
  function EVP_KDF_get_params(kdf: PEVP_KDF; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KDF_get_params';
  function EVP_KDF_CTX_get_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KDF_CTX_get_params';
  function EVP_KDF_CTX_set_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KDF_CTX_set_params';
  function EVP_KDF_gettable_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KDF_gettable_params';
  function EVP_KDF_gettable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KDF_gettable_ctx_params';
  function EVP_KDF_settable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KDF_settable_ctx_params';
  function EVP_KDF_CTX_gettable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KDF_CTX_gettable_params';
  function EVP_KDF_CTX_settable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KDF_CTX_settable_params';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM EVP_KDF_up_ref}
  {$EXTERNALSYM EVP_KDF_free}
  {$EXTERNALSYM EVP_KDF_fetch}
  {$EXTERNALSYM EVP_KDF_CTX_new}
  {$EXTERNALSYM EVP_KDF_CTX_free}
  {$EXTERNALSYM EVP_KDF_CTX_dup}
  {$EXTERNALSYM EVP_KDF_get0_description}
  {$EXTERNALSYM EVP_KDF_is_a}
  {$EXTERNALSYM EVP_KDF_get0_name}
  {$EXTERNALSYM EVP_KDF_get0_provider}
  {$EXTERNALSYM EVP_KDF_CTX_kdf}
  {$EXTERNALSYM EVP_KDF_CTX_reset}
  {$EXTERNALSYM EVP_KDF_CTX_get_kdf_size}
  {$EXTERNALSYM EVP_KDF_derive}
  {$EXTERNALSYM EVP_KDF_get_params}
  {$EXTERNALSYM EVP_KDF_CTX_get_params}
  {$EXTERNALSYM EVP_KDF_CTX_set_params}
  {$EXTERNALSYM EVP_KDF_gettable_params}
  {$EXTERNALSYM EVP_KDF_gettable_ctx_params}
  {$EXTERNALSYM EVP_KDF_settable_ctx_params}
  {$EXTERNALSYM EVP_KDF_CTX_gettable_params}
  {$EXTERNALSYM EVP_KDF_CTX_settable_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_KDF_up_ref(kdf: PEVP_KDF): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_KDF_free(kdf: PEVP_KDF); cdecl;
  function Load_EVP_KDF_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KDF; cdecl;
  function Load_EVP_KDF_CTX_new(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl;
  procedure Load_EVP_KDF_CTX_free(ctx: PEVP_KDF_CTX); cdecl;
  function Load_EVP_KDF_CTX_dup(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl;
  function Load_EVP_KDF_get0_description(kdf: PEVP_KDF): PAnsiChar; cdecl;
  function Load_EVP_KDF_is_a(kdf: PEVP_KDF; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KDF_get0_name(kdf: PEVP_KDF): PAnsiChar; cdecl;
  function Load_EVP_KDF_get0_provider(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl;
  function Load_EVP_KDF_CTX_kdf(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl;
  procedure Load_EVP_KDF_CTX_reset(ctx: PEVP_KDF_CTX); cdecl;
  function Load_EVP_KDF_CTX_get_kdf_size(ctx: PEVP_KDF_CTX): TOpenSSL_C_SIZET; cdecl;
  function Load_EVP_KDF_derive(ctx: PEVP_KDF_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KDF_get_params(kdf: PEVP_KDF; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KDF_CTX_get_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KDF_CTX_set_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KDF_gettable_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
  function Load_EVP_KDF_gettable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
  function Load_EVP_KDF_settable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
  function Load_EVP_KDF_CTX_gettable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_KDF_CTX_settable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl;

var
  EVP_KDF_up_ref: function(kdf: PEVP_KDF): TOpenSSL_C_INT; cdecl = Load_EVP_KDF_up_ref;
  EVP_KDF_free: procedure(kdf: PEVP_KDF); cdecl = Load_EVP_KDF_free;
  EVP_KDF_fetch: function(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KDF; cdecl = Load_EVP_KDF_fetch;
  EVP_KDF_CTX_new: function(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl = Load_EVP_KDF_CTX_new;
  EVP_KDF_CTX_free: procedure(ctx: PEVP_KDF_CTX); cdecl = Load_EVP_KDF_CTX_free;
  EVP_KDF_CTX_dup: function(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl = Load_EVP_KDF_CTX_dup;
  EVP_KDF_get0_description: function(kdf: PEVP_KDF): PAnsiChar; cdecl = Load_EVP_KDF_get0_description;
  EVP_KDF_is_a: function(kdf: PEVP_KDF; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_KDF_is_a;
  EVP_KDF_get0_name: function(kdf: PEVP_KDF): PAnsiChar; cdecl = Load_EVP_KDF_get0_name;
  EVP_KDF_get0_provider: function(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl = Load_EVP_KDF_get0_provider;
  EVP_KDF_CTX_kdf: function(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl = Load_EVP_KDF_CTX_kdf;
  EVP_KDF_CTX_reset: procedure(ctx: PEVP_KDF_CTX); cdecl = Load_EVP_KDF_CTX_reset;
  EVP_KDF_CTX_get_kdf_size: function(ctx: PEVP_KDF_CTX): TOpenSSL_C_SIZET; cdecl = Load_EVP_KDF_CTX_get_kdf_size;
  EVP_KDF_derive: function(ctx: PEVP_KDF_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_KDF_derive;
  EVP_KDF_get_params: function(kdf: PEVP_KDF; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_KDF_get_params;
  EVP_KDF_CTX_get_params: function(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_KDF_CTX_get_params;
  EVP_KDF_CTX_set_params: function(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_KDF_CTX_set_params;
  EVP_KDF_gettable_params: function(kdf: PEVP_KDF): POSSL_PARAM; cdecl = Load_EVP_KDF_gettable_params;
  EVP_KDF_gettable_ctx_params: function(kdf: PEVP_KDF): POSSL_PARAM; cdecl = Load_EVP_KDF_gettable_ctx_params;
  EVP_KDF_settable_ctx_params: function(kdf: PEVP_KDF): POSSL_PARAM; cdecl = Load_EVP_KDF_settable_ctx_params;
  EVP_KDF_CTX_gettable_params: function(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl = Load_EVP_KDF_CTX_gettable_params;
  EVP_KDF_CTX_settable_params: function(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl = Load_EVP_KDF_CTX_settable_params;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = procedure(kdf: PEVP_KDF; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_KDF_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl; external CLibCrypto name 'EVP_KDF_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_KDF_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_KDF_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;

var
  EVP_KDF_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl = Load_EVP_KDF_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_KDF_names_do_all(kdf: PEVP_KDF; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KDF_names_do_all';
  {$else}
  {$EXTERNALSYM EVP_KDF_names_do_all}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_KDF_names_do_all(kdf: PEVP_KDF; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;

var
  EVP_KDF_names_do_all: function(kdf: PEVP_KDF; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_KDF_names_do_all;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND = 0;
  EVP_KDF_HKDF_MODE_EXTRACT_ONLY = 1;
  EVP_KDF_HKDF_MODE_EXPAND_ONLY = 2;
  EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV = 65;
  EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI = 66;
  EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV = 67;
  EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI = 68;
  EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV = 69;
  EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI = 70;
  {*** The legacy PKEY-based KDF API follows. ***}
  EVP_PKEY_CTRL_TLS_MD = EVP_PKEY_ALG_CTRL;
  EVP_PKEY_CTRL_TLS_SECRET = EVP_PKEY_ALG_CTRL+1;
  EVP_PKEY_CTRL_TLS_SEED = EVP_PKEY_ALG_CTRL+2;
  EVP_PKEY_CTRL_HKDF_MD = EVP_PKEY_ALG_CTRL+3;
  EVP_PKEY_CTRL_HKDF_SALT = EVP_PKEY_ALG_CTRL+4;
  EVP_PKEY_CTRL_HKDF_KEY = EVP_PKEY_ALG_CTRL+5;
  EVP_PKEY_CTRL_HKDF_INFO = EVP_PKEY_ALG_CTRL+6;
  EVP_PKEY_CTRL_HKDF_MODE = EVP_PKEY_ALG_CTRL+7;
  EVP_PKEY_CTRL_PASS = EVP_PKEY_ALG_CTRL+8;
  EVP_PKEY_CTRL_SCRYPT_SALT = EVP_PKEY_ALG_CTRL+9;
  EVP_PKEY_CTRL_SCRYPT_N = EVP_PKEY_ALG_CTRL+10;
  EVP_PKEY_CTRL_SCRYPT_R = EVP_PKEY_ALG_CTRL+11;
  EVP_PKEY_CTRL_SCRYPT_P = EVP_PKEY_ALG_CTRL+12;
  EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES = EVP_PKEY_ALG_CTRL+13;
  EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
  EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
  EVP_PKEY_HKDEF_MODE_EXPAND_ONLY = EVP_KDF_HKDF_MODE_EXPAND_ONLY;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_tls1_prf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_tls1_prf_md';
  function EVP_PKEY_CTX_set1_tls1_prf_secret(pctx: PEVP_PKEY_CTX; sec: Pbyte; seclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set1_tls1_prf_secret';
  function EVP_PKEY_CTX_add1_tls1_prf_seed(pctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_add1_tls1_prf_seed';
  function EVP_PKEY_CTX_set_hkdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_hkdf_md';
  function EVP_PKEY_CTX_set1_hkdf_salt(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set1_hkdf_salt';
  function EVP_PKEY_CTX_set1_hkdf_key(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set1_hkdf_key';
  function EVP_PKEY_CTX_add1_hkdf_info(ctx: PEVP_PKEY_CTX; info: Pbyte; infolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_add1_hkdf_info';
  function EVP_PKEY_CTX_set_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_hkdf_mode';
  function EVP_PKEY_CTX_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_hkdf_mode';
  function EVP_PKEY_CTX_set1_pbe_pass(ctx: PEVP_PKEY_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set1_pbe_pass';
  function EVP_PKEY_CTX_set1_scrypt_salt(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set1_scrypt_salt';
  function EVP_PKEY_CTX_set_scrypt_N(ctx: PEVP_PKEY_CTX; n: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_N';
  function EVP_PKEY_CTX_set_scrypt_r(ctx: PEVP_PKEY_CTX; r: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_r';
  function EVP_PKEY_CTX_set_scrypt_p(ctx: PEVP_PKEY_CTX; p: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_p';
  function EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: PEVP_PKEY_CTX; maxmem_bytes: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_scrypt_maxmem_bytes';
  {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_set_tls1_prf_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set1_tls1_prf_secret}
  {$EXTERNALSYM EVP_PKEY_CTX_add1_tls1_prf_seed}
  {$EXTERNALSYM EVP_PKEY_CTX_set_hkdf_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set1_hkdf_salt}
  {$EXTERNALSYM EVP_PKEY_CTX_set1_hkdf_key}
  {$EXTERNALSYM EVP_PKEY_CTX_add1_hkdf_info}
  {$EXTERNALSYM EVP_PKEY_CTX_set_hkdf_mode}
  {$EXTERNALSYM EVP_PKEY_CTX_hkdf_mode}
  {$EXTERNALSYM EVP_PKEY_CTX_set1_pbe_pass}
  {$EXTERNALSYM EVP_PKEY_CTX_set1_scrypt_salt}
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_N}
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_r}
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_p}
  {$EXTERNALSYM EVP_PKEY_CTX_set_scrypt_maxmem_bytes}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_tls1_prf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set1_tls1_prf_secret(pctx: PEVP_PKEY_CTX; sec: Pbyte; seclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_add1_tls1_prf_seed(pctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_hkdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set1_hkdf_salt(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set1_hkdf_key(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_add1_hkdf_info(ctx: PEVP_PKEY_CTX; info: Pbyte; infolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set1_pbe_pass(ctx: PEVP_PKEY_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set1_scrypt_salt(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_scrypt_N(ctx: PEVP_PKEY_CTX; n: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_scrypt_r(ctx: PEVP_PKEY_CTX; r: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_scrypt_p(ctx: PEVP_PKEY_CTX; p: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: PEVP_PKEY_CTX; maxmem_bytes: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_tls1_prf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_tls1_prf_md;
  EVP_PKEY_CTX_set1_tls1_prf_secret: function(pctx: PEVP_PKEY_CTX; sec: Pbyte; seclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set1_tls1_prf_secret;
  EVP_PKEY_CTX_add1_tls1_prf_seed: function(pctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_add1_tls1_prf_seed;
  EVP_PKEY_CTX_set_hkdf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_hkdf_md;
  EVP_PKEY_CTX_set1_hkdf_salt: function(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set1_hkdf_salt;
  EVP_PKEY_CTX_set1_hkdf_key: function(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set1_hkdf_key;
  EVP_PKEY_CTX_add1_hkdf_info: function(ctx: PEVP_PKEY_CTX; info: Pbyte; infolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_add1_hkdf_info;
  EVP_PKEY_CTX_set_hkdf_mode: function(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_hkdf_mode;
  EVP_PKEY_CTX_hkdf_mode: function(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_hkdf_mode;
  EVP_PKEY_CTX_set1_pbe_pass: function(ctx: PEVP_PKEY_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set1_pbe_pass;
  EVP_PKEY_CTX_set1_scrypt_salt: function(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set1_scrypt_salt;
  EVP_PKEY_CTX_set_scrypt_N: function(ctx: PEVP_PKEY_CTX; n: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_scrypt_N;
  EVP_PKEY_CTX_set_scrypt_r: function(ctx: PEVP_PKEY_CTX; r: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_scrypt_r;
  EVP_PKEY_CTX_set_scrypt_p: function(ctx: PEVP_PKEY_CTX; p: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_scrypt_p;
  EVP_PKEY_CTX_set_scrypt_maxmem_bytes: function(ctx: PEVP_PKEY_CTX; maxmem_bytes: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_scrypt_maxmem_bytes;
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

{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_EVP_KDF_up_ref(kdf: PEVP_KDF): TOpenSSL_C_INT; cdecl;
begin
  EVP_KDF_up_ref := LoadLibCryptoFunction('EVP_KDF_up_ref');
  if not assigned(EVP_KDF_up_ref) then
    {$if declared(LEGACY_EVP_KDF_up_ref)}
    EVP_KDF_up_ref := @LEGACY_EVP_KDF_up_ref;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_up_ref');
    {$ifend}
  Result := EVP_KDF_up_ref(kdf);
end;

procedure Load_EVP_KDF_free(kdf: PEVP_KDF); cdecl;
begin
  EVP_KDF_free := LoadLibCryptoFunction('EVP_KDF_free');
  if not assigned(EVP_KDF_free) then
    {$if declared(LEGACY_EVP_KDF_free)}
    EVP_KDF_free := @LEGACY_EVP_KDF_free;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_free');
    {$ifend}
  EVP_KDF_free(kdf);
end;

function Load_EVP_KDF_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KDF; cdecl;
begin
  EVP_KDF_fetch := LoadLibCryptoFunction('EVP_KDF_fetch');
  if not assigned(EVP_KDF_fetch) then
    {$if declared(LEGACY_EVP_KDF_fetch)}
    EVP_KDF_fetch := @LEGACY_EVP_KDF_fetch;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_fetch');
    {$ifend}
  Result := EVP_KDF_fetch(libctx, algorithm, properties);
end;

function Load_EVP_KDF_CTX_new(kdf: PEVP_KDF): PEVP_KDF_CTX; cdecl;
begin
  EVP_KDF_CTX_new := LoadLibCryptoFunction('EVP_KDF_CTX_new');
  if not assigned(EVP_KDF_CTX_new) then
    {$if declared(LEGACY_EVP_KDF_CTX_new)}
    EVP_KDF_CTX_new := @LEGACY_EVP_KDF_CTX_new;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_new');
    {$ifend}
  Result := EVP_KDF_CTX_new(kdf);
end;

procedure Load_EVP_KDF_CTX_free(ctx: PEVP_KDF_CTX); cdecl;
begin
  EVP_KDF_CTX_free := LoadLibCryptoFunction('EVP_KDF_CTX_free');
  if not assigned(EVP_KDF_CTX_free) then
    {$if declared(LEGACY_EVP_KDF_CTX_free)}
    EVP_KDF_CTX_free := @LEGACY_EVP_KDF_CTX_free;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_free');
    {$ifend}
  EVP_KDF_CTX_free(ctx);
end;

function Load_EVP_KDF_CTX_dup(src: PEVP_KDF_CTX): PEVP_KDF_CTX; cdecl;
begin
  EVP_KDF_CTX_dup := LoadLibCryptoFunction('EVP_KDF_CTX_dup');
  if not assigned(EVP_KDF_CTX_dup) then
    {$if declared(LEGACY_EVP_KDF_CTX_dup)}
    EVP_KDF_CTX_dup := @LEGACY_EVP_KDF_CTX_dup;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_dup');
    {$ifend}
  Result := EVP_KDF_CTX_dup(src);
end;

function Load_EVP_KDF_get0_description(kdf: PEVP_KDF): PAnsiChar; cdecl;
begin
  EVP_KDF_get0_description := LoadLibCryptoFunction('EVP_KDF_get0_description');
  if not assigned(EVP_KDF_get0_description) then
    {$if declared(LEGACY_EVP_KDF_get0_description)}
    EVP_KDF_get0_description := @LEGACY_EVP_KDF_get0_description;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_get0_description');
    {$ifend}
  Result := EVP_KDF_get0_description(kdf);
end;

function Load_EVP_KDF_is_a(kdf: PEVP_KDF; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_KDF_is_a := LoadLibCryptoFunction('EVP_KDF_is_a');
  if not assigned(EVP_KDF_is_a) then
    {$if declared(LEGACY_EVP_KDF_is_a)}
    EVP_KDF_is_a := @LEGACY_EVP_KDF_is_a;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_is_a');
    {$ifend}
  Result := EVP_KDF_is_a(kdf, name);
end;

function Load_EVP_KDF_get0_name(kdf: PEVP_KDF): PAnsiChar; cdecl;
begin
  EVP_KDF_get0_name := LoadLibCryptoFunction('EVP_KDF_get0_name');
  if not assigned(EVP_KDF_get0_name) then
    {$if declared(LEGACY_EVP_KDF_get0_name)}
    EVP_KDF_get0_name := @LEGACY_EVP_KDF_get0_name;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_get0_name');
    {$ifend}
  Result := EVP_KDF_get0_name(kdf);
end;

function Load_EVP_KDF_get0_provider(kdf: PEVP_KDF): POSSL_PROVIDER; cdecl;
begin
  EVP_KDF_get0_provider := LoadLibCryptoFunction('EVP_KDF_get0_provider');
  if not assigned(EVP_KDF_get0_provider) then
    {$if declared(LEGACY_EVP_KDF_get0_provider)}
    EVP_KDF_get0_provider := @LEGACY_EVP_KDF_get0_provider;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_get0_provider');
    {$ifend}
  Result := EVP_KDF_get0_provider(kdf);
end;

function Load_EVP_KDF_CTX_kdf(ctx: PEVP_KDF_CTX): PEVP_KDF; cdecl;
begin
  EVP_KDF_CTX_kdf := LoadLibCryptoFunction('EVP_KDF_CTX_kdf');
  if not assigned(EVP_KDF_CTX_kdf) then
    {$if declared(LEGACY_EVP_KDF_CTX_kdf)}
    EVP_KDF_CTX_kdf := @LEGACY_EVP_KDF_CTX_kdf;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_kdf');
    {$ifend}
  Result := EVP_KDF_CTX_kdf(ctx);
end;

procedure Load_EVP_KDF_CTX_reset(ctx: PEVP_KDF_CTX); cdecl;
begin
  EVP_KDF_CTX_reset := LoadLibCryptoFunction('EVP_KDF_CTX_reset');
  if not assigned(EVP_KDF_CTX_reset) then
    {$if declared(LEGACY_EVP_KDF_CTX_reset)}
    EVP_KDF_CTX_reset := @LEGACY_EVP_KDF_CTX_reset;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_reset');
    {$ifend}
  EVP_KDF_CTX_reset(ctx);
end;

function Load_EVP_KDF_CTX_get_kdf_size(ctx: PEVP_KDF_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EVP_KDF_CTX_get_kdf_size := LoadLibCryptoFunction('EVP_KDF_CTX_get_kdf_size');
  if not assigned(EVP_KDF_CTX_get_kdf_size) then
    {$if declared(LEGACY_EVP_KDF_CTX_get_kdf_size)}
    EVP_KDF_CTX_get_kdf_size := @LEGACY_EVP_KDF_CTX_get_kdf_size;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_get_kdf_size');
    {$ifend}
  Result := EVP_KDF_CTX_get_kdf_size(ctx);
end;

function Load_EVP_KDF_derive(ctx: PEVP_KDF_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_KDF_derive := LoadLibCryptoFunction('EVP_KDF_derive');
  if not assigned(EVP_KDF_derive) then
    {$if declared(LEGACY_EVP_KDF_derive)}
    EVP_KDF_derive := @LEGACY_EVP_KDF_derive;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_derive');
    {$ifend}
  Result := EVP_KDF_derive(ctx, key, keylen, params);
end;

function Load_EVP_KDF_get_params(kdf: PEVP_KDF; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_KDF_get_params := LoadLibCryptoFunction('EVP_KDF_get_params');
  if not assigned(EVP_KDF_get_params) then
    {$if declared(LEGACY_EVP_KDF_get_params)}
    EVP_KDF_get_params := @LEGACY_EVP_KDF_get_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_get_params');
    {$ifend}
  Result := EVP_KDF_get_params(kdf, params);
end;

function Load_EVP_KDF_CTX_get_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_KDF_CTX_get_params := LoadLibCryptoFunction('EVP_KDF_CTX_get_params');
  if not assigned(EVP_KDF_CTX_get_params) then
    {$if declared(LEGACY_EVP_KDF_CTX_get_params)}
    EVP_KDF_CTX_get_params := @LEGACY_EVP_KDF_CTX_get_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_get_params');
    {$ifend}
  Result := EVP_KDF_CTX_get_params(ctx, params);
end;

function Load_EVP_KDF_CTX_set_params(ctx: PEVP_KDF_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_KDF_CTX_set_params := LoadLibCryptoFunction('EVP_KDF_CTX_set_params');
  if not assigned(EVP_KDF_CTX_set_params) then
    {$if declared(LEGACY_EVP_KDF_CTX_set_params)}
    EVP_KDF_CTX_set_params := @LEGACY_EVP_KDF_CTX_set_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_set_params');
    {$ifend}
  Result := EVP_KDF_CTX_set_params(ctx, params);
end;

function Load_EVP_KDF_gettable_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
begin
  EVP_KDF_gettable_params := LoadLibCryptoFunction('EVP_KDF_gettable_params');
  if not assigned(EVP_KDF_gettable_params) then
    {$if declared(LEGACY_EVP_KDF_gettable_params)}
    EVP_KDF_gettable_params := @LEGACY_EVP_KDF_gettable_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_gettable_params');
    {$ifend}
  Result := EVP_KDF_gettable_params(kdf);
end;

function Load_EVP_KDF_gettable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
begin
  EVP_KDF_gettable_ctx_params := LoadLibCryptoFunction('EVP_KDF_gettable_ctx_params');
  if not assigned(EVP_KDF_gettable_ctx_params) then
    {$if declared(LEGACY_EVP_KDF_gettable_ctx_params)}
    EVP_KDF_gettable_ctx_params := @LEGACY_EVP_KDF_gettable_ctx_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_gettable_ctx_params');
    {$ifend}
  Result := EVP_KDF_gettable_ctx_params(kdf);
end;

function Load_EVP_KDF_settable_ctx_params(kdf: PEVP_KDF): POSSL_PARAM; cdecl;
begin
  EVP_KDF_settable_ctx_params := LoadLibCryptoFunction('EVP_KDF_settable_ctx_params');
  if not assigned(EVP_KDF_settable_ctx_params) then
    {$if declared(LEGACY_EVP_KDF_settable_ctx_params)}
    EVP_KDF_settable_ctx_params := @LEGACY_EVP_KDF_settable_ctx_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_settable_ctx_params');
    {$ifend}
  Result := EVP_KDF_settable_ctx_params(kdf);
end;

function Load_EVP_KDF_CTX_gettable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl;
begin
  EVP_KDF_CTX_gettable_params := LoadLibCryptoFunction('EVP_KDF_CTX_gettable_params');
  if not assigned(EVP_KDF_CTX_gettable_params) then
    {$if declared(LEGACY_EVP_KDF_CTX_gettable_params)}
    EVP_KDF_CTX_gettable_params := @LEGACY_EVP_KDF_CTX_gettable_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_gettable_params');
    {$ifend}
  Result := EVP_KDF_CTX_gettable_params(ctx);
end;

function Load_EVP_KDF_CTX_settable_params(ctx: PEVP_KDF_CTX): POSSL_PARAM; cdecl;
begin
  EVP_KDF_CTX_settable_params := LoadLibCryptoFunction('EVP_KDF_CTX_settable_params');
  if not assigned(EVP_KDF_CTX_settable_params) then
    {$if declared(LEGACY_EVP_KDF_CTX_settable_params)}
    EVP_KDF_CTX_settable_params := @LEGACY_EVP_KDF_CTX_settable_params;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_CTX_settable_params');
    {$ifend}
  Result := EVP_KDF_CTX_settable_params(ctx);
end;

procedure Load_EVP_KDF_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;
begin
  EVP_KDF_do_all_provided := LoadLibCryptoFunction('EVP_KDF_do_all_provided');
  if not assigned(EVP_KDF_do_all_provided) then
    {$if declared(LEGACY_EVP_KDF_do_all_provided)}
    EVP_KDF_do_all_provided := @LEGACY_EVP_KDF_do_all_provided;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_do_all_provided');
    {$ifend}
  EVP_KDF_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_KDF_names_do_all(kdf: PEVP_KDF; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_KDF_names_do_all := LoadLibCryptoFunction('EVP_KDF_names_do_all');
  if not assigned(EVP_KDF_names_do_all) then
    {$if declared(LEGACY_EVP_KDF_names_do_all)}
    EVP_KDF_names_do_all := @LEGACY_EVP_KDF_names_do_all;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KDF_names_do_all');
    {$ifend}
  Result := EVP_KDF_names_do_all(kdf, fn, data);
end;

function Load_EVP_PKEY_CTX_set_tls1_prf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_tls1_prf_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_tls1_prf_md');
  if not assigned(EVP_PKEY_CTX_set_tls1_prf_md) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_tls1_prf_md)}
    EVP_PKEY_CTX_set_tls1_prf_md := @LEGACY_EVP_PKEY_CTX_set_tls1_prf_md;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_tls1_prf_md');
    {$ifend}
  Result := EVP_PKEY_CTX_set_tls1_prf_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set1_tls1_prf_secret(pctx: PEVP_PKEY_CTX; sec: Pbyte; seclen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set1_tls1_prf_secret := LoadLibCryptoFunction('EVP_PKEY_CTX_set1_tls1_prf_secret');
  if not assigned(EVP_PKEY_CTX_set1_tls1_prf_secret) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set1_tls1_prf_secret)}
    EVP_PKEY_CTX_set1_tls1_prf_secret := @LEGACY_EVP_PKEY_CTX_set1_tls1_prf_secret;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set1_tls1_prf_secret');
    {$ifend}
  Result := EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, seclen);
end;

function Load_EVP_PKEY_CTX_add1_tls1_prf_seed(pctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_add1_tls1_prf_seed := LoadLibCryptoFunction('EVP_PKEY_CTX_add1_tls1_prf_seed');
  if not assigned(EVP_PKEY_CTX_add1_tls1_prf_seed) then
    {$if declared(LEGACY_EVP_PKEY_CTX_add1_tls1_prf_seed)}
    EVP_PKEY_CTX_add1_tls1_prf_seed := @LEGACY_EVP_PKEY_CTX_add1_tls1_prf_seed;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_add1_tls1_prf_seed');
    {$ifend}
  Result := EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seedlen);
end;

function Load_EVP_PKEY_CTX_set_hkdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_hkdf_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_hkdf_md');
  if not assigned(EVP_PKEY_CTX_set_hkdf_md) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_hkdf_md)}
    EVP_PKEY_CTX_set_hkdf_md := @LEGACY_EVP_PKEY_CTX_set_hkdf_md;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_hkdf_md');
    {$ifend}
  Result := EVP_PKEY_CTX_set_hkdf_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set1_hkdf_salt(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set1_hkdf_salt := LoadLibCryptoFunction('EVP_PKEY_CTX_set1_hkdf_salt');
  if not assigned(EVP_PKEY_CTX_set1_hkdf_salt) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set1_hkdf_salt)}
    EVP_PKEY_CTX_set1_hkdf_salt := @LEGACY_EVP_PKEY_CTX_set1_hkdf_salt;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set1_hkdf_salt');
    {$ifend}
  Result := EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, saltlen);
end;

function Load_EVP_PKEY_CTX_set1_hkdf_key(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set1_hkdf_key := LoadLibCryptoFunction('EVP_PKEY_CTX_set1_hkdf_key');
  if not assigned(EVP_PKEY_CTX_set1_hkdf_key) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set1_hkdf_key)}
    EVP_PKEY_CTX_set1_hkdf_key := @LEGACY_EVP_PKEY_CTX_set1_hkdf_key;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set1_hkdf_key');
    {$ifend}
  Result := EVP_PKEY_CTX_set1_hkdf_key(ctx, key, keylen);
end;

function Load_EVP_PKEY_CTX_add1_hkdf_info(ctx: PEVP_PKEY_CTX; info: Pbyte; infolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_add1_hkdf_info := LoadLibCryptoFunction('EVP_PKEY_CTX_add1_hkdf_info');
  if not assigned(EVP_PKEY_CTX_add1_hkdf_info) then
    {$if declared(LEGACY_EVP_PKEY_CTX_add1_hkdf_info)}
    EVP_PKEY_CTX_add1_hkdf_info := @LEGACY_EVP_PKEY_CTX_add1_hkdf_info;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_add1_hkdf_info');
    {$ifend}
  Result := EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infolen);
end;

function Load_EVP_PKEY_CTX_set_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_hkdf_mode := LoadLibCryptoFunction('EVP_PKEY_CTX_set_hkdf_mode');
  if not assigned(EVP_PKEY_CTX_set_hkdf_mode) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_hkdf_mode)}
    EVP_PKEY_CTX_set_hkdf_mode := @LEGACY_EVP_PKEY_CTX_set_hkdf_mode;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_hkdf_mode');
    {$ifend}
  Result := EVP_PKEY_CTX_set_hkdf_mode(ctx, mode);
end;

function Load_EVP_PKEY_CTX_hkdf_mode(ctx: PEVP_PKEY_CTX; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_hkdf_mode := LoadLibCryptoFunction('EVP_PKEY_CTX_set_hkdf_mode');
  if not assigned(EVP_PKEY_CTX_hkdf_mode) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_hkdf_mode)}
    EVP_PKEY_CTX_hkdf_mode := @LEGACY_EVP_PKEY_CTX_set_hkdf_mode;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_hkdf_mode');
    {$ifend}
  Result := EVP_PKEY_CTX_hkdf_mode(ctx, mode);
end;

function Load_EVP_PKEY_CTX_set1_pbe_pass(ctx: PEVP_PKEY_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set1_pbe_pass := LoadLibCryptoFunction('EVP_PKEY_CTX_set1_pbe_pass');
  if not assigned(EVP_PKEY_CTX_set1_pbe_pass) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set1_pbe_pass)}
    EVP_PKEY_CTX_set1_pbe_pass := @LEGACY_EVP_PKEY_CTX_set1_pbe_pass;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set1_pbe_pass');
    {$ifend}
  Result := EVP_PKEY_CTX_set1_pbe_pass(ctx, pass, passlen);
end;

function Load_EVP_PKEY_CTX_set1_scrypt_salt(ctx: PEVP_PKEY_CTX; salt: Pbyte; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set1_scrypt_salt := LoadLibCryptoFunction('EVP_PKEY_CTX_set1_scrypt_salt');
  if not assigned(EVP_PKEY_CTX_set1_scrypt_salt) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set1_scrypt_salt)}
    EVP_PKEY_CTX_set1_scrypt_salt := @LEGACY_EVP_PKEY_CTX_set1_scrypt_salt;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set1_scrypt_salt');
    {$ifend}
  Result := EVP_PKEY_CTX_set1_scrypt_salt(ctx, salt, saltlen);
end;

function Load_EVP_PKEY_CTX_set_scrypt_N(ctx: PEVP_PKEY_CTX; n: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_scrypt_N := LoadLibCryptoFunction('EVP_PKEY_CTX_set_scrypt_N');
  if not assigned(EVP_PKEY_CTX_set_scrypt_N) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_scrypt_N)}
    EVP_PKEY_CTX_set_scrypt_N := @LEGACY_EVP_PKEY_CTX_set_scrypt_N;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_scrypt_N');
    {$ifend}
  Result := EVP_PKEY_CTX_set_scrypt_N(ctx, n);
end;

function Load_EVP_PKEY_CTX_set_scrypt_r(ctx: PEVP_PKEY_CTX; r: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_scrypt_r := LoadLibCryptoFunction('EVP_PKEY_CTX_set_scrypt_r');
  if not assigned(EVP_PKEY_CTX_set_scrypt_r) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_scrypt_r)}
    EVP_PKEY_CTX_set_scrypt_r := @LEGACY_EVP_PKEY_CTX_set_scrypt_r;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_scrypt_r');
    {$ifend}
  Result := EVP_PKEY_CTX_set_scrypt_r(ctx, r);
end;

function Load_EVP_PKEY_CTX_set_scrypt_p(ctx: PEVP_PKEY_CTX; p: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_scrypt_p := LoadLibCryptoFunction('EVP_PKEY_CTX_set_scrypt_p');
  if not assigned(EVP_PKEY_CTX_set_scrypt_p) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_scrypt_p)}
    EVP_PKEY_CTX_set_scrypt_p := @LEGACY_EVP_PKEY_CTX_set_scrypt_p;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_scrypt_p');
    {$ifend}
  Result := EVP_PKEY_CTX_set_scrypt_p(ctx, p);
end;

function Load_EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: PEVP_PKEY_CTX; maxmem_bytes: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_scrypt_maxmem_bytes := LoadLibCryptoFunction('EVP_PKEY_CTX_set_scrypt_maxmem_bytes');
  if not assigned(EVP_PKEY_CTX_set_scrypt_maxmem_bytes) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_scrypt_maxmem_bytes)}
    EVP_PKEY_CTX_set_scrypt_maxmem_bytes := @LEGACY_EVP_PKEY_CTX_set_scrypt_maxmem_bytes;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_scrypt_maxmem_bytes');
    {$ifend}
  Result := EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx, maxmem_bytes);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  EVP_KDF_up_ref := Load_EVP_KDF_up_ref;
  EVP_KDF_free := Load_EVP_KDF_free;
  EVP_KDF_fetch := Load_EVP_KDF_fetch;
  EVP_KDF_CTX_new := Load_EVP_KDF_CTX_new;
  EVP_KDF_CTX_free := Load_EVP_KDF_CTX_free;
  EVP_KDF_CTX_dup := Load_EVP_KDF_CTX_dup;
  EVP_KDF_get0_description := Load_EVP_KDF_get0_description;
  EVP_KDF_is_a := Load_EVP_KDF_is_a;
  EVP_KDF_get0_name := Load_EVP_KDF_get0_name;
  EVP_KDF_get0_provider := Load_EVP_KDF_get0_provider;
  EVP_KDF_CTX_kdf := Load_EVP_KDF_CTX_kdf;
  EVP_KDF_CTX_reset := Load_EVP_KDF_CTX_reset;
  EVP_KDF_CTX_get_kdf_size := Load_EVP_KDF_CTX_get_kdf_size;
  EVP_KDF_derive := Load_EVP_KDF_derive;
  EVP_KDF_get_params := Load_EVP_KDF_get_params;
  EVP_KDF_CTX_get_params := Load_EVP_KDF_CTX_get_params;
  EVP_KDF_CTX_set_params := Load_EVP_KDF_CTX_set_params;
  EVP_KDF_gettable_params := Load_EVP_KDF_gettable_params;
  EVP_KDF_gettable_ctx_params := Load_EVP_KDF_gettable_ctx_params;
  EVP_KDF_settable_ctx_params := Load_EVP_KDF_settable_ctx_params;
  EVP_KDF_CTX_gettable_params := Load_EVP_KDF_CTX_gettable_params;
  EVP_KDF_CTX_settable_params := Load_EVP_KDF_CTX_settable_params;
  EVP_KDF_do_all_provided := Load_EVP_KDF_do_all_provided;
  EVP_KDF_names_do_all := Load_EVP_KDF_names_do_all;
  EVP_PKEY_CTX_set_tls1_prf_md := Load_EVP_PKEY_CTX_set_tls1_prf_md;
  EVP_PKEY_CTX_set1_tls1_prf_secret := Load_EVP_PKEY_CTX_set1_tls1_prf_secret;
  EVP_PKEY_CTX_add1_tls1_prf_seed := Load_EVP_PKEY_CTX_add1_tls1_prf_seed;
  EVP_PKEY_CTX_set_hkdf_md := Load_EVP_PKEY_CTX_set_hkdf_md;
  EVP_PKEY_CTX_set1_hkdf_salt := Load_EVP_PKEY_CTX_set1_hkdf_salt;
  EVP_PKEY_CTX_set1_hkdf_key := Load_EVP_PKEY_CTX_set1_hkdf_key;
  EVP_PKEY_CTX_add1_hkdf_info := Load_EVP_PKEY_CTX_add1_hkdf_info;
  EVP_PKEY_CTX_set_hkdf_mode := Load_EVP_PKEY_CTX_set_hkdf_mode;
  EVP_PKEY_CTX_hkdf_mode := Load_EVP_PKEY_CTX_hkdf_mode;
  EVP_PKEY_CTX_set1_pbe_pass := Load_EVP_PKEY_CTX_set1_pbe_pass;
  EVP_PKEY_CTX_set1_scrypt_salt := Load_EVP_PKEY_CTX_set1_scrypt_salt;
  EVP_PKEY_CTX_set_scrypt_N := Load_EVP_PKEY_CTX_set_scrypt_N;
  EVP_PKEY_CTX_set_scrypt_r := Load_EVP_PKEY_CTX_set_scrypt_r;
  EVP_PKEY_CTX_set_scrypt_p := Load_EVP_PKEY_CTX_set_scrypt_p;
  EVP_PKEY_CTX_set_scrypt_maxmem_bytes := Load_EVP_PKEY_CTX_set_scrypt_maxmem_bytes;
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



