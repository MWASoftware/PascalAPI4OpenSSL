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

unit openssl_encoder;

{
  Generated from OpenSSL 3.5.6 Header File encoder.h - Tue 19 May 14:27:38 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_encoder.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_encodererr,openssl_types,openssl_core;


{* Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_ENCODER_H}
  {$define OPENSSL_ENCODER_H}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_STDIO}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_ENCODER; cdecl; external CLibCrypto name 'OSSL_ENCODER_fetch';
  function OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_up_ref';
  procedure OSSL_ENCODER_free(encoder: POSSL_ENCODER); cdecl; external CLibCrypto name 'OSSL_ENCODER_free';
  function OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_ENCODER_get0_provider';
  function OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_ENCODER_get0_properties';
  function OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_ENCODER_get0_name';
  function OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_ENCODER_get0_description';
  function OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_is_a';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_ENCODER_fetch}
  {$EXTERNALSYM OSSL_ENCODER_up_ref}
  {$EXTERNALSYM OSSL_ENCODER_free}
  {$EXTERNALSYM OSSL_ENCODER_get0_provider}
  {$EXTERNALSYM OSSL_ENCODER_get0_properties}
  {$EXTERNALSYM OSSL_ENCODER_get0_name}
  {$EXTERNALSYM OSSL_ENCODER_get0_description}
  {$EXTERNALSYM OSSL_ENCODER_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_ENCODER; cdecl;
  function Load_OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_ENCODER_free(encoder: POSSL_ENCODER); cdecl;
  function Load_OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl;
  function Load_OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER): PAnsiChar; cdecl;
  function Load_OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PAnsiChar; cdecl;
  function Load_OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PAnsiChar; cdecl;
  function Load_OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  OSSL_ENCODER_fetch: function(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_ENCODER; cdecl = Load_OSSL_ENCODER_fetch;
  OSSL_ENCODER_up_ref: function(encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_up_ref;
  OSSL_ENCODER_free: procedure(encoder: POSSL_ENCODER); cdecl = Load_OSSL_ENCODER_free;
  OSSL_ENCODER_get0_provider: function(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl = Load_OSSL_ENCODER_get0_provider;
  OSSL_ENCODER_get0_properties: function(encoder: POSSL_ENCODER): PAnsiChar; cdecl = Load_OSSL_ENCODER_get0_properties;
  OSSL_ENCODER_get0_name: function(kdf: POSSL_ENCODER): PAnsiChar; cdecl = Load_OSSL_ENCODER_get0_name;
  OSSL_ENCODER_get0_description: function(kdf: POSSL_ENCODER): PAnsiChar; cdecl = Load_OSSL_ENCODER_get0_description;
  OSSL_ENCODER_is_a: function(encoder: POSSL_ENCODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = procedure(encoder: POSSL_ENCODER; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl; external CLibCrypto name 'OSSL_ENCODER_do_all_provided';
  {$else}
  {$EXTERNALSYM OSSL_ENCODER_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;

var
  OSSL_ENCODER_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl = Load_OSSL_ENCODER_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_names_do_all';
  function OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_ENCODER_gettable_params';
  function OSSL_ENCODER_get_params(encoder: POSSL_ENCODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_get_params';
  function OSSL_ENCODER_settable_ctx_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_ENCODER_settable_ctx_params';
  function OSSL_ENCODER_CTX_new: POSSL_ENCODER_CTX; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_new';
  function OSSL_ENCODER_CTX_set_params(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_params';
  procedure OSSL_ENCODER_CTX_free(ctx: POSSL_ENCODER_CTX); cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_free';
  { Utilities that help set specific parameters }
  function OSSL_ENCODER_CTX_set_passphrase(ctx: POSSL_ENCODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_passphrase';
  function OSSL_ENCODER_CTX_set_pem_password_cb(ctx: POSSL_ENCODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_pem_password_cb';
  function OSSL_ENCODER_CTX_set_passphrase_cb(ctx: POSSL_ENCODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_passphrase_cb';
  function OSSL_ENCODER_CTX_set_passphrase_ui(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_passphrase_ui';
  function OSSL_ENCODER_CTX_set_cipher(ctx: POSSL_ENCODER_CTX; cipher_name: PAnsiChar; propquery: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_cipher';
  function OSSL_ENCODER_CTX_set_selection(ctx: POSSL_ENCODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_selection';
  function OSSL_ENCODER_CTX_set_output_type(ctx: POSSL_ENCODER_CTX; output_type: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_output_type';
  function OSSL_ENCODER_CTX_set_output_structure(ctx: POSSL_ENCODER_CTX; output_structure: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_output_structure';
  { Utilities to add encoders }
  function OSSL_ENCODER_CTX_add_encoder(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_add_encoder';
  function OSSL_ENCODER_CTX_add_extra(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_add_extra';
  function OSSL_ENCODER_CTX_get_num_encoders(ctx: POSSL_ENCODER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_get_num_encoders';
  {$else}
  {$EXTERNALSYM OSSL_ENCODER_names_do_all}
  {$EXTERNALSYM OSSL_ENCODER_gettable_params}
  {$EXTERNALSYM OSSL_ENCODER_get_params}
  {$EXTERNALSYM OSSL_ENCODER_settable_ctx_params}
  {$EXTERNALSYM OSSL_ENCODER_CTX_new}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_params}
  {$EXTERNALSYM OSSL_ENCODER_CTX_free}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_pem_password_cb}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_cb}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_passphrase_ui}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_cipher}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_selection}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_type}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_output_structure}
  {$EXTERNALSYM OSSL_ENCODER_CTX_add_encoder}
  {$EXTERNALSYM OSSL_ENCODER_CTX_add_extra}
  {$EXTERNALSYM OSSL_ENCODER_CTX_get_num_encoders}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl;
  function Load_OSSL_ENCODER_get_params(encoder: POSSL_ENCODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_settable_ctx_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl;
  function Load_OSSL_ENCODER_CTX_new: POSSL_ENCODER_CTX; cdecl;
  function Load_OSSL_ENCODER_CTX_set_params(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_ENCODER_CTX_free(ctx: POSSL_ENCODER_CTX); cdecl;
  function Load_OSSL_ENCODER_CTX_set_passphrase(ctx: POSSL_ENCODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_pem_password_cb(ctx: POSSL_ENCODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_passphrase_cb(ctx: POSSL_ENCODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_passphrase_ui(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_cipher(ctx: POSSL_ENCODER_CTX; cipher_name: PAnsiChar; propquery: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_selection(ctx: POSSL_ENCODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_output_type(ctx: POSSL_ENCODER_CTX; output_type: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_output_structure(ctx: POSSL_ENCODER_CTX; output_structure: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_add_encoder(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_add_extra(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_get_num_encoders(ctx: POSSL_ENCODER_CTX): TOpenSSL_C_INT; cdecl;

var
  OSSL_ENCODER_names_do_all: function(encoder: POSSL_ENCODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_names_do_all;
  OSSL_ENCODER_gettable_params: function(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl = Load_OSSL_ENCODER_gettable_params;
  OSSL_ENCODER_get_params: function(encoder: POSSL_ENCODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_get_params;
  OSSL_ENCODER_settable_ctx_params: function(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl = Load_OSSL_ENCODER_settable_ctx_params;
  OSSL_ENCODER_CTX_new: function: POSSL_ENCODER_CTX; cdecl = Load_OSSL_ENCODER_CTX_new;
  OSSL_ENCODER_CTX_set_params: function(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_params;
  OSSL_ENCODER_CTX_free: procedure(ctx: POSSL_ENCODER_CTX); cdecl = Load_OSSL_ENCODER_CTX_free;
  { Utilities that help set specific parameters }
  OSSL_ENCODER_CTX_set_passphrase: function(ctx: POSSL_ENCODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_passphrase;
  OSSL_ENCODER_CTX_set_pem_password_cb: function(ctx: POSSL_ENCODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_pem_password_cb;
  OSSL_ENCODER_CTX_set_passphrase_cb: function(ctx: POSSL_ENCODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_passphrase_cb;
  OSSL_ENCODER_CTX_set_passphrase_ui: function(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_passphrase_ui;
  OSSL_ENCODER_CTX_set_cipher: function(ctx: POSSL_ENCODER_CTX; cipher_name: PAnsiChar; propquery: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_cipher;
  OSSL_ENCODER_CTX_set_selection: function(ctx: POSSL_ENCODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_selection;
  OSSL_ENCODER_CTX_set_output_type: function(ctx: POSSL_ENCODER_CTX; output_type: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_output_type;
  OSSL_ENCODER_CTX_set_output_structure: function(ctx: POSSL_ENCODER_CTX; output_structure: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_output_structure;
  { Utilities to add encoders }
  OSSL_ENCODER_CTX_add_encoder: function(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_add_encoder;
  OSSL_ENCODER_CTX_add_extra: function(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_add_extra;
  OSSL_ENCODER_CTX_get_num_encoders: function(ctx: POSSL_ENCODER_CTX): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_get_num_encoders;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  Possl_encoder_instance_st = ^TOSSL_ENCODER_INSTANCE;
  PPossl_encoder_instance_st = ^Possl_encoder_instance_st;
  POSSL_ENCODER_INSTANCE = ^TOSSL_ENCODER_INSTANCE;
  PPOSSL_ENCODER_INSTANCE = ^POSSL_ENCODER_INSTANCE;
  {end of auto-generated forward references}

  Tossl_encoder_instance_st = record end;
  TOSSL_ENCODER_INSTANCE = Tossl_encoder_instance_st;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl; external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_encoder';
  function OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst: POSSL_ENCODER_INSTANCE): pointer; cdecl; external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_encoder_ctx';
  function OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_output_type';
  function OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_ENCODER_INSTANCE_get_output_structure';
  {$else}
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_encoder}
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_encoder_ctx}
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_output_type}
  {$EXTERNALSYM OSSL_ENCODER_INSTANCE_get_output_structure}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl;
  function Load_OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst: POSSL_ENCODER_INSTANCE): pointer; cdecl;
  function Load_OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl;
  function Load_OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl;

var
  OSSL_ENCODER_INSTANCE_get_encoder: function(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl = Load_OSSL_ENCODER_INSTANCE_get_encoder;
  OSSL_ENCODER_INSTANCE_get_encoder_ctx: function(encoder_inst: POSSL_ENCODER_INSTANCE): pointer; cdecl = Load_OSSL_ENCODER_INSTANCE_get_encoder_ctx;
  OSSL_ENCODER_INSTANCE_get_output_type: function(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl = Load_OSSL_ENCODER_INSTANCE_get_output_type;
  OSSL_ENCODER_INSTANCE_get_output_structure: function(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl = Load_OSSL_ENCODER_INSTANCE_get_output_structure;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  POSSL_ENCODER_CONSTRUCT = ^TOSSL_ENCODER_CONSTRUCT;
  PPOSSL_ENCODER_CONSTRUCT = ^POSSL_ENCODER_CONSTRUCT;
  POSSL_ENCODER_CLEANUP = ^TOSSL_ENCODER_CLEANUP;
  PPOSSL_ENCODER_CLEANUP = ^POSSL_ENCODER_CLEANUP;
  {end of auto-generated forward references}

  TOSSL_ENCODER_CONSTRUCT = function(encoder_inst: POSSL_ENCODER_INSTANCE; construct_data: pointer): pointer; cdecl;
  TOSSL_ENCODER_CLEANUP = procedure(construct_data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_ENCODER_CTX_set_construct(ctx: POSSL_ENCODER_CTX; construct: POSSL_ENCODER_CONSTRUCT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_construct';
  function OSSL_ENCODER_CTX_set_construct_data(ctx: POSSL_ENCODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_construct_data';
  function OSSL_ENCODER_CTX_set_cleanup(ctx: POSSL_ENCODER_CTX; cleanup: POSSL_ENCODER_CLEANUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_set_cleanup';
  { Utilities to output the object to encode }
  function OSSL_ENCODER_to_bio(ctx: POSSL_ENCODER_CTX; out_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_to_bio';
  {$else}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_construct}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_construct_data}
  {$EXTERNALSYM OSSL_ENCODER_CTX_set_cleanup}
  {$EXTERNALSYM OSSL_ENCODER_to_bio}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_ENCODER_CTX_set_construct(ctx: POSSL_ENCODER_CTX; construct: POSSL_ENCODER_CONSTRUCT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_construct_data(ctx: POSSL_ENCODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_set_cleanup(ctx: POSSL_ENCODER_CTX; cleanup: POSSL_ENCODER_CLEANUP): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_to_bio(ctx: POSSL_ENCODER_CTX; out_: PBIO): TOpenSSL_C_INT; cdecl;

var
  OSSL_ENCODER_CTX_set_construct: function(ctx: POSSL_ENCODER_CTX; construct: POSSL_ENCODER_CONSTRUCT): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_construct;
  OSSL_ENCODER_CTX_set_construct_data: function(ctx: POSSL_ENCODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_construct_data;
  OSSL_ENCODER_CTX_set_cleanup: function(ctx: POSSL_ENCODER_CTX; cleanup: POSSL_ENCODER_CLEANUP): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_CTX_set_cleanup;
  { Utilities to output the object to encode }
  OSSL_ENCODER_to_bio: function(ctx: POSSL_ENCODER_CTX; out_: PBIO): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_to_bio;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_STDIO}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_ENCODER_to_fp(ctx: POSSL_ENCODER_CTX; fp: PFILE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_to_fp';
    {$else}
  {$EXTERNALSYM OSSL_ENCODER_to_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_ENCODER_to_fp(ctx: POSSL_ENCODER_CTX; fp: PFILE): TOpenSSL_C_INT; cdecl;

var
  OSSL_ENCODER_to_fp: function(ctx: POSSL_ENCODER_CTX; fp: PFILE): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_to_fp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_ENCODER_to_data(ctx: POSSL_ENCODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ENCODER_to_data';
  
  {* Create the OSSL_ENCODER_CTX with an associated type.  This will perform
  * an implicit OSSL_ENCODER_fetch(), suitable for the object of that type.
  * This is more useful than calling OSSL_ENCODER_CTX_new().
  }
  function OSSL_ENCODER_CTX_new_for_pkey(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; output_type: PAnsiChar; output_struct: PAnsiChar; propquery: PAnsiChar): POSSL_ENCODER_CTX; cdecl; external CLibCrypto name 'OSSL_ENCODER_CTX_new_for_pkey';
  {$else}
  {$EXTERNALSYM OSSL_ENCODER_to_data}
  {$EXTERNALSYM OSSL_ENCODER_CTX_new_for_pkey}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_ENCODER_to_data(ctx: POSSL_ENCODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ENCODER_CTX_new_for_pkey(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; output_type: PAnsiChar; output_struct: PAnsiChar; propquery: PAnsiChar): POSSL_ENCODER_CTX; cdecl;

var
  OSSL_ENCODER_to_data: function(ctx: POSSL_ENCODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_ENCODER_to_data;
  
  {* Create the OSSL_ENCODER_CTX with an associated type.  This will perform
  * an implicit OSSL_ENCODER_fetch(), suitable for the object of that type.
  * This is more useful than calling OSSL_ENCODER_CTX_new().
  }
  OSSL_ENCODER_CTX_new_for_pkey: function(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; output_type: PAnsiChar; output_struct: PAnsiChar; propquery: PAnsiChar): POSSL_ENCODER_CTX; cdecl = Load_OSSL_ENCODER_CTX_new_for_pkey;
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
function Load_OSSL_ENCODER_fetch(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_ENCODER; cdecl;
begin
  OSSL_ENCODER_fetch := LoadLibCryptoFunction('OSSL_ENCODER_fetch');
  if not assigned(OSSL_ENCODER_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_fetch');
  Result := OSSL_ENCODER_fetch(libctx, name, properties);
end;

function Load_OSSL_ENCODER_up_ref(encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_up_ref := LoadLibCryptoFunction('OSSL_ENCODER_up_ref');
  if not assigned(OSSL_ENCODER_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_up_ref');
  Result := OSSL_ENCODER_up_ref(encoder);
end;

procedure Load_OSSL_ENCODER_free(encoder: POSSL_ENCODER); cdecl;
begin
  OSSL_ENCODER_free := LoadLibCryptoFunction('OSSL_ENCODER_free');
  if not assigned(OSSL_ENCODER_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_free');
  OSSL_ENCODER_free(encoder);
end;

function Load_OSSL_ENCODER_get0_provider(encoder: POSSL_ENCODER): POSSL_PROVIDER; cdecl;
begin
  OSSL_ENCODER_get0_provider := LoadLibCryptoFunction('OSSL_ENCODER_get0_provider');
  if not assigned(OSSL_ENCODER_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_get0_provider');
  Result := OSSL_ENCODER_get0_provider(encoder);
end;

function Load_OSSL_ENCODER_get0_properties(encoder: POSSL_ENCODER): PAnsiChar; cdecl;
begin
  OSSL_ENCODER_get0_properties := LoadLibCryptoFunction('OSSL_ENCODER_get0_properties');
  if not assigned(OSSL_ENCODER_get0_properties) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_get0_properties');
  Result := OSSL_ENCODER_get0_properties(encoder);
end;

function Load_OSSL_ENCODER_get0_name(kdf: POSSL_ENCODER): PAnsiChar; cdecl;
begin
  OSSL_ENCODER_get0_name := LoadLibCryptoFunction('OSSL_ENCODER_get0_name');
  if not assigned(OSSL_ENCODER_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_get0_name');
  Result := OSSL_ENCODER_get0_name(kdf);
end;

function Load_OSSL_ENCODER_get0_description(kdf: POSSL_ENCODER): PAnsiChar; cdecl;
begin
  OSSL_ENCODER_get0_description := LoadLibCryptoFunction('OSSL_ENCODER_get0_description');
  if not assigned(OSSL_ENCODER_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_get0_description');
  Result := OSSL_ENCODER_get0_description(kdf);
end;

function Load_OSSL_ENCODER_is_a(encoder: POSSL_ENCODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_is_a := LoadLibCryptoFunction('OSSL_ENCODER_is_a');
  if not assigned(OSSL_ENCODER_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_is_a');
  Result := OSSL_ENCODER_is_a(encoder, name);
end;

procedure Load_OSSL_ENCODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;
begin
  OSSL_ENCODER_do_all_provided := LoadLibCryptoFunction('OSSL_ENCODER_do_all_provided');
  if not assigned(OSSL_ENCODER_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_do_all_provided');
  OSSL_ENCODER_do_all_provided(libctx, fn, arg);
end;

function Load_OSSL_ENCODER_names_do_all(encoder: POSSL_ENCODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_names_do_all := LoadLibCryptoFunction('OSSL_ENCODER_names_do_all');
  if not assigned(OSSL_ENCODER_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_names_do_all');
  Result := OSSL_ENCODER_names_do_all(encoder, fn, data);
end;

function Load_OSSL_ENCODER_gettable_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl;
begin
  OSSL_ENCODER_gettable_params := LoadLibCryptoFunction('OSSL_ENCODER_gettable_params');
  if not assigned(OSSL_ENCODER_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_gettable_params');
  Result := OSSL_ENCODER_gettable_params(encoder);
end;

function Load_OSSL_ENCODER_get_params(encoder: POSSL_ENCODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_get_params := LoadLibCryptoFunction('OSSL_ENCODER_get_params');
  if not assigned(OSSL_ENCODER_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_get_params');
  Result := OSSL_ENCODER_get_params(encoder, params);
end;

function Load_OSSL_ENCODER_settable_ctx_params(encoder: POSSL_ENCODER): POSSL_PARAM; cdecl;
begin
  OSSL_ENCODER_settable_ctx_params := LoadLibCryptoFunction('OSSL_ENCODER_settable_ctx_params');
  if not assigned(OSSL_ENCODER_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_settable_ctx_params');
  Result := OSSL_ENCODER_settable_ctx_params(encoder);
end;

function Load_OSSL_ENCODER_CTX_new: POSSL_ENCODER_CTX; cdecl;
begin
  OSSL_ENCODER_CTX_new := LoadLibCryptoFunction('OSSL_ENCODER_CTX_new');
  if not assigned(OSSL_ENCODER_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_new');
  Result := OSSL_ENCODER_CTX_new;
end;

function Load_OSSL_ENCODER_CTX_set_params(ctx: POSSL_ENCODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_params := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_params');
  if not assigned(OSSL_ENCODER_CTX_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_params');
  Result := OSSL_ENCODER_CTX_set_params(ctx, params);
end;

procedure Load_OSSL_ENCODER_CTX_free(ctx: POSSL_ENCODER_CTX); cdecl;
begin
  OSSL_ENCODER_CTX_free := LoadLibCryptoFunction('OSSL_ENCODER_CTX_free');
  if not assigned(OSSL_ENCODER_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_free');
  OSSL_ENCODER_CTX_free(ctx);
end;

function Load_OSSL_ENCODER_CTX_set_passphrase(ctx: POSSL_ENCODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_passphrase := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_passphrase');
  if not assigned(OSSL_ENCODER_CTX_set_passphrase) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_passphrase');
  Result := OSSL_ENCODER_CTX_set_passphrase(ctx, kstr, klen);
end;

function Load_OSSL_ENCODER_CTX_set_pem_password_cb(ctx: POSSL_ENCODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_pem_password_cb := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_pem_password_cb');
  if not assigned(OSSL_ENCODER_CTX_set_pem_password_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_pem_password_cb');
  Result := OSSL_ENCODER_CTX_set_pem_password_cb(ctx, cb, cbarg);
end;

function Load_OSSL_ENCODER_CTX_set_passphrase_cb(ctx: POSSL_ENCODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_passphrase_cb := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_passphrase_cb');
  if not assigned(OSSL_ENCODER_CTX_set_passphrase_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_passphrase_cb');
  Result := OSSL_ENCODER_CTX_set_passphrase_cb(ctx, cb, cbarg);
end;

function Load_OSSL_ENCODER_CTX_set_passphrase_ui(ctx: POSSL_ENCODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_passphrase_ui := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_passphrase_ui');
  if not assigned(OSSL_ENCODER_CTX_set_passphrase_ui) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_passphrase_ui');
  Result := OSSL_ENCODER_CTX_set_passphrase_ui(ctx, ui_method, ui_data);
end;

function Load_OSSL_ENCODER_CTX_set_cipher(ctx: POSSL_ENCODER_CTX; cipher_name: PAnsiChar; propquery: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_cipher := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_cipher');
  if not assigned(OSSL_ENCODER_CTX_set_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_cipher');
  Result := OSSL_ENCODER_CTX_set_cipher(ctx, cipher_name, propquery);
end;

function Load_OSSL_ENCODER_CTX_set_selection(ctx: POSSL_ENCODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_selection := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_selection');
  if not assigned(OSSL_ENCODER_CTX_set_selection) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_selection');
  Result := OSSL_ENCODER_CTX_set_selection(ctx, selection);
end;

function Load_OSSL_ENCODER_CTX_set_output_type(ctx: POSSL_ENCODER_CTX; output_type: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_output_type := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_output_type');
  if not assigned(OSSL_ENCODER_CTX_set_output_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_output_type');
  Result := OSSL_ENCODER_CTX_set_output_type(ctx, output_type);
end;

function Load_OSSL_ENCODER_CTX_set_output_structure(ctx: POSSL_ENCODER_CTX; output_structure: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_output_structure := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_output_structure');
  if not assigned(OSSL_ENCODER_CTX_set_output_structure) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_output_structure');
  Result := OSSL_ENCODER_CTX_set_output_structure(ctx, output_structure);
end;

function Load_OSSL_ENCODER_CTX_add_encoder(ctx: POSSL_ENCODER_CTX; encoder: POSSL_ENCODER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_add_encoder := LoadLibCryptoFunction('OSSL_ENCODER_CTX_add_encoder');
  if not assigned(OSSL_ENCODER_CTX_add_encoder) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_add_encoder');
  Result := OSSL_ENCODER_CTX_add_encoder(ctx, encoder);
end;

function Load_OSSL_ENCODER_CTX_add_extra(ctx: POSSL_ENCODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_add_extra := LoadLibCryptoFunction('OSSL_ENCODER_CTX_add_extra');
  if not assigned(OSSL_ENCODER_CTX_add_extra) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_add_extra');
  Result := OSSL_ENCODER_CTX_add_extra(ctx, libctx, propq);
end;

function Load_OSSL_ENCODER_CTX_get_num_encoders(ctx: POSSL_ENCODER_CTX): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_get_num_encoders := LoadLibCryptoFunction('OSSL_ENCODER_CTX_get_num_encoders');
  if not assigned(OSSL_ENCODER_CTX_get_num_encoders) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_get_num_encoders');
  Result := OSSL_ENCODER_CTX_get_num_encoders(ctx);
end;

function Load_OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst: POSSL_ENCODER_INSTANCE): POSSL_ENCODER; cdecl;
begin
  OSSL_ENCODER_INSTANCE_get_encoder := LoadLibCryptoFunction('OSSL_ENCODER_INSTANCE_get_encoder');
  if not assigned(OSSL_ENCODER_INSTANCE_get_encoder) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_INSTANCE_get_encoder');
  Result := OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
end;

function Load_OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst: POSSL_ENCODER_INSTANCE): pointer; cdecl;
begin
  OSSL_ENCODER_INSTANCE_get_encoder_ctx := LoadLibCryptoFunction('OSSL_ENCODER_INSTANCE_get_encoder_ctx');
  if not assigned(OSSL_ENCODER_INSTANCE_get_encoder_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_INSTANCE_get_encoder_ctx');
  Result := OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst);
end;

function Load_OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl;
begin
  OSSL_ENCODER_INSTANCE_get_output_type := LoadLibCryptoFunction('OSSL_ENCODER_INSTANCE_get_output_type');
  if not assigned(OSSL_ENCODER_INSTANCE_get_output_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_INSTANCE_get_output_type');
  Result := OSSL_ENCODER_INSTANCE_get_output_type(encoder_inst);
end;

function Load_OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst: POSSL_ENCODER_INSTANCE): PAnsiChar; cdecl;
begin
  OSSL_ENCODER_INSTANCE_get_output_structure := LoadLibCryptoFunction('OSSL_ENCODER_INSTANCE_get_output_structure');
  if not assigned(OSSL_ENCODER_INSTANCE_get_output_structure) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_INSTANCE_get_output_structure');
  Result := OSSL_ENCODER_INSTANCE_get_output_structure(encoder_inst);
end;

function Load_OSSL_ENCODER_CTX_set_construct(ctx: POSSL_ENCODER_CTX; construct: POSSL_ENCODER_CONSTRUCT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_construct := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_construct');
  if not assigned(OSSL_ENCODER_CTX_set_construct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_construct');
  Result := OSSL_ENCODER_CTX_set_construct(ctx, construct);
end;

function Load_OSSL_ENCODER_CTX_set_construct_data(ctx: POSSL_ENCODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_construct_data := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_construct_data');
  if not assigned(OSSL_ENCODER_CTX_set_construct_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_construct_data');
  Result := OSSL_ENCODER_CTX_set_construct_data(ctx, construct_data);
end;

function Load_OSSL_ENCODER_CTX_set_cleanup(ctx: POSSL_ENCODER_CTX; cleanup: POSSL_ENCODER_CLEANUP): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_CTX_set_cleanup := LoadLibCryptoFunction('OSSL_ENCODER_CTX_set_cleanup');
  if not assigned(OSSL_ENCODER_CTX_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_set_cleanup');
  Result := OSSL_ENCODER_CTX_set_cleanup(ctx, cleanup);
end;

function Load_OSSL_ENCODER_to_bio(ctx: POSSL_ENCODER_CTX; out_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_to_bio := LoadLibCryptoFunction('OSSL_ENCODER_to_bio');
  if not assigned(OSSL_ENCODER_to_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_to_bio');
  Result := OSSL_ENCODER_to_bio(ctx, out_);
end;

{$ifndef  OPENSSL_NO_STDIO}
function Load_OSSL_ENCODER_to_fp(ctx: POSSL_ENCODER_CTX; fp: PFILE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_to_fp := LoadLibCryptoFunction('OSSL_ENCODER_to_fp');
  if not assigned(OSSL_ENCODER_to_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_to_fp');
  Result := OSSL_ENCODER_to_fp(ctx, fp);
end;

{$endif} { OPENSSL_NO_STDIO}
function Load_OSSL_ENCODER_to_data(ctx: POSSL_ENCODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ENCODER_to_data := LoadLibCryptoFunction('OSSL_ENCODER_to_data');
  if not assigned(OSSL_ENCODER_to_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_to_data');
  Result := OSSL_ENCODER_to_data(ctx, pdata, pdata_len);
end;

function Load_OSSL_ENCODER_CTX_new_for_pkey(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; output_type: PAnsiChar; output_struct: PAnsiChar; propquery: PAnsiChar): POSSL_ENCODER_CTX; cdecl;
begin
  OSSL_ENCODER_CTX_new_for_pkey := LoadLibCryptoFunction('OSSL_ENCODER_CTX_new_for_pkey');
  if not assigned(OSSL_ENCODER_CTX_new_for_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ENCODER_CTX_new_for_pkey');
  Result := OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, output_type, output_struct, propquery);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_ENCODER_fetch := Load_OSSL_ENCODER_fetch;
  OSSL_ENCODER_up_ref := Load_OSSL_ENCODER_up_ref;
  OSSL_ENCODER_free := Load_OSSL_ENCODER_free;
  OSSL_ENCODER_get0_provider := Load_OSSL_ENCODER_get0_provider;
  OSSL_ENCODER_get0_properties := Load_OSSL_ENCODER_get0_properties;
  OSSL_ENCODER_get0_name := Load_OSSL_ENCODER_get0_name;
  OSSL_ENCODER_get0_description := Load_OSSL_ENCODER_get0_description;
  OSSL_ENCODER_is_a := Load_OSSL_ENCODER_is_a;
  OSSL_ENCODER_do_all_provided := Load_OSSL_ENCODER_do_all_provided;
  OSSL_ENCODER_names_do_all := Load_OSSL_ENCODER_names_do_all;
  OSSL_ENCODER_gettable_params := Load_OSSL_ENCODER_gettable_params;
  OSSL_ENCODER_get_params := Load_OSSL_ENCODER_get_params;
  OSSL_ENCODER_settable_ctx_params := Load_OSSL_ENCODER_settable_ctx_params;
  OSSL_ENCODER_CTX_new := Load_OSSL_ENCODER_CTX_new;
  OSSL_ENCODER_CTX_set_params := Load_OSSL_ENCODER_CTX_set_params;
  OSSL_ENCODER_CTX_free := Load_OSSL_ENCODER_CTX_free;
  OSSL_ENCODER_CTX_set_passphrase := Load_OSSL_ENCODER_CTX_set_passphrase;
  OSSL_ENCODER_CTX_set_pem_password_cb := Load_OSSL_ENCODER_CTX_set_pem_password_cb;
  OSSL_ENCODER_CTX_set_passphrase_cb := Load_OSSL_ENCODER_CTX_set_passphrase_cb;
  OSSL_ENCODER_CTX_set_passphrase_ui := Load_OSSL_ENCODER_CTX_set_passphrase_ui;
  OSSL_ENCODER_CTX_set_cipher := Load_OSSL_ENCODER_CTX_set_cipher;
  OSSL_ENCODER_CTX_set_selection := Load_OSSL_ENCODER_CTX_set_selection;
  OSSL_ENCODER_CTX_set_output_type := Load_OSSL_ENCODER_CTX_set_output_type;
  OSSL_ENCODER_CTX_set_output_structure := Load_OSSL_ENCODER_CTX_set_output_structure;
  OSSL_ENCODER_CTX_add_encoder := Load_OSSL_ENCODER_CTX_add_encoder;
  OSSL_ENCODER_CTX_add_extra := Load_OSSL_ENCODER_CTX_add_extra;
  OSSL_ENCODER_CTX_get_num_encoders := Load_OSSL_ENCODER_CTX_get_num_encoders;
  OSSL_ENCODER_INSTANCE_get_encoder := Load_OSSL_ENCODER_INSTANCE_get_encoder;
  OSSL_ENCODER_INSTANCE_get_encoder_ctx := Load_OSSL_ENCODER_INSTANCE_get_encoder_ctx;
  OSSL_ENCODER_INSTANCE_get_output_type := Load_OSSL_ENCODER_INSTANCE_get_output_type;
  OSSL_ENCODER_INSTANCE_get_output_structure := Load_OSSL_ENCODER_INSTANCE_get_output_structure;
  OSSL_ENCODER_CTX_set_construct := Load_OSSL_ENCODER_CTX_set_construct;
  OSSL_ENCODER_CTX_set_construct_data := Load_OSSL_ENCODER_CTX_set_construct_data;
  OSSL_ENCODER_CTX_set_cleanup := Load_OSSL_ENCODER_CTX_set_cleanup;
  OSSL_ENCODER_to_bio := Load_OSSL_ENCODER_to_bio;
{$ifndef  OPENSSL_NO_STDIO}
  OSSL_ENCODER_to_fp := Load_OSSL_ENCODER_to_fp;
{$endif} { OPENSSL_NO_STDIO}
  OSSL_ENCODER_to_data := Load_OSSL_ENCODER_to_data;
  OSSL_ENCODER_CTX_new_for_pkey := Load_OSSL_ENCODER_CTX_new_for_pkey;
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



