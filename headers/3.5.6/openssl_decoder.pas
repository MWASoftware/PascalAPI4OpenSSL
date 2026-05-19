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

unit openssl_decoder;

{
  Generated from OpenSSL 3.5.6 Header File decoder.h - Tue 19 May 14:27:30 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_decoder.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_decodererr,openssl_types,openssl_core;


{* Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_DECODER_H}
  {$define OPENSSL_DECODER_H}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_STDIO}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_DECODER_fetch(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_DECODER; cdecl; external CLibCrypto name 'OSSL_DECODER_fetch';
  function OSSL_DECODER_up_ref(encoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_up_ref';
  procedure OSSL_DECODER_free(encoder: POSSL_DECODER); cdecl; external CLibCrypto name 'OSSL_DECODER_free';
  function OSSL_DECODER_get0_provider(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_DECODER_get0_provider';
  function OSSL_DECODER_get0_properties(encoder: POSSL_DECODER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_DECODER_get0_properties';
  function OSSL_DECODER_get0_name(decoder: POSSL_DECODER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_DECODER_get0_name';
  function OSSL_DECODER_get0_description(decoder: POSSL_DECODER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_DECODER_get0_description';
  function OSSL_DECODER_is_a(encoder: POSSL_DECODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_is_a';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_DECODER_fetch}
  {$EXTERNALSYM OSSL_DECODER_up_ref}
  {$EXTERNALSYM OSSL_DECODER_free}
  {$EXTERNALSYM OSSL_DECODER_get0_provider}
  {$EXTERNALSYM OSSL_DECODER_get0_properties}
  {$EXTERNALSYM OSSL_DECODER_get0_name}
  {$EXTERNALSYM OSSL_DECODER_get0_description}
  {$EXTERNALSYM OSSL_DECODER_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_DECODER_fetch(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_DECODER; cdecl;
  function Load_OSSL_DECODER_up_ref(encoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_DECODER_free(encoder: POSSL_DECODER); cdecl;
  function Load_OSSL_DECODER_get0_provider(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl;
  function Load_OSSL_DECODER_get0_properties(encoder: POSSL_DECODER): PAnsiChar; cdecl;
  function Load_OSSL_DECODER_get0_name(decoder: POSSL_DECODER): PAnsiChar; cdecl;
  function Load_OSSL_DECODER_get0_description(decoder: POSSL_DECODER): PAnsiChar; cdecl;
  function Load_OSSL_DECODER_is_a(encoder: POSSL_DECODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  OSSL_DECODER_fetch: function(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_DECODER; cdecl = Load_OSSL_DECODER_fetch;
  OSSL_DECODER_up_ref: function(encoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_up_ref;
  OSSL_DECODER_free: procedure(encoder: POSSL_DECODER); cdecl = Load_OSSL_DECODER_free;
  OSSL_DECODER_get0_provider: function(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl = Load_OSSL_DECODER_get0_provider;
  OSSL_DECODER_get0_properties: function(encoder: POSSL_DECODER): PAnsiChar; cdecl = Load_OSSL_DECODER_get0_properties;
  OSSL_DECODER_get0_name: function(decoder: POSSL_DECODER): PAnsiChar; cdecl = Load_OSSL_DECODER_get0_name;
  OSSL_DECODER_get0_description: function(decoder: POSSL_DECODER): PAnsiChar; cdecl = Load_OSSL_DECODER_get0_description;
  OSSL_DECODER_is_a: function(encoder: POSSL_DECODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = procedure(encoder: POSSL_DECODER; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OSSL_DECODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl; external CLibCrypto name 'OSSL_DECODER_do_all_provided';
  {$else}
  {$EXTERNALSYM OSSL_DECODER_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OSSL_DECODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;

var
  OSSL_DECODER_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl = Load_OSSL_DECODER_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_DECODER_names_do_all(encoder: POSSL_DECODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_names_do_all';
  function OSSL_DECODER_gettable_params(decoder: POSSL_DECODER): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_DECODER_gettable_params';
  function OSSL_DECODER_get_params(decoder: POSSL_DECODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_get_params';
  function OSSL_DECODER_settable_ctx_params(encoder: POSSL_DECODER): POSSL_PARAM; cdecl; external CLibCrypto name 'OSSL_DECODER_settable_ctx_params';
  function OSSL_DECODER_CTX_new: POSSL_DECODER_CTX; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_new';
  function OSSL_DECODER_CTX_set_params(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_params';
  procedure OSSL_DECODER_CTX_free(ctx: POSSL_DECODER_CTX); cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_free';
  { Utilities that help set specific parameters }
  function OSSL_DECODER_CTX_set_passphrase(ctx: POSSL_DECODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_passphrase';
  function OSSL_DECODER_CTX_set_pem_password_cb(ctx: POSSL_DECODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_pem_password_cb';
  function OSSL_DECODER_CTX_set_passphrase_cb(ctx: POSSL_DECODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_passphrase_cb';
  function OSSL_DECODER_CTX_set_passphrase_ui(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_passphrase_ui';
  
  {* Utilities to read the object to decode, with the result sent to cb.
  * These will discover all provided methods
  }
  function OSSL_DECODER_CTX_set_selection(ctx: POSSL_DECODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_selection';
  function OSSL_DECODER_CTX_set_input_type(ctx: POSSL_DECODER_CTX; input_type: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_input_type';
  function OSSL_DECODER_CTX_set_input_structure(ctx: POSSL_DECODER_CTX; input_structure: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_input_structure';
  function OSSL_DECODER_CTX_add_decoder(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_add_decoder';
  function OSSL_DECODER_CTX_add_extra(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_add_extra';
  function OSSL_DECODER_CTX_get_num_decoders(ctx: POSSL_DECODER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_get_num_decoders';
  {$else}
  {$EXTERNALSYM OSSL_DECODER_names_do_all}
  {$EXTERNALSYM OSSL_DECODER_gettable_params}
  {$EXTERNALSYM OSSL_DECODER_get_params}
  {$EXTERNALSYM OSSL_DECODER_settable_ctx_params}
  {$EXTERNALSYM OSSL_DECODER_CTX_new}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_params}
  {$EXTERNALSYM OSSL_DECODER_CTX_free}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_passphrase}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_pem_password_cb}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_passphrase_cb}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_passphrase_ui}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_selection}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_input_type}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_input_structure}
  {$EXTERNALSYM OSSL_DECODER_CTX_add_decoder}
  {$EXTERNALSYM OSSL_DECODER_CTX_add_extra}
  {$EXTERNALSYM OSSL_DECODER_CTX_get_num_decoders}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_DECODER_names_do_all(encoder: POSSL_DECODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_gettable_params(decoder: POSSL_DECODER): POSSL_PARAM; cdecl;
  function Load_OSSL_DECODER_get_params(decoder: POSSL_DECODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_settable_ctx_params(encoder: POSSL_DECODER): POSSL_PARAM; cdecl;
  function Load_OSSL_DECODER_CTX_new: POSSL_DECODER_CTX; cdecl;
  function Load_OSSL_DECODER_CTX_set_params(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_DECODER_CTX_free(ctx: POSSL_DECODER_CTX); cdecl;
  function Load_OSSL_DECODER_CTX_set_passphrase(ctx: POSSL_DECODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_pem_password_cb(ctx: POSSL_DECODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_passphrase_cb(ctx: POSSL_DECODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_passphrase_ui(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_selection(ctx: POSSL_DECODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_input_type(ctx: POSSL_DECODER_CTX; input_type: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_input_structure(ctx: POSSL_DECODER_CTX; input_structure: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_add_decoder(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_add_extra(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_get_num_decoders(ctx: POSSL_DECODER_CTX): TOpenSSL_C_INT; cdecl;

var
  OSSL_DECODER_names_do_all: function(encoder: POSSL_DECODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_names_do_all;
  OSSL_DECODER_gettable_params: function(decoder: POSSL_DECODER): POSSL_PARAM; cdecl = Load_OSSL_DECODER_gettable_params;
  OSSL_DECODER_get_params: function(decoder: POSSL_DECODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_get_params;
  OSSL_DECODER_settable_ctx_params: function(encoder: POSSL_DECODER): POSSL_PARAM; cdecl = Load_OSSL_DECODER_settable_ctx_params;
  OSSL_DECODER_CTX_new: function: POSSL_DECODER_CTX; cdecl = Load_OSSL_DECODER_CTX_new;
  OSSL_DECODER_CTX_set_params: function(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_params;
  OSSL_DECODER_CTX_free: procedure(ctx: POSSL_DECODER_CTX); cdecl = Load_OSSL_DECODER_CTX_free;
  { Utilities that help set specific parameters }
  OSSL_DECODER_CTX_set_passphrase: function(ctx: POSSL_DECODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_passphrase;
  OSSL_DECODER_CTX_set_pem_password_cb: function(ctx: POSSL_DECODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_pem_password_cb;
  OSSL_DECODER_CTX_set_passphrase_cb: function(ctx: POSSL_DECODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_passphrase_cb;
  OSSL_DECODER_CTX_set_passphrase_ui: function(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_passphrase_ui;
  
  {* Utilities to read the object to decode, with the result sent to cb.
  * These will discover all provided methods
  }
  OSSL_DECODER_CTX_set_selection: function(ctx: POSSL_DECODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_selection;
  OSSL_DECODER_CTX_set_input_type: function(ctx: POSSL_DECODER_CTX; input_type: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_input_type;
  OSSL_DECODER_CTX_set_input_structure: function(ctx: POSSL_DECODER_CTX; input_structure: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_input_structure;
  OSSL_DECODER_CTX_add_decoder: function(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_add_decoder;
  OSSL_DECODER_CTX_add_extra: function(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_add_extra;
  OSSL_DECODER_CTX_get_num_decoders: function(ctx: POSSL_DECODER_CTX): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_get_num_decoders;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  Possl_decoder_instance_st = ^TOSSL_DECODER_INSTANCE;
  PPossl_decoder_instance_st = ^Possl_decoder_instance_st;
  POSSL_DECODER_INSTANCE = ^TOSSL_DECODER_INSTANCE;
  PPOSSL_DECODER_INSTANCE = ^POSSL_DECODER_INSTANCE;
  {end of auto-generated forward references}

  Tossl_decoder_instance_st = record end;
  TOSSL_DECODER_INSTANCE = Tossl_decoder_instance_st;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_DECODER_INSTANCE_get_decoder(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl; external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_decoder';
  function OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst: POSSL_DECODER_INSTANCE): pointer; cdecl; external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_decoder_ctx';
  function OSSL_DECODER_INSTANCE_get_input_type(decoder_inst: POSSL_DECODER_INSTANCE): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_input_type';
  function OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst: POSSL_DECODER_INSTANCE; was_set: POpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_DECODER_INSTANCE_get_input_structure';
  {$else}
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_decoder}
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_decoder_ctx}
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_input_type}
  {$EXTERNALSYM OSSL_DECODER_INSTANCE_get_input_structure}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_DECODER_INSTANCE_get_decoder(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl;
  function Load_OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst: POSSL_DECODER_INSTANCE): pointer; cdecl;
  function Load_OSSL_DECODER_INSTANCE_get_input_type(decoder_inst: POSSL_DECODER_INSTANCE): PAnsiChar; cdecl;
  function Load_OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst: POSSL_DECODER_INSTANCE; was_set: POpenSSL_C_INT): PAnsiChar; cdecl;

var
  OSSL_DECODER_INSTANCE_get_decoder: function(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl = Load_OSSL_DECODER_INSTANCE_get_decoder;
  OSSL_DECODER_INSTANCE_get_decoder_ctx: function(decoder_inst: POSSL_DECODER_INSTANCE): pointer; cdecl = Load_OSSL_DECODER_INSTANCE_get_decoder_ctx;
  OSSL_DECODER_INSTANCE_get_input_type: function(decoder_inst: POSSL_DECODER_INSTANCE): PAnsiChar; cdecl = Load_OSSL_DECODER_INSTANCE_get_input_type;
  OSSL_DECODER_INSTANCE_get_input_structure: function(decoder_inst: POSSL_DECODER_INSTANCE; was_set: POpenSSL_C_INT): PAnsiChar; cdecl = Load_OSSL_DECODER_INSTANCE_get_input_structure;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  POSSL_DECODER_CONSTRUCT = ^TOSSL_DECODER_CONSTRUCT;
  PPOSSL_DECODER_CONSTRUCT = ^POSSL_DECODER_CONSTRUCT;
  POSSL_DECODER_CLEANUP = ^TOSSL_DECODER_CLEANUP;
  PPOSSL_DECODER_CLEANUP = ^POSSL_DECODER_CLEANUP;
  {end of auto-generated forward references}

  TOSSL_DECODER_CONSTRUCT = function(decoder_inst: POSSL_DECODER_INSTANCE; params: POSSL_PARAM; construct_data: pointer): TOpenSSL_C_INT; cdecl;
  TOSSL_DECODER_CLEANUP = procedure(construct_data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_DECODER_CTX_set_construct(ctx: POSSL_DECODER_CTX; construct: POSSL_DECODER_CONSTRUCT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_construct';
  function OSSL_DECODER_CTX_set_construct_data(ctx: POSSL_DECODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_construct_data';
  function OSSL_DECODER_CTX_set_cleanup(ctx: POSSL_DECODER_CTX; cleanup: POSSL_DECODER_CLEANUP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_set_cleanup';
  function OSSL_DECODER_CTX_get_construct(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CONSTRUCT; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_get_construct';
  function OSSL_DECODER_CTX_get_construct_data(ctx: POSSL_DECODER_CTX): pointer; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_get_construct_data';
  function OSSL_DECODER_CTX_get_cleanup(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CLEANUP; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_get_cleanup';
  function OSSL_DECODER_export(decoder_inst: POSSL_DECODER_INSTANCE; reference: pointer; reference_sz: TOpenSSL_C_SIZET; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_export';
  function OSSL_DECODER_from_bio(ctx: POSSL_DECODER_CTX; in_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_from_bio';
  {$else}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_construct}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_construct_data}
  {$EXTERNALSYM OSSL_DECODER_CTX_set_cleanup}
  {$EXTERNALSYM OSSL_DECODER_CTX_get_construct}
  {$EXTERNALSYM OSSL_DECODER_CTX_get_construct_data}
  {$EXTERNALSYM OSSL_DECODER_CTX_get_cleanup}
  {$EXTERNALSYM OSSL_DECODER_export}
  {$EXTERNALSYM OSSL_DECODER_from_bio}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_DECODER_CTX_set_construct(ctx: POSSL_DECODER_CTX; construct: POSSL_DECODER_CONSTRUCT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_construct_data(ctx: POSSL_DECODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_set_cleanup(ctx: POSSL_DECODER_CTX; cleanup: POSSL_DECODER_CLEANUP): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_get_construct(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CONSTRUCT; cdecl;
  function Load_OSSL_DECODER_CTX_get_construct_data(ctx: POSSL_DECODER_CTX): pointer; cdecl;
  function Load_OSSL_DECODER_CTX_get_cleanup(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CLEANUP; cdecl;
  function Load_OSSL_DECODER_export(decoder_inst: POSSL_DECODER_INSTANCE; reference: pointer; reference_sz: TOpenSSL_C_SIZET; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_from_bio(ctx: POSSL_DECODER_CTX; in_: PBIO): TOpenSSL_C_INT; cdecl;

var
  OSSL_DECODER_CTX_set_construct: function(ctx: POSSL_DECODER_CTX; construct: POSSL_DECODER_CONSTRUCT): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_construct;
  OSSL_DECODER_CTX_set_construct_data: function(ctx: POSSL_DECODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_construct_data;
  OSSL_DECODER_CTX_set_cleanup: function(ctx: POSSL_DECODER_CTX; cleanup: POSSL_DECODER_CLEANUP): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_CTX_set_cleanup;
  OSSL_DECODER_CTX_get_construct: function(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CONSTRUCT; cdecl = Load_OSSL_DECODER_CTX_get_construct;
  OSSL_DECODER_CTX_get_construct_data: function(ctx: POSSL_DECODER_CTX): pointer; cdecl = Load_OSSL_DECODER_CTX_get_construct_data;
  OSSL_DECODER_CTX_get_cleanup: function(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CLEANUP; cdecl = Load_OSSL_DECODER_CTX_get_cleanup;
  OSSL_DECODER_export: function(decoder_inst: POSSL_DECODER_INSTANCE; reference: pointer; reference_sz: TOpenSSL_C_SIZET; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_export;
  OSSL_DECODER_from_bio: function(ctx: POSSL_DECODER_CTX; in_: PBIO): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_from_bio;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_STDIO}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_DECODER_from_fp(ctx: POSSL_DECODER_CTX; in_: PFILE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_from_fp';
    {$else}
  {$EXTERNALSYM OSSL_DECODER_from_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_DECODER_from_fp(ctx: POSSL_DECODER_CTX; in_: PFILE): TOpenSSL_C_INT; cdecl;

var
  OSSL_DECODER_from_fp: function(ctx: POSSL_DECODER_CTX; in_: PFILE): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_from_fp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_DECODER_from_data(ctx: POSSL_DECODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_DECODER_from_data';
  
  {* Create the OSSL_DECODER_CTX with an associated type.  This will perform
  * an implicit OSSL_DECODER_fetch(), suitable for the object of that type.
  }
  function OSSL_DECODER_CTX_new_for_pkey(pkey: PPEVP_PKEY; input_type: PAnsiChar; input_struct: PAnsiChar; keytype: PAnsiChar; selection: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propquery: PAnsiChar): POSSL_DECODER_CTX; cdecl; external CLibCrypto name 'OSSL_DECODER_CTX_new_for_pkey';
  {$else}
  {$EXTERNALSYM OSSL_DECODER_from_data}
  {$EXTERNALSYM OSSL_DECODER_CTX_new_for_pkey}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_DECODER_from_data(ctx: POSSL_DECODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_DECODER_CTX_new_for_pkey(pkey: PPEVP_PKEY; input_type: PAnsiChar; input_struct: PAnsiChar; keytype: PAnsiChar; selection: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propquery: PAnsiChar): POSSL_DECODER_CTX; cdecl;

var
  OSSL_DECODER_from_data: function(ctx: POSSL_DECODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_DECODER_from_data;
  
  {* Create the OSSL_DECODER_CTX with an associated type.  This will perform
  * an implicit OSSL_DECODER_fetch(), suitable for the object of that type.
  }
  OSSL_DECODER_CTX_new_for_pkey: function(pkey: PPEVP_PKEY; input_type: PAnsiChar; input_struct: PAnsiChar; keytype: PAnsiChar; selection: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propquery: PAnsiChar): POSSL_DECODER_CTX; cdecl = Load_OSSL_DECODER_CTX_new_for_pkey;
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
function Load_OSSL_DECODER_fetch(libctx: POSSL_LIB_CTX; name: PAnsiChar; properties: PAnsiChar): POSSL_DECODER; cdecl;
begin
  OSSL_DECODER_fetch := LoadLibCryptoFunction('OSSL_DECODER_fetch');
  if not assigned(OSSL_DECODER_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_fetch');
  Result := OSSL_DECODER_fetch(libctx, name, properties);
end;

function Load_OSSL_DECODER_up_ref(encoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_up_ref := LoadLibCryptoFunction('OSSL_DECODER_up_ref');
  if not assigned(OSSL_DECODER_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_up_ref');
  Result := OSSL_DECODER_up_ref(encoder);
end;

procedure Load_OSSL_DECODER_free(encoder: POSSL_DECODER); cdecl;
begin
  OSSL_DECODER_free := LoadLibCryptoFunction('OSSL_DECODER_free');
  if not assigned(OSSL_DECODER_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_free');
  OSSL_DECODER_free(encoder);
end;

function Load_OSSL_DECODER_get0_provider(encoder: POSSL_DECODER): POSSL_PROVIDER; cdecl;
begin
  OSSL_DECODER_get0_provider := LoadLibCryptoFunction('OSSL_DECODER_get0_provider');
  if not assigned(OSSL_DECODER_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_get0_provider');
  Result := OSSL_DECODER_get0_provider(encoder);
end;

function Load_OSSL_DECODER_get0_properties(encoder: POSSL_DECODER): PAnsiChar; cdecl;
begin
  OSSL_DECODER_get0_properties := LoadLibCryptoFunction('OSSL_DECODER_get0_properties');
  if not assigned(OSSL_DECODER_get0_properties) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_get0_properties');
  Result := OSSL_DECODER_get0_properties(encoder);
end;

function Load_OSSL_DECODER_get0_name(decoder: POSSL_DECODER): PAnsiChar; cdecl;
begin
  OSSL_DECODER_get0_name := LoadLibCryptoFunction('OSSL_DECODER_get0_name');
  if not assigned(OSSL_DECODER_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_get0_name');
  Result := OSSL_DECODER_get0_name(decoder);
end;

function Load_OSSL_DECODER_get0_description(decoder: POSSL_DECODER): PAnsiChar; cdecl;
begin
  OSSL_DECODER_get0_description := LoadLibCryptoFunction('OSSL_DECODER_get0_description');
  if not assigned(OSSL_DECODER_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_get0_description');
  Result := OSSL_DECODER_get0_description(decoder);
end;

function Load_OSSL_DECODER_is_a(encoder: POSSL_DECODER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_is_a := LoadLibCryptoFunction('OSSL_DECODER_is_a');
  if not assigned(OSSL_DECODER_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_is_a');
  Result := OSSL_DECODER_is_a(encoder, name);
end;

procedure Load_OSSL_DECODER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;
begin
  OSSL_DECODER_do_all_provided := LoadLibCryptoFunction('OSSL_DECODER_do_all_provided');
  if not assigned(OSSL_DECODER_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_do_all_provided');
  OSSL_DECODER_do_all_provided(libctx, fn, arg);
end;

function Load_OSSL_DECODER_names_do_all(encoder: POSSL_DECODER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_names_do_all := LoadLibCryptoFunction('OSSL_DECODER_names_do_all');
  if not assigned(OSSL_DECODER_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_names_do_all');
  Result := OSSL_DECODER_names_do_all(encoder, fn, data);
end;

function Load_OSSL_DECODER_gettable_params(decoder: POSSL_DECODER): POSSL_PARAM; cdecl;
begin
  OSSL_DECODER_gettable_params := LoadLibCryptoFunction('OSSL_DECODER_gettable_params');
  if not assigned(OSSL_DECODER_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_gettable_params');
  Result := OSSL_DECODER_gettable_params(decoder);
end;

function Load_OSSL_DECODER_get_params(decoder: POSSL_DECODER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_get_params := LoadLibCryptoFunction('OSSL_DECODER_get_params');
  if not assigned(OSSL_DECODER_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_get_params');
  Result := OSSL_DECODER_get_params(decoder, params);
end;

function Load_OSSL_DECODER_settable_ctx_params(encoder: POSSL_DECODER): POSSL_PARAM; cdecl;
begin
  OSSL_DECODER_settable_ctx_params := LoadLibCryptoFunction('OSSL_DECODER_settable_ctx_params');
  if not assigned(OSSL_DECODER_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_settable_ctx_params');
  Result := OSSL_DECODER_settable_ctx_params(encoder);
end;

function Load_OSSL_DECODER_CTX_new: POSSL_DECODER_CTX; cdecl;
begin
  OSSL_DECODER_CTX_new := LoadLibCryptoFunction('OSSL_DECODER_CTX_new');
  if not assigned(OSSL_DECODER_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_new');
  Result := OSSL_DECODER_CTX_new;
end;

function Load_OSSL_DECODER_CTX_set_params(ctx: POSSL_DECODER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_params := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_params');
  if not assigned(OSSL_DECODER_CTX_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_params');
  Result := OSSL_DECODER_CTX_set_params(ctx, params);
end;

procedure Load_OSSL_DECODER_CTX_free(ctx: POSSL_DECODER_CTX); cdecl;
begin
  OSSL_DECODER_CTX_free := LoadLibCryptoFunction('OSSL_DECODER_CTX_free');
  if not assigned(OSSL_DECODER_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_free');
  OSSL_DECODER_CTX_free(ctx);
end;

function Load_OSSL_DECODER_CTX_set_passphrase(ctx: POSSL_DECODER_CTX; kstr: Pbyte; klen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_passphrase := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_passphrase');
  if not assigned(OSSL_DECODER_CTX_set_passphrase) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_passphrase');
  Result := OSSL_DECODER_CTX_set_passphrase(ctx, kstr, klen);
end;

function Load_OSSL_DECODER_CTX_set_pem_password_cb(ctx: POSSL_DECODER_CTX; cb: Tpem_password_cb; cbarg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_pem_password_cb := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_pem_password_cb');
  if not assigned(OSSL_DECODER_CTX_set_pem_password_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_pem_password_cb');
  Result := OSSL_DECODER_CTX_set_pem_password_cb(ctx, cb, cbarg);
end;

function Load_OSSL_DECODER_CTX_set_passphrase_cb(ctx: POSSL_DECODER_CTX; cb: POSSL_PASSPHRASE_CALLBACK; cbarg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_passphrase_cb := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_passphrase_cb');
  if not assigned(OSSL_DECODER_CTX_set_passphrase_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_passphrase_cb');
  Result := OSSL_DECODER_CTX_set_passphrase_cb(ctx, cb, cbarg);
end;

function Load_OSSL_DECODER_CTX_set_passphrase_ui(ctx: POSSL_DECODER_CTX; ui_method: PUI_METHOD; ui_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_passphrase_ui := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_passphrase_ui');
  if not assigned(OSSL_DECODER_CTX_set_passphrase_ui) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_passphrase_ui');
  Result := OSSL_DECODER_CTX_set_passphrase_ui(ctx, ui_method, ui_data);
end;

function Load_OSSL_DECODER_CTX_set_selection(ctx: POSSL_DECODER_CTX; selection: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_selection := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_selection');
  if not assigned(OSSL_DECODER_CTX_set_selection) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_selection');
  Result := OSSL_DECODER_CTX_set_selection(ctx, selection);
end;

function Load_OSSL_DECODER_CTX_set_input_type(ctx: POSSL_DECODER_CTX; input_type: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_input_type := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_input_type');
  if not assigned(OSSL_DECODER_CTX_set_input_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_input_type');
  Result := OSSL_DECODER_CTX_set_input_type(ctx, input_type);
end;

function Load_OSSL_DECODER_CTX_set_input_structure(ctx: POSSL_DECODER_CTX; input_structure: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_input_structure := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_input_structure');
  if not assigned(OSSL_DECODER_CTX_set_input_structure) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_input_structure');
  Result := OSSL_DECODER_CTX_set_input_structure(ctx, input_structure);
end;

function Load_OSSL_DECODER_CTX_add_decoder(ctx: POSSL_DECODER_CTX; decoder: POSSL_DECODER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_add_decoder := LoadLibCryptoFunction('OSSL_DECODER_CTX_add_decoder');
  if not assigned(OSSL_DECODER_CTX_add_decoder) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_add_decoder');
  Result := OSSL_DECODER_CTX_add_decoder(ctx, decoder);
end;

function Load_OSSL_DECODER_CTX_add_extra(ctx: POSSL_DECODER_CTX; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_add_extra := LoadLibCryptoFunction('OSSL_DECODER_CTX_add_extra');
  if not assigned(OSSL_DECODER_CTX_add_extra) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_add_extra');
  Result := OSSL_DECODER_CTX_add_extra(ctx, libctx, propq);
end;

function Load_OSSL_DECODER_CTX_get_num_decoders(ctx: POSSL_DECODER_CTX): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_get_num_decoders := LoadLibCryptoFunction('OSSL_DECODER_CTX_get_num_decoders');
  if not assigned(OSSL_DECODER_CTX_get_num_decoders) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_get_num_decoders');
  Result := OSSL_DECODER_CTX_get_num_decoders(ctx);
end;

function Load_OSSL_DECODER_INSTANCE_get_decoder(decoder_inst: POSSL_DECODER_INSTANCE): POSSL_DECODER; cdecl;
begin
  OSSL_DECODER_INSTANCE_get_decoder := LoadLibCryptoFunction('OSSL_DECODER_INSTANCE_get_decoder');
  if not assigned(OSSL_DECODER_INSTANCE_get_decoder) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_INSTANCE_get_decoder');
  Result := OSSL_DECODER_INSTANCE_get_decoder(decoder_inst);
end;

function Load_OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst: POSSL_DECODER_INSTANCE): pointer; cdecl;
begin
  OSSL_DECODER_INSTANCE_get_decoder_ctx := LoadLibCryptoFunction('OSSL_DECODER_INSTANCE_get_decoder_ctx');
  if not assigned(OSSL_DECODER_INSTANCE_get_decoder_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_INSTANCE_get_decoder_ctx');
  Result := OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst);
end;

function Load_OSSL_DECODER_INSTANCE_get_input_type(decoder_inst: POSSL_DECODER_INSTANCE): PAnsiChar; cdecl;
begin
  OSSL_DECODER_INSTANCE_get_input_type := LoadLibCryptoFunction('OSSL_DECODER_INSTANCE_get_input_type');
  if not assigned(OSSL_DECODER_INSTANCE_get_input_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_INSTANCE_get_input_type');
  Result := OSSL_DECODER_INSTANCE_get_input_type(decoder_inst);
end;

function Load_OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst: POSSL_DECODER_INSTANCE; was_set: POpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OSSL_DECODER_INSTANCE_get_input_structure := LoadLibCryptoFunction('OSSL_DECODER_INSTANCE_get_input_structure');
  if not assigned(OSSL_DECODER_INSTANCE_get_input_structure) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_INSTANCE_get_input_structure');
  Result := OSSL_DECODER_INSTANCE_get_input_structure(decoder_inst, was_set);
end;

function Load_OSSL_DECODER_CTX_set_construct(ctx: POSSL_DECODER_CTX; construct: POSSL_DECODER_CONSTRUCT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_construct := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_construct');
  if not assigned(OSSL_DECODER_CTX_set_construct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_construct');
  Result := OSSL_DECODER_CTX_set_construct(ctx, construct);
end;

function Load_OSSL_DECODER_CTX_set_construct_data(ctx: POSSL_DECODER_CTX; construct_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_construct_data := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_construct_data');
  if not assigned(OSSL_DECODER_CTX_set_construct_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_construct_data');
  Result := OSSL_DECODER_CTX_set_construct_data(ctx, construct_data);
end;

function Load_OSSL_DECODER_CTX_set_cleanup(ctx: POSSL_DECODER_CTX; cleanup: POSSL_DECODER_CLEANUP): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_CTX_set_cleanup := LoadLibCryptoFunction('OSSL_DECODER_CTX_set_cleanup');
  if not assigned(OSSL_DECODER_CTX_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_set_cleanup');
  Result := OSSL_DECODER_CTX_set_cleanup(ctx, cleanup);
end;

function Load_OSSL_DECODER_CTX_get_construct(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CONSTRUCT; cdecl;
begin
  OSSL_DECODER_CTX_get_construct := LoadLibCryptoFunction('OSSL_DECODER_CTX_get_construct');
  if not assigned(OSSL_DECODER_CTX_get_construct) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_get_construct');
  Result := OSSL_DECODER_CTX_get_construct(ctx);
end;

function Load_OSSL_DECODER_CTX_get_construct_data(ctx: POSSL_DECODER_CTX): pointer; cdecl;
begin
  OSSL_DECODER_CTX_get_construct_data := LoadLibCryptoFunction('OSSL_DECODER_CTX_get_construct_data');
  if not assigned(OSSL_DECODER_CTX_get_construct_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_get_construct_data');
  Result := OSSL_DECODER_CTX_get_construct_data(ctx);
end;

function Load_OSSL_DECODER_CTX_get_cleanup(ctx: POSSL_DECODER_CTX): POSSL_DECODER_CLEANUP; cdecl;
begin
  OSSL_DECODER_CTX_get_cleanup := LoadLibCryptoFunction('OSSL_DECODER_CTX_get_cleanup');
  if not assigned(OSSL_DECODER_CTX_get_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_get_cleanup');
  Result := OSSL_DECODER_CTX_get_cleanup(ctx);
end;

function Load_OSSL_DECODER_export(decoder_inst: POSSL_DECODER_INSTANCE; reference: pointer; reference_sz: TOpenSSL_C_SIZET; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_export := LoadLibCryptoFunction('OSSL_DECODER_export');
  if not assigned(OSSL_DECODER_export) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_export');
  Result := OSSL_DECODER_export(decoder_inst, reference, reference_sz, export_cb, export_cbarg);
end;

function Load_OSSL_DECODER_from_bio(ctx: POSSL_DECODER_CTX; in_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_from_bio := LoadLibCryptoFunction('OSSL_DECODER_from_bio');
  if not assigned(OSSL_DECODER_from_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_from_bio');
  Result := OSSL_DECODER_from_bio(ctx, in_);
end;

{$ifndef  OPENSSL_NO_STDIO}
function Load_OSSL_DECODER_from_fp(ctx: POSSL_DECODER_CTX; in_: PFILE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_from_fp := LoadLibCryptoFunction('OSSL_DECODER_from_fp');
  if not assigned(OSSL_DECODER_from_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_from_fp');
  Result := OSSL_DECODER_from_fp(ctx, in_);
end;

{$endif} { OPENSSL_NO_STDIO}
function Load_OSSL_DECODER_from_data(ctx: POSSL_DECODER_CTX; pdata: PPbyte; pdata_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_DECODER_from_data := LoadLibCryptoFunction('OSSL_DECODER_from_data');
  if not assigned(OSSL_DECODER_from_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_from_data');
  Result := OSSL_DECODER_from_data(ctx, pdata, pdata_len);
end;

function Load_OSSL_DECODER_CTX_new_for_pkey(pkey: PPEVP_PKEY; input_type: PAnsiChar; input_struct: PAnsiChar; keytype: PAnsiChar; selection: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propquery: PAnsiChar): POSSL_DECODER_CTX; cdecl;
begin
  OSSL_DECODER_CTX_new_for_pkey := LoadLibCryptoFunction('OSSL_DECODER_CTX_new_for_pkey');
  if not assigned(OSSL_DECODER_CTX_new_for_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_DECODER_CTX_new_for_pkey');
  Result := OSSL_DECODER_CTX_new_for_pkey(pkey, input_type, input_struct, keytype, selection, libctx, propquery);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_DECODER_fetch := Load_OSSL_DECODER_fetch;
  OSSL_DECODER_up_ref := Load_OSSL_DECODER_up_ref;
  OSSL_DECODER_free := Load_OSSL_DECODER_free;
  OSSL_DECODER_get0_provider := Load_OSSL_DECODER_get0_provider;
  OSSL_DECODER_get0_properties := Load_OSSL_DECODER_get0_properties;
  OSSL_DECODER_get0_name := Load_OSSL_DECODER_get0_name;
  OSSL_DECODER_get0_description := Load_OSSL_DECODER_get0_description;
  OSSL_DECODER_is_a := Load_OSSL_DECODER_is_a;
  OSSL_DECODER_do_all_provided := Load_OSSL_DECODER_do_all_provided;
  OSSL_DECODER_names_do_all := Load_OSSL_DECODER_names_do_all;
  OSSL_DECODER_gettable_params := Load_OSSL_DECODER_gettable_params;
  OSSL_DECODER_get_params := Load_OSSL_DECODER_get_params;
  OSSL_DECODER_settable_ctx_params := Load_OSSL_DECODER_settable_ctx_params;
  OSSL_DECODER_CTX_new := Load_OSSL_DECODER_CTX_new;
  OSSL_DECODER_CTX_set_params := Load_OSSL_DECODER_CTX_set_params;
  OSSL_DECODER_CTX_free := Load_OSSL_DECODER_CTX_free;
  OSSL_DECODER_CTX_set_passphrase := Load_OSSL_DECODER_CTX_set_passphrase;
  OSSL_DECODER_CTX_set_pem_password_cb := Load_OSSL_DECODER_CTX_set_pem_password_cb;
  OSSL_DECODER_CTX_set_passphrase_cb := Load_OSSL_DECODER_CTX_set_passphrase_cb;
  OSSL_DECODER_CTX_set_passphrase_ui := Load_OSSL_DECODER_CTX_set_passphrase_ui;
  OSSL_DECODER_CTX_set_selection := Load_OSSL_DECODER_CTX_set_selection;
  OSSL_DECODER_CTX_set_input_type := Load_OSSL_DECODER_CTX_set_input_type;
  OSSL_DECODER_CTX_set_input_structure := Load_OSSL_DECODER_CTX_set_input_structure;
  OSSL_DECODER_CTX_add_decoder := Load_OSSL_DECODER_CTX_add_decoder;
  OSSL_DECODER_CTX_add_extra := Load_OSSL_DECODER_CTX_add_extra;
  OSSL_DECODER_CTX_get_num_decoders := Load_OSSL_DECODER_CTX_get_num_decoders;
  OSSL_DECODER_INSTANCE_get_decoder := Load_OSSL_DECODER_INSTANCE_get_decoder;
  OSSL_DECODER_INSTANCE_get_decoder_ctx := Load_OSSL_DECODER_INSTANCE_get_decoder_ctx;
  OSSL_DECODER_INSTANCE_get_input_type := Load_OSSL_DECODER_INSTANCE_get_input_type;
  OSSL_DECODER_INSTANCE_get_input_structure := Load_OSSL_DECODER_INSTANCE_get_input_structure;
  OSSL_DECODER_CTX_set_construct := Load_OSSL_DECODER_CTX_set_construct;
  OSSL_DECODER_CTX_set_construct_data := Load_OSSL_DECODER_CTX_set_construct_data;
  OSSL_DECODER_CTX_set_cleanup := Load_OSSL_DECODER_CTX_set_cleanup;
  OSSL_DECODER_CTX_get_construct := Load_OSSL_DECODER_CTX_get_construct;
  OSSL_DECODER_CTX_get_construct_data := Load_OSSL_DECODER_CTX_get_construct_data;
  OSSL_DECODER_CTX_get_cleanup := Load_OSSL_DECODER_CTX_get_cleanup;
  OSSL_DECODER_export := Load_OSSL_DECODER_export;
  OSSL_DECODER_from_bio := Load_OSSL_DECODER_from_bio;
{$ifndef  OPENSSL_NO_STDIO}
  OSSL_DECODER_from_fp := Load_OSSL_DECODER_from_fp;
{$endif} { OPENSSL_NO_STDIO}
  OSSL_DECODER_from_data := Load_OSSL_DECODER_from_data;
  OSSL_DECODER_CTX_new_for_pkey := Load_OSSL_DECODER_CTX_new_for_pkey;
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



