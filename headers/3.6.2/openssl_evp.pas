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

unit openssl_evp;

{
  Generated from OpenSSL 3.6.2 Header File evp.h - Tue 19 May 14:30:07 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_evp.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_obj_mac,openssl_types,openssl_core,
     openssl_core_dispatch,openssl_symhacks,openssl_bio,openssl_evperr,
     openssl_params,openssl_objects;


{* Copyright 1995-2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_EVP_H}
  {$define OPENSSL_EVP_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_ENVELOPE_H}
  {$endif}
  {$ifndef  OPENSSL_NO_STDIO}
  {$endif}
  {$include openssl_opensslconf.inc}

const
  EVP_MAX_MD_SIZE = 64;
  EVP_MAX_KEY_LENGTH = 64;
  EVP_MAX_IV_LENGTH = 16;
  EVP_MAX_BLOCK_LENGTH = 32;
  EVP_MAX_AEAD_TAG_LENGTH = 16;
  { Maximum pipes in cipher pipelining }
  EVP_MAX_PIPES = 32;
  PKCS5_SALT_LEN = 8;
  { Default PKCS#5 iteration count }
  PKCS5_DEFAULT_ITER = 2048;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  EVP_PK_RSA = $0001;
  EVP_PK_DSA = $0002;
  EVP_PK_DH = $0004;
  EVP_PK_EC = $0008;
  EVP_PKT_SIGN = $0010;
  EVP_PKT_ENC = $0020;
  EVP_PKT_EXCH = $0040;
  EVP_PKS_RSA = $0100;
  EVP_PKS_DSA = $0200;
  EVP_PKS_EC = $0400;
  {$endif}

const
  EVP_PKEY_NONE = NID_undef;
  EVP_PKEY_RSA = NID_rsaEncryption;
  EVP_PKEY_RSA2 = NID_rsa;
  EVP_PKEY_RSA_PSS = NID_rsassaPss;
  EVP_PKEY_DSA = NID_dsa;
  EVP_PKEY_DSA1 = NID_dsa_2;
  EVP_PKEY_DSA2 = NID_dsaWithSHA;
  EVP_PKEY_DSA3 = NID_dsaWithSHA1;
  EVP_PKEY_DSA4 = NID_dsaWithSHA1_2;
  EVP_PKEY_DH = NID_dhKeyAgreement;
  EVP_PKEY_DHX = NID_dhpublicnumber;
  EVP_PKEY_EC = NID_X9_62_id_ecPublicKey;
  EVP_PKEY_SM2 = NID_sm2;
  EVP_PKEY_HMAC = NID_hmac;
  EVP_PKEY_CMAC = NID_cmac;
  EVP_PKEY_SCRYPT = NID_id_scrypt;
  EVP_PKEY_TLS1_PRF = NID_tls1_prf;
  EVP_PKEY_HKDF = NID_hkdf;
  EVP_PKEY_POLY1305 = NID_poly1305;
  EVP_PKEY_SIPHASH = NID_siphash;
  EVP_PKEY_X25519 = NID_X25519;
  EVP_PKEY_ED25519 = NID_ED25519;
  EVP_PKEY_X448 = NID_X448;
  EVP_PKEY_ED448 = NID_ED448;
  EVP_PKEY_ML_DSA_44 = NID_ML_DSA_44;
  EVP_PKEY_ML_DSA_65 = NID_ML_DSA_65;
  EVP_PKEY_ML_DSA_87 = NID_ML_DSA_87;
  EVP_PKEY_SLH_DSA_SHA2_128S = NID_SLH_DSA_SHA2_128s;
  EVP_PKEY_SLH_DSA_SHA2_128F = NID_SLH_DSA_SHA2_128f;
  EVP_PKEY_SLH_DSA_SHA2_192S = NID_SLH_DSA_SHA2_192s;
  EVP_PKEY_SLH_DSA_SHA2_192F = NID_SLH_DSA_SHA2_192f;
  EVP_PKEY_SLH_DSA_SHA2_256S = NID_SLH_DSA_SHA2_256s;
  EVP_PKEY_SLH_DSA_SHA2_256F = NID_SLH_DSA_SHA2_256f;
  EVP_PKEY_SLH_DSA_SHAKE_128S = NID_SLH_DSA_SHAKE_128s;
  EVP_PKEY_SLH_DSA_SHAKE_128F = NID_SLH_DSA_SHAKE_128f;
  EVP_PKEY_SLH_DSA_SHAKE_192S = NID_SLH_DSA_SHAKE_192s;
  EVP_PKEY_SLH_DSA_SHAKE_192F = NID_SLH_DSA_SHAKE_192f;
  EVP_PKEY_SLH_DSA_SHAKE_256S = NID_SLH_DSA_SHAKE_256s;
  EVP_PKEY_SLH_DSA_SHAKE_256F = NID_SLH_DSA_SHAKE_256f;
  { Special indicator that the object is uniquely provider side }
  EVP_PKEY_KEYMGMT = -(1);
  { Easy to use macros for EVP_PKEY related selections }
  EVP_PKEY_KEY_PARAMETERS = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
  EVP_PKEY_PRIVATE_KEY = EVP_PKEY_KEY_PARAMETERS or OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
  EVP_PKEY_PUBLIC_KEY = EVP_PKEY_KEY_PARAMETERS or OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
  EVP_PKEY_KEYPAIR = EVP_PKEY_PUBLIC_KEY or OSSL_KEYMGMT_SELECT_PRIVATE_KEY;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_set_default_properties(libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_set_default_properties';
  function EVP_get1_default_properties(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl; external CLibCrypto name 'EVP_get1_default_properties';
  function EVP_default_properties_is_fips_enabled(libctx: POSSL_LIB_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_default_properties_is_fips_enabled';
  function EVP_default_properties_enable_fips(libctx: POSSL_LIB_CTX; enable: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_default_properties_enable_fips';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM EVP_set_default_properties}
  {$EXTERNALSYM EVP_get1_default_properties}
  {$EXTERNALSYM EVP_default_properties_is_fips_enabled}
  {$EXTERNALSYM EVP_default_properties_enable_fips}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_set_default_properties(libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_get1_default_properties(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl;
  function Load_EVP_default_properties_is_fips_enabled(libctx: POSSL_LIB_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_default_properties_enable_fips(libctx: POSSL_LIB_CTX; enable: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_set_default_properties: function(libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_set_default_properties;
  EVP_get1_default_properties: function(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl = Load_EVP_get1_default_properties;
  EVP_default_properties_is_fips_enabled: function(libctx: POSSL_LIB_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_default_properties_is_fips_enabled;
  EVP_default_properties_enable_fips: function(libctx: POSSL_LIB_CTX; enable: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_default_properties_enable_fips;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_PKEY_MO_SIGN = $0001;
  EVP_PKEY_MO_VERIFY = $0002;
  EVP_PKEY_MO_ENCRYPT = $0004;
  EVP_PKEY_MO_DECRYPT = $0008;
  {$ifndef  EVP_MD}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl; external CLibCrypto name 'EVP_MD_meth_new'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_dup(md: PEVP_MD): PEVP_MD; cdecl; external CLibCrypto name 'EVP_MD_meth_dup'; deprecated 'Since OpenSSL 3.0';
  procedure EVP_MD_meth_free(md: PEVP_MD); cdecl; external CLibCrypto name 'EVP_MD_meth_free'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_input_blocksize'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_result_size'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_app_datasize'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_flags'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_new}
  {$EXTERNALSYM EVP_MD_meth_dup}
  {$EXTERNALSYM EVP_MD_meth_free}
  {$EXTERNALSYM EVP_MD_meth_set_input_blocksize}
  {$EXTERNALSYM EVP_MD_meth_set_result_size}
  {$EXTERNALSYM EVP_MD_meth_set_app_datasize}
  {$EXTERNALSYM EVP_MD_meth_set_flags}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl;
  function Load_EVP_MD_meth_dup(md: PEVP_MD): PEVP_MD; cdecl;
  procedure Load_EVP_MD_meth_free(md: PEVP_MD); cdecl;
  function Load_EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_meth_new: function(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl = Load_EVP_MD_meth_new;
  EVP_MD_meth_dup: function(md: PEVP_MD): PEVP_MD; cdecl = Load_EVP_MD_meth_dup;
  EVP_MD_meth_free: procedure(md: PEVP_MD); cdecl = Load_EVP_MD_meth_free;
  EVP_MD_meth_set_input_blocksize: function(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_input_blocksize;
  EVP_MD_meth_set_result_size: function(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_result_size;
  EVP_MD_meth_set_app_datasize: function(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_app_datasize;
  EVP_MD_meth_set_flags: function(md: PEVP_MD; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_flags;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_set_init(md: PEVP_MD; init: TFuncType000): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_set_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_set_init(md: PEVP_MD; init: TFuncType000): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_meth_set_init: function(md: PEVP_MD; init: TFuncType000): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = function(ctx: PEVP_MD_CTX; data: pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_set_update(md: PEVP_MD; update: TFuncType001): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_update'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_set_update}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_set_update(md: PEVP_MD; update: TFuncType001): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_meth_set_update: function(md: PEVP_MD; update: TFuncType001): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_update;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  {end of auto-generated forward references}

  TFuncType002 = function(ctx: PEVP_MD_CTX; md: Pbyte): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_set_final(md: PEVP_MD; final: TFuncType002): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_final'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_set_final}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_set_final(md: PEVP_MD; final: TFuncType002): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_meth_set_final: function(md: PEVP_MD; final: TFuncType002): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_final;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType003 = ^TFuncType003;
  PPFuncType003 = ^PFuncType003;
  {end of auto-generated forward references}

  TFuncType003 = function(to_: PEVP_MD_CTX; from_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_set_copy(md: PEVP_MD; copy: TFuncType003): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_copy'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_set_copy}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_set_copy(md: PEVP_MD; copy: TFuncType003): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_meth_set_copy: function(md: PEVP_MD; copy: TFuncType003): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_copy;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType004 = ^TFuncType004;
  PPFuncType004 = ^PFuncType004;
  {end of auto-generated forward references}

  TFuncType004 = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: TFuncType004): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_cleanup'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_set_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: TFuncType004): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_meth_set_cleanup: function(md: PEVP_MD; cleanup: TFuncType004): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_cleanup;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType005 = ^TFuncType005;
  PPFuncType005 = ^PFuncType005;
  {end of auto-generated forward references}

  TFuncType005 = function(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: TFuncType005): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_set_ctrl'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_get_input_blocksize(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_get_input_blocksize'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_get_result_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_get_result_size'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_get_app_datasize(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_meth_get_app_datasize'; deprecated 'Since OpenSSL 3.0';
  function EVP_MD_meth_get_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'EVP_MD_meth_get_flags'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_set_ctrl}
  {$EXTERNALSYM EVP_MD_meth_get_input_blocksize}
  {$EXTERNALSYM EVP_MD_meth_get_result_size}
  {$EXTERNALSYM EVP_MD_meth_get_app_datasize}
  {$EXTERNALSYM EVP_MD_meth_get_flags}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: TFuncType005): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_meth_get_input_blocksize(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_meth_get_result_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_meth_get_app_datasize(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_meth_get_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl;

var
  EVP_MD_meth_set_ctrl: function(md: PEVP_MD; ctrl: TFuncType005): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_set_ctrl;
  EVP_MD_meth_get_input_blocksize: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_get_input_blocksize;
  EVP_MD_meth_get_result_size: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_get_result_size;
  EVP_MD_meth_get_app_datasize: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_meth_get_app_datasize;
  EVP_MD_meth_get_flags: function(md: PEVP_MD): TOpenSSL_C_UINT; cdecl = Load_EVP_MD_meth_get_flags;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType006 = ^TFuncType006;
  PPFuncType006 = ^PFuncType006;
  {end of auto-generated forward references}

  TFuncType006 = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_get_init(md: PEVP_MD): TFuncType006; cdecl; external CLibCrypto name 'EVP_MD_meth_get_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_get_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_get_init(md: PEVP_MD): TFuncType006; cdecl;

var
  EVP_MD_meth_get_init: function(md: PEVP_MD): TFuncType006; cdecl = Load_EVP_MD_meth_get_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType007 = ^TFuncType007;
  PPFuncType007 = ^PFuncType007;
  {end of auto-generated forward references}

  TFuncType007 = function(ctx: PEVP_MD_CTX; data: pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_get_update(md: PEVP_MD): TFuncType007; cdecl; external CLibCrypto name 'EVP_MD_meth_get_update'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_get_update}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_get_update(md: PEVP_MD): TFuncType007; cdecl;

var
  EVP_MD_meth_get_update: function(md: PEVP_MD): TFuncType007; cdecl = Load_EVP_MD_meth_get_update;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType008 = ^TFuncType008;
  PPFuncType008 = ^PFuncType008;
  {end of auto-generated forward references}

  TFuncType008 = function(ctx: PEVP_MD_CTX; md: Pbyte): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_get_final(md: PEVP_MD): TFuncType008; cdecl; external CLibCrypto name 'EVP_MD_meth_get_final'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_get_final}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_get_final(md: PEVP_MD): TFuncType008; cdecl;

var
  EVP_MD_meth_get_final: function(md: PEVP_MD): TFuncType008; cdecl = Load_EVP_MD_meth_get_final;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType009 = ^TFuncType009;
  PPFuncType009 = ^PFuncType009;
  {end of auto-generated forward references}

  TFuncType009 = function(to_: PEVP_MD_CTX; from_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_get_copy(md: PEVP_MD): TFuncType009; cdecl; external CLibCrypto name 'EVP_MD_meth_get_copy'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_get_copy}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_get_copy(md: PEVP_MD): TFuncType009; cdecl;

var
  EVP_MD_meth_get_copy: function(md: PEVP_MD): TFuncType009; cdecl = Load_EVP_MD_meth_get_copy;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType010 = ^TFuncType010;
  PPFuncType010 = ^PFuncType010;
  {end of auto-generated forward references}

  TFuncType010 = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_get_cleanup(md: PEVP_MD): TFuncType010; cdecl; external CLibCrypto name 'EVP_MD_meth_get_cleanup'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_get_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_get_cleanup(md: PEVP_MD): TFuncType010; cdecl;

var
  EVP_MD_meth_get_cleanup: function(md: PEVP_MD): TFuncType010; cdecl = Load_EVP_MD_meth_get_cleanup;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType011 = ^TFuncType011;
  PPFuncType011 = ^PFuncType011;
  {end of auto-generated forward references}

  TFuncType011 = function(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_meth_get_ctrl(md: PEVP_MD): TFuncType011; cdecl; external CLibCrypto name 'EVP_MD_meth_get_ctrl'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_MD_meth_get_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_meth_get_ctrl(md: PEVP_MD): TFuncType011; cdecl;

var
  EVP_MD_meth_get_ctrl: function(md: PEVP_MD): TFuncType011; cdecl = Load_EVP_MD_meth_get_ctrl;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}

const
    { digest can only handle a single block }
  EVP_MD_FLAG_ONESHOT = $0001;
    { digest is extensible-output function, XOF }
  EVP_MD_FLAG_XOF = $0002;
    { DigestAlgorithmIdentifier flags... }
  EVP_MD_FLAG_DIGALGID_MASK = $0018;
    { NULL or absent parameter accepted. Use NULL }
  EVP_MD_FLAG_DIGALGID_NULL = $0000;
    { NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent }
  EVP_MD_FLAG_DIGALGID_ABSENT = $0008;
    { Custom handling via ctrl }
  EVP_MD_FLAG_DIGALGID_CUSTOM = $0018;
    { Note if suitable for use in FIPS mode }
  EVP_MD_FLAG_FIPS = $0400;
    { Digest ctrls }
  EVP_MD_CTRL_DIGALGID = $1;
  EVP_MD_CTRL_MICALG = $2;
  EVP_MD_CTRL_XOF_LEN = $3;
  EVP_MD_CTRL_TLSTREE = $4;
    { Minimum Algorithm specific ctrl value }
  EVP_MD_CTRL_ALG_CTRL = $1000;
  {$endif}

const
  { !EVP_MD }
  { values for EVP_MD_CTX flags }
  EVP_MD_CTX_FLAG_ONESHOT = $0001;
  EVP_MD_CTX_FLAG_CLEANED = $0002;
  EVP_MD_CTX_FLAG_REUSE = $0004;
  
  {* FIPS and pad options are ignored in 1.0.0, definitions are here so we
  * don't accidentally reuse the values for other purposes.
  }
  { This flag has no effect from openssl-3.0 onwards }
  EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = $0008;
  
  {* The following PAD options are also currently ignored in 1.0.0, digest
  * parameters are handled through EVP_DigestSign*() and EVP_DigestVerify*()
  * instead.
  }
  EVP_MD_CTX_FLAG_PAD_MASK = $F0;
  EVP_MD_CTX_FLAG_PAD_PKCS1 = $00;
  EVP_MD_CTX_FLAG_PAD_X931 = $10;
  EVP_MD_CTX_FLAG_PAD_PSS = $20;
  EVP_MD_CTX_FLAG_NO_INIT = $0100;
  
  {* Some functions such as EVP_DigestSign only finalise copies of internal
  * contexts so additional data can be included after the finalisation call.
  * This is inefficient if this functionality is not required: it is disabled
  * if the following flag is set.
  }
  EVP_MD_CTX_FLAG_FINALISE = $0200;
  { NOTE: 0x0400 and 0x0800 are reserved for internal usage }
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_new'; deprecated 'Since OpenSSL 3.0';
  function EVP_CIPHER_meth_dup(cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_dup'; deprecated 'Since OpenSSL 3.0';
  procedure EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl; external CLibCrypto name 'EVP_CIPHER_meth_free'; deprecated 'Since OpenSSL 3.0';
  function EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_iv_length'; deprecated 'Since OpenSSL 3.0';
  function EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_flags'; deprecated 'Since OpenSSL 3.0';
  function EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_impl_ctx_size'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_new}
  {$EXTERNALSYM EVP_CIPHER_meth_dup}
  {$EXTERNALSYM EVP_CIPHER_meth_free}
  {$EXTERNALSYM EVP_CIPHER_meth_set_iv_length}
  {$EXTERNALSYM EVP_CIPHER_meth_set_flags}
  {$EXTERNALSYM EVP_CIPHER_meth_set_impl_ctx_size}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
  function Load_EVP_CIPHER_meth_dup(cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl;
  procedure Load_EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl;
  function Load_EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_meth_new: function(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_meth_new;
  EVP_CIPHER_meth_dup: function(cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_meth_dup;
  EVP_CIPHER_meth_free: procedure(cipher: PEVP_CIPHER); cdecl = Load_EVP_CIPHER_meth_free;
  EVP_CIPHER_meth_set_iv_length: function(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_iv_length;
  EVP_CIPHER_meth_set_flags: function(cipher: PEVP_CIPHER; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_flags;
  EVP_CIPHER_meth_set_impl_ctx_size: function(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_impl_ctx_size;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType012 = ^TFuncType012;
  PPFuncType012 = ^PFuncType012;
  {end of auto-generated forward references}

  TFuncType012 = function(ctx: PEVP_CIPHER_CTX; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: TFuncType012): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_init'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_set_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: TFuncType012): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_meth_set_init: function(cipher: PEVP_CIPHER; init: TFuncType012): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_init;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType013 = ^TFuncType013;
  PPFuncType013 = ^PFuncType013;
  {end of auto-generated forward references}

  TFuncType013 = function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; in_: Pbyte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: TFuncType013): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_do_cipher'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_set_do_cipher}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: TFuncType013): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_meth_set_do_cipher: function(cipher: PEVP_CIPHER; do_cipher: TFuncType013): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_do_cipher;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType014 = ^TFuncType014;
  PPFuncType014 = ^PFuncType014;
  {end of auto-generated forward references}

  TFuncType014 = function(_param1: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: TFuncType014): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_cleanup'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_set_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: TFuncType014): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_meth_set_cleanup: function(cipher: PEVP_CIPHER; cleanup: TFuncType014): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_cleanup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType015 = ^TFuncType015;
  PPFuncType015 = ^PFuncType015;
  {end of auto-generated forward references}

  TFuncType015 = function(_param1: PEVP_CIPHER_CTX; _param2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: TFuncType015): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_set_asn1_params'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_set_set_asn1_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: TFuncType015): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_meth_set_set_asn1_params: function(cipher: PEVP_CIPHER; set_asn1_parameters: TFuncType015): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_set_asn1_params;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType016 = ^TFuncType016;
  PPFuncType016 = ^PFuncType016;
  {end of auto-generated forward references}

  TFuncType016 = function(_param1: PEVP_CIPHER_CTX; _param2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: TFuncType016): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_get_asn1_params'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_set_get_asn1_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: TFuncType016): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_meth_set_get_asn1_params: function(cipher: PEVP_CIPHER; get_asn1_parameters: TFuncType016): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_get_asn1_params;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType017 = ^TFuncType017;
  PPFuncType017 = ^PFuncType017;
  {end of auto-generated forward references}

  TFuncType017 = function(_param1: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: pointer): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: TFuncType017): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_set_ctrl'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_set_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: TFuncType017): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_meth_set_ctrl: function(cipher: PEVP_CIPHER; ctrl: TFuncType017): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_meth_set_ctrl;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType018 = ^TFuncType018;
  PPFuncType018 = ^PFuncType018;
  {end of auto-generated forward references}

  TFuncType018 = function(ctx: PEVP_CIPHER_CTX; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_get_init(cipher: PEVP_CIPHER): TFuncType018; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_get_init'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_get_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_get_init(cipher: PEVP_CIPHER): TFuncType018; cdecl;

var
  EVP_CIPHER_meth_get_init: function(cipher: PEVP_CIPHER): TFuncType018; cdecl = Load_EVP_CIPHER_meth_get_init;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType019 = ^TFuncType019;
  PPFuncType019 = ^PFuncType019;
  {end of auto-generated forward references}

  TFuncType019 = function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; in_: Pbyte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_get_do_cipher(cipher: PEVP_CIPHER): TFuncType019; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_get_do_cipher'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_get_do_cipher}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_get_do_cipher(cipher: PEVP_CIPHER): TFuncType019; cdecl;

var
  EVP_CIPHER_meth_get_do_cipher: function(cipher: PEVP_CIPHER): TFuncType019; cdecl = Load_EVP_CIPHER_meth_get_do_cipher;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType020 = ^TFuncType020;
  PPFuncType020 = ^PFuncType020;
  {end of auto-generated forward references}

  TFuncType020 = function(_param1: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_get_cleanup(cipher: PEVP_CIPHER): TFuncType020; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_get_cleanup'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_get_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_get_cleanup(cipher: PEVP_CIPHER): TFuncType020; cdecl;

var
  EVP_CIPHER_meth_get_cleanup: function(cipher: PEVP_CIPHER): TFuncType020; cdecl = Load_EVP_CIPHER_meth_get_cleanup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType021 = ^TFuncType021;
  PPFuncType021 = ^PFuncType021;
  {end of auto-generated forward references}

  TFuncType021 = function(_param1: PEVP_CIPHER_CTX; _param2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_get_set_asn1_params(cipher: PEVP_CIPHER): TFuncType021; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_get_set_asn1_params'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_get_set_asn1_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_get_set_asn1_params(cipher: PEVP_CIPHER): TFuncType021; cdecl;

var
  EVP_CIPHER_meth_get_set_asn1_params: function(cipher: PEVP_CIPHER): TFuncType021; cdecl = Load_EVP_CIPHER_meth_get_set_asn1_params;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType022 = ^TFuncType022;
  PPFuncType022 = ^PFuncType022;
  {end of auto-generated forward references}

  TFuncType022 = function(_param1: PEVP_CIPHER_CTX; _param2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_get_get_asn1_params(cipher: PEVP_CIPHER): TFuncType022; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_get_get_asn1_params'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_get_get_asn1_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_get_get_asn1_params(cipher: PEVP_CIPHER): TFuncType022; cdecl;

var
  EVP_CIPHER_meth_get_get_asn1_params: function(cipher: PEVP_CIPHER): TFuncType022; cdecl = Load_EVP_CIPHER_meth_get_get_asn1_params;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType023 = ^TFuncType023;
  PPFuncType023 = ^PFuncType023;
  {end of auto-generated forward references}

  TFuncType023 = function(_param1: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: pointer): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_meth_get_ctrl(cipher: PEVP_CIPHER): TFuncType023; cdecl; external CLibCrypto name 'EVP_CIPHER_meth_get_ctrl'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_meth_get_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_meth_get_ctrl(cipher: PEVP_CIPHER): TFuncType023; cdecl;

var
  EVP_CIPHER_meth_get_ctrl: function(cipher: PEVP_CIPHER): TFuncType023; cdecl = Load_EVP_CIPHER_meth_get_ctrl;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}

const
  { Values for cipher flags }
  { Modes for ciphers }
  EVP_CIPH_STREAM_CIPHER = $0;
  EVP_CIPH_ECB_MODE = $1;
  EVP_CIPH_CBC_MODE = $2;
  EVP_CIPH_CFB_MODE = $3;
  EVP_CIPH_OFB_MODE = $4;
  EVP_CIPH_CTR_MODE = $5;
  EVP_CIPH_GCM_MODE = $6;
  EVP_CIPH_CCM_MODE = $7;
  EVP_CIPH_XTS_MODE = $10001;
  EVP_CIPH_WRAP_MODE = $10002;
  EVP_CIPH_OCB_MODE = $10003;
  EVP_CIPH_SIV_MODE = $10004;
  EVP_CIPH_GCM_SIV_MODE = $10005;
  EVP_CIPH_MODE = $F0007;
  { Set if variable length cipher }
  EVP_CIPH_VARIABLE_LENGTH = $8;
  { Set if the iv handling should be done by the cipher itself }
  EVP_CIPH_CUSTOM_IV = $10;
  { Set if the cipher's init() function should be called if key is NULL }
  EVP_CIPH_ALWAYS_CALL_INIT = $20;
  { Call ctrl() to init cipher parameters }
  EVP_CIPH_CTRL_INIT = $40;
  { Don't use standard key length function }
  EVP_CIPH_CUSTOM_KEY_LENGTH = $80;
  { Don't use standard block padding }
  EVP_CIPH_NO_PADDING = $100;
  { cipher handles random key generation }
  EVP_CIPH_RAND_KEY = $200;
  { cipher has its own additional copying logic }
  EVP_CIPH_CUSTOM_COPY = $400;
  { Don't use standard iv length function }
  EVP_CIPH_CUSTOM_IV_LENGTH = $800;
  { Legacy and no longer relevant: Allow use default ASN1 get/set iv }
  EVP_CIPH_FLAG_DEFAULT_ASN1 = 0;
  { Free:                                         0x1000 }
  { Buffer length in bits not bytes: CFB1 mode only }
  EVP_CIPH_FLAG_LENGTH_BITS = $2000;
  { Deprecated FIPS flag: was 0x4000 }
  EVP_CIPH_FLAG_FIPS = 0;
  { Deprecated FIPS flag: was 0x8000 }
  EVP_CIPH_FLAG_NON_FIPS_ALLOW = 0;
  
  {* Cipher handles any and all padding logic as well as finalisation.
  }
  EVP_CIPH_FLAG_CTS = $4000;
  EVP_CIPH_FLAG_CUSTOM_CIPHER = $100000;
  EVP_CIPH_FLAG_AEAD_CIPHER = $200000;
  EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK = $400000;
  { Cipher can handle pipeline operations }
  EVP_CIPH_FLAG_PIPELINE = $800000;
  { For provider implementations that handle  ASN1 get/set param themselves }
  EVP_CIPH_FLAG_CUSTOM_ASN1 = $1000000;
  { For ciphers generating unprotected CMS attributes }
  EVP_CIPH_FLAG_CIPHER_WITH_MAC = $2000000;
  { For supplementary wrap cipher support }
  EVP_CIPH_FLAG_GET_WRAP_CIPHER = $4000000;
  EVP_CIPH_FLAG_INVERSE_CIPHER = $8000000;
  EVP_CIPH_FLAG_ENC_THEN_MAC = $10000000;
  
  {* Cipher context flag to indicate we can handle wrap mode: if allowed in
  * older applications it could overflow buffers.
  }
  EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = $1;
  { ctrl() values }
  EVP_CTRL_INIT = $0;
  EVP_CTRL_SET_KEY_LENGTH = $1;
  EVP_CTRL_GET_RC2_KEY_BITS = $2;
  EVP_CTRL_SET_RC2_KEY_BITS = $3;
  EVP_CTRL_GET_RC5_ROUNDS = $4;
  EVP_CTRL_SET_RC5_ROUNDS = $5;
  EVP_CTRL_RAND_KEY = $6;
  EVP_CTRL_PBE_PRF_NID = $7;
  EVP_CTRL_COPY = $8;
  EVP_CTRL_AEAD_SET_IVLEN = $9;
  EVP_CTRL_AEAD_GET_TAG = $10;
  EVP_CTRL_AEAD_SET_TAG = $11;
  EVP_CTRL_AEAD_SET_IV_FIXED = $12;
  EVP_CTRL_GCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;
  EVP_CTRL_GCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;
  EVP_CTRL_GCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;
  EVP_CTRL_GCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;
  EVP_CTRL_GCM_IV_GEN = $13;
  EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN;
  EVP_CTRL_CCM_GET_TAG = EVP_CTRL_AEAD_GET_TAG;
  EVP_CTRL_CCM_SET_TAG = EVP_CTRL_AEAD_SET_TAG;
  EVP_CTRL_CCM_SET_IV_FIXED = EVP_CTRL_AEAD_SET_IV_FIXED;
  EVP_CTRL_CCM_SET_L = $14;
  EVP_CTRL_CCM_SET_MSGLEN = $15;
  
  {* AEAD cipher deduces payload length and returns number of bytes required to
  * store MAC and eventual padding. Subsequent call to EVP_Cipher even
  * appends/verifies MAC.
  }
  EVP_CTRL_AEAD_TLS1_AAD = $16;
  { Used by composite AEAD ciphers, no-op in GCM, CCM... }
  EVP_CTRL_AEAD_SET_MAC_KEY = $17;
  { Set the GCM invocation field, decrypt only }
  EVP_CTRL_GCM_SET_IV_INV = $18;
  EVP_CTRL_TLS1_1_MULTIBLOCK_AAD = $19;
  EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT = $1a;
  EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT = $1b;
  EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE = $1c;
  EVP_CTRL_SSL3_MASTER_SECRET = $1d;
  { EVP_CTRL_SET_SBOX takes the char * specifying S-boxes }
  EVP_CTRL_SET_SBOX = $1e;
  
  {* EVP_CTRL_SBOX_USED takes a 'size_t' and 'char *', pointing at a
  * pre-allocated buffer with specified size
  }
  EVP_CTRL_SBOX_USED = $1f;
  { EVP_CTRL_KEY_MESH takes 'size_t' number of bytes to mesh the key after,
  * 0 switches meshing off
  }
  EVP_CTRL_KEY_MESH = $20;
  { EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode }
  EVP_CTRL_BLOCK_PADDING_MODE = $21;
  { Set the output buffers to use for a pipelined operation }
  EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS = $22;
  { Set the input buffers to use for a pipelined operation }
  EVP_CTRL_SET_PIPELINE_INPUT_BUFS = $23;
  { Set the input buffer lengths to use for a pipelined operation }
  EVP_CTRL_SET_PIPELINE_INPUT_LENS = $24;
  { Get the IV length used by the cipher }
  EVP_CTRL_GET_IVLEN = $25;
  { 0x26 is unused }
  { Tell the cipher it's doing a speed test (SIV disallows multiple ops) }
  EVP_CTRL_SET_SPEED = $27;
  { Get the unprotectedAttrs from cipher ctx }
  EVP_CTRL_PROCESS_UNPROTECTED = $28;
  { Get the supplementary wrap cipher }
  EVP_CTRL_GET_WRAP_CIPHER = $29;
  { TLSTREE key diversification }
  EVP_CTRL_TLSTREE = $2A;
  { Padding modes }
  EVP_PADDING_PKCS7 = 1;
  EVP_PADDING_ISO7816_4 = 2;
  EVP_PADDING_ANSI923 = 3;
  EVP_PADDING_ISO10126 = 4;
  EVP_PADDING_ZERO = 5;
  { RFC 5246 defines additional data to be 13 bytes in length }
  EVP_AEAD_TLS1_AAD_LEN = 13;

type
  {Auto-generated forward references}
  PEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = ^TEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;
  PPEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = ^PEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM;
  {end of auto-generated forward references}

  TEVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = record 
    out_: Pbyte;
    inp: Pbyte;
    len: TOpenSSL_C_SIZET;
    interleave: TOpenSSL_C_UINT;
  end;

const
  { GCM TLS constants }
  { Length of fixed part of IV derived from PRF }
  EVP_GCM_TLS_FIXED_IV_LEN = 4;
  { Length of explicit part of IV part of TLS records }
  EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;
  { Length of tag for TLS }
  EVP_GCM_TLS_TAG_LEN = 16;
  { CCM TLS constants }
  { Length of fixed part of IV derived from PRF }
  EVP_CCM_TLS_FIXED_IV_LEN = 4;
  { Length of explicit part of IV part of TLS records }
  EVP_CCM_TLS_EXPLICIT_IV_LEN = 8;
  { Total length of CCM IV length for TLS }
  EVP_CCM_TLS_IV_LEN = 12;
  { Length of tag for TLS }
  EVP_CCM_TLS_TAG_LEN = 16;
  { Length of CCM8 tag for TLS }
  EVP_CCM8_TLS_TAG_LEN = 8;
  { Length of tag for TLS }
  EVP_CHACHAPOLY_TLS_TAG_LEN = 16;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_Cipher(c: PEVP_CIPHER_CTX; out_: Pbyte; in_: Pbyte; inl: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_Cipher';
  {$else}
  {$EXTERNALSYM EVP_Cipher}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_Cipher(c: PEVP_CIPHER_CTX; out_: Pbyte; in_: Pbyte; inl: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

var
  EVP_Cipher: function(c: PEVP_CIPHER_CTX; out_: Pbyte; in_: Pbyte; inl: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EVP_Cipher;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  Pevp_cipher_info_st = ^Tevp_cipher_info_st;
  PPevp_cipher_info_st = ^Pevp_cipher_info_st;
  PEVP_CIPHER_INFO = ^TEVP_CIPHER_INFO;
  PPEVP_CIPHER_INFO = ^PEVP_CIPHER_INFO;
  PEVP_PBE_KEYGEN = ^TEVP_PBE_KEYGEN;
  PPEVP_PBE_KEYGEN = ^PEVP_PBE_KEYGEN;
  PEVP_PBE_KEYGEN_EX = ^TEVP_PBE_KEYGEN_EX;
  PPEVP_PBE_KEYGEN_EX = ^PEVP_PBE_KEYGEN_EX;
  {end of auto-generated forward references}

  Tevp_cipher_info_st = record 
    cipher: PEVP_CIPHER;
    iv: array[0..15] of byte;
  end;
  TEVP_CIPHER_INFO = Tevp_cipher_info_st;
  { Password based encryption function }
  TEVP_PBE_KEYGEN = function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TEVP_PBE_KEYGEN_EX = function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


  function EVP_PKEY_assign_RSA(pkey:PEVP_PKEY; rsa:pointer): TOpenSSL_C_INT; inline;
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_6}
    {$ifndef  OPENSSL_NO_DSA}


  function EVP_PKEY_assign_DSA(pkey:PEVP_PKEY; dsa:pointer): TOpenSSL_C_INT; inline;
    {$endif}
  {$endif}
  {$if  not defined(OPENSSL_NO_DH)  and  not defined(OPENSSL_NO_DEPRECATED_3_0)}


  function EVP_PKEY_assign_DH(pkey:PEVP_PKEY; dh:pointer): TOpenSSL_C_INT; inline;
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_EC}


  function EVP_PKEY_assign_EC_KEY(pkey:PEVP_PKEY; eckey:pointer): TOpenSSL_C_INT; inline;
    {$endif}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_6}
    {$ifndef  OPENSSL_NO_SIPHASH}


  function EVP_PKEY_assign_SIPHASH(pkey:PEVP_PKEY; shkey:pointer): TOpenSSL_C_INT; inline;
    {$endif}
    {$ifndef  OPENSSL_NO_POLY1305}


  function EVP_PKEY_assign_POLY1305(pkey:PEVP_PKEY; polykey:pointer): TOpenSSL_C_INT; inline;
    {$endif}
  {$endif}


  { Add some extra combinations }
  function EVP_get_digestbynid(a: TOpenSSL_C_INT): PEVP_MD; inline;
  function EVP_get_digestbyobj(a:PASN1_OBJECT): PEVP_MD; inline;
  function EVP_get_cipherbynid(a: TOpenSSL_C_INT): PEVP_CIPHER; inline;
  function EVP_get_cipherbyobj(a:PASN1_OBJECT): PEVP_CIPHER; inline;
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_get_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_type';
  function EVP_MD_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_type';
  function EVP_MD_nid(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_type';
  function EVP_MD_get0_name(md: PEVP_MD): PAnsiChar; cdecl; external CLibCrypto name 'EVP_MD_get0_name';
  function EVP_MD_name(md: PEVP_MD): PAnsiChar; cdecl; external CLibCrypto name 'EVP_MD_get0_name';
  function EVP_MD_get0_description(md: PEVP_MD): PAnsiChar; cdecl; external CLibCrypto name 'EVP_MD_get0_description';
  function EVP_MD_is_a(md: PEVP_MD; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_is_a';
  {$else}
  {$EXTERNALSYM EVP_MD_get_type}
  {$EXTERNALSYM EVP_MD_type}
  {$EXTERNALSYM EVP_MD_nid}
  {$EXTERNALSYM EVP_MD_get0_name}
  {$EXTERNALSYM EVP_MD_name}
  {$EXTERNALSYM EVP_MD_get0_description}
  {$EXTERNALSYM EVP_MD_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_get_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_nid(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_get0_name(md: PEVP_MD): PAnsiChar; cdecl;
  function Load_EVP_MD_name(md: PEVP_MD): PAnsiChar; cdecl;
  function Load_EVP_MD_get0_description(md: PEVP_MD): PAnsiChar; cdecl;
  function Load_EVP_MD_is_a(md: PEVP_MD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_get_type: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_get_type;
  EVP_MD_type: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_type;
  EVP_MD_nid: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_nid;
  EVP_MD_get0_name: function(md: PEVP_MD): PAnsiChar; cdecl = Load_EVP_MD_get0_name;
  EVP_MD_name: function(md: PEVP_MD): PAnsiChar; cdecl = Load_EVP_MD_name;
  EVP_MD_get0_description: function(md: PEVP_MD): PAnsiChar; cdecl = Load_EVP_MD_get0_description;
  EVP_MD_is_a: function(md: PEVP_MD; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_MD_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType024 = ^TFuncType024;
  PPFuncType024 = ^PFuncType024;
  {end of auto-generated forward references}

  TFuncType024 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_names_do_all(md: PEVP_MD; fn: TFuncType024; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_names_do_all';
  function EVP_MD_get0_provider(md: PEVP_MD): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_MD_get0_provider';
  function EVP_MD_get_pkey_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_pkey_type';
  function EVP_MD_pkey_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_pkey_type';
  function EVP_MD_get_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_size';
  function EVP_MD_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_size';
  function EVP_MD_get_block_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_block_size';
  function EVP_MD_block_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_block_size';
  function EVP_MD_get_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'EVP_MD_get_flags';
  function EVP_MD_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'EVP_MD_get_flags';
  function EVP_MD_xof(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_xof';
  function EVP_MD_CTX_get0_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl; external CLibCrypto name 'EVP_MD_CTX_get0_md';
  function EVP_MD_CTX_get1_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl; external CLibCrypto name 'EVP_MD_CTX_get1_md';
  {$else}
  {$EXTERNALSYM EVP_MD_names_do_all}
  {$EXTERNALSYM EVP_MD_get0_provider}
  {$EXTERNALSYM EVP_MD_get_pkey_type}
  {$EXTERNALSYM EVP_MD_pkey_type}
  {$EXTERNALSYM EVP_MD_get_size}
  {$EXTERNALSYM EVP_MD_size}
  {$EXTERNALSYM EVP_MD_get_block_size}
  {$EXTERNALSYM EVP_MD_block_size}
  {$EXTERNALSYM EVP_MD_get_flags}
  {$EXTERNALSYM EVP_MD_flags}
  {$EXTERNALSYM EVP_MD_xof}
  {$EXTERNALSYM EVP_MD_CTX_get0_md}
  {$EXTERNALSYM EVP_MD_CTX_get1_md}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_names_do_all(md: PEVP_MD; fn: TFuncType024; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_get0_provider(md: PEVP_MD): POSSL_PROVIDER; cdecl;
  function Load_EVP_MD_get_pkey_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_pkey_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_get_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_get_block_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_block_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_get_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl;
  function Load_EVP_MD_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl;
  function Load_EVP_MD_xof(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_CTX_get0_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;
  function Load_EVP_MD_CTX_get1_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;

var
  EVP_MD_names_do_all: function(md: PEVP_MD; fn: TFuncType024; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_MD_names_do_all;
  EVP_MD_get0_provider: function(md: PEVP_MD): POSSL_PROVIDER; cdecl = Load_EVP_MD_get0_provider;
  EVP_MD_get_pkey_type: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_get_pkey_type;
  EVP_MD_pkey_type: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_pkey_type;
  EVP_MD_get_size: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_get_size;
  EVP_MD_size: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_size;
  EVP_MD_get_block_size: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_get_block_size;
  EVP_MD_block_size: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_block_size;
  EVP_MD_get_flags: function(md: PEVP_MD): TOpenSSL_C_UINT; cdecl = Load_EVP_MD_get_flags;
  EVP_MD_flags: function(md: PEVP_MD): TOpenSSL_C_UINT; cdecl = Load_EVP_MD_flags;
  EVP_MD_xof: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_xof;
  EVP_MD_CTX_get0_md: function(ctx: PEVP_MD_CTX): PEVP_MD; cdecl = Load_EVP_MD_CTX_get0_md;
  EVP_MD_CTX_get1_md: function(ctx: PEVP_MD_CTX): PEVP_MD; cdecl = Load_EVP_MD_CTX_get1_md;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl; external CLibCrypto name 'EVP_MD_CTX_md'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_MD_CTX_md}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;

var
  EVP_MD_CTX_md: function(ctx: PEVP_MD_CTX): PEVP_MD; cdecl = Load_EVP_MD_CTX_md;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType025 = ^TFuncType025;
  PPFuncType025 = ^PFuncType025;
  {end of auto-generated forward references}

  TFuncType025 = function(ctx: PEVP_MD_CTX; data: pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): TFuncType025; cdecl; external CLibCrypto name 'EVP_MD_CTX_update_fn'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_MD_CTX_update_fn}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): TFuncType025; cdecl;

var
  EVP_MD_CTX_update_fn: function(ctx: PEVP_MD_CTX): TFuncType025; cdecl = Load_EVP_MD_CTX_update_fn;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType026 = ^TFuncType026;
  PPFuncType026 = ^PFuncType026;
  {end of auto-generated forward references}

  TFuncType026 = function(ctx: PEVP_MD_CTX; data: pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: TFuncType026); cdecl; external CLibCrypto name 'EVP_MD_CTX_set_update_fn'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_MD_CTX_set_update_fn}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: TFuncType026); cdecl;

var
  EVP_MD_CTX_set_update_fn: procedure(ctx: PEVP_MD_CTX; update: TFuncType026); cdecl = Load_EVP_MD_CTX_set_update_fn;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_CTX_get_size_ex(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_get_size_ex';
  {$else}
  {$EXTERNALSYM EVP_MD_CTX_get_size_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_CTX_get_size_ex(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_CTX_get_size_ex: function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_get_size_ex;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}


  function EVP_MD_CTX_get0_name(e:PEVP_MD_CTX): PAnsiChar; inline;
  function EVP_MD_CTX_get_size(e:PEVP_MD_CTX): TOpenSSL_C_INT; inline;
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_CTX_size(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_get_size_ex';
  {$else}
  {$EXTERNALSYM EVP_MD_CTX_size}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_CTX_size(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_CTX_size: function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_size;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}


  function EVP_MD_CTX_get_block_size(e:PEVP_MD_CTX): TOpenSSL_C_INT; inline;
  function EVP_MD_CTX_block_size(e:PEVP_MD_CTX): TOpenSSL_C_INT; inline;
  function EVP_MD_CTX_get_type(e:PEVP_MD_CTX): TOpenSSL_C_INT; inline;
  function EVP_MD_CTX_type(e:PEVP_MD_CTX): TOpenSSL_C_INT; inline;
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_CTX_get_pkey_ctx(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl; external CLibCrypto name 'EVP_MD_CTX_get_pkey_ctx';
  function EVP_MD_CTX_pkey_ctx(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl; external CLibCrypto name 'EVP_MD_CTX_get_pkey_ctx';
  procedure EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl; external CLibCrypto name 'EVP_MD_CTX_set_pkey_ctx';
  function EVP_MD_CTX_get0_md_data(ctx: PEVP_MD_CTX): pointer; cdecl; external CLibCrypto name 'EVP_MD_CTX_get0_md_data';
  function EVP_MD_CTX_md_data(ctx: PEVP_MD_CTX): pointer; cdecl; external CLibCrypto name 'EVP_MD_CTX_get0_md_data';
  function EVP_CIPHER_get_nid(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_nid';
  function EVP_CIPHER_nid(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_nid';
  function EVP_CIPHER_get0_name(cipher: PEVP_CIPHER): PAnsiChar; cdecl; external CLibCrypto name 'EVP_CIPHER_get0_name';
  function EVP_CIPHER_name(cipher: PEVP_CIPHER): PAnsiChar; cdecl; external CLibCrypto name 'EVP_CIPHER_get0_name';
  function EVP_CIPHER_get0_description(cipher: PEVP_CIPHER): PAnsiChar; cdecl; external CLibCrypto name 'EVP_CIPHER_get0_description';
  function EVP_CIPHER_is_a(cipher: PEVP_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_is_a';
  {$else}
  {$EXTERNALSYM EVP_MD_CTX_get_pkey_ctx}
  {$EXTERNALSYM EVP_MD_CTX_pkey_ctx}
  {$EXTERNALSYM EVP_MD_CTX_set_pkey_ctx}
  {$EXTERNALSYM EVP_MD_CTX_get0_md_data}
  {$EXTERNALSYM EVP_MD_CTX_md_data}
  {$EXTERNALSYM EVP_CIPHER_get_nid}
  {$EXTERNALSYM EVP_CIPHER_nid}
  {$EXTERNALSYM EVP_CIPHER_get0_name}
  {$EXTERNALSYM EVP_CIPHER_name}
  {$EXTERNALSYM EVP_CIPHER_get0_description}
  {$EXTERNALSYM EVP_CIPHER_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_CTX_get_pkey_ctx(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl;
  function Load_EVP_MD_CTX_pkey_ctx(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl;
  procedure Load_EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl;
  function Load_EVP_MD_CTX_get0_md_data(ctx: PEVP_MD_CTX): pointer; cdecl;
  function Load_EVP_MD_CTX_md_data(ctx: PEVP_MD_CTX): pointer; cdecl;
  function Load_EVP_CIPHER_get_nid(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_nid(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_get0_name(cipher: PEVP_CIPHER): PAnsiChar; cdecl;
  function Load_EVP_CIPHER_name(cipher: PEVP_CIPHER): PAnsiChar; cdecl;
  function Load_EVP_CIPHER_get0_description(cipher: PEVP_CIPHER): PAnsiChar; cdecl;
  function Load_EVP_CIPHER_is_a(cipher: PEVP_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_CTX_get_pkey_ctx: function(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl = Load_EVP_MD_CTX_get_pkey_ctx;
  EVP_MD_CTX_pkey_ctx: function(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl = Load_EVP_MD_CTX_pkey_ctx;
  EVP_MD_CTX_set_pkey_ctx: procedure(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl = Load_EVP_MD_CTX_set_pkey_ctx;
  EVP_MD_CTX_get0_md_data: function(ctx: PEVP_MD_CTX): pointer; cdecl = Load_EVP_MD_CTX_get0_md_data;
  EVP_MD_CTX_md_data: function(ctx: PEVP_MD_CTX): pointer; cdecl = Load_EVP_MD_CTX_md_data;
  EVP_CIPHER_get_nid: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_nid;
  EVP_CIPHER_nid: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_nid;
  EVP_CIPHER_get0_name: function(cipher: PEVP_CIPHER): PAnsiChar; cdecl = Load_EVP_CIPHER_get0_name;
  EVP_CIPHER_name: function(cipher: PEVP_CIPHER): PAnsiChar; cdecl = Load_EVP_CIPHER_name;
  EVP_CIPHER_get0_description: function(cipher: PEVP_CIPHER): PAnsiChar; cdecl = Load_EVP_CIPHER_get0_description;
  EVP_CIPHER_is_a: function(cipher: PEVP_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType027 = ^TFuncType027;
  PPFuncType027 = ^PFuncType027;
  {end of auto-generated forward references}

  TFuncType027 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_names_do_all(cipher: PEVP_CIPHER; fn: TFuncType027; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_names_do_all';
  function EVP_CIPHER_get0_provider(cipher: PEVP_CIPHER): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_CIPHER_get0_provider';
  function EVP_CIPHER_get_block_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_block_size';
  function EVP_CIPHER_block_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_block_size';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_names_do_all}
  {$EXTERNALSYM EVP_CIPHER_get0_provider}
  {$EXTERNALSYM EVP_CIPHER_get_block_size}
  {$EXTERNALSYM EVP_CIPHER_block_size}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_names_do_all(cipher: PEVP_CIPHER; fn: TFuncType027; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_get0_provider(cipher: PEVP_CIPHER): POSSL_PROVIDER; cdecl;
  function Load_EVP_CIPHER_get_block_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_block_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_names_do_all: function(cipher: PEVP_CIPHER; fn: TFuncType027; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_names_do_all;
  EVP_CIPHER_get0_provider: function(cipher: PEVP_CIPHER): POSSL_PROVIDER; cdecl = Load_EVP_CIPHER_get0_provider;
  EVP_CIPHER_get_block_size: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_block_size;
  EVP_CIPHER_block_size: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_block_size;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_impl_ctx_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_impl_ctx_size'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_impl_ctx_size}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_impl_ctx_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_impl_ctx_size: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_impl_ctx_size;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_get_key_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_key_length';
  function EVP_CIPHER_key_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_key_length';
  function EVP_CIPHER_get_iv_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_iv_length';
  function EVP_CIPHER_iv_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_iv_length';
  function EVP_CIPHER_get_flags(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_flags';
  function EVP_CIPHER_flags(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_flags';
  function EVP_CIPHER_get_mode(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_mode';
  function EVP_CIPHER_mode(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_mode';
  function EVP_CIPHER_get_type(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_type';
  function EVP_CIPHER_type(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_type';
  function EVP_CIPHER_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_CIPHER_fetch';
  function EVP_CIPHER_can_pipeline(cipher: PEVP_CIPHER; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_can_pipeline';
  function EVP_CIPHER_up_ref(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_up_ref';
  procedure EVP_CIPHER_free(cipher: PEVP_CIPHER); cdecl; external CLibCrypto name 'EVP_CIPHER_free';
  function EVP_CIPHER_CTX_get0_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get0_cipher';
  function EVP_CIPHER_CTX_get1_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get1_cipher';
  function EVP_CIPHER_CTX_is_encrypting(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_is_encrypting';
  function EVP_CIPHER_CTX_encrypting(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_is_encrypting';
  function EVP_CIPHER_CTX_get_nid(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_nid';
  function EVP_CIPHER_CTX_nid(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_nid';
  function EVP_CIPHER_CTX_get_block_size(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_block_size';
  function EVP_CIPHER_CTX_block_size(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_block_size';
  function EVP_CIPHER_CTX_get_key_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_key_length';
  function EVP_CIPHER_CTX_key_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_key_length';
  function EVP_CIPHER_CTX_get_iv_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_iv_length';
  function EVP_CIPHER_CTX_iv_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_iv_length';
  function EVP_CIPHER_CTX_get_tag_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_tag_length';
  function EVP_CIPHER_CTX_tag_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_tag_length';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_get_key_length}
  {$EXTERNALSYM EVP_CIPHER_key_length}
  {$EXTERNALSYM EVP_CIPHER_get_iv_length}
  {$EXTERNALSYM EVP_CIPHER_iv_length}
  {$EXTERNALSYM EVP_CIPHER_get_flags}
  {$EXTERNALSYM EVP_CIPHER_flags}
  {$EXTERNALSYM EVP_CIPHER_get_mode}
  {$EXTERNALSYM EVP_CIPHER_mode}
  {$EXTERNALSYM EVP_CIPHER_get_type}
  {$EXTERNALSYM EVP_CIPHER_type}
  {$EXTERNALSYM EVP_CIPHER_fetch}
  {$EXTERNALSYM EVP_CIPHER_can_pipeline}
  {$EXTERNALSYM EVP_CIPHER_up_ref}
  {$EXTERNALSYM EVP_CIPHER_free}
  {$EXTERNALSYM EVP_CIPHER_CTX_get0_cipher}
  {$EXTERNALSYM EVP_CIPHER_CTX_get1_cipher}
  {$EXTERNALSYM EVP_CIPHER_CTX_is_encrypting}
  {$EXTERNALSYM EVP_CIPHER_CTX_encrypting}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_nid}
  {$EXTERNALSYM EVP_CIPHER_CTX_nid}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_block_size}
  {$EXTERNALSYM EVP_CIPHER_CTX_block_size}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_key_length}
  {$EXTERNALSYM EVP_CIPHER_CTX_key_length}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_iv_length}
  {$EXTERNALSYM EVP_CIPHER_CTX_iv_length}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_tag_length}
  {$EXTERNALSYM EVP_CIPHER_CTX_tag_length}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_get_key_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_key_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_get_iv_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_iv_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_get_flags(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl;
  function Load_EVP_CIPHER_flags(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl;
  function Load_EVP_CIPHER_get_mode(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_mode(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_get_type(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_type(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_CIPHER; cdecl;
  function Load_EVP_CIPHER_can_pipeline(cipher: PEVP_CIPHER; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_up_ref(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_CIPHER_free(cipher: PEVP_CIPHER); cdecl;
  function Load_EVP_CIPHER_CTX_get0_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
  function Load_EVP_CIPHER_CTX_get1_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
  function Load_EVP_CIPHER_CTX_is_encrypting(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_encrypting(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_nid(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_nid(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_block_size(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_block_size(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_key_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_key_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_iv_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_iv_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_tag_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_tag_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_get_key_length: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_key_length;
  EVP_CIPHER_key_length: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_key_length;
  EVP_CIPHER_get_iv_length: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_iv_length;
  EVP_CIPHER_iv_length: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_iv_length;
  EVP_CIPHER_get_flags: function(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl = Load_EVP_CIPHER_get_flags;
  EVP_CIPHER_flags: function(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl = Load_EVP_CIPHER_flags;
  EVP_CIPHER_get_mode: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_mode;
  EVP_CIPHER_mode: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_mode;
  EVP_CIPHER_get_type: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_type;
  EVP_CIPHER_type: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_type;
  EVP_CIPHER_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_fetch;
  EVP_CIPHER_can_pipeline: function(cipher: PEVP_CIPHER; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_can_pipeline;
  EVP_CIPHER_up_ref: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_up_ref;
  EVP_CIPHER_free: procedure(cipher: PEVP_CIPHER); cdecl = Load_EVP_CIPHER_free;
  EVP_CIPHER_CTX_get0_cipher: function(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_CTX_get0_cipher;
  EVP_CIPHER_CTX_get1_cipher: function(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_CTX_get1_cipher;
  EVP_CIPHER_CTX_is_encrypting: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_is_encrypting;
  EVP_CIPHER_CTX_encrypting: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_encrypting;
  EVP_CIPHER_CTX_get_nid: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_nid;
  EVP_CIPHER_CTX_nid: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_nid;
  EVP_CIPHER_CTX_get_block_size: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_block_size;
  EVP_CIPHER_CTX_block_size: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_block_size;
  EVP_CIPHER_CTX_get_key_length: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_key_length;
  EVP_CIPHER_CTX_key_length: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_key_length;
  EVP_CIPHER_CTX_get_iv_length: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_iv_length;
  EVP_CIPHER_CTX_iv_length: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_iv_length;
  EVP_CIPHER_CTX_get_tag_length: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_tag_length;
  EVP_CIPHER_CTX_tag_length: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_tag_length;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_CTX_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_cipher';
  function EVP_CIPHER_CTX_iv(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_iv'; deprecated 'Since OpenSSL 3.0';
  function EVP_CIPHER_CTX_original_iv(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_original_iv'; deprecated 'Since OpenSSL 3.0';
  function EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_iv_noconst'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_CTX_cipher}
  {$EXTERNALSYM EVP_CIPHER_CTX_iv}
  {$EXTERNALSYM EVP_CIPHER_CTX_original_iv}
  {$EXTERNALSYM EVP_CIPHER_CTX_iv_noconst}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_CTX_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
  function Load_EVP_CIPHER_CTX_iv(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;
  function Load_EVP_CIPHER_CTX_original_iv(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;
  function Load_EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;

var
  EVP_CIPHER_CTX_cipher: function(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl = Load_EVP_CIPHER_CTX_cipher;
  EVP_CIPHER_CTX_iv: function(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl = Load_EVP_CIPHER_CTX_iv;
  EVP_CIPHER_CTX_original_iv: function(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl = Load_EVP_CIPHER_CTX_original_iv;
  EVP_CIPHER_CTX_iv_noconst: function(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl = Load_EVP_CIPHER_CTX_iv_noconst;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_CTX_get_updated_iv(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_updated_iv';
  function EVP_CIPHER_CTX_get_original_iv(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_original_iv';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_updated_iv}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_original_iv}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_CTX_get_updated_iv(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_original_iv(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

var
  EVP_CIPHER_CTX_get_updated_iv: function(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_updated_iv;
  EVP_CIPHER_CTX_get_original_iv: function(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_original_iv;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_buf_noconst'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_CIPHER_CTX_buf_noconst}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;

var
  EVP_CIPHER_CTX_buf_noconst: function(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl = Load_EVP_CIPHER_CTX_buf_noconst;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_CTX_get_num(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_num';
  function EVP_CIPHER_CTX_num(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_num';
  function EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_num';
  function EVP_CIPHER_CTX_dup(in_: PEVP_CIPHER_CTX): PEVP_CIPHER_CTX; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_dup';
  function EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_copy';
  function EVP_CIPHER_CTX_get_app_data(ctx: PEVP_CIPHER_CTX): pointer; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_app_data';
  procedure EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: pointer); cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_app_data';
  function EVP_CIPHER_CTX_get_cipher_data(ctx: PEVP_CIPHER_CTX): pointer; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_cipher_data';
  function EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: pointer): pointer; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_cipher_data';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_num}
  {$EXTERNALSYM EVP_CIPHER_CTX_num}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_num}
  {$EXTERNALSYM EVP_CIPHER_CTX_dup}
  {$EXTERNALSYM EVP_CIPHER_CTX_copy}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_app_data}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_app_data}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_cipher_data}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_cipher_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_CTX_get_num(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_num(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_dup(in_: PEVP_CIPHER_CTX): PEVP_CIPHER_CTX; cdecl;
  function Load_EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_app_data(ctx: PEVP_CIPHER_CTX): pointer; cdecl;
  procedure Load_EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: pointer); cdecl;
  function Load_EVP_CIPHER_CTX_get_cipher_data(ctx: PEVP_CIPHER_CTX): pointer; cdecl;
  function Load_EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: pointer): pointer; cdecl;

var
  EVP_CIPHER_CTX_get_num: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_num;
  EVP_CIPHER_CTX_num: function(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_num;
  EVP_CIPHER_CTX_set_num: function(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_set_num;
  EVP_CIPHER_CTX_dup: function(in_: PEVP_CIPHER_CTX): PEVP_CIPHER_CTX; cdecl = Load_EVP_CIPHER_CTX_dup;
  EVP_CIPHER_CTX_copy: function(out_: PEVP_CIPHER_CTX; in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_copy;
  EVP_CIPHER_CTX_get_app_data: function(ctx: PEVP_CIPHER_CTX): pointer; cdecl = Load_EVP_CIPHER_CTX_get_app_data;
  EVP_CIPHER_CTX_set_app_data: procedure(ctx: PEVP_CIPHER_CTX; data: pointer); cdecl = Load_EVP_CIPHER_CTX_set_app_data;
  EVP_CIPHER_CTX_get_cipher_data: function(ctx: PEVP_CIPHER_CTX): pointer; cdecl = Load_EVP_CIPHER_CTX_get_cipher_data;
  EVP_CIPHER_CTX_set_cipher_data: function(ctx: PEVP_CIPHER_CTX; cipher_data: pointer): pointer; cdecl = Load_EVP_CIPHER_CTX_set_cipher_data;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}


  function EVP_CIPHER_CTX_get0_name(c:PEVP_CIPHER_CTX): PAnsiChar; inline;
  function EVP_CIPHER_CTX_get_type(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT; inline;
  function EVP_CIPHER_CTX_type(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT; inline;
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


  function EVP_CIPHER_CTX_flags(c:PEVP_CIPHER_CTX): TOpenSSL_C_UINT; inline;
  {$endif}


  function EVP_CIPHER_CTX_get_mode(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT; inline;
  function EVP_CIPHER_CTX_mode(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT; inline;
  function EVP_ENCODE_LENGTH(l:int64): int64; inline;
  function EVP_DECODE_LENGTH(l:int64): int64; inline;
  function EVP_SignInit_ex(a:PEVP_MD_CTX; b:PEVP_MD; c:PENGINE): TOpenSSL_C_INT; inline;
  function EVP_SignInit(a:PEVP_MD_CTX; b:PEVP_MD): TOpenSSL_C_INT; inline;
  function EVP_SignUpdate(a:PEVP_MD_CTX; b:pointer; c:TOpenSSL_C_SIZET): TOpenSSL_C_INT; inline;
  function EVP_VerifyInit_ex(a:PEVP_MD_CTX; b:PEVP_MD; c:PENGINE): TOpenSSL_C_INT; inline;
  function EVP_VerifyInit(a:PEVP_MD_CTX; b:PEVP_MD): TOpenSSL_C_INT; inline;
  function EVP_VerifyUpdate(a:PEVP_MD_CTX; b:pointer; c:TOpenSSL_C_SIZET): TOpenSSL_C_INT; inline;
  function EVP_OpenUpdate(a:PEVP_CIPHER_CTX; b:Pbyte; c:POpenSSL_C_INT; d:Pbyte; e:TOpenSSL_C_INT): TOpenSSL_C_INT; inline;
  function EVP_SealUpdate(a:PEVP_CIPHER_CTX; b:Pbyte; c:POpenSSL_C_INT; d:Pbyte; e:TOpenSSL_C_INT): TOpenSSL_C_INT; inline;
  {$ifdef CONST_STRICT}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure BIO_set_md(_param1: PBIO; md: PEVP_MD); cdecl; external CLibCrypto name 'BIO_set_md';
    {$else}
  {$EXTERNALSYM BIO_set_md}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_BIO_set_md(_param1: PBIO; md: PEVP_MD); cdecl;

var
  BIO_set_md: procedure(_param1: PBIO; md: PEVP_MD); cdecl = Load_BIO_set_md;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$else}
{# define  BIO_set_md(b,md) BIO_ctrl(b, BIO_C_SET_MD, 0, (void *)(md))} {Macro Return Type unknown at line no 696}
  {$endif}
{# define  BIO_get_md(b,mdp) BIO_ctrl(b, BIO_C_GET_MD, 0, (mdp))} {Macro Return Type unknown at line no 698}
{# define  BIO_get_md_ctx(b,mdcp) BIO_ctrl(b, BIO_C_GET_MD_CTX, 0, (mdcp))} {Macro Return Type unknown at line no 699}
{# define  BIO_set_md_ctx(b,mdcp) BIO_ctrl(b, BIO_C_SET_MD_CTX, 0, (mdcp))} {Macro Return Type unknown at line no 700}
{# define  BIO_get_cipher_status(b) BIO_ctrl(b, BIO_C_GET_CIPHER_STATUS, 0, NULL)} {Macro Return Type unknown at line no 701}
{# define  BIO_get_cipher_ctx(b,c_pp) BIO_ctrl(b, BIO_C_GET_CIPHER_CTX, 0, (c_pp))} {Macro Return Type unknown at line no 702}
{# define  EVP_add_cipher_alias(n,alias) OBJ_NAME_add((alias), OBJ_NAME_TYPE_CIPHER_METH | OBJ_NAME_ALIAS, (n))} {Macro Return Type unknown at line no 708}
{# define  EVP_add_digest_alias(n,alias) OBJ_NAME_add((alias), OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS, (n))} {Macro Return Type unknown at line no 710}
{# define  EVP_delete_cipher_alias(alias) OBJ_NAME_remove(alias, OBJ_NAME_TYPE_CIPHER_METH | OBJ_NAME_ALIAS);}
{# define  EVP_delete_digest_alias(alias) OBJ_NAME_remove(alias, OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS);}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_get_params(digest: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_get_params';
  function EVP_MD_CTX_set_params(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_set_params';
  function EVP_MD_CTX_get_params(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_get_params';
  function EVP_MD_gettable_params(digest: PEVP_MD): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MD_gettable_params';
  function EVP_MD_settable_ctx_params(md: PEVP_MD): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MD_settable_ctx_params';
  function EVP_MD_gettable_ctx_params(md: PEVP_MD): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MD_gettable_ctx_params';
  function EVP_MD_CTX_settable_params(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MD_CTX_settable_params';
  function EVP_MD_CTX_gettable_params(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MD_CTX_gettable_params';
  function EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_ctrl';
  function EVP_MD_CTX_new: PEVP_MD_CTX; cdecl; external CLibCrypto name 'EVP_MD_CTX_new';
  function EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_reset';
  procedure EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl; external CLibCrypto name 'EVP_MD_CTX_free';
  {$else}
  {$EXTERNALSYM EVP_MD_get_params}
  {$EXTERNALSYM EVP_MD_CTX_set_params}
  {$EXTERNALSYM EVP_MD_CTX_get_params}
  {$EXTERNALSYM EVP_MD_gettable_params}
  {$EXTERNALSYM EVP_MD_settable_ctx_params}
  {$EXTERNALSYM EVP_MD_gettable_ctx_params}
  {$EXTERNALSYM EVP_MD_CTX_settable_params}
  {$EXTERNALSYM EVP_MD_CTX_gettable_params}
  {$EXTERNALSYM EVP_MD_CTX_ctrl}
  {$EXTERNALSYM EVP_MD_CTX_new}
  {$EXTERNALSYM EVP_MD_CTX_reset}
  {$EXTERNALSYM EVP_MD_CTX_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_get_params(digest: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_CTX_set_params(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_CTX_get_params(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_gettable_params(digest: PEVP_MD): POSSL_PARAM; cdecl;
  function Load_EVP_MD_settable_ctx_params(md: PEVP_MD): POSSL_PARAM; cdecl;
  function Load_EVP_MD_gettable_ctx_params(md: PEVP_MD): POSSL_PARAM; cdecl;
  function Load_EVP_MD_CTX_settable_params(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_MD_CTX_gettable_params(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_CTX_new: PEVP_MD_CTX; cdecl;
  function Load_EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;

var
  EVP_MD_get_params: function(digest: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MD_get_params;
  EVP_MD_CTX_set_params: function(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_set_params;
  EVP_MD_CTX_get_params: function(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_get_params;
  EVP_MD_gettable_params: function(digest: PEVP_MD): POSSL_PARAM; cdecl = Load_EVP_MD_gettable_params;
  EVP_MD_settable_ctx_params: function(md: PEVP_MD): POSSL_PARAM; cdecl = Load_EVP_MD_settable_ctx_params;
  EVP_MD_gettable_ctx_params: function(md: PEVP_MD): POSSL_PARAM; cdecl = Load_EVP_MD_gettable_ctx_params;
  EVP_MD_CTX_settable_params: function(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl = Load_EVP_MD_CTX_settable_params;
  EVP_MD_CTX_gettable_params: function(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl = Load_EVP_MD_CTX_gettable_params;
  EVP_MD_CTX_ctrl: function(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_ctrl;
  EVP_MD_CTX_new: function: PEVP_MD_CTX; cdecl = Load_EVP_MD_CTX_new;
  EVP_MD_CTX_reset: function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_reset;
  EVP_MD_CTX_free: procedure(ctx: PEVP_MD_CTX); cdecl = Load_EVP_MD_CTX_free;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}


  function EVP_MD_CTX_create(): PEVP_MD_CTX; inline;
  function EVP_MD_CTX_init(ctx:PEVP_MD_CTX): TOpenSSL_C_INT; inline;
  procedure EVP_MD_CTX_destroy(ctx:PEVP_MD_CTX); inline;
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MD_CTX_dup(in_: PEVP_MD_CTX): PEVP_MD_CTX; cdecl; external CLibCrypto name 'EVP_MD_CTX_dup';
  function EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_copy_ex';
  procedure EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EVP_MD_CTX_set_flags';
  procedure EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EVP_MD_CTX_clear_flags';
  function EVP_MD_CTX_test_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_test_flags';
  function EVP_DigestInit_ex2(ctx: PEVP_MD_CTX; type_: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestInit_ex2';
  function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestInit_ex';
  function EVP_DigestUpdate(ctx: PEVP_MD_CTX; d: pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestUpdate';
  function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestFinal_ex';
  function EVP_Digest(data: pointer; count: TOpenSSL_C_SIZET; md: Pbyte; size: POpenSSL_C_UINT; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_Digest';
  function EVP_Q_digest(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; data: pointer; datalen: TOpenSSL_C_SIZET; md: Pbyte; mdlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_Q_digest';
  function EVP_MD_CTX_copy(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_CTX_copy';
  function EVP_DigestInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestInit';
  function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestFinal';
  function EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestFinalXOF';
  function EVP_DigestSqueeze(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestSqueeze';
  function EVP_MD_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MD; cdecl; external CLibCrypto name 'EVP_MD_fetch';
  function EVP_MD_up_ref(md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MD_up_ref';
  procedure EVP_MD_free(md: PEVP_MD); cdecl; external CLibCrypto name 'EVP_MD_free';
  function EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_read_pw_string';
  function EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_read_pw_string_min';
  procedure EVP_set_pw_prompt(prompt: PAnsiChar); cdecl; external CLibCrypto name 'EVP_set_pw_prompt';
  function EVP_get_pw_prompt: PAnsiChar; cdecl; external CLibCrypto name 'EVP_get_pw_prompt';
  function EVP_BytesToKey(type_: PEVP_CIPHER; md: PEVP_MD; salt: Pbyte; data: Pbyte; datal: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_BytesToKey';
  procedure EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_flags';
  procedure EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_clear_flags';
  function EVP_CIPHER_CTX_test_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_test_flags';
  function EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncryptInit';
  function EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncryptInit_ex';
  function EVP_EncryptInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncryptInit_ex2';
  function EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncryptUpdate';
  function EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncryptFinal_ex';
  function EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncryptFinal';
  function EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecryptInit';
  function EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecryptInit_ex';
  function EVP_DecryptInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecryptInit_ex2';
  function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecryptUpdate';
  function EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecryptFinal';
  function EVP_DecryptFinal_ex(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecryptFinal_ex';
  function EVP_CipherInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherInit';
  function EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherInit_ex';
  function EVP_CipherInit_SKEY(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; skey: PEVP_SKEY; iv: Pbyte; iv_len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherInit_SKEY';
  function EVP_CipherInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherInit_ex2';
  function EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherUpdate';
  function EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherFinal';
  function EVP_CipherPipelineEncryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherPipelineEncryptInit';
  function EVP_CipherPipelineDecryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherPipelineDecryptInit';
  function EVP_CipherPipelineUpdate(ctx: PEVP_CIPHER_CTX; out_: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET; in_: PPbyte; inl: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherPipelineUpdate';
  function EVP_CipherPipelineFinal(ctx: PEVP_CIPHER_CTX; outm: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherPipelineFinal';
  function EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CipherFinal_ex';
  function EVP_SignFinal(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SignFinal';
  function EVP_SignFinal_ex(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SignFinal_ex';
  function EVP_DigestSign(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestSign';
  function EVP_VerifyFinal(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_VerifyFinal';
  function EVP_VerifyFinal_ex(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_VerifyFinal_ex';
  function EVP_DigestVerify(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestVerify';
  function EVP_DigestSignInit_ex(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestSignInit_ex';
  function EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestSignInit';
  function EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestSignUpdate';
  function EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestSignFinal';
  function EVP_DigestVerifyInit_ex(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestVerifyInit_ex';
  function EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestVerifyInit';
  function EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestVerifyUpdate';
  function EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DigestVerifyFinal';
  function EVP_OpenInit(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: Pbyte; ekl: TOpenSSL_C_INT; iv: Pbyte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_OpenInit';
  function EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_OpenFinal';
  function EVP_SealInit(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: PPbyte; ekl: POpenSSL_C_INT; iv: Pbyte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SealInit';
  function EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SealFinal';
  function EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl; external CLibCrypto name 'EVP_ENCODE_CTX_new';
  procedure EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto name 'EVP_ENCODE_CTX_free';
  function EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_ENCODE_CTX_copy';
  function EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_ENCODE_CTX_num';
  procedure EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto name 'EVP_EncodeInit';
  function EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncodeUpdate';
  procedure EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT); cdecl; external CLibCrypto name 'EVP_EncodeFinal';
  function EVP_EncodeBlock(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_EncodeBlock';
  procedure EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto name 'EVP_DecodeInit';
  function EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecodeUpdate';
  function EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecodeFinal';
  function EVP_DecodeBlock(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_DecodeBlock';
  {$else}
  {$EXTERNALSYM EVP_MD_CTX_dup}
  {$EXTERNALSYM EVP_MD_CTX_copy_ex}
  {$EXTERNALSYM EVP_MD_CTX_set_flags}
  {$EXTERNALSYM EVP_MD_CTX_clear_flags}
  {$EXTERNALSYM EVP_MD_CTX_test_flags}
  {$EXTERNALSYM EVP_DigestInit_ex2}
  {$EXTERNALSYM EVP_DigestInit_ex}
  {$EXTERNALSYM EVP_DigestUpdate}
  {$EXTERNALSYM EVP_DigestFinal_ex}
  {$EXTERNALSYM EVP_Digest}
  {$EXTERNALSYM EVP_Q_digest}
  {$EXTERNALSYM EVP_MD_CTX_copy}
  {$EXTERNALSYM EVP_DigestInit}
  {$EXTERNALSYM EVP_DigestFinal}
  {$EXTERNALSYM EVP_DigestFinalXOF}
  {$EXTERNALSYM EVP_DigestSqueeze}
  {$EXTERNALSYM EVP_MD_fetch}
  {$EXTERNALSYM EVP_MD_up_ref}
  {$EXTERNALSYM EVP_MD_free}
  {$EXTERNALSYM EVP_read_pw_string}
  {$EXTERNALSYM EVP_read_pw_string_min}
  {$EXTERNALSYM EVP_set_pw_prompt}
  {$EXTERNALSYM EVP_get_pw_prompt}
  {$EXTERNALSYM EVP_BytesToKey}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_flags}
  {$EXTERNALSYM EVP_CIPHER_CTX_clear_flags}
  {$EXTERNALSYM EVP_CIPHER_CTX_test_flags}
  {$EXTERNALSYM EVP_EncryptInit}
  {$EXTERNALSYM EVP_EncryptInit_ex}
  {$EXTERNALSYM EVP_EncryptInit_ex2}
  {$EXTERNALSYM EVP_EncryptUpdate}
  {$EXTERNALSYM EVP_EncryptFinal_ex}
  {$EXTERNALSYM EVP_EncryptFinal}
  {$EXTERNALSYM EVP_DecryptInit}
  {$EXTERNALSYM EVP_DecryptInit_ex}
  {$EXTERNALSYM EVP_DecryptInit_ex2}
  {$EXTERNALSYM EVP_DecryptUpdate}
  {$EXTERNALSYM EVP_DecryptFinal}
  {$EXTERNALSYM EVP_DecryptFinal_ex}
  {$EXTERNALSYM EVP_CipherInit}
  {$EXTERNALSYM EVP_CipherInit_ex}
  {$EXTERNALSYM EVP_CipherInit_SKEY}
  {$EXTERNALSYM EVP_CipherInit_ex2}
  {$EXTERNALSYM EVP_CipherUpdate}
  {$EXTERNALSYM EVP_CipherFinal}
  {$EXTERNALSYM EVP_CipherPipelineEncryptInit}
  {$EXTERNALSYM EVP_CipherPipelineDecryptInit}
  {$EXTERNALSYM EVP_CipherPipelineUpdate}
  {$EXTERNALSYM EVP_CipherPipelineFinal}
  {$EXTERNALSYM EVP_CipherFinal_ex}
  {$EXTERNALSYM EVP_SignFinal}
  {$EXTERNALSYM EVP_SignFinal_ex}
  {$EXTERNALSYM EVP_DigestSign}
  {$EXTERNALSYM EVP_VerifyFinal}
  {$EXTERNALSYM EVP_VerifyFinal_ex}
  {$EXTERNALSYM EVP_DigestVerify}
  {$EXTERNALSYM EVP_DigestSignInit_ex}
  {$EXTERNALSYM EVP_DigestSignInit}
  {$EXTERNALSYM EVP_DigestSignUpdate}
  {$EXTERNALSYM EVP_DigestSignFinal}
  {$EXTERNALSYM EVP_DigestVerifyInit_ex}
  {$EXTERNALSYM EVP_DigestVerifyInit}
  {$EXTERNALSYM EVP_DigestVerifyUpdate}
  {$EXTERNALSYM EVP_DigestVerifyFinal}
  {$EXTERNALSYM EVP_OpenInit}
  {$EXTERNALSYM EVP_OpenFinal}
  {$EXTERNALSYM EVP_SealInit}
  {$EXTERNALSYM EVP_SealFinal}
  {$EXTERNALSYM EVP_ENCODE_CTX_new}
  {$EXTERNALSYM EVP_ENCODE_CTX_free}
  {$EXTERNALSYM EVP_ENCODE_CTX_copy}
  {$EXTERNALSYM EVP_ENCODE_CTX_num}
  {$EXTERNALSYM EVP_EncodeInit}
  {$EXTERNALSYM EVP_EncodeUpdate}
  {$EXTERNALSYM EVP_EncodeFinal}
  {$EXTERNALSYM EVP_EncodeBlock}
  {$EXTERNALSYM EVP_DecodeInit}
  {$EXTERNALSYM EVP_DecodeUpdate}
  {$EXTERNALSYM EVP_DecodeFinal}
  {$EXTERNALSYM EVP_DecodeBlock}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MD_CTX_dup(in_: PEVP_MD_CTX): PEVP_MD_CTX; cdecl;
  function Load_EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
  procedure Load_EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
  function Load_EVP_MD_CTX_test_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestInit_ex2(ctx: PEVP_MD_CTX; type_: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestInit_ex(ctx: PEVP_MD_CTX; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestUpdate(ctx: PEVP_MD_CTX; d: pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_Digest(data: pointer; count: TOpenSSL_C_SIZET; md: Pbyte; size: POpenSSL_C_UINT; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_EVP_Q_digest(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; data: pointer; datalen: TOpenSSL_C_SIZET; md: Pbyte; mdlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_CTX_copy(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestFinal(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestSqueeze(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MD_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MD; cdecl;
  function Load_EVP_MD_up_ref(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_MD_free(md: PEVP_MD); cdecl;
  function Load_EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_set_pw_prompt(prompt: PAnsiChar); cdecl;
  function Load_EVP_get_pw_prompt: PAnsiChar; cdecl;
  function Load_EVP_BytesToKey(type_: PEVP_CIPHER; md: PEVP_MD; salt: Pbyte; data: Pbyte; datal: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
  procedure Load_EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
  function Load_EVP_CIPHER_CTX_test_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
  function Load_EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
  function Load_EVP_EncryptInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecryptInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecryptFinal_ex(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherInit_SKEY(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; skey: PEVP_SKEY; iv: Pbyte; iv_len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherPipelineEncryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherPipelineDecryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherPipelineUpdate(ctx: PEVP_CIPHER_CTX; out_: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET; in_: PPbyte; inl: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherPipelineFinal(ctx: PEVP_CIPHER_CTX; outm: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SignFinal(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SignFinal_ex(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestSign(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_VerifyFinal(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_VerifyFinal_ex(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestVerify(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestSignInit_ex(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestVerifyInit_ex(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_OpenInit(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: Pbyte; ekl: TOpenSSL_C_INT; iv: Pbyte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SealInit(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: PPbyte; ekl: POpenSSL_C_INT; iv: Pbyte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl;
  procedure Load_EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl;
  function Load_EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
  function Load_EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT); cdecl;
  function Load_EVP_EncodeBlock(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
  function Load_EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_DecodeBlock(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_MD_CTX_dup: function(in_: PEVP_MD_CTX): PEVP_MD_CTX; cdecl = Load_EVP_MD_CTX_dup;
  EVP_MD_CTX_copy_ex: function(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_copy_ex;
  EVP_MD_CTX_set_flags: procedure(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_MD_CTX_set_flags;
  EVP_MD_CTX_clear_flags: procedure(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_MD_CTX_clear_flags;
  EVP_MD_CTX_test_flags: function(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_test_flags;
  EVP_DigestInit_ex2: function(ctx: PEVP_MD_CTX; type_: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_DigestInit_ex2;
  EVP_DigestInit_ex: function(ctx: PEVP_MD_CTX; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = Load_EVP_DigestInit_ex;
  EVP_DigestUpdate: function(ctx: PEVP_MD_CTX; d: pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestUpdate;
  EVP_DigestFinal_ex: function(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EVP_DigestFinal_ex;
  EVP_Digest: function(data: pointer; count: TOpenSSL_C_SIZET; md: Pbyte; size: POpenSSL_C_UINT; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = Load_EVP_Digest;
  EVP_Q_digest: function(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; data: pointer; datalen: TOpenSSL_C_SIZET; md: Pbyte; mdlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_Q_digest;
  EVP_MD_CTX_copy: function(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_MD_CTX_copy;
  EVP_DigestInit: function(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_DigestInit;
  EVP_DigestFinal: function(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_EVP_DigestFinal;
  EVP_DigestFinalXOF: function(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestFinalXOF;
  EVP_DigestSqueeze: function(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSqueeze;
  EVP_MD_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MD; cdecl = Load_EVP_MD_fetch;
  EVP_MD_up_ref: function(md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_MD_up_ref;
  EVP_MD_free: procedure(md: PEVP_MD); cdecl = Load_EVP_MD_free;
  EVP_read_pw_string: function(buf: PAnsiChar; length: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_read_pw_string;
  EVP_read_pw_string_min: function(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_read_pw_string_min;
  EVP_set_pw_prompt: procedure(prompt: PAnsiChar); cdecl = Load_EVP_set_pw_prompt;
  EVP_get_pw_prompt: function: PAnsiChar; cdecl = Load_EVP_get_pw_prompt;
  EVP_BytesToKey: function(type_: PEVP_CIPHER; md: PEVP_MD; salt: Pbyte; data: Pbyte; datal: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl = Load_EVP_BytesToKey;
  EVP_CIPHER_CTX_set_flags: procedure(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_CIPHER_CTX_set_flags;
  EVP_CIPHER_CTX_clear_flags: procedure(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl = Load_EVP_CIPHER_CTX_clear_flags;
  EVP_CIPHER_CTX_test_flags: function(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_test_flags;
  EVP_EncryptInit: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptInit;
  EVP_EncryptInit_ex: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptInit_ex;
  EVP_EncryptInit_ex2: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptInit_ex2;
  EVP_EncryptUpdate: function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptUpdate;
  EVP_EncryptFinal_ex: function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptFinal_ex;
  EVP_EncryptFinal: function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncryptFinal;
  EVP_DecryptInit: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptInit;
  EVP_DecryptInit_ex: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptInit_ex;
  EVP_DecryptInit_ex2: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptInit_ex2;
  EVP_DecryptUpdate: function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptUpdate;
  EVP_DecryptFinal: function(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptFinal;
  EVP_DecryptFinal_ex: function(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecryptFinal_ex;
  EVP_CipherInit: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherInit;
  EVP_CipherInit_ex: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherInit_ex;
  EVP_CipherInit_SKEY: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; skey: PEVP_SKEY; iv: Pbyte; iv_len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_CipherInit_SKEY;
  EVP_CipherInit_ex2: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_CipherInit_ex2;
  EVP_CipherUpdate: function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherUpdate;
  EVP_CipherFinal: function(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherFinal;
  EVP_CipherPipelineEncryptInit: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_CipherPipelineEncryptInit;
  EVP_CipherPipelineDecryptInit: function(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_CipherPipelineDecryptInit;
  EVP_CipherPipelineUpdate: function(ctx: PEVP_CIPHER_CTX; out_: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET; in_: PPbyte; inl: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_CipherPipelineUpdate;
  EVP_CipherPipelineFinal: function(ctx: PEVP_CIPHER_CTX; outm: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_CipherPipelineFinal;
  EVP_CipherFinal_ex: function(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CipherFinal_ex;
  EVP_SignFinal: function(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_SignFinal;
  EVP_SignFinal_ex: function(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_SignFinal_ex;
  EVP_DigestSign: function(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSign;
  EVP_VerifyFinal: function(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_VerifyFinal;
  EVP_VerifyFinal_ex: function(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_VerifyFinal_ex;
  EVP_DigestVerify: function(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerify;
  EVP_DigestSignInit_ex: function(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSignInit_ex;
  EVP_DigestSignInit: function(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSignInit;
  EVP_DigestSignUpdate: function(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSignUpdate;
  EVP_DigestSignFinal: function(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestSignFinal;
  EVP_DigestVerifyInit_ex: function(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerifyInit_ex;
  EVP_DigestVerifyInit: function(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerifyInit;
  EVP_DigestVerifyUpdate: function(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerifyUpdate;
  EVP_DigestVerifyFinal: function(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_DigestVerifyFinal;
  EVP_OpenInit: function(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: Pbyte; ekl: TOpenSSL_C_INT; iv: Pbyte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_OpenInit;
  EVP_OpenFinal: function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_OpenFinal;
  EVP_SealInit: function(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: PPbyte; ekl: POpenSSL_C_INT; iv: Pbyte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_SealInit;
  EVP_SealFinal: function(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_SealFinal;
  EVP_ENCODE_CTX_new: function: PEVP_ENCODE_CTX; cdecl = Load_EVP_ENCODE_CTX_new;
  EVP_ENCODE_CTX_free: procedure(ctx: PEVP_ENCODE_CTX); cdecl = Load_EVP_ENCODE_CTX_free;
  EVP_ENCODE_CTX_copy: function(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_ENCODE_CTX_copy;
  EVP_ENCODE_CTX_num: function(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_ENCODE_CTX_num;
  EVP_EncodeInit: procedure(ctx: PEVP_ENCODE_CTX); cdecl = Load_EVP_EncodeInit;
  EVP_EncodeUpdate: function(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncodeUpdate;
  EVP_EncodeFinal: procedure(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT); cdecl = Load_EVP_EncodeFinal;
  EVP_EncodeBlock: function(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_EncodeBlock;
  EVP_DecodeInit: procedure(ctx: PEVP_ENCODE_CTX); cdecl = Load_EVP_DecodeInit;
  EVP_DecodeUpdate: function(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecodeUpdate;
  EVP_DecodeFinal: function(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecodeFinal;
  EVP_DecodeBlock: function(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_DecodeBlock;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


  function EVP_CIPHER_CTX_init(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT; inline;
  function EVP_CIPHER_CTX_cleanup(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT; inline;
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_new';
  function EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_reset';
  procedure EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_free';
  function EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_key_length';
  function EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_padding';
  function EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_ctrl';
  function EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_rand_key';
  function EVP_CIPHER_get_params(cipher: PEVP_CIPHER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_params';
  function EVP_CIPHER_CTX_set_params(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_params';
  function EVP_CIPHER_CTX_get_params(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_params';
  function EVP_CIPHER_gettable_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_CIPHER_gettable_params';
  function EVP_CIPHER_settable_ctx_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_CIPHER_settable_ctx_params';
  function EVP_CIPHER_gettable_ctx_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_CIPHER_gettable_ctx_params';
  function EVP_CIPHER_CTX_settable_params(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_settable_params';
  function EVP_CIPHER_CTX_gettable_params(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_gettable_params';
  function EVP_CIPHER_CTX_set_algor_params(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_set_algor_params';
  function EVP_CIPHER_CTX_get_algor_params(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_algor_params';
  function EVP_CIPHER_CTX_get_algor(ctx: PEVP_CIPHER_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_CTX_get_algor';
  function BIO_f_md: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_md';
  function BIO_f_base64: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_base64';
  function BIO_f_cipher: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_cipher';
  function BIO_f_reliable: PBIO_METHOD; cdecl; external CLibCrypto name 'BIO_f_reliable';
  function BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; k: Pbyte; i: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'BIO_set_cipher';
  function EVP_md_null: PEVP_MD; cdecl; external CLibCrypto name 'EVP_md_null';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_CTX_new}
  {$EXTERNALSYM EVP_CIPHER_CTX_reset}
  {$EXTERNALSYM EVP_CIPHER_CTX_free}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_key_length}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_padding}
  {$EXTERNALSYM EVP_CIPHER_CTX_ctrl}
  {$EXTERNALSYM EVP_CIPHER_CTX_rand_key}
  {$EXTERNALSYM EVP_CIPHER_get_params}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_params}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_params}
  {$EXTERNALSYM EVP_CIPHER_gettable_params}
  {$EXTERNALSYM EVP_CIPHER_settable_ctx_params}
  {$EXTERNALSYM EVP_CIPHER_gettable_ctx_params}
  {$EXTERNALSYM EVP_CIPHER_CTX_settable_params}
  {$EXTERNALSYM EVP_CIPHER_CTX_gettable_params}
  {$EXTERNALSYM EVP_CIPHER_CTX_set_algor_params}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_algor_params}
  {$EXTERNALSYM EVP_CIPHER_CTX_get_algor}
  {$EXTERNALSYM BIO_f_md}
  {$EXTERNALSYM BIO_f_base64}
  {$EXTERNALSYM BIO_f_cipher}
  {$EXTERNALSYM BIO_f_reliable}
  {$EXTERNALSYM BIO_set_cipher}
  {$EXTERNALSYM EVP_md_null}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl;
  function Load_EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl;
  function Load_EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: Pbyte): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_get_params(cipher: PEVP_CIPHER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_set_params(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_params(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_gettable_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl;
  function Load_EVP_CIPHER_settable_ctx_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl;
  function Load_EVP_CIPHER_gettable_ctx_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl;
  function Load_EVP_CIPHER_CTX_settable_params(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_CIPHER_CTX_gettable_params(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_CIPHER_CTX_set_algor_params(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_algor_params(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_CTX_get_algor(ctx: PEVP_CIPHER_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_BIO_f_md: PBIO_METHOD; cdecl;
  function Load_BIO_f_base64: PBIO_METHOD; cdecl;
  function Load_BIO_f_cipher: PBIO_METHOD; cdecl;
  function Load_BIO_f_reliable: PBIO_METHOD; cdecl;
  function Load_BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; k: Pbyte; i: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_md_null: PEVP_MD; cdecl;

var
  EVP_CIPHER_CTX_new: function: PEVP_CIPHER_CTX; cdecl = Load_EVP_CIPHER_CTX_new;
  EVP_CIPHER_CTX_reset: function(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_reset;
  EVP_CIPHER_CTX_free: procedure(c: PEVP_CIPHER_CTX); cdecl = Load_EVP_CIPHER_CTX_free;
  EVP_CIPHER_CTX_set_key_length: function(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_set_key_length;
  EVP_CIPHER_CTX_set_padding: function(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_set_padding;
  EVP_CIPHER_CTX_ctrl: function(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_ctrl;
  EVP_CIPHER_CTX_rand_key: function(ctx: PEVP_CIPHER_CTX; key: Pbyte): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_rand_key;
  EVP_CIPHER_get_params: function(cipher: PEVP_CIPHER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_params;
  EVP_CIPHER_CTX_set_params: function(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_set_params;
  EVP_CIPHER_CTX_get_params: function(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_params;
  EVP_CIPHER_gettable_params: function(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl = Load_EVP_CIPHER_gettable_params;
  EVP_CIPHER_settable_ctx_params: function(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl = Load_EVP_CIPHER_settable_ctx_params;
  EVP_CIPHER_gettable_ctx_params: function(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl = Load_EVP_CIPHER_gettable_ctx_params;
  EVP_CIPHER_CTX_settable_params: function(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl = Load_EVP_CIPHER_CTX_settable_params;
  EVP_CIPHER_CTX_gettable_params: function(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl = Load_EVP_CIPHER_CTX_gettable_params;
  EVP_CIPHER_CTX_set_algor_params: function(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_set_algor_params;
  EVP_CIPHER_CTX_get_algor_params: function(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_algor_params;
  EVP_CIPHER_CTX_get_algor: function(ctx: PEVP_CIPHER_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_CTX_get_algor;
  BIO_f_md: function: PBIO_METHOD; cdecl = Load_BIO_f_md;
  BIO_f_base64: function: PBIO_METHOD; cdecl = Load_BIO_f_base64;
  BIO_f_cipher: function: PBIO_METHOD; cdecl = Load_BIO_f_cipher;
  BIO_f_reliable: function: PBIO_METHOD; cdecl = Load_BIO_f_reliable;
  BIO_set_cipher: function(b: PBIO; c: PEVP_CIPHER; k: Pbyte; i: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_BIO_set_cipher;
  EVP_md_null: function: PEVP_MD; cdecl = Load_EVP_md_null;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_MD2}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_md2: PEVP_MD; cdecl; external CLibCrypto name 'EVP_md2';
    {$else}
  {$EXTERNALSYM EVP_md2}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_md2: PEVP_MD; cdecl;

var
  EVP_md2: function: PEVP_MD; cdecl = Load_EVP_md2;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_MD4}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_md4: PEVP_MD; cdecl; external CLibCrypto name 'EVP_md4';
    {$else}
  {$EXTERNALSYM EVP_md4}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_md4: PEVP_MD; cdecl;

var
  EVP_md4: function: PEVP_MD; cdecl = Load_EVP_md4;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_MD5}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_md5: PEVP_MD; cdecl; external CLibCrypto name 'EVP_md5';
  function EVP_md5_sha1: PEVP_MD; cdecl; external CLibCrypto name 'EVP_md5_sha1';
    {$else}
  {$EXTERNALSYM EVP_md5}
  {$EXTERNALSYM EVP_md5_sha1}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_md5: PEVP_MD; cdecl;
  function Load_EVP_md5_sha1: PEVP_MD; cdecl;

var
  EVP_md5: function: PEVP_MD; cdecl = Load_EVP_md5;
  EVP_md5_sha1: function: PEVP_MD; cdecl = Load_EVP_md5_sha1;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_BLAKE2}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_blake2b512: PEVP_MD; cdecl; external CLibCrypto name 'EVP_blake2b512';
  function EVP_blake2s256: PEVP_MD; cdecl; external CLibCrypto name 'EVP_blake2s256';
    {$else}
  {$EXTERNALSYM EVP_blake2b512}
  {$EXTERNALSYM EVP_blake2s256}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_blake2b512: PEVP_MD; cdecl;
  function Load_EVP_blake2s256: PEVP_MD; cdecl;

var
  EVP_blake2b512: function: PEVP_MD; cdecl = Load_EVP_blake2b512;
  EVP_blake2s256: function: PEVP_MD; cdecl = Load_EVP_blake2s256;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_sha1: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha1';
  function EVP_sha224: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha224';
  function EVP_sha256: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha256';
  function EVP_sha384: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha384';
  function EVP_sha512: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha512';
  function EVP_sha512_224: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha512_224';
  function EVP_sha512_256: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha512_256';
  function EVP_sha3_224: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha3_224';
  function EVP_sha3_256: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha3_256';
  function EVP_sha3_384: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha3_384';
  function EVP_sha3_512: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sha3_512';
  function EVP_shake128: PEVP_MD; cdecl; external CLibCrypto name 'EVP_shake128';
  function EVP_shake256: PEVP_MD; cdecl; external CLibCrypto name 'EVP_shake256';
  {$else}
  {$EXTERNALSYM EVP_sha1}
  {$EXTERNALSYM EVP_sha224}
  {$EXTERNALSYM EVP_sha256}
  {$EXTERNALSYM EVP_sha384}
  {$EXTERNALSYM EVP_sha512}
  {$EXTERNALSYM EVP_sha512_224}
  {$EXTERNALSYM EVP_sha512_256}
  {$EXTERNALSYM EVP_sha3_224}
  {$EXTERNALSYM EVP_sha3_256}
  {$EXTERNALSYM EVP_sha3_384}
  {$EXTERNALSYM EVP_sha3_512}
  {$EXTERNALSYM EVP_shake128}
  {$EXTERNALSYM EVP_shake256}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_sha1: PEVP_MD; cdecl;
  function Load_EVP_sha224: PEVP_MD; cdecl;
  function Load_EVP_sha256: PEVP_MD; cdecl;
  function Load_EVP_sha384: PEVP_MD; cdecl;
  function Load_EVP_sha512: PEVP_MD; cdecl;
  function Load_EVP_sha512_224: PEVP_MD; cdecl;
  function Load_EVP_sha512_256: PEVP_MD; cdecl;
  function Load_EVP_sha3_224: PEVP_MD; cdecl;
  function Load_EVP_sha3_256: PEVP_MD; cdecl;
  function Load_EVP_sha3_384: PEVP_MD; cdecl;
  function Load_EVP_sha3_512: PEVP_MD; cdecl;
  function Load_EVP_shake128: PEVP_MD; cdecl;
  function Load_EVP_shake256: PEVP_MD; cdecl;

var
  EVP_sha1: function: PEVP_MD; cdecl = Load_EVP_sha1;
  EVP_sha224: function: PEVP_MD; cdecl = Load_EVP_sha224;
  EVP_sha256: function: PEVP_MD; cdecl = Load_EVP_sha256;
  EVP_sha384: function: PEVP_MD; cdecl = Load_EVP_sha384;
  EVP_sha512: function: PEVP_MD; cdecl = Load_EVP_sha512;
  EVP_sha512_224: function: PEVP_MD; cdecl = Load_EVP_sha512_224;
  EVP_sha512_256: function: PEVP_MD; cdecl = Load_EVP_sha512_256;
  EVP_sha3_224: function: PEVP_MD; cdecl = Load_EVP_sha3_224;
  EVP_sha3_256: function: PEVP_MD; cdecl = Load_EVP_sha3_256;
  EVP_sha3_384: function: PEVP_MD; cdecl = Load_EVP_sha3_384;
  EVP_sha3_512: function: PEVP_MD; cdecl = Load_EVP_sha3_512;
  EVP_shake128: function: PEVP_MD; cdecl = Load_EVP_shake128;
  EVP_shake256: function: PEVP_MD; cdecl = Load_EVP_shake256;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_MDC2}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_mdc2: PEVP_MD; cdecl; external CLibCrypto name 'EVP_mdc2';
    {$else}
  {$EXTERNALSYM EVP_mdc2}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_mdc2: PEVP_MD; cdecl;

var
  EVP_mdc2: function: PEVP_MD; cdecl = Load_EVP_mdc2;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_RMD160}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_ripemd160: PEVP_MD; cdecl; external CLibCrypto name 'EVP_ripemd160';
    {$else}
  {$EXTERNALSYM EVP_ripemd160}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_ripemd160: PEVP_MD; cdecl;

var
  EVP_ripemd160: function: PEVP_MD; cdecl = Load_EVP_ripemd160;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_WHIRLPOOL}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_whirlpool: PEVP_MD; cdecl; external CLibCrypto name 'EVP_whirlpool';
    {$else}
  {$EXTERNALSYM EVP_whirlpool}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_whirlpool: PEVP_MD; cdecl;

var
  EVP_whirlpool: function: PEVP_MD; cdecl = Load_EVP_whirlpool;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_SM3}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_sm3: PEVP_MD; cdecl; external CLibCrypto name 'EVP_sm3';
    {$else}
  {$EXTERNALSYM EVP_sm3}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_sm3: PEVP_MD; cdecl;

var
  EVP_sm3: function: PEVP_MD; cdecl = Load_EVP_sm3;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_enc_null: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_enc_null';
  { does nothing :-) }
  {$else}
  {$EXTERNALSYM EVP_enc_null}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_enc_null: PEVP_CIPHER; cdecl;

var
  EVP_enc_null: function: PEVP_CIPHER; cdecl = Load_EVP_enc_null;
  { does nothing :-) }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DES}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_des_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ecb';
  function EVP_des_ede: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede';
  function EVP_des_ede3: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3';
  function EVP_des_ede_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede_ecb';
  function EVP_des_ede3_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_ecb';
  function EVP_des_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_cfb64';
  function EVP_des_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_cfb64';
  function EVP_des_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_cfb1';
  function EVP_des_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_cfb8';
  function EVP_des_ede_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede_cfb64';
  function EVP_des_ede_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede_cfb64';
  function EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_cfb64';
  function EVP_des_ede3_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_cfb64';
  function EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_cfb1';
  function EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_cfb8';
  function EVP_des_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ofb';
  function EVP_des_ede_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede_ofb';
  function EVP_des_ede3_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_ofb';
  function EVP_des_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_cbc';
  function EVP_des_ede_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede_cbc';
  function EVP_des_ede3_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_cbc';
  function EVP_desx_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_desx_cbc';
  function EVP_des_ede3_wrap: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_des_ede3_wrap';
  
  {* This should now be supported through the dev_crypto ENGINE. But also, why
  * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
  * branch?
  }
    {$else}
  {$EXTERNALSYM EVP_des_ecb}
  {$EXTERNALSYM EVP_des_ede}
  {$EXTERNALSYM EVP_des_ede3}
  {$EXTERNALSYM EVP_des_ede_ecb}
  {$EXTERNALSYM EVP_des_ede3_ecb}
  {$EXTERNALSYM EVP_des_cfb64}
  {$EXTERNALSYM EVP_des_cfb}
  {$EXTERNALSYM EVP_des_cfb1}
  {$EXTERNALSYM EVP_des_cfb8}
  {$EXTERNALSYM EVP_des_ede_cfb64}
  {$EXTERNALSYM EVP_des_ede_cfb}
  {$EXTERNALSYM EVP_des_ede3_cfb64}
  {$EXTERNALSYM EVP_des_ede3_cfb}
  {$EXTERNALSYM EVP_des_ede3_cfb1}
  {$EXTERNALSYM EVP_des_ede3_cfb8}
  {$EXTERNALSYM EVP_des_ofb}
  {$EXTERNALSYM EVP_des_ede_ofb}
  {$EXTERNALSYM EVP_des_ede3_ofb}
  {$EXTERNALSYM EVP_des_cbc}
  {$EXTERNALSYM EVP_des_ede_cbc}
  {$EXTERNALSYM EVP_des_ede3_cbc}
  {$EXTERNALSYM EVP_desx_cbc}
  {$EXTERNALSYM EVP_des_ede3_wrap}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_des_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_des_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_des_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_des_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_desx_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_des_ede3_wrap: PEVP_CIPHER; cdecl;

var
  EVP_des_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ecb;
  EVP_des_ede: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede;
  EVP_des_ede3: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3;
  EVP_des_ede_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede_ecb;
  EVP_des_ede3_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_ecb;
  EVP_des_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_des_cfb64;
  EVP_des_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_des_cfb;
  EVP_des_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_des_cfb1;
  EVP_des_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_des_cfb8;
  EVP_des_ede_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede_cfb64;
  EVP_des_ede_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede_cfb;
  EVP_des_ede3_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cfb64;
  EVP_des_ede3_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cfb;
  EVP_des_ede3_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cfb1;
  EVP_des_ede3_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cfb8;
  EVP_des_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ofb;
  EVP_des_ede_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede_ofb;
  EVP_des_ede3_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_ofb;
  EVP_des_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_des_cbc;
  EVP_des_ede_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede_cbc;
  EVP_des_ede3_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_cbc;
  EVP_desx_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_desx_cbc;
  EVP_des_ede3_wrap: function: PEVP_CIPHER; cdecl = Load_EVP_des_ede3_wrap;
  
  {* This should now be supported through the dev_crypto ENGINE. But also, why
  * are rc4 and md5 declarations made here inside a "NO_DES" precompiler
  * branch?
  }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_RC4}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_rc4: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc4';
  function EVP_rc4_40: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc4_40';
    {$else}
  {$EXTERNALSYM EVP_rc4}
  {$EXTERNALSYM EVP_rc4_40}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_rc4: PEVP_CIPHER; cdecl;
  function Load_EVP_rc4_40: PEVP_CIPHER; cdecl;

var
  EVP_rc4: function: PEVP_CIPHER; cdecl = Load_EVP_rc4;
  EVP_rc4_40: function: PEVP_CIPHER; cdecl = Load_EVP_rc4_40;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_MD5}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_rc4_hmac_md5: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc4_hmac_md5';
      {$else}
  {$EXTERNALSYM EVP_rc4_hmac_md5}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_rc4_hmac_md5: PEVP_CIPHER; cdecl;

var
  EVP_rc4_hmac_md5: function: PEVP_CIPHER; cdecl = Load_EVP_rc4_hmac_md5;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}
  {$ifndef  OPENSSL_NO_IDEA}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_idea_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_idea_ecb';
  function EVP_idea_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_idea_cfb64';
  function EVP_idea_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_idea_cfb64';
  function EVP_idea_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_idea_ofb';
  function EVP_idea_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_idea_cbc';
    {$else}
  {$EXTERNALSYM EVP_idea_ecb}
  {$EXTERNALSYM EVP_idea_cfb64}
  {$EXTERNALSYM EVP_idea_cfb}
  {$EXTERNALSYM EVP_idea_ofb}
  {$EXTERNALSYM EVP_idea_cbc}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_idea_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_idea_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_idea_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_idea_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_idea_cbc: PEVP_CIPHER; cdecl;

var
  EVP_idea_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_idea_ecb;
  EVP_idea_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_idea_cfb64;
  EVP_idea_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_idea_cfb;
  EVP_idea_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_idea_ofb;
  EVP_idea_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_idea_cbc;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_RC2}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_rc2_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc2_ecb';
  function EVP_rc2_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc2_cbc';
  function EVP_rc2_40_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc2_40_cbc';
  function EVP_rc2_64_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc2_64_cbc';
  function EVP_rc2_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc2_cfb64';
  function EVP_rc2_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc2_cfb64';
  function EVP_rc2_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc2_ofb';
    {$else}
  {$EXTERNALSYM EVP_rc2_ecb}
  {$EXTERNALSYM EVP_rc2_cbc}
  {$EXTERNALSYM EVP_rc2_40_cbc}
  {$EXTERNALSYM EVP_rc2_64_cbc}
  {$EXTERNALSYM EVP_rc2_cfb64}
  {$EXTERNALSYM EVP_rc2_cfb}
  {$EXTERNALSYM EVP_rc2_ofb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_rc2_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_rc2_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_rc2_40_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_rc2_64_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_rc2_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_rc2_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_rc2_ofb: PEVP_CIPHER; cdecl;

var
  EVP_rc2_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_rc2_ecb;
  EVP_rc2_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_rc2_cbc;
  EVP_rc2_40_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_rc2_40_cbc;
  EVP_rc2_64_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_rc2_64_cbc;
  EVP_rc2_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_rc2_cfb64;
  EVP_rc2_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_rc2_cfb;
  EVP_rc2_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_rc2_ofb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_BF}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_bf_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_bf_ecb';
  function EVP_bf_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_bf_cbc';
  function EVP_bf_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_bf_cfb64';
  function EVP_bf_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_bf_cfb64';
  function EVP_bf_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_bf_ofb';
    {$else}
  {$EXTERNALSYM EVP_bf_ecb}
  {$EXTERNALSYM EVP_bf_cbc}
  {$EXTERNALSYM EVP_bf_cfb64}
  {$EXTERNALSYM EVP_bf_cfb}
  {$EXTERNALSYM EVP_bf_ofb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_bf_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_bf_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_bf_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_bf_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_bf_ofb: PEVP_CIPHER; cdecl;

var
  EVP_bf_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_bf_ecb;
  EVP_bf_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_bf_cbc;
  EVP_bf_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_bf_cfb64;
  EVP_bf_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_bf_cfb;
  EVP_bf_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_bf_ofb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_CAST}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_cast5_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_cast5_ecb';
  function EVP_cast5_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_cast5_cbc';
  function EVP_cast5_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_cast5_cfb64';
  function EVP_cast5_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_cast5_cfb64';
  function EVP_cast5_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_cast5_ofb';
    {$else}
  {$EXTERNALSYM EVP_cast5_ecb}
  {$EXTERNALSYM EVP_cast5_cbc}
  {$EXTERNALSYM EVP_cast5_cfb64}
  {$EXTERNALSYM EVP_cast5_cfb}
  {$EXTERNALSYM EVP_cast5_ofb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_cast5_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_cast5_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_cast5_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_cast5_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_cast5_ofb: PEVP_CIPHER; cdecl;

var
  EVP_cast5_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_cast5_ecb;
  EVP_cast5_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_cast5_cbc;
  EVP_cast5_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_cast5_cfb64;
  EVP_cast5_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_cast5_cfb;
  EVP_cast5_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_cast5_ofb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_RC5}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_rc5_32_12_16_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc5_32_12_16_cbc';
  function EVP_rc5_32_12_16_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc5_32_12_16_ecb';
  function EVP_rc5_32_12_16_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc5_32_12_16_cfb64';
  function EVP_rc5_32_12_16_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc5_32_12_16_cfb64';
  function EVP_rc5_32_12_16_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_rc5_32_12_16_ofb';
    {$else}
  {$EXTERNALSYM EVP_rc5_32_12_16_cbc}
  {$EXTERNALSYM EVP_rc5_32_12_16_ecb}
  {$EXTERNALSYM EVP_rc5_32_12_16_cfb64}
  {$EXTERNALSYM EVP_rc5_32_12_16_cfb}
  {$EXTERNALSYM EVP_rc5_32_12_16_ofb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_rc5_32_12_16_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_rc5_32_12_16_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_rc5_32_12_16_cfb64: PEVP_CIPHER; cdecl;
  function Load_EVP_rc5_32_12_16_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_rc5_32_12_16_ofb: PEVP_CIPHER; cdecl;

var
  EVP_rc5_32_12_16_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_rc5_32_12_16_cbc;
  EVP_rc5_32_12_16_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_rc5_32_12_16_ecb;
  EVP_rc5_32_12_16_cfb64: function: PEVP_CIPHER; cdecl = Load_EVP_rc5_32_12_16_cfb64;
  EVP_rc5_32_12_16_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_rc5_32_12_16_cfb;
  EVP_rc5_32_12_16_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_rc5_32_12_16_ofb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aes_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_ecb';
  function EVP_aes_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_cbc';
  function EVP_aes_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_cfb1';
  function EVP_aes_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_cfb8';
  function EVP_aes_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_cfb128';
  function EVP_aes_128_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_cfb128';
  function EVP_aes_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_ofb';
  function EVP_aes_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_ctr';
  function EVP_aes_128_ccm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_ccm';
  function EVP_aes_128_gcm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_gcm';
  function EVP_aes_128_xts: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_xts';
  function EVP_aes_128_wrap: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_wrap';
  function EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_wrap_pad';
  {$else}
  {$EXTERNALSYM EVP_aes_128_ecb}
  {$EXTERNALSYM EVP_aes_128_cbc}
  {$EXTERNALSYM EVP_aes_128_cfb1}
  {$EXTERNALSYM EVP_aes_128_cfb8}
  {$EXTERNALSYM EVP_aes_128_cfb128}
  {$EXTERNALSYM EVP_aes_128_cfb}
  {$EXTERNALSYM EVP_aes_128_ofb}
  {$EXTERNALSYM EVP_aes_128_ctr}
  {$EXTERNALSYM EVP_aes_128_ccm}
  {$EXTERNALSYM EVP_aes_128_gcm}
  {$EXTERNALSYM EVP_aes_128_xts}
  {$EXTERNALSYM EVP_aes_128_wrap}
  {$EXTERNALSYM EVP_aes_128_wrap_pad}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aes_128_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_ccm: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_gcm: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_xts: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_wrap: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl;

var
  EVP_aes_128_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_ecb;
  EVP_aes_128_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_cbc;
  EVP_aes_128_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_cfb1;
  EVP_aes_128_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_cfb8;
  EVP_aes_128_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_cfb128;
  EVP_aes_128_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_cfb;
  EVP_aes_128_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_ofb;
  EVP_aes_128_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_ctr;
  EVP_aes_128_ccm: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_ccm;
  EVP_aes_128_gcm: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_gcm;
  EVP_aes_128_xts: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_xts;
  EVP_aes_128_wrap: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_wrap;
  EVP_aes_128_wrap_pad: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_wrap_pad;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_OCB}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aes_128_ocb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_ocb';
    {$else}
  {$EXTERNALSYM EVP_aes_128_ocb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aes_128_ocb: PEVP_CIPHER; cdecl;

var
  EVP_aes_128_ocb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_ocb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aes_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_ecb';
  function EVP_aes_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_cbc';
  function EVP_aes_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_cfb1';
  function EVP_aes_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_cfb8';
  function EVP_aes_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_cfb128';
  function EVP_aes_192_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_cfb128';
  function EVP_aes_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_ofb';
  function EVP_aes_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_ctr';
  function EVP_aes_192_ccm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_ccm';
  function EVP_aes_192_gcm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_gcm';
  function EVP_aes_192_wrap: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_wrap';
  function EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_wrap_pad';
  {$else}
  {$EXTERNALSYM EVP_aes_192_ecb}
  {$EXTERNALSYM EVP_aes_192_cbc}
  {$EXTERNALSYM EVP_aes_192_cfb1}
  {$EXTERNALSYM EVP_aes_192_cfb8}
  {$EXTERNALSYM EVP_aes_192_cfb128}
  {$EXTERNALSYM EVP_aes_192_cfb}
  {$EXTERNALSYM EVP_aes_192_ofb}
  {$EXTERNALSYM EVP_aes_192_ctr}
  {$EXTERNALSYM EVP_aes_192_ccm}
  {$EXTERNALSYM EVP_aes_192_gcm}
  {$EXTERNALSYM EVP_aes_192_wrap}
  {$EXTERNALSYM EVP_aes_192_wrap_pad}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aes_192_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_ccm: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_gcm: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_wrap: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl;

var
  EVP_aes_192_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_ecb;
  EVP_aes_192_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_cbc;
  EVP_aes_192_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_cfb1;
  EVP_aes_192_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_cfb8;
  EVP_aes_192_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_cfb128;
  EVP_aes_192_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_cfb;
  EVP_aes_192_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_ofb;
  EVP_aes_192_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_ctr;
  EVP_aes_192_ccm: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_ccm;
  EVP_aes_192_gcm: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_gcm;
  EVP_aes_192_wrap: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_wrap;
  EVP_aes_192_wrap_pad: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_wrap_pad;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_OCB}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aes_192_ocb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_192_ocb';
    {$else}
  {$EXTERNALSYM EVP_aes_192_ocb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aes_192_ocb: PEVP_CIPHER; cdecl;

var
  EVP_aes_192_ocb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_192_ocb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aes_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_ecb';
  function EVP_aes_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_cbc';
  function EVP_aes_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_cfb1';
  function EVP_aes_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_cfb8';
  function EVP_aes_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_cfb128';
  function EVP_aes_256_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_cfb128';
  function EVP_aes_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_ofb';
  function EVP_aes_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_ctr';
  function EVP_aes_256_ccm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_ccm';
  function EVP_aes_256_gcm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_gcm';
  function EVP_aes_256_xts: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_xts';
  function EVP_aes_256_wrap: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_wrap';
  function EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_wrap_pad';
  {$else}
  {$EXTERNALSYM EVP_aes_256_ecb}
  {$EXTERNALSYM EVP_aes_256_cbc}
  {$EXTERNALSYM EVP_aes_256_cfb1}
  {$EXTERNALSYM EVP_aes_256_cfb8}
  {$EXTERNALSYM EVP_aes_256_cfb128}
  {$EXTERNALSYM EVP_aes_256_cfb}
  {$EXTERNALSYM EVP_aes_256_ofb}
  {$EXTERNALSYM EVP_aes_256_ctr}
  {$EXTERNALSYM EVP_aes_256_ccm}
  {$EXTERNALSYM EVP_aes_256_gcm}
  {$EXTERNALSYM EVP_aes_256_xts}
  {$EXTERNALSYM EVP_aes_256_wrap}
  {$EXTERNALSYM EVP_aes_256_wrap_pad}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aes_256_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_ccm: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_gcm: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_xts: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_wrap: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl;

var
  EVP_aes_256_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_ecb;
  EVP_aes_256_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_cbc;
  EVP_aes_256_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_cfb1;
  EVP_aes_256_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_cfb8;
  EVP_aes_256_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_cfb128;
  EVP_aes_256_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_cfb;
  EVP_aes_256_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_ofb;
  EVP_aes_256_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_ctr;
  EVP_aes_256_ccm: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_ccm;
  EVP_aes_256_gcm: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_gcm;
  EVP_aes_256_xts: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_xts;
  EVP_aes_256_wrap: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_wrap;
  EVP_aes_256_wrap_pad: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_wrap_pad;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_OCB}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aes_256_ocb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_ocb';
    {$else}
  {$EXTERNALSYM EVP_aes_256_ocb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aes_256_ocb: PEVP_CIPHER; cdecl;

var
  EVP_aes_256_ocb: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_ocb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_cbc_hmac_sha1';
  function EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_cbc_hmac_sha1';
  function EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_128_cbc_hmac_sha256';
  function EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aes_256_cbc_hmac_sha256';
  {$else}
  {$EXTERNALSYM EVP_aes_128_cbc_hmac_sha1}
  {$EXTERNALSYM EVP_aes_256_cbc_hmac_sha1}
  {$EXTERNALSYM EVP_aes_128_cbc_hmac_sha256}
  {$EXTERNALSYM EVP_aes_256_cbc_hmac_sha256}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
  function Load_EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl;

var
  EVP_aes_128_cbc_hmac_sha1: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_cbc_hmac_sha1;
  EVP_aes_256_cbc_hmac_sha1: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_cbc_hmac_sha1;
  EVP_aes_128_cbc_hmac_sha256: function: PEVP_CIPHER; cdecl = Load_EVP_aes_128_cbc_hmac_sha256;
  EVP_aes_256_cbc_hmac_sha256: function: PEVP_CIPHER; cdecl = Load_EVP_aes_256_cbc_hmac_sha256;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_ARIA}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_aria_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_ecb';
  function EVP_aria_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_cbc';
  function EVP_aria_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_cfb1';
  function EVP_aria_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_cfb8';
  function EVP_aria_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_cfb128';
  function EVP_aria_128_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_cfb128';
  function EVP_aria_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_ctr';
  function EVP_aria_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_ofb';
  function EVP_aria_128_gcm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_gcm';
  function EVP_aria_128_ccm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_128_ccm';
  function EVP_aria_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_ecb';
  function EVP_aria_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_cbc';
  function EVP_aria_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_cfb1';
  function EVP_aria_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_cfb8';
  function EVP_aria_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_cfb128';
  function EVP_aria_192_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_cfb128';
  function EVP_aria_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_ctr';
  function EVP_aria_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_ofb';
  function EVP_aria_192_gcm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_gcm';
  function EVP_aria_192_ccm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_192_ccm';
  function EVP_aria_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_ecb';
  function EVP_aria_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_cbc';
  function EVP_aria_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_cfb1';
  function EVP_aria_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_cfb8';
  function EVP_aria_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_cfb128';
  function EVP_aria_256_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_cfb128';
  function EVP_aria_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_ctr';
  function EVP_aria_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_ofb';
  function EVP_aria_256_gcm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_gcm';
  function EVP_aria_256_ccm: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_aria_256_ccm';
    {$else}
  {$EXTERNALSYM EVP_aria_128_ecb}
  {$EXTERNALSYM EVP_aria_128_cbc}
  {$EXTERNALSYM EVP_aria_128_cfb1}
  {$EXTERNALSYM EVP_aria_128_cfb8}
  {$EXTERNALSYM EVP_aria_128_cfb128}
  {$EXTERNALSYM EVP_aria_128_cfb}
  {$EXTERNALSYM EVP_aria_128_ctr}
  {$EXTERNALSYM EVP_aria_128_ofb}
  {$EXTERNALSYM EVP_aria_128_gcm}
  {$EXTERNALSYM EVP_aria_128_ccm}
  {$EXTERNALSYM EVP_aria_192_ecb}
  {$EXTERNALSYM EVP_aria_192_cbc}
  {$EXTERNALSYM EVP_aria_192_cfb1}
  {$EXTERNALSYM EVP_aria_192_cfb8}
  {$EXTERNALSYM EVP_aria_192_cfb128}
  {$EXTERNALSYM EVP_aria_192_cfb}
  {$EXTERNALSYM EVP_aria_192_ctr}
  {$EXTERNALSYM EVP_aria_192_ofb}
  {$EXTERNALSYM EVP_aria_192_gcm}
  {$EXTERNALSYM EVP_aria_192_ccm}
  {$EXTERNALSYM EVP_aria_256_ecb}
  {$EXTERNALSYM EVP_aria_256_cbc}
  {$EXTERNALSYM EVP_aria_256_cfb1}
  {$EXTERNALSYM EVP_aria_256_cfb8}
  {$EXTERNALSYM EVP_aria_256_cfb128}
  {$EXTERNALSYM EVP_aria_256_cfb}
  {$EXTERNALSYM EVP_aria_256_ctr}
  {$EXTERNALSYM EVP_aria_256_ofb}
  {$EXTERNALSYM EVP_aria_256_gcm}
  {$EXTERNALSYM EVP_aria_256_ccm}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_aria_128_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_gcm: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_128_ccm: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_gcm: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_192_ccm: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_gcm: PEVP_CIPHER; cdecl;
  function Load_EVP_aria_256_ccm: PEVP_CIPHER; cdecl;

var
  EVP_aria_128_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_ecb;
  EVP_aria_128_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_cbc;
  EVP_aria_128_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_cfb1;
  EVP_aria_128_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_cfb8;
  EVP_aria_128_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_cfb128;
  EVP_aria_128_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_cfb;
  EVP_aria_128_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_ctr;
  EVP_aria_128_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_ofb;
  EVP_aria_128_gcm: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_gcm;
  EVP_aria_128_ccm: function: PEVP_CIPHER; cdecl = Load_EVP_aria_128_ccm;
  EVP_aria_192_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_ecb;
  EVP_aria_192_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_cbc;
  EVP_aria_192_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_cfb1;
  EVP_aria_192_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_cfb8;
  EVP_aria_192_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_cfb128;
  EVP_aria_192_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_cfb;
  EVP_aria_192_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_ctr;
  EVP_aria_192_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_ofb;
  EVP_aria_192_gcm: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_gcm;
  EVP_aria_192_ccm: function: PEVP_CIPHER; cdecl = Load_EVP_aria_192_ccm;
  EVP_aria_256_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_ecb;
  EVP_aria_256_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_cbc;
  EVP_aria_256_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_cfb1;
  EVP_aria_256_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_cfb8;
  EVP_aria_256_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_cfb128;
  EVP_aria_256_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_cfb;
  EVP_aria_256_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_ctr;
  EVP_aria_256_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_ofb;
  EVP_aria_256_gcm: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_gcm;
  EVP_aria_256_ccm: function: PEVP_CIPHER; cdecl = Load_EVP_aria_256_ccm;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_CAMELLIA}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_camellia_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_ecb';
  function EVP_camellia_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_cbc';
  function EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_cfb1';
  function EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_cfb8';
  function EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_cfb128';
  function EVP_camellia_128_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_cfb128';
  function EVP_camellia_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_ofb';
  function EVP_camellia_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_128_ctr';
  function EVP_camellia_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_ecb';
  function EVP_camellia_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_cbc';
  function EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_cfb1';
  function EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_cfb8';
  function EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_cfb128';
  function EVP_camellia_192_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_cfb128';
  function EVP_camellia_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_ofb';
  function EVP_camellia_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_192_ctr';
  function EVP_camellia_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_ecb';
  function EVP_camellia_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_cbc';
  function EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_cfb1';
  function EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_cfb8';
  function EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_cfb128';
  function EVP_camellia_256_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_cfb128';
  function EVP_camellia_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_ofb';
  function EVP_camellia_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_camellia_256_ctr';
    {$else}
  {$EXTERNALSYM EVP_camellia_128_ecb}
  {$EXTERNALSYM EVP_camellia_128_cbc}
  {$EXTERNALSYM EVP_camellia_128_cfb1}
  {$EXTERNALSYM EVP_camellia_128_cfb8}
  {$EXTERNALSYM EVP_camellia_128_cfb128}
  {$EXTERNALSYM EVP_camellia_128_cfb}
  {$EXTERNALSYM EVP_camellia_128_ofb}
  {$EXTERNALSYM EVP_camellia_128_ctr}
  {$EXTERNALSYM EVP_camellia_192_ecb}
  {$EXTERNALSYM EVP_camellia_192_cbc}
  {$EXTERNALSYM EVP_camellia_192_cfb1}
  {$EXTERNALSYM EVP_camellia_192_cfb8}
  {$EXTERNALSYM EVP_camellia_192_cfb128}
  {$EXTERNALSYM EVP_camellia_192_cfb}
  {$EXTERNALSYM EVP_camellia_192_ofb}
  {$EXTERNALSYM EVP_camellia_192_ctr}
  {$EXTERNALSYM EVP_camellia_256_ecb}
  {$EXTERNALSYM EVP_camellia_256_cbc}
  {$EXTERNALSYM EVP_camellia_256_cfb1}
  {$EXTERNALSYM EVP_camellia_256_cfb8}
  {$EXTERNALSYM EVP_camellia_256_cfb128}
  {$EXTERNALSYM EVP_camellia_256_cfb}
  {$EXTERNALSYM EVP_camellia_256_ofb}
  {$EXTERNALSYM EVP_camellia_256_ctr}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_camellia_128_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_128_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_128_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_128_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_128_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_192_ctr: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_camellia_256_ctr: PEVP_CIPHER; cdecl;

var
  EVP_camellia_128_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_ecb;
  EVP_camellia_128_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cbc;
  EVP_camellia_128_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cfb1;
  EVP_camellia_128_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cfb8;
  EVP_camellia_128_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cfb128;
  EVP_camellia_128_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_cfb;
  EVP_camellia_128_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_ofb;
  EVP_camellia_128_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_128_ctr;
  EVP_camellia_192_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_ecb;
  EVP_camellia_192_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cbc;
  EVP_camellia_192_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cfb1;
  EVP_camellia_192_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cfb8;
  EVP_camellia_192_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cfb128;
  EVP_camellia_192_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_cfb;
  EVP_camellia_192_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_ofb;
  EVP_camellia_192_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_192_ctr;
  EVP_camellia_256_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_ecb;
  EVP_camellia_256_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cbc;
  EVP_camellia_256_cfb1: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cfb1;
  EVP_camellia_256_cfb8: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cfb8;
  EVP_camellia_256_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cfb128;
  EVP_camellia_256_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_cfb;
  EVP_camellia_256_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_ofb;
  EVP_camellia_256_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_camellia_256_ctr;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_CHACHA}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_chacha20: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_chacha20';
    {$else}
  {$EXTERNALSYM EVP_chacha20}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_chacha20: PEVP_CIPHER; cdecl;

var
  EVP_chacha20: function: PEVP_CIPHER; cdecl = Load_EVP_chacha20;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_POLY1305}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_chacha20_poly1305: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_chacha20_poly1305';
      {$else}
  {$EXTERNALSYM EVP_chacha20_poly1305}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_chacha20_poly1305: PEVP_CIPHER; cdecl;

var
  EVP_chacha20_poly1305: function: PEVP_CIPHER; cdecl = Load_EVP_chacha20_poly1305;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}
  {$ifndef  OPENSSL_NO_SEED}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_seed_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_seed_ecb';
  function EVP_seed_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_seed_cbc';
  function EVP_seed_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_seed_cfb128';
  function EVP_seed_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_seed_cfb128';
  function EVP_seed_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_seed_ofb';
    {$else}
  {$EXTERNALSYM EVP_seed_ecb}
  {$EXTERNALSYM EVP_seed_cbc}
  {$EXTERNALSYM EVP_seed_cfb128}
  {$EXTERNALSYM EVP_seed_cfb}
  {$EXTERNALSYM EVP_seed_ofb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_seed_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_seed_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_seed_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_seed_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_seed_ofb: PEVP_CIPHER; cdecl;

var
  EVP_seed_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_seed_ecb;
  EVP_seed_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_seed_cbc;
  EVP_seed_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_seed_cfb128;
  EVP_seed_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_seed_cfb;
  EVP_seed_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_seed_ofb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_SM4}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_sm4_ecb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_sm4_ecb';
  function EVP_sm4_cbc: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_sm4_cbc';
  function EVP_sm4_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_sm4_cfb128';
  function EVP_sm4_cfb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_sm4_cfb128';
  function EVP_sm4_ofb: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_sm4_ofb';
  function EVP_sm4_ctr: PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_sm4_ctr';
    {$else}
  {$EXTERNALSYM EVP_sm4_ecb}
  {$EXTERNALSYM EVP_sm4_cbc}
  {$EXTERNALSYM EVP_sm4_cfb128}
  {$EXTERNALSYM EVP_sm4_cfb}
  {$EXTERNALSYM EVP_sm4_ofb}
  {$EXTERNALSYM EVP_sm4_ctr}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_sm4_ecb: PEVP_CIPHER; cdecl;
  function Load_EVP_sm4_cbc: PEVP_CIPHER; cdecl;
  function Load_EVP_sm4_cfb128: PEVP_CIPHER; cdecl;
  function Load_EVP_sm4_cfb: PEVP_CIPHER; cdecl;
  function Load_EVP_sm4_ofb: PEVP_CIPHER; cdecl;
  function Load_EVP_sm4_ctr: PEVP_CIPHER; cdecl;

var
  EVP_sm4_ecb: function: PEVP_CIPHER; cdecl = Load_EVP_sm4_ecb;
  EVP_sm4_cbc: function: PEVP_CIPHER; cdecl = Load_EVP_sm4_cbc;
  EVP_sm4_cfb128: function: PEVP_CIPHER; cdecl = Load_EVP_sm4_cfb128;
  EVP_sm4_cfb: function: PEVP_CIPHER; cdecl = Load_EVP_sm4_cfb;
  EVP_sm4_ofb: function: PEVP_CIPHER; cdecl = Load_EVP_sm4_ofb;
  EVP_sm4_ctr: function: PEVP_CIPHER; cdecl = Load_EVP_sm4_ctr;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


  function OPENSSL_add_all_algorithms_conf(): TOpenSSL_C_INT; inline;
  function OPENSSL_add_all_algorithms_noconf(): TOpenSSL_C_INT; inline;
    {$ifdef OPENSSL_LOAD_CONF}


  function OpenSSL_add_all_algorithms(): TOpenSSL_C_INT; inline;
    {$else}


  function OpenSSL_add_all_algorithms(): TOpenSSL_C_INT; inline;
    {$endif}


  function OpenSSL_add_all_ciphers(): TOpenSSL_C_INT; inline;
  function OpenSSL_add_all_digests(): TOpenSSL_C_INT; inline;
  {# define  EVP_cleanup() while (0) continue}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_add_cipher(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_add_cipher';
  function EVP_add_digest(digest: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_add_digest';
  function EVP_get_cipherbyname(name: PAnsiChar): PEVP_CIPHER; cdecl; external CLibCrypto name 'EVP_get_cipherbyname';
  function EVP_get_digestbyname(name: PAnsiChar): PEVP_MD; cdecl; external CLibCrypto name 'EVP_get_digestbyname';
  {$else}
  {$EXTERNALSYM EVP_add_cipher}
  {$EXTERNALSYM EVP_add_digest}
  {$EXTERNALSYM EVP_get_cipherbyname}
  {$EXTERNALSYM EVP_get_digestbyname}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_add_cipher(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_add_digest(digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_get_cipherbyname(name: PAnsiChar): PEVP_CIPHER; cdecl;
  function Load_EVP_get_digestbyname(name: PAnsiChar): PEVP_MD; cdecl;

var
  EVP_add_cipher: function(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_add_cipher;
  EVP_add_digest: function(digest: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_add_digest;
  EVP_get_cipherbyname: function(name: PAnsiChar): PEVP_CIPHER; cdecl = Load_EVP_get_cipherbyname;
  EVP_get_digestbyname: function(name: PAnsiChar): PEVP_MD; cdecl = Load_EVP_get_digestbyname;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType028 = ^TFuncType028;
  PPFuncType028 = ^PFuncType028;
  {end of auto-generated forward references}

  TFuncType028 = procedure(ciph: PEVP_CIPHER; from_: PAnsiChar; to_: PAnsiChar; x: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_CIPHER_do_all(fn: TFuncType028; arg: pointer); cdecl; external CLibCrypto name 'EVP_CIPHER_do_all';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_do_all}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_CIPHER_do_all(fn: TFuncType028; arg: pointer); cdecl;

var
  EVP_CIPHER_do_all: procedure(fn: TFuncType028; arg: pointer); cdecl = Load_EVP_CIPHER_do_all;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType029 = ^TFuncType029;
  PPFuncType029 = ^PFuncType029;
  {end of auto-generated forward references}

  TFuncType029 = procedure(ciph: PEVP_CIPHER; from_: PAnsiChar; to_: PAnsiChar; x: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_CIPHER_do_all_sorted(fn: TFuncType029; arg: pointer); cdecl; external CLibCrypto name 'EVP_CIPHER_do_all_sorted';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_do_all_sorted}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_CIPHER_do_all_sorted(fn: TFuncType029; arg: pointer); cdecl;

var
  EVP_CIPHER_do_all_sorted: procedure(fn: TFuncType029; arg: pointer); cdecl = Load_EVP_CIPHER_do_all_sorted;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType030 = ^TFuncType030;
  PPFuncType030 = ^PFuncType030;
  {end of auto-generated forward references}

  TFuncType030 = procedure(cipher: PEVP_CIPHER; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_CIPHER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType030; arg: pointer); cdecl; external CLibCrypto name 'EVP_CIPHER_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_CIPHER_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_CIPHER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType030; arg: pointer); cdecl;

var
  EVP_CIPHER_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType030; arg: pointer); cdecl = Load_EVP_CIPHER_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType031 = ^TFuncType031;
  PPFuncType031 = ^PFuncType031;
  {end of auto-generated forward references}

  TFuncType031 = procedure(ciph: PEVP_MD; from_: PAnsiChar; to_: PAnsiChar; x: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_MD_do_all(fn: TFuncType031; arg: pointer); cdecl; external CLibCrypto name 'EVP_MD_do_all';
  {$else}
  {$EXTERNALSYM EVP_MD_do_all}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_MD_do_all(fn: TFuncType031; arg: pointer); cdecl;

var
  EVP_MD_do_all: procedure(fn: TFuncType031; arg: pointer); cdecl = Load_EVP_MD_do_all;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType032 = ^TFuncType032;
  PPFuncType032 = ^PFuncType032;
  {end of auto-generated forward references}

  TFuncType032 = procedure(ciph: PEVP_MD; from_: PAnsiChar; to_: PAnsiChar; x: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_MD_do_all_sorted(fn: TFuncType032; arg: pointer); cdecl; external CLibCrypto name 'EVP_MD_do_all_sorted';
  {$else}
  {$EXTERNALSYM EVP_MD_do_all_sorted}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_MD_do_all_sorted(fn: TFuncType032; arg: pointer); cdecl;

var
  EVP_MD_do_all_sorted: procedure(fn: TFuncType032; arg: pointer); cdecl = Load_EVP_MD_do_all_sorted;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType033 = ^TFuncType033;
  PPFuncType033 = ^PFuncType033;
  {end of auto-generated forward references}

  TFuncType033 = procedure(md: PEVP_MD; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_MD_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType033; arg: pointer); cdecl; external CLibCrypto name 'EVP_MD_do_all_provided';
  { MAC stuff }
  function EVP_MAC_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MAC; cdecl; external CLibCrypto name 'EVP_MAC_fetch';
  function EVP_MAC_up_ref(mac: PEVP_MAC): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_up_ref';
  procedure EVP_MAC_free(mac: PEVP_MAC); cdecl; external CLibCrypto name 'EVP_MAC_free';
  function EVP_MAC_get0_name(mac: PEVP_MAC): PAnsiChar; cdecl; external CLibCrypto name 'EVP_MAC_get0_name';
  function EVP_MAC_get0_description(mac: PEVP_MAC): PAnsiChar; cdecl; external CLibCrypto name 'EVP_MAC_get0_description';
  function EVP_MAC_is_a(mac: PEVP_MAC; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_is_a';
  function EVP_MAC_get0_provider(mac: PEVP_MAC): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_MAC_get0_provider';
  function EVP_MAC_get_params(mac: PEVP_MAC; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_get_params';
  function EVP_MAC_CTX_new(mac: PEVP_MAC): PEVP_MAC_CTX; cdecl; external CLibCrypto name 'EVP_MAC_CTX_new';
  procedure EVP_MAC_CTX_free(ctx: PEVP_MAC_CTX); cdecl; external CLibCrypto name 'EVP_MAC_CTX_free';
  function EVP_MAC_CTX_dup(src: PEVP_MAC_CTX): PEVP_MAC_CTX; cdecl; external CLibCrypto name 'EVP_MAC_CTX_dup';
  function EVP_MAC_CTX_get0_mac(ctx: PEVP_MAC_CTX): PEVP_MAC; cdecl; external CLibCrypto name 'EVP_MAC_CTX_get0_mac';
  function EVP_MAC_CTX_get_params(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_CTX_get_params';
  function EVP_MAC_CTX_set_params(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_CTX_set_params';
  function EVP_MAC_CTX_get_mac_size(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EVP_MAC_CTX_get_mac_size';
  function EVP_MAC_CTX_get_block_size(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EVP_MAC_CTX_get_block_size';
  function EVP_Q_mac(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; subalg: PAnsiChar; params: POSSL_PARAM; key: pointer; keylen: TOpenSSL_C_SIZET; data: Pbyte; datalen: TOpenSSL_C_SIZET; out_: Pbyte; outsize: TOpenSSL_C_SIZET; outlen: POpenSSL_C_SIZET): Pbyte; cdecl; external CLibCrypto name 'EVP_Q_mac';
  function EVP_MAC_init(ctx: PEVP_MAC_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_init';
  function EVP_MAC_init_SKEY(ctx: PEVP_MAC_CTX; skey: PEVP_SKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_init_SKEY';
  function EVP_MAC_update(ctx: PEVP_MAC_CTX; data: Pbyte; datalen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_update';
  function EVP_MAC_final(ctx: PEVP_MAC_CTX; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_final';
  function EVP_MAC_finalXOF(ctx: PEVP_MAC_CTX; out_: Pbyte; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_finalXOF';
  function EVP_MAC_gettable_params(mac: PEVP_MAC): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MAC_gettable_params';
  function EVP_MAC_gettable_ctx_params(mac: PEVP_MAC): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MAC_gettable_ctx_params';
  function EVP_MAC_settable_ctx_params(mac: PEVP_MAC): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MAC_settable_ctx_params';
  function EVP_MAC_CTX_gettable_params(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MAC_CTX_gettable_params';
  function EVP_MAC_CTX_settable_params(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_MAC_CTX_settable_params';
  {$else}
  {$EXTERNALSYM EVP_MD_do_all_provided}
  {$EXTERNALSYM EVP_MAC_fetch}
  {$EXTERNALSYM EVP_MAC_up_ref}
  {$EXTERNALSYM EVP_MAC_free}
  {$EXTERNALSYM EVP_MAC_get0_name}
  {$EXTERNALSYM EVP_MAC_get0_description}
  {$EXTERNALSYM EVP_MAC_is_a}
  {$EXTERNALSYM EVP_MAC_get0_provider}
  {$EXTERNALSYM EVP_MAC_get_params}
  {$EXTERNALSYM EVP_MAC_CTX_new}
  {$EXTERNALSYM EVP_MAC_CTX_free}
  {$EXTERNALSYM EVP_MAC_CTX_dup}
  {$EXTERNALSYM EVP_MAC_CTX_get0_mac}
  {$EXTERNALSYM EVP_MAC_CTX_get_params}
  {$EXTERNALSYM EVP_MAC_CTX_set_params}
  {$EXTERNALSYM EVP_MAC_CTX_get_mac_size}
  {$EXTERNALSYM EVP_MAC_CTX_get_block_size}
  {$EXTERNALSYM EVP_Q_mac}
  {$EXTERNALSYM EVP_MAC_init}
  {$EXTERNALSYM EVP_MAC_init_SKEY}
  {$EXTERNALSYM EVP_MAC_update}
  {$EXTERNALSYM EVP_MAC_final}
  {$EXTERNALSYM EVP_MAC_finalXOF}
  {$EXTERNALSYM EVP_MAC_gettable_params}
  {$EXTERNALSYM EVP_MAC_gettable_ctx_params}
  {$EXTERNALSYM EVP_MAC_settable_ctx_params}
  {$EXTERNALSYM EVP_MAC_CTX_gettable_params}
  {$EXTERNALSYM EVP_MAC_CTX_settable_params}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_MD_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType033; arg: pointer); cdecl;
  function Load_EVP_MAC_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MAC; cdecl;
  function Load_EVP_MAC_up_ref(mac: PEVP_MAC): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_MAC_free(mac: PEVP_MAC); cdecl;
  function Load_EVP_MAC_get0_name(mac: PEVP_MAC): PAnsiChar; cdecl;
  function Load_EVP_MAC_get0_description(mac: PEVP_MAC): PAnsiChar; cdecl;
  function Load_EVP_MAC_is_a(mac: PEVP_MAC; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_get0_provider(mac: PEVP_MAC): POSSL_PROVIDER; cdecl;
  function Load_EVP_MAC_get_params(mac: PEVP_MAC; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_CTX_new(mac: PEVP_MAC): PEVP_MAC_CTX; cdecl;
  procedure Load_EVP_MAC_CTX_free(ctx: PEVP_MAC_CTX); cdecl;
  function Load_EVP_MAC_CTX_dup(src: PEVP_MAC_CTX): PEVP_MAC_CTX; cdecl;
  function Load_EVP_MAC_CTX_get0_mac(ctx: PEVP_MAC_CTX): PEVP_MAC; cdecl;
  function Load_EVP_MAC_CTX_get_params(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_CTX_set_params(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_CTX_get_mac_size(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl;
  function Load_EVP_MAC_CTX_get_block_size(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl;
  function Load_EVP_Q_mac(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; subalg: PAnsiChar; params: POSSL_PARAM; key: pointer; keylen: TOpenSSL_C_SIZET; data: Pbyte; datalen: TOpenSSL_C_SIZET; out_: Pbyte; outsize: TOpenSSL_C_SIZET; outlen: POpenSSL_C_SIZET): Pbyte; cdecl;
  function Load_EVP_MAC_init(ctx: PEVP_MAC_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_init_SKEY(ctx: PEVP_MAC_CTX; skey: PEVP_SKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_update(ctx: PEVP_MAC_CTX; data: Pbyte; datalen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_final(ctx: PEVP_MAC_CTX; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_finalXOF(ctx: PEVP_MAC_CTX; out_: Pbyte; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_MAC_gettable_params(mac: PEVP_MAC): POSSL_PARAM; cdecl;
  function Load_EVP_MAC_gettable_ctx_params(mac: PEVP_MAC): POSSL_PARAM; cdecl;
  function Load_EVP_MAC_settable_ctx_params(mac: PEVP_MAC): POSSL_PARAM; cdecl;
  function Load_EVP_MAC_CTX_gettable_params(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_MAC_CTX_settable_params(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl;

var
  EVP_MD_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType033; arg: pointer); cdecl = Load_EVP_MD_do_all_provided;
  { MAC stuff }
  EVP_MAC_fetch: function(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MAC; cdecl = Load_EVP_MAC_fetch;
  EVP_MAC_up_ref: function(mac: PEVP_MAC): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_up_ref;
  EVP_MAC_free: procedure(mac: PEVP_MAC); cdecl = Load_EVP_MAC_free;
  EVP_MAC_get0_name: function(mac: PEVP_MAC): PAnsiChar; cdecl = Load_EVP_MAC_get0_name;
  EVP_MAC_get0_description: function(mac: PEVP_MAC): PAnsiChar; cdecl = Load_EVP_MAC_get0_description;
  EVP_MAC_is_a: function(mac: PEVP_MAC; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_is_a;
  EVP_MAC_get0_provider: function(mac: PEVP_MAC): POSSL_PROVIDER; cdecl = Load_EVP_MAC_get0_provider;
  EVP_MAC_get_params: function(mac: PEVP_MAC; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_get_params;
  EVP_MAC_CTX_new: function(mac: PEVP_MAC): PEVP_MAC_CTX; cdecl = Load_EVP_MAC_CTX_new;
  EVP_MAC_CTX_free: procedure(ctx: PEVP_MAC_CTX); cdecl = Load_EVP_MAC_CTX_free;
  EVP_MAC_CTX_dup: function(src: PEVP_MAC_CTX): PEVP_MAC_CTX; cdecl = Load_EVP_MAC_CTX_dup;
  EVP_MAC_CTX_get0_mac: function(ctx: PEVP_MAC_CTX): PEVP_MAC; cdecl = Load_EVP_MAC_CTX_get0_mac;
  EVP_MAC_CTX_get_params: function(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_CTX_get_params;
  EVP_MAC_CTX_set_params: function(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_CTX_set_params;
  EVP_MAC_CTX_get_mac_size: function(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl = Load_EVP_MAC_CTX_get_mac_size;
  EVP_MAC_CTX_get_block_size: function(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl = Load_EVP_MAC_CTX_get_block_size;
  EVP_Q_mac: function(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; subalg: PAnsiChar; params: POSSL_PARAM; key: pointer; keylen: TOpenSSL_C_SIZET; data: Pbyte; datalen: TOpenSSL_C_SIZET; out_: Pbyte; outsize: TOpenSSL_C_SIZET; outlen: POpenSSL_C_SIZET): Pbyte; cdecl = Load_EVP_Q_mac;
  EVP_MAC_init: function(ctx: PEVP_MAC_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_init;
  EVP_MAC_init_SKEY: function(ctx: PEVP_MAC_CTX; skey: PEVP_SKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_init_SKEY;
  EVP_MAC_update: function(ctx: PEVP_MAC_CTX; data: Pbyte; datalen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_update;
  EVP_MAC_final: function(ctx: PEVP_MAC_CTX; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_final;
  EVP_MAC_finalXOF: function(ctx: PEVP_MAC_CTX; out_: Pbyte; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_finalXOF;
  EVP_MAC_gettable_params: function(mac: PEVP_MAC): POSSL_PARAM; cdecl = Load_EVP_MAC_gettable_params;
  EVP_MAC_gettable_ctx_params: function(mac: PEVP_MAC): POSSL_PARAM; cdecl = Load_EVP_MAC_gettable_ctx_params;
  EVP_MAC_settable_ctx_params: function(mac: PEVP_MAC): POSSL_PARAM; cdecl = Load_EVP_MAC_settable_ctx_params;
  EVP_MAC_CTX_gettable_params: function(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl = Load_EVP_MAC_CTX_gettable_params;
  EVP_MAC_CTX_settable_params: function(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl = Load_EVP_MAC_CTX_settable_params;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType034 = ^TFuncType034;
  PPFuncType034 = ^PFuncType034;
  {end of auto-generated forward references}

  TFuncType034 = procedure(mac: PEVP_MAC; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_MAC_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType034; arg: pointer); cdecl; external CLibCrypto name 'EVP_MAC_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_MAC_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_MAC_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType034; arg: pointer); cdecl;

var
  EVP_MAC_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType034; arg: pointer); cdecl = Load_EVP_MAC_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType035 = ^TFuncType035;
  PPFuncType035 = ^PFuncType035;
  {end of auto-generated forward references}

  TFuncType035 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_MAC_names_do_all(mac: PEVP_MAC; fn: TFuncType035; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_MAC_names_do_all';
  { RAND stuff }
  function EVP_RAND_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_RAND; cdecl; external CLibCrypto name 'EVP_RAND_fetch';
  function EVP_RAND_up_ref(rand: PEVP_RAND): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_up_ref';
  procedure EVP_RAND_free(rand: PEVP_RAND); cdecl; external CLibCrypto name 'EVP_RAND_free';
  function EVP_RAND_get0_name(rand: PEVP_RAND): PAnsiChar; cdecl; external CLibCrypto name 'EVP_RAND_get0_name';
  function EVP_RAND_get0_description(md: PEVP_RAND): PAnsiChar; cdecl; external CLibCrypto name 'EVP_RAND_get0_description';
  function EVP_RAND_is_a(rand: PEVP_RAND; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_is_a';
  function EVP_RAND_get0_provider(rand: PEVP_RAND): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_RAND_get0_provider';
  function EVP_RAND_get_params(rand: PEVP_RAND; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_get_params';
  function EVP_RAND_CTX_new(rand: PEVP_RAND; parent: PEVP_RAND_CTX): PEVP_RAND_CTX; cdecl; external CLibCrypto name 'EVP_RAND_CTX_new';
  function EVP_RAND_CTX_up_ref(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_CTX_up_ref';
  procedure EVP_RAND_CTX_free(ctx: PEVP_RAND_CTX); cdecl; external CLibCrypto name 'EVP_RAND_CTX_free';
  function EVP_RAND_CTX_get0_rand(ctx: PEVP_RAND_CTX): PEVP_RAND; cdecl; external CLibCrypto name 'EVP_RAND_CTX_get0_rand';
  function EVP_RAND_CTX_get_params(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_CTX_get_params';
  function EVP_RAND_CTX_set_params(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_CTX_set_params';
  function EVP_RAND_gettable_params(rand: PEVP_RAND): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_RAND_gettable_params';
  function EVP_RAND_gettable_ctx_params(rand: PEVP_RAND): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_RAND_gettable_ctx_params';
  function EVP_RAND_settable_ctx_params(rand: PEVP_RAND): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_RAND_settable_ctx_params';
  function EVP_RAND_CTX_gettable_params(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_RAND_CTX_gettable_params';
  function EVP_RAND_CTX_settable_params(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_RAND_CTX_settable_params';
  {$else}
  {$EXTERNALSYM EVP_MAC_names_do_all}
  {$EXTERNALSYM EVP_RAND_fetch}
  {$EXTERNALSYM EVP_RAND_up_ref}
  {$EXTERNALSYM EVP_RAND_free}
  {$EXTERNALSYM EVP_RAND_get0_name}
  {$EXTERNALSYM EVP_RAND_get0_description}
  {$EXTERNALSYM EVP_RAND_is_a}
  {$EXTERNALSYM EVP_RAND_get0_provider}
  {$EXTERNALSYM EVP_RAND_get_params}
  {$EXTERNALSYM EVP_RAND_CTX_new}
  {$EXTERNALSYM EVP_RAND_CTX_up_ref}
  {$EXTERNALSYM EVP_RAND_CTX_free}
  {$EXTERNALSYM EVP_RAND_CTX_get0_rand}
  {$EXTERNALSYM EVP_RAND_CTX_get_params}
  {$EXTERNALSYM EVP_RAND_CTX_set_params}
  {$EXTERNALSYM EVP_RAND_gettable_params}
  {$EXTERNALSYM EVP_RAND_gettable_ctx_params}
  {$EXTERNALSYM EVP_RAND_settable_ctx_params}
  {$EXTERNALSYM EVP_RAND_CTX_gettable_params}
  {$EXTERNALSYM EVP_RAND_CTX_settable_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_MAC_names_do_all(mac: PEVP_MAC; fn: TFuncType035; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_RAND; cdecl;
  function Load_EVP_RAND_up_ref(rand: PEVP_RAND): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_RAND_free(rand: PEVP_RAND); cdecl;
  function Load_EVP_RAND_get0_name(rand: PEVP_RAND): PAnsiChar; cdecl;
  function Load_EVP_RAND_get0_description(md: PEVP_RAND): PAnsiChar; cdecl;
  function Load_EVP_RAND_is_a(rand: PEVP_RAND; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_get0_provider(rand: PEVP_RAND): POSSL_PROVIDER; cdecl;
  function Load_EVP_RAND_get_params(rand: PEVP_RAND; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_CTX_new(rand: PEVP_RAND; parent: PEVP_RAND_CTX): PEVP_RAND_CTX; cdecl;
  function Load_EVP_RAND_CTX_up_ref(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_RAND_CTX_free(ctx: PEVP_RAND_CTX); cdecl;
  function Load_EVP_RAND_CTX_get0_rand(ctx: PEVP_RAND_CTX): PEVP_RAND; cdecl;
  function Load_EVP_RAND_CTX_get_params(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_CTX_set_params(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_gettable_params(rand: PEVP_RAND): POSSL_PARAM; cdecl;
  function Load_EVP_RAND_gettable_ctx_params(rand: PEVP_RAND): POSSL_PARAM; cdecl;
  function Load_EVP_RAND_settable_ctx_params(rand: PEVP_RAND): POSSL_PARAM; cdecl;
  function Load_EVP_RAND_CTX_gettable_params(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_RAND_CTX_settable_params(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl;

var
  EVP_MAC_names_do_all: function(mac: PEVP_MAC; fn: TFuncType035; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_MAC_names_do_all;
  { RAND stuff }
  EVP_RAND_fetch: function(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_RAND; cdecl = Load_EVP_RAND_fetch;
  EVP_RAND_up_ref: function(rand: PEVP_RAND): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_up_ref;
  EVP_RAND_free: procedure(rand: PEVP_RAND); cdecl = Load_EVP_RAND_free;
  EVP_RAND_get0_name: function(rand: PEVP_RAND): PAnsiChar; cdecl = Load_EVP_RAND_get0_name;
  EVP_RAND_get0_description: function(md: PEVP_RAND): PAnsiChar; cdecl = Load_EVP_RAND_get0_description;
  EVP_RAND_is_a: function(rand: PEVP_RAND; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_is_a;
  EVP_RAND_get0_provider: function(rand: PEVP_RAND): POSSL_PROVIDER; cdecl = Load_EVP_RAND_get0_provider;
  EVP_RAND_get_params: function(rand: PEVP_RAND; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_get_params;
  EVP_RAND_CTX_new: function(rand: PEVP_RAND; parent: PEVP_RAND_CTX): PEVP_RAND_CTX; cdecl = Load_EVP_RAND_CTX_new;
  EVP_RAND_CTX_up_ref: function(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_CTX_up_ref;
  EVP_RAND_CTX_free: procedure(ctx: PEVP_RAND_CTX); cdecl = Load_EVP_RAND_CTX_free;
  EVP_RAND_CTX_get0_rand: function(ctx: PEVP_RAND_CTX): PEVP_RAND; cdecl = Load_EVP_RAND_CTX_get0_rand;
  EVP_RAND_CTX_get_params: function(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_CTX_get_params;
  EVP_RAND_CTX_set_params: function(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_CTX_set_params;
  EVP_RAND_gettable_params: function(rand: PEVP_RAND): POSSL_PARAM; cdecl = Load_EVP_RAND_gettable_params;
  EVP_RAND_gettable_ctx_params: function(rand: PEVP_RAND): POSSL_PARAM; cdecl = Load_EVP_RAND_gettable_ctx_params;
  EVP_RAND_settable_ctx_params: function(rand: PEVP_RAND): POSSL_PARAM; cdecl = Load_EVP_RAND_settable_ctx_params;
  EVP_RAND_CTX_gettable_params: function(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl = Load_EVP_RAND_CTX_gettable_params;
  EVP_RAND_CTX_settable_params: function(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl = Load_EVP_RAND_CTX_settable_params;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType036 = ^TFuncType036;
  PPFuncType036 = ^PFuncType036;
  {end of auto-generated forward references}

  TFuncType036 = procedure(rand: PEVP_RAND; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_RAND_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType036; arg: pointer); cdecl; external CLibCrypto name 'EVP_RAND_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_RAND_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_RAND_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType036; arg: pointer); cdecl;

var
  EVP_RAND_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType036; arg: pointer); cdecl = Load_EVP_RAND_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType037 = ^TFuncType037;
  PPFuncType037 = ^PFuncType037;
  {end of auto-generated forward references}

  TFuncType037 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_RAND_names_do_all(rand: PEVP_RAND; fn: TFuncType037; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_names_do_all';
  function EVP_RAND_instantiate(ctx: PEVP_RAND_CTX; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; pstr: Pbyte; pstr_len: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_instantiate';
  function EVP_RAND_uninstantiate(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_uninstantiate';
  function EVP_RAND_generate(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_generate';
  function EVP_RAND_reseed(ctx: PEVP_RAND_CTX; prediction_resistance: TOpenSSL_C_INT; ent: Pbyte; ent_len: TOpenSSL_C_SIZET; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_reseed';
  function EVP_RAND_nonce(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_nonce';
  function EVP_RAND_enable_locking(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_enable_locking';
  function EVP_RAND_verify_zeroization(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_verify_zeroization';
  function EVP_RAND_get_strength(ctx: PEVP_RAND_CTX): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'EVP_RAND_get_strength';
  function EVP_RAND_get_state(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_RAND_get_state';
  {$else}
  {$EXTERNALSYM EVP_RAND_names_do_all}
  {$EXTERNALSYM EVP_RAND_instantiate}
  {$EXTERNALSYM EVP_RAND_uninstantiate}
  {$EXTERNALSYM EVP_RAND_generate}
  {$EXTERNALSYM EVP_RAND_reseed}
  {$EXTERNALSYM EVP_RAND_nonce}
  {$EXTERNALSYM EVP_RAND_enable_locking}
  {$EXTERNALSYM EVP_RAND_verify_zeroization}
  {$EXTERNALSYM EVP_RAND_get_strength}
  {$EXTERNALSYM EVP_RAND_get_state}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_RAND_names_do_all(rand: PEVP_RAND; fn: TFuncType037; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_instantiate(ctx: PEVP_RAND_CTX; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; pstr: Pbyte; pstr_len: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_uninstantiate(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_generate(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_reseed(ctx: PEVP_RAND_CTX; prediction_resistance: TOpenSSL_C_INT; ent: Pbyte; ent_len: TOpenSSL_C_SIZET; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_nonce(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_enable_locking(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_verify_zeroization(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_RAND_get_strength(ctx: PEVP_RAND_CTX): TOpenSSL_C_UINT; cdecl;
  function Load_EVP_RAND_get_state(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;

var
  EVP_RAND_names_do_all: function(rand: PEVP_RAND; fn: TFuncType037; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_names_do_all;
  EVP_RAND_instantiate: function(ctx: PEVP_RAND_CTX; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; pstr: Pbyte; pstr_len: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_instantiate;
  EVP_RAND_uninstantiate: function(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_uninstantiate;
  EVP_RAND_generate: function(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_generate;
  EVP_RAND_reseed: function(ctx: PEVP_RAND_CTX; prediction_resistance: TOpenSSL_C_INT; ent: Pbyte; ent_len: TOpenSSL_C_SIZET; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_reseed;
  EVP_RAND_nonce: function(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_nonce;
  EVP_RAND_enable_locking: function(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_enable_locking;
  EVP_RAND_verify_zeroization: function(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_verify_zeroization;
  EVP_RAND_get_strength: function(ctx: PEVP_RAND_CTX): TOpenSSL_C_UINT; cdecl = Load_EVP_RAND_get_strength;
  EVP_RAND_get_state: function(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_RAND_get_state;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_RAND_STATE_UNINITIALISED = 0;
  EVP_RAND_STATE_READY = 1;
  EVP_RAND_STATE_ERROR = 2;
  { PKEY stuff }
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_decrypt_old(dec_key: Pbyte; enc_key: Pbyte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_decrypt_old'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_encrypt_old(enc_key: Pbyte; key: Pbyte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_encrypt_old'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_decrypt_old}
  {$EXTERNALSYM EVP_PKEY_encrypt_old}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_decrypt_old(dec_key: Pbyte; enc_key: Pbyte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_encrypt_old(enc_key: Pbyte; key: Pbyte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_decrypt_old: function(dec_key: Pbyte; enc_key: Pbyte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decrypt_old;
  EVP_PKEY_encrypt_old: function(enc_key: Pbyte; key: Pbyte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encrypt_old;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_is_a(pkey: PEVP_PKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_is_a';
  {$else}
  {$EXTERNALSYM EVP_PKEY_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_is_a(pkey: PEVP_PKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_is_a: function(pkey: PEVP_PKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType038 = ^TFuncType038;
  PPFuncType038 = ^PFuncType038;
  {end of auto-generated forward references}

  TFuncType038 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_type_names_do_all(pkey: PEVP_PKEY; fn: TFuncType038; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_type_names_do_all';
  function EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_type';
  function EVP_PKEY_get_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_id';
  function EVP_PKEY_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_id';
  function EVP_PKEY_get_base_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_base_id';
  function EVP_PKEY_base_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_base_id';
  function EVP_PKEY_get_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_bits';
  function EVP_PKEY_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_bits';
  function EVP_PKEY_get_security_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_security_bits';
  function EVP_PKEY_security_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_security_bits';
  function EVP_PKEY_get_security_category(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_security_category';
  function EVP_PKEY_get_size(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_size';
  function EVP_PKEY_size(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_size';
  function EVP_PKEY_can_sign(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_can_sign';
  function EVP_PKEY_set_type(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_type';
  function EVP_PKEY_set_type_str(pkey: PEVP_PKEY; str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_type_str';
  function EVP_PKEY_set_type_by_keymgmt(pkey: PEVP_PKEY; keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_type_by_keymgmt';
  {$else}
  {$EXTERNALSYM EVP_PKEY_type_names_do_all}
  {$EXTERNALSYM EVP_PKEY_type}
  {$EXTERNALSYM EVP_PKEY_get_id}
  {$EXTERNALSYM EVP_PKEY_id}
  {$EXTERNALSYM EVP_PKEY_get_base_id}
  {$EXTERNALSYM EVP_PKEY_base_id}
  {$EXTERNALSYM EVP_PKEY_get_bits}
  {$EXTERNALSYM EVP_PKEY_bits}
  {$EXTERNALSYM EVP_PKEY_get_security_bits}
  {$EXTERNALSYM EVP_PKEY_security_bits}
  {$EXTERNALSYM EVP_PKEY_get_security_category}
  {$EXTERNALSYM EVP_PKEY_get_size}
  {$EXTERNALSYM EVP_PKEY_size}
  {$EXTERNALSYM EVP_PKEY_can_sign}
  {$EXTERNALSYM EVP_PKEY_set_type}
  {$EXTERNALSYM EVP_PKEY_set_type_str}
  {$EXTERNALSYM EVP_PKEY_set_type_by_keymgmt}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_type_names_do_all(pkey: PEVP_PKEY; fn: TFuncType038; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_base_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_base_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_security_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_security_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_security_category(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_size(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_size(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_can_sign(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_type(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_type_str(pkey: PEVP_PKEY; str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_type_by_keymgmt(pkey: PEVP_PKEY; keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_type_names_do_all: function(pkey: PEVP_PKEY; fn: TFuncType038; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_type_names_do_all;
  EVP_PKEY_type: function(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_type;
  EVP_PKEY_get_id: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_id;
  EVP_PKEY_id: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_id;
  EVP_PKEY_get_base_id: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_base_id;
  EVP_PKEY_base_id: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_base_id;
  EVP_PKEY_get_bits: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_bits;
  EVP_PKEY_bits: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_bits;
  EVP_PKEY_get_security_bits: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_security_bits;
  EVP_PKEY_security_bits: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_security_bits;
  EVP_PKEY_get_security_category: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_security_category;
  EVP_PKEY_get_size: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_size;
  EVP_PKEY_size: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_size;
  EVP_PKEY_can_sign: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_can_sign;
  EVP_PKEY_set_type: function(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_type;
  EVP_PKEY_set_type_str: function(pkey: PEVP_PKEY; str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_type_str;
  EVP_PKEY_set_type_by_keymgmt: function(pkey: PEVP_PKEY; keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_type_by_keymgmt;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_ENGINE}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set1_engine'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get0_engine(pkey: PEVP_PKEY): PENGINE; cdecl; external CLibCrypto name 'EVP_PKEY_get0_engine'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_PKEY_set1_engine}
  {$EXTERNALSYM EVP_PKEY_get0_engine}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0_engine(pkey: PEVP_PKEY): PENGINE; cdecl;

var
  EVP_PKEY_set1_engine: function(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_engine;
  EVP_PKEY_get0_engine: function(pkey: PEVP_PKEY): PENGINE; cdecl = Load_EVP_PKEY_get0_engine;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_assign'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get0(pkey: PEVP_PKEY): pointer; cdecl; external CLibCrypto name 'EVP_PKEY_get0'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get0_hmac(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl; external CLibCrypto name 'EVP_PKEY_get0_hmac'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_assign}
  {$EXTERNALSYM EVP_PKEY_get0}
  {$EXTERNALSYM EVP_PKEY_get0_hmac}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0(pkey: PEVP_PKEY): pointer; cdecl;
  function Load_EVP_PKEY_get0_hmac(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl;

var
  EVP_PKEY_assign: function(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_assign;
  EVP_PKEY_get0: function(pkey: PEVP_PKEY): pointer; cdecl = Load_EVP_PKEY_get0;
  EVP_PKEY_get0_hmac: function(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl = Load_EVP_PKEY_get0_hmac;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_POLY1305}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_get0_poly1305(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl; external CLibCrypto name 'EVP_PKEY_get0_poly1305'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_PKEY_get0_poly1305}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_get0_poly1305(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl;

var
  EVP_PKEY_get0_poly1305: function(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl = Load_EVP_PKEY_get0_poly1305;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_SIPHASH}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_get0_siphash(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl; external CLibCrypto name 'EVP_PKEY_get0_siphash'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_PKEY_get0_siphash}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_get0_siphash(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl;

var
  EVP_PKEY_get0_siphash: function(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl = Load_EVP_PKEY_get0_siphash;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}

type
  {Auto-generated forward references}
  Prsa_st = ^Trsa_st;
  PPrsa_st = ^Prsa_st;
  {end of auto-generated forward references}

  Trsa_st = record 
  end;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: Prsa_st): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set1_RSA'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): Prsa_st; cdecl; external CLibCrypto name 'EVP_PKEY_get0_RSA'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): Prsa_st; cdecl; external CLibCrypto name 'EVP_PKEY_get1_RSA'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_set1_RSA}
  {$EXTERNALSYM EVP_PKEY_get0_RSA}
  {$EXTERNALSYM EVP_PKEY_get1_RSA}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: Prsa_st): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): Prsa_st; cdecl;
  function Load_EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): Prsa_st; cdecl;

var
  EVP_PKEY_set1_RSA: function(pkey: PEVP_PKEY; key: Prsa_st): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_RSA;
  EVP_PKEY_get0_RSA: function(pkey: PEVP_PKEY): Prsa_st; cdecl = Load_EVP_PKEY_get0_RSA;
  EVP_PKEY_get1_RSA: function(pkey: PEVP_PKEY): Prsa_st; cdecl = Load_EVP_PKEY_get1_RSA;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DSA}

type
  {Auto-generated forward references}
  Pdsa_st = ^Tdsa_st;
  PPdsa_st = ^Pdsa_st;
  {end of auto-generated forward references}

  Tdsa_st = record 
  end;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: Pdsa_st): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set1_DSA'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): Pdsa_st; cdecl; external CLibCrypto name 'EVP_PKEY_get0_DSA'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): Pdsa_st; cdecl; external CLibCrypto name 'EVP_PKEY_get1_DSA'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_PKEY_set1_DSA}
  {$EXTERNALSYM EVP_PKEY_get0_DSA}
  {$EXTERNALSYM EVP_PKEY_get1_DSA}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: Pdsa_st): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): Pdsa_st; cdecl;
  function Load_EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): Pdsa_st; cdecl;

var
  EVP_PKEY_set1_DSA: function(pkey: PEVP_PKEY; key: Pdsa_st): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_DSA;
  EVP_PKEY_get0_DSA: function(pkey: PEVP_PKEY): Pdsa_st; cdecl = Load_EVP_PKEY_get0_DSA;
  EVP_PKEY_get1_DSA: function(pkey: PEVP_PKEY): Pdsa_st; cdecl = Load_EVP_PKEY_get1_DSA;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DH}

type
  {Auto-generated forward references}
  Pdh_st = ^Tdh_st;
  PPdh_st = ^Pdh_st;
  {end of auto-generated forward references}

  Tdh_st = record 
  end;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: Pdh_st): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set1_DH'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get0_DH(pkey: PEVP_PKEY): Pdh_st; cdecl; external CLibCrypto name 'EVP_PKEY_get0_DH'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get1_DH(pkey: PEVP_PKEY): Pdh_st; cdecl; external CLibCrypto name 'EVP_PKEY_get1_DH'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_PKEY_set1_DH}
  {$EXTERNALSYM EVP_PKEY_get0_DH}
  {$EXTERNALSYM EVP_PKEY_get1_DH}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: Pdh_st): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0_DH(pkey: PEVP_PKEY): Pdh_st; cdecl;
  function Load_EVP_PKEY_get1_DH(pkey: PEVP_PKEY): Pdh_st; cdecl;

var
  EVP_PKEY_set1_DH: function(pkey: PEVP_PKEY; key: Pdh_st): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_DH;
  EVP_PKEY_get0_DH: function(pkey: PEVP_PKEY): Pdh_st; cdecl = Load_EVP_PKEY_get0_DH;
  EVP_PKEY_get1_DH: function(pkey: PEVP_PKEY): Pdh_st; cdecl = Load_EVP_PKEY_get1_DH;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_EC}

type
  {Auto-generated forward references}
  Pec_key_st = ^Tec_key_st;
  PPec_key_st = ^Pec_key_st;
  {end of auto-generated forward references}

  Tec_key_st = record 
  end;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: Pec_key_st): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set1_EC_KEY'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): Pec_key_st; cdecl; external CLibCrypto name 'EVP_PKEY_get0_EC_KEY'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): Pec_key_st; cdecl; external CLibCrypto name 'EVP_PKEY_get1_EC_KEY'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM EVP_PKEY_set1_EC_KEY}
  {$EXTERNALSYM EVP_PKEY_get0_EC_KEY}
  {$EXTERNALSYM EVP_PKEY_get1_EC_KEY}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: Pec_key_st): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): Pec_key_st; cdecl;
  function Load_EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): Pec_key_st; cdecl;

var
  EVP_PKEY_set1_EC_KEY: function(pkey: PEVP_PKEY; key: Pec_key_st): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_EC_KEY;
  EVP_PKEY_get0_EC_KEY: function(pkey: PEVP_PKEY): Pec_key_st; cdecl = Load_EVP_PKEY_get0_EC_KEY;
  EVP_PKEY_get1_EC_KEY: function(pkey: PEVP_PKEY): Pec_key_st; cdecl = Load_EVP_PKEY_get1_EC_KEY;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
  {$endif}


  { OPENSSL_NO_DEPRECATED_3_0 }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_new: PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_new';
  function EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_up_ref';
  function EVP_PKEY_dup(pkey: PEVP_PKEY): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_dup';
  procedure EVP_PKEY_free(pkey: PEVP_PKEY); cdecl; external CLibCrypto name 'EVP_PKEY_free';
  function EVP_PKEY_get0_description(pkey: PEVP_PKEY): PAnsiChar; cdecl; external CLibCrypto name 'EVP_PKEY_get0_description';
  function EVP_PKEY_get0_provider(key: PEVP_PKEY): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_PKEY_get0_provider';
  function d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_PublicKey';
  function i2d_PublicKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_PublicKey';
  function d2i_PrivateKey_ex(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_PrivateKey_ex';
  function d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_PrivateKey';
  function d2i_AutoPrivateKey_ex(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_AutoPrivateKey_ex';
  function d2i_AutoPrivateKey(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_AutoPrivateKey';
  function i2d_PrivateKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_PrivateKey';
  function i2d_PKCS8PrivateKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_PKCS8PrivateKey';
  function i2d_KeyParams(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_KeyParams';
  function d2i_KeyParams(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_KeyParams';
  function i2d_KeyParams_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_KeyParams_bio';
  function d2i_KeyParams_bio(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; in_: PBIO): PEVP_PKEY; cdecl; external CLibCrypto name 'd2i_KeyParams_bio';
  function EVP_PKEY_copy_parameters(to_: PEVP_PKEY; from_: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_copy_parameters';
  function EVP_PKEY_missing_parameters(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_missing_parameters';
  function EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_save_parameters';
  function EVP_PKEY_parameters_eq(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_parameters_eq';
  function EVP_PKEY_eq(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_eq';
  {$else}
  {$EXTERNALSYM EVP_PKEY_new}
  {$EXTERNALSYM EVP_PKEY_up_ref}
  {$EXTERNALSYM EVP_PKEY_dup}
  {$EXTERNALSYM EVP_PKEY_free}
  {$EXTERNALSYM EVP_PKEY_get0_description}
  {$EXTERNALSYM EVP_PKEY_get0_provider}
  {$EXTERNALSYM d2i_PublicKey}
  {$EXTERNALSYM i2d_PublicKey}
  {$EXTERNALSYM d2i_PrivateKey_ex}
  {$EXTERNALSYM d2i_PrivateKey}
  {$EXTERNALSYM d2i_AutoPrivateKey_ex}
  {$EXTERNALSYM d2i_AutoPrivateKey}
  {$EXTERNALSYM i2d_PrivateKey}
  {$EXTERNALSYM i2d_PKCS8PrivateKey}
  {$EXTERNALSYM i2d_KeyParams}
  {$EXTERNALSYM d2i_KeyParams}
  {$EXTERNALSYM i2d_KeyParams_bio}
  {$EXTERNALSYM d2i_KeyParams_bio}
  {$EXTERNALSYM EVP_PKEY_copy_parameters}
  {$EXTERNALSYM EVP_PKEY_missing_parameters}
  {$EXTERNALSYM EVP_PKEY_save_parameters}
  {$EXTERNALSYM EVP_PKEY_parameters_eq}
  {$EXTERNALSYM EVP_PKEY_eq}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_new: PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_dup(pkey: PEVP_PKEY): PEVP_PKEY; cdecl;
  procedure Load_EVP_PKEY_free(pkey: PEVP_PKEY); cdecl;
  function Load_EVP_PKEY_get0_description(pkey: PEVP_PKEY): PAnsiChar; cdecl;
  function Load_EVP_PKEY_get0_provider(key: PEVP_PKEY): POSSL_PROVIDER; cdecl;
  function Load_d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
  function Load_i2d_PublicKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_d2i_PrivateKey_ex(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
  function Load_d2i_AutoPrivateKey_ex(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_d2i_AutoPrivateKey(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
  function Load_i2d_PrivateKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_i2d_PKCS8PrivateKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_i2d_KeyParams(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_d2i_KeyParams(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
  function Load_i2d_KeyParams_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_d2i_KeyParams_bio(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; in_: PBIO): PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_copy_parameters(to_: PEVP_PKEY; from_: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_missing_parameters(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_parameters_eq(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_eq(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_new: function: PEVP_PKEY; cdecl = Load_EVP_PKEY_new;
  EVP_PKEY_up_ref: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_up_ref;
  EVP_PKEY_dup: function(pkey: PEVP_PKEY): PEVP_PKEY; cdecl = Load_EVP_PKEY_dup;
  EVP_PKEY_free: procedure(pkey: PEVP_PKEY); cdecl = Load_EVP_PKEY_free;
  EVP_PKEY_get0_description: function(pkey: PEVP_PKEY): PAnsiChar; cdecl = Load_EVP_PKEY_get0_description;
  EVP_PKEY_get0_provider: function(key: PEVP_PKEY): POSSL_PROVIDER; cdecl = Load_EVP_PKEY_get0_provider;
  d2i_PublicKey: function(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_d2i_PublicKey;
  i2d_PublicKey: function(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_PublicKey;
  d2i_PrivateKey_ex: function(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_d2i_PrivateKey_ex;
  d2i_PrivateKey: function(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_d2i_PrivateKey;
  d2i_AutoPrivateKey_ex: function(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl = Load_d2i_AutoPrivateKey_ex;
  d2i_AutoPrivateKey: function(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_d2i_AutoPrivateKey;
  i2d_PrivateKey: function(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_PrivateKey;
  i2d_PKCS8PrivateKey: function(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_PKCS8PrivateKey;
  i2d_KeyParams: function(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_KeyParams;
  d2i_KeyParams: function(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_d2i_KeyParams;
  i2d_KeyParams_bio: function(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_i2d_KeyParams_bio;
  d2i_KeyParams_bio: function(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; in_: PBIO): PEVP_PKEY; cdecl = Load_d2i_KeyParams_bio;
  EVP_PKEY_copy_parameters: function(to_: PEVP_PKEY; from_: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_copy_parameters;
  EVP_PKEY_missing_parameters: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_missing_parameters;
  EVP_PKEY_save_parameters: function(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_save_parameters;
  EVP_PKEY_parameters_eq: function(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_parameters_eq;
  EVP_PKEY_eq: function(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_eq;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_cmp_parameters(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_cmp_parameters'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_cmp(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_cmp'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_cmp_parameters}
  {$EXTERNALSYM EVP_PKEY_cmp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_cmp_parameters(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_cmp(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_cmp_parameters: function(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_cmp_parameters;
  EVP_PKEY_cmp: function(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_cmp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_print_public(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_print_public';
  function EVP_PKEY_print_private(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_print_private';
  function EVP_PKEY_print_params(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_print_params';
  {$else}
  {$EXTERNALSYM EVP_PKEY_print_public}
  {$EXTERNALSYM EVP_PKEY_print_private}
  {$EXTERNALSYM EVP_PKEY_print_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_print_public(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_print_private(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_print_params(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_print_public: function(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_public;
  EVP_PKEY_print_private: function(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_private;
  EVP_PKEY_print_params: function(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_params;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_STDIO}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_print_public_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_print_public_fp';
  function EVP_PKEY_print_private_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_print_private_fp';
  function EVP_PKEY_print_params_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_print_params_fp';
    {$else}
  {$EXTERNALSYM EVP_PKEY_print_public_fp}
  {$EXTERNALSYM EVP_PKEY_print_private_fp}
  {$EXTERNALSYM EVP_PKEY_print_params_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_print_public_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_print_private_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_print_params_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_print_public_fp: function(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_public_fp;
  EVP_PKEY_print_private_fp: function(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_private_fp;
  EVP_PKEY_print_params_fp: function(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_print_params_fp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_default_digest_nid';
  function EVP_PKEY_get_default_digest_name(pkey: PEVP_PKEY; mdname: PAnsiChar; mdname_sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_default_digest_name';
  function EVP_PKEY_digestsign_supports_digest(pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_digestsign_supports_digest';
  {$else}
  {$EXTERNALSYM EVP_PKEY_get_default_digest_nid}
  {$EXTERNALSYM EVP_PKEY_get_default_digest_name}
  {$EXTERNALSYM EVP_PKEY_digestsign_supports_digest}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_default_digest_name(pkey: PEVP_PKEY; mdname: PAnsiChar; mdname_sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_digestsign_supports_digest(pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_get_default_digest_nid: function(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_default_digest_nid;
  EVP_PKEY_get_default_digest_name: function(pkey: PEVP_PKEY; mdname: PAnsiChar; mdname_sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_default_digest_name;
  EVP_PKEY_digestsign_supports_digest: function(pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_digestsign_supports_digest;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    
    {* For backwards compatibility. Use EVP_PKEY_set1_encoded_public_key in
    * preference
    }
  function EVP_PKEY_set1_tls_encodedpoint(pkey:PEVP_PKEY; pt:Pbyte; ptlen:TOpenSSL_C_SIZET): TOpenSSL_C_INT; inline;
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_set1_encoded_public_key(pkey: PEVP_PKEY; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set1_encoded_public_key';
  {$else}
  {$EXTERNALSYM EVP_PKEY_set1_encoded_public_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_set1_encoded_public_key(pkey: PEVP_PKEY; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_set1_encoded_public_key: function(pkey: PEVP_PKEY; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set1_encoded_public_key;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    
    {* For backwards compatibility. Use EVP_PKEY_get1_encoded_public_key in
    * preference
    }
  function EVP_PKEY_get1_tls_encodedpoint(pkey:PEVP_PKEY; ppt:PPbyte): TOpenSSL_C_SIZET; inline;
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_get1_encoded_public_key(pkey: PEVP_PKEY; ppub: PPbyte): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EVP_PKEY_get1_encoded_public_key';
  { calls methods }
  function EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_param_to_asn1';
  function EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_asn1_to_param';
  { These are used by EVP_CIPHER methods }
  function EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_set_asn1_iv';
  function EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_CIPHER_get_asn1_iv';
  { PKCS5 password based encryption }
  function PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_PBE_keyivgen';
  function PKCS5_PBE_keyivgen_ex(cctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_PBE_keyivgen_ex';
  function PKCS5_PBKDF2_HMAC_SHA1(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_PBKDF2_HMAC_SHA1';
  function PKCS5_PBKDF2_HMAC(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_PBKDF2_HMAC';
  function PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_v2_PBE_keyivgen';
  function PKCS5_v2_PBE_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_v2_PBE_keyivgen_ex';
  {$else}
  {$EXTERNALSYM EVP_PKEY_get1_encoded_public_key}
  {$EXTERNALSYM EVP_CIPHER_param_to_asn1}
  {$EXTERNALSYM EVP_CIPHER_asn1_to_param}
  {$EXTERNALSYM EVP_CIPHER_set_asn1_iv}
  {$EXTERNALSYM EVP_CIPHER_get_asn1_iv}
  {$EXTERNALSYM PKCS5_PBE_keyivgen}
  {$EXTERNALSYM PKCS5_PBE_keyivgen_ex}
  {$EXTERNALSYM PKCS5_PBKDF2_HMAC_SHA1}
  {$EXTERNALSYM PKCS5_PBKDF2_HMAC}
  {$EXTERNALSYM PKCS5_v2_PBE_keyivgen}
  {$EXTERNALSYM PKCS5_v2_PBE_keyivgen_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_get1_encoded_public_key(pkey: PEVP_PKEY; ppub: PPbyte): TOpenSSL_C_SIZET; cdecl;
  function Load_EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  function Load_EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_PBE_keyivgen_ex(cctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_PBKDF2_HMAC_SHA1(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_PBKDF2_HMAC(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_v2_PBE_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_get1_encoded_public_key: function(pkey: PEVP_PKEY; ppub: PPbyte): TOpenSSL_C_SIZET; cdecl = Load_EVP_PKEY_get1_encoded_public_key;
  { calls methods }
  EVP_CIPHER_param_to_asn1: function(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_param_to_asn1;
  EVP_CIPHER_asn1_to_param: function(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_asn1_to_param;
  { These are used by EVP_CIPHER methods }
  EVP_CIPHER_set_asn1_iv: function(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_set_asn1_iv;
  EVP_CIPHER_get_asn1_iv: function(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = Load_EVP_CIPHER_get_asn1_iv;
  { PKCS5 password based encryption }
  PKCS5_PBE_keyivgen: function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS5_PBE_keyivgen;
  PKCS5_PBE_keyivgen_ex: function(cctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PKCS5_PBE_keyivgen_ex;
  PKCS5_PBKDF2_HMAC_SHA1: function(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl = Load_PKCS5_PBKDF2_HMAC_SHA1;
  PKCS5_PBKDF2_HMAC: function(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl = Load_PKCS5_PBKDF2_HMAC;
  PKCS5_v2_PBE_keyivgen: function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS5_v2_PBE_keyivgen;
  PKCS5_v2_PBE_keyivgen_ex: function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PKCS5_v2_PBE_keyivgen_ex;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_SCRYPT}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PBE_scrypt(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_scrypt';
  function EVP_PBE_scrypt_ex(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET; ctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_scrypt_ex';
  function PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_v2_scrypt_keyivgen';
  function PKCS5_v2_scrypt_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS5_v2_scrypt_keyivgen_ex';
    {$else}
  {$EXTERNALSYM EVP_PBE_scrypt}
  {$EXTERNALSYM EVP_PBE_scrypt_ex}
  {$EXTERNALSYM PKCS5_v2_scrypt_keyivgen}
  {$EXTERNALSYM PKCS5_v2_scrypt_keyivgen_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PBE_scrypt(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PBE_scrypt_ex(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET; ctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_PKCS5_v2_scrypt_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_PBE_scrypt: function(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_scrypt;
  EVP_PBE_scrypt_ex: function(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET; ctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_scrypt_ex;
  PKCS5_v2_scrypt_keyivgen: function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_PKCS5_v2_scrypt_keyivgen;
  PKCS5_v2_scrypt_keyivgen_ex: function(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_PKCS5_v2_scrypt_keyivgen_ex;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure PKCS5_PBE_add; cdecl; external CLibCrypto name 'PKCS5_PBE_add';
  function EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_CipherInit';
  function EVP_PBE_CipherInit_ex(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_CipherInit_ex';
  { PBE type }
  { Can appear as the outermost AlgorithmIdentifier }
  {$else}
  {$EXTERNALSYM PKCS5_PBE_add}
  {$EXTERNALSYM EVP_PBE_CipherInit}
  {$EXTERNALSYM EVP_PBE_CipherInit_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_PKCS5_PBE_add; cdecl;
  function Load_EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PBE_CipherInit_ex(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  PKCS5_PBE_add: procedure; cdecl = Load_PKCS5_PBE_add;
  EVP_PBE_CipherInit: function(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_CipherInit;
  EVP_PBE_CipherInit_ex: function(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_CipherInit_ex;
  { PBE type }
  { Can appear as the outermost AlgorithmIdentifier }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_PBE_TYPE_OUTER = $0;
  { Is an PRF type OID }
  EVP_PBE_TYPE_PRF = $1;
  { Is a PKCS#5 v2.0 KDF }
  EVP_PBE_TYPE_KDF = $2;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_alg_add_type';
  function EVP_PBE_alg_add(nid: TOpenSSL_C_INT; cipher: PEVP_CIPHER; md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_alg_add';
  function EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_find';
  function EVP_PBE_find_ex(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN; pkeygen_ex: PPEVP_PBE_KEYGEN_EX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_find_ex';
  procedure EVP_PBE_cleanup; cdecl; external CLibCrypto name 'EVP_PBE_cleanup';
  function EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PBE_get';
  {$else}
  {$EXTERNALSYM EVP_PBE_alg_add_type}
  {$EXTERNALSYM EVP_PBE_alg_add}
  {$EXTERNALSYM EVP_PBE_find}
  {$EXTERNALSYM EVP_PBE_find_ex}
  {$EXTERNALSYM EVP_PBE_cleanup}
  {$EXTERNALSYM EVP_PBE_get}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PBE_alg_add(nid: TOpenSSL_C_INT; cipher: PEVP_CIPHER; md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PBE_find_ex(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN; pkeygen_ex: PPEVP_PBE_KEYGEN_EX): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_PBE_cleanup; cdecl;
  function Load_EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

var
  EVP_PBE_alg_add_type: function(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_alg_add_type;
  EVP_PBE_alg_add: function(nid: TOpenSSL_C_INT; cipher: PEVP_CIPHER; md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_alg_add;
  EVP_PBE_find: function(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_find;
  EVP_PBE_find_ex: function(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN; pkeygen_ex: PPEVP_PBE_KEYGEN_EX): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_find_ex;
  EVP_PBE_cleanup: procedure; cdecl = Load_EVP_PBE_cleanup;
  EVP_PBE_get: function(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PBE_get;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  ASN1_PKEY_ALIAS = $1;
  ASN1_PKEY_DYNAMIC = $2;
  ASN1_PKEY_SIGPARAM_NULL = $4;
  ASN1_PKEY_CTRL_PKCS7_SIGN = $1;
  ASN1_PKEY_CTRL_PKCS7_ENCRYPT = $2;
  ASN1_PKEY_CTRL_DEFAULT_MD_NID = $3;
  ASN1_PKEY_CTRL_CMS_SIGN = $5;
  ASN1_PKEY_CTRL_CMS_ENVELOPE = $7;
  ASN1_PKEY_CTRL_CMS_RI_TYPE = $8;
  ASN1_PKEY_CTRL_SET1_TLS_ENCPT = $9;
  ASN1_PKEY_CTRL_GET1_TLS_ENCPT = $a;
  ASN1_PKEY_CTRL_CMS_IS_RI_TYPE_SUPPORTED = $b;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_6}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_get_count'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_get0'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_find'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_asn1_find_str(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_find_str'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_asn1_add0(ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_add0'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_add_alias'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; pinfo: PPAnsiChar; ppem_str: PPAnsiChar; ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_get0_info'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_get0_asn1(pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_get0_asn1'; deprecated 'Since OpenSSL 3.6';
  function EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; pem_str: PAnsiChar; info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_asn1_new'; deprecated 'Since OpenSSL 3.6';
  procedure EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; src: PEVP_PKEY_ASN1_METHOD); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_copy'; deprecated 'Since OpenSSL 3.6';
  procedure EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_free'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_get_count}
  {$EXTERNALSYM EVP_PKEY_asn1_get0}
  {$EXTERNALSYM EVP_PKEY_asn1_find}
  {$EXTERNALSYM EVP_PKEY_asn1_find_str}
  {$EXTERNALSYM EVP_PKEY_asn1_add0}
  {$EXTERNALSYM EVP_PKEY_asn1_add_alias}
  {$EXTERNALSYM EVP_PKEY_asn1_get0_info}
  {$EXTERNALSYM EVP_PKEY_get0_asn1}
  {$EXTERNALSYM EVP_PKEY_asn1_new}
  {$EXTERNALSYM EVP_PKEY_asn1_copy}
  {$EXTERNALSYM EVP_PKEY_asn1_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
  function Load_EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
  function Load_EVP_PKEY_asn1_find_str(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
  function Load_EVP_PKEY_asn1_add0(ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; pinfo: PPAnsiChar; ppem_str: PPAnsiChar; ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0_asn1(pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl;
  function Load_EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; pem_str: PAnsiChar; info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl;
  procedure Load_EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; src: PEVP_PKEY_ASN1_METHOD); cdecl;
  procedure Load_EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl;

var
  EVP_PKEY_asn1_get_count: function: TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_get_count;
  EVP_PKEY_asn1_get0: function(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_get0;
  EVP_PKEY_asn1_find: function(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_find;
  EVP_PKEY_asn1_find_str: function(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_find_str;
  EVP_PKEY_asn1_add0: function(ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_add0;
  EVP_PKEY_asn1_add_alias: function(to_: TOpenSSL_C_INT; from_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_add_alias;
  EVP_PKEY_asn1_get0_info: function(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; pinfo: PPAnsiChar; ppem_str: PPAnsiChar; ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_asn1_get0_info;
  EVP_PKEY_get0_asn1: function(pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_get0_asn1;
  EVP_PKEY_asn1_new: function(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; pem_str: PAnsiChar; info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl = Load_EVP_PKEY_asn1_new;
  EVP_PKEY_asn1_copy: procedure(dst: PEVP_PKEY_ASN1_METHOD; src: PEVP_PKEY_ASN1_METHOD); cdecl = Load_EVP_PKEY_asn1_copy;
  EVP_PKEY_asn1_free: procedure(ameth: PEVP_PKEY_ASN1_METHOD); cdecl = Load_EVP_PKEY_asn1_free;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType039 = ^TFuncType039;
  PPFuncType039 = ^PFuncType039;
  PFuncType040 = ^TFuncType040;
  PPFuncType040 = ^PFuncType040;
  PFuncType041 = ^TFuncType041;
  PPFuncType041 = ^PFuncType041;
  PFuncType042 = ^TFuncType042;
  PPFuncType042 = ^PFuncType042;
  PFuncType043 = ^TFuncType043;
  PPFuncType043 = ^PFuncType043;
  PFuncType044 = ^TFuncType044;
  PPFuncType044 = ^PFuncType044;
  {end of auto-generated forward references}

  TFuncType039 = function(pk: PEVP_PKEY; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
  TFuncType040 = function(pub: PX509_PUBKEY; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType041 = function(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType042 = function(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
  TFuncType043 = function(pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType044 = function(pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; pub_decode: TFuncType039; pub_encode: TFuncType040; pub_cmp: TFuncType041; pub_print: TFuncType042; pkey_size: TFuncType043; pkey_bits: TFuncType044); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_public'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_public}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; pub_decode: TFuncType039; pub_encode: TFuncType040; pub_cmp: TFuncType041; pub_print: TFuncType042; pkey_size: TFuncType043; pkey_bits: TFuncType044); cdecl;

var
  EVP_PKEY_asn1_set_public: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pub_decode: TFuncType039; pub_encode: TFuncType040; pub_cmp: TFuncType041; pub_print: TFuncType042; pkey_size: TFuncType043; pkey_bits: TFuncType044); cdecl = Load_EVP_PKEY_asn1_set_public;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType045 = ^TFuncType045;
  PPFuncType045 = ^PFuncType045;
  PFuncType046 = ^TFuncType046;
  PPFuncType046 = ^PFuncType046;
  PFuncType047 = ^TFuncType047;
  PPFuncType047 = ^PFuncType047;
  {end of auto-generated forward references}

  TFuncType045 = function(pk: PEVP_PKEY; p8inf: PPKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
  TFuncType046 = function(p8: PPKCS8_PRIV_KEY_INFO; pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType047 = function(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; priv_decode: TFuncType045; priv_encode: TFuncType046; priv_print: TFuncType047); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_private'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_private}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; priv_decode: TFuncType045; priv_encode: TFuncType046; priv_print: TFuncType047); cdecl;

var
  EVP_PKEY_asn1_set_private: procedure(ameth: PEVP_PKEY_ASN1_METHOD; priv_decode: TFuncType045; priv_encode: TFuncType046; priv_print: TFuncType047); cdecl = Load_EVP_PKEY_asn1_set_private;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType048 = ^TFuncType048;
  PPFuncType048 = ^PFuncType048;
  PFuncType049 = ^TFuncType049;
  PPFuncType049 = ^PFuncType049;
  PFuncType050 = ^TFuncType050;
  PPFuncType050 = ^PFuncType050;
  PFuncType051 = ^TFuncType051;
  PPFuncType051 = ^PFuncType051;
  PFuncType052 = ^TFuncType052;
  PPFuncType052 = ^PFuncType052;
  PFuncType053 = ^TFuncType053;
  PPFuncType053 = ^PFuncType053;
  {end of auto-generated forward references}

  TFuncType048 = function(pkey: PEVP_PKEY; pder: PPbyte; derlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TFuncType049 = function(pkey: PEVP_PKEY; pder: PPbyte): TOpenSSL_C_INT; cdecl;
  TFuncType050 = function(pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType051 = function(to_: PEVP_PKEY; from_: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType052 = function(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType053 = function(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; param_decode: TFuncType048; param_encode: TFuncType049; param_missing: TFuncType050; param_copy: TFuncType051; param_cmp: TFuncType052; param_print: TFuncType053); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_param'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_param}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; param_decode: TFuncType048; param_encode: TFuncType049; param_missing: TFuncType050; param_copy: TFuncType051; param_cmp: TFuncType052; param_print: TFuncType053); cdecl;

var
  EVP_PKEY_asn1_set_param: procedure(ameth: PEVP_PKEY_ASN1_METHOD; param_decode: TFuncType048; param_encode: TFuncType049; param_missing: TFuncType050; param_copy: TFuncType051; param_cmp: TFuncType052; param_print: TFuncType053); cdecl = Load_EVP_PKEY_asn1_set_param;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType054 = ^TFuncType054;
  PPFuncType054 = ^PFuncType054;
  {end of auto-generated forward references}

  TFuncType054 = procedure(pkey: PEVP_PKEY); cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; pkey_free: TFuncType054); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_free'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_free}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; pkey_free: TFuncType054); cdecl;

var
  EVP_PKEY_asn1_set_free: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pkey_free: TFuncType054); cdecl = Load_EVP_PKEY_asn1_set_free;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType055 = ^TFuncType055;
  PPFuncType055 = ^PFuncType055;
  {end of auto-generated forward references}

  TFuncType055 = function(pkey: PEVP_PKEY; op: TOpenSSL_C_INT; arg1: TOpenSSL_C_INT; arg2: pointer): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; pkey_ctrl: TFuncType055); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_ctrl'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; pkey_ctrl: TFuncType055); cdecl;

var
  EVP_PKEY_asn1_set_ctrl: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pkey_ctrl: TFuncType055); cdecl = Load_EVP_PKEY_asn1_set_ctrl;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType056 = ^TFuncType056;
  PPFuncType056 = ^PFuncType056;
  PFuncType057 = ^TFuncType057;
  PPFuncType057 = ^PFuncType057;
  {end of auto-generated forward references}

  TFuncType056 = function(ctx: PEVP_MD_CTX; it: PASN1_ITEM; data: pointer; a: PX509_ALGOR; sig: PASN1_BIT_STRING; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  TFuncType057 = function(ctx: PEVP_MD_CTX; it: PASN1_ITEM; data: pointer; alg1: PX509_ALGOR; alg2: PX509_ALGOR; sig: PASN1_BIT_STRING): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; item_verify: TFuncType056; item_sign: TFuncType057); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_item'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_item}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; item_verify: TFuncType056; item_sign: TFuncType057); cdecl;

var
  EVP_PKEY_asn1_set_item: procedure(ameth: PEVP_PKEY_ASN1_METHOD; item_verify: TFuncType056; item_sign: TFuncType057); cdecl = Load_EVP_PKEY_asn1_set_item;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType058 = ^TFuncType058;
  PPFuncType058 = ^PFuncType058;
  {end of auto-generated forward references}

  TFuncType058 = function(siginf: PX509_SIG_INFO; alg: PX509_ALGOR; sig: PASN1_STRING): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; siginf_set: TFuncType058); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_siginf'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_siginf}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; siginf_set: TFuncType058); cdecl;

var
  EVP_PKEY_asn1_set_siginf: procedure(ameth: PEVP_PKEY_ASN1_METHOD; siginf_set: TFuncType058); cdecl = Load_EVP_PKEY_asn1_set_siginf;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType059 = ^TFuncType059;
  PPFuncType059 = ^PFuncType059;
  {end of auto-generated forward references}

  TFuncType059 = function(pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_check: TFuncType059); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_check'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_check: TFuncType059); cdecl;

var
  EVP_PKEY_asn1_set_check: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pkey_check: TFuncType059); cdecl = Load_EVP_PKEY_asn1_set_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType060 = ^TFuncType060;
  PPFuncType060 = ^PFuncType060;
  {end of auto-generated forward references}

  TFuncType060 = function(pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_pub_check: TFuncType060); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_public_check'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_public_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_pub_check: TFuncType060); cdecl;

var
  EVP_PKEY_asn1_set_public_check: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pkey_pub_check: TFuncType060); cdecl = Load_EVP_PKEY_asn1_set_public_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType061 = ^TFuncType061;
  PPFuncType061 = ^PFuncType061;
  {end of auto-generated forward references}

  TFuncType061 = function(pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_param_check: TFuncType061); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_param_check'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_param_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_param_check: TFuncType061); cdecl;

var
  EVP_PKEY_asn1_set_param_check: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pkey_param_check: TFuncType061); cdecl = Load_EVP_PKEY_asn1_set_param_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType062 = ^TFuncType062;
  PPFuncType062 = ^PFuncType062;
  {end of auto-generated forward references}

  TFuncType062 = function(pk: PEVP_PKEY; priv: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; set_priv_key: TFuncType062); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_set_priv_key'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_set_priv_key}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; set_priv_key: TFuncType062); cdecl;

var
  EVP_PKEY_asn1_set_set_priv_key: procedure(ameth: PEVP_PKEY_ASN1_METHOD; set_priv_key: TFuncType062); cdecl = Load_EVP_PKEY_asn1_set_set_priv_key;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType063 = ^TFuncType063;
  PPFuncType063 = ^PFuncType063;
  {end of auto-generated forward references}

  TFuncType063 = function(pk: PEVP_PKEY; pub: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; set_pub_key: TFuncType063); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_set_pub_key'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_set_pub_key}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; set_pub_key: TFuncType063); cdecl;

var
  EVP_PKEY_asn1_set_set_pub_key: procedure(ameth: PEVP_PKEY_ASN1_METHOD; set_pub_key: TFuncType063); cdecl = Load_EVP_PKEY_asn1_set_set_pub_key;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType064 = ^TFuncType064;
  PPFuncType064 = ^PFuncType064;
  {end of auto-generated forward references}

  TFuncType064 = function(pk: PEVP_PKEY; priv: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; get_priv_key: TFuncType064); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_get_priv_key'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_get_priv_key}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; get_priv_key: TFuncType064); cdecl;

var
  EVP_PKEY_asn1_set_get_priv_key: procedure(ameth: PEVP_PKEY_ASN1_METHOD; get_priv_key: TFuncType064); cdecl = Load_EVP_PKEY_asn1_set_get_priv_key;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType065 = ^TFuncType065;
  PPFuncType065 = ^PFuncType065;
  {end of auto-generated forward references}

  TFuncType065 = function(pk: PEVP_PKEY; pub: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; get_pub_key: TFuncType065); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_get_pub_key'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_get_pub_key}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; get_pub_key: TFuncType065); cdecl;

var
  EVP_PKEY_asn1_set_get_pub_key: procedure(ameth: PEVP_PKEY_ASN1_METHOD; get_pub_key: TFuncType065); cdecl = Load_EVP_PKEY_asn1_set_get_pub_key;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType066 = ^TFuncType066;
  PPFuncType066 = ^PFuncType066;
  {end of auto-generated forward references}

  TFuncType066 = function(pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; pkey_security_bits: TFuncType066); cdecl; external CLibCrypto name 'EVP_PKEY_asn1_set_security_bits'; deprecated 'Since OpenSSL 3.6';
    {$else}
  {$EXTERNALSYM EVP_PKEY_asn1_set_security_bits}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; pkey_security_bits: TFuncType066); cdecl;

var
  EVP_PKEY_asn1_set_security_bits: procedure(ameth: PEVP_PKEY_ASN1_METHOD; pkey_security_bits: TFuncType066); cdecl = Load_EVP_PKEY_asn1_set_security_bits;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  { OPENSSL_NO_DEPRECATED_3_6 }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_get_signature_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_signature_md';
  function EVP_PKEY_CTX_set_signature_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_signature_md';
  function EVP_PKEY_CTX_set1_id(ctx: PEVP_PKEY_CTX; id: pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set1_id';
  function EVP_PKEY_CTX_get1_id(ctx: PEVP_PKEY_CTX; id: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get1_id';
  function EVP_PKEY_CTX_get1_id_len(ctx: PEVP_PKEY_CTX; id_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get1_id_len';
  function EVP_PKEY_CTX_set_kem_op(ctx: PEVP_PKEY_CTX; op: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_kem_op';
  function EVP_PKEY_get0_type_name(key: PEVP_PKEY): PAnsiChar; cdecl; external CLibCrypto name 'EVP_PKEY_get0_type_name';
  {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_get_signature_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set_signature_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set1_id}
  {$EXTERNALSYM EVP_PKEY_CTX_get1_id}
  {$EXTERNALSYM EVP_PKEY_CTX_get1_id_len}
  {$EXTERNALSYM EVP_PKEY_CTX_set_kem_op}
  {$EXTERNALSYM EVP_PKEY_get0_type_name}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_get_signature_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_signature_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set1_id(ctx: PEVP_PKEY_CTX; id: pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get1_id(ctx: PEVP_PKEY_CTX; id: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get1_id_len(ctx: PEVP_PKEY_CTX; id_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_kem_op(ctx: PEVP_PKEY_CTX; op: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get0_type_name(key: PEVP_PKEY): PAnsiChar; cdecl;

var
  EVP_PKEY_CTX_get_signature_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_signature_md;
  EVP_PKEY_CTX_set_signature_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_signature_md;
  EVP_PKEY_CTX_set1_id: function(ctx: PEVP_PKEY_CTX; id: pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set1_id;
  EVP_PKEY_CTX_get1_id: function(ctx: PEVP_PKEY_CTX; id: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get1_id;
  EVP_PKEY_CTX_get1_id_len: function(ctx: PEVP_PKEY_CTX; id_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get1_id_len;
  EVP_PKEY_CTX_set_kem_op: function(ctx: PEVP_PKEY_CTX; op: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_kem_op;
  EVP_PKEY_get0_type_name: function(key: PEVP_PKEY): PAnsiChar; cdecl = Load_EVP_PKEY_get0_type_name;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_PKEY_OP_UNDEFINED = 0;
  EVP_PKEY_OP_PARAMGEN = 1 shl 1;
  EVP_PKEY_OP_KEYGEN = 1 shl 2;
  EVP_PKEY_OP_FROMDATA = 1 shl 3;
  EVP_PKEY_OP_SIGN = 1 shl 4;
  EVP_PKEY_OP_VERIFY = 1 shl 5;
  EVP_PKEY_OP_VERIFYRECOVER = 1 shl 6;
  EVP_PKEY_OP_SIGNCTX = 1 shl 7;
  EVP_PKEY_OP_VERIFYCTX = 1 shl 8;
  EVP_PKEY_OP_ENCRYPT = 1 shl 9;
  EVP_PKEY_OP_DECRYPT = 1 shl 10;
  EVP_PKEY_OP_DERIVE = 1 shl 11;
  EVP_PKEY_OP_ENCAPSULATE = 1 shl 12;
  EVP_PKEY_OP_DECAPSULATE = 1 shl 13;
  EVP_PKEY_OP_SIGNMSG = 1 shl 14;
  EVP_PKEY_OP_VERIFYMSG = 1 shl 15;
  { Update the following when adding new EVP_PKEY_OPs }
  EVP_PKEY_OP_ALL = (1 shl 16)-1;
  EVP_PKEY_OP_TYPE_SIG = (((((EVP_PKEY_OP_SIGN or EVP_PKEY_OP_SIGNMSG) or EVP_PKEY_OP_VERIFY) or EVP_PKEY_OP_VERIFYMSG) or EVP_PKEY_OP_VERIFYRECOVER) or EVP_PKEY_OP_SIGNCTX) or EVP_PKEY_OP_VERIFYCTX;
  EVP_PKEY_OP_TYPE_CRYPT = EVP_PKEY_OP_ENCRYPT or EVP_PKEY_OP_DECRYPT;
  EVP_PKEY_OP_TYPE_DERIVE = EVP_PKEY_OP_DERIVE;
  EVP_PKEY_OP_TYPE_DATA = EVP_PKEY_OP_FROMDATA;
  EVP_PKEY_OP_TYPE_KEM = EVP_PKEY_OP_ENCAPSULATE or EVP_PKEY_OP_DECAPSULATE;
  EVP_PKEY_OP_TYPE_GEN = EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN;
  EVP_PKEY_OP_TYPE_NOGEN = EVP_PKEY_OP_ALL and ( not (EVP_PKEY_OP_TYPE_GEN));


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_mac_key(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_mac_key';
  {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_set_mac_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_mac_key(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_mac_key: function(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_mac_key;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_PKEY_CTRL_MD = 1;
  EVP_PKEY_CTRL_PEER_KEY = 2;
  EVP_PKEY_CTRL_SET_MAC_KEY = 6;
  EVP_PKEY_CTRL_DIGESTINIT = 7;
  { Used by GOST key encryption in TLS }
  EVP_PKEY_CTRL_SET_IV = 8;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;
  EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;
  EVP_PKEY_CTRL_PKCS7_SIGN = 5;
  EVP_PKEY_CTRL_CMS_ENCRYPT = 9;
  EVP_PKEY_CTRL_CMS_DECRYPT = 10;
  EVP_PKEY_CTRL_CMS_SIGN = 11;
  {$endif}

const
  EVP_PKEY_CTRL_CIPHER = 12;
  EVP_PKEY_CTRL_GET_MD = 13;
  EVP_PKEY_CTRL_SET_DIGEST_SIZE = 14;
  EVP_PKEY_CTRL_SET1_ID = 15;
  EVP_PKEY_CTRL_GET1_ID = 16;
  EVP_PKEY_CTRL_GET1_ID_LEN = 17;
  EVP_PKEY_ALG_CTRL = $1000;
  EVP_PKEY_FLAG_AUTOARGLEN = 2;
  
  {* Method handles all operations: don't assume any digest related defaults.
  }
  EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_meth_find'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_meth_new'; deprecated 'Since OpenSSL 3.0';
  procedure EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; meth: PEVP_PKEY_METHOD); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get0_info'; deprecated 'Since OpenSSL 3.0';
  procedure EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; src: PEVP_PKEY_METHOD); cdecl; external CLibCrypto name 'EVP_PKEY_meth_copy'; deprecated 'Since OpenSSL 3.0';
  procedure EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl; external CLibCrypto name 'EVP_PKEY_meth_free'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_meth_add0(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_meth_add0'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_meth_remove(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_meth_remove'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_count'; deprecated 'Since OpenSSL 3.0';
  function EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl; external CLibCrypto name 'EVP_PKEY_meth_get0'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_find}
  {$EXTERNALSYM EVP_PKEY_meth_new}
  {$EXTERNALSYM EVP_PKEY_meth_get0_info}
  {$EXTERNALSYM EVP_PKEY_meth_copy}
  {$EXTERNALSYM EVP_PKEY_meth_free}
  {$EXTERNALSYM EVP_PKEY_meth_add0}
  {$EXTERNALSYM EVP_PKEY_meth_remove}
  {$EXTERNALSYM EVP_PKEY_meth_get_count}
  {$EXTERNALSYM EVP_PKEY_meth_get0}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
  function Load_EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
  procedure Load_EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; meth: PEVP_PKEY_METHOD); cdecl;
  procedure Load_EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; src: PEVP_PKEY_METHOD); cdecl;
  procedure Load_EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl;
  function Load_EVP_PKEY_meth_add0(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_meth_remove(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl;
  function Load_EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl;

var
  EVP_PKEY_meth_find: function(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = Load_EVP_PKEY_meth_find;
  EVP_PKEY_meth_new: function(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = Load_EVP_PKEY_meth_new;
  EVP_PKEY_meth_get0_info: procedure(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; meth: PEVP_PKEY_METHOD); cdecl = Load_EVP_PKEY_meth_get0_info;
  EVP_PKEY_meth_copy: procedure(dst: PEVP_PKEY_METHOD; src: PEVP_PKEY_METHOD); cdecl = Load_EVP_PKEY_meth_copy;
  EVP_PKEY_meth_free: procedure(pmeth: PEVP_PKEY_METHOD); cdecl = Load_EVP_PKEY_meth_free;
  EVP_PKEY_meth_add0: function(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_meth_add0;
  EVP_PKEY_meth_remove: function(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_meth_remove;
  EVP_PKEY_meth_get_count: function: TOpenSSL_C_SIZET; cdecl = Load_EVP_PKEY_meth_get_count;
  EVP_PKEY_meth_get0: function(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl = Load_EVP_PKEY_meth_get0;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_KEYMGMT_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYMGMT; cdecl; external CLibCrypto name 'EVP_KEYMGMT_fetch';
  function EVP_KEYMGMT_up_ref(keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEYMGMT_up_ref';
  procedure EVP_KEYMGMT_free(keymgmt: PEVP_KEYMGMT); cdecl; external CLibCrypto name 'EVP_KEYMGMT_free';
  function EVP_KEYMGMT_get0_provider(keymgmt: PEVP_KEYMGMT): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_KEYMGMT_get0_provider';
  function EVP_KEYMGMT_get0_name(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KEYMGMT_get0_name';
  function EVP_KEYMGMT_get0_description(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KEYMGMT_get0_description';
  function EVP_KEYMGMT_is_a(keymgmt: PEVP_KEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEYMGMT_is_a';
  {$else}
  {$EXTERNALSYM EVP_KEYMGMT_fetch}
  {$EXTERNALSYM EVP_KEYMGMT_up_ref}
  {$EXTERNALSYM EVP_KEYMGMT_free}
  {$EXTERNALSYM EVP_KEYMGMT_get0_provider}
  {$EXTERNALSYM EVP_KEYMGMT_get0_name}
  {$EXTERNALSYM EVP_KEYMGMT_get0_description}
  {$EXTERNALSYM EVP_KEYMGMT_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_KEYMGMT_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYMGMT; cdecl;
  function Load_EVP_KEYMGMT_up_ref(keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_KEYMGMT_free(keymgmt: PEVP_KEYMGMT); cdecl;
  function Load_EVP_KEYMGMT_get0_provider(keymgmt: PEVP_KEYMGMT): POSSL_PROVIDER; cdecl;
  function Load_EVP_KEYMGMT_get0_name(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl;
  function Load_EVP_KEYMGMT_get0_description(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl;
  function Load_EVP_KEYMGMT_is_a(keymgmt: PEVP_KEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_KEYMGMT_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYMGMT; cdecl = Load_EVP_KEYMGMT_fetch;
  EVP_KEYMGMT_up_ref: function(keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl = Load_EVP_KEYMGMT_up_ref;
  EVP_KEYMGMT_free: procedure(keymgmt: PEVP_KEYMGMT); cdecl = Load_EVP_KEYMGMT_free;
  EVP_KEYMGMT_get0_provider: function(keymgmt: PEVP_KEYMGMT): POSSL_PROVIDER; cdecl = Load_EVP_KEYMGMT_get0_provider;
  EVP_KEYMGMT_get0_name: function(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl = Load_EVP_KEYMGMT_get0_name;
  EVP_KEYMGMT_get0_description: function(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl = Load_EVP_KEYMGMT_get0_description;
  EVP_KEYMGMT_is_a: function(keymgmt: PEVP_KEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_KEYMGMT_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType067 = ^TFuncType067;
  PPFuncType067 = ^PFuncType067;
  {end of auto-generated forward references}

  TFuncType067 = procedure(keymgmt: PEVP_KEYMGMT; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_KEYMGMT_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType067; arg: pointer); cdecl; external CLibCrypto name 'EVP_KEYMGMT_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_KEYMGMT_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_KEYMGMT_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType067; arg: pointer); cdecl;

var
  EVP_KEYMGMT_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType067; arg: pointer); cdecl = Load_EVP_KEYMGMT_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType068 = ^TFuncType068;
  PPFuncType068 = ^PFuncType068;
  {end of auto-generated forward references}

  TFuncType068 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_KEYMGMT_names_do_all(keymgmt: PEVP_KEYMGMT; fn: TFuncType068; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEYMGMT_names_do_all';
  function EVP_KEYMGMT_gettable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEYMGMT_gettable_params';
  function EVP_KEYMGMT_settable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEYMGMT_settable_params';
  function EVP_KEYMGMT_gen_settable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEYMGMT_gen_settable_params';
  function EVP_KEYMGMT_gen_gettable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEYMGMT_gen_gettable_params';
  function EVP_SKEYMGMT_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SKEYMGMT; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_fetch';
  function EVP_SKEYMGMT_up_ref(keymgmt: PEVP_SKEYMGMT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_up_ref';
  procedure EVP_SKEYMGMT_free(keymgmt: PEVP_SKEYMGMT); cdecl; external CLibCrypto name 'EVP_SKEYMGMT_free';
  function EVP_SKEYMGMT_get0_provider(keymgmt: PEVP_SKEYMGMT): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_get0_provider';
  function EVP_SKEYMGMT_get0_name(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_get0_name';
  function EVP_SKEYMGMT_get0_description(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_get0_description';
  function EVP_SKEYMGMT_is_a(keymgmt: PEVP_SKEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_is_a';
  {$else}
  {$EXTERNALSYM EVP_KEYMGMT_names_do_all}
  {$EXTERNALSYM EVP_KEYMGMT_gettable_params}
  {$EXTERNALSYM EVP_KEYMGMT_settable_params}
  {$EXTERNALSYM EVP_KEYMGMT_gen_settable_params}
  {$EXTERNALSYM EVP_KEYMGMT_gen_gettable_params}
  {$EXTERNALSYM EVP_SKEYMGMT_fetch}
  {$EXTERNALSYM EVP_SKEYMGMT_up_ref}
  {$EXTERNALSYM EVP_SKEYMGMT_free}
  {$EXTERNALSYM EVP_SKEYMGMT_get0_provider}
  {$EXTERNALSYM EVP_SKEYMGMT_get0_name}
  {$EXTERNALSYM EVP_SKEYMGMT_get0_description}
  {$EXTERNALSYM EVP_SKEYMGMT_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_KEYMGMT_names_do_all(keymgmt: PEVP_KEYMGMT; fn: TFuncType068; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KEYMGMT_gettable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
  function Load_EVP_KEYMGMT_settable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
  function Load_EVP_KEYMGMT_gen_settable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
  function Load_EVP_KEYMGMT_gen_gettable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
  function Load_EVP_SKEYMGMT_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SKEYMGMT; cdecl;
  function Load_EVP_SKEYMGMT_up_ref(keymgmt: PEVP_SKEYMGMT): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_SKEYMGMT_free(keymgmt: PEVP_SKEYMGMT); cdecl;
  function Load_EVP_SKEYMGMT_get0_provider(keymgmt: PEVP_SKEYMGMT): POSSL_PROVIDER; cdecl;
  function Load_EVP_SKEYMGMT_get0_name(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl;
  function Load_EVP_SKEYMGMT_get0_description(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl;
  function Load_EVP_SKEYMGMT_is_a(keymgmt: PEVP_SKEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  EVP_KEYMGMT_names_do_all: function(keymgmt: PEVP_KEYMGMT; fn: TFuncType068; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_KEYMGMT_names_do_all;
  EVP_KEYMGMT_gettable_params: function(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl = Load_EVP_KEYMGMT_gettable_params;
  EVP_KEYMGMT_settable_params: function(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl = Load_EVP_KEYMGMT_settable_params;
  EVP_KEYMGMT_gen_settable_params: function(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl = Load_EVP_KEYMGMT_gen_settable_params;
  EVP_KEYMGMT_gen_gettable_params: function(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl = Load_EVP_KEYMGMT_gen_gettable_params;
  EVP_SKEYMGMT_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SKEYMGMT; cdecl = Load_EVP_SKEYMGMT_fetch;
  EVP_SKEYMGMT_up_ref: function(keymgmt: PEVP_SKEYMGMT): TOpenSSL_C_INT; cdecl = Load_EVP_SKEYMGMT_up_ref;
  EVP_SKEYMGMT_free: procedure(keymgmt: PEVP_SKEYMGMT); cdecl = Load_EVP_SKEYMGMT_free;
  EVP_SKEYMGMT_get0_provider: function(keymgmt: PEVP_SKEYMGMT): POSSL_PROVIDER; cdecl = Load_EVP_SKEYMGMT_get0_provider;
  EVP_SKEYMGMT_get0_name: function(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl = Load_EVP_SKEYMGMT_get0_name;
  EVP_SKEYMGMT_get0_description: function(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl = Load_EVP_SKEYMGMT_get0_description;
  EVP_SKEYMGMT_is_a: function(keymgmt: PEVP_SKEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_SKEYMGMT_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType069 = ^TFuncType069;
  PPFuncType069 = ^PFuncType069;
  {end of auto-generated forward references}

  TFuncType069 = procedure(keymgmt: PEVP_SKEYMGMT; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_SKEYMGMT_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType069; arg: pointer); cdecl; external CLibCrypto name 'EVP_SKEYMGMT_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_SKEYMGMT_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_SKEYMGMT_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType069; arg: pointer); cdecl;

var
  EVP_SKEYMGMT_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType069; arg: pointer); cdecl = Load_EVP_SKEYMGMT_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType070 = ^TFuncType070;
  PPFuncType070 = ^PFuncType070;
  {end of auto-generated forward references}

  TFuncType070 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_SKEYMGMT_names_do_all(keymgmt: PEVP_SKEYMGMT; fn: TFuncType070; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_names_do_all';
  function EVP_SKEYMGMT_get0_gen_settable_params(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_get0_gen_settable_params';
  function EVP_SKEYMGMT_get0_imp_settable_params(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_SKEYMGMT_get0_imp_settable_params';
  function EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_new';
  function EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_new_id';
  function EVP_PKEY_CTX_new_from_name(libctx: POSSL_LIB_CTX; name: PAnsiChar; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_new_from_name';
  function EVP_PKEY_CTX_new_from_pkey(libctx: POSSL_LIB_CTX; pkey: PEVP_PKEY; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_new_from_pkey';
  function EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_dup';
  procedure EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl; external CLibCrypto name 'EVP_PKEY_CTX_free';
  function EVP_PKEY_CTX_is_a(ctx: PEVP_PKEY_CTX; keytype: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_is_a';
  function EVP_PKEY_CTX_get_params(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_params';
  function EVP_PKEY_CTX_gettable_params(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_gettable_params';
  function EVP_PKEY_CTX_set_params(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_params';
  function EVP_PKEY_CTX_settable_params(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_settable_params';
  function EVP_PKEY_CTX_set_algor_params(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_algor_params';
  function EVP_PKEY_CTX_get_algor_params(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_algor_params';
  function EVP_PKEY_CTX_get_algor(ctx: PEVP_PKEY_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_algor';
  function EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_ctrl';
  function EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; type_: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_ctrl_str';
  function EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_ctrl_uint64';
  function EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_str2ctrl';
  function EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; hex: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_hex2ctrl';
  function EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; md: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_md';
  function EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_operation';
  procedure EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set0_keygen_info';
  function EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; key: Pbyte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_new_mac_key';
  function EVP_PKEY_new_raw_private_key_ex(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_new_raw_private_key_ex';
  function EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_new_raw_private_key';
  function EVP_PKEY_new_raw_public_key_ex(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_new_raw_public_key_ex';
  function EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_new_raw_public_key';
  function EVP_PKEY_get_raw_private_key(pkey: PEVP_PKEY; priv: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_raw_private_key';
  function EVP_PKEY_get_raw_public_key(pkey: PEVP_PKEY; pub: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_raw_public_key';
  {$else}
  {$EXTERNALSYM EVP_SKEYMGMT_names_do_all}
  {$EXTERNALSYM EVP_SKEYMGMT_get0_gen_settable_params}
  {$EXTERNALSYM EVP_SKEYMGMT_get0_imp_settable_params}
  {$EXTERNALSYM EVP_PKEY_CTX_new}
  {$EXTERNALSYM EVP_PKEY_CTX_new_id}
  {$EXTERNALSYM EVP_PKEY_CTX_new_from_name}
  {$EXTERNALSYM EVP_PKEY_CTX_new_from_pkey}
  {$EXTERNALSYM EVP_PKEY_CTX_dup}
  {$EXTERNALSYM EVP_PKEY_CTX_free}
  {$EXTERNALSYM EVP_PKEY_CTX_is_a}
  {$EXTERNALSYM EVP_PKEY_CTX_get_params}
  {$EXTERNALSYM EVP_PKEY_CTX_gettable_params}
  {$EXTERNALSYM EVP_PKEY_CTX_set_params}
  {$EXTERNALSYM EVP_PKEY_CTX_settable_params}
  {$EXTERNALSYM EVP_PKEY_CTX_set_algor_params}
  {$EXTERNALSYM EVP_PKEY_CTX_get_algor_params}
  {$EXTERNALSYM EVP_PKEY_CTX_get_algor}
  {$EXTERNALSYM EVP_PKEY_CTX_ctrl}
  {$EXTERNALSYM EVP_PKEY_CTX_ctrl_str}
  {$EXTERNALSYM EVP_PKEY_CTX_ctrl_uint64}
  {$EXTERNALSYM EVP_PKEY_CTX_str2ctrl}
  {$EXTERNALSYM EVP_PKEY_CTX_hex2ctrl}
  {$EXTERNALSYM EVP_PKEY_CTX_md}
  {$EXTERNALSYM EVP_PKEY_CTX_get_operation}
  {$EXTERNALSYM EVP_PKEY_CTX_set0_keygen_info}
  {$EXTERNALSYM EVP_PKEY_new_mac_key}
  {$EXTERNALSYM EVP_PKEY_new_raw_private_key_ex}
  {$EXTERNALSYM EVP_PKEY_new_raw_private_key}
  {$EXTERNALSYM EVP_PKEY_new_raw_public_key_ex}
  {$EXTERNALSYM EVP_PKEY_new_raw_public_key}
  {$EXTERNALSYM EVP_PKEY_get_raw_private_key}
  {$EXTERNALSYM EVP_PKEY_get_raw_public_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_SKEYMGMT_names_do_all(keymgmt: PEVP_SKEYMGMT; fn: TFuncType070; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SKEYMGMT_get0_gen_settable_params(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl;
  function Load_EVP_SKEYMGMT_get0_imp_settable_params(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl;
  function Load_EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl;
  function Load_EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl;
  function Load_EVP_PKEY_CTX_new_from_name(libctx: POSSL_LIB_CTX; name: PAnsiChar; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl;
  function Load_EVP_PKEY_CTX_new_from_pkey(libctx: POSSL_LIB_CTX; pkey: PEVP_PKEY; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl;
  function Load_EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl;
  procedure Load_EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl;
  function Load_EVP_PKEY_CTX_is_a(ctx: PEVP_PKEY_CTX; keytype: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_params(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_gettable_params(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_PKEY_CTX_set_params(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_settable_params(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl;
  function Load_EVP_PKEY_CTX_set_algor_params(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_algor_params(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_algor(ctx: PEVP_PKEY_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; type_: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; hex: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; md: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl;
  function Load_EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; key: Pbyte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_new_raw_private_key_ex(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_new_raw_public_key_ex(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_get_raw_private_key(pkey: PEVP_PKEY; priv: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_raw_public_key(pkey: PEVP_PKEY; pub: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

var
  EVP_SKEYMGMT_names_do_all: function(keymgmt: PEVP_SKEYMGMT; fn: TFuncType070; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_SKEYMGMT_names_do_all;
  EVP_SKEYMGMT_get0_gen_settable_params: function(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl = Load_EVP_SKEYMGMT_get0_gen_settable_params;
  EVP_SKEYMGMT_get0_imp_settable_params: function(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl = Load_EVP_SKEYMGMT_get0_imp_settable_params;
  EVP_PKEY_CTX_new: function(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_new;
  EVP_PKEY_CTX_new_id: function(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_new_id;
  EVP_PKEY_CTX_new_from_name: function(libctx: POSSL_LIB_CTX; name: PAnsiChar; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_new_from_name;
  EVP_PKEY_CTX_new_from_pkey: function(libctx: POSSL_LIB_CTX; pkey: PEVP_PKEY; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_new_from_pkey;
  EVP_PKEY_CTX_dup: function(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl = Load_EVP_PKEY_CTX_dup;
  EVP_PKEY_CTX_free: procedure(ctx: PEVP_PKEY_CTX); cdecl = Load_EVP_PKEY_CTX_free;
  EVP_PKEY_CTX_is_a: function(ctx: PEVP_PKEY_CTX; keytype: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_is_a;
  EVP_PKEY_CTX_get_params: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_params;
  EVP_PKEY_CTX_gettable_params: function(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl = Load_EVP_PKEY_CTX_gettable_params;
  EVP_PKEY_CTX_set_params: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_params;
  EVP_PKEY_CTX_settable_params: function(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl = Load_EVP_PKEY_CTX_settable_params;
  EVP_PKEY_CTX_set_algor_params: function(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_algor_params;
  EVP_PKEY_CTX_get_algor_params: function(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_algor_params;
  EVP_PKEY_CTX_get_algor: function(ctx: PEVP_PKEY_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_algor;
  EVP_PKEY_CTX_ctrl: function(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_ctrl;
  EVP_PKEY_CTX_ctrl_str: function(ctx: PEVP_PKEY_CTX; type_: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_ctrl_str;
  EVP_PKEY_CTX_ctrl_uint64: function(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_ctrl_uint64;
  EVP_PKEY_CTX_str2ctrl: function(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_str2ctrl;
  EVP_PKEY_CTX_hex2ctrl: function(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; hex: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_hex2ctrl;
  EVP_PKEY_CTX_md: function(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; md: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_md;
  EVP_PKEY_CTX_get_operation: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_operation;
  EVP_PKEY_CTX_set0_keygen_info: procedure(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl = Load_EVP_PKEY_CTX_set0_keygen_info;
  EVP_PKEY_new_mac_key: function(type_: TOpenSSL_C_INT; e: PENGINE; key: Pbyte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_mac_key;
  EVP_PKEY_new_raw_private_key_ex: function(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_raw_private_key_ex;
  EVP_PKEY_new_raw_private_key: function(type_: TOpenSSL_C_INT; e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_raw_private_key;
  EVP_PKEY_new_raw_public_key_ex: function(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_raw_public_key_ex;
  EVP_PKEY_new_raw_public_key: function(type_: TOpenSSL_C_INT; e: PENGINE; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_raw_public_key;
  EVP_PKEY_get_raw_private_key: function(pkey: PEVP_PKEY; priv: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_raw_private_key;
  EVP_PKEY_get_raw_public_key: function(pkey: PEVP_PKEY; pub: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_raw_public_key;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_new_CMAC_key(e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_new_CMAC_key'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_new_CMAC_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_new_CMAC_key(e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER): PEVP_PKEY; cdecl;

var
  EVP_PKEY_new_CMAC_key: function(e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER): PEVP_PKEY; cdecl = Load_EVP_PKEY_new_CMAC_key;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: pointer); cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_data';
  function EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): pointer; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_data';
  function EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_pkey';
  function EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_peerkey';
  procedure EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: pointer); cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_app_data';
  function EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): pointer; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_app_data';
  function EVP_PKEY_CTX_set_signature(pctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_signature';
  procedure EVP_SIGNATURE_free(signature: PEVP_SIGNATURE); cdecl; external CLibCrypto name 'EVP_SIGNATURE_free';
  function EVP_SIGNATURE_up_ref(signature: PEVP_SIGNATURE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SIGNATURE_up_ref';
  function EVP_SIGNATURE_get0_provider(signature: PEVP_SIGNATURE): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_SIGNATURE_get0_provider';
  function EVP_SIGNATURE_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SIGNATURE; cdecl; external CLibCrypto name 'EVP_SIGNATURE_fetch';
  function EVP_SIGNATURE_is_a(signature: PEVP_SIGNATURE; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SIGNATURE_is_a';
  function EVP_SIGNATURE_get0_name(signature: PEVP_SIGNATURE): PAnsiChar; cdecl; external CLibCrypto name 'EVP_SIGNATURE_get0_name';
  function EVP_SIGNATURE_get0_description(signature: PEVP_SIGNATURE): PAnsiChar; cdecl; external CLibCrypto name 'EVP_SIGNATURE_get0_description';
  {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_set_data}
  {$EXTERNALSYM EVP_PKEY_CTX_get_data}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_pkey}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_peerkey}
  {$EXTERNALSYM EVP_PKEY_CTX_set_app_data}
  {$EXTERNALSYM EVP_PKEY_CTX_get_app_data}
  {$EXTERNALSYM EVP_PKEY_CTX_set_signature}
  {$EXTERNALSYM EVP_SIGNATURE_free}
  {$EXTERNALSYM EVP_SIGNATURE_up_ref}
  {$EXTERNALSYM EVP_SIGNATURE_get0_provider}
  {$EXTERNALSYM EVP_SIGNATURE_fetch}
  {$EXTERNALSYM EVP_SIGNATURE_is_a}
  {$EXTERNALSYM EVP_SIGNATURE_get0_name}
  {$EXTERNALSYM EVP_SIGNATURE_get0_description}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: pointer); cdecl;
  function Load_EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): pointer; cdecl;
  function Load_EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
  function Load_EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
  procedure Load_EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: pointer); cdecl;
  function Load_EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): pointer; cdecl;
  function Load_EVP_PKEY_CTX_set_signature(pctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_SIGNATURE_free(signature: PEVP_SIGNATURE); cdecl;
  function Load_EVP_SIGNATURE_up_ref(signature: PEVP_SIGNATURE): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SIGNATURE_get0_provider(signature: PEVP_SIGNATURE): POSSL_PROVIDER; cdecl;
  function Load_EVP_SIGNATURE_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SIGNATURE; cdecl;
  function Load_EVP_SIGNATURE_is_a(signature: PEVP_SIGNATURE; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SIGNATURE_get0_name(signature: PEVP_SIGNATURE): PAnsiChar; cdecl;
  function Load_EVP_SIGNATURE_get0_description(signature: PEVP_SIGNATURE): PAnsiChar; cdecl;

var
  EVP_PKEY_CTX_set_data: procedure(ctx: PEVP_PKEY_CTX; data: pointer); cdecl = Load_EVP_PKEY_CTX_set_data;
  EVP_PKEY_CTX_get_data: function(ctx: PEVP_PKEY_CTX): pointer; cdecl = Load_EVP_PKEY_CTX_get_data;
  EVP_PKEY_CTX_get0_pkey: function(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = Load_EVP_PKEY_CTX_get0_pkey;
  EVP_PKEY_CTX_get0_peerkey: function(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = Load_EVP_PKEY_CTX_get0_peerkey;
  EVP_PKEY_CTX_set_app_data: procedure(ctx: PEVP_PKEY_CTX; data: pointer); cdecl = Load_EVP_PKEY_CTX_set_app_data;
  EVP_PKEY_CTX_get_app_data: function(ctx: PEVP_PKEY_CTX): pointer; cdecl = Load_EVP_PKEY_CTX_get_app_data;
  EVP_PKEY_CTX_set_signature: function(pctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_signature;
  EVP_SIGNATURE_free: procedure(signature: PEVP_SIGNATURE); cdecl = Load_EVP_SIGNATURE_free;
  EVP_SIGNATURE_up_ref: function(signature: PEVP_SIGNATURE): TOpenSSL_C_INT; cdecl = Load_EVP_SIGNATURE_up_ref;
  EVP_SIGNATURE_get0_provider: function(signature: PEVP_SIGNATURE): POSSL_PROVIDER; cdecl = Load_EVP_SIGNATURE_get0_provider;
  EVP_SIGNATURE_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SIGNATURE; cdecl = Load_EVP_SIGNATURE_fetch;
  EVP_SIGNATURE_is_a: function(signature: PEVP_SIGNATURE; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_SIGNATURE_is_a;
  EVP_SIGNATURE_get0_name: function(signature: PEVP_SIGNATURE): PAnsiChar; cdecl = Load_EVP_SIGNATURE_get0_name;
  EVP_SIGNATURE_get0_description: function(signature: PEVP_SIGNATURE): PAnsiChar; cdecl = Load_EVP_SIGNATURE_get0_description;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType071 = ^TFuncType071;
  PPFuncType071 = ^PFuncType071;
  {end of auto-generated forward references}

  TFuncType071 = procedure(signature: PEVP_SIGNATURE; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_SIGNATURE_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType071; data: pointer); cdecl; external CLibCrypto name 'EVP_SIGNATURE_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_SIGNATURE_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_SIGNATURE_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType071; data: pointer); cdecl;

var
  EVP_SIGNATURE_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType071; data: pointer); cdecl = Load_EVP_SIGNATURE_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType072 = ^TFuncType072;
  PPFuncType072 = ^PFuncType072;
  {end of auto-generated forward references}

  TFuncType072 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_SIGNATURE_names_do_all(signature: PEVP_SIGNATURE; fn: TFuncType072; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SIGNATURE_names_do_all';
  function EVP_SIGNATURE_gettable_ctx_params(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_SIGNATURE_gettable_ctx_params';
  function EVP_SIGNATURE_settable_ctx_params(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_SIGNATURE_settable_ctx_params';
  procedure EVP_ASYM_CIPHER_free(cipher: PEVP_ASYM_CIPHER); cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_free';
  function EVP_ASYM_CIPHER_up_ref(cipher: PEVP_ASYM_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_up_ref';
  function EVP_ASYM_CIPHER_get0_provider(cipher: PEVP_ASYM_CIPHER): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_get0_provider';
  function EVP_ASYM_CIPHER_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_ASYM_CIPHER; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_fetch';
  function EVP_ASYM_CIPHER_is_a(cipher: PEVP_ASYM_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_is_a';
  function EVP_ASYM_CIPHER_get0_name(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_get0_name';
  function EVP_ASYM_CIPHER_get0_description(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_get0_description';
  {$else}
  {$EXTERNALSYM EVP_SIGNATURE_names_do_all}
  {$EXTERNALSYM EVP_SIGNATURE_gettable_ctx_params}
  {$EXTERNALSYM EVP_SIGNATURE_settable_ctx_params}
  {$EXTERNALSYM EVP_ASYM_CIPHER_free}
  {$EXTERNALSYM EVP_ASYM_CIPHER_up_ref}
  {$EXTERNALSYM EVP_ASYM_CIPHER_get0_provider}
  {$EXTERNALSYM EVP_ASYM_CIPHER_fetch}
  {$EXTERNALSYM EVP_ASYM_CIPHER_is_a}
  {$EXTERNALSYM EVP_ASYM_CIPHER_get0_name}
  {$EXTERNALSYM EVP_ASYM_CIPHER_get0_description}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_SIGNATURE_names_do_all(signature: PEVP_SIGNATURE; fn: TFuncType072; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SIGNATURE_gettable_ctx_params(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl;
  function Load_EVP_SIGNATURE_settable_ctx_params(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl;
  procedure Load_EVP_ASYM_CIPHER_free(cipher: PEVP_ASYM_CIPHER); cdecl;
  function Load_EVP_ASYM_CIPHER_up_ref(cipher: PEVP_ASYM_CIPHER): TOpenSSL_C_INT; cdecl;
  function Load_EVP_ASYM_CIPHER_get0_provider(cipher: PEVP_ASYM_CIPHER): POSSL_PROVIDER; cdecl;
  function Load_EVP_ASYM_CIPHER_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_ASYM_CIPHER; cdecl;
  function Load_EVP_ASYM_CIPHER_is_a(cipher: PEVP_ASYM_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_ASYM_CIPHER_get0_name(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl;
  function Load_EVP_ASYM_CIPHER_get0_description(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl;

var
  EVP_SIGNATURE_names_do_all: function(signature: PEVP_SIGNATURE; fn: TFuncType072; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_SIGNATURE_names_do_all;
  EVP_SIGNATURE_gettable_ctx_params: function(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl = Load_EVP_SIGNATURE_gettable_ctx_params;
  EVP_SIGNATURE_settable_ctx_params: function(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl = Load_EVP_SIGNATURE_settable_ctx_params;
  EVP_ASYM_CIPHER_free: procedure(cipher: PEVP_ASYM_CIPHER); cdecl = Load_EVP_ASYM_CIPHER_free;
  EVP_ASYM_CIPHER_up_ref: function(cipher: PEVP_ASYM_CIPHER): TOpenSSL_C_INT; cdecl = Load_EVP_ASYM_CIPHER_up_ref;
  EVP_ASYM_CIPHER_get0_provider: function(cipher: PEVP_ASYM_CIPHER): POSSL_PROVIDER; cdecl = Load_EVP_ASYM_CIPHER_get0_provider;
  EVP_ASYM_CIPHER_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_ASYM_CIPHER; cdecl = Load_EVP_ASYM_CIPHER_fetch;
  EVP_ASYM_CIPHER_is_a: function(cipher: PEVP_ASYM_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_ASYM_CIPHER_is_a;
  EVP_ASYM_CIPHER_get0_name: function(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl = Load_EVP_ASYM_CIPHER_get0_name;
  EVP_ASYM_CIPHER_get0_description: function(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl = Load_EVP_ASYM_CIPHER_get0_description;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType073 = ^TFuncType073;
  PPFuncType073 = ^PFuncType073;
  {end of auto-generated forward references}

  TFuncType073 = procedure(cipher: PEVP_ASYM_CIPHER; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_ASYM_CIPHER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType073; arg: pointer); cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_ASYM_CIPHER_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_ASYM_CIPHER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType073; arg: pointer); cdecl;

var
  EVP_ASYM_CIPHER_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType073; arg: pointer); cdecl = Load_EVP_ASYM_CIPHER_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType074 = ^TFuncType074;
  PPFuncType074 = ^PFuncType074;
  {end of auto-generated forward references}

  TFuncType074 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_ASYM_CIPHER_names_do_all(cipher: PEVP_ASYM_CIPHER; fn: TFuncType074; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_names_do_all';
  function EVP_ASYM_CIPHER_gettable_ctx_params(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_gettable_ctx_params';
  function EVP_ASYM_CIPHER_settable_ctx_params(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_ASYM_CIPHER_settable_ctx_params';
  procedure EVP_KEM_free(wrap: PEVP_KEM); cdecl; external CLibCrypto name 'EVP_KEM_free';
  function EVP_KEM_up_ref(wrap: PEVP_KEM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEM_up_ref';
  function EVP_KEM_get0_provider(wrap: PEVP_KEM): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_KEM_get0_provider';
  function EVP_KEM_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEM; cdecl; external CLibCrypto name 'EVP_KEM_fetch';
  function EVP_KEM_is_a(wrap: PEVP_KEM; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEM_is_a';
  function EVP_KEM_get0_name(wrap: PEVP_KEM): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KEM_get0_name';
  function EVP_KEM_get0_description(wrap: PEVP_KEM): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KEM_get0_description';
  {$else}
  {$EXTERNALSYM EVP_ASYM_CIPHER_names_do_all}
  {$EXTERNALSYM EVP_ASYM_CIPHER_gettable_ctx_params}
  {$EXTERNALSYM EVP_ASYM_CIPHER_settable_ctx_params}
  {$EXTERNALSYM EVP_KEM_free}
  {$EXTERNALSYM EVP_KEM_up_ref}
  {$EXTERNALSYM EVP_KEM_get0_provider}
  {$EXTERNALSYM EVP_KEM_fetch}
  {$EXTERNALSYM EVP_KEM_is_a}
  {$EXTERNALSYM EVP_KEM_get0_name}
  {$EXTERNALSYM EVP_KEM_get0_description}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_ASYM_CIPHER_names_do_all(cipher: PEVP_ASYM_CIPHER; fn: TFuncType074; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_ASYM_CIPHER_gettable_ctx_params(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl;
  function Load_EVP_ASYM_CIPHER_settable_ctx_params(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl;
  procedure Load_EVP_KEM_free(wrap: PEVP_KEM); cdecl;
  function Load_EVP_KEM_up_ref(wrap: PEVP_KEM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KEM_get0_provider(wrap: PEVP_KEM): POSSL_PROVIDER; cdecl;
  function Load_EVP_KEM_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEM; cdecl;
  function Load_EVP_KEM_is_a(wrap: PEVP_KEM; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KEM_get0_name(wrap: PEVP_KEM): PAnsiChar; cdecl;
  function Load_EVP_KEM_get0_description(wrap: PEVP_KEM): PAnsiChar; cdecl;

var
  EVP_ASYM_CIPHER_names_do_all: function(cipher: PEVP_ASYM_CIPHER; fn: TFuncType074; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_ASYM_CIPHER_names_do_all;
  EVP_ASYM_CIPHER_gettable_ctx_params: function(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl = Load_EVP_ASYM_CIPHER_gettable_ctx_params;
  EVP_ASYM_CIPHER_settable_ctx_params: function(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl = Load_EVP_ASYM_CIPHER_settable_ctx_params;
  EVP_KEM_free: procedure(wrap: PEVP_KEM); cdecl = Load_EVP_KEM_free;
  EVP_KEM_up_ref: function(wrap: PEVP_KEM): TOpenSSL_C_INT; cdecl = Load_EVP_KEM_up_ref;
  EVP_KEM_get0_provider: function(wrap: PEVP_KEM): POSSL_PROVIDER; cdecl = Load_EVP_KEM_get0_provider;
  EVP_KEM_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEM; cdecl = Load_EVP_KEM_fetch;
  EVP_KEM_is_a: function(wrap: PEVP_KEM; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_KEM_is_a;
  EVP_KEM_get0_name: function(wrap: PEVP_KEM): PAnsiChar; cdecl = Load_EVP_KEM_get0_name;
  EVP_KEM_get0_description: function(wrap: PEVP_KEM): PAnsiChar; cdecl = Load_EVP_KEM_get0_description;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType075 = ^TFuncType075;
  PPFuncType075 = ^PFuncType075;
  {end of auto-generated forward references}

  TFuncType075 = procedure(wrap: PEVP_KEM; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_KEM_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType075; arg: pointer); cdecl; external CLibCrypto name 'EVP_KEM_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_KEM_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_KEM_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType075; arg: pointer); cdecl;

var
  EVP_KEM_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType075; arg: pointer); cdecl = Load_EVP_KEM_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType076 = ^TFuncType076;
  PPFuncType076 = ^PFuncType076;
  {end of auto-generated forward references}

  TFuncType076 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_KEM_names_do_all(wrap: PEVP_KEM; fn: TFuncType076; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEM_names_do_all';
  function EVP_KEM_gettable_ctx_params(kem: PEVP_KEM): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEM_gettable_ctx_params';
  function EVP_KEM_settable_ctx_params(kem: PEVP_KEM): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEM_settable_ctx_params';
  function EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_sign_init';
  function EVP_PKEY_sign_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_sign_init_ex';
  function EVP_PKEY_sign_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_sign_init_ex2';
  function EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_sign';
  function EVP_PKEY_sign_message_init(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_sign_message_init';
  function EVP_PKEY_sign_message_update(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_sign_message_update';
  function EVP_PKEY_sign_message_final(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_sign_message_final';
  function EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_init';
  function EVP_PKEY_verify_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_init_ex';
  function EVP_PKEY_verify_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_init_ex2';
  function EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify';
  function EVP_PKEY_verify_message_init(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_message_init';
  function EVP_PKEY_verify_message_update(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_message_update';
  function EVP_PKEY_verify_message_final(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_message_final';
  function EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_recover_init';
  function EVP_PKEY_verify_recover_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_recover_init_ex';
  function EVP_PKEY_verify_recover_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_recover_init_ex2';
  function EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: Pbyte; routlen: POpenSSL_C_SIZET; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_verify_recover';
  function EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_encrypt_init';
  function EVP_PKEY_encrypt_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_encrypt_init_ex';
  function EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_encrypt';
  function EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_decrypt_init';
  function EVP_PKEY_decrypt_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_decrypt_init_ex';
  function EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_decrypt';
  function EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_derive_init';
  function EVP_PKEY_derive_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_derive_init_ex';
  function EVP_PKEY_derive_set_peer_ex(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY; validate_peer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_derive_set_peer_ex';
  function EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_derive_set_peer';
  function EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_derive';
  function EVP_PKEY_derive_SKEY(ctx: PEVP_PKEY_CTX; mgmt: PEVP_SKEYMGMT; key_type: PAnsiChar; propquery: PAnsiChar; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl; external CLibCrypto name 'EVP_PKEY_derive_SKEY';
  function EVP_PKEY_encapsulate_init(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_encapsulate_init';
  function EVP_PKEY_auth_encapsulate_init(ctx: PEVP_PKEY_CTX; authpriv: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_auth_encapsulate_init';
  function EVP_PKEY_encapsulate(ctx: PEVP_PKEY_CTX; wrappedkey: Pbyte; wrappedkeylen: POpenSSL_C_SIZET; genkey: Pbyte; genkeylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_encapsulate';
  function EVP_PKEY_decapsulate_init(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_decapsulate_init';
  function EVP_PKEY_auth_decapsulate_init(ctx: PEVP_PKEY_CTX; authpub: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_auth_decapsulate_init';
  function EVP_PKEY_decapsulate(ctx: PEVP_PKEY_CTX; unwrapped: Pbyte; unwrappedlen: POpenSSL_C_SIZET; wrapped: Pbyte; wrappedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_decapsulate';
  {$else}
  {$EXTERNALSYM EVP_KEM_names_do_all}
  {$EXTERNALSYM EVP_KEM_gettable_ctx_params}
  {$EXTERNALSYM EVP_KEM_settable_ctx_params}
  {$EXTERNALSYM EVP_PKEY_sign_init}
  {$EXTERNALSYM EVP_PKEY_sign_init_ex}
  {$EXTERNALSYM EVP_PKEY_sign_init_ex2}
  {$EXTERNALSYM EVP_PKEY_sign}
  {$EXTERNALSYM EVP_PKEY_sign_message_init}
  {$EXTERNALSYM EVP_PKEY_sign_message_update}
  {$EXTERNALSYM EVP_PKEY_sign_message_final}
  {$EXTERNALSYM EVP_PKEY_verify_init}
  {$EXTERNALSYM EVP_PKEY_verify_init_ex}
  {$EXTERNALSYM EVP_PKEY_verify_init_ex2}
  {$EXTERNALSYM EVP_PKEY_verify}
  {$EXTERNALSYM EVP_PKEY_verify_message_init}
  {$EXTERNALSYM EVP_PKEY_verify_message_update}
  {$EXTERNALSYM EVP_PKEY_verify_message_final}
  {$EXTERNALSYM EVP_PKEY_verify_recover_init}
  {$EXTERNALSYM EVP_PKEY_verify_recover_init_ex}
  {$EXTERNALSYM EVP_PKEY_verify_recover_init_ex2}
  {$EXTERNALSYM EVP_PKEY_verify_recover}
  {$EXTERNALSYM EVP_PKEY_encrypt_init}
  {$EXTERNALSYM EVP_PKEY_encrypt_init_ex}
  {$EXTERNALSYM EVP_PKEY_encrypt}
  {$EXTERNALSYM EVP_PKEY_decrypt_init}
  {$EXTERNALSYM EVP_PKEY_decrypt_init_ex}
  {$EXTERNALSYM EVP_PKEY_decrypt}
  {$EXTERNALSYM EVP_PKEY_derive_init}
  {$EXTERNALSYM EVP_PKEY_derive_init_ex}
  {$EXTERNALSYM EVP_PKEY_derive_set_peer_ex}
  {$EXTERNALSYM EVP_PKEY_derive_set_peer}
  {$EXTERNALSYM EVP_PKEY_derive}
  {$EXTERNALSYM EVP_PKEY_derive_SKEY}
  {$EXTERNALSYM EVP_PKEY_encapsulate_init}
  {$EXTERNALSYM EVP_PKEY_auth_encapsulate_init}
  {$EXTERNALSYM EVP_PKEY_encapsulate}
  {$EXTERNALSYM EVP_PKEY_decapsulate_init}
  {$EXTERNALSYM EVP_PKEY_auth_decapsulate_init}
  {$EXTERNALSYM EVP_PKEY_decapsulate}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_KEM_names_do_all(wrap: PEVP_KEM; fn: TFuncType076; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KEM_gettable_ctx_params(kem: PEVP_KEM): POSSL_PARAM; cdecl;
  function Load_EVP_KEM_settable_ctx_params(kem: PEVP_KEM): POSSL_PARAM; cdecl;
  function Load_EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_sign_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_sign_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_sign_message_init(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_sign_message_update(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_sign_message_final(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_message_init(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_message_update(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_message_final(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_recover_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_recover_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: Pbyte; routlen: POpenSSL_C_SIZET; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_encrypt_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_decrypt_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_derive_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_derive_set_peer_ex(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY; validate_peer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_derive_SKEY(ctx: PEVP_PKEY_CTX; mgmt: PEVP_SKEYMGMT; key_type: PAnsiChar; propquery: PAnsiChar; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl;
  function Load_EVP_PKEY_encapsulate_init(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_auth_encapsulate_init(ctx: PEVP_PKEY_CTX; authpriv: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_encapsulate(ctx: PEVP_PKEY_CTX; wrappedkey: Pbyte; wrappedkeylen: POpenSSL_C_SIZET; genkey: Pbyte; genkeylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_decapsulate_init(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_auth_decapsulate_init(ctx: PEVP_PKEY_CTX; authpub: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_decapsulate(ctx: PEVP_PKEY_CTX; unwrapped: Pbyte; unwrappedlen: POpenSSL_C_SIZET; wrapped: Pbyte; wrappedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

var
  EVP_KEM_names_do_all: function(wrap: PEVP_KEM; fn: TFuncType076; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_KEM_names_do_all;
  EVP_KEM_gettable_ctx_params: function(kem: PEVP_KEM): POSSL_PARAM; cdecl = Load_EVP_KEM_gettable_ctx_params;
  EVP_KEM_settable_ctx_params: function(kem: PEVP_KEM): POSSL_PARAM; cdecl = Load_EVP_KEM_settable_ctx_params;
  EVP_PKEY_sign_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign_init;
  EVP_PKEY_sign_init_ex: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign_init_ex;
  EVP_PKEY_sign_init_ex2: function(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign_init_ex2;
  EVP_PKEY_sign: function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign;
  EVP_PKEY_sign_message_init: function(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign_message_init;
  EVP_PKEY_sign_message_update: function(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign_message_update;
  EVP_PKEY_sign_message_final: function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_sign_message_final;
  EVP_PKEY_verify_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_init;
  EVP_PKEY_verify_init_ex: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_init_ex;
  EVP_PKEY_verify_init_ex2: function(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_init_ex2;
  EVP_PKEY_verify: function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify;
  EVP_PKEY_verify_message_init: function(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_message_init;
  EVP_PKEY_verify_message_update: function(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_message_update;
  EVP_PKEY_verify_message_final: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_message_final;
  EVP_PKEY_verify_recover_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_recover_init;
  EVP_PKEY_verify_recover_init_ex: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_recover_init_ex;
  EVP_PKEY_verify_recover_init_ex2: function(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_recover_init_ex2;
  EVP_PKEY_verify_recover: function(ctx: PEVP_PKEY_CTX; rout: Pbyte; routlen: POpenSSL_C_SIZET; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_verify_recover;
  EVP_PKEY_encrypt_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encrypt_init;
  EVP_PKEY_encrypt_init_ex: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encrypt_init_ex;
  EVP_PKEY_encrypt: function(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encrypt;
  EVP_PKEY_decrypt_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decrypt_init;
  EVP_PKEY_decrypt_init_ex: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decrypt_init_ex;
  EVP_PKEY_decrypt: function(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decrypt;
  EVP_PKEY_derive_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive_init;
  EVP_PKEY_derive_init_ex: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive_init_ex;
  EVP_PKEY_derive_set_peer_ex: function(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY; validate_peer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive_set_peer_ex;
  EVP_PKEY_derive_set_peer: function(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive_set_peer;
  EVP_PKEY_derive: function(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_derive;
  EVP_PKEY_derive_SKEY: function(ctx: PEVP_PKEY_CTX; mgmt: PEVP_SKEYMGMT; key_type: PAnsiChar; propquery: PAnsiChar; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl = Load_EVP_PKEY_derive_SKEY;
  EVP_PKEY_encapsulate_init: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encapsulate_init;
  EVP_PKEY_auth_encapsulate_init: function(ctx: PEVP_PKEY_CTX; authpriv: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_auth_encapsulate_init;
  EVP_PKEY_encapsulate: function(ctx: PEVP_PKEY_CTX; wrappedkey: Pbyte; wrappedkeylen: POpenSSL_C_SIZET; genkey: Pbyte; genkeylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_encapsulate;
  EVP_PKEY_decapsulate_init: function(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decapsulate_init;
  EVP_PKEY_auth_decapsulate_init: function(ctx: PEVP_PKEY_CTX; authpub: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_auth_decapsulate_init;
  EVP_PKEY_decapsulate: function(ctx: PEVP_PKEY_CTX; unwrapped: Pbyte; unwrappedlen: POpenSSL_C_SIZET; wrapped: Pbyte; wrappedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_decapsulate;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PEVP_PKEY_gen_cb = ^TEVP_PKEY_gen_cb;
  PPEVP_PKEY_gen_cb = ^PEVP_PKEY_gen_cb;
  {end of auto-generated forward references}

  TEVP_PKEY_gen_cb = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_fromdata_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_fromdata_init';
  function EVP_PKEY_fromdata(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY; selection: TOpenSSL_C_INT; param: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_fromdata';
  function EVP_PKEY_fromdata_settable(ctx: PEVP_PKEY_CTX; selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_PKEY_fromdata_settable';
  function EVP_PKEY_todata(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; params: PPOSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_todata';
  function EVP_PKEY_export(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_export';
  function EVP_PKEY_gettable_params(pkey: PEVP_PKEY): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_PKEY_gettable_params';
  function EVP_PKEY_get_params(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_params';
  function EVP_PKEY_get_int_param(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_int_param';
  function EVP_PKEY_get_size_t_param(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_size_t_param';
  function EVP_PKEY_get_bn_param(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_bn_param';
  function EVP_PKEY_get_utf8_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_utf8_string_param';
  function EVP_PKEY_get_octet_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_octet_string_param';
  function EVP_PKEY_settable_params(pkey: PEVP_PKEY): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_PKEY_settable_params';
  function EVP_PKEY_set_params(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_params';
  function EVP_PKEY_set_int_param(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_int_param';
  function EVP_PKEY_set_size_t_param(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_size_t_param';
  function EVP_PKEY_set_bn_param(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_bn_param';
  function EVP_PKEY_set_utf8_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_utf8_string_param';
  function EVP_PKEY_set_octet_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_octet_string_param';
  function EVP_PKEY_get_ec_point_conv_form(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_ec_point_conv_form';
  function EVP_PKEY_get_field_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_field_type';
  function EVP_PKEY_Q_keygen(libctx: POSSL_LIB_CTX; propq: PAnsiChar; type_: PAnsiChar): PEVP_PKEY; cdecl varargs; external CLibCrypto name 'EVP_PKEY_Q_keygen';
  function EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_paramgen_init';
  function EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_paramgen';
  function EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_keygen_init';
  function EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_keygen';
  function EVP_PKEY_generate(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_generate';
  function EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_check';
  function EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_public_check';
  function EVP_PKEY_public_check_quick(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_public_check_quick';
  function EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_param_check';
  function EVP_PKEY_param_check_quick(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_param_check_quick';
  function EVP_PKEY_private_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_private_check';
  function EVP_PKEY_pairwise_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_pairwise_check';
  {$else}
  {$EXTERNALSYM EVP_PKEY_fromdata_init}
  {$EXTERNALSYM EVP_PKEY_fromdata}
  {$EXTERNALSYM EVP_PKEY_fromdata_settable}
  {$EXTERNALSYM EVP_PKEY_todata}
  {$EXTERNALSYM EVP_PKEY_export}
  {$EXTERNALSYM EVP_PKEY_gettable_params}
  {$EXTERNALSYM EVP_PKEY_get_params}
  {$EXTERNALSYM EVP_PKEY_get_int_param}
  {$EXTERNALSYM EVP_PKEY_get_size_t_param}
  {$EXTERNALSYM EVP_PKEY_get_bn_param}
  {$EXTERNALSYM EVP_PKEY_get_utf8_string_param}
  {$EXTERNALSYM EVP_PKEY_get_octet_string_param}
  {$EXTERNALSYM EVP_PKEY_settable_params}
  {$EXTERNALSYM EVP_PKEY_set_params}
  {$EXTERNALSYM EVP_PKEY_set_int_param}
  {$EXTERNALSYM EVP_PKEY_set_size_t_param}
  {$EXTERNALSYM EVP_PKEY_set_bn_param}
  {$EXTERNALSYM EVP_PKEY_set_utf8_string_param}
  {$EXTERNALSYM EVP_PKEY_set_octet_string_param}
  {$EXTERNALSYM EVP_PKEY_get_ec_point_conv_form}
  {$EXTERNALSYM EVP_PKEY_get_field_type}
  {$EXTERNALSYM EVP_PKEY_Q_keygen}
  {$EXTERNALSYM EVP_PKEY_paramgen_init}
  {$EXTERNALSYM EVP_PKEY_paramgen}
  {$EXTERNALSYM EVP_PKEY_keygen_init}
  {$EXTERNALSYM EVP_PKEY_keygen}
  {$EXTERNALSYM EVP_PKEY_generate}
  {$EXTERNALSYM EVP_PKEY_check}
  {$EXTERNALSYM EVP_PKEY_public_check}
  {$EXTERNALSYM EVP_PKEY_public_check_quick}
  {$EXTERNALSYM EVP_PKEY_param_check}
  {$EXTERNALSYM EVP_PKEY_param_check_quick}
  {$EXTERNALSYM EVP_PKEY_private_check}
  {$EXTERNALSYM EVP_PKEY_pairwise_check}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_fromdata_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_fromdata(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY; selection: TOpenSSL_C_INT; param: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_fromdata_settable(ctx: PEVP_PKEY_CTX; selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl;
  function Load_EVP_PKEY_todata(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; params: PPOSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_export(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_gettable_params(pkey: PEVP_PKEY): POSSL_PARAM; cdecl;
  function Load_EVP_PKEY_get_params(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_int_param(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_size_t_param(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_bn_param(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_utf8_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_octet_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_settable_params(pkey: PEVP_PKEY): POSSL_PARAM; cdecl;
  function Load_EVP_PKEY_set_params(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_int_param(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_size_t_param(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_bn_param(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_utf8_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_set_octet_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_ec_point_conv_form(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_field_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_generate(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_public_check_quick(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_param_check_quick(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_private_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_pairwise_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_fromdata_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_fromdata_init;
  EVP_PKEY_fromdata: function(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY; selection: TOpenSSL_C_INT; param: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_fromdata;
  EVP_PKEY_fromdata_settable: function(ctx: PEVP_PKEY_CTX; selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl = Load_EVP_PKEY_fromdata_settable;
  EVP_PKEY_todata: function(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; params: PPOSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_todata;
  EVP_PKEY_export: function(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_export;
  EVP_PKEY_gettable_params: function(pkey: PEVP_PKEY): POSSL_PARAM; cdecl = Load_EVP_PKEY_gettable_params;
  EVP_PKEY_get_params: function(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_params;
  EVP_PKEY_get_int_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_int_param;
  EVP_PKEY_get_size_t_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_size_t_param;
  EVP_PKEY_get_bn_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PPBIGNUM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_bn_param;
  EVP_PKEY_get_utf8_string_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_utf8_string_param;
  EVP_PKEY_get_octet_string_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_octet_string_param;
  EVP_PKEY_settable_params: function(pkey: PEVP_PKEY): POSSL_PARAM; cdecl = Load_EVP_PKEY_settable_params;
  EVP_PKEY_set_params: function(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_params;
  EVP_PKEY_set_int_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_int_param;
  EVP_PKEY_set_size_t_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_size_t_param;
  EVP_PKEY_set_bn_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_bn_param;
  EVP_PKEY_set_utf8_string_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_utf8_string_param;
  EVP_PKEY_set_octet_string_param: function(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_octet_string_param;
  EVP_PKEY_get_ec_point_conv_form: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_ec_point_conv_form;
  EVP_PKEY_get_field_type: function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_field_type;
  EVP_PKEY_Q_keygen: function(libctx: POSSL_LIB_CTX; propq: PAnsiChar; type_: PAnsiChar): PEVP_PKEY; cdecl varargs = nil;
  EVP_PKEY_paramgen_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_paramgen_init;
  EVP_PKEY_paramgen: function(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_paramgen;
  EVP_PKEY_keygen_init: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_keygen_init;
  EVP_PKEY_keygen: function(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_keygen;
  EVP_PKEY_generate: function(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_generate;
  EVP_PKEY_check: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_check;
  EVP_PKEY_public_check: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_public_check;
  EVP_PKEY_public_check_quick: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_public_check_quick;
  EVP_PKEY_param_check: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_param_check;
  EVP_PKEY_param_check_quick: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_param_check_quick;
  EVP_PKEY_private_check: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_private_check;
  EVP_PKEY_pairwise_check: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_pairwise_check;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {# define  EVP_PKEY_get_ex_new_index(l,p,newf,dupf,freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_EVP_PKEY, l, p, newf, dupf, freef)} {Macro Return Type unknown at line no 2134}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_set_ex_data(key: PEVP_PKEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_set_ex_data';
  function EVP_PKEY_get_ex_data(key: PEVP_PKEY; idx: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'EVP_PKEY_get_ex_data';
  procedure EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: PEVP_PKEY_gen_cb); cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_cb';
  function EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): PEVP_PKEY_gen_cb; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_cb';
  function EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_keygen_info';
  {$else}
  {$EXTERNALSYM EVP_PKEY_set_ex_data}
  {$EXTERNALSYM EVP_PKEY_get_ex_data}
  {$EXTERNALSYM EVP_PKEY_CTX_set_cb}
  {$EXTERNALSYM EVP_PKEY_CTX_get_cb}
  {$EXTERNALSYM EVP_PKEY_CTX_get_keygen_info}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_set_ex_data(key: PEVP_PKEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_ex_data(key: PEVP_PKEY; idx: TOpenSSL_C_INT): pointer; cdecl;
  procedure Load_EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: PEVP_PKEY_gen_cb); cdecl;
  function Load_EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): PEVP_PKEY_gen_cb; cdecl;
  function Load_EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_set_ex_data: function(key: PEVP_PKEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_set_ex_data;
  EVP_PKEY_get_ex_data: function(key: PEVP_PKEY; idx: TOpenSSL_C_INT): pointer; cdecl = Load_EVP_PKEY_get_ex_data;
  EVP_PKEY_CTX_set_cb: procedure(ctx: PEVP_PKEY_CTX; cb: PEVP_PKEY_gen_cb); cdecl = Load_EVP_PKEY_CTX_set_cb;
  EVP_PKEY_CTX_get_cb: function(ctx: PEVP_PKEY_CTX): PEVP_PKEY_gen_cb; cdecl = Load_EVP_PKEY_CTX_get_cb;
  EVP_PKEY_CTX_get_keygen_info: function(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_keygen_info;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PFuncType077 = ^TFuncType077;
  PPFuncType077 = ^PFuncType077;
  {end of auto-generated forward references}

  TFuncType077 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; init: TFuncType077); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_init'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_init}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; init: TFuncType077); cdecl;

var
  EVP_PKEY_meth_set_init: procedure(pmeth: PEVP_PKEY_METHOD; init: TFuncType077); cdecl = Load_EVP_PKEY_meth_set_init;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType078 = ^TFuncType078;
  PPFuncType078 = ^PFuncType078;
  {end of auto-generated forward references}

  TFuncType078 = function(dst: PEVP_PKEY_CTX; src: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; copy: TFuncType078); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_copy'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_copy}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; copy: TFuncType078); cdecl;

var
  EVP_PKEY_meth_set_copy: procedure(pmeth: PEVP_PKEY_METHOD; copy: TFuncType078); cdecl = Load_EVP_PKEY_meth_set_copy;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType079 = ^TFuncType079;
  PPFuncType079 = ^PFuncType079;
  {end of auto-generated forward references}

  TFuncType079 = procedure(ctx: PEVP_PKEY_CTX); cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; cleanup: TFuncType079); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_cleanup'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; cleanup: TFuncType079); cdecl;

var
  EVP_PKEY_meth_set_cleanup: procedure(pmeth: PEVP_PKEY_METHOD; cleanup: TFuncType079); cdecl = Load_EVP_PKEY_meth_set_cleanup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType080 = ^TFuncType080;
  PPFuncType080 = ^PFuncType080;
  PFuncType081 = ^TFuncType081;
  PPFuncType081 = ^PFuncType081;
  {end of auto-generated forward references}

  TFuncType080 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType081 = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; paramgen_init: TFuncType080; paramgen: TFuncType081); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_paramgen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_paramgen}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; paramgen_init: TFuncType080; paramgen: TFuncType081); cdecl;

var
  EVP_PKEY_meth_set_paramgen: procedure(pmeth: PEVP_PKEY_METHOD; paramgen_init: TFuncType080; paramgen: TFuncType081); cdecl = Load_EVP_PKEY_meth_set_paramgen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType082 = ^TFuncType082;
  PPFuncType082 = ^PFuncType082;
  PFuncType083 = ^TFuncType083;
  PPFuncType083 = ^PFuncType083;
  {end of auto-generated forward references}

  TFuncType082 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType083 = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; keygen_init: TFuncType082; keygen: TFuncType083); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_keygen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; keygen_init: TFuncType082; keygen: TFuncType083); cdecl;

var
  EVP_PKEY_meth_set_keygen: procedure(pmeth: PEVP_PKEY_METHOD; keygen_init: TFuncType082; keygen: TFuncType083); cdecl = Load_EVP_PKEY_meth_set_keygen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType084 = ^TFuncType084;
  PPFuncType084 = ^PFuncType084;
  PFuncType085 = ^TFuncType085;
  PPFuncType085 = ^PFuncType085;
  {end of auto-generated forward references}

  TFuncType084 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType085 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; sign_init: TFuncType084; sign: TFuncType085); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_sign'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; sign_init: TFuncType084; sign: TFuncType085); cdecl;

var
  EVP_PKEY_meth_set_sign: procedure(pmeth: PEVP_PKEY_METHOD; sign_init: TFuncType084; sign: TFuncType085); cdecl = Load_EVP_PKEY_meth_set_sign;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType086 = ^TFuncType086;
  PPFuncType086 = ^PFuncType086;
  PFuncType087 = ^TFuncType087;
  PPFuncType087 = ^PFuncType087;
  {end of auto-generated forward references}

  TFuncType086 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType087 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; verify_init: TFuncType086; verify: TFuncType087); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_verify'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; verify_init: TFuncType086; verify: TFuncType087); cdecl;

var
  EVP_PKEY_meth_set_verify: procedure(pmeth: PEVP_PKEY_METHOD; verify_init: TFuncType086; verify: TFuncType087); cdecl = Load_EVP_PKEY_meth_set_verify;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType088 = ^TFuncType088;
  PPFuncType088 = ^PFuncType088;
  PFuncType089 = ^TFuncType089;
  PPFuncType089 = ^PFuncType089;
  {end of auto-generated forward references}

  TFuncType088 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType089 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; verify_recover_init: TFuncType088; verify_recover: TFuncType089); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_verify_recover'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_verify_recover}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; verify_recover_init: TFuncType088; verify_recover: TFuncType089); cdecl;

var
  EVP_PKEY_meth_set_verify_recover: procedure(pmeth: PEVP_PKEY_METHOD; verify_recover_init: TFuncType088; verify_recover: TFuncType089); cdecl = Load_EVP_PKEY_meth_set_verify_recover;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType090 = ^TFuncType090;
  PPFuncType090 = ^PFuncType090;
  PFuncType091 = ^TFuncType091;
  PPFuncType091 = ^PFuncType091;
  {end of auto-generated forward references}

  TFuncType090 = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType091 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; signctx_init: TFuncType090; signctx: TFuncType091); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_signctx'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_signctx}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; signctx_init: TFuncType090; signctx: TFuncType091); cdecl;

var
  EVP_PKEY_meth_set_signctx: procedure(pmeth: PEVP_PKEY_METHOD; signctx_init: TFuncType090; signctx: TFuncType091); cdecl = Load_EVP_PKEY_meth_set_signctx;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType092 = ^TFuncType092;
  PPFuncType092 = ^PFuncType092;
  PFuncType093 = ^TFuncType093;
  PPFuncType093 = ^PFuncType093;
  {end of auto-generated forward references}

  TFuncType092 = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType093 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_INT; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; verifyctx_init: TFuncType092; verifyctx: TFuncType093); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_verifyctx'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_verifyctx}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; verifyctx_init: TFuncType092; verifyctx: TFuncType093); cdecl;

var
  EVP_PKEY_meth_set_verifyctx: procedure(pmeth: PEVP_PKEY_METHOD; verifyctx_init: TFuncType092; verifyctx: TFuncType093); cdecl = Load_EVP_PKEY_meth_set_verifyctx;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType094 = ^TFuncType094;
  PPFuncType094 = ^PFuncType094;
  PFuncType095 = ^TFuncType095;
  PPFuncType095 = ^PFuncType095;
  {end of auto-generated forward references}

  TFuncType094 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType095 = function(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; encrypt_init: TFuncType094; encryptfn: TFuncType095); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_encrypt'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; encrypt_init: TFuncType094; encryptfn: TFuncType095); cdecl;

var
  EVP_PKEY_meth_set_encrypt: procedure(pmeth: PEVP_PKEY_METHOD; encrypt_init: TFuncType094; encryptfn: TFuncType095); cdecl = Load_EVP_PKEY_meth_set_encrypt;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType096 = ^TFuncType096;
  PPFuncType096 = ^PFuncType096;
  PFuncType097 = ^TFuncType097;
  PPFuncType097 = ^PFuncType097;
  {end of auto-generated forward references}

  TFuncType096 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType097 = function(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; decrypt_init: TFuncType096; decrypt: TFuncType097); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_decrypt'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_decrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; decrypt_init: TFuncType096; decrypt: TFuncType097); cdecl;

var
  EVP_PKEY_meth_set_decrypt: procedure(pmeth: PEVP_PKEY_METHOD; decrypt_init: TFuncType096; decrypt: TFuncType097); cdecl = Load_EVP_PKEY_meth_set_decrypt;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType098 = ^TFuncType098;
  PPFuncType098 = ^PFuncType098;
  PFuncType099 = ^TFuncType099;
  PPFuncType099 = ^PFuncType099;
  {end of auto-generated forward references}

  TFuncType098 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType099 = function(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; derive_init: TFuncType098; derive: TFuncType099); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_derive'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_derive}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; derive_init: TFuncType098; derive: TFuncType099); cdecl;

var
  EVP_PKEY_meth_set_derive: procedure(pmeth: PEVP_PKEY_METHOD; derive_init: TFuncType098; derive: TFuncType099); cdecl = Load_EVP_PKEY_meth_set_derive;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType100 = ^TFuncType100;
  PPFuncType100 = ^PFuncType100;
  PFuncType101 = ^TFuncType101;
  PPFuncType101 = ^PFuncType101;
  {end of auto-generated forward references}

  TFuncType100 = function(ctx: PEVP_PKEY_CTX; type_: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;
  TFuncType101 = function(ctx: PEVP_PKEY_CTX; type_: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; ctrl: TFuncType100; ctrl_str: TFuncType101); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_ctrl'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; ctrl: TFuncType100; ctrl_str: TFuncType101); cdecl;

var
  EVP_PKEY_meth_set_ctrl: procedure(pmeth: PEVP_PKEY_METHOD; ctrl: TFuncType100; ctrl_str: TFuncType101); cdecl = Load_EVP_PKEY_meth_set_ctrl;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType102 = ^TFuncType102;
  PPFuncType102 = ^PFuncType102;
  {end of auto-generated forward references}

  TFuncType102 = function(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType102); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_digestsign'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_digestsign}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType102); cdecl;

var
  EVP_PKEY_meth_set_digestsign: procedure(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType102); cdecl = Load_EVP_PKEY_meth_set_digestsign;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType103 = ^TFuncType103;
  PPFuncType103 = ^PFuncType103;
  {end of auto-generated forward references}

  TFuncType103 = function(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType103); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_digestverify'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_digestverify}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType103); cdecl;

var
  EVP_PKEY_meth_set_digestverify: procedure(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType103); cdecl = Load_EVP_PKEY_meth_set_digestverify;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType104 = ^TFuncType104;
  PPFuncType104 = ^PFuncType104;
  {end of auto-generated forward references}

  TFuncType104 = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType104); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_check'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType104); cdecl;

var
  EVP_PKEY_meth_set_check: procedure(pmeth: PEVP_PKEY_METHOD; check: TFuncType104); cdecl = Load_EVP_PKEY_meth_set_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType105 = ^TFuncType105;
  PPFuncType105 = ^PFuncType105;
  {end of auto-generated forward references}

  TFuncType105 = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType105); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_public_check'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_public_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType105); cdecl;

var
  EVP_PKEY_meth_set_public_check: procedure(pmeth: PEVP_PKEY_METHOD; check: TFuncType105); cdecl = Load_EVP_PKEY_meth_set_public_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType106 = ^TFuncType106;
  PPFuncType106 = ^PFuncType106;
  {end of auto-generated forward references}

  TFuncType106 = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType106); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_param_check'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_param_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType106); cdecl;

var
  EVP_PKEY_meth_set_param_check: procedure(pmeth: PEVP_PKEY_METHOD; check: TFuncType106); cdecl = Load_EVP_PKEY_meth_set_param_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType107 = ^TFuncType107;
  PPFuncType107 = ^PFuncType107;
  {end of auto-generated forward references}

  TFuncType107 = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; digest_custom: TFuncType107); cdecl; external CLibCrypto name 'EVP_PKEY_meth_set_digest_custom'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_set_digest_custom}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; digest_custom: TFuncType107); cdecl;

var
  EVP_PKEY_meth_set_digest_custom: procedure(pmeth: PEVP_PKEY_METHOD; digest_custom: TFuncType107); cdecl = Load_EVP_PKEY_meth_set_digest_custom;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType108 = ^TFuncType108;
  PPFuncType108 = ^PFuncType108;
  {end of auto-generated forward references}

  TFuncType108 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_init(pmeth: PEVP_PKEY_METHOD; pinit: TFuncType108); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_init'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_init}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_init(pmeth: PEVP_PKEY_METHOD; pinit: TFuncType108); cdecl;

var
  EVP_PKEY_meth_get_init: procedure(pmeth: PEVP_PKEY_METHOD; pinit: TFuncType108); cdecl = Load_EVP_PKEY_meth_get_init;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType109 = ^TFuncType109;
  PPFuncType109 = ^PFuncType109;
  {end of auto-generated forward references}

  TFuncType109 = function(dst: PEVP_PKEY_CTX; src: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_copy(pmeth: PEVP_PKEY_METHOD; pcopy: TFuncType109); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_copy'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_copy}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_copy(pmeth: PEVP_PKEY_METHOD; pcopy: TFuncType109); cdecl;

var
  EVP_PKEY_meth_get_copy: procedure(pmeth: PEVP_PKEY_METHOD; pcopy: TFuncType109); cdecl = Load_EVP_PKEY_meth_get_copy;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType110 = ^TFuncType110;
  PPFuncType110 = ^PFuncType110;
  {end of auto-generated forward references}

  TFuncType110 = procedure(ctx: PEVP_PKEY_CTX); cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_cleanup(pmeth: PEVP_PKEY_METHOD; pcleanup: TFuncType110); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_cleanup'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_cleanup(pmeth: PEVP_PKEY_METHOD; pcleanup: TFuncType110); cdecl;

var
  EVP_PKEY_meth_get_cleanup: procedure(pmeth: PEVP_PKEY_METHOD; pcleanup: TFuncType110); cdecl = Load_EVP_PKEY_meth_get_cleanup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType111 = ^TFuncType111;
  PPFuncType111 = ^PFuncType111;
  PFuncType112 = ^TFuncType112;
  PPFuncType112 = ^PFuncType112;
  {end of auto-generated forward references}

  TFuncType111 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType112 = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_paramgen(pmeth: PEVP_PKEY_METHOD; pparamgen_init: TFuncType111; pparamgen: TFuncType112); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_paramgen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_paramgen}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_paramgen(pmeth: PEVP_PKEY_METHOD; pparamgen_init: TFuncType111; pparamgen: TFuncType112); cdecl;

var
  EVP_PKEY_meth_get_paramgen: procedure(pmeth: PEVP_PKEY_METHOD; pparamgen_init: TFuncType111; pparamgen: TFuncType112); cdecl = Load_EVP_PKEY_meth_get_paramgen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType113 = ^TFuncType113;
  PPFuncType113 = ^PFuncType113;
  PFuncType114 = ^TFuncType114;
  PPFuncType114 = ^PFuncType114;
  {end of auto-generated forward references}

  TFuncType113 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType114 = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_keygen(pmeth: PEVP_PKEY_METHOD; pkeygen_init: TFuncType113; pkeygen: TFuncType114); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_keygen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_keygen(pmeth: PEVP_PKEY_METHOD; pkeygen_init: TFuncType113; pkeygen: TFuncType114); cdecl;

var
  EVP_PKEY_meth_get_keygen: procedure(pmeth: PEVP_PKEY_METHOD; pkeygen_init: TFuncType113; pkeygen: TFuncType114); cdecl = Load_EVP_PKEY_meth_get_keygen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType115 = ^TFuncType115;
  PPFuncType115 = ^PFuncType115;
  PFuncType116 = ^TFuncType116;
  PPFuncType116 = ^PFuncType116;
  {end of auto-generated forward references}

  TFuncType115 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType116 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_sign(pmeth: PEVP_PKEY_METHOD; psign_init: TFuncType115; psign: TFuncType116); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_sign'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_sign(pmeth: PEVP_PKEY_METHOD; psign_init: TFuncType115; psign: TFuncType116); cdecl;

var
  EVP_PKEY_meth_get_sign: procedure(pmeth: PEVP_PKEY_METHOD; psign_init: TFuncType115; psign: TFuncType116); cdecl = Load_EVP_PKEY_meth_get_sign;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType117 = ^TFuncType117;
  PPFuncType117 = ^PFuncType117;
  PFuncType118 = ^TFuncType118;
  PPFuncType118 = ^PFuncType118;
  {end of auto-generated forward references}

  TFuncType117 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType118 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; pverify_init: TFuncType117; pverify: TFuncType118); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_verify'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; pverify_init: TFuncType117; pverify: TFuncType118); cdecl;

var
  EVP_PKEY_meth_get_verify: procedure(pmeth: PEVP_PKEY_METHOD; pverify_init: TFuncType117; pverify: TFuncType118); cdecl = Load_EVP_PKEY_meth_get_verify;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType119 = ^TFuncType119;
  PPFuncType119 = ^PFuncType119;
  PFuncType120 = ^TFuncType120;
  PPFuncType120 = ^PFuncType120;
  {end of auto-generated forward references}

  TFuncType119 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType120 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; pverify_recover_init: TFuncType119; pverify_recover: TFuncType120); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_verify_recover'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_verify_recover}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; pverify_recover_init: TFuncType119; pverify_recover: TFuncType120); cdecl;

var
  EVP_PKEY_meth_get_verify_recover: procedure(pmeth: PEVP_PKEY_METHOD; pverify_recover_init: TFuncType119; pverify_recover: TFuncType120); cdecl = Load_EVP_PKEY_meth_get_verify_recover;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType121 = ^TFuncType121;
  PPFuncType121 = ^PFuncType121;
  PFuncType122 = ^TFuncType122;
  PPFuncType122 = ^PFuncType122;
  {end of auto-generated forward references}

  TFuncType121 = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType122 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; psignctx_init: TFuncType121; psignctx: TFuncType122); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_signctx'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_signctx}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; psignctx_init: TFuncType121; psignctx: TFuncType122); cdecl;

var
  EVP_PKEY_meth_get_signctx: procedure(pmeth: PEVP_PKEY_METHOD; psignctx_init: TFuncType121; psignctx: TFuncType122); cdecl = Load_EVP_PKEY_meth_get_signctx;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType123 = ^TFuncType123;
  PPFuncType123 = ^PFuncType123;
  PFuncType124 = ^TFuncType124;
  PPFuncType124 = ^PFuncType124;
  {end of auto-generated forward references}

  TFuncType123 = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType124 = function(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_INT; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; pverifyctx_init: TFuncType123; pverifyctx: TFuncType124); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_verifyctx'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_verifyctx}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; pverifyctx_init: TFuncType123; pverifyctx: TFuncType124); cdecl;

var
  EVP_PKEY_meth_get_verifyctx: procedure(pmeth: PEVP_PKEY_METHOD; pverifyctx_init: TFuncType123; pverifyctx: TFuncType124); cdecl = Load_EVP_PKEY_meth_get_verifyctx;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType125 = ^TFuncType125;
  PPFuncType125 = ^PFuncType125;
  PFuncType126 = ^TFuncType126;
  PPFuncType126 = ^PFuncType126;
  {end of auto-generated forward references}

  TFuncType125 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType126 = function(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; pencrypt_init: TFuncType125; pencryptfn: TFuncType126); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_encrypt'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; pencrypt_init: TFuncType125; pencryptfn: TFuncType126); cdecl;

var
  EVP_PKEY_meth_get_encrypt: procedure(pmeth: PEVP_PKEY_METHOD; pencrypt_init: TFuncType125; pencryptfn: TFuncType126); cdecl = Load_EVP_PKEY_meth_get_encrypt;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType127 = ^TFuncType127;
  PPFuncType127 = ^PFuncType127;
  PFuncType128 = ^TFuncType128;
  PPFuncType128 = ^PFuncType128;
  {end of auto-generated forward references}

  TFuncType127 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType128 = function(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; pdecrypt_init: TFuncType127; pdecrypt: TFuncType128); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_decrypt'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_decrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; pdecrypt_init: TFuncType127; pdecrypt: TFuncType128); cdecl;

var
  EVP_PKEY_meth_get_decrypt: procedure(pmeth: PEVP_PKEY_METHOD; pdecrypt_init: TFuncType127; pdecrypt: TFuncType128); cdecl = Load_EVP_PKEY_meth_get_decrypt;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType129 = ^TFuncType129;
  PPFuncType129 = ^PFuncType129;
  PFuncType130 = ^TFuncType130;
  PPFuncType130 = ^PFuncType130;
  {end of auto-generated forward references}

  TFuncType129 = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  TFuncType130 = function(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; pderive_init: TFuncType129; pderive: TFuncType130); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_derive'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_derive}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; pderive_init: TFuncType129; pderive: TFuncType130); cdecl;

var
  EVP_PKEY_meth_get_derive: procedure(pmeth: PEVP_PKEY_METHOD; pderive_init: TFuncType129; pderive: TFuncType130); cdecl = Load_EVP_PKEY_meth_get_derive;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType131 = ^TFuncType131;
  PPFuncType131 = ^PFuncType131;
  PFuncType132 = ^TFuncType132;
  PPFuncType132 = ^PFuncType132;
  {end of auto-generated forward references}

  TFuncType131 = function(ctx: PEVP_PKEY_CTX; type_: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;
  TFuncType132 = function(ctx: PEVP_PKEY_CTX; type_: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; pctrl: TFuncType131; pctrl_str: TFuncType132); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_ctrl'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; pctrl: TFuncType131; pctrl_str: TFuncType132); cdecl;

var
  EVP_PKEY_meth_get_ctrl: procedure(pmeth: PEVP_PKEY_METHOD; pctrl: TFuncType131; pctrl_str: TFuncType132); cdecl = Load_EVP_PKEY_meth_get_ctrl;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType133 = ^TFuncType133;
  PPFuncType133 = ^PFuncType133;
  {end of auto-generated forward references}

  TFuncType133 = function(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType133); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_digestsign'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_digestsign}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType133); cdecl;

var
  EVP_PKEY_meth_get_digestsign: procedure(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType133); cdecl = Load_EVP_PKEY_meth_get_digestsign;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType134 = ^TFuncType134;
  PPFuncType134 = ^PFuncType134;
  {end of auto-generated forward references}

  TFuncType134 = function(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType134); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_digestverify'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_digestverify}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType134); cdecl;

var
  EVP_PKEY_meth_get_digestverify: procedure(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType134); cdecl = Load_EVP_PKEY_meth_get_digestverify;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType135 = ^TFuncType135;
  PPFuncType135 = ^PFuncType135;
  {end of auto-generated forward references}

  TFuncType135 = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType135); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_check'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType135); cdecl;

var
  EVP_PKEY_meth_get_check: procedure(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType135); cdecl = Load_EVP_PKEY_meth_get_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType136 = ^TFuncType136;
  PPFuncType136 = ^PFuncType136;
  {end of auto-generated forward references}

  TFuncType136 = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType136); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_public_check'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_public_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType136); cdecl;

var
  EVP_PKEY_meth_get_public_check: procedure(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType136); cdecl = Load_EVP_PKEY_meth_get_public_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType137 = ^TFuncType137;
  PPFuncType137 = ^PFuncType137;
  {end of auto-generated forward references}

  TFuncType137 = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType137); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_param_check'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_param_check}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType137); cdecl;

var
  EVP_PKEY_meth_get_param_check: procedure(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType137); cdecl = Load_EVP_PKEY_meth_get_param_check;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType138 = ^TFuncType138;
  PPFuncType138 = ^PFuncType138;
  {end of auto-generated forward references}

  TFuncType138 = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; pdigest_custom: TFuncType138); cdecl; external CLibCrypto name 'EVP_PKEY_meth_get_digest_custom'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_meth_get_digest_custom}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; pdigest_custom: TFuncType138); cdecl;

var
  EVP_PKEY_meth_get_digest_custom: procedure(pmeth: PEVP_PKEY_METHOD; pdigest_custom: TFuncType138); cdecl = Load_EVP_PKEY_meth_get_digest_custom;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_KEYEXCH_free(exchange: PEVP_KEYEXCH); cdecl; external CLibCrypto name 'EVP_KEYEXCH_free';
  function EVP_KEYEXCH_up_ref(exchange: PEVP_KEYEXCH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEYEXCH_up_ref';
  function EVP_KEYEXCH_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYEXCH; cdecl; external CLibCrypto name 'EVP_KEYEXCH_fetch';
  function EVP_KEYEXCH_get0_provider(exchange: PEVP_KEYEXCH): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_KEYEXCH_get0_provider';
  function EVP_KEYEXCH_is_a(keyexch: PEVP_KEYEXCH; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEYEXCH_is_a';
  function EVP_KEYEXCH_get0_name(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KEYEXCH_get0_name';
  function EVP_KEYEXCH_get0_description(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl; external CLibCrypto name 'EVP_KEYEXCH_get0_description';
  {$else}
  {$EXTERNALSYM EVP_KEYEXCH_free}
  {$EXTERNALSYM EVP_KEYEXCH_up_ref}
  {$EXTERNALSYM EVP_KEYEXCH_fetch}
  {$EXTERNALSYM EVP_KEYEXCH_get0_provider}
  {$EXTERNALSYM EVP_KEYEXCH_is_a}
  {$EXTERNALSYM EVP_KEYEXCH_get0_name}
  {$EXTERNALSYM EVP_KEYEXCH_get0_description}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_KEYEXCH_free(exchange: PEVP_KEYEXCH); cdecl;
  function Load_EVP_KEYEXCH_up_ref(exchange: PEVP_KEYEXCH): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KEYEXCH_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYEXCH; cdecl;
  function Load_EVP_KEYEXCH_get0_provider(exchange: PEVP_KEYEXCH): POSSL_PROVIDER; cdecl;
  function Load_EVP_KEYEXCH_is_a(keyexch: PEVP_KEYEXCH; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KEYEXCH_get0_name(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl;
  function Load_EVP_KEYEXCH_get0_description(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl;

var
  EVP_KEYEXCH_free: procedure(exchange: PEVP_KEYEXCH); cdecl = Load_EVP_KEYEXCH_free;
  EVP_KEYEXCH_up_ref: function(exchange: PEVP_KEYEXCH): TOpenSSL_C_INT; cdecl = Load_EVP_KEYEXCH_up_ref;
  EVP_KEYEXCH_fetch: function(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYEXCH; cdecl = Load_EVP_KEYEXCH_fetch;
  EVP_KEYEXCH_get0_provider: function(exchange: PEVP_KEYEXCH): POSSL_PROVIDER; cdecl = Load_EVP_KEYEXCH_get0_provider;
  EVP_KEYEXCH_is_a: function(keyexch: PEVP_KEYEXCH; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_KEYEXCH_is_a;
  EVP_KEYEXCH_get0_name: function(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl = Load_EVP_KEYEXCH_get0_name;
  EVP_KEYEXCH_get0_description: function(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl = Load_EVP_KEYEXCH_get0_description;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType139 = ^TFuncType139;
  PPFuncType139 = ^PFuncType139;
  {end of auto-generated forward references}

  TFuncType139 = procedure(keyexch: PEVP_KEYEXCH; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure EVP_KEYEXCH_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType139; data: pointer); cdecl; external CLibCrypto name 'EVP_KEYEXCH_do_all_provided';
  {$else}
  {$EXTERNALSYM EVP_KEYEXCH_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_EVP_KEYEXCH_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType139; data: pointer); cdecl;

var
  EVP_KEYEXCH_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType139; data: pointer); cdecl = Load_EVP_KEYEXCH_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType140 = ^TFuncType140;
  PPFuncType140 = ^PFuncType140;
  {end of auto-generated forward references}

  TFuncType140 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_KEYEXCH_names_do_all(keyexch: PEVP_KEYEXCH; fn: TFuncType140; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_KEYEXCH_names_do_all';
  function EVP_KEYEXCH_gettable_ctx_params(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEYEXCH_gettable_ctx_params';
  function EVP_KEYEXCH_settable_ctx_params(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl; external CLibCrypto name 'EVP_KEYEXCH_settable_ctx_params';
  procedure EVP_add_alg_module; cdecl; external CLibCrypto name 'EVP_add_alg_module';
  function EVP_PKEY_CTX_set_group_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_group_name';
  function EVP_PKEY_CTX_get_group_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_group_name';
  function EVP_PKEY_get_group_name(pkey: PEVP_PKEY; name: PAnsiChar; name_sz: TOpenSSL_C_SIZET; gname_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_get_group_name';
  function EVP_PKEY_CTX_get0_libctx(ctx: PEVP_PKEY_CTX): POSSL_LIB_CTX; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_libctx';
  function EVP_PKEY_CTX_get0_propq(ctx: PEVP_PKEY_CTX): PAnsiChar; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_propq';
  function EVP_PKEY_CTX_get0_provider(ctx: PEVP_PKEY_CTX): POSSL_PROVIDER; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_provider';
  function EVP_SKEY_is_a(skey: PEVP_SKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SKEY_is_a';
  function EVP_SKEY_import(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl; external CLibCrypto name 'EVP_SKEY_import';
  function EVP_SKEY_generate(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; params: POSSL_PARAM): PEVP_SKEY; cdecl; external CLibCrypto name 'EVP_SKEY_generate';
  function EVP_SKEY_import_raw_key(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; key: Pbyte; keylen: TOpenSSL_C_SIZET; propquery: PAnsiChar): PEVP_SKEY; cdecl; external CLibCrypto name 'EVP_SKEY_import_raw_key';
  function EVP_SKEY_import_SKEYMGMT(libctx: POSSL_LIB_CTX; skeymgmt: PEVP_SKEYMGMT; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl; external CLibCrypto name 'EVP_SKEY_import_SKEYMGMT';
  function EVP_SKEY_get0_raw_key(skey: PEVP_SKEY; key: PPbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SKEY_get0_raw_key';
  function EVP_SKEY_get0_key_id(skey: PEVP_SKEY): PAnsiChar; cdecl; external CLibCrypto name 'EVP_SKEY_get0_key_id';
  function EVP_SKEY_export(skey: PEVP_SKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SKEY_export';
  function EVP_SKEY_up_ref(skey: PEVP_SKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_SKEY_up_ref';
  procedure EVP_SKEY_free(skey: PEVP_SKEY); cdecl; external CLibCrypto name 'EVP_SKEY_free';
  function EVP_SKEY_get0_skeymgmt_name(skey: PEVP_SKEY): PAnsiChar; cdecl; external CLibCrypto name 'EVP_SKEY_get0_skeymgmt_name';
  function EVP_SKEY_get0_provider_name(skey: PEVP_SKEY): PAnsiChar; cdecl; external CLibCrypto name 'EVP_SKEY_get0_provider_name';
  function EVP_SKEY_to_provider(skey: PEVP_SKEY; libctx: POSSL_LIB_CTX; prov: POSSL_PROVIDER; propquery: PAnsiChar): PEVP_SKEY; cdecl; external CLibCrypto name 'EVP_SKEY_to_provider';
  {$else}
  {$EXTERNALSYM EVP_KEYEXCH_names_do_all}
  {$EXTERNALSYM EVP_KEYEXCH_gettable_ctx_params}
  {$EXTERNALSYM EVP_KEYEXCH_settable_ctx_params}
  {$EXTERNALSYM EVP_add_alg_module}
  {$EXTERNALSYM EVP_PKEY_CTX_set_group_name}
  {$EXTERNALSYM EVP_PKEY_CTX_get_group_name}
  {$EXTERNALSYM EVP_PKEY_get_group_name}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_libctx}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_propq}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_provider}
  {$EXTERNALSYM EVP_SKEY_is_a}
  {$EXTERNALSYM EVP_SKEY_import}
  {$EXTERNALSYM EVP_SKEY_generate}
  {$EXTERNALSYM EVP_SKEY_import_raw_key}
  {$EXTERNALSYM EVP_SKEY_import_SKEYMGMT}
  {$EXTERNALSYM EVP_SKEY_get0_raw_key}
  {$EXTERNALSYM EVP_SKEY_get0_key_id}
  {$EXTERNALSYM EVP_SKEY_export}
  {$EXTERNALSYM EVP_SKEY_up_ref}
  {$EXTERNALSYM EVP_SKEY_free}
  {$EXTERNALSYM EVP_SKEY_get0_skeymgmt_name}
  {$EXTERNALSYM EVP_SKEY_get0_provider_name}
  {$EXTERNALSYM EVP_SKEY_to_provider}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_KEYEXCH_names_do_all(keyexch: PEVP_KEYEXCH; fn: TFuncType140; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_KEYEXCH_gettable_ctx_params(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl;
  function Load_EVP_KEYEXCH_settable_ctx_params(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl;
  procedure Load_EVP_add_alg_module; cdecl;
  function Load_EVP_PKEY_CTX_set_group_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_group_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_get_group_name(pkey: PEVP_PKEY; name: PAnsiChar; name_sz: TOpenSSL_C_SIZET; gname_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get0_libctx(ctx: PEVP_PKEY_CTX): POSSL_LIB_CTX; cdecl;
  function Load_EVP_PKEY_CTX_get0_propq(ctx: PEVP_PKEY_CTX): PAnsiChar; cdecl;
  function Load_EVP_PKEY_CTX_get0_provider(ctx: PEVP_PKEY_CTX): POSSL_PROVIDER; cdecl;
  function Load_EVP_SKEY_is_a(skey: PEVP_SKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SKEY_import(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl;
  function Load_EVP_SKEY_generate(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; params: POSSL_PARAM): PEVP_SKEY; cdecl;
  function Load_EVP_SKEY_import_raw_key(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; key: Pbyte; keylen: TOpenSSL_C_SIZET; propquery: PAnsiChar): PEVP_SKEY; cdecl;
  function Load_EVP_SKEY_import_SKEYMGMT(libctx: POSSL_LIB_CTX; skeymgmt: PEVP_SKEYMGMT; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl;
  function Load_EVP_SKEY_get0_raw_key(skey: PEVP_SKEY; key: PPbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SKEY_get0_key_id(skey: PEVP_SKEY): PAnsiChar; cdecl;
  function Load_EVP_SKEY_export(skey: PEVP_SKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_EVP_SKEY_up_ref(skey: PEVP_SKEY): TOpenSSL_C_INT; cdecl;
  procedure Load_EVP_SKEY_free(skey: PEVP_SKEY); cdecl;
  function Load_EVP_SKEY_get0_skeymgmt_name(skey: PEVP_SKEY): PAnsiChar; cdecl;
  function Load_EVP_SKEY_get0_provider_name(skey: PEVP_SKEY): PAnsiChar; cdecl;
  function Load_EVP_SKEY_to_provider(skey: PEVP_SKEY; libctx: POSSL_LIB_CTX; prov: POSSL_PROVIDER; propquery: PAnsiChar): PEVP_SKEY; cdecl;

var
  EVP_KEYEXCH_names_do_all: function(keyexch: PEVP_KEYEXCH; fn: TFuncType140; data: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_KEYEXCH_names_do_all;
  EVP_KEYEXCH_gettable_ctx_params: function(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl = Load_EVP_KEYEXCH_gettable_ctx_params;
  EVP_KEYEXCH_settable_ctx_params: function(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl = Load_EVP_KEYEXCH_settable_ctx_params;
  EVP_add_alg_module: procedure; cdecl = Load_EVP_add_alg_module;
  EVP_PKEY_CTX_set_group_name: function(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_group_name;
  EVP_PKEY_CTX_get_group_name: function(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_group_name;
  EVP_PKEY_get_group_name: function(pkey: PEVP_PKEY; name: PAnsiChar; name_sz: TOpenSSL_C_SIZET; gname_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_get_group_name;
  EVP_PKEY_CTX_get0_libctx: function(ctx: PEVP_PKEY_CTX): POSSL_LIB_CTX; cdecl = Load_EVP_PKEY_CTX_get0_libctx;
  EVP_PKEY_CTX_get0_propq: function(ctx: PEVP_PKEY_CTX): PAnsiChar; cdecl = Load_EVP_PKEY_CTX_get0_propq;
  EVP_PKEY_CTX_get0_provider: function(ctx: PEVP_PKEY_CTX): POSSL_PROVIDER; cdecl = Load_EVP_PKEY_CTX_get0_provider;
  EVP_SKEY_is_a: function(skey: PEVP_SKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_SKEY_is_a;
  EVP_SKEY_import: function(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl = Load_EVP_SKEY_import;
  EVP_SKEY_generate: function(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; params: POSSL_PARAM): PEVP_SKEY; cdecl = Load_EVP_SKEY_generate;
  EVP_SKEY_import_raw_key: function(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; key: Pbyte; keylen: TOpenSSL_C_SIZET; propquery: PAnsiChar): PEVP_SKEY; cdecl = Load_EVP_SKEY_import_raw_key;
  EVP_SKEY_import_SKEYMGMT: function(libctx: POSSL_LIB_CTX; skeymgmt: PEVP_SKEYMGMT; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl = Load_EVP_SKEY_import_SKEYMGMT;
  EVP_SKEY_get0_raw_key: function(skey: PEVP_SKEY; key: PPbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_SKEY_get0_raw_key;
  EVP_SKEY_get0_key_id: function(skey: PEVP_SKEY): PAnsiChar; cdecl = Load_EVP_SKEY_get0_key_id;
  EVP_SKEY_export: function(skey: PEVP_SKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl = Load_EVP_SKEY_export;
  EVP_SKEY_up_ref: function(skey: PEVP_SKEY): TOpenSSL_C_INT; cdecl = Load_EVP_SKEY_up_ref;
  EVP_SKEY_free: procedure(skey: PEVP_SKEY); cdecl = Load_EVP_SKEY_free;
  EVP_SKEY_get0_skeymgmt_name: function(skey: PEVP_SKEY): PAnsiChar; cdecl = Load_EVP_SKEY_get0_skeymgmt_name;
  EVP_SKEY_get0_provider_name: function(skey: PEVP_SKEY): PAnsiChar; cdecl = Load_EVP_SKEY_get0_provider_name;
  EVP_SKEY_to_provider: function(skey: PEVP_SKEY; libctx: POSSL_LIB_CTX; prov: POSSL_PROVIDER; propquery: PAnsiChar): PEVP_SKEY; cdecl = Load_EVP_SKEY_to_provider;
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
  ,Classes, OpenSSLExceptionHandlers,openssl_crypto;

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

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}

{# define  EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey), EVP_PKEY_RSA, (rsa))}

function EVP_PKEY_assign_RSA(pkey:PEVP_PKEY; rsa:pointer): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_PKEY_assign(pkey,EVP_PKEY_RSA,rsa));
end;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_6}
    {$ifndef  OPENSSL_NO_DSA}

{# define  EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey), EVP_PKEY_DSA, (dsa))}

function EVP_PKEY_assign_DSA(pkey:PEVP_PKEY; dsa:pointer): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_PKEY_assign(pkey,EVP_PKEY_DSA,dsa));
end;
    {$endif} { OPENSSL_NO_DSA}
{$endif} { OPENSSL_NO_DEPRECATED_3_6}
{$if  not defined(OPENSSL_NO_DH)  and  not defined(OPENSSL_NO_DEPRECATED_3_0)}

{# define  EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey), EVP_PKEY_DH, (dh))}

function EVP_PKEY_assign_DH(pkey:PEVP_PKEY; dh:pointer): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_PKEY_assign(pkey,EVP_PKEY_DH,dh));
end;
{$endif} { not defined(OPENSSL_NO_DH)  and  not defined(OPENSSL_NO_DEPRECATED_3_0)}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_EC}

{# define  EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey), EVP_PKEY_EC, (eckey))}

function EVP_PKEY_assign_EC_KEY(pkey:PEVP_PKEY; eckey:pointer): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_PKEY_assign(pkey,EVP_PKEY_EC,eckey));
end;
    {$endif} { OPENSSL_NO_EC}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_6}
    {$ifndef  OPENSSL_NO_SIPHASH}

{# define  EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey), EVP_PKEY_SIPHASH, (shkey))}

function EVP_PKEY_assign_SIPHASH(pkey:PEVP_PKEY; shkey:pointer): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_PKEY_assign(pkey,EVP_PKEY_SIPHASH,shkey));
end;
    {$endif} { OPENSSL_NO_SIPHASH}
    {$ifndef  OPENSSL_NO_POLY1305}

{# define  EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey), EVP_PKEY_POLY1305, (polykey))}

function EVP_PKEY_assign_POLY1305(pkey:PEVP_PKEY; polykey:pointer): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_PKEY_assign(pkey,EVP_PKEY_POLY1305,polykey));
end;
    {$endif} { OPENSSL_NO_POLY1305}
{$endif} { OPENSSL_NO_DEPRECATED_3_6}

{# define  EVP_get_digestbynid(a) EVP_get_digestbyname(OBJ_nid2sn(a))}

function EVP_get_digestbynid(a: TOpenSSL_C_INT): PEVP_MD;
begin
  Result := PEVP_MD(EVP_get_digestbyname(OBJ_nid2sn(a)));
end;

{# define  EVP_get_digestbyobj(a) EVP_get_digestbynid(OBJ_obj2nid(a))}

function EVP_get_digestbyobj(a:PASN1_OBJECT): PEVP_MD;
begin
  Result := PEVP_MD(EVP_get_digestbynid(OBJ_obj2nid(a)));
end;

{# define  EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))}

function EVP_get_cipherbynid(a: TOpenSSL_C_INT): PEVP_CIPHER;
begin
  Result := PEVP_CIPHER(EVP_get_cipherbyname(OBJ_nid2sn(a)));
end;

{# define  EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))}

function EVP_get_cipherbyobj(a:PASN1_OBJECT): PEVP_CIPHER;
begin
  Result := PEVP_CIPHER(EVP_get_cipherbynid(OBJ_obj2nid(a)));
end;

{# define  EVP_MD_CTX_get0_name(e) EVP_MD_get0_name(EVP_MD_CTX_get0_md(e))}

function EVP_MD_CTX_get0_name(e:PEVP_MD_CTX): PAnsiChar;
begin
  Result := PAnsiChar(EVP_MD_get0_name(EVP_MD_CTX_get0_md(e)));
end;

{# define  EVP_MD_CTX_get_size(e) EVP_MD_CTX_get_size_ex(e)}

function EVP_MD_CTX_get_size(e:PEVP_MD_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_MD_CTX_get_size_ex(e));
end;

{# define  EVP_MD_CTX_get_block_size(e) EVP_MD_get_block_size(EVP_MD_CTX_get0_md(e))}

function EVP_MD_CTX_get_block_size(e:PEVP_MD_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_MD_get_block_size(EVP_MD_CTX_get0_md(e)));
end;

{# define  EVP_MD_CTX_block_size EVP_MD_CTX_get_block_size}

function EVP_MD_CTX_block_size(e:PEVP_MD_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_MD_get_block_size(EVP_MD_CTX_get0_md(e)));
end;

{# define  EVP_MD_CTX_get_type(e) EVP_MD_get_type(EVP_MD_CTX_get0_md(e))}

function EVP_MD_CTX_get_type(e:PEVP_MD_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_MD_get_type(EVP_MD_CTX_get0_md(e)));
end;

{# define  EVP_MD_CTX_type EVP_MD_CTX_get_type}

function EVP_MD_CTX_type(e:PEVP_MD_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_MD_get_type(EVP_MD_CTX_get0_md(e)));
end;

{# define  EVP_CIPHER_CTX_get0_name(c) EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(c))}

function EVP_CIPHER_CTX_get0_name(c:PEVP_CIPHER_CTX): PAnsiChar;
begin
  Result := PAnsiChar(EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(c)));
end;

{# define  EVP_CIPHER_CTX_get_type(c) EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c))}

function EVP_CIPHER_CTX_get_type(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c)));
end;

{# define  EVP_CIPHER_CTX_type EVP_CIPHER_CTX_get_type}

function EVP_CIPHER_CTX_type(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_CIPHER_get_type(EVP_CIPHER_CTX_get0_cipher(c)));
end;
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

{# define  EVP_CIPHER_CTX_flags(c) EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(c))}

function EVP_CIPHER_CTX_flags(c:PEVP_CIPHER_CTX): TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(EVP_CIPHER_get_flags(EVP_CIPHER_CTX_get0_cipher(c)));
end;
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}

{# define  EVP_CIPHER_CTX_get_mode(c) EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c))}

function EVP_CIPHER_CTX_get_mode(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c)));
end;

{# define  EVP_CIPHER_CTX_mode EVP_CIPHER_CTX_get_mode}

function EVP_CIPHER_CTX_mode(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c)));
end;

{# define  EVP_ENCODE_LENGTH(l) ((((l) + 2) / 3 * 4) + ((l) / 48 + 1) * 2 + 80)}

function EVP_ENCODE_LENGTH(l:int64): int64;
begin
  Result := int64(((((l+(2)) div 3)*4)+(((l div 48)+1)*2))+80);
end;

{# define  EVP_DECODE_LENGTH(l) (((l) + 3) / 4 * 3 + 80)}

function EVP_DECODE_LENGTH(l:int64): int64;
begin
  Result := int64((((l+(3)) div 4)*3)+80);
end;

{# define  EVP_SignInit_ex(a,b,c) EVP_DigestInit_ex(a, b, c)}

function EVP_SignInit_ex(a:PEVP_MD_CTX; b:PEVP_MD; c:PENGINE): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_DigestInit_ex(a,b,c));
end;

{# define  EVP_SignInit(a,b) EVP_DigestInit(a, b)}

function EVP_SignInit(a:PEVP_MD_CTX; b:PEVP_MD): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_DigestInit(a,b));
end;

{# define  EVP_SignUpdate(a,b,c) EVP_DigestUpdate(a, b, c)}

function EVP_SignUpdate(a:PEVP_MD_CTX; b:pointer; c:TOpenSSL_C_SIZET): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_DigestUpdate(a,b,c));
end;

{# define  EVP_VerifyInit_ex(a,b,c) EVP_DigestInit_ex(a, b, c)}

function EVP_VerifyInit_ex(a:PEVP_MD_CTX; b:PEVP_MD; c:PENGINE): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_DigestInit_ex(a,b,c));
end;

{# define  EVP_VerifyInit(a,b) EVP_DigestInit(a, b)}

function EVP_VerifyInit(a:PEVP_MD_CTX; b:PEVP_MD): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_DigestInit(a,b));
end;

{# define  EVP_VerifyUpdate(a,b,c) EVP_DigestUpdate(a, b, c)}

function EVP_VerifyUpdate(a:PEVP_MD_CTX; b:pointer; c:TOpenSSL_C_SIZET): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_DigestUpdate(a,b,c));
end;

{# define  EVP_OpenUpdate(a,b,c,d,e) EVP_DecryptUpdate(a, b, c, d, e)}

function EVP_OpenUpdate(a:PEVP_CIPHER_CTX; b:Pbyte; c:POpenSSL_C_INT; d:Pbyte; e:TOpenSSL_C_INT): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_DecryptUpdate(a,b,c,d,e));
end;

{# define  EVP_SealUpdate(a,b,c,d,e) EVP_EncryptUpdate(a, b, c, d, e)}

function EVP_SealUpdate(a:PEVP_CIPHER_CTX; b:Pbyte; c:POpenSSL_C_INT; d:Pbyte; e:TOpenSSL_C_INT): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_EncryptUpdate(a,b,c,d,e));
end;

{# define  EVP_MD_CTX_create() EVP_MD_CTX_new()}

function EVP_MD_CTX_create(): PEVP_MD_CTX;
begin
  Result := PEVP_MD_CTX(EVP_MD_CTX_new);
end;

{# define  EVP_MD_CTX_init(ctx) EVP_MD_CTX_reset((ctx))}

function EVP_MD_CTX_init(ctx:PEVP_MD_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_MD_CTX_reset(ctx));
end;

{# define  EVP_MD_CTX_destroy(ctx) EVP_MD_CTX_free((ctx))}

procedure EVP_MD_CTX_destroy(ctx:PEVP_MD_CTX);
begin
  EVP_MD_CTX_free(ctx);
end;
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

{# define  EVP_CIPHER_CTX_init(c) EVP_CIPHER_CTX_reset(c)}

function EVP_CIPHER_CTX_init(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_CIPHER_CTX_reset(c));
end;

{# define  EVP_CIPHER_CTX_cleanup(c) EVP_CIPHER_CTX_reset(c)}

function EVP_CIPHER_CTX_cleanup(c:PEVP_CIPHER_CTX): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_CIPHER_CTX_reset(c));
end;
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

{# define  OPENSSL_add_all_algorithms_conf() OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS | OPENSSL_INIT_LOAD_CONFIG,
 NULL)}

function OPENSSL_add_all_algorithms_conf(): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_init_crypto((OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS) or OPENSSL_INIT_LOAD_CONFIG,nil));
end;

{# define  OPENSSL_add_all_algorithms_noconf() OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, 
NULL)}

function OPENSSL_add_all_algorithms_noconf(): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS or OPENSSL_INIT_ADD_ALL_DIGESTS,nil));
end;
    {$ifdef OPENSSL_LOAD_CONF}

{# define  OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_conf()}

function OpenSSL_add_all_algorithms(): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_add_all_algorithms_conf);
end;
    {$else}

{# define  OpenSSL_add_all_algorithms() OPENSSL_add_all_algorithms_noconf()}

function OpenSSL_add_all_algorithms(): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_add_all_algorithms_noconf);
end;
  {$endif} {OPENSSL_LOAD_CONF}

{# define  OpenSSL_add_all_ciphers() OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)}

function OpenSSL_add_all_ciphers(): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS,nil));
end;

{# define  OpenSSL_add_all_digests() OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)}

function OpenSSL_add_all_digests(): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS,nil));
end;
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}

{# define  EVP_PKEY_set1_tls_encodedpoint(pkey,pt,ptlen) EVP_PKEY_set1_encoded_public_key((pkey), (pt), (ptlen))}

function EVP_PKEY_set1_tls_encodedpoint(pkey:PEVP_PKEY; pt:Pbyte; ptlen:TOpenSSL_C_SIZET): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(EVP_PKEY_set1_encoded_public_key(pkey,pt,ptlen));
end;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}

{# define  EVP_PKEY_get1_tls_encodedpoint(pkey,ppt) EVP_PKEY_get1_encoded_public_key((pkey), (ppt))}

function EVP_PKEY_get1_tls_encodedpoint(pkey:PEVP_PKEY; ppt:PPbyte): TOpenSSL_C_SIZET;
begin
  Result := TOpenSSL_C_SIZET(EVP_PKEY_get1_encoded_public_key(pkey,ppt));
end;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_EVP_set_default_properties(libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_set_default_properties := LoadLibCryptoFunction('EVP_set_default_properties');
  if not assigned(EVP_set_default_properties) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_set_default_properties');
  Result := EVP_set_default_properties(libctx, propq);
end;

function Load_EVP_get1_default_properties(libctx: POSSL_LIB_CTX): PAnsiChar; cdecl;
begin
  EVP_get1_default_properties := LoadLibCryptoFunction('EVP_get1_default_properties');
  if not assigned(EVP_get1_default_properties) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get1_default_properties');
  Result := EVP_get1_default_properties(libctx);
end;

function Load_EVP_default_properties_is_fips_enabled(libctx: POSSL_LIB_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_default_properties_is_fips_enabled := LoadLibCryptoFunction('EVP_default_properties_is_fips_enabled');
  if not assigned(EVP_default_properties_is_fips_enabled) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_default_properties_is_fips_enabled');
  Result := EVP_default_properties_is_fips_enabled(libctx);
end;

function Load_EVP_default_properties_enable_fips(libctx: POSSL_LIB_CTX; enable: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_default_properties_enable_fips := LoadLibCryptoFunction('EVP_default_properties_enable_fips');
  if not assigned(EVP_default_properties_enable_fips) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_default_properties_enable_fips');
  Result := EVP_default_properties_enable_fips(libctx, enable);
end;

{$ifndef  EVP_MD}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl;
begin
  EVP_MD_meth_new := LoadLibCryptoFunction('EVP_MD_meth_new');
  if not assigned(EVP_MD_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_new');
  Result := EVP_MD_meth_new(md_type, pkey_type);
end;

function Load_EVP_MD_meth_dup(md: PEVP_MD): PEVP_MD; cdecl;
begin
  EVP_MD_meth_dup := LoadLibCryptoFunction('EVP_MD_meth_dup');
  if not assigned(EVP_MD_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_dup');
  Result := EVP_MD_meth_dup(md);
end;

procedure Load_EVP_MD_meth_free(md: PEVP_MD); cdecl;
begin
  EVP_MD_meth_free := LoadLibCryptoFunction('EVP_MD_meth_free');
  if not assigned(EVP_MD_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_free');
  EVP_MD_meth_free(md);
end;

function Load_EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_input_blocksize := LoadLibCryptoFunction('EVP_MD_meth_set_input_blocksize');
  if not assigned(EVP_MD_meth_set_input_blocksize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_input_blocksize');
  Result := EVP_MD_meth_set_input_blocksize(md, blocksize);
end;

function Load_EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_result_size := LoadLibCryptoFunction('EVP_MD_meth_set_result_size');
  if not assigned(EVP_MD_meth_set_result_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_result_size');
  Result := EVP_MD_meth_set_result_size(md, resultsize);
end;

function Load_EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_app_datasize := LoadLibCryptoFunction('EVP_MD_meth_set_app_datasize');
  if not assigned(EVP_MD_meth_set_app_datasize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_app_datasize');
  Result := EVP_MD_meth_set_app_datasize(md, datasize);
end;

function Load_EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_flags := LoadLibCryptoFunction('EVP_MD_meth_set_flags');
  if not assigned(EVP_MD_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_flags');
  Result := EVP_MD_meth_set_flags(md, flags);
end;

function Load_EVP_MD_meth_set_init(md: PEVP_MD; init: TFuncType000): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_init := LoadLibCryptoFunction('EVP_MD_meth_set_init');
  if not assigned(EVP_MD_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_init');
  Result := EVP_MD_meth_set_init(md, init);
end;

function Load_EVP_MD_meth_set_update(md: PEVP_MD; update: TFuncType001): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_update := LoadLibCryptoFunction('EVP_MD_meth_set_update');
  if not assigned(EVP_MD_meth_set_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_update');
  Result := EVP_MD_meth_set_update(md, update);
end;

function Load_EVP_MD_meth_set_final(md: PEVP_MD; final: TFuncType002): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_final := LoadLibCryptoFunction('EVP_MD_meth_set_final');
  if not assigned(EVP_MD_meth_set_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_final');
  Result := EVP_MD_meth_set_final(md, final);
end;

function Load_EVP_MD_meth_set_copy(md: PEVP_MD; copy: TFuncType003): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_copy := LoadLibCryptoFunction('EVP_MD_meth_set_copy');
  if not assigned(EVP_MD_meth_set_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_copy');
  Result := EVP_MD_meth_set_copy(md, copy);
end;

function Load_EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: TFuncType004): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_cleanup := LoadLibCryptoFunction('EVP_MD_meth_set_cleanup');
  if not assigned(EVP_MD_meth_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_cleanup');
  Result := EVP_MD_meth_set_cleanup(md, cleanup);
end;

function Load_EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: TFuncType005): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_set_ctrl := LoadLibCryptoFunction('EVP_MD_meth_set_ctrl');
  if not assigned(EVP_MD_meth_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_ctrl');
  Result := EVP_MD_meth_set_ctrl(md, ctrl);
end;

function Load_EVP_MD_meth_get_input_blocksize(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_get_input_blocksize := LoadLibCryptoFunction('EVP_MD_meth_get_input_blocksize');
  if not assigned(EVP_MD_meth_get_input_blocksize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_input_blocksize');
  Result := EVP_MD_meth_get_input_blocksize(md);
end;

function Load_EVP_MD_meth_get_result_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_get_result_size := LoadLibCryptoFunction('EVP_MD_meth_get_result_size');
  if not assigned(EVP_MD_meth_get_result_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_result_size');
  Result := EVP_MD_meth_get_result_size(md);
end;

function Load_EVP_MD_meth_get_app_datasize(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_meth_get_app_datasize := LoadLibCryptoFunction('EVP_MD_meth_get_app_datasize');
  if not assigned(EVP_MD_meth_get_app_datasize) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_app_datasize');
  Result := EVP_MD_meth_get_app_datasize(md);
end;

function Load_EVP_MD_meth_get_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl;
begin
  EVP_MD_meth_get_flags := LoadLibCryptoFunction('EVP_MD_meth_get_flags');
  if not assigned(EVP_MD_meth_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_flags');
  Result := EVP_MD_meth_get_flags(md);
end;

function Load_EVP_MD_meth_get_init(md: PEVP_MD): TFuncType006; cdecl;
begin
  EVP_MD_meth_get_init := LoadLibCryptoFunction('EVP_MD_meth_get_init');
  if not assigned(EVP_MD_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_init');
  Result := EVP_MD_meth_get_init(md);
end;

function Load_EVP_MD_meth_get_update(md: PEVP_MD): TFuncType007; cdecl;
begin
  EVP_MD_meth_get_update := LoadLibCryptoFunction('EVP_MD_meth_get_update');
  if not assigned(EVP_MD_meth_get_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_update');
  Result := EVP_MD_meth_get_update(md);
end;

function Load_EVP_MD_meth_get_final(md: PEVP_MD): TFuncType008; cdecl;
begin
  EVP_MD_meth_get_final := LoadLibCryptoFunction('EVP_MD_meth_get_final');
  if not assigned(EVP_MD_meth_get_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_final');
  Result := EVP_MD_meth_get_final(md);
end;

function Load_EVP_MD_meth_get_copy(md: PEVP_MD): TFuncType009; cdecl;
begin
  EVP_MD_meth_get_copy := LoadLibCryptoFunction('EVP_MD_meth_get_copy');
  if not assigned(EVP_MD_meth_get_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_copy');
  Result := EVP_MD_meth_get_copy(md);
end;

function Load_EVP_MD_meth_get_cleanup(md: PEVP_MD): TFuncType010; cdecl;
begin
  EVP_MD_meth_get_cleanup := LoadLibCryptoFunction('EVP_MD_meth_get_cleanup');
  if not assigned(EVP_MD_meth_get_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_cleanup');
  Result := EVP_MD_meth_get_cleanup(md);
end;

function Load_EVP_MD_meth_get_ctrl(md: PEVP_MD): TFuncType011; cdecl;
begin
  EVP_MD_meth_get_ctrl := LoadLibCryptoFunction('EVP_MD_meth_get_ctrl');
  if not assigned(EVP_MD_meth_get_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_ctrl');
  Result := EVP_MD_meth_get_ctrl(md);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { EVP_MD}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_meth_new := LoadLibCryptoFunction('EVP_CIPHER_meth_new');
  if not assigned(EVP_CIPHER_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_new');
  Result := EVP_CIPHER_meth_new(cipher_type, block_size, key_len);
end;

function Load_EVP_CIPHER_meth_dup(cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_meth_dup := LoadLibCryptoFunction('EVP_CIPHER_meth_dup');
  if not assigned(EVP_CIPHER_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_dup');
  Result := EVP_CIPHER_meth_dup(cipher);
end;

procedure Load_EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl;
begin
  EVP_CIPHER_meth_free := LoadLibCryptoFunction('EVP_CIPHER_meth_free');
  if not assigned(EVP_CIPHER_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_free');
  EVP_CIPHER_meth_free(cipher);
end;

function Load_EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_iv_length := LoadLibCryptoFunction('EVP_CIPHER_meth_set_iv_length');
  if not assigned(EVP_CIPHER_meth_set_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_iv_length');
  Result := EVP_CIPHER_meth_set_iv_length(cipher, iv_len);
end;

function Load_EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_flags := LoadLibCryptoFunction('EVP_CIPHER_meth_set_flags');
  if not assigned(EVP_CIPHER_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_flags');
  Result := EVP_CIPHER_meth_set_flags(cipher, flags);
end;

function Load_EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_impl_ctx_size := LoadLibCryptoFunction('EVP_CIPHER_meth_set_impl_ctx_size');
  if not assigned(EVP_CIPHER_meth_set_impl_ctx_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_impl_ctx_size');
  Result := EVP_CIPHER_meth_set_impl_ctx_size(cipher, ctx_size);
end;

function Load_EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: TFuncType012): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_init := LoadLibCryptoFunction('EVP_CIPHER_meth_set_init');
  if not assigned(EVP_CIPHER_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_init');
  Result := EVP_CIPHER_meth_set_init(cipher, init);
end;

function Load_EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: TFuncType013): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_do_cipher := LoadLibCryptoFunction('EVP_CIPHER_meth_set_do_cipher');
  if not assigned(EVP_CIPHER_meth_set_do_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_do_cipher');
  Result := EVP_CIPHER_meth_set_do_cipher(cipher, do_cipher);
end;

function Load_EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: TFuncType014): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_cleanup := LoadLibCryptoFunction('EVP_CIPHER_meth_set_cleanup');
  if not assigned(EVP_CIPHER_meth_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_cleanup');
  Result := EVP_CIPHER_meth_set_cleanup(cipher, cleanup);
end;

function Load_EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: TFuncType015): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_set_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_set_set_asn1_params');
  if not assigned(EVP_CIPHER_meth_set_set_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_set_asn1_params');
  Result := EVP_CIPHER_meth_set_set_asn1_params(cipher, set_asn1_parameters);
end;

function Load_EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: TFuncType016): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_get_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_set_get_asn1_params');
  if not assigned(EVP_CIPHER_meth_set_get_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_get_asn1_params');
  Result := EVP_CIPHER_meth_set_get_asn1_params(cipher, get_asn1_parameters);
end;

function Load_EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: TFuncType017): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_meth_set_ctrl := LoadLibCryptoFunction('EVP_CIPHER_meth_set_ctrl');
  if not assigned(EVP_CIPHER_meth_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_ctrl');
  Result := EVP_CIPHER_meth_set_ctrl(cipher, ctrl);
end;

function Load_EVP_CIPHER_meth_get_init(cipher: PEVP_CIPHER): TFuncType018; cdecl;
begin
  EVP_CIPHER_meth_get_init := LoadLibCryptoFunction('EVP_CIPHER_meth_get_init');
  if not assigned(EVP_CIPHER_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_init');
  Result := EVP_CIPHER_meth_get_init(cipher);
end;

function Load_EVP_CIPHER_meth_get_do_cipher(cipher: PEVP_CIPHER): TFuncType019; cdecl;
begin
  EVP_CIPHER_meth_get_do_cipher := LoadLibCryptoFunction('EVP_CIPHER_meth_get_do_cipher');
  if not assigned(EVP_CIPHER_meth_get_do_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_do_cipher');
  Result := EVP_CIPHER_meth_get_do_cipher(cipher);
end;

function Load_EVP_CIPHER_meth_get_cleanup(cipher: PEVP_CIPHER): TFuncType020; cdecl;
begin
  EVP_CIPHER_meth_get_cleanup := LoadLibCryptoFunction('EVP_CIPHER_meth_get_cleanup');
  if not assigned(EVP_CIPHER_meth_get_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_cleanup');
  Result := EVP_CIPHER_meth_get_cleanup(cipher);
end;

function Load_EVP_CIPHER_meth_get_set_asn1_params(cipher: PEVP_CIPHER): TFuncType021; cdecl;
begin
  EVP_CIPHER_meth_get_set_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_get_set_asn1_params');
  if not assigned(EVP_CIPHER_meth_get_set_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_set_asn1_params');
  Result := EVP_CIPHER_meth_get_set_asn1_params(cipher);
end;

function Load_EVP_CIPHER_meth_get_get_asn1_params(cipher: PEVP_CIPHER): TFuncType022; cdecl;
begin
  EVP_CIPHER_meth_get_get_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_get_get_asn1_params');
  if not assigned(EVP_CIPHER_meth_get_get_asn1_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_get_asn1_params');
  Result := EVP_CIPHER_meth_get_get_asn1_params(cipher);
end;

function Load_EVP_CIPHER_meth_get_ctrl(cipher: PEVP_CIPHER): TFuncType023; cdecl;
begin
  EVP_CIPHER_meth_get_ctrl := LoadLibCryptoFunction('EVP_CIPHER_meth_get_ctrl');
  if not assigned(EVP_CIPHER_meth_get_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_ctrl');
  Result := EVP_CIPHER_meth_get_ctrl(cipher);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_Cipher(c: PEVP_CIPHER_CTX; out_: Pbyte; in_: Pbyte; inl: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EVP_Cipher := LoadLibCryptoFunction('EVP_Cipher');
  if not assigned(EVP_Cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_Cipher');
  Result := EVP_Cipher(c, out_, in_, inl);
end;

function Load_EVP_MD_get_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_get_type := LoadLibCryptoFunction('EVP_MD_get_type');
  if not assigned(EVP_MD_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_type');
  Result := EVP_MD_get_type(md);
end;

function Load_EVP_MD_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_type := LoadLibCryptoFunction('EVP_MD_get_type');
  if not assigned(EVP_MD_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_type');
  Result := EVP_MD_type(md);
end;

function Load_EVP_MD_nid(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_nid := LoadLibCryptoFunction('EVP_MD_get_type');
  if not assigned(EVP_MD_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_type');
  Result := EVP_MD_nid(md);
end;

function Load_EVP_MD_get0_name(md: PEVP_MD): PAnsiChar; cdecl;
begin
  EVP_MD_get0_name := LoadLibCryptoFunction('EVP_MD_get0_name');
  if not assigned(EVP_MD_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get0_name');
  Result := EVP_MD_get0_name(md);
end;

function Load_EVP_MD_name(md: PEVP_MD): PAnsiChar; cdecl;
begin
  EVP_MD_name := LoadLibCryptoFunction('EVP_MD_get0_name');
  if not assigned(EVP_MD_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get0_name');
  Result := EVP_MD_name(md);
end;

function Load_EVP_MD_get0_description(md: PEVP_MD): PAnsiChar; cdecl;
begin
  EVP_MD_get0_description := LoadLibCryptoFunction('EVP_MD_get0_description');
  if not assigned(EVP_MD_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get0_description');
  Result := EVP_MD_get0_description(md);
end;

function Load_EVP_MD_is_a(md: PEVP_MD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_is_a := LoadLibCryptoFunction('EVP_MD_is_a');
  if not assigned(EVP_MD_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_is_a');
  Result := EVP_MD_is_a(md, name);
end;

function Load_EVP_MD_names_do_all(md: PEVP_MD; fn: TFuncType024; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_names_do_all := LoadLibCryptoFunction('EVP_MD_names_do_all');
  if not assigned(EVP_MD_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_names_do_all');
  Result := EVP_MD_names_do_all(md, fn, data);
end;

function Load_EVP_MD_get0_provider(md: PEVP_MD): POSSL_PROVIDER; cdecl;
begin
  EVP_MD_get0_provider := LoadLibCryptoFunction('EVP_MD_get0_provider');
  if not assigned(EVP_MD_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get0_provider');
  Result := EVP_MD_get0_provider(md);
end;

function Load_EVP_MD_get_pkey_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_get_pkey_type := LoadLibCryptoFunction('EVP_MD_get_pkey_type');
  if not assigned(EVP_MD_get_pkey_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_pkey_type');
  Result := EVP_MD_get_pkey_type(md);
end;

function Load_EVP_MD_pkey_type(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_pkey_type := LoadLibCryptoFunction('EVP_MD_get_pkey_type');
  if not assigned(EVP_MD_pkey_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_pkey_type');
  Result := EVP_MD_pkey_type(md);
end;

function Load_EVP_MD_get_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_get_size := LoadLibCryptoFunction('EVP_MD_get_size');
  if not assigned(EVP_MD_get_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_size');
  Result := EVP_MD_get_size(md);
end;

function Load_EVP_MD_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_size := LoadLibCryptoFunction('EVP_MD_get_size');
  if not assigned(EVP_MD_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_size');
  Result := EVP_MD_size(md);
end;

function Load_EVP_MD_get_block_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_get_block_size := LoadLibCryptoFunction('EVP_MD_get_block_size');
  if not assigned(EVP_MD_get_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_block_size');
  Result := EVP_MD_get_block_size(md);
end;

function Load_EVP_MD_block_size(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_block_size := LoadLibCryptoFunction('EVP_MD_get_block_size');
  if not assigned(EVP_MD_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_block_size');
  Result := EVP_MD_block_size(md);
end;

function Load_EVP_MD_get_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl;
begin
  EVP_MD_get_flags := LoadLibCryptoFunction('EVP_MD_get_flags');
  if not assigned(EVP_MD_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_flags');
  Result := EVP_MD_get_flags(md);
end;

function Load_EVP_MD_flags(md: PEVP_MD): TOpenSSL_C_UINT; cdecl;
begin
  EVP_MD_flags := LoadLibCryptoFunction('EVP_MD_get_flags');
  if not assigned(EVP_MD_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_flags');
  Result := EVP_MD_flags(md);
end;

function Load_EVP_MD_xof(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_xof := LoadLibCryptoFunction('EVP_MD_xof');
  if not assigned(EVP_MD_xof) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_xof');
  Result := EVP_MD_xof(md);
end;

function Load_EVP_MD_CTX_get0_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;
begin
  EVP_MD_CTX_get0_md := LoadLibCryptoFunction('EVP_MD_CTX_get0_md');
  if not assigned(EVP_MD_CTX_get0_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get0_md');
  Result := EVP_MD_CTX_get0_md(ctx);
end;

function Load_EVP_MD_CTX_get1_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;
begin
  EVP_MD_CTX_get1_md := LoadLibCryptoFunction('EVP_MD_CTX_get1_md');
  if not assigned(EVP_MD_CTX_get1_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get1_md');
  Result := EVP_MD_CTX_get1_md(ctx);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;
begin
  EVP_MD_CTX_md := LoadLibCryptoFunction('EVP_MD_CTX_md');
  if not assigned(EVP_MD_CTX_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_md');
  Result := EVP_MD_CTX_md(ctx);
end;

function Load_EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): TFuncType025; cdecl;
begin
  EVP_MD_CTX_update_fn := LoadLibCryptoFunction('EVP_MD_CTX_update_fn');
  if not assigned(EVP_MD_CTX_update_fn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_update_fn');
  Result := EVP_MD_CTX_update_fn(ctx);
end;

procedure Load_EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: TFuncType026); cdecl;
begin
  EVP_MD_CTX_set_update_fn := LoadLibCryptoFunction('EVP_MD_CTX_set_update_fn');
  if not assigned(EVP_MD_CTX_set_update_fn) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_update_fn');
  EVP_MD_CTX_set_update_fn(ctx, update);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_MD_CTX_get_size_ex(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_get_size_ex := LoadLibCryptoFunction('EVP_MD_CTX_get_size_ex');
  if not assigned(EVP_MD_CTX_get_size_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get_size_ex');
  Result := EVP_MD_CTX_get_size_ex(ctx);
end;

function Load_EVP_MD_CTX_size(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_size := LoadLibCryptoFunction('EVP_MD_CTX_get_size_ex');
  if not assigned(EVP_MD_CTX_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get_size_ex');
  Result := EVP_MD_CTX_size(ctx);
end;

function Load_EVP_MD_CTX_get_pkey_ctx(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl;
begin
  EVP_MD_CTX_get_pkey_ctx := LoadLibCryptoFunction('EVP_MD_CTX_get_pkey_ctx');
  if not assigned(EVP_MD_CTX_get_pkey_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get_pkey_ctx');
  Result := EVP_MD_CTX_get_pkey_ctx(ctx);
end;

function Load_EVP_MD_CTX_pkey_ctx(ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl;
begin
  EVP_MD_CTX_pkey_ctx := LoadLibCryptoFunction('EVP_MD_CTX_get_pkey_ctx');
  if not assigned(EVP_MD_CTX_pkey_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get_pkey_ctx');
  Result := EVP_MD_CTX_pkey_ctx(ctx);
end;

procedure Load_EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl;
begin
  EVP_MD_CTX_set_pkey_ctx := LoadLibCryptoFunction('EVP_MD_CTX_set_pkey_ctx');
  if not assigned(EVP_MD_CTX_set_pkey_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_pkey_ctx');
  EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
end;

function Load_EVP_MD_CTX_get0_md_data(ctx: PEVP_MD_CTX): pointer; cdecl;
begin
  EVP_MD_CTX_get0_md_data := LoadLibCryptoFunction('EVP_MD_CTX_get0_md_data');
  if not assigned(EVP_MD_CTX_get0_md_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get0_md_data');
  Result := EVP_MD_CTX_get0_md_data(ctx);
end;

function Load_EVP_MD_CTX_md_data(ctx: PEVP_MD_CTX): pointer; cdecl;
begin
  EVP_MD_CTX_md_data := LoadLibCryptoFunction('EVP_MD_CTX_get0_md_data');
  if not assigned(EVP_MD_CTX_md_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get0_md_data');
  Result := EVP_MD_CTX_md_data(ctx);
end;

function Load_EVP_CIPHER_get_nid(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_nid := LoadLibCryptoFunction('EVP_CIPHER_get_nid');
  if not assigned(EVP_CIPHER_get_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_nid');
  Result := EVP_CIPHER_get_nid(cipher);
end;

function Load_EVP_CIPHER_nid(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_nid := LoadLibCryptoFunction('EVP_CIPHER_get_nid');
  if not assigned(EVP_CIPHER_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_nid');
  Result := EVP_CIPHER_nid(cipher);
end;

function Load_EVP_CIPHER_get0_name(cipher: PEVP_CIPHER): PAnsiChar; cdecl;
begin
  EVP_CIPHER_get0_name := LoadLibCryptoFunction('EVP_CIPHER_get0_name');
  if not assigned(EVP_CIPHER_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get0_name');
  Result := EVP_CIPHER_get0_name(cipher);
end;

function Load_EVP_CIPHER_name(cipher: PEVP_CIPHER): PAnsiChar; cdecl;
begin
  EVP_CIPHER_name := LoadLibCryptoFunction('EVP_CIPHER_get0_name');
  if not assigned(EVP_CIPHER_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get0_name');
  Result := EVP_CIPHER_name(cipher);
end;

function Load_EVP_CIPHER_get0_description(cipher: PEVP_CIPHER): PAnsiChar; cdecl;
begin
  EVP_CIPHER_get0_description := LoadLibCryptoFunction('EVP_CIPHER_get0_description');
  if not assigned(EVP_CIPHER_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get0_description');
  Result := EVP_CIPHER_get0_description(cipher);
end;

function Load_EVP_CIPHER_is_a(cipher: PEVP_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_is_a := LoadLibCryptoFunction('EVP_CIPHER_is_a');
  if not assigned(EVP_CIPHER_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_is_a');
  Result := EVP_CIPHER_is_a(cipher, name);
end;

function Load_EVP_CIPHER_names_do_all(cipher: PEVP_CIPHER; fn: TFuncType027; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_names_do_all := LoadLibCryptoFunction('EVP_CIPHER_names_do_all');
  if not assigned(EVP_CIPHER_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_names_do_all');
  Result := EVP_CIPHER_names_do_all(cipher, fn, data);
end;

function Load_EVP_CIPHER_get0_provider(cipher: PEVP_CIPHER): POSSL_PROVIDER; cdecl;
begin
  EVP_CIPHER_get0_provider := LoadLibCryptoFunction('EVP_CIPHER_get0_provider');
  if not assigned(EVP_CIPHER_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get0_provider');
  Result := EVP_CIPHER_get0_provider(cipher);
end;

function Load_EVP_CIPHER_get_block_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_block_size := LoadLibCryptoFunction('EVP_CIPHER_get_block_size');
  if not assigned(EVP_CIPHER_get_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_block_size');
  Result := EVP_CIPHER_get_block_size(cipher);
end;

function Load_EVP_CIPHER_block_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_block_size := LoadLibCryptoFunction('EVP_CIPHER_get_block_size');
  if not assigned(EVP_CIPHER_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_block_size');
  Result := EVP_CIPHER_block_size(cipher);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_CIPHER_impl_ctx_size(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_impl_ctx_size := LoadLibCryptoFunction('EVP_CIPHER_impl_ctx_size');
  if not assigned(EVP_CIPHER_impl_ctx_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_impl_ctx_size');
  Result := EVP_CIPHER_impl_ctx_size(cipher);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_CIPHER_get_key_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_key_length := LoadLibCryptoFunction('EVP_CIPHER_get_key_length');
  if not assigned(EVP_CIPHER_get_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_key_length');
  Result := EVP_CIPHER_get_key_length(cipher);
end;

function Load_EVP_CIPHER_key_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_key_length := LoadLibCryptoFunction('EVP_CIPHER_get_key_length');
  if not assigned(EVP_CIPHER_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_key_length');
  Result := EVP_CIPHER_key_length(cipher);
end;

function Load_EVP_CIPHER_get_iv_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_iv_length := LoadLibCryptoFunction('EVP_CIPHER_get_iv_length');
  if not assigned(EVP_CIPHER_get_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_iv_length');
  Result := EVP_CIPHER_get_iv_length(cipher);
end;

function Load_EVP_CIPHER_iv_length(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_iv_length := LoadLibCryptoFunction('EVP_CIPHER_get_iv_length');
  if not assigned(EVP_CIPHER_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_iv_length');
  Result := EVP_CIPHER_iv_length(cipher);
end;

function Load_EVP_CIPHER_get_flags(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl;
begin
  EVP_CIPHER_get_flags := LoadLibCryptoFunction('EVP_CIPHER_get_flags');
  if not assigned(EVP_CIPHER_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_flags');
  Result := EVP_CIPHER_get_flags(cipher);
end;

function Load_EVP_CIPHER_flags(cipher: PEVP_CIPHER): TOpenSSL_C_UINT; cdecl;
begin
  EVP_CIPHER_flags := LoadLibCryptoFunction('EVP_CIPHER_get_flags');
  if not assigned(EVP_CIPHER_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_flags');
  Result := EVP_CIPHER_flags(cipher);
end;

function Load_EVP_CIPHER_get_mode(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_mode := LoadLibCryptoFunction('EVP_CIPHER_get_mode');
  if not assigned(EVP_CIPHER_get_mode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_mode');
  Result := EVP_CIPHER_get_mode(cipher);
end;

function Load_EVP_CIPHER_mode(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_mode := LoadLibCryptoFunction('EVP_CIPHER_get_mode');
  if not assigned(EVP_CIPHER_mode) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_mode');
  Result := EVP_CIPHER_mode(cipher);
end;

function Load_EVP_CIPHER_get_type(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_type := LoadLibCryptoFunction('EVP_CIPHER_get_type');
  if not assigned(EVP_CIPHER_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_type');
  Result := EVP_CIPHER_get_type(cipher);
end;

function Load_EVP_CIPHER_type(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_type := LoadLibCryptoFunction('EVP_CIPHER_get_type');
  if not assigned(EVP_CIPHER_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_type');
  Result := EVP_CIPHER_type(cipher);
end;

function Load_EVP_CIPHER_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_fetch := LoadLibCryptoFunction('EVP_CIPHER_fetch');
  if not assigned(EVP_CIPHER_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_fetch');
  Result := EVP_CIPHER_fetch(ctx, algorithm, properties);
end;

function Load_EVP_CIPHER_can_pipeline(cipher: PEVP_CIPHER; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_can_pipeline := LoadLibCryptoFunction('EVP_CIPHER_can_pipeline');
  if not assigned(EVP_CIPHER_can_pipeline) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_can_pipeline');
  Result := EVP_CIPHER_can_pipeline(cipher, enc);
end;

function Load_EVP_CIPHER_up_ref(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_up_ref := LoadLibCryptoFunction('EVP_CIPHER_up_ref');
  if not assigned(EVP_CIPHER_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_up_ref');
  Result := EVP_CIPHER_up_ref(cipher);
end;

procedure Load_EVP_CIPHER_free(cipher: PEVP_CIPHER); cdecl;
begin
  EVP_CIPHER_free := LoadLibCryptoFunction('EVP_CIPHER_free');
  if not assigned(EVP_CIPHER_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_free');
  EVP_CIPHER_free(cipher);
end;

function Load_EVP_CIPHER_CTX_get0_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_CTX_get0_cipher := LoadLibCryptoFunction('EVP_CIPHER_CTX_get0_cipher');
  if not assigned(EVP_CIPHER_CTX_get0_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get0_cipher');
  Result := EVP_CIPHER_CTX_get0_cipher(ctx);
end;

function Load_EVP_CIPHER_CTX_get1_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_CTX_get1_cipher := LoadLibCryptoFunction('EVP_CIPHER_CTX_get1_cipher');
  if not assigned(EVP_CIPHER_CTX_get1_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get1_cipher');
  Result := EVP_CIPHER_CTX_get1_cipher(ctx);
end;

function Load_EVP_CIPHER_CTX_is_encrypting(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_is_encrypting := LoadLibCryptoFunction('EVP_CIPHER_CTX_is_encrypting');
  if not assigned(EVP_CIPHER_CTX_is_encrypting) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_is_encrypting');
  Result := EVP_CIPHER_CTX_is_encrypting(ctx);
end;

function Load_EVP_CIPHER_CTX_encrypting(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_encrypting := LoadLibCryptoFunction('EVP_CIPHER_CTX_is_encrypting');
  if not assigned(EVP_CIPHER_CTX_encrypting) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_is_encrypting');
  Result := EVP_CIPHER_CTX_encrypting(ctx);
end;

function Load_EVP_CIPHER_CTX_get_nid(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_nid := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_nid');
  if not assigned(EVP_CIPHER_CTX_get_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_nid');
  Result := EVP_CIPHER_CTX_get_nid(ctx);
end;

function Load_EVP_CIPHER_CTX_nid(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_nid := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_nid');
  if not assigned(EVP_CIPHER_CTX_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_nid');
  Result := EVP_CIPHER_CTX_nid(ctx);
end;

function Load_EVP_CIPHER_CTX_get_block_size(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_block_size := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_block_size');
  if not assigned(EVP_CIPHER_CTX_get_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_block_size');
  Result := EVP_CIPHER_CTX_get_block_size(ctx);
end;

function Load_EVP_CIPHER_CTX_block_size(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_block_size := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_block_size');
  if not assigned(EVP_CIPHER_CTX_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_block_size');
  Result := EVP_CIPHER_CTX_block_size(ctx);
end;

function Load_EVP_CIPHER_CTX_get_key_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_key_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_key_length');
  if not assigned(EVP_CIPHER_CTX_get_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_key_length');
  Result := EVP_CIPHER_CTX_get_key_length(ctx);
end;

function Load_EVP_CIPHER_CTX_key_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_key_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_key_length');
  if not assigned(EVP_CIPHER_CTX_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_key_length');
  Result := EVP_CIPHER_CTX_key_length(ctx);
end;

function Load_EVP_CIPHER_CTX_get_iv_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_iv_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_iv_length');
  if not assigned(EVP_CIPHER_CTX_get_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_iv_length');
  Result := EVP_CIPHER_CTX_get_iv_length(ctx);
end;

function Load_EVP_CIPHER_CTX_iv_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_iv_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_iv_length');
  if not assigned(EVP_CIPHER_CTX_iv_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_iv_length');
  Result := EVP_CIPHER_CTX_iv_length(ctx);
end;

function Load_EVP_CIPHER_CTX_get_tag_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_tag_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_tag_length');
  if not assigned(EVP_CIPHER_CTX_get_tag_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_tag_length');
  Result := EVP_CIPHER_CTX_get_tag_length(ctx);
end;

function Load_EVP_CIPHER_CTX_tag_length(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_tag_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_tag_length');
  if not assigned(EVP_CIPHER_CTX_tag_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_tag_length');
  Result := EVP_CIPHER_CTX_tag_length(ctx);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_CIPHER_CTX_cipher(ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  EVP_CIPHER_CTX_cipher := LoadLibCryptoFunction('EVP_CIPHER_CTX_cipher');
  if not assigned(EVP_CIPHER_CTX_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_cipher');
  Result := EVP_CIPHER_CTX_cipher(ctx);
end;

function Load_EVP_CIPHER_CTX_iv(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;
begin
  EVP_CIPHER_CTX_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv');
  if not assigned(EVP_CIPHER_CTX_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv');
  Result := EVP_CIPHER_CTX_iv(ctx);
end;

function Load_EVP_CIPHER_CTX_original_iv(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;
begin
  EVP_CIPHER_CTX_original_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_original_iv');
  if not assigned(EVP_CIPHER_CTX_original_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_original_iv');
  Result := EVP_CIPHER_CTX_original_iv(ctx);
end;

function Load_EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;
begin
  EVP_CIPHER_CTX_iv_noconst := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv_noconst');
  if not assigned(EVP_CIPHER_CTX_iv_noconst) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv_noconst');
  Result := EVP_CIPHER_CTX_iv_noconst(ctx);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_CIPHER_CTX_get_updated_iv(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_updated_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_updated_iv');
  if not assigned(EVP_CIPHER_CTX_get_updated_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_updated_iv');
  Result := EVP_CIPHER_CTX_get_updated_iv(ctx, buf, len);
end;

function Load_EVP_CIPHER_CTX_get_original_iv(ctx: PEVP_CIPHER_CTX; buf: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_original_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_original_iv');
  if not assigned(EVP_CIPHER_CTX_get_original_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_original_iv');
  Result := EVP_CIPHER_CTX_get_original_iv(ctx, buf, len);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): Pbyte; cdecl;
begin
  EVP_CIPHER_CTX_buf_noconst := LoadLibCryptoFunction('EVP_CIPHER_CTX_buf_noconst');
  if not assigned(EVP_CIPHER_CTX_buf_noconst) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_buf_noconst');
  Result := EVP_CIPHER_CTX_buf_noconst(ctx);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_CIPHER_CTX_get_num(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_num := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_num');
  if not assigned(EVP_CIPHER_CTX_get_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_num');
  Result := EVP_CIPHER_CTX_get_num(ctx);
end;

function Load_EVP_CIPHER_CTX_num(ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_num := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_num');
  if not assigned(EVP_CIPHER_CTX_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_num');
  Result := EVP_CIPHER_CTX_num(ctx);
end;

function Load_EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_set_num := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_num');
  if not assigned(EVP_CIPHER_CTX_set_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_num');
  Result := EVP_CIPHER_CTX_set_num(ctx, num);
end;

function Load_EVP_CIPHER_CTX_dup(in_: PEVP_CIPHER_CTX): PEVP_CIPHER_CTX; cdecl;
begin
  EVP_CIPHER_CTX_dup := LoadLibCryptoFunction('EVP_CIPHER_CTX_dup');
  if not assigned(EVP_CIPHER_CTX_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_dup');
  Result := EVP_CIPHER_CTX_dup(in_);
end;

function Load_EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_copy := LoadLibCryptoFunction('EVP_CIPHER_CTX_copy');
  if not assigned(EVP_CIPHER_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_copy');
  Result := EVP_CIPHER_CTX_copy(out_, in_);
end;

function Load_EVP_CIPHER_CTX_get_app_data(ctx: PEVP_CIPHER_CTX): pointer; cdecl;
begin
  EVP_CIPHER_CTX_get_app_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_app_data');
  if not assigned(EVP_CIPHER_CTX_get_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_app_data');
  Result := EVP_CIPHER_CTX_get_app_data(ctx);
end;

procedure Load_EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: pointer); cdecl;
begin
  EVP_CIPHER_CTX_set_app_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_app_data');
  if not assigned(EVP_CIPHER_CTX_set_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_app_data');
  EVP_CIPHER_CTX_set_app_data(ctx, data);
end;

function Load_EVP_CIPHER_CTX_get_cipher_data(ctx: PEVP_CIPHER_CTX): pointer; cdecl;
begin
  EVP_CIPHER_CTX_get_cipher_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_cipher_data');
  if not assigned(EVP_CIPHER_CTX_get_cipher_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_cipher_data');
  Result := EVP_CIPHER_CTX_get_cipher_data(ctx);
end;

function Load_EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: pointer): pointer; cdecl;
begin
  EVP_CIPHER_CTX_set_cipher_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_cipher_data');
  if not assigned(EVP_CIPHER_CTX_set_cipher_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_cipher_data');
  Result := EVP_CIPHER_CTX_set_cipher_data(ctx, cipher_data);
end;

{$ifdef CONST_STRICT}
procedure Load_BIO_set_md(_param1: PBIO; md: PEVP_MD); cdecl;
begin
  BIO_set_md := LoadLibCryptoFunction('BIO_set_md');
  if not assigned(BIO_set_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_md');
  BIO_set_md(_param1, md);
end;

{$endif} {CONST_STRICT}
function Load_EVP_MD_get_params(digest: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_get_params := LoadLibCryptoFunction('EVP_MD_get_params');
  if not assigned(EVP_MD_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_get_params');
  Result := EVP_MD_get_params(digest, params);
end;

function Load_EVP_MD_CTX_set_params(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_set_params := LoadLibCryptoFunction('EVP_MD_CTX_set_params');
  if not assigned(EVP_MD_CTX_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_params');
  Result := EVP_MD_CTX_set_params(ctx, params);
end;

function Load_EVP_MD_CTX_get_params(ctx: PEVP_MD_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_get_params := LoadLibCryptoFunction('EVP_MD_CTX_get_params');
  if not assigned(EVP_MD_CTX_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_get_params');
  Result := EVP_MD_CTX_get_params(ctx, params);
end;

function Load_EVP_MD_gettable_params(digest: PEVP_MD): POSSL_PARAM; cdecl;
begin
  EVP_MD_gettable_params := LoadLibCryptoFunction('EVP_MD_gettable_params');
  if not assigned(EVP_MD_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_gettable_params');
  Result := EVP_MD_gettable_params(digest);
end;

function Load_EVP_MD_settable_ctx_params(md: PEVP_MD): POSSL_PARAM; cdecl;
begin
  EVP_MD_settable_ctx_params := LoadLibCryptoFunction('EVP_MD_settable_ctx_params');
  if not assigned(EVP_MD_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_settable_ctx_params');
  Result := EVP_MD_settable_ctx_params(md);
end;

function Load_EVP_MD_gettable_ctx_params(md: PEVP_MD): POSSL_PARAM; cdecl;
begin
  EVP_MD_gettable_ctx_params := LoadLibCryptoFunction('EVP_MD_gettable_ctx_params');
  if not assigned(EVP_MD_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_gettable_ctx_params');
  Result := EVP_MD_gettable_ctx_params(md);
end;

function Load_EVP_MD_CTX_settable_params(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl;
begin
  EVP_MD_CTX_settable_params := LoadLibCryptoFunction('EVP_MD_CTX_settable_params');
  if not assigned(EVP_MD_CTX_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_settable_params');
  Result := EVP_MD_CTX_settable_params(ctx);
end;

function Load_EVP_MD_CTX_gettable_params(ctx: PEVP_MD_CTX): POSSL_PARAM; cdecl;
begin
  EVP_MD_CTX_gettable_params := LoadLibCryptoFunction('EVP_MD_CTX_gettable_params');
  if not assigned(EVP_MD_CTX_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_gettable_params');
  Result := EVP_MD_CTX_gettable_params(ctx);
end;

function Load_EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_ctrl := LoadLibCryptoFunction('EVP_MD_CTX_ctrl');
  if not assigned(EVP_MD_CTX_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_ctrl');
  Result := EVP_MD_CTX_ctrl(ctx, cmd, p1, p2);
end;

function Load_EVP_MD_CTX_new: PEVP_MD_CTX; cdecl;
begin
  EVP_MD_CTX_new := LoadLibCryptoFunction('EVP_MD_CTX_new');
  if not assigned(EVP_MD_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_new');
  Result := EVP_MD_CTX_new;
end;

function Load_EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_reset := LoadLibCryptoFunction('EVP_MD_CTX_reset');
  if not assigned(EVP_MD_CTX_reset) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_reset');
  Result := EVP_MD_CTX_reset(ctx);
end;

procedure Load_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;
begin
  EVP_MD_CTX_free := LoadLibCryptoFunction('EVP_MD_CTX_free');
  if not assigned(EVP_MD_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_free');
  EVP_MD_CTX_free(ctx);
end;

function Load_EVP_MD_CTX_dup(in_: PEVP_MD_CTX): PEVP_MD_CTX; cdecl;
begin
  EVP_MD_CTX_dup := LoadLibCryptoFunction('EVP_MD_CTX_dup');
  if not assigned(EVP_MD_CTX_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_dup');
  Result := EVP_MD_CTX_dup(in_);
end;

function Load_EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_copy_ex := LoadLibCryptoFunction('EVP_MD_CTX_copy_ex');
  if not assigned(EVP_MD_CTX_copy_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_copy_ex');
  Result := EVP_MD_CTX_copy_ex(out_, in_);
end;

procedure Load_EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_MD_CTX_set_flags := LoadLibCryptoFunction('EVP_MD_CTX_set_flags');
  if not assigned(EVP_MD_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_flags');
  EVP_MD_CTX_set_flags(ctx, flags);
end;

procedure Load_EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_MD_CTX_clear_flags := LoadLibCryptoFunction('EVP_MD_CTX_clear_flags');
  if not assigned(EVP_MD_CTX_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_clear_flags');
  EVP_MD_CTX_clear_flags(ctx, flags);
end;

function Load_EVP_MD_CTX_test_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_test_flags := LoadLibCryptoFunction('EVP_MD_CTX_test_flags');
  if not assigned(EVP_MD_CTX_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_test_flags');
  Result := EVP_MD_CTX_test_flags(ctx, flags);
end;

function Load_EVP_DigestInit_ex2(ctx: PEVP_MD_CTX; type_: PEVP_MD; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestInit_ex2 := LoadLibCryptoFunction('EVP_DigestInit_ex2');
  if not assigned(EVP_DigestInit_ex2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestInit_ex2');
  Result := EVP_DigestInit_ex2(ctx, type_, params);
end;

function Load_EVP_DigestInit_ex(ctx: PEVP_MD_CTX; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestInit_ex := LoadLibCryptoFunction('EVP_DigestInit_ex');
  if not assigned(EVP_DigestInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestInit_ex');
  Result := EVP_DigestInit_ex(ctx, type_, impl);
end;

function Load_EVP_DigestUpdate(ctx: PEVP_MD_CTX; d: pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestUpdate := LoadLibCryptoFunction('EVP_DigestUpdate');
  if not assigned(EVP_DigestUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestUpdate');
  Result := EVP_DigestUpdate(ctx, d, cnt);
end;

function Load_EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestFinal_ex := LoadLibCryptoFunction('EVP_DigestFinal_ex');
  if not assigned(EVP_DigestFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinal_ex');
  Result := EVP_DigestFinal_ex(ctx, md, s);
end;

function Load_EVP_Digest(data: pointer; count: TOpenSSL_C_SIZET; md: Pbyte; size: POpenSSL_C_UINT; type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EVP_Digest := LoadLibCryptoFunction('EVP_Digest');
  if not assigned(EVP_Digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_Digest');
  Result := EVP_Digest(data, count, md, size, type_, impl);
end;

function Load_EVP_Q_digest(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; data: pointer; datalen: TOpenSSL_C_SIZET; md: Pbyte; mdlen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_Q_digest := LoadLibCryptoFunction('EVP_Q_digest');
  if not assigned(EVP_Q_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_Q_digest');
  Result := EVP_Q_digest(libctx, name, propq, data, datalen, md, mdlen);
end;

function Load_EVP_MD_CTX_copy(out_: PEVP_MD_CTX; in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_CTX_copy := LoadLibCryptoFunction('EVP_MD_CTX_copy');
  if not assigned(EVP_MD_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_copy');
  Result := EVP_MD_CTX_copy(out_, in_);
end;

function Load_EVP_DigestInit(ctx: PEVP_MD_CTX; type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestInit := LoadLibCryptoFunction('EVP_DigestInit');
  if not assigned(EVP_DigestInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestInit');
  Result := EVP_DigestInit(ctx, type_);
end;

function Load_EVP_DigestFinal(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestFinal := LoadLibCryptoFunction('EVP_DigestFinal');
  if not assigned(EVP_DigestFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinal');
  Result := EVP_DigestFinal(ctx, md, s);
end;

function Load_EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestFinalXOF := LoadLibCryptoFunction('EVP_DigestFinalXOF');
  if not assigned(EVP_DigestFinalXOF) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinalXOF');
  Result := EVP_DigestFinalXOF(ctx, out_, outlen);
end;

function Load_EVP_DigestSqueeze(ctx: PEVP_MD_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSqueeze := LoadLibCryptoFunction('EVP_DigestSqueeze');
  if not assigned(EVP_DigestSqueeze) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSqueeze');
  Result := EVP_DigestSqueeze(ctx, out_, outlen);
end;

function Load_EVP_MD_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MD; cdecl;
begin
  EVP_MD_fetch := LoadLibCryptoFunction('EVP_MD_fetch');
  if not assigned(EVP_MD_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_fetch');
  Result := EVP_MD_fetch(ctx, algorithm, properties);
end;

function Load_EVP_MD_up_ref(md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_MD_up_ref := LoadLibCryptoFunction('EVP_MD_up_ref');
  if not assigned(EVP_MD_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_up_ref');
  Result := EVP_MD_up_ref(md);
end;

procedure Load_EVP_MD_free(md: PEVP_MD); cdecl;
begin
  EVP_MD_free := LoadLibCryptoFunction('EVP_MD_free');
  if not assigned(EVP_MD_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_free');
  EVP_MD_free(md);
end;

function Load_EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_read_pw_string := LoadLibCryptoFunction('EVP_read_pw_string');
  if not assigned(EVP_read_pw_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_read_pw_string');
  Result := EVP_read_pw_string(buf, length, prompt, verify);
end;

function Load_EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_read_pw_string_min := LoadLibCryptoFunction('EVP_read_pw_string_min');
  if not assigned(EVP_read_pw_string_min) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_read_pw_string_min');
  Result := EVP_read_pw_string_min(buf, minlen, maxlen, prompt, verify);
end;

procedure Load_EVP_set_pw_prompt(prompt: PAnsiChar); cdecl;
begin
  EVP_set_pw_prompt := LoadLibCryptoFunction('EVP_set_pw_prompt');
  if not assigned(EVP_set_pw_prompt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_set_pw_prompt');
  EVP_set_pw_prompt(prompt);
end;

function Load_EVP_get_pw_prompt: PAnsiChar; cdecl;
begin
  EVP_get_pw_prompt := LoadLibCryptoFunction('EVP_get_pw_prompt');
  if not assigned(EVP_get_pw_prompt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_pw_prompt');
  Result := EVP_get_pw_prompt;
end;

function Load_EVP_BytesToKey(type_: PEVP_CIPHER; md: PEVP_MD; salt: Pbyte; data: Pbyte; datal: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_BytesToKey := LoadLibCryptoFunction('EVP_BytesToKey');
  if not assigned(EVP_BytesToKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_BytesToKey');
  Result := EVP_BytesToKey(type_, md, salt, data, datal, count, key, iv);
end;

procedure Load_EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_CIPHER_CTX_set_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_flags');
  if not assigned(EVP_CIPHER_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_flags');
  EVP_CIPHER_CTX_set_flags(ctx, flags);
end;

procedure Load_EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EVP_CIPHER_CTX_clear_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_clear_flags');
  if not assigned(EVP_CIPHER_CTX_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_clear_flags');
  EVP_CIPHER_CTX_clear_flags(ctx, flags);
end;

function Load_EVP_CIPHER_CTX_test_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_test_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_test_flags');
  if not assigned(EVP_CIPHER_CTX_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_test_flags');
  Result := EVP_CIPHER_CTX_test_flags(ctx, flags);
end;

function Load_EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptInit := LoadLibCryptoFunction('EVP_EncryptInit');
  if not assigned(EVP_EncryptInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptInit');
  Result := EVP_EncryptInit(ctx, cipher, key, iv);
end;

function Load_EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptInit_ex := LoadLibCryptoFunction('EVP_EncryptInit_ex');
  if not assigned(EVP_EncryptInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptInit_ex');
  Result := EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
end;

function Load_EVP_EncryptInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptInit_ex2 := LoadLibCryptoFunction('EVP_EncryptInit_ex2');
  if not assigned(EVP_EncryptInit_ex2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptInit_ex2');
  Result := EVP_EncryptInit_ex2(ctx, cipher, key, iv, params);
end;

function Load_EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptUpdate := LoadLibCryptoFunction('EVP_EncryptUpdate');
  if not assigned(EVP_EncryptUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptUpdate');
  Result := EVP_EncryptUpdate(ctx, out_, outl, in_, inl);
end;

function Load_EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptFinal_ex := LoadLibCryptoFunction('EVP_EncryptFinal_ex');
  if not assigned(EVP_EncryptFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptFinal_ex');
  Result := EVP_EncryptFinal_ex(ctx, out_, outl);
end;

function Load_EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncryptFinal := LoadLibCryptoFunction('EVP_EncryptFinal');
  if not assigned(EVP_EncryptFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptFinal');
  Result := EVP_EncryptFinal(ctx, out_, outl);
end;

function Load_EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptInit := LoadLibCryptoFunction('EVP_DecryptInit');
  if not assigned(EVP_DecryptInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptInit');
  Result := EVP_DecryptInit(ctx, cipher, key, iv);
end;

function Load_EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptInit_ex := LoadLibCryptoFunction('EVP_DecryptInit_ex');
  if not assigned(EVP_DecryptInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptInit_ex');
  Result := EVP_DecryptInit_ex(ctx, cipher, impl, key, iv);
end;

function Load_EVP_DecryptInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptInit_ex2 := LoadLibCryptoFunction('EVP_DecryptInit_ex2');
  if not assigned(EVP_DecryptInit_ex2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptInit_ex2');
  Result := EVP_DecryptInit_ex2(ctx, cipher, key, iv, params);
end;

function Load_EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptUpdate := LoadLibCryptoFunction('EVP_DecryptUpdate');
  if not assigned(EVP_DecryptUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptUpdate');
  Result := EVP_DecryptUpdate(ctx, out_, outl, in_, inl);
end;

function Load_EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptFinal := LoadLibCryptoFunction('EVP_DecryptFinal');
  if not assigned(EVP_DecryptFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptFinal');
  Result := EVP_DecryptFinal(ctx, outm, outl);
end;

function Load_EVP_DecryptFinal_ex(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecryptFinal_ex := LoadLibCryptoFunction('EVP_DecryptFinal_ex');
  if not assigned(EVP_DecryptFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptFinal_ex');
  Result := EVP_DecryptFinal_ex(ctx, outm, outl);
end;

function Load_EVP_CipherInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherInit := LoadLibCryptoFunction('EVP_CipherInit');
  if not assigned(EVP_CipherInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit');
  Result := EVP_CipherInit(ctx, cipher, key, iv, enc);
end;

function Load_EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; impl: PENGINE; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherInit_ex := LoadLibCryptoFunction('EVP_CipherInit_ex');
  if not assigned(EVP_CipherInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit_ex');
  Result := EVP_CipherInit_ex(ctx, cipher, impl, key, iv, enc);
end;

function Load_EVP_CipherInit_SKEY(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; skey: PEVP_SKEY; iv: Pbyte; iv_len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherInit_SKEY := LoadLibCryptoFunction('EVP_CipherInit_SKEY');
  if not assigned(EVP_CipherInit_SKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit_SKEY');
  Result := EVP_CipherInit_SKEY(ctx, cipher, skey, iv, iv_len, enc, params);
end;

function Load_EVP_CipherInit_ex2(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; iv: Pbyte; enc: TOpenSSL_C_INT; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherInit_ex2 := LoadLibCryptoFunction('EVP_CipherInit_ex2');
  if not assigned(EVP_CipherInit_ex2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit_ex2');
  Result := EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, params);
end;

function Load_EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherUpdate := LoadLibCryptoFunction('EVP_CipherUpdate');
  if not assigned(EVP_CipherUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherUpdate');
  Result := EVP_CipherUpdate(ctx, out_, outl, in_, inl);
end;

function Load_EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherFinal := LoadLibCryptoFunction('EVP_CipherFinal');
  if not assigned(EVP_CipherFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherFinal');
  Result := EVP_CipherFinal(ctx, outm, outl);
end;

function Load_EVP_CipherPipelineEncryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherPipelineEncryptInit := LoadLibCryptoFunction('EVP_CipherPipelineEncryptInit');
  if not assigned(EVP_CipherPipelineEncryptInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherPipelineEncryptInit');
  Result := EVP_CipherPipelineEncryptInit(ctx, cipher, key, keylen, numpipes, iv, ivlen);
end;

function Load_EVP_CipherPipelineDecryptInit(ctx: PEVP_CIPHER_CTX; cipher: PEVP_CIPHER; key: Pbyte; keylen: TOpenSSL_C_SIZET; numpipes: TOpenSSL_C_SIZET; iv: PPbyte; ivlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherPipelineDecryptInit := LoadLibCryptoFunction('EVP_CipherPipelineDecryptInit');
  if not assigned(EVP_CipherPipelineDecryptInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherPipelineDecryptInit');
  Result := EVP_CipherPipelineDecryptInit(ctx, cipher, key, keylen, numpipes, iv, ivlen);
end;

function Load_EVP_CipherPipelineUpdate(ctx: PEVP_CIPHER_CTX; out_: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET; in_: PPbyte; inl: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherPipelineUpdate := LoadLibCryptoFunction('EVP_CipherPipelineUpdate');
  if not assigned(EVP_CipherPipelineUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherPipelineUpdate');
  Result := EVP_CipherPipelineUpdate(ctx, out_, outl, outsize, in_, inl);
end;

function Load_EVP_CipherPipelineFinal(ctx: PEVP_CIPHER_CTX; outm: PPbyte; outl: POpenSSL_C_SIZET; outsize: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherPipelineFinal := LoadLibCryptoFunction('EVP_CipherPipelineFinal');
  if not assigned(EVP_CipherPipelineFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherPipelineFinal');
  Result := EVP_CipherPipelineFinal(ctx, outm, outl, outsize);
end;

function Load_EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CipherFinal_ex := LoadLibCryptoFunction('EVP_CipherFinal_ex');
  if not assigned(EVP_CipherFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherFinal_ex');
  Result := EVP_CipherFinal_ex(ctx, outm, outl);
end;

function Load_EVP_SignFinal(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_SignFinal := LoadLibCryptoFunction('EVP_SignFinal');
  if not assigned(EVP_SignFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SignFinal');
  Result := EVP_SignFinal(ctx, md, s, pkey);
end;

function Load_EVP_SignFinal_ex(ctx: PEVP_MD_CTX; md: Pbyte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_SignFinal_ex := LoadLibCryptoFunction('EVP_SignFinal_ex');
  if not assigned(EVP_SignFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SignFinal_ex');
  Result := EVP_SignFinal_ex(ctx, md, s, pkey, libctx, propq);
end;

function Load_EVP_DigestSign(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSign := LoadLibCryptoFunction('EVP_DigestSign');
  if not assigned(EVP_DigestSign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSign');
  Result := EVP_DigestSign(ctx, sigret, siglen, tbs, tbslen);
end;

function Load_EVP_VerifyFinal(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_VerifyFinal := LoadLibCryptoFunction('EVP_VerifyFinal');
  if not assigned(EVP_VerifyFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_VerifyFinal');
  Result := EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
end;

function Load_EVP_VerifyFinal_ex(ctx: PEVP_MD_CTX; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_VerifyFinal_ex := LoadLibCryptoFunction('EVP_VerifyFinal_ex');
  if not assigned(EVP_VerifyFinal_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_VerifyFinal_ex');
  Result := EVP_VerifyFinal_ex(ctx, sigbuf, siglen, pkey, libctx, propq);
end;

function Load_EVP_DigestVerify(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerify := LoadLibCryptoFunction('EVP_DigestVerify');
  if not assigned(EVP_DigestVerify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerify');
  Result := EVP_DigestVerify(ctx, sigret, siglen, tbs, tbslen);
end;

function Load_EVP_DigestSignInit_ex(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSignInit_ex := LoadLibCryptoFunction('EVP_DigestSignInit_ex');
  if not assigned(EVP_DigestSignInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignInit_ex');
  Result := EVP_DigestSignInit_ex(ctx, pctx, mdname, libctx, props, pkey, params);
end;

function Load_EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSignInit := LoadLibCryptoFunction('EVP_DigestSignInit');
  if not assigned(EVP_DigestSignInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignInit');
  Result := EVP_DigestSignInit(ctx, pctx, type_, e, pkey);
end;

function Load_EVP_DigestSignUpdate(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSignUpdate := LoadLibCryptoFunction('EVP_DigestSignUpdate');
  if not assigned(EVP_DigestSignUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignUpdate');
  Result := EVP_DigestSignUpdate(ctx, data, dsize);
end;

function Load_EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestSignFinal := LoadLibCryptoFunction('EVP_DigestSignFinal');
  if not assigned(EVP_DigestSignFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignFinal');
  Result := EVP_DigestSignFinal(ctx, sigret, siglen);
end;

function Load_EVP_DigestVerifyInit_ex(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; mdname: PAnsiChar; libctx: POSSL_LIB_CTX; props: PAnsiChar; pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerifyInit_ex := LoadLibCryptoFunction('EVP_DigestVerifyInit_ex');
  if not assigned(EVP_DigestVerifyInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyInit_ex');
  Result := EVP_DigestVerifyInit_ex(ctx, pctx, mdname, libctx, props, pkey, params);
end;

function Load_EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerifyInit := LoadLibCryptoFunction('EVP_DigestVerifyInit');
  if not assigned(EVP_DigestVerifyInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyInit');
  Result := EVP_DigestVerifyInit(ctx, pctx, type_, e, pkey);
end;

function Load_EVP_DigestVerifyUpdate(ctx: PEVP_MD_CTX; data: pointer; dsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerifyUpdate := LoadLibCryptoFunction('EVP_DigestVerifyUpdate');
  if not assigned(EVP_DigestVerifyUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyUpdate');
  Result := EVP_DigestVerifyUpdate(ctx, data, dsize);
end;

function Load_EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_DigestVerifyFinal := LoadLibCryptoFunction('EVP_DigestVerifyFinal');
  if not assigned(EVP_DigestVerifyFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyFinal');
  Result := EVP_DigestVerifyFinal(ctx, sig, siglen);
end;

function Load_EVP_OpenInit(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: Pbyte; ekl: TOpenSSL_C_INT; iv: Pbyte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_OpenInit := LoadLibCryptoFunction('EVP_OpenInit');
  if not assigned(EVP_OpenInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_OpenInit');
  Result := EVP_OpenInit(ctx, type_, ek, ekl, iv, priv);
end;

function Load_EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_OpenFinal := LoadLibCryptoFunction('EVP_OpenFinal');
  if not assigned(EVP_OpenFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_OpenFinal');
  Result := EVP_OpenFinal(ctx, out_, outl);
end;

function Load_EVP_SealInit(ctx: PEVP_CIPHER_CTX; type_: PEVP_CIPHER; ek: PPbyte; ekl: POpenSSL_C_INT; iv: Pbyte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_SealInit := LoadLibCryptoFunction('EVP_SealInit');
  if not assigned(EVP_SealInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SealInit');
  Result := EVP_SealInit(ctx, type_, ek, ekl, iv, pubk, npubk);
end;

function Load_EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_SealFinal := LoadLibCryptoFunction('EVP_SealFinal');
  if not assigned(EVP_SealFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SealFinal');
  Result := EVP_SealFinal(ctx, out_, outl);
end;

function Load_EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl;
begin
  EVP_ENCODE_CTX_new := LoadLibCryptoFunction('EVP_ENCODE_CTX_new');
  if not assigned(EVP_ENCODE_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_new');
  Result := EVP_ENCODE_CTX_new;
end;

procedure Load_EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EVP_ENCODE_CTX_free := LoadLibCryptoFunction('EVP_ENCODE_CTX_free');
  if not assigned(EVP_ENCODE_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_free');
  EVP_ENCODE_CTX_free(ctx);
end;

function Load_EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_ENCODE_CTX_copy := LoadLibCryptoFunction('EVP_ENCODE_CTX_copy');
  if not assigned(EVP_ENCODE_CTX_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_copy');
  Result := EVP_ENCODE_CTX_copy(dctx, sctx);
end;

function Load_EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_ENCODE_CTX_num := LoadLibCryptoFunction('EVP_ENCODE_CTX_num');
  if not assigned(EVP_ENCODE_CTX_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_num');
  Result := EVP_ENCODE_CTX_num(ctx);
end;

procedure Load_EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EVP_EncodeInit := LoadLibCryptoFunction('EVP_EncodeInit');
  if not assigned(EVP_EncodeInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeInit');
  EVP_EncodeInit(ctx);
end;

function Load_EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncodeUpdate := LoadLibCryptoFunction('EVP_EncodeUpdate');
  if not assigned(EVP_EncodeUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeUpdate');
  Result := EVP_EncodeUpdate(ctx, out_, outl, in_, inl);
end;

procedure Load_EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT); cdecl;
begin
  EVP_EncodeFinal := LoadLibCryptoFunction('EVP_EncodeFinal');
  if not assigned(EVP_EncodeFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeFinal');
  EVP_EncodeFinal(ctx, out_, outl);
end;

function Load_EVP_EncodeBlock(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_EncodeBlock := LoadLibCryptoFunction('EVP_EncodeBlock');
  if not assigned(EVP_EncodeBlock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeBlock');
  Result := EVP_EncodeBlock(t, f, n);
end;

procedure Load_EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EVP_DecodeInit := LoadLibCryptoFunction('EVP_DecodeInit');
  if not assigned(EVP_DecodeInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeInit');
  EVP_DecodeInit(ctx);
end;

function Load_EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT; in_: Pbyte; inl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecodeUpdate := LoadLibCryptoFunction('EVP_DecodeUpdate');
  if not assigned(EVP_DecodeUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeUpdate');
  Result := EVP_DecodeUpdate(ctx, out_, outl, in_, inl);
end;

function Load_EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: Pbyte; outl: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecodeFinal := LoadLibCryptoFunction('EVP_DecodeFinal');
  if not assigned(EVP_DecodeFinal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeFinal');
  Result := EVP_DecodeFinal(ctx, out_, outl);
end;

function Load_EVP_DecodeBlock(t: Pbyte; f: Pbyte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_DecodeBlock := LoadLibCryptoFunction('EVP_DecodeBlock');
  if not assigned(EVP_DecodeBlock) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeBlock');
  Result := EVP_DecodeBlock(t, f, n);
end;

function Load_EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl;
begin
  EVP_CIPHER_CTX_new := LoadLibCryptoFunction('EVP_CIPHER_CTX_new');
  if not assigned(EVP_CIPHER_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_new');
  Result := EVP_CIPHER_CTX_new;
end;

function Load_EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_reset := LoadLibCryptoFunction('EVP_CIPHER_CTX_reset');
  if not assigned(EVP_CIPHER_CTX_reset) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_reset');
  Result := EVP_CIPHER_CTX_reset(c);
end;

procedure Load_EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl;
begin
  EVP_CIPHER_CTX_free := LoadLibCryptoFunction('EVP_CIPHER_CTX_free');
  if not assigned(EVP_CIPHER_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_free');
  EVP_CIPHER_CTX_free(c);
end;

function Load_EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_set_key_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_key_length');
  if not assigned(EVP_CIPHER_CTX_set_key_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_key_length');
  Result := EVP_CIPHER_CTX_set_key_length(x, keylen);
end;

function Load_EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_set_padding := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_padding');
  if not assigned(EVP_CIPHER_CTX_set_padding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_padding');
  Result := EVP_CIPHER_CTX_set_padding(c, pad);
end;

function Load_EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_ctrl := LoadLibCryptoFunction('EVP_CIPHER_CTX_ctrl');
  if not assigned(EVP_CIPHER_CTX_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_ctrl');
  Result := EVP_CIPHER_CTX_ctrl(ctx, type_, arg, ptr);
end;

function Load_EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_rand_key := LoadLibCryptoFunction('EVP_CIPHER_CTX_rand_key');
  if not assigned(EVP_CIPHER_CTX_rand_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_rand_key');
  Result := EVP_CIPHER_CTX_rand_key(ctx, key);
end;

function Load_EVP_CIPHER_get_params(cipher: PEVP_CIPHER; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_params := LoadLibCryptoFunction('EVP_CIPHER_get_params');
  if not assigned(EVP_CIPHER_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_params');
  Result := EVP_CIPHER_get_params(cipher, params);
end;

function Load_EVP_CIPHER_CTX_set_params(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_set_params := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_params');
  if not assigned(EVP_CIPHER_CTX_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_params');
  Result := EVP_CIPHER_CTX_set_params(ctx, params);
end;

function Load_EVP_CIPHER_CTX_get_params(ctx: PEVP_CIPHER_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_params := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_params');
  if not assigned(EVP_CIPHER_CTX_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_params');
  Result := EVP_CIPHER_CTX_get_params(ctx, params);
end;

function Load_EVP_CIPHER_gettable_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl;
begin
  EVP_CIPHER_gettable_params := LoadLibCryptoFunction('EVP_CIPHER_gettable_params');
  if not assigned(EVP_CIPHER_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_gettable_params');
  Result := EVP_CIPHER_gettable_params(cipher);
end;

function Load_EVP_CIPHER_settable_ctx_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl;
begin
  EVP_CIPHER_settable_ctx_params := LoadLibCryptoFunction('EVP_CIPHER_settable_ctx_params');
  if not assigned(EVP_CIPHER_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_settable_ctx_params');
  Result := EVP_CIPHER_settable_ctx_params(cipher);
end;

function Load_EVP_CIPHER_gettable_ctx_params(cipher: PEVP_CIPHER): POSSL_PARAM; cdecl;
begin
  EVP_CIPHER_gettable_ctx_params := LoadLibCryptoFunction('EVP_CIPHER_gettable_ctx_params');
  if not assigned(EVP_CIPHER_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_gettable_ctx_params');
  Result := EVP_CIPHER_gettable_ctx_params(cipher);
end;

function Load_EVP_CIPHER_CTX_settable_params(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl;
begin
  EVP_CIPHER_CTX_settable_params := LoadLibCryptoFunction('EVP_CIPHER_CTX_settable_params');
  if not assigned(EVP_CIPHER_CTX_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_settable_params');
  Result := EVP_CIPHER_CTX_settable_params(ctx);
end;

function Load_EVP_CIPHER_CTX_gettable_params(ctx: PEVP_CIPHER_CTX): POSSL_PARAM; cdecl;
begin
  EVP_CIPHER_CTX_gettable_params := LoadLibCryptoFunction('EVP_CIPHER_CTX_gettable_params');
  if not assigned(EVP_CIPHER_CTX_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_gettable_params');
  Result := EVP_CIPHER_CTX_gettable_params(ctx);
end;

function Load_EVP_CIPHER_CTX_set_algor_params(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_set_algor_params := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_algor_params');
  if not assigned(EVP_CIPHER_CTX_set_algor_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_algor_params');
  Result := EVP_CIPHER_CTX_set_algor_params(ctx, alg);
end;

function Load_EVP_CIPHER_CTX_get_algor_params(ctx: PEVP_CIPHER_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_algor_params := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_algor_params');
  if not assigned(EVP_CIPHER_CTX_get_algor_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_algor_params');
  Result := EVP_CIPHER_CTX_get_algor_params(ctx, alg);
end;

function Load_EVP_CIPHER_CTX_get_algor(ctx: PEVP_CIPHER_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_CTX_get_algor := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_algor');
  if not assigned(EVP_CIPHER_CTX_get_algor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_algor');
  Result := EVP_CIPHER_CTX_get_algor(ctx, alg);
end;

function Load_BIO_f_md: PBIO_METHOD; cdecl;
begin
  BIO_f_md := LoadLibCryptoFunction('BIO_f_md');
  if not assigned(BIO_f_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_md');
  Result := BIO_f_md;
end;

function Load_BIO_f_base64: PBIO_METHOD; cdecl;
begin
  BIO_f_base64 := LoadLibCryptoFunction('BIO_f_base64');
  if not assigned(BIO_f_base64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_base64');
  Result := BIO_f_base64;
end;

function Load_BIO_f_cipher: PBIO_METHOD; cdecl;
begin
  BIO_f_cipher := LoadLibCryptoFunction('BIO_f_cipher');
  if not assigned(BIO_f_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_cipher');
  Result := BIO_f_cipher;
end;

function Load_BIO_f_reliable: PBIO_METHOD; cdecl;
begin
  BIO_f_reliable := LoadLibCryptoFunction('BIO_f_reliable');
  if not assigned(BIO_f_reliable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_reliable');
  Result := BIO_f_reliable;
end;

function Load_BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; k: Pbyte; i: Pbyte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  BIO_set_cipher := LoadLibCryptoFunction('BIO_set_cipher');
  if not assigned(BIO_set_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_cipher');
  Result := BIO_set_cipher(b, c, k, i, enc);
end;

function Load_EVP_md_null: PEVP_MD; cdecl;
begin
  EVP_md_null := LoadLibCryptoFunction('EVP_md_null');
  if not assigned(EVP_md_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md_null');
  Result := EVP_md_null;
end;

{$ifndef  OPENSSL_NO_MD2}
function Load_EVP_md2: PEVP_MD; cdecl;
begin
  EVP_md2 := LoadLibCryptoFunction('EVP_md2');
  if not assigned(EVP_md2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md2');
  Result := EVP_md2;
end;

{$endif} { OPENSSL_NO_MD2}
{$ifndef  OPENSSL_NO_MD4}
function Load_EVP_md4: PEVP_MD; cdecl;
begin
  EVP_md4 := LoadLibCryptoFunction('EVP_md4');
  if not assigned(EVP_md4) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md4');
  Result := EVP_md4;
end;

{$endif} { OPENSSL_NO_MD4}
{$ifndef  OPENSSL_NO_MD5}
function Load_EVP_md5: PEVP_MD; cdecl;
begin
  EVP_md5 := LoadLibCryptoFunction('EVP_md5');
  if not assigned(EVP_md5) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md5');
  Result := EVP_md5;
end;

function Load_EVP_md5_sha1: PEVP_MD; cdecl;
begin
  EVP_md5_sha1 := LoadLibCryptoFunction('EVP_md5_sha1');
  if not assigned(EVP_md5_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md5_sha1');
  Result := EVP_md5_sha1;
end;

{$endif} { OPENSSL_NO_MD5}
{$ifndef  OPENSSL_NO_BLAKE2}
function Load_EVP_blake2b512: PEVP_MD; cdecl;
begin
  EVP_blake2b512 := LoadLibCryptoFunction('EVP_blake2b512');
  if not assigned(EVP_blake2b512) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_blake2b512');
  Result := EVP_blake2b512;
end;

function Load_EVP_blake2s256: PEVP_MD; cdecl;
begin
  EVP_blake2s256 := LoadLibCryptoFunction('EVP_blake2s256');
  if not assigned(EVP_blake2s256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_blake2s256');
  Result := EVP_blake2s256;
end;

{$endif} { OPENSSL_NO_BLAKE2}
function Load_EVP_sha1: PEVP_MD; cdecl;
begin
  EVP_sha1 := LoadLibCryptoFunction('EVP_sha1');
  if not assigned(EVP_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha1');
  Result := EVP_sha1;
end;

function Load_EVP_sha224: PEVP_MD; cdecl;
begin
  EVP_sha224 := LoadLibCryptoFunction('EVP_sha224');
  if not assigned(EVP_sha224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha224');
  Result := EVP_sha224;
end;

function Load_EVP_sha256: PEVP_MD; cdecl;
begin
  EVP_sha256 := LoadLibCryptoFunction('EVP_sha256');
  if not assigned(EVP_sha256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha256');
  Result := EVP_sha256;
end;

function Load_EVP_sha384: PEVP_MD; cdecl;
begin
  EVP_sha384 := LoadLibCryptoFunction('EVP_sha384');
  if not assigned(EVP_sha384) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha384');
  Result := EVP_sha384;
end;

function Load_EVP_sha512: PEVP_MD; cdecl;
begin
  EVP_sha512 := LoadLibCryptoFunction('EVP_sha512');
  if not assigned(EVP_sha512) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512');
  Result := EVP_sha512;
end;

function Load_EVP_sha512_224: PEVP_MD; cdecl;
begin
  EVP_sha512_224 := LoadLibCryptoFunction('EVP_sha512_224');
  if not assigned(EVP_sha512_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512_224');
  Result := EVP_sha512_224;
end;

function Load_EVP_sha512_256: PEVP_MD; cdecl;
begin
  EVP_sha512_256 := LoadLibCryptoFunction('EVP_sha512_256');
  if not assigned(EVP_sha512_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512_256');
  Result := EVP_sha512_256;
end;

function Load_EVP_sha3_224: PEVP_MD; cdecl;
begin
  EVP_sha3_224 := LoadLibCryptoFunction('EVP_sha3_224');
  if not assigned(EVP_sha3_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_224');
  Result := EVP_sha3_224;
end;

function Load_EVP_sha3_256: PEVP_MD; cdecl;
begin
  EVP_sha3_256 := LoadLibCryptoFunction('EVP_sha3_256');
  if not assigned(EVP_sha3_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_256');
  Result := EVP_sha3_256;
end;

function Load_EVP_sha3_384: PEVP_MD; cdecl;
begin
  EVP_sha3_384 := LoadLibCryptoFunction('EVP_sha3_384');
  if not assigned(EVP_sha3_384) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_384');
  Result := EVP_sha3_384;
end;

function Load_EVP_sha3_512: PEVP_MD; cdecl;
begin
  EVP_sha3_512 := LoadLibCryptoFunction('EVP_sha3_512');
  if not assigned(EVP_sha3_512) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_512');
  Result := EVP_sha3_512;
end;

function Load_EVP_shake128: PEVP_MD; cdecl;
begin
  EVP_shake128 := LoadLibCryptoFunction('EVP_shake128');
  if not assigned(EVP_shake128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_shake128');
  Result := EVP_shake128;
end;

function Load_EVP_shake256: PEVP_MD; cdecl;
begin
  EVP_shake256 := LoadLibCryptoFunction('EVP_shake256');
  if not assigned(EVP_shake256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_shake256');
  Result := EVP_shake256;
end;

{$ifndef  OPENSSL_NO_MDC2}
function Load_EVP_mdc2: PEVP_MD; cdecl;
begin
  EVP_mdc2 := LoadLibCryptoFunction('EVP_mdc2');
  if not assigned(EVP_mdc2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_mdc2');
  Result := EVP_mdc2;
end;

{$endif} { OPENSSL_NO_MDC2}
{$ifndef  OPENSSL_NO_RMD160}
function Load_EVP_ripemd160: PEVP_MD; cdecl;
begin
  EVP_ripemd160 := LoadLibCryptoFunction('EVP_ripemd160');
  if not assigned(EVP_ripemd160) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ripemd160');
  Result := EVP_ripemd160;
end;

{$endif} { OPENSSL_NO_RMD160}
{$ifndef  OPENSSL_NO_WHIRLPOOL}
function Load_EVP_whirlpool: PEVP_MD; cdecl;
begin
  EVP_whirlpool := LoadLibCryptoFunction('EVP_whirlpool');
  if not assigned(EVP_whirlpool) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_whirlpool');
  Result := EVP_whirlpool;
end;

{$endif} { OPENSSL_NO_WHIRLPOOL}
{$ifndef  OPENSSL_NO_SM3}
function Load_EVP_sm3: PEVP_MD; cdecl;
begin
  EVP_sm3 := LoadLibCryptoFunction('EVP_sm3');
  if not assigned(EVP_sm3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm3');
  Result := EVP_sm3;
end;

{$endif} { OPENSSL_NO_SM3}
function Load_EVP_enc_null: PEVP_CIPHER; cdecl;
begin
  EVP_enc_null := LoadLibCryptoFunction('EVP_enc_null');
  if not assigned(EVP_enc_null) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_enc_null');
  Result := EVP_enc_null;
end;

{$ifndef  OPENSSL_NO_DES}
function Load_EVP_des_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ecb := LoadLibCryptoFunction('EVP_des_ecb');
  if not assigned(EVP_des_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ecb');
  Result := EVP_des_ecb;
end;

function Load_EVP_des_ede: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede := LoadLibCryptoFunction('EVP_des_ede');
  if not assigned(EVP_des_ede) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede');
  Result := EVP_des_ede;
end;

function Load_EVP_des_ede3: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3 := LoadLibCryptoFunction('EVP_des_ede3');
  if not assigned(EVP_des_ede3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3');
  Result := EVP_des_ede3;
end;

function Load_EVP_des_ede_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_ecb := LoadLibCryptoFunction('EVP_des_ede_ecb');
  if not assigned(EVP_des_ede_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_ecb');
  Result := EVP_des_ede_ecb;
end;

function Load_EVP_des_ede3_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_ecb := LoadLibCryptoFunction('EVP_des_ede3_ecb');
  if not assigned(EVP_des_ede3_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_ecb');
  Result := EVP_des_ede3_ecb;
end;

function Load_EVP_des_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_des_cfb64 := LoadLibCryptoFunction('EVP_des_cfb64');
  if not assigned(EVP_des_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb64');
  Result := EVP_des_cfb64;
end;

function Load_EVP_des_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_des_cfb := LoadLibCryptoFunction('EVP_des_cfb64');
  if not assigned(EVP_des_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb64');
  Result := EVP_des_cfb;
end;

function Load_EVP_des_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_des_cfb1 := LoadLibCryptoFunction('EVP_des_cfb1');
  if not assigned(EVP_des_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb1');
  Result := EVP_des_cfb1;
end;

function Load_EVP_des_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_des_cfb8 := LoadLibCryptoFunction('EVP_des_cfb8');
  if not assigned(EVP_des_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb8');
  Result := EVP_des_cfb8;
end;

function Load_EVP_des_ede_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_cfb64 := LoadLibCryptoFunction('EVP_des_ede_cfb64');
  if not assigned(EVP_des_ede_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_cfb64');
  Result := EVP_des_ede_cfb64;
end;

function Load_EVP_des_ede_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_cfb := LoadLibCryptoFunction('EVP_des_ede_cfb64');
  if not assigned(EVP_des_ede_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_cfb64');
  Result := EVP_des_ede_cfb;
end;

function Load_EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cfb64 := LoadLibCryptoFunction('EVP_des_ede3_cfb64');
  if not assigned(EVP_des_ede3_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb64');
  Result := EVP_des_ede3_cfb64;
end;

function Load_EVP_des_ede3_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cfb := LoadLibCryptoFunction('EVP_des_ede3_cfb64');
  if not assigned(EVP_des_ede3_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb64');
  Result := EVP_des_ede3_cfb;
end;

function Load_EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cfb1 := LoadLibCryptoFunction('EVP_des_ede3_cfb1');
  if not assigned(EVP_des_ede3_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb1');
  Result := EVP_des_ede3_cfb1;
end;

function Load_EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cfb8 := LoadLibCryptoFunction('EVP_des_ede3_cfb8');
  if not assigned(EVP_des_ede3_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb8');
  Result := EVP_des_ede3_cfb8;
end;

function Load_EVP_des_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ofb := LoadLibCryptoFunction('EVP_des_ofb');
  if not assigned(EVP_des_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ofb');
  Result := EVP_des_ofb;
end;

function Load_EVP_des_ede_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_ofb := LoadLibCryptoFunction('EVP_des_ede_ofb');
  if not assigned(EVP_des_ede_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_ofb');
  Result := EVP_des_ede_ofb;
end;

function Load_EVP_des_ede3_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_ofb := LoadLibCryptoFunction('EVP_des_ede3_ofb');
  if not assigned(EVP_des_ede3_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_ofb');
  Result := EVP_des_ede3_ofb;
end;

function Load_EVP_des_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_des_cbc := LoadLibCryptoFunction('EVP_des_cbc');
  if not assigned(EVP_des_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cbc');
  Result := EVP_des_cbc;
end;

function Load_EVP_des_ede_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede_cbc := LoadLibCryptoFunction('EVP_des_ede_cbc');
  if not assigned(EVP_des_ede_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_cbc');
  Result := EVP_des_ede_cbc;
end;

function Load_EVP_des_ede3_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_cbc := LoadLibCryptoFunction('EVP_des_ede3_cbc');
  if not assigned(EVP_des_ede3_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cbc');
  Result := EVP_des_ede3_cbc;
end;

function Load_EVP_desx_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_desx_cbc := LoadLibCryptoFunction('EVP_desx_cbc');
  if not assigned(EVP_desx_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_desx_cbc');
  Result := EVP_desx_cbc;
end;

function Load_EVP_des_ede3_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_des_ede3_wrap := LoadLibCryptoFunction('EVP_des_ede3_wrap');
  if not assigned(EVP_des_ede3_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_wrap');
  Result := EVP_des_ede3_wrap;
end;

{$endif} { OPENSSL_NO_DES}
{$ifndef  OPENSSL_NO_RC4}
function Load_EVP_rc4: PEVP_CIPHER; cdecl;
begin
  EVP_rc4 := LoadLibCryptoFunction('EVP_rc4');
  if not assigned(EVP_rc4) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc4');
  Result := EVP_rc4;
end;

function Load_EVP_rc4_40: PEVP_CIPHER; cdecl;
begin
  EVP_rc4_40 := LoadLibCryptoFunction('EVP_rc4_40');
  if not assigned(EVP_rc4_40) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc4_40');
  Result := EVP_rc4_40;
end;

    {$ifndef  OPENSSL_NO_MD5}
function Load_EVP_rc4_hmac_md5: PEVP_CIPHER; cdecl;
begin
  EVP_rc4_hmac_md5 := LoadLibCryptoFunction('EVP_rc4_hmac_md5');
  if not assigned(EVP_rc4_hmac_md5) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc4_hmac_md5');
  Result := EVP_rc4_hmac_md5;
end;

    {$endif} { OPENSSL_NO_MD5}
{$endif} { OPENSSL_NO_RC4}
{$ifndef  OPENSSL_NO_IDEA}
function Load_EVP_idea_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_idea_ecb := LoadLibCryptoFunction('EVP_idea_ecb');
  if not assigned(EVP_idea_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_idea_ecb');
  Result := EVP_idea_ecb;
end;

function Load_EVP_idea_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_idea_cfb64 := LoadLibCryptoFunction('EVP_idea_cfb64');
  if not assigned(EVP_idea_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_idea_cfb64');
  Result := EVP_idea_cfb64;
end;

function Load_EVP_idea_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_idea_cfb := LoadLibCryptoFunction('EVP_idea_cfb64');
  if not assigned(EVP_idea_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_idea_cfb64');
  Result := EVP_idea_cfb;
end;

function Load_EVP_idea_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_idea_ofb := LoadLibCryptoFunction('EVP_idea_ofb');
  if not assigned(EVP_idea_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_idea_ofb');
  Result := EVP_idea_ofb;
end;

function Load_EVP_idea_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_idea_cbc := LoadLibCryptoFunction('EVP_idea_cbc');
  if not assigned(EVP_idea_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_idea_cbc');
  Result := EVP_idea_cbc;
end;

{$endif} { OPENSSL_NO_IDEA}
{$ifndef  OPENSSL_NO_RC2}
function Load_EVP_rc2_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_ecb := LoadLibCryptoFunction('EVP_rc2_ecb');
  if not assigned(EVP_rc2_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_ecb');
  Result := EVP_rc2_ecb;
end;

function Load_EVP_rc2_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_cbc := LoadLibCryptoFunction('EVP_rc2_cbc');
  if not assigned(EVP_rc2_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_cbc');
  Result := EVP_rc2_cbc;
end;

function Load_EVP_rc2_40_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_40_cbc := LoadLibCryptoFunction('EVP_rc2_40_cbc');
  if not assigned(EVP_rc2_40_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_40_cbc');
  Result := EVP_rc2_40_cbc;
end;

function Load_EVP_rc2_64_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_64_cbc := LoadLibCryptoFunction('EVP_rc2_64_cbc');
  if not assigned(EVP_rc2_64_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_64_cbc');
  Result := EVP_rc2_64_cbc;
end;

function Load_EVP_rc2_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_cfb64 := LoadLibCryptoFunction('EVP_rc2_cfb64');
  if not assigned(EVP_rc2_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_cfb64');
  Result := EVP_rc2_cfb64;
end;

function Load_EVP_rc2_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_cfb := LoadLibCryptoFunction('EVP_rc2_cfb64');
  if not assigned(EVP_rc2_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_cfb64');
  Result := EVP_rc2_cfb;
end;

function Load_EVP_rc2_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_rc2_ofb := LoadLibCryptoFunction('EVP_rc2_ofb');
  if not assigned(EVP_rc2_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_ofb');
  Result := EVP_rc2_ofb;
end;

{$endif} { OPENSSL_NO_RC2}
{$ifndef  OPENSSL_NO_BF}
function Load_EVP_bf_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_bf_ecb := LoadLibCryptoFunction('EVP_bf_ecb');
  if not assigned(EVP_bf_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_ecb');
  Result := EVP_bf_ecb;
end;

function Load_EVP_bf_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_bf_cbc := LoadLibCryptoFunction('EVP_bf_cbc');
  if not assigned(EVP_bf_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_cbc');
  Result := EVP_bf_cbc;
end;

function Load_EVP_bf_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_bf_cfb64 := LoadLibCryptoFunction('EVP_bf_cfb64');
  if not assigned(EVP_bf_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_cfb64');
  Result := EVP_bf_cfb64;
end;

function Load_EVP_bf_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_bf_cfb := LoadLibCryptoFunction('EVP_bf_cfb64');
  if not assigned(EVP_bf_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_cfb64');
  Result := EVP_bf_cfb;
end;

function Load_EVP_bf_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_bf_ofb := LoadLibCryptoFunction('EVP_bf_ofb');
  if not assigned(EVP_bf_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_ofb');
  Result := EVP_bf_ofb;
end;

{$endif} { OPENSSL_NO_BF}
{$ifndef  OPENSSL_NO_CAST}
function Load_EVP_cast5_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_ecb := LoadLibCryptoFunction('EVP_cast5_ecb');
  if not assigned(EVP_cast5_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_ecb');
  Result := EVP_cast5_ecb;
end;

function Load_EVP_cast5_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_cbc := LoadLibCryptoFunction('EVP_cast5_cbc');
  if not assigned(EVP_cast5_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_cbc');
  Result := EVP_cast5_cbc;
end;

function Load_EVP_cast5_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_cfb64 := LoadLibCryptoFunction('EVP_cast5_cfb64');
  if not assigned(EVP_cast5_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_cfb64');
  Result := EVP_cast5_cfb64;
end;

function Load_EVP_cast5_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_cfb := LoadLibCryptoFunction('EVP_cast5_cfb64');
  if not assigned(EVP_cast5_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_cfb64');
  Result := EVP_cast5_cfb;
end;

function Load_EVP_cast5_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_cast5_ofb := LoadLibCryptoFunction('EVP_cast5_ofb');
  if not assigned(EVP_cast5_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_ofb');
  Result := EVP_cast5_ofb;
end;

{$endif} { OPENSSL_NO_CAST}
{$ifndef  OPENSSL_NO_RC5}
function Load_EVP_rc5_32_12_16_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_rc5_32_12_16_cbc := LoadLibCryptoFunction('EVP_rc5_32_12_16_cbc');
  if not assigned(EVP_rc5_32_12_16_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc5_32_12_16_cbc');
  Result := EVP_rc5_32_12_16_cbc;
end;

function Load_EVP_rc5_32_12_16_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_rc5_32_12_16_ecb := LoadLibCryptoFunction('EVP_rc5_32_12_16_ecb');
  if not assigned(EVP_rc5_32_12_16_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc5_32_12_16_ecb');
  Result := EVP_rc5_32_12_16_ecb;
end;

function Load_EVP_rc5_32_12_16_cfb64: PEVP_CIPHER; cdecl;
begin
  EVP_rc5_32_12_16_cfb64 := LoadLibCryptoFunction('EVP_rc5_32_12_16_cfb64');
  if not assigned(EVP_rc5_32_12_16_cfb64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc5_32_12_16_cfb64');
  Result := EVP_rc5_32_12_16_cfb64;
end;

function Load_EVP_rc5_32_12_16_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_rc5_32_12_16_cfb := LoadLibCryptoFunction('EVP_rc5_32_12_16_cfb64');
  if not assigned(EVP_rc5_32_12_16_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc5_32_12_16_cfb64');
  Result := EVP_rc5_32_12_16_cfb;
end;

function Load_EVP_rc5_32_12_16_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_rc5_32_12_16_ofb := LoadLibCryptoFunction('EVP_rc5_32_12_16_ofb');
  if not assigned(EVP_rc5_32_12_16_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc5_32_12_16_ofb');
  Result := EVP_rc5_32_12_16_ofb;
end;

{$endif} { OPENSSL_NO_RC5}
function Load_EVP_aes_128_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ecb := LoadLibCryptoFunction('EVP_aes_128_ecb');
  if not assigned(EVP_aes_128_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ecb');
  Result := EVP_aes_128_ecb;
end;

function Load_EVP_aes_128_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cbc := LoadLibCryptoFunction('EVP_aes_128_cbc');
  if not assigned(EVP_aes_128_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc');
  Result := EVP_aes_128_cbc;
end;

function Load_EVP_aes_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cfb1 := LoadLibCryptoFunction('EVP_aes_128_cfb1');
  if not assigned(EVP_aes_128_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb1');
  Result := EVP_aes_128_cfb1;
end;

function Load_EVP_aes_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cfb8 := LoadLibCryptoFunction('EVP_aes_128_cfb8');
  if not assigned(EVP_aes_128_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb8');
  Result := EVP_aes_128_cfb8;
end;

function Load_EVP_aes_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cfb128 := LoadLibCryptoFunction('EVP_aes_128_cfb128');
  if not assigned(EVP_aes_128_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb128');
  Result := EVP_aes_128_cfb128;
end;

function Load_EVP_aes_128_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cfb := LoadLibCryptoFunction('EVP_aes_128_cfb128');
  if not assigned(EVP_aes_128_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb128');
  Result := EVP_aes_128_cfb;
end;

function Load_EVP_aes_128_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ofb := LoadLibCryptoFunction('EVP_aes_128_ofb');
  if not assigned(EVP_aes_128_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ofb');
  Result := EVP_aes_128_ofb;
end;

function Load_EVP_aes_128_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ctr := LoadLibCryptoFunction('EVP_aes_128_ctr');
  if not assigned(EVP_aes_128_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ctr');
  Result := EVP_aes_128_ctr;
end;

function Load_EVP_aes_128_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ccm := LoadLibCryptoFunction('EVP_aes_128_ccm');
  if not assigned(EVP_aes_128_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ccm');
  Result := EVP_aes_128_ccm;
end;

function Load_EVP_aes_128_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_gcm := LoadLibCryptoFunction('EVP_aes_128_gcm');
  if not assigned(EVP_aes_128_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_gcm');
  Result := EVP_aes_128_gcm;
end;

function Load_EVP_aes_128_xts: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_xts := LoadLibCryptoFunction('EVP_aes_128_xts');
  if not assigned(EVP_aes_128_xts) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_xts');
  Result := EVP_aes_128_xts;
end;

function Load_EVP_aes_128_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_wrap := LoadLibCryptoFunction('EVP_aes_128_wrap');
  if not assigned(EVP_aes_128_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_wrap');
  Result := EVP_aes_128_wrap;
end;

function Load_EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_wrap_pad := LoadLibCryptoFunction('EVP_aes_128_wrap_pad');
  if not assigned(EVP_aes_128_wrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_wrap_pad');
  Result := EVP_aes_128_wrap_pad;
end;

{$ifndef  OPENSSL_NO_OCB}
function Load_EVP_aes_128_ocb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_ocb := LoadLibCryptoFunction('EVP_aes_128_ocb');
  if not assigned(EVP_aes_128_ocb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ocb');
  Result := EVP_aes_128_ocb;
end;

{$endif} { OPENSSL_NO_OCB}
function Load_EVP_aes_192_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ecb := LoadLibCryptoFunction('EVP_aes_192_ecb');
  if not assigned(EVP_aes_192_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ecb');
  Result := EVP_aes_192_ecb;
end;

function Load_EVP_aes_192_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cbc := LoadLibCryptoFunction('EVP_aes_192_cbc');
  if not assigned(EVP_aes_192_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cbc');
  Result := EVP_aes_192_cbc;
end;

function Load_EVP_aes_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cfb1 := LoadLibCryptoFunction('EVP_aes_192_cfb1');
  if not assigned(EVP_aes_192_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb1');
  Result := EVP_aes_192_cfb1;
end;

function Load_EVP_aes_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cfb8 := LoadLibCryptoFunction('EVP_aes_192_cfb8');
  if not assigned(EVP_aes_192_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb8');
  Result := EVP_aes_192_cfb8;
end;

function Load_EVP_aes_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cfb128 := LoadLibCryptoFunction('EVP_aes_192_cfb128');
  if not assigned(EVP_aes_192_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb128');
  Result := EVP_aes_192_cfb128;
end;

function Load_EVP_aes_192_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_cfb := LoadLibCryptoFunction('EVP_aes_192_cfb128');
  if not assigned(EVP_aes_192_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb128');
  Result := EVP_aes_192_cfb;
end;

function Load_EVP_aes_192_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ofb := LoadLibCryptoFunction('EVP_aes_192_ofb');
  if not assigned(EVP_aes_192_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ofb');
  Result := EVP_aes_192_ofb;
end;

function Load_EVP_aes_192_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ctr := LoadLibCryptoFunction('EVP_aes_192_ctr');
  if not assigned(EVP_aes_192_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ctr');
  Result := EVP_aes_192_ctr;
end;

function Load_EVP_aes_192_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ccm := LoadLibCryptoFunction('EVP_aes_192_ccm');
  if not assigned(EVP_aes_192_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ccm');
  Result := EVP_aes_192_ccm;
end;

function Load_EVP_aes_192_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_gcm := LoadLibCryptoFunction('EVP_aes_192_gcm');
  if not assigned(EVP_aes_192_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_gcm');
  Result := EVP_aes_192_gcm;
end;

function Load_EVP_aes_192_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_wrap := LoadLibCryptoFunction('EVP_aes_192_wrap');
  if not assigned(EVP_aes_192_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_wrap');
  Result := EVP_aes_192_wrap;
end;

function Load_EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_wrap_pad := LoadLibCryptoFunction('EVP_aes_192_wrap_pad');
  if not assigned(EVP_aes_192_wrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_wrap_pad');
  Result := EVP_aes_192_wrap_pad;
end;

{$ifndef  OPENSSL_NO_OCB}
function Load_EVP_aes_192_ocb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_192_ocb := LoadLibCryptoFunction('EVP_aes_192_ocb');
  if not assigned(EVP_aes_192_ocb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ocb');
  Result := EVP_aes_192_ocb;
end;

{$endif} { OPENSSL_NO_OCB}
function Load_EVP_aes_256_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ecb := LoadLibCryptoFunction('EVP_aes_256_ecb');
  if not assigned(EVP_aes_256_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ecb');
  Result := EVP_aes_256_ecb;
end;

function Load_EVP_aes_256_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cbc := LoadLibCryptoFunction('EVP_aes_256_cbc');
  if not assigned(EVP_aes_256_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc');
  Result := EVP_aes_256_cbc;
end;

function Load_EVP_aes_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cfb1 := LoadLibCryptoFunction('EVP_aes_256_cfb1');
  if not assigned(EVP_aes_256_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb1');
  Result := EVP_aes_256_cfb1;
end;

function Load_EVP_aes_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cfb8 := LoadLibCryptoFunction('EVP_aes_256_cfb8');
  if not assigned(EVP_aes_256_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb8');
  Result := EVP_aes_256_cfb8;
end;

function Load_EVP_aes_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cfb128 := LoadLibCryptoFunction('EVP_aes_256_cfb128');
  if not assigned(EVP_aes_256_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb128');
  Result := EVP_aes_256_cfb128;
end;

function Load_EVP_aes_256_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cfb := LoadLibCryptoFunction('EVP_aes_256_cfb128');
  if not assigned(EVP_aes_256_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb128');
  Result := EVP_aes_256_cfb;
end;

function Load_EVP_aes_256_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ofb := LoadLibCryptoFunction('EVP_aes_256_ofb');
  if not assigned(EVP_aes_256_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ofb');
  Result := EVP_aes_256_ofb;
end;

function Load_EVP_aes_256_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ctr := LoadLibCryptoFunction('EVP_aes_256_ctr');
  if not assigned(EVP_aes_256_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ctr');
  Result := EVP_aes_256_ctr;
end;

function Load_EVP_aes_256_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ccm := LoadLibCryptoFunction('EVP_aes_256_ccm');
  if not assigned(EVP_aes_256_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ccm');
  Result := EVP_aes_256_ccm;
end;

function Load_EVP_aes_256_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_gcm := LoadLibCryptoFunction('EVP_aes_256_gcm');
  if not assigned(EVP_aes_256_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_gcm');
  Result := EVP_aes_256_gcm;
end;

function Load_EVP_aes_256_xts: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_xts := LoadLibCryptoFunction('EVP_aes_256_xts');
  if not assigned(EVP_aes_256_xts) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_xts');
  Result := EVP_aes_256_xts;
end;

function Load_EVP_aes_256_wrap: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_wrap := LoadLibCryptoFunction('EVP_aes_256_wrap');
  if not assigned(EVP_aes_256_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_wrap');
  Result := EVP_aes_256_wrap;
end;

function Load_EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_wrap_pad := LoadLibCryptoFunction('EVP_aes_256_wrap_pad');
  if not assigned(EVP_aes_256_wrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_wrap_pad');
  Result := EVP_aes_256_wrap_pad;
end;

{$ifndef  OPENSSL_NO_OCB}
function Load_EVP_aes_256_ocb: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_ocb := LoadLibCryptoFunction('EVP_aes_256_ocb');
  if not assigned(EVP_aes_256_ocb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ocb');
  Result := EVP_aes_256_ocb;
end;

{$endif} { OPENSSL_NO_OCB}
function Load_EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cbc_hmac_sha1 := LoadLibCryptoFunction('EVP_aes_128_cbc_hmac_sha1');
  if not assigned(EVP_aes_128_cbc_hmac_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc_hmac_sha1');
  Result := EVP_aes_128_cbc_hmac_sha1;
end;

function Load_EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cbc_hmac_sha1 := LoadLibCryptoFunction('EVP_aes_256_cbc_hmac_sha1');
  if not assigned(EVP_aes_256_cbc_hmac_sha1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc_hmac_sha1');
  Result := EVP_aes_256_cbc_hmac_sha1;
end;

function Load_EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
begin
  EVP_aes_128_cbc_hmac_sha256 := LoadLibCryptoFunction('EVP_aes_128_cbc_hmac_sha256');
  if not assigned(EVP_aes_128_cbc_hmac_sha256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc_hmac_sha256');
  Result := EVP_aes_128_cbc_hmac_sha256;
end;

function Load_EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
begin
  EVP_aes_256_cbc_hmac_sha256 := LoadLibCryptoFunction('EVP_aes_256_cbc_hmac_sha256');
  if not assigned(EVP_aes_256_cbc_hmac_sha256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc_hmac_sha256');
  Result := EVP_aes_256_cbc_hmac_sha256;
end;

{$ifndef  OPENSSL_NO_ARIA}
function Load_EVP_aria_128_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ecb := LoadLibCryptoFunction('EVP_aria_128_ecb');
  if not assigned(EVP_aria_128_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ecb');
  Result := EVP_aria_128_ecb;
end;

function Load_EVP_aria_128_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cbc := LoadLibCryptoFunction('EVP_aria_128_cbc');
  if not assigned(EVP_aria_128_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cbc');
  Result := EVP_aria_128_cbc;
end;

function Load_EVP_aria_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cfb1 := LoadLibCryptoFunction('EVP_aria_128_cfb1');
  if not assigned(EVP_aria_128_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb1');
  Result := EVP_aria_128_cfb1;
end;

function Load_EVP_aria_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cfb8 := LoadLibCryptoFunction('EVP_aria_128_cfb8');
  if not assigned(EVP_aria_128_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb8');
  Result := EVP_aria_128_cfb8;
end;

function Load_EVP_aria_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cfb128 := LoadLibCryptoFunction('EVP_aria_128_cfb128');
  if not assigned(EVP_aria_128_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb128');
  Result := EVP_aria_128_cfb128;
end;

function Load_EVP_aria_128_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_cfb := LoadLibCryptoFunction('EVP_aria_128_cfb128');
  if not assigned(EVP_aria_128_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb128');
  Result := EVP_aria_128_cfb;
end;

function Load_EVP_aria_128_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ctr := LoadLibCryptoFunction('EVP_aria_128_ctr');
  if not assigned(EVP_aria_128_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ctr');
  Result := EVP_aria_128_ctr;
end;

function Load_EVP_aria_128_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ofb := LoadLibCryptoFunction('EVP_aria_128_ofb');
  if not assigned(EVP_aria_128_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ofb');
  Result := EVP_aria_128_ofb;
end;

function Load_EVP_aria_128_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_gcm := LoadLibCryptoFunction('EVP_aria_128_gcm');
  if not assigned(EVP_aria_128_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_gcm');
  Result := EVP_aria_128_gcm;
end;

function Load_EVP_aria_128_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_128_ccm := LoadLibCryptoFunction('EVP_aria_128_ccm');
  if not assigned(EVP_aria_128_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ccm');
  Result := EVP_aria_128_ccm;
end;

function Load_EVP_aria_192_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ecb := LoadLibCryptoFunction('EVP_aria_192_ecb');
  if not assigned(EVP_aria_192_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ecb');
  Result := EVP_aria_192_ecb;
end;

function Load_EVP_aria_192_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cbc := LoadLibCryptoFunction('EVP_aria_192_cbc');
  if not assigned(EVP_aria_192_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cbc');
  Result := EVP_aria_192_cbc;
end;

function Load_EVP_aria_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cfb1 := LoadLibCryptoFunction('EVP_aria_192_cfb1');
  if not assigned(EVP_aria_192_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb1');
  Result := EVP_aria_192_cfb1;
end;

function Load_EVP_aria_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cfb8 := LoadLibCryptoFunction('EVP_aria_192_cfb8');
  if not assigned(EVP_aria_192_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb8');
  Result := EVP_aria_192_cfb8;
end;

function Load_EVP_aria_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cfb128 := LoadLibCryptoFunction('EVP_aria_192_cfb128');
  if not assigned(EVP_aria_192_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb128');
  Result := EVP_aria_192_cfb128;
end;

function Load_EVP_aria_192_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_cfb := LoadLibCryptoFunction('EVP_aria_192_cfb128');
  if not assigned(EVP_aria_192_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb128');
  Result := EVP_aria_192_cfb;
end;

function Load_EVP_aria_192_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ctr := LoadLibCryptoFunction('EVP_aria_192_ctr');
  if not assigned(EVP_aria_192_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ctr');
  Result := EVP_aria_192_ctr;
end;

function Load_EVP_aria_192_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ofb := LoadLibCryptoFunction('EVP_aria_192_ofb');
  if not assigned(EVP_aria_192_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ofb');
  Result := EVP_aria_192_ofb;
end;

function Load_EVP_aria_192_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_gcm := LoadLibCryptoFunction('EVP_aria_192_gcm');
  if not assigned(EVP_aria_192_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_gcm');
  Result := EVP_aria_192_gcm;
end;

function Load_EVP_aria_192_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_192_ccm := LoadLibCryptoFunction('EVP_aria_192_ccm');
  if not assigned(EVP_aria_192_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ccm');
  Result := EVP_aria_192_ccm;
end;

function Load_EVP_aria_256_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ecb := LoadLibCryptoFunction('EVP_aria_256_ecb');
  if not assigned(EVP_aria_256_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ecb');
  Result := EVP_aria_256_ecb;
end;

function Load_EVP_aria_256_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cbc := LoadLibCryptoFunction('EVP_aria_256_cbc');
  if not assigned(EVP_aria_256_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cbc');
  Result := EVP_aria_256_cbc;
end;

function Load_EVP_aria_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cfb1 := LoadLibCryptoFunction('EVP_aria_256_cfb1');
  if not assigned(EVP_aria_256_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb1');
  Result := EVP_aria_256_cfb1;
end;

function Load_EVP_aria_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cfb8 := LoadLibCryptoFunction('EVP_aria_256_cfb8');
  if not assigned(EVP_aria_256_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb8');
  Result := EVP_aria_256_cfb8;
end;

function Load_EVP_aria_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cfb128 := LoadLibCryptoFunction('EVP_aria_256_cfb128');
  if not assigned(EVP_aria_256_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb128');
  Result := EVP_aria_256_cfb128;
end;

function Load_EVP_aria_256_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_cfb := LoadLibCryptoFunction('EVP_aria_256_cfb128');
  if not assigned(EVP_aria_256_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb128');
  Result := EVP_aria_256_cfb;
end;

function Load_EVP_aria_256_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ctr := LoadLibCryptoFunction('EVP_aria_256_ctr');
  if not assigned(EVP_aria_256_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ctr');
  Result := EVP_aria_256_ctr;
end;

function Load_EVP_aria_256_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ofb := LoadLibCryptoFunction('EVP_aria_256_ofb');
  if not assigned(EVP_aria_256_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ofb');
  Result := EVP_aria_256_ofb;
end;

function Load_EVP_aria_256_gcm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_gcm := LoadLibCryptoFunction('EVP_aria_256_gcm');
  if not assigned(EVP_aria_256_gcm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_gcm');
  Result := EVP_aria_256_gcm;
end;

function Load_EVP_aria_256_ccm: PEVP_CIPHER; cdecl;
begin
  EVP_aria_256_ccm := LoadLibCryptoFunction('EVP_aria_256_ccm');
  if not assigned(EVP_aria_256_ccm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ccm');
  Result := EVP_aria_256_ccm;
end;

{$endif} { OPENSSL_NO_ARIA}
{$ifndef  OPENSSL_NO_CAMELLIA}
function Load_EVP_camellia_128_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_ecb := LoadLibCryptoFunction('EVP_camellia_128_ecb');
  if not assigned(EVP_camellia_128_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ecb');
  Result := EVP_camellia_128_ecb;
end;

function Load_EVP_camellia_128_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cbc := LoadLibCryptoFunction('EVP_camellia_128_cbc');
  if not assigned(EVP_camellia_128_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cbc');
  Result := EVP_camellia_128_cbc;
end;

function Load_EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cfb1 := LoadLibCryptoFunction('EVP_camellia_128_cfb1');
  if not assigned(EVP_camellia_128_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb1');
  Result := EVP_camellia_128_cfb1;
end;

function Load_EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cfb8 := LoadLibCryptoFunction('EVP_camellia_128_cfb8');
  if not assigned(EVP_camellia_128_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb8');
  Result := EVP_camellia_128_cfb8;
end;

function Load_EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cfb128 := LoadLibCryptoFunction('EVP_camellia_128_cfb128');
  if not assigned(EVP_camellia_128_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb128');
  Result := EVP_camellia_128_cfb128;
end;

function Load_EVP_camellia_128_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_cfb := LoadLibCryptoFunction('EVP_camellia_128_cfb128');
  if not assigned(EVP_camellia_128_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb128');
  Result := EVP_camellia_128_cfb;
end;

function Load_EVP_camellia_128_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_ofb := LoadLibCryptoFunction('EVP_camellia_128_ofb');
  if not assigned(EVP_camellia_128_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ofb');
  Result := EVP_camellia_128_ofb;
end;

function Load_EVP_camellia_128_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_128_ctr := LoadLibCryptoFunction('EVP_camellia_128_ctr');
  if not assigned(EVP_camellia_128_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ctr');
  Result := EVP_camellia_128_ctr;
end;

function Load_EVP_camellia_192_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_ecb := LoadLibCryptoFunction('EVP_camellia_192_ecb');
  if not assigned(EVP_camellia_192_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ecb');
  Result := EVP_camellia_192_ecb;
end;

function Load_EVP_camellia_192_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cbc := LoadLibCryptoFunction('EVP_camellia_192_cbc');
  if not assigned(EVP_camellia_192_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cbc');
  Result := EVP_camellia_192_cbc;
end;

function Load_EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cfb1 := LoadLibCryptoFunction('EVP_camellia_192_cfb1');
  if not assigned(EVP_camellia_192_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb1');
  Result := EVP_camellia_192_cfb1;
end;

function Load_EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cfb8 := LoadLibCryptoFunction('EVP_camellia_192_cfb8');
  if not assigned(EVP_camellia_192_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb8');
  Result := EVP_camellia_192_cfb8;
end;

function Load_EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cfb128 := LoadLibCryptoFunction('EVP_camellia_192_cfb128');
  if not assigned(EVP_camellia_192_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb128');
  Result := EVP_camellia_192_cfb128;
end;

function Load_EVP_camellia_192_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_cfb := LoadLibCryptoFunction('EVP_camellia_192_cfb128');
  if not assigned(EVP_camellia_192_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb128');
  Result := EVP_camellia_192_cfb;
end;

function Load_EVP_camellia_192_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_ofb := LoadLibCryptoFunction('EVP_camellia_192_ofb');
  if not assigned(EVP_camellia_192_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ofb');
  Result := EVP_camellia_192_ofb;
end;

function Load_EVP_camellia_192_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_192_ctr := LoadLibCryptoFunction('EVP_camellia_192_ctr');
  if not assigned(EVP_camellia_192_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ctr');
  Result := EVP_camellia_192_ctr;
end;

function Load_EVP_camellia_256_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_ecb := LoadLibCryptoFunction('EVP_camellia_256_ecb');
  if not assigned(EVP_camellia_256_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ecb');
  Result := EVP_camellia_256_ecb;
end;

function Load_EVP_camellia_256_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cbc := LoadLibCryptoFunction('EVP_camellia_256_cbc');
  if not assigned(EVP_camellia_256_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cbc');
  Result := EVP_camellia_256_cbc;
end;

function Load_EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cfb1 := LoadLibCryptoFunction('EVP_camellia_256_cfb1');
  if not assigned(EVP_camellia_256_cfb1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb1');
  Result := EVP_camellia_256_cfb1;
end;

function Load_EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cfb8 := LoadLibCryptoFunction('EVP_camellia_256_cfb8');
  if not assigned(EVP_camellia_256_cfb8) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb8');
  Result := EVP_camellia_256_cfb8;
end;

function Load_EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cfb128 := LoadLibCryptoFunction('EVP_camellia_256_cfb128');
  if not assigned(EVP_camellia_256_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb128');
  Result := EVP_camellia_256_cfb128;
end;

function Load_EVP_camellia_256_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_cfb := LoadLibCryptoFunction('EVP_camellia_256_cfb128');
  if not assigned(EVP_camellia_256_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb128');
  Result := EVP_camellia_256_cfb;
end;

function Load_EVP_camellia_256_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_ofb := LoadLibCryptoFunction('EVP_camellia_256_ofb');
  if not assigned(EVP_camellia_256_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ofb');
  Result := EVP_camellia_256_ofb;
end;

function Load_EVP_camellia_256_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_camellia_256_ctr := LoadLibCryptoFunction('EVP_camellia_256_ctr');
  if not assigned(EVP_camellia_256_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ctr');
  Result := EVP_camellia_256_ctr;
end;

{$endif} { OPENSSL_NO_CAMELLIA}
{$ifndef  OPENSSL_NO_CHACHA}
function Load_EVP_chacha20: PEVP_CIPHER; cdecl;
begin
  EVP_chacha20 := LoadLibCryptoFunction('EVP_chacha20');
  if not assigned(EVP_chacha20) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_chacha20');
  Result := EVP_chacha20;
end;

    {$ifndef  OPENSSL_NO_POLY1305}
function Load_EVP_chacha20_poly1305: PEVP_CIPHER; cdecl;
begin
  EVP_chacha20_poly1305 := LoadLibCryptoFunction('EVP_chacha20_poly1305');
  if not assigned(EVP_chacha20_poly1305) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_chacha20_poly1305');
  Result := EVP_chacha20_poly1305;
end;

    {$endif} { OPENSSL_NO_POLY1305}
{$endif} { OPENSSL_NO_CHACHA}
{$ifndef  OPENSSL_NO_SEED}
function Load_EVP_seed_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_seed_ecb := LoadLibCryptoFunction('EVP_seed_ecb');
  if not assigned(EVP_seed_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_ecb');
  Result := EVP_seed_ecb;
end;

function Load_EVP_seed_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_seed_cbc := LoadLibCryptoFunction('EVP_seed_cbc');
  if not assigned(EVP_seed_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_cbc');
  Result := EVP_seed_cbc;
end;

function Load_EVP_seed_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_seed_cfb128 := LoadLibCryptoFunction('EVP_seed_cfb128');
  if not assigned(EVP_seed_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_cfb128');
  Result := EVP_seed_cfb128;
end;

function Load_EVP_seed_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_seed_cfb := LoadLibCryptoFunction('EVP_seed_cfb128');
  if not assigned(EVP_seed_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_cfb128');
  Result := EVP_seed_cfb;
end;

function Load_EVP_seed_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_seed_ofb := LoadLibCryptoFunction('EVP_seed_ofb');
  if not assigned(EVP_seed_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_ofb');
  Result := EVP_seed_ofb;
end;

{$endif} { OPENSSL_NO_SEED}
{$ifndef  OPENSSL_NO_SM4}
function Load_EVP_sm4_ecb: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_ecb := LoadLibCryptoFunction('EVP_sm4_ecb');
  if not assigned(EVP_sm4_ecb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ecb');
  Result := EVP_sm4_ecb;
end;

function Load_EVP_sm4_cbc: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_cbc := LoadLibCryptoFunction('EVP_sm4_cbc');
  if not assigned(EVP_sm4_cbc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_cbc');
  Result := EVP_sm4_cbc;
end;

function Load_EVP_sm4_cfb128: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_cfb128 := LoadLibCryptoFunction('EVP_sm4_cfb128');
  if not assigned(EVP_sm4_cfb128) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_cfb128');
  Result := EVP_sm4_cfb128;
end;

function Load_EVP_sm4_cfb: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_cfb := LoadLibCryptoFunction('EVP_sm4_cfb128');
  if not assigned(EVP_sm4_cfb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_cfb128');
  Result := EVP_sm4_cfb;
end;

function Load_EVP_sm4_ofb: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_ofb := LoadLibCryptoFunction('EVP_sm4_ofb');
  if not assigned(EVP_sm4_ofb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ofb');
  Result := EVP_sm4_ofb;
end;

function Load_EVP_sm4_ctr: PEVP_CIPHER; cdecl;
begin
  EVP_sm4_ctr := LoadLibCryptoFunction('EVP_sm4_ctr');
  if not assigned(EVP_sm4_ctr) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ctr');
  Result := EVP_sm4_ctr;
end;

{$endif} { OPENSSL_NO_SM4}
function Load_EVP_add_cipher(cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_add_cipher := LoadLibCryptoFunction('EVP_add_cipher');
  if not assigned(EVP_add_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_cipher');
  Result := EVP_add_cipher(cipher);
end;

function Load_EVP_add_digest(digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_add_digest := LoadLibCryptoFunction('EVP_add_digest');
  if not assigned(EVP_add_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_digest');
  Result := EVP_add_digest(digest);
end;

function Load_EVP_get_cipherbyname(name: PAnsiChar): PEVP_CIPHER; cdecl;
begin
  EVP_get_cipherbyname := LoadLibCryptoFunction('EVP_get_cipherbyname');
  if not assigned(EVP_get_cipherbyname) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_cipherbyname');
  Result := EVP_get_cipherbyname(name);
end;

function Load_EVP_get_digestbyname(name: PAnsiChar): PEVP_MD; cdecl;
begin
  EVP_get_digestbyname := LoadLibCryptoFunction('EVP_get_digestbyname');
  if not assigned(EVP_get_digestbyname) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_digestbyname');
  Result := EVP_get_digestbyname(name);
end;

procedure Load_EVP_CIPHER_do_all(fn: TFuncType028; arg: pointer); cdecl;
begin
  EVP_CIPHER_do_all := LoadLibCryptoFunction('EVP_CIPHER_do_all');
  if not assigned(EVP_CIPHER_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_do_all');
  EVP_CIPHER_do_all(fn, arg);
end;

procedure Load_EVP_CIPHER_do_all_sorted(fn: TFuncType029; arg: pointer); cdecl;
begin
  EVP_CIPHER_do_all_sorted := LoadLibCryptoFunction('EVP_CIPHER_do_all_sorted');
  if not assigned(EVP_CIPHER_do_all_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_do_all_sorted');
  EVP_CIPHER_do_all_sorted(fn, arg);
end;

procedure Load_EVP_CIPHER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType030; arg: pointer); cdecl;
begin
  EVP_CIPHER_do_all_provided := LoadLibCryptoFunction('EVP_CIPHER_do_all_provided');
  if not assigned(EVP_CIPHER_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_do_all_provided');
  EVP_CIPHER_do_all_provided(libctx, fn, arg);
end;

procedure Load_EVP_MD_do_all(fn: TFuncType031; arg: pointer); cdecl;
begin
  EVP_MD_do_all := LoadLibCryptoFunction('EVP_MD_do_all');
  if not assigned(EVP_MD_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_do_all');
  EVP_MD_do_all(fn, arg);
end;

procedure Load_EVP_MD_do_all_sorted(fn: TFuncType032; arg: pointer); cdecl;
begin
  EVP_MD_do_all_sorted := LoadLibCryptoFunction('EVP_MD_do_all_sorted');
  if not assigned(EVP_MD_do_all_sorted) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_do_all_sorted');
  EVP_MD_do_all_sorted(fn, arg);
end;

procedure Load_EVP_MD_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType033; arg: pointer); cdecl;
begin
  EVP_MD_do_all_provided := LoadLibCryptoFunction('EVP_MD_do_all_provided');
  if not assigned(EVP_MD_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_do_all_provided');
  EVP_MD_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_MAC_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_MAC; cdecl;
begin
  EVP_MAC_fetch := LoadLibCryptoFunction('EVP_MAC_fetch');
  if not assigned(EVP_MAC_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_fetch');
  Result := EVP_MAC_fetch(libctx, algorithm, properties);
end;

function Load_EVP_MAC_up_ref(mac: PEVP_MAC): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_up_ref := LoadLibCryptoFunction('EVP_MAC_up_ref');
  if not assigned(EVP_MAC_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_up_ref');
  Result := EVP_MAC_up_ref(mac);
end;

procedure Load_EVP_MAC_free(mac: PEVP_MAC); cdecl;
begin
  EVP_MAC_free := LoadLibCryptoFunction('EVP_MAC_free');
  if not assigned(EVP_MAC_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_free');
  EVP_MAC_free(mac);
end;

function Load_EVP_MAC_get0_name(mac: PEVP_MAC): PAnsiChar; cdecl;
begin
  EVP_MAC_get0_name := LoadLibCryptoFunction('EVP_MAC_get0_name');
  if not assigned(EVP_MAC_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_get0_name');
  Result := EVP_MAC_get0_name(mac);
end;

function Load_EVP_MAC_get0_description(mac: PEVP_MAC): PAnsiChar; cdecl;
begin
  EVP_MAC_get0_description := LoadLibCryptoFunction('EVP_MAC_get0_description');
  if not assigned(EVP_MAC_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_get0_description');
  Result := EVP_MAC_get0_description(mac);
end;

function Load_EVP_MAC_is_a(mac: PEVP_MAC; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_is_a := LoadLibCryptoFunction('EVP_MAC_is_a');
  if not assigned(EVP_MAC_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_is_a');
  Result := EVP_MAC_is_a(mac, name);
end;

function Load_EVP_MAC_get0_provider(mac: PEVP_MAC): POSSL_PROVIDER; cdecl;
begin
  EVP_MAC_get0_provider := LoadLibCryptoFunction('EVP_MAC_get0_provider');
  if not assigned(EVP_MAC_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_get0_provider');
  Result := EVP_MAC_get0_provider(mac);
end;

function Load_EVP_MAC_get_params(mac: PEVP_MAC; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_get_params := LoadLibCryptoFunction('EVP_MAC_get_params');
  if not assigned(EVP_MAC_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_get_params');
  Result := EVP_MAC_get_params(mac, params);
end;

function Load_EVP_MAC_CTX_new(mac: PEVP_MAC): PEVP_MAC_CTX; cdecl;
begin
  EVP_MAC_CTX_new := LoadLibCryptoFunction('EVP_MAC_CTX_new');
  if not assigned(EVP_MAC_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_new');
  Result := EVP_MAC_CTX_new(mac);
end;

procedure Load_EVP_MAC_CTX_free(ctx: PEVP_MAC_CTX); cdecl;
begin
  EVP_MAC_CTX_free := LoadLibCryptoFunction('EVP_MAC_CTX_free');
  if not assigned(EVP_MAC_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_free');
  EVP_MAC_CTX_free(ctx);
end;

function Load_EVP_MAC_CTX_dup(src: PEVP_MAC_CTX): PEVP_MAC_CTX; cdecl;
begin
  EVP_MAC_CTX_dup := LoadLibCryptoFunction('EVP_MAC_CTX_dup');
  if not assigned(EVP_MAC_CTX_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_dup');
  Result := EVP_MAC_CTX_dup(src);
end;

function Load_EVP_MAC_CTX_get0_mac(ctx: PEVP_MAC_CTX): PEVP_MAC; cdecl;
begin
  EVP_MAC_CTX_get0_mac := LoadLibCryptoFunction('EVP_MAC_CTX_get0_mac');
  if not assigned(EVP_MAC_CTX_get0_mac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_get0_mac');
  Result := EVP_MAC_CTX_get0_mac(ctx);
end;

function Load_EVP_MAC_CTX_get_params(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_CTX_get_params := LoadLibCryptoFunction('EVP_MAC_CTX_get_params');
  if not assigned(EVP_MAC_CTX_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_get_params');
  Result := EVP_MAC_CTX_get_params(ctx, params);
end;

function Load_EVP_MAC_CTX_set_params(ctx: PEVP_MAC_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_CTX_set_params := LoadLibCryptoFunction('EVP_MAC_CTX_set_params');
  if not assigned(EVP_MAC_CTX_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_set_params');
  Result := EVP_MAC_CTX_set_params(ctx, params);
end;

function Load_EVP_MAC_CTX_get_mac_size(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EVP_MAC_CTX_get_mac_size := LoadLibCryptoFunction('EVP_MAC_CTX_get_mac_size');
  if not assigned(EVP_MAC_CTX_get_mac_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_get_mac_size');
  Result := EVP_MAC_CTX_get_mac_size(ctx);
end;

function Load_EVP_MAC_CTX_get_block_size(ctx: PEVP_MAC_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EVP_MAC_CTX_get_block_size := LoadLibCryptoFunction('EVP_MAC_CTX_get_block_size');
  if not assigned(EVP_MAC_CTX_get_block_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_get_block_size');
  Result := EVP_MAC_CTX_get_block_size(ctx);
end;

function Load_EVP_Q_mac(libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar; subalg: PAnsiChar; params: POSSL_PARAM; key: pointer; keylen: TOpenSSL_C_SIZET; data: Pbyte; datalen: TOpenSSL_C_SIZET; out_: Pbyte; outsize: TOpenSSL_C_SIZET; outlen: POpenSSL_C_SIZET): Pbyte; cdecl;
begin
  EVP_Q_mac := LoadLibCryptoFunction('EVP_Q_mac');
  if not assigned(EVP_Q_mac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_Q_mac');
  Result := EVP_Q_mac(libctx, name, propq, subalg, params, key, keylen, data, datalen, out_, outsize, outlen);
end;

function Load_EVP_MAC_init(ctx: PEVP_MAC_CTX; key: Pbyte; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_init := LoadLibCryptoFunction('EVP_MAC_init');
  if not assigned(EVP_MAC_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_init');
  Result := EVP_MAC_init(ctx, key, keylen, params);
end;

function Load_EVP_MAC_init_SKEY(ctx: PEVP_MAC_CTX; skey: PEVP_SKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_init_SKEY := LoadLibCryptoFunction('EVP_MAC_init_SKEY');
  if not assigned(EVP_MAC_init_SKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_init_SKEY');
  Result := EVP_MAC_init_SKEY(ctx, skey, params);
end;

function Load_EVP_MAC_update(ctx: PEVP_MAC_CTX; data: Pbyte; datalen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_update := LoadLibCryptoFunction('EVP_MAC_update');
  if not assigned(EVP_MAC_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_update');
  Result := EVP_MAC_update(ctx, data, datalen);
end;

function Load_EVP_MAC_final(ctx: PEVP_MAC_CTX; out_: Pbyte; outl: POpenSSL_C_SIZET; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_final := LoadLibCryptoFunction('EVP_MAC_final');
  if not assigned(EVP_MAC_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_final');
  Result := EVP_MAC_final(ctx, out_, outl, outsize);
end;

function Load_EVP_MAC_finalXOF(ctx: PEVP_MAC_CTX; out_: Pbyte; outsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_finalXOF := LoadLibCryptoFunction('EVP_MAC_finalXOF');
  if not assigned(EVP_MAC_finalXOF) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_finalXOF');
  Result := EVP_MAC_finalXOF(ctx, out_, outsize);
end;

function Load_EVP_MAC_gettable_params(mac: PEVP_MAC): POSSL_PARAM; cdecl;
begin
  EVP_MAC_gettable_params := LoadLibCryptoFunction('EVP_MAC_gettable_params');
  if not assigned(EVP_MAC_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_gettable_params');
  Result := EVP_MAC_gettable_params(mac);
end;

function Load_EVP_MAC_gettable_ctx_params(mac: PEVP_MAC): POSSL_PARAM; cdecl;
begin
  EVP_MAC_gettable_ctx_params := LoadLibCryptoFunction('EVP_MAC_gettable_ctx_params');
  if not assigned(EVP_MAC_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_gettable_ctx_params');
  Result := EVP_MAC_gettable_ctx_params(mac);
end;

function Load_EVP_MAC_settable_ctx_params(mac: PEVP_MAC): POSSL_PARAM; cdecl;
begin
  EVP_MAC_settable_ctx_params := LoadLibCryptoFunction('EVP_MAC_settable_ctx_params');
  if not assigned(EVP_MAC_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_settable_ctx_params');
  Result := EVP_MAC_settable_ctx_params(mac);
end;

function Load_EVP_MAC_CTX_gettable_params(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl;
begin
  EVP_MAC_CTX_gettable_params := LoadLibCryptoFunction('EVP_MAC_CTX_gettable_params');
  if not assigned(EVP_MAC_CTX_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_gettable_params');
  Result := EVP_MAC_CTX_gettable_params(ctx);
end;

function Load_EVP_MAC_CTX_settable_params(ctx: PEVP_MAC_CTX): POSSL_PARAM; cdecl;
begin
  EVP_MAC_CTX_settable_params := LoadLibCryptoFunction('EVP_MAC_CTX_settable_params');
  if not assigned(EVP_MAC_CTX_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_CTX_settable_params');
  Result := EVP_MAC_CTX_settable_params(ctx);
end;

procedure Load_EVP_MAC_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType034; arg: pointer); cdecl;
begin
  EVP_MAC_do_all_provided := LoadLibCryptoFunction('EVP_MAC_do_all_provided');
  if not assigned(EVP_MAC_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_do_all_provided');
  EVP_MAC_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_MAC_names_do_all(mac: PEVP_MAC; fn: TFuncType035; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_MAC_names_do_all := LoadLibCryptoFunction('EVP_MAC_names_do_all');
  if not assigned(EVP_MAC_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MAC_names_do_all');
  Result := EVP_MAC_names_do_all(mac, fn, data);
end;

function Load_EVP_RAND_fetch(libctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_RAND; cdecl;
begin
  EVP_RAND_fetch := LoadLibCryptoFunction('EVP_RAND_fetch');
  if not assigned(EVP_RAND_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_fetch');
  Result := EVP_RAND_fetch(libctx, algorithm, properties);
end;

function Load_EVP_RAND_up_ref(rand: PEVP_RAND): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_up_ref := LoadLibCryptoFunction('EVP_RAND_up_ref');
  if not assigned(EVP_RAND_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_up_ref');
  Result := EVP_RAND_up_ref(rand);
end;

procedure Load_EVP_RAND_free(rand: PEVP_RAND); cdecl;
begin
  EVP_RAND_free := LoadLibCryptoFunction('EVP_RAND_free');
  if not assigned(EVP_RAND_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_free');
  EVP_RAND_free(rand);
end;

function Load_EVP_RAND_get0_name(rand: PEVP_RAND): PAnsiChar; cdecl;
begin
  EVP_RAND_get0_name := LoadLibCryptoFunction('EVP_RAND_get0_name');
  if not assigned(EVP_RAND_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_get0_name');
  Result := EVP_RAND_get0_name(rand);
end;

function Load_EVP_RAND_get0_description(md: PEVP_RAND): PAnsiChar; cdecl;
begin
  EVP_RAND_get0_description := LoadLibCryptoFunction('EVP_RAND_get0_description');
  if not assigned(EVP_RAND_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_get0_description');
  Result := EVP_RAND_get0_description(md);
end;

function Load_EVP_RAND_is_a(rand: PEVP_RAND; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_is_a := LoadLibCryptoFunction('EVP_RAND_is_a');
  if not assigned(EVP_RAND_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_is_a');
  Result := EVP_RAND_is_a(rand, name);
end;

function Load_EVP_RAND_get0_provider(rand: PEVP_RAND): POSSL_PROVIDER; cdecl;
begin
  EVP_RAND_get0_provider := LoadLibCryptoFunction('EVP_RAND_get0_provider');
  if not assigned(EVP_RAND_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_get0_provider');
  Result := EVP_RAND_get0_provider(rand);
end;

function Load_EVP_RAND_get_params(rand: PEVP_RAND; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_get_params := LoadLibCryptoFunction('EVP_RAND_get_params');
  if not assigned(EVP_RAND_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_get_params');
  Result := EVP_RAND_get_params(rand, params);
end;

function Load_EVP_RAND_CTX_new(rand: PEVP_RAND; parent: PEVP_RAND_CTX): PEVP_RAND_CTX; cdecl;
begin
  EVP_RAND_CTX_new := LoadLibCryptoFunction('EVP_RAND_CTX_new');
  if not assigned(EVP_RAND_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_new');
  Result := EVP_RAND_CTX_new(rand, parent);
end;

function Load_EVP_RAND_CTX_up_ref(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_CTX_up_ref := LoadLibCryptoFunction('EVP_RAND_CTX_up_ref');
  if not assigned(EVP_RAND_CTX_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_up_ref');
  Result := EVP_RAND_CTX_up_ref(ctx);
end;

procedure Load_EVP_RAND_CTX_free(ctx: PEVP_RAND_CTX); cdecl;
begin
  EVP_RAND_CTX_free := LoadLibCryptoFunction('EVP_RAND_CTX_free');
  if not assigned(EVP_RAND_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_free');
  EVP_RAND_CTX_free(ctx);
end;

function Load_EVP_RAND_CTX_get0_rand(ctx: PEVP_RAND_CTX): PEVP_RAND; cdecl;
begin
  EVP_RAND_CTX_get0_rand := LoadLibCryptoFunction('EVP_RAND_CTX_get0_rand');
  if not assigned(EVP_RAND_CTX_get0_rand) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_get0_rand');
  Result := EVP_RAND_CTX_get0_rand(ctx);
end;

function Load_EVP_RAND_CTX_get_params(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_CTX_get_params := LoadLibCryptoFunction('EVP_RAND_CTX_get_params');
  if not assigned(EVP_RAND_CTX_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_get_params');
  Result := EVP_RAND_CTX_get_params(ctx, params);
end;

function Load_EVP_RAND_CTX_set_params(ctx: PEVP_RAND_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_CTX_set_params := LoadLibCryptoFunction('EVP_RAND_CTX_set_params');
  if not assigned(EVP_RAND_CTX_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_set_params');
  Result := EVP_RAND_CTX_set_params(ctx, params);
end;

function Load_EVP_RAND_gettable_params(rand: PEVP_RAND): POSSL_PARAM; cdecl;
begin
  EVP_RAND_gettable_params := LoadLibCryptoFunction('EVP_RAND_gettable_params');
  if not assigned(EVP_RAND_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_gettable_params');
  Result := EVP_RAND_gettable_params(rand);
end;

function Load_EVP_RAND_gettable_ctx_params(rand: PEVP_RAND): POSSL_PARAM; cdecl;
begin
  EVP_RAND_gettable_ctx_params := LoadLibCryptoFunction('EVP_RAND_gettable_ctx_params');
  if not assigned(EVP_RAND_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_gettable_ctx_params');
  Result := EVP_RAND_gettable_ctx_params(rand);
end;

function Load_EVP_RAND_settable_ctx_params(rand: PEVP_RAND): POSSL_PARAM; cdecl;
begin
  EVP_RAND_settable_ctx_params := LoadLibCryptoFunction('EVP_RAND_settable_ctx_params');
  if not assigned(EVP_RAND_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_settable_ctx_params');
  Result := EVP_RAND_settable_ctx_params(rand);
end;

function Load_EVP_RAND_CTX_gettable_params(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl;
begin
  EVP_RAND_CTX_gettable_params := LoadLibCryptoFunction('EVP_RAND_CTX_gettable_params');
  if not assigned(EVP_RAND_CTX_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_gettable_params');
  Result := EVP_RAND_CTX_gettable_params(ctx);
end;

function Load_EVP_RAND_CTX_settable_params(ctx: PEVP_RAND_CTX): POSSL_PARAM; cdecl;
begin
  EVP_RAND_CTX_settable_params := LoadLibCryptoFunction('EVP_RAND_CTX_settable_params');
  if not assigned(EVP_RAND_CTX_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_CTX_settable_params');
  Result := EVP_RAND_CTX_settable_params(ctx);
end;

procedure Load_EVP_RAND_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType036; arg: pointer); cdecl;
begin
  EVP_RAND_do_all_provided := LoadLibCryptoFunction('EVP_RAND_do_all_provided');
  if not assigned(EVP_RAND_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_do_all_provided');
  EVP_RAND_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_RAND_names_do_all(rand: PEVP_RAND; fn: TFuncType037; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_names_do_all := LoadLibCryptoFunction('EVP_RAND_names_do_all');
  if not assigned(EVP_RAND_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_names_do_all');
  Result := EVP_RAND_names_do_all(rand, fn, data);
end;

function Load_EVP_RAND_instantiate(ctx: PEVP_RAND_CTX; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; pstr: Pbyte; pstr_len: TOpenSSL_C_SIZET; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_instantiate := LoadLibCryptoFunction('EVP_RAND_instantiate');
  if not assigned(EVP_RAND_instantiate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_instantiate');
  Result := EVP_RAND_instantiate(ctx, strength, prediction_resistance, pstr, pstr_len, params);
end;

function Load_EVP_RAND_uninstantiate(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_uninstantiate := LoadLibCryptoFunction('EVP_RAND_uninstantiate');
  if not assigned(EVP_RAND_uninstantiate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_uninstantiate');
  Result := EVP_RAND_uninstantiate(ctx);
end;

function Load_EVP_RAND_generate(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET; strength: TOpenSSL_C_UINT; prediction_resistance: TOpenSSL_C_INT; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_generate := LoadLibCryptoFunction('EVP_RAND_generate');
  if not assigned(EVP_RAND_generate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_generate');
  Result := EVP_RAND_generate(ctx, out_, outlen, strength, prediction_resistance, addin, addin_len);
end;

function Load_EVP_RAND_reseed(ctx: PEVP_RAND_CTX; prediction_resistance: TOpenSSL_C_INT; ent: Pbyte; ent_len: TOpenSSL_C_SIZET; addin: Pbyte; addin_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_reseed := LoadLibCryptoFunction('EVP_RAND_reseed');
  if not assigned(EVP_RAND_reseed) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_reseed');
  Result := EVP_RAND_reseed(ctx, prediction_resistance, ent, ent_len, addin, addin_len);
end;

function Load_EVP_RAND_nonce(ctx: PEVP_RAND_CTX; out_: Pbyte; outlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_nonce := LoadLibCryptoFunction('EVP_RAND_nonce');
  if not assigned(EVP_RAND_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_nonce');
  Result := EVP_RAND_nonce(ctx, out_, outlen);
end;

function Load_EVP_RAND_enable_locking(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_enable_locking := LoadLibCryptoFunction('EVP_RAND_enable_locking');
  if not assigned(EVP_RAND_enable_locking) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_enable_locking');
  Result := EVP_RAND_enable_locking(ctx);
end;

function Load_EVP_RAND_verify_zeroization(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_verify_zeroization := LoadLibCryptoFunction('EVP_RAND_verify_zeroization');
  if not assigned(EVP_RAND_verify_zeroization) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_verify_zeroization');
  Result := EVP_RAND_verify_zeroization(ctx);
end;

function Load_EVP_RAND_get_strength(ctx: PEVP_RAND_CTX): TOpenSSL_C_UINT; cdecl;
begin
  EVP_RAND_get_strength := LoadLibCryptoFunction('EVP_RAND_get_strength');
  if not assigned(EVP_RAND_get_strength) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_get_strength');
  Result := EVP_RAND_get_strength(ctx);
end;

function Load_EVP_RAND_get_state(ctx: PEVP_RAND_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_RAND_get_state := LoadLibCryptoFunction('EVP_RAND_get_state');
  if not assigned(EVP_RAND_get_state) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_RAND_get_state');
  Result := EVP_RAND_get_state(ctx);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_decrypt_old(dec_key: Pbyte; enc_key: Pbyte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decrypt_old := LoadLibCryptoFunction('EVP_PKEY_decrypt_old');
  if not assigned(EVP_PKEY_decrypt_old) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt_old');
  Result := EVP_PKEY_decrypt_old(dec_key, enc_key, enc_key_len, private_key);
end;

function Load_EVP_PKEY_encrypt_old(enc_key: Pbyte; key: Pbyte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encrypt_old := LoadLibCryptoFunction('EVP_PKEY_encrypt_old');
  if not assigned(EVP_PKEY_encrypt_old) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt_old');
  Result := EVP_PKEY_encrypt_old(enc_key, key, key_len, pub_key);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_is_a(pkey: PEVP_PKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_is_a := LoadLibCryptoFunction('EVP_PKEY_is_a');
  if not assigned(EVP_PKEY_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_is_a');
  Result := EVP_PKEY_is_a(pkey, name);
end;

function Load_EVP_PKEY_type_names_do_all(pkey: PEVP_PKEY; fn: TFuncType038; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_type_names_do_all := LoadLibCryptoFunction('EVP_PKEY_type_names_do_all');
  if not assigned(EVP_PKEY_type_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_type_names_do_all');
  Result := EVP_PKEY_type_names_do_all(pkey, fn, data);
end;

function Load_EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_type := LoadLibCryptoFunction('EVP_PKEY_type');
  if not assigned(EVP_PKEY_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_type');
  Result := EVP_PKEY_type(type_);
end;

function Load_EVP_PKEY_get_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_id := LoadLibCryptoFunction('EVP_PKEY_get_id');
  if not assigned(EVP_PKEY_get_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_id');
  Result := EVP_PKEY_get_id(pkey);
end;

function Load_EVP_PKEY_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_id := LoadLibCryptoFunction('EVP_PKEY_get_id');
  if not assigned(EVP_PKEY_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_id');
  Result := EVP_PKEY_id(pkey);
end;

function Load_EVP_PKEY_get_base_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_base_id := LoadLibCryptoFunction('EVP_PKEY_get_base_id');
  if not assigned(EVP_PKEY_get_base_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_base_id');
  Result := EVP_PKEY_get_base_id(pkey);
end;

function Load_EVP_PKEY_base_id(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_base_id := LoadLibCryptoFunction('EVP_PKEY_get_base_id');
  if not assigned(EVP_PKEY_base_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_base_id');
  Result := EVP_PKEY_base_id(pkey);
end;

function Load_EVP_PKEY_get_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_bits := LoadLibCryptoFunction('EVP_PKEY_get_bits');
  if not assigned(EVP_PKEY_get_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_bits');
  Result := EVP_PKEY_get_bits(pkey);
end;

function Load_EVP_PKEY_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_bits := LoadLibCryptoFunction('EVP_PKEY_get_bits');
  if not assigned(EVP_PKEY_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_bits');
  Result := EVP_PKEY_bits(pkey);
end;

function Load_EVP_PKEY_get_security_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_security_bits := LoadLibCryptoFunction('EVP_PKEY_get_security_bits');
  if not assigned(EVP_PKEY_get_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_security_bits');
  Result := EVP_PKEY_get_security_bits(pkey);
end;

function Load_EVP_PKEY_security_bits(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_security_bits := LoadLibCryptoFunction('EVP_PKEY_get_security_bits');
  if not assigned(EVP_PKEY_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_security_bits');
  Result := EVP_PKEY_security_bits(pkey);
end;

function Load_EVP_PKEY_get_security_category(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_security_category := LoadLibCryptoFunction('EVP_PKEY_get_security_category');
  if not assigned(EVP_PKEY_get_security_category) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_security_category');
  Result := EVP_PKEY_get_security_category(pkey);
end;

function Load_EVP_PKEY_get_size(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_size := LoadLibCryptoFunction('EVP_PKEY_get_size');
  if not assigned(EVP_PKEY_get_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_size');
  Result := EVP_PKEY_get_size(pkey);
end;

function Load_EVP_PKEY_size(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_size := LoadLibCryptoFunction('EVP_PKEY_get_size');
  if not assigned(EVP_PKEY_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_size');
  Result := EVP_PKEY_size(pkey);
end;

function Load_EVP_PKEY_can_sign(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_can_sign := LoadLibCryptoFunction('EVP_PKEY_can_sign');
  if not assigned(EVP_PKEY_can_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_can_sign');
  Result := EVP_PKEY_can_sign(pkey);
end;

function Load_EVP_PKEY_set_type(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_type := LoadLibCryptoFunction('EVP_PKEY_set_type');
  if not assigned(EVP_PKEY_set_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_type');
  Result := EVP_PKEY_set_type(pkey, type_);
end;

function Load_EVP_PKEY_set_type_str(pkey: PEVP_PKEY; str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_type_str := LoadLibCryptoFunction('EVP_PKEY_set_type_str');
  if not assigned(EVP_PKEY_set_type_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_type_str');
  Result := EVP_PKEY_set_type_str(pkey, str, len);
end;

function Load_EVP_PKEY_set_type_by_keymgmt(pkey: PEVP_PKEY; keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_type_by_keymgmt := LoadLibCryptoFunction('EVP_PKEY_set_type_by_keymgmt');
  if not assigned(EVP_PKEY_set_type_by_keymgmt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_type_by_keymgmt');
  Result := EVP_PKEY_set_type_by_keymgmt(pkey, keymgmt);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_ENGINE}
function Load_EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_engine := LoadLibCryptoFunction('EVP_PKEY_set1_engine');
  if not assigned(EVP_PKEY_set1_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_engine');
  Result := EVP_PKEY_set1_engine(pkey, e);
end;

function Load_EVP_PKEY_get0_engine(pkey: PEVP_PKEY): PENGINE; cdecl;
begin
  EVP_PKEY_get0_engine := LoadLibCryptoFunction('EVP_PKEY_get0_engine');
  if not assigned(EVP_PKEY_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_engine');
  Result := EVP_PKEY_get0_engine(pkey);
end;

    {$endif} { OPENSSL_NO_ENGINE}
function Load_EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_assign := LoadLibCryptoFunction('EVP_PKEY_assign');
  if not assigned(EVP_PKEY_assign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign');
  Result := EVP_PKEY_assign(pkey, type_, key);
end;

function Load_EVP_PKEY_get0(pkey: PEVP_PKEY): pointer; cdecl;
begin
  EVP_PKEY_get0 := LoadLibCryptoFunction('EVP_PKEY_get0');
  if not assigned(EVP_PKEY_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0');
  Result := EVP_PKEY_get0(pkey);
end;

function Load_EVP_PKEY_get0_hmac(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl;
begin
  EVP_PKEY_get0_hmac := LoadLibCryptoFunction('EVP_PKEY_get0_hmac');
  if not assigned(EVP_PKEY_get0_hmac) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_hmac');
  Result := EVP_PKEY_get0_hmac(pkey, len);
end;

    {$ifndef  OPENSSL_NO_POLY1305}
function Load_EVP_PKEY_get0_poly1305(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl;
begin
  EVP_PKEY_get0_poly1305 := LoadLibCryptoFunction('EVP_PKEY_get0_poly1305');
  if not assigned(EVP_PKEY_get0_poly1305) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_poly1305');
  Result := EVP_PKEY_get0_poly1305(pkey, len);
end;

    {$endif} { OPENSSL_NO_POLY1305}
    {$ifndef  OPENSSL_NO_SIPHASH}
function Load_EVP_PKEY_get0_siphash(pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): Pbyte; cdecl;
begin
  EVP_PKEY_get0_siphash := LoadLibCryptoFunction('EVP_PKEY_get0_siphash');
  if not assigned(EVP_PKEY_get0_siphash) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_siphash');
  Result := EVP_PKEY_get0_siphash(pkey, len);
end;

    {$endif} { OPENSSL_NO_SIPHASH}
function Load_EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: Prsa_st): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_RSA := LoadLibCryptoFunction('EVP_PKEY_set1_RSA');
  if not assigned(EVP_PKEY_set1_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_RSA');
  Result := EVP_PKEY_set1_RSA(pkey, key);
end;

function Load_EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): Prsa_st; cdecl;
begin
  EVP_PKEY_get0_RSA := LoadLibCryptoFunction('EVP_PKEY_get0_RSA');
  if not assigned(EVP_PKEY_get0_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_RSA');
  Result := EVP_PKEY_get0_RSA(pkey);
end;

function Load_EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): Prsa_st; cdecl;
begin
  EVP_PKEY_get1_RSA := LoadLibCryptoFunction('EVP_PKEY_get1_RSA');
  if not assigned(EVP_PKEY_get1_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_RSA');
  Result := EVP_PKEY_get1_RSA(pkey);
end;

    {$ifndef  OPENSSL_NO_DSA}
function Load_EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: Pdsa_st): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_DSA := LoadLibCryptoFunction('EVP_PKEY_set1_DSA');
  if not assigned(EVP_PKEY_set1_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_DSA');
  Result := EVP_PKEY_set1_DSA(pkey, key);
end;

function Load_EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): Pdsa_st; cdecl;
begin
  EVP_PKEY_get0_DSA := LoadLibCryptoFunction('EVP_PKEY_get0_DSA');
  if not assigned(EVP_PKEY_get0_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_DSA');
  Result := EVP_PKEY_get0_DSA(pkey);
end;

function Load_EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): Pdsa_st; cdecl;
begin
  EVP_PKEY_get1_DSA := LoadLibCryptoFunction('EVP_PKEY_get1_DSA');
  if not assigned(EVP_PKEY_get1_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_DSA');
  Result := EVP_PKEY_get1_DSA(pkey);
end;

    {$endif} { OPENSSL_NO_DSA}
    {$ifndef  OPENSSL_NO_DH}
function Load_EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: Pdh_st): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_DH := LoadLibCryptoFunction('EVP_PKEY_set1_DH');
  if not assigned(EVP_PKEY_set1_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_DH');
  Result := EVP_PKEY_set1_DH(pkey, key);
end;

function Load_EVP_PKEY_get0_DH(pkey: PEVP_PKEY): Pdh_st; cdecl;
begin
  EVP_PKEY_get0_DH := LoadLibCryptoFunction('EVP_PKEY_get0_DH');
  if not assigned(EVP_PKEY_get0_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_DH');
  Result := EVP_PKEY_get0_DH(pkey);
end;

function Load_EVP_PKEY_get1_DH(pkey: PEVP_PKEY): Pdh_st; cdecl;
begin
  EVP_PKEY_get1_DH := LoadLibCryptoFunction('EVP_PKEY_get1_DH');
  if not assigned(EVP_PKEY_get1_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_DH');
  Result := EVP_PKEY_get1_DH(pkey);
end;

    {$endif} { OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_EC}
function Load_EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: Pec_key_st): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_set1_EC_KEY');
  if not assigned(EVP_PKEY_set1_EC_KEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_EC_KEY');
  Result := EVP_PKEY_set1_EC_KEY(pkey, key);
end;

function Load_EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): Pec_key_st; cdecl;
begin
  EVP_PKEY_get0_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_get0_EC_KEY');
  if not assigned(EVP_PKEY_get0_EC_KEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_EC_KEY');
  Result := EVP_PKEY_get0_EC_KEY(pkey);
end;

function Load_EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): Pec_key_st; cdecl;
begin
  EVP_PKEY_get1_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_get1_EC_KEY');
  if not assigned(EVP_PKEY_get1_EC_KEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_EC_KEY');
  Result := EVP_PKEY_get1_EC_KEY(pkey);
end;

    {$endif} { OPENSSL_NO_EC}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_new: PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new := LoadLibCryptoFunction('EVP_PKEY_new');
  if not assigned(EVP_PKEY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new');
  Result := EVP_PKEY_new;
end;

function Load_EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_up_ref := LoadLibCryptoFunction('EVP_PKEY_up_ref');
  if not assigned(EVP_PKEY_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_up_ref');
  Result := EVP_PKEY_up_ref(pkey);
end;

function Load_EVP_PKEY_dup(pkey: PEVP_PKEY): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_dup := LoadLibCryptoFunction('EVP_PKEY_dup');
  if not assigned(EVP_PKEY_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_dup');
  Result := EVP_PKEY_dup(pkey);
end;

procedure Load_EVP_PKEY_free(pkey: PEVP_PKEY); cdecl;
begin
  EVP_PKEY_free := LoadLibCryptoFunction('EVP_PKEY_free');
  if not assigned(EVP_PKEY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_free');
  EVP_PKEY_free(pkey);
end;

function Load_EVP_PKEY_get0_description(pkey: PEVP_PKEY): PAnsiChar; cdecl;
begin
  EVP_PKEY_get0_description := LoadLibCryptoFunction('EVP_PKEY_get0_description');
  if not assigned(EVP_PKEY_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_description');
  Result := EVP_PKEY_get0_description(pkey);
end;

function Load_EVP_PKEY_get0_provider(key: PEVP_PKEY): POSSL_PROVIDER; cdecl;
begin
  EVP_PKEY_get0_provider := LoadLibCryptoFunction('EVP_PKEY_get0_provider');
  if not assigned(EVP_PKEY_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_provider');
  Result := EVP_PKEY_get0_provider(key);
end;

function Load_d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  d2i_PublicKey := LoadLibCryptoFunction('d2i_PublicKey');
  if not assigned(d2i_PublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PublicKey');
  Result := d2i_PublicKey(type_, a, pp, length);
end;

function Load_i2d_PublicKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PublicKey := LoadLibCryptoFunction('i2d_PublicKey');
  if not assigned(i2d_PublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PublicKey');
  Result := i2d_PublicKey(a, pp);
end;

function Load_d2i_PrivateKey_ex(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  d2i_PrivateKey_ex := LoadLibCryptoFunction('d2i_PrivateKey_ex');
  if not assigned(d2i_PrivateKey_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PrivateKey_ex');
  Result := d2i_PrivateKey_ex(type_, a, pp, length, libctx, propq);
end;

function Load_d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  d2i_PrivateKey := LoadLibCryptoFunction('d2i_PrivateKey');
  if not assigned(d2i_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PrivateKey');
  Result := d2i_PrivateKey(type_, a, pp, length);
end;

function Load_d2i_AutoPrivateKey_ex(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): PEVP_PKEY; cdecl;
begin
  d2i_AutoPrivateKey_ex := LoadLibCryptoFunction('d2i_AutoPrivateKey_ex');
  if not assigned(d2i_AutoPrivateKey_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_AutoPrivateKey_ex');
  Result := d2i_AutoPrivateKey_ex(a, pp, length, libctx, propq);
end;

function Load_d2i_AutoPrivateKey(a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  d2i_AutoPrivateKey := LoadLibCryptoFunction('d2i_AutoPrivateKey');
  if not assigned(d2i_AutoPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_AutoPrivateKey');
  Result := d2i_AutoPrivateKey(a, pp, length);
end;

function Load_i2d_PrivateKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PrivateKey := LoadLibCryptoFunction('i2d_PrivateKey');
  if not assigned(i2d_PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PrivateKey');
  Result := i2d_PrivateKey(a, pp);
end;

function Load_i2d_PKCS8PrivateKey(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_PKCS8PrivateKey := LoadLibCryptoFunction('i2d_PKCS8PrivateKey');
  if not assigned(i2d_PKCS8PrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PKCS8PrivateKey');
  Result := i2d_PKCS8PrivateKey(a, pp);
end;

function Load_i2d_KeyParams(a: PEVP_PKEY; pp: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_KeyParams := LoadLibCryptoFunction('i2d_KeyParams');
  if not assigned(i2d_KeyParams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_KeyParams');
  Result := i2d_KeyParams(a, pp);
end;

function Load_d2i_KeyParams(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; pp: PPbyte; length: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  d2i_KeyParams := LoadLibCryptoFunction('d2i_KeyParams');
  if not assigned(d2i_KeyParams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_KeyParams');
  Result := d2i_KeyParams(type_, a, pp, length);
end;

function Load_i2d_KeyParams_bio(bp: PBIO; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  i2d_KeyParams_bio := LoadLibCryptoFunction('i2d_KeyParams_bio');
  if not assigned(i2d_KeyParams_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_KeyParams_bio');
  Result := i2d_KeyParams_bio(bp, pkey);
end;

function Load_d2i_KeyParams_bio(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; in_: PBIO): PEVP_PKEY; cdecl;
begin
  d2i_KeyParams_bio := LoadLibCryptoFunction('d2i_KeyParams_bio');
  if not assigned(d2i_KeyParams_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_KeyParams_bio');
  Result := d2i_KeyParams_bio(type_, a, in_);
end;

function Load_EVP_PKEY_copy_parameters(to_: PEVP_PKEY; from_: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_copy_parameters := LoadLibCryptoFunction('EVP_PKEY_copy_parameters');
  if not assigned(EVP_PKEY_copy_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_copy_parameters');
  Result := EVP_PKEY_copy_parameters(to_, from_);
end;

function Load_EVP_PKEY_missing_parameters(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_missing_parameters := LoadLibCryptoFunction('EVP_PKEY_missing_parameters');
  if not assigned(EVP_PKEY_missing_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_missing_parameters');
  Result := EVP_PKEY_missing_parameters(pkey);
end;

function Load_EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_save_parameters := LoadLibCryptoFunction('EVP_PKEY_save_parameters');
  if not assigned(EVP_PKEY_save_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_save_parameters');
  Result := EVP_PKEY_save_parameters(pkey, mode);
end;

function Load_EVP_PKEY_parameters_eq(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_parameters_eq := LoadLibCryptoFunction('EVP_PKEY_parameters_eq');
  if not assigned(EVP_PKEY_parameters_eq) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_parameters_eq');
  Result := EVP_PKEY_parameters_eq(a, b);
end;

function Load_EVP_PKEY_eq(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_eq := LoadLibCryptoFunction('EVP_PKEY_eq');
  if not assigned(EVP_PKEY_eq) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_eq');
  Result := EVP_PKEY_eq(a, b);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_cmp_parameters(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_cmp_parameters := LoadLibCryptoFunction('EVP_PKEY_cmp_parameters');
  if not assigned(EVP_PKEY_cmp_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_cmp_parameters');
  Result := EVP_PKEY_cmp_parameters(a, b);
end;

function Load_EVP_PKEY_cmp(a: PEVP_PKEY; b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_cmp := LoadLibCryptoFunction('EVP_PKEY_cmp');
  if not assigned(EVP_PKEY_cmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_cmp');
  Result := EVP_PKEY_cmp(a, b);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_print_public(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_public := LoadLibCryptoFunction('EVP_PKEY_print_public');
  if not assigned(EVP_PKEY_print_public) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_public');
  Result := EVP_PKEY_print_public(out_, pkey, indent, pctx);
end;

function Load_EVP_PKEY_print_private(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_private := LoadLibCryptoFunction('EVP_PKEY_print_private');
  if not assigned(EVP_PKEY_print_private) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_private');
  Result := EVP_PKEY_print_private(out_, pkey, indent, pctx);
end;

function Load_EVP_PKEY_print_params(out_: PBIO; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_params := LoadLibCryptoFunction('EVP_PKEY_print_params');
  if not assigned(EVP_PKEY_print_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_params');
  Result := EVP_PKEY_print_params(out_, pkey, indent, pctx);
end;

{$ifndef  OPENSSL_NO_STDIO}
function Load_EVP_PKEY_print_public_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_public_fp := LoadLibCryptoFunction('EVP_PKEY_print_public_fp');
  if not assigned(EVP_PKEY_print_public_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_public_fp');
  Result := EVP_PKEY_print_public_fp(fp, pkey, indent, pctx);
end;

function Load_EVP_PKEY_print_private_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_private_fp := LoadLibCryptoFunction('EVP_PKEY_print_private_fp');
  if not assigned(EVP_PKEY_print_private_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_private_fp');
  Result := EVP_PKEY_print_private_fp(fp, pkey, indent, pctx);
end;

function Load_EVP_PKEY_print_params_fp(fp: PFILE; pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_print_params_fp := LoadLibCryptoFunction('EVP_PKEY_print_params_fp');
  if not assigned(EVP_PKEY_print_params_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_params_fp');
  Result := EVP_PKEY_print_params_fp(fp, pkey, indent, pctx);
end;

{$endif} { OPENSSL_NO_STDIO}
function Load_EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_default_digest_nid := LoadLibCryptoFunction('EVP_PKEY_get_default_digest_nid');
  if not assigned(EVP_PKEY_get_default_digest_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_default_digest_nid');
  Result := EVP_PKEY_get_default_digest_nid(pkey, pnid);
end;

function Load_EVP_PKEY_get_default_digest_name(pkey: PEVP_PKEY; mdname: PAnsiChar; mdname_sz: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_default_digest_name := LoadLibCryptoFunction('EVP_PKEY_get_default_digest_name');
  if not assigned(EVP_PKEY_get_default_digest_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_default_digest_name');
  Result := EVP_PKEY_get_default_digest_name(pkey, mdname, mdname_sz);
end;

function Load_EVP_PKEY_digestsign_supports_digest(pkey: PEVP_PKEY; libctx: POSSL_LIB_CTX; name: PAnsiChar; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_digestsign_supports_digest := LoadLibCryptoFunction('EVP_PKEY_digestsign_supports_digest');
  if not assigned(EVP_PKEY_digestsign_supports_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_digestsign_supports_digest');
  Result := EVP_PKEY_digestsign_supports_digest(pkey, libctx, name, propq);
end;

function Load_EVP_PKEY_set1_encoded_public_key(pkey: PEVP_PKEY; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set1_encoded_public_key := LoadLibCryptoFunction('EVP_PKEY_set1_encoded_public_key');
  if not assigned(EVP_PKEY_set1_encoded_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_encoded_public_key');
  Result := EVP_PKEY_set1_encoded_public_key(pkey, pub, publen);
end;

function Load_EVP_PKEY_get1_encoded_public_key(pkey: PEVP_PKEY; ppub: PPbyte): TOpenSSL_C_SIZET; cdecl;
begin
  EVP_PKEY_get1_encoded_public_key := LoadLibCryptoFunction('EVP_PKEY_get1_encoded_public_key');
  if not assigned(EVP_PKEY_get1_encoded_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_encoded_public_key');
  Result := EVP_PKEY_get1_encoded_public_key(pkey, ppub);
end;

function Load_EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_param_to_asn1 := LoadLibCryptoFunction('EVP_CIPHER_param_to_asn1');
  if not assigned(EVP_CIPHER_param_to_asn1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_param_to_asn1');
  Result := EVP_CIPHER_param_to_asn1(c, type_);
end;

function Load_EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_asn1_to_param := LoadLibCryptoFunction('EVP_CIPHER_asn1_to_param');
  if not assigned(EVP_CIPHER_asn1_to_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_asn1_to_param');
  Result := EVP_CIPHER_asn1_to_param(c, type_);
end;

function Load_EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_set_asn1_iv := LoadLibCryptoFunction('EVP_CIPHER_set_asn1_iv');
  if not assigned(EVP_CIPHER_set_asn1_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_set_asn1_iv');
  Result := EVP_CIPHER_set_asn1_iv(c, type_);
end;

function Load_EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EVP_CIPHER_get_asn1_iv := LoadLibCryptoFunction('EVP_CIPHER_get_asn1_iv');
  if not assigned(EVP_CIPHER_get_asn1_iv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_asn1_iv');
  Result := EVP_CIPHER_get_asn1_iv(c, type_);
end;

function Load_PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_PBE_keyivgen := LoadLibCryptoFunction('PKCS5_PBE_keyivgen');
  if not assigned(PKCS5_PBE_keyivgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBE_keyivgen');
  Result := PKCS5_PBE_keyivgen(ctx, pass, passlen, param, cipher, md, en_de);
end;

function Load_PKCS5_PBE_keyivgen_ex(cctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_PBE_keyivgen_ex := LoadLibCryptoFunction('PKCS5_PBE_keyivgen_ex');
  if not assigned(PKCS5_PBE_keyivgen_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBE_keyivgen_ex');
  Result := PKCS5_PBE_keyivgen_ex(cctx, pass, passlen, param, cipher, md, en_de, libctx, propq);
end;

function Load_PKCS5_PBKDF2_HMAC_SHA1(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_PBKDF2_HMAC_SHA1 := LoadLibCryptoFunction('PKCS5_PBKDF2_HMAC_SHA1');
  if not assigned(PKCS5_PBKDF2_HMAC_SHA1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBKDF2_HMAC_SHA1');
  Result := PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, salt, saltlen, iter, keylen, out_);
end;

function Load_PKCS5_PBKDF2_HMAC(pass: PAnsiChar; passlen: TOpenSSL_C_INT; salt: Pbyte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_PBKDF2_HMAC := LoadLibCryptoFunction('PKCS5_PBKDF2_HMAC');
  if not assigned(PKCS5_PBKDF2_HMAC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBKDF2_HMAC');
  Result := PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out_);
end;

function Load_PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_v2_PBE_keyivgen := LoadLibCryptoFunction('PKCS5_v2_PBE_keyivgen');
  if not assigned(PKCS5_v2_PBE_keyivgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_PBE_keyivgen');
  Result := PKCS5_v2_PBE_keyivgen(ctx, pass, passlen, param, cipher, md, en_de);
end;

function Load_PKCS5_v2_PBE_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; cipher: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_v2_PBE_keyivgen_ex := LoadLibCryptoFunction('PKCS5_v2_PBE_keyivgen_ex');
  if not assigned(PKCS5_v2_PBE_keyivgen_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_PBE_keyivgen_ex');
  Result := PKCS5_v2_PBE_keyivgen_ex(ctx, pass, passlen, param, cipher, md, en_de, libctx, propq);
end;

{$ifndef  OPENSSL_NO_SCRYPT}
function Load_EVP_PBE_scrypt(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_scrypt := LoadLibCryptoFunction('EVP_PBE_scrypt');
  if not assigned(EVP_PBE_scrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_scrypt');
  Result := EVP_PBE_scrypt(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen);
end;

function Load_EVP_PBE_scrypt_ex(pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; salt: Pbyte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: Pbyte; keylen: TOpenSSL_C_SIZET; ctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_scrypt_ex := LoadLibCryptoFunction('EVP_PBE_scrypt_ex');
  if not assigned(EVP_PBE_scrypt_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_scrypt_ex');
  Result := EVP_PBE_scrypt_ex(pass, passlen, salt, saltlen, N, r, p, maxmem, key, keylen, ctx, propq);
end;

function Load_PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_v2_scrypt_keyivgen := LoadLibCryptoFunction('PKCS5_v2_scrypt_keyivgen');
  if not assigned(PKCS5_v2_scrypt_keyivgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_scrypt_keyivgen');
  Result := PKCS5_v2_scrypt_keyivgen(ctx, pass, passlen, param, c, md, en_de);
end;

function Load_PKCS5_v2_scrypt_keyivgen_ex(ctx: PEVP_CIPHER_CTX; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; c: PEVP_CIPHER; md: PEVP_MD; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  PKCS5_v2_scrypt_keyivgen_ex := LoadLibCryptoFunction('PKCS5_v2_scrypt_keyivgen_ex');
  if not assigned(PKCS5_v2_scrypt_keyivgen_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_scrypt_keyivgen_ex');
  Result := PKCS5_v2_scrypt_keyivgen_ex(ctx, pass, passlen, param, c, md, en_de, libctx, propq);
end;

{$endif} { OPENSSL_NO_SCRYPT}
procedure Load_PKCS5_PBE_add; cdecl;
begin
  PKCS5_PBE_add := LoadLibCryptoFunction('PKCS5_PBE_add');
  if not assigned(PKCS5_PBE_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBE_add');
  PKCS5_PBE_add;
end;

function Load_EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_CipherInit := LoadLibCryptoFunction('EVP_PBE_CipherInit');
  if not assigned(EVP_PBE_CipherInit) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_CipherInit');
  Result := EVP_PBE_CipherInit(pbe_obj, pass, passlen, param, ctx, en_de);
end;

function Load_EVP_PBE_CipherInit_ex(pbe_obj: PASN1_OBJECT; pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_CipherInit_ex := LoadLibCryptoFunction('EVP_PBE_CipherInit_ex');
  if not assigned(EVP_PBE_CipherInit_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_CipherInit_ex');
  Result := EVP_PBE_CipherInit_ex(pbe_obj, pass, passlen, param, ctx, en_de, libctx, propq);
end;

function Load_EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_alg_add_type := LoadLibCryptoFunction('EVP_PBE_alg_add_type');
  if not assigned(EVP_PBE_alg_add_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_alg_add_type');
  Result := EVP_PBE_alg_add_type(pbe_type, pbe_nid, cipher_nid, md_nid, keygen);
end;

function Load_EVP_PBE_alg_add(nid: TOpenSSL_C_INT; cipher: PEVP_CIPHER; md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_alg_add := LoadLibCryptoFunction('EVP_PBE_alg_add');
  if not assigned(EVP_PBE_alg_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_alg_add');
  Result := EVP_PBE_alg_add(nid, cipher, md, keygen);
end;

function Load_EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_find := LoadLibCryptoFunction('EVP_PBE_find');
  if not assigned(EVP_PBE_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_find');
  Result := EVP_PBE_find(type_, pbe_nid, pcnid, pmnid, pkeygen);
end;

function Load_EVP_PBE_find_ex(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN; pkeygen_ex: PPEVP_PBE_KEYGEN_EX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_find_ex := LoadLibCryptoFunction('EVP_PBE_find_ex');
  if not assigned(EVP_PBE_find_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_find_ex');
  Result := EVP_PBE_find_ex(type_, pbe_nid, pcnid, pmnid, pkeygen, pkeygen_ex);
end;

procedure Load_EVP_PBE_cleanup; cdecl;
begin
  EVP_PBE_cleanup := LoadLibCryptoFunction('EVP_PBE_cleanup');
  if not assigned(EVP_PBE_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_cleanup');
  EVP_PBE_cleanup;
end;

function Load_EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PBE_get := LoadLibCryptoFunction('EVP_PBE_get');
  if not assigned(EVP_PBE_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_get');
  Result := EVP_PBE_get(ptype, ppbe_nid, num);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_6}
function Load_EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_get_count := LoadLibCryptoFunction('EVP_PKEY_asn1_get_count');
  if not assigned(EVP_PKEY_asn1_get_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get_count');
  Result := EVP_PKEY_asn1_get_count;
end;

function Load_EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_get0 := LoadLibCryptoFunction('EVP_PKEY_asn1_get0');
  if not assigned(EVP_PKEY_asn1_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get0');
  Result := EVP_PKEY_asn1_get0(idx);
end;

function Load_EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_find := LoadLibCryptoFunction('EVP_PKEY_asn1_find');
  if not assigned(EVP_PKEY_asn1_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_find');
  Result := EVP_PKEY_asn1_find(pe, type_);
end;

function Load_EVP_PKEY_asn1_find_str(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_find_str := LoadLibCryptoFunction('EVP_PKEY_asn1_find_str');
  if not assigned(EVP_PKEY_asn1_find_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_find_str');
  Result := EVP_PKEY_asn1_find_str(pe, str, len);
end;

function Load_EVP_PKEY_asn1_add0(ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_add0 := LoadLibCryptoFunction('EVP_PKEY_asn1_add0');
  if not assigned(EVP_PKEY_asn1_add0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_add0');
  Result := EVP_PKEY_asn1_add0(ameth);
end;

function Load_EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_add_alias := LoadLibCryptoFunction('EVP_PKEY_asn1_add_alias');
  if not assigned(EVP_PKEY_asn1_add_alias) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_add_alias');
  Result := EVP_PKEY_asn1_add_alias(to_, from_);
end;

function Load_EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; pinfo: PPAnsiChar; ppem_str: PPAnsiChar; ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_asn1_get0_info := LoadLibCryptoFunction('EVP_PKEY_asn1_get0_info');
  if not assigned(EVP_PKEY_asn1_get0_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get0_info');
  Result := EVP_PKEY_asn1_get0_info(ppkey_id, pkey_base_id, ppkey_flags, pinfo, ppem_str, ameth);
end;

function Load_EVP_PKEY_get0_asn1(pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_get0_asn1 := LoadLibCryptoFunction('EVP_PKEY_get0_asn1');
  if not assigned(EVP_PKEY_get0_asn1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_asn1');
  Result := EVP_PKEY_get0_asn1(pkey);
end;

function Load_EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; pem_str: PAnsiChar; info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EVP_PKEY_asn1_new := LoadLibCryptoFunction('EVP_PKEY_asn1_new');
  if not assigned(EVP_PKEY_asn1_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_new');
  Result := EVP_PKEY_asn1_new(id, flags, pem_str, info);
end;

procedure Load_EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; src: PEVP_PKEY_ASN1_METHOD); cdecl;
begin
  EVP_PKEY_asn1_copy := LoadLibCryptoFunction('EVP_PKEY_asn1_copy');
  if not assigned(EVP_PKEY_asn1_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_copy');
  EVP_PKEY_asn1_copy(dst, src);
end;

procedure Load_EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl;
begin
  EVP_PKEY_asn1_free := LoadLibCryptoFunction('EVP_PKEY_asn1_free');
  if not assigned(EVP_PKEY_asn1_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_free');
  EVP_PKEY_asn1_free(ameth);
end;

procedure Load_EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; pub_decode: TFuncType039; pub_encode: TFuncType040; pub_cmp: TFuncType041; pub_print: TFuncType042; pkey_size: TFuncType043; pkey_bits: TFuncType044); cdecl;
begin
  EVP_PKEY_asn1_set_public := LoadLibCryptoFunction('EVP_PKEY_asn1_set_public');
  if not assigned(EVP_PKEY_asn1_set_public) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_public');
  EVP_PKEY_asn1_set_public(ameth, pub_decode, pub_encode, pub_cmp, pub_print, pkey_size, pkey_bits);
end;

procedure Load_EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; priv_decode: TFuncType045; priv_encode: TFuncType046; priv_print: TFuncType047); cdecl;
begin
  EVP_PKEY_asn1_set_private := LoadLibCryptoFunction('EVP_PKEY_asn1_set_private');
  if not assigned(EVP_PKEY_asn1_set_private) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_private');
  EVP_PKEY_asn1_set_private(ameth, priv_decode, priv_encode, priv_print);
end;

procedure Load_EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; param_decode: TFuncType048; param_encode: TFuncType049; param_missing: TFuncType050; param_copy: TFuncType051; param_cmp: TFuncType052; param_print: TFuncType053); cdecl;
begin
  EVP_PKEY_asn1_set_param := LoadLibCryptoFunction('EVP_PKEY_asn1_set_param');
  if not assigned(EVP_PKEY_asn1_set_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_param');
  EVP_PKEY_asn1_set_param(ameth, param_decode, param_encode, param_missing, param_copy, param_cmp, param_print);
end;

procedure Load_EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; pkey_free: TFuncType054); cdecl;
begin
  EVP_PKEY_asn1_set_free := LoadLibCryptoFunction('EVP_PKEY_asn1_set_free');
  if not assigned(EVP_PKEY_asn1_set_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_free');
  EVP_PKEY_asn1_set_free(ameth, pkey_free);
end;

procedure Load_EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; pkey_ctrl: TFuncType055); cdecl;
begin
  EVP_PKEY_asn1_set_ctrl := LoadLibCryptoFunction('EVP_PKEY_asn1_set_ctrl');
  if not assigned(EVP_PKEY_asn1_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_ctrl');
  EVP_PKEY_asn1_set_ctrl(ameth, pkey_ctrl);
end;

procedure Load_EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; item_verify: TFuncType056; item_sign: TFuncType057); cdecl;
begin
  EVP_PKEY_asn1_set_item := LoadLibCryptoFunction('EVP_PKEY_asn1_set_item');
  if not assigned(EVP_PKEY_asn1_set_item) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_item');
  EVP_PKEY_asn1_set_item(ameth, item_verify, item_sign);
end;

procedure Load_EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; siginf_set: TFuncType058); cdecl;
begin
  EVP_PKEY_asn1_set_siginf := LoadLibCryptoFunction('EVP_PKEY_asn1_set_siginf');
  if not assigned(EVP_PKEY_asn1_set_siginf) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_siginf');
  EVP_PKEY_asn1_set_siginf(ameth, siginf_set);
end;

procedure Load_EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_check: TFuncType059); cdecl;
begin
  EVP_PKEY_asn1_set_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_check');
  if not assigned(EVP_PKEY_asn1_set_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_check');
  EVP_PKEY_asn1_set_check(ameth, pkey_check);
end;

procedure Load_EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_pub_check: TFuncType060); cdecl;
begin
  EVP_PKEY_asn1_set_public_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_public_check');
  if not assigned(EVP_PKEY_asn1_set_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_public_check');
  EVP_PKEY_asn1_set_public_check(ameth, pkey_pub_check);
end;

procedure Load_EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; pkey_param_check: TFuncType061); cdecl;
begin
  EVP_PKEY_asn1_set_param_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_param_check');
  if not assigned(EVP_PKEY_asn1_set_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_param_check');
  EVP_PKEY_asn1_set_param_check(ameth, pkey_param_check);
end;

procedure Load_EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; set_priv_key: TFuncType062); cdecl;
begin
  EVP_PKEY_asn1_set_set_priv_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_set_priv_key');
  if not assigned(EVP_PKEY_asn1_set_set_priv_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_set_priv_key');
  EVP_PKEY_asn1_set_set_priv_key(ameth, set_priv_key);
end;

procedure Load_EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; set_pub_key: TFuncType063); cdecl;
begin
  EVP_PKEY_asn1_set_set_pub_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_set_pub_key');
  if not assigned(EVP_PKEY_asn1_set_set_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_set_pub_key');
  EVP_PKEY_asn1_set_set_pub_key(ameth, set_pub_key);
end;

procedure Load_EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; get_priv_key: TFuncType064); cdecl;
begin
  EVP_PKEY_asn1_set_get_priv_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_get_priv_key');
  if not assigned(EVP_PKEY_asn1_set_get_priv_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_get_priv_key');
  EVP_PKEY_asn1_set_get_priv_key(ameth, get_priv_key);
end;

procedure Load_EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; get_pub_key: TFuncType065); cdecl;
begin
  EVP_PKEY_asn1_set_get_pub_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_get_pub_key');
  if not assigned(EVP_PKEY_asn1_set_get_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_get_pub_key');
  EVP_PKEY_asn1_set_get_pub_key(ameth, get_pub_key);
end;

procedure Load_EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; pkey_security_bits: TFuncType066); cdecl;
begin
  EVP_PKEY_asn1_set_security_bits := LoadLibCryptoFunction('EVP_PKEY_asn1_set_security_bits');
  if not assigned(EVP_PKEY_asn1_set_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_security_bits');
  EVP_PKEY_asn1_set_security_bits(ameth, pkey_security_bits);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_6}
function Load_EVP_PKEY_CTX_get_signature_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_signature_md := LoadLibCryptoFunction('EVP_PKEY_CTX_get_signature_md');
  if not assigned(EVP_PKEY_CTX_get_signature_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_signature_md');
  Result := EVP_PKEY_CTX_get_signature_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set_signature_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_signature_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_signature_md');
  if not assigned(EVP_PKEY_CTX_set_signature_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_signature_md');
  Result := EVP_PKEY_CTX_set_signature_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set1_id(ctx: PEVP_PKEY_CTX; id: pointer; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set1_id := LoadLibCryptoFunction('EVP_PKEY_CTX_set1_id');
  if not assigned(EVP_PKEY_CTX_set1_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set1_id');
  Result := EVP_PKEY_CTX_set1_id(ctx, id, len);
end;

function Load_EVP_PKEY_CTX_get1_id(ctx: PEVP_PKEY_CTX; id: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get1_id := LoadLibCryptoFunction('EVP_PKEY_CTX_get1_id');
  if not assigned(EVP_PKEY_CTX_get1_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get1_id');
  Result := EVP_PKEY_CTX_get1_id(ctx, id);
end;

function Load_EVP_PKEY_CTX_get1_id_len(ctx: PEVP_PKEY_CTX; id_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get1_id_len := LoadLibCryptoFunction('EVP_PKEY_CTX_get1_id_len');
  if not assigned(EVP_PKEY_CTX_get1_id_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get1_id_len');
  Result := EVP_PKEY_CTX_get1_id_len(ctx, id_len);
end;

function Load_EVP_PKEY_CTX_set_kem_op(ctx: PEVP_PKEY_CTX; op: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_kem_op := LoadLibCryptoFunction('EVP_PKEY_CTX_set_kem_op');
  if not assigned(EVP_PKEY_CTX_set_kem_op) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_kem_op');
  Result := EVP_PKEY_CTX_set_kem_op(ctx, op);
end;

function Load_EVP_PKEY_get0_type_name(key: PEVP_PKEY): PAnsiChar; cdecl;
begin
  EVP_PKEY_get0_type_name := LoadLibCryptoFunction('EVP_PKEY_get0_type_name');
  if not assigned(EVP_PKEY_get0_type_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_type_name');
  Result := EVP_PKEY_get0_type_name(key);
end;

function Load_EVP_PKEY_CTX_set_mac_key(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_mac_key := LoadLibCryptoFunction('EVP_PKEY_CTX_set_mac_key');
  if not assigned(EVP_PKEY_CTX_set_mac_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_mac_key');
  Result := EVP_PKEY_CTX_set_mac_key(ctx, key, keylen);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  EVP_PKEY_meth_find := LoadLibCryptoFunction('EVP_PKEY_meth_find');
  if not assigned(EVP_PKEY_meth_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_find');
  Result := EVP_PKEY_meth_find(type_);
end;

function Load_EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  EVP_PKEY_meth_new := LoadLibCryptoFunction('EVP_PKEY_meth_new');
  if not assigned(EVP_PKEY_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_new');
  Result := EVP_PKEY_meth_new(id, flags);
end;

procedure Load_EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; meth: PEVP_PKEY_METHOD); cdecl;
begin
  EVP_PKEY_meth_get0_info := LoadLibCryptoFunction('EVP_PKEY_meth_get0_info');
  if not assigned(EVP_PKEY_meth_get0_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get0_info');
  EVP_PKEY_meth_get0_info(ppkey_id, pflags, meth);
end;

procedure Load_EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; src: PEVP_PKEY_METHOD); cdecl;
begin
  EVP_PKEY_meth_copy := LoadLibCryptoFunction('EVP_PKEY_meth_copy');
  if not assigned(EVP_PKEY_meth_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_copy');
  EVP_PKEY_meth_copy(dst, src);
end;

procedure Load_EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl;
begin
  EVP_PKEY_meth_free := LoadLibCryptoFunction('EVP_PKEY_meth_free');
  if not assigned(EVP_PKEY_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_free');
  EVP_PKEY_meth_free(pmeth);
end;

function Load_EVP_PKEY_meth_add0(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_meth_add0 := LoadLibCryptoFunction('EVP_PKEY_meth_add0');
  if not assigned(EVP_PKEY_meth_add0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_add0');
  Result := EVP_PKEY_meth_add0(pmeth);
end;

function Load_EVP_PKEY_meth_remove(pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_meth_remove := LoadLibCryptoFunction('EVP_PKEY_meth_remove');
  if not assigned(EVP_PKEY_meth_remove) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_remove');
  Result := EVP_PKEY_meth_remove(pmeth);
end;

function Load_EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl;
begin
  EVP_PKEY_meth_get_count := LoadLibCryptoFunction('EVP_PKEY_meth_get_count');
  if not assigned(EVP_PKEY_meth_get_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_count');
  Result := EVP_PKEY_meth_get_count;
end;

function Load_EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl;
begin
  EVP_PKEY_meth_get0 := LoadLibCryptoFunction('EVP_PKEY_meth_get0');
  if not assigned(EVP_PKEY_meth_get0) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get0');
  Result := EVP_PKEY_meth_get0(idx);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_KEYMGMT_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYMGMT; cdecl;
begin
  EVP_KEYMGMT_fetch := LoadLibCryptoFunction('EVP_KEYMGMT_fetch');
  if not assigned(EVP_KEYMGMT_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_fetch');
  Result := EVP_KEYMGMT_fetch(ctx, algorithm, properties);
end;

function Load_EVP_KEYMGMT_up_ref(keymgmt: PEVP_KEYMGMT): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEYMGMT_up_ref := LoadLibCryptoFunction('EVP_KEYMGMT_up_ref');
  if not assigned(EVP_KEYMGMT_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_up_ref');
  Result := EVP_KEYMGMT_up_ref(keymgmt);
end;

procedure Load_EVP_KEYMGMT_free(keymgmt: PEVP_KEYMGMT); cdecl;
begin
  EVP_KEYMGMT_free := LoadLibCryptoFunction('EVP_KEYMGMT_free');
  if not assigned(EVP_KEYMGMT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_free');
  EVP_KEYMGMT_free(keymgmt);
end;

function Load_EVP_KEYMGMT_get0_provider(keymgmt: PEVP_KEYMGMT): POSSL_PROVIDER; cdecl;
begin
  EVP_KEYMGMT_get0_provider := LoadLibCryptoFunction('EVP_KEYMGMT_get0_provider');
  if not assigned(EVP_KEYMGMT_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_get0_provider');
  Result := EVP_KEYMGMT_get0_provider(keymgmt);
end;

function Load_EVP_KEYMGMT_get0_name(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl;
begin
  EVP_KEYMGMT_get0_name := LoadLibCryptoFunction('EVP_KEYMGMT_get0_name');
  if not assigned(EVP_KEYMGMT_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_get0_name');
  Result := EVP_KEYMGMT_get0_name(keymgmt);
end;

function Load_EVP_KEYMGMT_get0_description(keymgmt: PEVP_KEYMGMT): PAnsiChar; cdecl;
begin
  EVP_KEYMGMT_get0_description := LoadLibCryptoFunction('EVP_KEYMGMT_get0_description');
  if not assigned(EVP_KEYMGMT_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_get0_description');
  Result := EVP_KEYMGMT_get0_description(keymgmt);
end;

function Load_EVP_KEYMGMT_is_a(keymgmt: PEVP_KEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEYMGMT_is_a := LoadLibCryptoFunction('EVP_KEYMGMT_is_a');
  if not assigned(EVP_KEYMGMT_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_is_a');
  Result := EVP_KEYMGMT_is_a(keymgmt, name);
end;

procedure Load_EVP_KEYMGMT_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType067; arg: pointer); cdecl;
begin
  EVP_KEYMGMT_do_all_provided := LoadLibCryptoFunction('EVP_KEYMGMT_do_all_provided');
  if not assigned(EVP_KEYMGMT_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_do_all_provided');
  EVP_KEYMGMT_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_KEYMGMT_names_do_all(keymgmt: PEVP_KEYMGMT; fn: TFuncType068; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEYMGMT_names_do_all := LoadLibCryptoFunction('EVP_KEYMGMT_names_do_all');
  if not assigned(EVP_KEYMGMT_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_names_do_all');
  Result := EVP_KEYMGMT_names_do_all(keymgmt, fn, data);
end;

function Load_EVP_KEYMGMT_gettable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
begin
  EVP_KEYMGMT_gettable_params := LoadLibCryptoFunction('EVP_KEYMGMT_gettable_params');
  if not assigned(EVP_KEYMGMT_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_gettable_params');
  Result := EVP_KEYMGMT_gettable_params(keymgmt);
end;

function Load_EVP_KEYMGMT_settable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
begin
  EVP_KEYMGMT_settable_params := LoadLibCryptoFunction('EVP_KEYMGMT_settable_params');
  if not assigned(EVP_KEYMGMT_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_settable_params');
  Result := EVP_KEYMGMT_settable_params(keymgmt);
end;

function Load_EVP_KEYMGMT_gen_settable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
begin
  EVP_KEYMGMT_gen_settable_params := LoadLibCryptoFunction('EVP_KEYMGMT_gen_settable_params');
  if not assigned(EVP_KEYMGMT_gen_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_gen_settable_params');
  Result := EVP_KEYMGMT_gen_settable_params(keymgmt);
end;

function Load_EVP_KEYMGMT_gen_gettable_params(keymgmt: PEVP_KEYMGMT): POSSL_PARAM; cdecl;
begin
  EVP_KEYMGMT_gen_gettable_params := LoadLibCryptoFunction('EVP_KEYMGMT_gen_gettable_params');
  if not assigned(EVP_KEYMGMT_gen_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYMGMT_gen_gettable_params');
  Result := EVP_KEYMGMT_gen_gettable_params(keymgmt);
end;

function Load_EVP_SKEYMGMT_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SKEYMGMT; cdecl;
begin
  EVP_SKEYMGMT_fetch := LoadLibCryptoFunction('EVP_SKEYMGMT_fetch');
  if not assigned(EVP_SKEYMGMT_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_fetch');
  Result := EVP_SKEYMGMT_fetch(ctx, algorithm, properties);
end;

function Load_EVP_SKEYMGMT_up_ref(keymgmt: PEVP_SKEYMGMT): TOpenSSL_C_INT; cdecl;
begin
  EVP_SKEYMGMT_up_ref := LoadLibCryptoFunction('EVP_SKEYMGMT_up_ref');
  if not assigned(EVP_SKEYMGMT_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_up_ref');
  Result := EVP_SKEYMGMT_up_ref(keymgmt);
end;

procedure Load_EVP_SKEYMGMT_free(keymgmt: PEVP_SKEYMGMT); cdecl;
begin
  EVP_SKEYMGMT_free := LoadLibCryptoFunction('EVP_SKEYMGMT_free');
  if not assigned(EVP_SKEYMGMT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_free');
  EVP_SKEYMGMT_free(keymgmt);
end;

function Load_EVP_SKEYMGMT_get0_provider(keymgmt: PEVP_SKEYMGMT): POSSL_PROVIDER; cdecl;
begin
  EVP_SKEYMGMT_get0_provider := LoadLibCryptoFunction('EVP_SKEYMGMT_get0_provider');
  if not assigned(EVP_SKEYMGMT_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_get0_provider');
  Result := EVP_SKEYMGMT_get0_provider(keymgmt);
end;

function Load_EVP_SKEYMGMT_get0_name(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl;
begin
  EVP_SKEYMGMT_get0_name := LoadLibCryptoFunction('EVP_SKEYMGMT_get0_name');
  if not assigned(EVP_SKEYMGMT_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_get0_name');
  Result := EVP_SKEYMGMT_get0_name(keymgmt);
end;

function Load_EVP_SKEYMGMT_get0_description(keymgmt: PEVP_SKEYMGMT): PAnsiChar; cdecl;
begin
  EVP_SKEYMGMT_get0_description := LoadLibCryptoFunction('EVP_SKEYMGMT_get0_description');
  if not assigned(EVP_SKEYMGMT_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_get0_description');
  Result := EVP_SKEYMGMT_get0_description(keymgmt);
end;

function Load_EVP_SKEYMGMT_is_a(keymgmt: PEVP_SKEYMGMT; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_SKEYMGMT_is_a := LoadLibCryptoFunction('EVP_SKEYMGMT_is_a');
  if not assigned(EVP_SKEYMGMT_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_is_a');
  Result := EVP_SKEYMGMT_is_a(keymgmt, name);
end;

procedure Load_EVP_SKEYMGMT_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType069; arg: pointer); cdecl;
begin
  EVP_SKEYMGMT_do_all_provided := LoadLibCryptoFunction('EVP_SKEYMGMT_do_all_provided');
  if not assigned(EVP_SKEYMGMT_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_do_all_provided');
  EVP_SKEYMGMT_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_SKEYMGMT_names_do_all(keymgmt: PEVP_SKEYMGMT; fn: TFuncType070; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_SKEYMGMT_names_do_all := LoadLibCryptoFunction('EVP_SKEYMGMT_names_do_all');
  if not assigned(EVP_SKEYMGMT_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_names_do_all');
  Result := EVP_SKEYMGMT_names_do_all(keymgmt, fn, data);
end;

function Load_EVP_SKEYMGMT_get0_gen_settable_params(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl;
begin
  EVP_SKEYMGMT_get0_gen_settable_params := LoadLibCryptoFunction('EVP_SKEYMGMT_get0_gen_settable_params');
  if not assigned(EVP_SKEYMGMT_get0_gen_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_get0_gen_settable_params');
  Result := EVP_SKEYMGMT_get0_gen_settable_params(skeymgmt);
end;

function Load_EVP_SKEYMGMT_get0_imp_settable_params(skeymgmt: PEVP_SKEYMGMT): POSSL_PARAM; cdecl;
begin
  EVP_SKEYMGMT_get0_imp_settable_params := LoadLibCryptoFunction('EVP_SKEYMGMT_get0_imp_settable_params');
  if not assigned(EVP_SKEYMGMT_get0_imp_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEYMGMT_get0_imp_settable_params');
  Result := EVP_SKEYMGMT_get0_imp_settable_params(skeymgmt);
end;

function Load_EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_new := LoadLibCryptoFunction('EVP_PKEY_CTX_new');
  if not assigned(EVP_PKEY_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new');
  Result := EVP_PKEY_CTX_new(pkey, e);
end;

function Load_EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_new_id := LoadLibCryptoFunction('EVP_PKEY_CTX_new_id');
  if not assigned(EVP_PKEY_CTX_new_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new_id');
  Result := EVP_PKEY_CTX_new_id(id, e);
end;

function Load_EVP_PKEY_CTX_new_from_name(libctx: POSSL_LIB_CTX; name: PAnsiChar; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_new_from_name := LoadLibCryptoFunction('EVP_PKEY_CTX_new_from_name');
  if not assigned(EVP_PKEY_CTX_new_from_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new_from_name');
  Result := EVP_PKEY_CTX_new_from_name(libctx, name, propquery);
end;

function Load_EVP_PKEY_CTX_new_from_pkey(libctx: POSSL_LIB_CTX; pkey: PEVP_PKEY; propquery: PAnsiChar): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_new_from_pkey := LoadLibCryptoFunction('EVP_PKEY_CTX_new_from_pkey');
  if not assigned(EVP_PKEY_CTX_new_from_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new_from_pkey');
  Result := EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propquery);
end;

function Load_EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl;
begin
  EVP_PKEY_CTX_dup := LoadLibCryptoFunction('EVP_PKEY_CTX_dup');
  if not assigned(EVP_PKEY_CTX_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_dup');
  Result := EVP_PKEY_CTX_dup(ctx);
end;

procedure Load_EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl;
begin
  EVP_PKEY_CTX_free := LoadLibCryptoFunction('EVP_PKEY_CTX_free');
  if not assigned(EVP_PKEY_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_free');
  EVP_PKEY_CTX_free(ctx);
end;

function Load_EVP_PKEY_CTX_is_a(ctx: PEVP_PKEY_CTX; keytype: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_is_a := LoadLibCryptoFunction('EVP_PKEY_CTX_is_a');
  if not assigned(EVP_PKEY_CTX_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_is_a');
  Result := EVP_PKEY_CTX_is_a(ctx, keytype);
end;

function Load_EVP_PKEY_CTX_get_params(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_params := LoadLibCryptoFunction('EVP_PKEY_CTX_get_params');
  if not assigned(EVP_PKEY_CTX_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_params');
  Result := EVP_PKEY_CTX_get_params(ctx, params);
end;

function Load_EVP_PKEY_CTX_gettable_params(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl;
begin
  EVP_PKEY_CTX_gettable_params := LoadLibCryptoFunction('EVP_PKEY_CTX_gettable_params');
  if not assigned(EVP_PKEY_CTX_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_gettable_params');
  Result := EVP_PKEY_CTX_gettable_params(ctx);
end;

function Load_EVP_PKEY_CTX_set_params(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_params := LoadLibCryptoFunction('EVP_PKEY_CTX_set_params');
  if not assigned(EVP_PKEY_CTX_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_params');
  Result := EVP_PKEY_CTX_set_params(ctx, params);
end;

function Load_EVP_PKEY_CTX_settable_params(ctx: PEVP_PKEY_CTX): POSSL_PARAM; cdecl;
begin
  EVP_PKEY_CTX_settable_params := LoadLibCryptoFunction('EVP_PKEY_CTX_settable_params');
  if not assigned(EVP_PKEY_CTX_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_settable_params');
  Result := EVP_PKEY_CTX_settable_params(ctx);
end;

function Load_EVP_PKEY_CTX_set_algor_params(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_algor_params := LoadLibCryptoFunction('EVP_PKEY_CTX_set_algor_params');
  if not assigned(EVP_PKEY_CTX_set_algor_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_algor_params');
  Result := EVP_PKEY_CTX_set_algor_params(ctx, alg);
end;

function Load_EVP_PKEY_CTX_get_algor_params(ctx: PEVP_PKEY_CTX; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_algor_params := LoadLibCryptoFunction('EVP_PKEY_CTX_get_algor_params');
  if not assigned(EVP_PKEY_CTX_get_algor_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_algor_params');
  Result := EVP_PKEY_CTX_get_algor_params(ctx, alg);
end;

function Load_EVP_PKEY_CTX_get_algor(ctx: PEVP_PKEY_CTX; alg: PPX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_algor := LoadLibCryptoFunction('EVP_PKEY_CTX_get_algor');
  if not assigned(EVP_PKEY_CTX_get_algor) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_algor');
  Result := EVP_PKEY_CTX_get_algor(ctx, alg);
end;

function Load_EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl');
  if not assigned(EVP_PKEY_CTX_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl');
  Result := EVP_PKEY_CTX_ctrl(ctx, keytype, optype, cmd, p1, p2);
end;

function Load_EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; type_: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_ctrl_str := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl_str');
  if not assigned(EVP_PKEY_CTX_ctrl_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl_str');
  Result := EVP_PKEY_CTX_ctrl_str(ctx, type_, value);
end;

function Load_EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_ctrl_uint64 := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl_uint64');
  if not assigned(EVP_PKEY_CTX_ctrl_uint64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl_uint64');
  Result := EVP_PKEY_CTX_ctrl_uint64(ctx, keytype, optype, cmd, value);
end;

function Load_EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_str2ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_str2ctrl');
  if not assigned(EVP_PKEY_CTX_str2ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_str2ctrl');
  Result := EVP_PKEY_CTX_str2ctrl(ctx, cmd, str);
end;

function Load_EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; hex: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_hex2ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_hex2ctrl');
  if not assigned(EVP_PKEY_CTX_hex2ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_hex2ctrl');
  Result := EVP_PKEY_CTX_hex2ctrl(ctx, cmd, hex);
end;

function Load_EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; md: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_md := LoadLibCryptoFunction('EVP_PKEY_CTX_md');
  if not assigned(EVP_PKEY_CTX_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_md');
  Result := EVP_PKEY_CTX_md(ctx, optype, cmd, md);
end;

function Load_EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_operation := LoadLibCryptoFunction('EVP_PKEY_CTX_get_operation');
  if not assigned(EVP_PKEY_CTX_get_operation) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_operation');
  Result := EVP_PKEY_CTX_get_operation(ctx);
end;

procedure Load_EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl;
begin
  EVP_PKEY_CTX_set0_keygen_info := LoadLibCryptoFunction('EVP_PKEY_CTX_set0_keygen_info');
  if not assigned(EVP_PKEY_CTX_set0_keygen_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set0_keygen_info');
  EVP_PKEY_CTX_set0_keygen_info(ctx, dat, datlen);
end;

function Load_EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; key: Pbyte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_mac_key := LoadLibCryptoFunction('EVP_PKEY_new_mac_key');
  if not assigned(EVP_PKEY_new_mac_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_mac_key');
  Result := EVP_PKEY_new_mac_key(type_, e, key, keylen);
end;

function Load_EVP_PKEY_new_raw_private_key_ex(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_raw_private_key_ex := LoadLibCryptoFunction('EVP_PKEY_new_raw_private_key_ex');
  if not assigned(EVP_PKEY_new_raw_private_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_private_key_ex');
  Result := EVP_PKEY_new_raw_private_key_ex(libctx, keytype, propq, priv, len);
end;

function Load_EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_raw_private_key := LoadLibCryptoFunction('EVP_PKEY_new_raw_private_key');
  if not assigned(EVP_PKEY_new_raw_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_private_key');
  Result := EVP_PKEY_new_raw_private_key(type_, e, priv, len);
end;

function Load_EVP_PKEY_new_raw_public_key_ex(libctx: POSSL_LIB_CTX; keytype: PAnsiChar; propq: PAnsiChar; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_raw_public_key_ex := LoadLibCryptoFunction('EVP_PKEY_new_raw_public_key_ex');
  if not assigned(EVP_PKEY_new_raw_public_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_public_key_ex');
  Result := EVP_PKEY_new_raw_public_key_ex(libctx, keytype, propq, pub, len);
end;

function Load_EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; pub: Pbyte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_raw_public_key := LoadLibCryptoFunction('EVP_PKEY_new_raw_public_key');
  if not assigned(EVP_PKEY_new_raw_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_public_key');
  Result := EVP_PKEY_new_raw_public_key(type_, e, pub, len);
end;

function Load_EVP_PKEY_get_raw_private_key(pkey: PEVP_PKEY; priv: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_raw_private_key := LoadLibCryptoFunction('EVP_PKEY_get_raw_private_key');
  if not assigned(EVP_PKEY_get_raw_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_raw_private_key');
  Result := EVP_PKEY_get_raw_private_key(pkey, priv, len);
end;

function Load_EVP_PKEY_get_raw_public_key(pkey: PEVP_PKEY; pub: Pbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_raw_public_key := LoadLibCryptoFunction('EVP_PKEY_get_raw_public_key');
  if not assigned(EVP_PKEY_get_raw_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_raw_public_key');
  Result := EVP_PKEY_get_raw_public_key(pkey, pub, len);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_new_CMAC_key(e: PENGINE; priv: Pbyte; len: TOpenSSL_C_SIZET; cipher: PEVP_CIPHER): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_new_CMAC_key := LoadLibCryptoFunction('EVP_PKEY_new_CMAC_key');
  if not assigned(EVP_PKEY_new_CMAC_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_CMAC_key');
  Result := EVP_PKEY_new_CMAC_key(e, priv, len, cipher);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load_EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: pointer); cdecl;
begin
  EVP_PKEY_CTX_set_data := LoadLibCryptoFunction('EVP_PKEY_CTX_set_data');
  if not assigned(EVP_PKEY_CTX_set_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_data');
  EVP_PKEY_CTX_set_data(ctx, data);
end;

function Load_EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): pointer; cdecl;
begin
  EVP_PKEY_CTX_get_data := LoadLibCryptoFunction('EVP_PKEY_CTX_get_data');
  if not assigned(EVP_PKEY_CTX_get_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_data');
  Result := EVP_PKEY_CTX_get_data(ctx);
end;

function Load_EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_CTX_get0_pkey := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_pkey');
  if not assigned(EVP_PKEY_CTX_get0_pkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_pkey');
  Result := EVP_PKEY_CTX_get0_pkey(ctx);
end;

function Load_EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
begin
  EVP_PKEY_CTX_get0_peerkey := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_peerkey');
  if not assigned(EVP_PKEY_CTX_get0_peerkey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_peerkey');
  Result := EVP_PKEY_CTX_get0_peerkey(ctx);
end;

procedure Load_EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: pointer); cdecl;
begin
  EVP_PKEY_CTX_set_app_data := LoadLibCryptoFunction('EVP_PKEY_CTX_set_app_data');
  if not assigned(EVP_PKEY_CTX_set_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_app_data');
  EVP_PKEY_CTX_set_app_data(ctx, data);
end;

function Load_EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): pointer; cdecl;
begin
  EVP_PKEY_CTX_get_app_data := LoadLibCryptoFunction('EVP_PKEY_CTX_get_app_data');
  if not assigned(EVP_PKEY_CTX_get_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_app_data');
  Result := EVP_PKEY_CTX_get_app_data(ctx);
end;

function Load_EVP_PKEY_CTX_set_signature(pctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_signature := LoadLibCryptoFunction('EVP_PKEY_CTX_set_signature');
  if not assigned(EVP_PKEY_CTX_set_signature) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_signature');
  Result := EVP_PKEY_CTX_set_signature(pctx, sig, siglen);
end;

procedure Load_EVP_SIGNATURE_free(signature: PEVP_SIGNATURE); cdecl;
begin
  EVP_SIGNATURE_free := LoadLibCryptoFunction('EVP_SIGNATURE_free');
  if not assigned(EVP_SIGNATURE_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_free');
  EVP_SIGNATURE_free(signature);
end;

function Load_EVP_SIGNATURE_up_ref(signature: PEVP_SIGNATURE): TOpenSSL_C_INT; cdecl;
begin
  EVP_SIGNATURE_up_ref := LoadLibCryptoFunction('EVP_SIGNATURE_up_ref');
  if not assigned(EVP_SIGNATURE_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_up_ref');
  Result := EVP_SIGNATURE_up_ref(signature);
end;

function Load_EVP_SIGNATURE_get0_provider(signature: PEVP_SIGNATURE): POSSL_PROVIDER; cdecl;
begin
  EVP_SIGNATURE_get0_provider := LoadLibCryptoFunction('EVP_SIGNATURE_get0_provider');
  if not assigned(EVP_SIGNATURE_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_get0_provider');
  Result := EVP_SIGNATURE_get0_provider(signature);
end;

function Load_EVP_SIGNATURE_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_SIGNATURE; cdecl;
begin
  EVP_SIGNATURE_fetch := LoadLibCryptoFunction('EVP_SIGNATURE_fetch');
  if not assigned(EVP_SIGNATURE_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_fetch');
  Result := EVP_SIGNATURE_fetch(ctx, algorithm, properties);
end;

function Load_EVP_SIGNATURE_is_a(signature: PEVP_SIGNATURE; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_SIGNATURE_is_a := LoadLibCryptoFunction('EVP_SIGNATURE_is_a');
  if not assigned(EVP_SIGNATURE_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_is_a');
  Result := EVP_SIGNATURE_is_a(signature, name);
end;

function Load_EVP_SIGNATURE_get0_name(signature: PEVP_SIGNATURE): PAnsiChar; cdecl;
begin
  EVP_SIGNATURE_get0_name := LoadLibCryptoFunction('EVP_SIGNATURE_get0_name');
  if not assigned(EVP_SIGNATURE_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_get0_name');
  Result := EVP_SIGNATURE_get0_name(signature);
end;

function Load_EVP_SIGNATURE_get0_description(signature: PEVP_SIGNATURE): PAnsiChar; cdecl;
begin
  EVP_SIGNATURE_get0_description := LoadLibCryptoFunction('EVP_SIGNATURE_get0_description');
  if not assigned(EVP_SIGNATURE_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_get0_description');
  Result := EVP_SIGNATURE_get0_description(signature);
end;

procedure Load_EVP_SIGNATURE_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType071; data: pointer); cdecl;
begin
  EVP_SIGNATURE_do_all_provided := LoadLibCryptoFunction('EVP_SIGNATURE_do_all_provided');
  if not assigned(EVP_SIGNATURE_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_do_all_provided');
  EVP_SIGNATURE_do_all_provided(libctx, fn, data);
end;

function Load_EVP_SIGNATURE_names_do_all(signature: PEVP_SIGNATURE; fn: TFuncType072; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_SIGNATURE_names_do_all := LoadLibCryptoFunction('EVP_SIGNATURE_names_do_all');
  if not assigned(EVP_SIGNATURE_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_names_do_all');
  Result := EVP_SIGNATURE_names_do_all(signature, fn, data);
end;

function Load_EVP_SIGNATURE_gettable_ctx_params(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl;
begin
  EVP_SIGNATURE_gettable_ctx_params := LoadLibCryptoFunction('EVP_SIGNATURE_gettable_ctx_params');
  if not assigned(EVP_SIGNATURE_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_gettable_ctx_params');
  Result := EVP_SIGNATURE_gettable_ctx_params(sig);
end;

function Load_EVP_SIGNATURE_settable_ctx_params(sig: PEVP_SIGNATURE): POSSL_PARAM; cdecl;
begin
  EVP_SIGNATURE_settable_ctx_params := LoadLibCryptoFunction('EVP_SIGNATURE_settable_ctx_params');
  if not assigned(EVP_SIGNATURE_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SIGNATURE_settable_ctx_params');
  Result := EVP_SIGNATURE_settable_ctx_params(sig);
end;

procedure Load_EVP_ASYM_CIPHER_free(cipher: PEVP_ASYM_CIPHER); cdecl;
begin
  EVP_ASYM_CIPHER_free := LoadLibCryptoFunction('EVP_ASYM_CIPHER_free');
  if not assigned(EVP_ASYM_CIPHER_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_free');
  EVP_ASYM_CIPHER_free(cipher);
end;

function Load_EVP_ASYM_CIPHER_up_ref(cipher: PEVP_ASYM_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EVP_ASYM_CIPHER_up_ref := LoadLibCryptoFunction('EVP_ASYM_CIPHER_up_ref');
  if not assigned(EVP_ASYM_CIPHER_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_up_ref');
  Result := EVP_ASYM_CIPHER_up_ref(cipher);
end;

function Load_EVP_ASYM_CIPHER_get0_provider(cipher: PEVP_ASYM_CIPHER): POSSL_PROVIDER; cdecl;
begin
  EVP_ASYM_CIPHER_get0_provider := LoadLibCryptoFunction('EVP_ASYM_CIPHER_get0_provider');
  if not assigned(EVP_ASYM_CIPHER_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_get0_provider');
  Result := EVP_ASYM_CIPHER_get0_provider(cipher);
end;

function Load_EVP_ASYM_CIPHER_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_ASYM_CIPHER; cdecl;
begin
  EVP_ASYM_CIPHER_fetch := LoadLibCryptoFunction('EVP_ASYM_CIPHER_fetch');
  if not assigned(EVP_ASYM_CIPHER_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_fetch');
  Result := EVP_ASYM_CIPHER_fetch(ctx, algorithm, properties);
end;

function Load_EVP_ASYM_CIPHER_is_a(cipher: PEVP_ASYM_CIPHER; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_ASYM_CIPHER_is_a := LoadLibCryptoFunction('EVP_ASYM_CIPHER_is_a');
  if not assigned(EVP_ASYM_CIPHER_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_is_a');
  Result := EVP_ASYM_CIPHER_is_a(cipher, name);
end;

function Load_EVP_ASYM_CIPHER_get0_name(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl;
begin
  EVP_ASYM_CIPHER_get0_name := LoadLibCryptoFunction('EVP_ASYM_CIPHER_get0_name');
  if not assigned(EVP_ASYM_CIPHER_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_get0_name');
  Result := EVP_ASYM_CIPHER_get0_name(cipher);
end;

function Load_EVP_ASYM_CIPHER_get0_description(cipher: PEVP_ASYM_CIPHER): PAnsiChar; cdecl;
begin
  EVP_ASYM_CIPHER_get0_description := LoadLibCryptoFunction('EVP_ASYM_CIPHER_get0_description');
  if not assigned(EVP_ASYM_CIPHER_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_get0_description');
  Result := EVP_ASYM_CIPHER_get0_description(cipher);
end;

procedure Load_EVP_ASYM_CIPHER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType073; arg: pointer); cdecl;
begin
  EVP_ASYM_CIPHER_do_all_provided := LoadLibCryptoFunction('EVP_ASYM_CIPHER_do_all_provided');
  if not assigned(EVP_ASYM_CIPHER_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_do_all_provided');
  EVP_ASYM_CIPHER_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_ASYM_CIPHER_names_do_all(cipher: PEVP_ASYM_CIPHER; fn: TFuncType074; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_ASYM_CIPHER_names_do_all := LoadLibCryptoFunction('EVP_ASYM_CIPHER_names_do_all');
  if not assigned(EVP_ASYM_CIPHER_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_names_do_all');
  Result := EVP_ASYM_CIPHER_names_do_all(cipher, fn, data);
end;

function Load_EVP_ASYM_CIPHER_gettable_ctx_params(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl;
begin
  EVP_ASYM_CIPHER_gettable_ctx_params := LoadLibCryptoFunction('EVP_ASYM_CIPHER_gettable_ctx_params');
  if not assigned(EVP_ASYM_CIPHER_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_gettable_ctx_params');
  Result := EVP_ASYM_CIPHER_gettable_ctx_params(ciph);
end;

function Load_EVP_ASYM_CIPHER_settable_ctx_params(ciph: PEVP_ASYM_CIPHER): POSSL_PARAM; cdecl;
begin
  EVP_ASYM_CIPHER_settable_ctx_params := LoadLibCryptoFunction('EVP_ASYM_CIPHER_settable_ctx_params');
  if not assigned(EVP_ASYM_CIPHER_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ASYM_CIPHER_settable_ctx_params');
  Result := EVP_ASYM_CIPHER_settable_ctx_params(ciph);
end;

procedure Load_EVP_KEM_free(wrap: PEVP_KEM); cdecl;
begin
  EVP_KEM_free := LoadLibCryptoFunction('EVP_KEM_free');
  if not assigned(EVP_KEM_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_free');
  EVP_KEM_free(wrap);
end;

function Load_EVP_KEM_up_ref(wrap: PEVP_KEM): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEM_up_ref := LoadLibCryptoFunction('EVP_KEM_up_ref');
  if not assigned(EVP_KEM_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_up_ref');
  Result := EVP_KEM_up_ref(wrap);
end;

function Load_EVP_KEM_get0_provider(wrap: PEVP_KEM): POSSL_PROVIDER; cdecl;
begin
  EVP_KEM_get0_provider := LoadLibCryptoFunction('EVP_KEM_get0_provider');
  if not assigned(EVP_KEM_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_get0_provider');
  Result := EVP_KEM_get0_provider(wrap);
end;

function Load_EVP_KEM_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEM; cdecl;
begin
  EVP_KEM_fetch := LoadLibCryptoFunction('EVP_KEM_fetch');
  if not assigned(EVP_KEM_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_fetch');
  Result := EVP_KEM_fetch(ctx, algorithm, properties);
end;

function Load_EVP_KEM_is_a(wrap: PEVP_KEM; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEM_is_a := LoadLibCryptoFunction('EVP_KEM_is_a');
  if not assigned(EVP_KEM_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_is_a');
  Result := EVP_KEM_is_a(wrap, name);
end;

function Load_EVP_KEM_get0_name(wrap: PEVP_KEM): PAnsiChar; cdecl;
begin
  EVP_KEM_get0_name := LoadLibCryptoFunction('EVP_KEM_get0_name');
  if not assigned(EVP_KEM_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_get0_name');
  Result := EVP_KEM_get0_name(wrap);
end;

function Load_EVP_KEM_get0_description(wrap: PEVP_KEM): PAnsiChar; cdecl;
begin
  EVP_KEM_get0_description := LoadLibCryptoFunction('EVP_KEM_get0_description');
  if not assigned(EVP_KEM_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_get0_description');
  Result := EVP_KEM_get0_description(wrap);
end;

procedure Load_EVP_KEM_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType075; arg: pointer); cdecl;
begin
  EVP_KEM_do_all_provided := LoadLibCryptoFunction('EVP_KEM_do_all_provided');
  if not assigned(EVP_KEM_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_do_all_provided');
  EVP_KEM_do_all_provided(libctx, fn, arg);
end;

function Load_EVP_KEM_names_do_all(wrap: PEVP_KEM; fn: TFuncType076; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEM_names_do_all := LoadLibCryptoFunction('EVP_KEM_names_do_all');
  if not assigned(EVP_KEM_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_names_do_all');
  Result := EVP_KEM_names_do_all(wrap, fn, data);
end;

function Load_EVP_KEM_gettable_ctx_params(kem: PEVP_KEM): POSSL_PARAM; cdecl;
begin
  EVP_KEM_gettable_ctx_params := LoadLibCryptoFunction('EVP_KEM_gettable_ctx_params');
  if not assigned(EVP_KEM_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_gettable_ctx_params');
  Result := EVP_KEM_gettable_ctx_params(kem);
end;

function Load_EVP_KEM_settable_ctx_params(kem: PEVP_KEM): POSSL_PARAM; cdecl;
begin
  EVP_KEM_settable_ctx_params := LoadLibCryptoFunction('EVP_KEM_settable_ctx_params');
  if not assigned(EVP_KEM_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEM_settable_ctx_params');
  Result := EVP_KEM_settable_ctx_params(kem);
end;

function Load_EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign_init := LoadLibCryptoFunction('EVP_PKEY_sign_init');
  if not assigned(EVP_PKEY_sign_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_init');
  Result := EVP_PKEY_sign_init(ctx);
end;

function Load_EVP_PKEY_sign_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign_init_ex := LoadLibCryptoFunction('EVP_PKEY_sign_init_ex');
  if not assigned(EVP_PKEY_sign_init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_init_ex');
  Result := EVP_PKEY_sign_init_ex(ctx, params);
end;

function Load_EVP_PKEY_sign_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign_init_ex2 := LoadLibCryptoFunction('EVP_PKEY_sign_init_ex2');
  if not assigned(EVP_PKEY_sign_init_ex2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_init_ex2');
  Result := EVP_PKEY_sign_init_ex2(ctx, algo, params);
end;

function Load_EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign := LoadLibCryptoFunction('EVP_PKEY_sign');
  if not assigned(EVP_PKEY_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign');
  Result := EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
end;

function Load_EVP_PKEY_sign_message_init(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign_message_init := LoadLibCryptoFunction('EVP_PKEY_sign_message_init');
  if not assigned(EVP_PKEY_sign_message_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_message_init');
  Result := EVP_PKEY_sign_message_init(ctx, algo, params);
end;

function Load_EVP_PKEY_sign_message_update(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign_message_update := LoadLibCryptoFunction('EVP_PKEY_sign_message_update');
  if not assigned(EVP_PKEY_sign_message_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_message_update');
  Result := EVP_PKEY_sign_message_update(ctx, in_, inlen);
end;

function Load_EVP_PKEY_sign_message_final(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_sign_message_final := LoadLibCryptoFunction('EVP_PKEY_sign_message_final');
  if not assigned(EVP_PKEY_sign_message_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_message_final');
  Result := EVP_PKEY_sign_message_final(ctx, sig, siglen);
end;

function Load_EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_init := LoadLibCryptoFunction('EVP_PKEY_verify_init');
  if not assigned(EVP_PKEY_verify_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_init');
  Result := EVP_PKEY_verify_init(ctx);
end;

function Load_EVP_PKEY_verify_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_init_ex := LoadLibCryptoFunction('EVP_PKEY_verify_init_ex');
  if not assigned(EVP_PKEY_verify_init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_init_ex');
  Result := EVP_PKEY_verify_init_ex(ctx, params);
end;

function Load_EVP_PKEY_verify_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_init_ex2 := LoadLibCryptoFunction('EVP_PKEY_verify_init_ex2');
  if not assigned(EVP_PKEY_verify_init_ex2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_init_ex2');
  Result := EVP_PKEY_verify_init_ex2(ctx, algo, params);
end;

function Load_EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; sig: Pbyte; siglen: TOpenSSL_C_SIZET; tbs: Pbyte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify := LoadLibCryptoFunction('EVP_PKEY_verify');
  if not assigned(EVP_PKEY_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify');
  Result := EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
end;

function Load_EVP_PKEY_verify_message_init(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_message_init := LoadLibCryptoFunction('EVP_PKEY_verify_message_init');
  if not assigned(EVP_PKEY_verify_message_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_message_init');
  Result := EVP_PKEY_verify_message_init(ctx, algo, params);
end;

function Load_EVP_PKEY_verify_message_update(ctx: PEVP_PKEY_CTX; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_message_update := LoadLibCryptoFunction('EVP_PKEY_verify_message_update');
  if not assigned(EVP_PKEY_verify_message_update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_message_update');
  Result := EVP_PKEY_verify_message_update(ctx, in_, inlen);
end;

function Load_EVP_PKEY_verify_message_final(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_message_final := LoadLibCryptoFunction('EVP_PKEY_verify_message_final');
  if not assigned(EVP_PKEY_verify_message_final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_message_final');
  Result := EVP_PKEY_verify_message_final(ctx);
end;

function Load_EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_recover_init := LoadLibCryptoFunction('EVP_PKEY_verify_recover_init');
  if not assigned(EVP_PKEY_verify_recover_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover_init');
  Result := EVP_PKEY_verify_recover_init(ctx);
end;

function Load_EVP_PKEY_verify_recover_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_recover_init_ex := LoadLibCryptoFunction('EVP_PKEY_verify_recover_init_ex');
  if not assigned(EVP_PKEY_verify_recover_init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover_init_ex');
  Result := EVP_PKEY_verify_recover_init_ex(ctx, params);
end;

function Load_EVP_PKEY_verify_recover_init_ex2(ctx: PEVP_PKEY_CTX; algo: PEVP_SIGNATURE; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_recover_init_ex2 := LoadLibCryptoFunction('EVP_PKEY_verify_recover_init_ex2');
  if not assigned(EVP_PKEY_verify_recover_init_ex2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover_init_ex2');
  Result := EVP_PKEY_verify_recover_init_ex2(ctx, algo, params);
end;

function Load_EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: Pbyte; routlen: POpenSSL_C_SIZET; sig: Pbyte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_verify_recover := LoadLibCryptoFunction('EVP_PKEY_verify_recover');
  if not assigned(EVP_PKEY_verify_recover) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover');
  Result := EVP_PKEY_verify_recover(ctx, rout, routlen, sig, siglen);
end;

function Load_EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encrypt_init := LoadLibCryptoFunction('EVP_PKEY_encrypt_init');
  if not assigned(EVP_PKEY_encrypt_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt_init');
  Result := EVP_PKEY_encrypt_init(ctx);
end;

function Load_EVP_PKEY_encrypt_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encrypt_init_ex := LoadLibCryptoFunction('EVP_PKEY_encrypt_init_ex');
  if not assigned(EVP_PKEY_encrypt_init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt_init_ex');
  Result := EVP_PKEY_encrypt_init_ex(ctx, params);
end;

function Load_EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encrypt := LoadLibCryptoFunction('EVP_PKEY_encrypt');
  if not assigned(EVP_PKEY_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt');
  Result := EVP_PKEY_encrypt(ctx, out_, outlen, in_, inlen);
end;

function Load_EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decrypt_init := LoadLibCryptoFunction('EVP_PKEY_decrypt_init');
  if not assigned(EVP_PKEY_decrypt_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt_init');
  Result := EVP_PKEY_decrypt_init(ctx);
end;

function Load_EVP_PKEY_decrypt_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decrypt_init_ex := LoadLibCryptoFunction('EVP_PKEY_decrypt_init_ex');
  if not assigned(EVP_PKEY_decrypt_init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt_init_ex');
  Result := EVP_PKEY_decrypt_init_ex(ctx, params);
end;

function Load_EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: Pbyte; outlen: POpenSSL_C_SIZET; in_: Pbyte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decrypt := LoadLibCryptoFunction('EVP_PKEY_decrypt');
  if not assigned(EVP_PKEY_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt');
  Result := EVP_PKEY_decrypt(ctx, out_, outlen, in_, inlen);
end;

function Load_EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive_init := LoadLibCryptoFunction('EVP_PKEY_derive_init');
  if not assigned(EVP_PKEY_derive_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_init');
  Result := EVP_PKEY_derive_init(ctx);
end;

function Load_EVP_PKEY_derive_init_ex(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive_init_ex := LoadLibCryptoFunction('EVP_PKEY_derive_init_ex');
  if not assigned(EVP_PKEY_derive_init_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_init_ex');
  Result := EVP_PKEY_derive_init_ex(ctx, params);
end;

function Load_EVP_PKEY_derive_set_peer_ex(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY; validate_peer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive_set_peer_ex := LoadLibCryptoFunction('EVP_PKEY_derive_set_peer_ex');
  if not assigned(EVP_PKEY_derive_set_peer_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_set_peer_ex');
  Result := EVP_PKEY_derive_set_peer_ex(ctx, peer, validate_peer);
end;

function Load_EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive_set_peer := LoadLibCryptoFunction('EVP_PKEY_derive_set_peer');
  if not assigned(EVP_PKEY_derive_set_peer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_set_peer');
  Result := EVP_PKEY_derive_set_peer(ctx, peer);
end;

function Load_EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: Pbyte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_derive := LoadLibCryptoFunction('EVP_PKEY_derive');
  if not assigned(EVP_PKEY_derive) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive');
  Result := EVP_PKEY_derive(ctx, key, keylen);
end;

function Load_EVP_PKEY_derive_SKEY(ctx: PEVP_PKEY_CTX; mgmt: PEVP_SKEYMGMT; key_type: PAnsiChar; propquery: PAnsiChar; keylen: TOpenSSL_C_SIZET; params: POSSL_PARAM): PEVP_SKEY; cdecl;
begin
  EVP_PKEY_derive_SKEY := LoadLibCryptoFunction('EVP_PKEY_derive_SKEY');
  if not assigned(EVP_PKEY_derive_SKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_SKEY');
  Result := EVP_PKEY_derive_SKEY(ctx, mgmt, key_type, propquery, keylen, params);
end;

function Load_EVP_PKEY_encapsulate_init(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encapsulate_init := LoadLibCryptoFunction('EVP_PKEY_encapsulate_init');
  if not assigned(EVP_PKEY_encapsulate_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encapsulate_init');
  Result := EVP_PKEY_encapsulate_init(ctx, params);
end;

function Load_EVP_PKEY_auth_encapsulate_init(ctx: PEVP_PKEY_CTX; authpriv: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_auth_encapsulate_init := LoadLibCryptoFunction('EVP_PKEY_auth_encapsulate_init');
  if not assigned(EVP_PKEY_auth_encapsulate_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_auth_encapsulate_init');
  Result := EVP_PKEY_auth_encapsulate_init(ctx, authpriv, params);
end;

function Load_EVP_PKEY_encapsulate(ctx: PEVP_PKEY_CTX; wrappedkey: Pbyte; wrappedkeylen: POpenSSL_C_SIZET; genkey: Pbyte; genkeylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_encapsulate := LoadLibCryptoFunction('EVP_PKEY_encapsulate');
  if not assigned(EVP_PKEY_encapsulate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encapsulate');
  Result := EVP_PKEY_encapsulate(ctx, wrappedkey, wrappedkeylen, genkey, genkeylen);
end;

function Load_EVP_PKEY_decapsulate_init(ctx: PEVP_PKEY_CTX; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decapsulate_init := LoadLibCryptoFunction('EVP_PKEY_decapsulate_init');
  if not assigned(EVP_PKEY_decapsulate_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decapsulate_init');
  Result := EVP_PKEY_decapsulate_init(ctx, params);
end;

function Load_EVP_PKEY_auth_decapsulate_init(ctx: PEVP_PKEY_CTX; authpub: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_auth_decapsulate_init := LoadLibCryptoFunction('EVP_PKEY_auth_decapsulate_init');
  if not assigned(EVP_PKEY_auth_decapsulate_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_auth_decapsulate_init');
  Result := EVP_PKEY_auth_decapsulate_init(ctx, authpub, params);
end;

function Load_EVP_PKEY_decapsulate(ctx: PEVP_PKEY_CTX; unwrapped: Pbyte; unwrappedlen: POpenSSL_C_SIZET; wrapped: Pbyte; wrappedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_decapsulate := LoadLibCryptoFunction('EVP_PKEY_decapsulate');
  if not assigned(EVP_PKEY_decapsulate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decapsulate');
  Result := EVP_PKEY_decapsulate(ctx, unwrapped, unwrappedlen, wrapped, wrappedlen);
end;

function Load_EVP_PKEY_fromdata_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_fromdata_init := LoadLibCryptoFunction('EVP_PKEY_fromdata_init');
  if not assigned(EVP_PKEY_fromdata_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_fromdata_init');
  Result := EVP_PKEY_fromdata_init(ctx);
end;

function Load_EVP_PKEY_fromdata(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY; selection: TOpenSSL_C_INT; param: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_fromdata := LoadLibCryptoFunction('EVP_PKEY_fromdata');
  if not assigned(EVP_PKEY_fromdata) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_fromdata');
  Result := EVP_PKEY_fromdata(ctx, ppkey, selection, param);
end;

function Load_EVP_PKEY_fromdata_settable(ctx: PEVP_PKEY_CTX; selection: TOpenSSL_C_INT): POSSL_PARAM; cdecl;
begin
  EVP_PKEY_fromdata_settable := LoadLibCryptoFunction('EVP_PKEY_fromdata_settable');
  if not assigned(EVP_PKEY_fromdata_settable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_fromdata_settable');
  Result := EVP_PKEY_fromdata_settable(ctx, selection);
end;

function Load_EVP_PKEY_todata(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; params: PPOSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_todata := LoadLibCryptoFunction('EVP_PKEY_todata');
  if not assigned(EVP_PKEY_todata) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_todata');
  Result := EVP_PKEY_todata(pkey, selection, params);
end;

function Load_EVP_PKEY_export(pkey: PEVP_PKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_export := LoadLibCryptoFunction('EVP_PKEY_export');
  if not assigned(EVP_PKEY_export) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_export');
  Result := EVP_PKEY_export(pkey, selection, export_cb, export_cbarg);
end;

function Load_EVP_PKEY_gettable_params(pkey: PEVP_PKEY): POSSL_PARAM; cdecl;
begin
  EVP_PKEY_gettable_params := LoadLibCryptoFunction('EVP_PKEY_gettable_params');
  if not assigned(EVP_PKEY_gettable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_gettable_params');
  Result := EVP_PKEY_gettable_params(pkey);
end;

function Load_EVP_PKEY_get_params(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_params := LoadLibCryptoFunction('EVP_PKEY_get_params');
  if not assigned(EVP_PKEY_get_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_params');
  Result := EVP_PKEY_get_params(pkey, params);
end;

function Load_EVP_PKEY_get_int_param(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_int_param := LoadLibCryptoFunction('EVP_PKEY_get_int_param');
  if not assigned(EVP_PKEY_get_int_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_int_param');
  Result := EVP_PKEY_get_int_param(pkey, key_name, out_);
end;

function Load_EVP_PKEY_get_size_t_param(pkey: PEVP_PKEY; key_name: PAnsiChar; out_: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_size_t_param := LoadLibCryptoFunction('EVP_PKEY_get_size_t_param');
  if not assigned(EVP_PKEY_get_size_t_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_size_t_param');
  Result := EVP_PKEY_get_size_t_param(pkey, key_name, out_);
end;

function Load_EVP_PKEY_get_bn_param(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_bn_param := LoadLibCryptoFunction('EVP_PKEY_get_bn_param');
  if not assigned(EVP_PKEY_get_bn_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_bn_param');
  Result := EVP_PKEY_get_bn_param(pkey, key_name, bn);
end;

function Load_EVP_PKEY_get_utf8_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_utf8_string_param := LoadLibCryptoFunction('EVP_PKEY_get_utf8_string_param');
  if not assigned(EVP_PKEY_get_utf8_string_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_utf8_string_param');
  Result := EVP_PKEY_get_utf8_string_param(pkey, key_name, str, max_buf_sz, out_sz);
end;

function Load_EVP_PKEY_get_octet_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; max_buf_sz: TOpenSSL_C_SIZET; out_sz: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_octet_string_param := LoadLibCryptoFunction('EVP_PKEY_get_octet_string_param');
  if not assigned(EVP_PKEY_get_octet_string_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_octet_string_param');
  Result := EVP_PKEY_get_octet_string_param(pkey, key_name, buf, max_buf_sz, out_sz);
end;

function Load_EVP_PKEY_settable_params(pkey: PEVP_PKEY): POSSL_PARAM; cdecl;
begin
  EVP_PKEY_settable_params := LoadLibCryptoFunction('EVP_PKEY_settable_params');
  if not assigned(EVP_PKEY_settable_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_settable_params');
  Result := EVP_PKEY_settable_params(pkey);
end;

function Load_EVP_PKEY_set_params(pkey: PEVP_PKEY; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_params := LoadLibCryptoFunction('EVP_PKEY_set_params');
  if not assigned(EVP_PKEY_set_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_params');
  Result := EVP_PKEY_set_params(pkey, params);
end;

function Load_EVP_PKEY_set_int_param(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_int_param := LoadLibCryptoFunction('EVP_PKEY_set_int_param');
  if not assigned(EVP_PKEY_set_int_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_int_param');
  Result := EVP_PKEY_set_int_param(pkey, key_name, in_);
end;

function Load_EVP_PKEY_set_size_t_param(pkey: PEVP_PKEY; key_name: PAnsiChar; in_: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_size_t_param := LoadLibCryptoFunction('EVP_PKEY_set_size_t_param');
  if not assigned(EVP_PKEY_set_size_t_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_size_t_param');
  Result := EVP_PKEY_set_size_t_param(pkey, key_name, in_);
end;

function Load_EVP_PKEY_set_bn_param(pkey: PEVP_PKEY; key_name: PAnsiChar; bn: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_bn_param := LoadLibCryptoFunction('EVP_PKEY_set_bn_param');
  if not assigned(EVP_PKEY_set_bn_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_bn_param');
  Result := EVP_PKEY_set_bn_param(pkey, key_name, bn);
end;

function Load_EVP_PKEY_set_utf8_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_utf8_string_param := LoadLibCryptoFunction('EVP_PKEY_set_utf8_string_param');
  if not assigned(EVP_PKEY_set_utf8_string_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_utf8_string_param');
  Result := EVP_PKEY_set_utf8_string_param(pkey, key_name, str);
end;

function Load_EVP_PKEY_set_octet_string_param(pkey: PEVP_PKEY; key_name: PAnsiChar; buf: Pbyte; bsize: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_octet_string_param := LoadLibCryptoFunction('EVP_PKEY_set_octet_string_param');
  if not assigned(EVP_PKEY_set_octet_string_param) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_octet_string_param');
  Result := EVP_PKEY_set_octet_string_param(pkey, key_name, buf, bsize);
end;

function Load_EVP_PKEY_get_ec_point_conv_form(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_ec_point_conv_form := LoadLibCryptoFunction('EVP_PKEY_get_ec_point_conv_form');
  if not assigned(EVP_PKEY_get_ec_point_conv_form) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_ec_point_conv_form');
  Result := EVP_PKEY_get_ec_point_conv_form(pkey);
end;

function Load_EVP_PKEY_get_field_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_field_type := LoadLibCryptoFunction('EVP_PKEY_get_field_type');
  if not assigned(EVP_PKEY_get_field_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_field_type');
  Result := EVP_PKEY_get_field_type(pkey);
end;

function Load_EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_paramgen_init := LoadLibCryptoFunction('EVP_PKEY_paramgen_init');
  if not assigned(EVP_PKEY_paramgen_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_paramgen_init');
  Result := EVP_PKEY_paramgen_init(ctx);
end;

function Load_EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_paramgen := LoadLibCryptoFunction('EVP_PKEY_paramgen');
  if not assigned(EVP_PKEY_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_paramgen');
  Result := EVP_PKEY_paramgen(ctx, ppkey);
end;

function Load_EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_keygen_init := LoadLibCryptoFunction('EVP_PKEY_keygen_init');
  if not assigned(EVP_PKEY_keygen_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_keygen_init');
  Result := EVP_PKEY_keygen_init(ctx);
end;

function Load_EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_keygen := LoadLibCryptoFunction('EVP_PKEY_keygen');
  if not assigned(EVP_PKEY_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_keygen');
  Result := EVP_PKEY_keygen(ctx, ppkey);
end;

function Load_EVP_PKEY_generate(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_generate := LoadLibCryptoFunction('EVP_PKEY_generate');
  if not assigned(EVP_PKEY_generate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_generate');
  Result := EVP_PKEY_generate(ctx, ppkey);
end;

function Load_EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_check := LoadLibCryptoFunction('EVP_PKEY_check');
  if not assigned(EVP_PKEY_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_check');
  Result := EVP_PKEY_check(ctx);
end;

function Load_EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_public_check := LoadLibCryptoFunction('EVP_PKEY_public_check');
  if not assigned(EVP_PKEY_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_public_check');
  Result := EVP_PKEY_public_check(ctx);
end;

function Load_EVP_PKEY_public_check_quick(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_public_check_quick := LoadLibCryptoFunction('EVP_PKEY_public_check_quick');
  if not assigned(EVP_PKEY_public_check_quick) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_public_check_quick');
  Result := EVP_PKEY_public_check_quick(ctx);
end;

function Load_EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_param_check := LoadLibCryptoFunction('EVP_PKEY_param_check');
  if not assigned(EVP_PKEY_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_param_check');
  Result := EVP_PKEY_param_check(ctx);
end;

function Load_EVP_PKEY_param_check_quick(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_param_check_quick := LoadLibCryptoFunction('EVP_PKEY_param_check_quick');
  if not assigned(EVP_PKEY_param_check_quick) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_param_check_quick');
  Result := EVP_PKEY_param_check_quick(ctx);
end;

function Load_EVP_PKEY_private_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_private_check := LoadLibCryptoFunction('EVP_PKEY_private_check');
  if not assigned(EVP_PKEY_private_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_private_check');
  Result := EVP_PKEY_private_check(ctx);
end;

function Load_EVP_PKEY_pairwise_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_pairwise_check := LoadLibCryptoFunction('EVP_PKEY_pairwise_check');
  if not assigned(EVP_PKEY_pairwise_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_pairwise_check');
  Result := EVP_PKEY_pairwise_check(ctx);
end;

function Load_EVP_PKEY_set_ex_data(key: PEVP_PKEY; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_set_ex_data := LoadLibCryptoFunction('EVP_PKEY_set_ex_data');
  if not assigned(EVP_PKEY_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_ex_data');
  Result := EVP_PKEY_set_ex_data(key, idx, arg);
end;

function Load_EVP_PKEY_get_ex_data(key: PEVP_PKEY; idx: TOpenSSL_C_INT): pointer; cdecl;
begin
  EVP_PKEY_get_ex_data := LoadLibCryptoFunction('EVP_PKEY_get_ex_data');
  if not assigned(EVP_PKEY_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_ex_data');
  Result := EVP_PKEY_get_ex_data(key, idx);
end;

procedure Load_EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: PEVP_PKEY_gen_cb); cdecl;
begin
  EVP_PKEY_CTX_set_cb := LoadLibCryptoFunction('EVP_PKEY_CTX_set_cb');
  if not assigned(EVP_PKEY_CTX_set_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_cb');
  EVP_PKEY_CTX_set_cb(ctx, cb);
end;

function Load_EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): PEVP_PKEY_gen_cb; cdecl;
begin
  EVP_PKEY_CTX_get_cb := LoadLibCryptoFunction('EVP_PKEY_CTX_get_cb');
  if not assigned(EVP_PKEY_CTX_get_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_cb');
  Result := EVP_PKEY_CTX_get_cb(ctx);
end;

function Load_EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_keygen_info := LoadLibCryptoFunction('EVP_PKEY_CTX_get_keygen_info');
  if not assigned(EVP_PKEY_CTX_get_keygen_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_keygen_info');
  Result := EVP_PKEY_CTX_get_keygen_info(ctx, idx);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; init: TFuncType077); cdecl;
begin
  EVP_PKEY_meth_set_init := LoadLibCryptoFunction('EVP_PKEY_meth_set_init');
  if not assigned(EVP_PKEY_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_init');
  EVP_PKEY_meth_set_init(pmeth, init);
end;

procedure Load_EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; copy: TFuncType078); cdecl;
begin
  EVP_PKEY_meth_set_copy := LoadLibCryptoFunction('EVP_PKEY_meth_set_copy');
  if not assigned(EVP_PKEY_meth_set_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_copy');
  EVP_PKEY_meth_set_copy(pmeth, copy);
end;

procedure Load_EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; cleanup: TFuncType079); cdecl;
begin
  EVP_PKEY_meth_set_cleanup := LoadLibCryptoFunction('EVP_PKEY_meth_set_cleanup');
  if not assigned(EVP_PKEY_meth_set_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_cleanup');
  EVP_PKEY_meth_set_cleanup(pmeth, cleanup);
end;

procedure Load_EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; paramgen_init: TFuncType080; paramgen: TFuncType081); cdecl;
begin
  EVP_PKEY_meth_set_paramgen := LoadLibCryptoFunction('EVP_PKEY_meth_set_paramgen');
  if not assigned(EVP_PKEY_meth_set_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_paramgen');
  EVP_PKEY_meth_set_paramgen(pmeth, paramgen_init, paramgen);
end;

procedure Load_EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; keygen_init: TFuncType082; keygen: TFuncType083); cdecl;
begin
  EVP_PKEY_meth_set_keygen := LoadLibCryptoFunction('EVP_PKEY_meth_set_keygen');
  if not assigned(EVP_PKEY_meth_set_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_keygen');
  EVP_PKEY_meth_set_keygen(pmeth, keygen_init, keygen);
end;

procedure Load_EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; sign_init: TFuncType084; sign: TFuncType085); cdecl;
begin
  EVP_PKEY_meth_set_sign := LoadLibCryptoFunction('EVP_PKEY_meth_set_sign');
  if not assigned(EVP_PKEY_meth_set_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_sign');
  EVP_PKEY_meth_set_sign(pmeth, sign_init, sign);
end;

procedure Load_EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; verify_init: TFuncType086; verify: TFuncType087); cdecl;
begin
  EVP_PKEY_meth_set_verify := LoadLibCryptoFunction('EVP_PKEY_meth_set_verify');
  if not assigned(EVP_PKEY_meth_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verify');
  EVP_PKEY_meth_set_verify(pmeth, verify_init, verify);
end;

procedure Load_EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; verify_recover_init: TFuncType088; verify_recover: TFuncType089); cdecl;
begin
  EVP_PKEY_meth_set_verify_recover := LoadLibCryptoFunction('EVP_PKEY_meth_set_verify_recover');
  if not assigned(EVP_PKEY_meth_set_verify_recover) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verify_recover');
  EVP_PKEY_meth_set_verify_recover(pmeth, verify_recover_init, verify_recover);
end;

procedure Load_EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; signctx_init: TFuncType090; signctx: TFuncType091); cdecl;
begin
  EVP_PKEY_meth_set_signctx := LoadLibCryptoFunction('EVP_PKEY_meth_set_signctx');
  if not assigned(EVP_PKEY_meth_set_signctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_signctx');
  EVP_PKEY_meth_set_signctx(pmeth, signctx_init, signctx);
end;

procedure Load_EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; verifyctx_init: TFuncType092; verifyctx: TFuncType093); cdecl;
begin
  EVP_PKEY_meth_set_verifyctx := LoadLibCryptoFunction('EVP_PKEY_meth_set_verifyctx');
  if not assigned(EVP_PKEY_meth_set_verifyctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verifyctx');
  EVP_PKEY_meth_set_verifyctx(pmeth, verifyctx_init, verifyctx);
end;

procedure Load_EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; encrypt_init: TFuncType094; encryptfn: TFuncType095); cdecl;
begin
  EVP_PKEY_meth_set_encrypt := LoadLibCryptoFunction('EVP_PKEY_meth_set_encrypt');
  if not assigned(EVP_PKEY_meth_set_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_encrypt');
  EVP_PKEY_meth_set_encrypt(pmeth, encrypt_init, encryptfn);
end;

procedure Load_EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; decrypt_init: TFuncType096; decrypt: TFuncType097); cdecl;
begin
  EVP_PKEY_meth_set_decrypt := LoadLibCryptoFunction('EVP_PKEY_meth_set_decrypt');
  if not assigned(EVP_PKEY_meth_set_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_decrypt');
  EVP_PKEY_meth_set_decrypt(pmeth, decrypt_init, decrypt);
end;

procedure Load_EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; derive_init: TFuncType098; derive: TFuncType099); cdecl;
begin
  EVP_PKEY_meth_set_derive := LoadLibCryptoFunction('EVP_PKEY_meth_set_derive');
  if not assigned(EVP_PKEY_meth_set_derive) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_derive');
  EVP_PKEY_meth_set_derive(pmeth, derive_init, derive);
end;

procedure Load_EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; ctrl: TFuncType100; ctrl_str: TFuncType101); cdecl;
begin
  EVP_PKEY_meth_set_ctrl := LoadLibCryptoFunction('EVP_PKEY_meth_set_ctrl');
  if not assigned(EVP_PKEY_meth_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_ctrl');
  EVP_PKEY_meth_set_ctrl(pmeth, ctrl, ctrl_str);
end;

procedure Load_EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType102); cdecl;
begin
  EVP_PKEY_meth_set_digestsign := LoadLibCryptoFunction('EVP_PKEY_meth_set_digestsign');
  if not assigned(EVP_PKEY_meth_set_digestsign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digestsign');
  EVP_PKEY_meth_set_digestsign(pmeth, digestsign);
end;

procedure Load_EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType103); cdecl;
begin
  EVP_PKEY_meth_set_digestverify := LoadLibCryptoFunction('EVP_PKEY_meth_set_digestverify');
  if not assigned(EVP_PKEY_meth_set_digestverify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digestverify');
  EVP_PKEY_meth_set_digestverify(pmeth, digestverify);
end;

procedure Load_EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType104); cdecl;
begin
  EVP_PKEY_meth_set_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_check');
  if not assigned(EVP_PKEY_meth_set_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_check');
  EVP_PKEY_meth_set_check(pmeth, check);
end;

procedure Load_EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType105); cdecl;
begin
  EVP_PKEY_meth_set_public_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_public_check');
  if not assigned(EVP_PKEY_meth_set_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_public_check');
  EVP_PKEY_meth_set_public_check(pmeth, check);
end;

procedure Load_EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; check: TFuncType106); cdecl;
begin
  EVP_PKEY_meth_set_param_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_param_check');
  if not assigned(EVP_PKEY_meth_set_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_param_check');
  EVP_PKEY_meth_set_param_check(pmeth, check);
end;

procedure Load_EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; digest_custom: TFuncType107); cdecl;
begin
  EVP_PKEY_meth_set_digest_custom := LoadLibCryptoFunction('EVP_PKEY_meth_set_digest_custom');
  if not assigned(EVP_PKEY_meth_set_digest_custom) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digest_custom');
  EVP_PKEY_meth_set_digest_custom(pmeth, digest_custom);
end;

procedure Load_EVP_PKEY_meth_get_init(pmeth: PEVP_PKEY_METHOD; pinit: TFuncType108); cdecl;
begin
  EVP_PKEY_meth_get_init := LoadLibCryptoFunction('EVP_PKEY_meth_get_init');
  if not assigned(EVP_PKEY_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_init');
  EVP_PKEY_meth_get_init(pmeth, pinit);
end;

procedure Load_EVP_PKEY_meth_get_copy(pmeth: PEVP_PKEY_METHOD; pcopy: TFuncType109); cdecl;
begin
  EVP_PKEY_meth_get_copy := LoadLibCryptoFunction('EVP_PKEY_meth_get_copy');
  if not assigned(EVP_PKEY_meth_get_copy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_copy');
  EVP_PKEY_meth_get_copy(pmeth, pcopy);
end;

procedure Load_EVP_PKEY_meth_get_cleanup(pmeth: PEVP_PKEY_METHOD; pcleanup: TFuncType110); cdecl;
begin
  EVP_PKEY_meth_get_cleanup := LoadLibCryptoFunction('EVP_PKEY_meth_get_cleanup');
  if not assigned(EVP_PKEY_meth_get_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_cleanup');
  EVP_PKEY_meth_get_cleanup(pmeth, pcleanup);
end;

procedure Load_EVP_PKEY_meth_get_paramgen(pmeth: PEVP_PKEY_METHOD; pparamgen_init: TFuncType111; pparamgen: TFuncType112); cdecl;
begin
  EVP_PKEY_meth_get_paramgen := LoadLibCryptoFunction('EVP_PKEY_meth_get_paramgen');
  if not assigned(EVP_PKEY_meth_get_paramgen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_paramgen');
  EVP_PKEY_meth_get_paramgen(pmeth, pparamgen_init, pparamgen);
end;

procedure Load_EVP_PKEY_meth_get_keygen(pmeth: PEVP_PKEY_METHOD; pkeygen_init: TFuncType113; pkeygen: TFuncType114); cdecl;
begin
  EVP_PKEY_meth_get_keygen := LoadLibCryptoFunction('EVP_PKEY_meth_get_keygen');
  if not assigned(EVP_PKEY_meth_get_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_keygen');
  EVP_PKEY_meth_get_keygen(pmeth, pkeygen_init, pkeygen);
end;

procedure Load_EVP_PKEY_meth_get_sign(pmeth: PEVP_PKEY_METHOD; psign_init: TFuncType115; psign: TFuncType116); cdecl;
begin
  EVP_PKEY_meth_get_sign := LoadLibCryptoFunction('EVP_PKEY_meth_get_sign');
  if not assigned(EVP_PKEY_meth_get_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_sign');
  EVP_PKEY_meth_get_sign(pmeth, psign_init, psign);
end;

procedure Load_EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; pverify_init: TFuncType117; pverify: TFuncType118); cdecl;
begin
  EVP_PKEY_meth_get_verify := LoadLibCryptoFunction('EVP_PKEY_meth_get_verify');
  if not assigned(EVP_PKEY_meth_get_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verify');
  EVP_PKEY_meth_get_verify(pmeth, pverify_init, pverify);
end;

procedure Load_EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; pverify_recover_init: TFuncType119; pverify_recover: TFuncType120); cdecl;
begin
  EVP_PKEY_meth_get_verify_recover := LoadLibCryptoFunction('EVP_PKEY_meth_get_verify_recover');
  if not assigned(EVP_PKEY_meth_get_verify_recover) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verify_recover');
  EVP_PKEY_meth_get_verify_recover(pmeth, pverify_recover_init, pverify_recover);
end;

procedure Load_EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; psignctx_init: TFuncType121; psignctx: TFuncType122); cdecl;
begin
  EVP_PKEY_meth_get_signctx := LoadLibCryptoFunction('EVP_PKEY_meth_get_signctx');
  if not assigned(EVP_PKEY_meth_get_signctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_signctx');
  EVP_PKEY_meth_get_signctx(pmeth, psignctx_init, psignctx);
end;

procedure Load_EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; pverifyctx_init: TFuncType123; pverifyctx: TFuncType124); cdecl;
begin
  EVP_PKEY_meth_get_verifyctx := LoadLibCryptoFunction('EVP_PKEY_meth_get_verifyctx');
  if not assigned(EVP_PKEY_meth_get_verifyctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verifyctx');
  EVP_PKEY_meth_get_verifyctx(pmeth, pverifyctx_init, pverifyctx);
end;

procedure Load_EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; pencrypt_init: TFuncType125; pencryptfn: TFuncType126); cdecl;
begin
  EVP_PKEY_meth_get_encrypt := LoadLibCryptoFunction('EVP_PKEY_meth_get_encrypt');
  if not assigned(EVP_PKEY_meth_get_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_encrypt');
  EVP_PKEY_meth_get_encrypt(pmeth, pencrypt_init, pencryptfn);
end;

procedure Load_EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; pdecrypt_init: TFuncType127; pdecrypt: TFuncType128); cdecl;
begin
  EVP_PKEY_meth_get_decrypt := LoadLibCryptoFunction('EVP_PKEY_meth_get_decrypt');
  if not assigned(EVP_PKEY_meth_get_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_decrypt');
  EVP_PKEY_meth_get_decrypt(pmeth, pdecrypt_init, pdecrypt);
end;

procedure Load_EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; pderive_init: TFuncType129; pderive: TFuncType130); cdecl;
begin
  EVP_PKEY_meth_get_derive := LoadLibCryptoFunction('EVP_PKEY_meth_get_derive');
  if not assigned(EVP_PKEY_meth_get_derive) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_derive');
  EVP_PKEY_meth_get_derive(pmeth, pderive_init, pderive);
end;

procedure Load_EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; pctrl: TFuncType131; pctrl_str: TFuncType132); cdecl;
begin
  EVP_PKEY_meth_get_ctrl := LoadLibCryptoFunction('EVP_PKEY_meth_get_ctrl');
  if not assigned(EVP_PKEY_meth_get_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_ctrl');
  EVP_PKEY_meth_get_ctrl(pmeth, pctrl, pctrl_str);
end;

procedure Load_EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; digestsign: TFuncType133); cdecl;
begin
  EVP_PKEY_meth_get_digestsign := LoadLibCryptoFunction('EVP_PKEY_meth_get_digestsign');
  if not assigned(EVP_PKEY_meth_get_digestsign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digestsign');
  EVP_PKEY_meth_get_digestsign(pmeth, digestsign);
end;

procedure Load_EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; digestverify: TFuncType134); cdecl;
begin
  EVP_PKEY_meth_get_digestverify := LoadLibCryptoFunction('EVP_PKEY_meth_get_digestverify');
  if not assigned(EVP_PKEY_meth_get_digestverify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digestverify');
  EVP_PKEY_meth_get_digestverify(pmeth, digestverify);
end;

procedure Load_EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType135); cdecl;
begin
  EVP_PKEY_meth_get_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_check');
  if not assigned(EVP_PKEY_meth_get_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_check');
  EVP_PKEY_meth_get_check(pmeth, pcheck);
end;

procedure Load_EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType136); cdecl;
begin
  EVP_PKEY_meth_get_public_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_public_check');
  if not assigned(EVP_PKEY_meth_get_public_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_public_check');
  EVP_PKEY_meth_get_public_check(pmeth, pcheck);
end;

procedure Load_EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; pcheck: TFuncType137); cdecl;
begin
  EVP_PKEY_meth_get_param_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_param_check');
  if not assigned(EVP_PKEY_meth_get_param_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_param_check');
  EVP_PKEY_meth_get_param_check(pmeth, pcheck);
end;

procedure Load_EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; pdigest_custom: TFuncType138); cdecl;
begin
  EVP_PKEY_meth_get_digest_custom := LoadLibCryptoFunction('EVP_PKEY_meth_get_digest_custom');
  if not assigned(EVP_PKEY_meth_get_digest_custom) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digest_custom');
  EVP_PKEY_meth_get_digest_custom(pmeth, pdigest_custom);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load_EVP_KEYEXCH_free(exchange: PEVP_KEYEXCH); cdecl;
begin
  EVP_KEYEXCH_free := LoadLibCryptoFunction('EVP_KEYEXCH_free');
  if not assigned(EVP_KEYEXCH_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_free');
  EVP_KEYEXCH_free(exchange);
end;

function Load_EVP_KEYEXCH_up_ref(exchange: PEVP_KEYEXCH): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEYEXCH_up_ref := LoadLibCryptoFunction('EVP_KEYEXCH_up_ref');
  if not assigned(EVP_KEYEXCH_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_up_ref');
  Result := EVP_KEYEXCH_up_ref(exchange);
end;

function Load_EVP_KEYEXCH_fetch(ctx: POSSL_LIB_CTX; algorithm: PAnsiChar; properties: PAnsiChar): PEVP_KEYEXCH; cdecl;
begin
  EVP_KEYEXCH_fetch := LoadLibCryptoFunction('EVP_KEYEXCH_fetch');
  if not assigned(EVP_KEYEXCH_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_fetch');
  Result := EVP_KEYEXCH_fetch(ctx, algorithm, properties);
end;

function Load_EVP_KEYEXCH_get0_provider(exchange: PEVP_KEYEXCH): POSSL_PROVIDER; cdecl;
begin
  EVP_KEYEXCH_get0_provider := LoadLibCryptoFunction('EVP_KEYEXCH_get0_provider');
  if not assigned(EVP_KEYEXCH_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_get0_provider');
  Result := EVP_KEYEXCH_get0_provider(exchange);
end;

function Load_EVP_KEYEXCH_is_a(keyexch: PEVP_KEYEXCH; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEYEXCH_is_a := LoadLibCryptoFunction('EVP_KEYEXCH_is_a');
  if not assigned(EVP_KEYEXCH_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_is_a');
  Result := EVP_KEYEXCH_is_a(keyexch, name);
end;

function Load_EVP_KEYEXCH_get0_name(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl;
begin
  EVP_KEYEXCH_get0_name := LoadLibCryptoFunction('EVP_KEYEXCH_get0_name');
  if not assigned(EVP_KEYEXCH_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_get0_name');
  Result := EVP_KEYEXCH_get0_name(keyexch);
end;

function Load_EVP_KEYEXCH_get0_description(keyexch: PEVP_KEYEXCH): PAnsiChar; cdecl;
begin
  EVP_KEYEXCH_get0_description := LoadLibCryptoFunction('EVP_KEYEXCH_get0_description');
  if not assigned(EVP_KEYEXCH_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_get0_description');
  Result := EVP_KEYEXCH_get0_description(keyexch);
end;

procedure Load_EVP_KEYEXCH_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType139; data: pointer); cdecl;
begin
  EVP_KEYEXCH_do_all_provided := LoadLibCryptoFunction('EVP_KEYEXCH_do_all_provided');
  if not assigned(EVP_KEYEXCH_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_do_all_provided');
  EVP_KEYEXCH_do_all_provided(libctx, fn, data);
end;

function Load_EVP_KEYEXCH_names_do_all(keyexch: PEVP_KEYEXCH; fn: TFuncType140; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_KEYEXCH_names_do_all := LoadLibCryptoFunction('EVP_KEYEXCH_names_do_all');
  if not assigned(EVP_KEYEXCH_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_names_do_all');
  Result := EVP_KEYEXCH_names_do_all(keyexch, fn, data);
end;

function Load_EVP_KEYEXCH_gettable_ctx_params(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl;
begin
  EVP_KEYEXCH_gettable_ctx_params := LoadLibCryptoFunction('EVP_KEYEXCH_gettable_ctx_params');
  if not assigned(EVP_KEYEXCH_gettable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_gettable_ctx_params');
  Result := EVP_KEYEXCH_gettable_ctx_params(keyexch);
end;

function Load_EVP_KEYEXCH_settable_ctx_params(keyexch: PEVP_KEYEXCH): POSSL_PARAM; cdecl;
begin
  EVP_KEYEXCH_settable_ctx_params := LoadLibCryptoFunction('EVP_KEYEXCH_settable_ctx_params');
  if not assigned(EVP_KEYEXCH_settable_ctx_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_KEYEXCH_settable_ctx_params');
  Result := EVP_KEYEXCH_settable_ctx_params(keyexch);
end;

procedure Load_EVP_add_alg_module; cdecl;
begin
  EVP_add_alg_module := LoadLibCryptoFunction('EVP_add_alg_module');
  if not assigned(EVP_add_alg_module) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_alg_module');
  EVP_add_alg_module;
end;

function Load_EVP_PKEY_CTX_set_group_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_group_name := LoadLibCryptoFunction('EVP_PKEY_CTX_set_group_name');
  if not assigned(EVP_PKEY_CTX_set_group_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_group_name');
  Result := EVP_PKEY_CTX_set_group_name(ctx, name);
end;

function Load_EVP_PKEY_CTX_get_group_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_group_name := LoadLibCryptoFunction('EVP_PKEY_CTX_get_group_name');
  if not assigned(EVP_PKEY_CTX_get_group_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_group_name');
  Result := EVP_PKEY_CTX_get_group_name(ctx, name, namelen);
end;

function Load_EVP_PKEY_get_group_name(pkey: PEVP_PKEY; name: PAnsiChar; name_sz: TOpenSSL_C_SIZET; gname_len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_get_group_name := LoadLibCryptoFunction('EVP_PKEY_get_group_name');
  if not assigned(EVP_PKEY_get_group_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_group_name');
  Result := EVP_PKEY_get_group_name(pkey, name, name_sz, gname_len);
end;

function Load_EVP_PKEY_CTX_get0_libctx(ctx: PEVP_PKEY_CTX): POSSL_LIB_CTX; cdecl;
begin
  EVP_PKEY_CTX_get0_libctx := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_libctx');
  if not assigned(EVP_PKEY_CTX_get0_libctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_libctx');
  Result := EVP_PKEY_CTX_get0_libctx(ctx);
end;

function Load_EVP_PKEY_CTX_get0_propq(ctx: PEVP_PKEY_CTX): PAnsiChar; cdecl;
begin
  EVP_PKEY_CTX_get0_propq := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_propq');
  if not assigned(EVP_PKEY_CTX_get0_propq) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_propq');
  Result := EVP_PKEY_CTX_get0_propq(ctx);
end;

function Load_EVP_PKEY_CTX_get0_provider(ctx: PEVP_PKEY_CTX): POSSL_PROVIDER; cdecl;
begin
  EVP_PKEY_CTX_get0_provider := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_provider');
  if not assigned(EVP_PKEY_CTX_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_provider');
  Result := EVP_PKEY_CTX_get0_provider(ctx);
end;

function Load_EVP_SKEY_is_a(skey: PEVP_SKEY; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_SKEY_is_a := LoadLibCryptoFunction('EVP_SKEY_is_a');
  if not assigned(EVP_SKEY_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_is_a');
  Result := EVP_SKEY_is_a(skey, name);
end;

function Load_EVP_SKEY_import(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl;
begin
  EVP_SKEY_import := LoadLibCryptoFunction('EVP_SKEY_import');
  if not assigned(EVP_SKEY_import) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_import');
  Result := EVP_SKEY_import(libctx, skeymgmtname, propquery, selection, params);
end;

function Load_EVP_SKEY_generate(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; propquery: PAnsiChar; params: POSSL_PARAM): PEVP_SKEY; cdecl;
begin
  EVP_SKEY_generate := LoadLibCryptoFunction('EVP_SKEY_generate');
  if not assigned(EVP_SKEY_generate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_generate');
  Result := EVP_SKEY_generate(libctx, skeymgmtname, propquery, params);
end;

function Load_EVP_SKEY_import_raw_key(libctx: POSSL_LIB_CTX; skeymgmtname: PAnsiChar; key: Pbyte; keylen: TOpenSSL_C_SIZET; propquery: PAnsiChar): PEVP_SKEY; cdecl;
begin
  EVP_SKEY_import_raw_key := LoadLibCryptoFunction('EVP_SKEY_import_raw_key');
  if not assigned(EVP_SKEY_import_raw_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_import_raw_key');
  Result := EVP_SKEY_import_raw_key(libctx, skeymgmtname, key, keylen, propquery);
end;

function Load_EVP_SKEY_import_SKEYMGMT(libctx: POSSL_LIB_CTX; skeymgmt: PEVP_SKEYMGMT; selection: TOpenSSL_C_INT; params: POSSL_PARAM): PEVP_SKEY; cdecl;
begin
  EVP_SKEY_import_SKEYMGMT := LoadLibCryptoFunction('EVP_SKEY_import_SKEYMGMT');
  if not assigned(EVP_SKEY_import_SKEYMGMT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_import_SKEYMGMT');
  Result := EVP_SKEY_import_SKEYMGMT(libctx, skeymgmt, selection, params);
end;

function Load_EVP_SKEY_get0_raw_key(skey: PEVP_SKEY; key: PPbyte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_SKEY_get0_raw_key := LoadLibCryptoFunction('EVP_SKEY_get0_raw_key');
  if not assigned(EVP_SKEY_get0_raw_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_get0_raw_key');
  Result := EVP_SKEY_get0_raw_key(skey, key, len);
end;

function Load_EVP_SKEY_get0_key_id(skey: PEVP_SKEY): PAnsiChar; cdecl;
begin
  EVP_SKEY_get0_key_id := LoadLibCryptoFunction('EVP_SKEY_get0_key_id');
  if not assigned(EVP_SKEY_get0_key_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_get0_key_id');
  Result := EVP_SKEY_get0_key_id(skey);
end;

function Load_EVP_SKEY_export(skey: PEVP_SKEY; selection: TOpenSSL_C_INT; export_cb: POSSL_CALLBACK; export_cbarg: pointer): TOpenSSL_C_INT; cdecl;
begin
  EVP_SKEY_export := LoadLibCryptoFunction('EVP_SKEY_export');
  if not assigned(EVP_SKEY_export) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_export');
  Result := EVP_SKEY_export(skey, selection, export_cb, export_cbarg);
end;

function Load_EVP_SKEY_up_ref(skey: PEVP_SKEY): TOpenSSL_C_INT; cdecl;
begin
  EVP_SKEY_up_ref := LoadLibCryptoFunction('EVP_SKEY_up_ref');
  if not assigned(EVP_SKEY_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_up_ref');
  Result := EVP_SKEY_up_ref(skey);
end;

procedure Load_EVP_SKEY_free(skey: PEVP_SKEY); cdecl;
begin
  EVP_SKEY_free := LoadLibCryptoFunction('EVP_SKEY_free');
  if not assigned(EVP_SKEY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_free');
  EVP_SKEY_free(skey);
end;

function Load_EVP_SKEY_get0_skeymgmt_name(skey: PEVP_SKEY): PAnsiChar; cdecl;
begin
  EVP_SKEY_get0_skeymgmt_name := LoadLibCryptoFunction('EVP_SKEY_get0_skeymgmt_name');
  if not assigned(EVP_SKEY_get0_skeymgmt_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_get0_skeymgmt_name');
  Result := EVP_SKEY_get0_skeymgmt_name(skey);
end;

function Load_EVP_SKEY_get0_provider_name(skey: PEVP_SKEY): PAnsiChar; cdecl;
begin
  EVP_SKEY_get0_provider_name := LoadLibCryptoFunction('EVP_SKEY_get0_provider_name');
  if not assigned(EVP_SKEY_get0_provider_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_get0_provider_name');
  Result := EVP_SKEY_get0_provider_name(skey);
end;

function Load_EVP_SKEY_to_provider(skey: PEVP_SKEY; libctx: POSSL_LIB_CTX; prov: POSSL_PROVIDER; propquery: PAnsiChar): PEVP_SKEY; cdecl;
begin
  EVP_SKEY_to_provider := LoadLibCryptoFunction('EVP_SKEY_to_provider');
  if not assigned(EVP_SKEY_to_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SKEY_to_provider');
  Result := EVP_SKEY_to_provider(skey, libctx, prov, propquery);
end;

procedure Load;
begin
{$ifndef  EVP_MD}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { EVP_MD}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifdef CONST_STRICT}
{$endif} {CONST_STRICT}
{$ifndef  OPENSSL_NO_MD2}
{$endif} { OPENSSL_NO_MD2}
{$ifndef  OPENSSL_NO_MD4}
{$endif} { OPENSSL_NO_MD4}
{$ifndef  OPENSSL_NO_MD5}
{$endif} { OPENSSL_NO_MD5}
{$ifndef  OPENSSL_NO_BLAKE2}
{$endif} { OPENSSL_NO_BLAKE2}
{$ifndef  OPENSSL_NO_MDC2}
{$endif} { OPENSSL_NO_MDC2}
{$ifndef  OPENSSL_NO_RMD160}
{$endif} { OPENSSL_NO_RMD160}
{$ifndef  OPENSSL_NO_WHIRLPOOL}
{$endif} { OPENSSL_NO_WHIRLPOOL}
{$ifndef  OPENSSL_NO_SM3}
{$endif} { OPENSSL_NO_SM3}
{$ifndef  OPENSSL_NO_DES}
{$endif} { OPENSSL_NO_DES}
{$ifndef  OPENSSL_NO_RC4}
    {$ifndef  OPENSSL_NO_MD5}
    {$endif} { OPENSSL_NO_MD5}
{$endif} { OPENSSL_NO_RC4}
{$ifndef  OPENSSL_NO_IDEA}
{$endif} { OPENSSL_NO_IDEA}
{$ifndef  OPENSSL_NO_RC2}
{$endif} { OPENSSL_NO_RC2}
{$ifndef  OPENSSL_NO_BF}
{$endif} { OPENSSL_NO_BF}
{$ifndef  OPENSSL_NO_CAST}
{$endif} { OPENSSL_NO_CAST}
{$ifndef  OPENSSL_NO_RC5}
{$endif} { OPENSSL_NO_RC5}
{$ifndef  OPENSSL_NO_OCB}
{$endif} { OPENSSL_NO_OCB}
{$ifndef  OPENSSL_NO_OCB}
{$endif} { OPENSSL_NO_OCB}
{$ifndef  OPENSSL_NO_OCB}
{$endif} { OPENSSL_NO_OCB}
{$ifndef  OPENSSL_NO_ARIA}
{$endif} { OPENSSL_NO_ARIA}
{$ifndef  OPENSSL_NO_CAMELLIA}
{$endif} { OPENSSL_NO_CAMELLIA}
{$ifndef  OPENSSL_NO_CHACHA}
    {$ifndef  OPENSSL_NO_POLY1305}
    {$endif} { OPENSSL_NO_POLY1305}
{$endif} { OPENSSL_NO_CHACHA}
{$ifndef  OPENSSL_NO_SEED}
{$endif} { OPENSSL_NO_SEED}
{$ifndef  OPENSSL_NO_SM4}
{$endif} { OPENSSL_NO_SM4}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_ENGINE}
    {$endif} { OPENSSL_NO_ENGINE}
    {$ifndef  OPENSSL_NO_POLY1305}
    {$endif} { OPENSSL_NO_POLY1305}
    {$ifndef  OPENSSL_NO_SIPHASH}
    {$endif} { OPENSSL_NO_SIPHASH}
    {$ifndef  OPENSSL_NO_DSA}
    {$endif} { OPENSSL_NO_DSA}
    {$ifndef  OPENSSL_NO_DH}
    {$endif} { OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_EC}
    {$endif} { OPENSSL_NO_EC}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_STDIO}
{$endif} { OPENSSL_NO_STDIO}
{$ifndef  OPENSSL_NO_SCRYPT}
{$endif} { OPENSSL_NO_SCRYPT}
{$ifndef  OPENSSL_NO_DEPRECATED_3_6}
{$endif} { OPENSSL_NO_DEPRECATED_3_6}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_Q_keygen := LoadLibCryptoFunction('EVP_PKEY_Q_keygen');
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
end;

procedure Unload;
begin
  EVP_set_default_properties := Load_EVP_set_default_properties;
  EVP_get1_default_properties := Load_EVP_get1_default_properties;
  EVP_default_properties_is_fips_enabled := Load_EVP_default_properties_is_fips_enabled;
  EVP_default_properties_enable_fips := Load_EVP_default_properties_enable_fips;
{$ifndef  EVP_MD}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_MD_meth_new := Load_EVP_MD_meth_new;
  EVP_MD_meth_dup := Load_EVP_MD_meth_dup;
  EVP_MD_meth_free := Load_EVP_MD_meth_free;
  EVP_MD_meth_set_input_blocksize := Load_EVP_MD_meth_set_input_blocksize;
  EVP_MD_meth_set_result_size := Load_EVP_MD_meth_set_result_size;
  EVP_MD_meth_set_app_datasize := Load_EVP_MD_meth_set_app_datasize;
  EVP_MD_meth_set_flags := Load_EVP_MD_meth_set_flags;
  EVP_MD_meth_set_init := Load_EVP_MD_meth_set_init;
  EVP_MD_meth_set_update := Load_EVP_MD_meth_set_update;
  EVP_MD_meth_set_final := Load_EVP_MD_meth_set_final;
  EVP_MD_meth_set_copy := Load_EVP_MD_meth_set_copy;
  EVP_MD_meth_set_cleanup := Load_EVP_MD_meth_set_cleanup;
  EVP_MD_meth_set_ctrl := Load_EVP_MD_meth_set_ctrl;
  EVP_MD_meth_get_input_blocksize := Load_EVP_MD_meth_get_input_blocksize;
  EVP_MD_meth_get_result_size := Load_EVP_MD_meth_get_result_size;
  EVP_MD_meth_get_app_datasize := Load_EVP_MD_meth_get_app_datasize;
  EVP_MD_meth_get_flags := Load_EVP_MD_meth_get_flags;
  EVP_MD_meth_get_init := Load_EVP_MD_meth_get_init;
  EVP_MD_meth_get_update := Load_EVP_MD_meth_get_update;
  EVP_MD_meth_get_final := Load_EVP_MD_meth_get_final;
  EVP_MD_meth_get_copy := Load_EVP_MD_meth_get_copy;
  EVP_MD_meth_get_cleanup := Load_EVP_MD_meth_get_cleanup;
  EVP_MD_meth_get_ctrl := Load_EVP_MD_meth_get_ctrl;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { EVP_MD}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_CIPHER_meth_new := Load_EVP_CIPHER_meth_new;
  EVP_CIPHER_meth_dup := Load_EVP_CIPHER_meth_dup;
  EVP_CIPHER_meth_free := Load_EVP_CIPHER_meth_free;
  EVP_CIPHER_meth_set_iv_length := Load_EVP_CIPHER_meth_set_iv_length;
  EVP_CIPHER_meth_set_flags := Load_EVP_CIPHER_meth_set_flags;
  EVP_CIPHER_meth_set_impl_ctx_size := Load_EVP_CIPHER_meth_set_impl_ctx_size;
  EVP_CIPHER_meth_set_init := Load_EVP_CIPHER_meth_set_init;
  EVP_CIPHER_meth_set_do_cipher := Load_EVP_CIPHER_meth_set_do_cipher;
  EVP_CIPHER_meth_set_cleanup := Load_EVP_CIPHER_meth_set_cleanup;
  EVP_CIPHER_meth_set_set_asn1_params := Load_EVP_CIPHER_meth_set_set_asn1_params;
  EVP_CIPHER_meth_set_get_asn1_params := Load_EVP_CIPHER_meth_set_get_asn1_params;
  EVP_CIPHER_meth_set_ctrl := Load_EVP_CIPHER_meth_set_ctrl;
  EVP_CIPHER_meth_get_init := Load_EVP_CIPHER_meth_get_init;
  EVP_CIPHER_meth_get_do_cipher := Load_EVP_CIPHER_meth_get_do_cipher;
  EVP_CIPHER_meth_get_cleanup := Load_EVP_CIPHER_meth_get_cleanup;
  EVP_CIPHER_meth_get_set_asn1_params := Load_EVP_CIPHER_meth_get_set_asn1_params;
  EVP_CIPHER_meth_get_get_asn1_params := Load_EVP_CIPHER_meth_get_get_asn1_params;
  EVP_CIPHER_meth_get_ctrl := Load_EVP_CIPHER_meth_get_ctrl;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_Cipher := Load_EVP_Cipher;
  EVP_MD_get_type := Load_EVP_MD_get_type;
  EVP_MD_type := Load_EVP_MD_type;
  EVP_MD_nid := Load_EVP_MD_nid;
  EVP_MD_get0_name := Load_EVP_MD_get0_name;
  EVP_MD_name := Load_EVP_MD_name;
  EVP_MD_get0_description := Load_EVP_MD_get0_description;
  EVP_MD_is_a := Load_EVP_MD_is_a;
  EVP_MD_names_do_all := Load_EVP_MD_names_do_all;
  EVP_MD_get0_provider := Load_EVP_MD_get0_provider;
  EVP_MD_get_pkey_type := Load_EVP_MD_get_pkey_type;
  EVP_MD_pkey_type := Load_EVP_MD_pkey_type;
  EVP_MD_get_size := Load_EVP_MD_get_size;
  EVP_MD_size := Load_EVP_MD_size;
  EVP_MD_get_block_size := Load_EVP_MD_get_block_size;
  EVP_MD_block_size := Load_EVP_MD_block_size;
  EVP_MD_get_flags := Load_EVP_MD_get_flags;
  EVP_MD_flags := Load_EVP_MD_flags;
  EVP_MD_xof := Load_EVP_MD_xof;
  EVP_MD_CTX_get0_md := Load_EVP_MD_CTX_get0_md;
  EVP_MD_CTX_get1_md := Load_EVP_MD_CTX_get1_md;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_MD_CTX_md := Load_EVP_MD_CTX_md;
  EVP_MD_CTX_update_fn := Load_EVP_MD_CTX_update_fn;
  EVP_MD_CTX_set_update_fn := Load_EVP_MD_CTX_set_update_fn;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_MD_CTX_get_size_ex := Load_EVP_MD_CTX_get_size_ex;
  EVP_MD_CTX_size := Load_EVP_MD_CTX_size;
  EVP_MD_CTX_get_pkey_ctx := Load_EVP_MD_CTX_get_pkey_ctx;
  EVP_MD_CTX_pkey_ctx := Load_EVP_MD_CTX_pkey_ctx;
  EVP_MD_CTX_set_pkey_ctx := Load_EVP_MD_CTX_set_pkey_ctx;
  EVP_MD_CTX_get0_md_data := Load_EVP_MD_CTX_get0_md_data;
  EVP_MD_CTX_md_data := Load_EVP_MD_CTX_md_data;
  EVP_CIPHER_get_nid := Load_EVP_CIPHER_get_nid;
  EVP_CIPHER_nid := Load_EVP_CIPHER_nid;
  EVP_CIPHER_get0_name := Load_EVP_CIPHER_get0_name;
  EVP_CIPHER_name := Load_EVP_CIPHER_name;
  EVP_CIPHER_get0_description := Load_EVP_CIPHER_get0_description;
  EVP_CIPHER_is_a := Load_EVP_CIPHER_is_a;
  EVP_CIPHER_names_do_all := Load_EVP_CIPHER_names_do_all;
  EVP_CIPHER_get0_provider := Load_EVP_CIPHER_get0_provider;
  EVP_CIPHER_get_block_size := Load_EVP_CIPHER_get_block_size;
  EVP_CIPHER_block_size := Load_EVP_CIPHER_block_size;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_CIPHER_impl_ctx_size := Load_EVP_CIPHER_impl_ctx_size;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_CIPHER_get_key_length := Load_EVP_CIPHER_get_key_length;
  EVP_CIPHER_key_length := Load_EVP_CIPHER_key_length;
  EVP_CIPHER_get_iv_length := Load_EVP_CIPHER_get_iv_length;
  EVP_CIPHER_iv_length := Load_EVP_CIPHER_iv_length;
  EVP_CIPHER_get_flags := Load_EVP_CIPHER_get_flags;
  EVP_CIPHER_flags := Load_EVP_CIPHER_flags;
  EVP_CIPHER_get_mode := Load_EVP_CIPHER_get_mode;
  EVP_CIPHER_mode := Load_EVP_CIPHER_mode;
  EVP_CIPHER_get_type := Load_EVP_CIPHER_get_type;
  EVP_CIPHER_type := Load_EVP_CIPHER_type;
  EVP_CIPHER_fetch := Load_EVP_CIPHER_fetch;
  EVP_CIPHER_can_pipeline := Load_EVP_CIPHER_can_pipeline;
  EVP_CIPHER_up_ref := Load_EVP_CIPHER_up_ref;
  EVP_CIPHER_free := Load_EVP_CIPHER_free;
  EVP_CIPHER_CTX_get0_cipher := Load_EVP_CIPHER_CTX_get0_cipher;
  EVP_CIPHER_CTX_get1_cipher := Load_EVP_CIPHER_CTX_get1_cipher;
  EVP_CIPHER_CTX_is_encrypting := Load_EVP_CIPHER_CTX_is_encrypting;
  EVP_CIPHER_CTX_encrypting := Load_EVP_CIPHER_CTX_encrypting;
  EVP_CIPHER_CTX_get_nid := Load_EVP_CIPHER_CTX_get_nid;
  EVP_CIPHER_CTX_nid := Load_EVP_CIPHER_CTX_nid;
  EVP_CIPHER_CTX_get_block_size := Load_EVP_CIPHER_CTX_get_block_size;
  EVP_CIPHER_CTX_block_size := Load_EVP_CIPHER_CTX_block_size;
  EVP_CIPHER_CTX_get_key_length := Load_EVP_CIPHER_CTX_get_key_length;
  EVP_CIPHER_CTX_key_length := Load_EVP_CIPHER_CTX_key_length;
  EVP_CIPHER_CTX_get_iv_length := Load_EVP_CIPHER_CTX_get_iv_length;
  EVP_CIPHER_CTX_iv_length := Load_EVP_CIPHER_CTX_iv_length;
  EVP_CIPHER_CTX_get_tag_length := Load_EVP_CIPHER_CTX_get_tag_length;
  EVP_CIPHER_CTX_tag_length := Load_EVP_CIPHER_CTX_tag_length;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_CIPHER_CTX_cipher := Load_EVP_CIPHER_CTX_cipher;
  EVP_CIPHER_CTX_iv := Load_EVP_CIPHER_CTX_iv;
  EVP_CIPHER_CTX_original_iv := Load_EVP_CIPHER_CTX_original_iv;
  EVP_CIPHER_CTX_iv_noconst := Load_EVP_CIPHER_CTX_iv_noconst;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_CIPHER_CTX_get_updated_iv := Load_EVP_CIPHER_CTX_get_updated_iv;
  EVP_CIPHER_CTX_get_original_iv := Load_EVP_CIPHER_CTX_get_original_iv;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_CIPHER_CTX_buf_noconst := Load_EVP_CIPHER_CTX_buf_noconst;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_CIPHER_CTX_get_num := Load_EVP_CIPHER_CTX_get_num;
  EVP_CIPHER_CTX_num := Load_EVP_CIPHER_CTX_num;
  EVP_CIPHER_CTX_set_num := Load_EVP_CIPHER_CTX_set_num;
  EVP_CIPHER_CTX_dup := Load_EVP_CIPHER_CTX_dup;
  EVP_CIPHER_CTX_copy := Load_EVP_CIPHER_CTX_copy;
  EVP_CIPHER_CTX_get_app_data := Load_EVP_CIPHER_CTX_get_app_data;
  EVP_CIPHER_CTX_set_app_data := Load_EVP_CIPHER_CTX_set_app_data;
  EVP_CIPHER_CTX_get_cipher_data := Load_EVP_CIPHER_CTX_get_cipher_data;
  EVP_CIPHER_CTX_set_cipher_data := Load_EVP_CIPHER_CTX_set_cipher_data;
{$ifdef CONST_STRICT}
  BIO_set_md := Load_BIO_set_md;
{$endif} {CONST_STRICT}
  EVP_MD_get_params := Load_EVP_MD_get_params;
  EVP_MD_CTX_set_params := Load_EVP_MD_CTX_set_params;
  EVP_MD_CTX_get_params := Load_EVP_MD_CTX_get_params;
  EVP_MD_gettable_params := Load_EVP_MD_gettable_params;
  EVP_MD_settable_ctx_params := Load_EVP_MD_settable_ctx_params;
  EVP_MD_gettable_ctx_params := Load_EVP_MD_gettable_ctx_params;
  EVP_MD_CTX_settable_params := Load_EVP_MD_CTX_settable_params;
  EVP_MD_CTX_gettable_params := Load_EVP_MD_CTX_gettable_params;
  EVP_MD_CTX_ctrl := Load_EVP_MD_CTX_ctrl;
  EVP_MD_CTX_new := Load_EVP_MD_CTX_new;
  EVP_MD_CTX_reset := Load_EVP_MD_CTX_reset;
  EVP_MD_CTX_free := Load_EVP_MD_CTX_free;
  EVP_MD_CTX_dup := Load_EVP_MD_CTX_dup;
  EVP_MD_CTX_copy_ex := Load_EVP_MD_CTX_copy_ex;
  EVP_MD_CTX_set_flags := Load_EVP_MD_CTX_set_flags;
  EVP_MD_CTX_clear_flags := Load_EVP_MD_CTX_clear_flags;
  EVP_MD_CTX_test_flags := Load_EVP_MD_CTX_test_flags;
  EVP_DigestInit_ex2 := Load_EVP_DigestInit_ex2;
  EVP_DigestInit_ex := Load_EVP_DigestInit_ex;
  EVP_DigestUpdate := Load_EVP_DigestUpdate;
  EVP_DigestFinal_ex := Load_EVP_DigestFinal_ex;
  EVP_Digest := Load_EVP_Digest;
  EVP_Q_digest := Load_EVP_Q_digest;
  EVP_MD_CTX_copy := Load_EVP_MD_CTX_copy;
  EVP_DigestInit := Load_EVP_DigestInit;
  EVP_DigestFinal := Load_EVP_DigestFinal;
  EVP_DigestFinalXOF := Load_EVP_DigestFinalXOF;
  EVP_DigestSqueeze := Load_EVP_DigestSqueeze;
  EVP_MD_fetch := Load_EVP_MD_fetch;
  EVP_MD_up_ref := Load_EVP_MD_up_ref;
  EVP_MD_free := Load_EVP_MD_free;
  EVP_read_pw_string := Load_EVP_read_pw_string;
  EVP_read_pw_string_min := Load_EVP_read_pw_string_min;
  EVP_set_pw_prompt := Load_EVP_set_pw_prompt;
  EVP_get_pw_prompt := Load_EVP_get_pw_prompt;
  EVP_BytesToKey := Load_EVP_BytesToKey;
  EVP_CIPHER_CTX_set_flags := Load_EVP_CIPHER_CTX_set_flags;
  EVP_CIPHER_CTX_clear_flags := Load_EVP_CIPHER_CTX_clear_flags;
  EVP_CIPHER_CTX_test_flags := Load_EVP_CIPHER_CTX_test_flags;
  EVP_EncryptInit := Load_EVP_EncryptInit;
  EVP_EncryptInit_ex := Load_EVP_EncryptInit_ex;
  EVP_EncryptInit_ex2 := Load_EVP_EncryptInit_ex2;
  EVP_EncryptUpdate := Load_EVP_EncryptUpdate;
  EVP_EncryptFinal_ex := Load_EVP_EncryptFinal_ex;
  EVP_EncryptFinal := Load_EVP_EncryptFinal;
  EVP_DecryptInit := Load_EVP_DecryptInit;
  EVP_DecryptInit_ex := Load_EVP_DecryptInit_ex;
  EVP_DecryptInit_ex2 := Load_EVP_DecryptInit_ex2;
  EVP_DecryptUpdate := Load_EVP_DecryptUpdate;
  EVP_DecryptFinal := Load_EVP_DecryptFinal;
  EVP_DecryptFinal_ex := Load_EVP_DecryptFinal_ex;
  EVP_CipherInit := Load_EVP_CipherInit;
  EVP_CipherInit_ex := Load_EVP_CipherInit_ex;
  EVP_CipherInit_SKEY := Load_EVP_CipherInit_SKEY;
  EVP_CipherInit_ex2 := Load_EVP_CipherInit_ex2;
  EVP_CipherUpdate := Load_EVP_CipherUpdate;
  EVP_CipherFinal := Load_EVP_CipherFinal;
  EVP_CipherPipelineEncryptInit := Load_EVP_CipherPipelineEncryptInit;
  EVP_CipherPipelineDecryptInit := Load_EVP_CipherPipelineDecryptInit;
  EVP_CipherPipelineUpdate := Load_EVP_CipherPipelineUpdate;
  EVP_CipherPipelineFinal := Load_EVP_CipherPipelineFinal;
  EVP_CipherFinal_ex := Load_EVP_CipherFinal_ex;
  EVP_SignFinal := Load_EVP_SignFinal;
  EVP_SignFinal_ex := Load_EVP_SignFinal_ex;
  EVP_DigestSign := Load_EVP_DigestSign;
  EVP_VerifyFinal := Load_EVP_VerifyFinal;
  EVP_VerifyFinal_ex := Load_EVP_VerifyFinal_ex;
  EVP_DigestVerify := Load_EVP_DigestVerify;
  EVP_DigestSignInit_ex := Load_EVP_DigestSignInit_ex;
  EVP_DigestSignInit := Load_EVP_DigestSignInit;
  EVP_DigestSignUpdate := Load_EVP_DigestSignUpdate;
  EVP_DigestSignFinal := Load_EVP_DigestSignFinal;
  EVP_DigestVerifyInit_ex := Load_EVP_DigestVerifyInit_ex;
  EVP_DigestVerifyInit := Load_EVP_DigestVerifyInit;
  EVP_DigestVerifyUpdate := Load_EVP_DigestVerifyUpdate;
  EVP_DigestVerifyFinal := Load_EVP_DigestVerifyFinal;
  EVP_OpenInit := Load_EVP_OpenInit;
  EVP_OpenFinal := Load_EVP_OpenFinal;
  EVP_SealInit := Load_EVP_SealInit;
  EVP_SealFinal := Load_EVP_SealFinal;
  EVP_ENCODE_CTX_new := Load_EVP_ENCODE_CTX_new;
  EVP_ENCODE_CTX_free := Load_EVP_ENCODE_CTX_free;
  EVP_ENCODE_CTX_copy := Load_EVP_ENCODE_CTX_copy;
  EVP_ENCODE_CTX_num := Load_EVP_ENCODE_CTX_num;
  EVP_EncodeInit := Load_EVP_EncodeInit;
  EVP_EncodeUpdate := Load_EVP_EncodeUpdate;
  EVP_EncodeFinal := Load_EVP_EncodeFinal;
  EVP_EncodeBlock := Load_EVP_EncodeBlock;
  EVP_DecodeInit := Load_EVP_DecodeInit;
  EVP_DecodeUpdate := Load_EVP_DecodeUpdate;
  EVP_DecodeFinal := Load_EVP_DecodeFinal;
  EVP_DecodeBlock := Load_EVP_DecodeBlock;
  EVP_CIPHER_CTX_new := Load_EVP_CIPHER_CTX_new;
  EVP_CIPHER_CTX_reset := Load_EVP_CIPHER_CTX_reset;
  EVP_CIPHER_CTX_free := Load_EVP_CIPHER_CTX_free;
  EVP_CIPHER_CTX_set_key_length := Load_EVP_CIPHER_CTX_set_key_length;
  EVP_CIPHER_CTX_set_padding := Load_EVP_CIPHER_CTX_set_padding;
  EVP_CIPHER_CTX_ctrl := Load_EVP_CIPHER_CTX_ctrl;
  EVP_CIPHER_CTX_rand_key := Load_EVP_CIPHER_CTX_rand_key;
  EVP_CIPHER_get_params := Load_EVP_CIPHER_get_params;
  EVP_CIPHER_CTX_set_params := Load_EVP_CIPHER_CTX_set_params;
  EVP_CIPHER_CTX_get_params := Load_EVP_CIPHER_CTX_get_params;
  EVP_CIPHER_gettable_params := Load_EVP_CIPHER_gettable_params;
  EVP_CIPHER_settable_ctx_params := Load_EVP_CIPHER_settable_ctx_params;
  EVP_CIPHER_gettable_ctx_params := Load_EVP_CIPHER_gettable_ctx_params;
  EVP_CIPHER_CTX_settable_params := Load_EVP_CIPHER_CTX_settable_params;
  EVP_CIPHER_CTX_gettable_params := Load_EVP_CIPHER_CTX_gettable_params;
  EVP_CIPHER_CTX_set_algor_params := Load_EVP_CIPHER_CTX_set_algor_params;
  EVP_CIPHER_CTX_get_algor_params := Load_EVP_CIPHER_CTX_get_algor_params;
  EVP_CIPHER_CTX_get_algor := Load_EVP_CIPHER_CTX_get_algor;
  BIO_f_md := Load_BIO_f_md;
  BIO_f_base64 := Load_BIO_f_base64;
  BIO_f_cipher := Load_BIO_f_cipher;
  BIO_f_reliable := Load_BIO_f_reliable;
  BIO_set_cipher := Load_BIO_set_cipher;
  EVP_md_null := Load_EVP_md_null;
{$ifndef  OPENSSL_NO_MD2}
  EVP_md2 := Load_EVP_md2;
{$endif} { OPENSSL_NO_MD2}
{$ifndef  OPENSSL_NO_MD4}
  EVP_md4 := Load_EVP_md4;
{$endif} { OPENSSL_NO_MD4}
{$ifndef  OPENSSL_NO_MD5}
  EVP_md5 := Load_EVP_md5;
  EVP_md5_sha1 := Load_EVP_md5_sha1;
{$endif} { OPENSSL_NO_MD5}
{$ifndef  OPENSSL_NO_BLAKE2}
  EVP_blake2b512 := Load_EVP_blake2b512;
  EVP_blake2s256 := Load_EVP_blake2s256;
{$endif} { OPENSSL_NO_BLAKE2}
  EVP_sha1 := Load_EVP_sha1;
  EVP_sha224 := Load_EVP_sha224;
  EVP_sha256 := Load_EVP_sha256;
  EVP_sha384 := Load_EVP_sha384;
  EVP_sha512 := Load_EVP_sha512;
  EVP_sha512_224 := Load_EVP_sha512_224;
  EVP_sha512_256 := Load_EVP_sha512_256;
  EVP_sha3_224 := Load_EVP_sha3_224;
  EVP_sha3_256 := Load_EVP_sha3_256;
  EVP_sha3_384 := Load_EVP_sha3_384;
  EVP_sha3_512 := Load_EVP_sha3_512;
  EVP_shake128 := Load_EVP_shake128;
  EVP_shake256 := Load_EVP_shake256;
{$ifndef  OPENSSL_NO_MDC2}
  EVP_mdc2 := Load_EVP_mdc2;
{$endif} { OPENSSL_NO_MDC2}
{$ifndef  OPENSSL_NO_RMD160}
  EVP_ripemd160 := Load_EVP_ripemd160;
{$endif} { OPENSSL_NO_RMD160}
{$ifndef  OPENSSL_NO_WHIRLPOOL}
  EVP_whirlpool := Load_EVP_whirlpool;
{$endif} { OPENSSL_NO_WHIRLPOOL}
{$ifndef  OPENSSL_NO_SM3}
  EVP_sm3 := Load_EVP_sm3;
{$endif} { OPENSSL_NO_SM3}
  EVP_enc_null := Load_EVP_enc_null;
{$ifndef  OPENSSL_NO_DES}
  EVP_des_ecb := Load_EVP_des_ecb;
  EVP_des_ede := Load_EVP_des_ede;
  EVP_des_ede3 := Load_EVP_des_ede3;
  EVP_des_ede_ecb := Load_EVP_des_ede_ecb;
  EVP_des_ede3_ecb := Load_EVP_des_ede3_ecb;
  EVP_des_cfb64 := Load_EVP_des_cfb64;
  EVP_des_cfb := Load_EVP_des_cfb;
  EVP_des_cfb1 := Load_EVP_des_cfb1;
  EVP_des_cfb8 := Load_EVP_des_cfb8;
  EVP_des_ede_cfb64 := Load_EVP_des_ede_cfb64;
  EVP_des_ede_cfb := Load_EVP_des_ede_cfb;
  EVP_des_ede3_cfb64 := Load_EVP_des_ede3_cfb64;
  EVP_des_ede3_cfb := Load_EVP_des_ede3_cfb;
  EVP_des_ede3_cfb1 := Load_EVP_des_ede3_cfb1;
  EVP_des_ede3_cfb8 := Load_EVP_des_ede3_cfb8;
  EVP_des_ofb := Load_EVP_des_ofb;
  EVP_des_ede_ofb := Load_EVP_des_ede_ofb;
  EVP_des_ede3_ofb := Load_EVP_des_ede3_ofb;
  EVP_des_cbc := Load_EVP_des_cbc;
  EVP_des_ede_cbc := Load_EVP_des_ede_cbc;
  EVP_des_ede3_cbc := Load_EVP_des_ede3_cbc;
  EVP_desx_cbc := Load_EVP_desx_cbc;
  EVP_des_ede3_wrap := Load_EVP_des_ede3_wrap;
{$endif} { OPENSSL_NO_DES}
{$ifndef  OPENSSL_NO_RC4}
  EVP_rc4 := Load_EVP_rc4;
  EVP_rc4_40 := Load_EVP_rc4_40;
    {$ifndef  OPENSSL_NO_MD5}
  EVP_rc4_hmac_md5 := Load_EVP_rc4_hmac_md5;
    {$endif} { OPENSSL_NO_MD5}
{$endif} { OPENSSL_NO_RC4}
{$ifndef  OPENSSL_NO_IDEA}
  EVP_idea_ecb := Load_EVP_idea_ecb;
  EVP_idea_cfb64 := Load_EVP_idea_cfb64;
  EVP_idea_cfb := Load_EVP_idea_cfb;
  EVP_idea_ofb := Load_EVP_idea_ofb;
  EVP_idea_cbc := Load_EVP_idea_cbc;
{$endif} { OPENSSL_NO_IDEA}
{$ifndef  OPENSSL_NO_RC2}
  EVP_rc2_ecb := Load_EVP_rc2_ecb;
  EVP_rc2_cbc := Load_EVP_rc2_cbc;
  EVP_rc2_40_cbc := Load_EVP_rc2_40_cbc;
  EVP_rc2_64_cbc := Load_EVP_rc2_64_cbc;
  EVP_rc2_cfb64 := Load_EVP_rc2_cfb64;
  EVP_rc2_cfb := Load_EVP_rc2_cfb;
  EVP_rc2_ofb := Load_EVP_rc2_ofb;
{$endif} { OPENSSL_NO_RC2}
{$ifndef  OPENSSL_NO_BF}
  EVP_bf_ecb := Load_EVP_bf_ecb;
  EVP_bf_cbc := Load_EVP_bf_cbc;
  EVP_bf_cfb64 := Load_EVP_bf_cfb64;
  EVP_bf_cfb := Load_EVP_bf_cfb;
  EVP_bf_ofb := Load_EVP_bf_ofb;
{$endif} { OPENSSL_NO_BF}
{$ifndef  OPENSSL_NO_CAST}
  EVP_cast5_ecb := Load_EVP_cast5_ecb;
  EVP_cast5_cbc := Load_EVP_cast5_cbc;
  EVP_cast5_cfb64 := Load_EVP_cast5_cfb64;
  EVP_cast5_cfb := Load_EVP_cast5_cfb;
  EVP_cast5_ofb := Load_EVP_cast5_ofb;
{$endif} { OPENSSL_NO_CAST}
{$ifndef  OPENSSL_NO_RC5}
  EVP_rc5_32_12_16_cbc := Load_EVP_rc5_32_12_16_cbc;
  EVP_rc5_32_12_16_ecb := Load_EVP_rc5_32_12_16_ecb;
  EVP_rc5_32_12_16_cfb64 := Load_EVP_rc5_32_12_16_cfb64;
  EVP_rc5_32_12_16_cfb := Load_EVP_rc5_32_12_16_cfb;
  EVP_rc5_32_12_16_ofb := Load_EVP_rc5_32_12_16_ofb;
{$endif} { OPENSSL_NO_RC5}
  EVP_aes_128_ecb := Load_EVP_aes_128_ecb;
  EVP_aes_128_cbc := Load_EVP_aes_128_cbc;
  EVP_aes_128_cfb1 := Load_EVP_aes_128_cfb1;
  EVP_aes_128_cfb8 := Load_EVP_aes_128_cfb8;
  EVP_aes_128_cfb128 := Load_EVP_aes_128_cfb128;
  EVP_aes_128_cfb := Load_EVP_aes_128_cfb;
  EVP_aes_128_ofb := Load_EVP_aes_128_ofb;
  EVP_aes_128_ctr := Load_EVP_aes_128_ctr;
  EVP_aes_128_ccm := Load_EVP_aes_128_ccm;
  EVP_aes_128_gcm := Load_EVP_aes_128_gcm;
  EVP_aes_128_xts := Load_EVP_aes_128_xts;
  EVP_aes_128_wrap := Load_EVP_aes_128_wrap;
  EVP_aes_128_wrap_pad := Load_EVP_aes_128_wrap_pad;
{$ifndef  OPENSSL_NO_OCB}
  EVP_aes_128_ocb := Load_EVP_aes_128_ocb;
{$endif} { OPENSSL_NO_OCB}
  EVP_aes_192_ecb := Load_EVP_aes_192_ecb;
  EVP_aes_192_cbc := Load_EVP_aes_192_cbc;
  EVP_aes_192_cfb1 := Load_EVP_aes_192_cfb1;
  EVP_aes_192_cfb8 := Load_EVP_aes_192_cfb8;
  EVP_aes_192_cfb128 := Load_EVP_aes_192_cfb128;
  EVP_aes_192_cfb := Load_EVP_aes_192_cfb;
  EVP_aes_192_ofb := Load_EVP_aes_192_ofb;
  EVP_aes_192_ctr := Load_EVP_aes_192_ctr;
  EVP_aes_192_ccm := Load_EVP_aes_192_ccm;
  EVP_aes_192_gcm := Load_EVP_aes_192_gcm;
  EVP_aes_192_wrap := Load_EVP_aes_192_wrap;
  EVP_aes_192_wrap_pad := Load_EVP_aes_192_wrap_pad;
{$ifndef  OPENSSL_NO_OCB}
  EVP_aes_192_ocb := Load_EVP_aes_192_ocb;
{$endif} { OPENSSL_NO_OCB}
  EVP_aes_256_ecb := Load_EVP_aes_256_ecb;
  EVP_aes_256_cbc := Load_EVP_aes_256_cbc;
  EVP_aes_256_cfb1 := Load_EVP_aes_256_cfb1;
  EVP_aes_256_cfb8 := Load_EVP_aes_256_cfb8;
  EVP_aes_256_cfb128 := Load_EVP_aes_256_cfb128;
  EVP_aes_256_cfb := Load_EVP_aes_256_cfb;
  EVP_aes_256_ofb := Load_EVP_aes_256_ofb;
  EVP_aes_256_ctr := Load_EVP_aes_256_ctr;
  EVP_aes_256_ccm := Load_EVP_aes_256_ccm;
  EVP_aes_256_gcm := Load_EVP_aes_256_gcm;
  EVP_aes_256_xts := Load_EVP_aes_256_xts;
  EVP_aes_256_wrap := Load_EVP_aes_256_wrap;
  EVP_aes_256_wrap_pad := Load_EVP_aes_256_wrap_pad;
{$ifndef  OPENSSL_NO_OCB}
  EVP_aes_256_ocb := Load_EVP_aes_256_ocb;
{$endif} { OPENSSL_NO_OCB}
  EVP_aes_128_cbc_hmac_sha1 := Load_EVP_aes_128_cbc_hmac_sha1;
  EVP_aes_256_cbc_hmac_sha1 := Load_EVP_aes_256_cbc_hmac_sha1;
  EVP_aes_128_cbc_hmac_sha256 := Load_EVP_aes_128_cbc_hmac_sha256;
  EVP_aes_256_cbc_hmac_sha256 := Load_EVP_aes_256_cbc_hmac_sha256;
{$ifndef  OPENSSL_NO_ARIA}
  EVP_aria_128_ecb := Load_EVP_aria_128_ecb;
  EVP_aria_128_cbc := Load_EVP_aria_128_cbc;
  EVP_aria_128_cfb1 := Load_EVP_aria_128_cfb1;
  EVP_aria_128_cfb8 := Load_EVP_aria_128_cfb8;
  EVP_aria_128_cfb128 := Load_EVP_aria_128_cfb128;
  EVP_aria_128_cfb := Load_EVP_aria_128_cfb;
  EVP_aria_128_ctr := Load_EVP_aria_128_ctr;
  EVP_aria_128_ofb := Load_EVP_aria_128_ofb;
  EVP_aria_128_gcm := Load_EVP_aria_128_gcm;
  EVP_aria_128_ccm := Load_EVP_aria_128_ccm;
  EVP_aria_192_ecb := Load_EVP_aria_192_ecb;
  EVP_aria_192_cbc := Load_EVP_aria_192_cbc;
  EVP_aria_192_cfb1 := Load_EVP_aria_192_cfb1;
  EVP_aria_192_cfb8 := Load_EVP_aria_192_cfb8;
  EVP_aria_192_cfb128 := Load_EVP_aria_192_cfb128;
  EVP_aria_192_cfb := Load_EVP_aria_192_cfb;
  EVP_aria_192_ctr := Load_EVP_aria_192_ctr;
  EVP_aria_192_ofb := Load_EVP_aria_192_ofb;
  EVP_aria_192_gcm := Load_EVP_aria_192_gcm;
  EVP_aria_192_ccm := Load_EVP_aria_192_ccm;
  EVP_aria_256_ecb := Load_EVP_aria_256_ecb;
  EVP_aria_256_cbc := Load_EVP_aria_256_cbc;
  EVP_aria_256_cfb1 := Load_EVP_aria_256_cfb1;
  EVP_aria_256_cfb8 := Load_EVP_aria_256_cfb8;
  EVP_aria_256_cfb128 := Load_EVP_aria_256_cfb128;
  EVP_aria_256_cfb := Load_EVP_aria_256_cfb;
  EVP_aria_256_ctr := Load_EVP_aria_256_ctr;
  EVP_aria_256_ofb := Load_EVP_aria_256_ofb;
  EVP_aria_256_gcm := Load_EVP_aria_256_gcm;
  EVP_aria_256_ccm := Load_EVP_aria_256_ccm;
{$endif} { OPENSSL_NO_ARIA}
{$ifndef  OPENSSL_NO_CAMELLIA}
  EVP_camellia_128_ecb := Load_EVP_camellia_128_ecb;
  EVP_camellia_128_cbc := Load_EVP_camellia_128_cbc;
  EVP_camellia_128_cfb1 := Load_EVP_camellia_128_cfb1;
  EVP_camellia_128_cfb8 := Load_EVP_camellia_128_cfb8;
  EVP_camellia_128_cfb128 := Load_EVP_camellia_128_cfb128;
  EVP_camellia_128_cfb := Load_EVP_camellia_128_cfb;
  EVP_camellia_128_ofb := Load_EVP_camellia_128_ofb;
  EVP_camellia_128_ctr := Load_EVP_camellia_128_ctr;
  EVP_camellia_192_ecb := Load_EVP_camellia_192_ecb;
  EVP_camellia_192_cbc := Load_EVP_camellia_192_cbc;
  EVP_camellia_192_cfb1 := Load_EVP_camellia_192_cfb1;
  EVP_camellia_192_cfb8 := Load_EVP_camellia_192_cfb8;
  EVP_camellia_192_cfb128 := Load_EVP_camellia_192_cfb128;
  EVP_camellia_192_cfb := Load_EVP_camellia_192_cfb;
  EVP_camellia_192_ofb := Load_EVP_camellia_192_ofb;
  EVP_camellia_192_ctr := Load_EVP_camellia_192_ctr;
  EVP_camellia_256_ecb := Load_EVP_camellia_256_ecb;
  EVP_camellia_256_cbc := Load_EVP_camellia_256_cbc;
  EVP_camellia_256_cfb1 := Load_EVP_camellia_256_cfb1;
  EVP_camellia_256_cfb8 := Load_EVP_camellia_256_cfb8;
  EVP_camellia_256_cfb128 := Load_EVP_camellia_256_cfb128;
  EVP_camellia_256_cfb := Load_EVP_camellia_256_cfb;
  EVP_camellia_256_ofb := Load_EVP_camellia_256_ofb;
  EVP_camellia_256_ctr := Load_EVP_camellia_256_ctr;
{$endif} { OPENSSL_NO_CAMELLIA}
{$ifndef  OPENSSL_NO_CHACHA}
  EVP_chacha20 := Load_EVP_chacha20;
    {$ifndef  OPENSSL_NO_POLY1305}
  EVP_chacha20_poly1305 := Load_EVP_chacha20_poly1305;
    {$endif} { OPENSSL_NO_POLY1305}
{$endif} { OPENSSL_NO_CHACHA}
{$ifndef  OPENSSL_NO_SEED}
  EVP_seed_ecb := Load_EVP_seed_ecb;
  EVP_seed_cbc := Load_EVP_seed_cbc;
  EVP_seed_cfb128 := Load_EVP_seed_cfb128;
  EVP_seed_cfb := Load_EVP_seed_cfb;
  EVP_seed_ofb := Load_EVP_seed_ofb;
{$endif} { OPENSSL_NO_SEED}
{$ifndef  OPENSSL_NO_SM4}
  EVP_sm4_ecb := Load_EVP_sm4_ecb;
  EVP_sm4_cbc := Load_EVP_sm4_cbc;
  EVP_sm4_cfb128 := Load_EVP_sm4_cfb128;
  EVP_sm4_cfb := Load_EVP_sm4_cfb;
  EVP_sm4_ofb := Load_EVP_sm4_ofb;
  EVP_sm4_ctr := Load_EVP_sm4_ctr;
{$endif} { OPENSSL_NO_SM4}
  EVP_add_cipher := Load_EVP_add_cipher;
  EVP_add_digest := Load_EVP_add_digest;
  EVP_get_cipherbyname := Load_EVP_get_cipherbyname;
  EVP_get_digestbyname := Load_EVP_get_digestbyname;
  EVP_CIPHER_do_all := Load_EVP_CIPHER_do_all;
  EVP_CIPHER_do_all_sorted := Load_EVP_CIPHER_do_all_sorted;
  EVP_CIPHER_do_all_provided := Load_EVP_CIPHER_do_all_provided;
  EVP_MD_do_all := Load_EVP_MD_do_all;
  EVP_MD_do_all_sorted := Load_EVP_MD_do_all_sorted;
  EVP_MD_do_all_provided := Load_EVP_MD_do_all_provided;
  EVP_MAC_fetch := Load_EVP_MAC_fetch;
  EVP_MAC_up_ref := Load_EVP_MAC_up_ref;
  EVP_MAC_free := Load_EVP_MAC_free;
  EVP_MAC_get0_name := Load_EVP_MAC_get0_name;
  EVP_MAC_get0_description := Load_EVP_MAC_get0_description;
  EVP_MAC_is_a := Load_EVP_MAC_is_a;
  EVP_MAC_get0_provider := Load_EVP_MAC_get0_provider;
  EVP_MAC_get_params := Load_EVP_MAC_get_params;
  EVP_MAC_CTX_new := Load_EVP_MAC_CTX_new;
  EVP_MAC_CTX_free := Load_EVP_MAC_CTX_free;
  EVP_MAC_CTX_dup := Load_EVP_MAC_CTX_dup;
  EVP_MAC_CTX_get0_mac := Load_EVP_MAC_CTX_get0_mac;
  EVP_MAC_CTX_get_params := Load_EVP_MAC_CTX_get_params;
  EVP_MAC_CTX_set_params := Load_EVP_MAC_CTX_set_params;
  EVP_MAC_CTX_get_mac_size := Load_EVP_MAC_CTX_get_mac_size;
  EVP_MAC_CTX_get_block_size := Load_EVP_MAC_CTX_get_block_size;
  EVP_Q_mac := Load_EVP_Q_mac;
  EVP_MAC_init := Load_EVP_MAC_init;
  EVP_MAC_init_SKEY := Load_EVP_MAC_init_SKEY;
  EVP_MAC_update := Load_EVP_MAC_update;
  EVP_MAC_final := Load_EVP_MAC_final;
  EVP_MAC_finalXOF := Load_EVP_MAC_finalXOF;
  EVP_MAC_gettable_params := Load_EVP_MAC_gettable_params;
  EVP_MAC_gettable_ctx_params := Load_EVP_MAC_gettable_ctx_params;
  EVP_MAC_settable_ctx_params := Load_EVP_MAC_settable_ctx_params;
  EVP_MAC_CTX_gettable_params := Load_EVP_MAC_CTX_gettable_params;
  EVP_MAC_CTX_settable_params := Load_EVP_MAC_CTX_settable_params;
  EVP_MAC_do_all_provided := Load_EVP_MAC_do_all_provided;
  EVP_MAC_names_do_all := Load_EVP_MAC_names_do_all;
  EVP_RAND_fetch := Load_EVP_RAND_fetch;
  EVP_RAND_up_ref := Load_EVP_RAND_up_ref;
  EVP_RAND_free := Load_EVP_RAND_free;
  EVP_RAND_get0_name := Load_EVP_RAND_get0_name;
  EVP_RAND_get0_description := Load_EVP_RAND_get0_description;
  EVP_RAND_is_a := Load_EVP_RAND_is_a;
  EVP_RAND_get0_provider := Load_EVP_RAND_get0_provider;
  EVP_RAND_get_params := Load_EVP_RAND_get_params;
  EVP_RAND_CTX_new := Load_EVP_RAND_CTX_new;
  EVP_RAND_CTX_up_ref := Load_EVP_RAND_CTX_up_ref;
  EVP_RAND_CTX_free := Load_EVP_RAND_CTX_free;
  EVP_RAND_CTX_get0_rand := Load_EVP_RAND_CTX_get0_rand;
  EVP_RAND_CTX_get_params := Load_EVP_RAND_CTX_get_params;
  EVP_RAND_CTX_set_params := Load_EVP_RAND_CTX_set_params;
  EVP_RAND_gettable_params := Load_EVP_RAND_gettable_params;
  EVP_RAND_gettable_ctx_params := Load_EVP_RAND_gettable_ctx_params;
  EVP_RAND_settable_ctx_params := Load_EVP_RAND_settable_ctx_params;
  EVP_RAND_CTX_gettable_params := Load_EVP_RAND_CTX_gettable_params;
  EVP_RAND_CTX_settable_params := Load_EVP_RAND_CTX_settable_params;
  EVP_RAND_do_all_provided := Load_EVP_RAND_do_all_provided;
  EVP_RAND_names_do_all := Load_EVP_RAND_names_do_all;
  EVP_RAND_instantiate := Load_EVP_RAND_instantiate;
  EVP_RAND_uninstantiate := Load_EVP_RAND_uninstantiate;
  EVP_RAND_generate := Load_EVP_RAND_generate;
  EVP_RAND_reseed := Load_EVP_RAND_reseed;
  EVP_RAND_nonce := Load_EVP_RAND_nonce;
  EVP_RAND_enable_locking := Load_EVP_RAND_enable_locking;
  EVP_RAND_verify_zeroization := Load_EVP_RAND_verify_zeroization;
  EVP_RAND_get_strength := Load_EVP_RAND_get_strength;
  EVP_RAND_get_state := Load_EVP_RAND_get_state;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_decrypt_old := Load_EVP_PKEY_decrypt_old;
  EVP_PKEY_encrypt_old := Load_EVP_PKEY_encrypt_old;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_is_a := Load_EVP_PKEY_is_a;
  EVP_PKEY_type_names_do_all := Load_EVP_PKEY_type_names_do_all;
  EVP_PKEY_type := Load_EVP_PKEY_type;
  EVP_PKEY_get_id := Load_EVP_PKEY_get_id;
  EVP_PKEY_id := Load_EVP_PKEY_id;
  EVP_PKEY_get_base_id := Load_EVP_PKEY_get_base_id;
  EVP_PKEY_base_id := Load_EVP_PKEY_base_id;
  EVP_PKEY_get_bits := Load_EVP_PKEY_get_bits;
  EVP_PKEY_bits := Load_EVP_PKEY_bits;
  EVP_PKEY_get_security_bits := Load_EVP_PKEY_get_security_bits;
  EVP_PKEY_security_bits := Load_EVP_PKEY_security_bits;
  EVP_PKEY_get_security_category := Load_EVP_PKEY_get_security_category;
  EVP_PKEY_get_size := Load_EVP_PKEY_get_size;
  EVP_PKEY_size := Load_EVP_PKEY_size;
  EVP_PKEY_can_sign := Load_EVP_PKEY_can_sign;
  EVP_PKEY_set_type := Load_EVP_PKEY_set_type;
  EVP_PKEY_set_type_str := Load_EVP_PKEY_set_type_str;
  EVP_PKEY_set_type_by_keymgmt := Load_EVP_PKEY_set_type_by_keymgmt;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_ENGINE}
  EVP_PKEY_set1_engine := Load_EVP_PKEY_set1_engine;
  EVP_PKEY_get0_engine := Load_EVP_PKEY_get0_engine;
    {$endif} { OPENSSL_NO_ENGINE}
  EVP_PKEY_assign := Load_EVP_PKEY_assign;
  EVP_PKEY_get0 := Load_EVP_PKEY_get0;
  EVP_PKEY_get0_hmac := Load_EVP_PKEY_get0_hmac;
    {$ifndef  OPENSSL_NO_POLY1305}
  EVP_PKEY_get0_poly1305 := Load_EVP_PKEY_get0_poly1305;
    {$endif} { OPENSSL_NO_POLY1305}
    {$ifndef  OPENSSL_NO_SIPHASH}
  EVP_PKEY_get0_siphash := Load_EVP_PKEY_get0_siphash;
    {$endif} { OPENSSL_NO_SIPHASH}
  EVP_PKEY_set1_RSA := Load_EVP_PKEY_set1_RSA;
  EVP_PKEY_get0_RSA := Load_EVP_PKEY_get0_RSA;
  EVP_PKEY_get1_RSA := Load_EVP_PKEY_get1_RSA;
    {$ifndef  OPENSSL_NO_DSA}
  EVP_PKEY_set1_DSA := Load_EVP_PKEY_set1_DSA;
  EVP_PKEY_get0_DSA := Load_EVP_PKEY_get0_DSA;
  EVP_PKEY_get1_DSA := Load_EVP_PKEY_get1_DSA;
    {$endif} { OPENSSL_NO_DSA}
    {$ifndef  OPENSSL_NO_DH}
  EVP_PKEY_set1_DH := Load_EVP_PKEY_set1_DH;
  EVP_PKEY_get0_DH := Load_EVP_PKEY_get0_DH;
  EVP_PKEY_get1_DH := Load_EVP_PKEY_get1_DH;
    {$endif} { OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_EC}
  EVP_PKEY_set1_EC_KEY := Load_EVP_PKEY_set1_EC_KEY;
  EVP_PKEY_get0_EC_KEY := Load_EVP_PKEY_get0_EC_KEY;
  EVP_PKEY_get1_EC_KEY := Load_EVP_PKEY_get1_EC_KEY;
    {$endif} { OPENSSL_NO_EC}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_new := Load_EVP_PKEY_new;
  EVP_PKEY_up_ref := Load_EVP_PKEY_up_ref;
  EVP_PKEY_dup := Load_EVP_PKEY_dup;
  EVP_PKEY_free := Load_EVP_PKEY_free;
  EVP_PKEY_get0_description := Load_EVP_PKEY_get0_description;
  EVP_PKEY_get0_provider := Load_EVP_PKEY_get0_provider;
  d2i_PublicKey := Load_d2i_PublicKey;
  i2d_PublicKey := Load_i2d_PublicKey;
  d2i_PrivateKey_ex := Load_d2i_PrivateKey_ex;
  d2i_PrivateKey := Load_d2i_PrivateKey;
  d2i_AutoPrivateKey_ex := Load_d2i_AutoPrivateKey_ex;
  d2i_AutoPrivateKey := Load_d2i_AutoPrivateKey;
  i2d_PrivateKey := Load_i2d_PrivateKey;
  i2d_PKCS8PrivateKey := Load_i2d_PKCS8PrivateKey;
  i2d_KeyParams := Load_i2d_KeyParams;
  d2i_KeyParams := Load_d2i_KeyParams;
  i2d_KeyParams_bio := Load_i2d_KeyParams_bio;
  d2i_KeyParams_bio := Load_d2i_KeyParams_bio;
  EVP_PKEY_copy_parameters := Load_EVP_PKEY_copy_parameters;
  EVP_PKEY_missing_parameters := Load_EVP_PKEY_missing_parameters;
  EVP_PKEY_save_parameters := Load_EVP_PKEY_save_parameters;
  EVP_PKEY_parameters_eq := Load_EVP_PKEY_parameters_eq;
  EVP_PKEY_eq := Load_EVP_PKEY_eq;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_cmp_parameters := Load_EVP_PKEY_cmp_parameters;
  EVP_PKEY_cmp := Load_EVP_PKEY_cmp;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_print_public := Load_EVP_PKEY_print_public;
  EVP_PKEY_print_private := Load_EVP_PKEY_print_private;
  EVP_PKEY_print_params := Load_EVP_PKEY_print_params;
{$ifndef  OPENSSL_NO_STDIO}
  EVP_PKEY_print_public_fp := Load_EVP_PKEY_print_public_fp;
  EVP_PKEY_print_private_fp := Load_EVP_PKEY_print_private_fp;
  EVP_PKEY_print_params_fp := Load_EVP_PKEY_print_params_fp;
{$endif} { OPENSSL_NO_STDIO}
  EVP_PKEY_get_default_digest_nid := Load_EVP_PKEY_get_default_digest_nid;
  EVP_PKEY_get_default_digest_name := Load_EVP_PKEY_get_default_digest_name;
  EVP_PKEY_digestsign_supports_digest := Load_EVP_PKEY_digestsign_supports_digest;
  EVP_PKEY_set1_encoded_public_key := Load_EVP_PKEY_set1_encoded_public_key;
  EVP_PKEY_get1_encoded_public_key := Load_EVP_PKEY_get1_encoded_public_key;
  EVP_CIPHER_param_to_asn1 := Load_EVP_CIPHER_param_to_asn1;
  EVP_CIPHER_asn1_to_param := Load_EVP_CIPHER_asn1_to_param;
  EVP_CIPHER_set_asn1_iv := Load_EVP_CIPHER_set_asn1_iv;
  EVP_CIPHER_get_asn1_iv := Load_EVP_CIPHER_get_asn1_iv;
  PKCS5_PBE_keyivgen := Load_PKCS5_PBE_keyivgen;
  PKCS5_PBE_keyivgen_ex := Load_PKCS5_PBE_keyivgen_ex;
  PKCS5_PBKDF2_HMAC_SHA1 := Load_PKCS5_PBKDF2_HMAC_SHA1;
  PKCS5_PBKDF2_HMAC := Load_PKCS5_PBKDF2_HMAC;
  PKCS5_v2_PBE_keyivgen := Load_PKCS5_v2_PBE_keyivgen;
  PKCS5_v2_PBE_keyivgen_ex := Load_PKCS5_v2_PBE_keyivgen_ex;
{$ifndef  OPENSSL_NO_SCRYPT}
  EVP_PBE_scrypt := Load_EVP_PBE_scrypt;
  EVP_PBE_scrypt_ex := Load_EVP_PBE_scrypt_ex;
  PKCS5_v2_scrypt_keyivgen := Load_PKCS5_v2_scrypt_keyivgen;
  PKCS5_v2_scrypt_keyivgen_ex := Load_PKCS5_v2_scrypt_keyivgen_ex;
{$endif} { OPENSSL_NO_SCRYPT}
  PKCS5_PBE_add := Load_PKCS5_PBE_add;
  EVP_PBE_CipherInit := Load_EVP_PBE_CipherInit;
  EVP_PBE_CipherInit_ex := Load_EVP_PBE_CipherInit_ex;
  EVP_PBE_alg_add_type := Load_EVP_PBE_alg_add_type;
  EVP_PBE_alg_add := Load_EVP_PBE_alg_add;
  EVP_PBE_find := Load_EVP_PBE_find;
  EVP_PBE_find_ex := Load_EVP_PBE_find_ex;
  EVP_PBE_cleanup := Load_EVP_PBE_cleanup;
  EVP_PBE_get := Load_EVP_PBE_get;
{$ifndef  OPENSSL_NO_DEPRECATED_3_6}
  EVP_PKEY_asn1_get_count := Load_EVP_PKEY_asn1_get_count;
  EVP_PKEY_asn1_get0 := Load_EVP_PKEY_asn1_get0;
  EVP_PKEY_asn1_find := Load_EVP_PKEY_asn1_find;
  EVP_PKEY_asn1_find_str := Load_EVP_PKEY_asn1_find_str;
  EVP_PKEY_asn1_add0 := Load_EVP_PKEY_asn1_add0;
  EVP_PKEY_asn1_add_alias := Load_EVP_PKEY_asn1_add_alias;
  EVP_PKEY_asn1_get0_info := Load_EVP_PKEY_asn1_get0_info;
  EVP_PKEY_get0_asn1 := Load_EVP_PKEY_get0_asn1;
  EVP_PKEY_asn1_new := Load_EVP_PKEY_asn1_new;
  EVP_PKEY_asn1_copy := Load_EVP_PKEY_asn1_copy;
  EVP_PKEY_asn1_free := Load_EVP_PKEY_asn1_free;
  EVP_PKEY_asn1_set_public := Load_EVP_PKEY_asn1_set_public;
  EVP_PKEY_asn1_set_private := Load_EVP_PKEY_asn1_set_private;
  EVP_PKEY_asn1_set_param := Load_EVP_PKEY_asn1_set_param;
  EVP_PKEY_asn1_set_free := Load_EVP_PKEY_asn1_set_free;
  EVP_PKEY_asn1_set_ctrl := Load_EVP_PKEY_asn1_set_ctrl;
  EVP_PKEY_asn1_set_item := Load_EVP_PKEY_asn1_set_item;
  EVP_PKEY_asn1_set_siginf := Load_EVP_PKEY_asn1_set_siginf;
  EVP_PKEY_asn1_set_check := Load_EVP_PKEY_asn1_set_check;
  EVP_PKEY_asn1_set_public_check := Load_EVP_PKEY_asn1_set_public_check;
  EVP_PKEY_asn1_set_param_check := Load_EVP_PKEY_asn1_set_param_check;
  EVP_PKEY_asn1_set_set_priv_key := Load_EVP_PKEY_asn1_set_set_priv_key;
  EVP_PKEY_asn1_set_set_pub_key := Load_EVP_PKEY_asn1_set_set_pub_key;
  EVP_PKEY_asn1_set_get_priv_key := Load_EVP_PKEY_asn1_set_get_priv_key;
  EVP_PKEY_asn1_set_get_pub_key := Load_EVP_PKEY_asn1_set_get_pub_key;
  EVP_PKEY_asn1_set_security_bits := Load_EVP_PKEY_asn1_set_security_bits;
{$endif} { OPENSSL_NO_DEPRECATED_3_6}
  EVP_PKEY_CTX_get_signature_md := Load_EVP_PKEY_CTX_get_signature_md;
  EVP_PKEY_CTX_set_signature_md := Load_EVP_PKEY_CTX_set_signature_md;
  EVP_PKEY_CTX_set1_id := Load_EVP_PKEY_CTX_set1_id;
  EVP_PKEY_CTX_get1_id := Load_EVP_PKEY_CTX_get1_id;
  EVP_PKEY_CTX_get1_id_len := Load_EVP_PKEY_CTX_get1_id_len;
  EVP_PKEY_CTX_set_kem_op := Load_EVP_PKEY_CTX_set_kem_op;
  EVP_PKEY_get0_type_name := Load_EVP_PKEY_get0_type_name;
  EVP_PKEY_CTX_set_mac_key := Load_EVP_PKEY_CTX_set_mac_key;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_meth_find := Load_EVP_PKEY_meth_find;
  EVP_PKEY_meth_new := Load_EVP_PKEY_meth_new;
  EVP_PKEY_meth_get0_info := Load_EVP_PKEY_meth_get0_info;
  EVP_PKEY_meth_copy := Load_EVP_PKEY_meth_copy;
  EVP_PKEY_meth_free := Load_EVP_PKEY_meth_free;
  EVP_PKEY_meth_add0 := Load_EVP_PKEY_meth_add0;
  EVP_PKEY_meth_remove := Load_EVP_PKEY_meth_remove;
  EVP_PKEY_meth_get_count := Load_EVP_PKEY_meth_get_count;
  EVP_PKEY_meth_get0 := Load_EVP_PKEY_meth_get0;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_KEYMGMT_fetch := Load_EVP_KEYMGMT_fetch;
  EVP_KEYMGMT_up_ref := Load_EVP_KEYMGMT_up_ref;
  EVP_KEYMGMT_free := Load_EVP_KEYMGMT_free;
  EVP_KEYMGMT_get0_provider := Load_EVP_KEYMGMT_get0_provider;
  EVP_KEYMGMT_get0_name := Load_EVP_KEYMGMT_get0_name;
  EVP_KEYMGMT_get0_description := Load_EVP_KEYMGMT_get0_description;
  EVP_KEYMGMT_is_a := Load_EVP_KEYMGMT_is_a;
  EVP_KEYMGMT_do_all_provided := Load_EVP_KEYMGMT_do_all_provided;
  EVP_KEYMGMT_names_do_all := Load_EVP_KEYMGMT_names_do_all;
  EVP_KEYMGMT_gettable_params := Load_EVP_KEYMGMT_gettable_params;
  EVP_KEYMGMT_settable_params := Load_EVP_KEYMGMT_settable_params;
  EVP_KEYMGMT_gen_settable_params := Load_EVP_KEYMGMT_gen_settable_params;
  EVP_KEYMGMT_gen_gettable_params := Load_EVP_KEYMGMT_gen_gettable_params;
  EVP_SKEYMGMT_fetch := Load_EVP_SKEYMGMT_fetch;
  EVP_SKEYMGMT_up_ref := Load_EVP_SKEYMGMT_up_ref;
  EVP_SKEYMGMT_free := Load_EVP_SKEYMGMT_free;
  EVP_SKEYMGMT_get0_provider := Load_EVP_SKEYMGMT_get0_provider;
  EVP_SKEYMGMT_get0_name := Load_EVP_SKEYMGMT_get0_name;
  EVP_SKEYMGMT_get0_description := Load_EVP_SKEYMGMT_get0_description;
  EVP_SKEYMGMT_is_a := Load_EVP_SKEYMGMT_is_a;
  EVP_SKEYMGMT_do_all_provided := Load_EVP_SKEYMGMT_do_all_provided;
  EVP_SKEYMGMT_names_do_all := Load_EVP_SKEYMGMT_names_do_all;
  EVP_SKEYMGMT_get0_gen_settable_params := Load_EVP_SKEYMGMT_get0_gen_settable_params;
  EVP_SKEYMGMT_get0_imp_settable_params := Load_EVP_SKEYMGMT_get0_imp_settable_params;
  EVP_PKEY_CTX_new := Load_EVP_PKEY_CTX_new;
  EVP_PKEY_CTX_new_id := Load_EVP_PKEY_CTX_new_id;
  EVP_PKEY_CTX_new_from_name := Load_EVP_PKEY_CTX_new_from_name;
  EVP_PKEY_CTX_new_from_pkey := Load_EVP_PKEY_CTX_new_from_pkey;
  EVP_PKEY_CTX_dup := Load_EVP_PKEY_CTX_dup;
  EVP_PKEY_CTX_free := Load_EVP_PKEY_CTX_free;
  EVP_PKEY_CTX_is_a := Load_EVP_PKEY_CTX_is_a;
  EVP_PKEY_CTX_get_params := Load_EVP_PKEY_CTX_get_params;
  EVP_PKEY_CTX_gettable_params := Load_EVP_PKEY_CTX_gettable_params;
  EVP_PKEY_CTX_set_params := Load_EVP_PKEY_CTX_set_params;
  EVP_PKEY_CTX_settable_params := Load_EVP_PKEY_CTX_settable_params;
  EVP_PKEY_CTX_set_algor_params := Load_EVP_PKEY_CTX_set_algor_params;
  EVP_PKEY_CTX_get_algor_params := Load_EVP_PKEY_CTX_get_algor_params;
  EVP_PKEY_CTX_get_algor := Load_EVP_PKEY_CTX_get_algor;
  EVP_PKEY_CTX_ctrl := Load_EVP_PKEY_CTX_ctrl;
  EVP_PKEY_CTX_ctrl_str := Load_EVP_PKEY_CTX_ctrl_str;
  EVP_PKEY_CTX_ctrl_uint64 := Load_EVP_PKEY_CTX_ctrl_uint64;
  EVP_PKEY_CTX_str2ctrl := Load_EVP_PKEY_CTX_str2ctrl;
  EVP_PKEY_CTX_hex2ctrl := Load_EVP_PKEY_CTX_hex2ctrl;
  EVP_PKEY_CTX_md := Load_EVP_PKEY_CTX_md;
  EVP_PKEY_CTX_get_operation := Load_EVP_PKEY_CTX_get_operation;
  EVP_PKEY_CTX_set0_keygen_info := Load_EVP_PKEY_CTX_set0_keygen_info;
  EVP_PKEY_new_mac_key := Load_EVP_PKEY_new_mac_key;
  EVP_PKEY_new_raw_private_key_ex := Load_EVP_PKEY_new_raw_private_key_ex;
  EVP_PKEY_new_raw_private_key := Load_EVP_PKEY_new_raw_private_key;
  EVP_PKEY_new_raw_public_key_ex := Load_EVP_PKEY_new_raw_public_key_ex;
  EVP_PKEY_new_raw_public_key := Load_EVP_PKEY_new_raw_public_key;
  EVP_PKEY_get_raw_private_key := Load_EVP_PKEY_get_raw_private_key;
  EVP_PKEY_get_raw_public_key := Load_EVP_PKEY_get_raw_public_key;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_new_CMAC_key := Load_EVP_PKEY_new_CMAC_key;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_CTX_set_data := Load_EVP_PKEY_CTX_set_data;
  EVP_PKEY_CTX_get_data := Load_EVP_PKEY_CTX_get_data;
  EVP_PKEY_CTX_get0_pkey := Load_EVP_PKEY_CTX_get0_pkey;
  EVP_PKEY_CTX_get0_peerkey := Load_EVP_PKEY_CTX_get0_peerkey;
  EVP_PKEY_CTX_set_app_data := Load_EVP_PKEY_CTX_set_app_data;
  EVP_PKEY_CTX_get_app_data := Load_EVP_PKEY_CTX_get_app_data;
  EVP_PKEY_CTX_set_signature := Load_EVP_PKEY_CTX_set_signature;
  EVP_SIGNATURE_free := Load_EVP_SIGNATURE_free;
  EVP_SIGNATURE_up_ref := Load_EVP_SIGNATURE_up_ref;
  EVP_SIGNATURE_get0_provider := Load_EVP_SIGNATURE_get0_provider;
  EVP_SIGNATURE_fetch := Load_EVP_SIGNATURE_fetch;
  EVP_SIGNATURE_is_a := Load_EVP_SIGNATURE_is_a;
  EVP_SIGNATURE_get0_name := Load_EVP_SIGNATURE_get0_name;
  EVP_SIGNATURE_get0_description := Load_EVP_SIGNATURE_get0_description;
  EVP_SIGNATURE_do_all_provided := Load_EVP_SIGNATURE_do_all_provided;
  EVP_SIGNATURE_names_do_all := Load_EVP_SIGNATURE_names_do_all;
  EVP_SIGNATURE_gettable_ctx_params := Load_EVP_SIGNATURE_gettable_ctx_params;
  EVP_SIGNATURE_settable_ctx_params := Load_EVP_SIGNATURE_settable_ctx_params;
  EVP_ASYM_CIPHER_free := Load_EVP_ASYM_CIPHER_free;
  EVP_ASYM_CIPHER_up_ref := Load_EVP_ASYM_CIPHER_up_ref;
  EVP_ASYM_CIPHER_get0_provider := Load_EVP_ASYM_CIPHER_get0_provider;
  EVP_ASYM_CIPHER_fetch := Load_EVP_ASYM_CIPHER_fetch;
  EVP_ASYM_CIPHER_is_a := Load_EVP_ASYM_CIPHER_is_a;
  EVP_ASYM_CIPHER_get0_name := Load_EVP_ASYM_CIPHER_get0_name;
  EVP_ASYM_CIPHER_get0_description := Load_EVP_ASYM_CIPHER_get0_description;
  EVP_ASYM_CIPHER_do_all_provided := Load_EVP_ASYM_CIPHER_do_all_provided;
  EVP_ASYM_CIPHER_names_do_all := Load_EVP_ASYM_CIPHER_names_do_all;
  EVP_ASYM_CIPHER_gettable_ctx_params := Load_EVP_ASYM_CIPHER_gettable_ctx_params;
  EVP_ASYM_CIPHER_settable_ctx_params := Load_EVP_ASYM_CIPHER_settable_ctx_params;
  EVP_KEM_free := Load_EVP_KEM_free;
  EVP_KEM_up_ref := Load_EVP_KEM_up_ref;
  EVP_KEM_get0_provider := Load_EVP_KEM_get0_provider;
  EVP_KEM_fetch := Load_EVP_KEM_fetch;
  EVP_KEM_is_a := Load_EVP_KEM_is_a;
  EVP_KEM_get0_name := Load_EVP_KEM_get0_name;
  EVP_KEM_get0_description := Load_EVP_KEM_get0_description;
  EVP_KEM_do_all_provided := Load_EVP_KEM_do_all_provided;
  EVP_KEM_names_do_all := Load_EVP_KEM_names_do_all;
  EVP_KEM_gettable_ctx_params := Load_EVP_KEM_gettable_ctx_params;
  EVP_KEM_settable_ctx_params := Load_EVP_KEM_settable_ctx_params;
  EVP_PKEY_sign_init := Load_EVP_PKEY_sign_init;
  EVP_PKEY_sign_init_ex := Load_EVP_PKEY_sign_init_ex;
  EVP_PKEY_sign_init_ex2 := Load_EVP_PKEY_sign_init_ex2;
  EVP_PKEY_sign := Load_EVP_PKEY_sign;
  EVP_PKEY_sign_message_init := Load_EVP_PKEY_sign_message_init;
  EVP_PKEY_sign_message_update := Load_EVP_PKEY_sign_message_update;
  EVP_PKEY_sign_message_final := Load_EVP_PKEY_sign_message_final;
  EVP_PKEY_verify_init := Load_EVP_PKEY_verify_init;
  EVP_PKEY_verify_init_ex := Load_EVP_PKEY_verify_init_ex;
  EVP_PKEY_verify_init_ex2 := Load_EVP_PKEY_verify_init_ex2;
  EVP_PKEY_verify := Load_EVP_PKEY_verify;
  EVP_PKEY_verify_message_init := Load_EVP_PKEY_verify_message_init;
  EVP_PKEY_verify_message_update := Load_EVP_PKEY_verify_message_update;
  EVP_PKEY_verify_message_final := Load_EVP_PKEY_verify_message_final;
  EVP_PKEY_verify_recover_init := Load_EVP_PKEY_verify_recover_init;
  EVP_PKEY_verify_recover_init_ex := Load_EVP_PKEY_verify_recover_init_ex;
  EVP_PKEY_verify_recover_init_ex2 := Load_EVP_PKEY_verify_recover_init_ex2;
  EVP_PKEY_verify_recover := Load_EVP_PKEY_verify_recover;
  EVP_PKEY_encrypt_init := Load_EVP_PKEY_encrypt_init;
  EVP_PKEY_encrypt_init_ex := Load_EVP_PKEY_encrypt_init_ex;
  EVP_PKEY_encrypt := Load_EVP_PKEY_encrypt;
  EVP_PKEY_decrypt_init := Load_EVP_PKEY_decrypt_init;
  EVP_PKEY_decrypt_init_ex := Load_EVP_PKEY_decrypt_init_ex;
  EVP_PKEY_decrypt := Load_EVP_PKEY_decrypt;
  EVP_PKEY_derive_init := Load_EVP_PKEY_derive_init;
  EVP_PKEY_derive_init_ex := Load_EVP_PKEY_derive_init_ex;
  EVP_PKEY_derive_set_peer_ex := Load_EVP_PKEY_derive_set_peer_ex;
  EVP_PKEY_derive_set_peer := Load_EVP_PKEY_derive_set_peer;
  EVP_PKEY_derive := Load_EVP_PKEY_derive;
  EVP_PKEY_derive_SKEY := Load_EVP_PKEY_derive_SKEY;
  EVP_PKEY_encapsulate_init := Load_EVP_PKEY_encapsulate_init;
  EVP_PKEY_auth_encapsulate_init := Load_EVP_PKEY_auth_encapsulate_init;
  EVP_PKEY_encapsulate := Load_EVP_PKEY_encapsulate;
  EVP_PKEY_decapsulate_init := Load_EVP_PKEY_decapsulate_init;
  EVP_PKEY_auth_decapsulate_init := Load_EVP_PKEY_auth_decapsulate_init;
  EVP_PKEY_decapsulate := Load_EVP_PKEY_decapsulate;
  EVP_PKEY_fromdata_init := Load_EVP_PKEY_fromdata_init;
  EVP_PKEY_fromdata := Load_EVP_PKEY_fromdata;
  EVP_PKEY_fromdata_settable := Load_EVP_PKEY_fromdata_settable;
  EVP_PKEY_todata := Load_EVP_PKEY_todata;
  EVP_PKEY_export := Load_EVP_PKEY_export;
  EVP_PKEY_gettable_params := Load_EVP_PKEY_gettable_params;
  EVP_PKEY_get_params := Load_EVP_PKEY_get_params;
  EVP_PKEY_get_int_param := Load_EVP_PKEY_get_int_param;
  EVP_PKEY_get_size_t_param := Load_EVP_PKEY_get_size_t_param;
  EVP_PKEY_get_bn_param := Load_EVP_PKEY_get_bn_param;
  EVP_PKEY_get_utf8_string_param := Load_EVP_PKEY_get_utf8_string_param;
  EVP_PKEY_get_octet_string_param := Load_EVP_PKEY_get_octet_string_param;
  EVP_PKEY_settable_params := Load_EVP_PKEY_settable_params;
  EVP_PKEY_set_params := Load_EVP_PKEY_set_params;
  EVP_PKEY_set_int_param := Load_EVP_PKEY_set_int_param;
  EVP_PKEY_set_size_t_param := Load_EVP_PKEY_set_size_t_param;
  EVP_PKEY_set_bn_param := Load_EVP_PKEY_set_bn_param;
  EVP_PKEY_set_utf8_string_param := Load_EVP_PKEY_set_utf8_string_param;
  EVP_PKEY_set_octet_string_param := Load_EVP_PKEY_set_octet_string_param;
  EVP_PKEY_get_ec_point_conv_form := Load_EVP_PKEY_get_ec_point_conv_form;
  EVP_PKEY_get_field_type := Load_EVP_PKEY_get_field_type;
  EVP_PKEY_Q_keygen := nil;
  EVP_PKEY_paramgen_init := Load_EVP_PKEY_paramgen_init;
  EVP_PKEY_paramgen := Load_EVP_PKEY_paramgen;
  EVP_PKEY_keygen_init := Load_EVP_PKEY_keygen_init;
  EVP_PKEY_keygen := Load_EVP_PKEY_keygen;
  EVP_PKEY_generate := Load_EVP_PKEY_generate;
  EVP_PKEY_check := Load_EVP_PKEY_check;
  EVP_PKEY_public_check := Load_EVP_PKEY_public_check;
  EVP_PKEY_public_check_quick := Load_EVP_PKEY_public_check_quick;
  EVP_PKEY_param_check := Load_EVP_PKEY_param_check;
  EVP_PKEY_param_check_quick := Load_EVP_PKEY_param_check_quick;
  EVP_PKEY_private_check := Load_EVP_PKEY_private_check;
  EVP_PKEY_pairwise_check := Load_EVP_PKEY_pairwise_check;
  EVP_PKEY_set_ex_data := Load_EVP_PKEY_set_ex_data;
  EVP_PKEY_get_ex_data := Load_EVP_PKEY_get_ex_data;
  EVP_PKEY_CTX_set_cb := Load_EVP_PKEY_CTX_set_cb;
  EVP_PKEY_CTX_get_cb := Load_EVP_PKEY_CTX_get_cb;
  EVP_PKEY_CTX_get_keygen_info := Load_EVP_PKEY_CTX_get_keygen_info;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_meth_set_init := Load_EVP_PKEY_meth_set_init;
  EVP_PKEY_meth_set_copy := Load_EVP_PKEY_meth_set_copy;
  EVP_PKEY_meth_set_cleanup := Load_EVP_PKEY_meth_set_cleanup;
  EVP_PKEY_meth_set_paramgen := Load_EVP_PKEY_meth_set_paramgen;
  EVP_PKEY_meth_set_keygen := Load_EVP_PKEY_meth_set_keygen;
  EVP_PKEY_meth_set_sign := Load_EVP_PKEY_meth_set_sign;
  EVP_PKEY_meth_set_verify := Load_EVP_PKEY_meth_set_verify;
  EVP_PKEY_meth_set_verify_recover := Load_EVP_PKEY_meth_set_verify_recover;
  EVP_PKEY_meth_set_signctx := Load_EVP_PKEY_meth_set_signctx;
  EVP_PKEY_meth_set_verifyctx := Load_EVP_PKEY_meth_set_verifyctx;
  EVP_PKEY_meth_set_encrypt := Load_EVP_PKEY_meth_set_encrypt;
  EVP_PKEY_meth_set_decrypt := Load_EVP_PKEY_meth_set_decrypt;
  EVP_PKEY_meth_set_derive := Load_EVP_PKEY_meth_set_derive;
  EVP_PKEY_meth_set_ctrl := Load_EVP_PKEY_meth_set_ctrl;
  EVP_PKEY_meth_set_digestsign := Load_EVP_PKEY_meth_set_digestsign;
  EVP_PKEY_meth_set_digestverify := Load_EVP_PKEY_meth_set_digestverify;
  EVP_PKEY_meth_set_check := Load_EVP_PKEY_meth_set_check;
  EVP_PKEY_meth_set_public_check := Load_EVP_PKEY_meth_set_public_check;
  EVP_PKEY_meth_set_param_check := Load_EVP_PKEY_meth_set_param_check;
  EVP_PKEY_meth_set_digest_custom := Load_EVP_PKEY_meth_set_digest_custom;
  EVP_PKEY_meth_get_init := Load_EVP_PKEY_meth_get_init;
  EVP_PKEY_meth_get_copy := Load_EVP_PKEY_meth_get_copy;
  EVP_PKEY_meth_get_cleanup := Load_EVP_PKEY_meth_get_cleanup;
  EVP_PKEY_meth_get_paramgen := Load_EVP_PKEY_meth_get_paramgen;
  EVP_PKEY_meth_get_keygen := Load_EVP_PKEY_meth_get_keygen;
  EVP_PKEY_meth_get_sign := Load_EVP_PKEY_meth_get_sign;
  EVP_PKEY_meth_get_verify := Load_EVP_PKEY_meth_get_verify;
  EVP_PKEY_meth_get_verify_recover := Load_EVP_PKEY_meth_get_verify_recover;
  EVP_PKEY_meth_get_signctx := Load_EVP_PKEY_meth_get_signctx;
  EVP_PKEY_meth_get_verifyctx := Load_EVP_PKEY_meth_get_verifyctx;
  EVP_PKEY_meth_get_encrypt := Load_EVP_PKEY_meth_get_encrypt;
  EVP_PKEY_meth_get_decrypt := Load_EVP_PKEY_meth_get_decrypt;
  EVP_PKEY_meth_get_derive := Load_EVP_PKEY_meth_get_derive;
  EVP_PKEY_meth_get_ctrl := Load_EVP_PKEY_meth_get_ctrl;
  EVP_PKEY_meth_get_digestsign := Load_EVP_PKEY_meth_get_digestsign;
  EVP_PKEY_meth_get_digestverify := Load_EVP_PKEY_meth_get_digestverify;
  EVP_PKEY_meth_get_check := Load_EVP_PKEY_meth_get_check;
  EVP_PKEY_meth_get_public_check := Load_EVP_PKEY_meth_get_public_check;
  EVP_PKEY_meth_get_param_check := Load_EVP_PKEY_meth_get_param_check;
  EVP_PKEY_meth_get_digest_custom := Load_EVP_PKEY_meth_get_digest_custom;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_KEYEXCH_free := Load_EVP_KEYEXCH_free;
  EVP_KEYEXCH_up_ref := Load_EVP_KEYEXCH_up_ref;
  EVP_KEYEXCH_fetch := Load_EVP_KEYEXCH_fetch;
  EVP_KEYEXCH_get0_provider := Load_EVP_KEYEXCH_get0_provider;
  EVP_KEYEXCH_is_a := Load_EVP_KEYEXCH_is_a;
  EVP_KEYEXCH_get0_name := Load_EVP_KEYEXCH_get0_name;
  EVP_KEYEXCH_get0_description := Load_EVP_KEYEXCH_get0_description;
  EVP_KEYEXCH_do_all_provided := Load_EVP_KEYEXCH_do_all_provided;
  EVP_KEYEXCH_names_do_all := Load_EVP_KEYEXCH_names_do_all;
  EVP_KEYEXCH_gettable_ctx_params := Load_EVP_KEYEXCH_gettable_ctx_params;
  EVP_KEYEXCH_settable_ctx_params := Load_EVP_KEYEXCH_settable_ctx_params;
  EVP_add_alg_module := Load_EVP_add_alg_module;
  EVP_PKEY_CTX_set_group_name := Load_EVP_PKEY_CTX_set_group_name;
  EVP_PKEY_CTX_get_group_name := Load_EVP_PKEY_CTX_get_group_name;
  EVP_PKEY_get_group_name := Load_EVP_PKEY_get_group_name;
  EVP_PKEY_CTX_get0_libctx := Load_EVP_PKEY_CTX_get0_libctx;
  EVP_PKEY_CTX_get0_propq := Load_EVP_PKEY_CTX_get0_propq;
  EVP_PKEY_CTX_get0_provider := Load_EVP_PKEY_CTX_get0_provider;
  EVP_SKEY_is_a := Load_EVP_SKEY_is_a;
  EVP_SKEY_import := Load_EVP_SKEY_import;
  EVP_SKEY_generate := Load_EVP_SKEY_generate;
  EVP_SKEY_import_raw_key := Load_EVP_SKEY_import_raw_key;
  EVP_SKEY_import_SKEYMGMT := Load_EVP_SKEY_import_SKEYMGMT;
  EVP_SKEY_get0_raw_key := Load_EVP_SKEY_get0_raw_key;
  EVP_SKEY_get0_key_id := Load_EVP_SKEY_get0_key_id;
  EVP_SKEY_export := Load_EVP_SKEY_export;
  EVP_SKEY_up_ref := Load_EVP_SKEY_up_ref;
  EVP_SKEY_free := Load_EVP_SKEY_free;
  EVP_SKEY_get0_skeymgmt_name := Load_EVP_SKEY_get0_skeymgmt_name;
  EVP_SKEY_get0_provider_name := Load_EVP_SKEY_get0_provider_name;
  EVP_SKEY_to_provider := Load_EVP_SKEY_to_provider;
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



