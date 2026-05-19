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

unit openssl_cryptoerr_legacy;

{
  Generated from OpenSSL 3.5.6 Header File cryptoerr_legacy.h - Tue 19 May 14:27:26 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_cryptoerr_legacy.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_evperr,openssl_symhacks;


{* Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}

(** This header file preserves symbols from pre-3.0 OpenSSL.
* It should never be included directly, as it's already included
* by the public {lib}err.h headers, and since it will go away some
* time in the future.
*)
{$ifndef  OPENSSL_CRYPTOERR_LEGACY_H}
  {$define OPENSSL_CRYPTOERR_LEGACY_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_ASN1_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_ASN1_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_ASYNC_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_ASYNC_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_BIO_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_BIO_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_BN_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_BN_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_BUF_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_BUF_strings'; deprecated 'Since OpenSSL 3.0';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM ERR_load_ASN1_strings}
  {$EXTERNALSYM ERR_load_ASYNC_strings}
  {$EXTERNALSYM ERR_load_BIO_strings}
  {$EXTERNALSYM ERR_load_BN_strings}
  {$EXTERNALSYM ERR_load_BUF_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_ASN1_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_ASYNC_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_BIO_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_BN_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_BUF_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_ASN1_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_ASN1_strings;
  ERR_load_ASYNC_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_ASYNC_strings;
  ERR_load_BIO_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_BIO_strings;
  ERR_load_BN_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_BN_strings;
  ERR_load_BUF_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_BUF_strings;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_CMS}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_CMS_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_CMS_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_CMS_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_CMS_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_CMS_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_CMS_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_COMP}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_COMP_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_COMP_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_COMP_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_COMP_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_COMP_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_COMP_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_CONF_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_CONF_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_CRYPTO_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_CRYPTO_strings'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_load_CONF_strings}
  {$EXTERNALSYM ERR_load_CRYPTO_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_CONF_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_CRYPTO_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_CONF_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_CONF_strings;
  ERR_load_CRYPTO_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_CRYPTO_strings;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_CT}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_CT_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_CT_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_CT_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_CT_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_CT_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_CT_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DH}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_DH_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_DH_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_DH_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_DH_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_DH_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_DH_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DSA}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_DSA_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_DSA_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_DSA_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_DSA_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_DSA_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_DSA_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_EC}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_EC_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_EC_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_EC_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_EC_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_EC_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_EC_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_ENGINE}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_ENGINE_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_ENGINE_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_ENGINE_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_ENGINE_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_ENGINE_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_ENGINE_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_ERR_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_ERR_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_EVP_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_EVP_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_KDF_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_KDF_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_OBJ_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_OBJ_strings'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_load_ERR_strings}
  {$EXTERNALSYM ERR_load_EVP_strings}
  {$EXTERNALSYM ERR_load_KDF_strings}
  {$EXTERNALSYM ERR_load_OBJ_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_ERR_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_EVP_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_KDF_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_OBJ_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_ERR_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_ERR_strings;
  ERR_load_EVP_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_EVP_strings;
  ERR_load_KDF_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_KDF_strings;
  ERR_load_OBJ_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_OBJ_strings;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_OCSP}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_OCSP_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_OCSP_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_OCSP_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_OCSP_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_OCSP_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_OCSP_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_PEM_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_PEM_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_PKCS12_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_PKCS12_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_PKCS7_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_PKCS7_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_RAND_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_RAND_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_RSA_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_RSA_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_OSSL_STORE_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_OSSL_STORE_strings'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_load_PEM_strings}
  {$EXTERNALSYM ERR_load_PKCS12_strings}
  {$EXTERNALSYM ERR_load_PKCS7_strings}
  {$EXTERNALSYM ERR_load_RAND_strings}
  {$EXTERNALSYM ERR_load_RSA_strings}
  {$EXTERNALSYM ERR_load_OSSL_STORE_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_PEM_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_PKCS12_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_PKCS7_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_RAND_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_RSA_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_OSSL_STORE_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_PEM_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_PEM_strings;
  ERR_load_PKCS12_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_PKCS12_strings;
  ERR_load_PKCS7_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_PKCS7_strings;
  ERR_load_RAND_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_RAND_strings;
  ERR_load_RSA_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_RSA_strings;
  ERR_load_OSSL_STORE_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_OSSL_STORE_strings;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_TS}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_TS_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_TS_strings'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ERR_load_TS_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_TS_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_TS_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_TS_strings;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_load_UI_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_UI_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_X509_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_X509_strings'; deprecated 'Since OpenSSL 3.0';
  function ERR_load_X509V3_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_X509V3_strings'; deprecated 'Since OpenSSL 3.0';
  { Collected _F_ macros from OpenSSL 1.1.1 }
  
  {* ASN1 function codes.
  }
    {$else}
  {$EXTERNALSYM ERR_load_UI_strings}
  {$EXTERNALSYM ERR_load_X509_strings}
  {$EXTERNALSYM ERR_load_X509V3_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_load_UI_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_X509_strings: TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_X509V3_strings: TOpenSSL_C_INT; cdecl;

var
  ERR_load_UI_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_UI_strings;
  ERR_load_X509_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_X509_strings;
  ERR_load_X509V3_strings: function: TOpenSSL_C_INT; cdecl = Load_ERR_load_X509V3_strings;
  { Collected _F_ macros from OpenSSL 1.1.1 }
  
  {* ASN1 function codes.
  }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  ASN1_F_A2D_ASN1_OBJECT = 0;
  ASN1_F_A2I_ASN1_INTEGER = 0;
  ASN1_F_A2I_ASN1_STRING = 0;
  ASN1_F_APPEND_EXP = 0;
  ASN1_F_ASN1_BIO_INIT = 0;
  ASN1_F_ASN1_BIT_STRING_SET_BIT = 0;
  ASN1_F_ASN1_CB = 0;
  ASN1_F_ASN1_CHECK_TLEN = 0;
  ASN1_F_ASN1_COLLECT = 0;
  ASN1_F_ASN1_D2I_EX_PRIMITIVE = 0;
  ASN1_F_ASN1_D2I_FP = 0;
  ASN1_F_ASN1_D2I_READ_BIO = 0;
  ASN1_F_ASN1_DIGEST = 0;
  ASN1_F_ASN1_DO_ADB = 0;
  ASN1_F_ASN1_DO_LOCK = 0;
  ASN1_F_ASN1_DUP = 0;
  ASN1_F_ASN1_ENC_SAVE = 0;
  ASN1_F_ASN1_EX_C2I = 0;
  ASN1_F_ASN1_FIND_END = 0;
  ASN1_F_ASN1_GENERALIZEDTIME_ADJ = 0;
  ASN1_F_ASN1_GENERATE_V3 = 0;
  ASN1_F_ASN1_GET_INT64 = 0;
  ASN1_F_ASN1_GET_OBJECT = 0;
  ASN1_F_ASN1_GET_UINT64 = 0;
  ASN1_F_ASN1_I2D_BIO = 0;
  ASN1_F_ASN1_I2D_FP = 0;
  ASN1_F_ASN1_ITEM_D2I_FP = 0;
  ASN1_F_ASN1_ITEM_DUP = 0;
  ASN1_F_ASN1_ITEM_EMBED_D2I = 0;
  ASN1_F_ASN1_ITEM_EMBED_NEW = 0;
  ASN1_F_ASN1_ITEM_FLAGS_I2D = 0;
  ASN1_F_ASN1_ITEM_I2D_BIO = 0;
  ASN1_F_ASN1_ITEM_I2D_FP = 0;
  ASN1_F_ASN1_ITEM_PACK = 0;
  ASN1_F_ASN1_ITEM_SIGN = 0;
  ASN1_F_ASN1_ITEM_SIGN_CTX = 0;
  ASN1_F_ASN1_ITEM_UNPACK = 0;
  ASN1_F_ASN1_ITEM_VERIFY = 0;
  ASN1_F_ASN1_MBSTRING_NCOPY = 0;
  ASN1_F_ASN1_OBJECT_NEW = 0;
  ASN1_F_ASN1_OUTPUT_DATA = 0;
  ASN1_F_ASN1_PCTX_NEW = 0;
  ASN1_F_ASN1_PRIMITIVE_NEW = 0;
  ASN1_F_ASN1_SCTX_NEW = 0;
  ASN1_F_ASN1_SIGN = 0;
  ASN1_F_ASN1_STR2TYPE = 0;
  ASN1_F_ASN1_STRING_GET_INT64 = 0;
  ASN1_F_ASN1_STRING_GET_UINT64 = 0;
  ASN1_F_ASN1_STRING_SET = 0;
  ASN1_F_ASN1_STRING_TABLE_ADD = 0;
  ASN1_F_ASN1_STRING_TO_BN = 0;
  ASN1_F_ASN1_STRING_TYPE_NEW = 0;
  ASN1_F_ASN1_TEMPLATE_EX_D2I = 0;
  ASN1_F_ASN1_TEMPLATE_NEW = 0;
  ASN1_F_ASN1_TEMPLATE_NOEXP_D2I = 0;
  ASN1_F_ASN1_TIME_ADJ = 0;
  ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING = 0;
  ASN1_F_ASN1_TYPE_GET_OCTETSTRING = 0;
  ASN1_F_ASN1_UTCTIME_ADJ = 0;
  ASN1_F_ASN1_VERIFY = 0;
  ASN1_F_B64_READ_ASN1 = 0;
  ASN1_F_B64_WRITE_ASN1 = 0;
  ASN1_F_BIO_NEW_NDEF = 0;
  ASN1_F_BITSTR_CB = 0;
  ASN1_F_BN_TO_ASN1_STRING = 0;
  ASN1_F_C2I_ASN1_BIT_STRING = 0;
  ASN1_F_C2I_ASN1_INTEGER = 0;
  ASN1_F_C2I_ASN1_OBJECT = 0;
  ASN1_F_C2I_IBUF = 0;
  ASN1_F_C2I_UINT64_INT = 0;
  ASN1_F_COLLECT_DATA = 0;
  ASN1_F_D2I_ASN1_OBJECT = 0;
  ASN1_F_D2I_ASN1_UINTEGER = 0;
  ASN1_F_D2I_AUTOPRIVATEKEY = 0;
  ASN1_F_D2I_PRIVATEKEY = 0;
  ASN1_F_D2I_PUBLICKEY = 0;
  ASN1_F_DO_BUF = 0;
  ASN1_F_DO_CREATE = 0;
  ASN1_F_DO_DUMP = 0;
  ASN1_F_DO_TCREATE = 0;
  ASN1_F_I2A_ASN1_OBJECT = 0;
  ASN1_F_I2D_ASN1_BIO_STREAM = 0;
  ASN1_F_I2D_ASN1_OBJECT = 0;
  ASN1_F_I2D_DSA_PUBKEY = 0;
  ASN1_F_I2D_EC_PUBKEY = 0;
  ASN1_F_I2D_PRIVATEKEY = 0;
  ASN1_F_I2D_PUBLICKEY = 0;
  ASN1_F_I2D_RSA_PUBKEY = 0;
  ASN1_F_LONG_C2I = 0;
  ASN1_F_NDEF_PREFIX = 0;
  ASN1_F_NDEF_SUFFIX = 0;
  ASN1_F_OID_MODULE_INIT = 0;
  ASN1_F_PARSE_TAGGING = 0;
  ASN1_F_PKCS5_PBE2_SET_IV = 0;
  ASN1_F_PKCS5_PBE2_SET_SCRYPT = 0;
  ASN1_F_PKCS5_PBE_SET = 0;
  ASN1_F_PKCS5_PBE_SET0_ALGOR = 0;
  ASN1_F_PKCS5_PBKDF2_SET = 0;
  ASN1_F_PKCS5_SCRYPT_SET = 0;
  ASN1_F_SMIME_READ_ASN1 = 0;
  ASN1_F_SMIME_TEXT = 0;
  ASN1_F_STABLE_GET = 0;
  ASN1_F_STBL_MODULE_INIT = 0;
  ASN1_F_UINT32_C2I = 0;
  ASN1_F_UINT32_NEW = 0;
  ASN1_F_UINT64_C2I = 0;
  ASN1_F_UINT64_NEW = 0;
  ASN1_F_X509_CRL_ADD0_REVOKED = 0;
  ASN1_F_X509_INFO_NEW = 0;
  ASN1_F_X509_NAME_ENCODE = 0;
  ASN1_F_X509_NAME_EX_D2I = 0;
  ASN1_F_X509_NAME_EX_NEW = 0;
  ASN1_F_X509_PKEY_NEW = 0;
    
    {* ASYNC function codes.
    }
  ASYNC_F_ASYNC_CTX_NEW = 0;
  ASYNC_F_ASYNC_INIT_THREAD = 0;
  ASYNC_F_ASYNC_JOB_NEW = 0;
  ASYNC_F_ASYNC_PAUSE_JOB = 0;
  ASYNC_F_ASYNC_START_FUNC = 0;
  ASYNC_F_ASYNC_START_JOB = 0;
  ASYNC_F_ASYNC_WAIT_CTX_SET_WAIT_FD = 0;
    
    {* BIO function codes.
    }
  BIO_F_ACPT_STATE = 0;
  BIO_F_ADDRINFO_WRAP = 0;
  BIO_F_ADDR_STRINGS = 0;
  BIO_F_BIO_ACCEPT = 0;
  BIO_F_BIO_ACCEPT_EX = 0;
  BIO_F_BIO_ACCEPT_NEW = 0;
  BIO_F_BIO_ADDR_NEW = 0;
  BIO_F_BIO_BIND = 0;
  BIO_F_BIO_CALLBACK_CTRL = 0;
  BIO_F_BIO_CONNECT = 0;
  BIO_F_BIO_CONNECT_NEW = 0;
  BIO_F_BIO_CTRL = 0;
  BIO_F_BIO_GETS = 0;
  BIO_F_BIO_GET_HOST_IP = 0;
  BIO_F_BIO_GET_NEW_INDEX = 0;
  BIO_F_BIO_GET_PORT = 0;
  BIO_F_BIO_LISTEN = 0;
  BIO_F_BIO_LOOKUP = 0;
  BIO_F_BIO_LOOKUP_EX = 0;
  BIO_F_BIO_MAKE_PAIR = 0;
  BIO_F_BIO_METH_NEW = 0;
  BIO_F_BIO_NEW = 0;
  BIO_F_BIO_NEW_DGRAM_SCTP = 0;
  BIO_F_BIO_NEW_FILE = 0;
  BIO_F_BIO_NEW_MEM_BUF = 0;
  BIO_F_BIO_NREAD = 0;
  BIO_F_BIO_NREAD0 = 0;
  BIO_F_BIO_NWRITE = 0;
  BIO_F_BIO_NWRITE0 = 0;
  BIO_F_BIO_PARSE_HOSTSERV = 0;
  BIO_F_BIO_PUTS = 0;
  BIO_F_BIO_READ = 0;
  BIO_F_BIO_READ_EX = 0;
  BIO_F_BIO_READ_INTERN = 0;
  BIO_F_BIO_SOCKET = 0;
  BIO_F_BIO_SOCKET_NBIO = 0;
  BIO_F_BIO_SOCK_INFO = 0;
  BIO_F_BIO_SOCK_INIT = 0;
  BIO_F_BIO_WRITE = 0;
  BIO_F_BIO_WRITE_EX = 0;
  BIO_F_BIO_WRITE_INTERN = 0;
  BIO_F_BUFFER_CTRL = 0;
  BIO_F_CONN_CTRL = 0;
  BIO_F_CONN_STATE = 0;
  BIO_F_DGRAM_SCTP_NEW = 0;
  BIO_F_DGRAM_SCTP_READ = 0;
  BIO_F_DGRAM_SCTP_WRITE = 0;
  BIO_F_DOAPR_OUTCH = 0;
  BIO_F_FILE_CTRL = 0;
  BIO_F_FILE_READ = 0;
  BIO_F_LINEBUFFER_CTRL = 0;
  BIO_F_LINEBUFFER_NEW = 0;
  BIO_F_MEM_WRITE = 0;
  BIO_F_NBIOF_NEW = 0;
  BIO_F_SLG_WRITE = 0;
  BIO_F_SSL_NEW = 0;
    
    {* BN function codes.
    }
  BN_F_BNRAND = 0;
  BN_F_BNRAND_RANGE = 0;
  BN_F_BN_BLINDING_CONVERT_EX = 0;
  BN_F_BN_BLINDING_CREATE_PARAM = 0;
  BN_F_BN_BLINDING_INVERT_EX = 0;
  BN_F_BN_BLINDING_NEW = 0;
  BN_F_BN_BLINDING_UPDATE = 0;
  BN_F_BN_BN2DEC = 0;
  BN_F_BN_BN2HEX = 0;
  BN_F_BN_COMPUTE_WNAF = 0;
  BN_F_BN_CTX_GET = 0;
  BN_F_BN_CTX_NEW = 0;
  BN_F_BN_CTX_START = 0;
  BN_F_BN_DIV = 0;
  BN_F_BN_DIV_RECP = 0;
  BN_F_BN_EXP = 0;
  BN_F_BN_EXPAND_INTERNAL = 0;
  BN_F_BN_GENCB_NEW = 0;
  BN_F_BN_GENERATE_DSA_NONCE = 0;
  BN_F_BN_GENERATE_PRIME_EX = 0;
  BN_F_BN_GF2M_MOD = 0;
  BN_F_BN_GF2M_MOD_EXP = 0;
  BN_F_BN_GF2M_MOD_MUL = 0;
  BN_F_BN_GF2M_MOD_SOLVE_QUAD = 0;
  BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR = 0;
  BN_F_BN_GF2M_MOD_SQR = 0;
  BN_F_BN_GF2M_MOD_SQRT = 0;
  BN_F_BN_LSHIFT = 0;
  BN_F_BN_MOD_EXP2_MONT = 0;
  BN_F_BN_MOD_EXP_MONT = 0;
  BN_F_BN_MOD_EXP_MONT_CONSTTIME = 0;
  BN_F_BN_MOD_EXP_MONT_WORD = 0;
  BN_F_BN_MOD_EXP_RECP = 0;
  BN_F_BN_MOD_EXP_SIMPLE = 0;
  BN_F_BN_MOD_INVERSE = 0;
  BN_F_BN_MOD_INVERSE_NO_BRANCH = 0;
  BN_F_BN_MOD_LSHIFT_QUICK = 0;
  BN_F_BN_MOD_SQRT = 0;
  BN_F_BN_MONT_CTX_NEW = 0;
  BN_F_BN_MPI2BN = 0;
  BN_F_BN_NEW = 0;
  BN_F_BN_POOL_GET = 0;
  BN_F_BN_RAND = 0;
  BN_F_BN_RAND_RANGE = 0;
  BN_F_BN_RECP_CTX_NEW = 0;
  BN_F_BN_RSHIFT = 0;
  BN_F_BN_SET_WORDS = 0;
  BN_F_BN_STACK_PUSH = 0;
  BN_F_BN_USUB = 0;
    
    {* BUF function codes.
    }
  BUF_F_BUF_MEM_GROW = 0;
  BUF_F_BUF_MEM_GROW_CLEAN = 0;
  BUF_F_BUF_MEM_NEW = 0;
    {$ifndef  OPENSSL_NO_CMS}

const
      
      {* CMS function codes.
      }
  CMS_F_CHECK_CONTENT = 0;
  CMS_F_CMS_ADD0_CERT = 0;
  CMS_F_CMS_ADD0_RECIPIENT_KEY = 0;
  CMS_F_CMS_ADD0_RECIPIENT_PASSWORD = 0;
  CMS_F_CMS_ADD1_RECEIPTREQUEST = 0;
  CMS_F_CMS_ADD1_RECIPIENT_CERT = 0;
  CMS_F_CMS_ADD1_SIGNER = 0;
  CMS_F_CMS_ADD1_SIGNINGTIME = 0;
  CMS_F_CMS_COMPRESS = 0;
  CMS_F_CMS_COMPRESSEDDATA_CREATE = 0;
  CMS_F_CMS_COMPRESSEDDATA_INIT_BIO = 0;
  CMS_F_CMS_COPY_CONTENT = 0;
  CMS_F_CMS_COPY_MESSAGEDIGEST = 0;
  CMS_F_CMS_DATA = 0;
  CMS_F_CMS_DATAFINAL = 0;
  CMS_F_CMS_DATAINIT = 0;
  CMS_F_CMS_DECRYPT = 0;
  CMS_F_CMS_DECRYPT_SET1_KEY = 0;
  CMS_F_CMS_DECRYPT_SET1_PASSWORD = 0;
  CMS_F_CMS_DECRYPT_SET1_PKEY = 0;
  CMS_F_CMS_DIGESTALGORITHM_FIND_CTX = 0;
  CMS_F_CMS_DIGESTALGORITHM_INIT_BIO = 0;
  CMS_F_CMS_DIGESTEDDATA_DO_FINAL = 0;
  CMS_F_CMS_DIGEST_VERIFY = 0;
  CMS_F_CMS_ENCODE_RECEIPT = 0;
  CMS_F_CMS_ENCRYPT = 0;
  CMS_F_CMS_ENCRYPTEDCONTENT_INIT = 0;
  CMS_F_CMS_ENCRYPTEDCONTENT_INIT_BIO = 0;
  CMS_F_CMS_ENCRYPTEDDATA_DECRYPT = 0;
  CMS_F_CMS_ENCRYPTEDDATA_ENCRYPT = 0;
  CMS_F_CMS_ENCRYPTEDDATA_SET1_KEY = 0;
  CMS_F_CMS_ENVELOPEDDATA_CREATE = 0;
  CMS_F_CMS_ENVELOPEDDATA_INIT_BIO = 0;
  CMS_F_CMS_ENVELOPED_DATA_INIT = 0;
  CMS_F_CMS_ENV_ASN1_CTRL = 0;
  CMS_F_CMS_FINAL = 0;
  CMS_F_CMS_GET0_CERTIFICATE_CHOICES = 0;
  CMS_F_CMS_GET0_CONTENT = 0;
  CMS_F_CMS_GET0_ECONTENT_TYPE = 0;
  CMS_F_CMS_GET0_ENVELOPED = 0;
  CMS_F_CMS_GET0_REVOCATION_CHOICES = 0;
  CMS_F_CMS_GET0_SIGNED = 0;
  CMS_F_CMS_MSGSIGDIGEST_ADD1 = 0;
  CMS_F_CMS_RECEIPTREQUEST_CREATE0 = 0;
  CMS_F_CMS_RECEIPT_VERIFY = 0;
  CMS_F_CMS_RECIPIENTINFO_DECRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_ENCRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_KARI_ENCRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ALG = 0;
  CMS_F_CMS_RECIPIENTINFO_KARI_GET0_ORIG_ID = 0;
  CMS_F_CMS_RECIPIENTINFO_KARI_GET0_REKS = 0;
  CMS_F_CMS_RECIPIENTINFO_KARI_ORIG_ID_CMP = 0;
  CMS_F_CMS_RECIPIENTINFO_KEKRI_DECRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_KEKRI_ENCRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_KEKRI_GET0_ID = 0;
  CMS_F_CMS_RECIPIENTINFO_KEKRI_ID_CMP = 0;
  CMS_F_CMS_RECIPIENTINFO_KTRI_CERT_CMP = 0;
  CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_KTRI_ENCRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_ALGS = 0;
  CMS_F_CMS_RECIPIENTINFO_KTRI_GET0_SIGNER_ID = 0;
  CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT = 0;
  CMS_F_CMS_RECIPIENTINFO_SET0_KEY = 0;
  CMS_F_CMS_RECIPIENTINFO_SET0_PASSWORD = 0;
  CMS_F_CMS_RECIPIENTINFO_SET0_PKEY = 0;
  CMS_F_CMS_SD_ASN1_CTRL = 0;
  CMS_F_CMS_SET1_IAS = 0;
  CMS_F_CMS_SET1_KEYID = 0;
  CMS_F_CMS_SET1_SIGNERIDENTIFIER = 0;
  CMS_F_CMS_SET_DETACHED = 0;
  CMS_F_CMS_SIGN = 0;
  CMS_F_CMS_SIGNED_DATA_INIT = 0;
  CMS_F_CMS_SIGNERINFO_CONTENT_SIGN = 0;
  CMS_F_CMS_SIGNERINFO_SIGN = 0;
  CMS_F_CMS_SIGNERINFO_VERIFY = 0;
  CMS_F_CMS_SIGNERINFO_VERIFY_CERT = 0;
  CMS_F_CMS_SIGNERINFO_VERIFY_CONTENT = 0;
  CMS_F_CMS_SIGN_RECEIPT = 0;
  CMS_F_CMS_SI_CHECK_ATTRIBUTES = 0;
  CMS_F_CMS_STREAM = 0;
  CMS_F_CMS_UNCOMPRESS = 0;
  CMS_F_CMS_VERIFY = 0;
  CMS_F_KEK_UNWRAP_KEY = 0;
    {$endif}
    {$ifndef  OPENSSL_NO_COMP}

const
      
      {* COMP function codes.
      }
  COMP_F_BIO_ZLIB_FLUSH = 0;
  COMP_F_BIO_ZLIB_NEW = 0;
  COMP_F_BIO_ZLIB_READ = 0;
  COMP_F_BIO_ZLIB_WRITE = 0;
  COMP_F_COMP_CTX_NEW = 0;
    {$endif}

const
    
    {* CONF function codes.
    }
  CONF_F_CONF_DUMP_FP = 0;
  CONF_F_CONF_LOAD = 0;
  CONF_F_CONF_LOAD_FP = 0;
  CONF_F_CONF_PARSE_LIST = 0;
  CONF_F_DEF_LOAD = 0;
  CONF_F_DEF_LOAD_BIO = 0;
  CONF_F_GET_NEXT_FILE = 0;
  CONF_F_MODULE_ADD = 0;
  CONF_F_MODULE_INIT = 0;
  CONF_F_MODULE_LOAD_DSO = 0;
  CONF_F_MODULE_RUN = 0;
  CONF_F_NCONF_DUMP_BIO = 0;
  CONF_F_NCONF_DUMP_FP = 0;
  CONF_F_NCONF_GET_NUMBER_E = 0;
  CONF_F_NCONF_GET_SECTION = 0;
  CONF_F_NCONF_GET_STRING = 0;
  CONF_F_NCONF_LOAD = 0;
  CONF_F_NCONF_LOAD_BIO = 0;
  CONF_F_NCONF_LOAD_FP = 0;
  CONF_F_NCONF_NEW = 0;
  CONF_F_PROCESS_INCLUDE = 0;
  CONF_F_SSL_MODULE_INIT = 0;
  CONF_F_STR_COPY = 0;
    
    {* CRYPTO function codes.
    }
  CRYPTO_F_CMAC_CTX_NEW = 0;
  CRYPTO_F_CRYPTO_DUP_EX_DATA = 0;
  CRYPTO_F_CRYPTO_FREE_EX_DATA = 0;
  CRYPTO_F_CRYPTO_GET_EX_NEW_INDEX = 0;
  CRYPTO_F_CRYPTO_MEMDUP = 0;
  CRYPTO_F_CRYPTO_NEW_EX_DATA = 0;
  CRYPTO_F_CRYPTO_OCB128_COPY_CTX = 0;
  CRYPTO_F_CRYPTO_OCB128_INIT = 0;
  CRYPTO_F_CRYPTO_SET_EX_DATA = 0;
  CRYPTO_F_GET_AND_LOCK = 0;
  CRYPTO_F_OPENSSL_ATEXIT = 0;
  CRYPTO_F_OPENSSL_BUF2HEXSTR = 0;
  CRYPTO_F_OPENSSL_FOPEN = 0;
  CRYPTO_F_OPENSSL_HEXSTR2BUF = 0;
  CRYPTO_F_OPENSSL_INIT_CRYPTO = 0;
  CRYPTO_F_OPENSSL_LH_NEW = 0;
  CRYPTO_F_OPENSSL_SK_DEEP_COPY = 0;
  CRYPTO_F_OPENSSL_SK_DUP = 0;
  CRYPTO_F_PKEY_HMAC_INIT = 0;
  CRYPTO_F_PKEY_POLY1305_INIT = 0;
  CRYPTO_F_PKEY_SIPHASH_INIT = 0;
  CRYPTO_F_SK_RESERVE = 0;
    {$ifndef  OPENSSL_NO_CT}

const
      
      {* CT function codes.
      }
  CT_F_CTLOG_NEW = 0;
  CT_F_CTLOG_NEW_FROM_BASE64 = 0;
  CT_F_CTLOG_NEW_FROM_CONF = 0;
  CT_F_CTLOG_STORE_LOAD_CTX_NEW = 0;
  CT_F_CTLOG_STORE_LOAD_FILE = 0;
  CT_F_CTLOG_STORE_LOAD_LOG = 0;
  CT_F_CTLOG_STORE_NEW = 0;
  CT_F_CT_BASE64_DECODE = 0;
  CT_F_CT_POLICY_EVAL_CTX_NEW = 0;
  CT_F_CT_V1_LOG_ID_FROM_PKEY = 0;
  CT_F_I2O_SCT = 0;
  CT_F_I2O_SCT_LIST = 0;
  CT_F_I2O_SCT_SIGNATURE = 0;
  CT_F_O2I_SCT = 0;
  CT_F_O2I_SCT_LIST = 0;
  CT_F_O2I_SCT_SIGNATURE = 0;
  CT_F_SCT_CTX_NEW = 0;
  CT_F_SCT_CTX_VERIFY = 0;
  CT_F_SCT_NEW = 0;
  CT_F_SCT_NEW_FROM_BASE64 = 0;
  CT_F_SCT_SET0_LOG_ID = 0;
  CT_F_SCT_SET1_EXTENSIONS = 0;
  CT_F_SCT_SET1_LOG_ID = 0;
  CT_F_SCT_SET1_SIGNATURE = 0;
  CT_F_SCT_SET_LOG_ENTRY_TYPE = 0;
  CT_F_SCT_SET_SIGNATURE_NID = 0;
  CT_F_SCT_SET_VERSION = 0;
    {$endif}
    {$ifndef  OPENSSL_NO_DH}

const
      
      {* DH function codes.
      }
  DH_F_COMPUTE_KEY = 0;
  DH_F_DHPARAMS_PRINT_FP = 0;
  DH_F_DH_BUILTIN_GENPARAMS = 0;
  DH_F_DH_CHECK_EX = 0;
  DH_F_DH_CHECK_PARAMS_EX = 0;
  DH_F_DH_CHECK_PUB_KEY_EX = 0;
  DH_F_DH_CMS_DECRYPT = 0;
  DH_F_DH_CMS_SET_PEERKEY = 0;
  DH_F_DH_CMS_SET_SHARED_INFO = 0;
  DH_F_DH_METH_DUP = 0;
  DH_F_DH_METH_NEW = 0;
  DH_F_DH_METH_SET1_NAME = 0;
  DH_F_DH_NEW_BY_NID = 0;
  DH_F_DH_NEW_METHOD = 0;
  DH_F_DH_PARAM_DECODE = 0;
  DH_F_DH_PKEY_PUBLIC_CHECK = 0;
  DH_F_DH_PRIV_DECODE = 0;
  DH_F_DH_PRIV_ENCODE = 0;
  DH_F_DH_PUB_DECODE = 0;
  DH_F_DH_PUB_ENCODE = 0;
  DH_F_DO_DH_PRINT = 0;
  DH_F_GENERATE_KEY = 0;
  DH_F_PKEY_DH_CTRL_STR = 0;
  DH_F_PKEY_DH_DERIVE = 0;
  DH_F_PKEY_DH_INIT = 0;
  DH_F_PKEY_DH_KEYGEN = 0;
    {$endif}
    {$ifndef  OPENSSL_NO_DSA}

const
      
      {* DSA function codes.
      }
  DSA_F_DSAPARAMS_PRINT = 0;
  DSA_F_DSAPARAMS_PRINT_FP = 0;
  DSA_F_DSA_BUILTIN_PARAMGEN = 0;
  DSA_F_DSA_BUILTIN_PARAMGEN2 = 0;
  DSA_F_DSA_DO_SIGN = 0;
  DSA_F_DSA_DO_VERIFY = 0;
  DSA_F_DSA_METH_DUP = 0;
  DSA_F_DSA_METH_NEW = 0;
  DSA_F_DSA_METH_SET1_NAME = 0;
  DSA_F_DSA_NEW_METHOD = 0;
  DSA_F_DSA_PARAM_DECODE = 0;
  DSA_F_DSA_PRINT_FP = 0;
  DSA_F_DSA_PRIV_DECODE = 0;
  DSA_F_DSA_PRIV_ENCODE = 0;
  DSA_F_DSA_PUB_DECODE = 0;
  DSA_F_DSA_PUB_ENCODE = 0;
  DSA_F_DSA_SIGN = 0;
  DSA_F_DSA_SIGN_SETUP = 0;
  DSA_F_DSA_SIG_NEW = 0;
  DSA_F_OLD_DSA_PRIV_DECODE = 0;
  DSA_F_PKEY_DSA_CTRL = 0;
  DSA_F_PKEY_DSA_CTRL_STR = 0;
  DSA_F_PKEY_DSA_KEYGEN = 0;
    {$endif}
    {$ifndef  OPENSSL_NO_EC}

const
      
      {* EC function codes.
      }
  EC_F_BN_TO_FELEM = 0;
  EC_F_D2I_ECPARAMETERS = 0;
  EC_F_D2I_ECPKPARAMETERS = 0;
  EC_F_D2I_ECPRIVATEKEY = 0;
  EC_F_DO_EC_KEY_PRINT = 0;
  EC_F_ECDH_CMS_DECRYPT = 0;
  EC_F_ECDH_CMS_SET_SHARED_INFO = 0;
  EC_F_ECDH_COMPUTE_KEY = 0;
  EC_F_ECDH_SIMPLE_COMPUTE_KEY = 0;
  EC_F_ECDSA_DO_SIGN_EX = 0;
  EC_F_ECDSA_DO_VERIFY = 0;
  EC_F_ECDSA_SIGN_EX = 0;
  EC_F_ECDSA_SIGN_SETUP = 0;
  EC_F_ECDSA_SIG_NEW = 0;
  EC_F_ECDSA_VERIFY = 0;
  EC_F_ECD_ITEM_VERIFY = 0;
  EC_F_ECKEY_PARAM2TYPE = 0;
  EC_F_ECKEY_PARAM_DECODE = 0;
  EC_F_ECKEY_PRIV_DECODE = 0;
  EC_F_ECKEY_PRIV_ENCODE = 0;
  EC_F_ECKEY_PUB_DECODE = 0;
  EC_F_ECKEY_PUB_ENCODE = 0;
  EC_F_ECKEY_TYPE2PARAM = 0;
  EC_F_ECPARAMETERS_PRINT = 0;
  EC_F_ECPARAMETERS_PRINT_FP = 0;
  EC_F_ECPKPARAMETERS_PRINT = 0;
  EC_F_ECPKPARAMETERS_PRINT_FP = 0;
  EC_F_ECP_NISTZ256_GET_AFFINE = 0;
  EC_F_ECP_NISTZ256_INV_MOD_ORD = 0;
  EC_F_ECP_NISTZ256_MULT_PRECOMPUTE = 0;
  EC_F_ECP_NISTZ256_POINTS_MUL = 0;
  EC_F_ECP_NISTZ256_PRE_COMP_NEW = 0;
  EC_F_ECP_NISTZ256_WINDOWED_MUL = 0;
  EC_F_ECX_KEY_OP = 0;
  EC_F_ECX_PRIV_ENCODE = 0;
  EC_F_ECX_PUB_ENCODE = 0;
  EC_F_EC_ASN1_GROUP2CURVE = 0;
  EC_F_EC_ASN1_GROUP2FIELDID = 0;
  EC_F_EC_GF2M_MONTGOMERY_POINT_MULTIPLY = 0;
  EC_F_EC_GF2M_SIMPLE_FIELD_INV = 0;
  EC_F_EC_GF2M_SIMPLE_GROUP_CHECK_DISCRIMINANT = 0;
  EC_F_EC_GF2M_SIMPLE_GROUP_SET_CURVE = 0;
  EC_F_EC_GF2M_SIMPLE_LADDER_POST = 0;
  EC_F_EC_GF2M_SIMPLE_LADDER_PRE = 0;
  EC_F_EC_GF2M_SIMPLE_OCT2POINT = 0;
  EC_F_EC_GF2M_SIMPLE_POINT2OCT = 0;
  EC_F_EC_GF2M_SIMPLE_POINTS_MUL = 0;
  EC_F_EC_GF2M_SIMPLE_POINT_GET_AFFINE_COORDINATES = 0;
  EC_F_EC_GF2M_SIMPLE_POINT_SET_AFFINE_COORDINATES = 0;
  EC_F_EC_GF2M_SIMPLE_SET_COMPRESSED_COORDINATES = 0;
  EC_F_EC_GFP_MONT_FIELD_DECODE = 0;
  EC_F_EC_GFP_MONT_FIELD_ENCODE = 0;
  EC_F_EC_GFP_MONT_FIELD_INV = 0;
  EC_F_EC_GFP_MONT_FIELD_MUL = 0;
  EC_F_EC_GFP_MONT_FIELD_SET_TO_ONE = 0;
  EC_F_EC_GFP_MONT_FIELD_SQR = 0;
  EC_F_EC_GFP_MONT_GROUP_SET_CURVE = 0;
  EC_F_EC_GFP_NISTP224_GROUP_SET_CURVE = 0;
  EC_F_EC_GFP_NISTP224_POINTS_MUL = 0;
  EC_F_EC_GFP_NISTP224_POINT_GET_AFFINE_COORDINATES = 0;
  EC_F_EC_GFP_NISTP256_GROUP_SET_CURVE = 0;
  EC_F_EC_GFP_NISTP256_POINTS_MUL = 0;
  EC_F_EC_GFP_NISTP256_POINT_GET_AFFINE_COORDINATES = 0;
  EC_F_EC_GFP_NISTP521_GROUP_SET_CURVE = 0;
  EC_F_EC_GFP_NISTP521_POINTS_MUL = 0;
  EC_F_EC_GFP_NISTP521_POINT_GET_AFFINE_COORDINATES = 0;
  EC_F_EC_GFP_NIST_FIELD_MUL = 0;
  EC_F_EC_GFP_NIST_FIELD_SQR = 0;
  EC_F_EC_GFP_NIST_GROUP_SET_CURVE = 0;
  EC_F_EC_GFP_SIMPLE_BLIND_COORDINATES = 0;
  EC_F_EC_GFP_SIMPLE_FIELD_INV = 0;
  EC_F_EC_GFP_SIMPLE_GROUP_CHECK_DISCRIMINANT = 0;
  EC_F_EC_GFP_SIMPLE_GROUP_SET_CURVE = 0;
  EC_F_EC_GFP_SIMPLE_MAKE_AFFINE = 0;
  EC_F_EC_GFP_SIMPLE_OCT2POINT = 0;
  EC_F_EC_GFP_SIMPLE_POINT2OCT = 0;
  EC_F_EC_GFP_SIMPLE_POINTS_MAKE_AFFINE = 0;
  EC_F_EC_GFP_SIMPLE_POINT_GET_AFFINE_COORDINATES = 0;
  EC_F_EC_GFP_SIMPLE_POINT_SET_AFFINE_COORDINATES = 0;
  EC_F_EC_GFP_SIMPLE_SET_COMPRESSED_COORDINATES = 0;
  EC_F_EC_GROUP_CHECK = 0;
  EC_F_EC_GROUP_CHECK_DISCRIMINANT = 0;
  EC_F_EC_GROUP_COPY = 0;
  EC_F_EC_GROUP_GET_CURVE = 0;
  EC_F_EC_GROUP_GET_CURVE_GF2M = 0;
  EC_F_EC_GROUP_GET_CURVE_GFP = 0;
  EC_F_EC_GROUP_GET_DEGREE = 0;
  EC_F_EC_GROUP_GET_ECPARAMETERS = 0;
  EC_F_EC_GROUP_GET_ECPKPARAMETERS = 0;
  EC_F_EC_GROUP_GET_PENTANOMIAL_BASIS = 0;
  EC_F_EC_GROUP_GET_TRINOMIAL_BASIS = 0;
  EC_F_EC_GROUP_NEW = 0;
  EC_F_EC_GROUP_NEW_BY_CURVE_NAME = 0;
  EC_F_EC_GROUP_NEW_FROM_DATA = 0;
  EC_F_EC_GROUP_NEW_FROM_ECPARAMETERS = 0;
  EC_F_EC_GROUP_NEW_FROM_ECPKPARAMETERS = 0;
  EC_F_EC_GROUP_SET_CURVE = 0;
  EC_F_EC_GROUP_SET_CURVE_GF2M = 0;
  EC_F_EC_GROUP_SET_CURVE_GFP = 0;
  EC_F_EC_GROUP_SET_GENERATOR = 0;
  EC_F_EC_GROUP_SET_SEED = 0;
  EC_F_EC_KEY_CHECK_KEY = 0;
  EC_F_EC_KEY_COPY = 0;
  EC_F_EC_KEY_GENERATE_KEY = 0;
  EC_F_EC_KEY_NEW = 0;
  EC_F_EC_KEY_NEW_METHOD = 0;
  EC_F_EC_KEY_OCT2PRIV = 0;
  EC_F_EC_KEY_PRINT = 0;
  EC_F_EC_KEY_PRINT_FP = 0;
  EC_F_EC_KEY_PRIV2BUF = 0;
  EC_F_EC_KEY_PRIV2OCT = 0;
  EC_F_EC_KEY_SET_PUBLIC_KEY_AFFINE_COORDINATES = 0;
  EC_F_EC_KEY_SIMPLE_CHECK_KEY = 0;
  EC_F_EC_KEY_SIMPLE_OCT2PRIV = 0;
  EC_F_EC_KEY_SIMPLE_PRIV2OCT = 0;
  EC_F_EC_PKEY_CHECK = 0;
  EC_F_EC_PKEY_PARAM_CHECK = 0;
  EC_F_EC_POINTS_MAKE_AFFINE = 0;
  EC_F_EC_POINTS_MUL = 0;
  EC_F_EC_POINT_ADD = 0;
  EC_F_EC_POINT_BN2POINT = 0;
  EC_F_EC_POINT_CMP = 0;
  EC_F_EC_POINT_COPY = 0;
  EC_F_EC_POINT_DBL = 0;
  EC_F_EC_POINT_GET_AFFINE_COORDINATES = 0;
  EC_F_EC_POINT_GET_AFFINE_COORDINATES_GF2M = 0;
  EC_F_EC_POINT_GET_AFFINE_COORDINATES_GFP = 0;
  EC_F_EC_POINT_GET_JPROJECTIVE_COORDINATES_GFP = 0;
  EC_F_EC_POINT_INVERT = 0;
  EC_F_EC_POINT_IS_AT_INFINITY = 0;
  EC_F_EC_POINT_IS_ON_CURVE = 0;
  EC_F_EC_POINT_MAKE_AFFINE = 0;
  EC_F_EC_POINT_NEW = 0;
  EC_F_EC_POINT_OCT2POINT = 0;
  EC_F_EC_POINT_POINT2BUF = 0;
  EC_F_EC_POINT_POINT2OCT = 0;
  EC_F_EC_POINT_SET_AFFINE_COORDINATES = 0;
  EC_F_EC_POINT_SET_AFFINE_COORDINATES_GF2M = 0;
  EC_F_EC_POINT_SET_AFFINE_COORDINATES_GFP = 0;
  EC_F_EC_POINT_SET_COMPRESSED_COORDINATES = 0;
  EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GF2M = 0;
  EC_F_EC_POINT_SET_COMPRESSED_COORDINATES_GFP = 0;
  EC_F_EC_POINT_SET_JPROJECTIVE_COORDINATES_GFP = 0;
  EC_F_EC_POINT_SET_TO_INFINITY = 0;
  EC_F_EC_PRE_COMP_NEW = 0;
  EC_F_EC_SCALAR_MUL_LADDER = 0;
  EC_F_EC_WNAF_MUL = 0;
  EC_F_EC_WNAF_PRECOMPUTE_MULT = 0;
  EC_F_I2D_ECPARAMETERS = 0;
  EC_F_I2D_ECPKPARAMETERS = 0;
  EC_F_I2D_ECPRIVATEKEY = 0;
  EC_F_I2O_ECPUBLICKEY = 0;
  EC_F_NISTP224_PRE_COMP_NEW = 0;
  EC_F_NISTP256_PRE_COMP_NEW = 0;
  EC_F_NISTP521_PRE_COMP_NEW = 0;
  EC_F_O2I_ECPUBLICKEY = 0;
  EC_F_OLD_EC_PRIV_DECODE = 0;
  EC_F_OSSL_ECDH_COMPUTE_KEY = 0;
  EC_F_OSSL_ECDSA_SIGN_SIG = 0;
  EC_F_OSSL_ECDSA_VERIFY_SIG = 0;
  EC_F_PKEY_ECD_CTRL = 0;
  EC_F_PKEY_ECD_DIGESTSIGN = 0;
  EC_F_PKEY_ECD_DIGESTSIGN25519 = 0;
  EC_F_PKEY_ECD_DIGESTSIGN448 = 0;
  EC_F_PKEY_ECX_DERIVE = 0;
  EC_F_PKEY_EC_CTRL = 0;
  EC_F_PKEY_EC_CTRL_STR = 0;
  EC_F_PKEY_EC_DERIVE = 0;
  EC_F_PKEY_EC_INIT = 0;
  EC_F_PKEY_EC_KDF_DERIVE = 0;
  EC_F_PKEY_EC_KEYGEN = 0;
  EC_F_PKEY_EC_PARAMGEN = 0;
  EC_F_PKEY_EC_SIGN = 0;
  EC_F_VALIDATE_ECX_DERIVE = 0;
    {$endif}
    {$ifndef  OPENSSL_NO_ENGINE}

const
      
      {* ENGINE function codes.
      }
  ENGINE_F_DIGEST_UPDATE = 0;
  ENGINE_F_DYNAMIC_CTRL = 0;
  ENGINE_F_DYNAMIC_GET_DATA_CTX = 0;
  ENGINE_F_DYNAMIC_LOAD = 0;
  ENGINE_F_DYNAMIC_SET_DATA_CTX = 0;
  ENGINE_F_ENGINE_ADD = 0;
  ENGINE_F_ENGINE_BY_ID = 0;
  ENGINE_F_ENGINE_CMD_IS_EXECUTABLE = 0;
  ENGINE_F_ENGINE_CTRL = 0;
  ENGINE_F_ENGINE_CTRL_CMD = 0;
  ENGINE_F_ENGINE_CTRL_CMD_STRING = 0;
  ENGINE_F_ENGINE_FINISH = 0;
  ENGINE_F_ENGINE_GET_CIPHER = 0;
  ENGINE_F_ENGINE_GET_DIGEST = 0;
  ENGINE_F_ENGINE_GET_FIRST = 0;
  ENGINE_F_ENGINE_GET_LAST = 0;
  ENGINE_F_ENGINE_GET_NEXT = 0;
  ENGINE_F_ENGINE_GET_PKEY_ASN1_METH = 0;
  ENGINE_F_ENGINE_GET_PKEY_METH = 0;
  ENGINE_F_ENGINE_GET_PREV = 0;
  ENGINE_F_ENGINE_INIT = 0;
  ENGINE_F_ENGINE_LIST_ADD = 0;
  ENGINE_F_ENGINE_LIST_REMOVE = 0;
  ENGINE_F_ENGINE_LOAD_PRIVATE_KEY = 0;
  ENGINE_F_ENGINE_LOAD_PUBLIC_KEY = 0;
  ENGINE_F_ENGINE_LOAD_SSL_CLIENT_CERT = 0;
  ENGINE_F_ENGINE_NEW = 0;
  ENGINE_F_ENGINE_PKEY_ASN1_FIND_STR = 0;
  ENGINE_F_ENGINE_REMOVE = 0;
  ENGINE_F_ENGINE_SET_DEFAULT_STRING = 0;
  ENGINE_F_ENGINE_SET_ID = 0;
  ENGINE_F_ENGINE_SET_NAME = 0;
  ENGINE_F_ENGINE_TABLE_REGISTER = 0;
  ENGINE_F_ENGINE_UNLOCKED_FINISH = 0;
  ENGINE_F_ENGINE_UP_REF = 0;
  ENGINE_F_INT_CLEANUP_ITEM = 0;
  ENGINE_F_INT_CTRL_HELPER = 0;
  ENGINE_F_INT_ENGINE_CONFIGURE = 0;
  ENGINE_F_INT_ENGINE_MODULE_INIT = 0;
  ENGINE_F_OSSL_HMAC_INIT = 0;
    {$endif}

const
    
    {* EVP function codes.
    }
  EVP_F_AESNI_INIT_KEY = 0;
  EVP_F_AESNI_XTS_INIT_KEY = 0;
  EVP_F_AES_GCM_CTRL = 0;
  EVP_F_AES_INIT_KEY = 0;
  EVP_F_AES_OCB_CIPHER = 0;
  EVP_F_AES_T4_INIT_KEY = 0;
  EVP_F_AES_T4_XTS_INIT_KEY = 0;
  EVP_F_AES_WRAP_CIPHER = 0;
  EVP_F_AES_XTS_INIT_KEY = 0;
  EVP_F_ALG_MODULE_INIT = 0;
  EVP_F_ARIA_CCM_INIT_KEY = 0;
  EVP_F_ARIA_GCM_CTRL = 0;
  EVP_F_ARIA_GCM_INIT_KEY = 0;
  EVP_F_ARIA_INIT_KEY = 0;
  EVP_F_B64_NEW = 0;
  EVP_F_CAMELLIA_INIT_KEY = 0;
  EVP_F_CHACHA20_POLY1305_CTRL = 0;
  EVP_F_CMLL_T4_INIT_KEY = 0;
  EVP_F_DES_EDE3_WRAP_CIPHER = 0;
  EVP_F_DO_SIGVER_INIT = 0;
  EVP_F_ENC_NEW = 0;
  EVP_F_EVP_CIPHERINIT_EX = 0;
  EVP_F_EVP_CIPHER_ASN1_TO_PARAM = 0;
  EVP_F_EVP_CIPHER_CTX_COPY = 0;
  EVP_F_EVP_CIPHER_CTX_CTRL = 0;
  EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH = 0;
  EVP_F_EVP_CIPHER_PARAM_TO_ASN1 = 0;
  EVP_F_EVP_DECRYPTFINAL_EX = 0;
  EVP_F_EVP_DECRYPTUPDATE = 0;
  EVP_F_EVP_DIGESTFINALXOF = 0;
  EVP_F_EVP_DIGESTINIT_EX = 0;
  EVP_F_EVP_ENCRYPTDECRYPTUPDATE = 0;
  EVP_F_EVP_ENCRYPTFINAL_EX = 0;
  EVP_F_EVP_ENCRYPTUPDATE = 0;
  EVP_F_EVP_MD_CTX_COPY_EX = 0;
  EVP_F_EVP_MD_SIZE = 0;
  EVP_F_EVP_OPENINIT = 0;
  EVP_F_EVP_PBE_ALG_ADD = 0;
  EVP_F_EVP_PBE_ALG_ADD_TYPE = 0;
  EVP_F_EVP_PBE_CIPHERINIT = 0;
  EVP_F_EVP_PBE_SCRYPT = 0;
  EVP_F_EVP_PKCS82PKEY = 0;
  EVP_F_EVP_PKEY2PKCS8 = 0;
  EVP_F_EVP_PKEY_ASN1_ADD0 = 0;
  EVP_F_EVP_PKEY_CHECK = 0;
  EVP_F_EVP_PKEY_COPY_PARAMETERS = 0;
  EVP_F_EVP_PKEY_CTX_CTRL = 0;
  EVP_F_EVP_PKEY_CTX_CTRL_STR = 0;
  EVP_F_EVP_PKEY_CTX_DUP = 0;
  EVP_F_EVP_PKEY_CTX_MD = 0;
  EVP_F_EVP_PKEY_DECRYPT = 0;
  EVP_F_EVP_PKEY_DECRYPT_INIT = 0;
  EVP_F_EVP_PKEY_DECRYPT_OLD = 0;
  EVP_F_EVP_PKEY_DERIVE = 0;
  EVP_F_EVP_PKEY_DERIVE_INIT = 0;
  EVP_F_EVP_PKEY_DERIVE_SET_PEER = 0;
  EVP_F_EVP_PKEY_ENCRYPT = 0;
  EVP_F_EVP_PKEY_ENCRYPT_INIT = 0;
  EVP_F_EVP_PKEY_ENCRYPT_OLD = 0;
  EVP_F_EVP_PKEY_GET0_DH = 0;
  EVP_F_EVP_PKEY_GET0_DSA = 0;
  EVP_F_EVP_PKEY_GET0_EC_KEY = 0;
  EVP_F_EVP_PKEY_GET0_HMAC = 0;
  EVP_F_EVP_PKEY_GET0_POLY1305 = 0;
  EVP_F_EVP_PKEY_GET0_RSA = 0;
  EVP_F_EVP_PKEY_GET0_SIPHASH = 0;
  EVP_F_EVP_PKEY_GET_RAW_PRIVATE_KEY = 0;
  EVP_F_EVP_PKEY_GET_RAW_PUBLIC_KEY = 0;
  EVP_F_EVP_PKEY_KEYGEN = 0;
  EVP_F_EVP_PKEY_KEYGEN_INIT = 0;
  EVP_F_EVP_PKEY_METH_ADD0 = 0;
  EVP_F_EVP_PKEY_METH_NEW = 0;
  EVP_F_EVP_PKEY_NEW = 0;
  EVP_F_EVP_PKEY_NEW_CMAC_KEY = 0;
  EVP_F_EVP_PKEY_NEW_RAW_PRIVATE_KEY = 0;
  EVP_F_EVP_PKEY_NEW_RAW_PUBLIC_KEY = 0;
  EVP_F_EVP_PKEY_PARAMGEN = 0;
  EVP_F_EVP_PKEY_PARAMGEN_INIT = 0;
  EVP_F_EVP_PKEY_PARAM_CHECK = 0;
  EVP_F_EVP_PKEY_PUBLIC_CHECK = 0;
  EVP_F_EVP_PKEY_SET1_ENGINE = 0;
  EVP_F_EVP_PKEY_SET_ALIAS_TYPE = 0;
  EVP_F_EVP_PKEY_SIGN = 0;
  EVP_F_EVP_PKEY_SIGN_INIT = 0;
  EVP_F_EVP_PKEY_VERIFY = 0;
  EVP_F_EVP_PKEY_VERIFY_INIT = 0;
  EVP_F_EVP_PKEY_VERIFY_RECOVER = 0;
  EVP_F_EVP_PKEY_VERIFY_RECOVER_INIT = 0;
  EVP_F_EVP_SIGNFINAL = 0;
  EVP_F_EVP_VERIFYFINAL = 0;
  EVP_F_INT_CTX_NEW = 0;
  EVP_F_OK_NEW = 0;
  EVP_F_PKCS5_PBE_KEYIVGEN = 0;
  EVP_F_PKCS5_V2_PBE_KEYIVGEN = 0;
  EVP_F_PKCS5_V2_PBKDF2_KEYIVGEN = 0;
  EVP_F_PKCS5_V2_SCRYPT_KEYIVGEN = 0;
  EVP_F_PKEY_SET_TYPE = 0;
  EVP_F_RC2_MAGIC_TO_METH = 0;
  EVP_F_RC5_CTRL = 0;
  EVP_F_R_32_12_16_INIT_KEY = 0;
  EVP_F_S390X_AES_GCM_CTRL = 0;
  EVP_F_UPDATE = 0;
    
    {* KDF function codes.
    }
  KDF_F_PKEY_HKDF_CTRL_STR = 0;
  KDF_F_PKEY_HKDF_DERIVE = 0;
  KDF_F_PKEY_HKDF_INIT = 0;
  KDF_F_PKEY_SCRYPT_CTRL_STR = 0;
  KDF_F_PKEY_SCRYPT_CTRL_UINT64 = 0;
  KDF_F_PKEY_SCRYPT_DERIVE = 0;
  KDF_F_PKEY_SCRYPT_INIT = 0;
  KDF_F_PKEY_SCRYPT_SET_MEMBUF = 0;
  KDF_F_PKEY_TLS1_PRF_CTRL_STR = 0;
  KDF_F_PKEY_TLS1_PRF_DERIVE = 0;
  KDF_F_PKEY_TLS1_PRF_INIT = 0;
  KDF_F_TLS1_PRF_ALG = 0;
    
    {* KDF reason codes.
    }
  KDF_R_INVALID_DIGEST = 0;
  KDF_R_MISSING_ITERATION_COUNT = 0;
  KDF_R_MISSING_KEY = 0;
  KDF_R_MISSING_MESSAGE_DIGEST = 0;
  KDF_R_MISSING_PARAMETER = 0;
  KDF_R_MISSING_PASS = 0;
  KDF_R_MISSING_SALT = 0;
  KDF_R_MISSING_SECRET = 0;
  KDF_R_MISSING_SEED = 0;
  KDF_R_UNKNOWN_PARAMETER_TYPE = 0;
  KDF_R_VALUE_ERROR = 0;
  KDF_R_VALUE_MISSING = 0;
    
    {* OBJ function codes.
    }
  OBJ_F_OBJ_ADD_OBJECT = 0;
  OBJ_F_OBJ_ADD_SIGID = 0;
  OBJ_F_OBJ_CREATE = 0;
  OBJ_F_OBJ_DUP = 0;
  OBJ_F_OBJ_NAME_NEW_INDEX = 0;
  OBJ_F_OBJ_NID2LN = 0;
  OBJ_F_OBJ_NID2OBJ = 0;
  OBJ_F_OBJ_NID2SN = 0;
  OBJ_F_OBJ_TXT2OBJ = 0;
    {$ifndef  OPENSSL_NO_OCSP}

const
      
      {* OCSP function codes.
      }
  OCSP_F_D2I_OCSP_NONCE = 0;
  OCSP_F_OCSP_BASIC_ADD1_STATUS = 0;
  OCSP_F_OCSP_BASIC_SIGN = 0;
  OCSP_F_OCSP_BASIC_SIGN_CTX = 0;
  OCSP_F_OCSP_BASIC_VERIFY = 0;
  OCSP_F_OCSP_CERT_ID_NEW = 0;
  OCSP_F_OCSP_CHECK_DELEGATED = 0;
  OCSP_F_OCSP_CHECK_IDS = 0;
  OCSP_F_OCSP_CHECK_ISSUER = 0;
  OCSP_F_OCSP_CHECK_VALIDITY = 0;
  OCSP_F_OCSP_MATCH_ISSUERID = 0;
  OCSP_F_OCSP_PARSE_URL = 0;
  OCSP_F_OCSP_REQUEST_SIGN = 0;
  OCSP_F_OCSP_REQUEST_VERIFY = 0;
  OCSP_F_OCSP_RESPONSE_GET1_BASIC = 0;
  OCSP_F_PARSE_HTTP_LINE1 = 0;
    {$endif}

const
    
    {* PEM function codes.
    }
  PEM_F_B2I_DSS = 0;
  PEM_F_B2I_PVK_BIO = 0;
  PEM_F_B2I_RSA = 0;
  PEM_F_CHECK_BITLEN_DSA = 0;
  PEM_F_CHECK_BITLEN_RSA = 0;
  PEM_F_D2I_PKCS8PRIVATEKEY_BIO = 0;
  PEM_F_D2I_PKCS8PRIVATEKEY_FP = 0;
  PEM_F_DO_B2I = 0;
  PEM_F_DO_B2I_BIO = 0;
  PEM_F_DO_BLOB_HEADER = 0;
  PEM_F_DO_I2B = 0;
  PEM_F_DO_PK8PKEY = 0;
  PEM_F_DO_PK8PKEY_FP = 0;
  PEM_F_DO_PVK_BODY = 0;
  PEM_F_DO_PVK_HEADER = 0;
  PEM_F_GET_HEADER_AND_DATA = 0;
  PEM_F_GET_NAME = 0;
  PEM_F_I2B_PVK = 0;
  PEM_F_I2B_PVK_BIO = 0;
  PEM_F_LOAD_IV = 0;
  PEM_F_PEM_ASN1_READ = 0;
  PEM_F_PEM_ASN1_READ_BIO = 0;
  PEM_F_PEM_ASN1_WRITE = 0;
  PEM_F_PEM_ASN1_WRITE_BIO = 0;
  PEM_F_PEM_DEF_CALLBACK = 0;
  PEM_F_PEM_DO_HEADER = 0;
  PEM_F_PEM_GET_EVP_CIPHER_INFO = 0;
  PEM_F_PEM_READ = 0;
  PEM_F_PEM_READ_BIO = 0;
  PEM_F_PEM_READ_BIO_DHPARAMS = 0;
  PEM_F_PEM_READ_BIO_EX = 0;
  PEM_F_PEM_READ_BIO_PARAMETERS = 0;
  PEM_F_PEM_READ_BIO_PRIVATEKEY = 0;
  PEM_F_PEM_READ_DHPARAMS = 0;
  PEM_F_PEM_READ_PRIVATEKEY = 0;
  PEM_F_PEM_SIGNFINAL = 0;
  PEM_F_PEM_WRITE = 0;
  PEM_F_PEM_WRITE_BIO = 0;
  PEM_F_PEM_WRITE_BIO_PRIVATEKEY_TRADITIONAL = 0;
  PEM_F_PEM_WRITE_PRIVATEKEY = 0;
  PEM_F_PEM_X509_INFO_READ = 0;
  PEM_F_PEM_X509_INFO_READ_BIO = 0;
  PEM_F_PEM_X509_INFO_WRITE_BIO = 0;
    
    {* PKCS12 function codes.
    }
  PKCS12_F_OPENSSL_ASC2UNI = 0;
  PKCS12_F_OPENSSL_UNI2ASC = 0;
  PKCS12_F_OPENSSL_UNI2UTF8 = 0;
  PKCS12_F_OPENSSL_UTF82UNI = 0;
  PKCS12_F_PKCS12_CREATE = 0;
  PKCS12_F_PKCS12_GEN_MAC = 0;
  PKCS12_F_PKCS12_INIT = 0;
  PKCS12_F_PKCS12_ITEM_DECRYPT_D2I = 0;
  PKCS12_F_PKCS12_ITEM_I2D_ENCRYPT = 0;
  PKCS12_F_PKCS12_ITEM_PACK_SAFEBAG = 0;
  PKCS12_F_PKCS12_KEY_GEN_ASC = 0;
  PKCS12_F_PKCS12_KEY_GEN_UNI = 0;
  PKCS12_F_PKCS12_KEY_GEN_UTF8 = 0;
  PKCS12_F_PKCS12_NEWPASS = 0;
  PKCS12_F_PKCS12_PACK_P7DATA = 0;
  PKCS12_F_PKCS12_PACK_P7ENCDATA = 0;
  PKCS12_F_PKCS12_PARSE = 0;
  PKCS12_F_PKCS12_PBE_CRYPT = 0;
  PKCS12_F_PKCS12_PBE_KEYIVGEN = 0;
  PKCS12_F_PKCS12_SAFEBAG_CREATE0_P8INF = 0;
  PKCS12_F_PKCS12_SAFEBAG_CREATE0_PKCS8 = 0;
  PKCS12_F_PKCS12_SAFEBAG_CREATE_PKCS8_ENCRYPT = 0;
  PKCS12_F_PKCS12_SETUP_MAC = 0;
  PKCS12_F_PKCS12_SET_MAC = 0;
  PKCS12_F_PKCS12_UNPACK_AUTHSAFES = 0;
  PKCS12_F_PKCS12_UNPACK_P7DATA = 0;
  PKCS12_F_PKCS12_VERIFY_MAC = 0;
  PKCS12_F_PKCS8_ENCRYPT = 0;
  PKCS12_F_PKCS8_SET0_PBE = 0;
    
    {* PKCS7 function codes.
    }
  PKCS7_F_DO_PKCS7_SIGNED_ATTRIB = 0;
  PKCS7_F_PKCS7_ADD0_ATTRIB_SIGNING_TIME = 0;
  PKCS7_F_PKCS7_ADD_ATTRIB_SMIMECAP = 0;
  PKCS7_F_PKCS7_ADD_CERTIFICATE = 0;
  PKCS7_F_PKCS7_ADD_CRL = 0;
  PKCS7_F_PKCS7_ADD_RECIPIENT_INFO = 0;
  PKCS7_F_PKCS7_ADD_SIGNATURE = 0;
  PKCS7_F_PKCS7_ADD_SIGNER = 0;
  PKCS7_F_PKCS7_BIO_ADD_DIGEST = 0;
  PKCS7_F_PKCS7_COPY_EXISTING_DIGEST = 0;
  PKCS7_F_PKCS7_CTRL = 0;
  PKCS7_F_PKCS7_DATADECODE = 0;
  PKCS7_F_PKCS7_DATAFINAL = 0;
  PKCS7_F_PKCS7_DATAINIT = 0;
  PKCS7_F_PKCS7_DATAVERIFY = 0;
  PKCS7_F_PKCS7_DECRYPT = 0;
  PKCS7_F_PKCS7_DECRYPT_RINFO = 0;
  PKCS7_F_PKCS7_ENCODE_RINFO = 0;
  PKCS7_F_PKCS7_ENCRYPT = 0;
  PKCS7_F_PKCS7_FINAL = 0;
  PKCS7_F_PKCS7_FIND_DIGEST = 0;
  PKCS7_F_PKCS7_GET0_SIGNERS = 0;
  PKCS7_F_PKCS7_RECIP_INFO_SET = 0;
  PKCS7_F_PKCS7_SET_CIPHER = 0;
  PKCS7_F_PKCS7_SET_CONTENT = 0;
  PKCS7_F_PKCS7_SET_DIGEST = 0;
  PKCS7_F_PKCS7_SET_TYPE = 0;
  PKCS7_F_PKCS7_SIGN = 0;
  PKCS7_F_PKCS7_SIGNATUREVERIFY = 0;
  PKCS7_F_PKCS7_SIGNER_INFO_SET = 0;
  PKCS7_F_PKCS7_SIGNER_INFO_SIGN = 0;
  PKCS7_F_PKCS7_SIGN_ADD_SIGNER = 0;
  PKCS7_F_PKCS7_SIMPLE_SMIMECAP = 0;
  PKCS7_F_PKCS7_VERIFY = 0;
    
    {* RAND function codes.
    }
  RAND_F_DATA_COLLECT_METHOD = 0;
  RAND_F_DRBG_BYTES = 0;
  RAND_F_DRBG_GET_ENTROPY = 0;
  RAND_F_DRBG_SETUP = 0;
  RAND_F_GET_ENTROPY = 0;
  RAND_F_RAND_BYTES = 0;
  RAND_F_RAND_DRBG_ENABLE_LOCKING = 0;
  RAND_F_RAND_DRBG_GENERATE = 0;
  RAND_F_RAND_DRBG_GET_ENTROPY = 0;
  RAND_F_RAND_DRBG_GET_NONCE = 0;
  RAND_F_RAND_DRBG_INSTANTIATE = 0;
  RAND_F_RAND_DRBG_NEW = 0;
  RAND_F_RAND_DRBG_RESEED = 0;
  RAND_F_RAND_DRBG_RESTART = 0;
  RAND_F_RAND_DRBG_SET = 0;
  RAND_F_RAND_DRBG_SET_DEFAULTS = 0;
  RAND_F_RAND_DRBG_UNINSTANTIATE = 0;
  RAND_F_RAND_LOAD_FILE = 0;
  RAND_F_RAND_POOL_ACQUIRE_ENTROPY = 0;
  RAND_F_RAND_POOL_ADD = 0;
  RAND_F_RAND_POOL_ADD_BEGIN = 0;
  RAND_F_RAND_POOL_ADD_END = 0;
  RAND_F_RAND_POOL_ATTACH = 0;
  RAND_F_RAND_POOL_BYTES_NEEDED = 0;
  RAND_F_RAND_POOL_GROW = 0;
  RAND_F_RAND_POOL_NEW = 0;
  RAND_F_RAND_PSEUDO_BYTES = 0;
  RAND_F_RAND_WRITE_FILE = 0;
    
    {* RSA function codes.
    }
  RSA_F_CHECK_PADDING_MD = 0;
  RSA_F_ENCODE_PKCS1 = 0;
  RSA_F_INT_RSA_VERIFY = 0;
  RSA_F_OLD_RSA_PRIV_DECODE = 0;
  RSA_F_PKEY_PSS_INIT = 0;
  RSA_F_PKEY_RSA_CTRL = 0;
  RSA_F_PKEY_RSA_CTRL_STR = 0;
  RSA_F_PKEY_RSA_SIGN = 0;
  RSA_F_PKEY_RSA_VERIFY = 0;
  RSA_F_PKEY_RSA_VERIFYRECOVER = 0;
  RSA_F_RSA_ALGOR_TO_MD = 0;
  RSA_F_RSA_BUILTIN_KEYGEN = 0;
  RSA_F_RSA_CHECK_KEY = 0;
  RSA_F_RSA_CHECK_KEY_EX = 0;
  RSA_F_RSA_CMS_DECRYPT = 0;
  RSA_F_RSA_CMS_VERIFY = 0;
  RSA_F_RSA_ITEM_VERIFY = 0;
  RSA_F_RSA_METH_DUP = 0;
  RSA_F_RSA_METH_NEW = 0;
  RSA_F_RSA_METH_SET1_NAME = 0;
  RSA_F_RSA_MGF1_TO_MD = 0;
  RSA_F_RSA_MULTIP_INFO_NEW = 0;
  RSA_F_RSA_NEW_METHOD = 0;
  RSA_F_RSA_NULL = 0;
  RSA_F_RSA_NULL_PRIVATE_DECRYPT = 0;
  RSA_F_RSA_NULL_PRIVATE_ENCRYPT = 0;
  RSA_F_RSA_NULL_PUBLIC_DECRYPT = 0;
  RSA_F_RSA_NULL_PUBLIC_ENCRYPT = 0;
  RSA_F_RSA_OSSL_PRIVATE_DECRYPT = 0;
  RSA_F_RSA_OSSL_PRIVATE_ENCRYPT = 0;
  RSA_F_RSA_OSSL_PUBLIC_DECRYPT = 0;
  RSA_F_RSA_OSSL_PUBLIC_ENCRYPT = 0;
  RSA_F_RSA_PADDING_ADD_NONE = 0;
  RSA_F_RSA_PADDING_ADD_PKCS1_OAEP = 0;
  RSA_F_RSA_PADDING_ADD_PKCS1_OAEP_MGF1 = 0;
  RSA_F_RSA_PADDING_ADD_PKCS1_PSS = 0;
  RSA_F_RSA_PADDING_ADD_PKCS1_PSS_MGF1 = 0;
  RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_1 = 0;
  RSA_F_RSA_PADDING_ADD_PKCS1_TYPE_2 = 0;
  RSA_F_RSA_PADDING_ADD_SSLV23 = 0;
  RSA_F_RSA_PADDING_ADD_X931 = 0;
  RSA_F_RSA_PADDING_CHECK_NONE = 0;
  RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP = 0;
  RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP_MGF1 = 0;
  RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_1 = 0;
  RSA_F_RSA_PADDING_CHECK_PKCS1_TYPE_2 = 0;
  RSA_F_RSA_PADDING_CHECK_SSLV23 = 0;
  RSA_F_RSA_PADDING_CHECK_X931 = 0;
  RSA_F_RSA_PARAM_DECODE = 0;
  RSA_F_RSA_PRINT = 0;
  RSA_F_RSA_PRINT_FP = 0;
  RSA_F_RSA_PRIV_DECODE = 0;
  RSA_F_RSA_PRIV_ENCODE = 0;
  RSA_F_RSA_PSS_GET_PARAM = 0;
  RSA_F_RSA_PSS_TO_CTX = 0;
  RSA_F_RSA_PUB_DECODE = 0;
  RSA_F_RSA_SETUP_BLINDING = 0;
  RSA_F_RSA_SIGN = 0;
  RSA_F_RSA_SIGN_ASN1_OCTET_STRING = 0;
  RSA_F_RSA_VERIFY = 0;
  RSA_F_RSA_VERIFY_ASN1_OCTET_STRING = 0;
  RSA_F_RSA_VERIFY_PKCS1_PSS_MGF1 = 0;
  RSA_F_SETUP_TBUF = 0;
    
    {* OSSL_STORE function codes.
    }
  OSSL_STORE_F_FILE_CTRL = 0;
  OSSL_STORE_F_FILE_FIND = 0;
  OSSL_STORE_F_FILE_GET_PASS = 0;
  OSSL_STORE_F_FILE_LOAD = 0;
  OSSL_STORE_F_FILE_LOAD_TRY_DECODE = 0;
  OSSL_STORE_F_FILE_NAME_TO_URI = 0;
  OSSL_STORE_F_FILE_OPEN = 0;
  OSSL_STORE_F_OSSL_STORE_ATTACH_PEM_BIO = 0;
  OSSL_STORE_F_OSSL_STORE_EXPECT = 0;
  OSSL_STORE_F_OSSL_STORE_FILE_ATTACH_PEM_BIO_INT = 0;
  OSSL_STORE_F_OSSL_STORE_FIND = 0;
  OSSL_STORE_F_OSSL_STORE_GET0_LOADER_INT = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_GET1_CERT = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_GET1_CRL = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_GET1_NAME = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_GET1_NAME_DESCRIPTION = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_GET1_PARAMS = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_GET1_PKEY = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_NEW_CERT = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_NEW_CRL = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_NEW_EMBEDDED = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_NEW_NAME = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_NEW_PARAMS = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_NEW_PKEY = 0;
  OSSL_STORE_F_OSSL_STORE_INFO_SET0_NAME_DESCRIPTION = 0;
  OSSL_STORE_F_OSSL_STORE_INIT_ONCE = 0;
  OSSL_STORE_F_OSSL_STORE_LOADER_NEW = 0;
  OSSL_STORE_F_OSSL_STORE_OPEN = 0;
  OSSL_STORE_F_OSSL_STORE_OPEN_INT = 0;
  OSSL_STORE_F_OSSL_STORE_REGISTER_LOADER_INT = 0;
  OSSL_STORE_F_OSSL_STORE_SEARCH_BY_ALIAS = 0;
  OSSL_STORE_F_OSSL_STORE_SEARCH_BY_ISSUER_SERIAL = 0;
  OSSL_STORE_F_OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT = 0;
  OSSL_STORE_F_OSSL_STORE_SEARCH_BY_NAME = 0;
  OSSL_STORE_F_OSSL_STORE_UNREGISTER_LOADER_INT = 0;
  OSSL_STORE_F_TRY_DECODE_PARAMS = 0;
  OSSL_STORE_F_TRY_DECODE_PKCS12 = 0;
  OSSL_STORE_F_TRY_DECODE_PKCS8ENCRYPTED = 0;
    {$ifndef  OPENSSL_NO_TS}

const
      
      {* TS function codes.
      }
  TS_F_DEF_SERIAL_CB = 0;
  TS_F_DEF_TIME_CB = 0;
  TS_F_ESS_ADD_SIGNING_CERT = 0;
  TS_F_ESS_ADD_SIGNING_CERT_V2 = 0;
  TS_F_ESS_CERT_ID_NEW_INIT = 0;
  TS_F_ESS_CERT_ID_V2_NEW_INIT = 0;
  TS_F_ESS_SIGNING_CERT_NEW_INIT = 0;
  TS_F_ESS_SIGNING_CERT_V2_NEW_INIT = 0;
  TS_F_INT_TS_RESP_VERIFY_TOKEN = 0;
  TS_F_PKCS7_TO_TS_TST_INFO = 0;
  TS_F_TS_ACCURACY_SET_MICROS = 0;
  TS_F_TS_ACCURACY_SET_MILLIS = 0;
  TS_F_TS_ACCURACY_SET_SECONDS = 0;
  TS_F_TS_CHECK_IMPRINTS = 0;
  TS_F_TS_CHECK_NONCES = 0;
  TS_F_TS_CHECK_POLICY = 0;
  TS_F_TS_CHECK_SIGNING_CERTS = 0;
  TS_F_TS_CHECK_STATUS_INFO = 0;
  TS_F_TS_COMPUTE_IMPRINT = 0;
  TS_F_TS_CONF_INVALID = 0;
  TS_F_TS_CONF_LOAD_CERT = 0;
  TS_F_TS_CONF_LOAD_CERTS = 0;
  TS_F_TS_CONF_LOAD_KEY = 0;
  TS_F_TS_CONF_LOOKUP_FAIL = 0;
  TS_F_TS_CONF_SET_DEFAULT_ENGINE = 0;
  TS_F_TS_GET_STATUS_TEXT = 0;
  TS_F_TS_MSG_IMPRINT_SET_ALGO = 0;
  TS_F_TS_REQ_SET_MSG_IMPRINT = 0;
  TS_F_TS_REQ_SET_NONCE = 0;
  TS_F_TS_REQ_SET_POLICY_ID = 0;
  TS_F_TS_RESP_CREATE_RESPONSE = 0;
  TS_F_TS_RESP_CREATE_TST_INFO = 0;
  TS_F_TS_RESP_CTX_ADD_FAILURE_INFO = 0;
  TS_F_TS_RESP_CTX_ADD_MD = 0;
  TS_F_TS_RESP_CTX_ADD_POLICY = 0;
  TS_F_TS_RESP_CTX_NEW = 0;
  TS_F_TS_RESP_CTX_SET_ACCURACY = 0;
  TS_F_TS_RESP_CTX_SET_CERTS = 0;
  TS_F_TS_RESP_CTX_SET_DEF_POLICY = 0;
  TS_F_TS_RESP_CTX_SET_SIGNER_CERT = 0;
  TS_F_TS_RESP_CTX_SET_STATUS_INFO = 0;
  TS_F_TS_RESP_GET_POLICY = 0;
  TS_F_TS_RESP_SET_GENTIME_WITH_PRECISION = 0;
  TS_F_TS_RESP_SET_STATUS_INFO = 0;
  TS_F_TS_RESP_SET_TST_INFO = 0;
  TS_F_TS_RESP_SIGN = 0;
  TS_F_TS_RESP_VERIFY_SIGNATURE = 0;
  TS_F_TS_TST_INFO_SET_ACCURACY = 0;
  TS_F_TS_TST_INFO_SET_MSG_IMPRINT = 0;
  TS_F_TS_TST_INFO_SET_NONCE = 0;
  TS_F_TS_TST_INFO_SET_POLICY_ID = 0;
  TS_F_TS_TST_INFO_SET_SERIAL = 0;
  TS_F_TS_TST_INFO_SET_TIME = 0;
  TS_F_TS_TST_INFO_SET_TSA = 0;
  TS_F_TS_VERIFY = 0;
  TS_F_TS_VERIFY_CERT = 0;
  TS_F_TS_VERIFY_CTX_NEW = 0;
    {$endif}

const
    
    {* UI function codes.
    }
  UI_F_CLOSE_CONSOLE = 0;
  UI_F_ECHO_CONSOLE = 0;
  UI_F_GENERAL_ALLOCATE_BOOLEAN = 0;
  UI_F_GENERAL_ALLOCATE_PROMPT = 0;
  UI_F_NOECHO_CONSOLE = 0;
  UI_F_OPEN_CONSOLE = 0;
  UI_F_UI_CONSTRUCT_PROMPT = 0;
  UI_F_UI_CREATE_METHOD = 0;
  UI_F_UI_CTRL = 0;
  UI_F_UI_DUP_ERROR_STRING = 0;
  UI_F_UI_DUP_INFO_STRING = 0;
  UI_F_UI_DUP_INPUT_BOOLEAN = 0;
  UI_F_UI_DUP_INPUT_STRING = 0;
  UI_F_UI_DUP_USER_DATA = 0;
  UI_F_UI_DUP_VERIFY_STRING = 0;
  UI_F_UI_GET0_RESULT = 0;
  UI_F_UI_GET_RESULT_LENGTH = 0;
  UI_F_UI_NEW_METHOD = 0;
  UI_F_UI_PROCESS = 0;
  UI_F_UI_SET_RESULT = 0;
  UI_F_UI_SET_RESULT_EX = 0;
    
    {* X509 function codes.
    }
  X509_F_ADD_CERT_DIR = 0;
  X509_F_BUILD_CHAIN = 0;
  X509_F_BY_FILE_CTRL = 0;
  X509_F_CHECK_NAME_CONSTRAINTS = 0;
  X509_F_CHECK_POLICY = 0;
  X509_F_DANE_I2D = 0;
  X509_F_DIR_CTRL = 0;
  X509_F_GET_CERT_BY_SUBJECT = 0;
  X509_F_I2D_X509_AUX = 0;
  X509_F_LOOKUP_CERTS_SK = 0;
  X509_F_NETSCAPE_SPKI_B64_DECODE = 0;
  X509_F_NETSCAPE_SPKI_B64_ENCODE = 0;
  X509_F_NEW_DIR = 0;
  X509_F_X509AT_ADD1_ATTR = 0;
  X509_F_X509V3_ADD_EXT = 0;
  X509_F_X509_ATTRIBUTE_CREATE_BY_NID = 0;
  X509_F_X509_ATTRIBUTE_CREATE_BY_OBJ = 0;
  X509_F_X509_ATTRIBUTE_CREATE_BY_TXT = 0;
  X509_F_X509_ATTRIBUTE_GET0_DATA = 0;
  X509_F_X509_ATTRIBUTE_SET1_DATA = 0;
  X509_F_X509_CHECK_PRIVATE_KEY = 0;
  X509_F_X509_CRL_DIFF = 0;
  X509_F_X509_CRL_METHOD_NEW = 0;
  X509_F_X509_CRL_PRINT_FP = 0;
  X509_F_X509_EXTENSION_CREATE_BY_NID = 0;
  X509_F_X509_EXTENSION_CREATE_BY_OBJ = 0;
  X509_F_X509_GET_PUBKEY_PARAMETERS = 0;
  X509_F_X509_LOAD_CERT_CRL_FILE = 0;
  X509_F_X509_LOAD_CERT_FILE = 0;
  X509_F_X509_LOAD_CRL_FILE = 0;
  X509_F_X509_LOOKUP_METH_NEW = 0;
  X509_F_X509_LOOKUP_NEW = 0;
  X509_F_X509_NAME_ADD_ENTRY = 0;
  X509_F_X509_NAME_CANON = 0;
  X509_F_X509_NAME_ENTRY_CREATE_BY_NID = 0;
  X509_F_X509_NAME_ENTRY_CREATE_BY_TXT = 0;
  X509_F_X509_NAME_ENTRY_SET_OBJECT = 0;
  X509_F_X509_NAME_ONELINE = 0;
  X509_F_X509_NAME_PRINT = 0;
  X509_F_X509_OBJECT_NEW = 0;
  X509_F_X509_PRINT_EX_FP = 0;
  X509_F_X509_PUBKEY_DECODE = 0;
  X509_F_X509_PUBKEY_GET = 0;
  X509_F_X509_PUBKEY_GET0 = 0;
  X509_F_X509_PUBKEY_SET = 0;
  X509_F_X509_REQ_CHECK_PRIVATE_KEY = 0;
  X509_F_X509_REQ_PRINT_EX = 0;
  X509_F_X509_REQ_PRINT_FP = 0;
  X509_F_X509_REQ_TO_X509 = 0;
  X509_F_X509_STORE_ADD_CERT = 0;
  X509_F_X509_STORE_ADD_CRL = 0;
  X509_F_X509_STORE_ADD_LOOKUP = 0;
  X509_F_X509_STORE_CTX_GET1_ISSUER = 0;
  X509_F_X509_STORE_CTX_INIT = 0;
  X509_F_X509_STORE_CTX_NEW = 0;
  X509_F_X509_STORE_CTX_PURPOSE_INHERIT = 0;
  X509_F_X509_STORE_NEW = 0;
  X509_F_X509_TO_X509_REQ = 0;
  X509_F_X509_TRUST_ADD = 0;
  X509_F_X509_TRUST_SET = 0;
  X509_F_X509_VERIFY_CERT = 0;
  X509_F_X509_VERIFY_PARAM_NEW = 0;
    
    {* X509V3 function codes.
    }
  X509V3_F_A2I_GENERAL_NAME = 0;
  X509V3_F_ADDR_VALIDATE_PATH_INTERNAL = 0;
  X509V3_F_ASIDENTIFIERCHOICE_CANONIZE = 0;
  X509V3_F_ASIDENTIFIERCHOICE_IS_CANONICAL = 0;
  X509V3_F_BIGNUM_TO_STRING = 0;
  X509V3_F_COPY_EMAIL = 0;
  X509V3_F_COPY_ISSUER = 0;
  X509V3_F_DO_DIRNAME = 0;
  X509V3_F_DO_EXT_I2D = 0;
  X509V3_F_DO_EXT_NCONF = 0;
  X509V3_F_GNAMES_FROM_SECTNAME = 0;
  X509V3_F_I2S_ASN1_ENUMERATED = 0;
  X509V3_F_I2S_ASN1_IA5STRING = 0;
  X509V3_F_I2S_ASN1_INTEGER = 0;
  X509V3_F_I2V_AUTHORITY_INFO_ACCESS = 0;
  X509V3_F_LEVEL_ADD_NODE = 0;
  X509V3_F_NOTICE_SECTION = 0;
  X509V3_F_NREF_NOS = 0;
  X509V3_F_POLICY_CACHE_CREATE = 0;
  X509V3_F_POLICY_CACHE_NEW = 0;
  X509V3_F_POLICY_DATA_NEW = 0;
  X509V3_F_POLICY_SECTION = 0;
  X509V3_F_PROCESS_PCI_VALUE = 0;
  X509V3_F_R2I_CERTPOL = 0;
  X509V3_F_R2I_PCI = 0;
  X509V3_F_S2I_ASN1_IA5STRING = 0;
  X509V3_F_S2I_ASN1_INTEGER = 0;
  X509V3_F_S2I_ASN1_OCTET_STRING = 0;
  X509V3_F_S2I_SKEY_ID = 0;
  X509V3_F_SET_DIST_POINT_NAME = 0;
  X509V3_F_SXNET_ADD_ID_ASC = 0;
  X509V3_F_SXNET_ADD_ID_INTEGER = 0;
  X509V3_F_SXNET_ADD_ID_ULONG = 0;
  X509V3_F_SXNET_GET_ID_ASC = 0;
  X509V3_F_SXNET_GET_ID_ULONG = 0;
  X509V3_F_TREE_INIT = 0;
  X509V3_F_V2I_ASIDENTIFIERS = 0;
  X509V3_F_V2I_ASN1_BIT_STRING = 0;
  X509V3_F_V2I_AUTHORITY_INFO_ACCESS = 0;
  X509V3_F_V2I_AUTHORITY_KEYID = 0;
  X509V3_F_V2I_BASIC_CONSTRAINTS = 0;
  X509V3_F_V2I_CRLD = 0;
  X509V3_F_V2I_EXTENDED_KEY_USAGE = 0;
  X509V3_F_V2I_GENERAL_NAMES = 0;
  X509V3_F_V2I_GENERAL_NAME_EX = 0;
  X509V3_F_V2I_IDP = 0;
  X509V3_F_V2I_IPADDRBLOCKS = 0;
  X509V3_F_V2I_ISSUER_ALT = 0;
  X509V3_F_V2I_NAME_CONSTRAINTS = 0;
  X509V3_F_V2I_POLICY_CONSTRAINTS = 0;
  X509V3_F_V2I_POLICY_MAPPINGS = 0;
  X509V3_F_V2I_SUBJECT_ALT = 0;
  X509V3_F_V2I_TLS_FEATURE = 0;
  X509V3_F_V3_GENERIC_EXTENSION = 0;
  X509V3_F_X509V3_ADD1_I2D = 0;
  X509V3_F_X509V3_ADD_VALUE = 0;
  X509V3_F_X509V3_EXT_ADD = 0;
  X509V3_F_X509V3_EXT_ADD_ALIAS = 0;
  X509V3_F_X509V3_EXT_I2D = 0;
  X509V3_F_X509V3_EXT_NCONF = 0;
  X509V3_F_X509V3_GET_SECTION = 0;
  X509V3_F_X509V3_GET_STRING = 0;
  X509V3_F_X509V3_GET_VALUE_BOOL = 0;
  X509V3_F_X509V3_PARSE_LIST = 0;
  X509V3_F_X509_PURPOSE_ADD = 0;
  X509V3_F_X509_PURPOSE_SET = 0;
    
    {* Compatibility defines.
    }
  EVP_R_OPERATON_NOT_INITIALIZED = EVP_R_OPERATION_NOT_INITIALIZED;
  {$endif}
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
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_load_ASN1_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_ASN1_strings := LoadLibCryptoFunction('ERR_load_ASN1_strings');
  if not assigned(ERR_load_ASN1_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_ASN1_strings');
  Result := ERR_load_ASN1_strings;
end;

function Load_ERR_load_ASYNC_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_ASYNC_strings := LoadLibCryptoFunction('ERR_load_ASYNC_strings');
  if not assigned(ERR_load_ASYNC_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_ASYNC_strings');
  Result := ERR_load_ASYNC_strings;
end;

function Load_ERR_load_BIO_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_BIO_strings := LoadLibCryptoFunction('ERR_load_BIO_strings');
  if not assigned(ERR_load_BIO_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_BIO_strings');
  Result := ERR_load_BIO_strings;
end;

function Load_ERR_load_BN_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_BN_strings := LoadLibCryptoFunction('ERR_load_BN_strings');
  if not assigned(ERR_load_BN_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_BN_strings');
  Result := ERR_load_BN_strings;
end;

function Load_ERR_load_BUF_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_BUF_strings := LoadLibCryptoFunction('ERR_load_BUF_strings');
  if not assigned(ERR_load_BUF_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_BUF_strings');
  Result := ERR_load_BUF_strings;
end;

    {$ifndef  OPENSSL_NO_CMS}
function Load_ERR_load_CMS_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_CMS_strings := LoadLibCryptoFunction('ERR_load_CMS_strings');
  if not assigned(ERR_load_CMS_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_CMS_strings');
  Result := ERR_load_CMS_strings;
end;

    {$endif} { OPENSSL_NO_CMS}
    {$ifndef  OPENSSL_NO_COMP}
function Load_ERR_load_COMP_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_COMP_strings := LoadLibCryptoFunction('ERR_load_COMP_strings');
  if not assigned(ERR_load_COMP_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_COMP_strings');
  Result := ERR_load_COMP_strings;
end;

    {$endif} { OPENSSL_NO_COMP}
function Load_ERR_load_CONF_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_CONF_strings := LoadLibCryptoFunction('ERR_load_CONF_strings');
  if not assigned(ERR_load_CONF_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_CONF_strings');
  Result := ERR_load_CONF_strings;
end;

function Load_ERR_load_CRYPTO_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_CRYPTO_strings := LoadLibCryptoFunction('ERR_load_CRYPTO_strings');
  if not assigned(ERR_load_CRYPTO_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_CRYPTO_strings');
  Result := ERR_load_CRYPTO_strings;
end;

    {$ifndef  OPENSSL_NO_CT}
function Load_ERR_load_CT_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_CT_strings := LoadLibCryptoFunction('ERR_load_CT_strings');
  if not assigned(ERR_load_CT_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_CT_strings');
  Result := ERR_load_CT_strings;
end;

    {$endif} { OPENSSL_NO_CT}
    {$ifndef  OPENSSL_NO_DH}
function Load_ERR_load_DH_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_DH_strings := LoadLibCryptoFunction('ERR_load_DH_strings');
  if not assigned(ERR_load_DH_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_DH_strings');
  Result := ERR_load_DH_strings;
end;

    {$endif} { OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_DSA}
function Load_ERR_load_DSA_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_DSA_strings := LoadLibCryptoFunction('ERR_load_DSA_strings');
  if not assigned(ERR_load_DSA_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_DSA_strings');
  Result := ERR_load_DSA_strings;
end;

    {$endif} { OPENSSL_NO_DSA}
    {$ifndef  OPENSSL_NO_EC}
function Load_ERR_load_EC_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_EC_strings := LoadLibCryptoFunction('ERR_load_EC_strings');
  if not assigned(ERR_load_EC_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_EC_strings');
  Result := ERR_load_EC_strings;
end;

    {$endif} { OPENSSL_NO_EC}
    {$ifndef  OPENSSL_NO_ENGINE}
function Load_ERR_load_ENGINE_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_ENGINE_strings := LoadLibCryptoFunction('ERR_load_ENGINE_strings');
  if not assigned(ERR_load_ENGINE_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_ENGINE_strings');
  Result := ERR_load_ENGINE_strings;
end;

    {$endif} { OPENSSL_NO_ENGINE}
function Load_ERR_load_ERR_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_ERR_strings := LoadLibCryptoFunction('ERR_load_ERR_strings');
  if not assigned(ERR_load_ERR_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_ERR_strings');
  Result := ERR_load_ERR_strings;
end;

function Load_ERR_load_EVP_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_EVP_strings := LoadLibCryptoFunction('ERR_load_EVP_strings');
  if not assigned(ERR_load_EVP_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_EVP_strings');
  Result := ERR_load_EVP_strings;
end;

function Load_ERR_load_KDF_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_KDF_strings := LoadLibCryptoFunction('ERR_load_KDF_strings');
  if not assigned(ERR_load_KDF_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_KDF_strings');
  Result := ERR_load_KDF_strings;
end;

function Load_ERR_load_OBJ_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_OBJ_strings := LoadLibCryptoFunction('ERR_load_OBJ_strings');
  if not assigned(ERR_load_OBJ_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_OBJ_strings');
  Result := ERR_load_OBJ_strings;
end;

    {$ifndef  OPENSSL_NO_OCSP}
function Load_ERR_load_OCSP_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_OCSP_strings := LoadLibCryptoFunction('ERR_load_OCSP_strings');
  if not assigned(ERR_load_OCSP_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_OCSP_strings');
  Result := ERR_load_OCSP_strings;
end;

    {$endif} { OPENSSL_NO_OCSP}
function Load_ERR_load_PEM_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_PEM_strings := LoadLibCryptoFunction('ERR_load_PEM_strings');
  if not assigned(ERR_load_PEM_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_PEM_strings');
  Result := ERR_load_PEM_strings;
end;

function Load_ERR_load_PKCS12_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_PKCS12_strings := LoadLibCryptoFunction('ERR_load_PKCS12_strings');
  if not assigned(ERR_load_PKCS12_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_PKCS12_strings');
  Result := ERR_load_PKCS12_strings;
end;

function Load_ERR_load_PKCS7_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_PKCS7_strings := LoadLibCryptoFunction('ERR_load_PKCS7_strings');
  if not assigned(ERR_load_PKCS7_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_PKCS7_strings');
  Result := ERR_load_PKCS7_strings;
end;

function Load_ERR_load_RAND_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_RAND_strings := LoadLibCryptoFunction('ERR_load_RAND_strings');
  if not assigned(ERR_load_RAND_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_RAND_strings');
  Result := ERR_load_RAND_strings;
end;

function Load_ERR_load_RSA_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_RSA_strings := LoadLibCryptoFunction('ERR_load_RSA_strings');
  if not assigned(ERR_load_RSA_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_RSA_strings');
  Result := ERR_load_RSA_strings;
end;

function Load_ERR_load_OSSL_STORE_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_OSSL_STORE_strings := LoadLibCryptoFunction('ERR_load_OSSL_STORE_strings');
  if not assigned(ERR_load_OSSL_STORE_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_OSSL_STORE_strings');
  Result := ERR_load_OSSL_STORE_strings;
end;

    {$ifndef  OPENSSL_NO_TS}
function Load_ERR_load_TS_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_TS_strings := LoadLibCryptoFunction('ERR_load_TS_strings');
  if not assigned(ERR_load_TS_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_TS_strings');
  Result := ERR_load_TS_strings;
end;

    {$endif} { OPENSSL_NO_TS}
function Load_ERR_load_UI_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_UI_strings := LoadLibCryptoFunction('ERR_load_UI_strings');
  if not assigned(ERR_load_UI_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_UI_strings');
  Result := ERR_load_UI_strings;
end;

function Load_ERR_load_X509_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_X509_strings := LoadLibCryptoFunction('ERR_load_X509_strings');
  if not assigned(ERR_load_X509_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_X509_strings');
  Result := ERR_load_X509_strings;
end;

function Load_ERR_load_X509V3_strings: TOpenSSL_C_INT; cdecl;
begin
  ERR_load_X509V3_strings := LoadLibCryptoFunction('ERR_load_X509V3_strings');
  if not assigned(ERR_load_X509V3_strings) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_X509V3_strings');
  Result := ERR_load_X509V3_strings;
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ERR_load_ASN1_strings := Load_ERR_load_ASN1_strings;
  ERR_load_ASYNC_strings := Load_ERR_load_ASYNC_strings;
  ERR_load_BIO_strings := Load_ERR_load_BIO_strings;
  ERR_load_BN_strings := Load_ERR_load_BN_strings;
  ERR_load_BUF_strings := Load_ERR_load_BUF_strings;
    {$ifndef  OPENSSL_NO_CMS}
  ERR_load_CMS_strings := Load_ERR_load_CMS_strings;
    {$endif} { OPENSSL_NO_CMS}
    {$ifndef  OPENSSL_NO_COMP}
  ERR_load_COMP_strings := Load_ERR_load_COMP_strings;
    {$endif} { OPENSSL_NO_COMP}
  ERR_load_CONF_strings := Load_ERR_load_CONF_strings;
  ERR_load_CRYPTO_strings := Load_ERR_load_CRYPTO_strings;
    {$ifndef  OPENSSL_NO_CT}
  ERR_load_CT_strings := Load_ERR_load_CT_strings;
    {$endif} { OPENSSL_NO_CT}
    {$ifndef  OPENSSL_NO_DH}
  ERR_load_DH_strings := Load_ERR_load_DH_strings;
    {$endif} { OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_DSA}
  ERR_load_DSA_strings := Load_ERR_load_DSA_strings;
    {$endif} { OPENSSL_NO_DSA}
    {$ifndef  OPENSSL_NO_EC}
  ERR_load_EC_strings := Load_ERR_load_EC_strings;
    {$endif} { OPENSSL_NO_EC}
    {$ifndef  OPENSSL_NO_ENGINE}
  ERR_load_ENGINE_strings := Load_ERR_load_ENGINE_strings;
    {$endif} { OPENSSL_NO_ENGINE}
  ERR_load_ERR_strings := Load_ERR_load_ERR_strings;
  ERR_load_EVP_strings := Load_ERR_load_EVP_strings;
  ERR_load_KDF_strings := Load_ERR_load_KDF_strings;
  ERR_load_OBJ_strings := Load_ERR_load_OBJ_strings;
    {$ifndef  OPENSSL_NO_OCSP}
  ERR_load_OCSP_strings := Load_ERR_load_OCSP_strings;
    {$endif} { OPENSSL_NO_OCSP}
  ERR_load_PEM_strings := Load_ERR_load_PEM_strings;
  ERR_load_PKCS12_strings := Load_ERR_load_PKCS12_strings;
  ERR_load_PKCS7_strings := Load_ERR_load_PKCS7_strings;
  ERR_load_RAND_strings := Load_ERR_load_RAND_strings;
  ERR_load_RSA_strings := Load_ERR_load_RSA_strings;
  ERR_load_OSSL_STORE_strings := Load_ERR_load_OSSL_STORE_strings;
    {$ifndef  OPENSSL_NO_TS}
  ERR_load_TS_strings := Load_ERR_load_TS_strings;
    {$endif} { OPENSSL_NO_TS}
  ERR_load_UI_strings := Load_ERR_load_UI_strings;
  ERR_load_X509_strings := Load_ERR_load_X509_strings;
  ERR_load_X509V3_strings := Load_ERR_load_X509V3_strings;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
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



