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

unit openssl_dh;

{
  Generated from OpenSSL 3.5.6 Header File dh.h - Tue 19 May 14:27:32 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_dh.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_evp,openssl_types,openssl_e_os2,openssl_bio,
     openssl_asn1,openssl_bn,openssl_dherr;


{* Copyright 1995-2023 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_DH_H}
  {$define OPENSSL_DH_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_DH_H}
  {$endif}
  {$include openssl_opensslconf.inc}

const
  
  {* DH parameter generation types used by EVP_PKEY_CTX_set_dh_paramgen_type()
  * Note that additions/changes to this set of values requires corresponding
  * adjustments to range checks in dh_gen()
  }
  DH_PARAMGEN_TYPE_GENERATOR = 0;
  DH_PARAMGEN_TYPE_FIPS_186_2 = 1;
  DH_PARAMGEN_TYPE_FIPS_186_4 = 2;
  DH_PARAMGEN_TYPE_GROUP = 3;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_dh_paramgen_type(ctx: PEVP_PKEY_CTX; typ: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_type';
  function EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_gindex';
  function EVP_PKEY_CTX_set_dh_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_seed';
  function EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx: PEVP_PKEY_CTX; pbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_prime_len';
  function EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx: PEVP_PKEY_CTX; qlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_subprime_len';
  function EVP_PKEY_CTX_set_dh_paramgen_generator(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_paramgen_generator';
  function EVP_PKEY_CTX_set_dh_nid(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_nid';
  function EVP_PKEY_CTX_set_dh_rfc5114(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_rfc5114';
  function EVP_PKEY_CTX_set_dhx_rfc5114(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dhx_rfc5114';
  function EVP_PKEY_CTX_set_dh_pad(ctx: PEVP_PKEY_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_pad';
  function EVP_PKEY_CTX_set_dh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_kdf_type';
  function EVP_PKEY_CTX_get_dh_kdf_type(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_dh_kdf_type';
  function EVP_PKEY_CTX_set0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set0_dh_kdf_oid';
  function EVP_PKEY_CTX_get0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_dh_kdf_oid';
  function EVP_PKEY_CTX_set_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_kdf_md';
  function EVP_PKEY_CTX_get_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_dh_kdf_md';
  function EVP_PKEY_CTX_set_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dh_kdf_outlen';
  function EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_dh_kdf_outlen';
  function EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set0_dh_kdf_ukm';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_type}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_gindex}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_seed}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_prime_len}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_subprime_len}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_paramgen_generator}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_nid}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_rfc5114}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dhx_rfc5114}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_pad}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_kdf_type}
  {$EXTERNALSYM EVP_PKEY_CTX_get_dh_kdf_type}
  {$EXTERNALSYM EVP_PKEY_CTX_set0_dh_kdf_oid}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_dh_kdf_oid}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_kdf_md}
  {$EXTERNALSYM EVP_PKEY_CTX_get_dh_kdf_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dh_kdf_outlen}
  {$EXTERNALSYM EVP_PKEY_CTX_get_dh_kdf_outlen}
  {$EXTERNALSYM EVP_PKEY_CTX_set0_dh_kdf_ukm}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_dh_paramgen_type(ctx: PEVP_PKEY_CTX; typ: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx: PEVP_PKEY_CTX; pbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx: PEVP_PKEY_CTX; qlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_paramgen_generator(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_nid(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_rfc5114(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dhx_rfc5114(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_pad(ctx: PEVP_PKEY_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_dh_kdf_type(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_dh_paramgen_type: function(ctx: PEVP_PKEY_CTX; typ: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_paramgen_type;
  EVP_PKEY_CTX_set_dh_paramgen_gindex: function(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_paramgen_gindex;
  EVP_PKEY_CTX_set_dh_paramgen_seed: function(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_paramgen_seed;
  EVP_PKEY_CTX_set_dh_paramgen_prime_len: function(ctx: PEVP_PKEY_CTX; pbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_paramgen_prime_len;
  EVP_PKEY_CTX_set_dh_paramgen_subprime_len: function(ctx: PEVP_PKEY_CTX; qlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_paramgen_subprime_len;
  EVP_PKEY_CTX_set_dh_paramgen_generator: function(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_paramgen_generator;
  EVP_PKEY_CTX_set_dh_nid: function(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_nid;
  EVP_PKEY_CTX_set_dh_rfc5114: function(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_rfc5114;
  EVP_PKEY_CTX_set_dhx_rfc5114: function(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dhx_rfc5114;
  EVP_PKEY_CTX_set_dh_pad: function(ctx: PEVP_PKEY_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_pad;
  EVP_PKEY_CTX_set_dh_kdf_type: function(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_kdf_type;
  EVP_PKEY_CTX_get_dh_kdf_type: function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_dh_kdf_type;
  EVP_PKEY_CTX_set0_dh_kdf_oid: function(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set0_dh_kdf_oid;
  EVP_PKEY_CTX_get0_dh_kdf_oid: function(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get0_dh_kdf_oid;
  EVP_PKEY_CTX_set_dh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_kdf_md;
  EVP_PKEY_CTX_get_dh_kdf_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_dh_kdf_md;
  EVP_PKEY_CTX_set_dh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dh_kdf_outlen;
  EVP_PKEY_CTX_get_dh_kdf_outlen: function(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_dh_kdf_outlen;
  EVP_PKEY_CTX_set0_dh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set0_dh_kdf_ukm;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_dh_kdf_ukm'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_dh_kdf_ukm}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_get0_dh_kdf_ukm: function(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get0_dh_kdf_ukm;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}

const
  EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN = EVP_PKEY_ALG_CTRL+1;
  EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR = EVP_PKEY_ALG_CTRL+2;
  EVP_PKEY_CTRL_DH_RFC5114 = EVP_PKEY_ALG_CTRL+3;
  EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN = EVP_PKEY_ALG_CTRL+4;
  EVP_PKEY_CTRL_DH_PARAMGEN_TYPE = EVP_PKEY_ALG_CTRL+5;
  EVP_PKEY_CTRL_DH_KDF_TYPE = EVP_PKEY_ALG_CTRL+6;
  EVP_PKEY_CTRL_DH_KDF_MD = EVP_PKEY_ALG_CTRL+7;
  EVP_PKEY_CTRL_GET_DH_KDF_MD = EVP_PKEY_ALG_CTRL+8;
  EVP_PKEY_CTRL_DH_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+9;
  EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN = EVP_PKEY_ALG_CTRL+10;
  EVP_PKEY_CTRL_DH_KDF_UKM = EVP_PKEY_ALG_CTRL+11;
  EVP_PKEY_CTRL_GET_DH_KDF_UKM = EVP_PKEY_ALG_CTRL+12;
  EVP_PKEY_CTRL_DH_KDF_OID = EVP_PKEY_ALG_CTRL+13;
  EVP_PKEY_CTRL_GET_DH_KDF_OID = EVP_PKEY_ALG_CTRL+14;
  EVP_PKEY_CTRL_DH_NID = EVP_PKEY_ALG_CTRL+15;
  EVP_PKEY_CTRL_DH_PAD = EVP_PKEY_ALG_CTRL+16;
  { KDF types }
  EVP_PKEY_DH_KDF_NONE = 1;
  EVP_PKEY_DH_KDF_X9_42 = 2;
  {$ifndef  OPENSSL_NO_STDIO}
  {$endif}
  {$ifndef  OPENSSL_NO_DH}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
    {$endif}
    {$ifndef  OPENSSL_DH_MAX_MODULUS_BITS}

const
  OPENSSL_DH_MAX_MODULUS_BITS = 10000;
    {$endif}
    {$ifndef  OPENSSL_DH_CHECK_MAX_MODULUS_BITS}

const
  OPENSSL_DH_CHECK_MAX_MODULUS_BITS = 32768;
    {$endif}

const
  OPENSSL_DH_FIPS_MIN_MODULUS_BITS = 1024;
  DH_FLAG_CACHE_MONT_P = $01;
  DH_FLAG_TYPE_MASK = $F000;
  DH_FLAG_TYPE_DH = $0000;
  DH_FLAG_TYPE_DHX = $1000;
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

const
      
      {* Does nothing. Previously this switched off constant time behaviour.
      }
  DH_FLAG_NO_EXP_CONSTTIME = $00;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
      
      {* If this flag is set the DH method is FIPS compliant and can be used in
      * FIPS mode. This is set in the validated module method. If an application
      * sets this flag in its own methods it is its responsibility to ensure the
      * result is compliant.
      }
  DH_FLAG_FIPS_METHOD = $0400;
      
      {* If this flag is set the operations normally disabled in FIPS mode are
      * permitted it is then the applications responsibility to ensure that the
      * usage is compliant.
      }
  DH_FLAG_NON_FIPS_ALLOW = $0400;
    {$endif}


    { Already defined in ossl_typ.h }
    { typedef struct dh_st DH; }
    { typedef struct dh_method DH_METHOD; }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DHparams_it: PASN1_ITEM; cdecl; external CLibCrypto name 'DHparams_it';
    {$else}
  {$EXTERNALSYM DHparams_it}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DHparams_it: PASN1_ITEM; cdecl;

var
  DHparams_it: function: PASN1_ITEM; cdecl = Load_DHparams_it;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  DH_GENERATOR_2 = 2;
  DH_GENERATOR_3 = 3;
  DH_GENERATOR_5 = 5;
      { DH_check error codes, some of them shared with DH_check_pub_key }
      
      {* NB: These values must align with the equivalently named macros in
      * internal/ffc.h.
      }
  DH_CHECK_P_NOT_PRIME = $01;
  DH_CHECK_P_NOT_SAFE_PRIME = $02;
  DH_UNABLE_TO_CHECK_GENERATOR = $04;
  DH_NOT_SUITABLE_GENERATOR = $08;
  DH_CHECK_Q_NOT_PRIME = $10;
  DH_CHECK_INVALID_Q_VALUE = $20;
  DH_CHECK_INVALID_J_VALUE = $40;
  DH_MODULUS_TOO_SMALL = $80;
  DH_MODULUS_TOO_LARGE = $100;
      { DH_check_pub_key error codes }
  DH_CHECK_PUBKEY_TOO_SMALL = $01;
  DH_CHECK_PUBKEY_TOO_LARGE = $02;
  DH_CHECK_PUBKEY_INVALID = $04;
      
      {* primes p where (p-1)/2 is prime too are called "safe"; we define this for
      * backward compatibility:
      }
  DH_CHECK_P_NOT_STRONG_PRIME = DH_CHECK_P_NOT_SAFE_PRIME;
  {# define  d2i_DHparams_fp(fp,x) (DH *)ASN1_d2i_fp((void *(*)(void))DH_new, (d2i_of_void *)d2i_DHparams, (fp), (void **)(x))}
  {# define  i2d_DHparams_fp(fp,x) ASN1_i2d_fp(i2d_DHparams, (fp), (unsigned char *)(x))} {Function argument out of range at line no 186}
  {# define  d2i_DHparams_bio(bp,x) ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)} {Function argument out of range at line no 188}
  {# define  i2d_DHparams_bio(bp,x) ASN1_i2d_bio_of(DH, i2d_DHparams, bp, x)} {Function argument out of range at line no 190}
  {# define  d2i_DHxparams_fp(fp,x) (DH *)ASN1_d2i_fp((void *(*)(void))DH_new, (d2i_of_void *)d2i_DHxparams, (fp), (void **)(x))}
  {# define  i2d_DHxparams_fp(fp,x) ASN1_i2d_fp(i2d_DHxparams, (fp), (unsigned char *)(x))} {Function argument out of range at line no 198}
  {# define  d2i_DHxparams_bio(bp,x) ASN1_d2i_bio_of(DH, DH_new, d2i_DHxparams, bp, x)} {Function argument out of range at line no 200}
  {# define  i2d_DHxparams_bio(bp,x) ASN1_i2d_bio_of(DH, i2d_DHxparams, bp, x)} {Function argument out of range at line no 202}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DHparams_dup(a: PDH): PDH; cdecl; external CLibCrypto name 'DHparams_dup'; deprecated 'Since OpenSSL 3.0';
  function DH_OpenSSL: PDH_METHOD; cdecl; external CLibCrypto name 'DH_OpenSSL'; deprecated 'Since OpenSSL 3.0';
  procedure DH_set_default_method(meth: PDH_METHOD); cdecl; external CLibCrypto name 'DH_set_default_method'; deprecated 'Since OpenSSL 3.0';
  function DH_get_default_method: PDH_METHOD; cdecl; external CLibCrypto name 'DH_get_default_method'; deprecated 'Since OpenSSL 3.0';
  function DH_set_method(dh: PDH; meth: PDH_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_set_method'; deprecated 'Since OpenSSL 3.0';
  function DH_new_method(engine: PENGINE): PDH; cdecl; external CLibCrypto name 'DH_new_method'; deprecated 'Since OpenSSL 3.0';
  function DH_new: PDH; cdecl; external CLibCrypto name 'DH_new'; deprecated 'Since OpenSSL 3.0';
  procedure DH_free(dh: PDH); cdecl; external CLibCrypto name 'DH_free'; deprecated 'Since OpenSSL 3.0';
  function DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_up_ref'; deprecated 'Since OpenSSL 3.0';
  function DH_bits(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_bits'; deprecated 'Since OpenSSL 3.0';
  function DH_size(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_size'; deprecated 'Since OpenSSL 3.0';
  function DH_security_bits(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_security_bits'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DHparams_dup}
  {$EXTERNALSYM DH_OpenSSL}
  {$EXTERNALSYM DH_set_default_method}
  {$EXTERNALSYM DH_get_default_method}
  {$EXTERNALSYM DH_set_method}
  {$EXTERNALSYM DH_new_method}
  {$EXTERNALSYM DH_new}
  {$EXTERNALSYM DH_free}
  {$EXTERNALSYM DH_up_ref}
  {$EXTERNALSYM DH_bits}
  {$EXTERNALSYM DH_size}
  {$EXTERNALSYM DH_security_bits}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DHparams_dup(a: PDH): PDH; cdecl;
  function Load_DH_OpenSSL: PDH_METHOD; cdecl;
  procedure Load_DH_set_default_method(meth: PDH_METHOD); cdecl;
  function Load_DH_get_default_method: PDH_METHOD; cdecl;
  function Load_DH_set_method(dh: PDH; meth: PDH_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_DH_new_method(engine: PENGINE): PDH; cdecl;
  function Load_DH_new: PDH; cdecl;
  procedure Load_DH_free(dh: PDH); cdecl;
  function Load_DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_bits(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_size(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_security_bits(dh: PDH): TOpenSSL_C_INT; cdecl;

var
  DHparams_dup: function(a: PDH): PDH; cdecl = Load_DHparams_dup;
  DH_OpenSSL: function: PDH_METHOD; cdecl = Load_DH_OpenSSL;
  DH_set_default_method: procedure(meth: PDH_METHOD); cdecl = Load_DH_set_default_method;
  DH_get_default_method: function: PDH_METHOD; cdecl = Load_DH_get_default_method;
  DH_set_method: function(dh: PDH; meth: PDH_METHOD): TOpenSSL_C_INT; cdecl = Load_DH_set_method;
  DH_new_method: function(engine: PENGINE): PDH; cdecl = Load_DH_new_method;
  DH_new: function: PDH; cdecl = Load_DH_new;
  DH_free: procedure(dh: PDH); cdecl = Load_DH_free;
  DH_up_ref: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_up_ref;
  DH_bits: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_bits;
  DH_size: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_size;
  DH_security_bits: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_security_bits;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {# define  DH_get_ex_new_index(l,p,newf,dupf,freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DH, l, p, newf, dupf, freef)} {Macro Return Type unknown at line no 221}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_set_ex_data'; deprecated 'Since OpenSSL 3.0';
  function DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'DH_get_ex_data'; deprecated 'Since OpenSSL 3.0';
  function DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_generate_parameters_ex'; deprecated 'Since OpenSSL 3.0';
  function DH_check_params_ex(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_check_params_ex'; deprecated 'Since OpenSSL 3.0';
  function DH_check_ex(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_check_ex'; deprecated 'Since OpenSSL 3.0';
  function DH_check_pub_key_ex(dh: PDH; pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_check_pub_key_ex'; deprecated 'Since OpenSSL 3.0';
  function DH_check_params(dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_check_params'; deprecated 'Since OpenSSL 3.0';
  function DH_check(dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_check'; deprecated 'Since OpenSSL 3.0';
  function DH_check_pub_key(dh: PDH; pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_check_pub_key'; deprecated 'Since OpenSSL 3.0';
  function DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_generate_key'; deprecated 'Since OpenSSL 3.0';
  function DH_compute_key(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_compute_key'; deprecated 'Since OpenSSL 3.0';
  function DH_compute_key_padded(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_compute_key_padded'; deprecated 'Since OpenSSL 3.0';
  function d2i_DHparams(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl; external CLibCrypto name 'd2i_DHparams'; deprecated 'Since OpenSSL 3.0';
  function i2d_DHparams(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_DHparams'; deprecated 'Since OpenSSL 3.0';
  function d2i_DHxparams(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl; external CLibCrypto name 'd2i_DHxparams'; deprecated 'Since OpenSSL 3.0';
  function i2d_DHxparams(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_DHxparams'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_set_ex_data}
  {$EXTERNALSYM DH_get_ex_data}
  {$EXTERNALSYM DH_generate_parameters_ex}
  {$EXTERNALSYM DH_check_params_ex}
  {$EXTERNALSYM DH_check_ex}
  {$EXTERNALSYM DH_check_pub_key_ex}
  {$EXTERNALSYM DH_check_params}
  {$EXTERNALSYM DH_check}
  {$EXTERNALSYM DH_check_pub_key}
  {$EXTERNALSYM DH_generate_key}
  {$EXTERNALSYM DH_compute_key}
  {$EXTERNALSYM DH_compute_key_padded}
  {$EXTERNALSYM d2i_DHparams}
  {$EXTERNALSYM i2d_DHparams}
  {$EXTERNALSYM d2i_DHxparams}
  {$EXTERNALSYM i2d_DHxparams}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): pointer; cdecl;
  function Load_DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
  function Load_DH_check_params_ex(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_check_ex(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_check_pub_key_ex(dh: PDH; pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_DH_check_params(dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_DH_check(dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_DH_check_pub_key(dh: PDH; pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_compute_key(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_compute_key_padded(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_d2i_DHparams(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl;
  function Load_i2d_DHparams(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_d2i_DHxparams(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl;
  function Load_i2d_DHxparams(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl;

var
  DH_set_ex_data: function(d: PDH; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl = Load_DH_set_ex_data;
  DH_get_ex_data: function(d: PDH; idx: TOpenSSL_C_INT): pointer; cdecl = Load_DH_get_ex_data;
  DH_generate_parameters_ex: function(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_DH_generate_parameters_ex;
  DH_check_params_ex: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_check_params_ex;
  DH_check_ex: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_check_ex;
  DH_check_pub_key_ex: function(dh: PDH; pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DH_check_pub_key_ex;
  DH_check_params: function(dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_check_params;
  DH_check: function(dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_check;
  DH_check_pub_key: function(dh: PDH; pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_check_pub_key;
  DH_generate_key: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_generate_key;
  DH_compute_key: function(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_compute_key;
  DH_compute_key_padded: function(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_compute_key_padded;
  d2i_DHparams: function(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl = Load_d2i_DHparams;
  i2d_DHparams: function(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_DHparams;
  d2i_DHxparams: function(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl = Load_d2i_DHxparams;
  i2d_DHxparams: function(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_DHxparams;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$ifndef  OPENSSL_NO_STDIO}


        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DHparams_print_fp(fp: PFILE; x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DHparams_print_fp'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM DHparams_print_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DHparams_print_fp(fp: PFILE; x: PDH): TOpenSSL_C_INT; cdecl;

var
  DHparams_print_fp: function(fp: PFILE; x: PDH): TOpenSSL_C_INT; cdecl = Load_DHparams_print_fp;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DHparams_print(bp: PBIO; x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DHparams_print'; deprecated 'Since OpenSSL 3.0';
  { RFC 5114 parameters }
  function DH_get_1024_160: PDH; cdecl; external CLibCrypto name 'DH_get_1024_160'; deprecated 'Since OpenSSL 3.0';
  function DH_get_2048_224: PDH; cdecl; external CLibCrypto name 'DH_get_2048_224'; deprecated 'Since OpenSSL 3.0';
  function DH_get_2048_256: PDH; cdecl; external CLibCrypto name 'DH_get_2048_256'; deprecated 'Since OpenSSL 3.0';
  { Named parameters, currently RFC7919 and RFC3526 }
  function DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl; external CLibCrypto name 'DH_new_by_nid'; deprecated 'Since OpenSSL 3.0';
  function DH_get_nid(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_get_nid'; deprecated 'Since OpenSSL 3.0';
  { RFC2631 KDF }
  function DH_KDF_X9_42(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; ukm: Pbyte; ukmlen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_KDF_X9_42'; deprecated 'Since OpenSSL 3.0';
  procedure DH_get0_pqg(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl; external CLibCrypto name 'DH_get0_pqg'; deprecated 'Since OpenSSL 3.0';
  function DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_set0_pqg'; deprecated 'Since OpenSSL 3.0';
  procedure DH_get0_key(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl; external CLibCrypto name 'DH_get0_key'; deprecated 'Since OpenSSL 3.0';
  function DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_set0_key'; deprecated 'Since OpenSSL 3.0';
  function DH_get0_p(dh: PDH): PBIGNUM; cdecl; external CLibCrypto name 'DH_get0_p'; deprecated 'Since OpenSSL 3.0';
  function DH_get0_q(dh: PDH): PBIGNUM; cdecl; external CLibCrypto name 'DH_get0_q'; deprecated 'Since OpenSSL 3.0';
  function DH_get0_g(dh: PDH): PBIGNUM; cdecl; external CLibCrypto name 'DH_get0_g'; deprecated 'Since OpenSSL 3.0';
  function DH_get0_priv_key(dh: PDH): PBIGNUM; cdecl; external CLibCrypto name 'DH_get0_priv_key'; deprecated 'Since OpenSSL 3.0';
  function DH_get0_pub_key(dh: PDH): PBIGNUM; cdecl; external CLibCrypto name 'DH_get0_pub_key'; deprecated 'Since OpenSSL 3.0';
  procedure DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DH_clear_flags'; deprecated 'Since OpenSSL 3.0';
  function DH_test_flags(dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_test_flags'; deprecated 'Since OpenSSL 3.0';
  procedure DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DH_set_flags'; deprecated 'Since OpenSSL 3.0';
  function DH_get0_engine(d: PDH): PENGINE; cdecl; external CLibCrypto name 'DH_get0_engine'; deprecated 'Since OpenSSL 3.0';
  function DH_get_length(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_get_length'; deprecated 'Since OpenSSL 3.0';
  function DH_set_length(dh: PDH; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_set_length'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_METHOD; cdecl; external CLibCrypto name 'DH_meth_new'; deprecated 'Since OpenSSL 3.0';
  procedure DH_meth_free(dhm: PDH_METHOD); cdecl; external CLibCrypto name 'DH_meth_free'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_dup(dhm: PDH_METHOD): PDH_METHOD; cdecl; external CLibCrypto name 'DH_meth_dup'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_get0_name(dhm: PDH_METHOD): PAnsiChar; cdecl; external CLibCrypto name 'DH_meth_get0_name'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_set1_name(dhm: PDH_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set1_name'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_get_flags(dhm: PDH_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_get_flags'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_set_flags(dhm: PDH_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set_flags'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_get0_app_data(dhm: PDH_METHOD): pointer; cdecl; external CLibCrypto name 'DH_meth_get0_app_data'; deprecated 'Since OpenSSL 3.0';
  function DH_meth_set0_app_data(dhm: PDH_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set0_app_data'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DHparams_print}
  {$EXTERNALSYM DH_get_1024_160}
  {$EXTERNALSYM DH_get_2048_224}
  {$EXTERNALSYM DH_get_2048_256}
  {$EXTERNALSYM DH_new_by_nid}
  {$EXTERNALSYM DH_get_nid}
  {$EXTERNALSYM DH_KDF_X9_42}
  {$EXTERNALSYM DH_get0_pqg}
  {$EXTERNALSYM DH_set0_pqg}
  {$EXTERNALSYM DH_get0_key}
  {$EXTERNALSYM DH_set0_key}
  {$EXTERNALSYM DH_get0_p}
  {$EXTERNALSYM DH_get0_q}
  {$EXTERNALSYM DH_get0_g}
  {$EXTERNALSYM DH_get0_priv_key}
  {$EXTERNALSYM DH_get0_pub_key}
  {$EXTERNALSYM DH_clear_flags}
  {$EXTERNALSYM DH_test_flags}
  {$EXTERNALSYM DH_set_flags}
  {$EXTERNALSYM DH_get0_engine}
  {$EXTERNALSYM DH_get_length}
  {$EXTERNALSYM DH_set_length}
  {$EXTERNALSYM DH_meth_new}
  {$EXTERNALSYM DH_meth_free}
  {$EXTERNALSYM DH_meth_dup}
  {$EXTERNALSYM DH_meth_get0_name}
  {$EXTERNALSYM DH_meth_set1_name}
  {$EXTERNALSYM DH_meth_get_flags}
  {$EXTERNALSYM DH_meth_set_flags}
  {$EXTERNALSYM DH_meth_get0_app_data}
  {$EXTERNALSYM DH_meth_set0_app_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DHparams_print(bp: PBIO; x: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_get_1024_160: PDH; cdecl;
  function Load_DH_get_2048_224: PDH; cdecl;
  function Load_DH_get_2048_256: PDH; cdecl;
  function Load_DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl;
  function Load_DH_get_nid(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_KDF_X9_42(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; ukm: Pbyte; ukmlen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  procedure Load_DH_get0_pqg(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl;
  function Load_DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
  procedure Load_DH_get0_key(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl;
  function Load_DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_DH_get0_p(dh: PDH): PBIGNUM; cdecl;
  function Load_DH_get0_q(dh: PDH): PBIGNUM; cdecl;
  function Load_DH_get0_g(dh: PDH): PBIGNUM; cdecl;
  function Load_DH_get0_priv_key(dh: PDH): PBIGNUM; cdecl;
  function Load_DH_get0_pub_key(dh: PDH): PBIGNUM; cdecl;
  procedure Load_DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
  function Load_DH_test_flags(dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
  function Load_DH_get0_engine(d: PDH): PENGINE; cdecl;
  function Load_DH_get_length(dh: PDH): TOpenSSL_C_INT; cdecl;
  function Load_DH_set_length(dh: PDH; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_DH_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_METHOD; cdecl;
  procedure Load_DH_meth_free(dhm: PDH_METHOD); cdecl;
  function Load_DH_meth_dup(dhm: PDH_METHOD): PDH_METHOD; cdecl;
  function Load_DH_meth_get0_name(dhm: PDH_METHOD): PAnsiChar; cdecl;
  function Load_DH_meth_set1_name(dhm: PDH_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_DH_meth_get_flags(dhm: PDH_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_DH_meth_set_flags(dhm: PDH_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_DH_meth_get0_app_data(dhm: PDH_METHOD): pointer; cdecl;
  function Load_DH_meth_set0_app_data(dhm: PDH_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl;

var
  DHparams_print: function(bp: PBIO; x: PDH): TOpenSSL_C_INT; cdecl = Load_DHparams_print;
  { RFC 5114 parameters }
  DH_get_1024_160: function: PDH; cdecl = Load_DH_get_1024_160;
  DH_get_2048_224: function: PDH; cdecl = Load_DH_get_2048_224;
  DH_get_2048_256: function: PDH; cdecl = Load_DH_get_2048_256;
  { Named parameters, currently RFC7919 and RFC3526 }
  DH_new_by_nid: function(nid: TOpenSSL_C_INT): PDH; cdecl = Load_DH_new_by_nid;
  DH_get_nid: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_get_nid;
  { RFC2631 KDF }
  DH_KDF_X9_42: function(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; ukm: Pbyte; ukmlen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_DH_KDF_X9_42;
  DH_get0_pqg: procedure(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl = Load_DH_get0_pqg;
  DH_set0_pqg: function(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DH_set0_pqg;
  DH_get0_key: procedure(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl = Load_DH_get0_key;
  DH_set0_key: function(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DH_set0_key;
  DH_get0_p: function(dh: PDH): PBIGNUM; cdecl = Load_DH_get0_p;
  DH_get0_q: function(dh: PDH): PBIGNUM; cdecl = Load_DH_get0_q;
  DH_get0_g: function(dh: PDH): PBIGNUM; cdecl = Load_DH_get0_g;
  DH_get0_priv_key: function(dh: PDH): PBIGNUM; cdecl = Load_DH_get0_priv_key;
  DH_get0_pub_key: function(dh: PDH): PBIGNUM; cdecl = Load_DH_get0_pub_key;
  DH_clear_flags: procedure(dh: PDH; flags: TOpenSSL_C_INT); cdecl = Load_DH_clear_flags;
  DH_test_flags: function(dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_test_flags;
  DH_set_flags: procedure(dh: PDH; flags: TOpenSSL_C_INT); cdecl = Load_DH_set_flags;
  DH_get0_engine: function(d: PDH): PENGINE; cdecl = Load_DH_get0_engine;
  DH_get_length: function(dh: PDH): TOpenSSL_C_INT; cdecl = Load_DH_get_length;
  DH_set_length: function(dh: PDH; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_set_length;
  DH_meth_new: function(name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_METHOD; cdecl = Load_DH_meth_new;
  DH_meth_free: procedure(dhm: PDH_METHOD); cdecl = Load_DH_meth_free;
  DH_meth_dup: function(dhm: PDH_METHOD): PDH_METHOD; cdecl = Load_DH_meth_dup;
  DH_meth_get0_name: function(dhm: PDH_METHOD): PAnsiChar; cdecl = Load_DH_meth_get0_name;
  DH_meth_set1_name: function(dhm: PDH_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_DH_meth_set1_name;
  DH_meth_get_flags: function(dhm: PDH_METHOD): TOpenSSL_C_INT; cdecl = Load_DH_meth_get_flags;
  DH_meth_set_flags: function(dhm: PDH_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_flags;
  DH_meth_get0_app_data: function(dhm: PDH_METHOD): pointer; cdecl = Load_DH_meth_get0_app_data;
  DH_meth_set0_app_data: function(dhm: PDH_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl = Load_DH_meth_set0_app_data;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = function(_param1: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_get_generate_key(dhm: PDH_METHOD): TFuncType000; cdecl; external CLibCrypto name 'DH_meth_get_generate_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_get_generate_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_get_generate_key(dhm: PDH_METHOD): TFuncType000; cdecl;

var
  DH_meth_get_generate_key: function(dhm: PDH_METHOD): TFuncType000; cdecl = Load_DH_meth_get_generate_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = function(_param1: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_set_generate_key(dhm: PDH_METHOD; generate_key: TFuncType001): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set_generate_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_set_generate_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_set_generate_key(dhm: PDH_METHOD; generate_key: TFuncType001): TOpenSSL_C_INT; cdecl;

var
  DH_meth_set_generate_key: function(dhm: PDH_METHOD; generate_key: TFuncType001): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_generate_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  {end of auto-generated forward references}

  TFuncType002 = function(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_get_compute_key(dhm: PDH_METHOD): TFuncType002; cdecl; external CLibCrypto name 'DH_meth_get_compute_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_get_compute_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_get_compute_key(dhm: PDH_METHOD): TFuncType002; cdecl;

var
  DH_meth_get_compute_key: function(dhm: PDH_METHOD): TFuncType002; cdecl = Load_DH_meth_get_compute_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType003 = ^TFuncType003;
  PPFuncType003 = ^PFuncType003;
  {end of auto-generated forward references}

  TFuncType003 = function(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_set_compute_key(dhm: PDH_METHOD; compute_key: TFuncType003): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set_compute_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_set_compute_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_set_compute_key(dhm: PDH_METHOD; compute_key: TFuncType003): TOpenSSL_C_INT; cdecl;

var
  DH_meth_set_compute_key: function(dhm: PDH_METHOD; compute_key: TFuncType003): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_compute_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType004 = ^TFuncType004;
  PPFuncType004 = ^PFuncType004;
  {end of auto-generated forward references}

  TFuncType004 = function(_param1: PDH; _param2: PBIGNUM; _param3: PBIGNUM; _param4: PBIGNUM; _param5: PBIGNUM; _param6: PBN_CTX; _param7: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_get_bn_mod_exp(dhm: PDH_METHOD): TFuncType004; cdecl; external CLibCrypto name 'DH_meth_get_bn_mod_exp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_get_bn_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_get_bn_mod_exp(dhm: PDH_METHOD): TFuncType004; cdecl;

var
  DH_meth_get_bn_mod_exp: function(dhm: PDH_METHOD): TFuncType004; cdecl = Load_DH_meth_get_bn_mod_exp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType005 = ^TFuncType005;
  PPFuncType005 = ^PFuncType005;
  {end of auto-generated forward references}

  TFuncType005 = function(_param1: PDH; _param2: PBIGNUM; _param3: PBIGNUM; _param4: PBIGNUM; _param5: PBIGNUM; _param6: PBN_CTX; _param7: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_set_bn_mod_exp(dhm: PDH_METHOD; bn_mod_exp: TFuncType005): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set_bn_mod_exp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_set_bn_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_set_bn_mod_exp(dhm: PDH_METHOD; bn_mod_exp: TFuncType005): TOpenSSL_C_INT; cdecl;

var
  DH_meth_set_bn_mod_exp: function(dhm: PDH_METHOD; bn_mod_exp: TFuncType005): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_bn_mod_exp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType006 = ^TFuncType006;
  PPFuncType006 = ^PFuncType006;
  {end of auto-generated forward references}

  TFuncType006 = function(_param1: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_get_init(dhm: PDH_METHOD): TFuncType006; cdecl; external CLibCrypto name 'DH_meth_get_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_get_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_get_init(dhm: PDH_METHOD): TFuncType006; cdecl;

var
  DH_meth_get_init: function(dhm: PDH_METHOD): TFuncType006; cdecl = Load_DH_meth_get_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType007 = ^TFuncType007;
  PPFuncType007 = ^PFuncType007;
  {end of auto-generated forward references}

  TFuncType007 = function(_param1: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_set_init(dhm: PDH_METHOD; init: TFuncType007): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_set_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_set_init(dhm: PDH_METHOD; init: TFuncType007): TOpenSSL_C_INT; cdecl;

var
  DH_meth_set_init: function(dhm: PDH_METHOD; init: TFuncType007): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType008 = ^TFuncType008;
  PPFuncType008 = ^PFuncType008;
  {end of auto-generated forward references}

  TFuncType008 = function(_param1: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_get_finish(dhm: PDH_METHOD): TFuncType008; cdecl; external CLibCrypto name 'DH_meth_get_finish'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_get_finish}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_get_finish(dhm: PDH_METHOD): TFuncType008; cdecl;

var
  DH_meth_get_finish: function(dhm: PDH_METHOD): TFuncType008; cdecl = Load_DH_meth_get_finish;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType009 = ^TFuncType009;
  PPFuncType009 = ^PFuncType009;
  {end of auto-generated forward references}

  TFuncType009 = function(_param1: PDH): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_set_finish(dhm: PDH_METHOD; finish: TFuncType009): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set_finish'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_set_finish}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_set_finish(dhm: PDH_METHOD; finish: TFuncType009): TOpenSSL_C_INT; cdecl;

var
  DH_meth_set_finish: function(dhm: PDH_METHOD; finish: TFuncType009): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_finish;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType010 = ^TFuncType010;
  PPFuncType010 = ^PFuncType010;
  {end of auto-generated forward references}

  TFuncType010 = function(_param1: PDH; _param2: TOpenSSL_C_INT; _param3: TOpenSSL_C_INT; _param4: PBN_GENCB): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_get_generate_params(dhm: PDH_METHOD): TFuncType010; cdecl; external CLibCrypto name 'DH_meth_get_generate_params'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_get_generate_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_get_generate_params(dhm: PDH_METHOD): TFuncType010; cdecl;

var
  DH_meth_get_generate_params: function(dhm: PDH_METHOD): TFuncType010; cdecl = Load_DH_meth_get_generate_params;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType011 = ^TFuncType011;
  PPFuncType011 = ^PFuncType011;
  {end of auto-generated forward references}

  TFuncType011 = function(_param1: PDH; _param2: TOpenSSL_C_INT; _param3: TOpenSSL_C_INT; _param4: PBN_GENCB): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_meth_set_generate_params(dhm: PDH_METHOD; generate_params: TFuncType011): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DH_meth_set_generate_params'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DH_meth_set_generate_params}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_meth_set_generate_params(dhm: PDH_METHOD; generate_params: TFuncType011): TOpenSSL_C_INT; cdecl;

var
  DH_meth_set_generate_params: function(dhm: PDH_METHOD; generate_params: TFuncType011): TOpenSSL_C_INT; cdecl = Load_DH_meth_set_generate_params;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { OPENSSL_NO_DEPRECATED_3_0 }
    {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}

type
  {Auto-generated forward references}
  PFuncType012 = ^TFuncType012;
  PPFuncType012 = ^PFuncType012;
  {end of auto-generated forward references}

  TFuncType012 = procedure(_param1: TOpenSSL_C_INT; _param2: TOpenSSL_C_INT; _param3: pointer); cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DH_generate_parameters(prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; callback: TFuncType012; cb_arg: pointer): PDH; cdecl; external CLibCrypto name 'DH_generate_parameters'; deprecated 'Since OpenSSL 0.9.8';
      {$else}
  {$EXTERNALSYM DH_generate_parameters}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DH_generate_parameters(prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; callback: TFuncType012; cb_arg: pointer): PDH; cdecl;

var
  DH_generate_parameters: function(prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; callback: TFuncType012; cb_arg: pointer): PDH; cdecl = Load_DH_generate_parameters;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
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
function Load_EVP_PKEY_CTX_set_dh_paramgen_type(ctx: PEVP_PKEY_CTX; typ: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_paramgen_type := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_paramgen_type');
  if not assigned(EVP_PKEY_CTX_set_dh_paramgen_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_paramgen_type');
  Result := EVP_PKEY_CTX_set_dh_paramgen_type(ctx, typ);
end;

function Load_EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_paramgen_gindex := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_paramgen_gindex');
  if not assigned(EVP_PKEY_CTX_set_dh_paramgen_gindex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_paramgen_gindex');
  Result := EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx, gindex);
end;

function Load_EVP_PKEY_CTX_set_dh_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_paramgen_seed := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_paramgen_seed');
  if not assigned(EVP_PKEY_CTX_set_dh_paramgen_seed) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_paramgen_seed');
  Result := EVP_PKEY_CTX_set_dh_paramgen_seed(ctx, seed, seedlen);
end;

function Load_EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx: PEVP_PKEY_CTX; pbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_paramgen_prime_len := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_paramgen_prime_len');
  if not assigned(EVP_PKEY_CTX_set_dh_paramgen_prime_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_paramgen_prime_len');
  Result := EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, pbits);
end;

function Load_EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx: PEVP_PKEY_CTX; qlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_paramgen_subprime_len := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_paramgen_subprime_len');
  if not assigned(EVP_PKEY_CTX_set_dh_paramgen_subprime_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_paramgen_subprime_len');
  Result := EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, qlen);
end;

function Load_EVP_PKEY_CTX_set_dh_paramgen_generator(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_paramgen_generator := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_paramgen_generator');
  if not assigned(EVP_PKEY_CTX_set_dh_paramgen_generator) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_paramgen_generator');
  Result := EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, gen);
end;

function Load_EVP_PKEY_CTX_set_dh_nid(ctx: PEVP_PKEY_CTX; nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_nid := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_nid');
  if not assigned(EVP_PKEY_CTX_set_dh_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_nid');
  Result := EVP_PKEY_CTX_set_dh_nid(ctx, nid);
end;

function Load_EVP_PKEY_CTX_set_dh_rfc5114(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_rfc5114 := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_rfc5114');
  if not assigned(EVP_PKEY_CTX_set_dh_rfc5114) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_rfc5114');
  Result := EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen);
end;

function Load_EVP_PKEY_CTX_set_dhx_rfc5114(ctx: PEVP_PKEY_CTX; gen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dhx_rfc5114 := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dhx_rfc5114');
  if not assigned(EVP_PKEY_CTX_set_dhx_rfc5114) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dhx_rfc5114');
  Result := EVP_PKEY_CTX_set_dhx_rfc5114(ctx, gen);
end;

function Load_EVP_PKEY_CTX_set_dh_pad(ctx: PEVP_PKEY_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_pad := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_pad');
  if not assigned(EVP_PKEY_CTX_set_dh_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_pad');
  Result := EVP_PKEY_CTX_set_dh_pad(ctx, pad);
end;

function Load_EVP_PKEY_CTX_set_dh_kdf_type(ctx: PEVP_PKEY_CTX; kdf: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_kdf_type := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_kdf_type');
  if not assigned(EVP_PKEY_CTX_set_dh_kdf_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_kdf_type');
  Result := EVP_PKEY_CTX_set_dh_kdf_type(ctx, kdf);
end;

function Load_EVP_PKEY_CTX_get_dh_kdf_type(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_dh_kdf_type := LoadLibCryptoFunction('EVP_PKEY_CTX_get_dh_kdf_type');
  if not assigned(EVP_PKEY_CTX_get_dh_kdf_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_dh_kdf_type');
  Result := EVP_PKEY_CTX_get_dh_kdf_type(ctx);
end;

function Load_EVP_PKEY_CTX_set0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set0_dh_kdf_oid := LoadLibCryptoFunction('EVP_PKEY_CTX_set0_dh_kdf_oid');
  if not assigned(EVP_PKEY_CTX_set0_dh_kdf_oid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set0_dh_kdf_oid');
  Result := EVP_PKEY_CTX_set0_dh_kdf_oid(ctx, oid);
end;

function Load_EVP_PKEY_CTX_get0_dh_kdf_oid(ctx: PEVP_PKEY_CTX; oid: PPASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get0_dh_kdf_oid := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_dh_kdf_oid');
  if not assigned(EVP_PKEY_CTX_get0_dh_kdf_oid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_dh_kdf_oid');
  Result := EVP_PKEY_CTX_get0_dh_kdf_oid(ctx, oid);
end;

function Load_EVP_PKEY_CTX_set_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_kdf_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_kdf_md');
  if not assigned(EVP_PKEY_CTX_set_dh_kdf_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_kdf_md');
  Result := EVP_PKEY_CTX_set_dh_kdf_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_get_dh_kdf_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_dh_kdf_md := LoadLibCryptoFunction('EVP_PKEY_CTX_get_dh_kdf_md');
  if not assigned(EVP_PKEY_CTX_get_dh_kdf_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_dh_kdf_md');
  Result := EVP_PKEY_CTX_get_dh_kdf_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dh_kdf_outlen := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dh_kdf_outlen');
  if not assigned(EVP_PKEY_CTX_set_dh_kdf_outlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dh_kdf_outlen');
  Result := EVP_PKEY_CTX_set_dh_kdf_outlen(ctx, len);
end;

function Load_EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: PEVP_PKEY_CTX; len: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_dh_kdf_outlen := LoadLibCryptoFunction('EVP_PKEY_CTX_get_dh_kdf_outlen');
  if not assigned(EVP_PKEY_CTX_get_dh_kdf_outlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_dh_kdf_outlen');
  Result := EVP_PKEY_CTX_get_dh_kdf_outlen(ctx, len);
end;

function Load_EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set0_dh_kdf_ukm := LoadLibCryptoFunction('EVP_PKEY_CTX_set0_dh_kdf_ukm');
  if not assigned(EVP_PKEY_CTX_set0_dh_kdf_ukm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set0_dh_kdf_ukm');
  Result := EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx, ukm, len);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx: PEVP_PKEY_CTX; ukm: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get0_dh_kdf_ukm := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_dh_kdf_ukm');
  if not assigned(EVP_PKEY_CTX_get0_dh_kdf_ukm) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_dh_kdf_ukm');
  Result := EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx, ukm);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DH}
function Load_DHparams_it: PASN1_ITEM; cdecl;
begin
  DHparams_it := LoadLibCryptoFunction('DHparams_it');
  if not assigned(DHparams_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_it');
  Result := DHparams_it;
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_DHparams_dup(a: PDH): PDH; cdecl;
begin
  DHparams_dup := LoadLibCryptoFunction('DHparams_dup');
  if not assigned(DHparams_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_dup');
  Result := DHparams_dup(a);
end;

function Load_DH_OpenSSL: PDH_METHOD; cdecl;
begin
  DH_OpenSSL := LoadLibCryptoFunction('DH_OpenSSL');
  if not assigned(DH_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_OpenSSL');
  Result := DH_OpenSSL;
end;

procedure Load_DH_set_default_method(meth: PDH_METHOD); cdecl;
begin
  DH_set_default_method := LoadLibCryptoFunction('DH_set_default_method');
  if not assigned(DH_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_default_method');
  DH_set_default_method(meth);
end;

function Load_DH_get_default_method: PDH_METHOD; cdecl;
begin
  DH_get_default_method := LoadLibCryptoFunction('DH_get_default_method');
  if not assigned(DH_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_default_method');
  Result := DH_get_default_method;
end;

function Load_DH_set_method(dh: PDH; meth: PDH_METHOD): TOpenSSL_C_INT; cdecl;
begin
  DH_set_method := LoadLibCryptoFunction('DH_set_method');
  if not assigned(DH_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_method');
  Result := DH_set_method(dh, meth);
end;

function Load_DH_new_method(engine: PENGINE): PDH; cdecl;
begin
  DH_new_method := LoadLibCryptoFunction('DH_new_method');
  if not assigned(DH_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new_method');
  Result := DH_new_method(engine);
end;

function Load_DH_new: PDH; cdecl;
begin
  DH_new := LoadLibCryptoFunction('DH_new');
  if not assigned(DH_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new');
  Result := DH_new;
end;

procedure Load_DH_free(dh: PDH); cdecl;
begin
  DH_free := LoadLibCryptoFunction('DH_free');
  if not assigned(DH_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_free');
  DH_free(dh);
end;

function Load_DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_up_ref := LoadLibCryptoFunction('DH_up_ref');
  if not assigned(DH_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_up_ref');
  Result := DH_up_ref(dh);
end;

function Load_DH_bits(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_bits := LoadLibCryptoFunction('DH_bits');
  if not assigned(DH_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_bits');
  Result := DH_bits(dh);
end;

function Load_DH_size(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_size := LoadLibCryptoFunction('DH_size');
  if not assigned(DH_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_size');
  Result := DH_size(dh);
end;

function Load_DH_security_bits(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_security_bits := LoadLibCryptoFunction('DH_security_bits');
  if not assigned(DH_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_security_bits');
  Result := DH_security_bits(dh);
end;

function Load_DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  DH_set_ex_data := LoadLibCryptoFunction('DH_set_ex_data');
  if not assigned(DH_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_ex_data');
  Result := DH_set_ex_data(d, idx, arg);
end;

function Load_DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): pointer; cdecl;
begin
  DH_get_ex_data := LoadLibCryptoFunction('DH_get_ex_data');
  if not assigned(DH_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_ex_data');
  Result := DH_get_ex_data(d, idx);
end;

function Load_DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  DH_generate_parameters_ex := LoadLibCryptoFunction('DH_generate_parameters_ex');
  if not assigned(DH_generate_parameters_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_generate_parameters_ex');
  Result := DH_generate_parameters_ex(dh, prime_len, generator, cb);
end;

function Load_DH_check_params_ex(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_check_params_ex := LoadLibCryptoFunction('DH_check_params_ex');
  if not assigned(DH_check_params_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_params_ex');
  Result := DH_check_params_ex(dh);
end;

function Load_DH_check_ex(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_check_ex := LoadLibCryptoFunction('DH_check_ex');
  if not assigned(DH_check_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_ex');
  Result := DH_check_ex(dh);
end;

function Load_DH_check_pub_key_ex(dh: PDH; pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DH_check_pub_key_ex := LoadLibCryptoFunction('DH_check_pub_key_ex');
  if not assigned(DH_check_pub_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_pub_key_ex');
  Result := DH_check_pub_key_ex(dh, pub_key);
end;

function Load_DH_check_params(dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_check_params := LoadLibCryptoFunction('DH_check_params');
  if not assigned(DH_check_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_params');
  Result := DH_check_params(dh, ret);
end;

function Load_DH_check(dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_check := LoadLibCryptoFunction('DH_check');
  if not assigned(DH_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check');
  Result := DH_check(dh, codes);
end;

function Load_DH_check_pub_key(dh: PDH; pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_check_pub_key := LoadLibCryptoFunction('DH_check_pub_key');
  if not assigned(DH_check_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_pub_key');
  Result := DH_check_pub_key(dh, pub_key, codes);
end;

function Load_DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_generate_key := LoadLibCryptoFunction('DH_generate_key');
  if not assigned(DH_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_generate_key');
  Result := DH_generate_key(dh);
end;

function Load_DH_compute_key(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_compute_key := LoadLibCryptoFunction('DH_compute_key');
  if not assigned(DH_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_compute_key');
  Result := DH_compute_key(key, pub_key, dh);
end;

function Load_DH_compute_key_padded(key: Pbyte; pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_compute_key_padded := LoadLibCryptoFunction('DH_compute_key_padded');
  if not assigned(DH_compute_key_padded) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_compute_key_padded');
  Result := DH_compute_key_padded(key, pub_key, dh);
end;

function Load_d2i_DHparams(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl;
begin
  d2i_DHparams := LoadLibCryptoFunction('d2i_DHparams');
  if not assigned(d2i_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DHparams');
  Result := d2i_DHparams(a, in_, len);
end;

function Load_i2d_DHparams(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DHparams := LoadLibCryptoFunction('i2d_DHparams');
  if not assigned(i2d_DHparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DHparams');
  Result := i2d_DHparams(a, out_);
end;

function Load_d2i_DHxparams(a: PPDH; in_: PPbyte; len: TOpenSSL_C_INT): PDH; cdecl;
begin
  d2i_DHxparams := LoadLibCryptoFunction('d2i_DHxparams');
  if not assigned(d2i_DHxparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DHxparams');
  Result := d2i_DHxparams(a, in_, len);
end;

function Load_i2d_DHxparams(a: PDH; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DHxparams := LoadLibCryptoFunction('i2d_DHxparams');
  if not assigned(i2d_DHxparams) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DHxparams');
  Result := i2d_DHxparams(a, out_);
end;

        {$ifndef  OPENSSL_NO_STDIO}
function Load_DHparams_print_fp(fp: PFILE; x: PDH): TOpenSSL_C_INT; cdecl;
begin
  DHparams_print_fp := LoadLibCryptoFunction('DHparams_print_fp');
  if not assigned(DHparams_print_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_print_fp');
  Result := DHparams_print_fp(fp, x);
end;

        {$endif} { OPENSSL_NO_STDIO}
function Load_DHparams_print(bp: PBIO; x: PDH): TOpenSSL_C_INT; cdecl;
begin
  DHparams_print := LoadLibCryptoFunction('DHparams_print');
  if not assigned(DHparams_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_print');
  Result := DHparams_print(bp, x);
end;

function Load_DH_get_1024_160: PDH; cdecl;
begin
  DH_get_1024_160 := LoadLibCryptoFunction('DH_get_1024_160');
  if not assigned(DH_get_1024_160) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_1024_160');
  Result := DH_get_1024_160;
end;

function Load_DH_get_2048_224: PDH; cdecl;
begin
  DH_get_2048_224 := LoadLibCryptoFunction('DH_get_2048_224');
  if not assigned(DH_get_2048_224) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_2048_224');
  Result := DH_get_2048_224;
end;

function Load_DH_get_2048_256: PDH; cdecl;
begin
  DH_get_2048_256 := LoadLibCryptoFunction('DH_get_2048_256');
  if not assigned(DH_get_2048_256) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_2048_256');
  Result := DH_get_2048_256;
end;

function Load_DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl;
begin
  DH_new_by_nid := LoadLibCryptoFunction('DH_new_by_nid');
  if not assigned(DH_new_by_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new_by_nid');
  Result := DH_new_by_nid(nid);
end;

function Load_DH_get_nid(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_get_nid := LoadLibCryptoFunction('DH_get_nid');
  if not assigned(DH_get_nid) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_nid');
  Result := DH_get_nid(dh);
end;

function Load_DH_KDF_X9_42(out_: Pbyte; outlen: TOpenSSL_C_SIZET; Z: Pbyte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; ukm: Pbyte; ukmlen: TOpenSSL_C_SIZET; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  DH_KDF_X9_42 := LoadLibCryptoFunction('DH_KDF_X9_42');
  if not assigned(DH_KDF_X9_42) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_KDF_X9_42');
  Result := DH_KDF_X9_42(out_, outlen, Z, Zlen, key_oid, ukm, ukmlen, md);
end;

procedure Load_DH_get0_pqg(dh: PDH; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl;
begin
  DH_get0_pqg := LoadLibCryptoFunction('DH_get0_pqg');
  if not assigned(DH_get0_pqg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_pqg');
  DH_get0_pqg(dh, p, q, g);
end;

function Load_DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DH_set0_pqg := LoadLibCryptoFunction('DH_set0_pqg');
  if not assigned(DH_set0_pqg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set0_pqg');
  Result := DH_set0_pqg(dh, p, q, g);
end;

procedure Load_DH_get0_key(dh: PDH; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl;
begin
  DH_get0_key := LoadLibCryptoFunction('DH_get0_key');
  if not assigned(DH_get0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_key');
  DH_get0_key(dh, pub_key, priv_key);
end;

function Load_DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DH_set0_key := LoadLibCryptoFunction('DH_set0_key');
  if not assigned(DH_set0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set0_key');
  Result := DH_set0_key(dh, pub_key, priv_key);
end;

function Load_DH_get0_p(dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_p := LoadLibCryptoFunction('DH_get0_p');
  if not assigned(DH_get0_p) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_p');
  Result := DH_get0_p(dh);
end;

function Load_DH_get0_q(dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_q := LoadLibCryptoFunction('DH_get0_q');
  if not assigned(DH_get0_q) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_q');
  Result := DH_get0_q(dh);
end;

function Load_DH_get0_g(dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_g := LoadLibCryptoFunction('DH_get0_g');
  if not assigned(DH_get0_g) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_g');
  Result := DH_get0_g(dh);
end;

function Load_DH_get0_priv_key(dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_priv_key := LoadLibCryptoFunction('DH_get0_priv_key');
  if not assigned(DH_get0_priv_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_priv_key');
  Result := DH_get0_priv_key(dh);
end;

function Load_DH_get0_pub_key(dh: PDH): PBIGNUM; cdecl;
begin
  DH_get0_pub_key := LoadLibCryptoFunction('DH_get0_pub_key');
  if not assigned(DH_get0_pub_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_pub_key');
  Result := DH_get0_pub_key(dh);
end;

procedure Load_DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
begin
  DH_clear_flags := LoadLibCryptoFunction('DH_clear_flags');
  if not assigned(DH_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_clear_flags');
  DH_clear_flags(dh, flags);
end;

function Load_DH_test_flags(dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_test_flags := LoadLibCryptoFunction('DH_test_flags');
  if not assigned(DH_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_test_flags');
  Result := DH_test_flags(dh, flags);
end;

procedure Load_DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
begin
  DH_set_flags := LoadLibCryptoFunction('DH_set_flags');
  if not assigned(DH_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_flags');
  DH_set_flags(dh, flags);
end;

function Load_DH_get0_engine(d: PDH): PENGINE; cdecl;
begin
  DH_get0_engine := LoadLibCryptoFunction('DH_get0_engine');
  if not assigned(DH_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_engine');
  Result := DH_get0_engine(d);
end;

function Load_DH_get_length(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  DH_get_length := LoadLibCryptoFunction('DH_get_length');
  if not assigned(DH_get_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_length');
  Result := DH_get_length(dh);
end;

function Load_DH_set_length(dh: PDH; length: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_set_length := LoadLibCryptoFunction('DH_set_length');
  if not assigned(DH_set_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_length');
  Result := DH_set_length(dh, length);
end;

function Load_DH_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_METHOD; cdecl;
begin
  DH_meth_new := LoadLibCryptoFunction('DH_meth_new');
  if not assigned(DH_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_new');
  Result := DH_meth_new(name, flags);
end;

procedure Load_DH_meth_free(dhm: PDH_METHOD); cdecl;
begin
  DH_meth_free := LoadLibCryptoFunction('DH_meth_free');
  if not assigned(DH_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_free');
  DH_meth_free(dhm);
end;

function Load_DH_meth_dup(dhm: PDH_METHOD): PDH_METHOD; cdecl;
begin
  DH_meth_dup := LoadLibCryptoFunction('DH_meth_dup');
  if not assigned(DH_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_dup');
  Result := DH_meth_dup(dhm);
end;

function Load_DH_meth_get0_name(dhm: PDH_METHOD): PAnsiChar; cdecl;
begin
  DH_meth_get0_name := LoadLibCryptoFunction('DH_meth_get0_name');
  if not assigned(DH_meth_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get0_name');
  Result := DH_meth_get0_name(dhm);
end;

function Load_DH_meth_set1_name(dhm: PDH_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set1_name := LoadLibCryptoFunction('DH_meth_set1_name');
  if not assigned(DH_meth_set1_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set1_name');
  Result := DH_meth_set1_name(dhm, name);
end;

function Load_DH_meth_get_flags(dhm: PDH_METHOD): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_get_flags := LoadLibCryptoFunction('DH_meth_get_flags');
  if not assigned(DH_meth_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_flags');
  Result := DH_meth_get_flags(dhm);
end;

function Load_DH_meth_set_flags(dhm: PDH_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_flags := LoadLibCryptoFunction('DH_meth_set_flags');
  if not assigned(DH_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_flags');
  Result := DH_meth_set_flags(dhm, flags);
end;

function Load_DH_meth_get0_app_data(dhm: PDH_METHOD): pointer; cdecl;
begin
  DH_meth_get0_app_data := LoadLibCryptoFunction('DH_meth_get0_app_data');
  if not assigned(DH_meth_get0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get0_app_data');
  Result := DH_meth_get0_app_data(dhm);
end;

function Load_DH_meth_set0_app_data(dhm: PDH_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set0_app_data := LoadLibCryptoFunction('DH_meth_set0_app_data');
  if not assigned(DH_meth_set0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set0_app_data');
  Result := DH_meth_set0_app_data(dhm, app_data);
end;

function Load_DH_meth_get_generate_key(dhm: PDH_METHOD): TFuncType000; cdecl;
begin
  DH_meth_get_generate_key := LoadLibCryptoFunction('DH_meth_get_generate_key');
  if not assigned(DH_meth_get_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_generate_key');
  Result := DH_meth_get_generate_key(dhm);
end;

function Load_DH_meth_set_generate_key(dhm: PDH_METHOD; generate_key: TFuncType001): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_generate_key := LoadLibCryptoFunction('DH_meth_set_generate_key');
  if not assigned(DH_meth_set_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_generate_key');
  Result := DH_meth_set_generate_key(dhm, generate_key);
end;

function Load_DH_meth_get_compute_key(dhm: PDH_METHOD): TFuncType002; cdecl;
begin
  DH_meth_get_compute_key := LoadLibCryptoFunction('DH_meth_get_compute_key');
  if not assigned(DH_meth_get_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_compute_key');
  Result := DH_meth_get_compute_key(dhm);
end;

function Load_DH_meth_set_compute_key(dhm: PDH_METHOD; compute_key: TFuncType003): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_compute_key := LoadLibCryptoFunction('DH_meth_set_compute_key');
  if not assigned(DH_meth_set_compute_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_compute_key');
  Result := DH_meth_set_compute_key(dhm, compute_key);
end;

function Load_DH_meth_get_bn_mod_exp(dhm: PDH_METHOD): TFuncType004; cdecl;
begin
  DH_meth_get_bn_mod_exp := LoadLibCryptoFunction('DH_meth_get_bn_mod_exp');
  if not assigned(DH_meth_get_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_bn_mod_exp');
  Result := DH_meth_get_bn_mod_exp(dhm);
end;

function Load_DH_meth_set_bn_mod_exp(dhm: PDH_METHOD; bn_mod_exp: TFuncType005): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_bn_mod_exp := LoadLibCryptoFunction('DH_meth_set_bn_mod_exp');
  if not assigned(DH_meth_set_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_bn_mod_exp');
  Result := DH_meth_set_bn_mod_exp(dhm, bn_mod_exp);
end;

function Load_DH_meth_get_init(dhm: PDH_METHOD): TFuncType006; cdecl;
begin
  DH_meth_get_init := LoadLibCryptoFunction('DH_meth_get_init');
  if not assigned(DH_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_init');
  Result := DH_meth_get_init(dhm);
end;

function Load_DH_meth_set_init(dhm: PDH_METHOD; init: TFuncType007): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_init := LoadLibCryptoFunction('DH_meth_set_init');
  if not assigned(DH_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_init');
  Result := DH_meth_set_init(dhm, init);
end;

function Load_DH_meth_get_finish(dhm: PDH_METHOD): TFuncType008; cdecl;
begin
  DH_meth_get_finish := LoadLibCryptoFunction('DH_meth_get_finish');
  if not assigned(DH_meth_get_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_finish');
  Result := DH_meth_get_finish(dhm);
end;

function Load_DH_meth_set_finish(dhm: PDH_METHOD; finish: TFuncType009): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_finish := LoadLibCryptoFunction('DH_meth_set_finish');
  if not assigned(DH_meth_set_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_finish');
  Result := DH_meth_set_finish(dhm, finish);
end;

function Load_DH_meth_get_generate_params(dhm: PDH_METHOD): TFuncType010; cdecl;
begin
  DH_meth_get_generate_params := LoadLibCryptoFunction('DH_meth_get_generate_params');
  if not assigned(DH_meth_get_generate_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_generate_params');
  Result := DH_meth_get_generate_params(dhm);
end;

function Load_DH_meth_set_generate_params(dhm: PDH_METHOD; generate_params: TFuncType011): TOpenSSL_C_INT; cdecl;
begin
  DH_meth_set_generate_params := LoadLibCryptoFunction('DH_meth_set_generate_params');
  if not assigned(DH_meth_set_generate_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_generate_params');
  Result := DH_meth_set_generate_params(dhm, generate_params);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}
function Load_DH_generate_parameters(prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; callback: TFuncType012; cb_arg: pointer): PDH; cdecl;
begin
  DH_generate_parameters := LoadLibCryptoFunction('DH_generate_parameters');
  if not assigned(DH_generate_parameters) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DH_generate_parameters');
  Result := DH_generate_parameters(prime_len, generator, callback, cb_arg);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_0_9_8}
{$endif} { OPENSSL_NO_DH}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  EVP_PKEY_CTX_set_dh_paramgen_type := Load_EVP_PKEY_CTX_set_dh_paramgen_type;
  EVP_PKEY_CTX_set_dh_paramgen_gindex := Load_EVP_PKEY_CTX_set_dh_paramgen_gindex;
  EVP_PKEY_CTX_set_dh_paramgen_seed := Load_EVP_PKEY_CTX_set_dh_paramgen_seed;
  EVP_PKEY_CTX_set_dh_paramgen_prime_len := Load_EVP_PKEY_CTX_set_dh_paramgen_prime_len;
  EVP_PKEY_CTX_set_dh_paramgen_subprime_len := Load_EVP_PKEY_CTX_set_dh_paramgen_subprime_len;
  EVP_PKEY_CTX_set_dh_paramgen_generator := Load_EVP_PKEY_CTX_set_dh_paramgen_generator;
  EVP_PKEY_CTX_set_dh_nid := Load_EVP_PKEY_CTX_set_dh_nid;
  EVP_PKEY_CTX_set_dh_rfc5114 := Load_EVP_PKEY_CTX_set_dh_rfc5114;
  EVP_PKEY_CTX_set_dhx_rfc5114 := Load_EVP_PKEY_CTX_set_dhx_rfc5114;
  EVP_PKEY_CTX_set_dh_pad := Load_EVP_PKEY_CTX_set_dh_pad;
  EVP_PKEY_CTX_set_dh_kdf_type := Load_EVP_PKEY_CTX_set_dh_kdf_type;
  EVP_PKEY_CTX_get_dh_kdf_type := Load_EVP_PKEY_CTX_get_dh_kdf_type;
  EVP_PKEY_CTX_set0_dh_kdf_oid := Load_EVP_PKEY_CTX_set0_dh_kdf_oid;
  EVP_PKEY_CTX_get0_dh_kdf_oid := Load_EVP_PKEY_CTX_get0_dh_kdf_oid;
  EVP_PKEY_CTX_set_dh_kdf_md := Load_EVP_PKEY_CTX_set_dh_kdf_md;
  EVP_PKEY_CTX_get_dh_kdf_md := Load_EVP_PKEY_CTX_get_dh_kdf_md;
  EVP_PKEY_CTX_set_dh_kdf_outlen := Load_EVP_PKEY_CTX_set_dh_kdf_outlen;
  EVP_PKEY_CTX_get_dh_kdf_outlen := Load_EVP_PKEY_CTX_get_dh_kdf_outlen;
  EVP_PKEY_CTX_set0_dh_kdf_ukm := Load_EVP_PKEY_CTX_set0_dh_kdf_ukm;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_CTX_get0_dh_kdf_ukm := Load_EVP_PKEY_CTX_get0_dh_kdf_ukm;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DH}
  DHparams_it := Load_DHparams_it;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DHparams_dup := Load_DHparams_dup;
  DH_OpenSSL := Load_DH_OpenSSL;
  DH_set_default_method := Load_DH_set_default_method;
  DH_get_default_method := Load_DH_get_default_method;
  DH_set_method := Load_DH_set_method;
  DH_new_method := Load_DH_new_method;
  DH_new := Load_DH_new;
  DH_free := Load_DH_free;
  DH_up_ref := Load_DH_up_ref;
  DH_bits := Load_DH_bits;
  DH_size := Load_DH_size;
  DH_security_bits := Load_DH_security_bits;
  DH_set_ex_data := Load_DH_set_ex_data;
  DH_get_ex_data := Load_DH_get_ex_data;
  DH_generate_parameters_ex := Load_DH_generate_parameters_ex;
  DH_check_params_ex := Load_DH_check_params_ex;
  DH_check_ex := Load_DH_check_ex;
  DH_check_pub_key_ex := Load_DH_check_pub_key_ex;
  DH_check_params := Load_DH_check_params;
  DH_check := Load_DH_check;
  DH_check_pub_key := Load_DH_check_pub_key;
  DH_generate_key := Load_DH_generate_key;
  DH_compute_key := Load_DH_compute_key;
  DH_compute_key_padded := Load_DH_compute_key_padded;
  d2i_DHparams := Load_d2i_DHparams;
  i2d_DHparams := Load_i2d_DHparams;
  d2i_DHxparams := Load_d2i_DHxparams;
  i2d_DHxparams := Load_i2d_DHxparams;
        {$ifndef  OPENSSL_NO_STDIO}
  DHparams_print_fp := Load_DHparams_print_fp;
        {$endif} { OPENSSL_NO_STDIO}
  DHparams_print := Load_DHparams_print;
  DH_get_1024_160 := Load_DH_get_1024_160;
  DH_get_2048_224 := Load_DH_get_2048_224;
  DH_get_2048_256 := Load_DH_get_2048_256;
  DH_new_by_nid := Load_DH_new_by_nid;
  DH_get_nid := Load_DH_get_nid;
  DH_KDF_X9_42 := Load_DH_KDF_X9_42;
  DH_get0_pqg := Load_DH_get0_pqg;
  DH_set0_pqg := Load_DH_set0_pqg;
  DH_get0_key := Load_DH_get0_key;
  DH_set0_key := Load_DH_set0_key;
  DH_get0_p := Load_DH_get0_p;
  DH_get0_q := Load_DH_get0_q;
  DH_get0_g := Load_DH_get0_g;
  DH_get0_priv_key := Load_DH_get0_priv_key;
  DH_get0_pub_key := Load_DH_get0_pub_key;
  DH_clear_flags := Load_DH_clear_flags;
  DH_test_flags := Load_DH_test_flags;
  DH_set_flags := Load_DH_set_flags;
  DH_get0_engine := Load_DH_get0_engine;
  DH_get_length := Load_DH_get_length;
  DH_set_length := Load_DH_set_length;
  DH_meth_new := Load_DH_meth_new;
  DH_meth_free := Load_DH_meth_free;
  DH_meth_dup := Load_DH_meth_dup;
  DH_meth_get0_name := Load_DH_meth_get0_name;
  DH_meth_set1_name := Load_DH_meth_set1_name;
  DH_meth_get_flags := Load_DH_meth_get_flags;
  DH_meth_set_flags := Load_DH_meth_set_flags;
  DH_meth_get0_app_data := Load_DH_meth_get0_app_data;
  DH_meth_set0_app_data := Load_DH_meth_set0_app_data;
  DH_meth_get_generate_key := Load_DH_meth_get_generate_key;
  DH_meth_set_generate_key := Load_DH_meth_set_generate_key;
  DH_meth_get_compute_key := Load_DH_meth_get_compute_key;
  DH_meth_set_compute_key := Load_DH_meth_set_compute_key;
  DH_meth_get_bn_mod_exp := Load_DH_meth_get_bn_mod_exp;
  DH_meth_set_bn_mod_exp := Load_DH_meth_set_bn_mod_exp;
  DH_meth_get_init := Load_DH_meth_get_init;
  DH_meth_set_init := Load_DH_meth_set_init;
  DH_meth_get_finish := Load_DH_meth_get_finish;
  DH_meth_set_finish := Load_DH_meth_set_finish;
  DH_meth_get_generate_params := Load_DH_meth_get_generate_params;
  DH_meth_set_generate_params := Load_DH_meth_set_generate_params;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}
  DH_generate_parameters := Load_DH_generate_parameters;
    {$endif} { OPENSSL_NO_DEPRECATED_0_9_8}
{$endif} { OPENSSL_NO_DH}
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



