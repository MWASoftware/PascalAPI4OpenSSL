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

unit openssl_dsa;

{
  Generated from OpenSSL 3.0.20 Header File dsa.h - Tue 19 May 14:24:57 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_dsa.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_evp,openssl_types,openssl_e_os2,openssl_asn1,
     openssl_bio,openssl_crypto,openssl_bn,openssl_dh,openssl_dsaerr;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_DSA_H}
  {$define OPENSSL_DSA_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_DSA_H}
  {$endif}
  {$include openssl_opensslconf.inc}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx: PEVP_PKEY_CTX; nbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dsa_paramgen_bits';
  function EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx: PEVP_PKEY_CTX; qbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dsa_paramgen_q_bits';
  function EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx: PEVP_PKEY_CTX; md_name: PAnsiChar; md_properties: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dsa_paramgen_md_props';
  function EVP_PKEY_CTX_set_dsa_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dsa_paramgen_gindex';
  function EVP_PKEY_CTX_set_dsa_paramgen_type(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dsa_paramgen_type';
  function EVP_PKEY_CTX_set_dsa_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dsa_paramgen_seed';
  function EVP_PKEY_CTX_set_dsa_paramgen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_dsa_paramgen_md';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM EVP_PKEY_CTX_set_dsa_paramgen_bits}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dsa_paramgen_q_bits}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dsa_paramgen_md_props}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dsa_paramgen_gindex}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dsa_paramgen_type}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dsa_paramgen_seed}
  {$EXTERNALSYM EVP_PKEY_CTX_set_dsa_paramgen_md}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx: PEVP_PKEY_CTX; nbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx: PEVP_PKEY_CTX; qbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx: PEVP_PKEY_CTX; md_name: PAnsiChar; md_properties: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dsa_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dsa_paramgen_type(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dsa_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_dsa_paramgen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_dsa_paramgen_bits: function(ctx: PEVP_PKEY_CTX; nbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dsa_paramgen_bits;
  EVP_PKEY_CTX_set_dsa_paramgen_q_bits: function(ctx: PEVP_PKEY_CTX; qbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dsa_paramgen_q_bits;
  EVP_PKEY_CTX_set_dsa_paramgen_md_props: function(ctx: PEVP_PKEY_CTX; md_name: PAnsiChar; md_properties: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dsa_paramgen_md_props;
  EVP_PKEY_CTX_set_dsa_paramgen_gindex: function(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dsa_paramgen_gindex;
  EVP_PKEY_CTX_set_dsa_paramgen_type: function(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dsa_paramgen_type;
  EVP_PKEY_CTX_set_dsa_paramgen_seed: function(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dsa_paramgen_seed;
  EVP_PKEY_CTX_set_dsa_paramgen_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_dsa_paramgen_md;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_PKEY_CTRL_DSA_PARAMGEN_BITS = EVP_PKEY_ALG_CTRL+1;
  EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = EVP_PKEY_ALG_CTRL+2;
  EVP_PKEY_CTRL_DSA_PARAMGEN_MD = EVP_PKEY_ALG_CTRL+3;
  {$ifndef  OPENSSL_NO_DSA}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
    {$endif}
    {$ifndef  OPENSSL_DSA_MAX_MODULUS_BITS}

const
  OPENSSL_DSA_MAX_MODULUS_BITS = 10000;
    {$endif}

const
  OPENSSL_DSA_FIPS_MIN_MODULUS_BITS = 1024;

type
  {Auto-generated forward references}
  PDSA_SIG_st = ^TDSA_SIG;
  PPDSA_SIG_st = ^PDSA_SIG_st;
  PDSA_SIG = ^TDSA_SIG;
  PPDSA_SIG = ^PDSA_SIG;
  {end of auto-generated forward references}

  TDSA_SIG_st = record end;
  TDSA_SIG = TDSA_SIG_st;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_SIG_new: PDSA_SIG; cdecl; external CLibCrypto name 'DSA_SIG_new';
  procedure DSA_SIG_free(a: PDSA_SIG); cdecl; external CLibCrypto name 'DSA_SIG_free';
  function d2i_DSA_SIG(a: PPDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PDSA_SIG; cdecl; external CLibCrypto name 'd2i_DSA_SIG';
  function i2d_DSA_SIG(a: PDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_DSA_SIG';
  procedure DSA_SIG_get0(sig: PDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl; external CLibCrypto name 'DSA_SIG_get0';
  function DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_SIG_set0';
    {$else}
  {$EXTERNALSYM DSA_SIG_new}
  {$EXTERNALSYM DSA_SIG_free}
  {$EXTERNALSYM d2i_DSA_SIG}
  {$EXTERNALSYM i2d_DSA_SIG}
  {$EXTERNALSYM DSA_SIG_get0}
  {$EXTERNALSYM DSA_SIG_set0}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_SIG_new: PDSA_SIG; cdecl;
  procedure Load_DSA_SIG_free(a: PDSA_SIG); cdecl;
  function Load_d2i_DSA_SIG(a: PPDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PDSA_SIG; cdecl;
  function Load_i2d_DSA_SIG(a: PDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  procedure Load_DSA_SIG_get0(sig: PDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl;
  function Load_DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;

var
  DSA_SIG_new: function: PDSA_SIG; cdecl = Load_DSA_SIG_new;
  DSA_SIG_free: procedure(a: PDSA_SIG); cdecl = Load_DSA_SIG_free;
  d2i_DSA_SIG: function(a: PPDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PDSA_SIG; cdecl = Load_d2i_DSA_SIG;
  i2d_DSA_SIG: function(a: PDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_DSA_SIG;
  DSA_SIG_get0: procedure(sig: PDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl = Load_DSA_SIG_get0;
  DSA_SIG_set0: function(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DSA_SIG_set0;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

const
      
      {* Does nothing. Previously this switched off constant time behaviour.
      }
  DSA_FLAG_NO_EXP_CONSTTIME = $00;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  DSA_FLAG_CACHE_MONT_P = $01;
      
      {* If this flag is set the DSA method is FIPS compliant and can be used in
      * FIPS mode. This is set in the validated module method. If an application
      * sets this flag in its own methods it is its responsibility to ensure the
      * result is compliant.
      }
  DSA_FLAG_FIPS_METHOD = $0400;
      
      {* If this flag is set the operations normally disabled in FIPS mode are
      * permitted it is then the applications responsibility to ensure that the
      * usage is compliant.
      }
  DSA_FLAG_NON_FIPS_ALLOW = $0400;
  DSA_FLAG_FIPS_CHECKED = $0800;
  {# define  d2i_DSAparams_fp(fp,x) (DSA *)ASN1_d2i_fp((void *(*)(void))DSA_new, (d2i_of_void *)d2i_DSAparams, (fp), (void **)(x))}
  {# define  i2d_DSAparams_fp(fp,x) ASN1_i2d_fp(i2d_DSAparams, (fp), (unsigned char *)(x))} {Function argument out of range at line no 109}
  {# define  d2i_DSAparams_bio(bp,x) ASN1_d2i_bio_of(DSA, DSA_new, d2i_DSAparams, bp, x)} {Function argument out of range at line no 111}
  {# define  i2d_DSAparams_bio(bp,x) ASN1_i2d_bio_of(DSA, i2d_DSAparams, bp, x)} {Function argument out of range at line no 113}


      { Already defined in ossl_typ.h }
      { typedef struct dsa_st DSA; }
      { typedef struct dsa_method DSA_METHOD; }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSAparams_dup(a: PDSA): PDSA; cdecl; external CLibCrypto name 'DSAparams_dup'; deprecated 'Since OpenSSL 3.0';
  function DSA_do_sign(dgst: Pbyte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl; external CLibCrypto name 'DSA_do_sign'; deprecated 'Since OpenSSL 3.0';
  function DSA_do_verify(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_do_verify'; deprecated 'Since OpenSSL 3.0';
  function DSA_OpenSSL: PDSA_METHOD; cdecl; external CLibCrypto name 'DSA_OpenSSL'; deprecated 'Since OpenSSL 3.0';
  procedure DSA_set_default_method(_param1: PDSA_METHOD); cdecl; external CLibCrypto name 'DSA_set_default_method'; deprecated 'Since OpenSSL 3.0';
  function DSA_get_default_method: PDSA_METHOD; cdecl; external CLibCrypto name 'DSA_get_default_method'; deprecated 'Since OpenSSL 3.0';
  function DSA_set_method(dsa: PDSA; _param2: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_set_method'; deprecated 'Since OpenSSL 3.0';
  function DSA_get_method(d: PDSA): PDSA_METHOD; cdecl; external CLibCrypto name 'DSA_get_method'; deprecated 'Since OpenSSL 3.0';
  function DSA_new: PDSA; cdecl; external CLibCrypto name 'DSA_new'; deprecated 'Since OpenSSL 3.0';
  function DSA_new_method(engine: PENGINE): PDSA; cdecl; external CLibCrypto name 'DSA_new_method'; deprecated 'Since OpenSSL 3.0';
  procedure DSA_free(r: PDSA); cdecl; external CLibCrypto name 'DSA_free'; deprecated 'Since OpenSSL 3.0';
  { "up" the DSA object's reference count }
  function DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_up_ref'; deprecated 'Since OpenSSL 3.0';
  function DSA_size(_param1: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_size'; deprecated 'Since OpenSSL 3.0';
  function DSA_bits(d: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_bits'; deprecated 'Since OpenSSL 3.0';
  function DSA_security_bits(d: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_security_bits'; deprecated 'Since OpenSSL 3.0';
  { next 4 return -1 on error }
  function DSA_sign_setup(dsa: PDSA; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_sign_setup'; deprecated 'Since OpenSSL 3.0';
  function DSA_sign(type_: TOpenSSL_C_INT; dgst: Pbyte; dlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_sign'; deprecated 'Since OpenSSL 3.0';
  function DSA_verify(type_: TOpenSSL_C_INT; dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sigbuf: Pbyte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_verify'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSAparams_dup}
  {$EXTERNALSYM DSA_do_sign}
  {$EXTERNALSYM DSA_do_verify}
  {$EXTERNALSYM DSA_OpenSSL}
  {$EXTERNALSYM DSA_set_default_method}
  {$EXTERNALSYM DSA_get_default_method}
  {$EXTERNALSYM DSA_set_method}
  {$EXTERNALSYM DSA_get_method}
  {$EXTERNALSYM DSA_new}
  {$EXTERNALSYM DSA_new_method}
  {$EXTERNALSYM DSA_free}
  {$EXTERNALSYM DSA_up_ref}
  {$EXTERNALSYM DSA_size}
  {$EXTERNALSYM DSA_bits}
  {$EXTERNALSYM DSA_security_bits}
  {$EXTERNALSYM DSA_sign_setup}
  {$EXTERNALSYM DSA_sign}
  {$EXTERNALSYM DSA_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSAparams_dup(a: PDSA): PDSA; cdecl;
  function Load_DSA_do_sign(dgst: Pbyte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl;
  function Load_DSA_do_verify(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_OpenSSL: PDSA_METHOD; cdecl;
  procedure Load_DSA_set_default_method(_param1: PDSA_METHOD); cdecl;
  function Load_DSA_get_default_method: PDSA_METHOD; cdecl;
  function Load_DSA_set_method(dsa: PDSA; _param2: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_DSA_get_method(d: PDSA): PDSA_METHOD; cdecl;
  function Load_DSA_new: PDSA; cdecl;
  function Load_DSA_new_method(engine: PENGINE): PDSA; cdecl;
  procedure Load_DSA_free(r: PDSA); cdecl;
  function Load_DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_size(_param1: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_bits(d: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_security_bits(d: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_sign_setup(dsa: PDSA; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_DSA_sign(type_: TOpenSSL_C_INT; dgst: Pbyte; dlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_verify(type_: TOpenSSL_C_INT; dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sigbuf: Pbyte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl;

var
  DSAparams_dup: function(a: PDSA): PDSA; cdecl = Load_DSAparams_dup;
  DSA_do_sign: function(dgst: Pbyte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl = Load_DSA_do_sign;
  DSA_do_verify: function(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_do_verify;
  DSA_OpenSSL: function: PDSA_METHOD; cdecl = Load_DSA_OpenSSL;
  DSA_set_default_method: procedure(_param1: PDSA_METHOD); cdecl = Load_DSA_set_default_method;
  DSA_get_default_method: function: PDSA_METHOD; cdecl = Load_DSA_get_default_method;
  DSA_set_method: function(dsa: PDSA; _param2: PDSA_METHOD): TOpenSSL_C_INT; cdecl = Load_DSA_set_method;
  DSA_get_method: function(d: PDSA): PDSA_METHOD; cdecl = Load_DSA_get_method;
  DSA_new: function: PDSA; cdecl = Load_DSA_new;
  DSA_new_method: function(engine: PENGINE): PDSA; cdecl = Load_DSA_new_method;
  DSA_free: procedure(r: PDSA); cdecl = Load_DSA_free;
  { "up" the DSA object's reference count }
  DSA_up_ref: function(r: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_up_ref;
  DSA_size: function(_param1: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_size;
  DSA_bits: function(d: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_bits;
  DSA_security_bits: function(d: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_security_bits;
  { next 4 return -1 on error }
  DSA_sign_setup: function(dsa: PDSA; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl = Load_DSA_sign_setup;
  DSA_sign: function(type_: TOpenSSL_C_INT; dgst: Pbyte; dlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_sign;
  DSA_verify: function(type_: TOpenSSL_C_INT; dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sigbuf: Pbyte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_verify;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {# define  DSA_get_ex_new_index(l,p,newf,dupf,freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_DSA, l, p, newf, dupf, freef)} {Macro Return Type unknown at line no 147}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_set_ex_data'; deprecated 'Since OpenSSL 3.0';
  function DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'DSA_get_ex_data'; deprecated 'Since OpenSSL 3.0';
  function d2i_DSAPublicKey(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl; external CLibCrypto name 'd2i_DSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function i2d_DSAPublicKey(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_DSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function d2i_DSAPrivateKey(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl; external CLibCrypto name 'd2i_DSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function i2d_DSAPrivateKey(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_DSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function d2i_DSAparams(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl; external CLibCrypto name 'd2i_DSAparams'; deprecated 'Since OpenSSL 3.0';
  function i2d_DSAparams(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_DSAparams'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_set_ex_data}
  {$EXTERNALSYM DSA_get_ex_data}
  {$EXTERNALSYM d2i_DSAPublicKey}
  {$EXTERNALSYM i2d_DSAPublicKey}
  {$EXTERNALSYM d2i_DSAPrivateKey}
  {$EXTERNALSYM i2d_DSAPrivateKey}
  {$EXTERNALSYM d2i_DSAparams}
  {$EXTERNALSYM i2d_DSAparams}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): pointer; cdecl;
  function Load_d2i_DSAPublicKey(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl;
  function Load_i2d_DSAPublicKey(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_d2i_DSAPrivateKey(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl;
  function Load_i2d_DSAPrivateKey(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_d2i_DSAparams(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl;
  function Load_i2d_DSAparams(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;

var
  DSA_set_ex_data: function(d: PDSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl = Load_DSA_set_ex_data;
  DSA_get_ex_data: function(d: PDSA; idx: TOpenSSL_C_INT): pointer; cdecl = Load_DSA_get_ex_data;
  d2i_DSAPublicKey: function(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl = Load_d2i_DSAPublicKey;
  i2d_DSAPublicKey: function(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_DSAPublicKey;
  d2i_DSAPrivateKey: function(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl = Load_d2i_DSAPrivateKey;
  i2d_DSAPrivateKey: function(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_DSAPrivateKey;
  d2i_DSAparams: function(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl = Load_d2i_DSAparams;
  i2d_DSAparams: function(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_DSAparams;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

      { Deprecated version }
  TFuncType000 = procedure(_param1: TOpenSSL_C_INT; _param2: TOpenSSL_C_INT; _param3: pointer); cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_generate_parameters(bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PDSA; cdecl; external CLibCrypto name 'DSA_generate_parameters'; deprecated 'Since OpenSSL 0.9.8';
      {$else}
  {$EXTERNALSYM DSA_generate_parameters}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_generate_parameters(bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PDSA; cdecl;

var
  DSA_generate_parameters: function(bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PDSA; cdecl = Load_DSA_generate_parameters;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      { New version }
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_generate_parameters_ex'; deprecated 'Since OpenSSL 3.0';
  function DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_generate_key'; deprecated 'Since OpenSSL 3.0';
  function DSAparams_print(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSAparams_print'; deprecated 'Since OpenSSL 3.0';
  function DSA_print(bp: PBIO; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_print'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_generate_parameters_ex}
  {$EXTERNALSYM DSA_generate_key}
  {$EXTERNALSYM DSAparams_print}
  {$EXTERNALSYM DSA_print}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
  function Load_DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSAparams_print(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_print(bp: PBIO; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  DSA_generate_parameters_ex: function(dsa: PDSA; bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_DSA_generate_parameters_ex;
  DSA_generate_key: function(a: PDSA): TOpenSSL_C_INT; cdecl = Load_DSA_generate_key;
  DSAparams_print: function(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl = Load_DSAparams_print;
  DSA_print: function(bp: PBIO; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DSA_print;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$ifndef  OPENSSL_NO_STDIO}


        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSAparams_print_fp(fp: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSAparams_print_fp'; deprecated 'Since OpenSSL 3.0';
  function DSA_print_fp(bp: PFILE; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_print_fp'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM DSAparams_print_fp}
  {$EXTERNALSYM DSA_print_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSAparams_print_fp(fp: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl;
  function Load_DSA_print_fp(bp: PFILE; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  DSAparams_print_fp: function(fp: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl = Load_DSAparams_print_fp;
  DSA_print_fp: function(bp: PFILE; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DSA_print_fp;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}

const
  DSS_prime_checks = 64;
  {# define  DSA_is_prime(n,callback,cb_arg) BN_is_prime(n, DSS_prime_checks, callback, NULL, cb_arg)} {Macro Return Type unknown at line no 194}
      
      {* Primality test according to FIPS PUB 186-4, Appendix C.3. Since we only
      * have one value here we set the number of checks to 64 which is the 128 bit
      * security level that is the highest level and valid for creating a 3072 bit
      * DSA key.
      }
      {$ifndef  OPENSSL_NO_DH}


        
        {* Convert DSA structure (key or just parameters) into DH structure (be
        * careful to avoid small subgroup attacks when using this!)
        }
        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_dup_DH(r: PDSA): PDH; cdecl; external CLibCrypto name 'DSA_dup_DH'; deprecated 'Since OpenSSL 3.0';
        {$else}
  {$EXTERNALSYM DSA_dup_DH}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_dup_DH(r: PDSA): PDH; cdecl;

var
  DSA_dup_DH: function(r: PDSA): PDH; cdecl = Load_DSA_dup_DH;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure DSA_get0_pqg(d: PDSA; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl; external CLibCrypto name 'DSA_get0_pqg'; deprecated 'Since OpenSSL 3.0';
  function DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_set0_pqg'; deprecated 'Since OpenSSL 3.0';
  procedure DSA_get0_key(d: PDSA; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl; external CLibCrypto name 'DSA_get0_key'; deprecated 'Since OpenSSL 3.0';
  function DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_set0_key'; deprecated 'Since OpenSSL 3.0';
  function DSA_get0_p(d: PDSA): PBIGNUM; cdecl; external CLibCrypto name 'DSA_get0_p'; deprecated 'Since OpenSSL 3.0';
  function DSA_get0_q(d: PDSA): PBIGNUM; cdecl; external CLibCrypto name 'DSA_get0_q'; deprecated 'Since OpenSSL 3.0';
  function DSA_get0_g(d: PDSA): PBIGNUM; cdecl; external CLibCrypto name 'DSA_get0_g'; deprecated 'Since OpenSSL 3.0';
  function DSA_get0_pub_key(d: PDSA): PBIGNUM; cdecl; external CLibCrypto name 'DSA_get0_pub_key'; deprecated 'Since OpenSSL 3.0';
  function DSA_get0_priv_key(d: PDSA): PBIGNUM; cdecl; external CLibCrypto name 'DSA_get0_priv_key'; deprecated 'Since OpenSSL 3.0';
  procedure DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DSA_clear_flags'; deprecated 'Since OpenSSL 3.0';
  function DSA_test_flags(d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_test_flags'; deprecated 'Since OpenSSL 3.0';
  procedure DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DSA_set_flags'; deprecated 'Since OpenSSL 3.0';
  function DSA_get0_engine(d: PDSA): PENGINE; cdecl; external CLibCrypto name 'DSA_get0_engine'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl; external CLibCrypto name 'DSA_meth_new'; deprecated 'Since OpenSSL 3.0';
  procedure DSA_meth_free(dsam: PDSA_METHOD); cdecl; external CLibCrypto name 'DSA_meth_free'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_dup(dsam: PDSA_METHOD): PDSA_METHOD; cdecl; external CLibCrypto name 'DSA_meth_dup'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_get0_name(dsam: PDSA_METHOD): PAnsiChar; cdecl; external CLibCrypto name 'DSA_meth_get0_name'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_set1_name(dsam: PDSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set1_name'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_get_flags(dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_get_flags'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_flags'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_get0_app_data(dsam: PDSA_METHOD): pointer; cdecl; external CLibCrypto name 'DSA_meth_get0_app_data'; deprecated 'Since OpenSSL 3.0';
  function DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set0_app_data'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_get0_pqg}
  {$EXTERNALSYM DSA_set0_pqg}
  {$EXTERNALSYM DSA_get0_key}
  {$EXTERNALSYM DSA_set0_key}
  {$EXTERNALSYM DSA_get0_p}
  {$EXTERNALSYM DSA_get0_q}
  {$EXTERNALSYM DSA_get0_g}
  {$EXTERNALSYM DSA_get0_pub_key}
  {$EXTERNALSYM DSA_get0_priv_key}
  {$EXTERNALSYM DSA_clear_flags}
  {$EXTERNALSYM DSA_test_flags}
  {$EXTERNALSYM DSA_set_flags}
  {$EXTERNALSYM DSA_get0_engine}
  {$EXTERNALSYM DSA_meth_new}
  {$EXTERNALSYM DSA_meth_free}
  {$EXTERNALSYM DSA_meth_dup}
  {$EXTERNALSYM DSA_meth_get0_name}
  {$EXTERNALSYM DSA_meth_set1_name}
  {$EXTERNALSYM DSA_meth_get_flags}
  {$EXTERNALSYM DSA_meth_set_flags}
  {$EXTERNALSYM DSA_meth_get0_app_data}
  {$EXTERNALSYM DSA_meth_set0_app_data}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_DSA_get0_pqg(d: PDSA; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl;
  function Load_DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
  procedure Load_DSA_get0_key(d: PDSA; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl;
  function Load_DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_DSA_get0_p(d: PDSA): PBIGNUM; cdecl;
  function Load_DSA_get0_q(d: PDSA): PBIGNUM; cdecl;
  function Load_DSA_get0_g(d: PDSA): PBIGNUM; cdecl;
  function Load_DSA_get0_pub_key(d: PDSA): PBIGNUM; cdecl;
  function Load_DSA_get0_priv_key(d: PDSA): PBIGNUM; cdecl;
  procedure Load_DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
  function Load_DSA_test_flags(d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
  function Load_DSA_get0_engine(d: PDSA): PENGINE; cdecl;
  function Load_DSA_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl;
  procedure Load_DSA_meth_free(dsam: PDSA_METHOD); cdecl;
  function Load_DSA_meth_dup(dsam: PDSA_METHOD): PDSA_METHOD; cdecl;
  function Load_DSA_meth_get0_name(dsam: PDSA_METHOD): PAnsiChar; cdecl;
  function Load_DSA_meth_set1_name(dsam: PDSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_DSA_meth_get_flags(dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_DSA_meth_get0_app_data(dsam: PDSA_METHOD): pointer; cdecl;
  function Load_DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl;

var
  DSA_get0_pqg: procedure(d: PDSA; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl = Load_DSA_get0_pqg;
  DSA_set0_pqg: function(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DSA_set0_pqg;
  DSA_get0_key: procedure(d: PDSA; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl = Load_DSA_get0_key;
  DSA_set0_key: function(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_DSA_set0_key;
  DSA_get0_p: function(d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_p;
  DSA_get0_q: function(d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_q;
  DSA_get0_g: function(d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_g;
  DSA_get0_pub_key: function(d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_pub_key;
  DSA_get0_priv_key: function(d: PDSA): PBIGNUM; cdecl = Load_DSA_get0_priv_key;
  DSA_clear_flags: procedure(d: PDSA; flags: TOpenSSL_C_INT); cdecl = Load_DSA_clear_flags;
  DSA_test_flags: function(d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DSA_test_flags;
  DSA_set_flags: procedure(d: PDSA; flags: TOpenSSL_C_INT); cdecl = Load_DSA_set_flags;
  DSA_get0_engine: function(d: PDSA): PENGINE; cdecl = Load_DSA_get0_engine;
  DSA_meth_new: function(name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl = Load_DSA_meth_new;
  DSA_meth_free: procedure(dsam: PDSA_METHOD); cdecl = Load_DSA_meth_free;
  DSA_meth_dup: function(dsam: PDSA_METHOD): PDSA_METHOD; cdecl = Load_DSA_meth_dup;
  DSA_meth_get0_name: function(dsam: PDSA_METHOD): PAnsiChar; cdecl = Load_DSA_meth_get0_name;
  DSA_meth_set1_name: function(dsam: PDSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set1_name;
  DSA_meth_get_flags: function(dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl = Load_DSA_meth_get_flags;
  DSA_meth_set_flags: function(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_flags;
  DSA_meth_get0_app_data: function(dsam: PDSA_METHOD): pointer; cdecl = Load_DSA_meth_get0_app_data;
  DSA_meth_set0_app_data: function(dsam: PDSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set0_app_data;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = function(_param1: Pbyte; _param2: TOpenSSL_C_INT; _param3: PDSA): PDSA_SIG; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_sign(dsam: PDSA_METHOD): TFuncType001; cdecl; external CLibCrypto name 'DSA_meth_get_sign'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_sign(dsam: PDSA_METHOD): TFuncType001; cdecl;

var
  DSA_meth_get_sign: function(dsam: PDSA_METHOD): TFuncType001; cdecl = Load_DSA_meth_get_sign;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  {end of auto-generated forward references}

  TFuncType002 = function(_param1: Pbyte; _param2: TOpenSSL_C_INT; _param3: PDSA): PDSA_SIG; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_sign(dsam: PDSA_METHOD; sign: TFuncType002): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_sign'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_sign(dsam: PDSA_METHOD; sign: TFuncType002): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_sign: function(dsam: PDSA_METHOD; sign: TFuncType002): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_sign;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType003 = ^TFuncType003;
  PPFuncType003 = ^PFuncType003;
  {end of auto-generated forward references}

  TFuncType003 = function(_param1: PDSA; _param2: PBN_CTX; _param3: PPBIGNUM; _param4: PPBIGNUM): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_sign_setup(dsam: PDSA_METHOD): TFuncType003; cdecl; external CLibCrypto name 'DSA_meth_get_sign_setup'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_sign_setup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_sign_setup(dsam: PDSA_METHOD): TFuncType003; cdecl;

var
  DSA_meth_get_sign_setup: function(dsam: PDSA_METHOD): TFuncType003; cdecl = Load_DSA_meth_get_sign_setup;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType004 = ^TFuncType004;
  PPFuncType004 = ^PFuncType004;
  {end of auto-generated forward references}

  TFuncType004 = function(_param1: PDSA; _param2: PBN_CTX; _param3: PPBIGNUM; _param4: PPBIGNUM): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: TFuncType004): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_sign_setup'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_sign_setup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: TFuncType004): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_sign_setup: function(dsam: PDSA_METHOD; sign_setup: TFuncType004): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_sign_setup;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType005 = ^TFuncType005;
  PPFuncType005 = ^PFuncType005;
  {end of auto-generated forward references}

  TFuncType005 = function(_param1: Pbyte; _param2: TOpenSSL_C_INT; _param3: PDSA_SIG; _param4: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_verify(dsam: PDSA_METHOD): TFuncType005; cdecl; external CLibCrypto name 'DSA_meth_get_verify'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_verify(dsam: PDSA_METHOD): TFuncType005; cdecl;

var
  DSA_meth_get_verify: function(dsam: PDSA_METHOD): TFuncType005; cdecl = Load_DSA_meth_get_verify;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType006 = ^TFuncType006;
  PPFuncType006 = ^PFuncType006;
  {end of auto-generated forward references}

  TFuncType006 = function(_param1: Pbyte; _param2: TOpenSSL_C_INT; _param3: PDSA_SIG; _param4: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_verify(dsam: PDSA_METHOD; verify: TFuncType006): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_verify'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_verify(dsam: PDSA_METHOD; verify: TFuncType006): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_verify: function(dsam: PDSA_METHOD; verify: TFuncType006): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_verify;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType007 = ^TFuncType007;
  PPFuncType007 = ^PFuncType007;
  {end of auto-generated forward references}

  TFuncType007 = function(_param1: PDSA; _param2: PBIGNUM; _param3: PBIGNUM; _param4: PBIGNUM; _param5: PBIGNUM; _param6: PBIGNUM; _param7: PBIGNUM; _param8: PBN_CTX; _param9: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_mod_exp(dsam: PDSA_METHOD): TFuncType007; cdecl; external CLibCrypto name 'DSA_meth_get_mod_exp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_mod_exp(dsam: PDSA_METHOD): TFuncType007; cdecl;

var
  DSA_meth_get_mod_exp: function(dsam: PDSA_METHOD): TFuncType007; cdecl = Load_DSA_meth_get_mod_exp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType008 = ^TFuncType008;
  PPFuncType008 = ^PFuncType008;
  {end of auto-generated forward references}

  TFuncType008 = function(_param1: PDSA; _param2: PBIGNUM; _param3: PBIGNUM; _param4: PBIGNUM; _param5: PBIGNUM; _param6: PBIGNUM; _param7: PBIGNUM; _param8: PBN_CTX; _param9: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: TFuncType008): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_mod_exp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: TFuncType008): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_mod_exp: function(dsam: PDSA_METHOD; mod_exp: TFuncType008): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_mod_exp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType009 = ^TFuncType009;
  PPFuncType009 = ^PFuncType009;
  {end of auto-generated forward references}

  TFuncType009 = function(_param1: PDSA; _param2: PBIGNUM; _param3: PBIGNUM; _param4: PBIGNUM; _param5: PBIGNUM; _param6: PBN_CTX; _param7: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_bn_mod_exp(dsam: PDSA_METHOD): TFuncType009; cdecl; external CLibCrypto name 'DSA_meth_get_bn_mod_exp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_bn_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_bn_mod_exp(dsam: PDSA_METHOD): TFuncType009; cdecl;

var
  DSA_meth_get_bn_mod_exp: function(dsam: PDSA_METHOD): TFuncType009; cdecl = Load_DSA_meth_get_bn_mod_exp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType010 = ^TFuncType010;
  PPFuncType010 = ^PFuncType010;
  {end of auto-generated forward references}

  TFuncType010 = function(_param1: PDSA; _param2: PBIGNUM; _param3: PBIGNUM; _param4: PBIGNUM; _param5: PBIGNUM; _param6: PBN_CTX; _param7: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_bn_mod_exp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_bn_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_bn_mod_exp: function(dsam: PDSA_METHOD; bn_mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_bn_mod_exp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType011 = ^TFuncType011;
  PPFuncType011 = ^PFuncType011;
  {end of auto-generated forward references}

  TFuncType011 = function(_param1: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_init(dsam: PDSA_METHOD): TFuncType011; cdecl; external CLibCrypto name 'DSA_meth_get_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_init(dsam: PDSA_METHOD): TFuncType011; cdecl;

var
  DSA_meth_get_init: function(dsam: PDSA_METHOD): TFuncType011; cdecl = Load_DSA_meth_get_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType012 = ^TFuncType012;
  PPFuncType012 = ^PFuncType012;
  {end of auto-generated forward references}

  TFuncType012 = function(_param1: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_init(dsam: PDSA_METHOD; init: TFuncType012): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_init(dsam: PDSA_METHOD; init: TFuncType012): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_init: function(dsam: PDSA_METHOD; init: TFuncType012): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType013 = ^TFuncType013;
  PPFuncType013 = ^PFuncType013;
  {end of auto-generated forward references}

  TFuncType013 = function(_param1: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_finish(dsam: PDSA_METHOD): TFuncType013; cdecl; external CLibCrypto name 'DSA_meth_get_finish'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_finish}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_finish(dsam: PDSA_METHOD): TFuncType013; cdecl;

var
  DSA_meth_get_finish: function(dsam: PDSA_METHOD): TFuncType013; cdecl = Load_DSA_meth_get_finish;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType014 = ^TFuncType014;
  PPFuncType014 = ^PFuncType014;
  {end of auto-generated forward references}

  TFuncType014 = function(_param1: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_finish(dsam: PDSA_METHOD; finish: TFuncType014): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_finish'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_finish}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_finish(dsam: PDSA_METHOD; finish: TFuncType014): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_finish: function(dsam: PDSA_METHOD; finish: TFuncType014): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_finish;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType015 = ^TFuncType015;
  PPFuncType015 = ^PFuncType015;
  {end of auto-generated forward references}

  TFuncType015 = function(_param1: PDSA; _param2: TOpenSSL_C_INT; _param3: Pbyte; _param4: TOpenSSL_C_INT; _param5: POpenSSL_C_INT; _param6: POpenSSL_C_UINT; _param7: PBN_GENCB): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_paramgen(dsam: PDSA_METHOD): TFuncType015; cdecl; external CLibCrypto name 'DSA_meth_get_paramgen'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_paramgen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_paramgen(dsam: PDSA_METHOD): TFuncType015; cdecl;

var
  DSA_meth_get_paramgen: function(dsam: PDSA_METHOD): TFuncType015; cdecl = Load_DSA_meth_get_paramgen;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType016 = ^TFuncType016;
  PPFuncType016 = ^PFuncType016;
  {end of auto-generated forward references}

  TFuncType016 = function(_param1: PDSA; _param2: TOpenSSL_C_INT; _param3: Pbyte; _param4: TOpenSSL_C_INT; _param5: POpenSSL_C_INT; _param6: POpenSSL_C_UINT; _param7: PBN_GENCB): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: TFuncType016): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_paramgen'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_paramgen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: TFuncType016): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_paramgen: function(dsam: PDSA_METHOD; paramgen: TFuncType016): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_paramgen;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType017 = ^TFuncType017;
  PPFuncType017 = ^PFuncType017;
  {end of auto-generated forward references}

  TFuncType017 = function(_param1: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_get_keygen(dsam: PDSA_METHOD): TFuncType017; cdecl; external CLibCrypto name 'DSA_meth_get_keygen'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_get_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_get_keygen(dsam: PDSA_METHOD): TFuncType017; cdecl;

var
  DSA_meth_get_keygen: function(dsam: PDSA_METHOD): TFuncType017; cdecl = Load_DSA_meth_get_keygen;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType018 = ^TFuncType018;
  PPFuncType018 = ^PFuncType018;
  {end of auto-generated forward references}

  TFuncType018 = function(_param1: PDSA): TOpenSSL_C_INT; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: TFuncType018): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DSA_meth_set_keygen'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DSA_meth_set_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: TFuncType018): TOpenSSL_C_INT; cdecl;

var
  DSA_meth_set_keygen: function(dsam: PDSA_METHOD; keygen: TFuncType018): TOpenSSL_C_INT; cdecl = Load_DSA_meth_set_keygen;
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
function Load_EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx: PEVP_PKEY_CTX; nbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_bits := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dsa_paramgen_bits');
  if not assigned(EVP_PKEY_CTX_set_dsa_paramgen_bits) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_bits)}
    EVP_PKEY_CTX_set_dsa_paramgen_bits := @LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_bits;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dsa_paramgen_bits');
    {$ifend}
  Result := EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
end;

function Load_EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx: PEVP_PKEY_CTX; qbits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_q_bits := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dsa_paramgen_q_bits');
  if not assigned(EVP_PKEY_CTX_set_dsa_paramgen_q_bits) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_q_bits)}
    EVP_PKEY_CTX_set_dsa_paramgen_q_bits := @LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_q_bits;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dsa_paramgen_q_bits');
    {$ifend}
  Result := EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, qbits);
end;

function Load_EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx: PEVP_PKEY_CTX; md_name: PAnsiChar; md_properties: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_md_props := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dsa_paramgen_md_props');
  if not assigned(EVP_PKEY_CTX_set_dsa_paramgen_md_props) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_md_props)}
    EVP_PKEY_CTX_set_dsa_paramgen_md_props := @LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_md_props;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dsa_paramgen_md_props');
    {$ifend}
  Result := EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx, md_name, md_properties);
end;

function Load_EVP_PKEY_CTX_set_dsa_paramgen_gindex(ctx: PEVP_PKEY_CTX; gindex: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_gindex := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dsa_paramgen_gindex');
  if not assigned(EVP_PKEY_CTX_set_dsa_paramgen_gindex) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_gindex)}
    EVP_PKEY_CTX_set_dsa_paramgen_gindex := @LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_gindex;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dsa_paramgen_gindex');
    {$ifend}
  Result := EVP_PKEY_CTX_set_dsa_paramgen_gindex(ctx, gindex);
end;

function Load_EVP_PKEY_CTX_set_dsa_paramgen_type(ctx: PEVP_PKEY_CTX; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_type := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dsa_paramgen_type');
  if not assigned(EVP_PKEY_CTX_set_dsa_paramgen_type) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_type)}
    EVP_PKEY_CTX_set_dsa_paramgen_type := @LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_type;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dsa_paramgen_type');
    {$ifend}
  Result := EVP_PKEY_CTX_set_dsa_paramgen_type(ctx, name);
end;

function Load_EVP_PKEY_CTX_set_dsa_paramgen_seed(ctx: PEVP_PKEY_CTX; seed: Pbyte; seedlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_seed := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dsa_paramgen_seed');
  if not assigned(EVP_PKEY_CTX_set_dsa_paramgen_seed) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_seed)}
    EVP_PKEY_CTX_set_dsa_paramgen_seed := @LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_seed;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dsa_paramgen_seed');
    {$ifend}
  Result := EVP_PKEY_CTX_set_dsa_paramgen_seed(ctx, seed, seedlen);
end;

function Load_EVP_PKEY_CTX_set_dsa_paramgen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_dsa_paramgen_md');
  if not assigned(EVP_PKEY_CTX_set_dsa_paramgen_md) then
    {$if declared(LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_md)}
    EVP_PKEY_CTX_set_dsa_paramgen_md := @LEGACY_EVP_PKEY_CTX_set_dsa_paramgen_md;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_dsa_paramgen_md');
    {$ifend}
  Result := EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md);
end;

{$ifndef  OPENSSL_NO_DSA}
function Load_DSA_SIG_new: PDSA_SIG; cdecl;
begin
  DSA_SIG_new := LoadLibCryptoFunction('DSA_SIG_new');
  if not assigned(DSA_SIG_new) then
    {$if declared(LEGACY_DSA_SIG_new)}
    DSA_SIG_new := @LEGACY_DSA_SIG_new;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_new');
    {$ifend}
  Result := DSA_SIG_new;
end;

procedure Load_DSA_SIG_free(a: PDSA_SIG); cdecl;
begin
  DSA_SIG_free := LoadLibCryptoFunction('DSA_SIG_free');
  if not assigned(DSA_SIG_free) then
    {$if declared(LEGACY_DSA_SIG_free)}
    DSA_SIG_free := @LEGACY_DSA_SIG_free;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_free');
    {$ifend}
  DSA_SIG_free(a);
end;

function Load_d2i_DSA_SIG(a: PPDSA_SIG; in_: PPbyte; len: TOpenSSL_C_INT): PDSA_SIG; cdecl;
begin
  d2i_DSA_SIG := LoadLibCryptoFunction('d2i_DSA_SIG');
  if not assigned(d2i_DSA_SIG) then
    {$if declared(LEGACY_d2i_DSA_SIG)}
    d2i_DSA_SIG := @LEGACY_d2i_DSA_SIG;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSA_SIG');
    {$ifend}
  Result := d2i_DSA_SIG(a, in_, len);
end;

function Load_i2d_DSA_SIG(a: PDSA_SIG; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSA_SIG := LoadLibCryptoFunction('i2d_DSA_SIG');
  if not assigned(i2d_DSA_SIG) then
    {$if declared(LEGACY_i2d_DSA_SIG)}
    i2d_DSA_SIG := @LEGACY_i2d_DSA_SIG;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSA_SIG');
    {$ifend}
  Result := i2d_DSA_SIG(a, out_);
end;

procedure Load_DSA_SIG_get0(sig: PDSA_SIG; pr: PPBIGNUM; ps: PPBIGNUM); cdecl;
begin
  DSA_SIG_get0 := LoadLibCryptoFunction('DSA_SIG_get0');
  if not assigned(DSA_SIG_get0) then
    {$if declared(LEGACY_DSA_SIG_get0)}
    DSA_SIG_get0 := @LEGACY_DSA_SIG_get0;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_get0');
    {$ifend}
  DSA_SIG_get0(sig, pr, ps);
end;

function Load_DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DSA_SIG_set0 := LoadLibCryptoFunction('DSA_SIG_set0');
  if not assigned(DSA_SIG_set0) then
    {$if declared(LEGACY_DSA_SIG_set0)}
    DSA_SIG_set0 := @LEGACY_DSA_SIG_set0;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_set0');
    {$ifend}
  Result := DSA_SIG_set0(sig, r, s);
end;

    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_DSAparams_dup(a: PDSA): PDSA; cdecl;
begin
  DSAparams_dup := LoadLibCryptoFunction('DSAparams_dup');
  if not assigned(DSAparams_dup) then
    {$if declared(LEGACY_DSAparams_dup)}
    DSAparams_dup := @LEGACY_DSAparams_dup;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSAparams_dup');
    {$ifend}
  Result := DSAparams_dup(a);
end;

function Load_DSA_do_sign(dgst: Pbyte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl;
begin
  DSA_do_sign := LoadLibCryptoFunction('DSA_do_sign');
  if not assigned(DSA_do_sign) then
    {$if declared(LEGACY_DSA_do_sign)}
    DSA_do_sign := @LEGACY_DSA_do_sign;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_do_sign');
    {$ifend}
  Result := DSA_do_sign(dgst, dlen, dsa);
end;

function Load_DSA_do_verify(dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_do_verify := LoadLibCryptoFunction('DSA_do_verify');
  if not assigned(DSA_do_verify) then
    {$if declared(LEGACY_DSA_do_verify)}
    DSA_do_verify := @LEGACY_DSA_do_verify;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_do_verify');
    {$ifend}
  Result := DSA_do_verify(dgst, dgst_len, sig, dsa);
end;

function Load_DSA_OpenSSL: PDSA_METHOD; cdecl;
begin
  DSA_OpenSSL := LoadLibCryptoFunction('DSA_OpenSSL');
  if not assigned(DSA_OpenSSL) then
    {$if declared(LEGACY_DSA_OpenSSL)}
    DSA_OpenSSL := @LEGACY_DSA_OpenSSL;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_OpenSSL');
    {$ifend}
  Result := DSA_OpenSSL;
end;

procedure Load_DSA_set_default_method(_param1: PDSA_METHOD); cdecl;
begin
  DSA_set_default_method := LoadLibCryptoFunction('DSA_set_default_method');
  if not assigned(DSA_set_default_method) then
    {$if declared(LEGACY_DSA_set_default_method)}
    DSA_set_default_method := @LEGACY_DSA_set_default_method;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_default_method');
    {$ifend}
  DSA_set_default_method(_param1);
end;

function Load_DSA_get_default_method: PDSA_METHOD; cdecl;
begin
  DSA_get_default_method := LoadLibCryptoFunction('DSA_get_default_method');
  if not assigned(DSA_get_default_method) then
    {$if declared(LEGACY_DSA_get_default_method)}
    DSA_get_default_method := @LEGACY_DSA_get_default_method;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_default_method');
    {$ifend}
  Result := DSA_get_default_method;
end;

function Load_DSA_set_method(dsa: PDSA; _param2: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  DSA_set_method := LoadLibCryptoFunction('DSA_set_method');
  if not assigned(DSA_set_method) then
    {$if declared(LEGACY_DSA_set_method)}
    DSA_set_method := @LEGACY_DSA_set_method;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_method');
    {$ifend}
  Result := DSA_set_method(dsa, _param2);
end;

function Load_DSA_get_method(d: PDSA): PDSA_METHOD; cdecl;
begin
  DSA_get_method := LoadLibCryptoFunction('DSA_get_method');
  if not assigned(DSA_get_method) then
    {$if declared(LEGACY_DSA_get_method)}
    DSA_get_method := @LEGACY_DSA_get_method;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_method');
    {$ifend}
  Result := DSA_get_method(d);
end;

function Load_DSA_new: PDSA; cdecl;
begin
  DSA_new := LoadLibCryptoFunction('DSA_new');
  if not assigned(DSA_new) then
    {$if declared(LEGACY_DSA_new)}
    DSA_new := @LEGACY_DSA_new;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_new');
    {$ifend}
  Result := DSA_new;
end;

function Load_DSA_new_method(engine: PENGINE): PDSA; cdecl;
begin
  DSA_new_method := LoadLibCryptoFunction('DSA_new_method');
  if not assigned(DSA_new_method) then
    {$if declared(LEGACY_DSA_new_method)}
    DSA_new_method := @LEGACY_DSA_new_method;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_new_method');
    {$ifend}
  Result := DSA_new_method(engine);
end;

procedure Load_DSA_free(r: PDSA); cdecl;
begin
  DSA_free := LoadLibCryptoFunction('DSA_free');
  if not assigned(DSA_free) then
    {$if declared(LEGACY_DSA_free)}
    DSA_free := @LEGACY_DSA_free;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_free');
    {$ifend}
  DSA_free(r);
end;

function Load_DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_up_ref := LoadLibCryptoFunction('DSA_up_ref');
  if not assigned(DSA_up_ref) then
    {$if declared(LEGACY_DSA_up_ref)}
    DSA_up_ref := @LEGACY_DSA_up_ref;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_up_ref');
    {$ifend}
  Result := DSA_up_ref(r);
end;

function Load_DSA_size(_param1: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_size := LoadLibCryptoFunction('DSA_size');
  if not assigned(DSA_size) then
    {$if declared(LEGACY_DSA_size)}
    DSA_size := @LEGACY_DSA_size;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_size');
    {$ifend}
  Result := DSA_size(_param1);
end;

function Load_DSA_bits(d: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_bits := LoadLibCryptoFunction('DSA_bits');
  if not assigned(DSA_bits) then
    {$if declared(LEGACY_DSA_bits)}
    DSA_bits := @LEGACY_DSA_bits;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_bits');
    {$ifend}
  Result := DSA_bits(d);
end;

function Load_DSA_security_bits(d: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_security_bits := LoadLibCryptoFunction('DSA_security_bits');
  if not assigned(DSA_security_bits) then
    {$if declared(LEGACY_DSA_security_bits)}
    DSA_security_bits := @LEGACY_DSA_security_bits;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_security_bits');
    {$ifend}
  Result := DSA_security_bits(d);
end;

function Load_DSA_sign_setup(dsa: PDSA; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DSA_sign_setup := LoadLibCryptoFunction('DSA_sign_setup');
  if not assigned(DSA_sign_setup) then
    {$if declared(LEGACY_DSA_sign_setup)}
    DSA_sign_setup := @LEGACY_DSA_sign_setup;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_sign_setup');
    {$ifend}
  Result := DSA_sign_setup(dsa, ctx_in, kinvp, rp);
end;

function Load_DSA_sign(type_: TOpenSSL_C_INT; dgst: Pbyte; dlen: TOpenSSL_C_INT; sig: Pbyte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_sign := LoadLibCryptoFunction('DSA_sign');
  if not assigned(DSA_sign) then
    {$if declared(LEGACY_DSA_sign)}
    DSA_sign := @LEGACY_DSA_sign;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_sign');
    {$ifend}
  Result := DSA_sign(type_, dgst, dlen, sig, siglen, dsa);
end;

function Load_DSA_verify(type_: TOpenSSL_C_INT; dgst: Pbyte; dgst_len: TOpenSSL_C_INT; sigbuf: Pbyte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_verify := LoadLibCryptoFunction('DSA_verify');
  if not assigned(DSA_verify) then
    {$if declared(LEGACY_DSA_verify)}
    DSA_verify := @LEGACY_DSA_verify;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_verify');
    {$ifend}
  Result := DSA_verify(type_, dgst, dgst_len, sigbuf, siglen, dsa);
end;

function Load_DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  DSA_set_ex_data := LoadLibCryptoFunction('DSA_set_ex_data');
  if not assigned(DSA_set_ex_data) then
    {$if declared(LEGACY_DSA_set_ex_data)}
    DSA_set_ex_data := @LEGACY_DSA_set_ex_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_ex_data');
    {$ifend}
  Result := DSA_set_ex_data(d, idx, arg);
end;

function Load_DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): pointer; cdecl;
begin
  DSA_get_ex_data := LoadLibCryptoFunction('DSA_get_ex_data');
  if not assigned(DSA_get_ex_data) then
    {$if declared(LEGACY_DSA_get_ex_data)}
    DSA_get_ex_data := @LEGACY_DSA_get_ex_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_ex_data');
    {$ifend}
  Result := DSA_get_ex_data(d, idx);
end;

function Load_d2i_DSAPublicKey(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl;
begin
  d2i_DSAPublicKey := LoadLibCryptoFunction('d2i_DSAPublicKey');
  if not assigned(d2i_DSAPublicKey) then
    {$if declared(LEGACY_d2i_DSAPublicKey)}
    d2i_DSAPublicKey := @LEGACY_d2i_DSAPublicKey;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPublicKey');
    {$ifend}
  Result := d2i_DSAPublicKey(a, in_, len);
end;

function Load_i2d_DSAPublicKey(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSAPublicKey := LoadLibCryptoFunction('i2d_DSAPublicKey');
  if not assigned(i2d_DSAPublicKey) then
    {$if declared(LEGACY_i2d_DSAPublicKey)}
    i2d_DSAPublicKey := @LEGACY_i2d_DSAPublicKey;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPublicKey');
    {$ifend}
  Result := i2d_DSAPublicKey(a, out_);
end;

function Load_d2i_DSAPrivateKey(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl;
begin
  d2i_DSAPrivateKey := LoadLibCryptoFunction('d2i_DSAPrivateKey');
  if not assigned(d2i_DSAPrivateKey) then
    {$if declared(LEGACY_d2i_DSAPrivateKey)}
    d2i_DSAPrivateKey := @LEGACY_d2i_DSAPrivateKey;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPrivateKey');
    {$ifend}
  Result := d2i_DSAPrivateKey(a, in_, len);
end;

function Load_i2d_DSAPrivateKey(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSAPrivateKey := LoadLibCryptoFunction('i2d_DSAPrivateKey');
  if not assigned(i2d_DSAPrivateKey) then
    {$if declared(LEGACY_i2d_DSAPrivateKey)}
    i2d_DSAPrivateKey := @LEGACY_i2d_DSAPrivateKey;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPrivateKey');
    {$ifend}
  Result := i2d_DSAPrivateKey(a, out_);
end;

function Load_d2i_DSAparams(a: PPDSA; in_: PPbyte; len: TOpenSSL_C_INT): PDSA; cdecl;
begin
  d2i_DSAparams := LoadLibCryptoFunction('d2i_DSAparams');
  if not assigned(d2i_DSAparams) then
    {$if declared(LEGACY_d2i_DSAparams)}
    d2i_DSAparams := @LEGACY_d2i_DSAparams;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAparams');
    {$ifend}
  Result := d2i_DSAparams(a, in_, len);
end;

function Load_i2d_DSAparams(a: PDSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_DSAparams := LoadLibCryptoFunction('i2d_DSAparams');
  if not assigned(i2d_DSAparams) then
    {$if declared(LEGACY_i2d_DSAparams)}
    i2d_DSAparams := @LEGACY_i2d_DSAparams;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAparams');
    {$ifend}
  Result := i2d_DSAparams(a, out_);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}
function Load_DSA_generate_parameters(bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PDSA; cdecl;
begin
  DSA_generate_parameters := LoadLibCryptoFunction('DSA_generate_parameters');
  if not assigned(DSA_generate_parameters) then
    {$if declared(LEGACY_DSA_generate_parameters)}
    DSA_generate_parameters := @LEGACY_DSA_generate_parameters;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_generate_parameters');
    {$ifend}
  Result := DSA_generate_parameters(bits, seed, seed_len, counter_ret, h_ret, callback, cb_arg);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_0_9_8}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; seed: Pbyte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_UINT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  DSA_generate_parameters_ex := LoadLibCryptoFunction('DSA_generate_parameters_ex');
  if not assigned(DSA_generate_parameters_ex) then
    {$if declared(LEGACY_DSA_generate_parameters_ex)}
    DSA_generate_parameters_ex := @LEGACY_DSA_generate_parameters_ex;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_generate_parameters_ex');
    {$ifend}
  Result := DSA_generate_parameters_ex(dsa, bits, seed, seed_len, counter_ret, h_ret, cb);
end;

function Load_DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSA_generate_key := LoadLibCryptoFunction('DSA_generate_key');
  if not assigned(DSA_generate_key) then
    {$if declared(LEGACY_DSA_generate_key)}
    DSA_generate_key := @LEGACY_DSA_generate_key;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_generate_key');
    {$ifend}
  Result := DSA_generate_key(a);
end;

function Load_DSAparams_print(bp: PBIO; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSAparams_print := LoadLibCryptoFunction('DSAparams_print');
  if not assigned(DSAparams_print) then
    {$if declared(LEGACY_DSAparams_print)}
    DSAparams_print := @LEGACY_DSAparams_print;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSAparams_print');
    {$ifend}
  Result := DSAparams_print(bp, x);
end;

function Load_DSA_print(bp: PBIO; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DSA_print := LoadLibCryptoFunction('DSA_print');
  if not assigned(DSA_print) then
    {$if declared(LEGACY_DSA_print)}
    DSA_print := @LEGACY_DSA_print;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_print');
    {$ifend}
  Result := DSA_print(bp, x, off);
end;

        {$ifndef  OPENSSL_NO_STDIO}
function Load_DSAparams_print_fp(fp: PFILE; x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  DSAparams_print_fp := LoadLibCryptoFunction('DSAparams_print_fp');
  if not assigned(DSAparams_print_fp) then
    {$if declared(LEGACY_DSAparams_print_fp)}
    DSAparams_print_fp := @LEGACY_DSAparams_print_fp;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSAparams_print_fp');
    {$ifend}
  Result := DSAparams_print_fp(fp, x);
end;

function Load_DSA_print_fp(bp: PFILE; x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DSA_print_fp := LoadLibCryptoFunction('DSA_print_fp');
  if not assigned(DSA_print_fp) then
    {$if declared(LEGACY_DSA_print_fp)}
    DSA_print_fp := @LEGACY_DSA_print_fp;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_print_fp');
    {$ifend}
  Result := DSA_print_fp(bp, x, off);
end;

        {$endif} { OPENSSL_NO_STDIO}
        {$ifndef  OPENSSL_NO_DH}
function Load_DSA_dup_DH(r: PDSA): PDH; cdecl;
begin
  DSA_dup_DH := LoadLibCryptoFunction('DSA_dup_DH');
  if not assigned(DSA_dup_DH) then
    {$if declared(LEGACY_DSA_dup_DH)}
    DSA_dup_DH := @LEGACY_DSA_dup_DH;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_dup_DH');
    {$ifend}
  Result := DSA_dup_DH(r);
end;

        {$endif} { OPENSSL_NO_DH}
procedure Load_DSA_get0_pqg(d: PDSA; p: PPBIGNUM; q: PPBIGNUM; g: PPBIGNUM); cdecl;
begin
  DSA_get0_pqg := LoadLibCryptoFunction('DSA_get0_pqg');
  if not assigned(DSA_get0_pqg) then
    {$if declared(LEGACY_DSA_get0_pqg)}
    DSA_get0_pqg := @LEGACY_DSA_get0_pqg;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_pqg');
    {$ifend}
  DSA_get0_pqg(d, p, q, g);
end;

function Load_DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DSA_set0_pqg := LoadLibCryptoFunction('DSA_set0_pqg');
  if not assigned(DSA_set0_pqg) then
    {$if declared(LEGACY_DSA_set0_pqg)}
    DSA_set0_pqg := @LEGACY_DSA_set0_pqg;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set0_pqg');
    {$ifend}
  Result := DSA_set0_pqg(d, p, q, g);
end;

procedure Load_DSA_get0_key(d: PDSA; pub_key: PPBIGNUM; priv_key: PPBIGNUM); cdecl;
begin
  DSA_get0_key := LoadLibCryptoFunction('DSA_get0_key');
  if not assigned(DSA_get0_key) then
    {$if declared(LEGACY_DSA_get0_key)}
    DSA_get0_key := @LEGACY_DSA_get0_key;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_key');
    {$ifend}
  DSA_get0_key(d, pub_key, priv_key);
end;

function Load_DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  DSA_set0_key := LoadLibCryptoFunction('DSA_set0_key');
  if not assigned(DSA_set0_key) then
    {$if declared(LEGACY_DSA_set0_key)}
    DSA_set0_key := @LEGACY_DSA_set0_key;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set0_key');
    {$ifend}
  Result := DSA_set0_key(d, pub_key, priv_key);
end;

function Load_DSA_get0_p(d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_p := LoadLibCryptoFunction('DSA_get0_p');
  if not assigned(DSA_get0_p) then
    {$if declared(LEGACY_DSA_get0_p)}
    DSA_get0_p := @LEGACY_DSA_get0_p;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_p');
    {$ifend}
  Result := DSA_get0_p(d);
end;

function Load_DSA_get0_q(d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_q := LoadLibCryptoFunction('DSA_get0_q');
  if not assigned(DSA_get0_q) then
    {$if declared(LEGACY_DSA_get0_q)}
    DSA_get0_q := @LEGACY_DSA_get0_q;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_q');
    {$ifend}
  Result := DSA_get0_q(d);
end;

function Load_DSA_get0_g(d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_g := LoadLibCryptoFunction('DSA_get0_g');
  if not assigned(DSA_get0_g) then
    {$if declared(LEGACY_DSA_get0_g)}
    DSA_get0_g := @LEGACY_DSA_get0_g;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_g');
    {$ifend}
  Result := DSA_get0_g(d);
end;

function Load_DSA_get0_pub_key(d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_pub_key := LoadLibCryptoFunction('DSA_get0_pub_key');
  if not assigned(DSA_get0_pub_key) then
    {$if declared(LEGACY_DSA_get0_pub_key)}
    DSA_get0_pub_key := @LEGACY_DSA_get0_pub_key;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_pub_key');
    {$ifend}
  Result := DSA_get0_pub_key(d);
end;

function Load_DSA_get0_priv_key(d: PDSA): PBIGNUM; cdecl;
begin
  DSA_get0_priv_key := LoadLibCryptoFunction('DSA_get0_priv_key');
  if not assigned(DSA_get0_priv_key) then
    {$if declared(LEGACY_DSA_get0_priv_key)}
    DSA_get0_priv_key := @LEGACY_DSA_get0_priv_key;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_priv_key');
    {$ifend}
  Result := DSA_get0_priv_key(d);
end;

procedure Load_DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
begin
  DSA_clear_flags := LoadLibCryptoFunction('DSA_clear_flags');
  if not assigned(DSA_clear_flags) then
    {$if declared(LEGACY_DSA_clear_flags)}
    DSA_clear_flags := @LEGACY_DSA_clear_flags;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_clear_flags');
    {$ifend}
  DSA_clear_flags(d, flags);
end;

function Load_DSA_test_flags(d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DSA_test_flags := LoadLibCryptoFunction('DSA_test_flags');
  if not assigned(DSA_test_flags) then
    {$if declared(LEGACY_DSA_test_flags)}
    DSA_test_flags := @LEGACY_DSA_test_flags;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_test_flags');
    {$ifend}
  Result := DSA_test_flags(d, flags);
end;

procedure Load_DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
begin
  DSA_set_flags := LoadLibCryptoFunction('DSA_set_flags');
  if not assigned(DSA_set_flags) then
    {$if declared(LEGACY_DSA_set_flags)}
    DSA_set_flags := @LEGACY_DSA_set_flags;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_flags');
    {$ifend}
  DSA_set_flags(d, flags);
end;

function Load_DSA_get0_engine(d: PDSA): PENGINE; cdecl;
begin
  DSA_get0_engine := LoadLibCryptoFunction('DSA_get0_engine');
  if not assigned(DSA_get0_engine) then
    {$if declared(LEGACY_DSA_get0_engine)}
    DSA_get0_engine := @LEGACY_DSA_get0_engine;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_engine');
    {$ifend}
  Result := DSA_get0_engine(d);
end;

function Load_DSA_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl;
begin
  DSA_meth_new := LoadLibCryptoFunction('DSA_meth_new');
  if not assigned(DSA_meth_new) then
    {$if declared(LEGACY_DSA_meth_new)}
    DSA_meth_new := @LEGACY_DSA_meth_new;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_new');
    {$ifend}
  Result := DSA_meth_new(name, flags);
end;

procedure Load_DSA_meth_free(dsam: PDSA_METHOD); cdecl;
begin
  DSA_meth_free := LoadLibCryptoFunction('DSA_meth_free');
  if not assigned(DSA_meth_free) then
    {$if declared(LEGACY_DSA_meth_free)}
    DSA_meth_free := @LEGACY_DSA_meth_free;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_free');
    {$ifend}
  DSA_meth_free(dsam);
end;

function Load_DSA_meth_dup(dsam: PDSA_METHOD): PDSA_METHOD; cdecl;
begin
  DSA_meth_dup := LoadLibCryptoFunction('DSA_meth_dup');
  if not assigned(DSA_meth_dup) then
    {$if declared(LEGACY_DSA_meth_dup)}
    DSA_meth_dup := @LEGACY_DSA_meth_dup;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_dup');
    {$ifend}
  Result := DSA_meth_dup(dsam);
end;

function Load_DSA_meth_get0_name(dsam: PDSA_METHOD): PAnsiChar; cdecl;
begin
  DSA_meth_get0_name := LoadLibCryptoFunction('DSA_meth_get0_name');
  if not assigned(DSA_meth_get0_name) then
    {$if declared(LEGACY_DSA_meth_get0_name)}
    DSA_meth_get0_name := @LEGACY_DSA_meth_get0_name;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get0_name');
    {$ifend}
  Result := DSA_meth_get0_name(dsam);
end;

function Load_DSA_meth_set1_name(dsam: PDSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set1_name := LoadLibCryptoFunction('DSA_meth_set1_name');
  if not assigned(DSA_meth_set1_name) then
    {$if declared(LEGACY_DSA_meth_set1_name)}
    DSA_meth_set1_name := @LEGACY_DSA_meth_set1_name;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set1_name');
    {$ifend}
  Result := DSA_meth_set1_name(dsam, name);
end;

function Load_DSA_meth_get_flags(dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_get_flags := LoadLibCryptoFunction('DSA_meth_get_flags');
  if not assigned(DSA_meth_get_flags) then
    {$if declared(LEGACY_DSA_meth_get_flags)}
    DSA_meth_get_flags := @LEGACY_DSA_meth_get_flags;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_flags');
    {$ifend}
  Result := DSA_meth_get_flags(dsam);
end;

function Load_DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_flags := LoadLibCryptoFunction('DSA_meth_set_flags');
  if not assigned(DSA_meth_set_flags) then
    {$if declared(LEGACY_DSA_meth_set_flags)}
    DSA_meth_set_flags := @LEGACY_DSA_meth_set_flags;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_flags');
    {$ifend}
  Result := DSA_meth_set_flags(dsam, flags);
end;

function Load_DSA_meth_get0_app_data(dsam: PDSA_METHOD): pointer; cdecl;
begin
  DSA_meth_get0_app_data := LoadLibCryptoFunction('DSA_meth_get0_app_data');
  if not assigned(DSA_meth_get0_app_data) then
    {$if declared(LEGACY_DSA_meth_get0_app_data)}
    DSA_meth_get0_app_data := @LEGACY_DSA_meth_get0_app_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get0_app_data');
    {$ifend}
  Result := DSA_meth_get0_app_data(dsam);
end;

function Load_DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set0_app_data := LoadLibCryptoFunction('DSA_meth_set0_app_data');
  if not assigned(DSA_meth_set0_app_data) then
    {$if declared(LEGACY_DSA_meth_set0_app_data)}
    DSA_meth_set0_app_data := @LEGACY_DSA_meth_set0_app_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set0_app_data');
    {$ifend}
  Result := DSA_meth_set0_app_data(dsam, app_data);
end;

function Load_DSA_meth_get_sign(dsam: PDSA_METHOD): TFuncType001; cdecl;
begin
  DSA_meth_get_sign := LoadLibCryptoFunction('DSA_meth_get_sign');
  if not assigned(DSA_meth_get_sign) then
    {$if declared(LEGACY_DSA_meth_get_sign)}
    DSA_meth_get_sign := @LEGACY_DSA_meth_get_sign;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_sign');
    {$ifend}
  Result := DSA_meth_get_sign(dsam);
end;

function Load_DSA_meth_set_sign(dsam: PDSA_METHOD; sign: TFuncType002): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_sign := LoadLibCryptoFunction('DSA_meth_set_sign');
  if not assigned(DSA_meth_set_sign) then
    {$if declared(LEGACY_DSA_meth_set_sign)}
    DSA_meth_set_sign := @LEGACY_DSA_meth_set_sign;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_sign');
    {$ifend}
  Result := DSA_meth_set_sign(dsam, sign);
end;

function Load_DSA_meth_get_sign_setup(dsam: PDSA_METHOD): TFuncType003; cdecl;
begin
  DSA_meth_get_sign_setup := LoadLibCryptoFunction('DSA_meth_get_sign_setup');
  if not assigned(DSA_meth_get_sign_setup) then
    {$if declared(LEGACY_DSA_meth_get_sign_setup)}
    DSA_meth_get_sign_setup := @LEGACY_DSA_meth_get_sign_setup;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_sign_setup');
    {$ifend}
  Result := DSA_meth_get_sign_setup(dsam);
end;

function Load_DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: TFuncType004): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_sign_setup := LoadLibCryptoFunction('DSA_meth_set_sign_setup');
  if not assigned(DSA_meth_set_sign_setup) then
    {$if declared(LEGACY_DSA_meth_set_sign_setup)}
    DSA_meth_set_sign_setup := @LEGACY_DSA_meth_set_sign_setup;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_sign_setup');
    {$ifend}
  Result := DSA_meth_set_sign_setup(dsam, sign_setup);
end;

function Load_DSA_meth_get_verify(dsam: PDSA_METHOD): TFuncType005; cdecl;
begin
  DSA_meth_get_verify := LoadLibCryptoFunction('DSA_meth_get_verify');
  if not assigned(DSA_meth_get_verify) then
    {$if declared(LEGACY_DSA_meth_get_verify)}
    DSA_meth_get_verify := @LEGACY_DSA_meth_get_verify;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_verify');
    {$ifend}
  Result := DSA_meth_get_verify(dsam);
end;

function Load_DSA_meth_set_verify(dsam: PDSA_METHOD; verify: TFuncType006): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_verify := LoadLibCryptoFunction('DSA_meth_set_verify');
  if not assigned(DSA_meth_set_verify) then
    {$if declared(LEGACY_DSA_meth_set_verify)}
    DSA_meth_set_verify := @LEGACY_DSA_meth_set_verify;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_verify');
    {$ifend}
  Result := DSA_meth_set_verify(dsam, verify);
end;

function Load_DSA_meth_get_mod_exp(dsam: PDSA_METHOD): TFuncType007; cdecl;
begin
  DSA_meth_get_mod_exp := LoadLibCryptoFunction('DSA_meth_get_mod_exp');
  if not assigned(DSA_meth_get_mod_exp) then
    {$if declared(LEGACY_DSA_meth_get_mod_exp)}
    DSA_meth_get_mod_exp := @LEGACY_DSA_meth_get_mod_exp;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_mod_exp');
    {$ifend}
  Result := DSA_meth_get_mod_exp(dsam);
end;

function Load_DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: TFuncType008): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_mod_exp := LoadLibCryptoFunction('DSA_meth_set_mod_exp');
  if not assigned(DSA_meth_set_mod_exp) then
    {$if declared(LEGACY_DSA_meth_set_mod_exp)}
    DSA_meth_set_mod_exp := @LEGACY_DSA_meth_set_mod_exp;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_mod_exp');
    {$ifend}
  Result := DSA_meth_set_mod_exp(dsam, mod_exp);
end;

function Load_DSA_meth_get_bn_mod_exp(dsam: PDSA_METHOD): TFuncType009; cdecl;
begin
  DSA_meth_get_bn_mod_exp := LoadLibCryptoFunction('DSA_meth_get_bn_mod_exp');
  if not assigned(DSA_meth_get_bn_mod_exp) then
    {$if declared(LEGACY_DSA_meth_get_bn_mod_exp)}
    DSA_meth_get_bn_mod_exp := @LEGACY_DSA_meth_get_bn_mod_exp;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_bn_mod_exp');
    {$ifend}
  Result := DSA_meth_get_bn_mod_exp(dsam);
end;

function Load_DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_bn_mod_exp := LoadLibCryptoFunction('DSA_meth_set_bn_mod_exp');
  if not assigned(DSA_meth_set_bn_mod_exp) then
    {$if declared(LEGACY_DSA_meth_set_bn_mod_exp)}
    DSA_meth_set_bn_mod_exp := @LEGACY_DSA_meth_set_bn_mod_exp;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_bn_mod_exp');
    {$ifend}
  Result := DSA_meth_set_bn_mod_exp(dsam, bn_mod_exp);
end;

function Load_DSA_meth_get_init(dsam: PDSA_METHOD): TFuncType011; cdecl;
begin
  DSA_meth_get_init := LoadLibCryptoFunction('DSA_meth_get_init');
  if not assigned(DSA_meth_get_init) then
    {$if declared(LEGACY_DSA_meth_get_init)}
    DSA_meth_get_init := @LEGACY_DSA_meth_get_init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_init');
    {$ifend}
  Result := DSA_meth_get_init(dsam);
end;

function Load_DSA_meth_set_init(dsam: PDSA_METHOD; init: TFuncType012): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_init := LoadLibCryptoFunction('DSA_meth_set_init');
  if not assigned(DSA_meth_set_init) then
    {$if declared(LEGACY_DSA_meth_set_init)}
    DSA_meth_set_init := @LEGACY_DSA_meth_set_init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_init');
    {$ifend}
  Result := DSA_meth_set_init(dsam, init);
end;

function Load_DSA_meth_get_finish(dsam: PDSA_METHOD): TFuncType013; cdecl;
begin
  DSA_meth_get_finish := LoadLibCryptoFunction('DSA_meth_get_finish');
  if not assigned(DSA_meth_get_finish) then
    {$if declared(LEGACY_DSA_meth_get_finish)}
    DSA_meth_get_finish := @LEGACY_DSA_meth_get_finish;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_finish');
    {$ifend}
  Result := DSA_meth_get_finish(dsam);
end;

function Load_DSA_meth_set_finish(dsam: PDSA_METHOD; finish: TFuncType014): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_finish := LoadLibCryptoFunction('DSA_meth_set_finish');
  if not assigned(DSA_meth_set_finish) then
    {$if declared(LEGACY_DSA_meth_set_finish)}
    DSA_meth_set_finish := @LEGACY_DSA_meth_set_finish;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_finish');
    {$ifend}
  Result := DSA_meth_set_finish(dsam, finish);
end;

function Load_DSA_meth_get_paramgen(dsam: PDSA_METHOD): TFuncType015; cdecl;
begin
  DSA_meth_get_paramgen := LoadLibCryptoFunction('DSA_meth_get_paramgen');
  if not assigned(DSA_meth_get_paramgen) then
    {$if declared(LEGACY_DSA_meth_get_paramgen)}
    DSA_meth_get_paramgen := @LEGACY_DSA_meth_get_paramgen;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_paramgen');
    {$ifend}
  Result := DSA_meth_get_paramgen(dsam);
end;

function Load_DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: TFuncType016): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_paramgen := LoadLibCryptoFunction('DSA_meth_set_paramgen');
  if not assigned(DSA_meth_set_paramgen) then
    {$if declared(LEGACY_DSA_meth_set_paramgen)}
    DSA_meth_set_paramgen := @LEGACY_DSA_meth_set_paramgen;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_paramgen');
    {$ifend}
  Result := DSA_meth_set_paramgen(dsam, paramgen);
end;

function Load_DSA_meth_get_keygen(dsam: PDSA_METHOD): TFuncType017; cdecl;
begin
  DSA_meth_get_keygen := LoadLibCryptoFunction('DSA_meth_get_keygen');
  if not assigned(DSA_meth_get_keygen) then
    {$if declared(LEGACY_DSA_meth_get_keygen)}
    DSA_meth_get_keygen := @LEGACY_DSA_meth_get_keygen;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_keygen');
    {$ifend}
  Result := DSA_meth_get_keygen(dsam);
end;

function Load_DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: TFuncType018): TOpenSSL_C_INT; cdecl;
begin
  DSA_meth_set_keygen := LoadLibCryptoFunction('DSA_meth_set_keygen');
  if not assigned(DSA_meth_set_keygen) then
    {$if declared(LEGACY_DSA_meth_set_keygen)}
    DSA_meth_set_keygen := @LEGACY_DSA_meth_set_keygen;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_keygen');
    {$ifend}
  Result := DSA_meth_set_keygen(dsam, keygen);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DSA}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  EVP_PKEY_CTX_set_dsa_paramgen_bits := Load_EVP_PKEY_CTX_set_dsa_paramgen_bits;
  EVP_PKEY_CTX_set_dsa_paramgen_q_bits := Load_EVP_PKEY_CTX_set_dsa_paramgen_q_bits;
  EVP_PKEY_CTX_set_dsa_paramgen_md_props := Load_EVP_PKEY_CTX_set_dsa_paramgen_md_props;
  EVP_PKEY_CTX_set_dsa_paramgen_gindex := Load_EVP_PKEY_CTX_set_dsa_paramgen_gindex;
  EVP_PKEY_CTX_set_dsa_paramgen_type := Load_EVP_PKEY_CTX_set_dsa_paramgen_type;
  EVP_PKEY_CTX_set_dsa_paramgen_seed := Load_EVP_PKEY_CTX_set_dsa_paramgen_seed;
  EVP_PKEY_CTX_set_dsa_paramgen_md := Load_EVP_PKEY_CTX_set_dsa_paramgen_md;
{$ifndef  OPENSSL_NO_DSA}
  DSA_SIG_new := Load_DSA_SIG_new;
  DSA_SIG_free := Load_DSA_SIG_free;
  d2i_DSA_SIG := Load_d2i_DSA_SIG;
  i2d_DSA_SIG := Load_i2d_DSA_SIG;
  DSA_SIG_get0 := Load_DSA_SIG_get0;
  DSA_SIG_set0 := Load_DSA_SIG_set0;
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DSAparams_dup := Load_DSAparams_dup;
  DSA_do_sign := Load_DSA_do_sign;
  DSA_do_verify := Load_DSA_do_verify;
  DSA_OpenSSL := Load_DSA_OpenSSL;
  DSA_set_default_method := Load_DSA_set_default_method;
  DSA_get_default_method := Load_DSA_get_default_method;
  DSA_set_method := Load_DSA_set_method;
  DSA_get_method := Load_DSA_get_method;
  DSA_new := Load_DSA_new;
  DSA_new_method := Load_DSA_new_method;
  DSA_free := Load_DSA_free;
  DSA_up_ref := Load_DSA_up_ref;
  DSA_size := Load_DSA_size;
  DSA_bits := Load_DSA_bits;
  DSA_security_bits := Load_DSA_security_bits;
  DSA_sign_setup := Load_DSA_sign_setup;
  DSA_sign := Load_DSA_sign;
  DSA_verify := Load_DSA_verify;
  DSA_set_ex_data := Load_DSA_set_ex_data;
  DSA_get_ex_data := Load_DSA_get_ex_data;
  d2i_DSAPublicKey := Load_d2i_DSAPublicKey;
  i2d_DSAPublicKey := Load_i2d_DSAPublicKey;
  d2i_DSAPrivateKey := Load_d2i_DSAPrivateKey;
  i2d_DSAPrivateKey := Load_i2d_DSAPrivateKey;
  d2i_DSAparams := Load_d2i_DSAparams;
  i2d_DSAparams := Load_i2d_DSAparams;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}
  DSA_generate_parameters := Load_DSA_generate_parameters;
    {$endif} { OPENSSL_NO_DEPRECATED_0_9_8}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DSA_generate_parameters_ex := Load_DSA_generate_parameters_ex;
  DSA_generate_key := Load_DSA_generate_key;
  DSAparams_print := Load_DSAparams_print;
  DSA_print := Load_DSA_print;
        {$ifndef  OPENSSL_NO_STDIO}
  DSAparams_print_fp := Load_DSAparams_print_fp;
  DSA_print_fp := Load_DSA_print_fp;
        {$endif} { OPENSSL_NO_STDIO}
        {$ifndef  OPENSSL_NO_DH}
  DSA_dup_DH := Load_DSA_dup_DH;
        {$endif} { OPENSSL_NO_DH}
  DSA_get0_pqg := Load_DSA_get0_pqg;
  DSA_set0_pqg := Load_DSA_set0_pqg;
  DSA_get0_key := Load_DSA_get0_key;
  DSA_set0_key := Load_DSA_set0_key;
  DSA_get0_p := Load_DSA_get0_p;
  DSA_get0_q := Load_DSA_get0_q;
  DSA_get0_g := Load_DSA_get0_g;
  DSA_get0_pub_key := Load_DSA_get0_pub_key;
  DSA_get0_priv_key := Load_DSA_get0_priv_key;
  DSA_clear_flags := Load_DSA_clear_flags;
  DSA_test_flags := Load_DSA_test_flags;
  DSA_set_flags := Load_DSA_set_flags;
  DSA_get0_engine := Load_DSA_get0_engine;
  DSA_meth_new := Load_DSA_meth_new;
  DSA_meth_free := Load_DSA_meth_free;
  DSA_meth_dup := Load_DSA_meth_dup;
  DSA_meth_get0_name := Load_DSA_meth_get0_name;
  DSA_meth_set1_name := Load_DSA_meth_set1_name;
  DSA_meth_get_flags := Load_DSA_meth_get_flags;
  DSA_meth_set_flags := Load_DSA_meth_set_flags;
  DSA_meth_get0_app_data := Load_DSA_meth_get0_app_data;
  DSA_meth_set0_app_data := Load_DSA_meth_set0_app_data;
  DSA_meth_get_sign := Load_DSA_meth_get_sign;
  DSA_meth_set_sign := Load_DSA_meth_set_sign;
  DSA_meth_get_sign_setup := Load_DSA_meth_get_sign_setup;
  DSA_meth_set_sign_setup := Load_DSA_meth_set_sign_setup;
  DSA_meth_get_verify := Load_DSA_meth_get_verify;
  DSA_meth_set_verify := Load_DSA_meth_set_verify;
  DSA_meth_get_mod_exp := Load_DSA_meth_get_mod_exp;
  DSA_meth_set_mod_exp := Load_DSA_meth_set_mod_exp;
  DSA_meth_get_bn_mod_exp := Load_DSA_meth_get_bn_mod_exp;
  DSA_meth_set_bn_mod_exp := Load_DSA_meth_set_bn_mod_exp;
  DSA_meth_get_init := Load_DSA_meth_get_init;
  DSA_meth_set_init := Load_DSA_meth_set_init;
  DSA_meth_get_finish := Load_DSA_meth_get_finish;
  DSA_meth_set_finish := Load_DSA_meth_set_finish;
  DSA_meth_get_paramgen := Load_DSA_meth_get_paramgen;
  DSA_meth_set_paramgen := Load_DSA_meth_set_paramgen;
  DSA_meth_get_keygen := Load_DSA_meth_get_keygen;
  DSA_meth_set_keygen := Load_DSA_meth_set_keygen;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DSA}
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



