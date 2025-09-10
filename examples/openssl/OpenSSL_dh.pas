(* This unit was generated from the source file dh.h2pas 
It should not be modified directly. All changes should be made to dh.h2pas
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


unit OpenSSL_dh;


interface

// Headers for OpenSSL 1.1.1
// dh.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_evp,
  OpenSSL_asn1;

const
  OPENSSL_DH_MAX_MODULUS_BITS      = 10000;
  OPENSSL_DH_FIPS_MIN_MODULUS_BITS =  1024;

  DH_FLAG_CACHE_MONT_P   =   $01;
  DH_FLAG_FIPS_METHOD    = $0400;
  DH_FLAG_NON_FIPS_ALLOW = $0400;

  DH_GENERATOR_2 = 2;
  DH_GENERATOR_5 = 5;

  DH_CHECK_P_NOT_PRIME         = $01;
  DH_CHECK_P_NOT_SAFE_PRIME    = $02;
  DH_UNABLE_TO_CHECK_GENERATOR = $04;
  DH_NOT_SUITABLE_GENERATOR    = $08;
  DH_CHECK_Q_NOT_PRIME         = $10;
  DH_CHECK_INVALID_Q_VALUE     = $20;
  DH_CHECK_INVALID_J_VALUE     = $40;
  DH_CHECK_PUBKEY_TOO_SMALL    = $01;
  DH_CHECK_PUBKEY_TOO_LARGE    = $02;
  DH_CHECK_PUBKEY_INVALID      = $04;
  DH_CHECK_P_NOT_STRONG_PRIME  = DH_CHECK_P_NOT_SAFE_PRIME;

  EVP_PKEY_DH_KDF_NONE  = 1;
  EVP_PKEY_DH_KDF_X9_42 = 2;

  EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN    = (EVP_PKEY_ALG_CTRL + 1);
  EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR    = (EVP_PKEY_ALG_CTRL + 2);
  EVP_PKEY_CTRL_DH_RFC5114               = (EVP_PKEY_ALG_CTRL + 3);
  EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN = (EVP_PKEY_ALG_CTRL + 4);
  EVP_PKEY_CTRL_DH_PARAMGEN_TYPE         = (EVP_PKEY_ALG_CTRL + 5);
  EVP_PKEY_CTRL_DH_KDF_TYPE              = (EVP_PKEY_ALG_CTRL + 6);
  EVP_PKEY_CTRL_DH_KDF_MD                = (EVP_PKEY_ALG_CTRL + 7);
  EVP_PKEY_CTRL_GET_DH_KDF_MD            = (EVP_PKEY_ALG_CTRL + 8);
  EVP_PKEY_CTRL_DH_KDF_OUTLEN            = (EVP_PKEY_ALG_CTRL + 9);
  EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN        = (EVP_PKEY_ALG_CTRL + 10);
  EVP_PKEY_CTRL_DH_KDF_UKM               = (EVP_PKEY_ALG_CTRL + 11);
  EVP_PKEY_CTRL_GET_DH_KDF_UKM           = (EVP_PKEY_ALG_CTRL + 12);
  EVP_PKEY_CTRL_DH_KDF_OID               = (EVP_PKEY_ALG_CTRL + 13);
  EVP_PKEY_CTRL_GET_DH_KDF_OID           = (EVP_PKEY_ALG_CTRL + 14);
  EVP_PKEY_CTRL_DH_NID                   = (EVP_PKEY_ALG_CTRL + 15);
  EVP_PKEY_CTRL_DH_PAD                   = (EVP_PKEY_ALG_CTRL + 16);

type
  DH_meth_generate_key_cb = function(dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_compute_key_cb = function(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_bn_mod_exp_cb = function(
    const dh: PDH; r: PBIGNUM; const a: PBIGNUM;
    const p: PBIGNUM; const m: PBIGNUM;
    ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT cdecl;
  DH_meth_init_cb = function(dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_finish_cb = function(dh: PDH): TOpenSSL_C_INT cdecl;
  DH_meth_generate_params_cb = function(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT cdecl;

{
  # define DH_CHECK_P_NOT_STRONG_PRIME     DH_CHECK_P_NOT_SAFE_PRIME

  # define d2i_DHparams_fp(fp,x) \
      (DH *)ASN1_d2i_fp((char *(*)())DH_new, \
                        (char *(*)())d2i_DHparams, \
                        (fp), \
                        (unsigned char **)(x))
  # define i2d_DHparams_fp(fp,x) \
      ASN1_i2d_fp(i2d_DHparams,(fp), (unsigned char *)(x))
  # define d2i_DHparams_bio(bp,x) \
      ASN1_d2i_bio_of(DH, DH_new, d2i_DHparams, bp, x)
  # define i2d_DHparams_bio(bp,x) \
      ASN1_i2d_bio_of_const(DH,i2d_DHparams,bp,x)

  # define d2i_DHxparams_fp(fp,x) \
      (DH *)ASN1_d2i_fp((char *(*)())DH_new, \
                        (char *(*)())d2i_DHxparams, \
                        (fp), \
                        (unsigned char **)(x))
  # define i2d_DHxparams_fp(fp,x) \
      ASN1_i2d_fp(i2d_DHxparams,(fp), (unsigned char *)(x))
  # define d2i_DHxparams_bio(bp,x) \
      ASN1_d2i_bio_of(DH, DH_new, d2i_DHxparams, bp, x)
  # define i2d_DHxparams_bio(bp,x) \
      ASN1_i2d_bio_of_const(DH, i2d_DHxparams, bp, x)
}

  

function d2i_DHparams_bio(bp: PBIO; x: PPDH): PDH;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

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
{$EXTERNALSYM DH_meth_get_generate_key}
{$EXTERNALSYM DH_meth_set_generate_key}
{$EXTERNALSYM DH_meth_get_compute_key}
{$EXTERNALSYM DH_meth_set_compute_key}
{$EXTERNALSYM DH_meth_get_bn_mod_exp}
{$EXTERNALSYM DH_meth_set_bn_mod_exp}
{$EXTERNALSYM DH_meth_get_init}
{$EXTERNALSYM DH_meth_set_init}
{$EXTERNALSYM DH_meth_get_finish}
{$EXTERNALSYM DH_meth_set_finish}
{$EXTERNALSYM DH_meth_get_generate_params}
{$EXTERNALSYM DH_meth_set_generate_params}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function DHparams_dup(dh: PDH): PDH; cdecl; external CLibCrypto;
function DH_OpenSSL: PDH_Method; cdecl; external CLibCrypto;
procedure DH_set_default_method(const meth: PDH_Method); cdecl; external CLibCrypto;
function DH_get_default_method: PDH_Method; cdecl; external CLibCrypto;
function DH_set_method(dh: PDH; const meth: PDH_Method): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_new_method(engine: PENGINE): PDH; cdecl; external CLibCrypto;
function DH_new: PDH; cdecl; external CLibCrypto;
procedure DH_free(dh: PDH); cdecl; external CLibCrypto;
function DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_bits(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_size(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_security_bits(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_params_ex(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_ex(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_pub_key_ex(const dh: PDH; const pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_params(const dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check(const dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_check_pub_key(const dh: PDH; const pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_compute_key(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_compute_key_padded(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DHparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl; external CLibCrypto;
function i2d_DHparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DHxparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl; external CLibCrypto;
function i2d_DHxparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DHparams_print(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_get_1024_160: PDH; cdecl; external CLibCrypto;
function DH_get_2048_224: PDH; cdecl; external CLibCrypto;
function DH_get_2048_256: PDH; cdecl; external CLibCrypto;
function DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl; external CLibCrypto;
function DH_get_nid(const dh: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_KDF_X9_42( out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DH_get0_pqg(const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl; external CLibCrypto;
function DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DH_get0_key(const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl; external CLibCrypto;
function DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_get0_p(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_q(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_g(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_priv_key(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
function DH_get0_pub_key(const dh: PDH): PBIGNUM; cdecl; external CLibCrypto;
procedure DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DH_test_flags(const dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DH_get0_engine(d: PDH): PENGINE; cdecl; external CLibCrypto;
function DH_get_length(const dh: PDH): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function DH_set_length(dh: PDH; length: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_Method; cdecl; external CLibCrypto;
procedure DH_meth_free(dhm: PDH_Method); cdecl; external CLibCrypto;
function DH_meth_dup(const dhm: PDH_Method): PDH_Method; cdecl; external CLibCrypto;
function DH_meth_get0_name(const dhm: PDH_Method): PAnsiChar; cdecl; external CLibCrypto;
function DH_meth_set1_name(dhm: PDH_Method; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_flags(const dhm: PDH_Method): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_set_flags(const dhm: PDH_Method; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get0_app_data(const dhm: PDH_Method): Pointer; cdecl; external CLibCrypto;
function DH_meth_set0_app_data(const dhm: PDH_Method; app_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_generate_key(const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl; external CLibCrypto;
function DH_meth_set_generate_key(const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_compute_key(const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl; external CLibCrypto;
function DH_meth_set_compute_key(const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_bn_mod_exp(const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl; external CLibCrypto;
function DH_meth_set_bn_mod_exp(const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_init(const dhm: PDH_Method): DH_meth_init_cb; cdecl; external CLibCrypto;
function DH_meth_set_init(const dhm: PDH_Method; init: DH_meth_init_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_finish(const dhm: PDH_Method): DH_meth_finish_cb; cdecl; external CLibCrypto;
function DH_meth_set_finish(const dhm: PDH_Method; finish: DH_meth_finish_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DH_meth_get_generate_params(const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl; external CLibCrypto;
function DH_meth_set_generate_params(const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;




{$ELSE}
var
  DHparams_dup: function (dh: PDH): PDH; cdecl = nil;
  DH_OpenSSL: function : PDH_Method; cdecl = nil;
  DH_set_default_method: procedure (const meth: PDH_Method); cdecl = nil;
  DH_get_default_method: function : PDH_Method; cdecl = nil;
  DH_set_method: function (dh: PDH; const meth: PDH_Method): TOpenSSL_C_INT; cdecl = nil;
  DH_new_method: function (engine: PENGINE): PDH; cdecl = nil;
  DH_new: function : PDH; cdecl = nil;
  DH_free: procedure (dh: PDH); cdecl = nil;
  DH_up_ref: function (dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_bits: function (const dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_size: function (const dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_security_bits: function (const dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_set_ex_data: function (d: PDH; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  DH_get_ex_data: function (d: PDH; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  DH_generate_parameters_ex: function (dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  DH_check_params_ex: function (const dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_check_ex: function (const dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_check_pub_key_ex: function (const dh: PDH; const pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  DH_check_params: function (const dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DH_check: function (const dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DH_check_pub_key: function (const dh: PDH; const pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DH_generate_key: function (dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_compute_key: function (key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_compute_key_padded: function (key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  d2i_DHparams: function (a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl = nil;
  i2d_DHparams: function (const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_DHxparams: function (a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl = nil;
  i2d_DHxparams: function (const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  DHparams_print: function (bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_get_1024_160: function : PDH; cdecl = nil;
  DH_get_2048_224: function : PDH; cdecl = nil;
  DH_get_2048_256: function : PDH; cdecl = nil;
  DH_new_by_nid: function (nid: TOpenSSL_C_INT): PDH; cdecl = nil;
  DH_get_nid: function (const dh: PDH): TOpenSSL_C_INT; cdecl = nil;
  DH_KDF_X9_42: function ( out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  DH_get0_pqg: procedure (const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl = nil;
  DH_set0_pqg: function (dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  DH_get0_key: procedure (const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl = nil;
  DH_set0_key: function (dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  DH_get0_p: function (const dh: PDH): PBIGNUM; cdecl = nil;
  DH_get0_q: function (const dh: PDH): PBIGNUM; cdecl = nil;
  DH_get0_g: function (const dh: PDH): PBIGNUM; cdecl = nil;
  DH_get0_priv_key: function (const dh: PDH): PBIGNUM; cdecl = nil;
  DH_get0_pub_key: function (const dh: PDH): PBIGNUM; cdecl = nil;
  DH_clear_flags: procedure (dh: PDH; flags: TOpenSSL_C_INT); cdecl = nil;
  DH_test_flags: function (const dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DH_set_flags: procedure (dh: PDH; flags: TOpenSSL_C_INT); cdecl = nil;
  DH_get0_engine: function (d: PDH): PENGINE; cdecl = nil;
  DH_get_length: function (const dh: PDH): TOpenSSL_C_LONG; cdecl = nil;
  DH_set_length: function (dh: PDH; length: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_new: function (const name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_Method; cdecl = nil;
  DH_meth_free: procedure (dhm: PDH_Method); cdecl = nil;
  DH_meth_dup: function (const dhm: PDH_Method): PDH_Method; cdecl = nil;
  DH_meth_get0_name: function (const dhm: PDH_Method): PAnsiChar; cdecl = nil;
  DH_meth_set1_name: function (dhm: PDH_Method; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get_flags: function (const dhm: PDH_Method): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_set_flags: function (const dhm: PDH_Method; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get0_app_data: function (const dhm: PDH_Method): Pointer; cdecl = nil;
  DH_meth_set0_app_data: function (const dhm: PDH_Method; app_data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get_generate_key: function (const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl = nil;
  DH_meth_set_generate_key: function (const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get_compute_key: function (const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl = nil;
  DH_meth_set_compute_key: function (const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get_bn_mod_exp: function (const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl = nil;
  DH_meth_set_bn_mod_exp: function (const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get_init: function (const dhm: PDH_Method): DH_meth_init_cb; cdecl = nil;
  DH_meth_set_init: function (const dhm: PDH_Method; init: DH_meth_init_cb): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get_finish: function (const dhm: PDH_Method): DH_meth_finish_cb; cdecl = nil;
  DH_meth_set_finish: function (const dhm: PDH_Method; finish: DH_meth_finish_cb): TOpenSSL_C_INT; cdecl = nil;
  DH_meth_get_generate_params: function (const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl = nil;
  DH_meth_set_generate_params: function (const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TOpenSSL_C_INT; cdecl = nil;



{$ENDIF}
const
  DH_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_security_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_params_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_pub_key_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_check_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_new_by_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get_nid_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_pqg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set0_pqg_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set0_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_p_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_q_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_g_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_priv_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_pub_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_clear_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_test_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get0_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_get_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_set_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get0_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set1_name_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get0_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set0_app_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_generate_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_generate_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_bn_mod_exp_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_bn_mod_exp_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_finish_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_finish_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_get_generate_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  DH_meth_set_generate_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation

uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;


function d2i_DHparams_bio(bp: PBIO; x: PPDH): PDH;
begin
  Result := PDH(ASN1_d2i_bio(pxnew(@DH_new), pd2i_of_void(@d2i_DHparams), bp, PPointer(x)));
end;




{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_DHparams_dup(dh: PDH): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_dup');
end;

function ERROR_DH_OpenSSL: PDH_Method; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_OpenSSL');
end;

procedure ERROR_DH_set_default_method(const meth: PDH_Method); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_default_method');
end;

function ERROR_DH_get_default_method: PDH_Method; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_default_method');
end;

function ERROR_DH_set_method(dh: PDH; const meth: PDH_Method): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_method');
end;

function ERROR_DH_new_method(engine: PENGINE): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new_method');
end;

function ERROR_DH_new: PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new');
end;

procedure ERROR_DH_free(dh: PDH); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_free');
end;

function ERROR_DH_up_ref(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_up_ref');
end;

function ERROR_DH_bits(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_bits');
end;

function ERROR_DH_size(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_size');
end;

function ERROR_DH_security_bits(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_security_bits');
end;

function ERROR_DH_set_ex_data(d: PDH; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_ex_data');
end;

function ERROR_DH_get_ex_data(d: PDH; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_ex_data');
end;

function ERROR_DH_generate_parameters_ex(dh: PDH; prime_len: TOpenSSL_C_INT; generator: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_generate_parameters_ex');
end;

function ERROR_DH_check_params_ex(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_params_ex');
end;

function ERROR_DH_check_ex(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_ex');
end;

function ERROR_DH_check_pub_key_ex(const dh: PDH; const pub_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_pub_key_ex');
end;

function ERROR_DH_check_params(const dh: PDH; ret: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_params');
end;

function ERROR_DH_check(const dh: PDH; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check');
end;

function ERROR_DH_check_pub_key(const dh: PDH; const pub_key: PBIGNUM; codes: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_check_pub_key');
end;

function ERROR_DH_generate_key(dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_generate_key');
end;

function ERROR_DH_compute_key(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_compute_key');
end;

function ERROR_DH_compute_key_padded(key: PByte; const pub_key: PBIGNUM; dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_compute_key_padded');
end;

function ERROR_d2i_DHparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DHparams');
end;

function ERROR_i2d_DHparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DHparams');
end;

function ERROR_d2i_DHxparams(a: PPDH; const pp: PPByte; length: TOpenSSL_C_LONG): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DHxparams');
end;

function ERROR_i2d_DHxparams(const a: PDH; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DHxparams');
end;

function ERROR_DHparams_print(bp: PBIO; const x: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DHparams_print');
end;

function ERROR_DH_get_1024_160: PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_1024_160');
end;

function ERROR_DH_get_2048_224: PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_2048_224');
end;

function ERROR_DH_get_2048_256: PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_2048_256');
end;

function ERROR_DH_new_by_nid(nid: TOpenSSL_C_INT): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_new_by_nid');
end;

function ERROR_DH_get_nid(const dh: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_nid');
end;

function ERROR_DH_KDF_X9_42( out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; key_oid: PASN1_OBJECT; const ukm: PByte; ukmlen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_KDF_X9_42');
end;

procedure ERROR_DH_get0_pqg(const dh: PDH; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_pqg');
end;

function ERROR_DH_set0_pqg(dh: PDH; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set0_pqg');
end;

procedure ERROR_DH_get0_key(const dh: PDH; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_key');
end;

function ERROR_DH_set0_key(dh: PDH; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set0_key');
end;

function ERROR_DH_get0_p(const dh: PDH): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_p');
end;

function ERROR_DH_get0_q(const dh: PDH): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_q');
end;

function ERROR_DH_get0_g(const dh: PDH): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_g');
end;

function ERROR_DH_get0_priv_key(const dh: PDH): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_priv_key');
end;

function ERROR_DH_get0_pub_key(const dh: PDH): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_pub_key');
end;

procedure ERROR_DH_clear_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_clear_flags');
end;

function ERROR_DH_test_flags(const dh: PDH; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_test_flags');
end;

procedure ERROR_DH_set_flags(dh: PDH; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_flags');
end;

function ERROR_DH_get0_engine(d: PDH): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get0_engine');
end;

function ERROR_DH_get_length(const dh: PDH): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_get_length');
end;

function ERROR_DH_set_length(dh: PDH; length: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_set_length');
end;

function ERROR_DH_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDH_Method; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_new');
end;

procedure ERROR_DH_meth_free(dhm: PDH_Method); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_free');
end;

function ERROR_DH_meth_dup(const dhm: PDH_Method): PDH_Method; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_dup');
end;

function ERROR_DH_meth_get0_name(const dhm: PDH_Method): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get0_name');
end;

function ERROR_DH_meth_set1_name(dhm: PDH_Method; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set1_name');
end;

function ERROR_DH_meth_get_flags(const dhm: PDH_Method): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_flags');
end;

function ERROR_DH_meth_set_flags(const dhm: PDH_Method; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_flags');
end;

function ERROR_DH_meth_get0_app_data(const dhm: PDH_Method): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get0_app_data');
end;

function ERROR_DH_meth_set0_app_data(const dhm: PDH_Method; app_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set0_app_data');
end;

function ERROR_DH_meth_get_generate_key(const dhm: PDH_Method): DH_meth_generate_key_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_generate_key');
end;

function ERROR_DH_meth_set_generate_key(const dhm: PDH_Method; generate_key: DH_meth_generate_key_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_generate_key');
end;

function ERROR_DH_meth_get_compute_key(const dhm: PDH_Method): DH_meth_compute_key_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_compute_key');
end;

function ERROR_DH_meth_set_compute_key(const dhm: PDH_Method; compute_key: DH_meth_compute_key_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_compute_key');
end;

function ERROR_DH_meth_get_bn_mod_exp(const dhm: PDH_Method): DH_meth_bn_mod_exp_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_bn_mod_exp');
end;

function ERROR_DH_meth_set_bn_mod_exp(const dhm: PDH_Method; bn_mod_expr: DH_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_bn_mod_exp');
end;

function ERROR_DH_meth_get_init(const dhm: PDH_Method): DH_meth_init_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_init');
end;

function ERROR_DH_meth_set_init(const dhm: PDH_Method; init: DH_meth_init_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_init');
end;

function ERROR_DH_meth_get_finish(const dhm: PDH_Method): DH_meth_finish_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_finish');
end;

function ERROR_DH_meth_set_finish(const dhm: PDH_Method; finish: DH_meth_finish_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_finish');
end;

function ERROR_DH_meth_get_generate_params(const dhm: PDH_Method): DH_meth_generate_params_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_get_generate_params');
end;

function ERROR_DH_meth_set_generate_params(const dhm: PDH_Method; generate_params: DH_meth_generate_params_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DH_meth_set_generate_params');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  DHparams_dup := LoadLibCryptoFunction('DHparams_dup');
  FuncLoadError := not assigned(DHparams_dup);
  if FuncLoadError then
  begin
    DHparams_dup :=  @ERROR_DHparams_dup;
  end;

  DH_OpenSSL := LoadLibCryptoFunction('DH_OpenSSL');
  FuncLoadError := not assigned(DH_OpenSSL);
  if FuncLoadError then
  begin
    DH_OpenSSL :=  @ERROR_DH_OpenSSL;
  end;

  DH_set_default_method := LoadLibCryptoFunction('DH_set_default_method');
  FuncLoadError := not assigned(DH_set_default_method);
  if FuncLoadError then
  begin
    DH_set_default_method :=  @ERROR_DH_set_default_method;
  end;

  DH_get_default_method := LoadLibCryptoFunction('DH_get_default_method');
  FuncLoadError := not assigned(DH_get_default_method);
  if FuncLoadError then
  begin
    DH_get_default_method :=  @ERROR_DH_get_default_method;
  end;

  DH_set_method := LoadLibCryptoFunction('DH_set_method');
  FuncLoadError := not assigned(DH_set_method);
  if FuncLoadError then
  begin
    DH_set_method :=  @ERROR_DH_set_method;
  end;

  DH_new_method := LoadLibCryptoFunction('DH_new_method');
  FuncLoadError := not assigned(DH_new_method);
  if FuncLoadError then
  begin
    DH_new_method :=  @ERROR_DH_new_method;
  end;

  DH_new := LoadLibCryptoFunction('DH_new');
  FuncLoadError := not assigned(DH_new);
  if FuncLoadError then
  begin
    DH_new :=  @ERROR_DH_new;
  end;

  DH_free := LoadLibCryptoFunction('DH_free');
  FuncLoadError := not assigned(DH_free);
  if FuncLoadError then
  begin
    DH_free :=  @ERROR_DH_free;
  end;

  DH_up_ref := LoadLibCryptoFunction('DH_up_ref');
  FuncLoadError := not assigned(DH_up_ref);
  if FuncLoadError then
  begin
    DH_up_ref :=  @ERROR_DH_up_ref;
  end;

  DH_bits := LoadLibCryptoFunction('DH_bits');
  FuncLoadError := not assigned(DH_bits);
  if FuncLoadError then
  begin
    DH_bits :=  @ERROR_DH_bits;
  end;

  DH_size := LoadLibCryptoFunction('DH_size');
  FuncLoadError := not assigned(DH_size);
  if FuncLoadError then
  begin
    DH_size :=  @ERROR_DH_size;
  end;

  DH_security_bits := LoadLibCryptoFunction('DH_security_bits');
  FuncLoadError := not assigned(DH_security_bits);
  if FuncLoadError then
  begin
    DH_security_bits :=  @ERROR_DH_security_bits;
  end;

  DH_set_ex_data := LoadLibCryptoFunction('DH_set_ex_data');
  FuncLoadError := not assigned(DH_set_ex_data);
  if FuncLoadError then
  begin
    DH_set_ex_data :=  @ERROR_DH_set_ex_data;
  end;

  DH_get_ex_data := LoadLibCryptoFunction('DH_get_ex_data');
  FuncLoadError := not assigned(DH_get_ex_data);
  if FuncLoadError then
  begin
    DH_get_ex_data :=  @ERROR_DH_get_ex_data;
  end;

  DH_generate_parameters_ex := LoadLibCryptoFunction('DH_generate_parameters_ex');
  FuncLoadError := not assigned(DH_generate_parameters_ex);
  if FuncLoadError then
  begin
    DH_generate_parameters_ex :=  @ERROR_DH_generate_parameters_ex;
  end;

  DH_check_params_ex := LoadLibCryptoFunction('DH_check_params_ex');
  FuncLoadError := not assigned(DH_check_params_ex);
  if FuncLoadError then
  begin
    DH_check_params_ex :=  @ERROR_DH_check_params_ex;
  end;

  DH_check_ex := LoadLibCryptoFunction('DH_check_ex');
  FuncLoadError := not assigned(DH_check_ex);
  if FuncLoadError then
  begin
    DH_check_ex :=  @ERROR_DH_check_ex;
  end;

  DH_check_pub_key_ex := LoadLibCryptoFunction('DH_check_pub_key_ex');
  FuncLoadError := not assigned(DH_check_pub_key_ex);
  if FuncLoadError then
  begin
    DH_check_pub_key_ex :=  @ERROR_DH_check_pub_key_ex;
  end;

  DH_check_params := LoadLibCryptoFunction('DH_check_params');
  FuncLoadError := not assigned(DH_check_params);
  if FuncLoadError then
  begin
    DH_check_params :=  @ERROR_DH_check_params;
  end;

  DH_check := LoadLibCryptoFunction('DH_check');
  FuncLoadError := not assigned(DH_check);
  if FuncLoadError then
  begin
    DH_check :=  @ERROR_DH_check;
  end;

  DH_check_pub_key := LoadLibCryptoFunction('DH_check_pub_key');
  FuncLoadError := not assigned(DH_check_pub_key);
  if FuncLoadError then
  begin
    DH_check_pub_key :=  @ERROR_DH_check_pub_key;
  end;

  DH_generate_key := LoadLibCryptoFunction('DH_generate_key');
  FuncLoadError := not assigned(DH_generate_key);
  if FuncLoadError then
  begin
    DH_generate_key :=  @ERROR_DH_generate_key;
  end;

  DH_compute_key := LoadLibCryptoFunction('DH_compute_key');
  FuncLoadError := not assigned(DH_compute_key);
  if FuncLoadError then
  begin
    DH_compute_key :=  @ERROR_DH_compute_key;
  end;

  DH_compute_key_padded := LoadLibCryptoFunction('DH_compute_key_padded');
  FuncLoadError := not assigned(DH_compute_key_padded);
  if FuncLoadError then
  begin
    DH_compute_key_padded :=  @ERROR_DH_compute_key_padded;
  end;

  d2i_DHparams := LoadLibCryptoFunction('d2i_DHparams');
  FuncLoadError := not assigned(d2i_DHparams);
  if FuncLoadError then
  begin
    d2i_DHparams :=  @ERROR_d2i_DHparams;
  end;

  i2d_DHparams := LoadLibCryptoFunction('i2d_DHparams');
  FuncLoadError := not assigned(i2d_DHparams);
  if FuncLoadError then
  begin
    i2d_DHparams :=  @ERROR_i2d_DHparams;
  end;

  d2i_DHxparams := LoadLibCryptoFunction('d2i_DHxparams');
  FuncLoadError := not assigned(d2i_DHxparams);
  if FuncLoadError then
  begin
    d2i_DHxparams :=  @ERROR_d2i_DHxparams;
  end;

  i2d_DHxparams := LoadLibCryptoFunction('i2d_DHxparams');
  FuncLoadError := not assigned(i2d_DHxparams);
  if FuncLoadError then
  begin
    i2d_DHxparams :=  @ERROR_i2d_DHxparams;
  end;

  DHparams_print := LoadLibCryptoFunction('DHparams_print');
  FuncLoadError := not assigned(DHparams_print);
  if FuncLoadError then
  begin
    DHparams_print :=  @ERROR_DHparams_print;
  end;

  DH_get_1024_160 := LoadLibCryptoFunction('DH_get_1024_160');
  FuncLoadError := not assigned(DH_get_1024_160);
  if FuncLoadError then
  begin
    DH_get_1024_160 :=  @ERROR_DH_get_1024_160;
  end;

  DH_get_2048_224 := LoadLibCryptoFunction('DH_get_2048_224');
  FuncLoadError := not assigned(DH_get_2048_224);
  if FuncLoadError then
  begin
    DH_get_2048_224 :=  @ERROR_DH_get_2048_224;
  end;

  DH_get_2048_256 := LoadLibCryptoFunction('DH_get_2048_256');
  FuncLoadError := not assigned(DH_get_2048_256);
  if FuncLoadError then
  begin
    DH_get_2048_256 :=  @ERROR_DH_get_2048_256;
  end;

  DH_new_by_nid := LoadLibCryptoFunction('DH_new_by_nid');
  FuncLoadError := not assigned(DH_new_by_nid);
  if FuncLoadError then
  begin
    DH_new_by_nid :=  @ERROR_DH_new_by_nid;
  end;

  DH_get_nid := LoadLibCryptoFunction('DH_get_nid');
  FuncLoadError := not assigned(DH_get_nid);
  if FuncLoadError then
  begin
    DH_get_nid :=  @ERROR_DH_get_nid;
  end;

  DH_KDF_X9_42 := LoadLibCryptoFunction('DH_KDF_X9_42');
  FuncLoadError := not assigned(DH_KDF_X9_42);
  if FuncLoadError then
  begin
    DH_KDF_X9_42 :=  @ERROR_DH_KDF_X9_42;
  end;

  DH_get0_pqg := LoadLibCryptoFunction('DH_get0_pqg');
  FuncLoadError := not assigned(DH_get0_pqg);
  if FuncLoadError then
  begin
    DH_get0_pqg :=  @ERROR_DH_get0_pqg;
  end;

  DH_set0_pqg := LoadLibCryptoFunction('DH_set0_pqg');
  FuncLoadError := not assigned(DH_set0_pqg);
  if FuncLoadError then
  begin
    DH_set0_pqg :=  @ERROR_DH_set0_pqg;
  end;

  DH_get0_key := LoadLibCryptoFunction('DH_get0_key');
  FuncLoadError := not assigned(DH_get0_key);
  if FuncLoadError then
  begin
    DH_get0_key :=  @ERROR_DH_get0_key;
  end;

  DH_set0_key := LoadLibCryptoFunction('DH_set0_key');
  FuncLoadError := not assigned(DH_set0_key);
  if FuncLoadError then
  begin
    DH_set0_key :=  @ERROR_DH_set0_key;
  end;

  DH_get0_p := LoadLibCryptoFunction('DH_get0_p');
  FuncLoadError := not assigned(DH_get0_p);
  if FuncLoadError then
  begin
    DH_get0_p :=  @ERROR_DH_get0_p;
  end;

  DH_get0_q := LoadLibCryptoFunction('DH_get0_q');
  FuncLoadError := not assigned(DH_get0_q);
  if FuncLoadError then
  begin
    DH_get0_q :=  @ERROR_DH_get0_q;
  end;

  DH_get0_g := LoadLibCryptoFunction('DH_get0_g');
  FuncLoadError := not assigned(DH_get0_g);
  if FuncLoadError then
  begin
    DH_get0_g :=  @ERROR_DH_get0_g;
  end;

  DH_get0_priv_key := LoadLibCryptoFunction('DH_get0_priv_key');
  FuncLoadError := not assigned(DH_get0_priv_key);
  if FuncLoadError then
  begin
    DH_get0_priv_key :=  @ERROR_DH_get0_priv_key;
  end;

  DH_get0_pub_key := LoadLibCryptoFunction('DH_get0_pub_key');
  FuncLoadError := not assigned(DH_get0_pub_key);
  if FuncLoadError then
  begin
    DH_get0_pub_key :=  @ERROR_DH_get0_pub_key;
  end;

  DH_clear_flags := LoadLibCryptoFunction('DH_clear_flags');
  FuncLoadError := not assigned(DH_clear_flags);
  if FuncLoadError then
  begin
    DH_clear_flags :=  @ERROR_DH_clear_flags;
  end;

  DH_test_flags := LoadLibCryptoFunction('DH_test_flags');
  FuncLoadError := not assigned(DH_test_flags);
  if FuncLoadError then
  begin
    DH_test_flags :=  @ERROR_DH_test_flags;
  end;

  DH_set_flags := LoadLibCryptoFunction('DH_set_flags');
  FuncLoadError := not assigned(DH_set_flags);
  if FuncLoadError then
  begin
    DH_set_flags :=  @ERROR_DH_set_flags;
  end;

  DH_get0_engine := LoadLibCryptoFunction('DH_get0_engine');
  FuncLoadError := not assigned(DH_get0_engine);
  if FuncLoadError then
  begin
    DH_get0_engine :=  @ERROR_DH_get0_engine;
  end;

  DH_get_length := LoadLibCryptoFunction('DH_get_length');
  FuncLoadError := not assigned(DH_get_length);
  if FuncLoadError then
  begin
    DH_get_length :=  @ERROR_DH_get_length;
  end;

  DH_set_length := LoadLibCryptoFunction('DH_set_length');
  FuncLoadError := not assigned(DH_set_length);
  if FuncLoadError then
  begin
    DH_set_length :=  @ERROR_DH_set_length;
  end;

  DH_meth_new := LoadLibCryptoFunction('DH_meth_new');
  FuncLoadError := not assigned(DH_meth_new);
  if FuncLoadError then
  begin
    DH_meth_new :=  @ERROR_DH_meth_new;
  end;

  DH_meth_free := LoadLibCryptoFunction('DH_meth_free');
  FuncLoadError := not assigned(DH_meth_free);
  if FuncLoadError then
  begin
    DH_meth_free :=  @ERROR_DH_meth_free;
  end;

  DH_meth_dup := LoadLibCryptoFunction('DH_meth_dup');
  FuncLoadError := not assigned(DH_meth_dup);
  if FuncLoadError then
  begin
    DH_meth_dup :=  @ERROR_DH_meth_dup;
  end;

  DH_meth_get0_name := LoadLibCryptoFunction('DH_meth_get0_name');
  FuncLoadError := not assigned(DH_meth_get0_name);
  if FuncLoadError then
  begin
    DH_meth_get0_name :=  @ERROR_DH_meth_get0_name;
  end;

  DH_meth_set1_name := LoadLibCryptoFunction('DH_meth_set1_name');
  FuncLoadError := not assigned(DH_meth_set1_name);
  if FuncLoadError then
  begin
    DH_meth_set1_name :=  @ERROR_DH_meth_set1_name;
  end;

  DH_meth_get_flags := LoadLibCryptoFunction('DH_meth_get_flags');
  FuncLoadError := not assigned(DH_meth_get_flags);
  if FuncLoadError then
  begin
    DH_meth_get_flags :=  @ERROR_DH_meth_get_flags;
  end;

  DH_meth_set_flags := LoadLibCryptoFunction('DH_meth_set_flags');
  FuncLoadError := not assigned(DH_meth_set_flags);
  if FuncLoadError then
  begin
    DH_meth_set_flags :=  @ERROR_DH_meth_set_flags;
  end;

  DH_meth_get0_app_data := LoadLibCryptoFunction('DH_meth_get0_app_data');
  FuncLoadError := not assigned(DH_meth_get0_app_data);
  if FuncLoadError then
  begin
    DH_meth_get0_app_data :=  @ERROR_DH_meth_get0_app_data;
  end;

  DH_meth_set0_app_data := LoadLibCryptoFunction('DH_meth_set0_app_data');
  FuncLoadError := not assigned(DH_meth_set0_app_data);
  if FuncLoadError then
  begin
    DH_meth_set0_app_data :=  @ERROR_DH_meth_set0_app_data;
  end;

  DH_meth_get_generate_key := LoadLibCryptoFunction('DH_meth_get_generate_key');
  FuncLoadError := not assigned(DH_meth_get_generate_key);
  if FuncLoadError then
  begin
    DH_meth_get_generate_key :=  @ERROR_DH_meth_get_generate_key;
  end;

  DH_meth_set_generate_key := LoadLibCryptoFunction('DH_meth_set_generate_key');
  FuncLoadError := not assigned(DH_meth_set_generate_key);
  if FuncLoadError then
  begin
    DH_meth_set_generate_key :=  @ERROR_DH_meth_set_generate_key;
  end;

  DH_meth_get_compute_key := LoadLibCryptoFunction('DH_meth_get_compute_key');
  FuncLoadError := not assigned(DH_meth_get_compute_key);
  if FuncLoadError then
  begin
    DH_meth_get_compute_key :=  @ERROR_DH_meth_get_compute_key;
  end;

  DH_meth_set_compute_key := LoadLibCryptoFunction('DH_meth_set_compute_key');
  FuncLoadError := not assigned(DH_meth_set_compute_key);
  if FuncLoadError then
  begin
    DH_meth_set_compute_key :=  @ERROR_DH_meth_set_compute_key;
  end;

  DH_meth_get_bn_mod_exp := LoadLibCryptoFunction('DH_meth_get_bn_mod_exp');
  FuncLoadError := not assigned(DH_meth_get_bn_mod_exp);
  if FuncLoadError then
  begin
    DH_meth_get_bn_mod_exp :=  @ERROR_DH_meth_get_bn_mod_exp;
  end;

  DH_meth_set_bn_mod_exp := LoadLibCryptoFunction('DH_meth_set_bn_mod_exp');
  FuncLoadError := not assigned(DH_meth_set_bn_mod_exp);
  if FuncLoadError then
  begin
    DH_meth_set_bn_mod_exp :=  @ERROR_DH_meth_set_bn_mod_exp;
  end;

  DH_meth_get_init := LoadLibCryptoFunction('DH_meth_get_init');
  FuncLoadError := not assigned(DH_meth_get_init);
  if FuncLoadError then
  begin
    DH_meth_get_init :=  @ERROR_DH_meth_get_init;
  end;

  DH_meth_set_init := LoadLibCryptoFunction('DH_meth_set_init');
  FuncLoadError := not assigned(DH_meth_set_init);
  if FuncLoadError then
  begin
    DH_meth_set_init :=  @ERROR_DH_meth_set_init;
  end;

  DH_meth_get_finish := LoadLibCryptoFunction('DH_meth_get_finish');
  FuncLoadError := not assigned(DH_meth_get_finish);
  if FuncLoadError then
  begin
    DH_meth_get_finish :=  @ERROR_DH_meth_get_finish;
  end;

  DH_meth_set_finish := LoadLibCryptoFunction('DH_meth_set_finish');
  FuncLoadError := not assigned(DH_meth_set_finish);
  if FuncLoadError then
  begin
    DH_meth_set_finish :=  @ERROR_DH_meth_set_finish;
  end;

  DH_meth_get_generate_params := LoadLibCryptoFunction('DH_meth_get_generate_params');
  FuncLoadError := not assigned(DH_meth_get_generate_params);
  if FuncLoadError then
  begin
    DH_meth_get_generate_params :=  @ERROR_DH_meth_get_generate_params;
  end;

  DH_meth_set_generate_params := LoadLibCryptoFunction('DH_meth_set_generate_params');
  FuncLoadError := not assigned(DH_meth_set_generate_params);
  if FuncLoadError then
  begin
    DH_meth_set_generate_params :=  @ERROR_DH_meth_set_generate_params;
  end;

end;

procedure UnLoad;
begin
  DHparams_dup := nil;
  DH_OpenSSL := nil;
  DH_set_default_method := nil;
  DH_get_default_method := nil;
  DH_set_method := nil;
  DH_new_method := nil;
  DH_new := nil;
  DH_free := nil;
  DH_up_ref := nil;
  DH_bits := nil;
  DH_size := nil;
  DH_security_bits := nil;
  DH_set_ex_data := nil;
  DH_get_ex_data := nil;
  DH_generate_parameters_ex := nil;
  DH_check_params_ex := nil;
  DH_check_ex := nil;
  DH_check_pub_key_ex := nil;
  DH_check_params := nil;
  DH_check := nil;
  DH_check_pub_key := nil;
  DH_generate_key := nil;
  DH_compute_key := nil;
  DH_compute_key_padded := nil;
  d2i_DHparams := nil;
  i2d_DHparams := nil;
  d2i_DHxparams := nil;
  i2d_DHxparams := nil;
  DHparams_print := nil;
  DH_get_1024_160 := nil;
  DH_get_2048_224 := nil;
  DH_get_2048_256 := nil;
  DH_new_by_nid := nil;
  DH_get_nid := nil;
  DH_KDF_X9_42 := nil;
  DH_get0_pqg := nil;
  DH_set0_pqg := nil;
  DH_get0_key := nil;
  DH_set0_key := nil;
  DH_get0_p := nil;
  DH_get0_q := nil;
  DH_get0_g := nil;
  DH_get0_priv_key := nil;
  DH_get0_pub_key := nil;
  DH_clear_flags := nil;
  DH_test_flags := nil;
  DH_set_flags := nil;
  DH_get0_engine := nil;
  DH_get_length := nil;
  DH_set_length := nil;
  DH_meth_new := nil;
  DH_meth_free := nil;
  DH_meth_dup := nil;
  DH_meth_get0_name := nil;
  DH_meth_set1_name := nil;
  DH_meth_get_flags := nil;
  DH_meth_set_flags := nil;
  DH_meth_get0_app_data := nil;
  DH_meth_set0_app_data := nil;
  DH_meth_get_generate_key := nil;
  DH_meth_set_generate_key := nil;
  DH_meth_get_compute_key := nil;
  DH_meth_set_compute_key := nil;
  DH_meth_get_bn_mod_exp := nil;
  DH_meth_set_bn_mod_exp := nil;
  DH_meth_get_init := nil;
  DH_meth_set_init := nil;
  DH_meth_get_finish := nil;
  DH_meth_set_finish := nil;
  DH_meth_get_generate_params := nil;
  DH_meth_set_generate_params := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
