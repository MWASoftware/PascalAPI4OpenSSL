(* This unit was generated from the source file ec.h2pas 
It should not be modified directly. All changes should be made to ec.h2pas
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


unit OpenSSL_ec;


interface

// Headers for OpenSSL 1.1.1
// ec.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_evp;

const
  OPENSSL_EC_EXPLICIT_CURVE = $000;
  OPENSSL_EC_NAMED_CURVE    = $001;
  EC_PKEY_NO_PARAMETERS = $001;
  EC_PKEY_NO_PUBKEY     = $002;
  EC_FLAG_NON_FIPS_ALLOW = $1;
  EC_FLAG_FIPS_CHECKED   = $2;
  EC_FLAG_COFACTOR_ECDH  = $1000;
  EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = (EVP_PKEY_ALG_CTRL + 1);
  EVP_PKEY_CTRL_EC_PARAM_ENC          = (EVP_PKEY_ALG_CTRL + 2);
  EVP_PKEY_CTRL_EC_ECDH_COFACTOR      = (EVP_PKEY_ALG_CTRL + 3);
  EVP_PKEY_CTRL_EC_KDF_TYPE           = (EVP_PKEY_ALG_CTRL + 4);
  EVP_PKEY_CTRL_EC_KDF_MD             = (EVP_PKEY_ALG_CTRL + 5);
  EVP_PKEY_CTRL_GET_EC_KDF_MD         = (EVP_PKEY_ALG_CTRL + 6);
  EVP_PKEY_CTRL_EC_KDF_OUTLEN         = (EVP_PKEY_ALG_CTRL + 7);
  EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN     = (EVP_PKEY_ALG_CTRL + 8);
  EVP_PKEY_CTRL_EC_KDF_UKM            = (EVP_PKEY_ALG_CTRL + 9);
  EVP_PKEY_CTRL_GET_EC_KDF_UKM        = (EVP_PKEY_ALG_CTRL + 10);
  EVP_PKEY_CTRL_SET1_ID               = (EVP_PKEY_ALG_CTRL + 11);
  EVP_PKEY_CTRL_GET1_ID               = (EVP_PKEY_ALG_CTRL + 12);
  EVP_PKEY_CTRL_GET1_ID_LEN           = (EVP_PKEY_ALG_CTRL + 13);
  EVP_PKEY_ECDH_KDF_NONE              = 1;
  EVP_PKEY_ECDH_KDF_X9_63             = 2;
  EVP_PKEY_ECDH_KDF_X9_62             = EVP_PKEY_ECDH_KDF_X9_63;

type
  {$MINENUMSIZE 4}
  point_conversion_form_t = (
    POINT_CONVERSION_COMPRESSED = 2,
    POINT_CONVERSION_UNCOMPRESSED = 4,
    POINT_CONVERSION_HYBRID = 6
  );

  EC_METHOD = type Pointer; // ec_method_st
  PEC_METHOD = ^EC_METHOD;
  
  EC_GROUP = type Pointer; // ec_group_st
  PEC_GROUP = ^EC_GROUP;
  PPEC_GROUP = ^PEC_GROUP;
  
  EC_POINT = type Pointer; // ec_point_st
  PEC_POINT = ^EC_POINT;
  PPEC_POINT = ^PEC_POINT;
  
  ECPKPARAMETERS = type Pointer; // ecpk_parameters_st
  PECPKPARAMETERS = ^ECPKPARAMETERS;
  
  ECPARAMETERS = type Pointer; // ec_parameters_st
  PECPARAMETERS = ^ECPARAMETERS;

  EC_builtin_curve = record
    nid: TOpenSSL_C_INT;
    comment: PAnsiChar;
  end;
  PEC_builtin_curve = ^EC_builtin_curve;

  ECDSA_SIG = type Pointer; // ECDSA_SIG_st
  PECDSA_SIG = ^ECDSA_SIG;
  PPECDSA_SIG = ^PECDSA_SIG;

  ECDH_compute_key_KDF = function(const in_: Pointer; inlen: TOpenSSL_C_SIZET; out_: Pointer; outlen: POpenSSL_C_SIZET): Pointer; cdecl;

  EC_KEY_METHOD_init_init = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_finish = procedure(key: PEC_KEY); cdecl;
  EC_KEY_METHOD_init_copy = function(dest: PEC_KEY; const src: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_set_group = function(key: PEC_KEY; const grp: PEC_GROUP): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_set_private = function(key: PEC_KEY; const priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_init_set_public = function(key: PEC_KEY; const pub_key: PEC_POINT): TOpenSSL_C_INT; cdecl;

  EC_KEY_METHOD_keygen_keygen = function(key: PEC_KEY): TOpenSSL_C_INT; cdecl;

  EC_KEY_METHOD_compute_key_ckey = function(psec: PPByte; pseclen: POpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY): TOpenSSL_C_INT; cdecl;

  EC_KEY_METHOD_sign_sign = function(type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const r: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_sign_sign_setup = function(eckey: PEC_KEY; ctx_in: PBN_CTX; kinvp: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_sign_sign_sig = function(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const in_kinv: PBIGNUM; const in_r: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;

  EC_KEY_METHOD_verify_verify = function(type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; sig_len: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
  EC_KEY_METHOD_verify_verify_sig = function(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;

  PEC_KEY_METHOD_init_init = ^EC_KEY_METHOD_init_init;
  PEC_KEY_METHOD_init_finish = ^EC_KEY_METHOD_init_finish;
  PEC_KEY_METHOD_init_copy = ^EC_KEY_METHOD_init_copy;
  PEC_KEY_METHOD_init_set_group = ^EC_KEY_METHOD_init_set_group;
  PEC_KEY_METHOD_init_set_private = ^EC_KEY_METHOD_init_set_private;
  PEC_KEY_METHOD_init_set_public = ^EC_KEY_METHOD_init_set_public;

  PEC_KEY_METHOD_keygen_keygen = ^EC_KEY_METHOD_keygen_keygen;

  PEC_KEY_METHOD_compute_key_ckey = ^EC_KEY_METHOD_compute_key_ckey;

  PEC_KEY_METHOD_sign_sign = ^EC_KEY_METHOD_sign_sign;
  PEC_KEY_METHOD_sign_sign_setup = ^EC_KEY_METHOD_sign_sign_setup;
  PEC_KEY_METHOD_sign_sign_sig = ^EC_KEY_METHOD_sign_sign_sig;

  PEC_KEY_METHOD_verify_verify = ^EC_KEY_METHOD_verify_verify;
  PEC_KEY_METHOD_verify_verify_sig = ^EC_KEY_METHOD_verify_verify_sig;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM EC_GFp_simple_method}
{$EXTERNALSYM EC_GFp_mont_method}
{$EXTERNALSYM EC_GFp_nist_method}
{$EXTERNALSYM EC_GF2m_simple_method}
{$EXTERNALSYM EC_GROUP_new}
{$EXTERNALSYM EC_GROUP_free}
{$EXTERNALSYM EC_GROUP_clear_free}
{$EXTERNALSYM EC_GROUP_copy}
{$EXTERNALSYM EC_GROUP_dup}
{$EXTERNALSYM EC_GROUP_method_of}
{$EXTERNALSYM EC_METHOD_get_field_type}
{$EXTERNALSYM EC_GROUP_set_generator}
{$EXTERNALSYM EC_GROUP_get0_generator}
{$EXTERNALSYM EC_GROUP_get_mont_data}
{$EXTERNALSYM EC_GROUP_get_order}
{$EXTERNALSYM EC_GROUP_get0_order}
{$EXTERNALSYM EC_GROUP_order_bits}
{$EXTERNALSYM EC_GROUP_get_cofactor}
{$EXTERNALSYM EC_GROUP_get0_cofactor}
{$EXTERNALSYM EC_GROUP_set_curve_name}
{$EXTERNALSYM EC_GROUP_get_curve_name}
{$EXTERNALSYM EC_GROUP_set_asn1_flag}
{$EXTERNALSYM EC_GROUP_get_asn1_flag}
{$EXTERNALSYM EC_GROUP_set_point_conversion_form}
{$EXTERNALSYM EC_GROUP_get_point_conversion_form}
{$EXTERNALSYM EC_GROUP_get0_seed}
{$EXTERNALSYM EC_GROUP_get_seed_len}
{$EXTERNALSYM EC_GROUP_set_seed}
{$EXTERNALSYM EC_GROUP_set_curve}
{$EXTERNALSYM EC_GROUP_get_curve}
{$EXTERNALSYM EC_GROUP_set_curve_GFp}
{$EXTERNALSYM EC_GROUP_get_curve_GFp}
{$EXTERNALSYM EC_GROUP_set_curve_GF2m}
{$EXTERNALSYM EC_GROUP_get_curve_GF2m}
{$EXTERNALSYM EC_GROUP_get_degree}
{$EXTERNALSYM EC_GROUP_check}
{$EXTERNALSYM EC_GROUP_check_discriminant}
{$EXTERNALSYM EC_GROUP_cmp}
{$EXTERNALSYM EC_GROUP_new_curve_GFp}
{$EXTERNALSYM EC_GROUP_new_curve_GF2m}
{$EXTERNALSYM EC_GROUP_new_by_curve_name}
{$EXTERNALSYM EC_GROUP_new_from_ecparameters}
{$EXTERNALSYM EC_GROUP_get_ecparameters}
{$EXTERNALSYM EC_GROUP_new_from_ecpkparameters}
{$EXTERNALSYM EC_GROUP_get_ecpkparameters}
{$EXTERNALSYM EC_get_builtin_curves}
{$EXTERNALSYM EC_curve_nid2nist}
{$EXTERNALSYM EC_curve_nist2nid}
{$EXTERNALSYM EC_POINT_new}
{$EXTERNALSYM EC_POINT_free}
{$EXTERNALSYM EC_POINT_clear_free}
{$EXTERNALSYM EC_POINT_copy}
{$EXTERNALSYM EC_POINT_dup}
{$EXTERNALSYM EC_POINT_method_of}
{$EXTERNALSYM EC_POINT_set_to_infinity}
{$EXTERNALSYM EC_POINT_set_Jprojective_coordinates_GFp}
{$EXTERNALSYM EC_POINT_get_Jprojective_coordinates_GFp}
{$EXTERNALSYM EC_POINT_set_affine_coordinates}
{$EXTERNALSYM EC_POINT_get_affine_coordinates}
{$EXTERNALSYM EC_POINT_set_affine_coordinates_GFp}
{$EXTERNALSYM EC_POINT_get_affine_coordinates_GFp}
{$EXTERNALSYM EC_POINT_set_compressed_coordinates}
{$EXTERNALSYM EC_POINT_set_compressed_coordinates_GFp}
{$EXTERNALSYM EC_POINT_set_affine_coordinates_GF2m}
{$EXTERNALSYM EC_POINT_get_affine_coordinates_GF2m}
{$EXTERNALSYM EC_POINT_set_compressed_coordinates_GF2m}
{$EXTERNALSYM EC_POINT_point2oct}
{$EXTERNALSYM EC_POINT_oct2point}
{$EXTERNALSYM EC_POINT_point2buf}
{$EXTERNALSYM EC_POINT_point2bn}
{$EXTERNALSYM EC_POINT_bn2point}
{$EXTERNALSYM EC_POINT_point2hex}
{$EXTERNALSYM EC_POINT_hex2point}
{$EXTERNALSYM EC_POINT_add}
{$EXTERNALSYM EC_POINT_dbl}
{$EXTERNALSYM EC_POINT_invert}
{$EXTERNALSYM EC_POINT_is_at_infinity}
{$EXTERNALSYM EC_POINT_is_on_curve}
{$EXTERNALSYM EC_POINT_cmp}
{$EXTERNALSYM EC_POINT_make_affine}
{$EXTERNALSYM EC_POINTs_make_affine}
{$EXTERNALSYM EC_POINTs_mul}
{$EXTERNALSYM EC_POINT_mul}
{$EXTERNALSYM EC_GROUP_precompute_mult}
{$EXTERNALSYM EC_GROUP_have_precompute_mult}
{$EXTERNALSYM ECPKPARAMETERS_it}
{$EXTERNALSYM ECPKPARAMETERS_new}
{$EXTERNALSYM ECPKPARAMETERS_free}
{$EXTERNALSYM ECPARAMETERS_it}
{$EXTERNALSYM ECPARAMETERS_new}
{$EXTERNALSYM ECPARAMETERS_free}
{$EXTERNALSYM EC_GROUP_get_basis_type}
{$EXTERNALSYM EC_GROUP_get_trinomial_basis}
{$EXTERNALSYM EC_GROUP_get_pentanomial_basis}
{$EXTERNALSYM d2i_ECPKParameters}
{$EXTERNALSYM i2d_ECPKParameters}
{$EXTERNALSYM ECPKParameters_print}
{$EXTERNALSYM EC_KEY_new}
{$EXTERNALSYM EC_KEY_get_flags}
{$EXTERNALSYM EC_KEY_set_flags}
{$EXTERNALSYM EC_KEY_clear_flags}
{$EXTERNALSYM EC_KEY_new_by_curve_name}
{$EXTERNALSYM EC_KEY_free}
{$EXTERNALSYM EC_KEY_copy}
{$EXTERNALSYM EC_KEY_dup}
{$EXTERNALSYM EC_KEY_up_ref}
{$EXTERNALSYM EC_KEY_get0_engine}
{$EXTERNALSYM EC_KEY_get0_group}
{$EXTERNALSYM EC_KEY_set_group}
{$EXTERNALSYM EC_KEY_get0_private_key}
{$EXTERNALSYM EC_KEY_set_private_key}
{$EXTERNALSYM EC_KEY_get0_public_key}
{$EXTERNALSYM EC_KEY_set_public_key}
{$EXTERNALSYM EC_KEY_get_enc_flags}
{$EXTERNALSYM EC_KEY_set_enc_flags}
{$EXTERNALSYM EC_KEY_get_conv_form}
{$EXTERNALSYM EC_KEY_set_conv_form}
{$EXTERNALSYM EC_KEY_set_ex_data}
{$EXTERNALSYM EC_KEY_get_ex_data}
{$EXTERNALSYM EC_KEY_set_asn1_flag}
{$EXTERNALSYM EC_KEY_precompute_mult}
{$EXTERNALSYM EC_KEY_generate_key}
{$EXTERNALSYM EC_KEY_check_key}
{$EXTERNALSYM EC_KEY_can_sign}
{$EXTERNALSYM EC_KEY_set_public_key_affine_coordinates}
{$EXTERNALSYM EC_KEY_key2buf}
{$EXTERNALSYM EC_KEY_oct2key}
{$EXTERNALSYM EC_KEY_oct2priv}
{$EXTERNALSYM EC_KEY_priv2oct}
{$EXTERNALSYM EC_KEY_priv2buf}
{$EXTERNALSYM d2i_ECPrivateKey}
{$EXTERNALSYM i2d_ECPrivateKey}
{$EXTERNALSYM o2i_ECPublicKey}
{$EXTERNALSYM i2o_ECPublicKey}
{$EXTERNALSYM ECParameters_print}
{$EXTERNALSYM EC_KEY_print}
{$EXTERNALSYM EC_KEY_OpenSSL}
{$EXTERNALSYM EC_KEY_get_default_method}
{$EXTERNALSYM EC_KEY_set_default_method}
{$EXTERNALSYM EC_KEY_get_method}
{$EXTERNALSYM EC_KEY_set_method}
{$EXTERNALSYM EC_KEY_new_method}
{$EXTERNALSYM ECDH_KDF_X9_62}
{$EXTERNALSYM ECDH_compute_key}
{$EXTERNALSYM ECDSA_SIG_new}
{$EXTERNALSYM ECDSA_SIG_free}
{$EXTERNALSYM i2d_ECDSA_SIG}
{$EXTERNALSYM d2i_ECDSA_SIG}
{$EXTERNALSYM ECDSA_SIG_get0}
{$EXTERNALSYM ECDSA_SIG_get0_r}
{$EXTERNALSYM ECDSA_SIG_get0_s}
{$EXTERNALSYM ECDSA_SIG_set0}
{$EXTERNALSYM ECDSA_do_sign}
{$EXTERNALSYM ECDSA_do_sign_ex}
{$EXTERNALSYM ECDSA_do_verify}
{$EXTERNALSYM ECDSA_sign_setup}
{$EXTERNALSYM ECDSA_sign}
{$EXTERNALSYM ECDSA_sign_ex}
{$EXTERNALSYM ECDSA_verify}
{$EXTERNALSYM ECDSA_size}
{$EXTERNALSYM EC_KEY_METHOD_new}
{$EXTERNALSYM EC_KEY_METHOD_free}
{$EXTERNALSYM EC_KEY_METHOD_set_init}
{$EXTERNALSYM EC_KEY_METHOD_set_keygen}
{$EXTERNALSYM EC_KEY_METHOD_set_compute_key}
{$EXTERNALSYM EC_KEY_METHOD_set_sign}
{$EXTERNALSYM EC_KEY_METHOD_set_verify}
{$EXTERNALSYM EC_KEY_METHOD_get_init}
{$EXTERNALSYM EC_KEY_METHOD_get_keygen}
{$EXTERNALSYM EC_KEY_METHOD_get_compute_key}
{$EXTERNALSYM EC_KEY_METHOD_get_sign}
{$EXTERNALSYM EC_KEY_METHOD_get_verify}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function EC_GFp_simple_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GFp_mont_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GFp_nist_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GF2m_simple_method: PEC_METHOD; cdecl; external CLibCrypto;
function EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP; cdecl; external CLibCrypto;
procedure EC_GROUP_free(group: PEC_GROUP); cdecl; external CLibCrypto;
procedure EC_GROUP_clear_free(group: PEC_GROUP); cdecl; external CLibCrypto;
function EC_GROUP_copy(dst: PEC_GROUP; const src: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_dup(const src: PEC_GROUP): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_method_of(const group: PEC_GROUP): PEC_GROUP; cdecl; external CLibCrypto;
function EC_METHOD_get_field_type(const meth: PEC_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto;
function EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX; cdecl; external CLibCrypto;
function EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM; cdecl; external CLibCrypto;
function EC_GROUP_order_bits(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM; cdecl; external CLibCrypto;
procedure EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_GROUP_get_curve_name(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_GROUP_get_asn1_flag(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: point_conversion_form_t); cdecl; external CLibCrypto;
function EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): point_conversion_form_t; cdecl; external CLibCrypto;
function EC_GROUP_get0_seed(const x: PEC_GROUP): PByte; cdecl; external CLibCrypto;
function EC_GROUP_get_seed_len(const x: PEC_GROUP): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_GROUP_set_seed(x: PEC_GROUP; const p: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_set_curve_GF2m(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_curve_GF2m(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_degree(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_check(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_new_curve_GF2m(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_new_from_ecparameters(const params: PECPARAMETERS): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_get_ecparameters(const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl; external CLibCrypto;
function EC_GROUP_new_from_ecpkparameters(const params: PECPKPARAMETERS): PEC_GROUP; cdecl; external CLibCrypto;
function EC_GROUP_get_ecpkparameters(const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl; external CLibCrypto;
function EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function EC_curve_nist2nid(const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_new(const group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto;
procedure EC_POINT_free(point: PEC_POINT); cdecl; external CLibCrypto;
procedure EC_POINT_clear_free(point: PEC_POINT); cdecl; external CLibCrypto;
function EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl; external CLibCrypto;
function EC_POINT_method_of(const point: PEC_POINT): PEC_METHOD; cdecl; external CLibCrypto;
function EC_POINT_set_to_infinity(const group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_Jprojective_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_Jprojective_coordinates_GFp(const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_affine_coordinates(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_affine_coordinates(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_compressed_coordinates(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_get_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_set_compressed_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_point2oct(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_POINT_oct2point(const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_point2buf(const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_POINT_point2bn(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
function EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl; external CLibCrypto;
function EC_POINT_point2hex(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PAnsiChar; cdecl; external CLibCrypto;
function EC_POINT_hex2point(const group: PEC_GROUP; const buf: PAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl; external CLibCrypto;
function EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_make_affine(const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINTs_make_affine(const group: PEC_METHOD; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINTs_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TOpenSSL_C_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_have_precompute_mult(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECPKPARAMETERS_it: PASN1_ITEM; cdecl; external CLibCrypto;
function ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl; external CLibCrypto;
procedure ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl; external CLibCrypto;
function ECPARAMETERS_it: PASN1_ITEM; cdecl; external CLibCrypto;
function ECPARAMETERS_new: PECPARAMETERS; cdecl; external CLibCrypto;
procedure ECPARAMETERS_free(a: PECPARAMETERS); cdecl; external CLibCrypto;
function EC_GROUP_get_basis_type(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_trinomial_basis(const group: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_GROUP_get_pentanomial_basis(const group: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ECPKParameters(group: PPEC_GROUP; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_GROUP; cdecl; external CLibCrypto;
function i2d_ECPKParameters(const group: PEC_GROUP; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECPKParameters_print(bp: PBIO; const x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_new: PEC_KEY; cdecl; external CLibCrypto;
function EC_KEY_get_flags(const key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl; external CLibCrypto;
procedure EC_KEY_free(key: PEC_KEY); cdecl; external CLibCrypto;
function EC_KEY_copy(dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl; external CLibCrypto;
function EC_KEY_dup(const src: PEC_KEY): PEC_KEY; cdecl; external CLibCrypto;
function EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; cdecl; external CLibCrypto;
function EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; cdecl; external CLibCrypto;
function EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; cdecl; external CLibCrypto;
function EC_KEY_set_private_key(const key: PEC_KEY; const prv: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; cdecl; external CLibCrypto;
function EC_KEY_set_public_key(key: PEC_KEY; const pub: PEC_POINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get_enc_flags(const key: PEC_KEY): TOpenSSL_C_UINT; cdecl; external CLibCrypto;
procedure EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl; external CLibCrypto;
function EC_KEY_get_conv_form(const key: PEC_KEY): point_conversion_form_t; cdecl; external CLibCrypto;
procedure EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t); cdecl; external CLibCrypto;
function EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_get_ex_data(const key: PEC_KEY; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
procedure EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_check_key(const key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_can_sign(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_key2buf(const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_KEY_oct2key(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_oct2priv(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_priv2oct(const key: PEC_KEY; buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EC_KEY_priv2buf(const eckey: PEC_KEY; buf: PPByte): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function d2i_ECPrivateKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl; external CLibCrypto;
function i2d_ECPrivateKey(key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function o2i_ECPublicKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl; external CLibCrypto;
function i2o_ECPublicKey(const key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECParameters_print(bp: PBIO; const key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_print(bp: PBIO; const key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl; external CLibCrypto;
function EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl; external CLibCrypto;
procedure EC_KEY_set_default_method(const meth: PEC_KEY_METHOD); cdecl; external CLibCrypto;
function EC_KEY_get_method(const key: PEC_KEY): PEC_KEY_METHOD; cdecl; external CLibCrypto;
function EC_KEY_set_method(key: PEC_KEY; const meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl; external CLibCrypto;
function ECDH_KDF_X9_62(out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; const sinfo: PByte; sinfolen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDH_compute_key(out_: Pointer; oulen: TOpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_SIG_new: PECDSA_SIG; cdecl; external CLibCrypto;
procedure ECDSA_SIG_free(sig: PECDSA_SIG); cdecl; external CLibCrypto;
function i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: TOpenSSL_C_LONG): PECDSA_SIG; cdecl; external CLibCrypto;
procedure ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl; external CLibCrypto;
function ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM; cdecl; external CLibCrypto;
function ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM; cdecl; external CLibCrypto;
function ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_do_sign(const dgst: PByte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl; external CLibCrypto;
function ECDSA_do_sign_ex(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl; external CLibCrypto;
function ECDSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_sign_ex(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; const sig: PByte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ECDSA_size(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EC_KEY_METHOD_new(const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_init(const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; pcopy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_keygen(const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_compute_key(const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_sign(const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl; external CLibCrypto;
procedure EC_KEY_METHOD_get_verify(const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl; external CLibCrypto;

{$ELSE}
var
  EC_GFp_simple_method: function : PEC_METHOD; cdecl = nil;
  EC_GFp_mont_method: function : PEC_METHOD; cdecl = nil;
  EC_GFp_nist_method: function : PEC_METHOD; cdecl = nil;
  EC_GF2m_simple_method: function : PEC_METHOD; cdecl = nil;
  EC_GROUP_new: function (const meth: PEC_METHOD): PEC_GROUP; cdecl = nil;
  EC_GROUP_free: procedure (group: PEC_GROUP); cdecl = nil;
  EC_GROUP_clear_free: procedure (group: PEC_GROUP); cdecl = nil;
  EC_GROUP_copy: function (dst: PEC_GROUP; const src: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_dup: function (const src: PEC_GROUP): PEC_GROUP; cdecl = nil;
  EC_GROUP_method_of: function (const group: PEC_GROUP): PEC_GROUP; cdecl = nil;
  EC_METHOD_get_field_type: function (const meth: PEC_METHOD): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_set_generator: function (group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get0_generator: function (const group: PEC_GROUP): PEC_POINT; cdecl = nil;
  EC_GROUP_get_mont_data: function (const group: PEC_GROUP): PBN_MONT_CTX; cdecl = nil;
  EC_GROUP_get_order: function (const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get0_order: function (const group: PEC_GROUP): PBIGNUM; cdecl = nil;
  EC_GROUP_order_bits: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get_cofactor: function (const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get0_cofactor: function (const group: PEC_GROUP): PBIGNUM; cdecl = nil;
  EC_GROUP_set_curve_name: procedure (group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl = nil;
  EC_GROUP_get_curve_name: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_set_asn1_flag: procedure (group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl = nil;
  EC_GROUP_get_asn1_flag: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_set_point_conversion_form: procedure (group: PEC_GROUP; form: point_conversion_form_t); cdecl = nil;
  EC_GROUP_get_point_conversion_form: function (const group: PEC_GROUP): point_conversion_form_t; cdecl = nil;
  EC_GROUP_get0_seed: function (const x: PEC_GROUP): PByte; cdecl = nil;
  EC_GROUP_get_seed_len: function (const x: PEC_GROUP): TOpenSSL_C_SIZET; cdecl = nil;
  EC_GROUP_set_seed: function (x: PEC_GROUP; const p: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  EC_GROUP_set_curve: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get_curve: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_set_curve_GFp: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get_curve_GFp: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_set_curve_GF2m: function (group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get_curve_GF2m: function (const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get_degree: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_check: function (const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_check_discriminant: function (const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_cmp: function (const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_new_curve_GFp: function (const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = nil;
  EC_GROUP_new_curve_GF2m: function (const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl = nil;
  EC_GROUP_new_by_curve_name: function (nid: TOpenSSL_C_INT): PEC_GROUP; cdecl = nil;
  EC_GROUP_new_from_ecparameters: function (const params: PECPARAMETERS): PEC_GROUP; cdecl = nil;
  EC_GROUP_get_ecparameters: function (const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl = nil;
  EC_GROUP_new_from_ecpkparameters: function (const params: PECPKPARAMETERS): PEC_GROUP; cdecl = nil;
  EC_GROUP_get_ecpkparameters: function (const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl = nil;
  EC_get_builtin_curves: function (r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  EC_curve_nid2nist: function (nid: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  EC_curve_nist2nid: function (const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_new: function (const group: PEC_GROUP): PEC_POINT; cdecl = nil;
  EC_POINT_free: procedure (point: PEC_POINT); cdecl = nil;
  EC_POINT_clear_free: procedure (point: PEC_POINT); cdecl = nil;
  EC_POINT_copy: function (dst: PEC_POINT; const src: PEC_POINT): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_dup: function (const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl = nil;
  EC_POINT_method_of: function (const point: PEC_POINT): PEC_METHOD; cdecl = nil;
  EC_POINT_set_to_infinity: function (const group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_set_Jprojective_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_get_Jprojective_coordinates_GFp: function (const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_set_affine_coordinates: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_get_affine_coordinates: function (const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_set_affine_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_get_affine_coordinates_GFp: function (const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_set_compressed_coordinates: function (const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_set_compressed_coordinates_GFp: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_set_affine_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_get_affine_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_set_compressed_coordinates_GF2m: function (const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_point2oct: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = nil;
  EC_POINT_oct2point: function (const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_point2buf: function (const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = nil;
  EC_POINT_point2bn: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = nil;
  EC_POINT_bn2point: function (const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl = nil;
  EC_POINT_point2hex: function (const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PAnsiChar; cdecl = nil;
  EC_POINT_hex2point: function (const group: PEC_GROUP; const buf: PAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl = nil;
  EC_POINT_add: function (const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_dbl: function (const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_invert: function (const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_is_at_infinity: function (const group: PEC_GROUP; const p: PEC_POINT): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_is_on_curve: function (const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_cmp: function (const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_make_affine: function (const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINTs_make_affine: function (const group: PEC_METHOD; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINTs_mul: function (const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TOpenSSL_C_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_POINT_mul: function (const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_precompute_mult: function (group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_have_precompute_mult: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  ECPKPARAMETERS_it: function : PASN1_ITEM; cdecl = nil;
  ECPKPARAMETERS_new: function : PECPKPARAMETERS; cdecl = nil;
  ECPKPARAMETERS_free: procedure (a: PECPKPARAMETERS); cdecl = nil;
  ECPARAMETERS_it: function : PASN1_ITEM; cdecl = nil;
  ECPARAMETERS_new: function : PECPARAMETERS; cdecl = nil;
  ECPARAMETERS_free: procedure (a: PECPARAMETERS); cdecl = nil;
  EC_GROUP_get_basis_type: function (const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get_trinomial_basis: function (const group: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  EC_GROUP_get_pentanomial_basis: function (const group: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  d2i_ECPKParameters: function (group: PPEC_GROUP; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_GROUP; cdecl = nil;
  i2d_ECPKParameters: function (const group: PEC_GROUP; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  ECPKParameters_print: function (bp: PBIO; const x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_new: function : PEC_KEY; cdecl = nil;
  EC_KEY_get_flags: function (const key: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_set_flags: procedure (key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl = nil;
  EC_KEY_clear_flags: procedure (key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl = nil;
  EC_KEY_new_by_curve_name: function (nid: TOpenSSL_C_INT): PEC_KEY; cdecl = nil;
  EC_KEY_free: procedure (key: PEC_KEY); cdecl = nil;
  EC_KEY_copy: function (dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl = nil;
  EC_KEY_dup: function (const src: PEC_KEY): PEC_KEY; cdecl = nil;
  EC_KEY_up_ref: function (key: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_get0_engine: function (const eckey: PEC_KEY): PENGINE; cdecl = nil;
  EC_KEY_get0_group: function (const key: PEC_KEY): PEC_GROUP; cdecl = nil;
  EC_KEY_set_group: function (key: PEC_KEY; const group: PEC_GROUP): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_get0_private_key: function (const key: PEC_KEY): PBIGNUM; cdecl = nil;
  EC_KEY_set_private_key: function (const key: PEC_KEY; const prv: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_get0_public_key: function (const key: PEC_KEY): PEC_POINT; cdecl = nil;
  EC_KEY_set_public_key: function (key: PEC_KEY; const pub: PEC_POINT): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_get_enc_flags: function (const key: PEC_KEY): TOpenSSL_C_UINT; cdecl = nil;
  EC_KEY_set_enc_flags: procedure (eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl = nil;
  EC_KEY_get_conv_form: function (const key: PEC_KEY): point_conversion_form_t; cdecl = nil;
  EC_KEY_set_conv_form: procedure (eckey: PEC_KEY; cform: point_conversion_form_t); cdecl = nil;
  EC_KEY_set_ex_data: function (key: PEC_KEY; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_get_ex_data: function (const key: PEC_KEY; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  EC_KEY_set_asn1_flag: procedure (eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl = nil;
  EC_KEY_precompute_mult: function (key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_generate_key: function (key: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_check_key: function (const key: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_can_sign: function (const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_set_public_key_affine_coordinates: function (key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_key2buf: function (const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl = nil;
  EC_KEY_oct2key: function (key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_oct2priv: function (key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_priv2oct: function (const key: PEC_KEY; buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  EC_KEY_priv2buf: function (const eckey: PEC_KEY; buf: PPByte): TOpenSSL_C_SIZET; cdecl = nil;
  d2i_ECPrivateKey: function (key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl = nil;
  i2d_ECPrivateKey: function (key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  o2i_ECPublicKey: function (key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl = nil;
  i2o_ECPublicKey: function (const key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl = nil;
  ECParameters_print: function (bp: PBIO; const key: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_print: function (bp: PBIO; const key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_OpenSSL: function : PEC_KEY_METHOD; cdecl = nil;
  EC_KEY_get_default_method: function : PEC_KEY_METHOD; cdecl = nil;
  EC_KEY_set_default_method: procedure (const meth: PEC_KEY_METHOD); cdecl = nil;
  EC_KEY_get_method: function (const key: PEC_KEY): PEC_KEY_METHOD; cdecl = nil;
  EC_KEY_set_method: function (key: PEC_KEY; const meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_new_method: function (engine: PENGINE): PEC_KEY; cdecl = nil;
  ECDH_KDF_X9_62: function (out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; const sinfo: PByte; sinfolen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  ECDH_compute_key: function (out_: Pointer; oulen: TOpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TOpenSSL_C_INT; cdecl = nil;
  ECDSA_SIG_new: function : PECDSA_SIG; cdecl = nil;
  ECDSA_SIG_free: procedure (sig: PECDSA_SIG); cdecl = nil;
  i2d_ECDSA_SIG: function (const sig: PECDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_ECDSA_SIG: function (sig: PPECDSA_SIG; const pp: PPByte; len: TOpenSSL_C_LONG): PECDSA_SIG; cdecl = nil;
  ECDSA_SIG_get0: procedure (const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl = nil;
  ECDSA_SIG_get0_r: function (const sig: PECDSA_SIG): PBIGNUM; cdecl = nil;
  ECDSA_SIG_get0_s: function (const sig: PECDSA_SIG): PBIGNUM; cdecl = nil;
  ECDSA_SIG_set0: function (sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  ECDSA_do_sign: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl = nil;
  ECDSA_do_sign_ex: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl = nil;
  ECDSA_do_verify: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  ECDSA_sign_setup: function (eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  ECDSA_sign: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  ECDSA_sign_ex: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  ECDSA_verify: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; const sig: PByte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  ECDSA_size: function (const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EC_KEY_METHOD_new: function (const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl = nil;
  EC_KEY_METHOD_free: procedure (meth: PEC_KEY_METHOD); cdecl = nil;
  EC_KEY_METHOD_set_init: procedure (meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl = nil;
  EC_KEY_METHOD_set_keygen: procedure (meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl = nil;
  EC_KEY_METHOD_set_compute_key: procedure (meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl = nil;
  EC_KEY_METHOD_set_sign: procedure (meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl = nil;
  EC_KEY_METHOD_set_verify: procedure (meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl = nil;
  EC_KEY_METHOD_get_init: procedure (const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; pcopy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl = nil;
  EC_KEY_METHOD_get_keygen: procedure (const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl = nil;
  EC_KEY_METHOD_get_compute_key: procedure (const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl = nil;
  EC_KEY_METHOD_get_sign: procedure (const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl = nil;
  EC_KEY_METHOD_get_verify: procedure (const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl = nil;
{$ENDIF}
const
  EC_GFp_nistp224_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GFp_nistp224_method_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EC_GFp_nistp256_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GFp_nistp256_method_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EC_GFp_nistp521_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GFp_nistp521_method_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EC_GROUP_get0_order_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_order_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get0_cofactor_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_set_curve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get_curve_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_new_from_ecparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get_ecparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_new_from_ecpkparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_GROUP_get_ecpkparameters_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_set_affine_coordinates_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_get_affine_coordinates_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_set_compressed_coordinates_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_POINT_point2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get0_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_set_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get_ex_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_can_sign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_key2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_oct2key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_oct2priv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_priv2oct_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_priv2buf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_OpenSSL_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get_default_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_set_default_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_get_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_set_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_new_method_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_get0_r_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_get0_s_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ECDSA_SIG_set0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_keygen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_sign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_set_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_keygen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_compute_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_sign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EC_KEY_METHOD_get_verify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  EC_GFp_nistp224_method: function : PEC_METHOD; cdecl = nil; {removed 3.0.0}
  EC_GFp_nistp256_method: function : PEC_METHOD; cdecl = nil; {removed 3.0.0}
  EC_GFp_nistp521_method: function : PEC_METHOD; cdecl = nil; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_EC_GFp_simple_method: PEC_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_simple_method');
end;

function ERROR_EC_GFp_mont_method: PEC_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_mont_method');
end;

function ERROR_EC_GFp_nist_method: PEC_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nist_method');
end;

function ERROR_EC_GFp_nistp224_method: PEC_METHOD; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp224_method');
end;

function ERROR_EC_GFp_nistp256_method: PEC_METHOD; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp256_method');
end;

function ERROR_EC_GFp_nistp521_method: PEC_METHOD; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GFp_nistp521_method');
end;

function ERROR_EC_GF2m_simple_method: PEC_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GF2m_simple_method');
end;

function ERROR_EC_GROUP_new(const meth: PEC_METHOD): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new');
end;

procedure ERROR_EC_GROUP_free(group: PEC_GROUP); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_free');
end;

procedure ERROR_EC_GROUP_clear_free(group: PEC_GROUP); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_clear_free');
end;

function ERROR_EC_GROUP_copy(dst: PEC_GROUP; const src: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_copy');
end;

function ERROR_EC_GROUP_dup(const src: PEC_GROUP): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_dup');
end;

function ERROR_EC_GROUP_method_of(const group: PEC_GROUP): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_method_of');
end;

function ERROR_EC_METHOD_get_field_type(const meth: PEC_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_METHOD_get_field_type');
end;

function ERROR_EC_GROUP_set_generator(group: PEC_GROUP; const generator: PEC_POINT; const order: PBIGNUM; const cofactor: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_generator');
end;

function ERROR_EC_GROUP_get0_generator(const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_generator');
end;

function ERROR_EC_GROUP_get_mont_data(const group: PEC_GROUP): PBN_MONT_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_mont_data');
end;

function ERROR_EC_GROUP_get_order(const group: PEC_GROUP; order: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_order');
end;

function ERROR_EC_GROUP_get0_order(const group: PEC_GROUP): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_order');
end;

function ERROR_EC_GROUP_order_bits(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_order_bits');
end;

function ERROR_EC_GROUP_get_cofactor(const group: PEC_GROUP; cofactor: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_cofactor');
end;

function ERROR_EC_GROUP_get0_cofactor(const group: PEC_GROUP): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_cofactor');
end;

procedure ERROR_EC_GROUP_set_curve_name(group: PEC_GROUP; nid: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_name');
end;

function ERROR_EC_GROUP_get_curve_name(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_name');
end;

procedure ERROR_EC_GROUP_set_asn1_flag(group: PEC_GROUP; flag: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_asn1_flag');
end;

function ERROR_EC_GROUP_get_asn1_flag(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_asn1_flag');
end;

procedure ERROR_EC_GROUP_set_point_conversion_form(group: PEC_GROUP; form: point_conversion_form_t); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_point_conversion_form');
end;

function ERROR_EC_GROUP_get_point_conversion_form(const group: PEC_GROUP): point_conversion_form_t; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_point_conversion_form');
end;

function ERROR_EC_GROUP_get0_seed(const x: PEC_GROUP): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get0_seed');
end;

function ERROR_EC_GROUP_get_seed_len(const x: PEC_GROUP): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_seed_len');
end;

function ERROR_EC_GROUP_set_seed(x: PEC_GROUP; const p: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_seed');
end;

function ERROR_EC_GROUP_set_curve(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve');
end;

function ERROR_EC_GROUP_get_curve(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve');
end;

function ERROR_EC_GROUP_set_curve_GFp(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_GFp');
end;

function ERROR_EC_GROUP_get_curve_GFp(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_GFp');
end;

function ERROR_EC_GROUP_set_curve_GF2m(group: PEC_GROUP; const p: PBIGNUM; const a: PBIGNUM; const b:PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_set_curve_GF2m');
end;

function ERROR_EC_GROUP_get_curve_GF2m(const group: PEC_GROUP; p: PBIGNUM; a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_curve_GF2m');
end;

function ERROR_EC_GROUP_get_degree(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_degree');
end;

function ERROR_EC_GROUP_check(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_check');
end;

function ERROR_EC_GROUP_check_discriminant(const group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_check_discriminant');
end;

function ERROR_EC_GROUP_cmp(const a: PEC_GROUP; const b: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_cmp');
end;

function ERROR_EC_GROUP_new_curve_GFp(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_curve_GFp');
end;

function ERROR_EC_GROUP_new_curve_GF2m(const p: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_curve_GF2m');
end;

function ERROR_EC_GROUP_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_by_curve_name');
end;

function ERROR_EC_GROUP_new_from_ecparameters(const params: PECPARAMETERS): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_from_ecparameters');
end;

function ERROR_EC_GROUP_get_ecparameters(const group: PEC_GROUP; params: PECPARAMETERS): PECPARAMETERS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_ecparameters');
end;

function ERROR_EC_GROUP_new_from_ecpkparameters(const params: PECPKPARAMETERS): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_new_from_ecpkparameters');
end;

function ERROR_EC_GROUP_get_ecpkparameters(const group: PEC_GROUP; params: PECPKPARAMETERS): PECPKPARAMETERS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_ecpkparameters');
end;

function ERROR_EC_get_builtin_curves(r: PEC_builtin_curve; nitems: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_get_builtin_curves');
end;

function ERROR_EC_curve_nid2nist(nid: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_curve_nid2nist');
end;

function ERROR_EC_curve_nist2nid(const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_curve_nist2nid');
end;

function ERROR_EC_POINT_new(const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_new');
end;

procedure ERROR_EC_POINT_free(point: PEC_POINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_free');
end;

procedure ERROR_EC_POINT_clear_free(point: PEC_POINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_clear_free');
end;

function ERROR_EC_POINT_copy(dst: PEC_POINT; const src: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_copy');
end;

function ERROR_EC_POINT_dup(const src: PEC_POINT; const group: PEC_GROUP): PEC_POINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_dup');
end;

function ERROR_EC_POINT_method_of(const point: PEC_POINT): PEC_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_method_of');
end;

function ERROR_EC_POINT_set_to_infinity(const group: PEC_GROUP; point: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_to_infinity');
end;

function ERROR_EC_POINT_set_Jprojective_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; const z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_Jprojective_coordinates_GFp');
end;

function ERROR_EC_POINT_get_Jprojective_coordinates_GFp(const group: PEC_METHOD; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; z: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_Jprojective_coordinates_GFp');
end;

function ERROR_EC_POINT_set_affine_coordinates(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates');
end;

function ERROR_EC_POINT_get_affine_coordinates(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates');
end;

function ERROR_EC_POINT_set_affine_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates_GFp');
end;

function ERROR_EC_POINT_get_affine_coordinates_GFp(const group: PEC_GROUP; const p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates_GFp');
end;

function ERROR_EC_POINT_set_compressed_coordinates(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates');
end;

function ERROR_EC_POINT_set_compressed_coordinates_GFp(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates_GFp');
end;

function ERROR_EC_POINT_set_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; const y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_affine_coordinates_GF2m');
end;

function ERROR_EC_POINT_get_affine_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; x: PBIGNUM; y: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_get_affine_coordinates_GF2m');
end;

function ERROR_EC_POINT_set_compressed_coordinates_GF2m(const group: PEC_GROUP; p: PEC_POINT; const x: PBIGNUM; y_bit: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_set_compressed_coordinates_GF2m');
end;

function ERROR_EC_POINT_point2oct(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2oct');
end;

function ERROR_EC_POINT_oct2point(const group: PEC_GROUP; p: PEC_POINT; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_oct2point');
end;

function ERROR_EC_POINT_point2buf(const group: PEC_GROUP; const point: PEC_POINT; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2buf');
end;

function ERROR_EC_POINT_point2bn(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; bn: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2bn');
end;

function ERROR_EC_POINT_bn2point(const group: PEC_GROUP; const bn: PBIGNUM; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_bn2point');
end;

function ERROR_EC_POINT_point2hex(const group: PEC_GROUP; const p: PEC_POINT; form: point_conversion_form_t; ctx: PBN_CTX): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_point2hex');
end;

function ERROR_EC_POINT_hex2point(const group: PEC_GROUP; const buf: PAnsiChar; p: PEC_POINT; ctx: PBN_CTX): PEC_POINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_hex2point');
end;

function ERROR_EC_POINT_add(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_add');
end;

function ERROR_EC_POINT_dbl(const group: PEC_GROUP; r: PEC_POINT; const a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_dbl');
end;

function ERROR_EC_POINT_invert(const group: PEC_GROUP; a: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_invert');
end;

function ERROR_EC_POINT_is_at_infinity(const group: PEC_GROUP; const p: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_is_at_infinity');
end;

function ERROR_EC_POINT_is_on_curve(const group: PEC_GROUP; const point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_is_on_curve');
end;

function ERROR_EC_POINT_cmp(const group: PEC_GROUP; const a: PEC_POINT; const b: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_cmp');
end;

function ERROR_EC_POINT_make_affine(const group: PEC_GROUP; point: PEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_make_affine');
end;

function ERROR_EC_POINTs_make_affine(const group: PEC_METHOD; num: TOpenSSL_C_SIZET; points: PPEC_POINT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINTs_make_affine');
end;

function ERROR_EC_POINTs_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; num: TOpenSSL_C_SIZET; const p: PPEC_POINT; const m: PPBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINTs_mul');
end;

function ERROR_EC_POINT_mul(const group: PEC_GROUP; r: PEC_POINT; const n: PBIGNUM; const q: PEC_POINT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_POINT_mul');
end;

function ERROR_EC_GROUP_precompute_mult(group: PEC_GROUP; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_precompute_mult');
end;

function ERROR_EC_GROUP_have_precompute_mult(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_have_precompute_mult');
end;

function ERROR_ECPKPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_it');
end;

function ERROR_ECPKPARAMETERS_new: PECPKPARAMETERS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_new');
end;

procedure ERROR_ECPKPARAMETERS_free(a: PECPKPARAMETERS); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKPARAMETERS_free');
end;

function ERROR_ECPARAMETERS_it: PASN1_ITEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_it');
end;

function ERROR_ECPARAMETERS_new: PECPARAMETERS; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_new');
end;

procedure ERROR_ECPARAMETERS_free(a: PECPARAMETERS); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECPARAMETERS_free');
end;

function ERROR_EC_GROUP_get_basis_type(const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_basis_type');
end;

function ERROR_EC_GROUP_get_trinomial_basis(const group: PEC_GROUP; k: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_trinomial_basis');
end;

function ERROR_EC_GROUP_get_pentanomial_basis(const group: PEC_GROUP; k1: POpenSSL_C_UINT; k2: POpenSSL_C_UINT; k3: POpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_GROUP_get_pentanomial_basis');
end;

function ERROR_d2i_ECPKParameters(group: PPEC_GROUP; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPKParameters');
end;

function ERROR_i2d_ECPKParameters(const group: PEC_GROUP; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPKParameters');
end;

function ERROR_ECPKParameters_print(bp: PBIO; const x: PEC_GROUP; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECPKParameters_print');
end;

function ERROR_EC_KEY_new: PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new');
end;

function ERROR_EC_KEY_get_flags(const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_flags');
end;

procedure ERROR_EC_KEY_set_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_flags');
end;

procedure ERROR_EC_KEY_clear_flags(key: PEC_KEY; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_clear_flags');
end;

function ERROR_EC_KEY_new_by_curve_name(nid: TOpenSSL_C_INT): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_by_curve_name');
end;

procedure ERROR_EC_KEY_free(key: PEC_KEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_free');
end;

function ERROR_EC_KEY_copy(dst: PEC_KEY; const src: PEC_KEY): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_copy');
end;

function ERROR_EC_KEY_dup(const src: PEC_KEY): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_dup');
end;

function ERROR_EC_KEY_up_ref(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_up_ref');
end;

function ERROR_EC_KEY_get0_engine(const eckey: PEC_KEY): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_engine');
end;

function ERROR_EC_KEY_get0_group(const key: PEC_KEY): PEC_GROUP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_group');
end;

function ERROR_EC_KEY_set_group(key: PEC_KEY; const group: PEC_GROUP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_group');
end;

function ERROR_EC_KEY_get0_private_key(const key: PEC_KEY): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_private_key');
end;

function ERROR_EC_KEY_set_private_key(const key: PEC_KEY; const prv: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_private_key');
end;

function ERROR_EC_KEY_get0_public_key(const key: PEC_KEY): PEC_POINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get0_public_key');
end;

function ERROR_EC_KEY_set_public_key(key: PEC_KEY; const pub: PEC_POINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_public_key');
end;

function ERROR_EC_KEY_get_enc_flags(const key: PEC_KEY): TOpenSSL_C_UINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_enc_flags');
end;

procedure ERROR_EC_KEY_set_enc_flags(eckey: PEC_KEY; flags: TOpenSSL_C_UINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_enc_flags');
end;

function ERROR_EC_KEY_get_conv_form(const key: PEC_KEY): point_conversion_form_t; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_conv_form');
end;

procedure ERROR_EC_KEY_set_conv_form(eckey: PEC_KEY; cform: point_conversion_form_t); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_conv_form');
end;

function ERROR_EC_KEY_set_ex_data(key: PEC_KEY; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_ex_data');
end;

function ERROR_EC_KEY_get_ex_data(const key: PEC_KEY; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_ex_data');
end;

procedure ERROR_EC_KEY_set_asn1_flag(eckey: PEC_KEY; asn1_flag: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_asn1_flag');
end;

function ERROR_EC_KEY_precompute_mult(key: PEC_KEY; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_precompute_mult');
end;

function ERROR_EC_KEY_generate_key(key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_generate_key');
end;

function ERROR_EC_KEY_check_key(const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_check_key');
end;

function ERROR_EC_KEY_can_sign(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_can_sign');
end;

function ERROR_EC_KEY_set_public_key_affine_coordinates(key: PEC_KEY; x: PBIGNUM; y: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_public_key_affine_coordinates');
end;

function ERROR_EC_KEY_key2buf(const key: PEC_KEY; form: point_conversion_form_t; pbuf: PPByte; ctx: PBN_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_key2buf');
end;

function ERROR_EC_KEY_oct2key(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_oct2key');
end;

function ERROR_EC_KEY_oct2priv(key: PEC_KEY; const buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_oct2priv');
end;

function ERROR_EC_KEY_priv2oct(const key: PEC_KEY; buf: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_priv2oct');
end;

function ERROR_EC_KEY_priv2buf(const eckey: PEC_KEY; buf: PPByte): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_priv2buf');
end;

function ERROR_d2i_ECPrivateKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECPrivateKey');
end;

function ERROR_i2d_ECPrivateKey(key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECPrivateKey');
end;

function ERROR_o2i_ECPublicKey(key: PPEC_KEY; const in_: PPByte; len: TOpenSSL_C_LONG): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('o2i_ECPublicKey');
end;

function ERROR_i2o_ECPublicKey(const key: PEC_KEY; out_: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2o_ECPublicKey');
end;

function ERROR_ECParameters_print(bp: PBIO; const key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECParameters_print');
end;

function ERROR_EC_KEY_print(bp: PBIO; const key: PEC_KEY; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_print');
end;

function ERROR_EC_KEY_OpenSSL: PEC_KEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_OpenSSL');
end;

function ERROR_EC_KEY_get_default_method: PEC_KEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_default_method');
end;

procedure ERROR_EC_KEY_set_default_method(const meth: PEC_KEY_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_default_method');
end;

function ERROR_EC_KEY_get_method(const key: PEC_KEY): PEC_KEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_get_method');
end;

function ERROR_EC_KEY_set_method(key: PEC_KEY; const meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_set_method');
end;

function ERROR_EC_KEY_new_method(engine: PENGINE): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_new_method');
end;

function ERROR_ECDH_KDF_X9_62(out_: PByte; outlen: TOpenSSL_C_SIZET; const Z: PByte; Zlen: TOpenSSL_C_SIZET; const sinfo: PByte; sinfolen: TOpenSSL_C_SIZET; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDH_KDF_X9_62');
end;

function ERROR_ECDH_compute_key(out_: Pointer; oulen: TOpenSSL_C_SIZET; const pub_key: PEC_POINT; const ecdh: PEC_KEY; kdf: ECDH_compute_key_KDF): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDH_compute_key');
end;

function ERROR_ECDSA_SIG_new: PECDSA_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_new');
end;

procedure ERROR_ECDSA_SIG_free(sig: PECDSA_SIG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_free');
end;

function ERROR_i2d_ECDSA_SIG(const sig: PECDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ECDSA_SIG');
end;

function ERROR_d2i_ECDSA_SIG(sig: PPECDSA_SIG; const pp: PPByte; len: TOpenSSL_C_LONG): PECDSA_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ECDSA_SIG');
end;

procedure ERROR_ECDSA_SIG_get0(const sig: PECDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0');
end;

function ERROR_ECDSA_SIG_get0_r(const sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0_r');
end;

function ERROR_ECDSA_SIG_get0_s(const sig: PECDSA_SIG): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_get0_s');
end;

function ERROR_ECDSA_SIG_set0(sig: PECDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_SIG_set0');
end;

function ERROR_ECDSA_do_sign(const dgst: PByte; dgst_len: TOpenSSL_C_INT; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_sign');
end;

function ERROR_ECDSA_do_sign_ex(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): PECDSA_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_sign_ex');
end;

function ERROR_ECDSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sig: PECDSA_SIG; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_do_verify');
end;

function ERROR_ECDSA_sign_setup(eckey: PEC_KEY; ctx: PBN_CTX; kiv: PPBIGNUM; rp: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign_setup');
end;

function ERROR_ECDSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign');
end;

function ERROR_ECDSA_sign_ex(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; const kinv: PBIGNUM; const rp: PBIGNUM; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_sign_ex');
end;

function ERROR_ECDSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgstlen: TOpenSSL_C_INT; const sig: PByte; siglen: TOpenSSL_C_INT; eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_verify');
end;

function ERROR_ECDSA_size(const eckey: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ECDSA_size');
end;

function ERROR_EC_KEY_METHOD_new(const meth: PEC_KEY_METHOD): PEC_KEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_new');
end;

procedure ERROR_EC_KEY_METHOD_free(meth: PEC_KEY_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_free');
end;

procedure ERROR_EC_KEY_METHOD_set_init(meth: PEC_KEY_METHOD; init: EC_KEY_METHOD_init_init; finish: EC_KEY_METHOD_init_finish; copy: EC_KEY_METHOD_init_copy; set_group: EC_KEY_METHOD_init_set_group; set_private: EC_KEY_METHOD_init_set_private; set_public: EC_KEY_METHOD_init_set_public); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_init');
end;

procedure ERROR_EC_KEY_METHOD_set_keygen(meth: PEC_KEY_METHOD; keygen: EC_KEY_METHOD_keygen_keygen); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_keygen');
end;

procedure ERROR_EC_KEY_METHOD_set_compute_key(meth: PEC_KEY_METHOD; ckey: EC_KEY_METHOD_compute_key_ckey); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_compute_key');
end;

procedure ERROR_EC_KEY_METHOD_set_sign(meth: PEC_KEY_METHOD; sign: EC_KEY_METHOD_sign_sign; sign_setup: EC_KEY_METHOD_sign_sign_setup; sign_sig: EC_KEY_METHOD_sign_sign_sig); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_sign');
end;

procedure ERROR_EC_KEY_METHOD_set_verify(meth: PEC_KEY_METHOD; verify: EC_KEY_METHOD_verify_verify; verify_sig: EC_KEY_METHOD_verify_verify_sig); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_set_verify');
end;

procedure ERROR_EC_KEY_METHOD_get_init(const meth: PEC_KEY_METHOD; pinit: PEC_KEY_METHOD_init_init; pfinish: PEC_KEY_METHOD_init_finish; pcopy: PEC_KEY_METHOD_init_copy; pset_group: PEC_KEY_METHOD_init_set_group; pset_private: PEC_KEY_METHOD_init_set_private; pset_public: PEC_KEY_METHOD_init_set_public); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_init');
end;

procedure ERROR_EC_KEY_METHOD_get_keygen(const meth: PEC_KEY_METHOD; pkeygen: PEC_KEY_METHOD_keygen_keygen); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_keygen');
end;

procedure ERROR_EC_KEY_METHOD_get_compute_key(const meth: PEC_KEY_METHOD; pck: PEC_KEY_METHOD_compute_key_ckey); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_compute_key');
end;

procedure ERROR_EC_KEY_METHOD_get_sign(const meth: PEC_KEY_METHOD; psign: PEC_KEY_METHOD_sign_sign; psign_setup: PEC_KEY_METHOD_sign_sign_setup; psign_sig: PEC_KEY_METHOD_sign_sign_sig); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_sign');
end;

procedure ERROR_EC_KEY_METHOD_get_verify(const meth: PEC_KEY_METHOD; pverify: PEC_KEY_METHOD_verify_verify; pverify_sig: PEC_KEY_METHOD_verify_verify_sig); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EC_KEY_METHOD_get_verify');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  EC_GFp_simple_method := LoadLibCryptoFunction('EC_GFp_simple_method');
  FuncLoadError := not assigned(EC_GFp_simple_method);
  if FuncLoadError then
  begin
    EC_GFp_simple_method :=  @ERROR_EC_GFp_simple_method;
  end;

  EC_GFp_mont_method := LoadLibCryptoFunction('EC_GFp_mont_method');
  FuncLoadError := not assigned(EC_GFp_mont_method);
  if FuncLoadError then
  begin
    EC_GFp_mont_method :=  @ERROR_EC_GFp_mont_method;
  end;

  EC_GFp_nist_method := LoadLibCryptoFunction('EC_GFp_nist_method');
  FuncLoadError := not assigned(EC_GFp_nist_method);
  if FuncLoadError then
  begin
    EC_GFp_nist_method :=  @ERROR_EC_GFp_nist_method;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EC_GFp_nistp224_method := LoadLibCryptoFunction('EC_GFp_nistp224_method');
  FuncLoadError := not assigned(EC_GFp_nistp224_method);
  if FuncLoadError then
  begin
    if EC_GFp_nistp224_method_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EC_GFp_nistp224_method');
  end;

  EC_GFp_nistp256_method := LoadLibCryptoFunction('EC_GFp_nistp256_method');
  FuncLoadError := not assigned(EC_GFp_nistp256_method);
  if FuncLoadError then
  begin
    if EC_GFp_nistp256_method_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EC_GFp_nistp256_method');
  end;

  EC_GFp_nistp521_method := LoadLibCryptoFunction('EC_GFp_nistp521_method');
  FuncLoadError := not assigned(EC_GFp_nistp521_method);
  if FuncLoadError then
  begin
    if EC_GFp_nistp521_method_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EC_GFp_nistp521_method');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EC_GF2m_simple_method := LoadLibCryptoFunction('EC_GF2m_simple_method');
  FuncLoadError := not assigned(EC_GF2m_simple_method);
  if FuncLoadError then
  begin
    EC_GF2m_simple_method :=  @ERROR_EC_GF2m_simple_method;
  end;

  EC_GROUP_new := LoadLibCryptoFunction('EC_GROUP_new');
  FuncLoadError := not assigned(EC_GROUP_new);
  if FuncLoadError then
  begin
    EC_GROUP_new :=  @ERROR_EC_GROUP_new;
  end;

  EC_GROUP_free := LoadLibCryptoFunction('EC_GROUP_free');
  FuncLoadError := not assigned(EC_GROUP_free);
  if FuncLoadError then
  begin
    EC_GROUP_free :=  @ERROR_EC_GROUP_free;
  end;

  EC_GROUP_clear_free := LoadLibCryptoFunction('EC_GROUP_clear_free');
  FuncLoadError := not assigned(EC_GROUP_clear_free);
  if FuncLoadError then
  begin
    EC_GROUP_clear_free :=  @ERROR_EC_GROUP_clear_free;
  end;

  EC_GROUP_copy := LoadLibCryptoFunction('EC_GROUP_copy');
  FuncLoadError := not assigned(EC_GROUP_copy);
  if FuncLoadError then
  begin
    EC_GROUP_copy :=  @ERROR_EC_GROUP_copy;
  end;

  EC_GROUP_dup := LoadLibCryptoFunction('EC_GROUP_dup');
  FuncLoadError := not assigned(EC_GROUP_dup);
  if FuncLoadError then
  begin
    EC_GROUP_dup :=  @ERROR_EC_GROUP_dup;
  end;

  EC_GROUP_method_of := LoadLibCryptoFunction('EC_GROUP_method_of');
  FuncLoadError := not assigned(EC_GROUP_method_of);
  if FuncLoadError then
  begin
    EC_GROUP_method_of :=  @ERROR_EC_GROUP_method_of;
  end;

  EC_METHOD_get_field_type := LoadLibCryptoFunction('EC_METHOD_get_field_type');
  FuncLoadError := not assigned(EC_METHOD_get_field_type);
  if FuncLoadError then
  begin
    EC_METHOD_get_field_type :=  @ERROR_EC_METHOD_get_field_type;
  end;

  EC_GROUP_set_generator := LoadLibCryptoFunction('EC_GROUP_set_generator');
  FuncLoadError := not assigned(EC_GROUP_set_generator);
  if FuncLoadError then
  begin
    EC_GROUP_set_generator :=  @ERROR_EC_GROUP_set_generator;
  end;

  EC_GROUP_get0_generator := LoadLibCryptoFunction('EC_GROUP_get0_generator');
  FuncLoadError := not assigned(EC_GROUP_get0_generator);
  if FuncLoadError then
  begin
    EC_GROUP_get0_generator :=  @ERROR_EC_GROUP_get0_generator;
  end;

  EC_GROUP_get_mont_data := LoadLibCryptoFunction('EC_GROUP_get_mont_data');
  FuncLoadError := not assigned(EC_GROUP_get_mont_data);
  if FuncLoadError then
  begin
    EC_GROUP_get_mont_data :=  @ERROR_EC_GROUP_get_mont_data;
  end;

  EC_GROUP_get_order := LoadLibCryptoFunction('EC_GROUP_get_order');
  FuncLoadError := not assigned(EC_GROUP_get_order);
  if FuncLoadError then
  begin
    EC_GROUP_get_order :=  @ERROR_EC_GROUP_get_order;
  end;

  EC_GROUP_get0_order := LoadLibCryptoFunction('EC_GROUP_get0_order');
  FuncLoadError := not assigned(EC_GROUP_get0_order);
  if FuncLoadError then
  begin
    EC_GROUP_get0_order :=  @ERROR_EC_GROUP_get0_order;
  end;

  EC_GROUP_order_bits := LoadLibCryptoFunction('EC_GROUP_order_bits');
  FuncLoadError := not assigned(EC_GROUP_order_bits);
  if FuncLoadError then
  begin
    EC_GROUP_order_bits :=  @ERROR_EC_GROUP_order_bits;
  end;

  EC_GROUP_get_cofactor := LoadLibCryptoFunction('EC_GROUP_get_cofactor');
  FuncLoadError := not assigned(EC_GROUP_get_cofactor);
  if FuncLoadError then
  begin
    EC_GROUP_get_cofactor :=  @ERROR_EC_GROUP_get_cofactor;
  end;

  EC_GROUP_get0_cofactor := LoadLibCryptoFunction('EC_GROUP_get0_cofactor');
  FuncLoadError := not assigned(EC_GROUP_get0_cofactor);
  if FuncLoadError then
  begin
    EC_GROUP_get0_cofactor :=  @ERROR_EC_GROUP_get0_cofactor;
  end;

  EC_GROUP_set_curve_name := LoadLibCryptoFunction('EC_GROUP_set_curve_name');
  FuncLoadError := not assigned(EC_GROUP_set_curve_name);
  if FuncLoadError then
  begin
    EC_GROUP_set_curve_name :=  @ERROR_EC_GROUP_set_curve_name;
  end;

  EC_GROUP_get_curve_name := LoadLibCryptoFunction('EC_GROUP_get_curve_name');
  FuncLoadError := not assigned(EC_GROUP_get_curve_name);
  if FuncLoadError then
  begin
    EC_GROUP_get_curve_name :=  @ERROR_EC_GROUP_get_curve_name;
  end;

  EC_GROUP_set_asn1_flag := LoadLibCryptoFunction('EC_GROUP_set_asn1_flag');
  FuncLoadError := not assigned(EC_GROUP_set_asn1_flag);
  if FuncLoadError then
  begin
    EC_GROUP_set_asn1_flag :=  @ERROR_EC_GROUP_set_asn1_flag;
  end;

  EC_GROUP_get_asn1_flag := LoadLibCryptoFunction('EC_GROUP_get_asn1_flag');
  FuncLoadError := not assigned(EC_GROUP_get_asn1_flag);
  if FuncLoadError then
  begin
    EC_GROUP_get_asn1_flag :=  @ERROR_EC_GROUP_get_asn1_flag;
  end;

  EC_GROUP_set_point_conversion_form := LoadLibCryptoFunction('EC_GROUP_set_point_conversion_form');
  FuncLoadError := not assigned(EC_GROUP_set_point_conversion_form);
  if FuncLoadError then
  begin
    EC_GROUP_set_point_conversion_form :=  @ERROR_EC_GROUP_set_point_conversion_form;
  end;

  EC_GROUP_get_point_conversion_form := LoadLibCryptoFunction('EC_GROUP_get_point_conversion_form');
  FuncLoadError := not assigned(EC_GROUP_get_point_conversion_form);
  if FuncLoadError then
  begin
    EC_GROUP_get_point_conversion_form :=  @ERROR_EC_GROUP_get_point_conversion_form;
  end;

  EC_GROUP_get0_seed := LoadLibCryptoFunction('EC_GROUP_get0_seed');
  FuncLoadError := not assigned(EC_GROUP_get0_seed);
  if FuncLoadError then
  begin
    EC_GROUP_get0_seed :=  @ERROR_EC_GROUP_get0_seed;
  end;

  EC_GROUP_get_seed_len := LoadLibCryptoFunction('EC_GROUP_get_seed_len');
  FuncLoadError := not assigned(EC_GROUP_get_seed_len);
  if FuncLoadError then
  begin
    EC_GROUP_get_seed_len :=  @ERROR_EC_GROUP_get_seed_len;
  end;

  EC_GROUP_set_seed := LoadLibCryptoFunction('EC_GROUP_set_seed');
  FuncLoadError := not assigned(EC_GROUP_set_seed);
  if FuncLoadError then
  begin
    EC_GROUP_set_seed :=  @ERROR_EC_GROUP_set_seed;
  end;

  EC_GROUP_set_curve := LoadLibCryptoFunction('EC_GROUP_set_curve');
  FuncLoadError := not assigned(EC_GROUP_set_curve);
  if FuncLoadError then
  begin
    EC_GROUP_set_curve :=  @ERROR_EC_GROUP_set_curve;
  end;

  EC_GROUP_get_curve := LoadLibCryptoFunction('EC_GROUP_get_curve');
  FuncLoadError := not assigned(EC_GROUP_get_curve);
  if FuncLoadError then
  begin
    EC_GROUP_get_curve :=  @ERROR_EC_GROUP_get_curve;
  end;

  EC_GROUP_set_curve_GFp := LoadLibCryptoFunction('EC_GROUP_set_curve_GFp');
  FuncLoadError := not assigned(EC_GROUP_set_curve_GFp);
  if FuncLoadError then
  begin
    EC_GROUP_set_curve_GFp :=  @ERROR_EC_GROUP_set_curve_GFp;
  end;

  EC_GROUP_get_curve_GFp := LoadLibCryptoFunction('EC_GROUP_get_curve_GFp');
  FuncLoadError := not assigned(EC_GROUP_get_curve_GFp);
  if FuncLoadError then
  begin
    EC_GROUP_get_curve_GFp :=  @ERROR_EC_GROUP_get_curve_GFp;
  end;

  EC_GROUP_set_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_set_curve_GF2m');
  FuncLoadError := not assigned(EC_GROUP_set_curve_GF2m);
  if FuncLoadError then
  begin
    EC_GROUP_set_curve_GF2m :=  @ERROR_EC_GROUP_set_curve_GF2m;
  end;

  EC_GROUP_get_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_get_curve_GF2m');
  FuncLoadError := not assigned(EC_GROUP_get_curve_GF2m);
  if FuncLoadError then
  begin
    EC_GROUP_get_curve_GF2m :=  @ERROR_EC_GROUP_get_curve_GF2m;
  end;

  EC_GROUP_get_degree := LoadLibCryptoFunction('EC_GROUP_get_degree');
  FuncLoadError := not assigned(EC_GROUP_get_degree);
  if FuncLoadError then
  begin
    EC_GROUP_get_degree :=  @ERROR_EC_GROUP_get_degree;
  end;

  EC_GROUP_check := LoadLibCryptoFunction('EC_GROUP_check');
  FuncLoadError := not assigned(EC_GROUP_check);
  if FuncLoadError then
  begin
    EC_GROUP_check :=  @ERROR_EC_GROUP_check;
  end;

  EC_GROUP_check_discriminant := LoadLibCryptoFunction('EC_GROUP_check_discriminant');
  FuncLoadError := not assigned(EC_GROUP_check_discriminant);
  if FuncLoadError then
  begin
    EC_GROUP_check_discriminant :=  @ERROR_EC_GROUP_check_discriminant;
  end;

  EC_GROUP_cmp := LoadLibCryptoFunction('EC_GROUP_cmp');
  FuncLoadError := not assigned(EC_GROUP_cmp);
  if FuncLoadError then
  begin
    EC_GROUP_cmp :=  @ERROR_EC_GROUP_cmp;
  end;

  EC_GROUP_new_curve_GFp := LoadLibCryptoFunction('EC_GROUP_new_curve_GFp');
  FuncLoadError := not assigned(EC_GROUP_new_curve_GFp);
  if FuncLoadError then
  begin
    EC_GROUP_new_curve_GFp :=  @ERROR_EC_GROUP_new_curve_GFp;
  end;

  EC_GROUP_new_curve_GF2m := LoadLibCryptoFunction('EC_GROUP_new_curve_GF2m');
  FuncLoadError := not assigned(EC_GROUP_new_curve_GF2m);
  if FuncLoadError then
  begin
    EC_GROUP_new_curve_GF2m :=  @ERROR_EC_GROUP_new_curve_GF2m;
  end;

  EC_GROUP_new_by_curve_name := LoadLibCryptoFunction('EC_GROUP_new_by_curve_name');
  FuncLoadError := not assigned(EC_GROUP_new_by_curve_name);
  if FuncLoadError then
  begin
    EC_GROUP_new_by_curve_name :=  @ERROR_EC_GROUP_new_by_curve_name;
  end;

  EC_GROUP_new_from_ecparameters := LoadLibCryptoFunction('EC_GROUP_new_from_ecparameters');
  FuncLoadError := not assigned(EC_GROUP_new_from_ecparameters);
  if FuncLoadError then
  begin
    EC_GROUP_new_from_ecparameters :=  @ERROR_EC_GROUP_new_from_ecparameters;
  end;

  EC_GROUP_get_ecparameters := LoadLibCryptoFunction('EC_GROUP_get_ecparameters');
  FuncLoadError := not assigned(EC_GROUP_get_ecparameters);
  if FuncLoadError then
  begin
    EC_GROUP_get_ecparameters :=  @ERROR_EC_GROUP_get_ecparameters;
  end;

  EC_GROUP_new_from_ecpkparameters := LoadLibCryptoFunction('EC_GROUP_new_from_ecpkparameters');
  FuncLoadError := not assigned(EC_GROUP_new_from_ecpkparameters);
  if FuncLoadError then
  begin
    EC_GROUP_new_from_ecpkparameters :=  @ERROR_EC_GROUP_new_from_ecpkparameters;
  end;

  EC_GROUP_get_ecpkparameters := LoadLibCryptoFunction('EC_GROUP_get_ecpkparameters');
  FuncLoadError := not assigned(EC_GROUP_get_ecpkparameters);
  if FuncLoadError then
  begin
    EC_GROUP_get_ecpkparameters :=  @ERROR_EC_GROUP_get_ecpkparameters;
  end;

  EC_get_builtin_curves := LoadLibCryptoFunction('EC_get_builtin_curves');
  FuncLoadError := not assigned(EC_get_builtin_curves);
  if FuncLoadError then
  begin
    EC_get_builtin_curves :=  @ERROR_EC_get_builtin_curves;
  end;

  EC_curve_nid2nist := LoadLibCryptoFunction('EC_curve_nid2nist');
  FuncLoadError := not assigned(EC_curve_nid2nist);
  if FuncLoadError then
  begin
    EC_curve_nid2nist :=  @ERROR_EC_curve_nid2nist;
  end;

  EC_curve_nist2nid := LoadLibCryptoFunction('EC_curve_nist2nid');
  FuncLoadError := not assigned(EC_curve_nist2nid);
  if FuncLoadError then
  begin
    EC_curve_nist2nid :=  @ERROR_EC_curve_nist2nid;
  end;

  EC_POINT_new := LoadLibCryptoFunction('EC_POINT_new');
  FuncLoadError := not assigned(EC_POINT_new);
  if FuncLoadError then
  begin
    EC_POINT_new :=  @ERROR_EC_POINT_new;
  end;

  EC_POINT_free := LoadLibCryptoFunction('EC_POINT_free');
  FuncLoadError := not assigned(EC_POINT_free);
  if FuncLoadError then
  begin
    EC_POINT_free :=  @ERROR_EC_POINT_free;
  end;

  EC_POINT_clear_free := LoadLibCryptoFunction('EC_POINT_clear_free');
  FuncLoadError := not assigned(EC_POINT_clear_free);
  if FuncLoadError then
  begin
    EC_POINT_clear_free :=  @ERROR_EC_POINT_clear_free;
  end;

  EC_POINT_copy := LoadLibCryptoFunction('EC_POINT_copy');
  FuncLoadError := not assigned(EC_POINT_copy);
  if FuncLoadError then
  begin
    EC_POINT_copy :=  @ERROR_EC_POINT_copy;
  end;

  EC_POINT_dup := LoadLibCryptoFunction('EC_POINT_dup');
  FuncLoadError := not assigned(EC_POINT_dup);
  if FuncLoadError then
  begin
    EC_POINT_dup :=  @ERROR_EC_POINT_dup;
  end;

  EC_POINT_method_of := LoadLibCryptoFunction('EC_POINT_method_of');
  FuncLoadError := not assigned(EC_POINT_method_of);
  if FuncLoadError then
  begin
    EC_POINT_method_of :=  @ERROR_EC_POINT_method_of;
  end;

  EC_POINT_set_to_infinity := LoadLibCryptoFunction('EC_POINT_set_to_infinity');
  FuncLoadError := not assigned(EC_POINT_set_to_infinity);
  if FuncLoadError then
  begin
    EC_POINT_set_to_infinity :=  @ERROR_EC_POINT_set_to_infinity;
  end;

  EC_POINT_set_Jprojective_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_Jprojective_coordinates_GFp');
  FuncLoadError := not assigned(EC_POINT_set_Jprojective_coordinates_GFp);
  if FuncLoadError then
  begin
    EC_POINT_set_Jprojective_coordinates_GFp :=  @ERROR_EC_POINT_set_Jprojective_coordinates_GFp;
  end;

  EC_POINT_get_Jprojective_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_get_Jprojective_coordinates_GFp');
  FuncLoadError := not assigned(EC_POINT_get_Jprojective_coordinates_GFp);
  if FuncLoadError then
  begin
    EC_POINT_get_Jprojective_coordinates_GFp :=  @ERROR_EC_POINT_get_Jprojective_coordinates_GFp;
  end;

  EC_POINT_set_affine_coordinates := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates');
  FuncLoadError := not assigned(EC_POINT_set_affine_coordinates);
  if FuncLoadError then
  begin
    EC_POINT_set_affine_coordinates :=  @ERROR_EC_POINT_set_affine_coordinates;
  end;

  EC_POINT_get_affine_coordinates := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates');
  FuncLoadError := not assigned(EC_POINT_get_affine_coordinates);
  if FuncLoadError then
  begin
    EC_POINT_get_affine_coordinates :=  @ERROR_EC_POINT_get_affine_coordinates;
  end;

  EC_POINT_set_affine_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates_GFp');
  FuncLoadError := not assigned(EC_POINT_set_affine_coordinates_GFp);
  if FuncLoadError then
  begin
    EC_POINT_set_affine_coordinates_GFp :=  @ERROR_EC_POINT_set_affine_coordinates_GFp;
  end;

  EC_POINT_get_affine_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates_GFp');
  FuncLoadError := not assigned(EC_POINT_get_affine_coordinates_GFp);
  if FuncLoadError then
  begin
    EC_POINT_get_affine_coordinates_GFp :=  @ERROR_EC_POINT_get_affine_coordinates_GFp;
  end;

  EC_POINT_set_compressed_coordinates := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates');
  FuncLoadError := not assigned(EC_POINT_set_compressed_coordinates);
  if FuncLoadError then
  begin
    EC_POINT_set_compressed_coordinates :=  @ERROR_EC_POINT_set_compressed_coordinates;
  end;

  EC_POINT_set_compressed_coordinates_GFp := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates_GFp');
  FuncLoadError := not assigned(EC_POINT_set_compressed_coordinates_GFp);
  if FuncLoadError then
  begin
    EC_POINT_set_compressed_coordinates_GFp :=  @ERROR_EC_POINT_set_compressed_coordinates_GFp;
  end;

  EC_POINT_set_affine_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_set_affine_coordinates_GF2m');
  FuncLoadError := not assigned(EC_POINT_set_affine_coordinates_GF2m);
  if FuncLoadError then
  begin
    EC_POINT_set_affine_coordinates_GF2m :=  @ERROR_EC_POINT_set_affine_coordinates_GF2m;
  end;

  EC_POINT_get_affine_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_get_affine_coordinates_GF2m');
  FuncLoadError := not assigned(EC_POINT_get_affine_coordinates_GF2m);
  if FuncLoadError then
  begin
    EC_POINT_get_affine_coordinates_GF2m :=  @ERROR_EC_POINT_get_affine_coordinates_GF2m;
  end;

  EC_POINT_set_compressed_coordinates_GF2m := LoadLibCryptoFunction('EC_POINT_set_compressed_coordinates_GF2m');
  FuncLoadError := not assigned(EC_POINT_set_compressed_coordinates_GF2m);
  if FuncLoadError then
  begin
    EC_POINT_set_compressed_coordinates_GF2m :=  @ERROR_EC_POINT_set_compressed_coordinates_GF2m;
  end;

  EC_POINT_point2oct := LoadLibCryptoFunction('EC_POINT_point2oct');
  FuncLoadError := not assigned(EC_POINT_point2oct);
  if FuncLoadError then
  begin
    EC_POINT_point2oct :=  @ERROR_EC_POINT_point2oct;
  end;

  EC_POINT_oct2point := LoadLibCryptoFunction('EC_POINT_oct2point');
  FuncLoadError := not assigned(EC_POINT_oct2point);
  if FuncLoadError then
  begin
    EC_POINT_oct2point :=  @ERROR_EC_POINT_oct2point;
  end;

  EC_POINT_point2buf := LoadLibCryptoFunction('EC_POINT_point2buf');
  FuncLoadError := not assigned(EC_POINT_point2buf);
  if FuncLoadError then
  begin
    EC_POINT_point2buf :=  @ERROR_EC_POINT_point2buf;
  end;

  EC_POINT_point2bn := LoadLibCryptoFunction('EC_POINT_point2bn');
  FuncLoadError := not assigned(EC_POINT_point2bn);
  if FuncLoadError then
  begin
    EC_POINT_point2bn :=  @ERROR_EC_POINT_point2bn;
  end;

  EC_POINT_bn2point := LoadLibCryptoFunction('EC_POINT_bn2point');
  FuncLoadError := not assigned(EC_POINT_bn2point);
  if FuncLoadError then
  begin
    EC_POINT_bn2point :=  @ERROR_EC_POINT_bn2point;
  end;

  EC_POINT_point2hex := LoadLibCryptoFunction('EC_POINT_point2hex');
  FuncLoadError := not assigned(EC_POINT_point2hex);
  if FuncLoadError then
  begin
    EC_POINT_point2hex :=  @ERROR_EC_POINT_point2hex;
  end;

  EC_POINT_hex2point := LoadLibCryptoFunction('EC_POINT_hex2point');
  FuncLoadError := not assigned(EC_POINT_hex2point);
  if FuncLoadError then
  begin
    EC_POINT_hex2point :=  @ERROR_EC_POINT_hex2point;
  end;

  EC_POINT_add := LoadLibCryptoFunction('EC_POINT_add');
  FuncLoadError := not assigned(EC_POINT_add);
  if FuncLoadError then
  begin
    EC_POINT_add :=  @ERROR_EC_POINT_add;
  end;

  EC_POINT_dbl := LoadLibCryptoFunction('EC_POINT_dbl');
  FuncLoadError := not assigned(EC_POINT_dbl);
  if FuncLoadError then
  begin
    EC_POINT_dbl :=  @ERROR_EC_POINT_dbl;
  end;

  EC_POINT_invert := LoadLibCryptoFunction('EC_POINT_invert');
  FuncLoadError := not assigned(EC_POINT_invert);
  if FuncLoadError then
  begin
    EC_POINT_invert :=  @ERROR_EC_POINT_invert;
  end;

  EC_POINT_is_at_infinity := LoadLibCryptoFunction('EC_POINT_is_at_infinity');
  FuncLoadError := not assigned(EC_POINT_is_at_infinity);
  if FuncLoadError then
  begin
    EC_POINT_is_at_infinity :=  @ERROR_EC_POINT_is_at_infinity;
  end;

  EC_POINT_is_on_curve := LoadLibCryptoFunction('EC_POINT_is_on_curve');
  FuncLoadError := not assigned(EC_POINT_is_on_curve);
  if FuncLoadError then
  begin
    EC_POINT_is_on_curve :=  @ERROR_EC_POINT_is_on_curve;
  end;

  EC_POINT_cmp := LoadLibCryptoFunction('EC_POINT_cmp');
  FuncLoadError := not assigned(EC_POINT_cmp);
  if FuncLoadError then
  begin
    EC_POINT_cmp :=  @ERROR_EC_POINT_cmp;
  end;

  EC_POINT_make_affine := LoadLibCryptoFunction('EC_POINT_make_affine');
  FuncLoadError := not assigned(EC_POINT_make_affine);
  if FuncLoadError then
  begin
    EC_POINT_make_affine :=  @ERROR_EC_POINT_make_affine;
  end;

  EC_POINTs_make_affine := LoadLibCryptoFunction('EC_POINTs_make_affine');
  FuncLoadError := not assigned(EC_POINTs_make_affine);
  if FuncLoadError then
  begin
    EC_POINTs_make_affine :=  @ERROR_EC_POINTs_make_affine;
  end;

  EC_POINTs_mul := LoadLibCryptoFunction('EC_POINTs_mul');
  FuncLoadError := not assigned(EC_POINTs_mul);
  if FuncLoadError then
  begin
    EC_POINTs_mul :=  @ERROR_EC_POINTs_mul;
  end;

  EC_POINT_mul := LoadLibCryptoFunction('EC_POINT_mul');
  FuncLoadError := not assigned(EC_POINT_mul);
  if FuncLoadError then
  begin
    EC_POINT_mul :=  @ERROR_EC_POINT_mul;
  end;

  EC_GROUP_precompute_mult := LoadLibCryptoFunction('EC_GROUP_precompute_mult');
  FuncLoadError := not assigned(EC_GROUP_precompute_mult);
  if FuncLoadError then
  begin
    EC_GROUP_precompute_mult :=  @ERROR_EC_GROUP_precompute_mult;
  end;

  EC_GROUP_have_precompute_mult := LoadLibCryptoFunction('EC_GROUP_have_precompute_mult');
  FuncLoadError := not assigned(EC_GROUP_have_precompute_mult);
  if FuncLoadError then
  begin
    EC_GROUP_have_precompute_mult :=  @ERROR_EC_GROUP_have_precompute_mult;
  end;

  ECPKPARAMETERS_it := LoadLibCryptoFunction('ECPKPARAMETERS_it');
  FuncLoadError := not assigned(ECPKPARAMETERS_it);
  if FuncLoadError then
  begin
    ECPKPARAMETERS_it :=  @ERROR_ECPKPARAMETERS_it;
  end;

  ECPKPARAMETERS_new := LoadLibCryptoFunction('ECPKPARAMETERS_new');
  FuncLoadError := not assigned(ECPKPARAMETERS_new);
  if FuncLoadError then
  begin
    ECPKPARAMETERS_new :=  @ERROR_ECPKPARAMETERS_new;
  end;

  ECPKPARAMETERS_free := LoadLibCryptoFunction('ECPKPARAMETERS_free');
  FuncLoadError := not assigned(ECPKPARAMETERS_free);
  if FuncLoadError then
  begin
    ECPKPARAMETERS_free :=  @ERROR_ECPKPARAMETERS_free;
  end;

  ECPARAMETERS_it := LoadLibCryptoFunction('ECPARAMETERS_it');
  FuncLoadError := not assigned(ECPARAMETERS_it);
  if FuncLoadError then
  begin
    ECPARAMETERS_it :=  @ERROR_ECPARAMETERS_it;
  end;

  ECPARAMETERS_new := LoadLibCryptoFunction('ECPARAMETERS_new');
  FuncLoadError := not assigned(ECPARAMETERS_new);
  if FuncLoadError then
  begin
    ECPARAMETERS_new :=  @ERROR_ECPARAMETERS_new;
  end;

  ECPARAMETERS_free := LoadLibCryptoFunction('ECPARAMETERS_free');
  FuncLoadError := not assigned(ECPARAMETERS_free);
  if FuncLoadError then
  begin
    ECPARAMETERS_free :=  @ERROR_ECPARAMETERS_free;
  end;

  EC_GROUP_get_basis_type := LoadLibCryptoFunction('EC_GROUP_get_basis_type');
  FuncLoadError := not assigned(EC_GROUP_get_basis_type);
  if FuncLoadError then
  begin
    EC_GROUP_get_basis_type :=  @ERROR_EC_GROUP_get_basis_type;
  end;

  EC_GROUP_get_trinomial_basis := LoadLibCryptoFunction('EC_GROUP_get_trinomial_basis');
  FuncLoadError := not assigned(EC_GROUP_get_trinomial_basis);
  if FuncLoadError then
  begin
    EC_GROUP_get_trinomial_basis :=  @ERROR_EC_GROUP_get_trinomial_basis;
  end;

  EC_GROUP_get_pentanomial_basis := LoadLibCryptoFunction('EC_GROUP_get_pentanomial_basis');
  FuncLoadError := not assigned(EC_GROUP_get_pentanomial_basis);
  if FuncLoadError then
  begin
    EC_GROUP_get_pentanomial_basis :=  @ERROR_EC_GROUP_get_pentanomial_basis;
  end;

  d2i_ECPKParameters := LoadLibCryptoFunction('d2i_ECPKParameters');
  FuncLoadError := not assigned(d2i_ECPKParameters);
  if FuncLoadError then
  begin
    d2i_ECPKParameters :=  @ERROR_d2i_ECPKParameters;
  end;

  i2d_ECPKParameters := LoadLibCryptoFunction('i2d_ECPKParameters');
  FuncLoadError := not assigned(i2d_ECPKParameters);
  if FuncLoadError then
  begin
    i2d_ECPKParameters :=  @ERROR_i2d_ECPKParameters;
  end;

  ECPKParameters_print := LoadLibCryptoFunction('ECPKParameters_print');
  FuncLoadError := not assigned(ECPKParameters_print);
  if FuncLoadError then
  begin
    ECPKParameters_print :=  @ERROR_ECPKParameters_print;
  end;

  EC_KEY_new := LoadLibCryptoFunction('EC_KEY_new');
  FuncLoadError := not assigned(EC_KEY_new);
  if FuncLoadError then
  begin
    EC_KEY_new :=  @ERROR_EC_KEY_new;
  end;

  EC_KEY_get_flags := LoadLibCryptoFunction('EC_KEY_get_flags');
  FuncLoadError := not assigned(EC_KEY_get_flags);
  if FuncLoadError then
  begin
    EC_KEY_get_flags :=  @ERROR_EC_KEY_get_flags;
  end;

  EC_KEY_set_flags := LoadLibCryptoFunction('EC_KEY_set_flags');
  FuncLoadError := not assigned(EC_KEY_set_flags);
  if FuncLoadError then
  begin
    EC_KEY_set_flags :=  @ERROR_EC_KEY_set_flags;
  end;

  EC_KEY_clear_flags := LoadLibCryptoFunction('EC_KEY_clear_flags');
  FuncLoadError := not assigned(EC_KEY_clear_flags);
  if FuncLoadError then
  begin
    EC_KEY_clear_flags :=  @ERROR_EC_KEY_clear_flags;
  end;

  EC_KEY_new_by_curve_name := LoadLibCryptoFunction('EC_KEY_new_by_curve_name');
  FuncLoadError := not assigned(EC_KEY_new_by_curve_name);
  if FuncLoadError then
  begin
    EC_KEY_new_by_curve_name :=  @ERROR_EC_KEY_new_by_curve_name;
  end;

  EC_KEY_free := LoadLibCryptoFunction('EC_KEY_free');
  FuncLoadError := not assigned(EC_KEY_free);
  if FuncLoadError then
  begin
    EC_KEY_free :=  @ERROR_EC_KEY_free;
  end;

  EC_KEY_copy := LoadLibCryptoFunction('EC_KEY_copy');
  FuncLoadError := not assigned(EC_KEY_copy);
  if FuncLoadError then
  begin
    EC_KEY_copy :=  @ERROR_EC_KEY_copy;
  end;

  EC_KEY_dup := LoadLibCryptoFunction('EC_KEY_dup');
  FuncLoadError := not assigned(EC_KEY_dup);
  if FuncLoadError then
  begin
    EC_KEY_dup :=  @ERROR_EC_KEY_dup;
  end;

  EC_KEY_up_ref := LoadLibCryptoFunction('EC_KEY_up_ref');
  FuncLoadError := not assigned(EC_KEY_up_ref);
  if FuncLoadError then
  begin
    EC_KEY_up_ref :=  @ERROR_EC_KEY_up_ref;
  end;

  EC_KEY_get0_engine := LoadLibCryptoFunction('EC_KEY_get0_engine');
  FuncLoadError := not assigned(EC_KEY_get0_engine);
  if FuncLoadError then
  begin
    EC_KEY_get0_engine :=  @ERROR_EC_KEY_get0_engine;
  end;

  EC_KEY_get0_group := LoadLibCryptoFunction('EC_KEY_get0_group');
  FuncLoadError := not assigned(EC_KEY_get0_group);
  if FuncLoadError then
  begin
    EC_KEY_get0_group :=  @ERROR_EC_KEY_get0_group;
  end;

  EC_KEY_set_group := LoadLibCryptoFunction('EC_KEY_set_group');
  FuncLoadError := not assigned(EC_KEY_set_group);
  if FuncLoadError then
  begin
    EC_KEY_set_group :=  @ERROR_EC_KEY_set_group;
  end;

  EC_KEY_get0_private_key := LoadLibCryptoFunction('EC_KEY_get0_private_key');
  FuncLoadError := not assigned(EC_KEY_get0_private_key);
  if FuncLoadError then
  begin
    EC_KEY_get0_private_key :=  @ERROR_EC_KEY_get0_private_key;
  end;

  EC_KEY_set_private_key := LoadLibCryptoFunction('EC_KEY_set_private_key');
  FuncLoadError := not assigned(EC_KEY_set_private_key);
  if FuncLoadError then
  begin
    EC_KEY_set_private_key :=  @ERROR_EC_KEY_set_private_key;
  end;

  EC_KEY_get0_public_key := LoadLibCryptoFunction('EC_KEY_get0_public_key');
  FuncLoadError := not assigned(EC_KEY_get0_public_key);
  if FuncLoadError then
  begin
    EC_KEY_get0_public_key :=  @ERROR_EC_KEY_get0_public_key;
  end;

  EC_KEY_set_public_key := LoadLibCryptoFunction('EC_KEY_set_public_key');
  FuncLoadError := not assigned(EC_KEY_set_public_key);
  if FuncLoadError then
  begin
    EC_KEY_set_public_key :=  @ERROR_EC_KEY_set_public_key;
  end;

  EC_KEY_get_enc_flags := LoadLibCryptoFunction('EC_KEY_get_enc_flags');
  FuncLoadError := not assigned(EC_KEY_get_enc_flags);
  if FuncLoadError then
  begin
    EC_KEY_get_enc_flags :=  @ERROR_EC_KEY_get_enc_flags;
  end;

  EC_KEY_set_enc_flags := LoadLibCryptoFunction('EC_KEY_set_enc_flags');
  FuncLoadError := not assigned(EC_KEY_set_enc_flags);
  if FuncLoadError then
  begin
    EC_KEY_set_enc_flags :=  @ERROR_EC_KEY_set_enc_flags;
  end;

  EC_KEY_get_conv_form := LoadLibCryptoFunction('EC_KEY_get_conv_form');
  FuncLoadError := not assigned(EC_KEY_get_conv_form);
  if FuncLoadError then
  begin
    EC_KEY_get_conv_form :=  @ERROR_EC_KEY_get_conv_form;
  end;

  EC_KEY_set_conv_form := LoadLibCryptoFunction('EC_KEY_set_conv_form');
  FuncLoadError := not assigned(EC_KEY_set_conv_form);
  if FuncLoadError then
  begin
    EC_KEY_set_conv_form :=  @ERROR_EC_KEY_set_conv_form;
  end;

  EC_KEY_set_ex_data := LoadLibCryptoFunction('EC_KEY_set_ex_data');
  FuncLoadError := not assigned(EC_KEY_set_ex_data);
  if FuncLoadError then
  begin
    EC_KEY_set_ex_data :=  @ERROR_EC_KEY_set_ex_data;
  end;

  EC_KEY_get_ex_data := LoadLibCryptoFunction('EC_KEY_get_ex_data');
  FuncLoadError := not assigned(EC_KEY_get_ex_data);
  if FuncLoadError then
  begin
    EC_KEY_get_ex_data :=  @ERROR_EC_KEY_get_ex_data;
  end;

  EC_KEY_set_asn1_flag := LoadLibCryptoFunction('EC_KEY_set_asn1_flag');
  FuncLoadError := not assigned(EC_KEY_set_asn1_flag);
  if FuncLoadError then
  begin
    EC_KEY_set_asn1_flag :=  @ERROR_EC_KEY_set_asn1_flag;
  end;

  EC_KEY_precompute_mult := LoadLibCryptoFunction('EC_KEY_precompute_mult');
  FuncLoadError := not assigned(EC_KEY_precompute_mult);
  if FuncLoadError then
  begin
    EC_KEY_precompute_mult :=  @ERROR_EC_KEY_precompute_mult;
  end;

  EC_KEY_generate_key := LoadLibCryptoFunction('EC_KEY_generate_key');
  FuncLoadError := not assigned(EC_KEY_generate_key);
  if FuncLoadError then
  begin
    EC_KEY_generate_key :=  @ERROR_EC_KEY_generate_key;
  end;

  EC_KEY_check_key := LoadLibCryptoFunction('EC_KEY_check_key');
  FuncLoadError := not assigned(EC_KEY_check_key);
  if FuncLoadError then
  begin
    EC_KEY_check_key :=  @ERROR_EC_KEY_check_key;
  end;

  EC_KEY_can_sign := LoadLibCryptoFunction('EC_KEY_can_sign');
  FuncLoadError := not assigned(EC_KEY_can_sign);
  if FuncLoadError then
  begin
    EC_KEY_can_sign :=  @ERROR_EC_KEY_can_sign;
  end;

  EC_KEY_set_public_key_affine_coordinates := LoadLibCryptoFunction('EC_KEY_set_public_key_affine_coordinates');
  FuncLoadError := not assigned(EC_KEY_set_public_key_affine_coordinates);
  if FuncLoadError then
  begin
    EC_KEY_set_public_key_affine_coordinates :=  @ERROR_EC_KEY_set_public_key_affine_coordinates;
  end;

  EC_KEY_key2buf := LoadLibCryptoFunction('EC_KEY_key2buf');
  FuncLoadError := not assigned(EC_KEY_key2buf);
  if FuncLoadError then
  begin
    EC_KEY_key2buf :=  @ERROR_EC_KEY_key2buf;
  end;

  EC_KEY_oct2key := LoadLibCryptoFunction('EC_KEY_oct2key');
  FuncLoadError := not assigned(EC_KEY_oct2key);
  if FuncLoadError then
  begin
    EC_KEY_oct2key :=  @ERROR_EC_KEY_oct2key;
  end;

  EC_KEY_oct2priv := LoadLibCryptoFunction('EC_KEY_oct2priv');
  FuncLoadError := not assigned(EC_KEY_oct2priv);
  if FuncLoadError then
  begin
    EC_KEY_oct2priv :=  @ERROR_EC_KEY_oct2priv;
  end;

  EC_KEY_priv2oct := LoadLibCryptoFunction('EC_KEY_priv2oct');
  FuncLoadError := not assigned(EC_KEY_priv2oct);
  if FuncLoadError then
  begin
    EC_KEY_priv2oct :=  @ERROR_EC_KEY_priv2oct;
  end;

  EC_KEY_priv2buf := LoadLibCryptoFunction('EC_KEY_priv2buf');
  FuncLoadError := not assigned(EC_KEY_priv2buf);
  if FuncLoadError then
  begin
    EC_KEY_priv2buf :=  @ERROR_EC_KEY_priv2buf;
  end;

  d2i_ECPrivateKey := LoadLibCryptoFunction('d2i_ECPrivateKey');
  FuncLoadError := not assigned(d2i_ECPrivateKey);
  if FuncLoadError then
  begin
    d2i_ECPrivateKey :=  @ERROR_d2i_ECPrivateKey;
  end;

  i2d_ECPrivateKey := LoadLibCryptoFunction('i2d_ECPrivateKey');
  FuncLoadError := not assigned(i2d_ECPrivateKey);
  if FuncLoadError then
  begin
    i2d_ECPrivateKey :=  @ERROR_i2d_ECPrivateKey;
  end;

  o2i_ECPublicKey := LoadLibCryptoFunction('o2i_ECPublicKey');
  FuncLoadError := not assigned(o2i_ECPublicKey);
  if FuncLoadError then
  begin
    o2i_ECPublicKey :=  @ERROR_o2i_ECPublicKey;
  end;

  i2o_ECPublicKey := LoadLibCryptoFunction('i2o_ECPublicKey');
  FuncLoadError := not assigned(i2o_ECPublicKey);
  if FuncLoadError then
  begin
    i2o_ECPublicKey :=  @ERROR_i2o_ECPublicKey;
  end;

  ECParameters_print := LoadLibCryptoFunction('ECParameters_print');
  FuncLoadError := not assigned(ECParameters_print);
  if FuncLoadError then
  begin
    ECParameters_print :=  @ERROR_ECParameters_print;
  end;

  EC_KEY_print := LoadLibCryptoFunction('EC_KEY_print');
  FuncLoadError := not assigned(EC_KEY_print);
  if FuncLoadError then
  begin
    EC_KEY_print :=  @ERROR_EC_KEY_print;
  end;

  EC_KEY_OpenSSL := LoadLibCryptoFunction('EC_KEY_OpenSSL');
  FuncLoadError := not assigned(EC_KEY_OpenSSL);
  if FuncLoadError then
  begin
    EC_KEY_OpenSSL :=  @ERROR_EC_KEY_OpenSSL;
  end;

  EC_KEY_get_default_method := LoadLibCryptoFunction('EC_KEY_get_default_method');
  FuncLoadError := not assigned(EC_KEY_get_default_method);
  if FuncLoadError then
  begin
    EC_KEY_get_default_method :=  @ERROR_EC_KEY_get_default_method;
  end;

  EC_KEY_set_default_method := LoadLibCryptoFunction('EC_KEY_set_default_method');
  FuncLoadError := not assigned(EC_KEY_set_default_method);
  if FuncLoadError then
  begin
    EC_KEY_set_default_method :=  @ERROR_EC_KEY_set_default_method;
  end;

  EC_KEY_get_method := LoadLibCryptoFunction('EC_KEY_get_method');
  FuncLoadError := not assigned(EC_KEY_get_method);
  if FuncLoadError then
  begin
    EC_KEY_get_method :=  @ERROR_EC_KEY_get_method;
  end;

  EC_KEY_set_method := LoadLibCryptoFunction('EC_KEY_set_method');
  FuncLoadError := not assigned(EC_KEY_set_method);
  if FuncLoadError then
  begin
    EC_KEY_set_method :=  @ERROR_EC_KEY_set_method;
  end;

  EC_KEY_new_method := LoadLibCryptoFunction('EC_KEY_new_method');
  FuncLoadError := not assigned(EC_KEY_new_method);
  if FuncLoadError then
  begin
    EC_KEY_new_method :=  @ERROR_EC_KEY_new_method;
  end;

  ECDH_KDF_X9_62 := LoadLibCryptoFunction('ECDH_KDF_X9_62');
  FuncLoadError := not assigned(ECDH_KDF_X9_62);
  if FuncLoadError then
  begin
    ECDH_KDF_X9_62 :=  @ERROR_ECDH_KDF_X9_62;
  end;

  ECDH_compute_key := LoadLibCryptoFunction('ECDH_compute_key');
  FuncLoadError := not assigned(ECDH_compute_key);
  if FuncLoadError then
  begin
    ECDH_compute_key :=  @ERROR_ECDH_compute_key;
  end;

  ECDSA_SIG_new := LoadLibCryptoFunction('ECDSA_SIG_new');
  FuncLoadError := not assigned(ECDSA_SIG_new);
  if FuncLoadError then
  begin
    ECDSA_SIG_new :=  @ERROR_ECDSA_SIG_new;
  end;

  ECDSA_SIG_free := LoadLibCryptoFunction('ECDSA_SIG_free');
  FuncLoadError := not assigned(ECDSA_SIG_free);
  if FuncLoadError then
  begin
    ECDSA_SIG_free :=  @ERROR_ECDSA_SIG_free;
  end;

  i2d_ECDSA_SIG := LoadLibCryptoFunction('i2d_ECDSA_SIG');
  FuncLoadError := not assigned(i2d_ECDSA_SIG);
  if FuncLoadError then
  begin
    i2d_ECDSA_SIG :=  @ERROR_i2d_ECDSA_SIG;
  end;

  d2i_ECDSA_SIG := LoadLibCryptoFunction('d2i_ECDSA_SIG');
  FuncLoadError := not assigned(d2i_ECDSA_SIG);
  if FuncLoadError then
  begin
    d2i_ECDSA_SIG :=  @ERROR_d2i_ECDSA_SIG;
  end;

  ECDSA_SIG_get0 := LoadLibCryptoFunction('ECDSA_SIG_get0');
  FuncLoadError := not assigned(ECDSA_SIG_get0);
  if FuncLoadError then
  begin
    ECDSA_SIG_get0 :=  @ERROR_ECDSA_SIG_get0;
  end;

  ECDSA_SIG_get0_r := LoadLibCryptoFunction('ECDSA_SIG_get0_r');
  FuncLoadError := not assigned(ECDSA_SIG_get0_r);
  if FuncLoadError then
  begin
    ECDSA_SIG_get0_r :=  @ERROR_ECDSA_SIG_get0_r;
  end;

  ECDSA_SIG_get0_s := LoadLibCryptoFunction('ECDSA_SIG_get0_s');
  FuncLoadError := not assigned(ECDSA_SIG_get0_s);
  if FuncLoadError then
  begin
    ECDSA_SIG_get0_s :=  @ERROR_ECDSA_SIG_get0_s;
  end;

  ECDSA_SIG_set0 := LoadLibCryptoFunction('ECDSA_SIG_set0');
  FuncLoadError := not assigned(ECDSA_SIG_set0);
  if FuncLoadError then
  begin
    ECDSA_SIG_set0 :=  @ERROR_ECDSA_SIG_set0;
  end;

  ECDSA_do_sign := LoadLibCryptoFunction('ECDSA_do_sign');
  FuncLoadError := not assigned(ECDSA_do_sign);
  if FuncLoadError then
  begin
    ECDSA_do_sign :=  @ERROR_ECDSA_do_sign;
  end;

  ECDSA_do_sign_ex := LoadLibCryptoFunction('ECDSA_do_sign_ex');
  FuncLoadError := not assigned(ECDSA_do_sign_ex);
  if FuncLoadError then
  begin
    ECDSA_do_sign_ex :=  @ERROR_ECDSA_do_sign_ex;
  end;

  ECDSA_do_verify := LoadLibCryptoFunction('ECDSA_do_verify');
  FuncLoadError := not assigned(ECDSA_do_verify);
  if FuncLoadError then
  begin
    ECDSA_do_verify :=  @ERROR_ECDSA_do_verify;
  end;

  ECDSA_sign_setup := LoadLibCryptoFunction('ECDSA_sign_setup');
  FuncLoadError := not assigned(ECDSA_sign_setup);
  if FuncLoadError then
  begin
    ECDSA_sign_setup :=  @ERROR_ECDSA_sign_setup;
  end;

  ECDSA_sign := LoadLibCryptoFunction('ECDSA_sign');
  FuncLoadError := not assigned(ECDSA_sign);
  if FuncLoadError then
  begin
    ECDSA_sign :=  @ERROR_ECDSA_sign;
  end;

  ECDSA_sign_ex := LoadLibCryptoFunction('ECDSA_sign_ex');
  FuncLoadError := not assigned(ECDSA_sign_ex);
  if FuncLoadError then
  begin
    ECDSA_sign_ex :=  @ERROR_ECDSA_sign_ex;
  end;

  ECDSA_verify := LoadLibCryptoFunction('ECDSA_verify');
  FuncLoadError := not assigned(ECDSA_verify);
  if FuncLoadError then
  begin
    ECDSA_verify :=  @ERROR_ECDSA_verify;
  end;

  ECDSA_size := LoadLibCryptoFunction('ECDSA_size');
  FuncLoadError := not assigned(ECDSA_size);
  if FuncLoadError then
  begin
    ECDSA_size :=  @ERROR_ECDSA_size;
  end;

  EC_KEY_METHOD_new := LoadLibCryptoFunction('EC_KEY_METHOD_new');
  FuncLoadError := not assigned(EC_KEY_METHOD_new);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_new :=  @ERROR_EC_KEY_METHOD_new;
  end;

  EC_KEY_METHOD_free := LoadLibCryptoFunction('EC_KEY_METHOD_free');
  FuncLoadError := not assigned(EC_KEY_METHOD_free);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_free :=  @ERROR_EC_KEY_METHOD_free;
  end;

  EC_KEY_METHOD_set_init := LoadLibCryptoFunction('EC_KEY_METHOD_set_init');
  FuncLoadError := not assigned(EC_KEY_METHOD_set_init);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_set_init :=  @ERROR_EC_KEY_METHOD_set_init;
  end;

  EC_KEY_METHOD_set_keygen := LoadLibCryptoFunction('EC_KEY_METHOD_set_keygen');
  FuncLoadError := not assigned(EC_KEY_METHOD_set_keygen);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_set_keygen :=  @ERROR_EC_KEY_METHOD_set_keygen;
  end;

  EC_KEY_METHOD_set_compute_key := LoadLibCryptoFunction('EC_KEY_METHOD_set_compute_key');
  FuncLoadError := not assigned(EC_KEY_METHOD_set_compute_key);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_set_compute_key :=  @ERROR_EC_KEY_METHOD_set_compute_key;
  end;

  EC_KEY_METHOD_set_sign := LoadLibCryptoFunction('EC_KEY_METHOD_set_sign');
  FuncLoadError := not assigned(EC_KEY_METHOD_set_sign);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_set_sign :=  @ERROR_EC_KEY_METHOD_set_sign;
  end;

  EC_KEY_METHOD_set_verify := LoadLibCryptoFunction('EC_KEY_METHOD_set_verify');
  FuncLoadError := not assigned(EC_KEY_METHOD_set_verify);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_set_verify :=  @ERROR_EC_KEY_METHOD_set_verify;
  end;

  EC_KEY_METHOD_get_init := LoadLibCryptoFunction('EC_KEY_METHOD_get_init');
  FuncLoadError := not assigned(EC_KEY_METHOD_get_init);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_get_init :=  @ERROR_EC_KEY_METHOD_get_init;
  end;

  EC_KEY_METHOD_get_keygen := LoadLibCryptoFunction('EC_KEY_METHOD_get_keygen');
  FuncLoadError := not assigned(EC_KEY_METHOD_get_keygen);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_get_keygen :=  @ERROR_EC_KEY_METHOD_get_keygen;
  end;

  EC_KEY_METHOD_get_compute_key := LoadLibCryptoFunction('EC_KEY_METHOD_get_compute_key');
  FuncLoadError := not assigned(EC_KEY_METHOD_get_compute_key);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_get_compute_key :=  @ERROR_EC_KEY_METHOD_get_compute_key;
  end;

  EC_KEY_METHOD_get_sign := LoadLibCryptoFunction('EC_KEY_METHOD_get_sign');
  FuncLoadError := not assigned(EC_KEY_METHOD_get_sign);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_get_sign :=  @ERROR_EC_KEY_METHOD_get_sign;
  end;

  EC_KEY_METHOD_get_verify := LoadLibCryptoFunction('EC_KEY_METHOD_get_verify');
  FuncLoadError := not assigned(EC_KEY_METHOD_get_verify);
  if FuncLoadError then
  begin
    EC_KEY_METHOD_get_verify :=  @ERROR_EC_KEY_METHOD_get_verify;
  end;

end;

procedure UnLoad;
begin
  EC_GFp_simple_method := nil;
  EC_GFp_mont_method := nil;
  EC_GFp_nist_method := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EC_GFp_nistp224_method := nil;
  EC_GFp_nistp256_method := nil;
  EC_GFp_nistp521_method := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EC_GF2m_simple_method := nil;
  EC_GROUP_new := nil;
  EC_GROUP_free := nil;
  EC_GROUP_clear_free := nil;
  EC_GROUP_copy := nil;
  EC_GROUP_dup := nil;
  EC_GROUP_method_of := nil;
  EC_METHOD_get_field_type := nil;
  EC_GROUP_set_generator := nil;
  EC_GROUP_get0_generator := nil;
  EC_GROUP_get_mont_data := nil;
  EC_GROUP_get_order := nil;
  EC_GROUP_get0_order := nil;
  EC_GROUP_order_bits := nil;
  EC_GROUP_get_cofactor := nil;
  EC_GROUP_get0_cofactor := nil;
  EC_GROUP_set_curve_name := nil;
  EC_GROUP_get_curve_name := nil;
  EC_GROUP_set_asn1_flag := nil;
  EC_GROUP_get_asn1_flag := nil;
  EC_GROUP_set_point_conversion_form := nil;
  EC_GROUP_get_point_conversion_form := nil;
  EC_GROUP_get0_seed := nil;
  EC_GROUP_get_seed_len := nil;
  EC_GROUP_set_seed := nil;
  EC_GROUP_set_curve := nil;
  EC_GROUP_get_curve := nil;
  EC_GROUP_set_curve_GFp := nil;
  EC_GROUP_get_curve_GFp := nil;
  EC_GROUP_set_curve_GF2m := nil;
  EC_GROUP_get_curve_GF2m := nil;
  EC_GROUP_get_degree := nil;
  EC_GROUP_check := nil;
  EC_GROUP_check_discriminant := nil;
  EC_GROUP_cmp := nil;
  EC_GROUP_new_curve_GFp := nil;
  EC_GROUP_new_curve_GF2m := nil;
  EC_GROUP_new_by_curve_name := nil;
  EC_GROUP_new_from_ecparameters := nil;
  EC_GROUP_get_ecparameters := nil;
  EC_GROUP_new_from_ecpkparameters := nil;
  EC_GROUP_get_ecpkparameters := nil;
  EC_get_builtin_curves := nil;
  EC_curve_nid2nist := nil;
  EC_curve_nist2nid := nil;
  EC_POINT_new := nil;
  EC_POINT_free := nil;
  EC_POINT_clear_free := nil;
  EC_POINT_copy := nil;
  EC_POINT_dup := nil;
  EC_POINT_method_of := nil;
  EC_POINT_set_to_infinity := nil;
  EC_POINT_set_Jprojective_coordinates_GFp := nil;
  EC_POINT_get_Jprojective_coordinates_GFp := nil;
  EC_POINT_set_affine_coordinates := nil;
  EC_POINT_get_affine_coordinates := nil;
  EC_POINT_set_affine_coordinates_GFp := nil;
  EC_POINT_get_affine_coordinates_GFp := nil;
  EC_POINT_set_compressed_coordinates := nil;
  EC_POINT_set_compressed_coordinates_GFp := nil;
  EC_POINT_set_affine_coordinates_GF2m := nil;
  EC_POINT_get_affine_coordinates_GF2m := nil;
  EC_POINT_set_compressed_coordinates_GF2m := nil;
  EC_POINT_point2oct := nil;
  EC_POINT_oct2point := nil;
  EC_POINT_point2buf := nil;
  EC_POINT_point2bn := nil;
  EC_POINT_bn2point := nil;
  EC_POINT_point2hex := nil;
  EC_POINT_hex2point := nil;
  EC_POINT_add := nil;
  EC_POINT_dbl := nil;
  EC_POINT_invert := nil;
  EC_POINT_is_at_infinity := nil;
  EC_POINT_is_on_curve := nil;
  EC_POINT_cmp := nil;
  EC_POINT_make_affine := nil;
  EC_POINTs_make_affine := nil;
  EC_POINTs_mul := nil;
  EC_POINT_mul := nil;
  EC_GROUP_precompute_mult := nil;
  EC_GROUP_have_precompute_mult := nil;
  ECPKPARAMETERS_it := nil;
  ECPKPARAMETERS_new := nil;
  ECPKPARAMETERS_free := nil;
  ECPARAMETERS_it := nil;
  ECPARAMETERS_new := nil;
  ECPARAMETERS_free := nil;
  EC_GROUP_get_basis_type := nil;
  EC_GROUP_get_trinomial_basis := nil;
  EC_GROUP_get_pentanomial_basis := nil;
  d2i_ECPKParameters := nil;
  i2d_ECPKParameters := nil;
  ECPKParameters_print := nil;
  EC_KEY_new := nil;
  EC_KEY_get_flags := nil;
  EC_KEY_set_flags := nil;
  EC_KEY_clear_flags := nil;
  EC_KEY_new_by_curve_name := nil;
  EC_KEY_free := nil;
  EC_KEY_copy := nil;
  EC_KEY_dup := nil;
  EC_KEY_up_ref := nil;
  EC_KEY_get0_engine := nil;
  EC_KEY_get0_group := nil;
  EC_KEY_set_group := nil;
  EC_KEY_get0_private_key := nil;
  EC_KEY_set_private_key := nil;
  EC_KEY_get0_public_key := nil;
  EC_KEY_set_public_key := nil;
  EC_KEY_get_enc_flags := nil;
  EC_KEY_set_enc_flags := nil;
  EC_KEY_get_conv_form := nil;
  EC_KEY_set_conv_form := nil;
  EC_KEY_set_ex_data := nil;
  EC_KEY_get_ex_data := nil;
  EC_KEY_set_asn1_flag := nil;
  EC_KEY_precompute_mult := nil;
  EC_KEY_generate_key := nil;
  EC_KEY_check_key := nil;
  EC_KEY_can_sign := nil;
  EC_KEY_set_public_key_affine_coordinates := nil;
  EC_KEY_key2buf := nil;
  EC_KEY_oct2key := nil;
  EC_KEY_oct2priv := nil;
  EC_KEY_priv2oct := nil;
  EC_KEY_priv2buf := nil;
  d2i_ECPrivateKey := nil;
  i2d_ECPrivateKey := nil;
  o2i_ECPublicKey := nil;
  i2o_ECPublicKey := nil;
  ECParameters_print := nil;
  EC_KEY_print := nil;
  EC_KEY_OpenSSL := nil;
  EC_KEY_get_default_method := nil;
  EC_KEY_set_default_method := nil;
  EC_KEY_get_method := nil;
  EC_KEY_set_method := nil;
  EC_KEY_new_method := nil;
  ECDH_KDF_X9_62 := nil;
  ECDH_compute_key := nil;
  ECDSA_SIG_new := nil;
  ECDSA_SIG_free := nil;
  i2d_ECDSA_SIG := nil;
  d2i_ECDSA_SIG := nil;
  ECDSA_SIG_get0 := nil;
  ECDSA_SIG_get0_r := nil;
  ECDSA_SIG_get0_s := nil;
  ECDSA_SIG_set0 := nil;
  ECDSA_do_sign := nil;
  ECDSA_do_sign_ex := nil;
  ECDSA_do_verify := nil;
  ECDSA_sign_setup := nil;
  ECDSA_sign := nil;
  ECDSA_sign_ex := nil;
  ECDSA_verify := nil;
  ECDSA_size := nil;
  EC_KEY_METHOD_new := nil;
  EC_KEY_METHOD_free := nil;
  EC_KEY_METHOD_set_init := nil;
  EC_KEY_METHOD_set_keygen := nil;
  EC_KEY_METHOD_set_compute_key := nil;
  EC_KEY_METHOD_set_sign := nil;
  EC_KEY_METHOD_set_verify := nil;
  EC_KEY_METHOD_get_init := nil;
  EC_KEY_METHOD_get_keygen := nil;
  EC_KEY_METHOD_get_compute_key := nil;
  EC_KEY_METHOD_get_sign := nil;
  EC_KEY_METHOD_get_verify := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
