(* This unit was generated from the source file dsa.h2pas 
It should not be modified directly. All changes should be made to dsa.h2pas
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


unit OpenSSL_dsa;


interface

// Headers for OpenSSL 1.1.1
// dsa.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_evp;

const
  OPENSSL_DSA_MAX_MODULUS_BITS = 10000;
  OPENSSL_DSA_FIPS_MIN_MODULUS_BITS = 1024;
  DSA_FLAG_CACHE_MONT_P = $01;
  DSA_FLAG_NO_EXP_CONSTTIME = $00;
  DSA_FLAG_FIPS_METHOD = $0400;
  DSA_FLAG_NON_FIPS_ALLOW = $0400;
  DSA_FLAG_FIPS_CHECKED = $0800;

  DSS_prime_checks = 64;

  EVP_PKEY_CTRL_DSA_PARAMGEN_BITS = EVP_PKEY_ALG_CTRL + 1;
  EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS = EVP_PKEY_ALG_CTRL + 2;
  EVP_PKEY_CTRL_DSA_PARAMGEN_MD = EVP_PKEY_ALG_CTRL + 3;

type
  DSA_SIG = type Pointer; // DSA_SIG_st
  PDSA_SIG = ^DSA_SIG;
  PPDSA_SIG = ^PDSA_SIG;

  DSA_meth_sign_cb = function (const v1: PByte; v2: TOpenSSL_C_INT; v3: PDSA): PDSA_SIG cdecl;
  DSA_meth_sign_setup_cb = function (v1: PDSA; v2: PBN_CTX;
    v3: PPBIGNUM; v4: PPBIGNUM): TOpenSSL_C_INT cdecl;
  DSA_meth_verify_cb = function (const v1: PByte; v2: TOpenSSL_C_INT;
    v3: PDSA_SIG; v4: PDSA): TOpenSSL_C_INT cdecl;
  DSA_meth_mod_exp_cb = function (v1: PDSA; v2: PBIGNUM;
    const v3: PBIGNUM; const v4: PBIGNUM; const v5: PBIGNUM; const v6: PBIGNUM;
    const v7: PBIGNUM; v8: PBN_CTX; v9: PBN_MONT_CTX): TOpenSSL_C_INT cdecl;
  DSA_meth_bn_mod_exp_cb = function (v1: PDSA; v2: PBIGNUM;
    const v3: PBIGNUM; const v4: PBIGNUM; const v5: PBIGNUM; v6: PBN_CTX; v7: PBN_MONT_CTX): TOpenSSL_C_INT cdecl;
  DSA_meth_init_cb = function(v1: PDSA): TOpenSSL_C_INT cdecl;
  DSA_meth_finish_cb = function (v1: PDSA): TOpenSSL_C_INT cdecl;
  DSA_meth_paramgen_cb = function (v1: PDSA; v2: TOpenSSL_C_INT;
    const v3: PByte; v4: TOpenSSL_C_INT; v5: POpenSSL_C_INT; v6: POpenSSL_C_ULONG; v7: PBN_GENCB): TOpenSSL_C_INT cdecl;
  DSA_meth_keygen_cb = function (v1: PDSA): TOpenSSL_C_INT cdecl;

//# define d2i_DSAparams_fp(fp,x) (DSA *)ASN1_d2i_fp((char *(*)())DSA_new, \
//                (char *(*)())d2i_DSAparams,(fp),(unsigned char **)(x))
//# define i2d_DSAparams_fp(fp,x) ASN1_i2d_fp(i2d_DSAparams,(fp), \
//                (unsigned char *)(x))
//# define d2i_DSAparams_bio(bp,x) ASN1_d2i_bio_of(DSA,DSA_new,d2i_DSAparams,bp,x)
//# define i2d_DSAparams_bio(bp,x) ASN1_i2d_bio_of_const(DSA,i2d_DSAparams,bp,x)

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM DSAparams_dup}
{$EXTERNALSYM DSA_SIG_new}
{$EXTERNALSYM DSA_SIG_free}
{$EXTERNALSYM i2d_DSA_SIG}
{$EXTERNALSYM d2i_DSA_SIG}
{$EXTERNALSYM DSA_SIG_get0}
{$EXTERNALSYM DSA_SIG_set0}
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
{$EXTERNALSYM DSA_sign}
{$EXTERNALSYM DSA_verify}
{$EXTERNALSYM DSA_set_ex_data}
{$EXTERNALSYM DSA_get_ex_data}
{$EXTERNALSYM d2i_DSAPublicKey}
{$EXTERNALSYM d2i_DSAPrivateKey}
{$EXTERNALSYM d2i_DSAparams}
{$EXTERNALSYM DSA_generate_parameters_ex}
{$EXTERNALSYM DSA_generate_key}
{$EXTERNALSYM i2d_DSAPublicKey}
{$EXTERNALSYM i2d_DSAPrivateKey}
{$EXTERNALSYM i2d_DSAparams}
{$EXTERNALSYM DSAparams_print}
{$EXTERNALSYM DSA_print}
{$EXTERNALSYM DSA_dup_DH}
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
{$EXTERNALSYM DSA_meth_get_sign}
{$EXTERNALSYM DSA_meth_set_sign}
{$EXTERNALSYM DSA_meth_get_sign_setup}
{$EXTERNALSYM DSA_meth_set_sign_setup}
{$EXTERNALSYM DSA_meth_get_verify}
{$EXTERNALSYM DSA_meth_set_verify}
{$EXTERNALSYM DSA_meth_get_mod_exp}
{$EXTERNALSYM DSA_meth_set_mod_exp}
{$EXTERNALSYM DSA_meth_get_bn_mod_exp}
{$EXTERNALSYM DSA_meth_set_bn_mod_exp}
{$EXTERNALSYM DSA_meth_get_init}
{$EXTERNALSYM DSA_meth_set_init}
{$EXTERNALSYM DSA_meth_get_finish}
{$EXTERNALSYM DSA_meth_set_finish}
{$EXTERNALSYM DSA_meth_get_paramgen}
{$EXTERNALSYM DSA_meth_set_paramgen}
{$EXTERNALSYM DSA_meth_get_keygen}
{$EXTERNALSYM DSA_meth_set_keygen}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function DSAparams_dup(x: PDSA): PDSA; cdecl; external CLibCrypto;
function DSA_SIG_new: PDSA_SIG; cdecl; external CLibCrypto;
procedure DSA_SIG_free(a: PDSA_SIG); cdecl; external CLibCrypto;
function i2d_DSA_SIG(const a: PDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_DSA_SIG(v: PPDSA_SIG; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA_SIG; cdecl; external CLibCrypto;
procedure DSA_SIG_get0(const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl; external CLibCrypto;
function DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_do_sign(const dgst: PByte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl; external CLibCrypto;
function DSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_OpenSSL: PDSA_METHOD; cdecl; external CLibCrypto;
procedure DSA_set_default_method(const v1: PDSA_METHOD); cdecl; external CLibCrypto;
function DSA_get_default_method: PDSA_METHOD; cdecl; external CLibCrypto;
function DSA_set_method(dsa: PDSA; const v1: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_get_method(d: PDSA): PDSA_METHOD; cdecl; external CLibCrypto;
function DSA_new: PDSA; cdecl; external CLibCrypto;
function DSA_new_method(engine: PENGINE): PDSA; cdecl; external CLibCrypto;
procedure DSA_free(r: PDSA); cdecl; external CLibCrypto;
function DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_size(const v1: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_bits(const d: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_security_bits(const d: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function d2i_DSAPublicKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function d2i_DSAPrivateKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function d2i_DSAparams(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl; external CLibCrypto;
function DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; const seed: PByte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_ULONG; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_DSAPublicKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_DSAPrivateKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function i2d_DSAparams(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSAparams_print(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_print(bp: PBIO; const x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_dup_DH(const r: PDSA): PDH; cdecl; external CLibCrypto;
procedure DSA_get0_pqg(const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl; external CLibCrypto;
function DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DSA_get0_key(const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl; external CLibCrypto;
function DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_get0_p(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_q(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_g(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_pub_key(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
function DSA_get0_priv_key(const d: PDSA): PBIGNUM; cdecl; external CLibCrypto;
procedure DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DSA_test_flags(const d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function DSA_get0_engine(d: PDSA): PENGINE; cdecl; external CLibCrypto;
function DSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl; external CLibCrypto;
procedure DSA_meth_free(dsam: PDSA_METHOD); cdecl; external CLibCrypto;
function DSA_meth_dup(const dsam: PDSA_METHOD): PDSA_METHOD; cdecl; external CLibCrypto;
function DSA_meth_get0_name(const dsam: PDSA_METHOD): PAnsiChar; cdecl; external CLibCrypto;
function DSA_meth_set1_name(dsam: PDSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_flags(const dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get0_app_data(const dsam: PDSA_METHOD): Pointer; cdecl; external CLibCrypto;
function DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_sign(const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl; external CLibCrypto;
function DSA_meth_set_sign(dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_sign_setup(const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl; external CLibCrypto;
function DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_verify(const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl; external CLibCrypto;
function DSA_meth_set_verify(dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_mod_exp(const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl; external CLibCrypto;
function DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_bn_mod_exp(const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl; external CLibCrypto;
function DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_init(const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl; external CLibCrypto;
function DSA_meth_set_init(dsam: PDSA_METHOD; init: DSA_meth_init_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_finish(const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl; external CLibCrypto;
function DSA_meth_set_finish(dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_paramgen(const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl; external CLibCrypto;
function DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function DSA_meth_get_keygen(const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl; external CLibCrypto;
function DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  DSAparams_dup: function (x: PDSA): PDSA; cdecl = nil;
  DSA_SIG_new: function : PDSA_SIG; cdecl = nil;
  DSA_SIG_free: procedure (a: PDSA_SIG); cdecl = nil;
  i2d_DSA_SIG: function (const a: PDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_DSA_SIG: function (v: PPDSA_SIG; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA_SIG; cdecl = nil;
  DSA_SIG_get0: procedure (const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl = nil;
  DSA_SIG_set0: function (sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  DSA_do_sign: function (const dgst: PByte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl = nil;
  DSA_do_verify: function (const dgst: PByte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_OpenSSL: function : PDSA_METHOD; cdecl = nil;
  DSA_set_default_method: procedure (const v1: PDSA_METHOD); cdecl = nil;
  DSA_get_default_method: function : PDSA_METHOD; cdecl = nil;
  DSA_set_method: function (dsa: PDSA; const v1: PDSA_METHOD): TOpenSSL_C_INT; cdecl = nil;
  DSA_get_method: function (d: PDSA): PDSA_METHOD; cdecl = nil;
  DSA_new: function : PDSA; cdecl = nil;
  DSA_new_method: function (engine: PENGINE): PDSA; cdecl = nil;
  DSA_free: procedure (r: PDSA); cdecl = nil;
  DSA_up_ref: function (r: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_size: function (const v1: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_bits: function (const d: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_security_bits: function (const d: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_sign: function (type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_verify: function (type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_set_ex_data: function (d: PDSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  DSA_get_ex_data: function (d: PDSA; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  d2i_DSAPublicKey: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = nil;
  d2i_DSAPrivateKey: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = nil;
  d2i_DSAparams: function (a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl = nil;
  DSA_generate_parameters_ex: function (dsa: PDSA; bits: TOpenSSL_C_INT; const seed: PByte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_ULONG; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  DSA_generate_key: function (a: PDSA): TOpenSSL_C_INT; cdecl = nil;
  i2d_DSAPublicKey: function (const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  i2d_DSAPrivateKey: function (const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  i2d_DSAparams: function (const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  DSAparams_print: function (bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl = nil;
  DSA_print: function (bp: PBIO; const x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DSA_dup_DH: function (const r: PDSA): PDH; cdecl = nil;
  DSA_get0_pqg: procedure (const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl = nil;
  DSA_set0_pqg: function (d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  DSA_get0_key: procedure (const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl = nil;
  DSA_set0_key: function (d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  DSA_get0_p: function (const d: PDSA): PBIGNUM; cdecl = nil;
  DSA_get0_q: function (const d: PDSA): PBIGNUM; cdecl = nil;
  DSA_get0_g: function (const d: PDSA): PBIGNUM; cdecl = nil;
  DSA_get0_pub_key: function (const d: PDSA): PBIGNUM; cdecl = nil;
  DSA_get0_priv_key: function (const d: PDSA): PBIGNUM; cdecl = nil;
  DSA_clear_flags: procedure (d: PDSA; flags: TOpenSSL_C_INT); cdecl = nil;
  DSA_test_flags: function (const d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DSA_set_flags: procedure (d: PDSA; flags: TOpenSSL_C_INT); cdecl = nil;
  DSA_get0_engine: function (d: PDSA): PENGINE; cdecl = nil;
  DSA_meth_new: function (const name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl = nil;
  DSA_meth_free: procedure (dsam: PDSA_METHOD); cdecl = nil;
  DSA_meth_dup: function (const dsam: PDSA_METHOD): PDSA_METHOD; cdecl = nil;
  DSA_meth_get0_name: function (const dsam: PDSA_METHOD): PAnsiChar; cdecl = nil;
  DSA_meth_set1_name: function (dsam: PDSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_flags: function (const dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_set_flags: function (dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get0_app_data: function (const dsam: PDSA_METHOD): Pointer; cdecl = nil;
  DSA_meth_set0_app_data: function (dsam: PDSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_sign: function (const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl = nil;
  DSA_meth_set_sign: function (dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_sign_setup: function (const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl = nil;
  DSA_meth_set_sign_setup: function (dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_verify: function (const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl = nil;
  DSA_meth_set_verify: function (dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_mod_exp: function (const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl = nil;
  DSA_meth_set_mod_exp: function (dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_bn_mod_exp: function (const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl = nil;
  DSA_meth_set_bn_mod_exp: function (dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_init: function (const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl = nil;
  DSA_meth_set_init: function (dsam: PDSA_METHOD; init: DSA_meth_init_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_finish: function (const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl = nil;
  DSA_meth_set_finish: function (dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_paramgen: function (const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl = nil;
  DSA_meth_set_paramgen: function (dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TOpenSSL_C_INT; cdecl = nil;
  DSA_meth_get_keygen: function (const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl = nil;
  DSA_meth_set_keygen: function (dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TOpenSSL_C_INT; cdecl = nil;
{$ENDIF}

implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_DSAparams_dup(x: PDSA): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSAparams_dup');
end;

function ERROR_DSA_SIG_new: PDSA_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_new');
end;

procedure ERROR_DSA_SIG_free(a: PDSA_SIG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_free');
end;

function ERROR_i2d_DSA_SIG(const a: PDSA_SIG; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSA_SIG');
end;

function ERROR_d2i_DSA_SIG(v: PPDSA_SIG; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSA_SIG');
end;

procedure ERROR_DSA_SIG_get0(const sig: PDSA_SIG; const pr: PPBIGNUM; const ps: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_get0');
end;

function ERROR_DSA_SIG_set0(sig: PDSA_SIG; r: PBIGNUM; s: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_SIG_set0');
end;

function ERROR_DSA_do_sign(const dgst: PByte; dlen: TOpenSSL_C_INT; dsa: PDSA): PDSA_SIG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_do_sign');
end;

function ERROR_DSA_do_verify(const dgst: PByte; dgst_len: TOpenSSL_C_INT; sig: PDSA_SIG; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_do_verify');
end;

function ERROR_DSA_OpenSSL: PDSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_OpenSSL');
end;

procedure ERROR_DSA_set_default_method(const v1: PDSA_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_default_method');
end;

function ERROR_DSA_get_default_method: PDSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_default_method');
end;

function ERROR_DSA_set_method(dsa: PDSA; const v1: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_method');
end;

function ERROR_DSA_get_method(d: PDSA): PDSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_method');
end;

function ERROR_DSA_new: PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_new');
end;

function ERROR_DSA_new_method(engine: PENGINE): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_new_method');
end;

procedure ERROR_DSA_free(r: PDSA); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_free');
end;

function ERROR_DSA_up_ref(r: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_up_ref');
end;

function ERROR_DSA_size(const v1: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_size');
end;

function ERROR_DSA_bits(const d: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_bits');
end;

function ERROR_DSA_security_bits(const d: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_security_bits');
end;

function ERROR_DSA_sign(type_: TOpenSSL_C_INT; const dgst: PByte; dlen: TOpenSSL_C_INT; sig: PByte; siglen: POpenSSL_C_UINT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_sign');
end;

function ERROR_DSA_verify(type_: TOpenSSL_C_INT; const dgst: PByte; dgst_len: TOpenSSL_C_INT; const sigbuf: PByte; siglen: TOpenSSL_C_INT; dsa: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_verify');
end;

function ERROR_DSA_set_ex_data(d: PDSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_ex_data');
end;

function ERROR_DSA_get_ex_data(d: PDSA; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get_ex_data');
end;

function ERROR_d2i_DSAPublicKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPublicKey');
end;

function ERROR_d2i_DSAPrivateKey(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAPrivateKey');
end;

function ERROR_d2i_DSAparams(a: PPDSA; const pp: PPByte; length: TOpenSSL_C_LONG): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_DSAparams');
end;

function ERROR_DSA_generate_parameters_ex(dsa: PDSA; bits: TOpenSSL_C_INT; const seed: PByte; seed_len: TOpenSSL_C_INT; counter_ret: POpenSSL_C_INT; h_ret: POpenSSL_C_ULONG; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_generate_parameters_ex');
end;

function ERROR_DSA_generate_key(a: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_generate_key');
end;

function ERROR_i2d_DSAPublicKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPublicKey');
end;

function ERROR_i2d_DSAPrivateKey(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAPrivateKey');
end;

function ERROR_i2d_DSAparams(const a: PDSA; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_DSAparams');
end;

function ERROR_DSAparams_print(bp: PBIO; const x: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSAparams_print');
end;

function ERROR_DSA_print(bp: PBIO; const x: PDSA; off: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_print');
end;

function ERROR_DSA_dup_DH(const r: PDSA): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_dup_DH');
end;

procedure ERROR_DSA_get0_pqg(const d: PDSA; const p: PPBIGNUM; const q: PPBIGNUM; const g: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_pqg');
end;

function ERROR_DSA_set0_pqg(d: PDSA; p: PBIGNUM; q: PBIGNUM; g: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set0_pqg');
end;

procedure ERROR_DSA_get0_key(const d: PDSA; const pub_key: PPBIGNUM; const priv_key: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_key');
end;

function ERROR_DSA_set0_key(d: PDSA; pub_key: PBIGNUM; priv_key: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set0_key');
end;

function ERROR_DSA_get0_p(const d: PDSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_p');
end;

function ERROR_DSA_get0_q(const d: PDSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_q');
end;

function ERROR_DSA_get0_g(const d: PDSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_g');
end;

function ERROR_DSA_get0_pub_key(const d: PDSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_pub_key');
end;

function ERROR_DSA_get0_priv_key(const d: PDSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_priv_key');
end;

procedure ERROR_DSA_clear_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_clear_flags');
end;

function ERROR_DSA_test_flags(const d: PDSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_test_flags');
end;

procedure ERROR_DSA_set_flags(d: PDSA; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_set_flags');
end;

function ERROR_DSA_get0_engine(d: PDSA): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_get0_engine');
end;

function ERROR_DSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PDSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_new');
end;

procedure ERROR_DSA_meth_free(dsam: PDSA_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_free');
end;

function ERROR_DSA_meth_dup(const dsam: PDSA_METHOD): PDSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_dup');
end;

function ERROR_DSA_meth_get0_name(const dsam: PDSA_METHOD): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get0_name');
end;

function ERROR_DSA_meth_set1_name(dsam: PDSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set1_name');
end;

function ERROR_DSA_meth_get_flags(const dsam: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_flags');
end;

function ERROR_DSA_meth_set_flags(dsam: PDSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_flags');
end;

function ERROR_DSA_meth_get0_app_data(const dsam: PDSA_METHOD): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get0_app_data');
end;

function ERROR_DSA_meth_set0_app_data(dsam: PDSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set0_app_data');
end;

function ERROR_DSA_meth_get_sign(const dsam: PDSA_METHOD): DSA_meth_sign_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_sign');
end;

function ERROR_DSA_meth_set_sign(dsam: PDSA_METHOD; sign: DSA_meth_sign_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_sign');
end;

function ERROR_DSA_meth_get_sign_setup(const dsam: PDSA_METHOD): DSA_meth_sign_setup_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_sign_setup');
end;

function ERROR_DSA_meth_set_sign_setup(dsam: PDSA_METHOD; sign_setup: DSA_meth_sign_setup_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_sign_setup');
end;

function ERROR_DSA_meth_get_verify(const dsam: PDSA_METHOD): DSA_meth_verify_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_verify');
end;

function ERROR_DSA_meth_set_verify(dsam: PDSA_METHOD; verify: DSA_meth_verify_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_verify');
end;

function ERROR_DSA_meth_get_mod_exp(const dsam: PDSA_METHOD): DSA_meth_mod_exp_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_mod_exp');
end;

function ERROR_DSA_meth_set_mod_exp(dsam: PDSA_METHOD; mod_exp: DSA_meth_mod_exp_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_mod_exp');
end;

function ERROR_DSA_meth_get_bn_mod_exp(const dsam: PDSA_METHOD): DSA_meth_bn_mod_exp_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_bn_mod_exp');
end;

function ERROR_DSA_meth_set_bn_mod_exp(dsam: PDSA_METHOD; bn_mod_exp: DSA_meth_bn_mod_exp_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_bn_mod_exp');
end;

function ERROR_DSA_meth_get_init(const dsam: PDSA_METHOD): DSA_meth_init_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_init');
end;

function ERROR_DSA_meth_set_init(dsam: PDSA_METHOD; init: DSA_meth_init_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_init');
end;

function ERROR_DSA_meth_get_finish(const dsam: PDSA_METHOD): DSA_meth_finish_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_finish');
end;

function ERROR_DSA_meth_set_finish(dsam: PDSA_METHOD; finish: DSA_meth_finish_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_finish');
end;

function ERROR_DSA_meth_get_paramgen(const dsam: PDSA_METHOD): DSA_meth_paramgen_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_paramgen');
end;

function ERROR_DSA_meth_set_paramgen(dsam: PDSA_METHOD; paramgen: DSA_meth_paramgen_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_paramgen');
end;

function ERROR_DSA_meth_get_keygen(const dsam: PDSA_METHOD): DSA_meth_keygen_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_get_keygen');
end;

function ERROR_DSA_meth_set_keygen(dsam: PDSA_METHOD; keygen: DSA_meth_keygen_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('DSA_meth_set_keygen');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  DSAparams_dup := LoadLibCryptoFunction('DSAparams_dup');
  FuncLoadError := not assigned(DSAparams_dup);
  if FuncLoadError then
  begin
    DSAparams_dup :=  @ERROR_DSAparams_dup;
  end;

  DSA_SIG_new := LoadLibCryptoFunction('DSA_SIG_new');
  FuncLoadError := not assigned(DSA_SIG_new);
  if FuncLoadError then
  begin
    DSA_SIG_new :=  @ERROR_DSA_SIG_new;
  end;

  DSA_SIG_free := LoadLibCryptoFunction('DSA_SIG_free');
  FuncLoadError := not assigned(DSA_SIG_free);
  if FuncLoadError then
  begin
    DSA_SIG_free :=  @ERROR_DSA_SIG_free;
  end;

  i2d_DSA_SIG := LoadLibCryptoFunction('i2d_DSA_SIG');
  FuncLoadError := not assigned(i2d_DSA_SIG);
  if FuncLoadError then
  begin
    i2d_DSA_SIG :=  @ERROR_i2d_DSA_SIG;
  end;

  d2i_DSA_SIG := LoadLibCryptoFunction('d2i_DSA_SIG');
  FuncLoadError := not assigned(d2i_DSA_SIG);
  if FuncLoadError then
  begin
    d2i_DSA_SIG :=  @ERROR_d2i_DSA_SIG;
  end;

  DSA_SIG_get0 := LoadLibCryptoFunction('DSA_SIG_get0');
  FuncLoadError := not assigned(DSA_SIG_get0);
  if FuncLoadError then
  begin
    DSA_SIG_get0 :=  @ERROR_DSA_SIG_get0;
  end;

  DSA_SIG_set0 := LoadLibCryptoFunction('DSA_SIG_set0');
  FuncLoadError := not assigned(DSA_SIG_set0);
  if FuncLoadError then
  begin
    DSA_SIG_set0 :=  @ERROR_DSA_SIG_set0;
  end;

  DSA_do_sign := LoadLibCryptoFunction('DSA_do_sign');
  FuncLoadError := not assigned(DSA_do_sign);
  if FuncLoadError then
  begin
    DSA_do_sign :=  @ERROR_DSA_do_sign;
  end;

  DSA_do_verify := LoadLibCryptoFunction('DSA_do_verify');
  FuncLoadError := not assigned(DSA_do_verify);
  if FuncLoadError then
  begin
    DSA_do_verify :=  @ERROR_DSA_do_verify;
  end;

  DSA_OpenSSL := LoadLibCryptoFunction('DSA_OpenSSL');
  FuncLoadError := not assigned(DSA_OpenSSL);
  if FuncLoadError then
  begin
    DSA_OpenSSL :=  @ERROR_DSA_OpenSSL;
  end;

  DSA_set_default_method := LoadLibCryptoFunction('DSA_set_default_method');
  FuncLoadError := not assigned(DSA_set_default_method);
  if FuncLoadError then
  begin
    DSA_set_default_method :=  @ERROR_DSA_set_default_method;
  end;

  DSA_get_default_method := LoadLibCryptoFunction('DSA_get_default_method');
  FuncLoadError := not assigned(DSA_get_default_method);
  if FuncLoadError then
  begin
    DSA_get_default_method :=  @ERROR_DSA_get_default_method;
  end;

  DSA_set_method := LoadLibCryptoFunction('DSA_set_method');
  FuncLoadError := not assigned(DSA_set_method);
  if FuncLoadError then
  begin
    DSA_set_method :=  @ERROR_DSA_set_method;
  end;

  DSA_get_method := LoadLibCryptoFunction('DSA_get_method');
  FuncLoadError := not assigned(DSA_get_method);
  if FuncLoadError then
  begin
    DSA_get_method :=  @ERROR_DSA_get_method;
  end;

  DSA_new := LoadLibCryptoFunction('DSA_new');
  FuncLoadError := not assigned(DSA_new);
  if FuncLoadError then
  begin
    DSA_new :=  @ERROR_DSA_new;
  end;

  DSA_new_method := LoadLibCryptoFunction('DSA_new_method');
  FuncLoadError := not assigned(DSA_new_method);
  if FuncLoadError then
  begin
    DSA_new_method :=  @ERROR_DSA_new_method;
  end;

  DSA_free := LoadLibCryptoFunction('DSA_free');
  FuncLoadError := not assigned(DSA_free);
  if FuncLoadError then
  begin
    DSA_free :=  @ERROR_DSA_free;
  end;

  DSA_up_ref := LoadLibCryptoFunction('DSA_up_ref');
  FuncLoadError := not assigned(DSA_up_ref);
  if FuncLoadError then
  begin
    DSA_up_ref :=  @ERROR_DSA_up_ref;
  end;

  DSA_size := LoadLibCryptoFunction('DSA_size');
  FuncLoadError := not assigned(DSA_size);
  if FuncLoadError then
  begin
    DSA_size :=  @ERROR_DSA_size;
  end;

  DSA_bits := LoadLibCryptoFunction('DSA_bits');
  FuncLoadError := not assigned(DSA_bits);
  if FuncLoadError then
  begin
    DSA_bits :=  @ERROR_DSA_bits;
  end;

  DSA_security_bits := LoadLibCryptoFunction('DSA_security_bits');
  FuncLoadError := not assigned(DSA_security_bits);
  if FuncLoadError then
  begin
    DSA_security_bits :=  @ERROR_DSA_security_bits;
  end;

  DSA_sign := LoadLibCryptoFunction('DSA_sign');
  FuncLoadError := not assigned(DSA_sign);
  if FuncLoadError then
  begin
    DSA_sign :=  @ERROR_DSA_sign;
  end;

  DSA_verify := LoadLibCryptoFunction('DSA_verify');
  FuncLoadError := not assigned(DSA_verify);
  if FuncLoadError then
  begin
    DSA_verify :=  @ERROR_DSA_verify;
  end;

  DSA_set_ex_data := LoadLibCryptoFunction('DSA_set_ex_data');
  FuncLoadError := not assigned(DSA_set_ex_data);
  if FuncLoadError then
  begin
    DSA_set_ex_data :=  @ERROR_DSA_set_ex_data;
  end;

  DSA_get_ex_data := LoadLibCryptoFunction('DSA_get_ex_data');
  FuncLoadError := not assigned(DSA_get_ex_data);
  if FuncLoadError then
  begin
    DSA_get_ex_data :=  @ERROR_DSA_get_ex_data;
  end;

  d2i_DSAPublicKey := LoadLibCryptoFunction('d2i_DSAPublicKey');
  FuncLoadError := not assigned(d2i_DSAPublicKey);
  if FuncLoadError then
  begin
    d2i_DSAPublicKey :=  @ERROR_d2i_DSAPublicKey;
  end;

  d2i_DSAPrivateKey := LoadLibCryptoFunction('d2i_DSAPrivateKey');
  FuncLoadError := not assigned(d2i_DSAPrivateKey);
  if FuncLoadError then
  begin
    d2i_DSAPrivateKey :=  @ERROR_d2i_DSAPrivateKey;
  end;

  d2i_DSAparams := LoadLibCryptoFunction('d2i_DSAparams');
  FuncLoadError := not assigned(d2i_DSAparams);
  if FuncLoadError then
  begin
    d2i_DSAparams :=  @ERROR_d2i_DSAparams;
  end;

  DSA_generate_parameters_ex := LoadLibCryptoFunction('DSA_generate_parameters_ex');
  FuncLoadError := not assigned(DSA_generate_parameters_ex);
  if FuncLoadError then
  begin
    DSA_generate_parameters_ex :=  @ERROR_DSA_generate_parameters_ex;
  end;

  DSA_generate_key := LoadLibCryptoFunction('DSA_generate_key');
  FuncLoadError := not assigned(DSA_generate_key);
  if FuncLoadError then
  begin
    DSA_generate_key :=  @ERROR_DSA_generate_key;
  end;

  i2d_DSAPublicKey := LoadLibCryptoFunction('i2d_DSAPublicKey');
  FuncLoadError := not assigned(i2d_DSAPublicKey);
  if FuncLoadError then
  begin
    i2d_DSAPublicKey :=  @ERROR_i2d_DSAPublicKey;
  end;

  i2d_DSAPrivateKey := LoadLibCryptoFunction('i2d_DSAPrivateKey');
  FuncLoadError := not assigned(i2d_DSAPrivateKey);
  if FuncLoadError then
  begin
    i2d_DSAPrivateKey :=  @ERROR_i2d_DSAPrivateKey;
  end;

  i2d_DSAparams := LoadLibCryptoFunction('i2d_DSAparams');
  FuncLoadError := not assigned(i2d_DSAparams);
  if FuncLoadError then
  begin
    i2d_DSAparams :=  @ERROR_i2d_DSAparams;
  end;

  DSAparams_print := LoadLibCryptoFunction('DSAparams_print');
  FuncLoadError := not assigned(DSAparams_print);
  if FuncLoadError then
  begin
    DSAparams_print :=  @ERROR_DSAparams_print;
  end;

  DSA_print := LoadLibCryptoFunction('DSA_print');
  FuncLoadError := not assigned(DSA_print);
  if FuncLoadError then
  begin
    DSA_print :=  @ERROR_DSA_print;
  end;

  DSA_dup_DH := LoadLibCryptoFunction('DSA_dup_DH');
  FuncLoadError := not assigned(DSA_dup_DH);
  if FuncLoadError then
  begin
    DSA_dup_DH :=  @ERROR_DSA_dup_DH;
  end;

  DSA_get0_pqg := LoadLibCryptoFunction('DSA_get0_pqg');
  FuncLoadError := not assigned(DSA_get0_pqg);
  if FuncLoadError then
  begin
    DSA_get0_pqg :=  @ERROR_DSA_get0_pqg;
  end;

  DSA_set0_pqg := LoadLibCryptoFunction('DSA_set0_pqg');
  FuncLoadError := not assigned(DSA_set0_pqg);
  if FuncLoadError then
  begin
    DSA_set0_pqg :=  @ERROR_DSA_set0_pqg;
  end;

  DSA_get0_key := LoadLibCryptoFunction('DSA_get0_key');
  FuncLoadError := not assigned(DSA_get0_key);
  if FuncLoadError then
  begin
    DSA_get0_key :=  @ERROR_DSA_get0_key;
  end;

  DSA_set0_key := LoadLibCryptoFunction('DSA_set0_key');
  FuncLoadError := not assigned(DSA_set0_key);
  if FuncLoadError then
  begin
    DSA_set0_key :=  @ERROR_DSA_set0_key;
  end;

  DSA_get0_p := LoadLibCryptoFunction('DSA_get0_p');
  FuncLoadError := not assigned(DSA_get0_p);
  if FuncLoadError then
  begin
    DSA_get0_p :=  @ERROR_DSA_get0_p;
  end;

  DSA_get0_q := LoadLibCryptoFunction('DSA_get0_q');
  FuncLoadError := not assigned(DSA_get0_q);
  if FuncLoadError then
  begin
    DSA_get0_q :=  @ERROR_DSA_get0_q;
  end;

  DSA_get0_g := LoadLibCryptoFunction('DSA_get0_g');
  FuncLoadError := not assigned(DSA_get0_g);
  if FuncLoadError then
  begin
    DSA_get0_g :=  @ERROR_DSA_get0_g;
  end;

  DSA_get0_pub_key := LoadLibCryptoFunction('DSA_get0_pub_key');
  FuncLoadError := not assigned(DSA_get0_pub_key);
  if FuncLoadError then
  begin
    DSA_get0_pub_key :=  @ERROR_DSA_get0_pub_key;
  end;

  DSA_get0_priv_key := LoadLibCryptoFunction('DSA_get0_priv_key');
  FuncLoadError := not assigned(DSA_get0_priv_key);
  if FuncLoadError then
  begin
    DSA_get0_priv_key :=  @ERROR_DSA_get0_priv_key;
  end;

  DSA_clear_flags := LoadLibCryptoFunction('DSA_clear_flags');
  FuncLoadError := not assigned(DSA_clear_flags);
  if FuncLoadError then
  begin
    DSA_clear_flags :=  @ERROR_DSA_clear_flags;
  end;

  DSA_test_flags := LoadLibCryptoFunction('DSA_test_flags');
  FuncLoadError := not assigned(DSA_test_flags);
  if FuncLoadError then
  begin
    DSA_test_flags :=  @ERROR_DSA_test_flags;
  end;

  DSA_set_flags := LoadLibCryptoFunction('DSA_set_flags');
  FuncLoadError := not assigned(DSA_set_flags);
  if FuncLoadError then
  begin
    DSA_set_flags :=  @ERROR_DSA_set_flags;
  end;

  DSA_get0_engine := LoadLibCryptoFunction('DSA_get0_engine');
  FuncLoadError := not assigned(DSA_get0_engine);
  if FuncLoadError then
  begin
    DSA_get0_engine :=  @ERROR_DSA_get0_engine;
  end;

  DSA_meth_new := LoadLibCryptoFunction('DSA_meth_new');
  FuncLoadError := not assigned(DSA_meth_new);
  if FuncLoadError then
  begin
    DSA_meth_new :=  @ERROR_DSA_meth_new;
  end;

  DSA_meth_free := LoadLibCryptoFunction('DSA_meth_free');
  FuncLoadError := not assigned(DSA_meth_free);
  if FuncLoadError then
  begin
    DSA_meth_free :=  @ERROR_DSA_meth_free;
  end;

  DSA_meth_dup := LoadLibCryptoFunction('DSA_meth_dup');
  FuncLoadError := not assigned(DSA_meth_dup);
  if FuncLoadError then
  begin
    DSA_meth_dup :=  @ERROR_DSA_meth_dup;
  end;

  DSA_meth_get0_name := LoadLibCryptoFunction('DSA_meth_get0_name');
  FuncLoadError := not assigned(DSA_meth_get0_name);
  if FuncLoadError then
  begin
    DSA_meth_get0_name :=  @ERROR_DSA_meth_get0_name;
  end;

  DSA_meth_set1_name := LoadLibCryptoFunction('DSA_meth_set1_name');
  FuncLoadError := not assigned(DSA_meth_set1_name);
  if FuncLoadError then
  begin
    DSA_meth_set1_name :=  @ERROR_DSA_meth_set1_name;
  end;

  DSA_meth_get_flags := LoadLibCryptoFunction('DSA_meth_get_flags');
  FuncLoadError := not assigned(DSA_meth_get_flags);
  if FuncLoadError then
  begin
    DSA_meth_get_flags :=  @ERROR_DSA_meth_get_flags;
  end;

  DSA_meth_set_flags := LoadLibCryptoFunction('DSA_meth_set_flags');
  FuncLoadError := not assigned(DSA_meth_set_flags);
  if FuncLoadError then
  begin
    DSA_meth_set_flags :=  @ERROR_DSA_meth_set_flags;
  end;

  DSA_meth_get0_app_data := LoadLibCryptoFunction('DSA_meth_get0_app_data');
  FuncLoadError := not assigned(DSA_meth_get0_app_data);
  if FuncLoadError then
  begin
    DSA_meth_get0_app_data :=  @ERROR_DSA_meth_get0_app_data;
  end;

  DSA_meth_set0_app_data := LoadLibCryptoFunction('DSA_meth_set0_app_data');
  FuncLoadError := not assigned(DSA_meth_set0_app_data);
  if FuncLoadError then
  begin
    DSA_meth_set0_app_data :=  @ERROR_DSA_meth_set0_app_data;
  end;

  DSA_meth_get_sign := LoadLibCryptoFunction('DSA_meth_get_sign');
  FuncLoadError := not assigned(DSA_meth_get_sign);
  if FuncLoadError then
  begin
    DSA_meth_get_sign :=  @ERROR_DSA_meth_get_sign;
  end;

  DSA_meth_set_sign := LoadLibCryptoFunction('DSA_meth_set_sign');
  FuncLoadError := not assigned(DSA_meth_set_sign);
  if FuncLoadError then
  begin
    DSA_meth_set_sign :=  @ERROR_DSA_meth_set_sign;
  end;

  DSA_meth_get_sign_setup := LoadLibCryptoFunction('DSA_meth_get_sign_setup');
  FuncLoadError := not assigned(DSA_meth_get_sign_setup);
  if FuncLoadError then
  begin
    DSA_meth_get_sign_setup :=  @ERROR_DSA_meth_get_sign_setup;
  end;

  DSA_meth_set_sign_setup := LoadLibCryptoFunction('DSA_meth_set_sign_setup');
  FuncLoadError := not assigned(DSA_meth_set_sign_setup);
  if FuncLoadError then
  begin
    DSA_meth_set_sign_setup :=  @ERROR_DSA_meth_set_sign_setup;
  end;

  DSA_meth_get_verify := LoadLibCryptoFunction('DSA_meth_get_verify');
  FuncLoadError := not assigned(DSA_meth_get_verify);
  if FuncLoadError then
  begin
    DSA_meth_get_verify :=  @ERROR_DSA_meth_get_verify;
  end;

  DSA_meth_set_verify := LoadLibCryptoFunction('DSA_meth_set_verify');
  FuncLoadError := not assigned(DSA_meth_set_verify);
  if FuncLoadError then
  begin
    DSA_meth_set_verify :=  @ERROR_DSA_meth_set_verify;
  end;

  DSA_meth_get_mod_exp := LoadLibCryptoFunction('DSA_meth_get_mod_exp');
  FuncLoadError := not assigned(DSA_meth_get_mod_exp);
  if FuncLoadError then
  begin
    DSA_meth_get_mod_exp :=  @ERROR_DSA_meth_get_mod_exp;
  end;

  DSA_meth_set_mod_exp := LoadLibCryptoFunction('DSA_meth_set_mod_exp');
  FuncLoadError := not assigned(DSA_meth_set_mod_exp);
  if FuncLoadError then
  begin
    DSA_meth_set_mod_exp :=  @ERROR_DSA_meth_set_mod_exp;
  end;

  DSA_meth_get_bn_mod_exp := LoadLibCryptoFunction('DSA_meth_get_bn_mod_exp');
  FuncLoadError := not assigned(DSA_meth_get_bn_mod_exp);
  if FuncLoadError then
  begin
    DSA_meth_get_bn_mod_exp :=  @ERROR_DSA_meth_get_bn_mod_exp;
  end;

  DSA_meth_set_bn_mod_exp := LoadLibCryptoFunction('DSA_meth_set_bn_mod_exp');
  FuncLoadError := not assigned(DSA_meth_set_bn_mod_exp);
  if FuncLoadError then
  begin
    DSA_meth_set_bn_mod_exp :=  @ERROR_DSA_meth_set_bn_mod_exp;
  end;

  DSA_meth_get_init := LoadLibCryptoFunction('DSA_meth_get_init');
  FuncLoadError := not assigned(DSA_meth_get_init);
  if FuncLoadError then
  begin
    DSA_meth_get_init :=  @ERROR_DSA_meth_get_init;
  end;

  DSA_meth_set_init := LoadLibCryptoFunction('DSA_meth_set_init');
  FuncLoadError := not assigned(DSA_meth_set_init);
  if FuncLoadError then
  begin
    DSA_meth_set_init :=  @ERROR_DSA_meth_set_init;
  end;

  DSA_meth_get_finish := LoadLibCryptoFunction('DSA_meth_get_finish');
  FuncLoadError := not assigned(DSA_meth_get_finish);
  if FuncLoadError then
  begin
    DSA_meth_get_finish :=  @ERROR_DSA_meth_get_finish;
  end;

  DSA_meth_set_finish := LoadLibCryptoFunction('DSA_meth_set_finish');
  FuncLoadError := not assigned(DSA_meth_set_finish);
  if FuncLoadError then
  begin
    DSA_meth_set_finish :=  @ERROR_DSA_meth_set_finish;
  end;

  DSA_meth_get_paramgen := LoadLibCryptoFunction('DSA_meth_get_paramgen');
  FuncLoadError := not assigned(DSA_meth_get_paramgen);
  if FuncLoadError then
  begin
    DSA_meth_get_paramgen :=  @ERROR_DSA_meth_get_paramgen;
  end;

  DSA_meth_set_paramgen := LoadLibCryptoFunction('DSA_meth_set_paramgen');
  FuncLoadError := not assigned(DSA_meth_set_paramgen);
  if FuncLoadError then
  begin
    DSA_meth_set_paramgen :=  @ERROR_DSA_meth_set_paramgen;
  end;

  DSA_meth_get_keygen := LoadLibCryptoFunction('DSA_meth_get_keygen');
  FuncLoadError := not assigned(DSA_meth_get_keygen);
  if FuncLoadError then
  begin
    DSA_meth_get_keygen :=  @ERROR_DSA_meth_get_keygen;
  end;

  DSA_meth_set_keygen := LoadLibCryptoFunction('DSA_meth_set_keygen');
  FuncLoadError := not assigned(DSA_meth_set_keygen);
  if FuncLoadError then
  begin
    DSA_meth_set_keygen :=  @ERROR_DSA_meth_set_keygen;
  end;

end;

procedure UnLoad;
begin
  DSAparams_dup := nil;
  DSA_SIG_new := nil;
  DSA_SIG_free := nil;
  i2d_DSA_SIG := nil;
  d2i_DSA_SIG := nil;
  DSA_SIG_get0 := nil;
  DSA_SIG_set0 := nil;
  DSA_do_sign := nil;
  DSA_do_verify := nil;
  DSA_OpenSSL := nil;
  DSA_set_default_method := nil;
  DSA_get_default_method := nil;
  DSA_set_method := nil;
  DSA_get_method := nil;
  DSA_new := nil;
  DSA_new_method := nil;
  DSA_free := nil;
  DSA_up_ref := nil;
  DSA_size := nil;
  DSA_bits := nil;
  DSA_security_bits := nil;
  DSA_sign := nil;
  DSA_verify := nil;
  DSA_set_ex_data := nil;
  DSA_get_ex_data := nil;
  d2i_DSAPublicKey := nil;
  d2i_DSAPrivateKey := nil;
  d2i_DSAparams := nil;
  DSA_generate_parameters_ex := nil;
  DSA_generate_key := nil;
  i2d_DSAPublicKey := nil;
  i2d_DSAPrivateKey := nil;
  i2d_DSAparams := nil;
  DSAparams_print := nil;
  DSA_print := nil;
  DSA_dup_DH := nil;
  DSA_get0_pqg := nil;
  DSA_set0_pqg := nil;
  DSA_get0_key := nil;
  DSA_set0_key := nil;
  DSA_get0_p := nil;
  DSA_get0_q := nil;
  DSA_get0_g := nil;
  DSA_get0_pub_key := nil;
  DSA_get0_priv_key := nil;
  DSA_clear_flags := nil;
  DSA_test_flags := nil;
  DSA_set_flags := nil;
  DSA_get0_engine := nil;
  DSA_meth_new := nil;
  DSA_meth_free := nil;
  DSA_meth_dup := nil;
  DSA_meth_get0_name := nil;
  DSA_meth_set1_name := nil;
  DSA_meth_get_flags := nil;
  DSA_meth_set_flags := nil;
  DSA_meth_get0_app_data := nil;
  DSA_meth_set0_app_data := nil;
  DSA_meth_get_sign := nil;
  DSA_meth_set_sign := nil;
  DSA_meth_get_sign_setup := nil;
  DSA_meth_set_sign_setup := nil;
  DSA_meth_get_verify := nil;
  DSA_meth_set_verify := nil;
  DSA_meth_get_mod_exp := nil;
  DSA_meth_set_mod_exp := nil;
  DSA_meth_get_bn_mod_exp := nil;
  DSA_meth_set_bn_mod_exp := nil;
  DSA_meth_get_init := nil;
  DSA_meth_set_init := nil;
  DSA_meth_get_finish := nil;
  DSA_meth_set_finish := nil;
  DSA_meth_get_paramgen := nil;
  DSA_meth_set_paramgen := nil;
  DSA_meth_get_keygen := nil;
  DSA_meth_set_keygen := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
