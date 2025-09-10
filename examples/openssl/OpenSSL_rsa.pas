(* This unit was generated from the source file rsa.h2pas 
It should not be modified directly. All changes should be made to rsa.h2pas
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


unit OpenSSL_rsa;


interface

// Headers for OpenSSL 1.1.1
// rsa.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_evp;

(* The types RSA and RSA_METHOD are defined in ossl_typ.h *)

const
  OPENSSL_RSA_MAX_MODULUS_BITS =  16384;
  OPENSSL_RSA_FIPS_MIN_MODULUS_BITS = 1024;
  OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;
  (* exponent limit enforced for "large" modulus only *)
  OPENSSL_RSA_MAX_PUBEXP_BITS =  64;

  RSA_3 =  TOpenSSL_C_Long($3);
  RSA_F4 = TOpenSSL_C_Long($10001);

  (* based on RFC 8017 appendix A.1.2 *)
  RSA_ASN1_VERSION_DEFAULT = 0;
  RSA_ASN1_VERSION_MULTI =   1;
  RSA_DEFAULT_PRIME_NUM =    2;

  RSA_METHOD_FLAG_NO_CHECK = $0001; (* don't check pub/private match *)
  RSA_FLAG_CACHE_PUBLIC =    $0002;
  RSA_FLAG_CACHE_PRIVATE =   $0004;
  RSA_FLAG_BLINDING =        $0008;
  RSA_FLAG_THREAD_SAFE =     $0010;
  (*
   * This flag means the private key operations will be handled by rsa_mod_exp
   * and that they do not depend on the private key components being present:
   * for example a key stored in external hardware. Without this flag
   * bn_mod_exp gets called when private key components are absent.
   *)
  RSA_FLAG_EXT_PKEY =        $0020;
  (*
   * new with 0.9.6j and 0.9.7b; the built-in
   * RSA implementation now uses blinding by
   * default (ignoring RSA_FLAG_BLINDING),
   * but other engines might not need it
   *)
  RSA_FLAG_NO_BLINDING =     $0080;
  (*
   * Does nothing. Previously this switched off constant time behaviour.
   *)
  RSA_FLAG_NO_CONSTTIME =    $0000;

  (* Salt length matches digest *)
  RSA_PSS_SALTLEN_DIGEST = -1;
  (* Verify only: auto detect salt length *)
  RSA_PSS_SALTLEN_AUTO = -2;
  (* Set salt length to maximum possible *)
  RSA_PSS_SALTLEN_MAX = -3;
  (* Old compatible max salt length for sign only *)
  RSA_PSS_SALTLEN_MAX_SIGN = -2;

  EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL + 1;
  EVP_PKEY_CTRL_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 2;

  EVP_PKEY_CTRL_RSA_KEYGEN_BITS = EVP_PKEY_ALG_CTRL + 3;
  EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = EVP_PKEY_ALG_CTRL + 4;
  EVP_PKEY_CTRL_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL + 5;

  EVP_PKEY_CTRL_GET_RSA_PADDING =  EVP_PKEY_ALG_CTRL + 6;
  EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL + 7;
  EVP_PKEY_CTRL_GET_RSA_MGF1_MD =  EVP_PKEY_ALG_CTRL + 8;

  EVP_PKEY_CTRL_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL + 9;
  EVP_PKEY_CTRL_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL + 10;

  EVP_PKEY_CTRL_GET_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL + 11;
  EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL + 12;

  EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES = EVP_PKEY_ALG_CTRL + 13;

  RSA_PKCS1_PADDING =   1;
  RSA_SSLV23_PADDING =  2;
  RSA_NO_PADDING =   3;
  RSA_PKCS1_OAEP_PADDING = 4;
  RSA_X931_PADDING =   5;
  RSA_PKCS1_PSS_PADDING =  6; (* EVP_PKEY_ only *)
  RSA_PKCS1_PADDING_SIZE = 11;

  (*
   * If this flag is set the RSA method is FIPS compliant and can be used in
   * FIPS mode. This is set in the validated module method. If an application
   * sets this flag in its own methods it is its responsibility to ensure the
   * result is compliant.
   *)
  RSA_FLAG_FIPS_METHOD = $0400;
  (*
   * If this flag is set the operations normally disabled in FIPS mode are
   * permitted it is then the applications responsibility to ensure that the
   * usage is compliant.
   *)
  RSA_FLAG_NON_FIPS_ALLOW = $0400;
  (*
   * Application has decided PRNG is good enough to generate a key: don't
   * check.
   *)
  RSA_FLAG_CHECKED = $0800;

type
  rsa_pss_params_st = record
    hashAlgorithm: PX509_ALGOR;
    maskGenAlgorithm: PX509_ALGOR;
    saltLength: PASN1_INTEGER;
    trailerField: PASN1_INTEGER;
    (* Decoded hash algorithm from maskGenAlgorithm *)
    maskHash: PX509_ALGOR;
  end;
  RSA_PSS_PARAMS = rsa_pss_params_st;
  // DECLARE_ASN1_FUNCTIONS(RSA_PSS_PARAMS)

  rsa_oaep_params_st = record
    hashFunc: PX509_ALGOR;
    maskGenFunc: PX509_ALGOR;
    pSourceFunc: PX509_ALGOR;
    (* Decoded hash algorithm from maskGenFunc *)
    maskHash: PX509_ALGOR;
  end;
  RSA_OAEP_PARAMS = rsa_oaep_params_st;
  //DECLARE_ASN1_FUNCTIONS(RSA_OAEP_PARAMS)

  //DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
  //DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPrivateKey)

  RSA_meth_set_priv_dec_priv_dec = function(flen: TOpenSSL_C_INT; const from: PByte;
    to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_mod_exp_mod_exp = function(r0: PBIGNUM; const i: PBIGNUM;
    rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_bn_mod_exp_bn_mod_exp = function(r: PBIGNUM; const a: PBIGNUM;
    const p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTx; m_ctx: PBN_MONT_CTx): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_init_init = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_finish_finish = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_sign_sign = function(type_: TOpenSSL_C_INT; const m: PByte;
    m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; const rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_verify_verify = function(dtype: TOpenSSL_C_INT; const m: PByte;
    m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; const rsa: PRSA): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_keygen_keygen = function(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCb): TOpenSSL_C_INT; cdecl;

  RSA_meth_set_multi_prime_keygen_keygen = function(rsa: PRSA; bits: TOpenSSL_C_INT;
    primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCb): TOpenSSL_C_INT; cdecl;

//# define EVP_PKEY_CTX_set_rsa_padding(ctx, pad) \
//        RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad, NULL)
//
//# define EVP_PKEY_CTX_get_rsa_padding(ctx, ppad) \
//        RSA_pkey_ctx_ctrl(ctx, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, ppad)
//
//# define EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, len) \
//        RSA_pkey_ctx_ctrl(ctx, (EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), \
//                          EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)

//# define EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, len) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_PSS_SALTLEN, len, NULL)
//
//# define EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, plen) \
//        RSA_pkey_ctx_ctrl(ctx, (EVP_PKEY_OP_SIGN|EVP_PKEY_OP_VERIFY), \
//                          EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, plen)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp)
//
//# define EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, primes, NULL)
//
//# define  EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, \
//                          EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, \
//                          EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)(md))
//
//# define  EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, pmd) \
//        RSA_pkey_ctx_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, \
//                          EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, (void *)(pmd))
//
//# define  EVP_PKEY_CTX_get_rsa_oaep_md(ctx, pmd) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, (void *)(pmd))
//
//# define  EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, l, llen) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)(l))
//
//# define  EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, l) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,  \
//                          EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, (void *)(l))
//
//# define  EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md) \
//        EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA_PSS,  \
//                          EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_MD,  \
//                          0, (void *)(md))

//# define RSA_set_app_data(s,arg)         RSA_set_ex_data(s,0,arg)
//# define RSA_get_app_data(s)             RSA_get_ex_data(s,0)

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM RSA_new}
{$EXTERNALSYM RSA_new_method}
{$EXTERNALSYM RSA_bits}
{$EXTERNALSYM RSA_size}
{$EXTERNALSYM RSA_security_bits}
{$EXTERNALSYM RSA_set0_key}
{$EXTERNALSYM RSA_set0_factors}
{$EXTERNALSYM RSA_set0_crt_params}
{$EXTERNALSYM RSA_get0_key}
{$EXTERNALSYM RSA_get0_factors}
{$EXTERNALSYM RSA_get_multi_prime_extra_count}
{$EXTERNALSYM RSA_get0_crt_params}
{$EXTERNALSYM RSA_get0_n}
{$EXTERNALSYM RSA_get0_e}
{$EXTERNALSYM RSA_get0_d}
{$EXTERNALSYM RSA_get0_p}
{$EXTERNALSYM RSA_get0_q}
{$EXTERNALSYM RSA_get0_dmp1}
{$EXTERNALSYM RSA_get0_dmq1}
{$EXTERNALSYM RSA_get0_iqmp}
{$EXTERNALSYM RSA_clear_flags}
{$EXTERNALSYM RSA_test_flags}
{$EXTERNALSYM RSA_set_flags}
{$EXTERNALSYM RSA_get_version}
{$EXTERNALSYM RSA_get0_engine}
{$EXTERNALSYM RSA_generate_key_ex}
{$EXTERNALSYM RSA_generate_multi_prime_key}
{$EXTERNALSYM RSA_X931_derive_ex}
{$EXTERNALSYM RSA_X931_generate_key_ex}
{$EXTERNALSYM RSA_check_key}
{$EXTERNALSYM RSA_check_key_ex}
{$EXTERNALSYM RSA_public_encrypt}
{$EXTERNALSYM RSA_private_encrypt}
{$EXTERNALSYM RSA_public_decrypt}
{$EXTERNALSYM RSA_private_decrypt}
{$EXTERNALSYM RSA_free}
{$EXTERNALSYM RSA_up_ref}
{$EXTERNALSYM RSA_flags}
{$EXTERNALSYM RSA_set_default_method}
{$EXTERNALSYM RSA_get_default_method}
{$EXTERNALSYM RSA_null_method}
{$EXTERNALSYM RSA_get_method}
{$EXTERNALSYM RSA_set_method}
{$EXTERNALSYM RSA_PKCS1_OpenSSL}
{$EXTERNALSYM RSA_pkey_ctx_ctrl}
{$EXTERNALSYM RSA_print}
{$EXTERNALSYM RSA_sign}
{$EXTERNALSYM RSA_verify}
{$EXTERNALSYM RSA_sign_ASN1_OCTET_STRING}
{$EXTERNALSYM RSA_verify_ASN1_OCTET_STRING}
{$EXTERNALSYM RSA_blinding_on}
{$EXTERNALSYM RSA_blinding_off}
{$EXTERNALSYM RSA_setup_blinding}
{$EXTERNALSYM RSA_padding_add_PKCS1_type_1}
{$EXTERNALSYM RSA_padding_check_PKCS1_type_1}
{$EXTERNALSYM RSA_padding_add_PKCS1_type_2}
{$EXTERNALSYM RSA_padding_check_PKCS1_type_2}
{$EXTERNALSYM PKCS1_MGF1}
{$EXTERNALSYM RSA_padding_add_PKCS1_OAEP}
{$EXTERNALSYM RSA_padding_check_PKCS1_OAEP}
{$EXTERNALSYM RSA_padding_add_PKCS1_OAEP_mgf1}
{$EXTERNALSYM RSA_padding_check_PKCS1_OAEP_mgf1}
{$EXTERNALSYM RSA_padding_add_none}
{$EXTERNALSYM RSA_padding_check_none}
{$EXTERNALSYM RSA_padding_add_X931}
{$EXTERNALSYM RSA_padding_check_X931}
{$EXTERNALSYM RSA_X931_hash_id}
{$EXTERNALSYM RSA_verify_PKCS1_PSS}
{$EXTERNALSYM RSA_padding_add_PKCS1_PSS}
{$EXTERNALSYM RSA_verify_PKCS1_PSS_mgf1}
{$EXTERNALSYM RSA_padding_add_PKCS1_PSS_mgf1}
{$EXTERNALSYM RSA_set_ex_data}
{$EXTERNALSYM RSA_get_ex_data}
{$EXTERNALSYM RSAPublicKey_dup}
{$EXTERNALSYM RSAPrivateKey_dup}
{$EXTERNALSYM RSA_meth_new}
{$EXTERNALSYM RSA_meth_free}
{$EXTERNALSYM RSA_meth_dup}
{$EXTERNALSYM RSA_meth_get0_name}
{$EXTERNALSYM RSA_meth_set1_name}
{$EXTERNALSYM RSA_meth_get_flags}
{$EXTERNALSYM RSA_meth_set_flags}
{$EXTERNALSYM RSA_meth_get0_app_data}
{$EXTERNALSYM RSA_meth_set0_app_data}
{$EXTERNALSYM RSA_meth_set_priv_dec}
{$EXTERNALSYM RSA_meth_set_mod_exp}
{$EXTERNALSYM RSA_meth_set_bn_mod_exp}
{$EXTERNALSYM RSA_meth_set_init}
{$EXTERNALSYM RSA_meth_set_finish}
{$EXTERNALSYM RSA_meth_set_sign}
{$EXTERNALSYM RSA_meth_set_verify}
{$EXTERNALSYM RSA_meth_set_keygen}
{$EXTERNALSYM RSA_meth_set_multi_prime_keygen}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function RSA_new: PRSA; cdecl; external CLibCrypto;
function RSA_new_method(engine: PENGINE): PRSA; cdecl; external CLibCrypto;
function RSA_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_size(const rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_security_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_get0_key(const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl; external CLibCrypto;
procedure RSA_get0_factors(const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl; external CLibCrypto;
function RSA_get_multi_prime_extra_count(const r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_get0_crt_params(const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl; external CLibCrypto;
function RSA_get0_n(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_e(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_d(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_p(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_q(const d: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_dmp1(const r: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_dmq1(const r: PRSA): PBIGNUM; cdecl; external CLibCrypto;
function RSA_get0_iqmp(const r: PRSA): PBIGNUM; cdecl; external CLibCrypto;
procedure RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function RSA_test_flags(const r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_get0_engine(const r: PRSA): PENGINE; cdecl; external CLibCrypto;
function RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_check_key(const v1: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_check_key_ex(const v1: PRSA; cb: BN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_public_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_private_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_public_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_private_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_free(r: PRSA); cdecl; external CLibCrypto;
function RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_flags(const r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_set_default_method(const meth: PRSA_METHOD); cdecl; external CLibCrypto;
function RSA_get_default_method: PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_null_method: PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_get_method(const rsa: PRSA): PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_set_method(rsa: PRSA; const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_print(bp: PBIO; const r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_sign(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure RSA_blinding_off(rsa: PRSA); cdecl; external CLibCrypto;
function RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS1_MGF1(mask: PByte; len: TOpenSSL_C_LONG; const seed: PByte; seedlen: TOpenSSL_C_LONG; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_check_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify_PKCS1_PSS(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_get_ex_data(const r: PRSA; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function RSAPublicKey_dup(rsa: PRSA): PRSA; cdecl; external CLibCrypto;
function RSAPrivateKey_dup(rsa: PRSA): PRSA; cdecl; external CLibCrypto;
function RSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl; external CLibCrypto;
procedure RSA_meth_free(meth: PRSA_METHOD); cdecl; external CLibCrypto;
function RSA_meth_dup(const meth: PRSA_METHOD): PRSA_METHOD; cdecl; external CLibCrypto;
function RSA_meth_get0_name(const meth: PRSA_METHOD): PAnsiChar; cdecl; external CLibCrypto;
function RSA_meth_set1_name(meth: PRSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_get_flags(const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_get0_app_data(const meth: PRSA_METHOD): Pointer; cdecl; external CLibCrypto;
function RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_init(rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_finish(rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_sign(rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_verify(rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  RSA_new: function : PRSA; cdecl = nil;
  RSA_new_method: function (engine: PENGINE): PRSA; cdecl = nil;
  RSA_bits: function (const rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_size: function (const rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_security_bits: function (const rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_set0_key: function (r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  RSA_set0_factors: function (r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  RSA_set0_crt_params: function (r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  RSA_get0_key: procedure (const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl = nil;
  RSA_get0_factors: procedure (const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl = nil;
  RSA_get_multi_prime_extra_count: function (const r: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_get0_crt_params: procedure (const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl = nil;
  RSA_get0_n: function (const d: PRSA): PBIGNUM; cdecl = nil;
  RSA_get0_e: function (const d: PRSA): PBIGNUM; cdecl = nil;
  RSA_get0_d: function (const d: PRSA): PBIGNUM; cdecl = nil;
  RSA_get0_p: function (const d: PRSA): PBIGNUM; cdecl = nil;
  RSA_get0_q: function (const d: PRSA): PBIGNUM; cdecl = nil;
  RSA_get0_dmp1: function (const r: PRSA): PBIGNUM; cdecl = nil;
  RSA_get0_dmq1: function (const r: PRSA): PBIGNUM; cdecl = nil;
  RSA_get0_iqmp: function (const r: PRSA): PBIGNUM; cdecl = nil;
  RSA_clear_flags: procedure (r: PRSA; flags: TOpenSSL_C_INT); cdecl = nil;
  RSA_test_flags: function (const r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_set_flags: procedure (r: PRSA; flags: TOpenSSL_C_INT); cdecl = nil;
  RSA_get_version: function (r: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_get0_engine: function (const r: PRSA): PENGINE; cdecl = nil;
  RSA_generate_key_ex: function (rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  RSA_generate_multi_prime_key: function (rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  RSA_X931_derive_ex: function (rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  RSA_X931_generate_key_ex: function (rsa: PRSA; bits: TOpenSSL_C_INT; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  RSA_check_key: function (const v1: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_check_key_ex: function (const v1: PRSA; cb: BN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  RSA_public_encrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_private_encrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_public_decrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_private_decrypt: function (flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_free: procedure (r: PRSA); cdecl = nil;
  RSA_up_ref: function (r: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_flags: function (const r: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_set_default_method: procedure (const meth: PRSA_METHOD); cdecl = nil;
  RSA_get_default_method: function : PRSA_METHOD; cdecl = nil;
  RSA_null_method: function : PRSA_METHOD; cdecl = nil;
  RSA_get_method: function (const rsa: PRSA): PRSA_METHOD; cdecl = nil;
  RSA_set_method: function (rsa: PRSA; const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = nil;
  RSA_PKCS1_OpenSSL: function : PRSA_METHOD; cdecl = nil;
  RSA_pkey_ctx_ctrl: function (ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl = nil;
  RSA_print: function (bp: PBIO; const r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_sign: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_verify: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_sign_ASN1_OCTET_STRING: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_verify_ASN1_OCTET_STRING: function (type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = nil;
  RSA_blinding_on: function (rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  RSA_blinding_off: procedure (rsa: PRSA); cdecl = nil;
  RSA_setup_blinding: function (rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl = nil;
  RSA_padding_add_PKCS1_type_1: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_check_PKCS1_type_1: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_add_PKCS1_type_2: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_check_PKCS1_type_2: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS1_MGF1: function (mask: PByte; len: TOpenSSL_C_LONG; const seed: PByte; seedlen: TOpenSSL_C_LONG; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_add_PKCS1_OAEP: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_check_PKCS1_OAEP: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_add_PKCS1_OAEP_mgf1: function (to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_check_PKCS1_OAEP_mgf1: function (to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_add_none: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_check_none: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_add_X931: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_check_X931: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_X931_hash_id: function (nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_verify_PKCS1_PSS: function (rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_add_PKCS1_PSS: function (rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_verify_PKCS1_PSS_mgf1: function (rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_padding_add_PKCS1_PSS_mgf1: function (rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_set_ex_data: function (r: PRSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  RSA_get_ex_data: function (const r: PRSA; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  RSAPublicKey_dup: function (rsa: PRSA): PRSA; cdecl = nil;
  RSAPrivateKey_dup: function (rsa: PRSA): PRSA; cdecl = nil;
  RSA_meth_new: function (const name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl = nil;
  RSA_meth_free: procedure (meth: PRSA_METHOD); cdecl = nil;
  RSA_meth_dup: function (const meth: PRSA_METHOD): PRSA_METHOD; cdecl = nil;
  RSA_meth_get0_name: function (const meth: PRSA_METHOD): PAnsiChar; cdecl = nil;
  RSA_meth_set1_name: function (meth: PRSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_get_flags: function (const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_flags: function (meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_get0_app_data: function (const meth: PRSA_METHOD): Pointer; cdecl = nil;
  RSA_meth_set0_app_data: function (meth: PRSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_priv_dec: function (rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_mod_exp: function (rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_bn_mod_exp: function (rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_init: function (rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_finish: function (rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_sign: function (rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_verify: function (rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_keygen: function (rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TOpenSSL_C_INT; cdecl = nil;
  RSA_meth_set_multi_prime_keygen: function (meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TOpenSSL_C_INT; cdecl = nil;
{$ENDIF}
const
  RSA_padding_add_SSLv23_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  RSA_padding_check_SSLv23_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}


implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  RSA_padding_add_SSLv23: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  RSA_padding_check_SSLv23: function (to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_RSA_new: PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_new');
end;

function ERROR_RSA_new_method(engine: PENGINE): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_new_method');
end;

function ERROR_RSA_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_bits');
end;

function ERROR_RSA_size(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_size');
end;

function ERROR_RSA_security_bits(const rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_security_bits');
end;

function ERROR_RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_key');
end;

function ERROR_RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_factors');
end;

function ERROR_RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_crt_params');
end;

procedure ERROR_RSA_get0_key(const r: PRSA; const n: PPBIGNUM; const e: PPBIGNUM; const d: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_key');
end;

procedure ERROR_RSA_get0_factors(const r: PRSA; const p: PPBIGNUM; const q: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_factors');
end;

function ERROR_RSA_get_multi_prime_extra_count(const r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_multi_prime_extra_count');
end;

procedure ERROR_RSA_get0_crt_params(const r: PRSA; const dmp1: PPBIGNUM; const dmq1: PPBIGNUM; const iqmp: PPBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_crt_params');
end;

function ERROR_RSA_get0_n(const d: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_n');
end;

function ERROR_RSA_get0_e(const d: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_e');
end;

function ERROR_RSA_get0_d(const d: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_d');
end;

function ERROR_RSA_get0_p(const d: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_p');
end;

function ERROR_RSA_get0_q(const d: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_q');
end;

function ERROR_RSA_get0_dmp1(const r: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_dmp1');
end;

function ERROR_RSA_get0_dmq1(const r: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_dmq1');
end;

function ERROR_RSA_get0_iqmp(const r: PRSA): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_iqmp');
end;

procedure ERROR_RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_clear_flags');
end;

function ERROR_RSA_test_flags(const r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_test_flags');
end;

procedure ERROR_RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_flags');
end;

function ERROR_RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_version');
end;

function ERROR_RSA_get0_engine(const r: PRSA): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_engine');
end;

function ERROR_RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_generate_key_ex');
end;

function ERROR_RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_generate_multi_prime_key');
end;

function ERROR_RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const Xp: PBIGNUM; const Xq1: PBIGNUM; const Xq2: PBIGNUM; const Xq: PBIGNUM; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_derive_ex');
end;

function ERROR_RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; const e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_generate_key_ex');
end;

function ERROR_RSA_check_key(const v1: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_check_key');
end;

function ERROR_RSA_check_key_ex(const v1: PRSA; cb: BN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_check_key_ex');
end;

function ERROR_RSA_public_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_public_encrypt');
end;

function ERROR_RSA_private_encrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_private_encrypt');
end;

function ERROR_RSA_public_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_public_decrypt');
end;

function ERROR_RSA_private_decrypt(flen: TOpenSSL_C_INT; const from: PByte; to_: PByte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_private_decrypt');
end;

procedure ERROR_RSA_free(r: PRSA); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_free');
end;

function ERROR_RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_up_ref');
end;

function ERROR_RSA_flags(const r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_flags');
end;

procedure ERROR_RSA_set_default_method(const meth: PRSA_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_default_method');
end;

function ERROR_RSA_get_default_method: PRSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_default_method');
end;

function ERROR_RSA_null_method: PRSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_null_method');
end;

function ERROR_RSA_get_method(const rsa: PRSA): PRSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_method');
end;

function ERROR_RSA_set_method(rsa: PRSA; const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_method');
end;

function ERROR_RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_PKCS1_OpenSSL');
end;

function ERROR_RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_pkey_ctx_ctrl');
end;

function ERROR_RSA_print(bp: PBIO; const r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_print');
end;

function ERROR_RSA_sign(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_sign');
end;

function ERROR_RSA_verify(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify');
end;

function ERROR_RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigret: PByte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_sign_ASN1_OCTET_STRING');
end;

function ERROR_RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; const m: PByte; m_length: TOpenSSL_C_UINT; sigbuf: PByte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_ASN1_OCTET_STRING');
end;

function ERROR_RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_blinding_on');
end;

procedure ERROR_RSA_blinding_off(rsa: PRSA); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_blinding_off');
end;

function ERROR_RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_setup_blinding');
end;

function ERROR_RSA_padding_add_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_type_1');
end;

function ERROR_RSA_padding_check_PKCS1_type_1(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_type_1');
end;

function ERROR_RSA_padding_add_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_type_2');
end;

function ERROR_RSA_padding_check_PKCS1_type_2(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_type_2');
end;

function ERROR_PKCS1_MGF1(mask: PByte; len: TOpenSSL_C_LONG; const seed: PByte; seedlen: TOpenSSL_C_LONG; const dgst: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS1_MGF1');
end;

function ERROR_RSA_padding_add_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_OAEP');
end;

function ERROR_RSA_padding_check_PKCS1_OAEP(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; const p: PByte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_OAEP');
end;

function ERROR_RSA_padding_add_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_OAEP_mgf1');
end;

function ERROR_RSA_padding_check_PKCS1_OAEP_mgf1(to_: PByte; tlen: TOpenSSL_C_INT; const from: PByte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; const param: PByte; plen: TOpenSSL_C_INT; const md: PEVP_MD; const mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_OAEP_mgf1');
end;

function ERROR_RSA_padding_add_SSLv23(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_SSLv23');
end;

function ERROR_RSA_padding_check_SSLv23(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_SSLv23');
end;

function ERROR_RSA_padding_add_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_none');
end;

function ERROR_RSA_padding_check_none(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_none');
end;

function ERROR_RSA_padding_add_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_X931');
end;

function ERROR_RSA_padding_check_X931(to_: PByte; tlen: TOpenSSL_C_INT; const f: PByte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_X931');
end;

function ERROR_RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_hash_id');
end;

function ERROR_RSA_verify_PKCS1_PSS(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_PKCS1_PSS');
end;

function ERROR_RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_PSS');
end;

function ERROR_RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; const EM: PByte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_PKCS1_PSS_mgf1');
end;

function ERROR_RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: PByte; const mHash: PByte; const Hash: PEVP_MD; const mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_PSS_mgf1');
end;

function ERROR_RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_ex_data');
end;

function ERROR_RSA_get_ex_data(const r: PRSA; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_ex_data');
end;

function ERROR_RSAPublicKey_dup(rsa: PRSA): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPublicKey_dup');
end;

function ERROR_RSAPrivateKey_dup(rsa: PRSA): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPrivateKey_dup');
end;

function ERROR_RSA_meth_new(const name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_new');
end;

procedure ERROR_RSA_meth_free(meth: PRSA_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_free');
end;

function ERROR_RSA_meth_dup(const meth: PRSA_METHOD): PRSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_dup');
end;

function ERROR_RSA_meth_get0_name(const meth: PRSA_METHOD): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get0_name');
end;

function ERROR_RSA_meth_set1_name(meth: PRSA_METHOD; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set1_name');
end;

function ERROR_RSA_meth_get_flags(const meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_flags');
end;

function ERROR_RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_flags');
end;

function ERROR_RSA_meth_get0_app_data(const meth: PRSA_METHOD): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get0_app_data');
end;

function ERROR_RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set0_app_data');
end;

function ERROR_RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: RSA_meth_set_priv_dec_priv_dec): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_priv_dec');
end;

function ERROR_RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: RSA_meth_set_mod_exp_mod_exp): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_mod_exp');
end;

function ERROR_RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: RSA_meth_set_bn_mod_exp_bn_mod_exp): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_bn_mod_exp');
end;

function ERROR_RSA_meth_set_init(rsa: PRSA_METHOD; init: RSA_meth_set_init_init): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_init');
end;

function ERROR_RSA_meth_set_finish(rsa: PRSA_METHOD; finish: RSA_meth_set_finish_finish): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_finish');
end;

function ERROR_RSA_meth_set_sign(rsa: PRSA_METHOD; sign: RSA_meth_set_sign_sign): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_sign');
end;

function ERROR_RSA_meth_set_verify(rsa: PRSA_METHOD; verify: RSA_meth_set_verify_verify): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_verify');
end;

function ERROR_RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: RSA_meth_set_keygen_keygen): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_keygen');
end;

function ERROR_RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: RSA_meth_set_multi_prime_keygen_keygen): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_multi_prime_keygen');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  RSA_new := LoadLibCryptoFunction('RSA_new');
  FuncLoadError := not assigned(RSA_new);
  if FuncLoadError then
  begin
    RSA_new :=  @ERROR_RSA_new;
  end;

  RSA_new_method := LoadLibCryptoFunction('RSA_new_method');
  FuncLoadError := not assigned(RSA_new_method);
  if FuncLoadError then
  begin
    RSA_new_method :=  @ERROR_RSA_new_method;
  end;

  RSA_bits := LoadLibCryptoFunction('RSA_bits');
  FuncLoadError := not assigned(RSA_bits);
  if FuncLoadError then
  begin
    RSA_bits :=  @ERROR_RSA_bits;
  end;

  RSA_size := LoadLibCryptoFunction('RSA_size');
  FuncLoadError := not assigned(RSA_size);
  if FuncLoadError then
  begin
    RSA_size :=  @ERROR_RSA_size;
  end;

  RSA_security_bits := LoadLibCryptoFunction('RSA_security_bits');
  FuncLoadError := not assigned(RSA_security_bits);
  if FuncLoadError then
  begin
    RSA_security_bits :=  @ERROR_RSA_security_bits;
  end;

  RSA_set0_key := LoadLibCryptoFunction('RSA_set0_key');
  FuncLoadError := not assigned(RSA_set0_key);
  if FuncLoadError then
  begin
    RSA_set0_key :=  @ERROR_RSA_set0_key;
  end;

  RSA_set0_factors := LoadLibCryptoFunction('RSA_set0_factors');
  FuncLoadError := not assigned(RSA_set0_factors);
  if FuncLoadError then
  begin
    RSA_set0_factors :=  @ERROR_RSA_set0_factors;
  end;

  RSA_set0_crt_params := LoadLibCryptoFunction('RSA_set0_crt_params');
  FuncLoadError := not assigned(RSA_set0_crt_params);
  if FuncLoadError then
  begin
    RSA_set0_crt_params :=  @ERROR_RSA_set0_crt_params;
  end;

  RSA_get0_key := LoadLibCryptoFunction('RSA_get0_key');
  FuncLoadError := not assigned(RSA_get0_key);
  if FuncLoadError then
  begin
    RSA_get0_key :=  @ERROR_RSA_get0_key;
  end;

  RSA_get0_factors := LoadLibCryptoFunction('RSA_get0_factors');
  FuncLoadError := not assigned(RSA_get0_factors);
  if FuncLoadError then
  begin
    RSA_get0_factors :=  @ERROR_RSA_get0_factors;
  end;

  RSA_get_multi_prime_extra_count := LoadLibCryptoFunction('RSA_get_multi_prime_extra_count');
  FuncLoadError := not assigned(RSA_get_multi_prime_extra_count);
  if FuncLoadError then
  begin
    RSA_get_multi_prime_extra_count :=  @ERROR_RSA_get_multi_prime_extra_count;
  end;

  RSA_get0_crt_params := LoadLibCryptoFunction('RSA_get0_crt_params');
  FuncLoadError := not assigned(RSA_get0_crt_params);
  if FuncLoadError then
  begin
    RSA_get0_crt_params :=  @ERROR_RSA_get0_crt_params;
  end;

  RSA_get0_n := LoadLibCryptoFunction('RSA_get0_n');
  FuncLoadError := not assigned(RSA_get0_n);
  if FuncLoadError then
  begin
    RSA_get0_n :=  @ERROR_RSA_get0_n;
  end;

  RSA_get0_e := LoadLibCryptoFunction('RSA_get0_e');
  FuncLoadError := not assigned(RSA_get0_e);
  if FuncLoadError then
  begin
    RSA_get0_e :=  @ERROR_RSA_get0_e;
  end;

  RSA_get0_d := LoadLibCryptoFunction('RSA_get0_d');
  FuncLoadError := not assigned(RSA_get0_d);
  if FuncLoadError then
  begin
    RSA_get0_d :=  @ERROR_RSA_get0_d;
  end;

  RSA_get0_p := LoadLibCryptoFunction('RSA_get0_p');
  FuncLoadError := not assigned(RSA_get0_p);
  if FuncLoadError then
  begin
    RSA_get0_p :=  @ERROR_RSA_get0_p;
  end;

  RSA_get0_q := LoadLibCryptoFunction('RSA_get0_q');
  FuncLoadError := not assigned(RSA_get0_q);
  if FuncLoadError then
  begin
    RSA_get0_q :=  @ERROR_RSA_get0_q;
  end;

  RSA_get0_dmp1 := LoadLibCryptoFunction('RSA_get0_dmp1');
  FuncLoadError := not assigned(RSA_get0_dmp1);
  if FuncLoadError then
  begin
    RSA_get0_dmp1 :=  @ERROR_RSA_get0_dmp1;
  end;

  RSA_get0_dmq1 := LoadLibCryptoFunction('RSA_get0_dmq1');
  FuncLoadError := not assigned(RSA_get0_dmq1);
  if FuncLoadError then
  begin
    RSA_get0_dmq1 :=  @ERROR_RSA_get0_dmq1;
  end;

  RSA_get0_iqmp := LoadLibCryptoFunction('RSA_get0_iqmp');
  FuncLoadError := not assigned(RSA_get0_iqmp);
  if FuncLoadError then
  begin
    RSA_get0_iqmp :=  @ERROR_RSA_get0_iqmp;
  end;

  RSA_clear_flags := LoadLibCryptoFunction('RSA_clear_flags');
  FuncLoadError := not assigned(RSA_clear_flags);
  if FuncLoadError then
  begin
    RSA_clear_flags :=  @ERROR_RSA_clear_flags;
  end;

  RSA_test_flags := LoadLibCryptoFunction('RSA_test_flags');
  FuncLoadError := not assigned(RSA_test_flags);
  if FuncLoadError then
  begin
    RSA_test_flags :=  @ERROR_RSA_test_flags;
  end;

  RSA_set_flags := LoadLibCryptoFunction('RSA_set_flags');
  FuncLoadError := not assigned(RSA_set_flags);
  if FuncLoadError then
  begin
    RSA_set_flags :=  @ERROR_RSA_set_flags;
  end;

  RSA_get_version := LoadLibCryptoFunction('RSA_get_version');
  FuncLoadError := not assigned(RSA_get_version);
  if FuncLoadError then
  begin
    RSA_get_version :=  @ERROR_RSA_get_version;
  end;

  RSA_get0_engine := LoadLibCryptoFunction('RSA_get0_engine');
  FuncLoadError := not assigned(RSA_get0_engine);
  if FuncLoadError then
  begin
    RSA_get0_engine :=  @ERROR_RSA_get0_engine;
  end;

  RSA_generate_key_ex := LoadLibCryptoFunction('RSA_generate_key_ex');
  FuncLoadError := not assigned(RSA_generate_key_ex);
  if FuncLoadError then
  begin
    RSA_generate_key_ex :=  @ERROR_RSA_generate_key_ex;
  end;

  RSA_generate_multi_prime_key := LoadLibCryptoFunction('RSA_generate_multi_prime_key');
  FuncLoadError := not assigned(RSA_generate_multi_prime_key);
  if FuncLoadError then
  begin
    RSA_generate_multi_prime_key :=  @ERROR_RSA_generate_multi_prime_key;
  end;

  RSA_X931_derive_ex := LoadLibCryptoFunction('RSA_X931_derive_ex');
  FuncLoadError := not assigned(RSA_X931_derive_ex);
  if FuncLoadError then
  begin
    RSA_X931_derive_ex :=  @ERROR_RSA_X931_derive_ex;
  end;

  RSA_X931_generate_key_ex := LoadLibCryptoFunction('RSA_X931_generate_key_ex');
  FuncLoadError := not assigned(RSA_X931_generate_key_ex);
  if FuncLoadError then
  begin
    RSA_X931_generate_key_ex :=  @ERROR_RSA_X931_generate_key_ex;
  end;

  RSA_check_key := LoadLibCryptoFunction('RSA_check_key');
  FuncLoadError := not assigned(RSA_check_key);
  if FuncLoadError then
  begin
    RSA_check_key :=  @ERROR_RSA_check_key;
  end;

  RSA_check_key_ex := LoadLibCryptoFunction('RSA_check_key_ex');
  FuncLoadError := not assigned(RSA_check_key_ex);
  if FuncLoadError then
  begin
    RSA_check_key_ex :=  @ERROR_RSA_check_key_ex;
  end;

  RSA_public_encrypt := LoadLibCryptoFunction('RSA_public_encrypt');
  FuncLoadError := not assigned(RSA_public_encrypt);
  if FuncLoadError then
  begin
    RSA_public_encrypt :=  @ERROR_RSA_public_encrypt;
  end;

  RSA_private_encrypt := LoadLibCryptoFunction('RSA_private_encrypt');
  FuncLoadError := not assigned(RSA_private_encrypt);
  if FuncLoadError then
  begin
    RSA_private_encrypt :=  @ERROR_RSA_private_encrypt;
  end;

  RSA_public_decrypt := LoadLibCryptoFunction('RSA_public_decrypt');
  FuncLoadError := not assigned(RSA_public_decrypt);
  if FuncLoadError then
  begin
    RSA_public_decrypt :=  @ERROR_RSA_public_decrypt;
  end;

  RSA_private_decrypt := LoadLibCryptoFunction('RSA_private_decrypt');
  FuncLoadError := not assigned(RSA_private_decrypt);
  if FuncLoadError then
  begin
    RSA_private_decrypt :=  @ERROR_RSA_private_decrypt;
  end;

  RSA_free := LoadLibCryptoFunction('RSA_free');
  FuncLoadError := not assigned(RSA_free);
  if FuncLoadError then
  begin
    RSA_free :=  @ERROR_RSA_free;
  end;

  RSA_up_ref := LoadLibCryptoFunction('RSA_up_ref');
  FuncLoadError := not assigned(RSA_up_ref);
  if FuncLoadError then
  begin
    RSA_up_ref :=  @ERROR_RSA_up_ref;
  end;

  RSA_flags := LoadLibCryptoFunction('RSA_flags');
  FuncLoadError := not assigned(RSA_flags);
  if FuncLoadError then
  begin
    RSA_flags :=  @ERROR_RSA_flags;
  end;

  RSA_set_default_method := LoadLibCryptoFunction('RSA_set_default_method');
  FuncLoadError := not assigned(RSA_set_default_method);
  if FuncLoadError then
  begin
    RSA_set_default_method :=  @ERROR_RSA_set_default_method;
  end;

  RSA_get_default_method := LoadLibCryptoFunction('RSA_get_default_method');
  FuncLoadError := not assigned(RSA_get_default_method);
  if FuncLoadError then
  begin
    RSA_get_default_method :=  @ERROR_RSA_get_default_method;
  end;

  RSA_null_method := LoadLibCryptoFunction('RSA_null_method');
  FuncLoadError := not assigned(RSA_null_method);
  if FuncLoadError then
  begin
    RSA_null_method :=  @ERROR_RSA_null_method;
  end;

  RSA_get_method := LoadLibCryptoFunction('RSA_get_method');
  FuncLoadError := not assigned(RSA_get_method);
  if FuncLoadError then
  begin
    RSA_get_method :=  @ERROR_RSA_get_method;
  end;

  RSA_set_method := LoadLibCryptoFunction('RSA_set_method');
  FuncLoadError := not assigned(RSA_set_method);
  if FuncLoadError then
  begin
    RSA_set_method :=  @ERROR_RSA_set_method;
  end;

  RSA_PKCS1_OpenSSL := LoadLibCryptoFunction('RSA_PKCS1_OpenSSL');
  FuncLoadError := not assigned(RSA_PKCS1_OpenSSL);
  if FuncLoadError then
  begin
    RSA_PKCS1_OpenSSL :=  @ERROR_RSA_PKCS1_OpenSSL;
  end;

  RSA_pkey_ctx_ctrl := LoadLibCryptoFunction('RSA_pkey_ctx_ctrl');
  FuncLoadError := not assigned(RSA_pkey_ctx_ctrl);
  if FuncLoadError then
  begin
    RSA_pkey_ctx_ctrl :=  @ERROR_RSA_pkey_ctx_ctrl;
  end;

  RSA_print := LoadLibCryptoFunction('RSA_print');
  FuncLoadError := not assigned(RSA_print);
  if FuncLoadError then
  begin
    RSA_print :=  @ERROR_RSA_print;
  end;

  RSA_sign := LoadLibCryptoFunction('RSA_sign');
  FuncLoadError := not assigned(RSA_sign);
  if FuncLoadError then
  begin
    RSA_sign :=  @ERROR_RSA_sign;
  end;

  RSA_verify := LoadLibCryptoFunction('RSA_verify');
  FuncLoadError := not assigned(RSA_verify);
  if FuncLoadError then
  begin
    RSA_verify :=  @ERROR_RSA_verify;
  end;

  RSA_sign_ASN1_OCTET_STRING := LoadLibCryptoFunction('RSA_sign_ASN1_OCTET_STRING');
  FuncLoadError := not assigned(RSA_sign_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    RSA_sign_ASN1_OCTET_STRING :=  @ERROR_RSA_sign_ASN1_OCTET_STRING;
  end;

  RSA_verify_ASN1_OCTET_STRING := LoadLibCryptoFunction('RSA_verify_ASN1_OCTET_STRING');
  FuncLoadError := not assigned(RSA_verify_ASN1_OCTET_STRING);
  if FuncLoadError then
  begin
    RSA_verify_ASN1_OCTET_STRING :=  @ERROR_RSA_verify_ASN1_OCTET_STRING;
  end;

  RSA_blinding_on := LoadLibCryptoFunction('RSA_blinding_on');
  FuncLoadError := not assigned(RSA_blinding_on);
  if FuncLoadError then
  begin
    RSA_blinding_on :=  @ERROR_RSA_blinding_on;
  end;

  RSA_blinding_off := LoadLibCryptoFunction('RSA_blinding_off');
  FuncLoadError := not assigned(RSA_blinding_off);
  if FuncLoadError then
  begin
    RSA_blinding_off :=  @ERROR_RSA_blinding_off;
  end;

  RSA_setup_blinding := LoadLibCryptoFunction('RSA_setup_blinding');
  FuncLoadError := not assigned(RSA_setup_blinding);
  if FuncLoadError then
  begin
    RSA_setup_blinding :=  @ERROR_RSA_setup_blinding;
  end;

  RSA_padding_add_PKCS1_type_1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_type_1');
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_type_1);
  if FuncLoadError then
  begin
    RSA_padding_add_PKCS1_type_1 :=  @ERROR_RSA_padding_add_PKCS1_type_1;
  end;

  RSA_padding_check_PKCS1_type_1 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_type_1');
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_type_1);
  if FuncLoadError then
  begin
    RSA_padding_check_PKCS1_type_1 :=  @ERROR_RSA_padding_check_PKCS1_type_1;
  end;

  RSA_padding_add_PKCS1_type_2 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_type_2');
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_type_2);
  if FuncLoadError then
  begin
    RSA_padding_add_PKCS1_type_2 :=  @ERROR_RSA_padding_add_PKCS1_type_2;
  end;

  RSA_padding_check_PKCS1_type_2 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_type_2');
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_type_2);
  if FuncLoadError then
  begin
    RSA_padding_check_PKCS1_type_2 :=  @ERROR_RSA_padding_check_PKCS1_type_2;
  end;

  PKCS1_MGF1 := LoadLibCryptoFunction('PKCS1_MGF1');
  FuncLoadError := not assigned(PKCS1_MGF1);
  if FuncLoadError then
  begin
    PKCS1_MGF1 :=  @ERROR_PKCS1_MGF1;
  end;

  RSA_padding_add_PKCS1_OAEP := LoadLibCryptoFunction('RSA_padding_add_PKCS1_OAEP');
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_OAEP);
  if FuncLoadError then
  begin
    RSA_padding_add_PKCS1_OAEP :=  @ERROR_RSA_padding_add_PKCS1_OAEP;
  end;

  RSA_padding_check_PKCS1_OAEP := LoadLibCryptoFunction('RSA_padding_check_PKCS1_OAEP');
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_OAEP);
  if FuncLoadError then
  begin
    RSA_padding_check_PKCS1_OAEP :=  @ERROR_RSA_padding_check_PKCS1_OAEP;
  end;

  RSA_padding_add_PKCS1_OAEP_mgf1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_OAEP_mgf1');
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_OAEP_mgf1);
  if FuncLoadError then
  begin
    RSA_padding_add_PKCS1_OAEP_mgf1 :=  @ERROR_RSA_padding_add_PKCS1_OAEP_mgf1;
  end;

  RSA_padding_check_PKCS1_OAEP_mgf1 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_OAEP_mgf1');
  FuncLoadError := not assigned(RSA_padding_check_PKCS1_OAEP_mgf1);
  if FuncLoadError then
  begin
    RSA_padding_check_PKCS1_OAEP_mgf1 :=  @ERROR_RSA_padding_check_PKCS1_OAEP_mgf1;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  RSA_padding_add_SSLv23 := LoadLibCryptoFunction('RSA_padding_add_SSLv23');
  FuncLoadError := not assigned(RSA_padding_add_SSLv23);
  if FuncLoadError then
  begin
    if RSA_padding_add_SSLv23_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('RSA_padding_add_SSLv23');
  end;

  RSA_padding_check_SSLv23 := LoadLibCryptoFunction('RSA_padding_check_SSLv23');
  FuncLoadError := not assigned(RSA_padding_check_SSLv23);
  if FuncLoadError then
  begin
    if RSA_padding_check_SSLv23_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('RSA_padding_check_SSLv23');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  RSA_padding_add_none := LoadLibCryptoFunction('RSA_padding_add_none');
  FuncLoadError := not assigned(RSA_padding_add_none);
  if FuncLoadError then
  begin
    RSA_padding_add_none :=  @ERROR_RSA_padding_add_none;
  end;

  RSA_padding_check_none := LoadLibCryptoFunction('RSA_padding_check_none');
  FuncLoadError := not assigned(RSA_padding_check_none);
  if FuncLoadError then
  begin
    RSA_padding_check_none :=  @ERROR_RSA_padding_check_none;
  end;

  RSA_padding_add_X931 := LoadLibCryptoFunction('RSA_padding_add_X931');
  FuncLoadError := not assigned(RSA_padding_add_X931);
  if FuncLoadError then
  begin
    RSA_padding_add_X931 :=  @ERROR_RSA_padding_add_X931;
  end;

  RSA_padding_check_X931 := LoadLibCryptoFunction('RSA_padding_check_X931');
  FuncLoadError := not assigned(RSA_padding_check_X931);
  if FuncLoadError then
  begin
    RSA_padding_check_X931 :=  @ERROR_RSA_padding_check_X931;
  end;

  RSA_X931_hash_id := LoadLibCryptoFunction('RSA_X931_hash_id');
  FuncLoadError := not assigned(RSA_X931_hash_id);
  if FuncLoadError then
  begin
    RSA_X931_hash_id :=  @ERROR_RSA_X931_hash_id;
  end;

  RSA_verify_PKCS1_PSS := LoadLibCryptoFunction('RSA_verify_PKCS1_PSS');
  FuncLoadError := not assigned(RSA_verify_PKCS1_PSS);
  if FuncLoadError then
  begin
    RSA_verify_PKCS1_PSS :=  @ERROR_RSA_verify_PKCS1_PSS;
  end;

  RSA_padding_add_PKCS1_PSS := LoadLibCryptoFunction('RSA_padding_add_PKCS1_PSS');
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_PSS);
  if FuncLoadError then
  begin
    RSA_padding_add_PKCS1_PSS :=  @ERROR_RSA_padding_add_PKCS1_PSS;
  end;

  RSA_verify_PKCS1_PSS_mgf1 := LoadLibCryptoFunction('RSA_verify_PKCS1_PSS_mgf1');
  FuncLoadError := not assigned(RSA_verify_PKCS1_PSS_mgf1);
  if FuncLoadError then
  begin
    RSA_verify_PKCS1_PSS_mgf1 :=  @ERROR_RSA_verify_PKCS1_PSS_mgf1;
  end;

  RSA_padding_add_PKCS1_PSS_mgf1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_PSS_mgf1');
  FuncLoadError := not assigned(RSA_padding_add_PKCS1_PSS_mgf1);
  if FuncLoadError then
  begin
    RSA_padding_add_PKCS1_PSS_mgf1 :=  @ERROR_RSA_padding_add_PKCS1_PSS_mgf1;
  end;

  RSA_set_ex_data := LoadLibCryptoFunction('RSA_set_ex_data');
  FuncLoadError := not assigned(RSA_set_ex_data);
  if FuncLoadError then
  begin
    RSA_set_ex_data :=  @ERROR_RSA_set_ex_data;
  end;

  RSA_get_ex_data := LoadLibCryptoFunction('RSA_get_ex_data');
  FuncLoadError := not assigned(RSA_get_ex_data);
  if FuncLoadError then
  begin
    RSA_get_ex_data :=  @ERROR_RSA_get_ex_data;
  end;

  RSAPublicKey_dup := LoadLibCryptoFunction('RSAPublicKey_dup');
  FuncLoadError := not assigned(RSAPublicKey_dup);
  if FuncLoadError then
  begin
    RSAPublicKey_dup :=  @ERROR_RSAPublicKey_dup;
  end;

  RSAPrivateKey_dup := LoadLibCryptoFunction('RSAPrivateKey_dup');
  FuncLoadError := not assigned(RSAPrivateKey_dup);
  if FuncLoadError then
  begin
    RSAPrivateKey_dup :=  @ERROR_RSAPrivateKey_dup;
  end;

  RSA_meth_new := LoadLibCryptoFunction('RSA_meth_new');
  FuncLoadError := not assigned(RSA_meth_new);
  if FuncLoadError then
  begin
    RSA_meth_new :=  @ERROR_RSA_meth_new;
  end;

  RSA_meth_free := LoadLibCryptoFunction('RSA_meth_free');
  FuncLoadError := not assigned(RSA_meth_free);
  if FuncLoadError then
  begin
    RSA_meth_free :=  @ERROR_RSA_meth_free;
  end;

  RSA_meth_dup := LoadLibCryptoFunction('RSA_meth_dup');
  FuncLoadError := not assigned(RSA_meth_dup);
  if FuncLoadError then
  begin
    RSA_meth_dup :=  @ERROR_RSA_meth_dup;
  end;

  RSA_meth_get0_name := LoadLibCryptoFunction('RSA_meth_get0_name');
  FuncLoadError := not assigned(RSA_meth_get0_name);
  if FuncLoadError then
  begin
    RSA_meth_get0_name :=  @ERROR_RSA_meth_get0_name;
  end;

  RSA_meth_set1_name := LoadLibCryptoFunction('RSA_meth_set1_name');
  FuncLoadError := not assigned(RSA_meth_set1_name);
  if FuncLoadError then
  begin
    RSA_meth_set1_name :=  @ERROR_RSA_meth_set1_name;
  end;

  RSA_meth_get_flags := LoadLibCryptoFunction('RSA_meth_get_flags');
  FuncLoadError := not assigned(RSA_meth_get_flags);
  if FuncLoadError then
  begin
    RSA_meth_get_flags :=  @ERROR_RSA_meth_get_flags;
  end;

  RSA_meth_set_flags := LoadLibCryptoFunction('RSA_meth_set_flags');
  FuncLoadError := not assigned(RSA_meth_set_flags);
  if FuncLoadError then
  begin
    RSA_meth_set_flags :=  @ERROR_RSA_meth_set_flags;
  end;

  RSA_meth_get0_app_data := LoadLibCryptoFunction('RSA_meth_get0_app_data');
  FuncLoadError := not assigned(RSA_meth_get0_app_data);
  if FuncLoadError then
  begin
    RSA_meth_get0_app_data :=  @ERROR_RSA_meth_get0_app_data;
  end;

  RSA_meth_set0_app_data := LoadLibCryptoFunction('RSA_meth_set0_app_data');
  FuncLoadError := not assigned(RSA_meth_set0_app_data);
  if FuncLoadError then
  begin
    RSA_meth_set0_app_data :=  @ERROR_RSA_meth_set0_app_data;
  end;

  RSA_meth_set_priv_dec := LoadLibCryptoFunction('RSA_meth_set_priv_dec');
  FuncLoadError := not assigned(RSA_meth_set_priv_dec);
  if FuncLoadError then
  begin
    RSA_meth_set_priv_dec :=  @ERROR_RSA_meth_set_priv_dec;
  end;

  RSA_meth_set_mod_exp := LoadLibCryptoFunction('RSA_meth_set_mod_exp');
  FuncLoadError := not assigned(RSA_meth_set_mod_exp);
  if FuncLoadError then
  begin
    RSA_meth_set_mod_exp :=  @ERROR_RSA_meth_set_mod_exp;
  end;

  RSA_meth_set_bn_mod_exp := LoadLibCryptoFunction('RSA_meth_set_bn_mod_exp');
  FuncLoadError := not assigned(RSA_meth_set_bn_mod_exp);
  if FuncLoadError then
  begin
    RSA_meth_set_bn_mod_exp :=  @ERROR_RSA_meth_set_bn_mod_exp;
  end;

  RSA_meth_set_init := LoadLibCryptoFunction('RSA_meth_set_init');
  FuncLoadError := not assigned(RSA_meth_set_init);
  if FuncLoadError then
  begin
    RSA_meth_set_init :=  @ERROR_RSA_meth_set_init;
  end;

  RSA_meth_set_finish := LoadLibCryptoFunction('RSA_meth_set_finish');
  FuncLoadError := not assigned(RSA_meth_set_finish);
  if FuncLoadError then
  begin
    RSA_meth_set_finish :=  @ERROR_RSA_meth_set_finish;
  end;

  RSA_meth_set_sign := LoadLibCryptoFunction('RSA_meth_set_sign');
  FuncLoadError := not assigned(RSA_meth_set_sign);
  if FuncLoadError then
  begin
    RSA_meth_set_sign :=  @ERROR_RSA_meth_set_sign;
  end;

  RSA_meth_set_verify := LoadLibCryptoFunction('RSA_meth_set_verify');
  FuncLoadError := not assigned(RSA_meth_set_verify);
  if FuncLoadError then
  begin
    RSA_meth_set_verify :=  @ERROR_RSA_meth_set_verify;
  end;

  RSA_meth_set_keygen := LoadLibCryptoFunction('RSA_meth_set_keygen');
  FuncLoadError := not assigned(RSA_meth_set_keygen);
  if FuncLoadError then
  begin
    RSA_meth_set_keygen :=  @ERROR_RSA_meth_set_keygen;
  end;

  RSA_meth_set_multi_prime_keygen := LoadLibCryptoFunction('RSA_meth_set_multi_prime_keygen');
  FuncLoadError := not assigned(RSA_meth_set_multi_prime_keygen);
  if FuncLoadError then
  begin
    RSA_meth_set_multi_prime_keygen :=  @ERROR_RSA_meth_set_multi_prime_keygen;
  end;

end;

procedure UnLoad;
begin
  RSA_new := nil;
  RSA_new_method := nil;
  RSA_bits := nil;
  RSA_size := nil;
  RSA_security_bits := nil;
  RSA_set0_key := nil;
  RSA_set0_factors := nil;
  RSA_set0_crt_params := nil;
  RSA_get0_key := nil;
  RSA_get0_factors := nil;
  RSA_get_multi_prime_extra_count := nil;
  RSA_get0_crt_params := nil;
  RSA_get0_n := nil;
  RSA_get0_e := nil;
  RSA_get0_d := nil;
  RSA_get0_p := nil;
  RSA_get0_q := nil;
  RSA_get0_dmp1 := nil;
  RSA_get0_dmq1 := nil;
  RSA_get0_iqmp := nil;
  RSA_clear_flags := nil;
  RSA_test_flags := nil;
  RSA_set_flags := nil;
  RSA_get_version := nil;
  RSA_get0_engine := nil;
  RSA_generate_key_ex := nil;
  RSA_generate_multi_prime_key := nil;
  RSA_X931_derive_ex := nil;
  RSA_X931_generate_key_ex := nil;
  RSA_check_key := nil;
  RSA_check_key_ex := nil;
  RSA_public_encrypt := nil;
  RSA_private_encrypt := nil;
  RSA_public_decrypt := nil;
  RSA_private_decrypt := nil;
  RSA_free := nil;
  RSA_up_ref := nil;
  RSA_flags := nil;
  RSA_set_default_method := nil;
  RSA_get_default_method := nil;
  RSA_null_method := nil;
  RSA_get_method := nil;
  RSA_set_method := nil;
  RSA_PKCS1_OpenSSL := nil;
  RSA_pkey_ctx_ctrl := nil;
  RSA_print := nil;
  RSA_sign := nil;
  RSA_verify := nil;
  RSA_sign_ASN1_OCTET_STRING := nil;
  RSA_verify_ASN1_OCTET_STRING := nil;
  RSA_blinding_on := nil;
  RSA_blinding_off := nil;
  RSA_setup_blinding := nil;
  RSA_padding_add_PKCS1_type_1 := nil;
  RSA_padding_check_PKCS1_type_1 := nil;
  RSA_padding_add_PKCS1_type_2 := nil;
  RSA_padding_check_PKCS1_type_2 := nil;
  PKCS1_MGF1 := nil;
  RSA_padding_add_PKCS1_OAEP := nil;
  RSA_padding_check_PKCS1_OAEP := nil;
  RSA_padding_add_PKCS1_OAEP_mgf1 := nil;
  RSA_padding_check_PKCS1_OAEP_mgf1 := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  RSA_padding_add_SSLv23 := nil;
  RSA_padding_check_SSLv23 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  RSA_padding_add_none := nil;
  RSA_padding_check_none := nil;
  RSA_padding_add_X931 := nil;
  RSA_padding_check_X931 := nil;
  RSA_X931_hash_id := nil;
  RSA_verify_PKCS1_PSS := nil;
  RSA_padding_add_PKCS1_PSS := nil;
  RSA_verify_PKCS1_PSS_mgf1 := nil;
  RSA_padding_add_PKCS1_PSS_mgf1 := nil;
  RSA_set_ex_data := nil;
  RSA_get_ex_data := nil;
  RSAPublicKey_dup := nil;
  RSAPrivateKey_dup := nil;
  RSA_meth_new := nil;
  RSA_meth_free := nil;
  RSA_meth_dup := nil;
  RSA_meth_get0_name := nil;
  RSA_meth_set1_name := nil;
  RSA_meth_get_flags := nil;
  RSA_meth_set_flags := nil;
  RSA_meth_get0_app_data := nil;
  RSA_meth_set0_app_data := nil;
  RSA_meth_set_priv_dec := nil;
  RSA_meth_set_mod_exp := nil;
  RSA_meth_set_bn_mod_exp := nil;
  RSA_meth_set_init := nil;
  RSA_meth_set_finish := nil;
  RSA_meth_set_sign := nil;
  RSA_meth_set_verify := nil;
  RSA_meth_set_keygen := nil;
  RSA_meth_set_multi_prime_keygen := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
