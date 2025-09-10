(* This unit was generated from the source file bn.h2pas 
It should not be modified directly. All changes should be made to bn.h2pas
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


unit OpenSSL_bn;


interface

// Headers for OpenSSL 1.1.1
// bn.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ;

const
  BN_FLG_MALLOCED = $01;
  BN_FLG_STATIC_DATA = $02;

  (*
   * avoid leaking exponent information through timing,
   * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
   * BN_div() will call BN_div_no_branch,
   * BN_mod_inverse() will call BN_mod_inverse_no_branch.
   *)
  BN_FLG_CONSTTIME = $04;
  BN_FLG_SECURE = $08;

  (* Values for |top| in BN_rand() *)
  BN_RAND_TOP_ANY = -1;
  BN_RAND_TOP_ONE = 0;
  BN_RAND_TOP_TWO = 1;

  (* Values for |bottom| in BN_rand() *)
  BN_RAND_BOTTOM_ANY = 0;
  BN_RAND_BOTTOM_ODD = 1;
  
  (* BN_BLINDING flags *)
  BN_BLINDING_NO_UPDATE = $00000001;
  BN_BLINDING_NO_RECREATE = $00000002;

type
  BN_ULONG = TOpenSSL_C_ULONG;

  BN_GENCB_set_old_cb = procedure (a: TOpenSSL_C_INT; b: TOpenSSL_C_INT; c: Pointer); cdecl;
  BN_GENCB_set_cb = function (a: TOpenSSL_C_INT; b: TOpenSSL_C_INT; c: PBN_GENCB): TOpenSSL_C_INT; cdecl;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BN_set_flags}
{$EXTERNALSYM BN_get_flags}
{$EXTERNALSYM BN_with_flags}
{$EXTERNALSYM BN_GENCB_call}
{$EXTERNALSYM BN_GENCB_new}
{$EXTERNALSYM BN_GENCB_free}
{$EXTERNALSYM BN_GENCB_set_old}
{$EXTERNALSYM BN_GENCB_set}
{$EXTERNALSYM BN_GENCB_get_arg}
{$EXTERNALSYM BN_abs_is_word}
{$EXTERNALSYM BN_is_zero}
{$EXTERNALSYM BN_is_one}
{$EXTERNALSYM BN_is_word}
{$EXTERNALSYM BN_is_odd}
{$EXTERNALSYM BN_zero_ex}
{$EXTERNALSYM BN_value_one}
{$EXTERNALSYM BN_options}
{$EXTERNALSYM BN_CTX_new}
{$EXTERNALSYM BN_CTX_secure_new}
{$EXTERNALSYM BN_CTX_free}
{$EXTERNALSYM BN_CTX_start}
{$EXTERNALSYM BN_CTX_get}
{$EXTERNALSYM BN_CTX_end}
{$EXTERNALSYM BN_rand}
{$EXTERNALSYM BN_priv_rand}
{$EXTERNALSYM BN_rand_range}
{$EXTERNALSYM BN_priv_rand_range}
{$EXTERNALSYM BN_pseudo_rand}
{$EXTERNALSYM BN_pseudo_rand_range}
{$EXTERNALSYM BN_num_bits}
{$EXTERNALSYM BN_num_bits_word}
{$EXTERNALSYM BN_security_bits}
{$EXTERNALSYM BN_new}
{$EXTERNALSYM BN_secure_new}
{$EXTERNALSYM BN_clear_free}
{$EXTERNALSYM BN_copy}
{$EXTERNALSYM BN_swap}
{$EXTERNALSYM BN_bin2bn}
{$EXTERNALSYM BN_bn2bin}
{$EXTERNALSYM BN_bn2binpad}
{$EXTERNALSYM BN_lebin2bn}
{$EXTERNALSYM BN_bn2lebinpad}
{$EXTERNALSYM BN_mpi2bn}
{$EXTERNALSYM BN_bn2mpi}
{$EXTERNALSYM BN_sub}
{$EXTERNALSYM BN_usub}
{$EXTERNALSYM BN_uadd}
{$EXTERNALSYM BN_add}
{$EXTERNALSYM BN_mul}
{$EXTERNALSYM BN_sqr}
{$EXTERNALSYM BN_set_negative}
{$EXTERNALSYM BN_is_negative}
{$EXTERNALSYM BN_div}
{$EXTERNALSYM BN_nnmod}
{$EXTERNALSYM BN_mod_add}
{$EXTERNALSYM BN_mod_add_quick}
{$EXTERNALSYM BN_mod_sub}
{$EXTERNALSYM BN_mod_sub_quick}
{$EXTERNALSYM BN_mod_mul}
{$EXTERNALSYM BN_mod_sqr}
{$EXTERNALSYM BN_mod_lshift1}
{$EXTERNALSYM BN_mod_lshift1_quick}
{$EXTERNALSYM BN_mod_lshift}
{$EXTERNALSYM BN_mod_lshift_quick}
{$EXTERNALSYM BN_mod_word}
{$EXTERNALSYM BN_div_word}
{$EXTERNALSYM BN_mul_word}
{$EXTERNALSYM BN_add_word}
{$EXTERNALSYM BN_sub_word}
{$EXTERNALSYM BN_set_word}
{$EXTERNALSYM BN_get_word}
{$EXTERNALSYM BN_cmp}
{$EXTERNALSYM BN_free}
{$EXTERNALSYM BN_is_bit_set}
{$EXTERNALSYM BN_lshift}
{$EXTERNALSYM BN_lshift1}
{$EXTERNALSYM BN_exp}
{$EXTERNALSYM BN_mod_exp}
{$EXTERNALSYM BN_mod_exp_mont}
{$EXTERNALSYM BN_mod_exp_mont_consttime}
{$EXTERNALSYM BN_mod_exp_mont_word}
{$EXTERNALSYM BN_mod_exp2_mont}
{$EXTERNALSYM BN_mod_exp_simple}
{$EXTERNALSYM BN_mask_bits}
{$EXTERNALSYM BN_print}
{$EXTERNALSYM BN_reciprocal}
{$EXTERNALSYM BN_rshift}
{$EXTERNALSYM BN_rshift1}
{$EXTERNALSYM BN_clear}
{$EXTERNALSYM BN_dup}
{$EXTERNALSYM BN_ucmp}
{$EXTERNALSYM BN_set_bit}
{$EXTERNALSYM BN_clear_bit}
{$EXTERNALSYM BN_bn2hex}
{$EXTERNALSYM BN_bn2dec}
{$EXTERNALSYM BN_hex2bn}
{$EXTERNALSYM BN_dec2bn}
{$EXTERNALSYM BN_asc2bn}
{$EXTERNALSYM BN_gcd}
{$EXTERNALSYM BN_kronecker}
{$EXTERNALSYM BN_mod_inverse}
{$EXTERNALSYM BN_mod_sqrt}
{$EXTERNALSYM BN_consttime_swap}
{$EXTERNALSYM BN_generate_prime_ex}
{$EXTERNALSYM BN_is_prime_ex}
{$EXTERNALSYM BN_is_prime_fasttest_ex}
{$EXTERNALSYM BN_X931_generate_Xpq}
{$EXTERNALSYM BN_X931_derive_prime_ex}
{$EXTERNALSYM BN_X931_generate_prime_ex}
{$EXTERNALSYM BN_MONT_CTX_new}
{$EXTERNALSYM BN_mod_mul_montgomery}
{$EXTERNALSYM BN_to_montgomery}
{$EXTERNALSYM BN_from_montgomery}
{$EXTERNALSYM BN_MONT_CTX_free}
{$EXTERNALSYM BN_MONT_CTX_set}
{$EXTERNALSYM BN_MONT_CTX_copy}
{$EXTERNALSYM BN_BLINDING_new}
{$EXTERNALSYM BN_BLINDING_free}
{$EXTERNALSYM BN_BLINDING_update}
{$EXTERNALSYM BN_BLINDING_convert}
{$EXTERNALSYM BN_BLINDING_invert}
{$EXTERNALSYM BN_BLINDING_convert_ex}
{$EXTERNALSYM BN_BLINDING_invert_ex}
{$EXTERNALSYM BN_BLINDING_is_current_thread}
{$EXTERNALSYM BN_BLINDING_set_current_thread}
{$EXTERNALSYM BN_BLINDING_lock}
{$EXTERNALSYM BN_BLINDING_unlock}
{$EXTERNALSYM BN_BLINDING_get_flags}
{$EXTERNALSYM BN_BLINDING_set_flags}
{$EXTERNALSYM BN_RECP_CTX_free}
{$EXTERNALSYM BN_RECP_CTX_set}
{$EXTERNALSYM BN_mod_mul_reciprocal}
{$EXTERNALSYM BN_mod_exp_recp}
{$EXTERNALSYM BN_div_recp}
{$EXTERNALSYM BN_GF2m_add}
{$EXTERNALSYM BN_GF2m_mod}
{$EXTERNALSYM BN_GF2m_mod_mul}
{$EXTERNALSYM BN_GF2m_mod_sqr}
{$EXTERNALSYM BN_GF2m_mod_inv}
{$EXTERNALSYM BN_GF2m_mod_div}
{$EXTERNALSYM BN_GF2m_mod_exp}
{$EXTERNALSYM BN_GF2m_mod_sqrt}
{$EXTERNALSYM BN_GF2m_mod_solve_quad}
{$EXTERNALSYM BN_nist_mod_192}
{$EXTERNALSYM BN_nist_mod_224}
{$EXTERNALSYM BN_nist_mod_256}
{$EXTERNALSYM BN_nist_mod_384}
{$EXTERNALSYM BN_nist_mod_521}
{$EXTERNALSYM BN_get0_nist_prime_192}
{$EXTERNALSYM BN_get0_nist_prime_224}
{$EXTERNALSYM BN_get0_nist_prime_256}
{$EXTERNALSYM BN_get0_nist_prime_384}
{$EXTERNALSYM BN_get0_nist_prime_521}
{$EXTERNALSYM BN_generate_dsa_nonce}
{$EXTERNALSYM BN_get_rfc2409_prime_768}
{$EXTERNALSYM BN_get_rfc2409_prime_1024}
{$EXTERNALSYM BN_get_rfc3526_prime_1536}
{$EXTERNALSYM BN_get_rfc3526_prime_2048}
{$EXTERNALSYM BN_get_rfc3526_prime_3072}
{$EXTERNALSYM BN_get_rfc3526_prime_4096}
{$EXTERNALSYM BN_get_rfc3526_prime_6144}
{$EXTERNALSYM BN_get_rfc3526_prime_8192}
{$EXTERNALSYM BN_bntest_rand}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure BN_set_flags(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_get_flags(b: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_with_flags(dest: PBIGNUM; b: PBIGNUM; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_GENCB_call(cb: PBN_GENCB; a: TOpenSSL_C_INT; b: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GENCB_new: PBN_GENCB; cdecl; external CLibCrypto;
procedure BN_GENCB_free(cb: PBN_GENCB); cdecl; external CLibCrypto;
procedure BN_GENCB_set_old(gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl; external CLibCrypto;
procedure BN_GENCB_set(gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl; external CLibCrypto;
function BN_GENCB_get_arg(cb: PBN_GENCB): Pointer; cdecl; external CLibCrypto;
function BN_abs_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_zero(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_one(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_odd(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_zero_ex(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_value_one: PBIGNUM; cdecl; external CLibCrypto;
function BN_options: PAnsiChar; cdecl; external CLibCrypto;
function BN_CTX_new: PBN_CTX; cdecl; external CLibCrypto;
function BN_CTX_secure_new: PBN_CTX; cdecl; external CLibCrypto;
procedure BN_CTX_free(c: PBN_CTX); cdecl; external CLibCrypto;
procedure BN_CTX_start(ctx: PBN_CTX); cdecl; external CLibCrypto;
function BN_CTX_get(ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
procedure BN_CTX_end(ctx: PBN_CTX); cdecl; external CLibCrypto;
function BN_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_priv_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_priv_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_pseudo_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_pseudo_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_num_bits(a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_num_bits_word(l: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_security_bits(L: TOpenSSL_C_INT; N: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_new: PBIGNUM; cdecl; external CLibCrypto;
function BN_secure_new: PBIGNUM; cdecl; external CLibCrypto;
procedure BN_clear_free(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_copy(a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
procedure BN_swap(a: PBIGNUM; b: PBIGNUM); cdecl; external CLibCrypto;
function BN_bin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bn2bin(const a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_bn2binpad(const a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_lebin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bn2lebinpad(a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mpi2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bn2mpi(a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_usub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_uadd(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_sqr(r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_set_negative(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_is_negative(b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_div(dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nnmod(r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_add_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_sub_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_sqr(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift1(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift1_quick(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_lshift_quick(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_word(const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl; external CLibCrypto;
function BN_div_word(a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl; external CLibCrypto;
function BN_mul_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_add_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_sub_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_set_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_get_word(const a: PBIGNUM): BN_ULONG; cdecl; external CLibCrypto;
function BN_cmp(const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_free(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_is_bit_set(const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_lshift1(r: PBIGNUM; const a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_mont(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_mont_consttime(rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_mont_word(r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp2_mont(r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_simple(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mask_bits(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_print(bio: PBIO; a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_reciprocal(r: PBIGNUM; m: PBIGNUM; len: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_rshift(r: PBIGNUM; a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_rshift1(r: PBIGNUM; a: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_clear(a: PBIGNUM); cdecl; external CLibCrypto;
function BN_dup(const a: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_ucmp(a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_set_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_clear_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_bn2hex(a: PBIGNUM): PAnsiChar; cdecl; external CLibCrypto;
function BN_bn2dec(a: PBIGNUM): PAnsiChar; cdecl; external CLibCrypto;
function BN_hex2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_dec2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_asc2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_gcd(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_kronecker(a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_inverse(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
function BN_mod_sqrt(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl; external CLibCrypto;
procedure BN_consttime_swap(swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BN_generate_prime_ex(ret: PBIGNUM; bits: TOpenSSL_C_INT; safe: TOpenSSL_C_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_prime_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_is_prime_fasttest_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; do_trial_division: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_X931_generate_Xpq(Xp: PBIGNUM; Xq: PBIGNUM; nbits: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_X931_derive_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_X931_generate_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_MONT_CTX_new: PBN_MONT_CTX; cdecl; external CLibCrypto;
function BN_mod_mul_montgomery(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_to_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_from_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_MONT_CTX_free(mont: PBN_MONT_CTX); cdecl; external CLibCrypto;
function BN_MONT_CTX_set(mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_MONT_CTX_copy(to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl; external CLibCrypto;
function BN_BLINDING_new(const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl; external CLibCrypto;
procedure BN_BLINDING_free(b: PBN_BLINDING); cdecl; external CLibCrypto;
function BN_BLINDING_update(b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_convert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_invert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_convert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_invert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_is_current_thread(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BN_BLINDING_set_current_thread(b: PBN_BLINDING); cdecl; external CLibCrypto;
function BN_BLINDING_lock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_unlock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_BLINDING_get_flags(v1: PBN_BLINDING): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure BN_BLINDING_set_flags(v1: PBN_BLINDING; v2: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
procedure BN_RECP_CTX_free(recp: PBN_RECP_CTX); cdecl; external CLibCrypto;
function BN_RECP_CTX_set(recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_mul_reciprocal(r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_mod_exp_recp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_div_recp(dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_add(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_mul(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_sqr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_inv(r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_div(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_exp(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_sqrt(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_GF2m_mod_solve_quad(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_192(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_224(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_256(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_384(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_nist_mod_521(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_get0_nist_prime_192: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_224: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_256: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_384: PBIGNUM; cdecl; external CLibCrypto;
function BN_get0_nist_prime_521: PBIGNUM; cdecl; external CLibCrypto;
function BN_generate_dsa_nonce(out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BN_get_rfc2409_prime_768(bn: PBIGNUM ): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc2409_prime_1024(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_1536(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_2048(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_3072(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_4096(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_6144(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_get_rfc3526_prime_8192(bn: PBIGNUM): PBIGNUM; cdecl; external CLibCrypto;
function BN_bntest_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  BN_set_flags: procedure (b: PBIGNUM; n: TOpenSSL_C_INT); cdecl = nil;
  BN_get_flags: function (b: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_with_flags: procedure (dest: PBIGNUM; b: PBIGNUM; flags: TOpenSSL_C_INT); cdecl = nil;
  BN_GENCB_call: function (cb: PBN_GENCB; a: TOpenSSL_C_INT; b: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_GENCB_new: function : PBN_GENCB; cdecl = nil;
  BN_GENCB_free: procedure (cb: PBN_GENCB); cdecl = nil;
  BN_GENCB_set_old: procedure (gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl = nil;
  BN_GENCB_set: procedure (gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl = nil;
  BN_GENCB_get_arg: function (cb: PBN_GENCB): Pointer; cdecl = nil;
  BN_abs_is_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = nil;
  BN_is_zero: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_is_one: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_is_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = nil;
  BN_is_odd: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_zero_ex: procedure (a: PBIGNUM); cdecl = nil;
  BN_value_one: function : PBIGNUM; cdecl = nil;
  BN_options: function : PAnsiChar; cdecl = nil;
  BN_CTX_new: function : PBN_CTX; cdecl = nil;
  BN_CTX_secure_new: function : PBN_CTX; cdecl = nil;
  BN_CTX_free: procedure (c: PBN_CTX); cdecl = nil;
  BN_CTX_start: procedure (ctx: PBN_CTX); cdecl = nil;
  BN_CTX_get: function (ctx: PBN_CTX): PBIGNUM; cdecl = nil;
  BN_CTX_end: procedure (ctx: PBN_CTX); cdecl = nil;
  BN_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_priv_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_priv_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_pseudo_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_pseudo_rand_range: function (rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_num_bits: function (a: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_num_bits_word: function (l: BN_ULONG): TOpenSSL_C_INT; cdecl = nil;
  BN_security_bits: function (L: TOpenSSL_C_INT; N: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_new: function : PBIGNUM; cdecl = nil;
  BN_secure_new: function : PBIGNUM; cdecl = nil;
  BN_clear_free: procedure (a: PBIGNUM); cdecl = nil;
  BN_copy: function (a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_swap: procedure (a: PBIGNUM; b: PBIGNUM); cdecl = nil;
  BN_bin2bn: function (const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_bn2bin: function (const a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl = nil;
  BN_bn2binpad: function (const a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_lebin2bn: function (const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_bn2lebinpad: function (a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_mpi2bn: function (const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_bn2mpi: function (a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl = nil;
  BN_sub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_usub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_uadd: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_add: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_mul: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_sqr: function (r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_set_negative: procedure (b: PBIGNUM; n: TOpenSSL_C_INT); cdecl = nil;
  BN_is_negative: function (b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_div: function (dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_nnmod: function (r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_add: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_add_quick: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_sub: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_sub_quick: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_mul: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_sqr: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_lshift1: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_lshift1_quick: function (r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_lshift: function (r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_lshift_quick: function (r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_word: function (const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl = nil;
  BN_div_word: function (a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl = nil;
  BN_mul_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = nil;
  BN_add_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = nil;
  BN_sub_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = nil;
  BN_set_word: function (a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl = nil;
  BN_get_word: function (const a: PBIGNUM): BN_ULONG; cdecl = nil;
  BN_cmp: function (const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_free: procedure (a: PBIGNUM); cdecl = nil;
  BN_is_bit_set: function (const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_lshift: function (r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_lshift1: function (r: PBIGNUM; const a: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_exp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_exp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_exp_mont: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_exp_mont_consttime: function (rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_exp_mont_word: function (r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_exp2_mont: function (r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_exp_simple: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mask_bits: function (a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_print: function (bio: PBIO; a: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_reciprocal: function (r: PBIGNUM; m: PBIGNUM; len: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_rshift: function (r: PBIGNUM; a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_rshift1: function (r: PBIGNUM; a: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_clear: procedure (a: PBIGNUM); cdecl = nil;
  BN_dup: function (const a: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_ucmp: function (a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_set_bit: function (a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_clear_bit: function (a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BN_bn2hex: function (a: PBIGNUM): PAnsiChar; cdecl = nil;
  BN_bn2dec: function (a: PBIGNUM): PAnsiChar; cdecl = nil;
  BN_hex2bn: function (a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  BN_dec2bn: function (a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  BN_asc2bn: function (a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  BN_gcd: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_kronecker: function (a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_inverse: function (ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = nil;
  BN_mod_sqrt: function (ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl = nil;
  BN_consttime_swap: procedure (swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TOpenSSL_C_INT); cdecl = nil;
  BN_generate_prime_ex: function (ret: PBIGNUM; bits: TOpenSSL_C_INT; safe: TOpenSSL_C_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  BN_is_prime_ex: function (const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  BN_is_prime_fasttest_ex: function (const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; do_trial_division: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  BN_X931_generate_Xpq: function (Xp: PBIGNUM; Xq: PBIGNUM; nbits: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_X931_derive_prime_ex: function (p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  BN_X931_generate_prime_ex: function (p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = nil;
  BN_MONT_CTX_new: function : PBN_MONT_CTX; cdecl = nil;
  BN_mod_mul_montgomery: function (r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_to_montgomery: function (r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_from_montgomery: function (r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_MONT_CTX_free: procedure (mont: PBN_MONT_CTX); cdecl = nil;
  BN_MONT_CTX_set: function (mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_MONT_CTX_copy: function (to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl = nil;
  BN_BLINDING_new: function (const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl = nil;
  BN_BLINDING_free: procedure (b: PBN_BLINDING); cdecl = nil;
  BN_BLINDING_update: function (b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_convert: function (n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_invert: function (n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_convert_ex: function (n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_invert_ex: function (n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_is_current_thread: function (b: PBN_BLINDING): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_set_current_thread: procedure (b: PBN_BLINDING); cdecl = nil;
  BN_BLINDING_lock: function (b: PBN_BLINDING): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_unlock: function (b: PBN_BLINDING): TOpenSSL_C_INT; cdecl = nil;
  BN_BLINDING_get_flags: function (v1: PBN_BLINDING): TOpenSSL_C_ULONG; cdecl = nil;
  BN_BLINDING_set_flags: procedure (v1: PBN_BLINDING; v2: TOpenSSL_C_ULONG); cdecl = nil;
  BN_RECP_CTX_free: procedure (recp: PBN_RECP_CTX); cdecl = nil;
  BN_RECP_CTX_set: function (recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_mul_reciprocal: function (r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_mod_exp_recp: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_div_recp: function (dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_add: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod_mul: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod_sqr: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod_inv: function (r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod_div: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod_exp: function (r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod_sqrt: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_GF2m_mod_solve_quad: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_nist_mod_192: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_nist_mod_224: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_nist_mod_256: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_nist_mod_384: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_nist_mod_521: function (r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_get0_nist_prime_192: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_224: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_256: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_384: function : PBIGNUM; cdecl = nil;
  BN_get0_nist_prime_521: function : PBIGNUM; cdecl = nil;
  BN_generate_dsa_nonce: function (out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = nil;
  BN_get_rfc2409_prime_768: function (bn: PBIGNUM ): PBIGNUM; cdecl = nil;
  BN_get_rfc2409_prime_1024: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_1536: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_2048: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_3072: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_4096: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_6144: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_get_rfc3526_prime_8192: function (bn: PBIGNUM): PBIGNUM; cdecl = nil;
  BN_bntest_rand: function (rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
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
procedure ERROR_BN_set_flags(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_flags');
end;

function ERROR_BN_get_flags(b: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_flags');
end;

procedure ERROR_BN_with_flags(dest: PBIGNUM; b: PBIGNUM; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_with_flags');
end;

function ERROR_BN_GENCB_call(cb: PBN_GENCB; a: TOpenSSL_C_INT; b: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_call');
end;

function ERROR_BN_GENCB_new: PBN_GENCB; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_new');
end;

procedure ERROR_BN_GENCB_free(cb: PBN_GENCB); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_free');
end;

procedure ERROR_BN_GENCB_set_old(gencb: PBN_GENCB; callback: BN_GENCB_set_old_cb; cb_arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_set_old');
end;

procedure ERROR_BN_GENCB_set(gencb: PBN_GENCB; callback: BN_GENCB_set_cb; cb_arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_set');
end;

function ERROR_BN_GENCB_get_arg(cb: PBN_GENCB): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GENCB_get_arg');
end;

function ERROR_BN_abs_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_abs_is_word');
end;

function ERROR_BN_is_zero(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_zero');
end;

function ERROR_BN_is_one(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_one');
end;

function ERROR_BN_is_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_word');
end;

function ERROR_BN_is_odd(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_odd');
end;

procedure ERROR_BN_zero_ex(a: PBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_zero_ex');
end;

function ERROR_BN_value_one: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_value_one');
end;

function ERROR_BN_options: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_options');
end;

function ERROR_BN_CTX_new: PBN_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_new');
end;

function ERROR_BN_CTX_secure_new: PBN_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_secure_new');
end;

procedure ERROR_BN_CTX_free(c: PBN_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_free');
end;

procedure ERROR_BN_CTX_start(ctx: PBN_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_start');
end;

function ERROR_BN_CTX_get(ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_get');
end;

procedure ERROR_BN_CTX_end(ctx: PBN_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_CTX_end');
end;

function ERROR_BN_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rand');
end;

function ERROR_BN_priv_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_priv_rand');
end;

function ERROR_BN_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rand_range');
end;

function ERROR_BN_priv_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_priv_rand_range');
end;

function ERROR_BN_pseudo_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_pseudo_rand');
end;

function ERROR_BN_pseudo_rand_range(rnd: PBIGNUM; range: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_pseudo_rand_range');
end;

function ERROR_BN_num_bits(a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_num_bits');
end;

function ERROR_BN_num_bits_word(l: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_num_bits_word');
end;

function ERROR_BN_security_bits(L: TOpenSSL_C_INT; N: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_security_bits');
end;

function ERROR_BN_new: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_new');
end;

function ERROR_BN_secure_new: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_secure_new');
end;

procedure ERROR_BN_clear_free(a: PBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_clear_free');
end;

function ERROR_BN_copy(a: PBIGNUM; b: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_copy');
end;

procedure ERROR_BN_swap(a: PBIGNUM; b: PBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_swap');
end;

function ERROR_BN_bin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bin2bn');
end;

function ERROR_BN_bn2bin(const a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2bin');
end;

function ERROR_BN_bn2binpad(const a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2binpad');
end;

function ERROR_BN_lebin2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_lebin2bn');
end;

function ERROR_BN_bn2lebinpad(a: PBIGNUM; to_: PByte; tolen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2lebinpad');
end;

function ERROR_BN_mpi2bn(const s: PByte; len: TOpenSSL_C_INT; ret: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mpi2bn');
end;

function ERROR_BN_bn2mpi(a: PBIGNUM; to_: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2mpi');
end;

function ERROR_BN_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_sub');
end;

function ERROR_BN_usub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_usub');
end;

function ERROR_BN_uadd(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_uadd');
end;

function ERROR_BN_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_add');
end;

function ERROR_BN_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mul');
end;

function ERROR_BN_sqr(r: PBIGNUM; const a: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_sqr');
end;

procedure ERROR_BN_set_negative(b: PBIGNUM; n: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_negative');
end;

function ERROR_BN_is_negative(b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_negative');
end;

function ERROR_BN_div(dv: PBIGNUM; rem: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_div');
end;

function ERROR_BN_nnmod(r: PBIGNUM; const m: PBIGNUM; const d: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nnmod');
end;

function ERROR_BN_mod_add(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_add');
end;

function ERROR_BN_mod_add_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_add_quick');
end;

function ERROR_BN_mod_sub(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sub');
end;

function ERROR_BN_mod_sub_quick(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sub_quick');
end;

function ERROR_BN_mod_mul(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_mul');
end;

function ERROR_BN_mod_sqr(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sqr');
end;

function ERROR_BN_mod_lshift1(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift1');
end;

function ERROR_BN_mod_lshift1_quick(r: PBIGNUM; const a: PBIGNUM; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift1_quick');
end;

function ERROR_BN_mod_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift');
end;

function ERROR_BN_mod_lshift_quick(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT; const m: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_lshift_quick');
end;

function ERROR_BN_mod_word(const a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_word');
end;

function ERROR_BN_div_word(a: PBIGNUM; w: BN_ULONG): BN_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_div_word');
end;

function ERROR_BN_mul_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mul_word');
end;

function ERROR_BN_add_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_add_word');
end;

function ERROR_BN_sub_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_sub_word');
end;

function ERROR_BN_set_word(a: PBIGNUM; w: BN_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_word');
end;

function ERROR_BN_get_word(const a: PBIGNUM): BN_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_word');
end;

function ERROR_BN_cmp(const a: PBIGNUM; const b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_cmp');
end;

procedure ERROR_BN_free(a: PBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_free');
end;

function ERROR_BN_is_bit_set(const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_bit_set');
end;

function ERROR_BN_lshift(r: PBIGNUM; const a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_lshift');
end;

function ERROR_BN_lshift1(r: PBIGNUM; const a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_lshift1');
end;

function ERROR_BN_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_exp');
end;

function ERROR_BN_mod_exp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp');
end;

function ERROR_BN_mod_exp_mont(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_mont');
end;

function ERROR_BN_mod_exp_mont_consttime(rr: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; in_mont: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_mont_consttime');
end;

function ERROR_BN_mod_exp_mont_word(r: PBIGNUM; a: BN_ULONG; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_mont_word');
end;

function ERROR_BN_mod_exp2_mont(r: PBIGNUM; const a1: PBIGNUM; const p1: PBIGNUM; const a2: PBIGNUM; const p2: PBIGNUM; const m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp2_mont');
end;

function ERROR_BN_mod_exp_simple(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_simple');
end;

function ERROR_BN_mask_bits(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mask_bits');
end;

function ERROR_BN_print(bio: PBIO; a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_print');
end;

function ERROR_BN_reciprocal(r: PBIGNUM; m: PBIGNUM; len: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_reciprocal');
end;

function ERROR_BN_rshift(r: PBIGNUM; a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rshift');
end;

function ERROR_BN_rshift1(r: PBIGNUM; a: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_rshift1');
end;

procedure ERROR_BN_clear(a: PBIGNUM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_clear');
end;

function ERROR_BN_dup(const a: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_dup');
end;

function ERROR_BN_ucmp(a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_ucmp');
end;

function ERROR_BN_set_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_set_bit');
end;

function ERROR_BN_clear_bit(a: PBIGNUM; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_clear_bit');
end;

function ERROR_BN_bn2hex(a: PBIGNUM): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2hex');
end;

function ERROR_BN_bn2dec(a: PBIGNUM): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bn2dec');
end;

function ERROR_BN_hex2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_hex2bn');
end;

function ERROR_BN_dec2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_dec2bn');
end;

function ERROR_BN_asc2bn(a: PPBIGNUM; str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_asc2bn');
end;

function ERROR_BN_gcd(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_gcd');
end;

function ERROR_BN_kronecker(a: PBIGNUM; b: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_kronecker');
end;

function ERROR_BN_mod_inverse(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_inverse');
end;

function ERROR_BN_mod_sqrt(ret: PBIGNUM; a: PBIGNUM; const n: PBIGNUM; ctx: PBN_CTX): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_sqrt');
end;

procedure ERROR_BN_consttime_swap(swap: BN_ULONG; a: PBIGNUM; b: PBIGNUM; nwords: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_consttime_swap');
end;

function ERROR_BN_generate_prime_ex(ret: PBIGNUM; bits: TOpenSSL_C_INT; safe: TOpenSSL_C_INT; const add: PBIGNUM; const rem: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_generate_prime_ex');
end;

function ERROR_BN_is_prime_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_prime_ex');
end;

function ERROR_BN_is_prime_fasttest_ex(const p: PBIGNUM; nchecks: TOpenSSL_C_INT; ctx: PBN_CTX; do_trial_division: TOpenSSL_C_INT; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_is_prime_fasttest_ex');
end;

function ERROR_BN_X931_generate_Xpq(Xp: PBIGNUM; Xq: PBIGNUM; nbits: TOpenSSL_C_INT; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_X931_generate_Xpq');
end;

function ERROR_BN_X931_derive_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; const Xp: PBIGNUM; const Xp1: PBIGNUM; const Xp2: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_X931_derive_prime_ex');
end;

function ERROR_BN_X931_generate_prime_ex(p: PBIGNUM; p1: PBIGNUM; p2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; const e: PBIGNUM; ctx: PBN_CTX; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_X931_generate_prime_ex');
end;

function ERROR_BN_MONT_CTX_new: PBN_MONT_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_new');
end;

function ERROR_BN_mod_mul_montgomery(r: PBIGNUM; const a: PBIGNUM; const b: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_mul_montgomery');
end;

function ERROR_BN_to_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_to_montgomery');
end;

function ERROR_BN_from_montgomery(r: PBIGNUM; a: PBIGNUM; mont: PBN_MONT_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_from_montgomery');
end;

procedure ERROR_BN_MONT_CTX_free(mont: PBN_MONT_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_free');
end;

function ERROR_BN_MONT_CTX_set(mont: PBN_MONT_CTX; mod_: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_set');
end;

function ERROR_BN_MONT_CTX_copy(to_: PBN_MONT_CTX; from: PBN_MONT_CTX): PBN_MONT_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_MONT_CTX_copy');
end;

function ERROR_BN_BLINDING_new(const A: PBIGNUM; const Ai: PBIGNUM; mod_: PBIGNUM): PBN_BLINDING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_new');
end;

procedure ERROR_BN_BLINDING_free(b: PBN_BLINDING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_free');
end;

function ERROR_BN_BLINDING_update(b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_update');
end;

function ERROR_BN_BLINDING_convert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_convert');
end;

function ERROR_BN_BLINDING_invert(n: PBIGNUM; b: PBN_BLINDING; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_invert');
end;

function ERROR_BN_BLINDING_convert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v4: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_convert_ex');
end;

function ERROR_BN_BLINDING_invert_ex(n: PBIGNUM; r: PBIGNUM; b: PBN_BLINDING; v2: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_invert_ex');
end;

function ERROR_BN_BLINDING_is_current_thread(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_is_current_thread');
end;

procedure ERROR_BN_BLINDING_set_current_thread(b: PBN_BLINDING); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_set_current_thread');
end;

function ERROR_BN_BLINDING_lock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_lock');
end;

function ERROR_BN_BLINDING_unlock(b: PBN_BLINDING): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_unlock');
end;

function ERROR_BN_BLINDING_get_flags(v1: PBN_BLINDING): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_get_flags');
end;

procedure ERROR_BN_BLINDING_set_flags(v1: PBN_BLINDING; v2: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_BLINDING_set_flags');
end;

procedure ERROR_BN_RECP_CTX_free(recp: PBN_RECP_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_RECP_CTX_free');
end;

function ERROR_BN_RECP_CTX_set(recp: PBN_RECP_CTX; rdiv: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_RECP_CTX_set');
end;

function ERROR_BN_mod_mul_reciprocal(r: PBIGNUM; x: PBIGNUM; y: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_mul_reciprocal');
end;

function ERROR_BN_mod_exp_recp(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_mod_exp_recp');
end;

function ERROR_BN_div_recp(dv: PBIGNUM; rem: PBIGNUM; m: PBIGNUM; recp: PBN_RECP_CTX; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_div_recp');
end;

function ERROR_BN_GF2m_add(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_add');
end;

function ERROR_BN_GF2m_mod(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod');
end;

function ERROR_BN_GF2m_mod_mul(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_mul');
end;

function ERROR_BN_GF2m_mod_sqr(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_sqr');
end;

function ERROR_BN_GF2m_mod_inv(r: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_inv');
end;

function ERROR_BN_GF2m_mod_div(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_div');
end;

function ERROR_BN_GF2m_mod_exp(r: PBIGNUM; a: PBIGNUM; b: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_exp');
end;

function ERROR_BN_GF2m_mod_sqrt(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_sqrt');
end;

function ERROR_BN_GF2m_mod_solve_quad(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_GF2m_mod_solve_quad');
end;

function ERROR_BN_nist_mod_192(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_192');
end;

function ERROR_BN_nist_mod_224(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_224');
end;

function ERROR_BN_nist_mod_256(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_256');
end;

function ERROR_BN_nist_mod_384(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_384');
end;

function ERROR_BN_nist_mod_521(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_nist_mod_521');
end;

function ERROR_BN_get0_nist_prime_192: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_192');
end;

function ERROR_BN_get0_nist_prime_224: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_224');
end;

function ERROR_BN_get0_nist_prime_256: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_256');
end;

function ERROR_BN_get0_nist_prime_384: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_384');
end;

function ERROR_BN_get0_nist_prime_521: PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get0_nist_prime_521');
end;

function ERROR_BN_generate_dsa_nonce(out_: PBIGNUM; range: PBIGNUM; priv: PBIGNUM; const message_: PByte; message_len: TOpenSSL_C_SIZET; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_generate_dsa_nonce');
end;

function ERROR_BN_get_rfc2409_prime_768(bn: PBIGNUM ): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc2409_prime_768');
end;

function ERROR_BN_get_rfc2409_prime_1024(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc2409_prime_1024');
end;

function ERROR_BN_get_rfc3526_prime_1536(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_1536');
end;

function ERROR_BN_get_rfc3526_prime_2048(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_2048');
end;

function ERROR_BN_get_rfc3526_prime_3072(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_3072');
end;

function ERROR_BN_get_rfc3526_prime_4096(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_4096');
end;

function ERROR_BN_get_rfc3526_prime_6144(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_6144');
end;

function ERROR_BN_get_rfc3526_prime_8192(bn: PBIGNUM): PBIGNUM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_get_rfc3526_prime_8192');
end;

function ERROR_BN_bntest_rand(rnd: PBIGNUM; bits: TOpenSSL_C_INT; top: TOpenSSL_C_INT; bottom: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BN_bntest_rand');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  BN_set_flags := LoadLibCryptoFunction('BN_set_flags');
  FuncLoadError := not assigned(BN_set_flags);
  if FuncLoadError then
  begin
    BN_set_flags :=  @ERROR_BN_set_flags;
  end;

  BN_get_flags := LoadLibCryptoFunction('BN_get_flags');
  FuncLoadError := not assigned(BN_get_flags);
  if FuncLoadError then
  begin
    BN_get_flags :=  @ERROR_BN_get_flags;
  end;

  BN_with_flags := LoadLibCryptoFunction('BN_with_flags');
  FuncLoadError := not assigned(BN_with_flags);
  if FuncLoadError then
  begin
    BN_with_flags :=  @ERROR_BN_with_flags;
  end;

  BN_GENCB_call := LoadLibCryptoFunction('BN_GENCB_call');
  FuncLoadError := not assigned(BN_GENCB_call);
  if FuncLoadError then
  begin
    BN_GENCB_call :=  @ERROR_BN_GENCB_call;
  end;

  BN_GENCB_new := LoadLibCryptoFunction('BN_GENCB_new');
  FuncLoadError := not assigned(BN_GENCB_new);
  if FuncLoadError then
  begin
    BN_GENCB_new :=  @ERROR_BN_GENCB_new;
  end;

  BN_GENCB_free := LoadLibCryptoFunction('BN_GENCB_free');
  FuncLoadError := not assigned(BN_GENCB_free);
  if FuncLoadError then
  begin
    BN_GENCB_free :=  @ERROR_BN_GENCB_free;
  end;

  BN_GENCB_set_old := LoadLibCryptoFunction('BN_GENCB_set_old');
  FuncLoadError := not assigned(BN_GENCB_set_old);
  if FuncLoadError then
  begin
    BN_GENCB_set_old :=  @ERROR_BN_GENCB_set_old;
  end;

  BN_GENCB_set := LoadLibCryptoFunction('BN_GENCB_set');
  FuncLoadError := not assigned(BN_GENCB_set);
  if FuncLoadError then
  begin
    BN_GENCB_set :=  @ERROR_BN_GENCB_set;
  end;

  BN_GENCB_get_arg := LoadLibCryptoFunction('BN_GENCB_get_arg');
  FuncLoadError := not assigned(BN_GENCB_get_arg);
  if FuncLoadError then
  begin
    BN_GENCB_get_arg :=  @ERROR_BN_GENCB_get_arg;
  end;

  BN_abs_is_word := LoadLibCryptoFunction('BN_abs_is_word');
  FuncLoadError := not assigned(BN_abs_is_word);
  if FuncLoadError then
  begin
    BN_abs_is_word :=  @ERROR_BN_abs_is_word;
  end;

  BN_is_zero := LoadLibCryptoFunction('BN_is_zero');
  FuncLoadError := not assigned(BN_is_zero);
  if FuncLoadError then
  begin
    BN_is_zero :=  @ERROR_BN_is_zero;
  end;

  BN_is_one := LoadLibCryptoFunction('BN_is_one');
  FuncLoadError := not assigned(BN_is_one);
  if FuncLoadError then
  begin
    BN_is_one :=  @ERROR_BN_is_one;
  end;

  BN_is_word := LoadLibCryptoFunction('BN_is_word');
  FuncLoadError := not assigned(BN_is_word);
  if FuncLoadError then
  begin
    BN_is_word :=  @ERROR_BN_is_word;
  end;

  BN_is_odd := LoadLibCryptoFunction('BN_is_odd');
  FuncLoadError := not assigned(BN_is_odd);
  if FuncLoadError then
  begin
    BN_is_odd :=  @ERROR_BN_is_odd;
  end;

  BN_zero_ex := LoadLibCryptoFunction('BN_zero_ex');
  FuncLoadError := not assigned(BN_zero_ex);
  if FuncLoadError then
  begin
    BN_zero_ex :=  @ERROR_BN_zero_ex;
  end;

  BN_value_one := LoadLibCryptoFunction('BN_value_one');
  FuncLoadError := not assigned(BN_value_one);
  if FuncLoadError then
  begin
    BN_value_one :=  @ERROR_BN_value_one;
  end;

  BN_options := LoadLibCryptoFunction('BN_options');
  FuncLoadError := not assigned(BN_options);
  if FuncLoadError then
  begin
    BN_options :=  @ERROR_BN_options;
  end;

  BN_CTX_new := LoadLibCryptoFunction('BN_CTX_new');
  FuncLoadError := not assigned(BN_CTX_new);
  if FuncLoadError then
  begin
    BN_CTX_new :=  @ERROR_BN_CTX_new;
  end;

  BN_CTX_secure_new := LoadLibCryptoFunction('BN_CTX_secure_new');
  FuncLoadError := not assigned(BN_CTX_secure_new);
  if FuncLoadError then
  begin
    BN_CTX_secure_new :=  @ERROR_BN_CTX_secure_new;
  end;

  BN_CTX_free := LoadLibCryptoFunction('BN_CTX_free');
  FuncLoadError := not assigned(BN_CTX_free);
  if FuncLoadError then
  begin
    BN_CTX_free :=  @ERROR_BN_CTX_free;
  end;

  BN_CTX_start := LoadLibCryptoFunction('BN_CTX_start');
  FuncLoadError := not assigned(BN_CTX_start);
  if FuncLoadError then
  begin
    BN_CTX_start :=  @ERROR_BN_CTX_start;
  end;

  BN_CTX_get := LoadLibCryptoFunction('BN_CTX_get');
  FuncLoadError := not assigned(BN_CTX_get);
  if FuncLoadError then
  begin
    BN_CTX_get :=  @ERROR_BN_CTX_get;
  end;

  BN_CTX_end := LoadLibCryptoFunction('BN_CTX_end');
  FuncLoadError := not assigned(BN_CTX_end);
  if FuncLoadError then
  begin
    BN_CTX_end :=  @ERROR_BN_CTX_end;
  end;

  BN_rand := LoadLibCryptoFunction('BN_rand');
  FuncLoadError := not assigned(BN_rand);
  if FuncLoadError then
  begin
    BN_rand :=  @ERROR_BN_rand;
  end;

  BN_priv_rand := LoadLibCryptoFunction('BN_priv_rand');
  FuncLoadError := not assigned(BN_priv_rand);
  if FuncLoadError then
  begin
    BN_priv_rand :=  @ERROR_BN_priv_rand;
  end;

  BN_rand_range := LoadLibCryptoFunction('BN_rand_range');
  FuncLoadError := not assigned(BN_rand_range);
  if FuncLoadError then
  begin
    BN_rand_range :=  @ERROR_BN_rand_range;
  end;

  BN_priv_rand_range := LoadLibCryptoFunction('BN_priv_rand_range');
  FuncLoadError := not assigned(BN_priv_rand_range);
  if FuncLoadError then
  begin
    BN_priv_rand_range :=  @ERROR_BN_priv_rand_range;
  end;

  BN_pseudo_rand := LoadLibCryptoFunction('BN_pseudo_rand');
  FuncLoadError := not assigned(BN_pseudo_rand);
  if FuncLoadError then
  begin
    BN_pseudo_rand :=  @ERROR_BN_pseudo_rand;
  end;

  BN_pseudo_rand_range := LoadLibCryptoFunction('BN_pseudo_rand_range');
  FuncLoadError := not assigned(BN_pseudo_rand_range);
  if FuncLoadError then
  begin
    BN_pseudo_rand_range :=  @ERROR_BN_pseudo_rand_range;
  end;

  BN_num_bits := LoadLibCryptoFunction('BN_num_bits');
  FuncLoadError := not assigned(BN_num_bits);
  if FuncLoadError then
  begin
    BN_num_bits :=  @ERROR_BN_num_bits;
  end;

  BN_num_bits_word := LoadLibCryptoFunction('BN_num_bits_word');
  FuncLoadError := not assigned(BN_num_bits_word);
  if FuncLoadError then
  begin
    BN_num_bits_word :=  @ERROR_BN_num_bits_word;
  end;

  BN_security_bits := LoadLibCryptoFunction('BN_security_bits');
  FuncLoadError := not assigned(BN_security_bits);
  if FuncLoadError then
  begin
    BN_security_bits :=  @ERROR_BN_security_bits;
  end;

  BN_new := LoadLibCryptoFunction('BN_new');
  FuncLoadError := not assigned(BN_new);
  if FuncLoadError then
  begin
    BN_new :=  @ERROR_BN_new;
  end;

  BN_secure_new := LoadLibCryptoFunction('BN_secure_new');
  FuncLoadError := not assigned(BN_secure_new);
  if FuncLoadError then
  begin
    BN_secure_new :=  @ERROR_BN_secure_new;
  end;

  BN_clear_free := LoadLibCryptoFunction('BN_clear_free');
  FuncLoadError := not assigned(BN_clear_free);
  if FuncLoadError then
  begin
    BN_clear_free :=  @ERROR_BN_clear_free;
  end;

  BN_copy := LoadLibCryptoFunction('BN_copy');
  FuncLoadError := not assigned(BN_copy);
  if FuncLoadError then
  begin
    BN_copy :=  @ERROR_BN_copy;
  end;

  BN_swap := LoadLibCryptoFunction('BN_swap');
  FuncLoadError := not assigned(BN_swap);
  if FuncLoadError then
  begin
    BN_swap :=  @ERROR_BN_swap;
  end;

  BN_bin2bn := LoadLibCryptoFunction('BN_bin2bn');
  FuncLoadError := not assigned(BN_bin2bn);
  if FuncLoadError then
  begin
    BN_bin2bn :=  @ERROR_BN_bin2bn;
  end;

  BN_bn2bin := LoadLibCryptoFunction('BN_bn2bin');
  FuncLoadError := not assigned(BN_bn2bin);
  if FuncLoadError then
  begin
    BN_bn2bin :=  @ERROR_BN_bn2bin;
  end;

  BN_bn2binpad := LoadLibCryptoFunction('BN_bn2binpad');
  FuncLoadError := not assigned(BN_bn2binpad);
  if FuncLoadError then
  begin
    BN_bn2binpad :=  @ERROR_BN_bn2binpad;
  end;

  BN_lebin2bn := LoadLibCryptoFunction('BN_lebin2bn');
  FuncLoadError := not assigned(BN_lebin2bn);
  if FuncLoadError then
  begin
    BN_lebin2bn :=  @ERROR_BN_lebin2bn;
  end;

  BN_bn2lebinpad := LoadLibCryptoFunction('BN_bn2lebinpad');
  FuncLoadError := not assigned(BN_bn2lebinpad);
  if FuncLoadError then
  begin
    BN_bn2lebinpad :=  @ERROR_BN_bn2lebinpad;
  end;

  BN_mpi2bn := LoadLibCryptoFunction('BN_mpi2bn');
  FuncLoadError := not assigned(BN_mpi2bn);
  if FuncLoadError then
  begin
    BN_mpi2bn :=  @ERROR_BN_mpi2bn;
  end;

  BN_bn2mpi := LoadLibCryptoFunction('BN_bn2mpi');
  FuncLoadError := not assigned(BN_bn2mpi);
  if FuncLoadError then
  begin
    BN_bn2mpi :=  @ERROR_BN_bn2mpi;
  end;

  BN_sub := LoadLibCryptoFunction('BN_sub');
  FuncLoadError := not assigned(BN_sub);
  if FuncLoadError then
  begin
    BN_sub :=  @ERROR_BN_sub;
  end;

  BN_usub := LoadLibCryptoFunction('BN_usub');
  FuncLoadError := not assigned(BN_usub);
  if FuncLoadError then
  begin
    BN_usub :=  @ERROR_BN_usub;
  end;

  BN_uadd := LoadLibCryptoFunction('BN_uadd');
  FuncLoadError := not assigned(BN_uadd);
  if FuncLoadError then
  begin
    BN_uadd :=  @ERROR_BN_uadd;
  end;

  BN_add := LoadLibCryptoFunction('BN_add');
  FuncLoadError := not assigned(BN_add);
  if FuncLoadError then
  begin
    BN_add :=  @ERROR_BN_add;
  end;

  BN_mul := LoadLibCryptoFunction('BN_mul');
  FuncLoadError := not assigned(BN_mul);
  if FuncLoadError then
  begin
    BN_mul :=  @ERROR_BN_mul;
  end;

  BN_sqr := LoadLibCryptoFunction('BN_sqr');
  FuncLoadError := not assigned(BN_sqr);
  if FuncLoadError then
  begin
    BN_sqr :=  @ERROR_BN_sqr;
  end;

  BN_set_negative := LoadLibCryptoFunction('BN_set_negative');
  FuncLoadError := not assigned(BN_set_negative);
  if FuncLoadError then
  begin
    BN_set_negative :=  @ERROR_BN_set_negative;
  end;

  BN_is_negative := LoadLibCryptoFunction('BN_is_negative');
  FuncLoadError := not assigned(BN_is_negative);
  if FuncLoadError then
  begin
    BN_is_negative :=  @ERROR_BN_is_negative;
  end;

  BN_div := LoadLibCryptoFunction('BN_div');
  FuncLoadError := not assigned(BN_div);
  if FuncLoadError then
  begin
    BN_div :=  @ERROR_BN_div;
  end;

  BN_nnmod := LoadLibCryptoFunction('BN_nnmod');
  FuncLoadError := not assigned(BN_nnmod);
  if FuncLoadError then
  begin
    BN_nnmod :=  @ERROR_BN_nnmod;
  end;

  BN_mod_add := LoadLibCryptoFunction('BN_mod_add');
  FuncLoadError := not assigned(BN_mod_add);
  if FuncLoadError then
  begin
    BN_mod_add :=  @ERROR_BN_mod_add;
  end;

  BN_mod_add_quick := LoadLibCryptoFunction('BN_mod_add_quick');
  FuncLoadError := not assigned(BN_mod_add_quick);
  if FuncLoadError then
  begin
    BN_mod_add_quick :=  @ERROR_BN_mod_add_quick;
  end;

  BN_mod_sub := LoadLibCryptoFunction('BN_mod_sub');
  FuncLoadError := not assigned(BN_mod_sub);
  if FuncLoadError then
  begin
    BN_mod_sub :=  @ERROR_BN_mod_sub;
  end;

  BN_mod_sub_quick := LoadLibCryptoFunction('BN_mod_sub_quick');
  FuncLoadError := not assigned(BN_mod_sub_quick);
  if FuncLoadError then
  begin
    BN_mod_sub_quick :=  @ERROR_BN_mod_sub_quick;
  end;

  BN_mod_mul := LoadLibCryptoFunction('BN_mod_mul');
  FuncLoadError := not assigned(BN_mod_mul);
  if FuncLoadError then
  begin
    BN_mod_mul :=  @ERROR_BN_mod_mul;
  end;

  BN_mod_sqr := LoadLibCryptoFunction('BN_mod_sqr');
  FuncLoadError := not assigned(BN_mod_sqr);
  if FuncLoadError then
  begin
    BN_mod_sqr :=  @ERROR_BN_mod_sqr;
  end;

  BN_mod_lshift1 := LoadLibCryptoFunction('BN_mod_lshift1');
  FuncLoadError := not assigned(BN_mod_lshift1);
  if FuncLoadError then
  begin
    BN_mod_lshift1 :=  @ERROR_BN_mod_lshift1;
  end;

  BN_mod_lshift1_quick := LoadLibCryptoFunction('BN_mod_lshift1_quick');
  FuncLoadError := not assigned(BN_mod_lshift1_quick);
  if FuncLoadError then
  begin
    BN_mod_lshift1_quick :=  @ERROR_BN_mod_lshift1_quick;
  end;

  BN_mod_lshift := LoadLibCryptoFunction('BN_mod_lshift');
  FuncLoadError := not assigned(BN_mod_lshift);
  if FuncLoadError then
  begin
    BN_mod_lshift :=  @ERROR_BN_mod_lshift;
  end;

  BN_mod_lshift_quick := LoadLibCryptoFunction('BN_mod_lshift_quick');
  FuncLoadError := not assigned(BN_mod_lshift_quick);
  if FuncLoadError then
  begin
    BN_mod_lshift_quick :=  @ERROR_BN_mod_lshift_quick;
  end;

  BN_mod_word := LoadLibCryptoFunction('BN_mod_word');
  FuncLoadError := not assigned(BN_mod_word);
  if FuncLoadError then
  begin
    BN_mod_word :=  @ERROR_BN_mod_word;
  end;

  BN_div_word := LoadLibCryptoFunction('BN_div_word');
  FuncLoadError := not assigned(BN_div_word);
  if FuncLoadError then
  begin
    BN_div_word :=  @ERROR_BN_div_word;
  end;

  BN_mul_word := LoadLibCryptoFunction('BN_mul_word');
  FuncLoadError := not assigned(BN_mul_word);
  if FuncLoadError then
  begin
    BN_mul_word :=  @ERROR_BN_mul_word;
  end;

  BN_add_word := LoadLibCryptoFunction('BN_add_word');
  FuncLoadError := not assigned(BN_add_word);
  if FuncLoadError then
  begin
    BN_add_word :=  @ERROR_BN_add_word;
  end;

  BN_sub_word := LoadLibCryptoFunction('BN_sub_word');
  FuncLoadError := not assigned(BN_sub_word);
  if FuncLoadError then
  begin
    BN_sub_word :=  @ERROR_BN_sub_word;
  end;

  BN_set_word := LoadLibCryptoFunction('BN_set_word');
  FuncLoadError := not assigned(BN_set_word);
  if FuncLoadError then
  begin
    BN_set_word :=  @ERROR_BN_set_word;
  end;

  BN_get_word := LoadLibCryptoFunction('BN_get_word');
  FuncLoadError := not assigned(BN_get_word);
  if FuncLoadError then
  begin
    BN_get_word :=  @ERROR_BN_get_word;
  end;

  BN_cmp := LoadLibCryptoFunction('BN_cmp');
  FuncLoadError := not assigned(BN_cmp);
  if FuncLoadError then
  begin
    BN_cmp :=  @ERROR_BN_cmp;
  end;

  BN_free := LoadLibCryptoFunction('BN_free');
  FuncLoadError := not assigned(BN_free);
  if FuncLoadError then
  begin
    BN_free :=  @ERROR_BN_free;
  end;

  BN_is_bit_set := LoadLibCryptoFunction('BN_is_bit_set');
  FuncLoadError := not assigned(BN_is_bit_set);
  if FuncLoadError then
  begin
    BN_is_bit_set :=  @ERROR_BN_is_bit_set;
  end;

  BN_lshift := LoadLibCryptoFunction('BN_lshift');
  FuncLoadError := not assigned(BN_lshift);
  if FuncLoadError then
  begin
    BN_lshift :=  @ERROR_BN_lshift;
  end;

  BN_lshift1 := LoadLibCryptoFunction('BN_lshift1');
  FuncLoadError := not assigned(BN_lshift1);
  if FuncLoadError then
  begin
    BN_lshift1 :=  @ERROR_BN_lshift1;
  end;

  BN_exp := LoadLibCryptoFunction('BN_exp');
  FuncLoadError := not assigned(BN_exp);
  if FuncLoadError then
  begin
    BN_exp :=  @ERROR_BN_exp;
  end;

  BN_mod_exp := LoadLibCryptoFunction('BN_mod_exp');
  FuncLoadError := not assigned(BN_mod_exp);
  if FuncLoadError then
  begin
    BN_mod_exp :=  @ERROR_BN_mod_exp;
  end;

  BN_mod_exp_mont := LoadLibCryptoFunction('BN_mod_exp_mont');
  FuncLoadError := not assigned(BN_mod_exp_mont);
  if FuncLoadError then
  begin
    BN_mod_exp_mont :=  @ERROR_BN_mod_exp_mont;
  end;

  BN_mod_exp_mont_consttime := LoadLibCryptoFunction('BN_mod_exp_mont_consttime');
  FuncLoadError := not assigned(BN_mod_exp_mont_consttime);
  if FuncLoadError then
  begin
    BN_mod_exp_mont_consttime :=  @ERROR_BN_mod_exp_mont_consttime;
  end;

  BN_mod_exp_mont_word := LoadLibCryptoFunction('BN_mod_exp_mont_word');
  FuncLoadError := not assigned(BN_mod_exp_mont_word);
  if FuncLoadError then
  begin
    BN_mod_exp_mont_word :=  @ERROR_BN_mod_exp_mont_word;
  end;

  BN_mod_exp2_mont := LoadLibCryptoFunction('BN_mod_exp2_mont');
  FuncLoadError := not assigned(BN_mod_exp2_mont);
  if FuncLoadError then
  begin
    BN_mod_exp2_mont :=  @ERROR_BN_mod_exp2_mont;
  end;

  BN_mod_exp_simple := LoadLibCryptoFunction('BN_mod_exp_simple');
  FuncLoadError := not assigned(BN_mod_exp_simple);
  if FuncLoadError then
  begin
    BN_mod_exp_simple :=  @ERROR_BN_mod_exp_simple;
  end;

  BN_mask_bits := LoadLibCryptoFunction('BN_mask_bits');
  FuncLoadError := not assigned(BN_mask_bits);
  if FuncLoadError then
  begin
    BN_mask_bits :=  @ERROR_BN_mask_bits;
  end;

  BN_print := LoadLibCryptoFunction('BN_print');
  FuncLoadError := not assigned(BN_print);
  if FuncLoadError then
  begin
    BN_print :=  @ERROR_BN_print;
  end;

  BN_reciprocal := LoadLibCryptoFunction('BN_reciprocal');
  FuncLoadError := not assigned(BN_reciprocal);
  if FuncLoadError then
  begin
    BN_reciprocal :=  @ERROR_BN_reciprocal;
  end;

  BN_rshift := LoadLibCryptoFunction('BN_rshift');
  FuncLoadError := not assigned(BN_rshift);
  if FuncLoadError then
  begin
    BN_rshift :=  @ERROR_BN_rshift;
  end;

  BN_rshift1 := LoadLibCryptoFunction('BN_rshift1');
  FuncLoadError := not assigned(BN_rshift1);
  if FuncLoadError then
  begin
    BN_rshift1 :=  @ERROR_BN_rshift1;
  end;

  BN_clear := LoadLibCryptoFunction('BN_clear');
  FuncLoadError := not assigned(BN_clear);
  if FuncLoadError then
  begin
    BN_clear :=  @ERROR_BN_clear;
  end;

  BN_dup := LoadLibCryptoFunction('BN_dup');
  FuncLoadError := not assigned(BN_dup);
  if FuncLoadError then
  begin
    BN_dup :=  @ERROR_BN_dup;
  end;

  BN_ucmp := LoadLibCryptoFunction('BN_ucmp');
  FuncLoadError := not assigned(BN_ucmp);
  if FuncLoadError then
  begin
    BN_ucmp :=  @ERROR_BN_ucmp;
  end;

  BN_set_bit := LoadLibCryptoFunction('BN_set_bit');
  FuncLoadError := not assigned(BN_set_bit);
  if FuncLoadError then
  begin
    BN_set_bit :=  @ERROR_BN_set_bit;
  end;

  BN_clear_bit := LoadLibCryptoFunction('BN_clear_bit');
  FuncLoadError := not assigned(BN_clear_bit);
  if FuncLoadError then
  begin
    BN_clear_bit :=  @ERROR_BN_clear_bit;
  end;

  BN_bn2hex := LoadLibCryptoFunction('BN_bn2hex');
  FuncLoadError := not assigned(BN_bn2hex);
  if FuncLoadError then
  begin
    BN_bn2hex :=  @ERROR_BN_bn2hex;
  end;

  BN_bn2dec := LoadLibCryptoFunction('BN_bn2dec');
  FuncLoadError := not assigned(BN_bn2dec);
  if FuncLoadError then
  begin
    BN_bn2dec :=  @ERROR_BN_bn2dec;
  end;

  BN_hex2bn := LoadLibCryptoFunction('BN_hex2bn');
  FuncLoadError := not assigned(BN_hex2bn);
  if FuncLoadError then
  begin
    BN_hex2bn :=  @ERROR_BN_hex2bn;
  end;

  BN_dec2bn := LoadLibCryptoFunction('BN_dec2bn');
  FuncLoadError := not assigned(BN_dec2bn);
  if FuncLoadError then
  begin
    BN_dec2bn :=  @ERROR_BN_dec2bn;
  end;

  BN_asc2bn := LoadLibCryptoFunction('BN_asc2bn');
  FuncLoadError := not assigned(BN_asc2bn);
  if FuncLoadError then
  begin
    BN_asc2bn :=  @ERROR_BN_asc2bn;
  end;

  BN_gcd := LoadLibCryptoFunction('BN_gcd');
  FuncLoadError := not assigned(BN_gcd);
  if FuncLoadError then
  begin
    BN_gcd :=  @ERROR_BN_gcd;
  end;

  BN_kronecker := LoadLibCryptoFunction('BN_kronecker');
  FuncLoadError := not assigned(BN_kronecker);
  if FuncLoadError then
  begin
    BN_kronecker :=  @ERROR_BN_kronecker;
  end;

  BN_mod_inverse := LoadLibCryptoFunction('BN_mod_inverse');
  FuncLoadError := not assigned(BN_mod_inverse);
  if FuncLoadError then
  begin
    BN_mod_inverse :=  @ERROR_BN_mod_inverse;
  end;

  BN_mod_sqrt := LoadLibCryptoFunction('BN_mod_sqrt');
  FuncLoadError := not assigned(BN_mod_sqrt);
  if FuncLoadError then
  begin
    BN_mod_sqrt :=  @ERROR_BN_mod_sqrt;
  end;

  BN_consttime_swap := LoadLibCryptoFunction('BN_consttime_swap');
  FuncLoadError := not assigned(BN_consttime_swap);
  if FuncLoadError then
  begin
    BN_consttime_swap :=  @ERROR_BN_consttime_swap;
  end;

  BN_generate_prime_ex := LoadLibCryptoFunction('BN_generate_prime_ex');
  FuncLoadError := not assigned(BN_generate_prime_ex);
  if FuncLoadError then
  begin
    BN_generate_prime_ex :=  @ERROR_BN_generate_prime_ex;
  end;

  BN_is_prime_ex := LoadLibCryptoFunction('BN_is_prime_ex');
  FuncLoadError := not assigned(BN_is_prime_ex);
  if FuncLoadError then
  begin
    BN_is_prime_ex :=  @ERROR_BN_is_prime_ex;
  end;

  BN_is_prime_fasttest_ex := LoadLibCryptoFunction('BN_is_prime_fasttest_ex');
  FuncLoadError := not assigned(BN_is_prime_fasttest_ex);
  if FuncLoadError then
  begin
    BN_is_prime_fasttest_ex :=  @ERROR_BN_is_prime_fasttest_ex;
  end;

  BN_X931_generate_Xpq := LoadLibCryptoFunction('BN_X931_generate_Xpq');
  FuncLoadError := not assigned(BN_X931_generate_Xpq);
  if FuncLoadError then
  begin
    BN_X931_generate_Xpq :=  @ERROR_BN_X931_generate_Xpq;
  end;

  BN_X931_derive_prime_ex := LoadLibCryptoFunction('BN_X931_derive_prime_ex');
  FuncLoadError := not assigned(BN_X931_derive_prime_ex);
  if FuncLoadError then
  begin
    BN_X931_derive_prime_ex :=  @ERROR_BN_X931_derive_prime_ex;
  end;

  BN_X931_generate_prime_ex := LoadLibCryptoFunction('BN_X931_generate_prime_ex');
  FuncLoadError := not assigned(BN_X931_generate_prime_ex);
  if FuncLoadError then
  begin
    BN_X931_generate_prime_ex :=  @ERROR_BN_X931_generate_prime_ex;
  end;

  BN_MONT_CTX_new := LoadLibCryptoFunction('BN_MONT_CTX_new');
  FuncLoadError := not assigned(BN_MONT_CTX_new);
  if FuncLoadError then
  begin
    BN_MONT_CTX_new :=  @ERROR_BN_MONT_CTX_new;
  end;

  BN_mod_mul_montgomery := LoadLibCryptoFunction('BN_mod_mul_montgomery');
  FuncLoadError := not assigned(BN_mod_mul_montgomery);
  if FuncLoadError then
  begin
    BN_mod_mul_montgomery :=  @ERROR_BN_mod_mul_montgomery;
  end;

  BN_to_montgomery := LoadLibCryptoFunction('BN_to_montgomery');
  FuncLoadError := not assigned(BN_to_montgomery);
  if FuncLoadError then
  begin
    BN_to_montgomery :=  @ERROR_BN_to_montgomery;
  end;

  BN_from_montgomery := LoadLibCryptoFunction('BN_from_montgomery');
  FuncLoadError := not assigned(BN_from_montgomery);
  if FuncLoadError then
  begin
    BN_from_montgomery :=  @ERROR_BN_from_montgomery;
  end;

  BN_MONT_CTX_free := LoadLibCryptoFunction('BN_MONT_CTX_free');
  FuncLoadError := not assigned(BN_MONT_CTX_free);
  if FuncLoadError then
  begin
    BN_MONT_CTX_free :=  @ERROR_BN_MONT_CTX_free;
  end;

  BN_MONT_CTX_set := LoadLibCryptoFunction('BN_MONT_CTX_set');
  FuncLoadError := not assigned(BN_MONT_CTX_set);
  if FuncLoadError then
  begin
    BN_MONT_CTX_set :=  @ERROR_BN_MONT_CTX_set;
  end;

  BN_MONT_CTX_copy := LoadLibCryptoFunction('BN_MONT_CTX_copy');
  FuncLoadError := not assigned(BN_MONT_CTX_copy);
  if FuncLoadError then
  begin
    BN_MONT_CTX_copy :=  @ERROR_BN_MONT_CTX_copy;
  end;

  BN_BLINDING_new := LoadLibCryptoFunction('BN_BLINDING_new');
  FuncLoadError := not assigned(BN_BLINDING_new);
  if FuncLoadError then
  begin
    BN_BLINDING_new :=  @ERROR_BN_BLINDING_new;
  end;

  BN_BLINDING_free := LoadLibCryptoFunction('BN_BLINDING_free');
  FuncLoadError := not assigned(BN_BLINDING_free);
  if FuncLoadError then
  begin
    BN_BLINDING_free :=  @ERROR_BN_BLINDING_free;
  end;

  BN_BLINDING_update := LoadLibCryptoFunction('BN_BLINDING_update');
  FuncLoadError := not assigned(BN_BLINDING_update);
  if FuncLoadError then
  begin
    BN_BLINDING_update :=  @ERROR_BN_BLINDING_update;
  end;

  BN_BLINDING_convert := LoadLibCryptoFunction('BN_BLINDING_convert');
  FuncLoadError := not assigned(BN_BLINDING_convert);
  if FuncLoadError then
  begin
    BN_BLINDING_convert :=  @ERROR_BN_BLINDING_convert;
  end;

  BN_BLINDING_invert := LoadLibCryptoFunction('BN_BLINDING_invert');
  FuncLoadError := not assigned(BN_BLINDING_invert);
  if FuncLoadError then
  begin
    BN_BLINDING_invert :=  @ERROR_BN_BLINDING_invert;
  end;

  BN_BLINDING_convert_ex := LoadLibCryptoFunction('BN_BLINDING_convert_ex');
  FuncLoadError := not assigned(BN_BLINDING_convert_ex);
  if FuncLoadError then
  begin
    BN_BLINDING_convert_ex :=  @ERROR_BN_BLINDING_convert_ex;
  end;

  BN_BLINDING_invert_ex := LoadLibCryptoFunction('BN_BLINDING_invert_ex');
  FuncLoadError := not assigned(BN_BLINDING_invert_ex);
  if FuncLoadError then
  begin
    BN_BLINDING_invert_ex :=  @ERROR_BN_BLINDING_invert_ex;
  end;

  BN_BLINDING_is_current_thread := LoadLibCryptoFunction('BN_BLINDING_is_current_thread');
  FuncLoadError := not assigned(BN_BLINDING_is_current_thread);
  if FuncLoadError then
  begin
    BN_BLINDING_is_current_thread :=  @ERROR_BN_BLINDING_is_current_thread;
  end;

  BN_BLINDING_set_current_thread := LoadLibCryptoFunction('BN_BLINDING_set_current_thread');
  FuncLoadError := not assigned(BN_BLINDING_set_current_thread);
  if FuncLoadError then
  begin
    BN_BLINDING_set_current_thread :=  @ERROR_BN_BLINDING_set_current_thread;
  end;

  BN_BLINDING_lock := LoadLibCryptoFunction('BN_BLINDING_lock');
  FuncLoadError := not assigned(BN_BLINDING_lock);
  if FuncLoadError then
  begin
    BN_BLINDING_lock :=  @ERROR_BN_BLINDING_lock;
  end;

  BN_BLINDING_unlock := LoadLibCryptoFunction('BN_BLINDING_unlock');
  FuncLoadError := not assigned(BN_BLINDING_unlock);
  if FuncLoadError then
  begin
    BN_BLINDING_unlock :=  @ERROR_BN_BLINDING_unlock;
  end;

  BN_BLINDING_get_flags := LoadLibCryptoFunction('BN_BLINDING_get_flags');
  FuncLoadError := not assigned(BN_BLINDING_get_flags);
  if FuncLoadError then
  begin
    BN_BLINDING_get_flags :=  @ERROR_BN_BLINDING_get_flags;
  end;

  BN_BLINDING_set_flags := LoadLibCryptoFunction('BN_BLINDING_set_flags');
  FuncLoadError := not assigned(BN_BLINDING_set_flags);
  if FuncLoadError then
  begin
    BN_BLINDING_set_flags :=  @ERROR_BN_BLINDING_set_flags;
  end;

  BN_RECP_CTX_free := LoadLibCryptoFunction('BN_RECP_CTX_free');
  FuncLoadError := not assigned(BN_RECP_CTX_free);
  if FuncLoadError then
  begin
    BN_RECP_CTX_free :=  @ERROR_BN_RECP_CTX_free;
  end;

  BN_RECP_CTX_set := LoadLibCryptoFunction('BN_RECP_CTX_set');
  FuncLoadError := not assigned(BN_RECP_CTX_set);
  if FuncLoadError then
  begin
    BN_RECP_CTX_set :=  @ERROR_BN_RECP_CTX_set;
  end;

  BN_mod_mul_reciprocal := LoadLibCryptoFunction('BN_mod_mul_reciprocal');
  FuncLoadError := not assigned(BN_mod_mul_reciprocal);
  if FuncLoadError then
  begin
    BN_mod_mul_reciprocal :=  @ERROR_BN_mod_mul_reciprocal;
  end;

  BN_mod_exp_recp := LoadLibCryptoFunction('BN_mod_exp_recp');
  FuncLoadError := not assigned(BN_mod_exp_recp);
  if FuncLoadError then
  begin
    BN_mod_exp_recp :=  @ERROR_BN_mod_exp_recp;
  end;

  BN_div_recp := LoadLibCryptoFunction('BN_div_recp');
  FuncLoadError := not assigned(BN_div_recp);
  if FuncLoadError then
  begin
    BN_div_recp :=  @ERROR_BN_div_recp;
  end;

  BN_GF2m_add := LoadLibCryptoFunction('BN_GF2m_add');
  FuncLoadError := not assigned(BN_GF2m_add);
  if FuncLoadError then
  begin
    BN_GF2m_add :=  @ERROR_BN_GF2m_add;
  end;

  BN_GF2m_mod := LoadLibCryptoFunction('BN_GF2m_mod');
  FuncLoadError := not assigned(BN_GF2m_mod);
  if FuncLoadError then
  begin
    BN_GF2m_mod :=  @ERROR_BN_GF2m_mod;
  end;

  BN_GF2m_mod_mul := LoadLibCryptoFunction('BN_GF2m_mod_mul');
  FuncLoadError := not assigned(BN_GF2m_mod_mul);
  if FuncLoadError then
  begin
    BN_GF2m_mod_mul :=  @ERROR_BN_GF2m_mod_mul;
  end;

  BN_GF2m_mod_sqr := LoadLibCryptoFunction('BN_GF2m_mod_sqr');
  FuncLoadError := not assigned(BN_GF2m_mod_sqr);
  if FuncLoadError then
  begin
    BN_GF2m_mod_sqr :=  @ERROR_BN_GF2m_mod_sqr;
  end;

  BN_GF2m_mod_inv := LoadLibCryptoFunction('BN_GF2m_mod_inv');
  FuncLoadError := not assigned(BN_GF2m_mod_inv);
  if FuncLoadError then
  begin
    BN_GF2m_mod_inv :=  @ERROR_BN_GF2m_mod_inv;
  end;

  BN_GF2m_mod_div := LoadLibCryptoFunction('BN_GF2m_mod_div');
  FuncLoadError := not assigned(BN_GF2m_mod_div);
  if FuncLoadError then
  begin
    BN_GF2m_mod_div :=  @ERROR_BN_GF2m_mod_div;
  end;

  BN_GF2m_mod_exp := LoadLibCryptoFunction('BN_GF2m_mod_exp');
  FuncLoadError := not assigned(BN_GF2m_mod_exp);
  if FuncLoadError then
  begin
    BN_GF2m_mod_exp :=  @ERROR_BN_GF2m_mod_exp;
  end;

  BN_GF2m_mod_sqrt := LoadLibCryptoFunction('BN_GF2m_mod_sqrt');
  FuncLoadError := not assigned(BN_GF2m_mod_sqrt);
  if FuncLoadError then
  begin
    BN_GF2m_mod_sqrt :=  @ERROR_BN_GF2m_mod_sqrt;
  end;

  BN_GF2m_mod_solve_quad := LoadLibCryptoFunction('BN_GF2m_mod_solve_quad');
  FuncLoadError := not assigned(BN_GF2m_mod_solve_quad);
  if FuncLoadError then
  begin
    BN_GF2m_mod_solve_quad :=  @ERROR_BN_GF2m_mod_solve_quad;
  end;

  BN_nist_mod_192 := LoadLibCryptoFunction('BN_nist_mod_192');
  FuncLoadError := not assigned(BN_nist_mod_192);
  if FuncLoadError then
  begin
    BN_nist_mod_192 :=  @ERROR_BN_nist_mod_192;
  end;

  BN_nist_mod_224 := LoadLibCryptoFunction('BN_nist_mod_224');
  FuncLoadError := not assigned(BN_nist_mod_224);
  if FuncLoadError then
  begin
    BN_nist_mod_224 :=  @ERROR_BN_nist_mod_224;
  end;

  BN_nist_mod_256 := LoadLibCryptoFunction('BN_nist_mod_256');
  FuncLoadError := not assigned(BN_nist_mod_256);
  if FuncLoadError then
  begin
    BN_nist_mod_256 :=  @ERROR_BN_nist_mod_256;
  end;

  BN_nist_mod_384 := LoadLibCryptoFunction('BN_nist_mod_384');
  FuncLoadError := not assigned(BN_nist_mod_384);
  if FuncLoadError then
  begin
    BN_nist_mod_384 :=  @ERROR_BN_nist_mod_384;
  end;

  BN_nist_mod_521 := LoadLibCryptoFunction('BN_nist_mod_521');
  FuncLoadError := not assigned(BN_nist_mod_521);
  if FuncLoadError then
  begin
    BN_nist_mod_521 :=  @ERROR_BN_nist_mod_521;
  end;

  BN_get0_nist_prime_192 := LoadLibCryptoFunction('BN_get0_nist_prime_192');
  FuncLoadError := not assigned(BN_get0_nist_prime_192);
  if FuncLoadError then
  begin
    BN_get0_nist_prime_192 :=  @ERROR_BN_get0_nist_prime_192;
  end;

  BN_get0_nist_prime_224 := LoadLibCryptoFunction('BN_get0_nist_prime_224');
  FuncLoadError := not assigned(BN_get0_nist_prime_224);
  if FuncLoadError then
  begin
    BN_get0_nist_prime_224 :=  @ERROR_BN_get0_nist_prime_224;
  end;

  BN_get0_nist_prime_256 := LoadLibCryptoFunction('BN_get0_nist_prime_256');
  FuncLoadError := not assigned(BN_get0_nist_prime_256);
  if FuncLoadError then
  begin
    BN_get0_nist_prime_256 :=  @ERROR_BN_get0_nist_prime_256;
  end;

  BN_get0_nist_prime_384 := LoadLibCryptoFunction('BN_get0_nist_prime_384');
  FuncLoadError := not assigned(BN_get0_nist_prime_384);
  if FuncLoadError then
  begin
    BN_get0_nist_prime_384 :=  @ERROR_BN_get0_nist_prime_384;
  end;

  BN_get0_nist_prime_521 := LoadLibCryptoFunction('BN_get0_nist_prime_521');
  FuncLoadError := not assigned(BN_get0_nist_prime_521);
  if FuncLoadError then
  begin
    BN_get0_nist_prime_521 :=  @ERROR_BN_get0_nist_prime_521;
  end;

  BN_generate_dsa_nonce := LoadLibCryptoFunction('BN_generate_dsa_nonce');
  FuncLoadError := not assigned(BN_generate_dsa_nonce);
  if FuncLoadError then
  begin
    BN_generate_dsa_nonce :=  @ERROR_BN_generate_dsa_nonce;
  end;

  BN_get_rfc2409_prime_768 := LoadLibCryptoFunction('BN_get_rfc2409_prime_768');
  FuncLoadError := not assigned(BN_get_rfc2409_prime_768);
  if FuncLoadError then
  begin
    BN_get_rfc2409_prime_768 :=  @ERROR_BN_get_rfc2409_prime_768;
  end;

  BN_get_rfc2409_prime_1024 := LoadLibCryptoFunction('BN_get_rfc2409_prime_1024');
  FuncLoadError := not assigned(BN_get_rfc2409_prime_1024);
  if FuncLoadError then
  begin
    BN_get_rfc2409_prime_1024 :=  @ERROR_BN_get_rfc2409_prime_1024;
  end;

  BN_get_rfc3526_prime_1536 := LoadLibCryptoFunction('BN_get_rfc3526_prime_1536');
  FuncLoadError := not assigned(BN_get_rfc3526_prime_1536);
  if FuncLoadError then
  begin
    BN_get_rfc3526_prime_1536 :=  @ERROR_BN_get_rfc3526_prime_1536;
  end;

  BN_get_rfc3526_prime_2048 := LoadLibCryptoFunction('BN_get_rfc3526_prime_2048');
  FuncLoadError := not assigned(BN_get_rfc3526_prime_2048);
  if FuncLoadError then
  begin
    BN_get_rfc3526_prime_2048 :=  @ERROR_BN_get_rfc3526_prime_2048;
  end;

  BN_get_rfc3526_prime_3072 := LoadLibCryptoFunction('BN_get_rfc3526_prime_3072');
  FuncLoadError := not assigned(BN_get_rfc3526_prime_3072);
  if FuncLoadError then
  begin
    BN_get_rfc3526_prime_3072 :=  @ERROR_BN_get_rfc3526_prime_3072;
  end;

  BN_get_rfc3526_prime_4096 := LoadLibCryptoFunction('BN_get_rfc3526_prime_4096');
  FuncLoadError := not assigned(BN_get_rfc3526_prime_4096);
  if FuncLoadError then
  begin
    BN_get_rfc3526_prime_4096 :=  @ERROR_BN_get_rfc3526_prime_4096;
  end;

  BN_get_rfc3526_prime_6144 := LoadLibCryptoFunction('BN_get_rfc3526_prime_6144');
  FuncLoadError := not assigned(BN_get_rfc3526_prime_6144);
  if FuncLoadError then
  begin
    BN_get_rfc3526_prime_6144 :=  @ERROR_BN_get_rfc3526_prime_6144;
  end;

  BN_get_rfc3526_prime_8192 := LoadLibCryptoFunction('BN_get_rfc3526_prime_8192');
  FuncLoadError := not assigned(BN_get_rfc3526_prime_8192);
  if FuncLoadError then
  begin
    BN_get_rfc3526_prime_8192 :=  @ERROR_BN_get_rfc3526_prime_8192;
  end;

  BN_bntest_rand := LoadLibCryptoFunction('BN_bntest_rand');
  FuncLoadError := not assigned(BN_bntest_rand);
  if FuncLoadError then
  begin
    BN_bntest_rand :=  @ERROR_BN_bntest_rand;
  end;

end;

procedure UnLoad;
begin
  BN_set_flags := nil;
  BN_get_flags := nil;
  BN_with_flags := nil;
  BN_GENCB_call := nil;
  BN_GENCB_new := nil;
  BN_GENCB_free := nil;
  BN_GENCB_set_old := nil;
  BN_GENCB_set := nil;
  BN_GENCB_get_arg := nil;
  BN_abs_is_word := nil;
  BN_is_zero := nil;
  BN_is_one := nil;
  BN_is_word := nil;
  BN_is_odd := nil;
  BN_zero_ex := nil;
  BN_value_one := nil;
  BN_options := nil;
  BN_CTX_new := nil;
  BN_CTX_secure_new := nil;
  BN_CTX_free := nil;
  BN_CTX_start := nil;
  BN_CTX_get := nil;
  BN_CTX_end := nil;
  BN_rand := nil;
  BN_priv_rand := nil;
  BN_rand_range := nil;
  BN_priv_rand_range := nil;
  BN_pseudo_rand := nil;
  BN_pseudo_rand_range := nil;
  BN_num_bits := nil;
  BN_num_bits_word := nil;
  BN_security_bits := nil;
  BN_new := nil;
  BN_secure_new := nil;
  BN_clear_free := nil;
  BN_copy := nil;
  BN_swap := nil;
  BN_bin2bn := nil;
  BN_bn2bin := nil;
  BN_bn2binpad := nil;
  BN_lebin2bn := nil;
  BN_bn2lebinpad := nil;
  BN_mpi2bn := nil;
  BN_bn2mpi := nil;
  BN_sub := nil;
  BN_usub := nil;
  BN_uadd := nil;
  BN_add := nil;
  BN_mul := nil;
  BN_sqr := nil;
  BN_set_negative := nil;
  BN_is_negative := nil;
  BN_div := nil;
  BN_nnmod := nil;
  BN_mod_add := nil;
  BN_mod_add_quick := nil;
  BN_mod_sub := nil;
  BN_mod_sub_quick := nil;
  BN_mod_mul := nil;
  BN_mod_sqr := nil;
  BN_mod_lshift1 := nil;
  BN_mod_lshift1_quick := nil;
  BN_mod_lshift := nil;
  BN_mod_lshift_quick := nil;
  BN_mod_word := nil;
  BN_div_word := nil;
  BN_mul_word := nil;
  BN_add_word := nil;
  BN_sub_word := nil;
  BN_set_word := nil;
  BN_get_word := nil;
  BN_cmp := nil;
  BN_free := nil;
  BN_is_bit_set := nil;
  BN_lshift := nil;
  BN_lshift1 := nil;
  BN_exp := nil;
  BN_mod_exp := nil;
  BN_mod_exp_mont := nil;
  BN_mod_exp_mont_consttime := nil;
  BN_mod_exp_mont_word := nil;
  BN_mod_exp2_mont := nil;
  BN_mod_exp_simple := nil;
  BN_mask_bits := nil;
  BN_print := nil;
  BN_reciprocal := nil;
  BN_rshift := nil;
  BN_rshift1 := nil;
  BN_clear := nil;
  BN_dup := nil;
  BN_ucmp := nil;
  BN_set_bit := nil;
  BN_clear_bit := nil;
  BN_bn2hex := nil;
  BN_bn2dec := nil;
  BN_hex2bn := nil;
  BN_dec2bn := nil;
  BN_asc2bn := nil;
  BN_gcd := nil;
  BN_kronecker := nil;
  BN_mod_inverse := nil;
  BN_mod_sqrt := nil;
  BN_consttime_swap := nil;
  BN_generate_prime_ex := nil;
  BN_is_prime_ex := nil;
  BN_is_prime_fasttest_ex := nil;
  BN_X931_generate_Xpq := nil;
  BN_X931_derive_prime_ex := nil;
  BN_X931_generate_prime_ex := nil;
  BN_MONT_CTX_new := nil;
  BN_mod_mul_montgomery := nil;
  BN_to_montgomery := nil;
  BN_from_montgomery := nil;
  BN_MONT_CTX_free := nil;
  BN_MONT_CTX_set := nil;
  BN_MONT_CTX_copy := nil;
  BN_BLINDING_new := nil;
  BN_BLINDING_free := nil;
  BN_BLINDING_update := nil;
  BN_BLINDING_convert := nil;
  BN_BLINDING_invert := nil;
  BN_BLINDING_convert_ex := nil;
  BN_BLINDING_invert_ex := nil;
  BN_BLINDING_is_current_thread := nil;
  BN_BLINDING_set_current_thread := nil;
  BN_BLINDING_lock := nil;
  BN_BLINDING_unlock := nil;
  BN_BLINDING_get_flags := nil;
  BN_BLINDING_set_flags := nil;
  BN_RECP_CTX_free := nil;
  BN_RECP_CTX_set := nil;
  BN_mod_mul_reciprocal := nil;
  BN_mod_exp_recp := nil;
  BN_div_recp := nil;
  BN_GF2m_add := nil;
  BN_GF2m_mod := nil;
  BN_GF2m_mod_mul := nil;
  BN_GF2m_mod_sqr := nil;
  BN_GF2m_mod_inv := nil;
  BN_GF2m_mod_div := nil;
  BN_GF2m_mod_exp := nil;
  BN_GF2m_mod_sqrt := nil;
  BN_GF2m_mod_solve_quad := nil;
  BN_nist_mod_192 := nil;
  BN_nist_mod_224 := nil;
  BN_nist_mod_256 := nil;
  BN_nist_mod_384 := nil;
  BN_nist_mod_521 := nil;
  BN_get0_nist_prime_192 := nil;
  BN_get0_nist_prime_224 := nil;
  BN_get0_nist_prime_256 := nil;
  BN_get0_nist_prime_384 := nil;
  BN_get0_nist_prime_521 := nil;
  BN_generate_dsa_nonce := nil;
  BN_get_rfc2409_prime_768 := nil;
  BN_get_rfc2409_prime_1024 := nil;
  BN_get_rfc3526_prime_1536 := nil;
  BN_get_rfc3526_prime_2048 := nil;
  BN_get_rfc3526_prime_3072 := nil;
  BN_get_rfc3526_prime_4096 := nil;
  BN_get_rfc3526_prime_6144 := nil;
  BN_get_rfc3526_prime_8192 := nil;
  BN_bntest_rand := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
