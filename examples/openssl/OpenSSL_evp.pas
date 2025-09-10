(* This unit was generated from the source file evp.h2pas 
It should not be modified directly. All changes should be made to evp.h2pas
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


unit OpenSSL_evp;


interface

// Headers for OpenSSL 1.1.1
// evp.h


uses
  OpenSSLAPI,
  OpenSSL_bio,
  OpenSSL_obj_mac,
  OpenSSL_ossl_typ;

const
  EVP_MAX_MD_SIZE = 64; // longest known is SHA512
  EVP_MAX_KEY_LENGTH = 64;
  EVP_MAX_IV_LENGTH = 16;
  EVP_MAX_BLOCK_LENGTH = 32;
  PKCS5_SALT_LEN = 8;
  // Default PKCS#5 iteration count
  PKCS5_DEFAULT_ITER = 2048;
  EVP_PK_RSA = $0001;
  EVP_PK_DSA = $0002;
  EVP_PK_DH  = $0004;
  EVP_PK_EC = $0008;
  EVP_PKT_SIGN = $0010;
  EVP_PKT_ENC = $0020;
  EVP_PKT_EXCH = $0040;
  EVP_PKS_RSA = $0100;
  EVP_PKS_DSA = $0200;
  EVP_PKS_EC = $0400;

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

  EVP_PKEY_MO_SIGN = $0001;
  EVP_PKEY_MO_VERIFY = $0002;
  EVP_PKEY_MO_ENCRYPT = $0004;
  EVP_PKEY_MO_DECRYPT = $0008;

// digest can only handle a single block ///
  EVP_MD_FLAG_ONESHOT = $0001;

// digest is extensible-output function; XOF ///

  EVP_MD_FLAG_XOF = $0002;

// DigestAlgorithmIdentifier flags... ///

  EVP_MD_FLAG_DIGALGID_MASK = $0018;

// NULL or absent parameter accepted. Use NULL ///

  EVP_MD_FLAG_DIGALGID_NULL = $0000;

// NULL or absent parameter accepted. Use NULL for PKCS#1 otherwise absent ///

  EVP_MD_FLAG_DIGALGID_ABSENT = $0008;

// Custom handling via ctrl ///

  EVP_MD_FLAG_DIGALGID_CUSTOM = $0018;

// Note if suitable for use in FIPS mode ///

  EVP_MD_FLAG_FIPS = $0400;

// Digest ctrls ///

  EVP_MD_CTRL_DIGALGID = $1;
  EVP_MD_CTRL_MICALG = $2;
  EVP_MD_CTRL_XOF_LEN = $3;

// Minimum Algorithm specific ctrl value ///

  EVP_MD_CTRL_ALG_CTRL = $1000;
 // not EVP_MD ///

// values for EVP_MD_CTX flags ///
  EVP_MD_CTX_FLAG_ONESHOT = $0001;
  EVP_MD_CTX_FLAG_CLEANED = $0002;
  EVP_MD_CTX_FLAG_REUSE = $0004;
//
 // FIPS and pad options are ignored in 1.0.0; definitions are here so we
 // don't accidentally reuse the values for other purposes.
 ///

  EVP_MD_CTX_FLAG_NON_FIPS_ALLOW = $0008;

//
 // The following PAD options are also currently ignored in 1.0.0; digest
 // parameters are handled through EVP_DigestSign//() and EVP_DigestVerify//()
 // instead.
 ///
  EVP_MD_CTX_FLAG_PAD_MASK = $F0;
  EVP_MD_CTX_FLAG_PAD_PKCS1 = $00;
  EVP_MD_CTX_FLAG_PAD_X931 = $10;
  EVP_MD_CTX_FLAG_PAD_PSS = $20;

  EVP_MD_CTX_FLAG_NO_INIT = $0100;
//
 // Some functions such as EVP_DigestSign only finalise copies of internal
 // contexts so additional data can be included after the finalisation call.
 // This is inefficient if this functionality is not required: it is disabled
 // if the following flag is set.
 ///
  EVP_MD_CTX_FLAG_FINALISE = $0200;


// NOTE: $0400 is reserved for internal usage ///
// Values for cipher flags ///

// Modes for ciphers ///

  EVP_CIPH_STREAM_CIPHER = $0;
  EVP_CIPH_ECB_MODE = $1;
  EVP_CIPHC_MODE = $2;
  EVP_CIPH_CFB_MODE = $3;
  EVP_CIPH_OFB_MODE = $4;
  EVP_CIPH_CTR_MODE = $5;
  EVP_CIPH_GCM_MODE = $6;
  EVP_CIPH_CCM_MODE = $7;
  EVP_CIPH_XTS_MODE = $10001;
  EVP_CIPH_WRAP_MODE = $10002;
  EVP_CIPH_OCB_MODE = $10003;
  EVP_CIPH_MODE = $F0007;
// Set if variable length cipher ///
  EVP_CIPH_VARIABLE_LENGTH = $8;
// Set if the iv handling should be done by the cipher itself ///
  EVP_CIPH_CUSTOM_IV = $10;
// Set if the cipher's init() function should be called if key is NULL ///
  EVP_CIPH_ALWAYS_CALL_INIT = $20;
// Call ctrl() to init cipher parameters ///
  EVP_CIPH_CTRL_INIT = $40;
// Don't use standard key length function ///
  EVP_CIPH_CUSTOM_KEY_LENGTH = $80;
// Don't use standard block padding ///
  EVP_CIPH_NO_PADDING = $100;
// cipher handles random key generation ///
  EVP_CIPH_RAND_KEY = $200;
// cipher has its own additional copying logic ///
  EVP_CIPH_CUSTOM_COPY = $400;
// Don't use standard iv length function ///
  EVP_CIPH_CUSTOM_IV_LENGTH = $800;
// Allow use default ASN1 get/set iv ///
  EVP_CIPH_FLAG_DEFAULT_ASN1 = $1000;
// Buffer length in bits not bytes: CFB1 mode only ///
  EVP_CIPH_FLAG_LENGTH_BITS = $2000;
// Note if suitable for use in FIPS mode ///
  EVP_CIPH_FLAG_FIPS = $4000;
// Allow non FIPS cipher in FIPS mode ///
  EVP_CIPH_FLAG_NON_FIPS_ALLOW = $8000;
//
 // Cipher handles any and all padding logic as well as finalisation.
 ///
  EVP_CIPH_FLAG_CUSTOM_CIPHER = $100000;
  EVP_CIPH_FLAG_AEAD_CIPHER = $200000;
  EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK = $400000;
// Cipher can handle pipeline operations ///
  EVP_CIPH_FLAG_PIPELINE = $800000;

//
 // Cipher context flag to indicate we can handle wrap mode: if allowed in
 // older applications it could overflow buffers.
 ///

  EVP_CIPHER_CTX_FLAG_WRAP_ALLOW = $1;

// ctrl() values ///

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
//
 // AEAD cipher deduces payload length and returns number of bytes required to
 // store MAC and eventual padding. Subsequent call to EVP_Cipher even
 // appends/verifies MAC.
 ///
  EVP_CTRL_AEAD_TLS1_AAD = $16;
// Used by composite AEAD ciphers; no-op in GCM; CCM... ///
  EVP_CTRL_AEAD_SET_MAC_KEY = $17;
// Set the GCM invocation field; decrypt only ///
  EVP_CTRL_GCM_SET_IV_INV = $18;

  EVP_CTRL_TLS1_1_MULTIBLOCK_AAD = $19;
  EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT = $1a;
  EVP_CTRL_TLS1_1_MULTIBLOCK_DECRYPT = $1b;
  EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE = $1c;

  EVP_CTRL_SSL3_MASTER_SECRET = $1d;

// EVP_CTRL_SET_SBOX takes the PAnsiChar// specifying S-boxes///
  EVP_CTRL_SET_SBOX = $1e;
//
// EVP_CTRL_SBOX_USED takes a 'TOpenSSL_C_SIZET' and 'PAnsiChar//'; pointing at a
// pre-allocated buffer with specified size
///
  EVP_CTRL_SBOX_USED = $1f;
// EVP_CTRL_KEY_MESH takes 'TOpenSSL_C_SIZET' number of bytes to mesh the key after;
// 0 switches meshing off
///
  EVP_CTRL_KEY_MESH = $20;
// EVP_CTRL_BLOCK_PADDING_MODE takes the padding mode///
  EVP_CTRL_BLOCK_PADDING_MODE = $21;

// Set the output buffers to use for a pipelined operation///
  EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS = $22;
// Set the input buffers to use for a pipelined operation///
  EVP_CTRL_SET_PIPELINE_INPUT_BUFS = $23;
// Set the input buffer lengths to use for a pipelined operation///
  EVP_CTRL_SET_PIPELINE_INPUT_LENS = $24;

  EVP_CTRL_GET_IVLEN = $25;

// Padding modes///
  EVP_PADDING_PKCS7 = 1;
  EVP_PADDING_ISO7816_4 = 2;
  EVP_PADDING_ANSI923 = 3;
  EVP_PADDING_ISO10126 = 4;
  EVP_PADDING_ZERO = 5;

// RFC 5246 defines additional data to be 13 bytes in length///
  EVP_AEAD_TLS1_AAD_LEN = 13;

// GCM TLS constants///
// Length of fixed part of IV derived from PRF///
  EVP_GCM_TLS_FIXED_IV_LEN = 4;
// Length of explicit part of IV part of TLS records///
  EVP_GCM_TLS_EXPLICIT_IV_LEN = 8;
// Length of tag for TLS
  EVP_GCM_TLS_TAG_LEN = 16;

/// CCM TLS constants ///
/// Length of fixed part of IV derived from PRF ///
  EVP_CCM_TLS_FIXED_IV_LEN = 4;
/// Length of explicit part of IV part of TLS records ///
  EVP_CCM_TLS_EXPLICIT_IV_LEN = 8;
/// Total length of CCM IV length for TLS ///
  EVP_CCM_TLS_IV_LEN = 12;
/// Length of tag for TLS ///
  EVP_CCM_TLS_TAG_LEN = 16;
/// Length of CCM8 tag for TLS ///
  EVP_CCM8_TLS_TAG_LEN = 8;

/// Length of tag for TLS ///
  EVP_CHACHAPOLY_TLS_TAG_LEN = 16;

(* Can appear as the outermost AlgorithmIdentifier *)
  EVP_PBE_TYPE_OUTER = $0;
(* Is an PRF type OID *)
  EVP_PBE_TYPE_PRF = $1;
(* Is a PKCS#5 v2.0 KDF *)
  EVP_PBE_TYPE_KDF = $2;

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

  EVP_PKEY_OP_UNDEFINED = 0;
  EVP_PKEY_OP_PARAMGEN = (1 shl 1);
  EVP_PKEY_OP_KEYGEN = (1 shl 2);
  EVP_PKEY_OP_SIGN = (1 shl 3);
  EVP_PKEY_OP_VERIFY = (1 shl 4);
  EVP_PKEY_OP_VERIFYRECOVER = (1 shl 5);
  EVP_PKEY_OP_SIGNCTX = (1 shl 6);
  EVP_PKEY_OP_VERIFYCTX = (1 shl 7);
  EVP_PKEY_OP_ENCRYPT = (1 shl 8);
  EVP_PKEY_OP_DECRYPT = (1 shl 9);
  EVP_PKEY_OP_DERIVE = (1 shl 10);

  EVP_PKEY_OP_TYPE_SIG = EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY
    or EVP_PKEY_OP_VERIFYRECOVER or EVP_PKEY_OP_SIGNCTX or EVP_PKEY_OP_VERIFYCTX;

  EVP_PKEY_OP_TYPE_CRYPT = EVP_PKEY_OP_ENCRYPT or EVP_PKEY_OP_DECRYPT;

  EVP_PKEY_OP_TYPE_NOGEN = EVP_PKEY_OP_TYPE_SIG or EVP_PKEY_OP_TYPE_CRYPT or EVP_PKEY_OP_DERIVE;

  EVP_PKEY_OP_TYPE_GEN = EVP_PKEY_OP_PARAMGEN or EVP_PKEY_OP_KEYGEN;

  EVP_PKEY_CTRL_MD = 1;
  EVP_PKEY_CTRL_PEER_KEY = 2;

  EVP_PKEY_CTRL_PKCS7_ENCRYPT = 3;
  EVP_PKEY_CTRL_PKCS7_DECRYPT = 4;

  EVP_PKEY_CTRL_PKCS7_SIGN = 5;

  EVP_PKEY_CTRL_SET_MAC_KEY = 6;

  EVP_PKEY_CTRL_DIGESTINIT = 7;

(* Used by GOST key encryption in TLS *)
  EVP_PKEY_CTRL_SET_IV = 8;

  EVP_PKEY_CTRL_CMS_ENCRYPT = 9;
  EVP_PKEY_CTRL_CMS_DECRYPT = 10;
  EVP_PKEY_CTRL_CMS_SIGN = 11;

  EVP_PKEY_CTRL_CIPHER = 12;

  EVP_PKEY_CTRL_GET_MD = 13;

  EVP_PKEY_CTRL_SET_DIGEST_SIZE = 14;

  EVP_PKEY_ALG_CTRL = $1000;

  EVP_PKEY_FLAG_AUTOARGLEN = 2;
  //
 // Method handles all operations: don't assume any digest related defaults.
 //
  EVP_PKEY_FLAG_SIGCTX_CUSTOM = 4;

type
  EVP_MD_meth_init = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_update = function(ctx: PEVP_MD_CTX; const data: Pointer;
    count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_final = function(ctx: PEVP_MD_CTX; const md: PByte): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_copy = function(to_: PEVP_MD_CTX; const from: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_cleanup = function(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  EVP_MD_meth_ctrl = function(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT;
    p2: Pointer): TOpenSSL_C_INT; cdecl;

  EVP_CIPHER_meth_init = function(ctx: PEVP_CIPHER_CTX; const key: PByte;
    const iv: PByte; enc: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_do_cipher = function(ctx: PEVP_CIPHER_CTX; out_: PByte;
    const in_: PByte; inl: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_cleanup = function(v1: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_set_asn1_params = function(v1: PEVP_CIPHER_CTX;
    v2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_get_asn1_params = function(v1: PEVP_CIPHER_CTX;
    v2: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
  EVP_CIPHER_meth_ctrl = function(v1: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT;
    arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl;

  EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM = record
    out_: PByte;
    inp: PByte;
    len: TOpenSSL_C_SIZET;
    interleave: TOpenSSL_C_UINT;
  end;

  evp_cipher_info_st = record
    cipher: PEVP_CIPHER;
    iv: array[0 .. EVP_MAX_IV_LENGTH - 1] of PByte;
  end;
  EVP_CIPHER_INFO = evp_cipher_info_st;

  EVP_MD_CTX_update = function(ctx: PEVP_MD_CTX; const data: Pointer; count: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

  fn = procedure(const ciph: PEVP_CIPHER; const from: PAnsiChar; const to_: PAnsiChar; x: Pointer); cdecl;

  pub_decode = function(pk: PEVP_PKEY; pub: PX509_PUBKEY): TOpenSSL_C_INT; cdecl;
  pub_encode = function(pub: PX509_PUBKEY; const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pub_cmd = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pub_print = function(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
  pkey_size = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pkey_bits = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

  priv_decode = function(pk: PEVP_PKEY; const p8inf: PKCS8_PRIV_KEY_INFO): TOpenSSL_C_INT; cdecl;
  priv_encode = function(p8: PPKCS8_PRIV_KEY_INFO; const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  priv_print = function(out_: PBIO; const pkea: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;

  param_decode = function(pkey: PEVP_PKEY; const pder: PPByte; derlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  param_encode = function(const pkey: PEVP_PKEY; pder: PPByte): TOpenSSL_C_INT; cdecl;
  param_missing = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  param_copy = function(to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  param_cmp = function(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  param_print = function(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;

  pkey_free = procedure(pkey: PEVP_PKEY); cdecl;
  pkey_ctrl = function(pkey: PEVP_PKEY; op: TOpenSSL_C_INT; arg1: TOpenSSL_C_LONG; arg2: Pointer): TOpenSSL_C_INT; cdecl;
  item_verify = function(ctx: PEVP_MD_CTX; const it: PASN1_ITEM; asn: Pointer;
    a: PX509_ALGOR; sig: PASN1_BIT_STRING; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  item_sign = function(ctx: PEVP_MD_CTX; const it: PASN1_ITEM; asn: Pointer;
    alg1: PX509_ALGOR; alg2: PX509_ALGOR; sig: PASN1_BIT_STRING): TOpenSSL_C_INT; cdecl;
  siginf_set = function(siginf: PX509_SIG_INFO; const alg: PX509_ALGOR; const sig: PASN1_STRING): TOpenSSL_C_INT; cdecl;
  pkey_check = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pkey_pub_check = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  pkey_param_check = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  set_priv_key = function(pk: PEVP_PKEY; const priv: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  set_pub_key = function(pk: PEVP_PKEY; const pub: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  get_priv_key = function(const pk: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  get_pub_key = function(const pk: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  pkey_security_bits = function(const pk: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

  EVP_PKEY_gen_cb = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
//  PEVP_PKEY_gen_cb = ^EVP_PKEY_gen_cb;

  EVP_PKEY_meth_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_init = ^EVP_PKEY_meth_init;
  EVP_PKEY_meth_copy_cb = function(dst: PEVP_PKEY_CTX; src: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_copy = ^EVP_PKEY_meth_copy_cb;
  EVP_PKEY_meth_cleanup = procedure(ctx: PEVP_PKEY_CTX); cdecl;
  PEVP_PKEY_meth_cleanup = ^EVP_PKEY_meth_cleanup;
  EVP_PKEY_meth_paramgen_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_paramgen_init = ^EVP_PKEY_meth_paramgen_init;
  EVP_PKEY_meth_paramgen = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_paramgen = ^EVP_PKEY_meth_paramgen;
  EVP_PKEY_meth_keygen_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_keygen_init = ^EVP_PKEY_meth_keygen_init;
  EVP_PKEY_meth_keygen = function(ctx: PEVP_PKEY_CTX; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_keygen = ^EVP_PKEY_meth_keygen;
  EVP_PKEY_meth_sign_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_sign_init = ^EVP_PKEY_meth_sign_init;
  EVP_PKEY_meth_sign = function(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: TOpenSSL_C_SIZET;
    const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_sign = ^EVP_PKEY_meth_sign;
  EVP_PKEY_meth_verify_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify_init = ^EVP_PKEY_meth_verify_init;
  EVP_PKEY_meth_verify = function(ctx: PEVP_PKEY_CTX; const sig: PByte;
    siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify = ^EVP_PKEY_meth_verify;
  EVP_PKEY_meth_verify_recover_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify_recover_init = ^EVP_PKEY_meth_verify_recover_init;
  EVP_PKEY_meth_verify_recover = function(ctx: PEVP_PKEY_CTX; sig: PByte;
    siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verify_recover = ^EVP_PKEY_meth_verify_recover;
  EVP_PKEY_meth_signctx_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_signctx_init = ^EVP_PKEY_meth_signctx_init;
  EVP_PKEY_meth_signctx = function(ctx: PEVP_PKEY_CTX; sig: Pbyte;
    siglen: TOpenSSL_C_SIZET; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_signctx = ^EVP_PKEY_meth_signctx;
  EVP_PKEY_meth_verifyctx_init = function(ctx: PEVP_PKEY_CTX; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verifyctx_init = ^EVP_PKEY_meth_verifyctx_init;
  EVP_PKEY_meth_verifyctx = function(ctx: PEVP_PKEY_CTX; const sig: PByte;
    siglen: TOpenSSL_C_INT; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_verifyctx = ^EVP_PKEY_meth_verifyctx;
  EVP_PKEY_meth_encrypt_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_encrypt_init = ^EVP_PKEY_meth_encrypt_init;
  EVP_PKEY_meth_encrypt = function(ctx: PEVP_PKEY_CTX; out_: PByte;
    outlen: TOpenSSL_C_SIZET; const in_: PByte): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_encrypt = ^ EVP_PKEY_meth_encrypt;
  EVP_PKEY_meth_decrypt_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_decrypt_init = ^EVP_PKEY_meth_decrypt_init;
  EVP_PKEY_meth_decrypt = function(ctx: PEVP_PKEY_CTX; out_: PByte;
    outlen: TOpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_decrypt = ^EVP_PKEY_meth_decrypt;
  EVP_PKEY_meth_derive_init = function(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_derive_init = ^EVP_PKEY_meth_derive_init;
  EVP_PKEY_meth_derive = function(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_derive = ^EVP_PKEY_meth_derive;
  EVP_PKEY_meth_ctrl = function(ctx: PEVP_PKEY_CTX; type_: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_ctrl = ^EVP_PKEY_meth_ctrl;
  EVP_PKEY_meth_ctrl_str = function(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_ctrl_str = ^EVP_PKEY_meth_ctrl_str;
  EVP_PKEY_meth_digestsign = function(ctx: PEVP_PKEY_CTX; sig: PByte;
    siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_digestsign = ^EVP_PKEY_meth_digestsign;
  EVP_PKEY_meth_digestverify = function(ctx: PEVP_MD_CTX; const sig: PByte;
    siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_digestverify = ^EVP_PKEY_meth_digestverify;
  EVP_PKEY_meth_check = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_check = ^EVP_PKEY_meth_check;
  EVP_PKEY_meth_public_check = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_public_check = ^EVP_PKEY_meth_public_check;
  EVP_PKEY_meth_param_check = function(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_param_check = ^EVP_PKEY_meth_param_check;
  EVP_PKEY_meth_digest_custom = function(pkey: PEVP_PKEY; mctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
  PEVP_PKEY_meth_digest_custom = ^EVP_PKEY_meth_digest_custom;

  // Password based encryption function
  EVP_PBE_KEYGEN = function(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar;
    passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER;
    const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  PEVP_PBE_KEYGEN = ^EVP_PBE_KEYGEN;
  PPEVP_PBE_KEYGEN = ^PEVP_PBE_KEYGEN;


{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM EVP_MD_meth_new}
{$EXTERNALSYM EVP_MD_meth_dup}
{$EXTERNALSYM EVP_MD_meth_free}
{$EXTERNALSYM EVP_MD_meth_set_input_blocksize}
{$EXTERNALSYM EVP_MD_meth_set_result_size}
{$EXTERNALSYM EVP_MD_meth_set_app_datasize}
{$EXTERNALSYM EVP_MD_meth_set_flags}
{$EXTERNALSYM EVP_MD_meth_set_init}
{$EXTERNALSYM EVP_MD_meth_set_update}
{$EXTERNALSYM EVP_MD_meth_set_final}
{$EXTERNALSYM EVP_MD_meth_set_copy}
{$EXTERNALSYM EVP_MD_meth_set_cleanup}
{$EXTERNALSYM EVP_MD_meth_set_ctrl}
{$EXTERNALSYM EVP_MD_meth_get_input_blocksize}
{$EXTERNALSYM EVP_MD_meth_get_result_size}
{$EXTERNALSYM EVP_MD_meth_get_app_datasize}
{$EXTERNALSYM EVP_MD_meth_get_flags}
{$EXTERNALSYM EVP_MD_meth_get_init}
{$EXTERNALSYM EVP_MD_meth_get_update}
{$EXTERNALSYM EVP_MD_meth_get_final}
{$EXTERNALSYM EVP_MD_meth_get_copy}
{$EXTERNALSYM EVP_MD_meth_get_cleanup}
{$EXTERNALSYM EVP_MD_meth_get_ctrl}
{$EXTERNALSYM EVP_CIPHER_meth_new}
{$EXTERNALSYM EVP_CIPHER_meth_dup}
{$EXTERNALSYM EVP_CIPHER_meth_free}
{$EXTERNALSYM EVP_CIPHER_meth_set_iv_length}
{$EXTERNALSYM EVP_CIPHER_meth_set_flags}
{$EXTERNALSYM EVP_CIPHER_meth_set_impl_ctx_size}
{$EXTERNALSYM EVP_CIPHER_meth_set_init}
{$EXTERNALSYM EVP_CIPHER_meth_set_do_cipher}
{$EXTERNALSYM EVP_CIPHER_meth_set_cleanup}
{$EXTERNALSYM EVP_CIPHER_meth_set_set_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_set_get_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_set_ctrl}
{$EXTERNALSYM EVP_CIPHER_meth_get_init}
{$EXTERNALSYM EVP_CIPHER_meth_get_do_cipher}
{$EXTERNALSYM EVP_CIPHER_meth_get_cleanup}
{$EXTERNALSYM EVP_CIPHER_meth_get_set_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_get_get_asn1_params}
{$EXTERNALSYM EVP_CIPHER_meth_get_ctrl}
{$EXTERNALSYM EVP_MD_CTX_md}
{$EXTERNALSYM EVP_MD_CTX_update_fn}
{$EXTERNALSYM EVP_MD_CTX_set_update_fn}
{$EXTERNALSYM EVP_MD_CTX_set_pkey_ctx}
{$EXTERNALSYM EVP_CIPHER_impl_ctx_size}
{$EXTERNALSYM EVP_CIPHER_CTX_cipher}
{$EXTERNALSYM EVP_CIPHER_CTX_iv}
{$EXTERNALSYM EVP_CIPHER_CTX_original_iv}
{$EXTERNALSYM EVP_CIPHER_CTX_iv_noconst}
{$EXTERNALSYM EVP_CIPHER_CTX_buf_noconst}
{$EXTERNALSYM EVP_CIPHER_CTX_set_num}
{$EXTERNALSYM EVP_CIPHER_CTX_copy}
{$EXTERNALSYM EVP_CIPHER_CTX_get_app_data}
{$EXTERNALSYM EVP_CIPHER_CTX_set_app_data}
{$EXTERNALSYM EVP_CIPHER_CTX_get_cipher_data}
{$EXTERNALSYM EVP_CIPHER_CTX_set_cipher_data}
{$EXTERNALSYM EVP_MD_CTX_ctrl}
{$EXTERNALSYM EVP_MD_CTX_new}
{$EXTERNALSYM EVP_MD_CTX_reset}
{$EXTERNALSYM EVP_MD_CTX_free}
{$EXTERNALSYM EVP_MD_CTX_copy_ex}
{$EXTERNALSYM EVP_MD_CTX_set_flags}
{$EXTERNALSYM EVP_MD_CTX_clear_flags}
{$EXTERNALSYM EVP_MD_CTX_test_flags}
{$EXTERNALSYM EVP_DigestInit_ex}
{$EXTERNALSYM EVP_DigestUpdate}
{$EXTERNALSYM EVP_DigestFinal_ex}
{$EXTERNALSYM EVP_Digest}
{$EXTERNALSYM EVP_MD_CTX_copy}
{$EXTERNALSYM EVP_DigestInit}
{$EXTERNALSYM EVP_DigestFinal}
{$EXTERNALSYM EVP_DigestFinalXOF}
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
{$EXTERNALSYM EVP_EncryptUpdate}
{$EXTERNALSYM EVP_EncryptFinal_ex}
{$EXTERNALSYM EVP_EncryptFinal}
{$EXTERNALSYM EVP_DecryptInit}
{$EXTERNALSYM EVP_DecryptInit_ex}
{$EXTERNALSYM EVP_DecryptUpdate}
{$EXTERNALSYM EVP_DecryptFinal}
{$EXTERNALSYM EVP_DecryptFinal_ex}
{$EXTERNALSYM EVP_CipherInit}
{$EXTERNALSYM EVP_CipherInit_ex}
{$EXTERNALSYM EVP_CipherUpdate}
{$EXTERNALSYM EVP_CipherFinal}
{$EXTERNALSYM EVP_CipherFinal_ex}
{$EXTERNALSYM EVP_SignFinal}
{$EXTERNALSYM EVP_DigestSign}
{$EXTERNALSYM EVP_VerifyFinal}
{$EXTERNALSYM EVP_DigestVerify}
{$EXTERNALSYM EVP_DigestSignInit}
{$EXTERNALSYM EVP_DigestSignFinal}
{$EXTERNALSYM EVP_DigestVerifyInit}
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
{$EXTERNALSYM EVP_CIPHER_CTX_new}
{$EXTERNALSYM EVP_CIPHER_CTX_reset}
{$EXTERNALSYM EVP_CIPHER_CTX_free}
{$EXTERNALSYM EVP_CIPHER_CTX_set_key_length}
{$EXTERNALSYM EVP_CIPHER_CTX_set_padding}
{$EXTERNALSYM EVP_CIPHER_CTX_ctrl}
{$EXTERNALSYM EVP_CIPHER_CTX_rand_key}
{$EXTERNALSYM BIO_f_md}
{$EXTERNALSYM BIO_f_base64}
{$EXTERNALSYM BIO_f_cipher}
{$EXTERNALSYM BIO_f_reliable}
{$EXTERNALSYM BIO_set_cipher}
{$EXTERNALSYM EVP_md_null}
{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
{$EXTERNALSYM EVP_md5_sha1}
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
{$EXTERNALSYM EVP_enc_null}
{$EXTERNALSYM EVP_des_ecb}
{$EXTERNALSYM EVP_des_ede}
{$EXTERNALSYM EVP_des_ede3}
{$EXTERNALSYM EVP_des_ede_ecb}
{$EXTERNALSYM EVP_des_ede3_ecb}
{$EXTERNALSYM EVP_des_cfb64}
{$EXTERNALSYM EVP_des_cfb1}
{$EXTERNALSYM EVP_des_cfb8}
{$EXTERNALSYM EVP_des_ede_cfb64}
{$EXTERNALSYM EVP_des_ede3_cfb64}
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
{$EXTERNALSYM EVP_rc4}
{$EXTERNALSYM EVP_rc4_40}
{$EXTERNALSYM EVP_rc2_ecb}
{$EXTERNALSYM EVP_rc2_cbc}
{$EXTERNALSYM EVP_rc2_40_cbc}
{$EXTERNALSYM EVP_rc2_64_cbc}
{$EXTERNALSYM EVP_rc2_cfb64}
{$EXTERNALSYM EVP_rc2_ofb}
{$EXTERNALSYM EVP_bf_ecb}
{$EXTERNALSYM EVP_bf_cbc}
{$EXTERNALSYM EVP_bf_cfb64}
{$EXTERNALSYM EVP_bf_ofb}
{$EXTERNALSYM EVP_cast5_ecb}
{$EXTERNALSYM EVP_cast5_cbc}
{$EXTERNALSYM EVP_cast5_cfb64}
{$EXTERNALSYM EVP_cast5_ofb}
{$EXTERNALSYM EVP_aes_128_ecb}
{$EXTERNALSYM EVP_aes_128_cbc}
{$EXTERNALSYM EVP_aes_128_cfb1}
{$EXTERNALSYM EVP_aes_128_cfb8}
{$EXTERNALSYM EVP_aes_128_cfb128}
{$EXTERNALSYM EVP_aes_128_ofb}
{$EXTERNALSYM EVP_aes_128_ctr}
{$EXTERNALSYM EVP_aes_128_ccm}
{$EXTERNALSYM EVP_aes_128_gcm}
{$EXTERNALSYM EVP_aes_128_xts}
{$EXTERNALSYM EVP_aes_128_wrap}
{$EXTERNALSYM EVP_aes_128_wrap_pad}
{$EXTERNALSYM EVP_aes_128_ocb}
{$EXTERNALSYM EVP_aes_192_ecb}
{$EXTERNALSYM EVP_aes_192_cbc}
{$EXTERNALSYM EVP_aes_192_cfb1}
{$EXTERNALSYM EVP_aes_192_cfb8}
{$EXTERNALSYM EVP_aes_192_cfb128}
{$EXTERNALSYM EVP_aes_192_ofb}
{$EXTERNALSYM EVP_aes_192_ctr}
{$EXTERNALSYM EVP_aes_192_ccm}
{$EXTERNALSYM EVP_aes_192_gcm}
{$EXTERNALSYM EVP_aes_192_wrap}
{$EXTERNALSYM EVP_aes_192_wrap_pad}
{$EXTERNALSYM EVP_aes_192_ocb}
{$EXTERNALSYM EVP_aes_256_ecb}
{$EXTERNALSYM EVP_aes_256_cbc}
{$EXTERNALSYM EVP_aes_256_cfb1}
{$EXTERNALSYM EVP_aes_256_cfb8}
{$EXTERNALSYM EVP_aes_256_cfb128}
{$EXTERNALSYM EVP_aes_256_ofb}
{$EXTERNALSYM EVP_aes_256_ctr}
{$EXTERNALSYM EVP_aes_256_ccm}
{$EXTERNALSYM EVP_aes_256_gcm}
{$EXTERNALSYM EVP_aes_256_xts}
{$EXTERNALSYM EVP_aes_256_wrap}
{$EXTERNALSYM EVP_aes_256_wrap_pad}
{$EXTERNALSYM EVP_aes_256_ocb}
{$EXTERNALSYM EVP_aes_128_cbc_hmac_sha1}
{$EXTERNALSYM EVP_aes_256_cbc_hmac_sha1}
{$EXTERNALSYM EVP_aes_128_cbc_hmac_sha256}
{$EXTERNALSYM EVP_aes_256_cbc_hmac_sha256}
{$EXTERNALSYM EVP_aria_128_ecb}
{$EXTERNALSYM EVP_aria_128_cbc}
{$EXTERNALSYM EVP_aria_128_cfb1}
{$EXTERNALSYM EVP_aria_128_cfb8}
{$EXTERNALSYM EVP_aria_128_cfb128}
{$EXTERNALSYM EVP_aria_128_ctr}
{$EXTERNALSYM EVP_aria_128_ofb}
{$EXTERNALSYM EVP_aria_128_gcm}
{$EXTERNALSYM EVP_aria_128_ccm}
{$EXTERNALSYM EVP_aria_192_ecb}
{$EXTERNALSYM EVP_aria_192_cbc}
{$EXTERNALSYM EVP_aria_192_cfb1}
{$EXTERNALSYM EVP_aria_192_cfb8}
{$EXTERNALSYM EVP_aria_192_cfb128}
{$EXTERNALSYM EVP_aria_192_ctr}
{$EXTERNALSYM EVP_aria_192_ofb}
{$EXTERNALSYM EVP_aria_192_gcm}
{$EXTERNALSYM EVP_aria_192_ccm}
{$EXTERNALSYM EVP_aria_256_ecb}
{$EXTERNALSYM EVP_aria_256_cbc}
{$EXTERNALSYM EVP_aria_256_cfb1}
{$EXTERNALSYM EVP_aria_256_cfb8}
{$EXTERNALSYM EVP_aria_256_cfb128}
{$EXTERNALSYM EVP_aria_256_ctr}
{$EXTERNALSYM EVP_aria_256_ofb}
{$EXTERNALSYM EVP_aria_256_gcm}
{$EXTERNALSYM EVP_aria_256_ccm}
{$EXTERNALSYM EVP_camellia_128_ecb}
{$EXTERNALSYM EVP_camellia_128_cbc}
{$EXTERNALSYM EVP_camellia_128_cfb1}
{$EXTERNALSYM EVP_camellia_128_cfb8}
{$EXTERNALSYM EVP_camellia_128_cfb128}
{$EXTERNALSYM EVP_camellia_128_ofb}
{$EXTERNALSYM EVP_camellia_128_ctr}
{$EXTERNALSYM EVP_camellia_192_ecb}
{$EXTERNALSYM EVP_camellia_192_cbc}
{$EXTERNALSYM EVP_camellia_192_cfb1}
{$EXTERNALSYM EVP_camellia_192_cfb8}
{$EXTERNALSYM EVP_camellia_192_cfb128}
{$EXTERNALSYM EVP_camellia_192_ofb}
{$EXTERNALSYM EVP_camellia_192_ctr}
{$EXTERNALSYM EVP_camellia_256_ecb}
{$EXTERNALSYM EVP_camellia_256_cbc}
{$EXTERNALSYM EVP_camellia_256_cfb1}
{$EXTERNALSYM EVP_camellia_256_cfb8}
{$EXTERNALSYM EVP_camellia_256_cfb128}
{$EXTERNALSYM EVP_camellia_256_ofb}
{$EXTERNALSYM EVP_camellia_256_ctr}
{$EXTERNALSYM EVP_chacha20}
{$EXTERNALSYM EVP_chacha20_poly1305}
{$EXTERNALSYM EVP_seed_ecb}
{$EXTERNALSYM EVP_seed_cbc}
{$EXTERNALSYM EVP_seed_cfb128}
{$EXTERNALSYM EVP_seed_ofb}
{$EXTERNALSYM EVP_sm4_ecb}
{$EXTERNALSYM EVP_sm4_cbc}
{$EXTERNALSYM EVP_sm4_cfb128}
{$EXTERNALSYM EVP_sm4_ofb}
{$EXTERNALSYM EVP_sm4_ctr}
{$EXTERNALSYM EVP_add_cipher}
{$EXTERNALSYM EVP_add_digest}
{$EXTERNALSYM EVP_get_cipherbyname}
{$EXTERNALSYM EVP_get_digestbyname}
{$EXTERNALSYM EVP_CIPHER_do_all}
{$EXTERNALSYM EVP_CIPHER_do_all_sorted}
{$EXTERNALSYM EVP_MD_do_all}
{$EXTERNALSYM EVP_MD_do_all_sorted}
{$EXTERNALSYM EVP_PKEY_decrypt_old}
{$EXTERNALSYM EVP_PKEY_encrypt_old}
{$EXTERNALSYM EVP_PKEY_type}
{$EXTERNALSYM EVP_PKEY_get_base_id}
{$EXTERNALSYM EVP_PKEY_get_security_bits}
{$EXTERNALSYM EVP_PKEY_get_size}
{$EXTERNALSYM EVP_PKEY_set_type}
{$EXTERNALSYM EVP_PKEY_set_type_str}
{$EXTERNALSYM EVP_PKEY_set1_engine}
{$EXTERNALSYM EVP_PKEY_get0_engine}
{$EXTERNALSYM EVP_PKEY_assign}
{$EXTERNALSYM EVP_PKEY_get0}
{$EXTERNALSYM EVP_PKEY_get0_hmac}
{$EXTERNALSYM EVP_PKEY_get0_poly1305}
{$EXTERNALSYM EVP_PKEY_get0_siphash}
{$EXTERNALSYM EVP_PKEY_set1_RSA}
{$EXTERNALSYM EVP_PKEY_get0_RSA}
{$EXTERNALSYM EVP_PKEY_get1_RSA}
{$EXTERNALSYM EVP_PKEY_set1_DSA}
{$EXTERNALSYM EVP_PKEY_get0_DSA}
{$EXTERNALSYM EVP_PKEY_get1_DSA}
{$EXTERNALSYM EVP_PKEY_set1_DH}
{$EXTERNALSYM EVP_PKEY_get0_DH}
{$EXTERNALSYM EVP_PKEY_get1_DH}
{$EXTERNALSYM EVP_PKEY_set1_EC_KEY}
{$EXTERNALSYM EVP_PKEY_get0_EC_KEY}
{$EXTERNALSYM EVP_PKEY_get1_EC_KEY}
{$EXTERNALSYM EVP_PKEY_new}
{$EXTERNALSYM EVP_PKEY_up_ref}
{$EXTERNALSYM EVP_PKEY_free}
{$EXTERNALSYM d2i_PublicKey}
{$EXTERNALSYM i2d_PublicKey}
{$EXTERNALSYM d2i_PrivateKey}
{$EXTERNALSYM d2i_AutoPrivateKey}
{$EXTERNALSYM i2d_PrivateKey}
{$EXTERNALSYM EVP_PKEY_copy_parameters}
{$EXTERNALSYM EVP_PKEY_missing_parameters}
{$EXTERNALSYM EVP_PKEY_save_parameters}
{$EXTERNALSYM EVP_PKEY_cmp_parameters}
{$EXTERNALSYM EVP_PKEY_cmp}
{$EXTERNALSYM EVP_PKEY_print_public}
{$EXTERNALSYM EVP_PKEY_print_private}
{$EXTERNALSYM EVP_PKEY_print_params}
{$EXTERNALSYM EVP_PKEY_get_default_digest_nid}
{$EXTERNALSYM EVP_CIPHER_param_to_asn1}
{$EXTERNALSYM EVP_CIPHER_asn1_to_param}
{$EXTERNALSYM EVP_CIPHER_set_asn1_iv}
{$EXTERNALSYM EVP_CIPHER_get_asn1_iv}
{$EXTERNALSYM PKCS5_PBE_keyivgen}
{$EXTERNALSYM PKCS5_PBKDF2_HMAC_SHA1}
{$EXTERNALSYM PKCS5_PBKDF2_HMAC}
{$EXTERNALSYM PKCS5_v2_PBE_keyivgen}
{$EXTERNALSYM EVP_PBE_scrypt}
{$EXTERNALSYM PKCS5_v2_scrypt_keyivgen}
{$EXTERNALSYM PKCS5_PBE_add}
{$EXTERNALSYM EVP_PBE_CipherInit}
{$EXTERNALSYM EVP_PBE_alg_add_type}
{$EXTERNALSYM EVP_PBE_alg_add}
{$EXTERNALSYM EVP_PBE_find}
{$EXTERNALSYM EVP_PBE_cleanup}
{$EXTERNALSYM EVP_PBE_get}
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
{$EXTERNALSYM EVP_PKEY_asn1_set_public}
{$EXTERNALSYM EVP_PKEY_asn1_set_private}
{$EXTERNALSYM EVP_PKEY_asn1_set_param}
{$EXTERNALSYM EVP_PKEY_asn1_set_free}
{$EXTERNALSYM EVP_PKEY_asn1_set_ctrl}
{$EXTERNALSYM EVP_PKEY_asn1_set_item}
{$EXTERNALSYM EVP_PKEY_asn1_set_siginf}
{$EXTERNALSYM EVP_PKEY_asn1_set_check}
{$EXTERNALSYM EVP_PKEY_asn1_set_public_check}
{$EXTERNALSYM EVP_PKEY_asn1_set_param_check}
{$EXTERNALSYM EVP_PKEY_asn1_set_set_priv_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_set_pub_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_get_priv_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_get_pub_key}
{$EXTERNALSYM EVP_PKEY_asn1_set_security_bits}
{$EXTERNALSYM EVP_PKEY_meth_find}
{$EXTERNALSYM EVP_PKEY_meth_new}
{$EXTERNALSYM EVP_PKEY_meth_get0_info}
{$EXTERNALSYM EVP_PKEY_meth_copy}
{$EXTERNALSYM EVP_PKEY_meth_free}
{$EXTERNALSYM EVP_PKEY_meth_add0}
{$EXTERNALSYM EVP_PKEY_meth_remove}
{$EXTERNALSYM EVP_PKEY_meth_get_count}
{$EXTERNALSYM EVP_PKEY_meth_get0}
{$EXTERNALSYM EVP_PKEY_CTX_new}
{$EXTERNALSYM EVP_PKEY_CTX_new_id}
{$EXTERNALSYM EVP_PKEY_CTX_dup}
{$EXTERNALSYM EVP_PKEY_CTX_free}
{$EXTERNALSYM EVP_PKEY_CTX_ctrl}
{$EXTERNALSYM EVP_PKEY_CTX_ctrl_str}
{$EXTERNALSYM EVP_PKEY_CTX_ctrl_uint64}
{$EXTERNALSYM EVP_PKEY_CTX_str2ctrl}
{$EXTERNALSYM EVP_PKEY_CTX_hex2ctrl}
{$EXTERNALSYM EVP_PKEY_CTX_md}
{$EXTERNALSYM EVP_PKEY_CTX_get_operation}
{$EXTERNALSYM EVP_PKEY_CTX_set0_keygen_info}
{$EXTERNALSYM EVP_PKEY_new_mac_key}
{$EXTERNALSYM EVP_PKEY_new_raw_private_key}
{$EXTERNALSYM EVP_PKEY_new_raw_public_key}
{$EXTERNALSYM EVP_PKEY_get_raw_private_key}
{$EXTERNALSYM EVP_PKEY_get_raw_public_key}
{$EXTERNALSYM EVP_PKEY_new_CMAC_key}
{$EXTERNALSYM EVP_PKEY_CTX_set_data}
{$EXTERNALSYM EVP_PKEY_CTX_get_data}
{$EXTERNALSYM EVP_PKEY_CTX_get0_pkey}
{$EXTERNALSYM EVP_PKEY_CTX_get0_peerkey}
{$EXTERNALSYM EVP_PKEY_CTX_set_app_data}
{$EXTERNALSYM EVP_PKEY_CTX_get_app_data}
{$EXTERNALSYM EVP_PKEY_sign_init}
{$EXTERNALSYM EVP_PKEY_sign}
{$EXTERNALSYM EVP_PKEY_verify_init}
{$EXTERNALSYM EVP_PKEY_verify}
{$EXTERNALSYM EVP_PKEY_verify_recover_init}
{$EXTERNALSYM EVP_PKEY_verify_recover}
{$EXTERNALSYM EVP_PKEY_encrypt_init}
{$EXTERNALSYM EVP_PKEY_encrypt}
{$EXTERNALSYM EVP_PKEY_decrypt_init}
{$EXTERNALSYM EVP_PKEY_decrypt}
{$EXTERNALSYM EVP_PKEY_derive_init}
{$EXTERNALSYM EVP_PKEY_derive_set_peer}
{$EXTERNALSYM EVP_PKEY_derive}
{$EXTERNALSYM EVP_PKEY_paramgen_init}
{$EXTERNALSYM EVP_PKEY_paramgen}
{$EXTERNALSYM EVP_PKEY_keygen_init}
{$EXTERNALSYM EVP_PKEY_keygen}
{$EXTERNALSYM EVP_PKEY_check}
{$EXTERNALSYM EVP_PKEY_public_check}
{$EXTERNALSYM EVP_PKEY_param_check}
{$EXTERNALSYM EVP_PKEY_CTX_set_cb}
{$EXTERNALSYM EVP_PKEY_CTX_get_cb}
{$EXTERNALSYM EVP_PKEY_CTX_get_keygen_info}
{$EXTERNALSYM EVP_PKEY_meth_set_init}
{$EXTERNALSYM EVP_PKEY_meth_set_copy}
{$EXTERNALSYM EVP_PKEY_meth_set_cleanup}
{$EXTERNALSYM EVP_PKEY_meth_set_paramgen}
{$EXTERNALSYM EVP_PKEY_meth_set_keygen}
{$EXTERNALSYM EVP_PKEY_meth_set_sign}
{$EXTERNALSYM EVP_PKEY_meth_set_verify}
{$EXTERNALSYM EVP_PKEY_meth_set_verify_recover}
{$EXTERNALSYM EVP_PKEY_meth_set_signctx}
{$EXTERNALSYM EVP_PKEY_meth_set_verifyctx}
{$EXTERNALSYM EVP_PKEY_meth_set_encrypt}
{$EXTERNALSYM EVP_PKEY_meth_set_decrypt}
{$EXTERNALSYM EVP_PKEY_meth_set_derive}
{$EXTERNALSYM EVP_PKEY_meth_set_ctrl}
{$EXTERNALSYM EVP_PKEY_meth_set_digestsign}
{$EXTERNALSYM EVP_PKEY_meth_set_digestverify}
{$EXTERNALSYM EVP_PKEY_meth_set_check}
{$EXTERNALSYM EVP_PKEY_meth_set_public_check}
{$EXTERNALSYM EVP_PKEY_meth_set_param_check}
{$EXTERNALSYM EVP_PKEY_meth_set_digest_custom}
{$EXTERNALSYM EVP_PKEY_meth_get_init}
{$EXTERNALSYM EVP_PKEY_meth_get_copy}
{$EXTERNALSYM EVP_PKEY_meth_get_cleanup}
{$EXTERNALSYM EVP_PKEY_meth_get_paramgen}
{$EXTERNALSYM EVP_PKEY_meth_get_keygen}
{$EXTERNALSYM EVP_PKEY_meth_get_sign}
{$EXTERNALSYM EVP_PKEY_meth_get_verify}
{$EXTERNALSYM EVP_PKEY_meth_get_verify_recover}
{$EXTERNALSYM EVP_PKEY_meth_get_signctx}
{$EXTERNALSYM EVP_PKEY_meth_get_verifyctx}
{$EXTERNALSYM EVP_PKEY_meth_get_encrypt}
{$EXTERNALSYM EVP_PKEY_meth_get_decrypt}
{$EXTERNALSYM EVP_PKEY_meth_get_derive}
{$EXTERNALSYM EVP_PKEY_meth_get_ctrl}
{$EXTERNALSYM EVP_PKEY_meth_get_digestsign}
{$EXTERNALSYM EVP_PKEY_meth_get_digestverify}
{$EXTERNALSYM EVP_PKEY_meth_get_check}
{$EXTERNALSYM EVP_PKEY_meth_get_public_check}
{$EXTERNALSYM EVP_PKEY_meth_get_param_check}
{$EXTERNALSYM EVP_PKEY_meth_get_digest_custom}
{$EXTERNALSYM EVP_add_alg_module}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl; external CLibCrypto;
function EVP_MD_meth_dup(const md: PEVP_MD): PEVP_MD; cdecl; external CLibCrypto;
procedure EVP_MD_meth_free(md: PEVP_MD); cdecl; external CLibCrypto;
function EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_init(md: PEVP_MD; init: EVP_MD_meth_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_update(md: PEVP_MD; update: EVP_MD_meth_update): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_final(md: PEVP_MD; final_: EVP_MD_meth_final): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_copy(md: PEVP_MD; copy: EVP_MD_meth_copy): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_input_blocksize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_result_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_app_datasize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_meth_get_flags(const md: PEVP_MD): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function EVP_MD_meth_get_init(const md: PEVP_MD): EVP_MD_meth_init; cdecl; external CLibCrypto;
function EVP_MD_meth_get_update(const md: PEVP_MD): EVP_MD_meth_update; cdecl; external CLibCrypto;
function EVP_MD_meth_get_final(const md: PEVP_MD): EVP_MD_meth_final; cdecl; external CLibCrypto;
function EVP_MD_meth_get_copy(const md: PEVP_MD): EVP_MD_meth_copy; cdecl; external CLibCrypto;
function EVP_MD_meth_get_cleanup(const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl; external CLibCrypto;
function EVP_MD_meth_get_ctrl(const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_dup(const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl; external CLibCrypto;
procedure EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_init(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_do_cipher(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_cleanup(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_set_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_get_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl; external CLibCrypto;
function EVP_CIPHER_meth_get_ctrl(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl; external CLibCrypto;
function EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl; external CLibCrypto;
function EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl; external CLibCrypto;
procedure EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl; external CLibCrypto;
procedure EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl; external CLibCrypto;
function EVP_CIPHER_impl_ctx_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_original_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_get_app_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_get_cipher_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl; external CLibCrypto;
function EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_CTX_new: PEVP_MD_CTX; cdecl; external CLibCrypto;
function EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl; external CLibCrypto;
function EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_MD_CTX_test_flags(const ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_Digest(const data: Pointer; count: TOpenSSL_C_SIZET; md: PByte; size: POpenSSL_C_UINT; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_MD_CTX_copy(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestInit(ctx: PEVP_MD_CTX; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; md: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_set_pw_prompt(const prompt: PAnsiChar); cdecl; external CLibCrypto;
function EVP_get_pw_prompt: PAnsiChar; cdecl; external CLibCrypto;
function EVP_BytesToKey(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: PByte; iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_test_flags(const ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecryptFinal_ex(ctx: PEVP_MD_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_SignFinal(ctx: PEVP_CIPHER_CTX; md: PByte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestSign(ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_VerifyFinal(ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestVerify(ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_OpenInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TOpenSSL_C_INT; const iv: PByte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_SealInit(ctx: PEVP_CIPHER_CTX; const type_: EVP_CIPHER; ek: PPByte; ek1: POpenSSL_C_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl; external CLibCrypto;
procedure EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto;
function EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto;
function EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_EncodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl; external CLibCrypto;
function EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_DecodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_f_md: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_base64: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_cipher: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_reliable: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_md_null: PEVP_MD; cdecl; external CLibCrypto;
{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_MD2}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_MD4}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_MD5}
  
{$ENDIF}
{$ENDIF}
  
function EVP_md5_sha1: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha1: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha224: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha384: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha512: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha512_224: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha512_256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_224: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_384: PEVP_MD; cdecl; external CLibCrypto;
function EVP_sha3_512: PEVP_MD; cdecl; external CLibCrypto;
function EVP_shake128: PEVP_MD; cdecl; external CLibCrypto;
function EVP_shake256: PEVP_MD; cdecl; external CLibCrypto;
function EVP_enc_null: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_desx_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_des_ede3_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc4: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc4_40: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_40_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_64_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_rc2_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_bf_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_cfb64: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_cast5_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_xts: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_ocb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_192_ocb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_xts: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_wrap: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_ocb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_128_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_192_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_gcm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_aria_256_ccm: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_128_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_192_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_camellia_256_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_chacha20: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_chacha20_poly1305: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_seed_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_ecb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_cbc: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_cfb128: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_ofb: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_sm4_ctr: PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_add_cipher(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_add_digest(const digest: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_get_cipherbyname(const name: PAnsiChar): PEVP_CIPHER; cdecl; external CLibCrypto;
function EVP_get_digestbyname(const name: PAnsiChar): PEVP_MD; cdecl; external CLibCrypto;
procedure EVP_CIPHER_do_all(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
procedure EVP_CIPHER_do_all_sorted(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
procedure EVP_MD_do_all(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
procedure EVP_MD_do_all_sorted(AFn: fn; arg: Pointer); cdecl; external CLibCrypto;
function EVP_PKEY_decrypt_old(dec_key: PByte; const enc_key: PByte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_encrypt_old(dec_key: PByte; const enc_key: PByte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_set_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_set_type_str(pkey: PEVP_PKEY; const str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_engine(const pkey: PEVP_PKEY): PENGINE; cdecl; external CLibCrypto;
function EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0(const pkey: PEVP_PKEY): Pointer; cdecl; external CLibCrypto;
function EVP_PKEY_get0_hmac(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl; external CLibCrypto;
function EVP_PKEY_get0_poly1305(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl; external CLibCrypto;
function EVP_PKEY_get0_siphash(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl; external CLibCrypto;
function EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): PRSA; cdecl; external CLibCrypto;
function EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): PRSA; cdecl; external CLibCrypto;
function EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: PDSA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): PDSA; cdecl; external CLibCrypto;
function EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): PDSA; cdecl; external CLibCrypto;
function EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: PDH): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_DH(pkey: PEVP_PKEY): PDH; cdecl; external CLibCrypto;
function EVP_PKEY_get1_DH(pkey: PEVP_PKEY): PDH; cdecl; external CLibCrypto;
function EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: PEC_KEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl; external CLibCrypto;
function EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl; external CLibCrypto;
function EVP_PKEY_new: PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_free(pkey: PEVP_PKEY); cdecl; external CLibCrypto;
function d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_PublicKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function d2i_AutoPrivateKey(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl; external CLibCrypto;
function i2d_PrivateKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_copy_parameters(to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_missing_parameters(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_cmp_parameters(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_cmp(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_print_public(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_print_private(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_print_params(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_PBKDF2_HMAC_SHA1(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_PBKDF2_HMAC(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_scrypt(const pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; const salt: PByte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure PKCS5_PBE_add; cdecl; external CLibCrypto;
function EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_alg_add(nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PBE_cleanup; cdecl; external CLibCrypto;
function EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_find_str(pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_add0(const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; const pinfo: PPAnsiChar; const ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get0_asn1(const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; const pem_str: PAnsiChar; const info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl; external CLibCrypto;
procedure EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl; external CLibCrypto;
function EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; const meth: PEVP_PKEY_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl; external CLibCrypto;
function EVP_PKEY_meth_add0(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_meth_remove(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; const type_: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const str: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const hex: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; const md: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; const key: PByte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; const pub: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_get_raw_private_key(const pkey: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_get_raw_public_key(const pkey: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_new_CMAC_key(e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl; external CLibCrypto;
function EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: PByte; routlen: POpenSSL_C_SIZET; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl; external CLibCrypto;
function EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_init(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_copy(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy: PEVP_PKEY_meth_copy); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_cleanup(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_paramgen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_keygen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_sign(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl; external CLibCrypto;
procedure EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl; external CLibCrypto;
procedure EVP_add_alg_module; cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
function EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; {removed 1.0.0}
procedure BIO_set_md(v1: PBIO; const md: PEVP_MD); {removed 1.0.0}
{$IFNDEF OPENSSL_NO_MD2}
function EVP_md2: PEVP_MD; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
function EVP_md4: PEVP_MD; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
function EVP_md5: PEVP_MD; {removed 1.1.0 allow_nil}
{$ENDIF}
function EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; {removed 3.0.0}
function EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; {removed 3.0.0}
procedure OpenSSL_add_all_ciphers; {removed 1.1.0}
procedure OpenSSL_add_all_digests; {removed 1.1.0}
procedure EVP_cleanup; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  EVP_MD_meth_new: function (md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl = nil;
  EVP_MD_meth_dup: function (const md: PEVP_MD): PEVP_MD; cdecl = nil;
  EVP_MD_meth_free: procedure (md: PEVP_MD); cdecl = nil;
  EVP_MD_meth_set_input_blocksize: function (md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_result_size: function (md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_app_datasize: function (md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_flags: function (md: PEVP_MD; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_init: function (md: PEVP_MD; init: EVP_MD_meth_init): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_update: function (md: PEVP_MD; update: EVP_MD_meth_update): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_final: function (md: PEVP_MD; final_: EVP_MD_meth_final): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_copy: function (md: PEVP_MD; copy: EVP_MD_meth_copy): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_cleanup: function (md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_set_ctrl: function (md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_get_input_blocksize: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_get_result_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_get_app_datasize: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_meth_get_flags: function (const md: PEVP_MD): TOpenSSL_C_ULONG; cdecl = nil;
  EVP_MD_meth_get_init: function (const md: PEVP_MD): EVP_MD_meth_init; cdecl = nil;
  EVP_MD_meth_get_update: function (const md: PEVP_MD): EVP_MD_meth_update; cdecl = nil;
  EVP_MD_meth_get_final: function (const md: PEVP_MD): EVP_MD_meth_final; cdecl = nil;
  EVP_MD_meth_get_copy: function (const md: PEVP_MD): EVP_MD_meth_copy; cdecl = nil;
  EVP_MD_meth_get_cleanup: function (const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl = nil;
  EVP_MD_meth_get_ctrl: function (const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl = nil;
  EVP_CIPHER_meth_new: function (cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl = nil;
  EVP_CIPHER_meth_dup: function (const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl = nil;
  EVP_CIPHER_meth_free: procedure (cipher: PEVP_CIPHER); cdecl = nil;
  EVP_CIPHER_meth_set_iv_length: function (cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_flags: function (cipher: PEVP_CIPHER; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_impl_ctx_size: function (cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_init: function (cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_do_cipher: function (cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_cleanup: function (cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_set_asn1_params: function (cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_get_asn1_params: function (cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_set_ctrl: function (cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_meth_get_init: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl = nil;
  EVP_CIPHER_meth_get_do_cipher: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl = nil;
  EVP_CIPHER_meth_get_cleanup: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl = nil;
  EVP_CIPHER_meth_get_set_asn1_params: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl = nil;
  EVP_CIPHER_meth_get_get_asn1_params: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl = nil;
  EVP_CIPHER_meth_get_ctrl: function (const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl = nil;
  EVP_MD_CTX_md: function (ctx: PEVP_MD_CTX): PEVP_MD; cdecl = nil;
  EVP_MD_CTX_update_fn: function (ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl = nil;
  EVP_MD_CTX_set_update_fn: procedure (ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl = nil;
  EVP_MD_CTX_set_pkey_ctx: procedure (ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl = nil;
  EVP_CIPHER_impl_ctx_size: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_cipher: function (const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl = nil;
  EVP_CIPHER_CTX_iv: function (const ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil;
  EVP_CIPHER_CTX_original_iv: function (const ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil;
  EVP_CIPHER_CTX_iv_noconst: function (ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil;
  EVP_CIPHER_CTX_buf_noconst: function (ctx: PEVP_CIPHER_CTX): PByte; cdecl = nil;
  EVP_CIPHER_CTX_set_num: procedure (ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT); cdecl = nil;
  EVP_CIPHER_CTX_copy: function (out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_get_app_data: function (const ctx: PEVP_CIPHER_CTX): Pointer; cdecl = nil;
  EVP_CIPHER_CTX_set_app_data: procedure (ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl = nil;
  EVP_CIPHER_CTX_get_cipher_data: function (const ctx: PEVP_CIPHER_CTX): Pointer; cdecl = nil;
  EVP_CIPHER_CTX_set_cipher_data: function (ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl = nil;
  EVP_MD_CTX_ctrl: function (ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_CTX_new: function : PEVP_MD_CTX; cdecl = nil;
  EVP_MD_CTX_reset: function (ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_CTX_free: procedure (ctx: PEVP_MD_CTX); cdecl = nil;
  EVP_MD_CTX_copy_ex: function (out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_CTX_set_flags: procedure (ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl = nil;
  EVP_MD_CTX_clear_flags: procedure (ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl = nil;
  EVP_MD_CTX_test_flags: function (const ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestInit_ex: function (ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestUpdate: function (ctx: PEVP_MD_CTX; const d: Pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestFinal_ex: function (ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  EVP_Digest: function (const data: Pointer; count: TOpenSSL_C_SIZET; md: PByte; size: POpenSSL_C_UINT; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  EVP_MD_CTX_copy: function (out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestInit: function (ctx: PEVP_MD_CTX; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestFinal: function (ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestFinalXOF: function (ctx: PEVP_MD_CTX; md: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_read_pw_string: function (buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_read_pw_string_min: function (buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_set_pw_prompt: procedure (const prompt: PAnsiChar); cdecl = nil;
  EVP_get_pw_prompt: function : PAnsiChar; cdecl = nil;
  EVP_BytesToKey: function (const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: PByte; iv: PByte): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_set_flags: procedure (ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl = nil;
  EVP_CIPHER_CTX_clear_flags: procedure (ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl = nil;
  EVP_CIPHER_CTX_test_flags: function (const ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_EncryptInit: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl = nil;
  EVP_EncryptInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl = nil;
  EVP_EncryptUpdate: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_EncryptFinal_ex: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_EncryptFinal: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecryptInit: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecryptInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecryptUpdate: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecryptFinal: function (ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecryptFinal_ex: function (ctx: PEVP_MD_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CipherInit: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CipherInit_ex: function (ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CipherUpdate: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CipherFinal: function (ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CipherFinal_ex: function (ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_SignFinal: function (ctx: PEVP_CIPHER_CTX; md: PByte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestSign: function (ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_VerifyFinal: function (ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestVerify: function (ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestSignInit: function (ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestSignFinal: function (ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestVerifyInit: function (ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_DigestVerifyFinal: function (ctx: PEVP_MD_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_OpenInit: function (ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TOpenSSL_C_INT; const iv: PByte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_OpenFinal: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_SealInit: function (ctx: PEVP_CIPHER_CTX; const type_: EVP_CIPHER; ek: PPByte; ek1: POpenSSL_C_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_SealFinal: function (ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_ENCODE_CTX_new: function : PEVP_ENCODE_CTX; cdecl = nil;
  EVP_ENCODE_CTX_free: procedure (ctx: PEVP_ENCODE_CTX); cdecl = nil;
  EVP_ENCODE_CTX_copy: function (dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_ENCODE_CTX_num: function (ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_EncodeInit: procedure (ctx: PEVP_ENCODE_CTX); cdecl = nil;
  EVP_EncodeUpdate: function (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_EncodeFinal: procedure (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT); cdecl = nil;
  EVP_EncodeBlock: function (t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecodeInit: procedure (ctx: PEVP_ENCODE_CTX); cdecl = nil;
  EVP_DecodeUpdate: function (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecodeFinal: function (ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_DecodeBlock: function (t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_new: function : PEVP_CIPHER_CTX; cdecl = nil;
  EVP_CIPHER_CTX_reset: function (c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_free: procedure (c: PEVP_CIPHER_CTX); cdecl = nil;
  EVP_CIPHER_CTX_set_key_length: function (x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_set_padding: function (c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_ctrl: function (ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_CTX_rand_key: function (ctx: PEVP_CIPHER_CTX; key: PByte): TOpenSSL_C_INT; cdecl = nil;
  BIO_f_md: function : PBIO_METHOD; cdecl = nil;
  BIO_f_base64: function : PBIO_METHOD; cdecl = nil;
  BIO_f_cipher: function : PBIO_METHOD; cdecl = nil;
  BIO_f_reliable: function : PBIO_METHOD; cdecl = nil;
  BIO_set_cipher: function (b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_md_null: function : PEVP_MD; cdecl = nil;
{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_MD2}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_MD4}
  
{$ENDIF}
{$ENDIF}
  
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_MD5}
  
{$ENDIF}
{$ENDIF}
  
  EVP_md5_sha1: function : PEVP_MD; cdecl = nil;
  EVP_sha1: function : PEVP_MD; cdecl = nil;
  EVP_sha224: function : PEVP_MD; cdecl = nil;
  EVP_sha256: function : PEVP_MD; cdecl = nil;
  EVP_sha384: function : PEVP_MD; cdecl = nil;
  EVP_sha512: function : PEVP_MD; cdecl = nil;
  EVP_sha512_224: function : PEVP_MD; cdecl = nil;
  EVP_sha512_256: function : PEVP_MD; cdecl = nil;
  EVP_sha3_224: function : PEVP_MD; cdecl = nil;
  EVP_sha3_256: function : PEVP_MD; cdecl = nil;
  EVP_sha3_384: function : PEVP_MD; cdecl = nil;
  EVP_sha3_512: function : PEVP_MD; cdecl = nil;
  EVP_shake128: function : PEVP_MD; cdecl = nil;
  EVP_shake256: function : PEVP_MD; cdecl = nil;
  EVP_enc_null: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_cfb64: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_cfb64: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cfb64: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_desx_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_des_ede3_wrap: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc4: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc4_40: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc2_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc2_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc2_40_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc2_64_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc2_cfb64: function : PEVP_CIPHER; cdecl = nil;
  EVP_rc2_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_bf_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_bf_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_bf_cfb64: function : PEVP_CIPHER; cdecl = nil;
  EVP_bf_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_cast5_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_cast5_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_cast5_cfb64: function : PEVP_CIPHER; cdecl = nil;
  EVP_cast5_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ccm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_gcm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_xts: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_wrap: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_wrap_pad: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_ocb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ccm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_gcm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_wrap: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_wrap_pad: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_192_ocb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ccm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_gcm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_xts: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_wrap: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_wrap_pad: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_ocb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cbc_hmac_sha1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cbc_hmac_sha1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_128_cbc_hmac_sha256: function : PEVP_CIPHER; cdecl = nil;
  EVP_aes_256_cbc_hmac_sha256: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_gcm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_128_ccm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_gcm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_192_ccm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_gcm: function : PEVP_CIPHER; cdecl = nil;
  EVP_aria_256_ccm: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_128_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_192_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cfb1: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cfb8: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_camellia_256_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_chacha20: function : PEVP_CIPHER; cdecl = nil;
  EVP_chacha20_poly1305: function : PEVP_CIPHER; cdecl = nil;
  EVP_seed_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_seed_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_seed_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_seed_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_sm4_ecb: function : PEVP_CIPHER; cdecl = nil;
  EVP_sm4_cbc: function : PEVP_CIPHER; cdecl = nil;
  EVP_sm4_cfb128: function : PEVP_CIPHER; cdecl = nil;
  EVP_sm4_ofb: function : PEVP_CIPHER; cdecl = nil;
  EVP_sm4_ctr: function : PEVP_CIPHER; cdecl = nil;
  EVP_add_cipher: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = nil;
  EVP_add_digest: function (const digest: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  EVP_get_cipherbyname: function (const name: PAnsiChar): PEVP_CIPHER; cdecl = nil;
  EVP_get_digestbyname: function (const name: PAnsiChar): PEVP_MD; cdecl = nil;
  EVP_CIPHER_do_all: procedure (AFn: fn; arg: Pointer); cdecl = nil;
  EVP_CIPHER_do_all_sorted: procedure (AFn: fn; arg: Pointer); cdecl = nil;
  EVP_MD_do_all: procedure (AFn: fn; arg: Pointer); cdecl = nil;
  EVP_MD_do_all_sorted: procedure (AFn: fn; arg: Pointer); cdecl = nil;
  EVP_PKEY_decrypt_old: function (dec_key: PByte; const enc_key: PByte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_encrypt_old: function (dec_key: PByte; const enc_key: PByte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_type: function (type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_base_id: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_security_bits: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_size: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_set_type: function (pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_set_type_str: function (pkey: PEVP_PKEY; const str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_set1_engine: function (pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get0_engine: function (const pkey: PEVP_PKEY): PENGINE; cdecl = nil;
  EVP_PKEY_assign: function (pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: Pointer): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get0: function (const pkey: PEVP_PKEY): Pointer; cdecl = nil;
  EVP_PKEY_get0_hmac: function (const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl = nil;
  EVP_PKEY_get0_poly1305: function (const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl = nil;
  EVP_PKEY_get0_siphash: function (const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl = nil;
  EVP_PKEY_set1_RSA: function (pkey: PEVP_PKEY; key: PRSA): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get0_RSA: function (pkey: PEVP_PKEY): PRSA; cdecl = nil;
  EVP_PKEY_get1_RSA: function (pkey: PEVP_PKEY): PRSA; cdecl = nil;
  EVP_PKEY_set1_DSA: function (pkey: PEVP_PKEY; key: PDSA): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get0_DSA: function (pkey: PEVP_PKEY): PDSA; cdecl = nil;
  EVP_PKEY_get1_DSA: function (pkey: PEVP_PKEY): PDSA; cdecl = nil;
  EVP_PKEY_set1_DH: function (pkey: PEVP_PKEY; key: PDH): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get0_DH: function (pkey: PEVP_PKEY): PDH; cdecl = nil;
  EVP_PKEY_get1_DH: function (pkey: PEVP_PKEY): PDH; cdecl = nil;
  EVP_PKEY_set1_EC_KEY: function (pkey: PEVP_PKEY; key: PEC_KEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get0_EC_KEY: function (pkey: PEVP_PKEY): PEC_KEY; cdecl = nil;
  EVP_PKEY_get1_EC_KEY: function (pkey: PEVP_PKEY): PEC_KEY; cdecl = nil;
  EVP_PKEY_new: function : PEVP_PKEY; cdecl = nil;
  EVP_PKEY_up_ref: function (pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_free: procedure (pkey: PEVP_PKEY); cdecl = nil;
  d2i_PublicKey: function (type_: TOpenSSL_C_INT; a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = nil;
  i2d_PublicKey: function (a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_PrivateKey: function (type_: TOpenSSL_C_INT; a: PEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = nil;
  d2i_AutoPrivateKey: function (a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl = nil;
  i2d_PrivateKey: function (a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_copy_parameters: function (to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_missing_parameters: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_save_parameters: function (pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_cmp_parameters: function (const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_cmp: function (const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_print_public: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_print_private: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_print_params: function (out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_default_digest_nid: function (pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_param_to_asn1: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_asn1_to_param: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_set_asn1_iv: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  EVP_CIPHER_get_asn1_iv: function (c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_PBKDF2_HMAC_SHA1: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_PBKDF2_HMAC: function (const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_v2_PBE_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PBE_scrypt: function (const pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; const salt: PByte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_v2_scrypt_keyivgen: function (ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  PKCS5_PBE_add: procedure ; cdecl = nil;
  EVP_PBE_CipherInit: function (pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PBE_alg_add_type: function (pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = nil;
  EVP_PBE_alg_add: function (nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = nil;
  EVP_PBE_find: function (type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl = nil;
  EVP_PBE_cleanup: procedure ; cdecl = nil;
  EVP_PBE_get: function (ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_asn1_get_count: function : TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_asn1_get0: function (idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_find: function (pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_find_str: function (pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_add0: function (const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_asn1_add_alias: function (to_: TOpenSSL_C_INT; from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_asn1_get0_info: function (ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; const pinfo: PPAnsiChar; const ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get0_asn1: function (const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_new: function (id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; const pem_str: PAnsiChar; const info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  EVP_PKEY_asn1_copy: procedure (dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl = nil;
  EVP_PKEY_asn1_free: procedure (ameth: PEVP_PKEY_ASN1_METHOD); cdecl = nil;
  EVP_PKEY_asn1_set_public: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl = nil;
  EVP_PKEY_asn1_set_private: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl = nil;
  EVP_PKEY_asn1_set_param: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl = nil;
  EVP_PKEY_asn1_set_free: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl = nil;
  EVP_PKEY_asn1_set_ctrl: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl = nil;
  EVP_PKEY_asn1_set_item: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl = nil;
  EVP_PKEY_asn1_set_siginf: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl = nil;
  EVP_PKEY_asn1_set_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl = nil;
  EVP_PKEY_asn1_set_public_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl = nil;
  EVP_PKEY_asn1_set_param_check: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl = nil;
  EVP_PKEY_asn1_set_set_priv_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl = nil;
  EVP_PKEY_asn1_set_set_pub_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl = nil;
  EVP_PKEY_asn1_set_get_priv_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl = nil;
  EVP_PKEY_asn1_set_get_pub_key: procedure (ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl = nil;
  EVP_PKEY_asn1_set_security_bits: procedure (ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl = nil;
  EVP_PKEY_meth_find: function (type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = nil;
  EVP_PKEY_meth_new: function (id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = nil;
  EVP_PKEY_meth_get0_info: procedure (ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; const meth: PEVP_PKEY_METHOD); cdecl = nil;
  EVP_PKEY_meth_copy: procedure (dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl = nil;
  EVP_PKEY_meth_free: procedure (pmeth: PEVP_PKEY_METHOD); cdecl = nil;
  EVP_PKEY_meth_add0: function (const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_meth_remove: function (const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_meth_get_count: function : TOpenSSL_C_SIZET; cdecl = nil;
  EVP_PKEY_meth_get0: function (idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl = nil;
  EVP_PKEY_CTX_new: function (pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl = nil;
  EVP_PKEY_CTX_new_id: function (id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl = nil;
  EVP_PKEY_CTX_dup: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl = nil;
  EVP_PKEY_CTX_free: procedure (ctx: PEVP_PKEY_CTX); cdecl = nil;
  EVP_PKEY_CTX_ctrl: function (ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_ctrl_str: function (ctx: PEVP_PKEY_CTX; const type_: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_ctrl_uint64: function (ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_str2ctrl: function (ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const str: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_hex2ctrl: function (ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const hex: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_md: function (ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; const md: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_get_operation: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_set0_keygen_info: procedure (ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl = nil;
  EVP_PKEY_new_mac_key: function (type_: TOpenSSL_C_INT; e: PENGINE; const key: PByte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_new_raw_private_key: function (type_: TOpenSSL_C_INT; e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_new_raw_public_key: function (type_: TOpenSSL_C_INT; e: PENGINE; const pub: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_get_raw_private_key: function (const pkey: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_get_raw_public_key: function (const pkey: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_new_CMAC_key: function (e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_CTX_set_data: procedure (ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = nil;
  EVP_PKEY_CTX_get_data: function (ctx: PEVP_PKEY_CTX): Pointer; cdecl = nil;
  EVP_PKEY_CTX_get0_pkey: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_CTX_get0_peerkey: function (ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl = nil;
  EVP_PKEY_CTX_set_app_data: procedure (ctx: PEVP_PKEY_CTX; data: Pointer); cdecl = nil;
  EVP_PKEY_CTX_get_app_data: function (ctx: PEVP_PKEY_CTX): Pointer; cdecl = nil;
  EVP_PKEY_sign_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_sign: function (ctx: PEVP_PKEY_CTX; sig: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_verify_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_verify: function (ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_verify_recover_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_verify_recover: function (ctx: PEVP_PKEY_CTX; rout: PByte; routlen: POpenSSL_C_SIZET; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_encrypt_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_encrypt: function (ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_decrypt_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_decrypt: function (ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_derive_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_derive_set_peer: function (ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_derive: function (ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_paramgen_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_paramgen: function (ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_keygen_init: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_keygen: function (ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_check: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_public_check: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_param_check: function (ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_CTX_set_cb: procedure (ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl = nil;
  EVP_PKEY_CTX_get_cb: function (ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl = nil;
  EVP_PKEY_CTX_get_keygen_info: function (ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  EVP_PKEY_meth_set_init: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl = nil;
  EVP_PKEY_meth_set_copy: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl = nil;
  EVP_PKEY_meth_set_cleanup: procedure (pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl = nil;
  EVP_PKEY_meth_set_paramgen: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl = nil;
  EVP_PKEY_meth_set_keygen: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl = nil;
  EVP_PKEY_meth_set_sign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl = nil;
  EVP_PKEY_meth_set_verify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl = nil;
  EVP_PKEY_meth_set_verify_recover: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl = nil;
  EVP_PKEY_meth_set_signctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl = nil;
  EVP_PKEY_meth_set_verifyctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl = nil;
  EVP_PKEY_meth_set_encrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl = nil;
  EVP_PKEY_meth_set_decrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl = nil;
  EVP_PKEY_meth_set_derive: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl = nil;
  EVP_PKEY_meth_set_ctrl: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl = nil;
  EVP_PKEY_meth_set_digestsign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl = nil;
  EVP_PKEY_meth_set_digestverify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl = nil;
  EVP_PKEY_meth_set_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl = nil;
  EVP_PKEY_meth_set_public_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl = nil;
  EVP_PKEY_meth_set_param_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl = nil;
  EVP_PKEY_meth_set_digest_custom: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl = nil;
  EVP_PKEY_meth_get_init: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl = nil;
  EVP_PKEY_meth_get_copy: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy: PEVP_PKEY_meth_copy); cdecl = nil;
  EVP_PKEY_meth_get_cleanup: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl = nil;
  EVP_PKEY_meth_get_paramgen: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl = nil;
  EVP_PKEY_meth_get_keygen: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl = nil;
  EVP_PKEY_meth_get_sign: procedure (const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl = nil;
  EVP_PKEY_meth_get_verify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl = nil;
  EVP_PKEY_meth_get_verify_recover: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl = nil;
  EVP_PKEY_meth_get_signctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl = nil;
  EVP_PKEY_meth_get_verifyctx: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl = nil;
  EVP_PKEY_meth_get_encrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl = nil;
  EVP_PKEY_meth_get_decrypt: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl = nil;
  EVP_PKEY_meth_get_derive: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl = nil;
  EVP_PKEY_meth_get_ctrl: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl = nil;
  EVP_PKEY_meth_get_digestsign: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl = nil;
  EVP_PKEY_meth_get_digestverify: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl = nil;
  EVP_PKEY_meth_get_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl = nil;
  EVP_PKEY_meth_get_public_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl = nil;
  EVP_PKEY_meth_get_param_check: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl = nil;
  EVP_PKEY_meth_get_digest_custom: procedure (pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl = nil;
  EVP_add_alg_module: procedure ; cdecl = nil;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  EVP_PKEY_assign_RSA: function (pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  EVP_PKEY_assign_DSA: function (pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  EVP_PKEY_assign_DH: function (pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  EVP_PKEY_assign_EC_KEY: function (pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  EVP_PKEY_assign_SIPHASH: function (pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  EVP_PKEY_assign_POLY1305: function (pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_set_md: procedure (v1: PBIO; const md: PEVP_MD); cdecl = nil; {removed 1.0.0}
{$IFNDEF OPENSSL_NO_MD2}
  EVP_md2: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
  EVP_md4: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
  EVP_md5: function : PEVP_MD; cdecl = nil; {removed 1.1.0 allow_nil}
{$ENDIF}
  EVP_PKEY_security_bits: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_PKEY_size: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  OpenSSL_add_all_ciphers: procedure ; cdecl = nil; {removed 1.1.0}
  OpenSSL_add_all_digests: procedure ; cdecl = nil; {removed 1.1.0}
  EVP_cleanup: procedure ; cdecl = nil; {removed 1.1.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  EVP_PKEY_assign_RSA_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_DSA_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_DH_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_EC_KEY_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_SIPHASH_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_PKEY_assign_POLY1305_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_MD_meth_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_input_blocksize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_result_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_app_datasize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_update_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_final_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_set_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_input_blocksize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_result_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_app_datasize_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_update_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_final_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_meth_get_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_dup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_iv_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_flags_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_impl_ctx_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_do_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_set_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_get_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_set_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_do_cipher_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_cleanup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_set_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_get_asn1_params_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_meth_get_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_pkey_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_block_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_flags_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_CTX_update_fn_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_set_update_fn_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_pkey_ctx_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_pkey_ctx_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_MD_CTX_set_pkey_ctx_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_md_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_md_data_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_nid_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_block_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_impl_ctx_size_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_key_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_iv_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_flags_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_encrypting_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_encrypting_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_nid_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_block_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_key_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_iv_length_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_iv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_original_iv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_iv_noconst_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_buf_noconst_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_num_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_CTX_set_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_get_cipher_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_set_cipher_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_md_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  EVP_MD_CTX_init_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_MD_CTX_cleanup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_MD_CTX_ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_reset_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_MD_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_DigestFinalXOF_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_DigestSign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_DigestVerify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_copy_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_ENCODE_CTX_num_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_CIPHER_CTX_reset_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_md2_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_md4_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_md5_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_md5_sha1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha512_224_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha512_256_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_224_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_256_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_384_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sha3_512_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_shake128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_shake256_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_128_wrap_pad_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_128_ocb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_192_wrap_pad_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_192_ocb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_256_wrap_pad_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aes_256_ocb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cfb1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cfb8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_gcm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_128_ccm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cfb1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cfb8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_gcm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_192_ccm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cfb1_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cfb8_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_gcm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_aria_256_ccm_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_camellia_128_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_camellia_192_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_camellia_256_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_chacha20_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_chacha20_poly1305_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_ecb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_cbc_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_cfb128_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_ofb_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_sm4_ctr_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_id_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_base_id_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get_base_id_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  EVP_PKEY_bits_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_security_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_security_bits_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get_security_bits_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  EVP_PKEY_size_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get_size_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  EVP_PKEY_set_alias_type_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_set_alias_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_set1_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_engine_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_hmac_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_poly1305_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_siphash_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_RSA_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_DSA_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_DH_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get0_EC_KEY_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_set1_tls_encodedpoint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_set1_tls_encodedpoint_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PKEY_get1_tls_encodedpoint_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get1_tls_encodedpoint_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_CIPHER_type_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  EVP_PBE_scrypt_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  PKCS5_v2_scrypt_keyivgen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PBE_get_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_siginf_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_priv_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_set_pub_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_priv_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_get_pub_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_asn1_set_security_bits_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_remove_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_count_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get0_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_ctrl_uint64_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_str2ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_hex2ctrl_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_CTX_md_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_new_raw_private_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_new_raw_public_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get_raw_private_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_get_raw_public_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_new_CMAC_key_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_digestsign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_digestverify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_set_digest_custom_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_digestsign_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_digestverify_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_public_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_param_check_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  EVP_PKEY_meth_get_digest_custom_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OpenSSL_add_all_ciphers_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  OpenSSL_add_all_digests_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}
  EVP_cleanup_removed = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.1.0}


implementation

uses OpenSSL_crypto,
Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

//#  define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA, (char *)(rsa))

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  EVP_MD_type: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_MD_pkey_type: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_MD_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_MD_block_size: function (const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_MD_flags: function (const md: PEVP_MD): POpenSSL_C_ULONG; cdecl = nil; {removed 3.0.0}
  EVP_MD_CTX_pkey_ctx: function (const ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl = nil; {removed 3.0.0}
  EVP_MD_CTX_md_data: function (const ctx: PEVP_MD_CTX): Pointer; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_nid: function (const ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_block_size: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_key_length: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_iv_length: function (const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_flags: function (const cipher: PEVP_CIPHER): TOpenSSL_C_ULONG; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_CTX_encrypting: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_CTX_nid: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_CTX_block_size: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_CTX_key_length: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_CTX_iv_length: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_CTX_num: function (const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_MD_CTX_init: procedure (ctx : PEVP_MD_CTX); cdecl = nil; {removed 1.1.0}
  EVP_MD_CTX_cleanup: function (ctx : PEVP_MD_CTX): TOpenSSL_C_INT; cdecl = nil; {removed 1.1.0}
{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
  EVP_PKEY_id: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_PKEY_base_id: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_PKEY_bits: function (const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_PKEY_set_alias_type: function (pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_PKEY_set1_tls_encodedpoint: function (pkey: PEVP_PKEY; const pt: PByte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
  EVP_PKEY_get1_tls_encodedpoint: function (pkey: PEVP_PKEY; ppt: PPByte): TOpenSSL_C_SIZET; cdecl = nil; {removed 3.0.0}
  EVP_CIPHER_type: function (const ctx: PEVP_CIPHER): TOpenSSL_C_INT; cdecl = nil; {removed 3.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
end;

//#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA, (char *)(dsa))


function EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
end;

//#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH, (char *)(dh))


function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh);
end;

//#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC, (char *)(eckey))


function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey);
end;

//#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),EVP_PKEY_SIPHASH, (char *)(shkey))


function EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_SIPHASH, shkey);
end;

//#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305, (char *)(polykey))


function EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_POLY1305, polykey);
end;



procedure OpenSSL_add_all_ciphers;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil);
end;



procedure OpenSSL_add_all_digests;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, Nil);
end;



procedure EVP_cleanup;

begin
end;



procedure BIO_set_md(v1: PBIO; const md: PEVP_MD);

begin
  {define BIO_set_md(b,md)  BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))}
  BIO_ctrl(v1,BIO_C_SET_MD,0,PAnsiChar(md));
end;



{$WARN   NO_RETVAL OFF}
{$IFNDEF  OPENSSL_NO_MD2}
function EVP_md2: PEVP_MD;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF }
{$IFNDEF  OPENSSL_NO_MD4}
function EVP_md4: PEVP_MD;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF }
{$IFNDEF  OPENSSL_NO_MD5}
function EVP_md5: PEVP_MD;

begin
  Result := EVP_md5_sha1;
end;

{$ENDIF }
{$WARN   NO_RETVAL ON}
function EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_get_security_bits(pkey);
end;



function EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT;

begin
  Result := EVP_PKEY_get_size(pkey);
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);
end;

//#  define EVP_PKEY_assign_DSA(pkey,dsa) EVP_PKEY_assign((pkey),EVP_PKEY_DSA, (char *)(dsa))


function COMPAT_EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DSA, dsa);
end;

//#  define EVP_PKEY_assign_DH(pkey,dh) EVP_PKEY_assign((pkey),EVP_PKEY_DH, (char *)(dh))


function COMPAT_EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_DH, dh);
end;

//#  define EVP_PKEY_assign_EC_KEY(pkey,eckey) EVP_PKEY_assign((pkey),EVP_PKEY_EC, (char *)(eckey))


function COMPAT_EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey);
end;

//#  define EVP_PKEY_assign_SIPHASH(pkey,shkey) EVP_PKEY_assign((pkey),EVP_PKEY_SIPHASH, (char *)(shkey))


function COMPAT_EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_SIPHASH, shkey);
end;

//#  define EVP_PKEY_assign_POLY1305(pkey,polykey) EVP_PKEY_assign((pkey),EVP_PKEY_POLY1305, (char *)(polykey))


function COMPAT_EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_assign(pkey, EVP_PKEY_POLY1305, polykey);
end;



procedure COMPAT_OpenSSL_add_all_ciphers; cdecl;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, nil);
end;



procedure COMPAT_OpenSSL_add_all_digests; cdecl;

begin
  OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, Nil);
end;



procedure COMPAT_EVP_cleanup; cdecl;

begin
end;



procedure COMPAT_BIO_set_md(v1: PBIO; const md: PEVP_MD); cdecl;

begin
  {define BIO_set_md(b,md)  BIO_ctrl(b,BIO_C_SET_MD,0,(char *)(md))}
  BIO_ctrl(v1,BIO_C_SET_MD,0,PAnsiChar(md));
end;



function COMPAT_EVP_MD_CTX_new: PEVP_MD_CTX; cdecl;

begin
  Result := AllocMem(SizeOf(EVP_MD_CTX));
  EVP_MD_CTX_init(Result);
end;



procedure COMPAT_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;

begin
  EVP_MD_CTX_cleanup(ctx);
  FreeMem(ctx,SizeOf(EVP_MD_CTX));
end;


{$WARN  NO_RETVAL OFF}
{$IFNDEF OPENSSL_NO_MD2}
function COMPAT_EVP_md2: PEVP_MD; cdecl;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
function COMPAT_EVP_md4: PEVP_MD; cdecl;

begin
  EOpenSSLAPIFunctionNotPresent.RaiseException(ROSUnsupported);
end;

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
function COMPAT_EVP_md5: PEVP_MD; cdecl;

begin
  Result := EVP_md5_sha1;
end;

{$ENDIF}
{$WARN  NO_RETVAL ON}
function COMPAT_EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_get_security_bits(pkey);
end;



function COMPAT_EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;

begin
  Result := EVP_PKEY_get_size(pkey);
end;




{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign_RSA');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign_DSA');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign_DH');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: Pointer): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign_EC_KEY');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_assign_SIPHASH(pkey: PEVP_PKEY; shkey: Pointer): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign_SIPHASH');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_assign_POLY1305(pkey: PEVP_PKEY; polykey: Pointer): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign_POLY1305');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_EVP_MD_meth_new(md_type: TOpenSSL_C_INT; pkey_type: TOpenSSL_C_INT): PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_new');
end;

function ERROR_EVP_MD_meth_dup(const md: PEVP_MD): PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_dup');
end;

procedure ERROR_EVP_MD_meth_free(md: PEVP_MD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_free');
end;

function ERROR_EVP_MD_meth_set_input_blocksize(md: PEVP_MD; blocksize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_input_blocksize');
end;

function ERROR_EVP_MD_meth_set_result_size(md: PEVP_MD; resultsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_result_size');
end;

function ERROR_EVP_MD_meth_set_app_datasize(md: PEVP_MD; datasize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_app_datasize');
end;

function ERROR_EVP_MD_meth_set_flags(md: PEVP_MD; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_flags');
end;

function ERROR_EVP_MD_meth_set_init(md: PEVP_MD; init: EVP_MD_meth_init): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_init');
end;

function ERROR_EVP_MD_meth_set_update(md: PEVP_MD; update: EVP_MD_meth_update): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_update');
end;

function ERROR_EVP_MD_meth_set_final(md: PEVP_MD; final_: EVP_MD_meth_final): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_final');
end;

function ERROR_EVP_MD_meth_set_copy(md: PEVP_MD; copy: EVP_MD_meth_copy): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_copy');
end;

function ERROR_EVP_MD_meth_set_cleanup(md: PEVP_MD; cleanup: EVP_MD_meth_cleanup): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_cleanup');
end;

function ERROR_EVP_MD_meth_set_ctrl(md: PEVP_MD; ctrl: EVP_MD_meth_ctrl): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_set_ctrl');
end;

function ERROR_EVP_MD_meth_get_input_blocksize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_input_blocksize');
end;

function ERROR_EVP_MD_meth_get_result_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_result_size');
end;

function ERROR_EVP_MD_meth_get_app_datasize(const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_app_datasize');
end;

function ERROR_EVP_MD_meth_get_flags(const md: PEVP_MD): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_flags');
end;

function ERROR_EVP_MD_meth_get_init(const md: PEVP_MD): EVP_MD_meth_init; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_init');
end;

function ERROR_EVP_MD_meth_get_update(const md: PEVP_MD): EVP_MD_meth_update; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_update');
end;

function ERROR_EVP_MD_meth_get_final(const md: PEVP_MD): EVP_MD_meth_final; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_final');
end;

function ERROR_EVP_MD_meth_get_copy(const md: PEVP_MD): EVP_MD_meth_copy; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_copy');
end;

function ERROR_EVP_MD_meth_get_cleanup(const md: PEVP_MD): EVP_MD_meth_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_cleanup');
end;

function ERROR_EVP_MD_meth_get_ctrl(const md: PEVP_MD): EVP_MD_meth_ctrl; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_meth_get_ctrl');
end;

function ERROR_EVP_CIPHER_meth_new(cipher_type: TOpenSSL_C_INT; block_size: TOpenSSL_C_INT; key_len: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_new');
end;

function ERROR_EVP_CIPHER_meth_dup(const cipher: PEVP_CIPHER): PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_dup');
end;

procedure ERROR_EVP_CIPHER_meth_free(cipher: PEVP_CIPHER); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_free');
end;

function ERROR_EVP_CIPHER_meth_set_iv_length(cipher: PEVP_CIPHER; iv_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_iv_length');
end;

function ERROR_EVP_CIPHER_meth_set_flags(cipher: PEVP_CIPHER; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_flags');
end;

function ERROR_EVP_CIPHER_meth_set_impl_ctx_size(cipher: PEVP_CIPHER; ctx_size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_impl_ctx_size');
end;

function ERROR_EVP_CIPHER_meth_set_init(cipher: PEVP_CIPHER; init: EVP_CIPHER_meth_init): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_init');
end;

function ERROR_EVP_CIPHER_meth_set_do_cipher(cipher: PEVP_CIPHER; do_cipher: EVP_CIPHER_meth_do_cipher): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_do_cipher');
end;

function ERROR_EVP_CIPHER_meth_set_cleanup(cipher: PEVP_CIPHER; cleanup: EVP_CIPHER_meth_cleanup): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_cleanup');
end;

function ERROR_EVP_CIPHER_meth_set_set_asn1_params(cipher: PEVP_CIPHER; set_asn1_parameters: EVP_CIPHER_meth_set_asn1_params): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_set_asn1_params');
end;

function ERROR_EVP_CIPHER_meth_set_get_asn1_params(cipher: PEVP_CIPHER; get_asn1_parameters: EVP_CIPHER_meth_get_asn1_params): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_get_asn1_params');
end;

function ERROR_EVP_CIPHER_meth_set_ctrl(cipher: PEVP_CIPHER; ctrl: EVP_CIPHER_meth_ctrl): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_set_ctrl');
end;

function ERROR_EVP_CIPHER_meth_get_init(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_init; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_init');
end;

function ERROR_EVP_CIPHER_meth_get_do_cipher(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_do_cipher; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_do_cipher');
end;

function ERROR_EVP_CIPHER_meth_get_cleanup(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_cleanup');
end;

function ERROR_EVP_CIPHER_meth_get_set_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_set_asn1_params; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_set_asn1_params');
end;

function ERROR_EVP_CIPHER_meth_get_get_asn1_params(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_get_asn1_params; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_get_asn1_params');
end;

function ERROR_EVP_CIPHER_meth_get_ctrl(const cipher: PEVP_CIPHER): EVP_CIPHER_meth_ctrl; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_meth_get_ctrl');
end;

function ERROR_EVP_MD_type(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_type');
end;

function ERROR_EVP_MD_pkey_type(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_pkey_type');
end;

function ERROR_EVP_MD_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_size');
end;

function ERROR_EVP_MD_block_size(const md: PEVP_MD): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_block_size');
end;

function ERROR_EVP_MD_flags(const md: PEVP_MD): POpenSSL_C_ULONG; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_flags');
end;

function ERROR_EVP_MD_CTX_md(ctx: PEVP_MD_CTX): PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_md');
end;

function ERROR_EVP_MD_CTX_update_fn(ctx: PEVP_MD_CTX): EVP_MD_CTX_update; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_update_fn');
end;

procedure ERROR_EVP_MD_CTX_set_update_fn(ctx: PEVP_MD_CTX; update: EVP_MD_CTX_update); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_update_fn');
end;

function ERROR_EVP_MD_CTX_pkey_ctx(const ctx: PEVP_MD_CTX): PEVP_PKEY_CTX; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_pkey_ctx');
end;

procedure ERROR_EVP_MD_CTX_set_pkey_ctx(ctx: PEVP_MD_CTX; pctx: PEVP_PKEY_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_pkey_ctx');
end;

function ERROR_EVP_MD_CTX_md_data(const ctx: PEVP_MD_CTX): Pointer; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_md_data');
end;

function ERROR_EVP_CIPHER_nid(const ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_nid');
end;

function ERROR_EVP_CIPHER_block_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_block_size');
end;

function ERROR_EVP_CIPHER_impl_ctx_size(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_impl_ctx_size');
end;

function ERROR_EVP_CIPHER_key_length(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_key_length');
end;

function ERROR_EVP_CIPHER_iv_length(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_iv_length');
end;

function ERROR_EVP_CIPHER_flags(const cipher: PEVP_CIPHER): TOpenSSL_C_ULONG; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_flags');
end;

function ERROR_EVP_CIPHER_CTX_cipher(const ctx: PEVP_CIPHER_CTX): PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_cipher');
end;

function ERROR_EVP_CIPHER_CTX_encrypting(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_encrypting');
end;

function ERROR_EVP_CIPHER_CTX_nid(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_nid');
end;

function ERROR_EVP_CIPHER_CTX_block_size(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_block_size');
end;

function ERROR_EVP_CIPHER_CTX_key_length(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_key_length');
end;

function ERROR_EVP_CIPHER_CTX_iv_length(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv_length');
end;

function ERROR_EVP_CIPHER_CTX_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv');
end;

function ERROR_EVP_CIPHER_CTX_original_iv(const ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_original_iv');
end;

function ERROR_EVP_CIPHER_CTX_iv_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_iv_noconst');
end;

function ERROR_EVP_CIPHER_CTX_buf_noconst(ctx: PEVP_CIPHER_CTX): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_buf_noconst');
end;

function ERROR_EVP_CIPHER_CTX_num(const ctx: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_num');
end;

procedure ERROR_EVP_CIPHER_CTX_set_num(ctx: PEVP_CIPHER_CTX; num: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_num');
end;

function ERROR_EVP_CIPHER_CTX_copy(out_: PEVP_CIPHER_CTX; const in_: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_copy');
end;

function ERROR_EVP_CIPHER_CTX_get_app_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_app_data');
end;

procedure ERROR_EVP_CIPHER_CTX_set_app_data(ctx: PEVP_CIPHER_CTX; data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_app_data');
end;

function ERROR_EVP_CIPHER_CTX_get_cipher_data(const ctx: PEVP_CIPHER_CTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_get_cipher_data');
end;

function ERROR_EVP_CIPHER_CTX_set_cipher_data(ctx: PEVP_CIPHER_CTX; cipher_data: Pointer): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_cipher_data');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_BIO_set_md(v1: PBIO; const md: PEVP_MD); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_md');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

procedure ERROR_EVP_MD_CTX_init(ctx : PEVP_MD_CTX); cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_init');
end;

function ERROR_EVP_MD_CTX_cleanup(ctx : PEVP_MD_CTX): TOpenSSL_C_INT; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_cleanup');
end;

function ERROR_EVP_MD_CTX_ctrl(ctx: PEVP_MD_CTX; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_ctrl');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_MD_CTX_new: PEVP_MD_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_new');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_EVP_MD_CTX_reset(ctx: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_reset');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_EVP_MD_CTX_free(ctx: PEVP_MD_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_free');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_EVP_MD_CTX_copy_ex(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_copy_ex');
end;

procedure ERROR_EVP_MD_CTX_set_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_set_flags');
end;

procedure ERROR_EVP_MD_CTX_clear_flags(ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_clear_flags');
end;

function ERROR_EVP_MD_CTX_test_flags(const ctx: PEVP_MD_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_test_flags');
end;

function ERROR_EVP_DigestInit_ex(ctx: PEVP_MD_CTX; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestInit_ex');
end;

function ERROR_EVP_DigestUpdate(ctx: PEVP_MD_CTX; const d: Pointer; cnt: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestUpdate');
end;

function ERROR_EVP_DigestFinal_ex(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinal_ex');
end;

function ERROR_EVP_Digest(const data: Pointer; count: TOpenSSL_C_SIZET; md: PByte; size: POpenSSL_C_UINT; const type_: PEVP_MD; impl: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_Digest');
end;

function ERROR_EVP_MD_CTX_copy(out_: PEVP_MD_CTX; const in_: PEVP_MD_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_CTX_copy');
end;

function ERROR_EVP_DigestInit(ctx: PEVP_MD_CTX; const type_: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestInit');
end;

function ERROR_EVP_DigestFinal(ctx: PEVP_MD_CTX; md: PByte; var s: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinal');
end;

function ERROR_EVP_DigestFinalXOF(ctx: PEVP_MD_CTX; md: PByte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestFinalXOF');
end;

function ERROR_EVP_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_read_pw_string');
end;

function ERROR_EVP_read_pw_string_min(buf: PAnsiChar; minlen: TOpenSSL_C_INT; maxlen: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_read_pw_string_min');
end;

procedure ERROR_EVP_set_pw_prompt(const prompt: PAnsiChar); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_set_pw_prompt');
end;

function ERROR_EVP_get_pw_prompt: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_pw_prompt');
end;

function ERROR_EVP_BytesToKey(const type_: PEVP_CIPHER; const md: PEVP_MD; const salt: PByte; const data: PByte; data1: TOpenSSL_C_INT; count: TOpenSSL_C_INT; key: PByte; iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_BytesToKey');
end;

procedure ERROR_EVP_CIPHER_CTX_set_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_flags');
end;

procedure ERROR_EVP_CIPHER_CTX_clear_flags(ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_clear_flags');
end;

function ERROR_EVP_CIPHER_CTX_test_flags(const ctx: PEVP_CIPHER_CTX; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_test_flags');
end;

function ERROR_EVP_EncryptInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptInit');
end;

function ERROR_EVP_EncryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptInit_ex');
end;

function ERROR_EVP_EncryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptUpdate');
end;

function ERROR_EVP_EncryptFinal_ex(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptFinal_ex');
end;

function ERROR_EVP_EncryptFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncryptFinal');
end;

function ERROR_EVP_DecryptInit(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptInit');
end;

function ERROR_EVP_DecryptInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptInit_ex');
end;

function ERROR_EVP_DecryptUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in_1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptUpdate');
end;

function ERROR_EVP_DecryptFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptFinal');
end;

function ERROR_EVP_DecryptFinal_ex(ctx: PEVP_MD_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecryptFinal_ex');
end;

function ERROR_EVP_CipherInit(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit');
end;

function ERROR_EVP_CipherInit_ex(ctx: PEVP_CIPHER_CTX; const cipher: PEVP_CIPHER; impl: PENGINE; const key: PByte; const iv: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherInit_ex');
end;

function ERROR_EVP_CipherUpdate(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherUpdate');
end;

function ERROR_EVP_CipherFinal(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherFinal');
end;

function ERROR_EVP_CipherFinal_ex(ctx: PEVP_CIPHER_CTX; outm: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CipherFinal_ex');
end;

function ERROR_EVP_SignFinal(ctx: PEVP_CIPHER_CTX; md: PByte; s: POpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SignFinal');
end;

function ERROR_EVP_DigestSign(ctx: PEVP_CIPHER_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSign');
end;

function ERROR_EVP_VerifyFinal(ctx: PEVP_MD_CTX; const sigbuf: PByte; siglen: TOpenSSL_C_UINT; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_VerifyFinal');
end;

function ERROR_EVP_DigestVerify(ctx: PEVP_CIPHER_CTX; const sigret: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerify');
end;

function ERROR_EVP_DigestSignInit(ctx: PEVP_MD_CTX; pctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignInit');
end;

function ERROR_EVP_DigestSignFinal(ctx: PEVP_MD_CTX; sigret: PByte; siglen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestSignFinal');
end;

function ERROR_EVP_DigestVerifyInit(ctx: PEVP_MD_CTX; ppctx: PPEVP_PKEY_CTX; const type_: PEVP_MD; e: PENGINE; pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyInit');
end;

function ERROR_EVP_DigestVerifyFinal(ctx: PEVP_MD_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DigestVerifyFinal');
end;

function ERROR_EVP_OpenInit(ctx: PEVP_CIPHER_CTX; const type_: PEVP_CIPHER; const ek: PByte; ek1: TOpenSSL_C_INT; const iv: PByte; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_OpenInit');
end;

function ERROR_EVP_OpenFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_OpenFinal');
end;

function ERROR_EVP_SealInit(ctx: PEVP_CIPHER_CTX; const type_: EVP_CIPHER; ek: PPByte; ek1: POpenSSL_C_INT; iv: PByte; pubk: PPEVP_PKEY; npubk: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SealInit');
end;

function ERROR_EVP_SealFinal(ctx: PEVP_CIPHER_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_SealFinal');
end;

function ERROR_EVP_ENCODE_CTX_new: PEVP_ENCODE_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_new');
end;

procedure ERROR_EVP_ENCODE_CTX_free(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_free');
end;

function ERROR_EVP_ENCODE_CTX_copy(dctx: PEVP_ENCODE_CTX; sctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_copy');
end;

function ERROR_EVP_ENCODE_CTX_num(ctx: PEVP_ENCODE_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_ENCODE_CTX_num');
end;

procedure ERROR_EVP_EncodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeInit');
end;

function ERROR_EVP_EncodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeUpdate');
end;

procedure ERROR_EVP_EncodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeFinal');
end;

function ERROR_EVP_EncodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_EncodeBlock');
end;

procedure ERROR_EVP_DecodeInit(ctx: PEVP_ENCODE_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeInit');
end;

function ERROR_EVP_DecodeUpdate(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT; const in_: PByte; in1: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeUpdate');
end;

function ERROR_EVP_DecodeFinal(ctx: PEVP_ENCODE_CTX; out_: PByte; out1: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeFinal');
end;

function ERROR_EVP_DecodeBlock(t: PByte; const f: PByte; n: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_DecodeBlock');
end;

function ERROR_EVP_CIPHER_CTX_new: PEVP_CIPHER_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_new');
end;

function ERROR_EVP_CIPHER_CTX_reset(c: PEVP_CIPHER_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_reset');
end;

procedure ERROR_EVP_CIPHER_CTX_free(c: PEVP_CIPHER_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_free');
end;

function ERROR_EVP_CIPHER_CTX_set_key_length(x: PEVP_CIPHER_CTX; keylen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_key_length');
end;

function ERROR_EVP_CIPHER_CTX_set_padding(c: PEVP_CIPHER_CTX; pad: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_set_padding');
end;

function ERROR_EVP_CIPHER_CTX_ctrl(ctx: PEVP_CIPHER_CTX; type_: TOpenSSL_C_INT; arg: TOpenSSL_C_INT; ptr: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_ctrl');
end;

function ERROR_EVP_CIPHER_CTX_rand_key(ctx: PEVP_CIPHER_CTX; key: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_CTX_rand_key');
end;

function ERROR_BIO_f_md: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_md');
end;

function ERROR_BIO_f_base64: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_base64');
end;

function ERROR_BIO_f_cipher: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_cipher');
end;

function ERROR_BIO_f_reliable: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_reliable');
end;

function ERROR_BIO_set_cipher(b: PBIO; c: PEVP_CIPHER; const k: PByte; const i: PByte; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_cipher');
end;

function ERROR_EVP_md_null: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md_null');
end;

{$IFNDEF OPENSSL_NO_MD2}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$ENDIF}
function ERROR_EVP_md5_sha1: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_md5_sha1');
end;

function ERROR_EVP_sha1: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha1');
end;

function ERROR_EVP_sha224: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha224');
end;

function ERROR_EVP_sha256: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha256');
end;

function ERROR_EVP_sha384: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha384');
end;

function ERROR_EVP_sha512: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512');
end;

function ERROR_EVP_sha512_224: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512_224');
end;

function ERROR_EVP_sha512_256: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha512_256');
end;

function ERROR_EVP_sha3_224: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_224');
end;

function ERROR_EVP_sha3_256: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_256');
end;

function ERROR_EVP_sha3_384: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_384');
end;

function ERROR_EVP_sha3_512: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sha3_512');
end;

function ERROR_EVP_shake128: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_shake128');
end;

function ERROR_EVP_shake256: PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_shake256');
end;

function ERROR_EVP_enc_null: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_enc_null');
end;

function ERROR_EVP_des_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ecb');
end;

function ERROR_EVP_des_ede: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede');
end;

function ERROR_EVP_des_ede3: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3');
end;

function ERROR_EVP_des_ede_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_ecb');
end;

function ERROR_EVP_des_ede3_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_ecb');
end;

function ERROR_EVP_des_cfb64: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb64');
end;

function ERROR_EVP_des_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb1');
end;

function ERROR_EVP_des_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cfb8');
end;

function ERROR_EVP_des_ede_cfb64: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_cfb64');
end;

function ERROR_EVP_des_ede3_cfb64: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb64');
end;

function ERROR_EVP_des_ede3_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb1');
end;

function ERROR_EVP_des_ede3_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cfb8');
end;

function ERROR_EVP_des_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ofb');
end;

function ERROR_EVP_des_ede_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_ofb');
end;

function ERROR_EVP_des_ede3_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_ofb');
end;

function ERROR_EVP_des_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_cbc');
end;

function ERROR_EVP_des_ede_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede_cbc');
end;

function ERROR_EVP_des_ede3_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_cbc');
end;

function ERROR_EVP_desx_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_desx_cbc');
end;

function ERROR_EVP_des_ede3_wrap: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_des_ede3_wrap');
end;

function ERROR_EVP_rc4: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc4');
end;

function ERROR_EVP_rc4_40: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc4_40');
end;

function ERROR_EVP_rc2_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_ecb');
end;

function ERROR_EVP_rc2_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_cbc');
end;

function ERROR_EVP_rc2_40_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_40_cbc');
end;

function ERROR_EVP_rc2_64_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_64_cbc');
end;

function ERROR_EVP_rc2_cfb64: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_cfb64');
end;

function ERROR_EVP_rc2_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_rc2_ofb');
end;

function ERROR_EVP_bf_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_ecb');
end;

function ERROR_EVP_bf_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_cbc');
end;

function ERROR_EVP_bf_cfb64: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_cfb64');
end;

function ERROR_EVP_bf_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_bf_ofb');
end;

function ERROR_EVP_cast5_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_ecb');
end;

function ERROR_EVP_cast5_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_cbc');
end;

function ERROR_EVP_cast5_cfb64: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_cfb64');
end;

function ERROR_EVP_cast5_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cast5_ofb');
end;

function ERROR_EVP_aes_128_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ecb');
end;

function ERROR_EVP_aes_128_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc');
end;

function ERROR_EVP_aes_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb1');
end;

function ERROR_EVP_aes_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb8');
end;

function ERROR_EVP_aes_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cfb128');
end;

function ERROR_EVP_aes_128_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ofb');
end;

function ERROR_EVP_aes_128_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ctr');
end;

function ERROR_EVP_aes_128_ccm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ccm');
end;

function ERROR_EVP_aes_128_gcm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_gcm');
end;

function ERROR_EVP_aes_128_xts: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_xts');
end;

function ERROR_EVP_aes_128_wrap: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_wrap');
end;

function ERROR_EVP_aes_128_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_wrap_pad');
end;

function ERROR_EVP_aes_128_ocb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_ocb');
end;

function ERROR_EVP_aes_192_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ecb');
end;

function ERROR_EVP_aes_192_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cbc');
end;

function ERROR_EVP_aes_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb1');
end;

function ERROR_EVP_aes_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb8');
end;

function ERROR_EVP_aes_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_cfb128');
end;

function ERROR_EVP_aes_192_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ofb');
end;

function ERROR_EVP_aes_192_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ctr');
end;

function ERROR_EVP_aes_192_ccm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ccm');
end;

function ERROR_EVP_aes_192_gcm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_gcm');
end;

function ERROR_EVP_aes_192_wrap: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_wrap');
end;

function ERROR_EVP_aes_192_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_wrap_pad');
end;

function ERROR_EVP_aes_192_ocb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_192_ocb');
end;

function ERROR_EVP_aes_256_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ecb');
end;

function ERROR_EVP_aes_256_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc');
end;

function ERROR_EVP_aes_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb1');
end;

function ERROR_EVP_aes_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb8');
end;

function ERROR_EVP_aes_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cfb128');
end;

function ERROR_EVP_aes_256_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ofb');
end;

function ERROR_EVP_aes_256_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ctr');
end;

function ERROR_EVP_aes_256_ccm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ccm');
end;

function ERROR_EVP_aes_256_gcm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_gcm');
end;

function ERROR_EVP_aes_256_xts: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_xts');
end;

function ERROR_EVP_aes_256_wrap: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_wrap');
end;

function ERROR_EVP_aes_256_wrap_pad: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_wrap_pad');
end;

function ERROR_EVP_aes_256_ocb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_ocb');
end;

function ERROR_EVP_aes_128_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc_hmac_sha1');
end;

function ERROR_EVP_aes_256_cbc_hmac_sha1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc_hmac_sha1');
end;

function ERROR_EVP_aes_128_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_128_cbc_hmac_sha256');
end;

function ERROR_EVP_aes_256_cbc_hmac_sha256: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aes_256_cbc_hmac_sha256');
end;

function ERROR_EVP_aria_128_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ecb');
end;

function ERROR_EVP_aria_128_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cbc');
end;

function ERROR_EVP_aria_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb1');
end;

function ERROR_EVP_aria_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb8');
end;

function ERROR_EVP_aria_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_cfb128');
end;

function ERROR_EVP_aria_128_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ctr');
end;

function ERROR_EVP_aria_128_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ofb');
end;

function ERROR_EVP_aria_128_gcm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_gcm');
end;

function ERROR_EVP_aria_128_ccm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_128_ccm');
end;

function ERROR_EVP_aria_192_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ecb');
end;

function ERROR_EVP_aria_192_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cbc');
end;

function ERROR_EVP_aria_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb1');
end;

function ERROR_EVP_aria_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb8');
end;

function ERROR_EVP_aria_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_cfb128');
end;

function ERROR_EVP_aria_192_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ctr');
end;

function ERROR_EVP_aria_192_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ofb');
end;

function ERROR_EVP_aria_192_gcm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_gcm');
end;

function ERROR_EVP_aria_192_ccm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_192_ccm');
end;

function ERROR_EVP_aria_256_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ecb');
end;

function ERROR_EVP_aria_256_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cbc');
end;

function ERROR_EVP_aria_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb1');
end;

function ERROR_EVP_aria_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb8');
end;

function ERROR_EVP_aria_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_cfb128');
end;

function ERROR_EVP_aria_256_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ctr');
end;

function ERROR_EVP_aria_256_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ofb');
end;

function ERROR_EVP_aria_256_gcm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_gcm');
end;

function ERROR_EVP_aria_256_ccm: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_aria_256_ccm');
end;

function ERROR_EVP_camellia_128_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ecb');
end;

function ERROR_EVP_camellia_128_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cbc');
end;

function ERROR_EVP_camellia_128_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb1');
end;

function ERROR_EVP_camellia_128_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb8');
end;

function ERROR_EVP_camellia_128_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_cfb128');
end;

function ERROR_EVP_camellia_128_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ofb');
end;

function ERROR_EVP_camellia_128_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_128_ctr');
end;

function ERROR_EVP_camellia_192_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ecb');
end;

function ERROR_EVP_camellia_192_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cbc');
end;

function ERROR_EVP_camellia_192_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb1');
end;

function ERROR_EVP_camellia_192_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb8');
end;

function ERROR_EVP_camellia_192_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_cfb128');
end;

function ERROR_EVP_camellia_192_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ofb');
end;

function ERROR_EVP_camellia_192_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_192_ctr');
end;

function ERROR_EVP_camellia_256_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ecb');
end;

function ERROR_EVP_camellia_256_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cbc');
end;

function ERROR_EVP_camellia_256_cfb1: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb1');
end;

function ERROR_EVP_camellia_256_cfb8: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb8');
end;

function ERROR_EVP_camellia_256_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_cfb128');
end;

function ERROR_EVP_camellia_256_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ofb');
end;

function ERROR_EVP_camellia_256_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_camellia_256_ctr');
end;

function ERROR_EVP_chacha20: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_chacha20');
end;

function ERROR_EVP_chacha20_poly1305: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_chacha20_poly1305');
end;

function ERROR_EVP_seed_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_ecb');
end;

function ERROR_EVP_seed_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_cbc');
end;

function ERROR_EVP_seed_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_cfb128');
end;

function ERROR_EVP_seed_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_seed_ofb');
end;

function ERROR_EVP_sm4_ecb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ecb');
end;

function ERROR_EVP_sm4_cbc: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_cbc');
end;

function ERROR_EVP_sm4_cfb128: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_cfb128');
end;

function ERROR_EVP_sm4_ofb: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ofb');
end;

function ERROR_EVP_sm4_ctr: PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_sm4_ctr');
end;

function ERROR_EVP_add_cipher(const cipher: PEVP_CIPHER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_cipher');
end;

function ERROR_EVP_add_digest(const digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_digest');
end;

function ERROR_EVP_get_cipherbyname(const name: PAnsiChar): PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_cipherbyname');
end;

function ERROR_EVP_get_digestbyname(const name: PAnsiChar): PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_get_digestbyname');
end;

procedure ERROR_EVP_CIPHER_do_all(AFn: fn; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_do_all');
end;

procedure ERROR_EVP_CIPHER_do_all_sorted(AFn: fn; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_do_all_sorted');
end;

procedure ERROR_EVP_MD_do_all(AFn: fn; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_do_all');
end;

procedure ERROR_EVP_MD_do_all_sorted(AFn: fn; arg: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_MD_do_all_sorted');
end;

function ERROR_EVP_PKEY_decrypt_old(dec_key: PByte; const enc_key: PByte; enc_key_len: TOpenSSL_C_INT; private_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt_old');
end;

function ERROR_EVP_PKEY_encrypt_old(dec_key: PByte; const enc_key: PByte; key_len: TOpenSSL_C_INT; pub_key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt_old');
end;

function ERROR_EVP_PKEY_type(type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_type');
end;

function ERROR_EVP_PKEY_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_id');
end;

function ERROR_EVP_PKEY_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_base_id');
end;

function ERROR_EVP_PKEY_get_base_id(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_base_id');
end;

function ERROR_EVP_PKEY_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_bits');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_security_bits');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_EVP_PKEY_get_security_bits(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_security_bits');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_EVP_PKEY_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_size');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_EVP_PKEY_get_size(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_size');
end;

function ERROR_EVP_PKEY_set_type(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_type');
end;

function ERROR_EVP_PKEY_set_type_str(pkey: PEVP_PKEY; const str: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_type_str');
end;

function ERROR_EVP_PKEY_set_alias_type(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set_alias_type');
end;

function ERROR_EVP_PKEY_set1_engine(pkey: PEVP_PKEY; e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_engine');
end;

function ERROR_EVP_PKEY_get0_engine(const pkey: PEVP_PKEY): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_engine');
end;

function ERROR_EVP_PKEY_assign(pkey: PEVP_PKEY; type_: TOpenSSL_C_INT; key: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_assign');
end;

function ERROR_EVP_PKEY_get0(const pkey: PEVP_PKEY): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0');
end;

function ERROR_EVP_PKEY_get0_hmac(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_hmac');
end;

function ERROR_EVP_PKEY_get0_poly1305(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_poly1305');
end;

function ERROR_EVP_PKEY_get0_siphash(const pkey: PEVP_PKEY; len: POpenSSL_C_SIZET): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_siphash');
end;

function ERROR_EVP_PKEY_set1_RSA(pkey: PEVP_PKEY; key: PRSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_RSA');
end;

function ERROR_EVP_PKEY_get0_RSA(pkey: PEVP_PKEY): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_RSA');
end;

function ERROR_EVP_PKEY_get1_RSA(pkey: PEVP_PKEY): PRSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_RSA');
end;

function ERROR_EVP_PKEY_set1_DSA(pkey: PEVP_PKEY; key: PDSA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_DSA');
end;

function ERROR_EVP_PKEY_get0_DSA(pkey: PEVP_PKEY): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_DSA');
end;

function ERROR_EVP_PKEY_get1_DSA(pkey: PEVP_PKEY): PDSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_DSA');
end;

function ERROR_EVP_PKEY_set1_DH(pkey: PEVP_PKEY; key: PDH): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_DH');
end;

function ERROR_EVP_PKEY_get0_DH(pkey: PEVP_PKEY): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_DH');
end;

function ERROR_EVP_PKEY_get1_DH(pkey: PEVP_PKEY): PDH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_DH');
end;

function ERROR_EVP_PKEY_set1_EC_KEY(pkey: PEVP_PKEY; key: PEC_KEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_EC_KEY');
end;

function ERROR_EVP_PKEY_get0_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_EC_KEY');
end;

function ERROR_EVP_PKEY_get1_EC_KEY(pkey: PEVP_PKEY): PEC_KEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_EC_KEY');
end;

function ERROR_EVP_PKEY_new: PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new');
end;

function ERROR_EVP_PKEY_up_ref(pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_up_ref');
end;

procedure ERROR_EVP_PKEY_free(pkey: PEVP_PKEY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_free');
end;

function ERROR_d2i_PublicKey(type_: TOpenSSL_C_INT; a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PublicKey');
end;

function ERROR_i2d_PublicKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PublicKey');
end;

function ERROR_d2i_PrivateKey(type_: TOpenSSL_C_INT; a: PEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_PrivateKey');
end;

function ERROR_d2i_AutoPrivateKey(a: PPEVP_PKEY; const pp: PPByte; length: TOpenSSL_C_LONG): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_AutoPrivateKey');
end;

function ERROR_i2d_PrivateKey(a: PEVP_PKEY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_PrivateKey');
end;

function ERROR_EVP_PKEY_copy_parameters(to_: PEVP_PKEY; const from: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_copy_parameters');
end;

function ERROR_EVP_PKEY_missing_parameters(const pkey: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_missing_parameters');
end;

function ERROR_EVP_PKEY_save_parameters(pkey: PEVP_PKEY; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_save_parameters');
end;

function ERROR_EVP_PKEY_cmp_parameters(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_cmp_parameters');
end;

function ERROR_EVP_PKEY_cmp(const a: PEVP_PKEY; const b: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_cmp');
end;

function ERROR_EVP_PKEY_print_public(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_public');
end;

function ERROR_EVP_PKEY_print_private(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_private');
end;

function ERROR_EVP_PKEY_print_params(out_: PBIO; const pkey: PEVP_PKEY; indent: TOpenSSL_C_INT; pctx: PASN1_PCTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_print_params');
end;

function ERROR_EVP_PKEY_get_default_digest_nid(pkey: PEVP_PKEY; pnid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_default_digest_nid');
end;

function ERROR_EVP_PKEY_set1_tls_encodedpoint(pkey: PEVP_PKEY; const pt: PByte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_set1_tls_encodedpoint');
end;

function ERROR_EVP_PKEY_get1_tls_encodedpoint(pkey: PEVP_PKEY; ppt: PPByte): TOpenSSL_C_SIZET; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get1_tls_encodedpoint');
end;

function ERROR_EVP_CIPHER_type(const ctx: PEVP_CIPHER): TOpenSSL_C_INT; cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_type');
end;

function ERROR_EVP_CIPHER_param_to_asn1(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_param_to_asn1');
end;

function ERROR_EVP_CIPHER_asn1_to_param(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_asn1_to_param');
end;

function ERROR_EVP_CIPHER_set_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_set_asn1_iv');
end;

function ERROR_EVP_CIPHER_get_asn1_iv(c: PEVP_CIPHER_CTX; type_: PASN1_TYPE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_CIPHER_get_asn1_iv');
end;

function ERROR_PKCS5_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBE_keyivgen');
end;

function ERROR_PKCS5_PBKDF2_HMAC_SHA1(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBKDF2_HMAC_SHA1');
end;

function ERROR_PKCS5_PBKDF2_HMAC(const pass: PAnsiChar; passlen: TOpenSSL_C_INT; const salt: PByte; saltlen: TOpenSSL_C_INT; iter: TOpenSSL_C_INT; const digest: PEVP_MD; keylen: TOpenSSL_C_INT; out_: PByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBKDF2_HMAC');
end;

function ERROR_PKCS5_v2_PBE_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const cipher: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_PBE_keyivgen');
end;

function ERROR_EVP_PBE_scrypt(const pass: PAnsiChar; passlen: TOpenSSL_C_SIZET; const salt: PByte; saltlen: TOpenSSL_C_SIZET; N: TOpenSSL_C_UINT64; r: TOpenSSL_C_UINT64; p: TOpenSSL_C_UINT64; maxmem: TOpenSSL_C_UINT64; key: PByte; keylen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_scrypt');
end;

function ERROR_PKCS5_v2_scrypt_keyivgen(ctx: PEVP_CIPHER_CTX; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; const c: PEVP_CIPHER; const md: PEVP_MD; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_v2_scrypt_keyivgen');
end;

procedure ERROR_PKCS5_PBE_add; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS5_PBE_add');
end;

function ERROR_EVP_PBE_CipherInit(pbe_obj: PASN1_OBJECT; const pass: PAnsiChar; passlen: TOpenSSL_C_INT; param: PASN1_TYPE; ctx: PEVP_CIPHER_CTX; en_de: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_CipherInit');
end;

function ERROR_EVP_PBE_alg_add_type(pbe_type: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; cipher_nid: TOpenSSL_C_INT; md_nid: TOpenSSL_C_INT; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_alg_add_type');
end;

function ERROR_EVP_PBE_alg_add(nid: TOpenSSL_C_INT; const cipher: PEVP_CIPHER; const md: PEVP_MD; keygen: PEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_alg_add');
end;

function ERROR_EVP_PBE_find(type_: TOpenSSL_C_INT; pbe_nid: TOpenSSL_C_INT; pcnid: POpenSSL_C_INT; pmnid: POpenSSL_C_INT; pkeygen: PPEVP_PBE_KEYGEN): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_find');
end;

procedure ERROR_EVP_PBE_cleanup; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_cleanup');
end;

function ERROR_EVP_PBE_get(ptype: POpenSSL_C_INT; ppbe_nid: POpenSSL_C_INT; num: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PBE_get');
end;

function ERROR_EVP_PKEY_asn1_get_count: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get_count');
end;

function ERROR_EVP_PKEY_asn1_get0(idx: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get0');
end;

function ERROR_EVP_PKEY_asn1_find(pe: PPENGINE; type_: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_find');
end;

function ERROR_EVP_PKEY_asn1_find_str(pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_find_str');
end;

function ERROR_EVP_PKEY_asn1_add0(const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_add0');
end;

function ERROR_EVP_PKEY_asn1_add_alias(to_: TOpenSSL_C_INT; from: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_add_alias');
end;

function ERROR_EVP_PKEY_asn1_get0_info(ppkey_id: POpenSSL_C_INT; pkey_base_id: POpenSSL_C_INT; ppkey_flags: POpenSSL_C_INT; const pinfo: PPAnsiChar; const ppem_str: PPAnsiChar; const ameth: PEVP_PKEY_ASN1_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_get0_info');
end;

function ERROR_EVP_PKEY_get0_asn1(const pkey: PEVP_PKEY): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get0_asn1');
end;

function ERROR_EVP_PKEY_asn1_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT; const pem_str: PAnsiChar; const info: PAnsiChar): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_new');
end;

procedure ERROR_EVP_PKEY_asn1_copy(dst: PEVP_PKEY_ASN1_METHOD; const src: PEVP_PKEY_ASN1_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_copy');
end;

procedure ERROR_EVP_PKEY_asn1_free(ameth: PEVP_PKEY_ASN1_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_free');
end;

procedure ERROR_EVP_PKEY_asn1_set_public(ameth: PEVP_PKEY_ASN1_METHOD; APub_decode: pub_decode; APub_encode: pub_encode; APub_cmd: pub_cmd; APub_print: pub_print; APkey_size: pkey_size; APkey_bits: pkey_bits); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_public');
end;

procedure ERROR_EVP_PKEY_asn1_set_private(ameth: PEVP_PKEY_ASN1_METHOD; APriv_decode: priv_decode; APriv_encode: priv_encode; APriv_print: priv_print); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_private');
end;

procedure ERROR_EVP_PKEY_asn1_set_param(ameth: PEVP_PKEY_ASN1_METHOD; AParam_decode: param_decode; AParam_encode: param_encode; AParam_missing: param_missing; AParam_copy: param_copy; AParam_cmp: param_cmp; AParam_print: param_print); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_param');
end;

procedure ERROR_EVP_PKEY_asn1_set_free(ameth: PEVP_PKEY_ASN1_METHOD; APkey_free: pkey_free); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_free');
end;

procedure ERROR_EVP_PKEY_asn1_set_ctrl(ameth: PEVP_PKEY_ASN1_METHOD; APkey_ctrl: pkey_ctrl); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_ctrl');
end;

procedure ERROR_EVP_PKEY_asn1_set_item(ameth: PEVP_PKEY_ASN1_METHOD; AItem_verify: item_verify; AItem_sign: item_sign); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_item');
end;

procedure ERROR_EVP_PKEY_asn1_set_siginf(ameth: PEVP_PKEY_ASN1_METHOD; ASiginf_set: siginf_set); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_siginf');
end;

procedure ERROR_EVP_PKEY_asn1_set_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_check: pkey_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_check');
end;

procedure ERROR_EVP_PKEY_asn1_set_public_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_pub_check: pkey_pub_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_public_check');
end;

procedure ERROR_EVP_PKEY_asn1_set_param_check(ameth: PEVP_PKEY_ASN1_METHOD; APkey_param_check: pkey_param_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_param_check');
end;

procedure ERROR_EVP_PKEY_asn1_set_set_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_priv_key: set_priv_key); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_set_priv_key');
end;

procedure ERROR_EVP_PKEY_asn1_set_set_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; ASet_pub_key: set_pub_key); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_set_pub_key');
end;

procedure ERROR_EVP_PKEY_asn1_set_get_priv_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_priv_key: get_priv_key); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_get_priv_key');
end;

procedure ERROR_EVP_PKEY_asn1_set_get_pub_key(ameth: PEVP_PKEY_ASN1_METHOD; AGet_pub_key: get_pub_key); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_get_pub_key');
end;

procedure ERROR_EVP_PKEY_asn1_set_security_bits(ameth: PEVP_PKEY_ASN1_METHOD; APkey_security_bits: pkey_security_bits); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_asn1_set_security_bits');
end;

function ERROR_EVP_PKEY_meth_find(type_: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_find');
end;

function ERROR_EVP_PKEY_meth_new(id: TOpenSSL_C_INT; flags: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_new');
end;

procedure ERROR_EVP_PKEY_meth_get0_info(ppkey_id: POpenSSL_C_INT; pflags: POpenSSL_C_INT; const meth: PEVP_PKEY_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get0_info');
end;

procedure ERROR_EVP_PKEY_meth_copy(dst: PEVP_PKEY_METHOD; const src: PEVP_PKEY_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_copy');
end;

procedure ERROR_EVP_PKEY_meth_free(pmeth: PEVP_PKEY_METHOD); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_free');
end;

function ERROR_EVP_PKEY_meth_add0(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_add0');
end;

function ERROR_EVP_PKEY_meth_remove(const pmeth: PEVP_PKEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_remove');
end;

function ERROR_EVP_PKEY_meth_get_count: TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_count');
end;

function ERROR_EVP_PKEY_meth_get0(idx: TOpenSSL_C_SIZET): PEVP_PKEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get0');
end;

function ERROR_EVP_PKEY_CTX_new(pkey: PEVP_PKEY; e: PENGINE): PEVP_PKEY_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new');
end;

function ERROR_EVP_PKEY_CTX_new_id(id: TOpenSSL_C_INT; e: PENGINE): PEVP_PKEY_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_new_id');
end;

function ERROR_EVP_PKEY_CTX_dup(ctx: PEVP_PKEY_CTX): PEVP_PKEY_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_dup');
end;

procedure ERROR_EVP_PKEY_CTX_free(ctx: PEVP_PKEY_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_free');
end;

function ERROR_EVP_PKEY_CTX_ctrl(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl');
end;

function ERROR_EVP_PKEY_CTX_ctrl_str(ctx: PEVP_PKEY_CTX; const type_: PAnsiChar; const value: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl_str');
end;

function ERROR_EVP_PKEY_CTX_ctrl_uint64(ctx: PEVP_PKEY_CTX; keytype: TOpenSSL_C_INT; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; value: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_ctrl_uint64');
end;

function ERROR_EVP_PKEY_CTX_str2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const str: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_str2ctrl');
end;

function ERROR_EVP_PKEY_CTX_hex2ctrl(ctx: PEVP_PKEY_CTX; cmd: TOpenSSL_C_INT; const hex: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_hex2ctrl');
end;

function ERROR_EVP_PKEY_CTX_md(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; const md: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_md');
end;

function ERROR_EVP_PKEY_CTX_get_operation(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_operation');
end;

procedure ERROR_EVP_PKEY_CTX_set0_keygen_info(ctx: PEVP_PKEY_CTX; dat: POpenSSL_C_INT; datlen: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set0_keygen_info');
end;

function ERROR_EVP_PKEY_new_mac_key(type_: TOpenSSL_C_INT; e: PENGINE; const key: PByte; keylen: TOpenSSL_C_INT): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_mac_key');
end;

function ERROR_EVP_PKEY_new_raw_private_key(type_: TOpenSSL_C_INT; e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_private_key');
end;

function ERROR_EVP_PKEY_new_raw_public_key(type_: TOpenSSL_C_INT; e: PENGINE; const pub: PByte; len: TOpenSSL_C_SIZET): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_raw_public_key');
end;

function ERROR_EVP_PKEY_get_raw_private_key(const pkey: PEVP_PKEY; priv: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_raw_private_key');
end;

function ERROR_EVP_PKEY_get_raw_public_key(const pkey: PEVP_PKEY; pub: PByte; len: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_get_raw_public_key');
end;

function ERROR_EVP_PKEY_new_CMAC_key(e: PENGINE; const priv: PByte; len: TOpenSSL_C_SIZET; const cipher: PEVP_CIPHER): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_new_CMAC_key');
end;

procedure ERROR_EVP_PKEY_CTX_set_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_data');
end;

function ERROR_EVP_PKEY_CTX_get_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_data');
end;

function ERROR_EVP_PKEY_CTX_get0_pkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_pkey');
end;

function ERROR_EVP_PKEY_CTX_get0_peerkey(ctx: PEVP_PKEY_CTX): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_peerkey');
end;

procedure ERROR_EVP_PKEY_CTX_set_app_data(ctx: PEVP_PKEY_CTX; data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_app_data');
end;

function ERROR_EVP_PKEY_CTX_get_app_data(ctx: PEVP_PKEY_CTX): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_app_data');
end;

function ERROR_EVP_PKEY_sign_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign_init');
end;

function ERROR_EVP_PKEY_sign(ctx: PEVP_PKEY_CTX; sig: PByte; siglen: POpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_sign');
end;

function ERROR_EVP_PKEY_verify_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_init');
end;

function ERROR_EVP_PKEY_verify(ctx: PEVP_PKEY_CTX; const sig: PByte; siglen: TOpenSSL_C_SIZET; const tbs: PByte; tbslen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify');
end;

function ERROR_EVP_PKEY_verify_recover_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover_init');
end;

function ERROR_EVP_PKEY_verify_recover(ctx: PEVP_PKEY_CTX; rout: PByte; routlen: POpenSSL_C_SIZET; const sig: PByte; siglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_verify_recover');
end;

function ERROR_EVP_PKEY_encrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt_init');
end;

function ERROR_EVP_PKEY_encrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_encrypt');
end;

function ERROR_EVP_PKEY_decrypt_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt_init');
end;

function ERROR_EVP_PKEY_decrypt(ctx: PEVP_PKEY_CTX; out_: PByte; outlen: POpenSSL_C_SIZET; const in_: PByte; inlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_decrypt');
end;

function ERROR_EVP_PKEY_derive_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_init');
end;

function ERROR_EVP_PKEY_derive_set_peer(ctx: PEVP_PKEY_CTX; peer: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive_set_peer');
end;

function ERROR_EVP_PKEY_derive(ctx: PEVP_PKEY_CTX; key: PByte; keylen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_derive');
end;

function ERROR_EVP_PKEY_paramgen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_paramgen_init');
end;

function ERROR_EVP_PKEY_paramgen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_paramgen');
end;

function ERROR_EVP_PKEY_keygen_init(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_keygen_init');
end;

function ERROR_EVP_PKEY_keygen(ctx: PEVP_PKEY_CTX; ppkey: PPEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_keygen');
end;

function ERROR_EVP_PKEY_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_check');
end;

function ERROR_EVP_PKEY_public_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_public_check');
end;

function ERROR_EVP_PKEY_param_check(ctx: PEVP_PKEY_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_param_check');
end;

procedure ERROR_EVP_PKEY_CTX_set_cb(ctx: PEVP_PKEY_CTX; cb: EVP_PKEY_gen_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_cb');
end;

function ERROR_EVP_PKEY_CTX_get_cb(ctx: PEVP_PKEY_CTX): EVP_PKEY_gen_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_cb');
end;

function ERROR_EVP_PKEY_CTX_get_keygen_info(ctx: PEVP_PKEY_CTX; idx: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_keygen_info');
end;

procedure ERROR_EVP_PKEY_meth_set_init(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: EVP_PKEY_meth_init); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_init');
end;

procedure ERROR_EVP_PKEY_meth_set_copy(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy_cb: EVP_PKEY_meth_copy_cb); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_copy');
end;

procedure ERROR_EVP_PKEY_meth_set_cleanup(pmeth: PEVP_PKEY_METHOD; PEVP_PKEY_meth_cleanup: EVP_PKEY_meth_cleanup); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_cleanup');
end;

procedure ERROR_EVP_PKEY_meth_set_paramgen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: EVP_PKEY_meth_paramgen_init); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_paramgen');
end;

procedure ERROR_EVP_PKEY_meth_set_keygen(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: EVP_PKEY_meth_keygen); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_keygen');
end;

procedure ERROR_EVP_PKEY_meth_set_sign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: EVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: EVP_PKEY_meth_sign); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_sign');
end;

procedure ERROR_EVP_PKEY_meth_set_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: EVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: EVP_PKEY_meth_verify_init); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verify');
end;

procedure ERROR_EVP_PKEY_meth_set_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: EVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: EVP_PKEY_meth_verify_recover_init); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verify_recover');
end;

procedure ERROR_EVP_PKEY_meth_set_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: EVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: EVP_PKEY_meth_signctx); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_signctx');
end;

procedure ERROR_EVP_PKEY_meth_set_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: EVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: EVP_PKEY_meth_verifyctx); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_verifyctx');
end;

procedure ERROR_EVP_PKEY_meth_set_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: EVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: EVP_PKEY_meth_encrypt); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_encrypt');
end;

procedure ERROR_EVP_PKEY_meth_set_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: EVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: EVP_PKEY_meth_decrypt); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_decrypt');
end;

procedure ERROR_EVP_PKEY_meth_set_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: EVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: EVP_PKEY_meth_derive); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_derive');
end;

procedure ERROR_EVP_PKEY_meth_set_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: EVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: EVP_PKEY_meth_ctrl_str); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_ctrl');
end;

procedure ERROR_EVP_PKEY_meth_set_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: EVP_PKEY_meth_digestsign); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digestsign');
end;

procedure ERROR_EVP_PKEY_meth_set_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: EVP_PKEY_meth_digestverify); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digestverify');
end;

procedure ERROR_EVP_PKEY_meth_set_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: EVP_PKEY_meth_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_check');
end;

procedure ERROR_EVP_PKEY_meth_set_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: EVP_PKEY_meth_public_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_public_check');
end;

procedure ERROR_EVP_PKEY_meth_set_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: EVP_PKEY_meth_param_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_param_check');
end;

procedure ERROR_EVP_PKEY_meth_set_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: EVP_PKEY_meth_digest_custom); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_set_digest_custom');
end;

procedure ERROR_EVP_PKEY_meth_get_init(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_init: PEVP_PKEY_meth_init); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_init');
end;

procedure ERROR_EVP_PKEY_meth_get_copy(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_copy: PEVP_PKEY_meth_copy); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_copy');
end;

procedure ERROR_EVP_PKEY_meth_get_cleanup(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_cleanup: PEVP_PKEY_meth_cleanup); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_cleanup');
end;

procedure ERROR_EVP_PKEY_meth_get_paramgen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_paramgen_init: EVP_PKEY_meth_paramgen_init; AEVP_PKEY_meth_paramgen: PEVP_PKEY_meth_paramgen); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_paramgen');
end;

procedure ERROR_EVP_PKEY_meth_get_keygen(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_keygen_init: EVP_PKEY_meth_keygen_init; AEVP_PKEY_meth_keygen: PEVP_PKEY_meth_keygen); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_keygen');
end;

procedure ERROR_EVP_PKEY_meth_get_sign(const pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_sign_init: PEVP_PKEY_meth_sign_init; AEVP_PKEY_meth_sign: PEVP_PKEY_meth_sign); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_sign');
end;

procedure ERROR_EVP_PKEY_meth_get_verify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_init: PEVP_PKEY_meth_verify_init; AEVP_PKEY_meth_verify: PEVP_PKEY_meth_verify_init); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verify');
end;

procedure ERROR_EVP_PKEY_meth_get_verify_recover(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verify_recover_init: PEVP_PKEY_meth_verify_recover_init; AEVP_PKEY_meth_verify_recover: PEVP_PKEY_meth_verify_recover_init); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verify_recover');
end;

procedure ERROR_EVP_PKEY_meth_get_signctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_signctx_init: PEVP_PKEY_meth_signctx_init; AEVP_PKEY_meth_signctx: PEVP_PKEY_meth_signctx); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_signctx');
end;

procedure ERROR_EVP_PKEY_meth_get_verifyctx(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_verifyctx_init: PEVP_PKEY_meth_verifyctx_init; AEVP_PKEY_meth_verifyctx: PEVP_PKEY_meth_verifyctx); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_verifyctx');
end;

procedure ERROR_EVP_PKEY_meth_get_encrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_encrypt_init: PEVP_PKEY_meth_encrypt_init; AEVP_PKEY_meth_encrypt: PEVP_PKEY_meth_encrypt); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_encrypt');
end;

procedure ERROR_EVP_PKEY_meth_get_decrypt(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_decrypt_init: PEVP_PKEY_meth_decrypt_init; AEVP_PKEY_meth_decrypt: PEVP_PKEY_meth_decrypt); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_decrypt');
end;

procedure ERROR_EVP_PKEY_meth_get_derive(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_derive_init: PEVP_PKEY_meth_derive_init; AEVP_PKEY_meth_derive: PEVP_PKEY_meth_derive); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_derive');
end;

procedure ERROR_EVP_PKEY_meth_get_ctrl(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_ctrl: PEVP_PKEY_meth_ctrl; AEVP_PKEY_meth_ctrl_str: PEVP_PKEY_meth_ctrl_str); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_ctrl');
end;

procedure ERROR_EVP_PKEY_meth_get_digestsign(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestsign: PEVP_PKEY_meth_digestsign); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digestsign');
end;

procedure ERROR_EVP_PKEY_meth_get_digestverify(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digestverify: PEVP_PKEY_meth_digestverify); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digestverify');
end;

procedure ERROR_EVP_PKEY_meth_get_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_check: PEVP_PKEY_meth_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_check');
end;

procedure ERROR_EVP_PKEY_meth_get_public_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_public_check: PEVP_PKEY_meth_public_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_public_check');
end;

procedure ERROR_EVP_PKEY_meth_get_param_check(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_param_check: PEVP_PKEY_meth_param_check); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_param_check');
end;

procedure ERROR_EVP_PKEY_meth_get_digest_custom(pmeth: PEVP_PKEY_METHOD; AEVP_PKEY_meth_digest_custom: PEVP_PKEY_meth_digest_custom); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_meth_get_digest_custom');
end;

procedure ERROR_EVP_add_alg_module; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_add_alg_module');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OpenSSL_add_all_ciphers; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_ciphers');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_OpenSSL_add_all_digests; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OpenSSL_add_all_digests');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_EVP_cleanup; cdecl; {removed 1.1.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_cleanup');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_assign_RSA := LoadLibCryptoFunction('EVP_PKEY_assign_RSA');
  FuncLoadError := not assigned(EVP_PKEY_assign_RSA);
  if FuncLoadError then
  begin
    EVP_PKEY_assign_RSA := @COMPAT_EVP_PKEY_assign_RSA;
    if EVP_PKEY_assign_RSA_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_RSA');
  end;

  EVP_PKEY_assign_DSA := LoadLibCryptoFunction('EVP_PKEY_assign_DSA');
  FuncLoadError := not assigned(EVP_PKEY_assign_DSA);
  if FuncLoadError then
  begin
    EVP_PKEY_assign_DSA := @COMPAT_EVP_PKEY_assign_DSA;
    if EVP_PKEY_assign_DSA_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_DSA');
  end;

  EVP_PKEY_assign_DH := LoadLibCryptoFunction('EVP_PKEY_assign_DH');
  FuncLoadError := not assigned(EVP_PKEY_assign_DH);
  if FuncLoadError then
  begin
    EVP_PKEY_assign_DH := @COMPAT_EVP_PKEY_assign_DH;
    if EVP_PKEY_assign_DH_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_DH');
  end;

  EVP_PKEY_assign_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_assign_EC_KEY');
  FuncLoadError := not assigned(EVP_PKEY_assign_EC_KEY);
  if FuncLoadError then
  begin
    EVP_PKEY_assign_EC_KEY := @COMPAT_EVP_PKEY_assign_EC_KEY;
    if EVP_PKEY_assign_EC_KEY_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_EC_KEY');
  end;

  EVP_PKEY_assign_SIPHASH := LoadLibCryptoFunction('EVP_PKEY_assign_SIPHASH');
  FuncLoadError := not assigned(EVP_PKEY_assign_SIPHASH);
  if FuncLoadError then
  begin
    EVP_PKEY_assign_SIPHASH := @COMPAT_EVP_PKEY_assign_SIPHASH;
    if EVP_PKEY_assign_SIPHASH_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_SIPHASH');
  end;

  EVP_PKEY_assign_POLY1305 := LoadLibCryptoFunction('EVP_PKEY_assign_POLY1305');
  FuncLoadError := not assigned(EVP_PKEY_assign_POLY1305);
  if FuncLoadError then
  begin
    EVP_PKEY_assign_POLY1305 := @COMPAT_EVP_PKEY_assign_POLY1305;
    if EVP_PKEY_assign_POLY1305_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_assign_POLY1305');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_meth_new := LoadLibCryptoFunction('EVP_MD_meth_new');
  FuncLoadError := not assigned(EVP_MD_meth_new);
  if FuncLoadError then
  begin
    EVP_MD_meth_new :=  @ERROR_EVP_MD_meth_new;
  end;

  EVP_MD_meth_dup := LoadLibCryptoFunction('EVP_MD_meth_dup');
  FuncLoadError := not assigned(EVP_MD_meth_dup);
  if FuncLoadError then
  begin
    EVP_MD_meth_dup :=  @ERROR_EVP_MD_meth_dup;
  end;

  EVP_MD_meth_free := LoadLibCryptoFunction('EVP_MD_meth_free');
  FuncLoadError := not assigned(EVP_MD_meth_free);
  if FuncLoadError then
  begin
    EVP_MD_meth_free :=  @ERROR_EVP_MD_meth_free;
  end;

  EVP_MD_meth_set_input_blocksize := LoadLibCryptoFunction('EVP_MD_meth_set_input_blocksize');
  FuncLoadError := not assigned(EVP_MD_meth_set_input_blocksize);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_input_blocksize :=  @ERROR_EVP_MD_meth_set_input_blocksize;
  end;

  EVP_MD_meth_set_result_size := LoadLibCryptoFunction('EVP_MD_meth_set_result_size');
  FuncLoadError := not assigned(EVP_MD_meth_set_result_size);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_result_size :=  @ERROR_EVP_MD_meth_set_result_size;
  end;

  EVP_MD_meth_set_app_datasize := LoadLibCryptoFunction('EVP_MD_meth_set_app_datasize');
  FuncLoadError := not assigned(EVP_MD_meth_set_app_datasize);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_app_datasize :=  @ERROR_EVP_MD_meth_set_app_datasize;
  end;

  EVP_MD_meth_set_flags := LoadLibCryptoFunction('EVP_MD_meth_set_flags');
  FuncLoadError := not assigned(EVP_MD_meth_set_flags);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_flags :=  @ERROR_EVP_MD_meth_set_flags;
  end;

  EVP_MD_meth_set_init := LoadLibCryptoFunction('EVP_MD_meth_set_init');
  FuncLoadError := not assigned(EVP_MD_meth_set_init);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_init :=  @ERROR_EVP_MD_meth_set_init;
  end;

  EVP_MD_meth_set_update := LoadLibCryptoFunction('EVP_MD_meth_set_update');
  FuncLoadError := not assigned(EVP_MD_meth_set_update);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_update :=  @ERROR_EVP_MD_meth_set_update;
  end;

  EVP_MD_meth_set_final := LoadLibCryptoFunction('EVP_MD_meth_set_final');
  FuncLoadError := not assigned(EVP_MD_meth_set_final);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_final :=  @ERROR_EVP_MD_meth_set_final;
  end;

  EVP_MD_meth_set_copy := LoadLibCryptoFunction('EVP_MD_meth_set_copy');
  FuncLoadError := not assigned(EVP_MD_meth_set_copy);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_copy :=  @ERROR_EVP_MD_meth_set_copy;
  end;

  EVP_MD_meth_set_cleanup := LoadLibCryptoFunction('EVP_MD_meth_set_cleanup');
  FuncLoadError := not assigned(EVP_MD_meth_set_cleanup);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_cleanup :=  @ERROR_EVP_MD_meth_set_cleanup;
  end;

  EVP_MD_meth_set_ctrl := LoadLibCryptoFunction('EVP_MD_meth_set_ctrl');
  FuncLoadError := not assigned(EVP_MD_meth_set_ctrl);
  if FuncLoadError then
  begin
    EVP_MD_meth_set_ctrl :=  @ERROR_EVP_MD_meth_set_ctrl;
  end;

  EVP_MD_meth_get_input_blocksize := LoadLibCryptoFunction('EVP_MD_meth_get_input_blocksize');
  FuncLoadError := not assigned(EVP_MD_meth_get_input_blocksize);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_input_blocksize :=  @ERROR_EVP_MD_meth_get_input_blocksize;
  end;

  EVP_MD_meth_get_result_size := LoadLibCryptoFunction('EVP_MD_meth_get_result_size');
  FuncLoadError := not assigned(EVP_MD_meth_get_result_size);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_result_size :=  @ERROR_EVP_MD_meth_get_result_size;
  end;

  EVP_MD_meth_get_app_datasize := LoadLibCryptoFunction('EVP_MD_meth_get_app_datasize');
  FuncLoadError := not assigned(EVP_MD_meth_get_app_datasize);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_app_datasize :=  @ERROR_EVP_MD_meth_get_app_datasize;
  end;

  EVP_MD_meth_get_flags := LoadLibCryptoFunction('EVP_MD_meth_get_flags');
  FuncLoadError := not assigned(EVP_MD_meth_get_flags);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_flags :=  @ERROR_EVP_MD_meth_get_flags;
  end;

  EVP_MD_meth_get_init := LoadLibCryptoFunction('EVP_MD_meth_get_init');
  FuncLoadError := not assigned(EVP_MD_meth_get_init);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_init :=  @ERROR_EVP_MD_meth_get_init;
  end;

  EVP_MD_meth_get_update := LoadLibCryptoFunction('EVP_MD_meth_get_update');
  FuncLoadError := not assigned(EVP_MD_meth_get_update);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_update :=  @ERROR_EVP_MD_meth_get_update;
  end;

  EVP_MD_meth_get_final := LoadLibCryptoFunction('EVP_MD_meth_get_final');
  FuncLoadError := not assigned(EVP_MD_meth_get_final);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_final :=  @ERROR_EVP_MD_meth_get_final;
  end;

  EVP_MD_meth_get_copy := LoadLibCryptoFunction('EVP_MD_meth_get_copy');
  FuncLoadError := not assigned(EVP_MD_meth_get_copy);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_copy :=  @ERROR_EVP_MD_meth_get_copy;
  end;

  EVP_MD_meth_get_cleanup := LoadLibCryptoFunction('EVP_MD_meth_get_cleanup');
  FuncLoadError := not assigned(EVP_MD_meth_get_cleanup);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_cleanup :=  @ERROR_EVP_MD_meth_get_cleanup;
  end;

  EVP_MD_meth_get_ctrl := LoadLibCryptoFunction('EVP_MD_meth_get_ctrl');
  FuncLoadError := not assigned(EVP_MD_meth_get_ctrl);
  if FuncLoadError then
  begin
    EVP_MD_meth_get_ctrl :=  @ERROR_EVP_MD_meth_get_ctrl;
  end;

  EVP_CIPHER_meth_new := LoadLibCryptoFunction('EVP_CIPHER_meth_new');
  FuncLoadError := not assigned(EVP_CIPHER_meth_new);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_new :=  @ERROR_EVP_CIPHER_meth_new;
  end;

  EVP_CIPHER_meth_dup := LoadLibCryptoFunction('EVP_CIPHER_meth_dup');
  FuncLoadError := not assigned(EVP_CIPHER_meth_dup);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_dup :=  @ERROR_EVP_CIPHER_meth_dup;
  end;

  EVP_CIPHER_meth_free := LoadLibCryptoFunction('EVP_CIPHER_meth_free');
  FuncLoadError := not assigned(EVP_CIPHER_meth_free);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_free :=  @ERROR_EVP_CIPHER_meth_free;
  end;

  EVP_CIPHER_meth_set_iv_length := LoadLibCryptoFunction('EVP_CIPHER_meth_set_iv_length');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_iv_length);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_iv_length :=  @ERROR_EVP_CIPHER_meth_set_iv_length;
  end;

  EVP_CIPHER_meth_set_flags := LoadLibCryptoFunction('EVP_CIPHER_meth_set_flags');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_flags);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_flags :=  @ERROR_EVP_CIPHER_meth_set_flags;
  end;

  EVP_CIPHER_meth_set_impl_ctx_size := LoadLibCryptoFunction('EVP_CIPHER_meth_set_impl_ctx_size');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_impl_ctx_size);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_impl_ctx_size :=  @ERROR_EVP_CIPHER_meth_set_impl_ctx_size;
  end;

  EVP_CIPHER_meth_set_init := LoadLibCryptoFunction('EVP_CIPHER_meth_set_init');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_init);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_init :=  @ERROR_EVP_CIPHER_meth_set_init;
  end;

  EVP_CIPHER_meth_set_do_cipher := LoadLibCryptoFunction('EVP_CIPHER_meth_set_do_cipher');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_do_cipher);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_do_cipher :=  @ERROR_EVP_CIPHER_meth_set_do_cipher;
  end;

  EVP_CIPHER_meth_set_cleanup := LoadLibCryptoFunction('EVP_CIPHER_meth_set_cleanup');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_cleanup);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_cleanup :=  @ERROR_EVP_CIPHER_meth_set_cleanup;
  end;

  EVP_CIPHER_meth_set_set_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_set_set_asn1_params');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_set_asn1_params);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_set_asn1_params :=  @ERROR_EVP_CIPHER_meth_set_set_asn1_params;
  end;

  EVP_CIPHER_meth_set_get_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_set_get_asn1_params');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_get_asn1_params);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_get_asn1_params :=  @ERROR_EVP_CIPHER_meth_set_get_asn1_params;
  end;

  EVP_CIPHER_meth_set_ctrl := LoadLibCryptoFunction('EVP_CIPHER_meth_set_ctrl');
  FuncLoadError := not assigned(EVP_CIPHER_meth_set_ctrl);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_set_ctrl :=  @ERROR_EVP_CIPHER_meth_set_ctrl;
  end;

  EVP_CIPHER_meth_get_init := LoadLibCryptoFunction('EVP_CIPHER_meth_get_init');
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_init);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_get_init :=  @ERROR_EVP_CIPHER_meth_get_init;
  end;

  EVP_CIPHER_meth_get_do_cipher := LoadLibCryptoFunction('EVP_CIPHER_meth_get_do_cipher');
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_do_cipher);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_get_do_cipher :=  @ERROR_EVP_CIPHER_meth_get_do_cipher;
  end;

  EVP_CIPHER_meth_get_cleanup := LoadLibCryptoFunction('EVP_CIPHER_meth_get_cleanup');
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_cleanup);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_get_cleanup :=  @ERROR_EVP_CIPHER_meth_get_cleanup;
  end;

  EVP_CIPHER_meth_get_set_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_get_set_asn1_params');
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_set_asn1_params);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_get_set_asn1_params :=  @ERROR_EVP_CIPHER_meth_get_set_asn1_params;
  end;

  EVP_CIPHER_meth_get_get_asn1_params := LoadLibCryptoFunction('EVP_CIPHER_meth_get_get_asn1_params');
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_get_asn1_params);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_get_get_asn1_params :=  @ERROR_EVP_CIPHER_meth_get_get_asn1_params;
  end;

  EVP_CIPHER_meth_get_ctrl := LoadLibCryptoFunction('EVP_CIPHER_meth_get_ctrl');
  FuncLoadError := not assigned(EVP_CIPHER_meth_get_ctrl);
  if FuncLoadError then
  begin
    EVP_CIPHER_meth_get_ctrl :=  @ERROR_EVP_CIPHER_meth_get_ctrl;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_type := LoadLibCryptoFunction('EVP_MD_type');
  FuncLoadError := not assigned(EVP_MD_type);
  if FuncLoadError then
  begin
    if EVP_MD_type_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_type');
  end;

  EVP_MD_pkey_type := LoadLibCryptoFunction('EVP_MD_pkey_type');
  FuncLoadError := not assigned(EVP_MD_pkey_type);
  if FuncLoadError then
  begin
    if EVP_MD_pkey_type_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_pkey_type');
  end;

  EVP_MD_size := LoadLibCryptoFunction('EVP_MD_size');
  FuncLoadError := not assigned(EVP_MD_size);
  if FuncLoadError then
  begin
    if EVP_MD_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_size');
  end;

  EVP_MD_block_size := LoadLibCryptoFunction('EVP_MD_block_size');
  FuncLoadError := not assigned(EVP_MD_block_size);
  if FuncLoadError then
  begin
    if EVP_MD_block_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_block_size');
  end;

  EVP_MD_flags := LoadLibCryptoFunction('EVP_MD_flags');
  FuncLoadError := not assigned(EVP_MD_flags);
  if FuncLoadError then
  begin
    if EVP_MD_flags_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_flags');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_md := LoadLibCryptoFunction('EVP_MD_CTX_md');
  FuncLoadError := not assigned(EVP_MD_CTX_md);
  if FuncLoadError then
  begin
    EVP_MD_CTX_md :=  @ERROR_EVP_MD_CTX_md;
  end;

  EVP_MD_CTX_update_fn := LoadLibCryptoFunction('EVP_MD_CTX_update_fn');
  FuncLoadError := not assigned(EVP_MD_CTX_update_fn);
  if FuncLoadError then
  begin
    EVP_MD_CTX_update_fn :=  @ERROR_EVP_MD_CTX_update_fn;
  end;

  EVP_MD_CTX_set_update_fn := LoadLibCryptoFunction('EVP_MD_CTX_set_update_fn');
  FuncLoadError := not assigned(EVP_MD_CTX_set_update_fn);
  if FuncLoadError then
  begin
    EVP_MD_CTX_set_update_fn :=  @ERROR_EVP_MD_CTX_set_update_fn;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_CTX_pkey_ctx := LoadLibCryptoFunction('EVP_MD_CTX_pkey_ctx');
  FuncLoadError := not assigned(EVP_MD_CTX_pkey_ctx);
  if FuncLoadError then
  begin
    if EVP_MD_CTX_pkey_ctx_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_pkey_ctx');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_set_pkey_ctx := LoadLibCryptoFunction('EVP_MD_CTX_set_pkey_ctx');
  FuncLoadError := not assigned(EVP_MD_CTX_set_pkey_ctx);
  if FuncLoadError then
  begin
    EVP_MD_CTX_set_pkey_ctx :=  @ERROR_EVP_MD_CTX_set_pkey_ctx;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_CTX_md_data := LoadLibCryptoFunction('EVP_MD_CTX_md_data');
  FuncLoadError := not assigned(EVP_MD_CTX_md_data);
  if FuncLoadError then
  begin
    if EVP_MD_CTX_md_data_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_md_data');
  end;

  EVP_CIPHER_nid := LoadLibCryptoFunction('EVP_CIPHER_nid');
  FuncLoadError := not assigned(EVP_CIPHER_nid);
  if FuncLoadError then
  begin
    if EVP_CIPHER_nid_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_nid');
  end;

  EVP_CIPHER_block_size := LoadLibCryptoFunction('EVP_CIPHER_block_size');
  FuncLoadError := not assigned(EVP_CIPHER_block_size);
  if FuncLoadError then
  begin
    if EVP_CIPHER_block_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_block_size');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_impl_ctx_size := LoadLibCryptoFunction('EVP_CIPHER_impl_ctx_size');
  FuncLoadError := not assigned(EVP_CIPHER_impl_ctx_size);
  if FuncLoadError then
  begin
    EVP_CIPHER_impl_ctx_size :=  @ERROR_EVP_CIPHER_impl_ctx_size;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_key_length := LoadLibCryptoFunction('EVP_CIPHER_key_length');
  FuncLoadError := not assigned(EVP_CIPHER_key_length);
  if FuncLoadError then
  begin
    if EVP_CIPHER_key_length_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_key_length');
  end;

  EVP_CIPHER_iv_length := LoadLibCryptoFunction('EVP_CIPHER_iv_length');
  FuncLoadError := not assigned(EVP_CIPHER_iv_length);
  if FuncLoadError then
  begin
    if EVP_CIPHER_iv_length_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_iv_length');
  end;

  EVP_CIPHER_flags := LoadLibCryptoFunction('EVP_CIPHER_flags');
  FuncLoadError := not assigned(EVP_CIPHER_flags);
  if FuncLoadError then
  begin
    if EVP_CIPHER_flags_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_flags');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_cipher := LoadLibCryptoFunction('EVP_CIPHER_CTX_cipher');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_cipher);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_cipher :=  @ERROR_EVP_CIPHER_CTX_cipher;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_CTX_encrypting := LoadLibCryptoFunction('EVP_CIPHER_CTX_encrypting');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_encrypting);
  if FuncLoadError then
  begin
    if EVP_CIPHER_CTX_encrypting_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_encrypting');
  end;

  EVP_CIPHER_CTX_nid := LoadLibCryptoFunction('EVP_CIPHER_CTX_nid');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_nid);
  if FuncLoadError then
  begin
    if EVP_CIPHER_CTX_nid_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_nid');
  end;

  EVP_CIPHER_CTX_block_size := LoadLibCryptoFunction('EVP_CIPHER_CTX_block_size');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_block_size);
  if FuncLoadError then
  begin
    if EVP_CIPHER_CTX_block_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_block_size');
  end;

  EVP_CIPHER_CTX_key_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_key_length');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_key_length);
  if FuncLoadError then
  begin
    if EVP_CIPHER_CTX_key_length_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_key_length');
  end;

  EVP_CIPHER_CTX_iv_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv_length');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_iv_length);
  if FuncLoadError then
  begin
    if EVP_CIPHER_CTX_iv_length_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_iv_length');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_iv);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_iv :=  @ERROR_EVP_CIPHER_CTX_iv;
  end;

  EVP_CIPHER_CTX_original_iv := LoadLibCryptoFunction('EVP_CIPHER_CTX_original_iv');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_original_iv);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_original_iv :=  @ERROR_EVP_CIPHER_CTX_original_iv;
  end;

  EVP_CIPHER_CTX_iv_noconst := LoadLibCryptoFunction('EVP_CIPHER_CTX_iv_noconst');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_iv_noconst);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_iv_noconst :=  @ERROR_EVP_CIPHER_CTX_iv_noconst;
  end;

  EVP_CIPHER_CTX_buf_noconst := LoadLibCryptoFunction('EVP_CIPHER_CTX_buf_noconst');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_buf_noconst);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_buf_noconst :=  @ERROR_EVP_CIPHER_CTX_buf_noconst;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_CTX_num := LoadLibCryptoFunction('EVP_CIPHER_CTX_num');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_num);
  if FuncLoadError then
  begin
    if EVP_CIPHER_CTX_num_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_CTX_num');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_set_num := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_num');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_num);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_set_num :=  @ERROR_EVP_CIPHER_CTX_set_num;
  end;

  EVP_CIPHER_CTX_copy := LoadLibCryptoFunction('EVP_CIPHER_CTX_copy');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_copy);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_copy :=  @ERROR_EVP_CIPHER_CTX_copy;
  end;

  EVP_CIPHER_CTX_get_app_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_app_data');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_app_data);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_get_app_data :=  @ERROR_EVP_CIPHER_CTX_get_app_data;
  end;

  EVP_CIPHER_CTX_set_app_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_app_data');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_app_data);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_set_app_data :=  @ERROR_EVP_CIPHER_CTX_set_app_data;
  end;

  EVP_CIPHER_CTX_get_cipher_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_get_cipher_data');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_get_cipher_data);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_get_cipher_data :=  @ERROR_EVP_CIPHER_CTX_get_cipher_data;
  end;

  EVP_CIPHER_CTX_set_cipher_data := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_cipher_data');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_cipher_data);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_set_cipher_data :=  @ERROR_EVP_CIPHER_CTX_set_cipher_data;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  BIO_set_md := LoadLibCryptoFunction('BIO_set_md');
  FuncLoadError := not assigned(BIO_set_md);
  if FuncLoadError then
  begin
    BIO_set_md := @COMPAT_BIO_set_md;
    if BIO_set_md_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_set_md');
  end;

  EVP_MD_CTX_init := LoadLibCryptoFunction('EVP_MD_CTX_init');
  FuncLoadError := not assigned(EVP_MD_CTX_init);
  if FuncLoadError then
  begin
    if EVP_MD_CTX_init_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_init');
  end;

  EVP_MD_CTX_cleanup := LoadLibCryptoFunction('EVP_MD_CTX_cleanup');
  FuncLoadError := not assigned(EVP_MD_CTX_cleanup);
  if FuncLoadError then
  begin
    if EVP_MD_CTX_cleanup_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_MD_CTX_cleanup');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_ctrl := LoadLibCryptoFunction('EVP_MD_CTX_ctrl');
  FuncLoadError := not assigned(EVP_MD_CTX_ctrl);
  if FuncLoadError then
  begin
    EVP_MD_CTX_ctrl :=  @ERROR_EVP_MD_CTX_ctrl;
  end;

  EVP_MD_CTX_new := LoadLibCryptoFunction('EVP_MD_CTX_new');
  FuncLoadError := not assigned(EVP_MD_CTX_new);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    EVP_MD_CTX_new := @COMPAT_EVP_MD_CTX_new;
{$ELSE}
    EVP_MD_CTX_new :=  @ERROR_EVP_MD_CTX_new;
{$ENDIF}
  end;

  EVP_MD_CTX_reset := LoadLibCryptoFunction('EVP_MD_CTX_reset');
  FuncLoadError := not assigned(EVP_MD_CTX_reset);
  if FuncLoadError then
  begin
    EVP_MD_CTX_reset :=  @ERROR_EVP_MD_CTX_reset;
  end;

  EVP_MD_CTX_free := LoadLibCryptoFunction('EVP_MD_CTX_free');
  FuncLoadError := not assigned(EVP_MD_CTX_free);
  if FuncLoadError then
  begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
    EVP_MD_CTX_free := @COMPAT_EVP_MD_CTX_free;
{$ELSE}
    EVP_MD_CTX_free :=  @ERROR_EVP_MD_CTX_free;
{$ENDIF}
  end;

  EVP_MD_CTX_copy_ex := LoadLibCryptoFunction('EVP_MD_CTX_copy_ex');
  FuncLoadError := not assigned(EVP_MD_CTX_copy_ex);
  if FuncLoadError then
  begin
    EVP_MD_CTX_copy_ex :=  @ERROR_EVP_MD_CTX_copy_ex;
  end;

  EVP_MD_CTX_set_flags := LoadLibCryptoFunction('EVP_MD_CTX_set_flags');
  FuncLoadError := not assigned(EVP_MD_CTX_set_flags);
  if FuncLoadError then
  begin
    EVP_MD_CTX_set_flags :=  @ERROR_EVP_MD_CTX_set_flags;
  end;

  EVP_MD_CTX_clear_flags := LoadLibCryptoFunction('EVP_MD_CTX_clear_flags');
  FuncLoadError := not assigned(EVP_MD_CTX_clear_flags);
  if FuncLoadError then
  begin
    EVP_MD_CTX_clear_flags :=  @ERROR_EVP_MD_CTX_clear_flags;
  end;

  EVP_MD_CTX_test_flags := LoadLibCryptoFunction('EVP_MD_CTX_test_flags');
  FuncLoadError := not assigned(EVP_MD_CTX_test_flags);
  if FuncLoadError then
  begin
    EVP_MD_CTX_test_flags :=  @ERROR_EVP_MD_CTX_test_flags;
  end;

  EVP_DigestInit_ex := LoadLibCryptoFunction('EVP_DigestInit_ex');
  FuncLoadError := not assigned(EVP_DigestInit_ex);
  if FuncLoadError then
  begin
    EVP_DigestInit_ex :=  @ERROR_EVP_DigestInit_ex;
  end;

  EVP_DigestUpdate := LoadLibCryptoFunction('EVP_DigestUpdate');
  FuncLoadError := not assigned(EVP_DigestUpdate);
  if FuncLoadError then
  begin
    EVP_DigestUpdate :=  @ERROR_EVP_DigestUpdate;
  end;

  EVP_DigestFinal_ex := LoadLibCryptoFunction('EVP_DigestFinal_ex');
  FuncLoadError := not assigned(EVP_DigestFinal_ex);
  if FuncLoadError then
  begin
    EVP_DigestFinal_ex :=  @ERROR_EVP_DigestFinal_ex;
  end;

  EVP_Digest := LoadLibCryptoFunction('EVP_Digest');
  FuncLoadError := not assigned(EVP_Digest);
  if FuncLoadError then
  begin
    EVP_Digest :=  @ERROR_EVP_Digest;
  end;

  EVP_MD_CTX_copy := LoadLibCryptoFunction('EVP_MD_CTX_copy');
  FuncLoadError := not assigned(EVP_MD_CTX_copy);
  if FuncLoadError then
  begin
    EVP_MD_CTX_copy :=  @ERROR_EVP_MD_CTX_copy;
  end;

  EVP_DigestInit := LoadLibCryptoFunction('EVP_DigestInit');
  FuncLoadError := not assigned(EVP_DigestInit);
  if FuncLoadError then
  begin
    EVP_DigestInit :=  @ERROR_EVP_DigestInit;
  end;

  EVP_DigestFinal := LoadLibCryptoFunction('EVP_DigestFinal');
  FuncLoadError := not assigned(EVP_DigestFinal);
  if FuncLoadError then
  begin
    EVP_DigestFinal :=  @ERROR_EVP_DigestFinal;
  end;

  EVP_DigestFinalXOF := LoadLibCryptoFunction('EVP_DigestFinalXOF');
  FuncLoadError := not assigned(EVP_DigestFinalXOF);
  if FuncLoadError then
  begin
    EVP_DigestFinalXOF :=  @ERROR_EVP_DigestFinalXOF;
  end;

  EVP_read_pw_string := LoadLibCryptoFunction('EVP_read_pw_string');
  FuncLoadError := not assigned(EVP_read_pw_string);
  if FuncLoadError then
  begin
    EVP_read_pw_string :=  @ERROR_EVP_read_pw_string;
  end;

  EVP_read_pw_string_min := LoadLibCryptoFunction('EVP_read_pw_string_min');
  FuncLoadError := not assigned(EVP_read_pw_string_min);
  if FuncLoadError then
  begin
    EVP_read_pw_string_min :=  @ERROR_EVP_read_pw_string_min;
  end;

  EVP_set_pw_prompt := LoadLibCryptoFunction('EVP_set_pw_prompt');
  FuncLoadError := not assigned(EVP_set_pw_prompt);
  if FuncLoadError then
  begin
    EVP_set_pw_prompt :=  @ERROR_EVP_set_pw_prompt;
  end;

  EVP_get_pw_prompt := LoadLibCryptoFunction('EVP_get_pw_prompt');
  FuncLoadError := not assigned(EVP_get_pw_prompt);
  if FuncLoadError then
  begin
    EVP_get_pw_prompt :=  @ERROR_EVP_get_pw_prompt;
  end;

  EVP_BytesToKey := LoadLibCryptoFunction('EVP_BytesToKey');
  FuncLoadError := not assigned(EVP_BytesToKey);
  if FuncLoadError then
  begin
    EVP_BytesToKey :=  @ERROR_EVP_BytesToKey;
  end;

  EVP_CIPHER_CTX_set_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_flags');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_flags);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_set_flags :=  @ERROR_EVP_CIPHER_CTX_set_flags;
  end;

  EVP_CIPHER_CTX_clear_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_clear_flags');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_clear_flags);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_clear_flags :=  @ERROR_EVP_CIPHER_CTX_clear_flags;
  end;

  EVP_CIPHER_CTX_test_flags := LoadLibCryptoFunction('EVP_CIPHER_CTX_test_flags');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_test_flags);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_test_flags :=  @ERROR_EVP_CIPHER_CTX_test_flags;
  end;

  EVP_EncryptInit := LoadLibCryptoFunction('EVP_EncryptInit');
  FuncLoadError := not assigned(EVP_EncryptInit);
  if FuncLoadError then
  begin
    EVP_EncryptInit :=  @ERROR_EVP_EncryptInit;
  end;

  EVP_EncryptInit_ex := LoadLibCryptoFunction('EVP_EncryptInit_ex');
  FuncLoadError := not assigned(EVP_EncryptInit_ex);
  if FuncLoadError then
  begin
    EVP_EncryptInit_ex :=  @ERROR_EVP_EncryptInit_ex;
  end;

  EVP_EncryptUpdate := LoadLibCryptoFunction('EVP_EncryptUpdate');
  FuncLoadError := not assigned(EVP_EncryptUpdate);
  if FuncLoadError then
  begin
    EVP_EncryptUpdate :=  @ERROR_EVP_EncryptUpdate;
  end;

  EVP_EncryptFinal_ex := LoadLibCryptoFunction('EVP_EncryptFinal_ex');
  FuncLoadError := not assigned(EVP_EncryptFinal_ex);
  if FuncLoadError then
  begin
    EVP_EncryptFinal_ex :=  @ERROR_EVP_EncryptFinal_ex;
  end;

  EVP_EncryptFinal := LoadLibCryptoFunction('EVP_EncryptFinal');
  FuncLoadError := not assigned(EVP_EncryptFinal);
  if FuncLoadError then
  begin
    EVP_EncryptFinal :=  @ERROR_EVP_EncryptFinal;
  end;

  EVP_DecryptInit := LoadLibCryptoFunction('EVP_DecryptInit');
  FuncLoadError := not assigned(EVP_DecryptInit);
  if FuncLoadError then
  begin
    EVP_DecryptInit :=  @ERROR_EVP_DecryptInit;
  end;

  EVP_DecryptInit_ex := LoadLibCryptoFunction('EVP_DecryptInit_ex');
  FuncLoadError := not assigned(EVP_DecryptInit_ex);
  if FuncLoadError then
  begin
    EVP_DecryptInit_ex :=  @ERROR_EVP_DecryptInit_ex;
  end;

  EVP_DecryptUpdate := LoadLibCryptoFunction('EVP_DecryptUpdate');
  FuncLoadError := not assigned(EVP_DecryptUpdate);
  if FuncLoadError then
  begin
    EVP_DecryptUpdate :=  @ERROR_EVP_DecryptUpdate;
  end;

  EVP_DecryptFinal := LoadLibCryptoFunction('EVP_DecryptFinal');
  FuncLoadError := not assigned(EVP_DecryptFinal);
  if FuncLoadError then
  begin
    EVP_DecryptFinal :=  @ERROR_EVP_DecryptFinal;
  end;

  EVP_DecryptFinal_ex := LoadLibCryptoFunction('EVP_DecryptFinal_ex');
  FuncLoadError := not assigned(EVP_DecryptFinal_ex);
  if FuncLoadError then
  begin
    EVP_DecryptFinal_ex :=  @ERROR_EVP_DecryptFinal_ex;
  end;

  EVP_CipherInit := LoadLibCryptoFunction('EVP_CipherInit');
  FuncLoadError := not assigned(EVP_CipherInit);
  if FuncLoadError then
  begin
    EVP_CipherInit :=  @ERROR_EVP_CipherInit;
  end;

  EVP_CipherInit_ex := LoadLibCryptoFunction('EVP_CipherInit_ex');
  FuncLoadError := not assigned(EVP_CipherInit_ex);
  if FuncLoadError then
  begin
    EVP_CipherInit_ex :=  @ERROR_EVP_CipherInit_ex;
  end;

  EVP_CipherUpdate := LoadLibCryptoFunction('EVP_CipherUpdate');
  FuncLoadError := not assigned(EVP_CipherUpdate);
  if FuncLoadError then
  begin
    EVP_CipherUpdate :=  @ERROR_EVP_CipherUpdate;
  end;

  EVP_CipherFinal := LoadLibCryptoFunction('EVP_CipherFinal');
  FuncLoadError := not assigned(EVP_CipherFinal);
  if FuncLoadError then
  begin
    EVP_CipherFinal :=  @ERROR_EVP_CipherFinal;
  end;

  EVP_CipherFinal_ex := LoadLibCryptoFunction('EVP_CipherFinal_ex');
  FuncLoadError := not assigned(EVP_CipherFinal_ex);
  if FuncLoadError then
  begin
    EVP_CipherFinal_ex :=  @ERROR_EVP_CipherFinal_ex;
  end;

  EVP_SignFinal := LoadLibCryptoFunction('EVP_SignFinal');
  FuncLoadError := not assigned(EVP_SignFinal);
  if FuncLoadError then
  begin
    EVP_SignFinal :=  @ERROR_EVP_SignFinal;
  end;

  EVP_DigestSign := LoadLibCryptoFunction('EVP_DigestSign');
  FuncLoadError := not assigned(EVP_DigestSign);
  if FuncLoadError then
  begin
    EVP_DigestSign :=  @ERROR_EVP_DigestSign;
  end;

  EVP_VerifyFinal := LoadLibCryptoFunction('EVP_VerifyFinal');
  FuncLoadError := not assigned(EVP_VerifyFinal);
  if FuncLoadError then
  begin
    EVP_VerifyFinal :=  @ERROR_EVP_VerifyFinal;
  end;

  EVP_DigestVerify := LoadLibCryptoFunction('EVP_DigestVerify');
  FuncLoadError := not assigned(EVP_DigestVerify);
  if FuncLoadError then
  begin
    EVP_DigestVerify :=  @ERROR_EVP_DigestVerify;
  end;

  EVP_DigestSignInit := LoadLibCryptoFunction('EVP_DigestSignInit');
  FuncLoadError := not assigned(EVP_DigestSignInit);
  if FuncLoadError then
  begin
    EVP_DigestSignInit :=  @ERROR_EVP_DigestSignInit;
  end;

  EVP_DigestSignFinal := LoadLibCryptoFunction('EVP_DigestSignFinal');
  FuncLoadError := not assigned(EVP_DigestSignFinal);
  if FuncLoadError then
  begin
    EVP_DigestSignFinal :=  @ERROR_EVP_DigestSignFinal;
  end;

  EVP_DigestVerifyInit := LoadLibCryptoFunction('EVP_DigestVerifyInit');
  FuncLoadError := not assigned(EVP_DigestVerifyInit);
  if FuncLoadError then
  begin
    EVP_DigestVerifyInit :=  @ERROR_EVP_DigestVerifyInit;
  end;

  EVP_DigestVerifyFinal := LoadLibCryptoFunction('EVP_DigestVerifyFinal');
  FuncLoadError := not assigned(EVP_DigestVerifyFinal);
  if FuncLoadError then
  begin
    EVP_DigestVerifyFinal :=  @ERROR_EVP_DigestVerifyFinal;
  end;

  EVP_OpenInit := LoadLibCryptoFunction('EVP_OpenInit');
  FuncLoadError := not assigned(EVP_OpenInit);
  if FuncLoadError then
  begin
    EVP_OpenInit :=  @ERROR_EVP_OpenInit;
  end;

  EVP_OpenFinal := LoadLibCryptoFunction('EVP_OpenFinal');
  FuncLoadError := not assigned(EVP_OpenFinal);
  if FuncLoadError then
  begin
    EVP_OpenFinal :=  @ERROR_EVP_OpenFinal;
  end;

  EVP_SealInit := LoadLibCryptoFunction('EVP_SealInit');
  FuncLoadError := not assigned(EVP_SealInit);
  if FuncLoadError then
  begin
    EVP_SealInit :=  @ERROR_EVP_SealInit;
  end;

  EVP_SealFinal := LoadLibCryptoFunction('EVP_SealFinal');
  FuncLoadError := not assigned(EVP_SealFinal);
  if FuncLoadError then
  begin
    EVP_SealFinal :=  @ERROR_EVP_SealFinal;
  end;

  EVP_ENCODE_CTX_new := LoadLibCryptoFunction('EVP_ENCODE_CTX_new');
  FuncLoadError := not assigned(EVP_ENCODE_CTX_new);
  if FuncLoadError then
  begin
    EVP_ENCODE_CTX_new :=  @ERROR_EVP_ENCODE_CTX_new;
  end;

  EVP_ENCODE_CTX_free := LoadLibCryptoFunction('EVP_ENCODE_CTX_free');
  FuncLoadError := not assigned(EVP_ENCODE_CTX_free);
  if FuncLoadError then
  begin
    EVP_ENCODE_CTX_free :=  @ERROR_EVP_ENCODE_CTX_free;
  end;

  EVP_ENCODE_CTX_copy := LoadLibCryptoFunction('EVP_ENCODE_CTX_copy');
  FuncLoadError := not assigned(EVP_ENCODE_CTX_copy);
  if FuncLoadError then
  begin
    EVP_ENCODE_CTX_copy :=  @ERROR_EVP_ENCODE_CTX_copy;
  end;

  EVP_ENCODE_CTX_num := LoadLibCryptoFunction('EVP_ENCODE_CTX_num');
  FuncLoadError := not assigned(EVP_ENCODE_CTX_num);
  if FuncLoadError then
  begin
    EVP_ENCODE_CTX_num :=  @ERROR_EVP_ENCODE_CTX_num;
  end;

  EVP_EncodeInit := LoadLibCryptoFunction('EVP_EncodeInit');
  FuncLoadError := not assigned(EVP_EncodeInit);
  if FuncLoadError then
  begin
    EVP_EncodeInit :=  @ERROR_EVP_EncodeInit;
  end;

  EVP_EncodeUpdate := LoadLibCryptoFunction('EVP_EncodeUpdate');
  FuncLoadError := not assigned(EVP_EncodeUpdate);
  if FuncLoadError then
  begin
    EVP_EncodeUpdate :=  @ERROR_EVP_EncodeUpdate;
  end;

  EVP_EncodeFinal := LoadLibCryptoFunction('EVP_EncodeFinal');
  FuncLoadError := not assigned(EVP_EncodeFinal);
  if FuncLoadError then
  begin
    EVP_EncodeFinal :=  @ERROR_EVP_EncodeFinal;
  end;

  EVP_EncodeBlock := LoadLibCryptoFunction('EVP_EncodeBlock');
  FuncLoadError := not assigned(EVP_EncodeBlock);
  if FuncLoadError then
  begin
    EVP_EncodeBlock :=  @ERROR_EVP_EncodeBlock;
  end;

  EVP_DecodeInit := LoadLibCryptoFunction('EVP_DecodeInit');
  FuncLoadError := not assigned(EVP_DecodeInit);
  if FuncLoadError then
  begin
    EVP_DecodeInit :=  @ERROR_EVP_DecodeInit;
  end;

  EVP_DecodeUpdate := LoadLibCryptoFunction('EVP_DecodeUpdate');
  FuncLoadError := not assigned(EVP_DecodeUpdate);
  if FuncLoadError then
  begin
    EVP_DecodeUpdate :=  @ERROR_EVP_DecodeUpdate;
  end;

  EVP_DecodeFinal := LoadLibCryptoFunction('EVP_DecodeFinal');
  FuncLoadError := not assigned(EVP_DecodeFinal);
  if FuncLoadError then
  begin
    EVP_DecodeFinal :=  @ERROR_EVP_DecodeFinal;
  end;

  EVP_DecodeBlock := LoadLibCryptoFunction('EVP_DecodeBlock');
  FuncLoadError := not assigned(EVP_DecodeBlock);
  if FuncLoadError then
  begin
    EVP_DecodeBlock :=  @ERROR_EVP_DecodeBlock;
  end;

  EVP_CIPHER_CTX_new := LoadLibCryptoFunction('EVP_CIPHER_CTX_new');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_new);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_new :=  @ERROR_EVP_CIPHER_CTX_new;
  end;

  EVP_CIPHER_CTX_reset := LoadLibCryptoFunction('EVP_CIPHER_CTX_reset');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_reset);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_reset :=  @ERROR_EVP_CIPHER_CTX_reset;
  end;

  EVP_CIPHER_CTX_free := LoadLibCryptoFunction('EVP_CIPHER_CTX_free');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_free);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_free :=  @ERROR_EVP_CIPHER_CTX_free;
  end;

  EVP_CIPHER_CTX_set_key_length := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_key_length');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_key_length);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_set_key_length :=  @ERROR_EVP_CIPHER_CTX_set_key_length;
  end;

  EVP_CIPHER_CTX_set_padding := LoadLibCryptoFunction('EVP_CIPHER_CTX_set_padding');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_set_padding);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_set_padding :=  @ERROR_EVP_CIPHER_CTX_set_padding;
  end;

  EVP_CIPHER_CTX_ctrl := LoadLibCryptoFunction('EVP_CIPHER_CTX_ctrl');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_ctrl);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_ctrl :=  @ERROR_EVP_CIPHER_CTX_ctrl;
  end;

  EVP_CIPHER_CTX_rand_key := LoadLibCryptoFunction('EVP_CIPHER_CTX_rand_key');
  FuncLoadError := not assigned(EVP_CIPHER_CTX_rand_key);
  if FuncLoadError then
  begin
    EVP_CIPHER_CTX_rand_key :=  @ERROR_EVP_CIPHER_CTX_rand_key;
  end;

  BIO_f_md := LoadLibCryptoFunction('BIO_f_md');
  FuncLoadError := not assigned(BIO_f_md);
  if FuncLoadError then
  begin
    BIO_f_md :=  @ERROR_BIO_f_md;
  end;

  BIO_f_base64 := LoadLibCryptoFunction('BIO_f_base64');
  FuncLoadError := not assigned(BIO_f_base64);
  if FuncLoadError then
  begin
    BIO_f_base64 :=  @ERROR_BIO_f_base64;
  end;

  BIO_f_cipher := LoadLibCryptoFunction('BIO_f_cipher');
  FuncLoadError := not assigned(BIO_f_cipher);
  if FuncLoadError then
  begin
    BIO_f_cipher :=  @ERROR_BIO_f_cipher;
  end;

  BIO_f_reliable := LoadLibCryptoFunction('BIO_f_reliable');
  FuncLoadError := not assigned(BIO_f_reliable);
  if FuncLoadError then
  begin
    BIO_f_reliable :=  @ERROR_BIO_f_reliable;
  end;

  BIO_set_cipher := LoadLibCryptoFunction('BIO_set_cipher');
  FuncLoadError := not assigned(BIO_set_cipher);
  if FuncLoadError then
  begin
    BIO_set_cipher :=  @ERROR_BIO_set_cipher;
  end;

  EVP_md_null := LoadLibCryptoFunction('EVP_md_null');
  FuncLoadError := not assigned(EVP_md_null);
  if FuncLoadError then
  begin
    EVP_md_null :=  @ERROR_EVP_md_null;
  end;

{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md2 := LoadLibCryptoFunction('EVP_md2');
  FuncLoadError := not assigned(EVP_md2);
  if FuncLoadError then
  begin
    EVP_md2 := @COMPAT_EVP_md2;
    {Don't report allow nil failure}
  end;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md4 := LoadLibCryptoFunction('EVP_md4');
  FuncLoadError := not assigned(EVP_md4);
  if FuncLoadError then
  begin
    EVP_md4 := @COMPAT_EVP_md4;
    {Don't report allow nil failure}
  end;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md5 := LoadLibCryptoFunction('EVP_md5');
  FuncLoadError := not assigned(EVP_md5);
  if FuncLoadError then
  begin
    EVP_md5 := @COMPAT_EVP_md5;
    {Don't report allow nil failure}
  end;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT

{$ENDIF}
  EVP_md5_sha1 := LoadLibCryptoFunction('EVP_md5_sha1');
  FuncLoadError := not assigned(EVP_md5_sha1);
  if FuncLoadError then
  begin
    EVP_md5_sha1 :=  @ERROR_EVP_md5_sha1;
  end;

  EVP_sha1 := LoadLibCryptoFunction('EVP_sha1');
  FuncLoadError := not assigned(EVP_sha1);
  if FuncLoadError then
  begin
    EVP_sha1 :=  @ERROR_EVP_sha1;
  end;

  EVP_sha224 := LoadLibCryptoFunction('EVP_sha224');
  FuncLoadError := not assigned(EVP_sha224);
  if FuncLoadError then
  begin
    EVP_sha224 :=  @ERROR_EVP_sha224;
  end;

  EVP_sha256 := LoadLibCryptoFunction('EVP_sha256');
  FuncLoadError := not assigned(EVP_sha256);
  if FuncLoadError then
  begin
    EVP_sha256 :=  @ERROR_EVP_sha256;
  end;

  EVP_sha384 := LoadLibCryptoFunction('EVP_sha384');
  FuncLoadError := not assigned(EVP_sha384);
  if FuncLoadError then
  begin
    EVP_sha384 :=  @ERROR_EVP_sha384;
  end;

  EVP_sha512 := LoadLibCryptoFunction('EVP_sha512');
  FuncLoadError := not assigned(EVP_sha512);
  if FuncLoadError then
  begin
    EVP_sha512 :=  @ERROR_EVP_sha512;
  end;

  EVP_sha512_224 := LoadLibCryptoFunction('EVP_sha512_224');
  FuncLoadError := not assigned(EVP_sha512_224);
  if FuncLoadError then
  begin
    EVP_sha512_224 :=  @ERROR_EVP_sha512_224;
  end;

  EVP_sha512_256 := LoadLibCryptoFunction('EVP_sha512_256');
  FuncLoadError := not assigned(EVP_sha512_256);
  if FuncLoadError then
  begin
    EVP_sha512_256 :=  @ERROR_EVP_sha512_256;
  end;

  EVP_sha3_224 := LoadLibCryptoFunction('EVP_sha3_224');
  FuncLoadError := not assigned(EVP_sha3_224);
  if FuncLoadError then
  begin
    EVP_sha3_224 :=  @ERROR_EVP_sha3_224;
  end;

  EVP_sha3_256 := LoadLibCryptoFunction('EVP_sha3_256');
  FuncLoadError := not assigned(EVP_sha3_256);
  if FuncLoadError then
  begin
    EVP_sha3_256 :=  @ERROR_EVP_sha3_256;
  end;

  EVP_sha3_384 := LoadLibCryptoFunction('EVP_sha3_384');
  FuncLoadError := not assigned(EVP_sha3_384);
  if FuncLoadError then
  begin
    EVP_sha3_384 :=  @ERROR_EVP_sha3_384;
  end;

  EVP_sha3_512 := LoadLibCryptoFunction('EVP_sha3_512');
  FuncLoadError := not assigned(EVP_sha3_512);
  if FuncLoadError then
  begin
    EVP_sha3_512 :=  @ERROR_EVP_sha3_512;
  end;

  EVP_shake128 := LoadLibCryptoFunction('EVP_shake128');
  FuncLoadError := not assigned(EVP_shake128);
  if FuncLoadError then
  begin
    EVP_shake128 :=  @ERROR_EVP_shake128;
  end;

  EVP_shake256 := LoadLibCryptoFunction('EVP_shake256');
  FuncLoadError := not assigned(EVP_shake256);
  if FuncLoadError then
  begin
    EVP_shake256 :=  @ERROR_EVP_shake256;
  end;

  EVP_enc_null := LoadLibCryptoFunction('EVP_enc_null');
  FuncLoadError := not assigned(EVP_enc_null);
  if FuncLoadError then
  begin
    EVP_enc_null :=  @ERROR_EVP_enc_null;
  end;

  EVP_des_ecb := LoadLibCryptoFunction('EVP_des_ecb');
  FuncLoadError := not assigned(EVP_des_ecb);
  if FuncLoadError then
  begin
    EVP_des_ecb :=  @ERROR_EVP_des_ecb;
  end;

  EVP_des_ede := LoadLibCryptoFunction('EVP_des_ede');
  FuncLoadError := not assigned(EVP_des_ede);
  if FuncLoadError then
  begin
    EVP_des_ede :=  @ERROR_EVP_des_ede;
  end;

  EVP_des_ede3 := LoadLibCryptoFunction('EVP_des_ede3');
  FuncLoadError := not assigned(EVP_des_ede3);
  if FuncLoadError then
  begin
    EVP_des_ede3 :=  @ERROR_EVP_des_ede3;
  end;

  EVP_des_ede_ecb := LoadLibCryptoFunction('EVP_des_ede_ecb');
  FuncLoadError := not assigned(EVP_des_ede_ecb);
  if FuncLoadError then
  begin
    EVP_des_ede_ecb :=  @ERROR_EVP_des_ede_ecb;
  end;

  EVP_des_ede3_ecb := LoadLibCryptoFunction('EVP_des_ede3_ecb');
  FuncLoadError := not assigned(EVP_des_ede3_ecb);
  if FuncLoadError then
  begin
    EVP_des_ede3_ecb :=  @ERROR_EVP_des_ede3_ecb;
  end;

  EVP_des_cfb64 := LoadLibCryptoFunction('EVP_des_cfb64');
  FuncLoadError := not assigned(EVP_des_cfb64);
  if FuncLoadError then
  begin
    EVP_des_cfb64 :=  @ERROR_EVP_des_cfb64;
  end;

  EVP_des_cfb1 := LoadLibCryptoFunction('EVP_des_cfb1');
  FuncLoadError := not assigned(EVP_des_cfb1);
  if FuncLoadError then
  begin
    EVP_des_cfb1 :=  @ERROR_EVP_des_cfb1;
  end;

  EVP_des_cfb8 := LoadLibCryptoFunction('EVP_des_cfb8');
  FuncLoadError := not assigned(EVP_des_cfb8);
  if FuncLoadError then
  begin
    EVP_des_cfb8 :=  @ERROR_EVP_des_cfb8;
  end;

  EVP_des_ede_cfb64 := LoadLibCryptoFunction('EVP_des_ede_cfb64');
  FuncLoadError := not assigned(EVP_des_ede_cfb64);
  if FuncLoadError then
  begin
    EVP_des_ede_cfb64 :=  @ERROR_EVP_des_ede_cfb64;
  end;

  EVP_des_ede3_cfb64 := LoadLibCryptoFunction('EVP_des_ede3_cfb64');
  FuncLoadError := not assigned(EVP_des_ede3_cfb64);
  if FuncLoadError then
  begin
    EVP_des_ede3_cfb64 :=  @ERROR_EVP_des_ede3_cfb64;
  end;

  EVP_des_ede3_cfb1 := LoadLibCryptoFunction('EVP_des_ede3_cfb1');
  FuncLoadError := not assigned(EVP_des_ede3_cfb1);
  if FuncLoadError then
  begin
    EVP_des_ede3_cfb1 :=  @ERROR_EVP_des_ede3_cfb1;
  end;

  EVP_des_ede3_cfb8 := LoadLibCryptoFunction('EVP_des_ede3_cfb8');
  FuncLoadError := not assigned(EVP_des_ede3_cfb8);
  if FuncLoadError then
  begin
    EVP_des_ede3_cfb8 :=  @ERROR_EVP_des_ede3_cfb8;
  end;

  EVP_des_ofb := LoadLibCryptoFunction('EVP_des_ofb');
  FuncLoadError := not assigned(EVP_des_ofb);
  if FuncLoadError then
  begin
    EVP_des_ofb :=  @ERROR_EVP_des_ofb;
  end;

  EVP_des_ede_ofb := LoadLibCryptoFunction('EVP_des_ede_ofb');
  FuncLoadError := not assigned(EVP_des_ede_ofb);
  if FuncLoadError then
  begin
    EVP_des_ede_ofb :=  @ERROR_EVP_des_ede_ofb;
  end;

  EVP_des_ede3_ofb := LoadLibCryptoFunction('EVP_des_ede3_ofb');
  FuncLoadError := not assigned(EVP_des_ede3_ofb);
  if FuncLoadError then
  begin
    EVP_des_ede3_ofb :=  @ERROR_EVP_des_ede3_ofb;
  end;

  EVP_des_cbc := LoadLibCryptoFunction('EVP_des_cbc');
  FuncLoadError := not assigned(EVP_des_cbc);
  if FuncLoadError then
  begin
    EVP_des_cbc :=  @ERROR_EVP_des_cbc;
  end;

  EVP_des_ede_cbc := LoadLibCryptoFunction('EVP_des_ede_cbc');
  FuncLoadError := not assigned(EVP_des_ede_cbc);
  if FuncLoadError then
  begin
    EVP_des_ede_cbc :=  @ERROR_EVP_des_ede_cbc;
  end;

  EVP_des_ede3_cbc := LoadLibCryptoFunction('EVP_des_ede3_cbc');
  FuncLoadError := not assigned(EVP_des_ede3_cbc);
  if FuncLoadError then
  begin
    EVP_des_ede3_cbc :=  @ERROR_EVP_des_ede3_cbc;
  end;

  EVP_desx_cbc := LoadLibCryptoFunction('EVP_desx_cbc');
  FuncLoadError := not assigned(EVP_desx_cbc);
  if FuncLoadError then
  begin
    EVP_desx_cbc :=  @ERROR_EVP_desx_cbc;
  end;

  EVP_des_ede3_wrap := LoadLibCryptoFunction('EVP_des_ede3_wrap');
  FuncLoadError := not assigned(EVP_des_ede3_wrap);
  if FuncLoadError then
  begin
    EVP_des_ede3_wrap :=  @ERROR_EVP_des_ede3_wrap;
  end;

  EVP_rc4 := LoadLibCryptoFunction('EVP_rc4');
  FuncLoadError := not assigned(EVP_rc4);
  if FuncLoadError then
  begin
    EVP_rc4 :=  @ERROR_EVP_rc4;
  end;

  EVP_rc4_40 := LoadLibCryptoFunction('EVP_rc4_40');
  FuncLoadError := not assigned(EVP_rc4_40);
  if FuncLoadError then
  begin
    EVP_rc4_40 :=  @ERROR_EVP_rc4_40;
  end;

  EVP_rc2_ecb := LoadLibCryptoFunction('EVP_rc2_ecb');
  FuncLoadError := not assigned(EVP_rc2_ecb);
  if FuncLoadError then
  begin
    EVP_rc2_ecb :=  @ERROR_EVP_rc2_ecb;
  end;

  EVP_rc2_cbc := LoadLibCryptoFunction('EVP_rc2_cbc');
  FuncLoadError := not assigned(EVP_rc2_cbc);
  if FuncLoadError then
  begin
    EVP_rc2_cbc :=  @ERROR_EVP_rc2_cbc;
  end;

  EVP_rc2_40_cbc := LoadLibCryptoFunction('EVP_rc2_40_cbc');
  FuncLoadError := not assigned(EVP_rc2_40_cbc);
  if FuncLoadError then
  begin
    EVP_rc2_40_cbc :=  @ERROR_EVP_rc2_40_cbc;
  end;

  EVP_rc2_64_cbc := LoadLibCryptoFunction('EVP_rc2_64_cbc');
  FuncLoadError := not assigned(EVP_rc2_64_cbc);
  if FuncLoadError then
  begin
    EVP_rc2_64_cbc :=  @ERROR_EVP_rc2_64_cbc;
  end;

  EVP_rc2_cfb64 := LoadLibCryptoFunction('EVP_rc2_cfb64');
  FuncLoadError := not assigned(EVP_rc2_cfb64);
  if FuncLoadError then
  begin
    EVP_rc2_cfb64 :=  @ERROR_EVP_rc2_cfb64;
  end;

  EVP_rc2_ofb := LoadLibCryptoFunction('EVP_rc2_ofb');
  FuncLoadError := not assigned(EVP_rc2_ofb);
  if FuncLoadError then
  begin
    EVP_rc2_ofb :=  @ERROR_EVP_rc2_ofb;
  end;

  EVP_bf_ecb := LoadLibCryptoFunction('EVP_bf_ecb');
  FuncLoadError := not assigned(EVP_bf_ecb);
  if FuncLoadError then
  begin
    EVP_bf_ecb :=  @ERROR_EVP_bf_ecb;
  end;

  EVP_bf_cbc := LoadLibCryptoFunction('EVP_bf_cbc');
  FuncLoadError := not assigned(EVP_bf_cbc);
  if FuncLoadError then
  begin
    EVP_bf_cbc :=  @ERROR_EVP_bf_cbc;
  end;

  EVP_bf_cfb64 := LoadLibCryptoFunction('EVP_bf_cfb64');
  FuncLoadError := not assigned(EVP_bf_cfb64);
  if FuncLoadError then
  begin
    EVP_bf_cfb64 :=  @ERROR_EVP_bf_cfb64;
  end;

  EVP_bf_ofb := LoadLibCryptoFunction('EVP_bf_ofb');
  FuncLoadError := not assigned(EVP_bf_ofb);
  if FuncLoadError then
  begin
    EVP_bf_ofb :=  @ERROR_EVP_bf_ofb;
  end;

  EVP_cast5_ecb := LoadLibCryptoFunction('EVP_cast5_ecb');
  FuncLoadError := not assigned(EVP_cast5_ecb);
  if FuncLoadError then
  begin
    EVP_cast5_ecb :=  @ERROR_EVP_cast5_ecb;
  end;

  EVP_cast5_cbc := LoadLibCryptoFunction('EVP_cast5_cbc');
  FuncLoadError := not assigned(EVP_cast5_cbc);
  if FuncLoadError then
  begin
    EVP_cast5_cbc :=  @ERROR_EVP_cast5_cbc;
  end;

  EVP_cast5_cfb64 := LoadLibCryptoFunction('EVP_cast5_cfb64');
  FuncLoadError := not assigned(EVP_cast5_cfb64);
  if FuncLoadError then
  begin
    EVP_cast5_cfb64 :=  @ERROR_EVP_cast5_cfb64;
  end;

  EVP_cast5_ofb := LoadLibCryptoFunction('EVP_cast5_ofb');
  FuncLoadError := not assigned(EVP_cast5_ofb);
  if FuncLoadError then
  begin
    EVP_cast5_ofb :=  @ERROR_EVP_cast5_ofb;
  end;

  EVP_aes_128_ecb := LoadLibCryptoFunction('EVP_aes_128_ecb');
  FuncLoadError := not assigned(EVP_aes_128_ecb);
  if FuncLoadError then
  begin
    EVP_aes_128_ecb :=  @ERROR_EVP_aes_128_ecb;
  end;

  EVP_aes_128_cbc := LoadLibCryptoFunction('EVP_aes_128_cbc');
  FuncLoadError := not assigned(EVP_aes_128_cbc);
  if FuncLoadError then
  begin
    EVP_aes_128_cbc :=  @ERROR_EVP_aes_128_cbc;
  end;

  EVP_aes_128_cfb1 := LoadLibCryptoFunction('EVP_aes_128_cfb1');
  FuncLoadError := not assigned(EVP_aes_128_cfb1);
  if FuncLoadError then
  begin
    EVP_aes_128_cfb1 :=  @ERROR_EVP_aes_128_cfb1;
  end;

  EVP_aes_128_cfb8 := LoadLibCryptoFunction('EVP_aes_128_cfb8');
  FuncLoadError := not assigned(EVP_aes_128_cfb8);
  if FuncLoadError then
  begin
    EVP_aes_128_cfb8 :=  @ERROR_EVP_aes_128_cfb8;
  end;

  EVP_aes_128_cfb128 := LoadLibCryptoFunction('EVP_aes_128_cfb128');
  FuncLoadError := not assigned(EVP_aes_128_cfb128);
  if FuncLoadError then
  begin
    EVP_aes_128_cfb128 :=  @ERROR_EVP_aes_128_cfb128;
  end;

  EVP_aes_128_ofb := LoadLibCryptoFunction('EVP_aes_128_ofb');
  FuncLoadError := not assigned(EVP_aes_128_ofb);
  if FuncLoadError then
  begin
    EVP_aes_128_ofb :=  @ERROR_EVP_aes_128_ofb;
  end;

  EVP_aes_128_ctr := LoadLibCryptoFunction('EVP_aes_128_ctr');
  FuncLoadError := not assigned(EVP_aes_128_ctr);
  if FuncLoadError then
  begin
    EVP_aes_128_ctr :=  @ERROR_EVP_aes_128_ctr;
  end;

  EVP_aes_128_ccm := LoadLibCryptoFunction('EVP_aes_128_ccm');
  FuncLoadError := not assigned(EVP_aes_128_ccm);
  if FuncLoadError then
  begin
    EVP_aes_128_ccm :=  @ERROR_EVP_aes_128_ccm;
  end;

  EVP_aes_128_gcm := LoadLibCryptoFunction('EVP_aes_128_gcm');
  FuncLoadError := not assigned(EVP_aes_128_gcm);
  if FuncLoadError then
  begin
    EVP_aes_128_gcm :=  @ERROR_EVP_aes_128_gcm;
  end;

  EVP_aes_128_xts := LoadLibCryptoFunction('EVP_aes_128_xts');
  FuncLoadError := not assigned(EVP_aes_128_xts);
  if FuncLoadError then
  begin
    EVP_aes_128_xts :=  @ERROR_EVP_aes_128_xts;
  end;

  EVP_aes_128_wrap := LoadLibCryptoFunction('EVP_aes_128_wrap');
  FuncLoadError := not assigned(EVP_aes_128_wrap);
  if FuncLoadError then
  begin
    EVP_aes_128_wrap :=  @ERROR_EVP_aes_128_wrap;
  end;

  EVP_aes_128_wrap_pad := LoadLibCryptoFunction('EVP_aes_128_wrap_pad');
  FuncLoadError := not assigned(EVP_aes_128_wrap_pad);
  if FuncLoadError then
  begin
    EVP_aes_128_wrap_pad :=  @ERROR_EVP_aes_128_wrap_pad;
  end;

  EVP_aes_128_ocb := LoadLibCryptoFunction('EVP_aes_128_ocb');
  FuncLoadError := not assigned(EVP_aes_128_ocb);
  if FuncLoadError then
  begin
    EVP_aes_128_ocb :=  @ERROR_EVP_aes_128_ocb;
  end;

  EVP_aes_192_ecb := LoadLibCryptoFunction('EVP_aes_192_ecb');
  FuncLoadError := not assigned(EVP_aes_192_ecb);
  if FuncLoadError then
  begin
    EVP_aes_192_ecb :=  @ERROR_EVP_aes_192_ecb;
  end;

  EVP_aes_192_cbc := LoadLibCryptoFunction('EVP_aes_192_cbc');
  FuncLoadError := not assigned(EVP_aes_192_cbc);
  if FuncLoadError then
  begin
    EVP_aes_192_cbc :=  @ERROR_EVP_aes_192_cbc;
  end;

  EVP_aes_192_cfb1 := LoadLibCryptoFunction('EVP_aes_192_cfb1');
  FuncLoadError := not assigned(EVP_aes_192_cfb1);
  if FuncLoadError then
  begin
    EVP_aes_192_cfb1 :=  @ERROR_EVP_aes_192_cfb1;
  end;

  EVP_aes_192_cfb8 := LoadLibCryptoFunction('EVP_aes_192_cfb8');
  FuncLoadError := not assigned(EVP_aes_192_cfb8);
  if FuncLoadError then
  begin
    EVP_aes_192_cfb8 :=  @ERROR_EVP_aes_192_cfb8;
  end;

  EVP_aes_192_cfb128 := LoadLibCryptoFunction('EVP_aes_192_cfb128');
  FuncLoadError := not assigned(EVP_aes_192_cfb128);
  if FuncLoadError then
  begin
    EVP_aes_192_cfb128 :=  @ERROR_EVP_aes_192_cfb128;
  end;

  EVP_aes_192_ofb := LoadLibCryptoFunction('EVP_aes_192_ofb');
  FuncLoadError := not assigned(EVP_aes_192_ofb);
  if FuncLoadError then
  begin
    EVP_aes_192_ofb :=  @ERROR_EVP_aes_192_ofb;
  end;

  EVP_aes_192_ctr := LoadLibCryptoFunction('EVP_aes_192_ctr');
  FuncLoadError := not assigned(EVP_aes_192_ctr);
  if FuncLoadError then
  begin
    EVP_aes_192_ctr :=  @ERROR_EVP_aes_192_ctr;
  end;

  EVP_aes_192_ccm := LoadLibCryptoFunction('EVP_aes_192_ccm');
  FuncLoadError := not assigned(EVP_aes_192_ccm);
  if FuncLoadError then
  begin
    EVP_aes_192_ccm :=  @ERROR_EVP_aes_192_ccm;
  end;

  EVP_aes_192_gcm := LoadLibCryptoFunction('EVP_aes_192_gcm');
  FuncLoadError := not assigned(EVP_aes_192_gcm);
  if FuncLoadError then
  begin
    EVP_aes_192_gcm :=  @ERROR_EVP_aes_192_gcm;
  end;

  EVP_aes_192_wrap := LoadLibCryptoFunction('EVP_aes_192_wrap');
  FuncLoadError := not assigned(EVP_aes_192_wrap);
  if FuncLoadError then
  begin
    EVP_aes_192_wrap :=  @ERROR_EVP_aes_192_wrap;
  end;

  EVP_aes_192_wrap_pad := LoadLibCryptoFunction('EVP_aes_192_wrap_pad');
  FuncLoadError := not assigned(EVP_aes_192_wrap_pad);
  if FuncLoadError then
  begin
    EVP_aes_192_wrap_pad :=  @ERROR_EVP_aes_192_wrap_pad;
  end;

  EVP_aes_192_ocb := LoadLibCryptoFunction('EVP_aes_192_ocb');
  FuncLoadError := not assigned(EVP_aes_192_ocb);
  if FuncLoadError then
  begin
    EVP_aes_192_ocb :=  @ERROR_EVP_aes_192_ocb;
  end;

  EVP_aes_256_ecb := LoadLibCryptoFunction('EVP_aes_256_ecb');
  FuncLoadError := not assigned(EVP_aes_256_ecb);
  if FuncLoadError then
  begin
    EVP_aes_256_ecb :=  @ERROR_EVP_aes_256_ecb;
  end;

  EVP_aes_256_cbc := LoadLibCryptoFunction('EVP_aes_256_cbc');
  FuncLoadError := not assigned(EVP_aes_256_cbc);
  if FuncLoadError then
  begin
    EVP_aes_256_cbc :=  @ERROR_EVP_aes_256_cbc;
  end;

  EVP_aes_256_cfb1 := LoadLibCryptoFunction('EVP_aes_256_cfb1');
  FuncLoadError := not assigned(EVP_aes_256_cfb1);
  if FuncLoadError then
  begin
    EVP_aes_256_cfb1 :=  @ERROR_EVP_aes_256_cfb1;
  end;

  EVP_aes_256_cfb8 := LoadLibCryptoFunction('EVP_aes_256_cfb8');
  FuncLoadError := not assigned(EVP_aes_256_cfb8);
  if FuncLoadError then
  begin
    EVP_aes_256_cfb8 :=  @ERROR_EVP_aes_256_cfb8;
  end;

  EVP_aes_256_cfb128 := LoadLibCryptoFunction('EVP_aes_256_cfb128');
  FuncLoadError := not assigned(EVP_aes_256_cfb128);
  if FuncLoadError then
  begin
    EVP_aes_256_cfb128 :=  @ERROR_EVP_aes_256_cfb128;
  end;

  EVP_aes_256_ofb := LoadLibCryptoFunction('EVP_aes_256_ofb');
  FuncLoadError := not assigned(EVP_aes_256_ofb);
  if FuncLoadError then
  begin
    EVP_aes_256_ofb :=  @ERROR_EVP_aes_256_ofb;
  end;

  EVP_aes_256_ctr := LoadLibCryptoFunction('EVP_aes_256_ctr');
  FuncLoadError := not assigned(EVP_aes_256_ctr);
  if FuncLoadError then
  begin
    EVP_aes_256_ctr :=  @ERROR_EVP_aes_256_ctr;
  end;

  EVP_aes_256_ccm := LoadLibCryptoFunction('EVP_aes_256_ccm');
  FuncLoadError := not assigned(EVP_aes_256_ccm);
  if FuncLoadError then
  begin
    EVP_aes_256_ccm :=  @ERROR_EVP_aes_256_ccm;
  end;

  EVP_aes_256_gcm := LoadLibCryptoFunction('EVP_aes_256_gcm');
  FuncLoadError := not assigned(EVP_aes_256_gcm);
  if FuncLoadError then
  begin
    EVP_aes_256_gcm :=  @ERROR_EVP_aes_256_gcm;
  end;

  EVP_aes_256_xts := LoadLibCryptoFunction('EVP_aes_256_xts');
  FuncLoadError := not assigned(EVP_aes_256_xts);
  if FuncLoadError then
  begin
    EVP_aes_256_xts :=  @ERROR_EVP_aes_256_xts;
  end;

  EVP_aes_256_wrap := LoadLibCryptoFunction('EVP_aes_256_wrap');
  FuncLoadError := not assigned(EVP_aes_256_wrap);
  if FuncLoadError then
  begin
    EVP_aes_256_wrap :=  @ERROR_EVP_aes_256_wrap;
  end;

  EVP_aes_256_wrap_pad := LoadLibCryptoFunction('EVP_aes_256_wrap_pad');
  FuncLoadError := not assigned(EVP_aes_256_wrap_pad);
  if FuncLoadError then
  begin
    EVP_aes_256_wrap_pad :=  @ERROR_EVP_aes_256_wrap_pad;
  end;

  EVP_aes_256_ocb := LoadLibCryptoFunction('EVP_aes_256_ocb');
  FuncLoadError := not assigned(EVP_aes_256_ocb);
  if FuncLoadError then
  begin
    EVP_aes_256_ocb :=  @ERROR_EVP_aes_256_ocb;
  end;

  EVP_aes_128_cbc_hmac_sha1 := LoadLibCryptoFunction('EVP_aes_128_cbc_hmac_sha1');
  FuncLoadError := not assigned(EVP_aes_128_cbc_hmac_sha1);
  if FuncLoadError then
  begin
    EVP_aes_128_cbc_hmac_sha1 :=  @ERROR_EVP_aes_128_cbc_hmac_sha1;
  end;

  EVP_aes_256_cbc_hmac_sha1 := LoadLibCryptoFunction('EVP_aes_256_cbc_hmac_sha1');
  FuncLoadError := not assigned(EVP_aes_256_cbc_hmac_sha1);
  if FuncLoadError then
  begin
    EVP_aes_256_cbc_hmac_sha1 :=  @ERROR_EVP_aes_256_cbc_hmac_sha1;
  end;

  EVP_aes_128_cbc_hmac_sha256 := LoadLibCryptoFunction('EVP_aes_128_cbc_hmac_sha256');
  FuncLoadError := not assigned(EVP_aes_128_cbc_hmac_sha256);
  if FuncLoadError then
  begin
    EVP_aes_128_cbc_hmac_sha256 :=  @ERROR_EVP_aes_128_cbc_hmac_sha256;
  end;

  EVP_aes_256_cbc_hmac_sha256 := LoadLibCryptoFunction('EVP_aes_256_cbc_hmac_sha256');
  FuncLoadError := not assigned(EVP_aes_256_cbc_hmac_sha256);
  if FuncLoadError then
  begin
    EVP_aes_256_cbc_hmac_sha256 :=  @ERROR_EVP_aes_256_cbc_hmac_sha256;
  end;

  EVP_aria_128_ecb := LoadLibCryptoFunction('EVP_aria_128_ecb');
  FuncLoadError := not assigned(EVP_aria_128_ecb);
  if FuncLoadError then
  begin
    EVP_aria_128_ecb :=  @ERROR_EVP_aria_128_ecb;
  end;

  EVP_aria_128_cbc := LoadLibCryptoFunction('EVP_aria_128_cbc');
  FuncLoadError := not assigned(EVP_aria_128_cbc);
  if FuncLoadError then
  begin
    EVP_aria_128_cbc :=  @ERROR_EVP_aria_128_cbc;
  end;

  EVP_aria_128_cfb1 := LoadLibCryptoFunction('EVP_aria_128_cfb1');
  FuncLoadError := not assigned(EVP_aria_128_cfb1);
  if FuncLoadError then
  begin
    EVP_aria_128_cfb1 :=  @ERROR_EVP_aria_128_cfb1;
  end;

  EVP_aria_128_cfb8 := LoadLibCryptoFunction('EVP_aria_128_cfb8');
  FuncLoadError := not assigned(EVP_aria_128_cfb8);
  if FuncLoadError then
  begin
    EVP_aria_128_cfb8 :=  @ERROR_EVP_aria_128_cfb8;
  end;

  EVP_aria_128_cfb128 := LoadLibCryptoFunction('EVP_aria_128_cfb128');
  FuncLoadError := not assigned(EVP_aria_128_cfb128);
  if FuncLoadError then
  begin
    EVP_aria_128_cfb128 :=  @ERROR_EVP_aria_128_cfb128;
  end;

  EVP_aria_128_ctr := LoadLibCryptoFunction('EVP_aria_128_ctr');
  FuncLoadError := not assigned(EVP_aria_128_ctr);
  if FuncLoadError then
  begin
    EVP_aria_128_ctr :=  @ERROR_EVP_aria_128_ctr;
  end;

  EVP_aria_128_ofb := LoadLibCryptoFunction('EVP_aria_128_ofb');
  FuncLoadError := not assigned(EVP_aria_128_ofb);
  if FuncLoadError then
  begin
    EVP_aria_128_ofb :=  @ERROR_EVP_aria_128_ofb;
  end;

  EVP_aria_128_gcm := LoadLibCryptoFunction('EVP_aria_128_gcm');
  FuncLoadError := not assigned(EVP_aria_128_gcm);
  if FuncLoadError then
  begin
    EVP_aria_128_gcm :=  @ERROR_EVP_aria_128_gcm;
  end;

  EVP_aria_128_ccm := LoadLibCryptoFunction('EVP_aria_128_ccm');
  FuncLoadError := not assigned(EVP_aria_128_ccm);
  if FuncLoadError then
  begin
    EVP_aria_128_ccm :=  @ERROR_EVP_aria_128_ccm;
  end;

  EVP_aria_192_ecb := LoadLibCryptoFunction('EVP_aria_192_ecb');
  FuncLoadError := not assigned(EVP_aria_192_ecb);
  if FuncLoadError then
  begin
    EVP_aria_192_ecb :=  @ERROR_EVP_aria_192_ecb;
  end;

  EVP_aria_192_cbc := LoadLibCryptoFunction('EVP_aria_192_cbc');
  FuncLoadError := not assigned(EVP_aria_192_cbc);
  if FuncLoadError then
  begin
    EVP_aria_192_cbc :=  @ERROR_EVP_aria_192_cbc;
  end;

  EVP_aria_192_cfb1 := LoadLibCryptoFunction('EVP_aria_192_cfb1');
  FuncLoadError := not assigned(EVP_aria_192_cfb1);
  if FuncLoadError then
  begin
    EVP_aria_192_cfb1 :=  @ERROR_EVP_aria_192_cfb1;
  end;

  EVP_aria_192_cfb8 := LoadLibCryptoFunction('EVP_aria_192_cfb8');
  FuncLoadError := not assigned(EVP_aria_192_cfb8);
  if FuncLoadError then
  begin
    EVP_aria_192_cfb8 :=  @ERROR_EVP_aria_192_cfb8;
  end;

  EVP_aria_192_cfb128 := LoadLibCryptoFunction('EVP_aria_192_cfb128');
  FuncLoadError := not assigned(EVP_aria_192_cfb128);
  if FuncLoadError then
  begin
    EVP_aria_192_cfb128 :=  @ERROR_EVP_aria_192_cfb128;
  end;

  EVP_aria_192_ctr := LoadLibCryptoFunction('EVP_aria_192_ctr');
  FuncLoadError := not assigned(EVP_aria_192_ctr);
  if FuncLoadError then
  begin
    EVP_aria_192_ctr :=  @ERROR_EVP_aria_192_ctr;
  end;

  EVP_aria_192_ofb := LoadLibCryptoFunction('EVP_aria_192_ofb');
  FuncLoadError := not assigned(EVP_aria_192_ofb);
  if FuncLoadError then
  begin
    EVP_aria_192_ofb :=  @ERROR_EVP_aria_192_ofb;
  end;

  EVP_aria_192_gcm := LoadLibCryptoFunction('EVP_aria_192_gcm');
  FuncLoadError := not assigned(EVP_aria_192_gcm);
  if FuncLoadError then
  begin
    EVP_aria_192_gcm :=  @ERROR_EVP_aria_192_gcm;
  end;

  EVP_aria_192_ccm := LoadLibCryptoFunction('EVP_aria_192_ccm');
  FuncLoadError := not assigned(EVP_aria_192_ccm);
  if FuncLoadError then
  begin
    EVP_aria_192_ccm :=  @ERROR_EVP_aria_192_ccm;
  end;

  EVP_aria_256_ecb := LoadLibCryptoFunction('EVP_aria_256_ecb');
  FuncLoadError := not assigned(EVP_aria_256_ecb);
  if FuncLoadError then
  begin
    EVP_aria_256_ecb :=  @ERROR_EVP_aria_256_ecb;
  end;

  EVP_aria_256_cbc := LoadLibCryptoFunction('EVP_aria_256_cbc');
  FuncLoadError := not assigned(EVP_aria_256_cbc);
  if FuncLoadError then
  begin
    EVP_aria_256_cbc :=  @ERROR_EVP_aria_256_cbc;
  end;

  EVP_aria_256_cfb1 := LoadLibCryptoFunction('EVP_aria_256_cfb1');
  FuncLoadError := not assigned(EVP_aria_256_cfb1);
  if FuncLoadError then
  begin
    EVP_aria_256_cfb1 :=  @ERROR_EVP_aria_256_cfb1;
  end;

  EVP_aria_256_cfb8 := LoadLibCryptoFunction('EVP_aria_256_cfb8');
  FuncLoadError := not assigned(EVP_aria_256_cfb8);
  if FuncLoadError then
  begin
    EVP_aria_256_cfb8 :=  @ERROR_EVP_aria_256_cfb8;
  end;

  EVP_aria_256_cfb128 := LoadLibCryptoFunction('EVP_aria_256_cfb128');
  FuncLoadError := not assigned(EVP_aria_256_cfb128);
  if FuncLoadError then
  begin
    EVP_aria_256_cfb128 :=  @ERROR_EVP_aria_256_cfb128;
  end;

  EVP_aria_256_ctr := LoadLibCryptoFunction('EVP_aria_256_ctr');
  FuncLoadError := not assigned(EVP_aria_256_ctr);
  if FuncLoadError then
  begin
    EVP_aria_256_ctr :=  @ERROR_EVP_aria_256_ctr;
  end;

  EVP_aria_256_ofb := LoadLibCryptoFunction('EVP_aria_256_ofb');
  FuncLoadError := not assigned(EVP_aria_256_ofb);
  if FuncLoadError then
  begin
    EVP_aria_256_ofb :=  @ERROR_EVP_aria_256_ofb;
  end;

  EVP_aria_256_gcm := LoadLibCryptoFunction('EVP_aria_256_gcm');
  FuncLoadError := not assigned(EVP_aria_256_gcm);
  if FuncLoadError then
  begin
    EVP_aria_256_gcm :=  @ERROR_EVP_aria_256_gcm;
  end;

  EVP_aria_256_ccm := LoadLibCryptoFunction('EVP_aria_256_ccm');
  FuncLoadError := not assigned(EVP_aria_256_ccm);
  if FuncLoadError then
  begin
    EVP_aria_256_ccm :=  @ERROR_EVP_aria_256_ccm;
  end;

  EVP_camellia_128_ecb := LoadLibCryptoFunction('EVP_camellia_128_ecb');
  FuncLoadError := not assigned(EVP_camellia_128_ecb);
  if FuncLoadError then
  begin
    EVP_camellia_128_ecb :=  @ERROR_EVP_camellia_128_ecb;
  end;

  EVP_camellia_128_cbc := LoadLibCryptoFunction('EVP_camellia_128_cbc');
  FuncLoadError := not assigned(EVP_camellia_128_cbc);
  if FuncLoadError then
  begin
    EVP_camellia_128_cbc :=  @ERROR_EVP_camellia_128_cbc;
  end;

  EVP_camellia_128_cfb1 := LoadLibCryptoFunction('EVP_camellia_128_cfb1');
  FuncLoadError := not assigned(EVP_camellia_128_cfb1);
  if FuncLoadError then
  begin
    EVP_camellia_128_cfb1 :=  @ERROR_EVP_camellia_128_cfb1;
  end;

  EVP_camellia_128_cfb8 := LoadLibCryptoFunction('EVP_camellia_128_cfb8');
  FuncLoadError := not assigned(EVP_camellia_128_cfb8);
  if FuncLoadError then
  begin
    EVP_camellia_128_cfb8 :=  @ERROR_EVP_camellia_128_cfb8;
  end;

  EVP_camellia_128_cfb128 := LoadLibCryptoFunction('EVP_camellia_128_cfb128');
  FuncLoadError := not assigned(EVP_camellia_128_cfb128);
  if FuncLoadError then
  begin
    EVP_camellia_128_cfb128 :=  @ERROR_EVP_camellia_128_cfb128;
  end;

  EVP_camellia_128_ofb := LoadLibCryptoFunction('EVP_camellia_128_ofb');
  FuncLoadError := not assigned(EVP_camellia_128_ofb);
  if FuncLoadError then
  begin
    EVP_camellia_128_ofb :=  @ERROR_EVP_camellia_128_ofb;
  end;

  EVP_camellia_128_ctr := LoadLibCryptoFunction('EVP_camellia_128_ctr');
  FuncLoadError := not assigned(EVP_camellia_128_ctr);
  if FuncLoadError then
  begin
    EVP_camellia_128_ctr :=  @ERROR_EVP_camellia_128_ctr;
  end;

  EVP_camellia_192_ecb := LoadLibCryptoFunction('EVP_camellia_192_ecb');
  FuncLoadError := not assigned(EVP_camellia_192_ecb);
  if FuncLoadError then
  begin
    EVP_camellia_192_ecb :=  @ERROR_EVP_camellia_192_ecb;
  end;

  EVP_camellia_192_cbc := LoadLibCryptoFunction('EVP_camellia_192_cbc');
  FuncLoadError := not assigned(EVP_camellia_192_cbc);
  if FuncLoadError then
  begin
    EVP_camellia_192_cbc :=  @ERROR_EVP_camellia_192_cbc;
  end;

  EVP_camellia_192_cfb1 := LoadLibCryptoFunction('EVP_camellia_192_cfb1');
  FuncLoadError := not assigned(EVP_camellia_192_cfb1);
  if FuncLoadError then
  begin
    EVP_camellia_192_cfb1 :=  @ERROR_EVP_camellia_192_cfb1;
  end;

  EVP_camellia_192_cfb8 := LoadLibCryptoFunction('EVP_camellia_192_cfb8');
  FuncLoadError := not assigned(EVP_camellia_192_cfb8);
  if FuncLoadError then
  begin
    EVP_camellia_192_cfb8 :=  @ERROR_EVP_camellia_192_cfb8;
  end;

  EVP_camellia_192_cfb128 := LoadLibCryptoFunction('EVP_camellia_192_cfb128');
  FuncLoadError := not assigned(EVP_camellia_192_cfb128);
  if FuncLoadError then
  begin
    EVP_camellia_192_cfb128 :=  @ERROR_EVP_camellia_192_cfb128;
  end;

  EVP_camellia_192_ofb := LoadLibCryptoFunction('EVP_camellia_192_ofb');
  FuncLoadError := not assigned(EVP_camellia_192_ofb);
  if FuncLoadError then
  begin
    EVP_camellia_192_ofb :=  @ERROR_EVP_camellia_192_ofb;
  end;

  EVP_camellia_192_ctr := LoadLibCryptoFunction('EVP_camellia_192_ctr');
  FuncLoadError := not assigned(EVP_camellia_192_ctr);
  if FuncLoadError then
  begin
    EVP_camellia_192_ctr :=  @ERROR_EVP_camellia_192_ctr;
  end;

  EVP_camellia_256_ecb := LoadLibCryptoFunction('EVP_camellia_256_ecb');
  FuncLoadError := not assigned(EVP_camellia_256_ecb);
  if FuncLoadError then
  begin
    EVP_camellia_256_ecb :=  @ERROR_EVP_camellia_256_ecb;
  end;

  EVP_camellia_256_cbc := LoadLibCryptoFunction('EVP_camellia_256_cbc');
  FuncLoadError := not assigned(EVP_camellia_256_cbc);
  if FuncLoadError then
  begin
    EVP_camellia_256_cbc :=  @ERROR_EVP_camellia_256_cbc;
  end;

  EVP_camellia_256_cfb1 := LoadLibCryptoFunction('EVP_camellia_256_cfb1');
  FuncLoadError := not assigned(EVP_camellia_256_cfb1);
  if FuncLoadError then
  begin
    EVP_camellia_256_cfb1 :=  @ERROR_EVP_camellia_256_cfb1;
  end;

  EVP_camellia_256_cfb8 := LoadLibCryptoFunction('EVP_camellia_256_cfb8');
  FuncLoadError := not assigned(EVP_camellia_256_cfb8);
  if FuncLoadError then
  begin
    EVP_camellia_256_cfb8 :=  @ERROR_EVP_camellia_256_cfb8;
  end;

  EVP_camellia_256_cfb128 := LoadLibCryptoFunction('EVP_camellia_256_cfb128');
  FuncLoadError := not assigned(EVP_camellia_256_cfb128);
  if FuncLoadError then
  begin
    EVP_camellia_256_cfb128 :=  @ERROR_EVP_camellia_256_cfb128;
  end;

  EVP_camellia_256_ofb := LoadLibCryptoFunction('EVP_camellia_256_ofb');
  FuncLoadError := not assigned(EVP_camellia_256_ofb);
  if FuncLoadError then
  begin
    EVP_camellia_256_ofb :=  @ERROR_EVP_camellia_256_ofb;
  end;

  EVP_camellia_256_ctr := LoadLibCryptoFunction('EVP_camellia_256_ctr');
  FuncLoadError := not assigned(EVP_camellia_256_ctr);
  if FuncLoadError then
  begin
    EVP_camellia_256_ctr :=  @ERROR_EVP_camellia_256_ctr;
  end;

  EVP_chacha20 := LoadLibCryptoFunction('EVP_chacha20');
  FuncLoadError := not assigned(EVP_chacha20);
  if FuncLoadError then
  begin
    EVP_chacha20 :=  @ERROR_EVP_chacha20;
  end;

  EVP_chacha20_poly1305 := LoadLibCryptoFunction('EVP_chacha20_poly1305');
  FuncLoadError := not assigned(EVP_chacha20_poly1305);
  if FuncLoadError then
  begin
    EVP_chacha20_poly1305 :=  @ERROR_EVP_chacha20_poly1305;
  end;

  EVP_seed_ecb := LoadLibCryptoFunction('EVP_seed_ecb');
  FuncLoadError := not assigned(EVP_seed_ecb);
  if FuncLoadError then
  begin
    EVP_seed_ecb :=  @ERROR_EVP_seed_ecb;
  end;

  EVP_seed_cbc := LoadLibCryptoFunction('EVP_seed_cbc');
  FuncLoadError := not assigned(EVP_seed_cbc);
  if FuncLoadError then
  begin
    EVP_seed_cbc :=  @ERROR_EVP_seed_cbc;
  end;

  EVP_seed_cfb128 := LoadLibCryptoFunction('EVP_seed_cfb128');
  FuncLoadError := not assigned(EVP_seed_cfb128);
  if FuncLoadError then
  begin
    EVP_seed_cfb128 :=  @ERROR_EVP_seed_cfb128;
  end;

  EVP_seed_ofb := LoadLibCryptoFunction('EVP_seed_ofb');
  FuncLoadError := not assigned(EVP_seed_ofb);
  if FuncLoadError then
  begin
    EVP_seed_ofb :=  @ERROR_EVP_seed_ofb;
  end;

  EVP_sm4_ecb := LoadLibCryptoFunction('EVP_sm4_ecb');
  FuncLoadError := not assigned(EVP_sm4_ecb);
  if FuncLoadError then
  begin
    EVP_sm4_ecb :=  @ERROR_EVP_sm4_ecb;
  end;

  EVP_sm4_cbc := LoadLibCryptoFunction('EVP_sm4_cbc');
  FuncLoadError := not assigned(EVP_sm4_cbc);
  if FuncLoadError then
  begin
    EVP_sm4_cbc :=  @ERROR_EVP_sm4_cbc;
  end;

  EVP_sm4_cfb128 := LoadLibCryptoFunction('EVP_sm4_cfb128');
  FuncLoadError := not assigned(EVP_sm4_cfb128);
  if FuncLoadError then
  begin
    EVP_sm4_cfb128 :=  @ERROR_EVP_sm4_cfb128;
  end;

  EVP_sm4_ofb := LoadLibCryptoFunction('EVP_sm4_ofb');
  FuncLoadError := not assigned(EVP_sm4_ofb);
  if FuncLoadError then
  begin
    EVP_sm4_ofb :=  @ERROR_EVP_sm4_ofb;
  end;

  EVP_sm4_ctr := LoadLibCryptoFunction('EVP_sm4_ctr');
  FuncLoadError := not assigned(EVP_sm4_ctr);
  if FuncLoadError then
  begin
    EVP_sm4_ctr :=  @ERROR_EVP_sm4_ctr;
  end;

  EVP_add_cipher := LoadLibCryptoFunction('EVP_add_cipher');
  FuncLoadError := not assigned(EVP_add_cipher);
  if FuncLoadError then
  begin
    EVP_add_cipher :=  @ERROR_EVP_add_cipher;
  end;

  EVP_add_digest := LoadLibCryptoFunction('EVP_add_digest');
  FuncLoadError := not assigned(EVP_add_digest);
  if FuncLoadError then
  begin
    EVP_add_digest :=  @ERROR_EVP_add_digest;
  end;

  EVP_get_cipherbyname := LoadLibCryptoFunction('EVP_get_cipherbyname');
  FuncLoadError := not assigned(EVP_get_cipherbyname);
  if FuncLoadError then
  begin
    EVP_get_cipherbyname :=  @ERROR_EVP_get_cipherbyname;
  end;

  EVP_get_digestbyname := LoadLibCryptoFunction('EVP_get_digestbyname');
  FuncLoadError := not assigned(EVP_get_digestbyname);
  if FuncLoadError then
  begin
    EVP_get_digestbyname :=  @ERROR_EVP_get_digestbyname;
  end;

  EVP_CIPHER_do_all := LoadLibCryptoFunction('EVP_CIPHER_do_all');
  FuncLoadError := not assigned(EVP_CIPHER_do_all);
  if FuncLoadError then
  begin
    EVP_CIPHER_do_all :=  @ERROR_EVP_CIPHER_do_all;
  end;

  EVP_CIPHER_do_all_sorted := LoadLibCryptoFunction('EVP_CIPHER_do_all_sorted');
  FuncLoadError := not assigned(EVP_CIPHER_do_all_sorted);
  if FuncLoadError then
  begin
    EVP_CIPHER_do_all_sorted :=  @ERROR_EVP_CIPHER_do_all_sorted;
  end;

  EVP_MD_do_all := LoadLibCryptoFunction('EVP_MD_do_all');
  FuncLoadError := not assigned(EVP_MD_do_all);
  if FuncLoadError then
  begin
    EVP_MD_do_all :=  @ERROR_EVP_MD_do_all;
  end;

  EVP_MD_do_all_sorted := LoadLibCryptoFunction('EVP_MD_do_all_sorted');
  FuncLoadError := not assigned(EVP_MD_do_all_sorted);
  if FuncLoadError then
  begin
    EVP_MD_do_all_sorted :=  @ERROR_EVP_MD_do_all_sorted;
  end;

  EVP_PKEY_decrypt_old := LoadLibCryptoFunction('EVP_PKEY_decrypt_old');
  FuncLoadError := not assigned(EVP_PKEY_decrypt_old);
  if FuncLoadError then
  begin
    EVP_PKEY_decrypt_old :=  @ERROR_EVP_PKEY_decrypt_old;
  end;

  EVP_PKEY_encrypt_old := LoadLibCryptoFunction('EVP_PKEY_encrypt_old');
  FuncLoadError := not assigned(EVP_PKEY_encrypt_old);
  if FuncLoadError then
  begin
    EVP_PKEY_encrypt_old :=  @ERROR_EVP_PKEY_encrypt_old;
  end;

  EVP_PKEY_type := LoadLibCryptoFunction('EVP_PKEY_type');
  FuncLoadError := not assigned(EVP_PKEY_type);
  if FuncLoadError then
  begin
    EVP_PKEY_type :=  @ERROR_EVP_PKEY_type;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_id := LoadLibCryptoFunction('EVP_PKEY_id');
  FuncLoadError := not assigned(EVP_PKEY_id);
  if FuncLoadError then
  begin
    if EVP_PKEY_id_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_id');
  end;

  EVP_PKEY_base_id := LoadLibCryptoFunction('EVP_PKEY_base_id');
  FuncLoadError := not assigned(EVP_PKEY_base_id);
  if FuncLoadError then
  begin
    if EVP_PKEY_base_id_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_base_id');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_base_id := LoadLibCryptoFunction('EVP_PKEY_get_base_id');
  FuncLoadError := not assigned(EVP_PKEY_get_base_id);
  if FuncLoadError then
  begin
    EVP_PKEY_get_base_id :=  @ERROR_EVP_PKEY_get_base_id;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_bits := LoadLibCryptoFunction('EVP_PKEY_bits');
  FuncLoadError := not assigned(EVP_PKEY_bits);
  if FuncLoadError then
  begin
    if EVP_PKEY_bits_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_bits');
  end;

  EVP_PKEY_security_bits := LoadLibCryptoFunction('EVP_PKEY_security_bits');
  FuncLoadError := not assigned(EVP_PKEY_security_bits);
  if FuncLoadError then
  begin
    EVP_PKEY_security_bits := @COMPAT_EVP_PKEY_security_bits;
    if EVP_PKEY_security_bits_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_security_bits');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_security_bits := LoadLibCryptoFunction('EVP_PKEY_get_security_bits');
  FuncLoadError := not assigned(EVP_PKEY_get_security_bits);
  if FuncLoadError then
  begin
    EVP_PKEY_get_security_bits :=  @ERROR_EVP_PKEY_get_security_bits;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_size := LoadLibCryptoFunction('EVP_PKEY_size');
  FuncLoadError := not assigned(EVP_PKEY_size);
  if FuncLoadError then
  begin
    EVP_PKEY_size := @COMPAT_EVP_PKEY_size;
    if EVP_PKEY_size_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_size');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_size := LoadLibCryptoFunction('EVP_PKEY_get_size');
  FuncLoadError := not assigned(EVP_PKEY_get_size);
  if FuncLoadError then
  begin
    EVP_PKEY_get_size :=  @ERROR_EVP_PKEY_get_size;
  end;

  EVP_PKEY_set_type := LoadLibCryptoFunction('EVP_PKEY_set_type');
  FuncLoadError := not assigned(EVP_PKEY_set_type);
  if FuncLoadError then
  begin
    EVP_PKEY_set_type :=  @ERROR_EVP_PKEY_set_type;
  end;

  EVP_PKEY_set_type_str := LoadLibCryptoFunction('EVP_PKEY_set_type_str');
  FuncLoadError := not assigned(EVP_PKEY_set_type_str);
  if FuncLoadError then
  begin
    EVP_PKEY_set_type_str :=  @ERROR_EVP_PKEY_set_type_str;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_set_alias_type := LoadLibCryptoFunction('EVP_PKEY_set_alias_type');
  FuncLoadError := not assigned(EVP_PKEY_set_alias_type);
  if FuncLoadError then
  begin
    if EVP_PKEY_set_alias_type_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set_alias_type');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_set1_engine := LoadLibCryptoFunction('EVP_PKEY_set1_engine');
  FuncLoadError := not assigned(EVP_PKEY_set1_engine);
  if FuncLoadError then
  begin
    EVP_PKEY_set1_engine :=  @ERROR_EVP_PKEY_set1_engine;
  end;

  EVP_PKEY_get0_engine := LoadLibCryptoFunction('EVP_PKEY_get0_engine');
  FuncLoadError := not assigned(EVP_PKEY_get0_engine);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_engine :=  @ERROR_EVP_PKEY_get0_engine;
  end;

  EVP_PKEY_assign := LoadLibCryptoFunction('EVP_PKEY_assign');
  FuncLoadError := not assigned(EVP_PKEY_assign);
  if FuncLoadError then
  begin
    EVP_PKEY_assign :=  @ERROR_EVP_PKEY_assign;
  end;

  EVP_PKEY_get0 := LoadLibCryptoFunction('EVP_PKEY_get0');
  FuncLoadError := not assigned(EVP_PKEY_get0);
  if FuncLoadError then
  begin
    EVP_PKEY_get0 :=  @ERROR_EVP_PKEY_get0;
  end;

  EVP_PKEY_get0_hmac := LoadLibCryptoFunction('EVP_PKEY_get0_hmac');
  FuncLoadError := not assigned(EVP_PKEY_get0_hmac);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_hmac :=  @ERROR_EVP_PKEY_get0_hmac;
  end;

  EVP_PKEY_get0_poly1305 := LoadLibCryptoFunction('EVP_PKEY_get0_poly1305');
  FuncLoadError := not assigned(EVP_PKEY_get0_poly1305);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_poly1305 :=  @ERROR_EVP_PKEY_get0_poly1305;
  end;

  EVP_PKEY_get0_siphash := LoadLibCryptoFunction('EVP_PKEY_get0_siphash');
  FuncLoadError := not assigned(EVP_PKEY_get0_siphash);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_siphash :=  @ERROR_EVP_PKEY_get0_siphash;
  end;

  EVP_PKEY_set1_RSA := LoadLibCryptoFunction('EVP_PKEY_set1_RSA');
  FuncLoadError := not assigned(EVP_PKEY_set1_RSA);
  if FuncLoadError then
  begin
    EVP_PKEY_set1_RSA :=  @ERROR_EVP_PKEY_set1_RSA;
  end;

  EVP_PKEY_get0_RSA := LoadLibCryptoFunction('EVP_PKEY_get0_RSA');
  FuncLoadError := not assigned(EVP_PKEY_get0_RSA);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_RSA :=  @ERROR_EVP_PKEY_get0_RSA;
  end;

  EVP_PKEY_get1_RSA := LoadLibCryptoFunction('EVP_PKEY_get1_RSA');
  FuncLoadError := not assigned(EVP_PKEY_get1_RSA);
  if FuncLoadError then
  begin
    EVP_PKEY_get1_RSA :=  @ERROR_EVP_PKEY_get1_RSA;
  end;

  EVP_PKEY_set1_DSA := LoadLibCryptoFunction('EVP_PKEY_set1_DSA');
  FuncLoadError := not assigned(EVP_PKEY_set1_DSA);
  if FuncLoadError then
  begin
    EVP_PKEY_set1_DSA :=  @ERROR_EVP_PKEY_set1_DSA;
  end;

  EVP_PKEY_get0_DSA := LoadLibCryptoFunction('EVP_PKEY_get0_DSA');
  FuncLoadError := not assigned(EVP_PKEY_get0_DSA);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_DSA :=  @ERROR_EVP_PKEY_get0_DSA;
  end;

  EVP_PKEY_get1_DSA := LoadLibCryptoFunction('EVP_PKEY_get1_DSA');
  FuncLoadError := not assigned(EVP_PKEY_get1_DSA);
  if FuncLoadError then
  begin
    EVP_PKEY_get1_DSA :=  @ERROR_EVP_PKEY_get1_DSA;
  end;

  EVP_PKEY_set1_DH := LoadLibCryptoFunction('EVP_PKEY_set1_DH');
  FuncLoadError := not assigned(EVP_PKEY_set1_DH);
  if FuncLoadError then
  begin
    EVP_PKEY_set1_DH :=  @ERROR_EVP_PKEY_set1_DH;
  end;

  EVP_PKEY_get0_DH := LoadLibCryptoFunction('EVP_PKEY_get0_DH');
  FuncLoadError := not assigned(EVP_PKEY_get0_DH);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_DH :=  @ERROR_EVP_PKEY_get0_DH;
  end;

  EVP_PKEY_get1_DH := LoadLibCryptoFunction('EVP_PKEY_get1_DH');
  FuncLoadError := not assigned(EVP_PKEY_get1_DH);
  if FuncLoadError then
  begin
    EVP_PKEY_get1_DH :=  @ERROR_EVP_PKEY_get1_DH;
  end;

  EVP_PKEY_set1_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_set1_EC_KEY');
  FuncLoadError := not assigned(EVP_PKEY_set1_EC_KEY);
  if FuncLoadError then
  begin
    EVP_PKEY_set1_EC_KEY :=  @ERROR_EVP_PKEY_set1_EC_KEY;
  end;

  EVP_PKEY_get0_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_get0_EC_KEY');
  FuncLoadError := not assigned(EVP_PKEY_get0_EC_KEY);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_EC_KEY :=  @ERROR_EVP_PKEY_get0_EC_KEY;
  end;

  EVP_PKEY_get1_EC_KEY := LoadLibCryptoFunction('EVP_PKEY_get1_EC_KEY');
  FuncLoadError := not assigned(EVP_PKEY_get1_EC_KEY);
  if FuncLoadError then
  begin
    EVP_PKEY_get1_EC_KEY :=  @ERROR_EVP_PKEY_get1_EC_KEY;
  end;

  EVP_PKEY_new := LoadLibCryptoFunction('EVP_PKEY_new');
  FuncLoadError := not assigned(EVP_PKEY_new);
  if FuncLoadError then
  begin
    EVP_PKEY_new :=  @ERROR_EVP_PKEY_new;
  end;

  EVP_PKEY_up_ref := LoadLibCryptoFunction('EVP_PKEY_up_ref');
  FuncLoadError := not assigned(EVP_PKEY_up_ref);
  if FuncLoadError then
  begin
    EVP_PKEY_up_ref :=  @ERROR_EVP_PKEY_up_ref;
  end;

  EVP_PKEY_free := LoadLibCryptoFunction('EVP_PKEY_free');
  FuncLoadError := not assigned(EVP_PKEY_free);
  if FuncLoadError then
  begin
    EVP_PKEY_free :=  @ERROR_EVP_PKEY_free;
  end;

  d2i_PublicKey := LoadLibCryptoFunction('d2i_PublicKey');
  FuncLoadError := not assigned(d2i_PublicKey);
  if FuncLoadError then
  begin
    d2i_PublicKey :=  @ERROR_d2i_PublicKey;
  end;

  i2d_PublicKey := LoadLibCryptoFunction('i2d_PublicKey');
  FuncLoadError := not assigned(i2d_PublicKey);
  if FuncLoadError then
  begin
    i2d_PublicKey :=  @ERROR_i2d_PublicKey;
  end;

  d2i_PrivateKey := LoadLibCryptoFunction('d2i_PrivateKey');
  FuncLoadError := not assigned(d2i_PrivateKey);
  if FuncLoadError then
  begin
    d2i_PrivateKey :=  @ERROR_d2i_PrivateKey;
  end;

  d2i_AutoPrivateKey := LoadLibCryptoFunction('d2i_AutoPrivateKey');
  FuncLoadError := not assigned(d2i_AutoPrivateKey);
  if FuncLoadError then
  begin
    d2i_AutoPrivateKey :=  @ERROR_d2i_AutoPrivateKey;
  end;

  i2d_PrivateKey := LoadLibCryptoFunction('i2d_PrivateKey');
  FuncLoadError := not assigned(i2d_PrivateKey);
  if FuncLoadError then
  begin
    i2d_PrivateKey :=  @ERROR_i2d_PrivateKey;
  end;

  EVP_PKEY_copy_parameters := LoadLibCryptoFunction('EVP_PKEY_copy_parameters');
  FuncLoadError := not assigned(EVP_PKEY_copy_parameters);
  if FuncLoadError then
  begin
    EVP_PKEY_copy_parameters :=  @ERROR_EVP_PKEY_copy_parameters;
  end;

  EVP_PKEY_missing_parameters := LoadLibCryptoFunction('EVP_PKEY_missing_parameters');
  FuncLoadError := not assigned(EVP_PKEY_missing_parameters);
  if FuncLoadError then
  begin
    EVP_PKEY_missing_parameters :=  @ERROR_EVP_PKEY_missing_parameters;
  end;

  EVP_PKEY_save_parameters := LoadLibCryptoFunction('EVP_PKEY_save_parameters');
  FuncLoadError := not assigned(EVP_PKEY_save_parameters);
  if FuncLoadError then
  begin
    EVP_PKEY_save_parameters :=  @ERROR_EVP_PKEY_save_parameters;
  end;

  EVP_PKEY_cmp_parameters := LoadLibCryptoFunction('EVP_PKEY_cmp_parameters');
  FuncLoadError := not assigned(EVP_PKEY_cmp_parameters);
  if FuncLoadError then
  begin
    EVP_PKEY_cmp_parameters :=  @ERROR_EVP_PKEY_cmp_parameters;
  end;

  EVP_PKEY_cmp := LoadLibCryptoFunction('EVP_PKEY_cmp');
  FuncLoadError := not assigned(EVP_PKEY_cmp);
  if FuncLoadError then
  begin
    EVP_PKEY_cmp :=  @ERROR_EVP_PKEY_cmp;
  end;

  EVP_PKEY_print_public := LoadLibCryptoFunction('EVP_PKEY_print_public');
  FuncLoadError := not assigned(EVP_PKEY_print_public);
  if FuncLoadError then
  begin
    EVP_PKEY_print_public :=  @ERROR_EVP_PKEY_print_public;
  end;

  EVP_PKEY_print_private := LoadLibCryptoFunction('EVP_PKEY_print_private');
  FuncLoadError := not assigned(EVP_PKEY_print_private);
  if FuncLoadError then
  begin
    EVP_PKEY_print_private :=  @ERROR_EVP_PKEY_print_private;
  end;

  EVP_PKEY_print_params := LoadLibCryptoFunction('EVP_PKEY_print_params');
  FuncLoadError := not assigned(EVP_PKEY_print_params);
  if FuncLoadError then
  begin
    EVP_PKEY_print_params :=  @ERROR_EVP_PKEY_print_params;
  end;

  EVP_PKEY_get_default_digest_nid := LoadLibCryptoFunction('EVP_PKEY_get_default_digest_nid');
  FuncLoadError := not assigned(EVP_PKEY_get_default_digest_nid);
  if FuncLoadError then
  begin
    EVP_PKEY_get_default_digest_nid :=  @ERROR_EVP_PKEY_get_default_digest_nid;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_set1_tls_encodedpoint := LoadLibCryptoFunction('EVP_PKEY_set1_tls_encodedpoint');
  FuncLoadError := not assigned(EVP_PKEY_set1_tls_encodedpoint);
  if FuncLoadError then
  begin
    if EVP_PKEY_set1_tls_encodedpoint_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_set1_tls_encodedpoint');
  end;

  EVP_PKEY_get1_tls_encodedpoint := LoadLibCryptoFunction('EVP_PKEY_get1_tls_encodedpoint');
  FuncLoadError := not assigned(EVP_PKEY_get1_tls_encodedpoint);
  if FuncLoadError then
  begin
    if EVP_PKEY_get1_tls_encodedpoint_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_PKEY_get1_tls_encodedpoint');
  end;

  EVP_CIPHER_type := LoadLibCryptoFunction('EVP_CIPHER_type');
  FuncLoadError := not assigned(EVP_CIPHER_type);
  if FuncLoadError then
  begin
    if EVP_CIPHER_type_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_CIPHER_type');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_param_to_asn1 := LoadLibCryptoFunction('EVP_CIPHER_param_to_asn1');
  FuncLoadError := not assigned(EVP_CIPHER_param_to_asn1);
  if FuncLoadError then
  begin
    EVP_CIPHER_param_to_asn1 :=  @ERROR_EVP_CIPHER_param_to_asn1;
  end;

  EVP_CIPHER_asn1_to_param := LoadLibCryptoFunction('EVP_CIPHER_asn1_to_param');
  FuncLoadError := not assigned(EVP_CIPHER_asn1_to_param);
  if FuncLoadError then
  begin
    EVP_CIPHER_asn1_to_param :=  @ERROR_EVP_CIPHER_asn1_to_param;
  end;

  EVP_CIPHER_set_asn1_iv := LoadLibCryptoFunction('EVP_CIPHER_set_asn1_iv');
  FuncLoadError := not assigned(EVP_CIPHER_set_asn1_iv);
  if FuncLoadError then
  begin
    EVP_CIPHER_set_asn1_iv :=  @ERROR_EVP_CIPHER_set_asn1_iv;
  end;

  EVP_CIPHER_get_asn1_iv := LoadLibCryptoFunction('EVP_CIPHER_get_asn1_iv');
  FuncLoadError := not assigned(EVP_CIPHER_get_asn1_iv);
  if FuncLoadError then
  begin
    EVP_CIPHER_get_asn1_iv :=  @ERROR_EVP_CIPHER_get_asn1_iv;
  end;

  PKCS5_PBE_keyivgen := LoadLibCryptoFunction('PKCS5_PBE_keyivgen');
  FuncLoadError := not assigned(PKCS5_PBE_keyivgen);
  if FuncLoadError then
  begin
    PKCS5_PBE_keyivgen :=  @ERROR_PKCS5_PBE_keyivgen;
  end;

  PKCS5_PBKDF2_HMAC_SHA1 := LoadLibCryptoFunction('PKCS5_PBKDF2_HMAC_SHA1');
  FuncLoadError := not assigned(PKCS5_PBKDF2_HMAC_SHA1);
  if FuncLoadError then
  begin
    PKCS5_PBKDF2_HMAC_SHA1 :=  @ERROR_PKCS5_PBKDF2_HMAC_SHA1;
  end;

  PKCS5_PBKDF2_HMAC := LoadLibCryptoFunction('PKCS5_PBKDF2_HMAC');
  FuncLoadError := not assigned(PKCS5_PBKDF2_HMAC);
  if FuncLoadError then
  begin
    PKCS5_PBKDF2_HMAC :=  @ERROR_PKCS5_PBKDF2_HMAC;
  end;

  PKCS5_v2_PBE_keyivgen := LoadLibCryptoFunction('PKCS5_v2_PBE_keyivgen');
  FuncLoadError := not assigned(PKCS5_v2_PBE_keyivgen);
  if FuncLoadError then
  begin
    PKCS5_v2_PBE_keyivgen :=  @ERROR_PKCS5_v2_PBE_keyivgen;
  end;

  EVP_PBE_scrypt := LoadLibCryptoFunction('EVP_PBE_scrypt');
  FuncLoadError := not assigned(EVP_PBE_scrypt);
  if FuncLoadError then
  begin
    EVP_PBE_scrypt :=  @ERROR_EVP_PBE_scrypt;
  end;

  PKCS5_v2_scrypt_keyivgen := LoadLibCryptoFunction('PKCS5_v2_scrypt_keyivgen');
  FuncLoadError := not assigned(PKCS5_v2_scrypt_keyivgen);
  if FuncLoadError then
  begin
    PKCS5_v2_scrypt_keyivgen :=  @ERROR_PKCS5_v2_scrypt_keyivgen;
  end;

  PKCS5_PBE_add := LoadLibCryptoFunction('PKCS5_PBE_add');
  FuncLoadError := not assigned(PKCS5_PBE_add);
  if FuncLoadError then
  begin
    PKCS5_PBE_add :=  @ERROR_PKCS5_PBE_add;
  end;

  EVP_PBE_CipherInit := LoadLibCryptoFunction('EVP_PBE_CipherInit');
  FuncLoadError := not assigned(EVP_PBE_CipherInit);
  if FuncLoadError then
  begin
    EVP_PBE_CipherInit :=  @ERROR_EVP_PBE_CipherInit;
  end;

  EVP_PBE_alg_add_type := LoadLibCryptoFunction('EVP_PBE_alg_add_type');
  FuncLoadError := not assigned(EVP_PBE_alg_add_type);
  if FuncLoadError then
  begin
    EVP_PBE_alg_add_type :=  @ERROR_EVP_PBE_alg_add_type;
  end;

  EVP_PBE_alg_add := LoadLibCryptoFunction('EVP_PBE_alg_add');
  FuncLoadError := not assigned(EVP_PBE_alg_add);
  if FuncLoadError then
  begin
    EVP_PBE_alg_add :=  @ERROR_EVP_PBE_alg_add;
  end;

  EVP_PBE_find := LoadLibCryptoFunction('EVP_PBE_find');
  FuncLoadError := not assigned(EVP_PBE_find);
  if FuncLoadError then
  begin
    EVP_PBE_find :=  @ERROR_EVP_PBE_find;
  end;

  EVP_PBE_cleanup := LoadLibCryptoFunction('EVP_PBE_cleanup');
  FuncLoadError := not assigned(EVP_PBE_cleanup);
  if FuncLoadError then
  begin
    EVP_PBE_cleanup :=  @ERROR_EVP_PBE_cleanup;
  end;

  EVP_PBE_get := LoadLibCryptoFunction('EVP_PBE_get');
  FuncLoadError := not assigned(EVP_PBE_get);
  if FuncLoadError then
  begin
    EVP_PBE_get :=  @ERROR_EVP_PBE_get;
  end;

  EVP_PKEY_asn1_get_count := LoadLibCryptoFunction('EVP_PKEY_asn1_get_count');
  FuncLoadError := not assigned(EVP_PKEY_asn1_get_count);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_get_count :=  @ERROR_EVP_PKEY_asn1_get_count;
  end;

  EVP_PKEY_asn1_get0 := LoadLibCryptoFunction('EVP_PKEY_asn1_get0');
  FuncLoadError := not assigned(EVP_PKEY_asn1_get0);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_get0 :=  @ERROR_EVP_PKEY_asn1_get0;
  end;

  EVP_PKEY_asn1_find := LoadLibCryptoFunction('EVP_PKEY_asn1_find');
  FuncLoadError := not assigned(EVP_PKEY_asn1_find);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_find :=  @ERROR_EVP_PKEY_asn1_find;
  end;

  EVP_PKEY_asn1_find_str := LoadLibCryptoFunction('EVP_PKEY_asn1_find_str');
  FuncLoadError := not assigned(EVP_PKEY_asn1_find_str);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_find_str :=  @ERROR_EVP_PKEY_asn1_find_str;
  end;

  EVP_PKEY_asn1_add0 := LoadLibCryptoFunction('EVP_PKEY_asn1_add0');
  FuncLoadError := not assigned(EVP_PKEY_asn1_add0);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_add0 :=  @ERROR_EVP_PKEY_asn1_add0;
  end;

  EVP_PKEY_asn1_add_alias := LoadLibCryptoFunction('EVP_PKEY_asn1_add_alias');
  FuncLoadError := not assigned(EVP_PKEY_asn1_add_alias);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_add_alias :=  @ERROR_EVP_PKEY_asn1_add_alias;
  end;

  EVP_PKEY_asn1_get0_info := LoadLibCryptoFunction('EVP_PKEY_asn1_get0_info');
  FuncLoadError := not assigned(EVP_PKEY_asn1_get0_info);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_get0_info :=  @ERROR_EVP_PKEY_asn1_get0_info;
  end;

  EVP_PKEY_get0_asn1 := LoadLibCryptoFunction('EVP_PKEY_get0_asn1');
  FuncLoadError := not assigned(EVP_PKEY_get0_asn1);
  if FuncLoadError then
  begin
    EVP_PKEY_get0_asn1 :=  @ERROR_EVP_PKEY_get0_asn1;
  end;

  EVP_PKEY_asn1_new := LoadLibCryptoFunction('EVP_PKEY_asn1_new');
  FuncLoadError := not assigned(EVP_PKEY_asn1_new);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_new :=  @ERROR_EVP_PKEY_asn1_new;
  end;

  EVP_PKEY_asn1_copy := LoadLibCryptoFunction('EVP_PKEY_asn1_copy');
  FuncLoadError := not assigned(EVP_PKEY_asn1_copy);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_copy :=  @ERROR_EVP_PKEY_asn1_copy;
  end;

  EVP_PKEY_asn1_free := LoadLibCryptoFunction('EVP_PKEY_asn1_free');
  FuncLoadError := not assigned(EVP_PKEY_asn1_free);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_free :=  @ERROR_EVP_PKEY_asn1_free;
  end;

  EVP_PKEY_asn1_set_public := LoadLibCryptoFunction('EVP_PKEY_asn1_set_public');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_public);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_public :=  @ERROR_EVP_PKEY_asn1_set_public;
  end;

  EVP_PKEY_asn1_set_private := LoadLibCryptoFunction('EVP_PKEY_asn1_set_private');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_private);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_private :=  @ERROR_EVP_PKEY_asn1_set_private;
  end;

  EVP_PKEY_asn1_set_param := LoadLibCryptoFunction('EVP_PKEY_asn1_set_param');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_param);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_param :=  @ERROR_EVP_PKEY_asn1_set_param;
  end;

  EVP_PKEY_asn1_set_free := LoadLibCryptoFunction('EVP_PKEY_asn1_set_free');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_free);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_free :=  @ERROR_EVP_PKEY_asn1_set_free;
  end;

  EVP_PKEY_asn1_set_ctrl := LoadLibCryptoFunction('EVP_PKEY_asn1_set_ctrl');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_ctrl);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_ctrl :=  @ERROR_EVP_PKEY_asn1_set_ctrl;
  end;

  EVP_PKEY_asn1_set_item := LoadLibCryptoFunction('EVP_PKEY_asn1_set_item');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_item);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_item :=  @ERROR_EVP_PKEY_asn1_set_item;
  end;

  EVP_PKEY_asn1_set_siginf := LoadLibCryptoFunction('EVP_PKEY_asn1_set_siginf');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_siginf);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_siginf :=  @ERROR_EVP_PKEY_asn1_set_siginf;
  end;

  EVP_PKEY_asn1_set_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_check');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_check);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_check :=  @ERROR_EVP_PKEY_asn1_set_check;
  end;

  EVP_PKEY_asn1_set_public_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_public_check');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_public_check);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_public_check :=  @ERROR_EVP_PKEY_asn1_set_public_check;
  end;

  EVP_PKEY_asn1_set_param_check := LoadLibCryptoFunction('EVP_PKEY_asn1_set_param_check');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_param_check);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_param_check :=  @ERROR_EVP_PKEY_asn1_set_param_check;
  end;

  EVP_PKEY_asn1_set_set_priv_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_set_priv_key');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_set_priv_key);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_set_priv_key :=  @ERROR_EVP_PKEY_asn1_set_set_priv_key;
  end;

  EVP_PKEY_asn1_set_set_pub_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_set_pub_key');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_set_pub_key);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_set_pub_key :=  @ERROR_EVP_PKEY_asn1_set_set_pub_key;
  end;

  EVP_PKEY_asn1_set_get_priv_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_get_priv_key');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_get_priv_key);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_get_priv_key :=  @ERROR_EVP_PKEY_asn1_set_get_priv_key;
  end;

  EVP_PKEY_asn1_set_get_pub_key := LoadLibCryptoFunction('EVP_PKEY_asn1_set_get_pub_key');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_get_pub_key);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_get_pub_key :=  @ERROR_EVP_PKEY_asn1_set_get_pub_key;
  end;

  EVP_PKEY_asn1_set_security_bits := LoadLibCryptoFunction('EVP_PKEY_asn1_set_security_bits');
  FuncLoadError := not assigned(EVP_PKEY_asn1_set_security_bits);
  if FuncLoadError then
  begin
    EVP_PKEY_asn1_set_security_bits :=  @ERROR_EVP_PKEY_asn1_set_security_bits;
  end;

  EVP_PKEY_meth_find := LoadLibCryptoFunction('EVP_PKEY_meth_find');
  FuncLoadError := not assigned(EVP_PKEY_meth_find);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_find :=  @ERROR_EVP_PKEY_meth_find;
  end;

  EVP_PKEY_meth_new := LoadLibCryptoFunction('EVP_PKEY_meth_new');
  FuncLoadError := not assigned(EVP_PKEY_meth_new);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_new :=  @ERROR_EVP_PKEY_meth_new;
  end;

  EVP_PKEY_meth_get0_info := LoadLibCryptoFunction('EVP_PKEY_meth_get0_info');
  FuncLoadError := not assigned(EVP_PKEY_meth_get0_info);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get0_info :=  @ERROR_EVP_PKEY_meth_get0_info;
  end;

  EVP_PKEY_meth_copy := LoadLibCryptoFunction('EVP_PKEY_meth_copy');
  FuncLoadError := not assigned(EVP_PKEY_meth_copy);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_copy :=  @ERROR_EVP_PKEY_meth_copy;
  end;

  EVP_PKEY_meth_free := LoadLibCryptoFunction('EVP_PKEY_meth_free');
  FuncLoadError := not assigned(EVP_PKEY_meth_free);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_free :=  @ERROR_EVP_PKEY_meth_free;
  end;

  EVP_PKEY_meth_add0 := LoadLibCryptoFunction('EVP_PKEY_meth_add0');
  FuncLoadError := not assigned(EVP_PKEY_meth_add0);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_add0 :=  @ERROR_EVP_PKEY_meth_add0;
  end;

  EVP_PKEY_meth_remove := LoadLibCryptoFunction('EVP_PKEY_meth_remove');
  FuncLoadError := not assigned(EVP_PKEY_meth_remove);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_remove :=  @ERROR_EVP_PKEY_meth_remove;
  end;

  EVP_PKEY_meth_get_count := LoadLibCryptoFunction('EVP_PKEY_meth_get_count');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_count);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_count :=  @ERROR_EVP_PKEY_meth_get_count;
  end;

  EVP_PKEY_meth_get0 := LoadLibCryptoFunction('EVP_PKEY_meth_get0');
  FuncLoadError := not assigned(EVP_PKEY_meth_get0);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get0 :=  @ERROR_EVP_PKEY_meth_get0;
  end;

  EVP_PKEY_CTX_new := LoadLibCryptoFunction('EVP_PKEY_CTX_new');
  FuncLoadError := not assigned(EVP_PKEY_CTX_new);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_new :=  @ERROR_EVP_PKEY_CTX_new;
  end;

  EVP_PKEY_CTX_new_id := LoadLibCryptoFunction('EVP_PKEY_CTX_new_id');
  FuncLoadError := not assigned(EVP_PKEY_CTX_new_id);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_new_id :=  @ERROR_EVP_PKEY_CTX_new_id;
  end;

  EVP_PKEY_CTX_dup := LoadLibCryptoFunction('EVP_PKEY_CTX_dup');
  FuncLoadError := not assigned(EVP_PKEY_CTX_dup);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_dup :=  @ERROR_EVP_PKEY_CTX_dup;
  end;

  EVP_PKEY_CTX_free := LoadLibCryptoFunction('EVP_PKEY_CTX_free');
  FuncLoadError := not assigned(EVP_PKEY_CTX_free);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_free :=  @ERROR_EVP_PKEY_CTX_free;
  end;

  EVP_PKEY_CTX_ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl');
  FuncLoadError := not assigned(EVP_PKEY_CTX_ctrl);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_ctrl :=  @ERROR_EVP_PKEY_CTX_ctrl;
  end;

  EVP_PKEY_CTX_ctrl_str := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl_str');
  FuncLoadError := not assigned(EVP_PKEY_CTX_ctrl_str);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_ctrl_str :=  @ERROR_EVP_PKEY_CTX_ctrl_str;
  end;

  EVP_PKEY_CTX_ctrl_uint64 := LoadLibCryptoFunction('EVP_PKEY_CTX_ctrl_uint64');
  FuncLoadError := not assigned(EVP_PKEY_CTX_ctrl_uint64);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_ctrl_uint64 :=  @ERROR_EVP_PKEY_CTX_ctrl_uint64;
  end;

  EVP_PKEY_CTX_str2ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_str2ctrl');
  FuncLoadError := not assigned(EVP_PKEY_CTX_str2ctrl);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_str2ctrl :=  @ERROR_EVP_PKEY_CTX_str2ctrl;
  end;

  EVP_PKEY_CTX_hex2ctrl := LoadLibCryptoFunction('EVP_PKEY_CTX_hex2ctrl');
  FuncLoadError := not assigned(EVP_PKEY_CTX_hex2ctrl);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_hex2ctrl :=  @ERROR_EVP_PKEY_CTX_hex2ctrl;
  end;

  EVP_PKEY_CTX_md := LoadLibCryptoFunction('EVP_PKEY_CTX_md');
  FuncLoadError := not assigned(EVP_PKEY_CTX_md);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_md :=  @ERROR_EVP_PKEY_CTX_md;
  end;

  EVP_PKEY_CTX_get_operation := LoadLibCryptoFunction('EVP_PKEY_CTX_get_operation');
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_operation);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_get_operation :=  @ERROR_EVP_PKEY_CTX_get_operation;
  end;

  EVP_PKEY_CTX_set0_keygen_info := LoadLibCryptoFunction('EVP_PKEY_CTX_set0_keygen_info');
  FuncLoadError := not assigned(EVP_PKEY_CTX_set0_keygen_info);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_set0_keygen_info :=  @ERROR_EVP_PKEY_CTX_set0_keygen_info;
  end;

  EVP_PKEY_new_mac_key := LoadLibCryptoFunction('EVP_PKEY_new_mac_key');
  FuncLoadError := not assigned(EVP_PKEY_new_mac_key);
  if FuncLoadError then
  begin
    EVP_PKEY_new_mac_key :=  @ERROR_EVP_PKEY_new_mac_key;
  end;

  EVP_PKEY_new_raw_private_key := LoadLibCryptoFunction('EVP_PKEY_new_raw_private_key');
  FuncLoadError := not assigned(EVP_PKEY_new_raw_private_key);
  if FuncLoadError then
  begin
    EVP_PKEY_new_raw_private_key :=  @ERROR_EVP_PKEY_new_raw_private_key;
  end;

  EVP_PKEY_new_raw_public_key := LoadLibCryptoFunction('EVP_PKEY_new_raw_public_key');
  FuncLoadError := not assigned(EVP_PKEY_new_raw_public_key);
  if FuncLoadError then
  begin
    EVP_PKEY_new_raw_public_key :=  @ERROR_EVP_PKEY_new_raw_public_key;
  end;

  EVP_PKEY_get_raw_private_key := LoadLibCryptoFunction('EVP_PKEY_get_raw_private_key');
  FuncLoadError := not assigned(EVP_PKEY_get_raw_private_key);
  if FuncLoadError then
  begin
    EVP_PKEY_get_raw_private_key :=  @ERROR_EVP_PKEY_get_raw_private_key;
  end;

  EVP_PKEY_get_raw_public_key := LoadLibCryptoFunction('EVP_PKEY_get_raw_public_key');
  FuncLoadError := not assigned(EVP_PKEY_get_raw_public_key);
  if FuncLoadError then
  begin
    EVP_PKEY_get_raw_public_key :=  @ERROR_EVP_PKEY_get_raw_public_key;
  end;

  EVP_PKEY_new_CMAC_key := LoadLibCryptoFunction('EVP_PKEY_new_CMAC_key');
  FuncLoadError := not assigned(EVP_PKEY_new_CMAC_key);
  if FuncLoadError then
  begin
    EVP_PKEY_new_CMAC_key :=  @ERROR_EVP_PKEY_new_CMAC_key;
  end;

  EVP_PKEY_CTX_set_data := LoadLibCryptoFunction('EVP_PKEY_CTX_set_data');
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_data);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_set_data :=  @ERROR_EVP_PKEY_CTX_set_data;
  end;

  EVP_PKEY_CTX_get_data := LoadLibCryptoFunction('EVP_PKEY_CTX_get_data');
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_data);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_get_data :=  @ERROR_EVP_PKEY_CTX_get_data;
  end;

  EVP_PKEY_CTX_get0_pkey := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_pkey');
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_pkey);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_get0_pkey :=  @ERROR_EVP_PKEY_CTX_get0_pkey;
  end;

  EVP_PKEY_CTX_get0_peerkey := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_peerkey');
  FuncLoadError := not assigned(EVP_PKEY_CTX_get0_peerkey);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_get0_peerkey :=  @ERROR_EVP_PKEY_CTX_get0_peerkey;
  end;

  EVP_PKEY_CTX_set_app_data := LoadLibCryptoFunction('EVP_PKEY_CTX_set_app_data');
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_app_data);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_set_app_data :=  @ERROR_EVP_PKEY_CTX_set_app_data;
  end;

  EVP_PKEY_CTX_get_app_data := LoadLibCryptoFunction('EVP_PKEY_CTX_get_app_data');
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_app_data);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_get_app_data :=  @ERROR_EVP_PKEY_CTX_get_app_data;
  end;

  EVP_PKEY_sign_init := LoadLibCryptoFunction('EVP_PKEY_sign_init');
  FuncLoadError := not assigned(EVP_PKEY_sign_init);
  if FuncLoadError then
  begin
    EVP_PKEY_sign_init :=  @ERROR_EVP_PKEY_sign_init;
  end;

  EVP_PKEY_sign := LoadLibCryptoFunction('EVP_PKEY_sign');
  FuncLoadError := not assigned(EVP_PKEY_sign);
  if FuncLoadError then
  begin
    EVP_PKEY_sign :=  @ERROR_EVP_PKEY_sign;
  end;

  EVP_PKEY_verify_init := LoadLibCryptoFunction('EVP_PKEY_verify_init');
  FuncLoadError := not assigned(EVP_PKEY_verify_init);
  if FuncLoadError then
  begin
    EVP_PKEY_verify_init :=  @ERROR_EVP_PKEY_verify_init;
  end;

  EVP_PKEY_verify := LoadLibCryptoFunction('EVP_PKEY_verify');
  FuncLoadError := not assigned(EVP_PKEY_verify);
  if FuncLoadError then
  begin
    EVP_PKEY_verify :=  @ERROR_EVP_PKEY_verify;
  end;

  EVP_PKEY_verify_recover_init := LoadLibCryptoFunction('EVP_PKEY_verify_recover_init');
  FuncLoadError := not assigned(EVP_PKEY_verify_recover_init);
  if FuncLoadError then
  begin
    EVP_PKEY_verify_recover_init :=  @ERROR_EVP_PKEY_verify_recover_init;
  end;

  EVP_PKEY_verify_recover := LoadLibCryptoFunction('EVP_PKEY_verify_recover');
  FuncLoadError := not assigned(EVP_PKEY_verify_recover);
  if FuncLoadError then
  begin
    EVP_PKEY_verify_recover :=  @ERROR_EVP_PKEY_verify_recover;
  end;

  EVP_PKEY_encrypt_init := LoadLibCryptoFunction('EVP_PKEY_encrypt_init');
  FuncLoadError := not assigned(EVP_PKEY_encrypt_init);
  if FuncLoadError then
  begin
    EVP_PKEY_encrypt_init :=  @ERROR_EVP_PKEY_encrypt_init;
  end;

  EVP_PKEY_encrypt := LoadLibCryptoFunction('EVP_PKEY_encrypt');
  FuncLoadError := not assigned(EVP_PKEY_encrypt);
  if FuncLoadError then
  begin
    EVP_PKEY_encrypt :=  @ERROR_EVP_PKEY_encrypt;
  end;

  EVP_PKEY_decrypt_init := LoadLibCryptoFunction('EVP_PKEY_decrypt_init');
  FuncLoadError := not assigned(EVP_PKEY_decrypt_init);
  if FuncLoadError then
  begin
    EVP_PKEY_decrypt_init :=  @ERROR_EVP_PKEY_decrypt_init;
  end;

  EVP_PKEY_decrypt := LoadLibCryptoFunction('EVP_PKEY_decrypt');
  FuncLoadError := not assigned(EVP_PKEY_decrypt);
  if FuncLoadError then
  begin
    EVP_PKEY_decrypt :=  @ERROR_EVP_PKEY_decrypt;
  end;

  EVP_PKEY_derive_init := LoadLibCryptoFunction('EVP_PKEY_derive_init');
  FuncLoadError := not assigned(EVP_PKEY_derive_init);
  if FuncLoadError then
  begin
    EVP_PKEY_derive_init :=  @ERROR_EVP_PKEY_derive_init;
  end;

  EVP_PKEY_derive_set_peer := LoadLibCryptoFunction('EVP_PKEY_derive_set_peer');
  FuncLoadError := not assigned(EVP_PKEY_derive_set_peer);
  if FuncLoadError then
  begin
    EVP_PKEY_derive_set_peer :=  @ERROR_EVP_PKEY_derive_set_peer;
  end;

  EVP_PKEY_derive := LoadLibCryptoFunction('EVP_PKEY_derive');
  FuncLoadError := not assigned(EVP_PKEY_derive);
  if FuncLoadError then
  begin
    EVP_PKEY_derive :=  @ERROR_EVP_PKEY_derive;
  end;

  EVP_PKEY_paramgen_init := LoadLibCryptoFunction('EVP_PKEY_paramgen_init');
  FuncLoadError := not assigned(EVP_PKEY_paramgen_init);
  if FuncLoadError then
  begin
    EVP_PKEY_paramgen_init :=  @ERROR_EVP_PKEY_paramgen_init;
  end;

  EVP_PKEY_paramgen := LoadLibCryptoFunction('EVP_PKEY_paramgen');
  FuncLoadError := not assigned(EVP_PKEY_paramgen);
  if FuncLoadError then
  begin
    EVP_PKEY_paramgen :=  @ERROR_EVP_PKEY_paramgen;
  end;

  EVP_PKEY_keygen_init := LoadLibCryptoFunction('EVP_PKEY_keygen_init');
  FuncLoadError := not assigned(EVP_PKEY_keygen_init);
  if FuncLoadError then
  begin
    EVP_PKEY_keygen_init :=  @ERROR_EVP_PKEY_keygen_init;
  end;

  EVP_PKEY_keygen := LoadLibCryptoFunction('EVP_PKEY_keygen');
  FuncLoadError := not assigned(EVP_PKEY_keygen);
  if FuncLoadError then
  begin
    EVP_PKEY_keygen :=  @ERROR_EVP_PKEY_keygen;
  end;

  EVP_PKEY_check := LoadLibCryptoFunction('EVP_PKEY_check');
  FuncLoadError := not assigned(EVP_PKEY_check);
  if FuncLoadError then
  begin
    EVP_PKEY_check :=  @ERROR_EVP_PKEY_check;
  end;

  EVP_PKEY_public_check := LoadLibCryptoFunction('EVP_PKEY_public_check');
  FuncLoadError := not assigned(EVP_PKEY_public_check);
  if FuncLoadError then
  begin
    EVP_PKEY_public_check :=  @ERROR_EVP_PKEY_public_check;
  end;

  EVP_PKEY_param_check := LoadLibCryptoFunction('EVP_PKEY_param_check');
  FuncLoadError := not assigned(EVP_PKEY_param_check);
  if FuncLoadError then
  begin
    EVP_PKEY_param_check :=  @ERROR_EVP_PKEY_param_check;
  end;

  EVP_PKEY_CTX_set_cb := LoadLibCryptoFunction('EVP_PKEY_CTX_set_cb');
  FuncLoadError := not assigned(EVP_PKEY_CTX_set_cb);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_set_cb :=  @ERROR_EVP_PKEY_CTX_set_cb;
  end;

  EVP_PKEY_CTX_get_cb := LoadLibCryptoFunction('EVP_PKEY_CTX_get_cb');
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_cb);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_get_cb :=  @ERROR_EVP_PKEY_CTX_get_cb;
  end;

  EVP_PKEY_CTX_get_keygen_info := LoadLibCryptoFunction('EVP_PKEY_CTX_get_keygen_info');
  FuncLoadError := not assigned(EVP_PKEY_CTX_get_keygen_info);
  if FuncLoadError then
  begin
    EVP_PKEY_CTX_get_keygen_info :=  @ERROR_EVP_PKEY_CTX_get_keygen_info;
  end;

  EVP_PKEY_meth_set_init := LoadLibCryptoFunction('EVP_PKEY_meth_set_init');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_init);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_init :=  @ERROR_EVP_PKEY_meth_set_init;
  end;

  EVP_PKEY_meth_set_copy := LoadLibCryptoFunction('EVP_PKEY_meth_set_copy');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_copy);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_copy :=  @ERROR_EVP_PKEY_meth_set_copy;
  end;

  EVP_PKEY_meth_set_cleanup := LoadLibCryptoFunction('EVP_PKEY_meth_set_cleanup');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_cleanup);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_cleanup :=  @ERROR_EVP_PKEY_meth_set_cleanup;
  end;

  EVP_PKEY_meth_set_paramgen := LoadLibCryptoFunction('EVP_PKEY_meth_set_paramgen');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_paramgen);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_paramgen :=  @ERROR_EVP_PKEY_meth_set_paramgen;
  end;

  EVP_PKEY_meth_set_keygen := LoadLibCryptoFunction('EVP_PKEY_meth_set_keygen');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_keygen);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_keygen :=  @ERROR_EVP_PKEY_meth_set_keygen;
  end;

  EVP_PKEY_meth_set_sign := LoadLibCryptoFunction('EVP_PKEY_meth_set_sign');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_sign);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_sign :=  @ERROR_EVP_PKEY_meth_set_sign;
  end;

  EVP_PKEY_meth_set_verify := LoadLibCryptoFunction('EVP_PKEY_meth_set_verify');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_verify);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_verify :=  @ERROR_EVP_PKEY_meth_set_verify;
  end;

  EVP_PKEY_meth_set_verify_recover := LoadLibCryptoFunction('EVP_PKEY_meth_set_verify_recover');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_verify_recover);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_verify_recover :=  @ERROR_EVP_PKEY_meth_set_verify_recover;
  end;

  EVP_PKEY_meth_set_signctx := LoadLibCryptoFunction('EVP_PKEY_meth_set_signctx');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_signctx);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_signctx :=  @ERROR_EVP_PKEY_meth_set_signctx;
  end;

  EVP_PKEY_meth_set_verifyctx := LoadLibCryptoFunction('EVP_PKEY_meth_set_verifyctx');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_verifyctx);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_verifyctx :=  @ERROR_EVP_PKEY_meth_set_verifyctx;
  end;

  EVP_PKEY_meth_set_encrypt := LoadLibCryptoFunction('EVP_PKEY_meth_set_encrypt');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_encrypt);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_encrypt :=  @ERROR_EVP_PKEY_meth_set_encrypt;
  end;

  EVP_PKEY_meth_set_decrypt := LoadLibCryptoFunction('EVP_PKEY_meth_set_decrypt');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_decrypt);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_decrypt :=  @ERROR_EVP_PKEY_meth_set_decrypt;
  end;

  EVP_PKEY_meth_set_derive := LoadLibCryptoFunction('EVP_PKEY_meth_set_derive');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_derive);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_derive :=  @ERROR_EVP_PKEY_meth_set_derive;
  end;

  EVP_PKEY_meth_set_ctrl := LoadLibCryptoFunction('EVP_PKEY_meth_set_ctrl');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_ctrl);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_ctrl :=  @ERROR_EVP_PKEY_meth_set_ctrl;
  end;

  EVP_PKEY_meth_set_digestsign := LoadLibCryptoFunction('EVP_PKEY_meth_set_digestsign');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_digestsign);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_digestsign :=  @ERROR_EVP_PKEY_meth_set_digestsign;
  end;

  EVP_PKEY_meth_set_digestverify := LoadLibCryptoFunction('EVP_PKEY_meth_set_digestverify');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_digestverify);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_digestverify :=  @ERROR_EVP_PKEY_meth_set_digestverify;
  end;

  EVP_PKEY_meth_set_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_check');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_check);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_check :=  @ERROR_EVP_PKEY_meth_set_check;
  end;

  EVP_PKEY_meth_set_public_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_public_check');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_public_check);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_public_check :=  @ERROR_EVP_PKEY_meth_set_public_check;
  end;

  EVP_PKEY_meth_set_param_check := LoadLibCryptoFunction('EVP_PKEY_meth_set_param_check');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_param_check);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_param_check :=  @ERROR_EVP_PKEY_meth_set_param_check;
  end;

  EVP_PKEY_meth_set_digest_custom := LoadLibCryptoFunction('EVP_PKEY_meth_set_digest_custom');
  FuncLoadError := not assigned(EVP_PKEY_meth_set_digest_custom);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_set_digest_custom :=  @ERROR_EVP_PKEY_meth_set_digest_custom;
  end;

  EVP_PKEY_meth_get_init := LoadLibCryptoFunction('EVP_PKEY_meth_get_init');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_init);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_init :=  @ERROR_EVP_PKEY_meth_get_init;
  end;

  EVP_PKEY_meth_get_copy := LoadLibCryptoFunction('EVP_PKEY_meth_get_copy');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_copy);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_copy :=  @ERROR_EVP_PKEY_meth_get_copy;
  end;

  EVP_PKEY_meth_get_cleanup := LoadLibCryptoFunction('EVP_PKEY_meth_get_cleanup');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_cleanup);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_cleanup :=  @ERROR_EVP_PKEY_meth_get_cleanup;
  end;

  EVP_PKEY_meth_get_paramgen := LoadLibCryptoFunction('EVP_PKEY_meth_get_paramgen');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_paramgen);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_paramgen :=  @ERROR_EVP_PKEY_meth_get_paramgen;
  end;

  EVP_PKEY_meth_get_keygen := LoadLibCryptoFunction('EVP_PKEY_meth_get_keygen');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_keygen);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_keygen :=  @ERROR_EVP_PKEY_meth_get_keygen;
  end;

  EVP_PKEY_meth_get_sign := LoadLibCryptoFunction('EVP_PKEY_meth_get_sign');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_sign);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_sign :=  @ERROR_EVP_PKEY_meth_get_sign;
  end;

  EVP_PKEY_meth_get_verify := LoadLibCryptoFunction('EVP_PKEY_meth_get_verify');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_verify);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_verify :=  @ERROR_EVP_PKEY_meth_get_verify;
  end;

  EVP_PKEY_meth_get_verify_recover := LoadLibCryptoFunction('EVP_PKEY_meth_get_verify_recover');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_verify_recover);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_verify_recover :=  @ERROR_EVP_PKEY_meth_get_verify_recover;
  end;

  EVP_PKEY_meth_get_signctx := LoadLibCryptoFunction('EVP_PKEY_meth_get_signctx');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_signctx);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_signctx :=  @ERROR_EVP_PKEY_meth_get_signctx;
  end;

  EVP_PKEY_meth_get_verifyctx := LoadLibCryptoFunction('EVP_PKEY_meth_get_verifyctx');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_verifyctx);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_verifyctx :=  @ERROR_EVP_PKEY_meth_get_verifyctx;
  end;

  EVP_PKEY_meth_get_encrypt := LoadLibCryptoFunction('EVP_PKEY_meth_get_encrypt');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_encrypt);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_encrypt :=  @ERROR_EVP_PKEY_meth_get_encrypt;
  end;

  EVP_PKEY_meth_get_decrypt := LoadLibCryptoFunction('EVP_PKEY_meth_get_decrypt');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_decrypt);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_decrypt :=  @ERROR_EVP_PKEY_meth_get_decrypt;
  end;

  EVP_PKEY_meth_get_derive := LoadLibCryptoFunction('EVP_PKEY_meth_get_derive');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_derive);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_derive :=  @ERROR_EVP_PKEY_meth_get_derive;
  end;

  EVP_PKEY_meth_get_ctrl := LoadLibCryptoFunction('EVP_PKEY_meth_get_ctrl');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_ctrl);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_ctrl :=  @ERROR_EVP_PKEY_meth_get_ctrl;
  end;

  EVP_PKEY_meth_get_digestsign := LoadLibCryptoFunction('EVP_PKEY_meth_get_digestsign');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_digestsign);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_digestsign :=  @ERROR_EVP_PKEY_meth_get_digestsign;
  end;

  EVP_PKEY_meth_get_digestverify := LoadLibCryptoFunction('EVP_PKEY_meth_get_digestverify');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_digestverify);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_digestverify :=  @ERROR_EVP_PKEY_meth_get_digestverify;
  end;

  EVP_PKEY_meth_get_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_check');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_check);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_check :=  @ERROR_EVP_PKEY_meth_get_check;
  end;

  EVP_PKEY_meth_get_public_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_public_check');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_public_check);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_public_check :=  @ERROR_EVP_PKEY_meth_get_public_check;
  end;

  EVP_PKEY_meth_get_param_check := LoadLibCryptoFunction('EVP_PKEY_meth_get_param_check');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_param_check);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_param_check :=  @ERROR_EVP_PKEY_meth_get_param_check;
  end;

  EVP_PKEY_meth_get_digest_custom := LoadLibCryptoFunction('EVP_PKEY_meth_get_digest_custom');
  FuncLoadError := not assigned(EVP_PKEY_meth_get_digest_custom);
  if FuncLoadError then
  begin
    EVP_PKEY_meth_get_digest_custom :=  @ERROR_EVP_PKEY_meth_get_digest_custom;
  end;

  EVP_add_alg_module := LoadLibCryptoFunction('EVP_add_alg_module');
  FuncLoadError := not assigned(EVP_add_alg_module);
  if FuncLoadError then
  begin
    EVP_add_alg_module :=  @ERROR_EVP_add_alg_module;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OpenSSL_add_all_ciphers := LoadLibCryptoFunction('OpenSSL_add_all_ciphers');
  FuncLoadError := not assigned(OpenSSL_add_all_ciphers);
  if FuncLoadError then
  begin
    OpenSSL_add_all_ciphers := @COMPAT_OpenSSL_add_all_ciphers;
    if OpenSSL_add_all_ciphers_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OpenSSL_add_all_ciphers');
  end;

  OpenSSL_add_all_digests := LoadLibCryptoFunction('OpenSSL_add_all_digests');
  FuncLoadError := not assigned(OpenSSL_add_all_digests);
  if FuncLoadError then
  begin
    OpenSSL_add_all_digests := @COMPAT_OpenSSL_add_all_digests;
    if OpenSSL_add_all_digests_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('OpenSSL_add_all_digests');
  end;

  EVP_cleanup := LoadLibCryptoFunction('EVP_cleanup');
  FuncLoadError := not assigned(EVP_cleanup);
  if FuncLoadError then
  begin
    EVP_cleanup := @COMPAT_EVP_cleanup;
    if EVP_cleanup_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('EVP_cleanup');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_assign_RSA := nil;
  EVP_PKEY_assign_DSA := nil;
  EVP_PKEY_assign_DH := nil;
  EVP_PKEY_assign_EC_KEY := nil;
  EVP_PKEY_assign_SIPHASH := nil;
  EVP_PKEY_assign_POLY1305 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_meth_new := nil;
  EVP_MD_meth_dup := nil;
  EVP_MD_meth_free := nil;
  EVP_MD_meth_set_input_blocksize := nil;
  EVP_MD_meth_set_result_size := nil;
  EVP_MD_meth_set_app_datasize := nil;
  EVP_MD_meth_set_flags := nil;
  EVP_MD_meth_set_init := nil;
  EVP_MD_meth_set_update := nil;
  EVP_MD_meth_set_final := nil;
  EVP_MD_meth_set_copy := nil;
  EVP_MD_meth_set_cleanup := nil;
  EVP_MD_meth_set_ctrl := nil;
  EVP_MD_meth_get_input_blocksize := nil;
  EVP_MD_meth_get_result_size := nil;
  EVP_MD_meth_get_app_datasize := nil;
  EVP_MD_meth_get_flags := nil;
  EVP_MD_meth_get_init := nil;
  EVP_MD_meth_get_update := nil;
  EVP_MD_meth_get_final := nil;
  EVP_MD_meth_get_copy := nil;
  EVP_MD_meth_get_cleanup := nil;
  EVP_MD_meth_get_ctrl := nil;
  EVP_CIPHER_meth_new := nil;
  EVP_CIPHER_meth_dup := nil;
  EVP_CIPHER_meth_free := nil;
  EVP_CIPHER_meth_set_iv_length := nil;
  EVP_CIPHER_meth_set_flags := nil;
  EVP_CIPHER_meth_set_impl_ctx_size := nil;
  EVP_CIPHER_meth_set_init := nil;
  EVP_CIPHER_meth_set_do_cipher := nil;
  EVP_CIPHER_meth_set_cleanup := nil;
  EVP_CIPHER_meth_set_set_asn1_params := nil;
  EVP_CIPHER_meth_set_get_asn1_params := nil;
  EVP_CIPHER_meth_set_ctrl := nil;
  EVP_CIPHER_meth_get_init := nil;
  EVP_CIPHER_meth_get_do_cipher := nil;
  EVP_CIPHER_meth_get_cleanup := nil;
  EVP_CIPHER_meth_get_set_asn1_params := nil;
  EVP_CIPHER_meth_get_get_asn1_params := nil;
  EVP_CIPHER_meth_get_ctrl := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_type := nil;
  EVP_MD_pkey_type := nil;
  EVP_MD_size := nil;
  EVP_MD_block_size := nil;
  EVP_MD_flags := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_md := nil;
  EVP_MD_CTX_update_fn := nil;
  EVP_MD_CTX_set_update_fn := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_CTX_pkey_ctx := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_set_pkey_ctx := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_MD_CTX_md_data := nil;
  EVP_CIPHER_nid := nil;
  EVP_CIPHER_block_size := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_impl_ctx_size := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_key_length := nil;
  EVP_CIPHER_iv_length := nil;
  EVP_CIPHER_flags := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_cipher := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_CTX_encrypting := nil;
  EVP_CIPHER_CTX_nid := nil;
  EVP_CIPHER_CTX_block_size := nil;
  EVP_CIPHER_CTX_key_length := nil;
  EVP_CIPHER_CTX_iv_length := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_iv := nil;
  EVP_CIPHER_CTX_original_iv := nil;
  EVP_CIPHER_CTX_iv_noconst := nil;
  EVP_CIPHER_CTX_buf_noconst := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_CIPHER_CTX_num := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_CTX_set_num := nil;
  EVP_CIPHER_CTX_copy := nil;
  EVP_CIPHER_CTX_get_app_data := nil;
  EVP_CIPHER_CTX_set_app_data := nil;
  EVP_CIPHER_CTX_get_cipher_data := nil;
  EVP_CIPHER_CTX_set_cipher_data := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  BIO_set_md := nil;
  EVP_MD_CTX_init := nil;
  EVP_MD_CTX_cleanup := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_MD_CTX_ctrl := nil;
  EVP_MD_CTX_new := nil;
  EVP_MD_CTX_reset := nil;
  EVP_MD_CTX_free := nil;
  EVP_MD_CTX_copy_ex := nil;
  EVP_MD_CTX_set_flags := nil;
  EVP_MD_CTX_clear_flags := nil;
  EVP_MD_CTX_test_flags := nil;
  EVP_DigestInit_ex := nil;
  EVP_DigestUpdate := nil;
  EVP_DigestFinal_ex := nil;
  EVP_Digest := nil;
  EVP_MD_CTX_copy := nil;
  EVP_DigestInit := nil;
  EVP_DigestFinal := nil;
  EVP_DigestFinalXOF := nil;
  EVP_read_pw_string := nil;
  EVP_read_pw_string_min := nil;
  EVP_set_pw_prompt := nil;
  EVP_get_pw_prompt := nil;
  EVP_BytesToKey := nil;
  EVP_CIPHER_CTX_set_flags := nil;
  EVP_CIPHER_CTX_clear_flags := nil;
  EVP_CIPHER_CTX_test_flags := nil;
  EVP_EncryptInit := nil;
  EVP_EncryptInit_ex := nil;
  EVP_EncryptUpdate := nil;
  EVP_EncryptFinal_ex := nil;
  EVP_EncryptFinal := nil;
  EVP_DecryptInit := nil;
  EVP_DecryptInit_ex := nil;
  EVP_DecryptUpdate := nil;
  EVP_DecryptFinal := nil;
  EVP_DecryptFinal_ex := nil;
  EVP_CipherInit := nil;
  EVP_CipherInit_ex := nil;
  EVP_CipherUpdate := nil;
  EVP_CipherFinal := nil;
  EVP_CipherFinal_ex := nil;
  EVP_SignFinal := nil;
  EVP_DigestSign := nil;
  EVP_VerifyFinal := nil;
  EVP_DigestVerify := nil;
  EVP_DigestSignInit := nil;
  EVP_DigestSignFinal := nil;
  EVP_DigestVerifyInit := nil;
  EVP_DigestVerifyFinal := nil;
  EVP_OpenInit := nil;
  EVP_OpenFinal := nil;
  EVP_SealInit := nil;
  EVP_SealFinal := nil;
  EVP_ENCODE_CTX_new := nil;
  EVP_ENCODE_CTX_free := nil;
  EVP_ENCODE_CTX_copy := nil;
  EVP_ENCODE_CTX_num := nil;
  EVP_EncodeInit := nil;
  EVP_EncodeUpdate := nil;
  EVP_EncodeFinal := nil;
  EVP_EncodeBlock := nil;
  EVP_DecodeInit := nil;
  EVP_DecodeUpdate := nil;
  EVP_DecodeFinal := nil;
  EVP_DecodeBlock := nil;
  EVP_CIPHER_CTX_new := nil;
  EVP_CIPHER_CTX_reset := nil;
  EVP_CIPHER_CTX_free := nil;
  EVP_CIPHER_CTX_set_key_length := nil;
  EVP_CIPHER_CTX_set_padding := nil;
  EVP_CIPHER_CTX_ctrl := nil;
  EVP_CIPHER_CTX_rand_key := nil;
  BIO_f_md := nil;
  BIO_f_base64 := nil;
  BIO_f_cipher := nil;
  BIO_f_reliable := nil;
  BIO_set_cipher := nil;
  EVP_md_null := nil;
{$IFNDEF OPENSSL_NO_MD2}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md2 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD4}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md4 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$ENDIF}
{$IFNDEF OPENSSL_NO_MD5}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_md5 := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
{$ENDIF}
  EVP_md5_sha1 := nil;
  EVP_sha1 := nil;
  EVP_sha224 := nil;
  EVP_sha256 := nil;
  EVP_sha384 := nil;
  EVP_sha512 := nil;
  EVP_sha512_224 := nil;
  EVP_sha512_256 := nil;
  EVP_sha3_224 := nil;
  EVP_sha3_256 := nil;
  EVP_sha3_384 := nil;
  EVP_sha3_512 := nil;
  EVP_shake128 := nil;
  EVP_shake256 := nil;
  EVP_enc_null := nil;
  EVP_des_ecb := nil;
  EVP_des_ede := nil;
  EVP_des_ede3 := nil;
  EVP_des_ede_ecb := nil;
  EVP_des_ede3_ecb := nil;
  EVP_des_cfb64 := nil;
  EVP_des_cfb1 := nil;
  EVP_des_cfb8 := nil;
  EVP_des_ede_cfb64 := nil;
  EVP_des_ede3_cfb64 := nil;
  EVP_des_ede3_cfb1 := nil;
  EVP_des_ede3_cfb8 := nil;
  EVP_des_ofb := nil;
  EVP_des_ede_ofb := nil;
  EVP_des_ede3_ofb := nil;
  EVP_des_cbc := nil;
  EVP_des_ede_cbc := nil;
  EVP_des_ede3_cbc := nil;
  EVP_desx_cbc := nil;
  EVP_des_ede3_wrap := nil;
  EVP_rc4 := nil;
  EVP_rc4_40 := nil;
  EVP_rc2_ecb := nil;
  EVP_rc2_cbc := nil;
  EVP_rc2_40_cbc := nil;
  EVP_rc2_64_cbc := nil;
  EVP_rc2_cfb64 := nil;
  EVP_rc2_ofb := nil;
  EVP_bf_ecb := nil;
  EVP_bf_cbc := nil;
  EVP_bf_cfb64 := nil;
  EVP_bf_ofb := nil;
  EVP_cast5_ecb := nil;
  EVP_cast5_cbc := nil;
  EVP_cast5_cfb64 := nil;
  EVP_cast5_ofb := nil;
  EVP_aes_128_ecb := nil;
  EVP_aes_128_cbc := nil;
  EVP_aes_128_cfb1 := nil;
  EVP_aes_128_cfb8 := nil;
  EVP_aes_128_cfb128 := nil;
  EVP_aes_128_ofb := nil;
  EVP_aes_128_ctr := nil;
  EVP_aes_128_ccm := nil;
  EVP_aes_128_gcm := nil;
  EVP_aes_128_xts := nil;
  EVP_aes_128_wrap := nil;
  EVP_aes_128_wrap_pad := nil;
  EVP_aes_128_ocb := nil;
  EVP_aes_192_ecb := nil;
  EVP_aes_192_cbc := nil;
  EVP_aes_192_cfb1 := nil;
  EVP_aes_192_cfb8 := nil;
  EVP_aes_192_cfb128 := nil;
  EVP_aes_192_ofb := nil;
  EVP_aes_192_ctr := nil;
  EVP_aes_192_ccm := nil;
  EVP_aes_192_gcm := nil;
  EVP_aes_192_wrap := nil;
  EVP_aes_192_wrap_pad := nil;
  EVP_aes_192_ocb := nil;
  EVP_aes_256_ecb := nil;
  EVP_aes_256_cbc := nil;
  EVP_aes_256_cfb1 := nil;
  EVP_aes_256_cfb8 := nil;
  EVP_aes_256_cfb128 := nil;
  EVP_aes_256_ofb := nil;
  EVP_aes_256_ctr := nil;
  EVP_aes_256_ccm := nil;
  EVP_aes_256_gcm := nil;
  EVP_aes_256_xts := nil;
  EVP_aes_256_wrap := nil;
  EVP_aes_256_wrap_pad := nil;
  EVP_aes_256_ocb := nil;
  EVP_aes_128_cbc_hmac_sha1 := nil;
  EVP_aes_256_cbc_hmac_sha1 := nil;
  EVP_aes_128_cbc_hmac_sha256 := nil;
  EVP_aes_256_cbc_hmac_sha256 := nil;
  EVP_aria_128_ecb := nil;
  EVP_aria_128_cbc := nil;
  EVP_aria_128_cfb1 := nil;
  EVP_aria_128_cfb8 := nil;
  EVP_aria_128_cfb128 := nil;
  EVP_aria_128_ctr := nil;
  EVP_aria_128_ofb := nil;
  EVP_aria_128_gcm := nil;
  EVP_aria_128_ccm := nil;
  EVP_aria_192_ecb := nil;
  EVP_aria_192_cbc := nil;
  EVP_aria_192_cfb1 := nil;
  EVP_aria_192_cfb8 := nil;
  EVP_aria_192_cfb128 := nil;
  EVP_aria_192_ctr := nil;
  EVP_aria_192_ofb := nil;
  EVP_aria_192_gcm := nil;
  EVP_aria_192_ccm := nil;
  EVP_aria_256_ecb := nil;
  EVP_aria_256_cbc := nil;
  EVP_aria_256_cfb1 := nil;
  EVP_aria_256_cfb8 := nil;
  EVP_aria_256_cfb128 := nil;
  EVP_aria_256_ctr := nil;
  EVP_aria_256_ofb := nil;
  EVP_aria_256_gcm := nil;
  EVP_aria_256_ccm := nil;
  EVP_camellia_128_ecb := nil;
  EVP_camellia_128_cbc := nil;
  EVP_camellia_128_cfb1 := nil;
  EVP_camellia_128_cfb8 := nil;
  EVP_camellia_128_cfb128 := nil;
  EVP_camellia_128_ofb := nil;
  EVP_camellia_128_ctr := nil;
  EVP_camellia_192_ecb := nil;
  EVP_camellia_192_cbc := nil;
  EVP_camellia_192_cfb1 := nil;
  EVP_camellia_192_cfb8 := nil;
  EVP_camellia_192_cfb128 := nil;
  EVP_camellia_192_ofb := nil;
  EVP_camellia_192_ctr := nil;
  EVP_camellia_256_ecb := nil;
  EVP_camellia_256_cbc := nil;
  EVP_camellia_256_cfb1 := nil;
  EVP_camellia_256_cfb8 := nil;
  EVP_camellia_256_cfb128 := nil;
  EVP_camellia_256_ofb := nil;
  EVP_camellia_256_ctr := nil;
  EVP_chacha20 := nil;
  EVP_chacha20_poly1305 := nil;
  EVP_seed_ecb := nil;
  EVP_seed_cbc := nil;
  EVP_seed_cfb128 := nil;
  EVP_seed_ofb := nil;
  EVP_sm4_ecb := nil;
  EVP_sm4_cbc := nil;
  EVP_sm4_cfb128 := nil;
  EVP_sm4_ofb := nil;
  EVP_sm4_ctr := nil;
  EVP_add_cipher := nil;
  EVP_add_digest := nil;
  EVP_get_cipherbyname := nil;
  EVP_get_digestbyname := nil;
  EVP_CIPHER_do_all := nil;
  EVP_CIPHER_do_all_sorted := nil;
  EVP_MD_do_all := nil;
  EVP_MD_do_all_sorted := nil;
  EVP_PKEY_decrypt_old := nil;
  EVP_PKEY_encrypt_old := nil;
  EVP_PKEY_type := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_id := nil;
  EVP_PKEY_base_id := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_base_id := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_bits := nil;
  EVP_PKEY_security_bits := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_security_bits := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_size := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_get_size := nil;
  EVP_PKEY_set_type := nil;
  EVP_PKEY_set_type_str := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_set_alias_type := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_PKEY_set1_engine := nil;
  EVP_PKEY_get0_engine := nil;
  EVP_PKEY_assign := nil;
  EVP_PKEY_get0 := nil;
  EVP_PKEY_get0_hmac := nil;
  EVP_PKEY_get0_poly1305 := nil;
  EVP_PKEY_get0_siphash := nil;
  EVP_PKEY_set1_RSA := nil;
  EVP_PKEY_get0_RSA := nil;
  EVP_PKEY_get1_RSA := nil;
  EVP_PKEY_set1_DSA := nil;
  EVP_PKEY_get0_DSA := nil;
  EVP_PKEY_get1_DSA := nil;
  EVP_PKEY_set1_DH := nil;
  EVP_PKEY_get0_DH := nil;
  EVP_PKEY_get1_DH := nil;
  EVP_PKEY_set1_EC_KEY := nil;
  EVP_PKEY_get0_EC_KEY := nil;
  EVP_PKEY_get1_EC_KEY := nil;
  EVP_PKEY_new := nil;
  EVP_PKEY_up_ref := nil;
  EVP_PKEY_free := nil;
  d2i_PublicKey := nil;
  i2d_PublicKey := nil;
  d2i_PrivateKey := nil;
  d2i_AutoPrivateKey := nil;
  i2d_PrivateKey := nil;
  EVP_PKEY_copy_parameters := nil;
  EVP_PKEY_missing_parameters := nil;
  EVP_PKEY_save_parameters := nil;
  EVP_PKEY_cmp_parameters := nil;
  EVP_PKEY_cmp := nil;
  EVP_PKEY_print_public := nil;
  EVP_PKEY_print_private := nil;
  EVP_PKEY_print_params := nil;
  EVP_PKEY_get_default_digest_nid := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  EVP_PKEY_set1_tls_encodedpoint := nil;
  EVP_PKEY_get1_tls_encodedpoint := nil;
  EVP_CIPHER_type := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  EVP_CIPHER_param_to_asn1 := nil;
  EVP_CIPHER_asn1_to_param := nil;
  EVP_CIPHER_set_asn1_iv := nil;
  EVP_CIPHER_get_asn1_iv := nil;
  PKCS5_PBE_keyivgen := nil;
  PKCS5_PBKDF2_HMAC_SHA1 := nil;
  PKCS5_PBKDF2_HMAC := nil;
  PKCS5_v2_PBE_keyivgen := nil;
  EVP_PBE_scrypt := nil;
  PKCS5_v2_scrypt_keyivgen := nil;
  PKCS5_PBE_add := nil;
  EVP_PBE_CipherInit := nil;
  EVP_PBE_alg_add_type := nil;
  EVP_PBE_alg_add := nil;
  EVP_PBE_find := nil;
  EVP_PBE_cleanup := nil;
  EVP_PBE_get := nil;
  EVP_PKEY_asn1_get_count := nil;
  EVP_PKEY_asn1_get0 := nil;
  EVP_PKEY_asn1_find := nil;
  EVP_PKEY_asn1_find_str := nil;
  EVP_PKEY_asn1_add0 := nil;
  EVP_PKEY_asn1_add_alias := nil;
  EVP_PKEY_asn1_get0_info := nil;
  EVP_PKEY_get0_asn1 := nil;
  EVP_PKEY_asn1_new := nil;
  EVP_PKEY_asn1_copy := nil;
  EVP_PKEY_asn1_free := nil;
  EVP_PKEY_asn1_set_public := nil;
  EVP_PKEY_asn1_set_private := nil;
  EVP_PKEY_asn1_set_param := nil;
  EVP_PKEY_asn1_set_free := nil;
  EVP_PKEY_asn1_set_ctrl := nil;
  EVP_PKEY_asn1_set_item := nil;
  EVP_PKEY_asn1_set_siginf := nil;
  EVP_PKEY_asn1_set_check := nil;
  EVP_PKEY_asn1_set_public_check := nil;
  EVP_PKEY_asn1_set_param_check := nil;
  EVP_PKEY_asn1_set_set_priv_key := nil;
  EVP_PKEY_asn1_set_set_pub_key := nil;
  EVP_PKEY_asn1_set_get_priv_key := nil;
  EVP_PKEY_asn1_set_get_pub_key := nil;
  EVP_PKEY_asn1_set_security_bits := nil;
  EVP_PKEY_meth_find := nil;
  EVP_PKEY_meth_new := nil;
  EVP_PKEY_meth_get0_info := nil;
  EVP_PKEY_meth_copy := nil;
  EVP_PKEY_meth_free := nil;
  EVP_PKEY_meth_add0 := nil;
  EVP_PKEY_meth_remove := nil;
  EVP_PKEY_meth_get_count := nil;
  EVP_PKEY_meth_get0 := nil;
  EVP_PKEY_CTX_new := nil;
  EVP_PKEY_CTX_new_id := nil;
  EVP_PKEY_CTX_dup := nil;
  EVP_PKEY_CTX_free := nil;
  EVP_PKEY_CTX_ctrl := nil;
  EVP_PKEY_CTX_ctrl_str := nil;
  EVP_PKEY_CTX_ctrl_uint64 := nil;
  EVP_PKEY_CTX_str2ctrl := nil;
  EVP_PKEY_CTX_hex2ctrl := nil;
  EVP_PKEY_CTX_md := nil;
  EVP_PKEY_CTX_get_operation := nil;
  EVP_PKEY_CTX_set0_keygen_info := nil;
  EVP_PKEY_new_mac_key := nil;
  EVP_PKEY_new_raw_private_key := nil;
  EVP_PKEY_new_raw_public_key := nil;
  EVP_PKEY_get_raw_private_key := nil;
  EVP_PKEY_get_raw_public_key := nil;
  EVP_PKEY_new_CMAC_key := nil;
  EVP_PKEY_CTX_set_data := nil;
  EVP_PKEY_CTX_get_data := nil;
  EVP_PKEY_CTX_get0_pkey := nil;
  EVP_PKEY_CTX_get0_peerkey := nil;
  EVP_PKEY_CTX_set_app_data := nil;
  EVP_PKEY_CTX_get_app_data := nil;
  EVP_PKEY_sign_init := nil;
  EVP_PKEY_sign := nil;
  EVP_PKEY_verify_init := nil;
  EVP_PKEY_verify := nil;
  EVP_PKEY_verify_recover_init := nil;
  EVP_PKEY_verify_recover := nil;
  EVP_PKEY_encrypt_init := nil;
  EVP_PKEY_encrypt := nil;
  EVP_PKEY_decrypt_init := nil;
  EVP_PKEY_decrypt := nil;
  EVP_PKEY_derive_init := nil;
  EVP_PKEY_derive_set_peer := nil;
  EVP_PKEY_derive := nil;
  EVP_PKEY_paramgen_init := nil;
  EVP_PKEY_paramgen := nil;
  EVP_PKEY_keygen_init := nil;
  EVP_PKEY_keygen := nil;
  EVP_PKEY_check := nil;
  EVP_PKEY_public_check := nil;
  EVP_PKEY_param_check := nil;
  EVP_PKEY_CTX_set_cb := nil;
  EVP_PKEY_CTX_get_cb := nil;
  EVP_PKEY_CTX_get_keygen_info := nil;
  EVP_PKEY_meth_set_init := nil;
  EVP_PKEY_meth_set_copy := nil;
  EVP_PKEY_meth_set_cleanup := nil;
  EVP_PKEY_meth_set_paramgen := nil;
  EVP_PKEY_meth_set_keygen := nil;
  EVP_PKEY_meth_set_sign := nil;
  EVP_PKEY_meth_set_verify := nil;
  EVP_PKEY_meth_set_verify_recover := nil;
  EVP_PKEY_meth_set_signctx := nil;
  EVP_PKEY_meth_set_verifyctx := nil;
  EVP_PKEY_meth_set_encrypt := nil;
  EVP_PKEY_meth_set_decrypt := nil;
  EVP_PKEY_meth_set_derive := nil;
  EVP_PKEY_meth_set_ctrl := nil;
  EVP_PKEY_meth_set_digestsign := nil;
  EVP_PKEY_meth_set_digestverify := nil;
  EVP_PKEY_meth_set_check := nil;
  EVP_PKEY_meth_set_public_check := nil;
  EVP_PKEY_meth_set_param_check := nil;
  EVP_PKEY_meth_set_digest_custom := nil;
  EVP_PKEY_meth_get_init := nil;
  EVP_PKEY_meth_get_copy := nil;
  EVP_PKEY_meth_get_cleanup := nil;
  EVP_PKEY_meth_get_paramgen := nil;
  EVP_PKEY_meth_get_keygen := nil;
  EVP_PKEY_meth_get_sign := nil;
  EVP_PKEY_meth_get_verify := nil;
  EVP_PKEY_meth_get_verify_recover := nil;
  EVP_PKEY_meth_get_signctx := nil;
  EVP_PKEY_meth_get_verifyctx := nil;
  EVP_PKEY_meth_get_encrypt := nil;
  EVP_PKEY_meth_get_decrypt := nil;
  EVP_PKEY_meth_get_derive := nil;
  EVP_PKEY_meth_get_ctrl := nil;
  EVP_PKEY_meth_get_digestsign := nil;
  EVP_PKEY_meth_get_digestverify := nil;
  EVP_PKEY_meth_get_check := nil;
  EVP_PKEY_meth_get_public_check := nil;
  EVP_PKEY_meth_get_param_check := nil;
  EVP_PKEY_meth_get_digest_custom := nil;
  EVP_add_alg_module := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  OpenSSL_add_all_ciphers := nil;
  OpenSSL_add_all_digests := nil;
  EVP_cleanup := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
