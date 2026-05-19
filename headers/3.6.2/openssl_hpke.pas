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

unit openssl_hpke;

{
  Generated from OpenSSL 3.6.2 Header File hpke.h - Tue 19 May 14:30:10 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_hpke.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types;


{* Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{ APIs and data structures for HPKE (RFC9180)  }
{$ifndef  OSSL_HPKE_H}
  {$define OSSL_HPKE_H}

const
  { HPKE modes }
  OSSL_HPKE_MODE_BASE = 0;
  OSSL_HPKE_MODE_PSK = 1;
  OSSL_HPKE_MODE_AUTH = 2;
  OSSL_HPKE_MODE_PSKAUTH = 3;
  
  {* Max for ikm, psk, pskid, info and exporter contexts.
  * RFC9180, section 7.2.1 RECOMMENDS 64 octets but we have test vectors from
  * Appendix A.6.1 with a 66 octet IKM so we'll allow that.
  }
  OSSL_HPKE_MAX_PARMLEN = 66;
  OSSL_HPKE_MIN_PSKLEN = 32;
  OSSL_HPKE_MAX_INFOLEN = 1024;
  
  {* The (16bit) HPKE algorithm ID IANA codepoints
  * If/when new IANA codepoints are added there are tables in
  * crypto/hpke/hpke_util.c that must also be updated.
  }
  OSSL_HPKE_KEM_ID_RESERVED = $0000;
  OSSL_HPKE_KEM_ID_P256 = $0010;
  OSSL_HPKE_KEM_ID_P384 = $0011;
  OSSL_HPKE_KEM_ID_P521 = $0012;
  OSSL_HPKE_KEM_ID_X25519 = $0020;
  OSSL_HPKE_KEM_ID_X448 = $0021;
  OSSL_HPKE_KDF_ID_RESERVED = $0000;
  OSSL_HPKE_KDF_ID_HKDF_SHA256 = $0001;
  OSSL_HPKE_KDF_ID_HKDF_SHA384 = $0002;
  OSSL_HPKE_KDF_ID_HKDF_SHA512 = $0003;
  OSSL_HPKE_AEAD_ID_RESERVED = $0000;
  OSSL_HPKE_AEAD_ID_AES_GCM_128 = $0001;
  OSSL_HPKE_AEAD_ID_AES_GCM_256 = $0002;
  OSSL_HPKE_AEAD_ID_CHACHA_POLY1305 = $0003;
  OSSL_HPKE_AEAD_ID_EXPORTONLY = $FFFF;
  { strings for suite components }
  OSSL_HPKE_KEMSTR_P256 = 'P-256';
  OSSL_HPKE_KEMSTR_P384 = 'P-384';
  OSSL_HPKE_KEMSTR_P521 = 'P-521';
  OSSL_HPKE_KEMSTR_X25519 = 'X25519';
  OSSL_HPKE_KEMSTR_X448 = 'X448';
  OSSL_HPKE_KDFSTR_256 = 'hkdf-sha256';
  OSSL_HPKE_KDFSTR_384 = 'hkdf-sha384';
  OSSL_HPKE_KDFSTR_512 = 'hkdf-sha512';
  OSSL_HPKE_AEADSTR_AES128GCM = 'aes-128-gcm';
  OSSL_HPKE_AEADSTR_AES256GCM = 'aes-256-gcm';
  OSSL_HPKE_AEADSTR_CP = 'chacha20-poly1305';
  OSSL_HPKE_AEADSTR_EXP = 'exporter';
  
  {* Roles for use in creating an OSSL_HPKE_CTX, most
  * important use of this is to control nonce reuse.
  }
  OSSL_HPKE_ROLE_SENDER = 0;
  OSSL_HPKE_ROLE_RECEIVER = 1;

type
  {Auto-generated forward references}
  POSSL_HPKE_SUITE = ^TOSSL_HPKE_SUITE;
  PPOSSL_HPKE_SUITE = ^POSSL_HPKE_SUITE;
  {end of auto-generated forward references}

  TOSSL_HPKE_SUITE = record 
    kem_id: TOpenSSL_C_UINT16; { Key Encapsulation Method id }
    kdf_id: TOpenSSL_C_UINT16; { Key Derivation Function id }
    aead_id: TOpenSSL_C_UINT16; { AEAD alg id }
  end;
  {*
  * Suite constants, use this like:
  *          OSSL_HPKE_SUITE myvar = OSSL_HPKE_SUITE_DEFAULT;
  }
  {$ifndef  OPENSSL_NO_ECX}
(*# define  OSSL_HPKE_SUITE_DEFAULT { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }*)
  {$else}
(*# define  OSSL_HPKE_SUITE_DEFAULT { OSSL_HPKE_KEM_ID_P256, OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_AEAD_ID_AES_GCM_128 }*)
  {$endif}

type
  {Auto-generated forward references}
  Possl_hpke_ctx_st = ^TOSSL_HPKE_CTX;
  PPossl_hpke_ctx_st = ^Possl_hpke_ctx_st;
  POSSL_HPKE_CTX = ^TOSSL_HPKE_CTX;
  PPOSSL_HPKE_CTX = ^POSSL_HPKE_CTX;
  {end of auto-generated forward references}

  Tossl_hpke_ctx_st = record end;
  TOSSL_HPKE_CTX = Tossl_hpke_ctx_st;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_HPKE_CTX_new(mode: TOpenSSL_C_INT; suite: TOSSL_HPKE_SUITE; role: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_HPKE_CTX; cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_new';
  procedure OSSL_HPKE_CTX_free(ctx: POSSL_HPKE_CTX); cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_free';
  function OSSL_HPKE_encap(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: POpenSSL_C_SIZET; pub: Pbyte; publen: TOpenSSL_C_SIZET; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_encap';
  function OSSL_HPKE_seal(ctx: POSSL_HPKE_CTX; ct: Pbyte; ctlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; pt: Pbyte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_seal';
  function OSSL_HPKE_keygen(suite: TOSSL_HPKE_SUITE; pub: Pbyte; publen: POpenSSL_C_SIZET; priv: PPEVP_PKEY; ikm: Pbyte; ikmlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_keygen';
  function OSSL_HPKE_decap(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: TOpenSSL_C_SIZET; recippriv: PEVP_PKEY; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_decap';
  function OSSL_HPKE_open(ctx: POSSL_HPKE_CTX; pt: Pbyte; ptlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_open';
  function OSSL_HPKE_export(ctx: POSSL_HPKE_CTX; secret: Pbyte; secretlen: TOpenSSL_C_SIZET; label_: Pbyte; labellen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_export';
  function OSSL_HPKE_CTX_set1_authpriv(ctx: POSSL_HPKE_CTX; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_set1_authpriv';
  function OSSL_HPKE_CTX_set1_authpub(ctx: POSSL_HPKE_CTX; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_set1_authpub';
  function OSSL_HPKE_CTX_set1_psk(ctx: POSSL_HPKE_CTX; pskid: PAnsiChar; psk: Pbyte; psklen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_set1_psk';
  function OSSL_HPKE_CTX_set1_ikme(ctx: POSSL_HPKE_CTX; ikme: Pbyte; ikmelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_set1_ikme';
  function OSSL_HPKE_CTX_set_seq(ctx: POSSL_HPKE_CTX; seq: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_set_seq';
  function OSSL_HPKE_CTX_get_seq(ctx: POSSL_HPKE_CTX; seq: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_CTX_get_seq';
  function OSSL_HPKE_suite_check(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_suite_check';
  function OSSL_HPKE_get_grease_value(suite_in: POSSL_HPKE_SUITE; suite: POSSL_HPKE_SUITE; enc: Pbyte; enclen: POpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_get_grease_value';
  function OSSL_HPKE_str2suite(str: PAnsiChar; suite: POSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HPKE_str2suite';
  function OSSL_HPKE_get_ciphertext_size(suite: TOSSL_HPKE_SUITE; clearlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'OSSL_HPKE_get_ciphertext_size';
  function OSSL_HPKE_get_public_encap_size(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'OSSL_HPKE_get_public_encap_size';
  function OSSL_HPKE_get_recommended_ikmelen(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'OSSL_HPKE_get_recommended_ikmelen';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_HPKE_CTX_new}
  {$EXTERNALSYM OSSL_HPKE_CTX_free}
  {$EXTERNALSYM OSSL_HPKE_encap}
  {$EXTERNALSYM OSSL_HPKE_seal}
  {$EXTERNALSYM OSSL_HPKE_keygen}
  {$EXTERNALSYM OSSL_HPKE_decap}
  {$EXTERNALSYM OSSL_HPKE_open}
  {$EXTERNALSYM OSSL_HPKE_export}
  {$EXTERNALSYM OSSL_HPKE_CTX_set1_authpriv}
  {$EXTERNALSYM OSSL_HPKE_CTX_set1_authpub}
  {$EXTERNALSYM OSSL_HPKE_CTX_set1_psk}
  {$EXTERNALSYM OSSL_HPKE_CTX_set1_ikme}
  {$EXTERNALSYM OSSL_HPKE_CTX_set_seq}
  {$EXTERNALSYM OSSL_HPKE_CTX_get_seq}
  {$EXTERNALSYM OSSL_HPKE_suite_check}
  {$EXTERNALSYM OSSL_HPKE_get_grease_value}
  {$EXTERNALSYM OSSL_HPKE_str2suite}
  {$EXTERNALSYM OSSL_HPKE_get_ciphertext_size}
  {$EXTERNALSYM OSSL_HPKE_get_public_encap_size}
  {$EXTERNALSYM OSSL_HPKE_get_recommended_ikmelen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_HPKE_CTX_new(mode: TOpenSSL_C_INT; suite: TOSSL_HPKE_SUITE; role: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_HPKE_CTX; cdecl;
  procedure Load_OSSL_HPKE_CTX_free(ctx: POSSL_HPKE_CTX); cdecl;
  function Load_OSSL_HPKE_encap(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: POpenSSL_C_SIZET; pub: Pbyte; publen: TOpenSSL_C_SIZET; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_seal(ctx: POSSL_HPKE_CTX; ct: Pbyte; ctlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; pt: Pbyte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_keygen(suite: TOSSL_HPKE_SUITE; pub: Pbyte; publen: POpenSSL_C_SIZET; priv: PPEVP_PKEY; ikm: Pbyte; ikmlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_decap(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: TOpenSSL_C_SIZET; recippriv: PEVP_PKEY; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_open(ctx: POSSL_HPKE_CTX; pt: Pbyte; ptlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_export(ctx: POSSL_HPKE_CTX; secret: Pbyte; secretlen: TOpenSSL_C_SIZET; label_: Pbyte; labellen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_CTX_set1_authpriv(ctx: POSSL_HPKE_CTX; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_CTX_set1_authpub(ctx: POSSL_HPKE_CTX; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_CTX_set1_psk(ctx: POSSL_HPKE_CTX; pskid: PAnsiChar; psk: Pbyte; psklen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_CTX_set1_ikme(ctx: POSSL_HPKE_CTX; ikme: Pbyte; ikmelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_CTX_set_seq(ctx: POSSL_HPKE_CTX; seq: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_CTX_get_seq(ctx: POSSL_HPKE_CTX; seq: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_suite_check(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_get_grease_value(suite_in: POSSL_HPKE_SUITE; suite: POSSL_HPKE_SUITE; enc: Pbyte; enclen: POpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_str2suite(str: PAnsiChar; suite: POSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HPKE_get_ciphertext_size(suite: TOSSL_HPKE_SUITE; clearlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
  function Load_OSSL_HPKE_get_public_encap_size(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl;
  function Load_OSSL_HPKE_get_recommended_ikmelen(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl;

var
  OSSL_HPKE_CTX_new: function(mode: TOpenSSL_C_INT; suite: TOSSL_HPKE_SUITE; role: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_HPKE_CTX; cdecl = Load_OSSL_HPKE_CTX_new;
  OSSL_HPKE_CTX_free: procedure(ctx: POSSL_HPKE_CTX); cdecl = Load_OSSL_HPKE_CTX_free;
  OSSL_HPKE_encap: function(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: POpenSSL_C_SIZET; pub: Pbyte; publen: TOpenSSL_C_SIZET; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_encap;
  OSSL_HPKE_seal: function(ctx: POSSL_HPKE_CTX; ct: Pbyte; ctlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; pt: Pbyte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_seal;
  OSSL_HPKE_keygen: function(suite: TOSSL_HPKE_SUITE; pub: Pbyte; publen: POpenSSL_C_SIZET; priv: PPEVP_PKEY; ikm: Pbyte; ikmlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_keygen;
  OSSL_HPKE_decap: function(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: TOpenSSL_C_SIZET; recippriv: PEVP_PKEY; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_decap;
  OSSL_HPKE_open: function(ctx: POSSL_HPKE_CTX; pt: Pbyte; ptlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_open;
  OSSL_HPKE_export: function(ctx: POSSL_HPKE_CTX; secret: Pbyte; secretlen: TOpenSSL_C_SIZET; label_: Pbyte; labellen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_export;
  OSSL_HPKE_CTX_set1_authpriv: function(ctx: POSSL_HPKE_CTX; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_CTX_set1_authpriv;
  OSSL_HPKE_CTX_set1_authpub: function(ctx: POSSL_HPKE_CTX; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_CTX_set1_authpub;
  OSSL_HPKE_CTX_set1_psk: function(ctx: POSSL_HPKE_CTX; pskid: PAnsiChar; psk: Pbyte; psklen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_CTX_set1_psk;
  OSSL_HPKE_CTX_set1_ikme: function(ctx: POSSL_HPKE_CTX; ikme: Pbyte; ikmelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_CTX_set1_ikme;
  OSSL_HPKE_CTX_set_seq: function(ctx: POSSL_HPKE_CTX; seq: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_CTX_set_seq;
  OSSL_HPKE_CTX_get_seq: function(ctx: POSSL_HPKE_CTX; seq: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_CTX_get_seq;
  OSSL_HPKE_suite_check: function(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_suite_check;
  OSSL_HPKE_get_grease_value: function(suite_in: POSSL_HPKE_SUITE; suite: POSSL_HPKE_SUITE; enc: Pbyte; enclen: POpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_get_grease_value;
  OSSL_HPKE_str2suite: function(str: PAnsiChar; suite: POSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl = Load_OSSL_HPKE_str2suite;
  OSSL_HPKE_get_ciphertext_size: function(suite: TOSSL_HPKE_SUITE; clearlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_OSSL_HPKE_get_ciphertext_size;
  OSSL_HPKE_get_public_encap_size: function(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl = Load_OSSL_HPKE_get_public_encap_size;
  OSSL_HPKE_get_recommended_ikmelen: function(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl = Load_OSSL_HPKE_get_recommended_ikmelen;
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
function Load_OSSL_HPKE_CTX_new(mode: TOpenSSL_C_INT; suite: TOSSL_HPKE_SUITE; role: TOpenSSL_C_INT; libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_HPKE_CTX; cdecl;
begin
  OSSL_HPKE_CTX_new := LoadLibCryptoFunction('OSSL_HPKE_CTX_new');
  if not assigned(OSSL_HPKE_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_new');
  Result := OSSL_HPKE_CTX_new(mode, suite, role, libctx, propq);
end;

procedure Load_OSSL_HPKE_CTX_free(ctx: POSSL_HPKE_CTX); cdecl;
begin
  OSSL_HPKE_CTX_free := LoadLibCryptoFunction('OSSL_HPKE_CTX_free');
  if not assigned(OSSL_HPKE_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_free');
  OSSL_HPKE_CTX_free(ctx);
end;

function Load_OSSL_HPKE_encap(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: POpenSSL_C_SIZET; pub: Pbyte; publen: TOpenSSL_C_SIZET; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_encap := LoadLibCryptoFunction('OSSL_HPKE_encap');
  if not assigned(OSSL_HPKE_encap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_encap');
  Result := OSSL_HPKE_encap(ctx, enc, enclen, pub, publen, info, infolen);
end;

function Load_OSSL_HPKE_seal(ctx: POSSL_HPKE_CTX; ct: Pbyte; ctlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; pt: Pbyte; ptlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_seal := LoadLibCryptoFunction('OSSL_HPKE_seal');
  if not assigned(OSSL_HPKE_seal) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_seal');
  Result := OSSL_HPKE_seal(ctx, ct, ctlen, aad, aadlen, pt, ptlen);
end;

function Load_OSSL_HPKE_keygen(suite: TOSSL_HPKE_SUITE; pub: Pbyte; publen: POpenSSL_C_SIZET; priv: PPEVP_PKEY; ikm: Pbyte; ikmlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_keygen := LoadLibCryptoFunction('OSSL_HPKE_keygen');
  if not assigned(OSSL_HPKE_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_keygen');
  Result := OSSL_HPKE_keygen(suite, pub, publen, priv, ikm, ikmlen, libctx, propq);
end;

function Load_OSSL_HPKE_decap(ctx: POSSL_HPKE_CTX; enc: Pbyte; enclen: TOpenSSL_C_SIZET; recippriv: PEVP_PKEY; info: Pbyte; infolen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_decap := LoadLibCryptoFunction('OSSL_HPKE_decap');
  if not assigned(OSSL_HPKE_decap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_decap');
  Result := OSSL_HPKE_decap(ctx, enc, enclen, recippriv, info, infolen);
end;

function Load_OSSL_HPKE_open(ctx: POSSL_HPKE_CTX; pt: Pbyte; ptlen: POpenSSL_C_SIZET; aad: Pbyte; aadlen: TOpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_open := LoadLibCryptoFunction('OSSL_HPKE_open');
  if not assigned(OSSL_HPKE_open) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_open');
  Result := OSSL_HPKE_open(ctx, pt, ptlen, aad, aadlen, ct, ctlen);
end;

function Load_OSSL_HPKE_export(ctx: POSSL_HPKE_CTX; secret: Pbyte; secretlen: TOpenSSL_C_SIZET; label_: Pbyte; labellen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_export := LoadLibCryptoFunction('OSSL_HPKE_export');
  if not assigned(OSSL_HPKE_export) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_export');
  Result := OSSL_HPKE_export(ctx, secret, secretlen, label_, labellen);
end;

function Load_OSSL_HPKE_CTX_set1_authpriv(ctx: POSSL_HPKE_CTX; priv: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_CTX_set1_authpriv := LoadLibCryptoFunction('OSSL_HPKE_CTX_set1_authpriv');
  if not assigned(OSSL_HPKE_CTX_set1_authpriv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_set1_authpriv');
  Result := OSSL_HPKE_CTX_set1_authpriv(ctx, priv);
end;

function Load_OSSL_HPKE_CTX_set1_authpub(ctx: POSSL_HPKE_CTX; pub: Pbyte; publen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_CTX_set1_authpub := LoadLibCryptoFunction('OSSL_HPKE_CTX_set1_authpub');
  if not assigned(OSSL_HPKE_CTX_set1_authpub) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_set1_authpub');
  Result := OSSL_HPKE_CTX_set1_authpub(ctx, pub, publen);
end;

function Load_OSSL_HPKE_CTX_set1_psk(ctx: POSSL_HPKE_CTX; pskid: PAnsiChar; psk: Pbyte; psklen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_CTX_set1_psk := LoadLibCryptoFunction('OSSL_HPKE_CTX_set1_psk');
  if not assigned(OSSL_HPKE_CTX_set1_psk) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_set1_psk');
  Result := OSSL_HPKE_CTX_set1_psk(ctx, pskid, psk, psklen);
end;

function Load_OSSL_HPKE_CTX_set1_ikme(ctx: POSSL_HPKE_CTX; ikme: Pbyte; ikmelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_CTX_set1_ikme := LoadLibCryptoFunction('OSSL_HPKE_CTX_set1_ikme');
  if not assigned(OSSL_HPKE_CTX_set1_ikme) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_set1_ikme');
  Result := OSSL_HPKE_CTX_set1_ikme(ctx, ikme, ikmelen);
end;

function Load_OSSL_HPKE_CTX_set_seq(ctx: POSSL_HPKE_CTX; seq: TOpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_CTX_set_seq := LoadLibCryptoFunction('OSSL_HPKE_CTX_set_seq');
  if not assigned(OSSL_HPKE_CTX_set_seq) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_set_seq');
  Result := OSSL_HPKE_CTX_set_seq(ctx, seq);
end;

function Load_OSSL_HPKE_CTX_get_seq(ctx: POSSL_HPKE_CTX; seq: POpenSSL_C_UINT64): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_CTX_get_seq := LoadLibCryptoFunction('OSSL_HPKE_CTX_get_seq');
  if not assigned(OSSL_HPKE_CTX_get_seq) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_CTX_get_seq');
  Result := OSSL_HPKE_CTX_get_seq(ctx, seq);
end;

function Load_OSSL_HPKE_suite_check(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_suite_check := LoadLibCryptoFunction('OSSL_HPKE_suite_check');
  if not assigned(OSSL_HPKE_suite_check) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_suite_check');
  Result := OSSL_HPKE_suite_check(suite);
end;

function Load_OSSL_HPKE_get_grease_value(suite_in: POSSL_HPKE_SUITE; suite: POSSL_HPKE_SUITE; enc: Pbyte; enclen: POpenSSL_C_SIZET; ct: Pbyte; ctlen: TOpenSSL_C_SIZET; libctx: POSSL_LIB_CTX; propq: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_get_grease_value := LoadLibCryptoFunction('OSSL_HPKE_get_grease_value');
  if not assigned(OSSL_HPKE_get_grease_value) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_get_grease_value');
  Result := OSSL_HPKE_get_grease_value(suite_in, suite, enc, enclen, ct, ctlen, libctx, propq);
end;

function Load_OSSL_HPKE_str2suite(str: PAnsiChar; suite: POSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HPKE_str2suite := LoadLibCryptoFunction('OSSL_HPKE_str2suite');
  if not assigned(OSSL_HPKE_str2suite) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_str2suite');
  Result := OSSL_HPKE_str2suite(str, suite);
end;

function Load_OSSL_HPKE_get_ciphertext_size(suite: TOSSL_HPKE_SUITE; clearlen: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  OSSL_HPKE_get_ciphertext_size := LoadLibCryptoFunction('OSSL_HPKE_get_ciphertext_size');
  if not assigned(OSSL_HPKE_get_ciphertext_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_get_ciphertext_size');
  Result := OSSL_HPKE_get_ciphertext_size(suite, clearlen);
end;

function Load_OSSL_HPKE_get_public_encap_size(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl;
begin
  OSSL_HPKE_get_public_encap_size := LoadLibCryptoFunction('OSSL_HPKE_get_public_encap_size');
  if not assigned(OSSL_HPKE_get_public_encap_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_get_public_encap_size');
  Result := OSSL_HPKE_get_public_encap_size(suite);
end;

function Load_OSSL_HPKE_get_recommended_ikmelen(suite: TOSSL_HPKE_SUITE): TOpenSSL_C_SIZET; cdecl;
begin
  OSSL_HPKE_get_recommended_ikmelen := LoadLibCryptoFunction('OSSL_HPKE_get_recommended_ikmelen');
  if not assigned(OSSL_HPKE_get_recommended_ikmelen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HPKE_get_recommended_ikmelen');
  Result := OSSL_HPKE_get_recommended_ikmelen(suite);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_HPKE_CTX_new := Load_OSSL_HPKE_CTX_new;
  OSSL_HPKE_CTX_free := Load_OSSL_HPKE_CTX_free;
  OSSL_HPKE_encap := Load_OSSL_HPKE_encap;
  OSSL_HPKE_seal := Load_OSSL_HPKE_seal;
  OSSL_HPKE_keygen := Load_OSSL_HPKE_keygen;
  OSSL_HPKE_decap := Load_OSSL_HPKE_decap;
  OSSL_HPKE_open := Load_OSSL_HPKE_open;
  OSSL_HPKE_export := Load_OSSL_HPKE_export;
  OSSL_HPKE_CTX_set1_authpriv := Load_OSSL_HPKE_CTX_set1_authpriv;
  OSSL_HPKE_CTX_set1_authpub := Load_OSSL_HPKE_CTX_set1_authpub;
  OSSL_HPKE_CTX_set1_psk := Load_OSSL_HPKE_CTX_set1_psk;
  OSSL_HPKE_CTX_set1_ikme := Load_OSSL_HPKE_CTX_set1_ikme;
  OSSL_HPKE_CTX_set_seq := Load_OSSL_HPKE_CTX_set_seq;
  OSSL_HPKE_CTX_get_seq := Load_OSSL_HPKE_CTX_get_seq;
  OSSL_HPKE_suite_check := Load_OSSL_HPKE_suite_check;
  OSSL_HPKE_get_grease_value := Load_OSSL_HPKE_get_grease_value;
  OSSL_HPKE_str2suite := Load_OSSL_HPKE_str2suite;
  OSSL_HPKE_get_ciphertext_size := Load_OSSL_HPKE_get_ciphertext_size;
  OSSL_HPKE_get_public_encap_size := Load_OSSL_HPKE_get_public_encap_size;
  OSSL_HPKE_get_recommended_ikmelen := Load_OSSL_HPKE_get_recommended_ikmelen;
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



