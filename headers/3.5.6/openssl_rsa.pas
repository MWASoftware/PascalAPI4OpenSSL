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

unit openssl_rsa;

{
  Generated from OpenSSL 3.5.6 Header File rsa.h - Tue 19 May 14:28:15 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_rsa.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_evp,openssl_asn1,openssl_bio,openssl_crypto,
     openssl_types,openssl_bn,openssl_rsaerr,openssl_safestack;


{* Copyright 1995-2026 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_RSA_H}
  {$define OPENSSL_RSA_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_RSA_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  {$endif}
  {$ifndef  OPENSSL_NO_STDIO}
  {$endif}
  {$ifndef  OPENSSL_RSA_MAX_MODULUS_BITS}

const
  OPENSSL_RSA_MAX_MODULUS_BITS = 16384;
  {$endif}

const
  RSA_3 = $3;
  RSA_F4 = $10001;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
    { The types RSA and RSA_METHOD are defined in ossl_typ.h }
  OPENSSL_RSA_FIPS_MIN_MODULUS_BITS = 2048;
    {$ifndef  OPENSSL_RSA_SMALL_MODULUS_BITS}

const
  OPENSSL_RSA_SMALL_MODULUS_BITS = 3072;
    {$endif}
    { exponent limit enforced for "large" modulus only }
    {$ifndef  OPENSSL_RSA_MAX_PUBEXP_BITS}

const
  OPENSSL_RSA_MAX_PUBEXP_BITS = 64;
    {$endif}

const
    { based on RFC 8017 appendix A.1.2 }
  RSA_ASN1_VERSION_DEFAULT = 0;
  RSA_ASN1_VERSION_MULTI = 1;
  RSA_DEFAULT_PRIME_NUM = 2;
  RSA_METHOD_FLAG_NO_CHECK = $0001;
  RSA_FLAG_CACHE_PUBLIC = $0002;
  RSA_FLAG_CACHE_PRIVATE = $0004;
  RSA_FLAG_BLINDING = $0008;
  RSA_FLAG_THREAD_SAFE = $0010;
    
    {* This flag means the private key operations will be handled by rsa_mod_exp
    * and that they do not depend on the private key components being present:
    * for example a key stored in external hardware. Without this flag
    * bn_mod_exp gets called when private key components are absent.
    }
  RSA_FLAG_EXT_PKEY = $0020;
    
    {* new with 0.9.6j and 0.9.7b; the built-in
    * RSA implementation now uses blinding by
    * default (ignoring RSA_FLAG_BLINDING),
    * but other engines might not need it
    }
  RSA_FLAG_NO_BLINDING = $0080;
  {$endif}
  { OPENSSL_NO_DEPRECATED_3_0 }
  
  {* Does nothing. Previously this switched off constant time behaviour.
  }
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}

const
  RSA_FLAG_NO_CONSTTIME = $0000;
  {$endif}
  { deprecated name for the flag}
  
  {* new with 0.9.7h; the built-in RSA
  * implementation now uses constant time
  * modular exponentiation for secret exponents
  * by default. This flag causes the
  * faster variable sliding window method to
  * be used for all exponents.
  }
  {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}

const
  RSA_FLAG_NO_EXP_CONSTTIME = RSA_FLAG_NO_CONSTTIME;
  {$endif}

const
  {-
  * New with 3.0: use part of the flags to denote exact type of RSA key,
  * some of which are limited to specific signature and encryption schemes.
  * These different types share the same RSA structure, but indicate the
  * use of certain fields in that structure.
  * Currently known are:
  * RSA          - this is the "normal" unlimited RSA structure (typenum 0)
  * RSASSA-PSS   - indicates that the PSS parameters are used.
  * RSAES-OAEP   - no specific field used for the moment, but OAEP padding
  *                is expected.  (currently unused)
  *
  * 4 bits allow for 16 types
  }
  RSA_FLAG_TYPE_MASK = $F000;
  RSA_FLAG_TYPE_RSA = $0000;
  RSA_FLAG_TYPE_RSASSAPSS = $1000;
  RSA_FLAG_TYPE_RSAESOAEP = $2000;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_padding';
  function EVP_PKEY_CTX_get_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_padding';
  function EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_saltlen';
  function EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_pss_saltlen';
  function EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: PEVP_PKEY_CTX; bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_keygen_bits';
  function EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set1_rsa_keygen_pubexp';
  function EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: PEVP_PKEY_CTX; primes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_keygen_primes';
  function EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_padding}
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_padding}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_saltlen}
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_pss_saltlen}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_keygen_bits}
  {$EXTERNALSYM EVP_PKEY_CTX_set1_rsa_keygen_pubexp}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_keygen_primes}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: PEVP_PKEY_CTX; bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: PEVP_PKEY_CTX; primes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_rsa_padding: function(ctx: PEVP_PKEY_CTX; pad_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_padding;
  EVP_PKEY_CTX_get_rsa_padding: function(ctx: PEVP_PKEY_CTX; pad_mode: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_rsa_padding;
  EVP_PKEY_CTX_set_rsa_pss_saltlen: function(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_pss_saltlen;
  EVP_PKEY_CTX_get_rsa_pss_saltlen: function(ctx: PEVP_PKEY_CTX; saltlen: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_rsa_pss_saltlen;
  EVP_PKEY_CTX_set_rsa_keygen_bits: function(ctx: PEVP_PKEY_CTX; bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_keygen_bits;
  EVP_PKEY_CTX_set1_rsa_keygen_pubexp: function(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set1_rsa_keygen_pubexp;
  EVP_PKEY_CTX_set_rsa_keygen_primes: function(ctx: PEVP_PKEY_CTX; primes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_keygen_primes;
  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen: function(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_keygen_pubexp'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_keygen_pubexp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_rsa_keygen_pubexp: function(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_keygen_pubexp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}

const
  { Salt length matches digest }
  RSA_PSS_SALTLEN_DIGEST = -(1);
  { Verify only: auto detect salt length }
  RSA_PSS_SALTLEN_AUTO = -(2);
  { Set salt length to maximum possible }
  RSA_PSS_SALTLEN_MAX = -(3);
  { Auto-detect on verify, set salt length to min(maximum possible, digest
  * length) on sign }
  RSA_PSS_SALTLEN_AUTO_DIGEST_MAX = -(4);
  { Old compatible max salt length for sign only }
  RSA_PSS_SALTLEN_MAX_SIGN = -(2);


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_mgf1_md';
  function EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_mgf1_md_name';
  function EVP_PKEY_CTX_get_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_mgf1_md';
  function EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_mgf1_md_name';
  function EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md';
  function EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name';
  function EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_md';
  function EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_pss_keygen_md_name';
  function EVP_PKEY_CTX_set_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_oaep_md';
  function EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set_rsa_oaep_md_name';
  function EVP_PKEY_CTX_get_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_oaep_md';
  function EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get_rsa_oaep_md_name';
  function EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; label_: pointer; llen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_set0_rsa_oaep_label';
  function EVP_PKEY_CTX_get0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; label_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'EVP_PKEY_CTX_get0_rsa_oaep_label';
  {$else}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_mgf1_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_mgf1_md_name}
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_mgf1_md}
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_mgf1_md_name}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_pss_keygen_md_name}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_oaep_md}
  {$EXTERNALSYM EVP_PKEY_CTX_set_rsa_oaep_md_name}
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_oaep_md}
  {$EXTERNALSYM EVP_PKEY_CTX_get_rsa_oaep_md_name}
  {$EXTERNALSYM EVP_PKEY_CTX_set0_rsa_oaep_label}
  {$EXTERNALSYM EVP_PKEY_CTX_get0_rsa_oaep_label}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; label_: pointer; llen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_EVP_PKEY_CTX_get0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; label_: PPbyte): TOpenSSL_C_INT; cdecl;

var
  EVP_PKEY_CTX_set_rsa_mgf1_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_mgf1_md;
  EVP_PKEY_CTX_set_rsa_mgf1_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_mgf1_md_name;
  EVP_PKEY_CTX_get_rsa_mgf1_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_rsa_mgf1_md;
  EVP_PKEY_CTX_get_rsa_mgf1_md_name: function(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_rsa_mgf1_md_name;
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md;
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name;
  EVP_PKEY_CTX_set_rsa_pss_keygen_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md;
  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name;
  EVP_PKEY_CTX_set_rsa_oaep_md: function(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_oaep_md;
  EVP_PKEY_CTX_set_rsa_oaep_md_name: function(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set_rsa_oaep_md_name;
  EVP_PKEY_CTX_get_rsa_oaep_md: function(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_rsa_oaep_md;
  EVP_PKEY_CTX_get_rsa_oaep_md_name: function(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get_rsa_oaep_md_name;
  EVP_PKEY_CTX_set0_rsa_oaep_label: function(ctx: PEVP_PKEY_CTX; label_: pointer; llen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_set0_rsa_oaep_label;
  EVP_PKEY_CTX_get0_rsa_oaep_label: function(ctx: PEVP_PKEY_CTX; label_: PPbyte): TOpenSSL_C_INT; cdecl = Load_EVP_PKEY_CTX_get0_rsa_oaep_label;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  EVP_PKEY_CTRL_RSA_PADDING = EVP_PKEY_ALG_CTRL+1;
  EVP_PKEY_CTRL_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL+2;
  EVP_PKEY_CTRL_RSA_KEYGEN_BITS = EVP_PKEY_ALG_CTRL+3;
  EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP = EVP_PKEY_ALG_CTRL+4;
  EVP_PKEY_CTRL_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL+5;
  EVP_PKEY_CTRL_GET_RSA_PADDING = EVP_PKEY_ALG_CTRL+6;
  EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN = EVP_PKEY_ALG_CTRL+7;
  EVP_PKEY_CTRL_GET_RSA_MGF1_MD = EVP_PKEY_ALG_CTRL+8;
  EVP_PKEY_CTRL_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL+9;
  EVP_PKEY_CTRL_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL+10;
  EVP_PKEY_CTRL_GET_RSA_OAEP_MD = EVP_PKEY_ALG_CTRL+11;
  EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL = EVP_PKEY_ALG_CTRL+12;
  EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES = EVP_PKEY_ALG_CTRL+13;
  EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION = EVP_PKEY_ALG_CTRL+14;
  RSA_PKCS1_PADDING = 1;
  RSA_NO_PADDING = 3;
  RSA_PKCS1_OAEP_PADDING = 4;
  RSA_X931_PADDING = 5;
  { EVP_PKEY_ only }
  RSA_PKCS1_PSS_PADDING = 6;
  RSA_PKCS1_WITH_TLS_PADDING = 7;
  { internal RSA_ only }
  RSA_PKCS1_NO_IMPLICIT_REJECT_PADDING = 8;
  RSA_PKCS1_PADDING_SIZE = 11;


  function RSA_set_app_data(s:PRSA; arg:pointer): TOpenSSL_C_INT; inline;
  function RSA_get_app_data(s:PRSA): pointer; inline;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_new: PRSA; cdecl; external CLibCrypto name 'RSA_new'; deprecated 'Since OpenSSL 3.0';
  function RSA_new_method(engine: PENGINE): PRSA; cdecl; external CLibCrypto name 'RSA_new_method'; deprecated 'Since OpenSSL 3.0';
  function RSA_bits(rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_bits'; deprecated 'Since OpenSSL 3.0';
  function RSA_size(rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_size'; deprecated 'Since OpenSSL 3.0';
  function RSA_security_bits(rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_security_bits'; deprecated 'Since OpenSSL 3.0';
  function RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_set0_key'; deprecated 'Since OpenSSL 3.0';
  function RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_set0_factors'; deprecated 'Since OpenSSL 3.0';
  function RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_set0_crt_params'; deprecated 'Since OpenSSL 3.0';
  function RSA_set0_multi_prime_params(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_set0_multi_prime_params'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_get0_key(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM); cdecl; external CLibCrypto name 'RSA_get0_key'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_get0_factors(r: PRSA; p: PPBIGNUM; q: PPBIGNUM); cdecl; external CLibCrypto name 'RSA_get0_factors'; deprecated 'Since OpenSSL 3.0';
  function RSA_get_multi_prime_extra_count(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_get_multi_prime_extra_count'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_multi_prime_factors(r: PRSA; primes: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_get0_multi_prime_factors'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_get0_crt_params(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM); cdecl; external CLibCrypto name 'RSA_get0_crt_params'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_multi_prime_crt_params(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_get0_multi_prime_crt_params'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_n(d: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_n'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_e(d: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_e'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_d(d: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_d'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_p(d: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_p'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_q(d: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_q'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_dmp1(r: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_dmp1'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_dmq1(r: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_dmq1'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_iqmp(r: PRSA): PBIGNUM; cdecl; external CLibCrypto name 'RSA_get0_iqmp'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_pss_params(r: PRSA): PRSA_PSS_PARAMS; cdecl; external CLibCrypto name 'RSA_get0_pss_params'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RSA_clear_flags'; deprecated 'Since OpenSSL 3.0';
  function RSA_test_flags(r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_test_flags'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'RSA_set_flags'; deprecated 'Since OpenSSL 3.0';
  function RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_get_version'; deprecated 'Since OpenSSL 3.0';
  function RSA_get0_engine(r: PRSA): PENGINE; cdecl; external CLibCrypto name 'RSA_get0_engine'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_new}
  {$EXTERNALSYM RSA_new_method}
  {$EXTERNALSYM RSA_bits}
  {$EXTERNALSYM RSA_size}
  {$EXTERNALSYM RSA_security_bits}
  {$EXTERNALSYM RSA_set0_key}
  {$EXTERNALSYM RSA_set0_factors}
  {$EXTERNALSYM RSA_set0_crt_params}
  {$EXTERNALSYM RSA_set0_multi_prime_params}
  {$EXTERNALSYM RSA_get0_key}
  {$EXTERNALSYM RSA_get0_factors}
  {$EXTERNALSYM RSA_get_multi_prime_extra_count}
  {$EXTERNALSYM RSA_get0_multi_prime_factors}
  {$EXTERNALSYM RSA_get0_crt_params}
  {$EXTERNALSYM RSA_get0_multi_prime_crt_params}
  {$EXTERNALSYM RSA_get0_n}
  {$EXTERNALSYM RSA_get0_e}
  {$EXTERNALSYM RSA_get0_d}
  {$EXTERNALSYM RSA_get0_p}
  {$EXTERNALSYM RSA_get0_q}
  {$EXTERNALSYM RSA_get0_dmp1}
  {$EXTERNALSYM RSA_get0_dmq1}
  {$EXTERNALSYM RSA_get0_iqmp}
  {$EXTERNALSYM RSA_get0_pss_params}
  {$EXTERNALSYM RSA_clear_flags}
  {$EXTERNALSYM RSA_test_flags}
  {$EXTERNALSYM RSA_set_flags}
  {$EXTERNALSYM RSA_get_version}
  {$EXTERNALSYM RSA_get0_engine}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_new: PRSA; cdecl;
  function Load_RSA_new_method(engine: PENGINE): PRSA; cdecl;
  function Load_RSA_bits(rsa: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_size(rsa: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_security_bits(rsa: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_RSA_set0_multi_prime_params(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_RSA_get0_key(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM); cdecl;
  procedure Load_RSA_get0_factors(r: PRSA; p: PPBIGNUM; q: PPBIGNUM); cdecl;
  function Load_RSA_get_multi_prime_extra_count(r: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_get0_multi_prime_factors(r: PRSA; primes: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  procedure Load_RSA_get0_crt_params(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM); cdecl;
  function Load_RSA_get0_multi_prime_crt_params(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TOpenSSL_C_INT; cdecl;
  function Load_RSA_get0_n(d: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_e(d: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_d(d: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_p(d: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_q(d: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_dmp1(r: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_dmq1(r: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_iqmp(r: PRSA): PBIGNUM; cdecl;
  function Load_RSA_get0_pss_params(r: PRSA): PRSA_PSS_PARAMS; cdecl;
  procedure Load_RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
  function Load_RSA_test_flags(r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
  function Load_RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_get0_engine(r: PRSA): PENGINE; cdecl;

var
  RSA_new: function: PRSA; cdecl = Load_RSA_new;
  RSA_new_method: function(engine: PENGINE): PRSA; cdecl = Load_RSA_new_method;
  RSA_bits: function(rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_bits;
  RSA_size: function(rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_size;
  RSA_security_bits: function(rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_security_bits;
  RSA_set0_key: function(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_set0_key;
  RSA_set0_factors: function(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_set0_factors;
  RSA_set0_crt_params: function(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_set0_crt_params;
  RSA_set0_multi_prime_params: function(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_set0_multi_prime_params;
  RSA_get0_key: procedure(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM); cdecl = Load_RSA_get0_key;
  RSA_get0_factors: procedure(r: PRSA; p: PPBIGNUM; q: PPBIGNUM); cdecl = Load_RSA_get0_factors;
  RSA_get_multi_prime_extra_count: function(r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_get_multi_prime_extra_count;
  RSA_get0_multi_prime_factors: function(r: PRSA; primes: PPBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_get0_multi_prime_factors;
  RSA_get0_crt_params: procedure(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM); cdecl = Load_RSA_get0_crt_params;
  RSA_get0_multi_prime_crt_params: function(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TOpenSSL_C_INT; cdecl = Load_RSA_get0_multi_prime_crt_params;
  RSA_get0_n: function(d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_n;
  RSA_get0_e: function(d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_e;
  RSA_get0_d: function(d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_d;
  RSA_get0_p: function(d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_p;
  RSA_get0_q: function(d: PRSA): PBIGNUM; cdecl = Load_RSA_get0_q;
  RSA_get0_dmp1: function(r: PRSA): PBIGNUM; cdecl = Load_RSA_get0_dmp1;
  RSA_get0_dmq1: function(r: PRSA): PBIGNUM; cdecl = Load_RSA_get0_dmq1;
  RSA_get0_iqmp: function(r: PRSA): PBIGNUM; cdecl = Load_RSA_get0_iqmp;
  RSA_get0_pss_params: function(r: PRSA): PRSA_PSS_PARAMS; cdecl = Load_RSA_get0_pss_params;
  RSA_clear_flags: procedure(r: PRSA; flags: TOpenSSL_C_INT); cdecl = Load_RSA_clear_flags;
  RSA_test_flags: function(r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_test_flags;
  RSA_set_flags: procedure(r: PRSA; flags: TOpenSSL_C_INT); cdecl = Load_RSA_set_flags;
  RSA_get_version: function(r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_get_version;
  RSA_get0_engine: function(r: PRSA): PENGINE; cdecl = Load_RSA_get0_engine;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
{# define  EVP_RSA_gen(bits) EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)(0 + (bits)))} {Macro Return Type unknown at line no 264}
  { !OPENSSL_NO_DEPRECATED_3_0 }
  { Deprecated version }
  {$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = procedure(_param1: TOpenSSL_C_INT; _param2: TOpenSSL_C_INT; _param3: pointer); cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_generate_key(bits: TOpenSSL_C_INT; e: TOpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PRSA; cdecl; external CLibCrypto name 'RSA_generate_key'; deprecated 'Since OpenSSL 0.9.8';
    {$else}
  {$EXTERNALSYM RSA_generate_key}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_generate_key(bits: TOpenSSL_C_INT; e: TOpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PRSA; cdecl;

var
  RSA_generate_key: function(bits: TOpenSSL_C_INT; e: TOpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PRSA; cdecl = Load_RSA_generate_key;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  { New version }
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_generate_key_ex'; deprecated 'Since OpenSSL 3.0';
  { Multi-prime version }
  function RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_generate_multi_prime_key'; deprecated 'Since OpenSSL 3.0';
  function RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_X931_derive_ex'; deprecated 'Since OpenSSL 3.0';
  function RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_X931_generate_key_ex'; deprecated 'Since OpenSSL 3.0';
  function RSA_check_key(_param1: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_check_key'; deprecated 'Since OpenSSL 3.0';
  function RSA_check_key_ex(_param1: PRSA; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_check_key_ex'; deprecated 'Since OpenSSL 3.0';
  { next 4 return -1 on error }
  function RSA_public_encrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_public_encrypt'; deprecated 'Since OpenSSL 3.0';
  function RSA_private_encrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_private_encrypt'; deprecated 'Since OpenSSL 3.0';
  function RSA_public_decrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_public_decrypt'; deprecated 'Since OpenSSL 3.0';
  function RSA_private_decrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_private_decrypt'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_free(r: PRSA); cdecl; external CLibCrypto name 'RSA_free'; deprecated 'Since OpenSSL 3.0';
  { "up" the RSA object's reference count }
  function RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_up_ref'; deprecated 'Since OpenSSL 3.0';
  function RSA_flags(r: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_flags'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_set_default_method(meth: PRSA_METHOD); cdecl; external CLibCrypto name 'RSA_set_default_method'; deprecated 'Since OpenSSL 3.0';
  function RSA_get_default_method: PRSA_METHOD; cdecl; external CLibCrypto name 'RSA_get_default_method'; deprecated 'Since OpenSSL 3.0';
  function RSA_null_method: PRSA_METHOD; cdecl; external CLibCrypto name 'RSA_null_method'; deprecated 'Since OpenSSL 3.0';
  function RSA_get_method(rsa: PRSA): PRSA_METHOD; cdecl; external CLibCrypto name 'RSA_get_method'; deprecated 'Since OpenSSL 3.0';
  function RSA_set_method(rsa: PRSA; meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_set_method'; deprecated 'Since OpenSSL 3.0';
  { these are the actual RSA functions }
  function RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl; external CLibCrypto name 'RSA_PKCS1_OpenSSL'; deprecated 'Since OpenSSL 3.0';
  function d2i_RSAPublicKey(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl; external CLibCrypto name 'd2i_RSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function i2d_RSAPublicKey(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_RSAPublicKey'; deprecated 'Since OpenSSL 3.0';
  function RSAPublicKey_it: PASN1_ITEM; cdecl; external CLibCrypto name 'RSAPublicKey_it'; deprecated 'Since OpenSSL 3.0';
  function d2i_RSAPrivateKey(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl; external CLibCrypto name 'd2i_RSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function i2d_RSAPrivateKey(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_RSAPrivateKey'; deprecated 'Since OpenSSL 3.0';
  function RSAPrivateKey_it: PASN1_ITEM; cdecl; external CLibCrypto name 'RSAPrivateKey_it'; deprecated 'Since OpenSSL 3.0';
    {$else}
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
  {$EXTERNALSYM d2i_RSAPublicKey}
  {$EXTERNALSYM i2d_RSAPublicKey}
  {$EXTERNALSYM RSAPublicKey_it}
  {$EXTERNALSYM d2i_RSAPrivateKey}
  {$EXTERNALSYM i2d_RSAPrivateKey}
  {$EXTERNALSYM RSAPrivateKey_it}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
  function Load_RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
  function Load_RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
  function Load_RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
  function Load_RSA_check_key(_param1: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_check_key_ex(_param1: PRSA; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
  function Load_RSA_public_encrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_private_encrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_public_decrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_private_decrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  procedure Load_RSA_free(r: PRSA); cdecl;
  function Load_RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_flags(r: PRSA): TOpenSSL_C_INT; cdecl;
  procedure Load_RSA_set_default_method(meth: PRSA_METHOD); cdecl;
  function Load_RSA_get_default_method: PRSA_METHOD; cdecl;
  function Load_RSA_null_method: PRSA_METHOD; cdecl;
  function Load_RSA_get_method(rsa: PRSA): PRSA_METHOD; cdecl;
  function Load_RSA_set_method(rsa: PRSA; meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl;
  function Load_d2i_RSAPublicKey(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl;
  function Load_i2d_RSAPublicKey(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_RSAPublicKey_it: PASN1_ITEM; cdecl;
  function Load_d2i_RSAPrivateKey(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl;
  function Load_i2d_RSAPrivateKey(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_RSAPrivateKey_it: PASN1_ITEM; cdecl;

var
  RSA_generate_key_ex: function(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_generate_key_ex;
  { Multi-prime version }
  RSA_generate_multi_prime_key: function(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_generate_multi_prime_key;
  RSA_X931_derive_ex: function(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_X931_derive_ex;
  RSA_X931_generate_key_ex: function(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_X931_generate_key_ex;
  RSA_check_key: function(_param1: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_check_key;
  RSA_check_key_ex: function(_param1: PRSA; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl = Load_RSA_check_key_ex;
  { next 4 return -1 on error }
  RSA_public_encrypt: function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_public_encrypt;
  RSA_private_encrypt: function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_private_encrypt;
  RSA_public_decrypt: function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_public_decrypt;
  RSA_private_decrypt: function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_private_decrypt;
  RSA_free: procedure(r: PRSA); cdecl = Load_RSA_free;
  { "up" the RSA object's reference count }
  RSA_up_ref: function(r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_up_ref;
  RSA_flags: function(r: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_flags;
  RSA_set_default_method: procedure(meth: PRSA_METHOD); cdecl = Load_RSA_set_default_method;
  RSA_get_default_method: function: PRSA_METHOD; cdecl = Load_RSA_get_default_method;
  RSA_null_method: function: PRSA_METHOD; cdecl = Load_RSA_null_method;
  RSA_get_method: function(rsa: PRSA): PRSA_METHOD; cdecl = Load_RSA_get_method;
  RSA_set_method: function(rsa: PRSA; meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = Load_RSA_set_method;
  { these are the actual RSA functions }
  RSA_PKCS1_OpenSSL: function: PRSA_METHOD; cdecl = Load_RSA_PKCS1_OpenSSL;
  d2i_RSAPublicKey: function(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl = Load_d2i_RSAPublicKey;
  i2d_RSAPublicKey: function(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_RSAPublicKey;
  RSAPublicKey_it: function: PASN1_ITEM; cdecl = Load_RSAPublicKey_it;
  d2i_RSAPrivateKey: function(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl = Load_d2i_RSAPrivateKey;
  i2d_RSAPrivateKey: function(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_RSAPrivateKey;
  RSAPrivateKey_it: function: PASN1_ITEM; cdecl = Load_RSAPrivateKey_it;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  { !OPENSSL_NO_DEPRECATED_3_0 }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_pkey_ctx_ctrl';
  {$else}
  {$EXTERNALSYM RSA_pkey_ctx_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;

var
  RSA_pkey_ctx_ctrl: function(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl = Load_RSA_pkey_ctx_ctrl;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  Prsa_pss_params_st = ^Trsa_pss_params_st;
  PPrsa_pss_params_st = ^Prsa_pss_params_st;
  {end of auto-generated forward references}

  Trsa_pss_params_st = record 
    hashAlgorithm: PX509_ALGOR;
    maskGenAlgorithm: PX509_ALGOR;
    saltLength: PASN1_INTEGER;
    trailerField: PASN1_INTEGER; { Decoded hash algorithm from maskGenAlgorithm }
    maskHash: PX509_ALGOR;
  end;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_PSS_PARAMS_new: PRSA_PSS_PARAMS; cdecl; external CLibCrypto name 'RSA_PSS_PARAMS_new';
  procedure RSA_PSS_PARAMS_free(a: PRSA_PSS_PARAMS); cdecl; external CLibCrypto name 'RSA_PSS_PARAMS_free';
  function d2i_RSA_PSS_PARAMS(a: PPRSA_PSS_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_PSS_PARAMS; cdecl; external CLibCrypto name 'd2i_RSA_PSS_PARAMS';
  function i2d_RSA_PSS_PARAMS(a: PRSA_PSS_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_RSA_PSS_PARAMS';
  function RSA_PSS_PARAMS_it: PASN1_ITEM; cdecl; external CLibCrypto name 'RSA_PSS_PARAMS_it';
  function RSA_PSS_PARAMS_dup(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl; external CLibCrypto name 'RSA_PSS_PARAMS_dup';
  {$else}
  {$EXTERNALSYM RSA_PSS_PARAMS_new}
  {$EXTERNALSYM RSA_PSS_PARAMS_free}
  {$EXTERNALSYM d2i_RSA_PSS_PARAMS}
  {$EXTERNALSYM i2d_RSA_PSS_PARAMS}
  {$EXTERNALSYM RSA_PSS_PARAMS_it}
  {$EXTERNALSYM RSA_PSS_PARAMS_dup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_PSS_PARAMS_new: PRSA_PSS_PARAMS; cdecl;
  procedure Load_RSA_PSS_PARAMS_free(a: PRSA_PSS_PARAMS); cdecl;
  function Load_d2i_RSA_PSS_PARAMS(a: PPRSA_PSS_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_PSS_PARAMS; cdecl;
  function Load_i2d_RSA_PSS_PARAMS(a: PRSA_PSS_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_RSA_PSS_PARAMS_it: PASN1_ITEM; cdecl;
  function Load_RSA_PSS_PARAMS_dup(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl;

var
  RSA_PSS_PARAMS_new: function: PRSA_PSS_PARAMS; cdecl = Load_RSA_PSS_PARAMS_new;
  RSA_PSS_PARAMS_free: procedure(a: PRSA_PSS_PARAMS); cdecl = Load_RSA_PSS_PARAMS_free;
  d2i_RSA_PSS_PARAMS: function(a: PPRSA_PSS_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_PSS_PARAMS; cdecl = Load_d2i_RSA_PSS_PARAMS;
  i2d_RSA_PSS_PARAMS: function(a: PRSA_PSS_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_RSA_PSS_PARAMS;
  RSA_PSS_PARAMS_it: function: PASN1_ITEM; cdecl = Load_RSA_PSS_PARAMS_it;
  RSA_PSS_PARAMS_dup: function(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl = Load_RSA_PSS_PARAMS_dup;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  Prsa_oaep_params_st = ^Trsa_oaep_params_st;
  PPrsa_oaep_params_st = ^Prsa_oaep_params_st;
  {end of auto-generated forward references}

  Trsa_oaep_params_st = record 
    hashFunc: PX509_ALGOR;
    maskGenFunc: PX509_ALGOR;
    pSourceFunc: PX509_ALGOR; { Decoded hash algorithm from maskGenFunc }
    maskHash: PX509_ALGOR;
  end;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_OAEP_PARAMS_new: PRSA_OAEP_PARAMS; cdecl; external CLibCrypto name 'RSA_OAEP_PARAMS_new';
  procedure RSA_OAEP_PARAMS_free(a: PRSA_OAEP_PARAMS); cdecl; external CLibCrypto name 'RSA_OAEP_PARAMS_free';
  function d2i_RSA_OAEP_PARAMS(a: PPRSA_OAEP_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_OAEP_PARAMS; cdecl; external CLibCrypto name 'd2i_RSA_OAEP_PARAMS';
  function i2d_RSA_OAEP_PARAMS(a: PRSA_OAEP_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_RSA_OAEP_PARAMS';
  function RSA_OAEP_PARAMS_it: PASN1_ITEM; cdecl; external CLibCrypto name 'RSA_OAEP_PARAMS_it';
  {$else}
  {$EXTERNALSYM RSA_OAEP_PARAMS_new}
  {$EXTERNALSYM RSA_OAEP_PARAMS_free}
  {$EXTERNALSYM d2i_RSA_OAEP_PARAMS}
  {$EXTERNALSYM i2d_RSA_OAEP_PARAMS}
  {$EXTERNALSYM RSA_OAEP_PARAMS_it}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_OAEP_PARAMS_new: PRSA_OAEP_PARAMS; cdecl;
  procedure Load_RSA_OAEP_PARAMS_free(a: PRSA_OAEP_PARAMS); cdecl;
  function Load_d2i_RSA_OAEP_PARAMS(a: PPRSA_OAEP_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_OAEP_PARAMS; cdecl;
  function Load_i2d_RSA_OAEP_PARAMS(a: PRSA_OAEP_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_RSA_OAEP_PARAMS_it: PASN1_ITEM; cdecl;

var
  RSA_OAEP_PARAMS_new: function: PRSA_OAEP_PARAMS; cdecl = Load_RSA_OAEP_PARAMS_new;
  RSA_OAEP_PARAMS_free: procedure(a: PRSA_OAEP_PARAMS); cdecl = Load_RSA_OAEP_PARAMS_free;
  d2i_RSA_OAEP_PARAMS: function(a: PPRSA_OAEP_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_OAEP_PARAMS; cdecl = Load_d2i_RSA_OAEP_PARAMS;
  i2d_RSA_OAEP_PARAMS: function(a: PRSA_OAEP_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_RSA_OAEP_PARAMS;
  RSA_OAEP_PARAMS_it: function: PASN1_ITEM; cdecl = Load_RSA_OAEP_PARAMS_it;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_STDIO}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_print_fp(fp: PFILE; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_print_fp'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM RSA_print_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_print_fp(fp: PFILE; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  RSA_print_fp: function(fp: PFILE; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_print_fp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_print(bp: PBIO; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_print'; deprecated 'Since OpenSSL 3.0';
  
  {* The following 2 functions sign and verify a X509_SIG ASN1 object inside
  * PKCS#1 padded RSA encryption
  }
  function RSA_sign(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_sign'; deprecated 'Since OpenSSL 3.0';
  function RSA_verify(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_verify'; deprecated 'Since OpenSSL 3.0';
  
  {* The following 2 function sign and verify a ASN1_OCTET_STRING object inside
  * PKCS#1 padded RSA encryption
  }
  function RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_sign_ASN1_OCTET_STRING'; deprecated 'Since OpenSSL 3.0';
  function RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_verify_ASN1_OCTET_STRING'; deprecated 'Since OpenSSL 3.0';
  function RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_blinding_on'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_blinding_off(rsa: PRSA); cdecl; external CLibCrypto name 'RSA_blinding_off'; deprecated 'Since OpenSSL 3.0';
  function RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl; external CLibCrypto name 'RSA_setup_blinding'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_PKCS1_type_1(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_PKCS1_type_1'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_check_PKCS1_type_1(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_check_PKCS1_type_1'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_PKCS1_type_2(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_PKCS1_type_2'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_check_PKCS1_type_2(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_check_PKCS1_type_2'; deprecated 'Since OpenSSL 3.0';
  function PKCS1_MGF1(mask: Pbyte; len: TOpenSSL_C_INT; seed: Pbyte; seedlen: TOpenSSL_C_INT; dgst: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'PKCS1_MGF1'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_PKCS1_OAEP(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_PKCS1_OAEP'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_check_PKCS1_OAEP(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_check_PKCS1_OAEP'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_PKCS1_OAEP_mgf1(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_PKCS1_OAEP_mgf1'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_check_PKCS1_OAEP_mgf1(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_check_PKCS1_OAEP_mgf1'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_none(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_none'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_check_none(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_check_none'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_X931(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_X931'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_check_X931(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_check_X931'; deprecated 'Since OpenSSL 3.0';
  function RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_X931_hash_id'; deprecated 'Since OpenSSL 3.0';
  function RSA_verify_PKCS1_PSS(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_verify_PKCS1_PSS'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_PKCS1_PSS'; deprecated 'Since OpenSSL 3.0';
  function RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_verify_PKCS1_PSS_mgf1'; deprecated 'Since OpenSSL 3.0';
  function RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_padding_add_PKCS1_PSS_mgf1'; deprecated 'Since OpenSSL 3.0';
    {$else}
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
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_print(bp: PBIO; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_sign(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_verify(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
  function Load_RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_RSA_blinding_off(rsa: PRSA); cdecl;
  function Load_RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl;
  function Load_RSA_padding_add_PKCS1_type_1(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_check_PKCS1_type_1(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_add_PKCS1_type_2(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_check_PKCS1_type_2(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_PKCS1_MGF1(mask: Pbyte; len: TOpenSSL_C_INT; seed: Pbyte; seedlen: TOpenSSL_C_INT; dgst: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_add_PKCS1_OAEP(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_check_PKCS1_OAEP(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_add_PKCS1_OAEP_mgf1(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_check_PKCS1_OAEP_mgf1(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_add_none(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_check_none(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_add_X931(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_check_X931(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_verify_PKCS1_PSS(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  RSA_print: function(bp: PBIO; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_print;
  
  {* The following 2 functions sign and verify a X509_SIG ASN1 object inside
  * PKCS#1 padded RSA encryption
  }
  RSA_sign: function(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_sign;
  RSA_verify: function(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_verify;
  
  {* The following 2 function sign and verify a ASN1_OCTET_STRING object inside
  * PKCS#1 padded RSA encryption
  }
  RSA_sign_ASN1_OCTET_STRING: function(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_sign_ASN1_OCTET_STRING;
  RSA_verify_ASN1_OCTET_STRING: function(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl = Load_RSA_verify_ASN1_OCTET_STRING;
  RSA_blinding_on: function(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl = Load_RSA_blinding_on;
  RSA_blinding_off: procedure(rsa: PRSA); cdecl = Load_RSA_blinding_off;
  RSA_setup_blinding: function(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl = Load_RSA_setup_blinding;
  RSA_padding_add_PKCS1_type_1: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_type_1;
  RSA_padding_check_PKCS1_type_1: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_type_1;
  RSA_padding_add_PKCS1_type_2: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_type_2;
  RSA_padding_check_PKCS1_type_2: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_type_2;
  PKCS1_MGF1: function(mask: Pbyte; len: TOpenSSL_C_INT; seed: Pbyte; seedlen: TOpenSSL_C_INT; dgst: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_PKCS1_MGF1;
  RSA_padding_add_PKCS1_OAEP: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_OAEP;
  RSA_padding_check_PKCS1_OAEP: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_OAEP;
  RSA_padding_add_PKCS1_OAEP_mgf1: function(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_OAEP_mgf1;
  RSA_padding_check_PKCS1_OAEP_mgf1: function(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_PKCS1_OAEP_mgf1;
  RSA_padding_add_none: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_none;
  RSA_padding_check_none: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_none;
  RSA_padding_add_X931: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_X931;
  RSA_padding_check_X931: function(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_check_X931;
  RSA_X931_hash_id: function(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_X931_hash_id;
  RSA_verify_PKCS1_PSS: function(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_verify_PKCS1_PSS;
  RSA_padding_add_PKCS1_PSS: function(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_PSS;
  RSA_verify_PKCS1_PSS_mgf1: function(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_verify_PKCS1_PSS_mgf1;
  RSA_padding_add_PKCS1_PSS_mgf1: function(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_padding_add_PKCS1_PSS_mgf1;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {# define  RSA_get_ex_new_index(l,p,newf,dupf,freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, l, p, newf, dupf, freef)} {Macro Return Type unknown at line no 458}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_set_ex_data'; deprecated 'Since OpenSSL 3.0';
  function RSA_get_ex_data(r: PRSA; idx: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'RSA_get_ex_data'; deprecated 'Since OpenSSL 3.0';
  function RSAPublicKey_dup(a: PRSA): PRSA; cdecl; external CLibCrypto name 'RSAPublicKey_dup'; deprecated 'Since OpenSSL 3.0';
  function RSAPrivateKey_dup(a: PRSA): PRSA; cdecl; external CLibCrypto name 'RSAPrivateKey_dup'; deprecated 'Since OpenSSL 3.0';
  
  {* If this flag is set the RSA method is FIPS compliant and can be used in
  * FIPS mode. This is set in the validated module method. If an application
  * sets this flag in its own methods it is its responsibility to ensure the
  * result is compliant.
  }
    {$else}
  {$EXTERNALSYM RSA_set_ex_data}
  {$EXTERNALSYM RSA_get_ex_data}
  {$EXTERNALSYM RSAPublicKey_dup}
  {$EXTERNALSYM RSAPrivateKey_dup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_RSA_get_ex_data(r: PRSA; idx: TOpenSSL_C_INT): pointer; cdecl;
  function Load_RSAPublicKey_dup(a: PRSA): PRSA; cdecl;
  function Load_RSAPrivateKey_dup(a: PRSA): PRSA; cdecl;

var
  RSA_set_ex_data: function(r: PRSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl = Load_RSA_set_ex_data;
  RSA_get_ex_data: function(r: PRSA; idx: TOpenSSL_C_INT): pointer; cdecl = Load_RSA_get_ex_data;
  RSAPublicKey_dup: function(a: PRSA): PRSA; cdecl = Load_RSAPublicKey_dup;
  RSAPrivateKey_dup: function(a: PRSA): PRSA; cdecl = Load_RSAPrivateKey_dup;
  
  {* If this flag is set the RSA method is FIPS compliant and can be used in
  * FIPS mode. This is set in the validated module method. If an application
  * sets this flag in its own methods it is its responsibility to ensure the
  * result is compliant.
  }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  RSA_FLAG_FIPS_METHOD = $0400;
    
    {* If this flag is set the operations normally disabled in FIPS mode are
    * permitted it is then the applications responsibility to ensure that the
    * usage is compliant.
    }
  RSA_FLAG_NON_FIPS_ALLOW = $0400;
    
    {* Application has decided PRNG is good enough to generate a key: don't
    * check.
    }
  RSA_FLAG_CHECKED = $0800;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl; external CLibCrypto name 'RSA_meth_new'; deprecated 'Since OpenSSL 3.0';
  procedure RSA_meth_free(meth: PRSA_METHOD); cdecl; external CLibCrypto name 'RSA_meth_free'; deprecated 'Since OpenSSL 3.0';
  function RSA_meth_dup(meth: PRSA_METHOD): PRSA_METHOD; cdecl; external CLibCrypto name 'RSA_meth_dup'; deprecated 'Since OpenSSL 3.0';
  function RSA_meth_get0_name(meth: PRSA_METHOD): PAnsiChar; cdecl; external CLibCrypto name 'RSA_meth_get0_name'; deprecated 'Since OpenSSL 3.0';
  function RSA_meth_set1_name(meth: PRSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set1_name'; deprecated 'Since OpenSSL 3.0';
  function RSA_meth_get_flags(meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_get_flags'; deprecated 'Since OpenSSL 3.0';
  function RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_flags'; deprecated 'Since OpenSSL 3.0';
  function RSA_meth_get0_app_data(meth: PRSA_METHOD): pointer; cdecl; external CLibCrypto name 'RSA_meth_get0_app_data'; deprecated 'Since OpenSSL 3.0';
  function RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set0_app_data'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_new}
  {$EXTERNALSYM RSA_meth_free}
  {$EXTERNALSYM RSA_meth_dup}
  {$EXTERNALSYM RSA_meth_get0_name}
  {$EXTERNALSYM RSA_meth_set1_name}
  {$EXTERNALSYM RSA_meth_get_flags}
  {$EXTERNALSYM RSA_meth_set_flags}
  {$EXTERNALSYM RSA_meth_get0_app_data}
  {$EXTERNALSYM RSA_meth_set0_app_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl;
  procedure Load_RSA_meth_free(meth: PRSA_METHOD); cdecl;
  function Load_RSA_meth_dup(meth: PRSA_METHOD): PRSA_METHOD; cdecl;
  function Load_RSA_meth_get0_name(meth: PRSA_METHOD): PAnsiChar; cdecl;
  function Load_RSA_meth_set1_name(meth: PRSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_RSA_meth_get_flags(meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_RSA_meth_get0_app_data(meth: PRSA_METHOD): pointer; cdecl;
  function Load_RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_new: function(name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl = Load_RSA_meth_new;
  RSA_meth_free: procedure(meth: PRSA_METHOD); cdecl = Load_RSA_meth_free;
  RSA_meth_dup: function(meth: PRSA_METHOD): PRSA_METHOD; cdecl = Load_RSA_meth_dup;
  RSA_meth_get0_name: function(meth: PRSA_METHOD): PAnsiChar; cdecl = Load_RSA_meth_get0_name;
  RSA_meth_set1_name: function(meth: PRSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set1_name;
  RSA_meth_get_flags: function(meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = Load_RSA_meth_get_flags;
  RSA_meth_set_flags: function(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_flags;
  RSA_meth_get0_app_data: function(meth: PRSA_METHOD): pointer; cdecl = Load_RSA_meth_get0_app_data;
  RSA_meth_set0_app_data: function(meth: PRSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set0_app_data;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_pub_enc(meth: PRSA_METHOD): TFuncType001; cdecl; external CLibCrypto name 'RSA_meth_get_pub_enc'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_pub_enc}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_pub_enc(meth: PRSA_METHOD): TFuncType001; cdecl;

var
  RSA_meth_get_pub_enc: function(meth: PRSA_METHOD): TFuncType001; cdecl = Load_RSA_meth_get_pub_enc;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  {end of auto-generated forward references}

  TFuncType002 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_pub_enc(rsa: PRSA_METHOD; pub_enc: TFuncType002): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_pub_enc'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_pub_enc}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_pub_enc(rsa: PRSA_METHOD; pub_enc: TFuncType002): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_pub_enc: function(rsa: PRSA_METHOD; pub_enc: TFuncType002): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_pub_enc;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType003 = ^TFuncType003;
  PPFuncType003 = ^PFuncType003;
  {end of auto-generated forward references}

  TFuncType003 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_pub_dec(meth: PRSA_METHOD): TFuncType003; cdecl; external CLibCrypto name 'RSA_meth_get_pub_dec'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_pub_dec}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_pub_dec(meth: PRSA_METHOD): TFuncType003; cdecl;

var
  RSA_meth_get_pub_dec: function(meth: PRSA_METHOD): TFuncType003; cdecl = Load_RSA_meth_get_pub_dec;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType004 = ^TFuncType004;
  PPFuncType004 = ^PFuncType004;
  {end of auto-generated forward references}

  TFuncType004 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_pub_dec(rsa: PRSA_METHOD; pub_dec: TFuncType004): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_pub_dec'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_pub_dec}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_pub_dec(rsa: PRSA_METHOD; pub_dec: TFuncType004): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_pub_dec: function(rsa: PRSA_METHOD; pub_dec: TFuncType004): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_pub_dec;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType005 = ^TFuncType005;
  PPFuncType005 = ^PFuncType005;
  {end of auto-generated forward references}

  TFuncType005 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_priv_enc(meth: PRSA_METHOD): TFuncType005; cdecl; external CLibCrypto name 'RSA_meth_get_priv_enc'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_priv_enc}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_priv_enc(meth: PRSA_METHOD): TFuncType005; cdecl;

var
  RSA_meth_get_priv_enc: function(meth: PRSA_METHOD): TFuncType005; cdecl = Load_RSA_meth_get_priv_enc;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType006 = ^TFuncType006;
  PPFuncType006 = ^PFuncType006;
  {end of auto-generated forward references}

  TFuncType006 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_priv_enc(rsa: PRSA_METHOD; priv_enc: TFuncType006): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_priv_enc'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_priv_enc}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_priv_enc(rsa: PRSA_METHOD; priv_enc: TFuncType006): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_priv_enc: function(rsa: PRSA_METHOD; priv_enc: TFuncType006): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_priv_enc;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType007 = ^TFuncType007;
  PPFuncType007 = ^PFuncType007;
  {end of auto-generated forward references}

  TFuncType007 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_priv_dec(meth: PRSA_METHOD): TFuncType007; cdecl; external CLibCrypto name 'RSA_meth_get_priv_dec'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_priv_dec}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_priv_dec(meth: PRSA_METHOD): TFuncType007; cdecl;

var
  RSA_meth_get_priv_dec: function(meth: PRSA_METHOD): TFuncType007; cdecl = Load_RSA_meth_get_priv_dec;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType008 = ^TFuncType008;
  PPFuncType008 = ^PFuncType008;
  {end of auto-generated forward references}

  TFuncType008 = function(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: TFuncType008): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_priv_dec'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_priv_dec}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: TFuncType008): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_priv_dec: function(rsa: PRSA_METHOD; priv_dec: TFuncType008): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_priv_dec;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType009 = ^TFuncType009;
  PPFuncType009 = ^PFuncType009;
  {end of auto-generated forward references}

  TFuncType009 = function(r0: PBIGNUM; i: PBIGNUM; rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_mod_exp(meth: PRSA_METHOD): TFuncType009; cdecl; external CLibCrypto name 'RSA_meth_get_mod_exp'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_mod_exp(meth: PRSA_METHOD): TFuncType009; cdecl;

var
  RSA_meth_get_mod_exp: function(meth: PRSA_METHOD): TFuncType009; cdecl = Load_RSA_meth_get_mod_exp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType010 = ^TFuncType010;
  PPFuncType010 = ^PFuncType010;
  {end of auto-generated forward references}

  TFuncType010 = function(r0: PBIGNUM; i: PBIGNUM; rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_mod_exp'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_mod_exp: function(rsa: PRSA_METHOD; mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_mod_exp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType011 = ^TFuncType011;
  PPFuncType011 = ^PFuncType011;
  {end of auto-generated forward references}

  TFuncType011 = function(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_bn_mod_exp(meth: PRSA_METHOD): TFuncType011; cdecl; external CLibCrypto name 'RSA_meth_get_bn_mod_exp'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_bn_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_bn_mod_exp(meth: PRSA_METHOD): TFuncType011; cdecl;

var
  RSA_meth_get_bn_mod_exp: function(meth: PRSA_METHOD): TFuncType011; cdecl = Load_RSA_meth_get_bn_mod_exp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType012 = ^TFuncType012;
  PPFuncType012 = ^PFuncType012;
  {end of auto-generated forward references}

  TFuncType012 = function(r: PBIGNUM; a: PBIGNUM; p: PBIGNUM; m: PBIGNUM; ctx: PBN_CTX; m_ctx: PBN_MONT_CTX): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: TFuncType012): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_bn_mod_exp'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_bn_mod_exp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: TFuncType012): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_bn_mod_exp: function(rsa: PRSA_METHOD; bn_mod_exp: TFuncType012): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_bn_mod_exp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType013 = ^TFuncType013;
  PPFuncType013 = ^PFuncType013;
  {end of auto-generated forward references}

  TFuncType013 = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_init(meth: PRSA_METHOD): TFuncType013; cdecl; external CLibCrypto name 'RSA_meth_get_init'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_init(meth: PRSA_METHOD): TFuncType013; cdecl;

var
  RSA_meth_get_init: function(meth: PRSA_METHOD): TFuncType013; cdecl = Load_RSA_meth_get_init;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType014 = ^TFuncType014;
  PPFuncType014 = ^PFuncType014;
  {end of auto-generated forward references}

  TFuncType014 = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_init(rsa: PRSA_METHOD; init: TFuncType014): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_init'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_init(rsa: PRSA_METHOD; init: TFuncType014): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_init: function(rsa: PRSA_METHOD; init: TFuncType014): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_init;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType015 = ^TFuncType015;
  PPFuncType015 = ^PFuncType015;
  {end of auto-generated forward references}

  TFuncType015 = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_finish(meth: PRSA_METHOD): TFuncType015; cdecl; external CLibCrypto name 'RSA_meth_get_finish'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_finish}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_finish(meth: PRSA_METHOD): TFuncType015; cdecl;

var
  RSA_meth_get_finish: function(meth: PRSA_METHOD): TFuncType015; cdecl = Load_RSA_meth_get_finish;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType016 = ^TFuncType016;
  PPFuncType016 = ^PFuncType016;
  {end of auto-generated forward references}

  TFuncType016 = function(rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_finish(rsa: PRSA_METHOD; finish: TFuncType016): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_finish'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_finish}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_finish(rsa: PRSA_METHOD; finish: TFuncType016): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_finish: function(rsa: PRSA_METHOD; finish: TFuncType016): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_finish;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType017 = ^TFuncType017;
  PPFuncType017 = ^PFuncType017;
  {end of auto-generated forward references}

  TFuncType017 = function(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_sign(meth: PRSA_METHOD): TFuncType017; cdecl; external CLibCrypto name 'RSA_meth_get_sign'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_sign(meth: PRSA_METHOD): TFuncType017; cdecl;

var
  RSA_meth_get_sign: function(meth: PRSA_METHOD): TFuncType017; cdecl = Load_RSA_meth_get_sign;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType018 = ^TFuncType018;
  PPFuncType018 = ^PFuncType018;
  {end of auto-generated forward references}

  TFuncType018 = function(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_sign(rsa: PRSA_METHOD; sign: TFuncType018): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_sign'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_sign}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_sign(rsa: PRSA_METHOD; sign: TFuncType018): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_sign: function(rsa: PRSA_METHOD; sign: TFuncType018): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_sign;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType019 = ^TFuncType019;
  PPFuncType019 = ^PFuncType019;
  {end of auto-generated forward references}

  TFuncType019 = function(dtype: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_verify(meth: PRSA_METHOD): TFuncType019; cdecl; external CLibCrypto name 'RSA_meth_get_verify'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_verify(meth: PRSA_METHOD): TFuncType019; cdecl;

var
  RSA_meth_get_verify: function(meth: PRSA_METHOD): TFuncType019; cdecl = Load_RSA_meth_get_verify;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType020 = ^TFuncType020;
  PPFuncType020 = ^PFuncType020;
  {end of auto-generated forward references}

  TFuncType020 = function(dtype: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_verify(rsa: PRSA_METHOD; verify: TFuncType020): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_verify'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_verify}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_verify(rsa: PRSA_METHOD; verify: TFuncType020): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_verify: function(rsa: PRSA_METHOD; verify: TFuncType020): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_verify;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType021 = ^TFuncType021;
  PPFuncType021 = ^PFuncType021;
  {end of auto-generated forward references}

  TFuncType021 = function(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_keygen(meth: PRSA_METHOD): TFuncType021; cdecl; external CLibCrypto name 'RSA_meth_get_keygen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_keygen(meth: PRSA_METHOD): TFuncType021; cdecl;

var
  RSA_meth_get_keygen: function(meth: PRSA_METHOD): TFuncType021; cdecl = Load_RSA_meth_get_keygen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType022 = ^TFuncType022;
  PPFuncType022 = ^PFuncType022;
  {end of auto-generated forward references}

  TFuncType022 = function(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: TFuncType022): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_keygen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: TFuncType022): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_keygen: function(rsa: PRSA_METHOD; keygen: TFuncType022): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_keygen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType023 = ^TFuncType023;
  PPFuncType023 = ^PFuncType023;
  {end of auto-generated forward references}

  TFuncType023 = function(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_get_multi_prime_keygen(meth: PRSA_METHOD): TFuncType023; cdecl; external CLibCrypto name 'RSA_meth_get_multi_prime_keygen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_get_multi_prime_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_get_multi_prime_keygen(meth: PRSA_METHOD): TFuncType023; cdecl;

var
  RSA_meth_get_multi_prime_keygen: function(meth: PRSA_METHOD): TFuncType023; cdecl = Load_RSA_meth_get_multi_prime_keygen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType024 = ^TFuncType024;
  PPFuncType024 = ^PFuncType024;
  {end of auto-generated forward references}

  TFuncType024 = function(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: TFuncType024): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RSA_meth_set_multi_prime_keygen'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM RSA_meth_set_multi_prime_keygen}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: TFuncType024): TOpenSSL_C_INT; cdecl;

var
  RSA_meth_set_multi_prime_keygen: function(meth: PRSA_METHOD; keygen: TFuncType024): TOpenSSL_C_INT; cdecl = Load_RSA_meth_set_multi_prime_keygen;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  { !OPENSSL_NO_DEPRECATED_3_0 }
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


{# define  RSA_set_app_data(s,arg) RSA_set_ex_data(s, 0, arg)}

function RSA_set_app_data(s:PRSA; arg:pointer): TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(RSA_set_ex_data(s,0,arg));
end;

{# define  RSA_get_app_data(s) RSA_get_ex_data(s, 0)}

function RSA_get_app_data(s:PRSA): pointer;
begin
  Result := pointer(RSA_get_ex_data(s,0));
end;
{$ifndef OPENSSL_STATIC_LINK_MODEL}
function Load_EVP_PKEY_CTX_set_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_padding := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_padding');
  if not assigned(EVP_PKEY_CTX_set_rsa_padding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_padding');
  Result := EVP_PKEY_CTX_set_rsa_padding(ctx, pad_mode);
end;

function Load_EVP_PKEY_CTX_get_rsa_padding(ctx: PEVP_PKEY_CTX; pad_mode: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_rsa_padding := LoadLibCryptoFunction('EVP_PKEY_CTX_get_rsa_padding');
  if not assigned(EVP_PKEY_CTX_get_rsa_padding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_rsa_padding');
  Result := EVP_PKEY_CTX_get_rsa_padding(ctx, pad_mode);
end;

function Load_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_pss_saltlen := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_pss_saltlen');
  if not assigned(EVP_PKEY_CTX_set_rsa_pss_saltlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_pss_saltlen');
  Result := EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen);
end;

function Load_EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: PEVP_PKEY_CTX; saltlen: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_rsa_pss_saltlen := LoadLibCryptoFunction('EVP_PKEY_CTX_get_rsa_pss_saltlen');
  if not assigned(EVP_PKEY_CTX_get_rsa_pss_saltlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_rsa_pss_saltlen');
  Result := EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, saltlen);
end;

function Load_EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: PEVP_PKEY_CTX; bits: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_keygen_bits := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_keygen_bits');
  if not assigned(EVP_PKEY_CTX_set_rsa_keygen_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_keygen_bits');
  Result := EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
end;

function Load_EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set1_rsa_keygen_pubexp := LoadLibCryptoFunction('EVP_PKEY_CTX_set1_rsa_keygen_pubexp');
  if not assigned(EVP_PKEY_CTX_set1_rsa_keygen_pubexp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set1_rsa_keygen_pubexp');
  Result := EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, pubexp);
end;

function Load_EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: PEVP_PKEY_CTX; primes: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_keygen_primes := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_keygen_primes');
  if not assigned(EVP_PKEY_CTX_set_rsa_keygen_primes) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_keygen_primes');
  Result := EVP_PKEY_CTX_set_rsa_keygen_primes(ctx, primes);
end;

function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: PEVP_PKEY_CTX; saltlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen');
  if not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen');
  Result := EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx, saltlen);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx: PEVP_PKEY_CTX; pubexp: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_keygen_pubexp := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_keygen_pubexp');
  if not assigned(EVP_PKEY_CTX_set_rsa_keygen_pubexp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_keygen_pubexp');
  Result := EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_mgf1_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_mgf1_md');
  if not assigned(EVP_PKEY_CTX_set_rsa_mgf1_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_mgf1_md');
  Result := EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_mgf1_md_name := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_mgf1_md_name');
  if not assigned(EVP_PKEY_CTX_set_rsa_mgf1_md_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_mgf1_md_name');
  Result := EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, mdname, mdprops);
end;

function Load_EVP_PKEY_CTX_get_rsa_mgf1_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_rsa_mgf1_md := LoadLibCryptoFunction('EVP_PKEY_CTX_get_rsa_mgf1_md');
  if not assigned(EVP_PKEY_CTX_get_rsa_mgf1_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_rsa_mgf1_md');
  Result := EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_rsa_mgf1_md_name := LoadLibCryptoFunction('EVP_PKEY_CTX_get_rsa_mgf1_md_name');
  if not assigned(EVP_PKEY_CTX_get_rsa_mgf1_md_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_rsa_mgf1_md_name');
  Result := EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, namelen);
end;

function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md');
  if not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md');
  Result := EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name');
  if not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name');
  Result := EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx, mdname);
end;

function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_pss_keygen_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_pss_keygen_md');
  if not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_pss_keygen_md');
  Result := EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_pss_keygen_md_name');
  if not assigned(EVP_PKEY_CTX_set_rsa_pss_keygen_md_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_pss_keygen_md_name');
  Result := EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx, mdname, mdprops);
end;

function Load_EVP_PKEY_CTX_set_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_oaep_md := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_oaep_md');
  if not assigned(EVP_PKEY_CTX_set_rsa_oaep_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_oaep_md');
  Result := EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; mdname: PAnsiChar; mdprops: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set_rsa_oaep_md_name := LoadLibCryptoFunction('EVP_PKEY_CTX_set_rsa_oaep_md_name');
  if not assigned(EVP_PKEY_CTX_set_rsa_oaep_md_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set_rsa_oaep_md_name');
  Result := EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, mdname, mdprops);
end;

function Load_EVP_PKEY_CTX_get_rsa_oaep_md(ctx: PEVP_PKEY_CTX; md: PPEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_rsa_oaep_md := LoadLibCryptoFunction('EVP_PKEY_CTX_get_rsa_oaep_md');
  if not assigned(EVP_PKEY_CTX_get_rsa_oaep_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_rsa_oaep_md');
  Result := EVP_PKEY_CTX_get_rsa_oaep_md(ctx, md);
end;

function Load_EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: PEVP_PKEY_CTX; name: PAnsiChar; namelen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get_rsa_oaep_md_name := LoadLibCryptoFunction('EVP_PKEY_CTX_get_rsa_oaep_md_name');
  if not assigned(EVP_PKEY_CTX_get_rsa_oaep_md_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get_rsa_oaep_md_name');
  Result := EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, namelen);
end;

function Load_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; label_: pointer; llen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_set0_rsa_oaep_label := LoadLibCryptoFunction('EVP_PKEY_CTX_set0_rsa_oaep_label');
  if not assigned(EVP_PKEY_CTX_set0_rsa_oaep_label) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_set0_rsa_oaep_label');
  Result := EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label_, llen);
end;

function Load_EVP_PKEY_CTX_get0_rsa_oaep_label(ctx: PEVP_PKEY_CTX; label_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  EVP_PKEY_CTX_get0_rsa_oaep_label := LoadLibCryptoFunction('EVP_PKEY_CTX_get0_rsa_oaep_label');
  if not assigned(EVP_PKEY_CTX_get0_rsa_oaep_label) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('EVP_PKEY_CTX_get0_rsa_oaep_label');
  Result := EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, label_);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_RSA_new: PRSA; cdecl;
begin
  RSA_new := LoadLibCryptoFunction('RSA_new');
  if not assigned(RSA_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_new');
  Result := RSA_new;
end;

function Load_RSA_new_method(engine: PENGINE): PRSA; cdecl;
begin
  RSA_new_method := LoadLibCryptoFunction('RSA_new_method');
  if not assigned(RSA_new_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_new_method');
  Result := RSA_new_method(engine);
end;

function Load_RSA_bits(rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_bits := LoadLibCryptoFunction('RSA_bits');
  if not assigned(RSA_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_bits');
  Result := RSA_bits(rsa);
end;

function Load_RSA_size(rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_size := LoadLibCryptoFunction('RSA_size');
  if not assigned(RSA_size) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_size');
  Result := RSA_size(rsa);
end;

function Load_RSA_security_bits(rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_security_bits := LoadLibCryptoFunction('RSA_security_bits');
  if not assigned(RSA_security_bits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_security_bits');
  Result := RSA_security_bits(rsa);
end;

function Load_RSA_set0_key(r: PRSA; n: PBIGNUM; e: PBIGNUM; d: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_set0_key := LoadLibCryptoFunction('RSA_set0_key');
  if not assigned(RSA_set0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_key');
  Result := RSA_set0_key(r, n, e, d);
end;

function Load_RSA_set0_factors(r: PRSA; p: PBIGNUM; q: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_set0_factors := LoadLibCryptoFunction('RSA_set0_factors');
  if not assigned(RSA_set0_factors) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_factors');
  Result := RSA_set0_factors(r, p, q);
end;

function Load_RSA_set0_crt_params(r: PRSA; dmp1: PBIGNUM; dmq1: PBIGNUM; iqmp: PBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_set0_crt_params := LoadLibCryptoFunction('RSA_set0_crt_params');
  if not assigned(RSA_set0_crt_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_crt_params');
  Result := RSA_set0_crt_params(r, dmp1, dmq1, iqmp);
end;

function Load_RSA_set0_multi_prime_params(r: PRSA; primes: PPBIGNUM; exps: PPBIGNUM; coeffs: PPBIGNUM; pnum: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_set0_multi_prime_params := LoadLibCryptoFunction('RSA_set0_multi_prime_params');
  if not assigned(RSA_set0_multi_prime_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set0_multi_prime_params');
  Result := RSA_set0_multi_prime_params(r, primes, exps, coeffs, pnum);
end;

procedure Load_RSA_get0_key(r: PRSA; n: PPBIGNUM; e: PPBIGNUM; d: PPBIGNUM); cdecl;
begin
  RSA_get0_key := LoadLibCryptoFunction('RSA_get0_key');
  if not assigned(RSA_get0_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_key');
  RSA_get0_key(r, n, e, d);
end;

procedure Load_RSA_get0_factors(r: PRSA; p: PPBIGNUM; q: PPBIGNUM); cdecl;
begin
  RSA_get0_factors := LoadLibCryptoFunction('RSA_get0_factors');
  if not assigned(RSA_get0_factors) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_factors');
  RSA_get0_factors(r, p, q);
end;

function Load_RSA_get_multi_prime_extra_count(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_get_multi_prime_extra_count := LoadLibCryptoFunction('RSA_get_multi_prime_extra_count');
  if not assigned(RSA_get_multi_prime_extra_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_multi_prime_extra_count');
  Result := RSA_get_multi_prime_extra_count(r);
end;

function Load_RSA_get0_multi_prime_factors(r: PRSA; primes: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_get0_multi_prime_factors := LoadLibCryptoFunction('RSA_get0_multi_prime_factors');
  if not assigned(RSA_get0_multi_prime_factors) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_multi_prime_factors');
  Result := RSA_get0_multi_prime_factors(r, primes);
end;

procedure Load_RSA_get0_crt_params(r: PRSA; dmp1: PPBIGNUM; dmq1: PPBIGNUM; iqmp: PPBIGNUM); cdecl;
begin
  RSA_get0_crt_params := LoadLibCryptoFunction('RSA_get0_crt_params');
  if not assigned(RSA_get0_crt_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_crt_params');
  RSA_get0_crt_params(r, dmp1, dmq1, iqmp);
end;

function Load_RSA_get0_multi_prime_crt_params(r: PRSA; exps: PPBIGNUM; coeffs: PPBIGNUM): TOpenSSL_C_INT; cdecl;
begin
  RSA_get0_multi_prime_crt_params := LoadLibCryptoFunction('RSA_get0_multi_prime_crt_params');
  if not assigned(RSA_get0_multi_prime_crt_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_multi_prime_crt_params');
  Result := RSA_get0_multi_prime_crt_params(r, exps, coeffs);
end;

function Load_RSA_get0_n(d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_n := LoadLibCryptoFunction('RSA_get0_n');
  if not assigned(RSA_get0_n) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_n');
  Result := RSA_get0_n(d);
end;

function Load_RSA_get0_e(d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_e := LoadLibCryptoFunction('RSA_get0_e');
  if not assigned(RSA_get0_e) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_e');
  Result := RSA_get0_e(d);
end;

function Load_RSA_get0_d(d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_d := LoadLibCryptoFunction('RSA_get0_d');
  if not assigned(RSA_get0_d) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_d');
  Result := RSA_get0_d(d);
end;

function Load_RSA_get0_p(d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_p := LoadLibCryptoFunction('RSA_get0_p');
  if not assigned(RSA_get0_p) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_p');
  Result := RSA_get0_p(d);
end;

function Load_RSA_get0_q(d: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_q := LoadLibCryptoFunction('RSA_get0_q');
  if not assigned(RSA_get0_q) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_q');
  Result := RSA_get0_q(d);
end;

function Load_RSA_get0_dmp1(r: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_dmp1 := LoadLibCryptoFunction('RSA_get0_dmp1');
  if not assigned(RSA_get0_dmp1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_dmp1');
  Result := RSA_get0_dmp1(r);
end;

function Load_RSA_get0_dmq1(r: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_dmq1 := LoadLibCryptoFunction('RSA_get0_dmq1');
  if not assigned(RSA_get0_dmq1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_dmq1');
  Result := RSA_get0_dmq1(r);
end;

function Load_RSA_get0_iqmp(r: PRSA): PBIGNUM; cdecl;
begin
  RSA_get0_iqmp := LoadLibCryptoFunction('RSA_get0_iqmp');
  if not assigned(RSA_get0_iqmp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_iqmp');
  Result := RSA_get0_iqmp(r);
end;

function Load_RSA_get0_pss_params(r: PRSA): PRSA_PSS_PARAMS; cdecl;
begin
  RSA_get0_pss_params := LoadLibCryptoFunction('RSA_get0_pss_params');
  if not assigned(RSA_get0_pss_params) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_pss_params');
  Result := RSA_get0_pss_params(r);
end;

procedure Load_RSA_clear_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
begin
  RSA_clear_flags := LoadLibCryptoFunction('RSA_clear_flags');
  if not assigned(RSA_clear_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_clear_flags');
  RSA_clear_flags(r, flags);
end;

function Load_RSA_test_flags(r: PRSA; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_test_flags := LoadLibCryptoFunction('RSA_test_flags');
  if not assigned(RSA_test_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_test_flags');
  Result := RSA_test_flags(r, flags);
end;

procedure Load_RSA_set_flags(r: PRSA; flags: TOpenSSL_C_INT); cdecl;
begin
  RSA_set_flags := LoadLibCryptoFunction('RSA_set_flags');
  if not assigned(RSA_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_flags');
  RSA_set_flags(r, flags);
end;

function Load_RSA_get_version(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_get_version := LoadLibCryptoFunction('RSA_get_version');
  if not assigned(RSA_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_version');
  Result := RSA_get_version(r);
end;

function Load_RSA_get0_engine(r: PRSA): PENGINE; cdecl;
begin
  RSA_get0_engine := LoadLibCryptoFunction('RSA_get0_engine');
  if not assigned(RSA_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get0_engine');
  Result := RSA_get0_engine(r);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}
function Load_RSA_generate_key(bits: TOpenSSL_C_INT; e: TOpenSSL_C_UINT; callback: TFuncType000; cb_arg: pointer): PRSA; cdecl;
begin
  RSA_generate_key := LoadLibCryptoFunction('RSA_generate_key');
  if not assigned(RSA_generate_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_generate_key');
  Result := RSA_generate_key(bits, e, callback, cb_arg);
end;

{$endif} { OPENSSL_NO_DEPRECATED_0_9_8}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_RSA_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_generate_key_ex := LoadLibCryptoFunction('RSA_generate_key_ex');
  if not assigned(RSA_generate_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_generate_key_ex');
  Result := RSA_generate_key_ex(rsa, bits, e, cb);
end;

function Load_RSA_generate_multi_prime_key(rsa: PRSA; bits: TOpenSSL_C_INT; primes: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_generate_multi_prime_key := LoadLibCryptoFunction('RSA_generate_multi_prime_key');
  if not assigned(RSA_generate_multi_prime_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_generate_multi_prime_key');
  Result := RSA_generate_multi_prime_key(rsa, bits, primes, e, cb);
end;

function Load_RSA_X931_derive_ex(rsa: PRSA; p1: PBIGNUM; p2: PBIGNUM; q1: PBIGNUM; q2: PBIGNUM; Xp1: PBIGNUM; Xp2: PBIGNUM; Xp: PBIGNUM; Xq1: PBIGNUM; Xq2: PBIGNUM; Xq: PBIGNUM; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_X931_derive_ex := LoadLibCryptoFunction('RSA_X931_derive_ex');
  if not assigned(RSA_X931_derive_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_derive_ex');
  Result := RSA_X931_derive_ex(rsa, p1, p2, q1, q2, Xp1, Xp2, Xp, Xq1, Xq2, Xq, e, cb);
end;

function Load_RSA_X931_generate_key_ex(rsa: PRSA; bits: TOpenSSL_C_INT; e: PBIGNUM; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_X931_generate_key_ex := LoadLibCryptoFunction('RSA_X931_generate_key_ex');
  if not assigned(RSA_X931_generate_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_generate_key_ex');
  Result := RSA_X931_generate_key_ex(rsa, bits, e, cb);
end;

function Load_RSA_check_key(_param1: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_check_key := LoadLibCryptoFunction('RSA_check_key');
  if not assigned(RSA_check_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_check_key');
  Result := RSA_check_key(_param1);
end;

function Load_RSA_check_key_ex(_param1: PRSA; cb: PBN_GENCB): TOpenSSL_C_INT; cdecl;
begin
  RSA_check_key_ex := LoadLibCryptoFunction('RSA_check_key_ex');
  if not assigned(RSA_check_key_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_check_key_ex');
  Result := RSA_check_key_ex(_param1, cb);
end;

function Load_RSA_public_encrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_public_encrypt := LoadLibCryptoFunction('RSA_public_encrypt');
  if not assigned(RSA_public_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_public_encrypt');
  Result := RSA_public_encrypt(flen, from_, to_, rsa, padding);
end;

function Load_RSA_private_encrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_private_encrypt := LoadLibCryptoFunction('RSA_private_encrypt');
  if not assigned(RSA_private_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_private_encrypt');
  Result := RSA_private_encrypt(flen, from_, to_, rsa, padding);
end;

function Load_RSA_public_decrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_public_decrypt := LoadLibCryptoFunction('RSA_public_decrypt');
  if not assigned(RSA_public_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_public_decrypt');
  Result := RSA_public_decrypt(flen, from_, to_, rsa, padding);
end;

function Load_RSA_private_decrypt(flen: TOpenSSL_C_INT; from_: Pbyte; to_: Pbyte; rsa: PRSA; padding: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_private_decrypt := LoadLibCryptoFunction('RSA_private_decrypt');
  if not assigned(RSA_private_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_private_decrypt');
  Result := RSA_private_decrypt(flen, from_, to_, rsa, padding);
end;

procedure Load_RSA_free(r: PRSA); cdecl;
begin
  RSA_free := LoadLibCryptoFunction('RSA_free');
  if not assigned(RSA_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_free');
  RSA_free(r);
end;

function Load_RSA_up_ref(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_up_ref := LoadLibCryptoFunction('RSA_up_ref');
  if not assigned(RSA_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_up_ref');
  Result := RSA_up_ref(r);
end;

function Load_RSA_flags(r: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_flags := LoadLibCryptoFunction('RSA_flags');
  if not assigned(RSA_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_flags');
  Result := RSA_flags(r);
end;

procedure Load_RSA_set_default_method(meth: PRSA_METHOD); cdecl;
begin
  RSA_set_default_method := LoadLibCryptoFunction('RSA_set_default_method');
  if not assigned(RSA_set_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_default_method');
  RSA_set_default_method(meth);
end;

function Load_RSA_get_default_method: PRSA_METHOD; cdecl;
begin
  RSA_get_default_method := LoadLibCryptoFunction('RSA_get_default_method');
  if not assigned(RSA_get_default_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_default_method');
  Result := RSA_get_default_method;
end;

function Load_RSA_null_method: PRSA_METHOD; cdecl;
begin
  RSA_null_method := LoadLibCryptoFunction('RSA_null_method');
  if not assigned(RSA_null_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_null_method');
  Result := RSA_null_method;
end;

function Load_RSA_get_method(rsa: PRSA): PRSA_METHOD; cdecl;
begin
  RSA_get_method := LoadLibCryptoFunction('RSA_get_method');
  if not assigned(RSA_get_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_method');
  Result := RSA_get_method(rsa);
end;

function Load_RSA_set_method(rsa: PRSA; meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  RSA_set_method := LoadLibCryptoFunction('RSA_set_method');
  if not assigned(RSA_set_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_method');
  Result := RSA_set_method(rsa, meth);
end;

function Load_RSA_PKCS1_OpenSSL: PRSA_METHOD; cdecl;
begin
  RSA_PKCS1_OpenSSL := LoadLibCryptoFunction('RSA_PKCS1_OpenSSL');
  if not assigned(RSA_PKCS1_OpenSSL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_PKCS1_OpenSSL');
  Result := RSA_PKCS1_OpenSSL;
end;

function Load_d2i_RSAPublicKey(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl;
begin
  d2i_RSAPublicKey := LoadLibCryptoFunction('d2i_RSAPublicKey');
  if not assigned(d2i_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSAPublicKey');
  Result := d2i_RSAPublicKey(a, in_, len);
end;

function Load_i2d_RSAPublicKey(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSAPublicKey := LoadLibCryptoFunction('i2d_RSAPublicKey');
  if not assigned(i2d_RSAPublicKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSAPublicKey');
  Result := i2d_RSAPublicKey(a, out_);
end;

function Load_RSAPublicKey_it: PASN1_ITEM; cdecl;
begin
  RSAPublicKey_it := LoadLibCryptoFunction('RSAPublicKey_it');
  if not assigned(RSAPublicKey_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPublicKey_it');
  Result := RSAPublicKey_it;
end;

function Load_d2i_RSAPrivateKey(a: PPRSA; in_: PPbyte; len: TOpenSSL_C_INT): PRSA; cdecl;
begin
  d2i_RSAPrivateKey := LoadLibCryptoFunction('d2i_RSAPrivateKey');
  if not assigned(d2i_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSAPrivateKey');
  Result := d2i_RSAPrivateKey(a, in_, len);
end;

function Load_i2d_RSAPrivateKey(a: PRSA; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSAPrivateKey := LoadLibCryptoFunction('i2d_RSAPrivateKey');
  if not assigned(i2d_RSAPrivateKey) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSAPrivateKey');
  Result := i2d_RSAPrivateKey(a, out_);
end;

function Load_RSAPrivateKey_it: PASN1_ITEM; cdecl;
begin
  RSAPrivateKey_it := LoadLibCryptoFunction('RSAPrivateKey_it');
  if not assigned(RSAPrivateKey_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPrivateKey_it');
  Result := RSAPrivateKey_it;
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_RSA_pkey_ctx_ctrl(ctx: PEVP_PKEY_CTX; optype: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; p1: TOpenSSL_C_INT; p2: pointer): TOpenSSL_C_INT; cdecl;
begin
  RSA_pkey_ctx_ctrl := LoadLibCryptoFunction('RSA_pkey_ctx_ctrl');
  if not assigned(RSA_pkey_ctx_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_pkey_ctx_ctrl');
  Result := RSA_pkey_ctx_ctrl(ctx, optype, cmd, p1, p2);
end;

function Load_RSA_PSS_PARAMS_new: PRSA_PSS_PARAMS; cdecl;
begin
  RSA_PSS_PARAMS_new := LoadLibCryptoFunction('RSA_PSS_PARAMS_new');
  if not assigned(RSA_PSS_PARAMS_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_PSS_PARAMS_new');
  Result := RSA_PSS_PARAMS_new;
end;

procedure Load_RSA_PSS_PARAMS_free(a: PRSA_PSS_PARAMS); cdecl;
begin
  RSA_PSS_PARAMS_free := LoadLibCryptoFunction('RSA_PSS_PARAMS_free');
  if not assigned(RSA_PSS_PARAMS_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_PSS_PARAMS_free');
  RSA_PSS_PARAMS_free(a);
end;

function Load_d2i_RSA_PSS_PARAMS(a: PPRSA_PSS_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_PSS_PARAMS; cdecl;
begin
  d2i_RSA_PSS_PARAMS := LoadLibCryptoFunction('d2i_RSA_PSS_PARAMS');
  if not assigned(d2i_RSA_PSS_PARAMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSA_PSS_PARAMS');
  Result := d2i_RSA_PSS_PARAMS(a, in_, len);
end;

function Load_i2d_RSA_PSS_PARAMS(a: PRSA_PSS_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSA_PSS_PARAMS := LoadLibCryptoFunction('i2d_RSA_PSS_PARAMS');
  if not assigned(i2d_RSA_PSS_PARAMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSA_PSS_PARAMS');
  Result := i2d_RSA_PSS_PARAMS(a, out_);
end;

function Load_RSA_PSS_PARAMS_it: PASN1_ITEM; cdecl;
begin
  RSA_PSS_PARAMS_it := LoadLibCryptoFunction('RSA_PSS_PARAMS_it');
  if not assigned(RSA_PSS_PARAMS_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_PSS_PARAMS_it');
  Result := RSA_PSS_PARAMS_it;
end;

function Load_RSA_PSS_PARAMS_dup(a: PRSA_PSS_PARAMS): PRSA_PSS_PARAMS; cdecl;
begin
  RSA_PSS_PARAMS_dup := LoadLibCryptoFunction('RSA_PSS_PARAMS_dup');
  if not assigned(RSA_PSS_PARAMS_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_PSS_PARAMS_dup');
  Result := RSA_PSS_PARAMS_dup(a);
end;

function Load_RSA_OAEP_PARAMS_new: PRSA_OAEP_PARAMS; cdecl;
begin
  RSA_OAEP_PARAMS_new := LoadLibCryptoFunction('RSA_OAEP_PARAMS_new');
  if not assigned(RSA_OAEP_PARAMS_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_OAEP_PARAMS_new');
  Result := RSA_OAEP_PARAMS_new;
end;

procedure Load_RSA_OAEP_PARAMS_free(a: PRSA_OAEP_PARAMS); cdecl;
begin
  RSA_OAEP_PARAMS_free := LoadLibCryptoFunction('RSA_OAEP_PARAMS_free');
  if not assigned(RSA_OAEP_PARAMS_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_OAEP_PARAMS_free');
  RSA_OAEP_PARAMS_free(a);
end;

function Load_d2i_RSA_OAEP_PARAMS(a: PPRSA_OAEP_PARAMS; in_: PPbyte; len: TOpenSSL_C_INT): PRSA_OAEP_PARAMS; cdecl;
begin
  d2i_RSA_OAEP_PARAMS := LoadLibCryptoFunction('d2i_RSA_OAEP_PARAMS');
  if not assigned(d2i_RSA_OAEP_PARAMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_RSA_OAEP_PARAMS');
  Result := d2i_RSA_OAEP_PARAMS(a, in_, len);
end;

function Load_i2d_RSA_OAEP_PARAMS(a: PRSA_OAEP_PARAMS; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_RSA_OAEP_PARAMS := LoadLibCryptoFunction('i2d_RSA_OAEP_PARAMS');
  if not assigned(i2d_RSA_OAEP_PARAMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_RSA_OAEP_PARAMS');
  Result := i2d_RSA_OAEP_PARAMS(a, out_);
end;

function Load_RSA_OAEP_PARAMS_it: PASN1_ITEM; cdecl;
begin
  RSA_OAEP_PARAMS_it := LoadLibCryptoFunction('RSA_OAEP_PARAMS_it');
  if not assigned(RSA_OAEP_PARAMS_it) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_OAEP_PARAMS_it');
  Result := RSA_OAEP_PARAMS_it;
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_STDIO}
function Load_RSA_print_fp(fp: PFILE; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_print_fp := LoadLibCryptoFunction('RSA_print_fp');
  if not assigned(RSA_print_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_print_fp');
  Result := RSA_print_fp(fp, r, offset);
end;

    {$endif} { OPENSSL_NO_STDIO}
function Load_RSA_print(bp: PBIO; r: PRSA; offset: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_print := LoadLibCryptoFunction('RSA_print');
  if not assigned(RSA_print) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_print');
  Result := RSA_print(bp, r, offset);
end;

function Load_RSA_sign(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_sign := LoadLibCryptoFunction('RSA_sign');
  if not assigned(RSA_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_sign');
  Result := RSA_sign(type_, m, m_length, sigret, siglen, rsa);
end;

function Load_RSA_verify(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify := LoadLibCryptoFunction('RSA_verify');
  if not assigned(RSA_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify');
  Result := RSA_verify(type_, m, m_length, sigbuf, siglen, rsa);
end;

function Load_RSA_sign_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigret: Pbyte; siglen: POpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_sign_ASN1_OCTET_STRING := LoadLibCryptoFunction('RSA_sign_ASN1_OCTET_STRING');
  if not assigned(RSA_sign_ASN1_OCTET_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_sign_ASN1_OCTET_STRING');
  Result := RSA_sign_ASN1_OCTET_STRING(type_, m, m_length, sigret, siglen, rsa);
end;

function Load_RSA_verify_ASN1_OCTET_STRING(type_: TOpenSSL_C_INT; m: Pbyte; m_length: TOpenSSL_C_UINT; sigbuf: Pbyte; siglen: TOpenSSL_C_UINT; rsa: PRSA): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify_ASN1_OCTET_STRING := LoadLibCryptoFunction('RSA_verify_ASN1_OCTET_STRING');
  if not assigned(RSA_verify_ASN1_OCTET_STRING) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_ASN1_OCTET_STRING');
  Result := RSA_verify_ASN1_OCTET_STRING(type_, m, m_length, sigbuf, siglen, rsa);
end;

function Load_RSA_blinding_on(rsa: PRSA; ctx: PBN_CTX): TOpenSSL_C_INT; cdecl;
begin
  RSA_blinding_on := LoadLibCryptoFunction('RSA_blinding_on');
  if not assigned(RSA_blinding_on) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_blinding_on');
  Result := RSA_blinding_on(rsa, ctx);
end;

procedure Load_RSA_blinding_off(rsa: PRSA); cdecl;
begin
  RSA_blinding_off := LoadLibCryptoFunction('RSA_blinding_off');
  if not assigned(RSA_blinding_off) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_blinding_off');
  RSA_blinding_off(rsa);
end;

function Load_RSA_setup_blinding(rsa: PRSA; ctx: PBN_CTX): PBN_BLINDING; cdecl;
begin
  RSA_setup_blinding := LoadLibCryptoFunction('RSA_setup_blinding');
  if not assigned(RSA_setup_blinding) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_setup_blinding');
  Result := RSA_setup_blinding(rsa, ctx);
end;

function Load_RSA_padding_add_PKCS1_type_1(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_type_1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_type_1');
  if not assigned(RSA_padding_add_PKCS1_type_1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_type_1');
  Result := RSA_padding_add_PKCS1_type_1(to_, tlen, f, fl);
end;

function Load_RSA_padding_check_PKCS1_type_1(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_type_1 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_type_1');
  if not assigned(RSA_padding_check_PKCS1_type_1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_type_1');
  Result := RSA_padding_check_PKCS1_type_1(to_, tlen, f, fl, rsa_len);
end;

function Load_RSA_padding_add_PKCS1_type_2(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_type_2 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_type_2');
  if not assigned(RSA_padding_add_PKCS1_type_2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_type_2');
  Result := RSA_padding_add_PKCS1_type_2(to_, tlen, f, fl);
end;

function Load_RSA_padding_check_PKCS1_type_2(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_type_2 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_type_2');
  if not assigned(RSA_padding_check_PKCS1_type_2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_type_2');
  Result := RSA_padding_check_PKCS1_type_2(to_, tlen, f, fl, rsa_len);
end;

function Load_PKCS1_MGF1(mask: Pbyte; len: TOpenSSL_C_INT; seed: Pbyte; seedlen: TOpenSSL_C_INT; dgst: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  PKCS1_MGF1 := LoadLibCryptoFunction('PKCS1_MGF1');
  if not assigned(PKCS1_MGF1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS1_MGF1');
  Result := PKCS1_MGF1(mask, len, seed, seedlen, dgst);
end;

function Load_RSA_padding_add_PKCS1_OAEP(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_OAEP := LoadLibCryptoFunction('RSA_padding_add_PKCS1_OAEP');
  if not assigned(RSA_padding_add_PKCS1_OAEP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_OAEP');
  Result := RSA_padding_add_PKCS1_OAEP(to_, tlen, f, fl, p, pl);
end;

function Load_RSA_padding_check_PKCS1_OAEP(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT; p: Pbyte; pl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_OAEP := LoadLibCryptoFunction('RSA_padding_check_PKCS1_OAEP');
  if not assigned(RSA_padding_check_PKCS1_OAEP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_OAEP');
  Result := RSA_padding_check_PKCS1_OAEP(to_, tlen, f, fl, rsa_len, p, pl);
end;

function Load_RSA_padding_add_PKCS1_OAEP_mgf1(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_OAEP_mgf1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_OAEP_mgf1');
  if not assigned(RSA_padding_add_PKCS1_OAEP_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_OAEP_mgf1');
  Result := RSA_padding_add_PKCS1_OAEP_mgf1(to_, tlen, from_, flen, param, plen, md, mgf1md);
end;

function Load_RSA_padding_check_PKCS1_OAEP_mgf1(to_: Pbyte; tlen: TOpenSSL_C_INT; from_: Pbyte; flen: TOpenSSL_C_INT; num: TOpenSSL_C_INT; param: Pbyte; plen: TOpenSSL_C_INT; md: PEVP_MD; mgf1md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_PKCS1_OAEP_mgf1 := LoadLibCryptoFunction('RSA_padding_check_PKCS1_OAEP_mgf1');
  if not assigned(RSA_padding_check_PKCS1_OAEP_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_PKCS1_OAEP_mgf1');
  Result := RSA_padding_check_PKCS1_OAEP_mgf1(to_, tlen, from_, flen, num, param, plen, md, mgf1md);
end;

function Load_RSA_padding_add_none(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_none := LoadLibCryptoFunction('RSA_padding_add_none');
  if not assigned(RSA_padding_add_none) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_none');
  Result := RSA_padding_add_none(to_, tlen, f, fl);
end;

function Load_RSA_padding_check_none(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_none := LoadLibCryptoFunction('RSA_padding_check_none');
  if not assigned(RSA_padding_check_none) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_none');
  Result := RSA_padding_check_none(to_, tlen, f, fl, rsa_len);
end;

function Load_RSA_padding_add_X931(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_X931 := LoadLibCryptoFunction('RSA_padding_add_X931');
  if not assigned(RSA_padding_add_X931) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_X931');
  Result := RSA_padding_add_X931(to_, tlen, f, fl);
end;

function Load_RSA_padding_check_X931(to_: Pbyte; tlen: TOpenSSL_C_INT; f: Pbyte; fl: TOpenSSL_C_INT; rsa_len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_check_X931 := LoadLibCryptoFunction('RSA_padding_check_X931');
  if not assigned(RSA_padding_check_X931) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_check_X931');
  Result := RSA_padding_check_X931(to_, tlen, f, fl, rsa_len);
end;

function Load_RSA_X931_hash_id(nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_X931_hash_id := LoadLibCryptoFunction('RSA_X931_hash_id');
  if not assigned(RSA_X931_hash_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_X931_hash_id');
  Result := RSA_X931_hash_id(nid);
end;

function Load_RSA_verify_PKCS1_PSS(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify_PKCS1_PSS := LoadLibCryptoFunction('RSA_verify_PKCS1_PSS');
  if not assigned(RSA_verify_PKCS1_PSS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_PKCS1_PSS');
  Result := RSA_verify_PKCS1_PSS(rsa, mHash, Hash, EM, sLen);
end;

function Load_RSA_padding_add_PKCS1_PSS(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_PSS := LoadLibCryptoFunction('RSA_padding_add_PKCS1_PSS');
  if not assigned(RSA_padding_add_PKCS1_PSS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_PSS');
  Result := RSA_padding_add_PKCS1_PSS(rsa, EM, mHash, Hash, sLen);
end;

function Load_RSA_verify_PKCS1_PSS_mgf1(rsa: PRSA; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; EM: Pbyte; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_verify_PKCS1_PSS_mgf1 := LoadLibCryptoFunction('RSA_verify_PKCS1_PSS_mgf1');
  if not assigned(RSA_verify_PKCS1_PSS_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_verify_PKCS1_PSS_mgf1');
  Result := RSA_verify_PKCS1_PSS_mgf1(rsa, mHash, Hash, mgf1Hash, EM, sLen);
end;

function Load_RSA_padding_add_PKCS1_PSS_mgf1(rsa: PRSA; EM: Pbyte; mHash: Pbyte; Hash: PEVP_MD; mgf1Hash: PEVP_MD; sLen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_padding_add_PKCS1_PSS_mgf1 := LoadLibCryptoFunction('RSA_padding_add_PKCS1_PSS_mgf1');
  if not assigned(RSA_padding_add_PKCS1_PSS_mgf1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_padding_add_PKCS1_PSS_mgf1');
  Result := RSA_padding_add_PKCS1_PSS_mgf1(rsa, EM, mHash, Hash, mgf1Hash, sLen);
end;

function Load_RSA_set_ex_data(r: PRSA; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  RSA_set_ex_data := LoadLibCryptoFunction('RSA_set_ex_data');
  if not assigned(RSA_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_set_ex_data');
  Result := RSA_set_ex_data(r, idx, arg);
end;

function Load_RSA_get_ex_data(r: PRSA; idx: TOpenSSL_C_INT): pointer; cdecl;
begin
  RSA_get_ex_data := LoadLibCryptoFunction('RSA_get_ex_data');
  if not assigned(RSA_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_get_ex_data');
  Result := RSA_get_ex_data(r, idx);
end;

function Load_RSAPublicKey_dup(a: PRSA): PRSA; cdecl;
begin
  RSAPublicKey_dup := LoadLibCryptoFunction('RSAPublicKey_dup');
  if not assigned(RSAPublicKey_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPublicKey_dup');
  Result := RSAPublicKey_dup(a);
end;

function Load_RSAPrivateKey_dup(a: PRSA): PRSA; cdecl;
begin
  RSAPrivateKey_dup := LoadLibCryptoFunction('RSAPrivateKey_dup');
  if not assigned(RSAPrivateKey_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSAPrivateKey_dup');
  Result := RSAPrivateKey_dup(a);
end;

function Load_RSA_meth_new(name: PAnsiChar; flags: TOpenSSL_C_INT): PRSA_METHOD; cdecl;
begin
  RSA_meth_new := LoadLibCryptoFunction('RSA_meth_new');
  if not assigned(RSA_meth_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_new');
  Result := RSA_meth_new(name, flags);
end;

procedure Load_RSA_meth_free(meth: PRSA_METHOD); cdecl;
begin
  RSA_meth_free := LoadLibCryptoFunction('RSA_meth_free');
  if not assigned(RSA_meth_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_free');
  RSA_meth_free(meth);
end;

function Load_RSA_meth_dup(meth: PRSA_METHOD): PRSA_METHOD; cdecl;
begin
  RSA_meth_dup := LoadLibCryptoFunction('RSA_meth_dup');
  if not assigned(RSA_meth_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_dup');
  Result := RSA_meth_dup(meth);
end;

function Load_RSA_meth_get0_name(meth: PRSA_METHOD): PAnsiChar; cdecl;
begin
  RSA_meth_get0_name := LoadLibCryptoFunction('RSA_meth_get0_name');
  if not assigned(RSA_meth_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get0_name');
  Result := RSA_meth_get0_name(meth);
end;

function Load_RSA_meth_set1_name(meth: PRSA_METHOD; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set1_name := LoadLibCryptoFunction('RSA_meth_set1_name');
  if not assigned(RSA_meth_set1_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set1_name');
  Result := RSA_meth_set1_name(meth, name);
end;

function Load_RSA_meth_get_flags(meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_get_flags := LoadLibCryptoFunction('RSA_meth_get_flags');
  if not assigned(RSA_meth_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_flags');
  Result := RSA_meth_get_flags(meth);
end;

function Load_RSA_meth_set_flags(meth: PRSA_METHOD; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_flags := LoadLibCryptoFunction('RSA_meth_set_flags');
  if not assigned(RSA_meth_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_flags');
  Result := RSA_meth_set_flags(meth, flags);
end;

function Load_RSA_meth_get0_app_data(meth: PRSA_METHOD): pointer; cdecl;
begin
  RSA_meth_get0_app_data := LoadLibCryptoFunction('RSA_meth_get0_app_data');
  if not assigned(RSA_meth_get0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get0_app_data');
  Result := RSA_meth_get0_app_data(meth);
end;

function Load_RSA_meth_set0_app_data(meth: PRSA_METHOD; app_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set0_app_data := LoadLibCryptoFunction('RSA_meth_set0_app_data');
  if not assigned(RSA_meth_set0_app_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set0_app_data');
  Result := RSA_meth_set0_app_data(meth, app_data);
end;

function Load_RSA_meth_get_pub_enc(meth: PRSA_METHOD): TFuncType001; cdecl;
begin
  RSA_meth_get_pub_enc := LoadLibCryptoFunction('RSA_meth_get_pub_enc');
  if not assigned(RSA_meth_get_pub_enc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_pub_enc');
  Result := RSA_meth_get_pub_enc(meth);
end;

function Load_RSA_meth_set_pub_enc(rsa: PRSA_METHOD; pub_enc: TFuncType002): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_pub_enc := LoadLibCryptoFunction('RSA_meth_set_pub_enc');
  if not assigned(RSA_meth_set_pub_enc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_pub_enc');
  Result := RSA_meth_set_pub_enc(rsa, pub_enc);
end;

function Load_RSA_meth_get_pub_dec(meth: PRSA_METHOD): TFuncType003; cdecl;
begin
  RSA_meth_get_pub_dec := LoadLibCryptoFunction('RSA_meth_get_pub_dec');
  if not assigned(RSA_meth_get_pub_dec) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_pub_dec');
  Result := RSA_meth_get_pub_dec(meth);
end;

function Load_RSA_meth_set_pub_dec(rsa: PRSA_METHOD; pub_dec: TFuncType004): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_pub_dec := LoadLibCryptoFunction('RSA_meth_set_pub_dec');
  if not assigned(RSA_meth_set_pub_dec) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_pub_dec');
  Result := RSA_meth_set_pub_dec(rsa, pub_dec);
end;

function Load_RSA_meth_get_priv_enc(meth: PRSA_METHOD): TFuncType005; cdecl;
begin
  RSA_meth_get_priv_enc := LoadLibCryptoFunction('RSA_meth_get_priv_enc');
  if not assigned(RSA_meth_get_priv_enc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_priv_enc');
  Result := RSA_meth_get_priv_enc(meth);
end;

function Load_RSA_meth_set_priv_enc(rsa: PRSA_METHOD; priv_enc: TFuncType006): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_priv_enc := LoadLibCryptoFunction('RSA_meth_set_priv_enc');
  if not assigned(RSA_meth_set_priv_enc) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_priv_enc');
  Result := RSA_meth_set_priv_enc(rsa, priv_enc);
end;

function Load_RSA_meth_get_priv_dec(meth: PRSA_METHOD): TFuncType007; cdecl;
begin
  RSA_meth_get_priv_dec := LoadLibCryptoFunction('RSA_meth_get_priv_dec');
  if not assigned(RSA_meth_get_priv_dec) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_priv_dec');
  Result := RSA_meth_get_priv_dec(meth);
end;

function Load_RSA_meth_set_priv_dec(rsa: PRSA_METHOD; priv_dec: TFuncType008): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_priv_dec := LoadLibCryptoFunction('RSA_meth_set_priv_dec');
  if not assigned(RSA_meth_set_priv_dec) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_priv_dec');
  Result := RSA_meth_set_priv_dec(rsa, priv_dec);
end;

function Load_RSA_meth_get_mod_exp(meth: PRSA_METHOD): TFuncType009; cdecl;
begin
  RSA_meth_get_mod_exp := LoadLibCryptoFunction('RSA_meth_get_mod_exp');
  if not assigned(RSA_meth_get_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_mod_exp');
  Result := RSA_meth_get_mod_exp(meth);
end;

function Load_RSA_meth_set_mod_exp(rsa: PRSA_METHOD; mod_exp: TFuncType010): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_mod_exp := LoadLibCryptoFunction('RSA_meth_set_mod_exp');
  if not assigned(RSA_meth_set_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_mod_exp');
  Result := RSA_meth_set_mod_exp(rsa, mod_exp);
end;

function Load_RSA_meth_get_bn_mod_exp(meth: PRSA_METHOD): TFuncType011; cdecl;
begin
  RSA_meth_get_bn_mod_exp := LoadLibCryptoFunction('RSA_meth_get_bn_mod_exp');
  if not assigned(RSA_meth_get_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_bn_mod_exp');
  Result := RSA_meth_get_bn_mod_exp(meth);
end;

function Load_RSA_meth_set_bn_mod_exp(rsa: PRSA_METHOD; bn_mod_exp: TFuncType012): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_bn_mod_exp := LoadLibCryptoFunction('RSA_meth_set_bn_mod_exp');
  if not assigned(RSA_meth_set_bn_mod_exp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_bn_mod_exp');
  Result := RSA_meth_set_bn_mod_exp(rsa, bn_mod_exp);
end;

function Load_RSA_meth_get_init(meth: PRSA_METHOD): TFuncType013; cdecl;
begin
  RSA_meth_get_init := LoadLibCryptoFunction('RSA_meth_get_init');
  if not assigned(RSA_meth_get_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_init');
  Result := RSA_meth_get_init(meth);
end;

function Load_RSA_meth_set_init(rsa: PRSA_METHOD; init: TFuncType014): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_init := LoadLibCryptoFunction('RSA_meth_set_init');
  if not assigned(RSA_meth_set_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_init');
  Result := RSA_meth_set_init(rsa, init);
end;

function Load_RSA_meth_get_finish(meth: PRSA_METHOD): TFuncType015; cdecl;
begin
  RSA_meth_get_finish := LoadLibCryptoFunction('RSA_meth_get_finish');
  if not assigned(RSA_meth_get_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_finish');
  Result := RSA_meth_get_finish(meth);
end;

function Load_RSA_meth_set_finish(rsa: PRSA_METHOD; finish: TFuncType016): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_finish := LoadLibCryptoFunction('RSA_meth_set_finish');
  if not assigned(RSA_meth_set_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_finish');
  Result := RSA_meth_set_finish(rsa, finish);
end;

function Load_RSA_meth_get_sign(meth: PRSA_METHOD): TFuncType017; cdecl;
begin
  RSA_meth_get_sign := LoadLibCryptoFunction('RSA_meth_get_sign');
  if not assigned(RSA_meth_get_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_sign');
  Result := RSA_meth_get_sign(meth);
end;

function Load_RSA_meth_set_sign(rsa: PRSA_METHOD; sign: TFuncType018): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_sign := LoadLibCryptoFunction('RSA_meth_set_sign');
  if not assigned(RSA_meth_set_sign) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_sign');
  Result := RSA_meth_set_sign(rsa, sign);
end;

function Load_RSA_meth_get_verify(meth: PRSA_METHOD): TFuncType019; cdecl;
begin
  RSA_meth_get_verify := LoadLibCryptoFunction('RSA_meth_get_verify');
  if not assigned(RSA_meth_get_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_verify');
  Result := RSA_meth_get_verify(meth);
end;

function Load_RSA_meth_set_verify(rsa: PRSA_METHOD; verify: TFuncType020): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_verify := LoadLibCryptoFunction('RSA_meth_set_verify');
  if not assigned(RSA_meth_set_verify) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_verify');
  Result := RSA_meth_set_verify(rsa, verify);
end;

function Load_RSA_meth_get_keygen(meth: PRSA_METHOD): TFuncType021; cdecl;
begin
  RSA_meth_get_keygen := LoadLibCryptoFunction('RSA_meth_get_keygen');
  if not assigned(RSA_meth_get_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_keygen');
  Result := RSA_meth_get_keygen(meth);
end;

function Load_RSA_meth_set_keygen(rsa: PRSA_METHOD; keygen: TFuncType022): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_keygen := LoadLibCryptoFunction('RSA_meth_set_keygen');
  if not assigned(RSA_meth_set_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_keygen');
  Result := RSA_meth_set_keygen(rsa, keygen);
end;

function Load_RSA_meth_get_multi_prime_keygen(meth: PRSA_METHOD): TFuncType023; cdecl;
begin
  RSA_meth_get_multi_prime_keygen := LoadLibCryptoFunction('RSA_meth_get_multi_prime_keygen');
  if not assigned(RSA_meth_get_multi_prime_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_get_multi_prime_keygen');
  Result := RSA_meth_get_multi_prime_keygen(meth);
end;

function Load_RSA_meth_set_multi_prime_keygen(meth: PRSA_METHOD; keygen: TFuncType024): TOpenSSL_C_INT; cdecl;
begin
  RSA_meth_set_multi_prime_keygen := LoadLibCryptoFunction('RSA_meth_set_multi_prime_keygen');
  if not assigned(RSA_meth_set_multi_prime_keygen) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RSA_meth_set_multi_prime_keygen');
  Result := RSA_meth_set_multi_prime_keygen(meth, keygen);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  EVP_PKEY_CTX_set_rsa_padding := Load_EVP_PKEY_CTX_set_rsa_padding;
  EVP_PKEY_CTX_get_rsa_padding := Load_EVP_PKEY_CTX_get_rsa_padding;
  EVP_PKEY_CTX_set_rsa_pss_saltlen := Load_EVP_PKEY_CTX_set_rsa_pss_saltlen;
  EVP_PKEY_CTX_get_rsa_pss_saltlen := Load_EVP_PKEY_CTX_get_rsa_pss_saltlen;
  EVP_PKEY_CTX_set_rsa_keygen_bits := Load_EVP_PKEY_CTX_set_rsa_keygen_bits;
  EVP_PKEY_CTX_set1_rsa_keygen_pubexp := Load_EVP_PKEY_CTX_set1_rsa_keygen_pubexp;
  EVP_PKEY_CTX_set_rsa_keygen_primes := Load_EVP_PKEY_CTX_set_rsa_keygen_primes;
  EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen := Load_EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_CTX_set_rsa_keygen_pubexp := Load_EVP_PKEY_CTX_set_rsa_keygen_pubexp;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  EVP_PKEY_CTX_set_rsa_mgf1_md := Load_EVP_PKEY_CTX_set_rsa_mgf1_md;
  EVP_PKEY_CTX_set_rsa_mgf1_md_name := Load_EVP_PKEY_CTX_set_rsa_mgf1_md_name;
  EVP_PKEY_CTX_get_rsa_mgf1_md := Load_EVP_PKEY_CTX_get_rsa_mgf1_md;
  EVP_PKEY_CTX_get_rsa_mgf1_md_name := Load_EVP_PKEY_CTX_get_rsa_mgf1_md_name;
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md := Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md;
  EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name := Load_EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name;
  EVP_PKEY_CTX_set_rsa_pss_keygen_md := Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md;
  EVP_PKEY_CTX_set_rsa_pss_keygen_md_name := Load_EVP_PKEY_CTX_set_rsa_pss_keygen_md_name;
  EVP_PKEY_CTX_set_rsa_oaep_md := Load_EVP_PKEY_CTX_set_rsa_oaep_md;
  EVP_PKEY_CTX_set_rsa_oaep_md_name := Load_EVP_PKEY_CTX_set_rsa_oaep_md_name;
  EVP_PKEY_CTX_get_rsa_oaep_md := Load_EVP_PKEY_CTX_get_rsa_oaep_md;
  EVP_PKEY_CTX_get_rsa_oaep_md_name := Load_EVP_PKEY_CTX_get_rsa_oaep_md_name;
  EVP_PKEY_CTX_set0_rsa_oaep_label := Load_EVP_PKEY_CTX_set0_rsa_oaep_label;
  EVP_PKEY_CTX_get0_rsa_oaep_label := Load_EVP_PKEY_CTX_get0_rsa_oaep_label;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  RSA_new := Load_RSA_new;
  RSA_new_method := Load_RSA_new_method;
  RSA_bits := Load_RSA_bits;
  RSA_size := Load_RSA_size;
  RSA_security_bits := Load_RSA_security_bits;
  RSA_set0_key := Load_RSA_set0_key;
  RSA_set0_factors := Load_RSA_set0_factors;
  RSA_set0_crt_params := Load_RSA_set0_crt_params;
  RSA_set0_multi_prime_params := Load_RSA_set0_multi_prime_params;
  RSA_get0_key := Load_RSA_get0_key;
  RSA_get0_factors := Load_RSA_get0_factors;
  RSA_get_multi_prime_extra_count := Load_RSA_get_multi_prime_extra_count;
  RSA_get0_multi_prime_factors := Load_RSA_get0_multi_prime_factors;
  RSA_get0_crt_params := Load_RSA_get0_crt_params;
  RSA_get0_multi_prime_crt_params := Load_RSA_get0_multi_prime_crt_params;
  RSA_get0_n := Load_RSA_get0_n;
  RSA_get0_e := Load_RSA_get0_e;
  RSA_get0_d := Load_RSA_get0_d;
  RSA_get0_p := Load_RSA_get0_p;
  RSA_get0_q := Load_RSA_get0_q;
  RSA_get0_dmp1 := Load_RSA_get0_dmp1;
  RSA_get0_dmq1 := Load_RSA_get0_dmq1;
  RSA_get0_iqmp := Load_RSA_get0_iqmp;
  RSA_get0_pss_params := Load_RSA_get0_pss_params;
  RSA_clear_flags := Load_RSA_clear_flags;
  RSA_test_flags := Load_RSA_test_flags;
  RSA_set_flags := Load_RSA_set_flags;
  RSA_get_version := Load_RSA_get_version;
  RSA_get0_engine := Load_RSA_get0_engine;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_0_9_8}
  RSA_generate_key := Load_RSA_generate_key;
{$endif} { OPENSSL_NO_DEPRECATED_0_9_8}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  RSA_generate_key_ex := Load_RSA_generate_key_ex;
  RSA_generate_multi_prime_key := Load_RSA_generate_multi_prime_key;
  RSA_X931_derive_ex := Load_RSA_X931_derive_ex;
  RSA_X931_generate_key_ex := Load_RSA_X931_generate_key_ex;
  RSA_check_key := Load_RSA_check_key;
  RSA_check_key_ex := Load_RSA_check_key_ex;
  RSA_public_encrypt := Load_RSA_public_encrypt;
  RSA_private_encrypt := Load_RSA_private_encrypt;
  RSA_public_decrypt := Load_RSA_public_decrypt;
  RSA_private_decrypt := Load_RSA_private_decrypt;
  RSA_free := Load_RSA_free;
  RSA_up_ref := Load_RSA_up_ref;
  RSA_flags := Load_RSA_flags;
  RSA_set_default_method := Load_RSA_set_default_method;
  RSA_get_default_method := Load_RSA_get_default_method;
  RSA_null_method := Load_RSA_null_method;
  RSA_get_method := Load_RSA_get_method;
  RSA_set_method := Load_RSA_set_method;
  RSA_PKCS1_OpenSSL := Load_RSA_PKCS1_OpenSSL;
  d2i_RSAPublicKey := Load_d2i_RSAPublicKey;
  i2d_RSAPublicKey := Load_i2d_RSAPublicKey;
  RSAPublicKey_it := Load_RSAPublicKey_it;
  d2i_RSAPrivateKey := Load_d2i_RSAPrivateKey;
  i2d_RSAPrivateKey := Load_i2d_RSAPrivateKey;
  RSAPrivateKey_it := Load_RSAPrivateKey_it;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  RSA_pkey_ctx_ctrl := Load_RSA_pkey_ctx_ctrl;
  RSA_PSS_PARAMS_new := Load_RSA_PSS_PARAMS_new;
  RSA_PSS_PARAMS_free := Load_RSA_PSS_PARAMS_free;
  d2i_RSA_PSS_PARAMS := Load_d2i_RSA_PSS_PARAMS;
  i2d_RSA_PSS_PARAMS := Load_i2d_RSA_PSS_PARAMS;
  RSA_PSS_PARAMS_it := Load_RSA_PSS_PARAMS_it;
  RSA_PSS_PARAMS_dup := Load_RSA_PSS_PARAMS_dup;
  RSA_OAEP_PARAMS_new := Load_RSA_OAEP_PARAMS_new;
  RSA_OAEP_PARAMS_free := Load_RSA_OAEP_PARAMS_free;
  d2i_RSA_OAEP_PARAMS := Load_d2i_RSA_OAEP_PARAMS;
  i2d_RSA_OAEP_PARAMS := Load_i2d_RSA_OAEP_PARAMS;
  RSA_OAEP_PARAMS_it := Load_RSA_OAEP_PARAMS_it;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_STDIO}
  RSA_print_fp := Load_RSA_print_fp;
    {$endif} { OPENSSL_NO_STDIO}
  RSA_print := Load_RSA_print;
  RSA_sign := Load_RSA_sign;
  RSA_verify := Load_RSA_verify;
  RSA_sign_ASN1_OCTET_STRING := Load_RSA_sign_ASN1_OCTET_STRING;
  RSA_verify_ASN1_OCTET_STRING := Load_RSA_verify_ASN1_OCTET_STRING;
  RSA_blinding_on := Load_RSA_blinding_on;
  RSA_blinding_off := Load_RSA_blinding_off;
  RSA_setup_blinding := Load_RSA_setup_blinding;
  RSA_padding_add_PKCS1_type_1 := Load_RSA_padding_add_PKCS1_type_1;
  RSA_padding_check_PKCS1_type_1 := Load_RSA_padding_check_PKCS1_type_1;
  RSA_padding_add_PKCS1_type_2 := Load_RSA_padding_add_PKCS1_type_2;
  RSA_padding_check_PKCS1_type_2 := Load_RSA_padding_check_PKCS1_type_2;
  PKCS1_MGF1 := Load_PKCS1_MGF1;
  RSA_padding_add_PKCS1_OAEP := Load_RSA_padding_add_PKCS1_OAEP;
  RSA_padding_check_PKCS1_OAEP := Load_RSA_padding_check_PKCS1_OAEP;
  RSA_padding_add_PKCS1_OAEP_mgf1 := Load_RSA_padding_add_PKCS1_OAEP_mgf1;
  RSA_padding_check_PKCS1_OAEP_mgf1 := Load_RSA_padding_check_PKCS1_OAEP_mgf1;
  RSA_padding_add_none := Load_RSA_padding_add_none;
  RSA_padding_check_none := Load_RSA_padding_check_none;
  RSA_padding_add_X931 := Load_RSA_padding_add_X931;
  RSA_padding_check_X931 := Load_RSA_padding_check_X931;
  RSA_X931_hash_id := Load_RSA_X931_hash_id;
  RSA_verify_PKCS1_PSS := Load_RSA_verify_PKCS1_PSS;
  RSA_padding_add_PKCS1_PSS := Load_RSA_padding_add_PKCS1_PSS;
  RSA_verify_PKCS1_PSS_mgf1 := Load_RSA_verify_PKCS1_PSS_mgf1;
  RSA_padding_add_PKCS1_PSS_mgf1 := Load_RSA_padding_add_PKCS1_PSS_mgf1;
  RSA_set_ex_data := Load_RSA_set_ex_data;
  RSA_get_ex_data := Load_RSA_get_ex_data;
  RSAPublicKey_dup := Load_RSAPublicKey_dup;
  RSAPrivateKey_dup := Load_RSAPrivateKey_dup;
  RSA_meth_new := Load_RSA_meth_new;
  RSA_meth_free := Load_RSA_meth_free;
  RSA_meth_dup := Load_RSA_meth_dup;
  RSA_meth_get0_name := Load_RSA_meth_get0_name;
  RSA_meth_set1_name := Load_RSA_meth_set1_name;
  RSA_meth_get_flags := Load_RSA_meth_get_flags;
  RSA_meth_set_flags := Load_RSA_meth_set_flags;
  RSA_meth_get0_app_data := Load_RSA_meth_get0_app_data;
  RSA_meth_set0_app_data := Load_RSA_meth_set0_app_data;
  RSA_meth_get_pub_enc := Load_RSA_meth_get_pub_enc;
  RSA_meth_set_pub_enc := Load_RSA_meth_set_pub_enc;
  RSA_meth_get_pub_dec := Load_RSA_meth_get_pub_dec;
  RSA_meth_set_pub_dec := Load_RSA_meth_set_pub_dec;
  RSA_meth_get_priv_enc := Load_RSA_meth_get_priv_enc;
  RSA_meth_set_priv_enc := Load_RSA_meth_set_priv_enc;
  RSA_meth_get_priv_dec := Load_RSA_meth_get_priv_dec;
  RSA_meth_set_priv_dec := Load_RSA_meth_set_priv_dec;
  RSA_meth_get_mod_exp := Load_RSA_meth_get_mod_exp;
  RSA_meth_set_mod_exp := Load_RSA_meth_set_mod_exp;
  RSA_meth_get_bn_mod_exp := Load_RSA_meth_get_bn_mod_exp;
  RSA_meth_set_bn_mod_exp := Load_RSA_meth_set_bn_mod_exp;
  RSA_meth_get_init := Load_RSA_meth_get_init;
  RSA_meth_set_init := Load_RSA_meth_set_init;
  RSA_meth_get_finish := Load_RSA_meth_get_finish;
  RSA_meth_set_finish := Load_RSA_meth_set_finish;
  RSA_meth_get_sign := Load_RSA_meth_get_sign;
  RSA_meth_set_sign := Load_RSA_meth_set_sign;
  RSA_meth_get_verify := Load_RSA_meth_get_verify;
  RSA_meth_set_verify := Load_RSA_meth_set_verify;
  RSA_meth_get_keygen := Load_RSA_meth_get_keygen;
  RSA_meth_set_keygen := Load_RSA_meth_set_keygen;
  RSA_meth_get_multi_prime_keygen := Load_RSA_meth_get_multi_prime_keygen;
  RSA_meth_set_multi_prime_keygen := Load_RSA_meth_set_multi_prime_keygen;
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



