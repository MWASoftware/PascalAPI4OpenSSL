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

unit openssl_err;

{
  Generated from OpenSSL 3.0.20 Header File err.h - Tue 19 May 14:25:05 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_err.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2,openssl_types,openssl_bio,openssl_lhash,
     openssl_cryptoerr_legacy;


{* Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{ clang-format off }
{ clang-format on }
{$ifndef  OPENSSL_ERR_H}
  {$define OPENSSL_ERR_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_ERR_H}
  {$endif}
  {$ifndef  OPENSSL_NO_STDIO}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_FILENAMES}
{# define  ERR_PUT_error(l,f,r,fn,ln) ERR_put_error(l, f, r, fn, ln)} {Macro Return Type unknown at line no 43}
    {$else}
{# define  ERR_PUT_error(l,f,r,fn,ln) ERR_put_error(l, f, r, NULL, 0)} {Macro Return Type unknown at line no 45}
    {$endif}
  {$endif}

const
  ERR_TXT_MALLOCED = $01;
  ERR_TXT_STRING = $02;
  {$if  not defined(OPENSSL_NO_DEPRECATED_3_0)  or defined(OSSL_FORCE_ERR_STATE)}

const
  ERR_FLAG_MARK = $01;
  ERR_FLAG_CLEAR = $02;
  ERR_NUM_ERRORS = 16;

type
  {Auto-generated forward references}
  Perr_state_st = ^Terr_state_st;
  PPerr_state_st = ^Perr_state_st;
  {end of auto-generated forward references}

  Terr_state_st = record 
    err_flags: array[0..15] of TOpenSSL_C_INT;
    err_marks: array[0..15] of TOpenSSL_C_INT;
    err_buffer: array[0..15] of TOpenSSL_C_UINT;
    err_data: array[0..15] of ansichar;
    err_data_size: array[0..15] of TOpenSSL_C_SIZET;
    err_data_flags: array[0..15] of TOpenSSL_C_INT;
    err_file: array[0..15] of ansichar;
    err_line: array[0..15] of TOpenSSL_C_INT;
    err_func: array[0..15] of ansichar;
    top: TOpenSSL_C_INT;
    bottom: TOpenSSL_C_INT;
  end;
  {$endif}

const
  { library }
  ERR_LIB_NONE = 1;
  ERR_LIB_SYS = 2;
  ERR_LIB_BN = 3;
  ERR_LIB_RSA = 4;
  ERR_LIB_DH = 5;
  ERR_LIB_EVP = 6;
  ERR_LIB_BUF = 7;
  ERR_LIB_OBJ = 8;
  ERR_LIB_PEM = 9;
  ERR_LIB_DSA = 10;
  ERR_LIB_X509 = 11;
  { #define ERR_LIB_METH         12 }
  ERR_LIB_ASN1 = 13;
  ERR_LIB_CONF = 14;
  ERR_LIB_CRYPTO = 15;
  ERR_LIB_EC = 16;
  ERR_LIB_SSL = 20;
  { #define ERR_LIB_SSL23        21 }
  { #define ERR_LIB_SSL2         22 }
  { #define ERR_LIB_SSL3         23 }
  { #define ERR_LIB_RSAREF       30 }
  { #define ERR_LIB_PROXY        31 }
  ERR_LIB_BIO = 32;
  ERR_LIB_PKCS7 = 33;
  ERR_LIB_X509V3 = 34;
  ERR_LIB_PKCS12 = 35;
  ERR_LIB_RAND = 36;
  ERR_LIB_DSO = 37;
  ERR_LIB_ENGINE = 38;
  ERR_LIB_OCSP = 39;
  ERR_LIB_UI = 40;
  ERR_LIB_COMP = 41;
  ERR_LIB_ECDSA = 42;
  ERR_LIB_ECDH = 43;
  ERR_LIB_OSSL_STORE = 44;
  ERR_LIB_FIPS = 45;
  ERR_LIB_CMS = 46;
  ERR_LIB_TS = 47;
  ERR_LIB_HMAC = 48;
  { # define ERR_LIB_JPAKE       49 }
  ERR_LIB_CT = 50;
  ERR_LIB_ASYNC = 51;
  ERR_LIB_KDF = 52;
  ERR_LIB_SM2 = 53;
  ERR_LIB_ESS = 54;
  ERR_LIB_PROP = 55;
  ERR_LIB_CRMF = 56;
  ERR_LIB_PROV = 57;
  ERR_LIB_CMP = 58;
  ERR_LIB_OSSL_ENCODER = 59;
  ERR_LIB_OSSL_DECODER = 60;
  ERR_LIB_HTTP = 61;
  ERR_LIB_USER = 128;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  ASN1err(f,r) ERR_raise_data(ERR_LIB_ASN1, (r), NULL)} {Macro Return Type unknown at line no 133}
{# define  ASYNCerr(f,r) ERR_raise_data(ERR_LIB_ASYNC, (r), NULL)} {Macro Return Type unknown at line no 134}
{# define  BIOerr(f,r) ERR_raise_data(ERR_LIB_BIO, (r), NULL)} {Macro Return Type unknown at line no 135}
{# define  BNerr(f,r) ERR_raise_data(ERR_LIB_BN, (r), NULL)} {Macro Return Type unknown at line no 136}
{# define  BUFerr(f,r) ERR_raise_data(ERR_LIB_BUF, (r), NULL)} {Macro Return Type unknown at line no 137}
{# define  CMPerr(f,r) ERR_raise_data(ERR_LIB_CMP, (r), NULL)} {Macro Return Type unknown at line no 138}
{# define  CMSerr(f,r) ERR_raise_data(ERR_LIB_CMS, (r), NULL)} {Macro Return Type unknown at line no 139}
{# define  COMPerr(f,r) ERR_raise_data(ERR_LIB_COMP, (r), NULL)} {Macro Return Type unknown at line no 140}
{# define  CONFerr(f,r) ERR_raise_data(ERR_LIB_CONF, (r), NULL)} {Macro Return Type unknown at line no 141}
{# define  CRMFerr(f,r) ERR_raise_data(ERR_LIB_CRMF, (r), NULL)} {Macro Return Type unknown at line no 142}
{# define  CRYPTOerr(f,r) ERR_raise_data(ERR_LIB_CRYPTO, (r), NULL)} {Macro Return Type unknown at line no 143}
{# define  CTerr(f,r) ERR_raise_data(ERR_LIB_CT, (r), NULL)} {Macro Return Type unknown at line no 144}
{# define  DHerr(f,r) ERR_raise_data(ERR_LIB_DH, (r), NULL)} {Macro Return Type unknown at line no 145}
{# define  DSAerr(f,r) ERR_raise_data(ERR_LIB_DSA, (r), NULL)} {Macro Return Type unknown at line no 146}
{# define  DSOerr(f,r) ERR_raise_data(ERR_LIB_DSO, (r), NULL)} {Macro Return Type unknown at line no 147}
{# define  ECDHerr(f,r) ERR_raise_data(ERR_LIB_ECDH, (r), NULL)} {Macro Return Type unknown at line no 148}
{# define  ECDSAerr(f,r) ERR_raise_data(ERR_LIB_ECDSA, (r), NULL)} {Macro Return Type unknown at line no 149}
{# define  ECerr(f,r) ERR_raise_data(ERR_LIB_EC, (r), NULL)} {Macro Return Type unknown at line no 150}
{# define  ENGINEerr(f,r) ERR_raise_data(ERR_LIB_ENGINE, (r), NULL)} {Macro Return Type unknown at line no 151}
{# define  ESSerr(f,r) ERR_raise_data(ERR_LIB_ESS, (r), NULL)} {Macro Return Type unknown at line no 152}
{# define  EVPerr(f,r) ERR_raise_data(ERR_LIB_EVP, (r), NULL)} {Macro Return Type unknown at line no 153}
{# define  FIPSerr(f,r) ERR_raise_data(ERR_LIB_FIPS, (r), NULL)} {Macro Return Type unknown at line no 154}
{# define  HMACerr(f,r) ERR_raise_data(ERR_LIB_HMAC, (r), NULL)} {Macro Return Type unknown at line no 155}
{# define  HTTPerr(f,r) ERR_raise_data(ERR_LIB_HTTP, (r), NULL)} {Macro Return Type unknown at line no 156}
{# define  KDFerr(f,r) ERR_raise_data(ERR_LIB_KDF, (r), NULL)} {Macro Return Type unknown at line no 157}
{# define  OBJerr(f,r) ERR_raise_data(ERR_LIB_OBJ, (r), NULL)} {Macro Return Type unknown at line no 158}
{# define  OCSPerr(f,r) ERR_raise_data(ERR_LIB_OCSP, (r), NULL)} {Macro Return Type unknown at line no 159}
{# define  OSSL_STOREerr(f,r) ERR_raise_data(ERR_LIB_OSSL_STORE, (r), NULL)} {Macro Return Type unknown at line no 160}
{# define  PEMerr(f,r) ERR_raise_data(ERR_LIB_PEM, (r), NULL)} {Macro Return Type unknown at line no 161}
{# define  PKCS12err(f,r) ERR_raise_data(ERR_LIB_PKCS12, (r), NULL)} {Macro Return Type unknown at line no 162}
{# define  PKCS7err(f,r) ERR_raise_data(ERR_LIB_PKCS7, (r), NULL)} {Macro Return Type unknown at line no 163}
{# define  PROPerr(f,r) ERR_raise_data(ERR_LIB_PROP, (r), NULL)} {Macro Return Type unknown at line no 164}
{# define  PROVerr(f,r) ERR_raise_data(ERR_LIB_PROV, (r), NULL)} {Macro Return Type unknown at line no 165}
{# define  RANDerr(f,r) ERR_raise_data(ERR_LIB_RAND, (r), NULL)} {Macro Return Type unknown at line no 166}
{# define  RSAerr(f,r) ERR_raise_data(ERR_LIB_RSA, (r), NULL)} {Macro Return Type unknown at line no 167}
{# define  KDFerr(f,r) ERR_raise_data(ERR_LIB_KDF, (r), NULL)} {Macro Return Type unknown at line no 168}
{# define  SM2err(f,r) ERR_raise_data(ERR_LIB_SM2, (r), NULL)} {Macro Return Type unknown at line no 169}
{# define  SSLerr(f,r) ERR_raise_data(ERR_LIB_SSL, (r), NULL)} {Macro Return Type unknown at line no 170}
{# define  SYSerr(f,r) ERR_raise_data(ERR_LIB_SYS, (r), NULL)} {Macro Return Type unknown at line no 171}
{# define  TSerr(f,r) ERR_raise_data(ERR_LIB_TS, (r), NULL)} {Macro Return Type unknown at line no 172}
{# define  UIerr(f,r) ERR_raise_data(ERR_LIB_UI, (r), NULL)} {Macro Return Type unknown at line no 173}
{# define  X509V3err(f,r) ERR_raise_data(ERR_LIB_X509V3, (r), NULL)} {Macro Return Type unknown at line no 174}
{# define  X509err(f,r) ERR_raise_data(ERR_LIB_X509, (r), NULL)} {Macro Return Type unknown at line no 175}
  {$endif}
{# define  ERR_SYSTEM_FLAG ((unsigned int)INT_MAX + 1)} {Macro Return Type unknown}


  {-
  * The error code packs differently depending on if it records a system
  * error or an OpenSSL error.
  *
  * A system error packs like this (we follow POSIX and only allow positive
  * numbers that fit in an |int|):
  *
  * +-+-------------------------------------------------------------+
  * |1|                     system error number                     |
  * +-+-------------------------------------------------------------+
  *
  * An OpenSSL error packs like this:
  *
  * <---------------------------- 32 bits -------------------------->
  *    <--- 8 bits ---><------------------ 23 bits ----------------->
  * +-+---------------+---------------------------------------------+
  * |0|    library    |                    reason                   |
  * +-+---------------+---------------------------------------------+
  *
  * A few of the reason bits are reserved as flags with special meaning:
  *
  *                    <5 bits-<>--------- 19 bits ----------------->
  *                   +-------+-+-----------------------------------+
  *                   | rflags| |          reason                   |
  *                   +-------+-+-----------------------------------+
  *                            ^
  *                            |
  *                           ERR_RFLAG_FATAL = ERR_R_FATAL
  *
  * The reason flags are part of the overall reason code for practical
  * reasons, as they provide an easy way to place different types of
  * reason codes in different numeric ranges.
  *
  * The currently known reason flags are:
  *
  * ERR_RFLAG_FATAL      Flags that the reason code is considered fatal.
  *                      For backward compatibility reasons, this flag
  *                      is also the code for ERR_R_FATAL (that reason
  *                      code served the dual purpose of flag and reason
  *                      code in one in pre-3.0 OpenSSL).
  * ERR_RFLAG_COMMON     Flags that the reason code is common to all
  *                      libraries.  All ERR_R_ macros must use this flag,
  *                      and no other _R_ macro is allowed to use it.
  }
  { Macros to help decode recorded system errors }
  function ERR_SYSTEM_MASK: TOpenSSL_C_UINT; inline;

const
  
  {* Macros to help decode recorded OpenSSL errors
  * As expressed above, RFLAGS and REASON overlap by one bit to allow
  * ERR_R_FATAL to use ERR_RFLAG_FATAL as its reason code.
  }
  ERR_LIB_OFFSET = 23;
  ERR_LIB_MASK = $FF;
  ERR_RFLAGS_OFFSET = 18;
  ERR_RFLAGS_MASK = $1F;
  ERR_REASON_MASK = $7FFFFF;
  
  {* Reason flags are defined pre-shifted to easily combine with the reason
  * number.
  }
  ERR_RFLAG_FATAL = $1 shl ERR_RFLAGS_OFFSET;
  ERR_RFLAG_COMMON = $2 shl ERR_RFLAGS_OFFSET;
  {# define  ERR_SYSTEM_ERROR(errcode) (((errcode) & ERR_SYSTEM_FLAG) != 0)} {Macro Return Type unknown at line no 245}


  function ERR_GET_LIB(errcode: TOpenSSL_C_UINT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function ERR_GET_RFLAGS(errcode: TOpenSSL_C_UINT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function ERR_GET_REASON(errcode: TOpenSSL_C_UINT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
  function ERR_FATAL_ERROR(errcode: TOpenSSL_C_UINT): boolean{Has C Attribute: unused}; inline;
  function ERR_COMMON_ERROR(errcode: TOpenSSL_C_UINT): boolean{Has C Attribute: unused}; inline;
  {# define  ERR_PACK(lib,func,reason) ((((unsigned long)(lib) & ERR_LIB_MASK) << ERR_LIB_OFFSET) | (((unsigned long)(reason) & ERR_REASON_MASK)))} {Macro Return Type unknown at line no 288}
  
  {* ERR_PACK is a helper macro to properly pack OpenSSL error codes and may
  * only be used for that purpose.  System errors are packed internally.
  * ERR_PACK takes reason flags and reason code combined in |reason|.
  * ERR_PACK ignores |func|, that parameter is just legacy from pre-3.0 OpenSSL.
  }
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  SYS_F_FOPEN = 0;
  SYS_F_CONNECT = 0;
  SYS_F_GETSERVBYNAME = 0;
  SYS_F_SOCKET = 0;
  SYS_F_IOCTLSOCKET = 0;
  SYS_F_BIND = 0;
  SYS_F_LISTEN = 0;
  SYS_F_ACCEPT = 0;
  SYS_F_WSASTARTUP = 0;
  SYS_F_OPENDIR = 0;
  SYS_F_FREAD = 0;
  SYS_F_GETADDRINFO = 0;
  SYS_F_GETNAMEINFO = 0;
  SYS_F_SETSOCKOPT = 0;
  SYS_F_GETSOCKOPT = 0;
  SYS_F_GETSOCKNAME = 0;
  SYS_F_GETHOSTBYNAME = 0;
  SYS_F_FFLUSH = 0;
  SYS_F_OPEN = 0;
  SYS_F_CLOSE = 0;
  SYS_F_IOCTL = 0;
  SYS_F_STAT = 0;
  SYS_F_FCNTL = 0;
  SYS_F_FSTAT = 0;
  SYS_F_SENDFILE = 0;
  {$endif}

const
  
  {* All ERR_R_ codes must be combined with ERR_RFLAG_COMMON.
  }
  { "we came from here" global reason codes, range 1..255 }
  ERR_R_SYS_LIB = ERR_LIB_SYS or ERR_RFLAG_COMMON;
  ERR_R_BN_LIB = ERR_LIB_BN or ERR_RFLAG_COMMON;
  ERR_R_RSA_LIB = ERR_LIB_RSA or ERR_RFLAG_COMMON;
  ERR_R_DH_LIB = ERR_LIB_DH or ERR_RFLAG_COMMON;
  ERR_R_EVP_LIB = ERR_LIB_EVP or ERR_RFLAG_COMMON;
  ERR_R_BUF_LIB = ERR_LIB_BUF or ERR_RFLAG_COMMON;
  ERR_R_OBJ_LIB = ERR_LIB_OBJ or ERR_RFLAG_COMMON;
  ERR_R_PEM_LIB = ERR_LIB_PEM or ERR_RFLAG_COMMON;
  ERR_R_DSA_LIB = ERR_LIB_DSA or ERR_RFLAG_COMMON;
  ERR_R_X509_LIB = ERR_LIB_X509 or ERR_RFLAG_COMMON;
  ERR_R_ASN1_LIB = ERR_LIB_ASN1 or ERR_RFLAG_COMMON;
  ERR_R_CONF_LIB = ERR_LIB_CONF or ERR_RFLAG_COMMON;
  ERR_R_CRYPTO_LIB = ERR_LIB_CRYPTO or ERR_RFLAG_COMMON;
  ERR_R_EC_LIB = ERR_LIB_EC or ERR_RFLAG_COMMON;
  ERR_R_SSL_LIB = ERR_LIB_SSL or ERR_RFLAG_COMMON;
  ERR_R_BIO_LIB = ERR_LIB_BIO or ERR_RFLAG_COMMON;
  ERR_R_PKCS7_LIB = ERR_LIB_PKCS7 or ERR_RFLAG_COMMON;
  ERR_R_X509V3_LIB = ERR_LIB_X509V3 or ERR_RFLAG_COMMON;
  ERR_R_PKCS12_LIB = ERR_LIB_PKCS12 or ERR_RFLAG_COMMON;
  ERR_R_RAND_LIB = ERR_LIB_RAND or ERR_RFLAG_COMMON;
  ERR_R_DSO_LIB = ERR_LIB_DSO or ERR_RFLAG_COMMON;
  ERR_R_ENGINE_LIB = ERR_LIB_ENGINE or ERR_RFLAG_COMMON;
  ERR_R_UI_LIB = ERR_LIB_UI or ERR_RFLAG_COMMON;
  ERR_R_ECDSA_LIB = ERR_LIB_ECDSA or ERR_RFLAG_COMMON;
  ERR_R_OSSL_STORE_LIB = ERR_LIB_OSSL_STORE or ERR_RFLAG_COMMON;
  ERR_R_CMS_LIB = ERR_LIB_CMS or ERR_RFLAG_COMMON;
  ERR_R_TS_LIB = ERR_LIB_TS or ERR_RFLAG_COMMON;
  ERR_R_CT_LIB = ERR_LIB_CT or ERR_RFLAG_COMMON;
  ERR_R_PROV_LIB = ERR_LIB_PROV or ERR_RFLAG_COMMON;
  ERR_R_ESS_LIB = ERR_LIB_ESS or ERR_RFLAG_COMMON;
  ERR_R_CMP_LIB = ERR_LIB_CMP or ERR_RFLAG_COMMON;
  ERR_R_OSSL_ENCODER_LIB = ERR_LIB_OSSL_ENCODER or ERR_RFLAG_COMMON;
  ERR_R_OSSL_DECODER_LIB = ERR_LIB_OSSL_DECODER or ERR_RFLAG_COMMON;
  { Other common error codes, range 256..2^ERR_RFLAGS_OFFSET-1 }
  ERR_R_FATAL = ERR_RFLAG_FATAL or ERR_RFLAG_COMMON;
  ERR_R_MALLOC_FAILURE = 256 or ERR_R_FATAL;
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = 257 or ERR_R_FATAL;
  ERR_R_PASSED_NULL_PARAMETER = 258 or ERR_R_FATAL;
  ERR_R_INTERNAL_ERROR = 259 or ERR_R_FATAL;
  ERR_R_DISABLED = 260 or ERR_R_FATAL;
  ERR_R_INIT_FAIL = 261 or ERR_R_FATAL;
  ERR_R_PASSED_INVALID_ARGUMENT = 262 or ERR_RFLAG_COMMON;
  ERR_R_OPERATION_FAIL = 263 or ERR_R_FATAL;
  ERR_R_INVALID_PROVIDER_FUNCTIONS = 264 or ERR_R_FATAL;
  ERR_R_INTERRUPTED_OR_CANCELLED = 265 or ERR_RFLAG_COMMON;
  ERR_R_NESTED_ASN1_ERROR = 266 or ERR_RFLAG_COMMON;
  ERR_R_MISSING_ASN1_EOS = 267 or ERR_RFLAG_COMMON;
  ERR_R_UNSUPPORTED = 268 or ERR_RFLAG_COMMON;
  ERR_R_FETCH_FAILED = 269 or ERR_RFLAG_COMMON;
  ERR_R_INVALID_PROPERTY_DEFINITION = 270 or ERR_RFLAG_COMMON;
  ERR_R_UNABLE_TO_GET_READ_LOCK = 271 or ERR_R_FATAL;
  ERR_R_UNABLE_TO_GET_WRITE_LOCK = 272 or ERR_R_FATAL;

type
  {Auto-generated forward references}
  PERR_string_data_st = ^TERR_string_data_st;
  PPERR_string_data_st = ^PERR_string_data_st;
  PERR_STRING_DATA = ^TERR_STRING_DATA;
  PPERR_STRING_DATA = ^PERR_STRING_DATA;
  Plh_ERR_STRING_DATA_dummy = ^Tlh_ERR_STRING_DATA_dummy;
  PPlh_ERR_STRING_DATA_dummy = ^Plh_ERR_STRING_DATA_dummy;
  Plhash_st_ERR_STRING_DATA = ^Tlhash_st_ERR_STRING_DATA;
  PPlhash_st_ERR_STRING_DATA = ^Plhash_st_ERR_STRING_DATA;
  Plh_ERR_STRING_DATA_compfunc = ^Tlh_ERR_STRING_DATA_compfunc;
  PPlh_ERR_STRING_DATA_compfunc = ^Plh_ERR_STRING_DATA_compfunc;
  Plh_ERR_STRING_DATA_hashfunc = ^Tlh_ERR_STRING_DATA_hashfunc;
  PPlh_ERR_STRING_DATA_hashfunc = ^Plh_ERR_STRING_DATA_hashfunc;
  Plh_ERR_STRING_DATA_doallfunc = ^Tlh_ERR_STRING_DATA_doallfunc;
  PPlh_ERR_STRING_DATA_doallfunc = ^Plh_ERR_STRING_DATA_doallfunc;
  {end of auto-generated forward references}

  TERR_string_data_st = record 
    error: TOpenSSL_C_UINT;
    string_: PAnsiChar;
  end;
  TERR_STRING_DATA = TERR_string_data_st;
  { clang-format off }
  Tlh_ERR_STRING_DATA_dummy = record 
    case integer of 
      0: (d1: pointer);
      1: (d2: TOpenSSL_C_UINT);
      2: (d3: TOpenSSL_C_INT);
  end;
  Tlhash_st_ERR_STRING_DATA = record 
    dummy: Tlh_ERR_STRING_DATA_dummy;
  end;
  Tlh_ERR_STRING_DATA_compfunc = function(a: PERR_STRING_DATA; b: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
  Tlh_ERR_STRING_DATA_hashfunc = function(a: PERR_STRING_DATA): TOpenSSL_C_UINT; cdecl;
  Tlh_ERR_STRING_DATA_doallfunc = procedure(a: PERR_STRING_DATA); cdecl;


  function ossl_check_ERR_STRING_DATA_lh_plain_type(ptr: PERR_STRING_DATA): PERR_STRING_DATA{Has C Attribute: unused}; inline;
  function ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr: PERR_STRING_DATA): PERR_STRING_DATA{Has C Attribute: unused}; inline;
  function ossl_check_const_ERR_STRING_DATA_lh_type(lh: Plhash_st_ERR_STRING_DATA): POPENSSL_LHASH{Has C Attribute: unused}; inline;
  function ossl_check_ERR_STRING_DATA_lh_type(lh: Plhash_st_ERR_STRING_DATA): POPENSSL_LHASH{Has C Attribute: unused}; inline;
  function ossl_check_ERR_STRING_DATA_lh_compfunc_type(cmp: Tlh_ERR_STRING_DATA_compfunc): TOPENSSL_LH_COMPFUNC{Has C Attribute: unused}; inline;
  function ossl_check_ERR_STRING_DATA_lh_hashfunc_type(hfn: Tlh_ERR_STRING_DATA_hashfunc): TOPENSSL_LH_HASHFUNC{Has C Attribute: unused}; inline;
  function ossl_check_ERR_STRING_DATA_lh_doallfunc_type(dfn: Tlh_ERR_STRING_DATA_doallfunc): TOPENSSL_LH_DOALL_FUNC{Has C Attribute: unused}; inline;
  {# define  lh_ERR_STRING_DATA_new(hfn,cmp) ((LHASH_OF(ERR_STRING_DATA) *)OPENSSL_LH_new(ossl_check_ERR_STRING_DATA_lh_hashfunc_type(hfn),
 ossl_check_ERR_STRING_DATA_lh_compfunc_type(cmp)))}
  {# define  lh_ERR_STRING_DATA_free(lh) OPENSSL_LH_free(ossl_check_ERR_STRING_DATA_lh_type(lh))} {Macro Return Type unknown at line no 386}
  {# define  lh_ERR_STRING_DATA_flush(lh) OPENSSL_LH_flush(ossl_check_ERR_STRING_DATA_lh_type(lh))} {Macro Return Type unknown at line no 387}
  function lh_ERR_STRING_DATA_insert(lh:Plhash_st_ERR_STRING_DATA; ptr:PERR_STRING_DATA): PERR_STRING_DATA; inline;
  function lh_ERR_STRING_DATA_delete(lh:Plhash_st_ERR_STRING_DATA; ptr:PERR_STRING_DATA): PERR_STRING_DATA; inline;
  function lh_ERR_STRING_DATA_retrieve(lh:Plhash_st_ERR_STRING_DATA; ptr:PERR_STRING_DATA): PERR_STRING_DATA; inline;
  {# define  lh_ERR_STRING_DATA_error(lh) OPENSSL_LH_error(ossl_check_ERR_STRING_DATA_lh_type(lh))} {Macro Return Type unknown at line no 391}
  {# define  lh_ERR_STRING_DATA_num_items(lh) OPENSSL_LH_num_items(ossl_check_ERR_STRING_DATA_lh_type(lh))} {Macro Return Type unknown at line no 392}
  {# define  lh_ERR_STRING_DATA_node_stats_bio(lh,out) OPENSSL_LH_node_stats_bio(ossl_check_const_ERR_STRING_DATA_lh_type(lh), out)} {Function argument out of range at line no 393}
  {# define  lh_ERR_STRING_DATA_node_usage_stats_bio(lh,out) OPENSSL_LH_node_usage_stats_bio(ossl_check_const_ERR_STRING_DATA_lh_type(lh),
 out)} {Function argument out of range at line no 394}
  {# define  lh_ERR_STRING_DATA_stats_bio(lh,out) OPENSSL_LH_stats_bio(ossl_check_const_ERR_STRING_DATA_lh_type(lh), out)} {Function argument out of range at line no 395}
  {# define  lh_ERR_STRING_DATA_get_down_load(lh) OPENSSL_LH_get_down_load(ossl_check_ERR_STRING_DATA_lh_type(lh))} {Macro Return Type unknown at line no 396}
  {# define  lh_ERR_STRING_DATA_set_down_load(lh,dl) OPENSSL_LH_set_down_load(ossl_check_ERR_STRING_DATA_lh_type(lh), dl)} {Function argument out of range at line no 397}
  {# define  lh_ERR_STRING_DATA_doall(lh,dfn) OPENSSL_LH_doall(ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_check_ERR_STRING_DATA_lh_doallfunc_type(dfn))} {Macro Return Type unknown at line no 398}

const
  { clang-format on }
  { 12 lines and some on an 80 column terminal }
  ERR_MAX_DATA_SIZE = 1024;


  { Building blocks }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_new; cdecl; external CLibCrypto name 'ERR_new';
  procedure ERR_set_debug(file_: PAnsiChar; line: TOpenSSL_C_INT; func: PAnsiChar); cdecl; external CLibCrypto name 'ERR_set_debug';
  procedure ERR_set_error(lib: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; fmt: PAnsiChar); cdecl varargs; external CLibCrypto name 'ERR_set_error';
  procedure ERR_vset_error(lib: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; fmt: PAnsiChar; args: array of const); cdecl; external CLibCrypto name 'ERR_vset_error';
  { Main error raising functions }
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM ERR_new}
  {$EXTERNALSYM ERR_set_debug}
  {$EXTERNALSYM ERR_set_error}
  {$EXTERNALSYM ERR_vset_error}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_new; cdecl;
  procedure Load_ERR_set_debug(file_: PAnsiChar; line: TOpenSSL_C_INT; func: PAnsiChar); cdecl;

var
  ERR_new: procedure; cdecl = Load_ERR_new;
  ERR_set_debug: procedure(file_: PAnsiChar; line: TOpenSSL_C_INT; func: PAnsiChar); cdecl = Load_ERR_set_debug;
  ERR_set_error: procedure(lib: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; fmt: PAnsiChar); cdecl varargs = nil;
  ERR_vset_error: procedure(lib: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; fmt: PAnsiChar; args: array of const); cdecl = nil;
  { Main error raising functions }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {# define  ERR_raise(lib,reason) ERR_raise_data((lib), (reason), NULL)} {Macro Return Type unknown at line no 412}
  {# define  ERR_raise_data (ERR_new(), ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC), ERR_set_error)}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{# define  ERR_put_error(lib,func,reason,file,line) (ERR_new(), ERR_set_debug((file), (line), OPENSSL_FUNC), ERR_set_error((lib),
 (reason), NULL))}
    { Backward compatibility }
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_set_error_data(data: PAnsiChar; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'ERR_set_error_data';
  function ERR_get_error: TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_get_error';
  function ERR_get_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_get_error_all';
  {$else}
  {$EXTERNALSYM ERR_set_error_data}
  {$EXTERNALSYM ERR_get_error}
  {$EXTERNALSYM ERR_get_error_all}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_set_error_data(data: PAnsiChar; flags: TOpenSSL_C_INT); cdecl;
  function Load_ERR_get_error: TOpenSSL_C_UINT; cdecl;
  function Load_ERR_get_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;

var
  ERR_set_error_data: procedure(data: PAnsiChar; flags: TOpenSSL_C_INT); cdecl = Load_ERR_set_error_data;
  ERR_get_error: function: TOpenSSL_C_UINT; cdecl = Load_ERR_get_error;
  ERR_get_error_all: function(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_get_error_all;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_get_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_get_error_line'; deprecated 'Since OpenSSL 3.0';
  function ERR_get_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_get_error_line_data'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_get_error_line}
  {$EXTERNALSYM ERR_get_error_line_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_get_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
  function Load_ERR_get_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;

var
  ERR_get_error_line: function(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_get_error_line;
  ERR_get_error_line_data: function(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_get_error_line_data;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_peek_error: TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_error';
  function ERR_peek_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_error_line';
  function ERR_peek_error_func(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_error_func';
  function ERR_peek_error_data(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_error_data';
  function ERR_peek_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_error_all';
  {$else}
  {$EXTERNALSYM ERR_peek_error}
  {$EXTERNALSYM ERR_peek_error_line}
  {$EXTERNALSYM ERR_peek_error_func}
  {$EXTERNALSYM ERR_peek_error_data}
  {$EXTERNALSYM ERR_peek_error_all}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_peek_error: TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_error_func(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_error_data(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;

var
  ERR_peek_error: function: TOpenSSL_C_UINT; cdecl = Load_ERR_peek_error;
  ERR_peek_error_line: function(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_error_line;
  ERR_peek_error_func: function(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_error_func;
  ERR_peek_error_data: function(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_error_data;
  ERR_peek_error_all: function(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_error_all;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_peek_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_error_line_data'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_peek_error_line_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_peek_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;

var
  ERR_peek_error_line_data: function(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_error_line_data;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_peek_last_error: TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_last_error';
  function ERR_peek_last_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_last_error_line';
  function ERR_peek_last_error_func(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_last_error_func';
  function ERR_peek_last_error_data(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_last_error_data';
  function ERR_peek_last_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_last_error_all';
  {$else}
  {$EXTERNALSYM ERR_peek_last_error}
  {$EXTERNALSYM ERR_peek_last_error_line}
  {$EXTERNALSYM ERR_peek_last_error_func}
  {$EXTERNALSYM ERR_peek_last_error_data}
  {$EXTERNALSYM ERR_peek_last_error_all}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_peek_last_error: TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_last_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_last_error_func(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_last_error_data(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
  function Load_ERR_peek_last_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;

var
  ERR_peek_last_error: function: TOpenSSL_C_UINT; cdecl = Load_ERR_peek_last_error;
  ERR_peek_last_error_line: function(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_last_error_line;
  ERR_peek_last_error_func: function(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_last_error_func;
  ERR_peek_last_error_data: function(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_last_error_data;
  ERR_peek_last_error_all: function(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_last_error_all;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_peek_last_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ERR_peek_last_error_line_data'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_peek_last_error_line_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_peek_last_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;

var
  ERR_peek_last_error_line_data: function(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl = Load_ERR_peek_last_error_line_data;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_clear_error; cdecl; external CLibCrypto name 'ERR_clear_error';
  function ERR_error_string(e: TOpenSSL_C_UINT; buf: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto name 'ERR_error_string';
  procedure ERR_error_string_n(e: TOpenSSL_C_UINT; buf: PAnsiChar; len: TOpenSSL_C_SIZET); cdecl; external CLibCrypto name 'ERR_error_string_n';
  function ERR_lib_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl; external CLibCrypto name 'ERR_lib_error_string';
  {$else}
  {$EXTERNALSYM ERR_clear_error}
  {$EXTERNALSYM ERR_error_string}
  {$EXTERNALSYM ERR_error_string_n}
  {$EXTERNALSYM ERR_lib_error_string}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_clear_error; cdecl;
  function Load_ERR_error_string(e: TOpenSSL_C_UINT; buf: PAnsiChar): PAnsiChar; cdecl;
  procedure Load_ERR_error_string_n(e: TOpenSSL_C_UINT; buf: PAnsiChar; len: TOpenSSL_C_SIZET); cdecl;
  function Load_ERR_lib_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl;

var
  ERR_clear_error: procedure; cdecl = Load_ERR_clear_error;
  ERR_error_string: function(e: TOpenSSL_C_UINT; buf: PAnsiChar): PAnsiChar; cdecl = Load_ERR_error_string;
  ERR_error_string_n: procedure(e: TOpenSSL_C_UINT; buf: PAnsiChar; len: TOpenSSL_C_SIZET); cdecl = Load_ERR_error_string_n;
  ERR_lib_error_string: function(e: TOpenSSL_C_UINT): PAnsiChar; cdecl = Load_ERR_lib_error_string;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_func_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl; external CLibCrypto name 'ERR_func_error_string'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_func_error_string}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_func_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl;

var
  ERR_func_error_string: function(e: TOpenSSL_C_UINT): PAnsiChar; cdecl = Load_ERR_func_error_string;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_reason_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl; external CLibCrypto name 'ERR_reason_error_string';
  {$else}
  {$EXTERNALSYM ERR_reason_error_string}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_reason_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl;

var
  ERR_reason_error_string: function(e: TOpenSSL_C_UINT): PAnsiChar; cdecl = Load_ERR_reason_error_string;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = function(str: PAnsiChar; len: TOpenSSL_C_SIZET; u: pointer): TOpenSSL_C_INT; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_print_errors_cb(cb: TFuncType000; u: pointer); cdecl; external CLibCrypto name 'ERR_print_errors_cb';
  {$else}
  {$EXTERNALSYM ERR_print_errors_cb}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_print_errors_cb(cb: TFuncType000; u: pointer); cdecl;

var
  ERR_print_errors_cb: procedure(cb: TFuncType000; u: pointer); cdecl = Load_ERR_print_errors_cb;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_STDIO}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_print_errors_fp(fp: PFILE); cdecl; external CLibCrypto name 'ERR_print_errors_fp';
    {$else}
  {$EXTERNALSYM ERR_print_errors_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_print_errors_fp(fp: PFILE); cdecl;

var
  ERR_print_errors_fp: procedure(fp: PFILE); cdecl = Load_ERR_print_errors_fp;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_print_errors(bp: PBIO); cdecl; external CLibCrypto name 'ERR_print_errors';
  procedure ERR_add_error_data(num: TOpenSSL_C_INT); cdecl varargs; external CLibCrypto name 'ERR_add_error_data';
  procedure ERR_add_error_vdata(num: TOpenSSL_C_INT; args: array of const); cdecl; external CLibCrypto name 'ERR_add_error_vdata';
  procedure ERR_add_error_txt(sepr: PAnsiChar; txt: PAnsiChar); cdecl; external CLibCrypto name 'ERR_add_error_txt';
  procedure ERR_add_error_mem_bio(sep: PAnsiChar; bio: PBIO); cdecl; external CLibCrypto name 'ERR_add_error_mem_bio';
  function ERR_load_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_strings';
  function ERR_load_strings_const(str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_load_strings_const';
  function ERR_unload_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_unload_strings';
  {$else}
  {$EXTERNALSYM ERR_print_errors}
  {$EXTERNALSYM ERR_add_error_data}
  {$EXTERNALSYM ERR_add_error_vdata}
  {$EXTERNALSYM ERR_add_error_txt}
  {$EXTERNALSYM ERR_add_error_mem_bio}
  {$EXTERNALSYM ERR_load_strings}
  {$EXTERNALSYM ERR_load_strings_const}
  {$EXTERNALSYM ERR_unload_strings}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_print_errors(bp: PBIO); cdecl;
  procedure Load_ERR_add_error_txt(sepr: PAnsiChar; txt: PAnsiChar); cdecl;
  procedure Load_ERR_add_error_mem_bio(sep: PAnsiChar; bio: PBIO); cdecl;
  function Load_ERR_load_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
  function Load_ERR_load_strings_const(str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
  function Load_ERR_unload_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;

var
  ERR_print_errors: procedure(bp: PBIO); cdecl = Load_ERR_print_errors;
  ERR_add_error_data: procedure(num: TOpenSSL_C_INT); cdecl varargs = nil;
  ERR_add_error_vdata: procedure(num: TOpenSSL_C_INT; args: array of const); cdecl = nil;
  ERR_add_error_txt: procedure(sepr: PAnsiChar; txt: PAnsiChar); cdecl = Load_ERR_add_error_txt;
  ERR_add_error_mem_bio: procedure(sep: PAnsiChar; bio: PBIO); cdecl = Load_ERR_add_error_mem_bio;
  ERR_load_strings: function(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl = Load_ERR_load_strings;
  ERR_load_strings_const: function(str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl = Load_ERR_load_strings_const;
  ERR_unload_strings: function(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl = Load_ERR_unload_strings;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{# define  ERR_load_crypto_strings() OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)} {Macro Return Type unknown at line no 491}
{# define  ERR_free_strings() while (0) continue}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_remove_thread_state(_param1: pointer); cdecl; external CLibCrypto name 'ERR_remove_thread_state'; deprecated 'Since OpenSSL 1.1.0';
    {$else}
  {$EXTERNALSYM ERR_remove_thread_state}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_remove_thread_state(_param1: pointer); cdecl;

var
  ERR_remove_thread_state: procedure(_param1: pointer); cdecl = Load_ERR_remove_thread_state;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_1_0_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ERR_remove_state(pid: TOpenSSL_C_UINT); cdecl; external CLibCrypto name 'ERR_remove_state'; deprecated 'Since OpenSSL 1.0.0';
    {$else}
  {$EXTERNALSYM ERR_remove_state}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ERR_remove_state(pid: TOpenSSL_C_UINT); cdecl;

var
  ERR_remove_state: procedure(pid: TOpenSSL_C_UINT); cdecl = Load_ERR_remove_state;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_get_state: PERR_STATE; cdecl; external CLibCrypto name 'ERR_get_state'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM ERR_get_state}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_get_state: PERR_STATE; cdecl;

var
  ERR_get_state: function: PERR_STATE; cdecl = Load_ERR_get_state;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ERR_get_next_error_library: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_get_next_error_library';
  function ERR_set_mark: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_set_mark';
  function ERR_pop_to_mark: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_pop_to_mark';
  function ERR_clear_last_mark: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ERR_clear_last_mark';
  {$else}
  {$EXTERNALSYM ERR_get_next_error_library}
  {$EXTERNALSYM ERR_set_mark}
  {$EXTERNALSYM ERR_pop_to_mark}
  {$EXTERNALSYM ERR_clear_last_mark}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ERR_get_next_error_library: TOpenSSL_C_INT; cdecl;
  function Load_ERR_set_mark: TOpenSSL_C_INT; cdecl;
  function Load_ERR_pop_to_mark: TOpenSSL_C_INT; cdecl;
  function Load_ERR_clear_last_mark: TOpenSSL_C_INT; cdecl;

var
  ERR_get_next_error_library: function: TOpenSSL_C_INT; cdecl = Load_ERR_get_next_error_library;
  ERR_set_mark: function: TOpenSSL_C_INT; cdecl = Load_ERR_set_mark;
  ERR_pop_to_mark: function: TOpenSSL_C_INT; cdecl = Load_ERR_pop_to_mark;
  ERR_clear_last_mark: function: TOpenSSL_C_INT; cdecl = Load_ERR_clear_last_mark;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}
{$include errfunctions_h.inc}

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


{# define  ERR_SYSTEM_MASK ((unsigned int)INT_MAX)}

function ERR_SYSTEM_MASK: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT(INT_MAX));
end;
function ERR_GET_LIB(errcode: TOpenSSL_C_UINT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
  if (errcode and ((TOpenSSL_C_UINT($7fffffff))+1))<>0 then
     Result := 2;
;
   Result := (errcode shr 23) and $FF;
end;

function ERR_GET_RFLAGS(errcode: TOpenSSL_C_UINT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
  if (errcode and ((TOpenSSL_C_UINT($7fffffff))+1))<>0 then
     Result := 0;
;
   Result := errcode and ($1F shl 18);
end;

function ERR_GET_REASON(errcode: TOpenSSL_C_UINT): TOpenSSL_C_INT{Has C Attribute: unused}; inline;
begin
  if (errcode and ((TOpenSSL_C_UINT($7fffffff))+1))<>0 then
     Result := errcode and (TOpenSSL_C_UINT($7fffffff));
;
   Result := errcode and $7FFFFF;
end;

function ERR_FATAL_ERROR(errcode: TOpenSSL_C_UINT): boolean{Has C Attribute: unused}; inline;
begin
   Result := ((ERR_GET_RFLAGS(errcode)) and ($1 shl 18))<>0;
end;

function ERR_COMMON_ERROR(errcode: TOpenSSL_C_UINT): boolean{Has C Attribute: unused}; inline;
begin
   Result := ((ERR_GET_RFLAGS(errcode)) and ($2 shl 18))<>0;
end;

function ossl_check_ERR_STRING_DATA_lh_plain_type(ptr: PERR_STRING_DATA): PERR_STRING_DATA{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr: PERR_STRING_DATA): PERR_STRING_DATA{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_ERR_STRING_DATA_lh_type(lh: Plhash_st_ERR_STRING_DATA): POPENSSL_LHASH{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_LHASH(lh);
end;

function ossl_check_ERR_STRING_DATA_lh_type(lh: Plhash_st_ERR_STRING_DATA): POPENSSL_LHASH{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_LHASH(lh);
end;

function ossl_check_ERR_STRING_DATA_lh_compfunc_type(cmp: Tlh_ERR_STRING_DATA_compfunc): TOPENSSL_LH_COMPFUNC{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "ossl_check_ERR_STRING_DATA_lh_compfunc_type"');

{Error: Line 384: Syntax Error parsing " return (OPENSSL_LH_COMPFUNC)cmp; "

 return (OPENSSL_LH_COMPFUNC)cmp; }
end;

function ossl_check_ERR_STRING_DATA_lh_hashfunc_type(hfn: Tlh_ERR_STRING_DATA_hashfunc): TOPENSSL_LH_HASHFUNC{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "ossl_check_ERR_STRING_DATA_lh_hashfunc_type"');

{Error: Line 384: Syntax Error parsing " return (OPENSSL_LH_HASHFUNC)hfn; "

 return (OPENSSL_LH_HASHFUNC)hfn; }
end;

function ossl_check_ERR_STRING_DATA_lh_doallfunc_type(dfn: Tlh_ERR_STRING_DATA_doallfunc): TOPENSSL_LH_DOALL_FUNC{Has C Attribute: unused}; inline;
begin
  raise Exception.Create('Unable to translate C Function "ossl_check_ERR_STRING_DATA_lh_doallfunc_type"');

{Error: Line 384: Syntax Error parsing " return (OPENSSL_LH_DOALL_FUNC)dfn; "

 return (OPENSSL_LH_DOALL_FUNC)dfn; }
end;


{# define  lh_ERR_STRING_DATA_insert(lh,ptr) ((ERR_STRING_DATA *)OPENSSL_LH_insert(ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_check_ERR_STRING_DATA_lh_plain_type(ptr)))}

function lh_ERR_STRING_DATA_insert(lh:Plhash_st_ERR_STRING_DATA; ptr:PERR_STRING_DATA): PERR_STRING_DATA;
begin
  Result := PERR_STRING_DATA(PERR_STRING_DATA(OPENSSL_LH_insert(ossl_check_ERR_STRING_DATA_lh_type(lh),ossl_check_ERR_STRING_DATA_lh_plain_type(ptr))));
end;

{# define  lh_ERR_STRING_DATA_delete(lh,ptr) ((ERR_STRING_DATA *)OPENSSL_LH_delete(ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr)))}

function lh_ERR_STRING_DATA_delete(lh:Plhash_st_ERR_STRING_DATA; ptr:PERR_STRING_DATA): PERR_STRING_DATA;
begin
  Result := PERR_STRING_DATA(PERR_STRING_DATA(OPENSSL_LH_delete(ossl_check_ERR_STRING_DATA_lh_type(lh),ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr))));
end;

{# define  lh_ERR_STRING_DATA_retrieve(lh,ptr) ((ERR_STRING_DATA *)OPENSSL_LH_retrieve(ossl_check_ERR_STRING_DATA_lh_type(lh), ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr)))}

function lh_ERR_STRING_DATA_retrieve(lh:Plhash_st_ERR_STRING_DATA; ptr:PERR_STRING_DATA): PERR_STRING_DATA;
begin
  Result := PERR_STRING_DATA(PERR_STRING_DATA(OPENSSL_LH_retrieve(ossl_check_ERR_STRING_DATA_lh_type(lh),ossl_check_const_ERR_STRING_DATA_lh_plain_type(ptr))));
end;
{$include errfunctions.inc}
{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Load_ERR_new; cdecl;
begin
  ERR_new := LoadLibCryptoFunction('ERR_new');
  if not assigned(ERR_new) then
    {$if declared(LEGACY_ERR_new)}
    ERR_new := @LEGACY_ERR_new;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_new');
    {$ifend}
  ERR_new;
end;

procedure Load_ERR_set_debug(file_: PAnsiChar; line: TOpenSSL_C_INT; func: PAnsiChar); cdecl;
begin
  ERR_set_debug := LoadLibCryptoFunction('ERR_set_debug');
  if not assigned(ERR_set_debug) then
    {$if declared(LEGACY_ERR_set_debug)}
    ERR_set_debug := @LEGACY_ERR_set_debug;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_set_debug');
    {$ifend}
  ERR_set_debug(file_, line, func);
end;

procedure Load_ERR_set_error_data(data: PAnsiChar; flags: TOpenSSL_C_INT); cdecl;
begin
  ERR_set_error_data := LoadLibCryptoFunction('ERR_set_error_data');
  if not assigned(ERR_set_error_data) then
    {$if declared(LEGACY_ERR_set_error_data)}
    ERR_set_error_data := @LEGACY_ERR_set_error_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_set_error_data');
    {$ifend}
  ERR_set_error_data(data, flags);
end;

function Load_ERR_get_error: TOpenSSL_C_UINT; cdecl;
begin
  ERR_get_error := LoadLibCryptoFunction('ERR_get_error');
  if not assigned(ERR_get_error) then
    {$if declared(LEGACY_ERR_get_error)}
    ERR_get_error := @LEGACY_ERR_get_error;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_error');
    {$ifend}
  Result := ERR_get_error;
end;

function Load_ERR_get_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_get_error_all := LoadLibCryptoFunction('ERR_get_error_all');
  if not assigned(ERR_get_error_all) then
    {$if declared(LEGACY_ERR_get_error_all)}
    ERR_get_error_all := @LEGACY_ERR_get_error_all;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_error_all');
    {$ifend}
  Result := ERR_get_error_all(file_, line, func, data, flags);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_get_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_get_error_line := LoadLibCryptoFunction('ERR_get_error_line');
  if not assigned(ERR_get_error_line) then
    {$if declared(LEGACY_ERR_get_error_line)}
    ERR_get_error_line := @LEGACY_ERR_get_error_line;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_error_line');
    {$ifend}
  Result := ERR_get_error_line(file_, line);
end;

function Load_ERR_get_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_get_error_line_data := LoadLibCryptoFunction('ERR_get_error_line_data');
  if not assigned(ERR_get_error_line_data) then
    {$if declared(LEGACY_ERR_get_error_line_data)}
    ERR_get_error_line_data := @LEGACY_ERR_get_error_line_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_error_line_data');
    {$ifend}
  Result := ERR_get_error_line_data(file_, line, data, flags);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_peek_error: TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_error := LoadLibCryptoFunction('ERR_peek_error');
  if not assigned(ERR_peek_error) then
    {$if declared(LEGACY_ERR_peek_error)}
    ERR_peek_error := @LEGACY_ERR_peek_error;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error');
    {$ifend}
  Result := ERR_peek_error;
end;

function Load_ERR_peek_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_error_line := LoadLibCryptoFunction('ERR_peek_error_line');
  if not assigned(ERR_peek_error_line) then
    {$if declared(LEGACY_ERR_peek_error_line)}
    ERR_peek_error_line := @LEGACY_ERR_peek_error_line;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error_line');
    {$ifend}
  Result := ERR_peek_error_line(file_, line);
end;

function Load_ERR_peek_error_func(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_error_func := LoadLibCryptoFunction('ERR_peek_error_func');
  if not assigned(ERR_peek_error_func) then
    {$if declared(LEGACY_ERR_peek_error_func)}
    ERR_peek_error_func := @LEGACY_ERR_peek_error_func;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error_func');
    {$ifend}
  Result := ERR_peek_error_func(func);
end;

function Load_ERR_peek_error_data(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_error_data := LoadLibCryptoFunction('ERR_peek_error_data');
  if not assigned(ERR_peek_error_data) then
    {$if declared(LEGACY_ERR_peek_error_data)}
    ERR_peek_error_data := @LEGACY_ERR_peek_error_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error_data');
    {$ifend}
  Result := ERR_peek_error_data(data, flags);
end;

function Load_ERR_peek_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_error_all := LoadLibCryptoFunction('ERR_peek_error_all');
  if not assigned(ERR_peek_error_all) then
    {$if declared(LEGACY_ERR_peek_error_all)}
    ERR_peek_error_all := @LEGACY_ERR_peek_error_all;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error_all');
    {$ifend}
  Result := ERR_peek_error_all(file_, line, func, data, flags);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_peek_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_error_line_data := LoadLibCryptoFunction('ERR_peek_error_line_data');
  if not assigned(ERR_peek_error_line_data) then
    {$if declared(LEGACY_ERR_peek_error_line_data)}
    ERR_peek_error_line_data := @LEGACY_ERR_peek_error_line_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error_line_data');
    {$ifend}
  Result := ERR_peek_error_line_data(file_, line, data, flags);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_peek_last_error: TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_last_error := LoadLibCryptoFunction('ERR_peek_last_error');
  if not assigned(ERR_peek_last_error) then
    {$if declared(LEGACY_ERR_peek_last_error)}
    ERR_peek_last_error := @LEGACY_ERR_peek_last_error;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error');
    {$ifend}
  Result := ERR_peek_last_error;
end;

function Load_ERR_peek_last_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_last_error_line := LoadLibCryptoFunction('ERR_peek_last_error_line');
  if not assigned(ERR_peek_last_error_line) then
    {$if declared(LEGACY_ERR_peek_last_error_line)}
    ERR_peek_last_error_line := @LEGACY_ERR_peek_last_error_line;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error_line');
    {$ifend}
  Result := ERR_peek_last_error_line(file_, line);
end;

function Load_ERR_peek_last_error_func(func: PPAnsiChar): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_last_error_func := LoadLibCryptoFunction('ERR_peek_last_error_func');
  if not assigned(ERR_peek_last_error_func) then
    {$if declared(LEGACY_ERR_peek_last_error_func)}
    ERR_peek_last_error_func := @LEGACY_ERR_peek_last_error_func;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error_func');
    {$ifend}
  Result := ERR_peek_last_error_func(func);
end;

function Load_ERR_peek_last_error_data(data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_last_error_data := LoadLibCryptoFunction('ERR_peek_last_error_data');
  if not assigned(ERR_peek_last_error_data) then
    {$if declared(LEGACY_ERR_peek_last_error_data)}
    ERR_peek_last_error_data := @LEGACY_ERR_peek_last_error_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error_data');
    {$ifend}
  Result := ERR_peek_last_error_data(data, flags);
end;

function Load_ERR_peek_last_error_all(file_: PPAnsiChar; line: POpenSSL_C_INT; func: PPAnsiChar; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_last_error_all := LoadLibCryptoFunction('ERR_peek_last_error_all');
  if not assigned(ERR_peek_last_error_all) then
    {$if declared(LEGACY_ERR_peek_last_error_all)}
    ERR_peek_last_error_all := @LEGACY_ERR_peek_last_error_all;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error_all');
    {$ifend}
  Result := ERR_peek_last_error_all(file_, line, func, data, flags);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_peek_last_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_UINT; cdecl;
begin
  ERR_peek_last_error_line_data := LoadLibCryptoFunction('ERR_peek_last_error_line_data');
  if not assigned(ERR_peek_last_error_line_data) then
    {$if declared(LEGACY_ERR_peek_last_error_line_data)}
    ERR_peek_last_error_line_data := @LEGACY_ERR_peek_last_error_line_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error_line_data');
    {$ifend}
  Result := ERR_peek_last_error_line_data(file_, line, data, flags);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load_ERR_clear_error; cdecl;
begin
  ERR_clear_error := LoadLibCryptoFunction('ERR_clear_error');
  if not assigned(ERR_clear_error) then
    {$if declared(LEGACY_ERR_clear_error)}
    ERR_clear_error := @LEGACY_ERR_clear_error;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_clear_error');
    {$ifend}
  ERR_clear_error;
end;

function Load_ERR_error_string(e: TOpenSSL_C_UINT; buf: PAnsiChar): PAnsiChar; cdecl;
begin
  ERR_error_string := LoadLibCryptoFunction('ERR_error_string');
  if not assigned(ERR_error_string) then
    {$if declared(LEGACY_ERR_error_string)}
    ERR_error_string := @LEGACY_ERR_error_string;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_error_string');
    {$ifend}
  Result := ERR_error_string(e, buf);
end;

procedure Load_ERR_error_string_n(e: TOpenSSL_C_UINT; buf: PAnsiChar; len: TOpenSSL_C_SIZET); cdecl;
begin
  ERR_error_string_n := LoadLibCryptoFunction('ERR_error_string_n');
  if not assigned(ERR_error_string_n) then
    {$if declared(LEGACY_ERR_error_string_n)}
    ERR_error_string_n := @LEGACY_ERR_error_string_n;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_error_string_n');
    {$ifend}
  ERR_error_string_n(e, buf, len);
end;

function Load_ERR_lib_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl;
begin
  ERR_lib_error_string := LoadLibCryptoFunction('ERR_lib_error_string');
  if not assigned(ERR_lib_error_string) then
    {$if declared(LEGACY_ERR_lib_error_string)}
    ERR_lib_error_string := @LEGACY_ERR_lib_error_string;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_lib_error_string');
    {$ifend}
  Result := ERR_lib_error_string(e);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_func_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl;
begin
  ERR_func_error_string := LoadLibCryptoFunction('ERR_func_error_string');
  if not assigned(ERR_func_error_string) then
    {$if declared(LEGACY_ERR_func_error_string)}
    ERR_func_error_string := @LEGACY_ERR_func_error_string;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_func_error_string');
    {$ifend}
  Result := ERR_func_error_string(e);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_reason_error_string(e: TOpenSSL_C_UINT): PAnsiChar; cdecl;
begin
  ERR_reason_error_string := LoadLibCryptoFunction('ERR_reason_error_string');
  if not assigned(ERR_reason_error_string) then
    {$if declared(LEGACY_ERR_reason_error_string)}
    ERR_reason_error_string := @LEGACY_ERR_reason_error_string;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_reason_error_string');
    {$ifend}
  Result := ERR_reason_error_string(e);
end;

procedure Load_ERR_print_errors_cb(cb: TFuncType000; u: pointer); cdecl;
begin
  ERR_print_errors_cb := LoadLibCryptoFunction('ERR_print_errors_cb');
  if not assigned(ERR_print_errors_cb) then
    {$if declared(LEGACY_ERR_print_errors_cb)}
    ERR_print_errors_cb := @LEGACY_ERR_print_errors_cb;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_print_errors_cb');
    {$ifend}
  ERR_print_errors_cb(cb, u);
end;

{$ifndef  OPENSSL_NO_STDIO}
procedure Load_ERR_print_errors_fp(fp: PFILE); cdecl;
begin
  ERR_print_errors_fp := LoadLibCryptoFunction('ERR_print_errors_fp');
  if not assigned(ERR_print_errors_fp) then
    {$if declared(LEGACY_ERR_print_errors_fp)}
    ERR_print_errors_fp := @LEGACY_ERR_print_errors_fp;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_print_errors_fp');
    {$ifend}
  ERR_print_errors_fp(fp);
end;

{$endif} { OPENSSL_NO_STDIO}
procedure Load_ERR_print_errors(bp: PBIO); cdecl;
begin
  ERR_print_errors := LoadLibCryptoFunction('ERR_print_errors');
  if not assigned(ERR_print_errors) then
    {$if declared(LEGACY_ERR_print_errors)}
    ERR_print_errors := @LEGACY_ERR_print_errors;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_print_errors');
    {$ifend}
  ERR_print_errors(bp);
end;

procedure Load_ERR_add_error_txt(sepr: PAnsiChar; txt: PAnsiChar); cdecl;
begin
  ERR_add_error_txt := LoadLibCryptoFunction('ERR_add_error_txt');
  if not assigned(ERR_add_error_txt) then
    {$if declared(LEGACY_ERR_add_error_txt)}
    ERR_add_error_txt := @LEGACY_ERR_add_error_txt;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_add_error_txt');
    {$ifend}
  ERR_add_error_txt(sepr, txt);
end;

procedure Load_ERR_add_error_mem_bio(sep: PAnsiChar; bio: PBIO); cdecl;
begin
  ERR_add_error_mem_bio := LoadLibCryptoFunction('ERR_add_error_mem_bio');
  if not assigned(ERR_add_error_mem_bio) then
    {$if declared(LEGACY_ERR_add_error_mem_bio)}
    ERR_add_error_mem_bio := @LEGACY_ERR_add_error_mem_bio;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_add_error_mem_bio');
    {$ifend}
  ERR_add_error_mem_bio(sep, bio);
end;

function Load_ERR_load_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
begin
  ERR_load_strings := LoadLibCryptoFunction('ERR_load_strings');
  if not assigned(ERR_load_strings) then
    {$if declared(LEGACY_ERR_load_strings)}
    ERR_load_strings := @LEGACY_ERR_load_strings;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_strings');
    {$ifend}
  Result := ERR_load_strings(lib, str);
end;

function Load_ERR_load_strings_const(str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
begin
  ERR_load_strings_const := LoadLibCryptoFunction('ERR_load_strings_const');
  if not assigned(ERR_load_strings_const) then
    {$if declared(LEGACY_ERR_load_strings_const)}
    ERR_load_strings_const := @LEGACY_ERR_load_strings_const;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_strings_const');
    {$ifend}
  Result := ERR_load_strings_const(str);
end;

function Load_ERR_unload_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
begin
  ERR_unload_strings := LoadLibCryptoFunction('ERR_unload_strings');
  if not assigned(ERR_unload_strings) then
    {$if declared(LEGACY_ERR_unload_strings)}
    ERR_unload_strings := @LEGACY_ERR_unload_strings;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_unload_strings');
    {$ifend}
  Result := ERR_unload_strings(lib, str);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
procedure Load_ERR_remove_thread_state(_param1: pointer); cdecl;
begin
  ERR_remove_thread_state := LoadLibCryptoFunction('ERR_remove_thread_state');
  if not assigned(ERR_remove_thread_state) then
    {$if declared(LEGACY_ERR_remove_thread_state)}
    ERR_remove_thread_state := @LEGACY_ERR_remove_thread_state;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_remove_thread_state');
    {$ifend}
  ERR_remove_thread_state(_param1);
end;

{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$ifndef  OPENSSL_NO_DEPRECATED_1_0_0}
procedure Load_ERR_remove_state(pid: TOpenSSL_C_UINT); cdecl;
begin
  ERR_remove_state := LoadLibCryptoFunction('ERR_remove_state');
  if not assigned(ERR_remove_state) then
    {$if declared(LEGACY_ERR_remove_state)}
    ERR_remove_state := @LEGACY_ERR_remove_state;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_remove_state');
    {$ifend}
  ERR_remove_state(pid);
end;

{$endif} { OPENSSL_NO_DEPRECATED_1_0_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_get_state: PERR_STATE; cdecl;
begin
  ERR_get_state := LoadLibCryptoFunction('ERR_get_state');
  if not assigned(ERR_get_state) then
    {$if declared(LEGACY_ERR_get_state)}
    ERR_get_state := @LEGACY_ERR_get_state;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_state');
    {$ifend}
  Result := ERR_get_state;
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_ERR_get_next_error_library: TOpenSSL_C_INT; cdecl;
begin
  ERR_get_next_error_library := LoadLibCryptoFunction('ERR_get_next_error_library');
  if not assigned(ERR_get_next_error_library) then
    {$if declared(LEGACY_ERR_get_next_error_library)}
    ERR_get_next_error_library := @LEGACY_ERR_get_next_error_library;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_next_error_library');
    {$ifend}
  Result := ERR_get_next_error_library;
end;

function Load_ERR_set_mark: TOpenSSL_C_INT; cdecl;
begin
  ERR_set_mark := LoadLibCryptoFunction('ERR_set_mark');
  if not assigned(ERR_set_mark) then
    {$if declared(LEGACY_ERR_set_mark)}
    ERR_set_mark := @LEGACY_ERR_set_mark;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_set_mark');
    {$ifend}
  Result := ERR_set_mark;
end;

function Load_ERR_pop_to_mark: TOpenSSL_C_INT; cdecl;
begin
  ERR_pop_to_mark := LoadLibCryptoFunction('ERR_pop_to_mark');
  if not assigned(ERR_pop_to_mark) then
    {$if declared(LEGACY_ERR_pop_to_mark)}
    ERR_pop_to_mark := @LEGACY_ERR_pop_to_mark;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_pop_to_mark');
    {$ifend}
  Result := ERR_pop_to_mark;
end;

function Load_ERR_clear_last_mark: TOpenSSL_C_INT; cdecl;
begin
  ERR_clear_last_mark := LoadLibCryptoFunction('ERR_clear_last_mark');
  if not assigned(ERR_clear_last_mark) then
    {$if declared(LEGACY_ERR_clear_last_mark)}
    ERR_clear_last_mark := @LEGACY_ERR_clear_last_mark;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_clear_last_mark');
    {$ifend}
  Result := ERR_clear_last_mark;
end;

procedure Load;
begin
  ERR_set_error := LoadLibCryptoFunction('ERR_set_error');
  ERR_vset_error := LoadLibCryptoFunction('ERR_vset_error');
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_STDIO}
{$endif} { OPENSSL_NO_STDIO}
  ERR_add_error_data := LoadLibCryptoFunction('ERR_add_error_data');
  ERR_add_error_vdata := LoadLibCryptoFunction('ERR_add_error_vdata');
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$ifndef  OPENSSL_NO_DEPRECATED_1_0_0}
{$endif} { OPENSSL_NO_DEPRECATED_1_0_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
end;

procedure Unload;
begin
  ERR_new := Load_ERR_new;
  ERR_set_debug := Load_ERR_set_debug;
  ERR_set_error := nil;
  ERR_vset_error := nil;
  ERR_set_error_data := Load_ERR_set_error_data;
  ERR_get_error := Load_ERR_get_error;
  ERR_get_error_all := Load_ERR_get_error_all;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ERR_get_error_line := Load_ERR_get_error_line;
  ERR_get_error_line_data := Load_ERR_get_error_line_data;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ERR_peek_error := Load_ERR_peek_error;
  ERR_peek_error_line := Load_ERR_peek_error_line;
  ERR_peek_error_func := Load_ERR_peek_error_func;
  ERR_peek_error_data := Load_ERR_peek_error_data;
  ERR_peek_error_all := Load_ERR_peek_error_all;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ERR_peek_error_line_data := Load_ERR_peek_error_line_data;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ERR_peek_last_error := Load_ERR_peek_last_error;
  ERR_peek_last_error_line := Load_ERR_peek_last_error_line;
  ERR_peek_last_error_func := Load_ERR_peek_last_error_func;
  ERR_peek_last_error_data := Load_ERR_peek_last_error_data;
  ERR_peek_last_error_all := Load_ERR_peek_last_error_all;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ERR_peek_last_error_line_data := Load_ERR_peek_last_error_line_data;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ERR_clear_error := Load_ERR_clear_error;
  ERR_error_string := Load_ERR_error_string;
  ERR_error_string_n := Load_ERR_error_string_n;
  ERR_lib_error_string := Load_ERR_lib_error_string;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ERR_func_error_string := Load_ERR_func_error_string;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ERR_reason_error_string := Load_ERR_reason_error_string;
  ERR_print_errors_cb := Load_ERR_print_errors_cb;
{$ifndef  OPENSSL_NO_STDIO}
  ERR_print_errors_fp := Load_ERR_print_errors_fp;
{$endif} { OPENSSL_NO_STDIO}
  ERR_print_errors := Load_ERR_print_errors;
  ERR_add_error_data := nil;
  ERR_add_error_vdata := nil;
  ERR_add_error_txt := Load_ERR_add_error_txt;
  ERR_add_error_mem_bio := Load_ERR_add_error_mem_bio;
  ERR_load_strings := Load_ERR_load_strings;
  ERR_load_strings_const := Load_ERR_load_strings_const;
  ERR_unload_strings := Load_ERR_unload_strings;
{$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  ERR_remove_thread_state := Load_ERR_remove_thread_state;
{$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
{$ifndef  OPENSSL_NO_DEPRECATED_1_0_0}
  ERR_remove_state := Load_ERR_remove_state;
{$endif} { OPENSSL_NO_DEPRECATED_1_0_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ERR_get_state := Load_ERR_get_state;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ERR_get_next_error_library := Load_ERR_get_next_error_library;
  ERR_set_mark := Load_ERR_set_mark;
  ERR_pop_to_mark := Load_ERR_pop_to_mark;
  ERR_clear_last_mark := Load_ERR_clear_last_mark;
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



