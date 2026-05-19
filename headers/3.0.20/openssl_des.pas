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

unit openssl_des;

{
  Generated from OpenSSL 3.0.20 Header File des.h - Tue 19 May 14:15:50 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_des.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2;


{* Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_DES_H}
  {$define OPENSSL_DES_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_DES_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_DES}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PDES_LONG = ^TDES_LONG;
  PPDES_LONG = ^PDES_LONG;
  {end of auto-generated forward references}

  TDES_LONG = TOpenSSL_C_UINT;
      {$ifdef OPENSSL_BUILD_SHLIBCRYPTO}
        {$undef  OPENSSL_EXTERN}

const
  OPENSSL_EXTERN = OPENSSL_EXPORT;
      {$endif}

type
  {Auto-generated forward references}
  PDES_cblock = ^TDES_cblock;
  PPDES_cblock = ^PDES_cblock;
  Pconst_DES_cblock = ^Tconst_DES_cblock;
  PPconst_DES_cblock = ^Pconst_DES_cblock;
  PDES_ks = ^TDES_ks;
  PPDES_ks = ^PDES_ks;
  PDES_key_schedule = ^TDES_key_schedule;
  PPDES_key_schedule = ^PDES_key_schedule;
  {end of auto-generated forward references}

  TDES_cblock = array[0..7] of byte;
      { const }
  Tconst_DES_cblock = array[0..7] of byte;
      
      {* With "const", gcc 2.8.1 on Solaris thinks that DES_cblock * and
      * const_DES_cblock * are incompatible pointer types.
      }
  TDES_ks = record 
    ks: array[0..15] of record case integer of 0: (cblock: TDES_cblock); 1: (deslong: array[0..1] of TDES_LONG);  end;
  end;
  TDES_key_schedule = TDES_ks;
  {# define  DES_KEY_SZ (sizeof(DES_cblock))} {Macro Return Type unknown}
  {# define  DES_SCHEDULE_SZ (sizeof(DES_key_schedule))} {Macro Return Type unknown}

const
  DES_ENCRYPT = 1;
  DES_DECRYPT = 0;
  DES_CBC_MODE = 0;
  DES_PCBC_MODE = 1;


  procedure DES_ecb2_encrypt(i:Pconst_DES_cblock; o:PDES_cblock; k1:PDES_key_schedule; k2:PDES_key_schedule; e:TOpenSSL_C_INT); inline;
  procedure DES_ede2_cbc_encrypt(i:Pbyte; o:Pbyte; l:TOpenSSL_C_INT; k1:PDES_key_schedule; k2:PDES_key_schedule; iv:PDES_cblock; e:TOpenSSL_C_INT); inline;
  procedure DES_ede2_cfb64_encrypt(i:Pbyte; o:Pbyte; l:TOpenSSL_C_INT; k1:PDES_key_schedule; k2:PDES_key_schedule; iv:PDES_cblock; n:POpenSSL_C_INT; e:TOpenSSL_C_INT); inline;
  procedure DES_ede2_ofb64_encrypt(i:Pbyte; o:Pbyte; l:TOpenSSL_C_INT; k1:PDES_key_schedule; k2:PDES_key_schedule; iv:PDES_cblock; n:POpenSSL_C_INT); inline;
      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure DES_fixup_key_parity(key: PDES_cblock); cdecl; external CLibCrypto name 'DES_set_odd_parity'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM DES_fixup_key_parity}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_DES_fixup_key_parity(key: PDES_cblock); cdecl;

var
  DES_fixup_key_parity: procedure(key: PDES_cblock); cdecl = Load_DES_fixup_key_parity;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DES_options: PAnsiChar; cdecl; external CLibCrypto name 'DES_options'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ecb3_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ecb3_encrypt'; deprecated 'Since OpenSSL 3.0';
  function DES_cbc_cksum(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl; external CLibCrypto name 'DES_cbc_cksum'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DES_options}
  {$EXTERNALSYM DES_ecb3_encrypt}
  {$EXTERNALSYM DES_cbc_cksum}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DES_options: PAnsiChar; cdecl;
  procedure Load_DES_ecb3_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;
  function Load_DES_cbc_cksum(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl;

var
  DES_options: function: PAnsiChar; cdecl = Load_DES_options;
  DES_ecb3_encrypt: procedure(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl = Load_DES_ecb3_encrypt;
  DES_cbc_cksum: function(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl = Load_DES_cbc_cksum;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { DES_cbc_encrypt does not update the IV!  Use DES_ncbc_encrypt instead. }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure DES_cbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ncbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ncbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_xcbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_xcbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_cfb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ecb_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ecb_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DES_cbc_encrypt}
  {$EXTERNALSYM DES_ncbc_encrypt}
  {$EXTERNALSYM DES_xcbc_encrypt}
  {$EXTERNALSYM DES_cfb_encrypt}
  {$EXTERNALSYM DES_ecb_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_DES_cbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_ncbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_xcbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_ecb_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;

var
  DES_cbc_encrypt: procedure(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl = Load_DES_cbc_encrypt;
  DES_ncbc_encrypt: procedure(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl = Load_DES_ncbc_encrypt;
  DES_xcbc_encrypt: procedure(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TOpenSSL_C_INT); cdecl = Load_DES_xcbc_encrypt;
  DES_cfb_encrypt: procedure(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl = Load_DES_cfb_encrypt;
  DES_ecb_encrypt: procedure(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl = Load_DES_ecb_encrypt;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* This is the DES encryption function that gets called by just about every
    * other DES routine in the library.  You should not use this function except
    * to implement 'modes' of DES.  I say this because the functions that call
    * this routine do the conversion from 'char *' to long, and this needs to be
    * done to make sure 'non-aligned' memory access do not occur.  The
    * characters are loaded 'little endian'. Data is a pointer to 2 unsigned
    * long's and ks is the DES_key_schedule to use.  enc, is non zero specifies
    * encryption, zero if decryption.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_encrypt1'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DES_encrypt1}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;

var
  DES_encrypt1: procedure(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl = Load_DES_encrypt1;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* This functions is the same as DES_encrypt1() except that the DES initial
    * permutation (IP) and final permutation (FP) have been left out.  As for
    * DES_encrypt1(), you should not use this function. It is used by the
    * routines in the library that implement triple DES. IP() DES_encrypt2()
    * DES_encrypt2() DES_encrypt2() FP() is the same as DES_encrypt1()
    * DES_encrypt1() DES_encrypt1() except faster :-).
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_encrypt2'; deprecated 'Since OpenSSL 3.0';
  procedure DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl; external CLibCrypto name 'DES_encrypt3'; deprecated 'Since OpenSSL 3.0';
  procedure DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl; external CLibCrypto name 'DES_decrypt3'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ede3_cbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ede3_cbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ede3_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ede3_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ede3_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ede3_cfb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ede3_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ede3_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  function DES_fcrypt(buf: PAnsiChar; salt: PAnsiChar; ret: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto name 'DES_fcrypt'; deprecated 'Since OpenSSL 3.0';
  function DES_crypt(buf: PAnsiChar; salt: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto name 'DES_crypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ofb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl; external CLibCrypto name 'DES_ofb_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_pcbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_pcbc_encrypt'; deprecated 'Since OpenSSL 3.0';
  function DES_quad_cksum(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; out_count: TOpenSSL_C_INT; seed: PDES_cblock): TDES_LONG; cdecl; external CLibCrypto name 'DES_quad_cksum'; deprecated 'Since OpenSSL 3.0';
  function DES_random_key(ret: PDES_cblock): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DES_random_key'; deprecated 'Since OpenSSL 3.0';
  procedure DES_set_odd_parity(key: PDES_cblock); cdecl; external CLibCrypto name 'DES_set_odd_parity'; deprecated 'Since OpenSSL 3.0';
  function DES_check_key_parity(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DES_check_key_parity'; deprecated 'Since OpenSSL 3.0';
  function DES_is_weak_key(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DES_is_weak_key'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DES_encrypt2}
  {$EXTERNALSYM DES_encrypt3}
  {$EXTERNALSYM DES_decrypt3}
  {$EXTERNALSYM DES_ede3_cbc_encrypt}
  {$EXTERNALSYM DES_ede3_cfb64_encrypt}
  {$EXTERNALSYM DES_ede3_cfb_encrypt}
  {$EXTERNALSYM DES_ede3_ofb64_encrypt}
  {$EXTERNALSYM DES_fcrypt}
  {$EXTERNALSYM DES_crypt}
  {$EXTERNALSYM DES_ofb_encrypt}
  {$EXTERNALSYM DES_pcbc_encrypt}
  {$EXTERNALSYM DES_quad_cksum}
  {$EXTERNALSYM DES_random_key}
  {$EXTERNALSYM DES_set_odd_parity}
  {$EXTERNALSYM DES_check_key_parity}
  {$EXTERNALSYM DES_is_weak_key}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl;
  procedure Load_DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl;
  procedure Load_DES_ede3_cbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_ede3_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_ede3_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_ede3_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl;
  function Load_DES_fcrypt(buf: PAnsiChar; salt: PAnsiChar; ret: PAnsiChar): PAnsiChar; cdecl;
  function Load_DES_crypt(buf: PAnsiChar; salt: PAnsiChar): PAnsiChar; cdecl;
  procedure Load_DES_ofb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl;
  procedure Load_DES_pcbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
  function Load_DES_quad_cksum(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; out_count: TOpenSSL_C_INT; seed: PDES_cblock): TDES_LONG; cdecl;
  function Load_DES_random_key(ret: PDES_cblock): TOpenSSL_C_INT; cdecl;
  procedure Load_DES_set_odd_parity(key: PDES_cblock); cdecl;
  function Load_DES_check_key_parity(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl;
  function Load_DES_is_weak_key(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl;

var
  DES_encrypt2: procedure(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl = Load_DES_encrypt2;
  DES_encrypt3: procedure(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl = Load_DES_encrypt3;
  DES_decrypt3: procedure(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl = Load_DES_decrypt3;
  DES_ede3_cbc_encrypt: procedure(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl = Load_DES_ede3_cbc_encrypt;
  DES_ede3_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_DES_ede3_cfb64_encrypt;
  DES_ede3_cfb_encrypt: procedure(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl = Load_DES_ede3_cfb_encrypt;
  DES_ede3_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl = Load_DES_ede3_ofb64_encrypt;
  DES_fcrypt: function(buf: PAnsiChar; salt: PAnsiChar; ret: PAnsiChar): PAnsiChar; cdecl = Load_DES_fcrypt;
  DES_crypt: function(buf: PAnsiChar; salt: PAnsiChar): PAnsiChar; cdecl = Load_DES_crypt;
  DES_ofb_encrypt: procedure(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl = Load_DES_ofb_encrypt;
  DES_pcbc_encrypt: procedure(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl = Load_DES_pcbc_encrypt;
  DES_quad_cksum: function(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; out_count: TOpenSSL_C_INT; seed: PDES_cblock): TDES_LONG; cdecl = Load_DES_quad_cksum;
  DES_random_key: function(ret: PDES_cblock): TOpenSSL_C_INT; cdecl = Load_DES_random_key;
  DES_set_odd_parity: procedure(key: PDES_cblock); cdecl = Load_DES_set_odd_parity;
  DES_check_key_parity: function(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl = Load_DES_check_key_parity;
  DES_is_weak_key: function(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl = Load_DES_is_weak_key;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* DES_set_key (= set_key = DES_key_sched = key_sched) calls
    * DES_set_key_checked
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function DES_set_key(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DES_set_key'; deprecated 'Since OpenSSL 3.0';
  function DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DES_key_sched'; deprecated 'Since OpenSSL 3.0';
  function DES_set_key_checked(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'DES_set_key_checked'; deprecated 'Since OpenSSL 3.0';
  procedure DES_set_key_unchecked(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl; external CLibCrypto name 'DES_set_key_unchecked'; deprecated 'Since OpenSSL 3.0';
  procedure DES_string_to_key(str: PAnsiChar; key: PDES_cblock); cdecl; external CLibCrypto name 'DES_string_to_key'; deprecated 'Since OpenSSL 3.0';
  procedure DES_string_to_2keys(str: PAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl; external CLibCrypto name 'DES_string_to_2keys'; deprecated 'Since OpenSSL 3.0';
  procedure DES_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_cfb64_encrypt'; deprecated 'Since OpenSSL 3.0';
  procedure DES_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl; external CLibCrypto name 'DES_ofb64_encrypt'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM DES_set_key}
  {$EXTERNALSYM DES_key_sched}
  {$EXTERNALSYM DES_set_key_checked}
  {$EXTERNALSYM DES_set_key_unchecked}
  {$EXTERNALSYM DES_string_to_key}
  {$EXTERNALSYM DES_string_to_2keys}
  {$EXTERNALSYM DES_cfb64_encrypt}
  {$EXTERNALSYM DES_ofb64_encrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_DES_set_key(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl;
  function Load_DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl;
  function Load_DES_set_key_checked(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl;
  procedure Load_DES_set_key_unchecked(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl;
  procedure Load_DES_string_to_key(str: PAnsiChar; key: PDES_cblock); cdecl;
  procedure Load_DES_string_to_2keys(str: PAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl;
  procedure Load_DES_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
  procedure Load_DES_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl;

var
  DES_set_key: function(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl = Load_DES_set_key;
  DES_key_sched: function(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl = Load_DES_key_sched;
  DES_set_key_checked: function(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl = Load_DES_set_key_checked;
  DES_set_key_unchecked: procedure(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl = Load_DES_set_key_unchecked;
  DES_string_to_key: procedure(str: PAnsiChar; key: PDES_cblock); cdecl = Load_DES_string_to_key;
  DES_string_to_2keys: procedure(str: PAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl = Load_DES_string_to_2keys;
  DES_cfb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl = Load_DES_cfb64_encrypt;
  DES_ofb64_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl = Load_DES_ofb64_encrypt;
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

{$ifndef  OPENSSL_NO_DES}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

{# define  DES_ecb2_encrypt(i,o,k1,k2,e) DES_ecb3_encrypt((i), (o), (k1), (k2), (k1), (e))}

procedure DES_ecb2_encrypt(i:Pconst_DES_cblock; o:PDES_cblock; k1:PDES_key_schedule; k2:PDES_key_schedule; e:TOpenSSL_C_INT);
begin
  DES_ecb3_encrypt(i,o,k1,k2,k1,e);
end;

{# define  DES_ede2_cbc_encrypt(i,o,l,k1,k2,iv,e) DES_ede3_cbc_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (e))}

procedure DES_ede2_cbc_encrypt(i:Pbyte; o:Pbyte; l:TOpenSSL_C_INT; k1:PDES_key_schedule; k2:PDES_key_schedule; iv:PDES_cblock; e:TOpenSSL_C_INT);
begin
  DES_ede3_cbc_encrypt(i,o,l,k1,k2,k1,iv,e);
end;

{# define  DES_ede2_cfb64_encrypt(i,o,l,k1,k2,iv,n,e) DES_ede3_cfb64_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (n), (e))}

procedure DES_ede2_cfb64_encrypt(i:Pbyte; o:Pbyte; l:TOpenSSL_C_INT; k1:PDES_key_schedule; k2:PDES_key_schedule; iv:PDES_cblock; n:POpenSSL_C_INT; e:TOpenSSL_C_INT);
begin
  DES_ede3_cfb64_encrypt(i,o,l,k1,k2,k1,iv,n,e);
end;

{# define  DES_ede2_ofb64_encrypt(i,o,l,k1,k2,iv,n) DES_ede3_ofb64_encrypt((i), (o), (l), (k1), (k2), (k1), (iv), (n))}

procedure DES_ede2_ofb64_encrypt(i:Pbyte; o:Pbyte; l:TOpenSSL_C_INT; k1:PDES_key_schedule; k2:PDES_key_schedule; iv:PDES_cblock; n:POpenSSL_C_INT);
begin
  DES_ede3_ofb64_encrypt(i,o,l,k1,k2,k1,iv,n);
end;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DES}
{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef  OPENSSL_NO_DES}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_DES_fixup_key_parity(key: PDES_cblock); cdecl;
begin
  DES_fixup_key_parity := LoadLibCryptoFunction('DES_set_odd_parity');
  if not assigned(DES_fixup_key_parity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_odd_parity');
  DES_fixup_key_parity(key);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_DES_options: PAnsiChar; cdecl;
begin
  DES_options := LoadLibCryptoFunction('DES_options');
  if not assigned(DES_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_options');
  Result := DES_options;
end;

procedure Load_DES_ecb3_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_ecb3_encrypt := LoadLibCryptoFunction('DES_ecb3_encrypt');
  if not assigned(DES_ecb3_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ecb3_encrypt');
  DES_ecb3_encrypt(input, output, ks1, ks2, ks3, enc);
end;

function Load_DES_cbc_cksum(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: Pconst_DES_cblock): TDES_LONG; cdecl;
begin
  DES_cbc_cksum := LoadLibCryptoFunction('DES_cbc_cksum');
  if not assigned(DES_cbc_cksum) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cbc_cksum');
  Result := DES_cbc_cksum(input, output, length, schedule, ivec);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_DES_cbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_cbc_encrypt := LoadLibCryptoFunction('DES_cbc_encrypt');
  if not assigned(DES_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cbc_encrypt');
  DES_cbc_encrypt(input, output, length, schedule, ivec, enc);
end;

procedure Load_DES_ncbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_ncbc_encrypt := LoadLibCryptoFunction('DES_ncbc_encrypt');
  if not assigned(DES_ncbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ncbc_encrypt');
  DES_ncbc_encrypt(input, output, length, schedule, ivec, enc);
end;

procedure Load_DES_xcbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; inw: Pconst_DES_cblock; outw: Pconst_DES_cblock; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_xcbc_encrypt := LoadLibCryptoFunction('DES_xcbc_encrypt');
  if not assigned(DES_xcbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_xcbc_encrypt');
  DES_xcbc_encrypt(input, output, length, schedule, ivec, inw, outw, enc);
end;

procedure Load_DES_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_cfb_encrypt := LoadLibCryptoFunction('DES_cfb_encrypt');
  if not assigned(DES_cfb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cfb_encrypt');
  DES_cfb_encrypt(in_, out_, numbits, length, schedule, ivec, enc);
end;

procedure Load_DES_ecb_encrypt(input: Pconst_DES_cblock; output: PDES_cblock; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_ecb_encrypt := LoadLibCryptoFunction('DES_ecb_encrypt');
  if not assigned(DES_ecb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ecb_encrypt');
  DES_ecb_encrypt(input, output, ks, enc);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_DES_encrypt1(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_encrypt1 := LoadLibCryptoFunction('DES_encrypt1');
  if not assigned(DES_encrypt1) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt1');
  DES_encrypt1(data, ks, enc);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_DES_encrypt2(data: PDES_LONG; ks: PDES_key_schedule; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_encrypt2 := LoadLibCryptoFunction('DES_encrypt2');
  if not assigned(DES_encrypt2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt2');
  DES_encrypt2(data, ks, enc);
end;

procedure Load_DES_encrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl;
begin
  DES_encrypt3 := LoadLibCryptoFunction('DES_encrypt3');
  if not assigned(DES_encrypt3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_encrypt3');
  DES_encrypt3(data, ks1, ks2, ks3);
end;

procedure Load_DES_decrypt3(data: PDES_LONG; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule); cdecl;
begin
  DES_decrypt3 := LoadLibCryptoFunction('DES_decrypt3');
  if not assigned(DES_decrypt3) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_decrypt3');
  DES_decrypt3(data, ks1, ks2, ks3);
end;

procedure Load_DES_ede3_cbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_ede3_cbc_encrypt := LoadLibCryptoFunction('DES_ede3_cbc_encrypt');
  if not assigned(DES_ede3_cbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cbc_encrypt');
  DES_ede3_cbc_encrypt(input, output, length, ks1, ks2, ks3, ivec, enc);
end;

procedure Load_DES_ede3_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_ede3_cfb64_encrypt := LoadLibCryptoFunction('DES_ede3_cfb64_encrypt');
  if not assigned(DES_ede3_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cfb64_encrypt');
  DES_ede3_cfb64_encrypt(in_, out_, length, ks1, ks2, ks3, ivec, num, enc);
end;

procedure Load_DES_ede3_cfb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_ede3_cfb_encrypt := LoadLibCryptoFunction('DES_ede3_cfb_encrypt');
  if not assigned(DES_ede3_cfb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_cfb_encrypt');
  DES_ede3_cfb_encrypt(in_, out_, numbits, length, ks1, ks2, ks3, ivec, enc);
end;

procedure Load_DES_ede3_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; ks1: PDES_key_schedule; ks2: PDES_key_schedule; ks3: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl;
begin
  DES_ede3_ofb64_encrypt := LoadLibCryptoFunction('DES_ede3_ofb64_encrypt');
  if not assigned(DES_ede3_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ede3_ofb64_encrypt');
  DES_ede3_ofb64_encrypt(in_, out_, length, ks1, ks2, ks3, ivec, num);
end;

function Load_DES_fcrypt(buf: PAnsiChar; salt: PAnsiChar; ret: PAnsiChar): PAnsiChar; cdecl;
begin
  DES_fcrypt := LoadLibCryptoFunction('DES_fcrypt');
  if not assigned(DES_fcrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_fcrypt');
  Result := DES_fcrypt(buf, salt, ret);
end;

function Load_DES_crypt(buf: PAnsiChar; salt: PAnsiChar): PAnsiChar; cdecl;
begin
  DES_crypt := LoadLibCryptoFunction('DES_crypt');
  if not assigned(DES_crypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_crypt');
  Result := DES_crypt(buf, salt);
end;

procedure Load_DES_ofb_encrypt(in_: Pbyte; out_: Pbyte; numbits: TOpenSSL_C_INT; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock); cdecl;
begin
  DES_ofb_encrypt := LoadLibCryptoFunction('DES_ofb_encrypt');
  if not assigned(DES_ofb_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ofb_encrypt');
  DES_ofb_encrypt(in_, out_, numbits, length, schedule, ivec);
end;

procedure Load_DES_pcbc_encrypt(input: Pbyte; output: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_pcbc_encrypt := LoadLibCryptoFunction('DES_pcbc_encrypt');
  if not assigned(DES_pcbc_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_pcbc_encrypt');
  DES_pcbc_encrypt(input, output, length, schedule, ivec, enc);
end;

function Load_DES_quad_cksum(input: Pbyte; output: PDES_cblock; length: TOpenSSL_C_INT; out_count: TOpenSSL_C_INT; seed: PDES_cblock): TDES_LONG; cdecl;
begin
  DES_quad_cksum := LoadLibCryptoFunction('DES_quad_cksum');
  if not assigned(DES_quad_cksum) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_quad_cksum');
  Result := DES_quad_cksum(input, output, length, out_count, seed);
end;

function Load_DES_random_key(ret: PDES_cblock): TOpenSSL_C_INT; cdecl;
begin
  DES_random_key := LoadLibCryptoFunction('DES_random_key');
  if not assigned(DES_random_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_random_key');
  Result := DES_random_key(ret);
end;

procedure Load_DES_set_odd_parity(key: PDES_cblock); cdecl;
begin
  DES_set_odd_parity := LoadLibCryptoFunction('DES_set_odd_parity');
  if not assigned(DES_set_odd_parity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_odd_parity');
  DES_set_odd_parity(key);
end;

function Load_DES_check_key_parity(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl;
begin
  DES_check_key_parity := LoadLibCryptoFunction('DES_check_key_parity');
  if not assigned(DES_check_key_parity) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_check_key_parity');
  Result := DES_check_key_parity(key);
end;

function Load_DES_is_weak_key(key: Pconst_DES_cblock): TOpenSSL_C_INT; cdecl;
begin
  DES_is_weak_key := LoadLibCryptoFunction('DES_is_weak_key');
  if not assigned(DES_is_weak_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_is_weak_key');
  Result := DES_is_weak_key(key);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_DES_set_key(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl;
begin
  DES_set_key := LoadLibCryptoFunction('DES_set_key');
  if not assigned(DES_set_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_key');
  Result := DES_set_key(key, schedule);
end;

function Load_DES_key_sched(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl;
begin
  DES_key_sched := LoadLibCryptoFunction('DES_key_sched');
  if not assigned(DES_key_sched) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_key_sched');
  Result := DES_key_sched(key, schedule);
end;

function Load_DES_set_key_checked(key: Pconst_DES_cblock; schedule: PDES_key_schedule): TOpenSSL_C_INT; cdecl;
begin
  DES_set_key_checked := LoadLibCryptoFunction('DES_set_key_checked');
  if not assigned(DES_set_key_checked) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_key_checked');
  Result := DES_set_key_checked(key, schedule);
end;

procedure Load_DES_set_key_unchecked(key: Pconst_DES_cblock; schedule: PDES_key_schedule); cdecl;
begin
  DES_set_key_unchecked := LoadLibCryptoFunction('DES_set_key_unchecked');
  if not assigned(DES_set_key_unchecked) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_set_key_unchecked');
  DES_set_key_unchecked(key, schedule);
end;

procedure Load_DES_string_to_key(str: PAnsiChar; key: PDES_cblock); cdecl;
begin
  DES_string_to_key := LoadLibCryptoFunction('DES_string_to_key');
  if not assigned(DES_string_to_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_string_to_key');
  DES_string_to_key(str, key);
end;

procedure Load_DES_string_to_2keys(str: PAnsiChar; key1: PDES_cblock; key2: PDES_cblock); cdecl;
begin
  DES_string_to_2keys := LoadLibCryptoFunction('DES_string_to_2keys');
  if not assigned(DES_string_to_2keys) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_string_to_2keys');
  DES_string_to_2keys(str, key1, key2);
end;

procedure Load_DES_cfb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT); cdecl;
begin
  DES_cfb64_encrypt := LoadLibCryptoFunction('DES_cfb64_encrypt');
  if not assigned(DES_cfb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_cfb64_encrypt');
  DES_cfb64_encrypt(in_, out_, length, schedule, ivec, num, enc);
end;

procedure Load_DES_ofb64_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_INT; schedule: PDES_key_schedule; ivec: PDES_cblock; num: POpenSSL_C_INT); cdecl;
begin
  DES_ofb64_encrypt := LoadLibCryptoFunction('DES_ofb64_encrypt');
  if not assigned(DES_ofb64_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('DES_ofb64_encrypt');
  DES_ofb64_encrypt(in_, out_, length, schedule, ivec, num);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DES}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_DES}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DES_fixup_key_parity := Load_DES_fixup_key_parity;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DES_options := Load_DES_options;
  DES_ecb3_encrypt := Load_DES_ecb3_encrypt;
  DES_cbc_cksum := Load_DES_cbc_cksum;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DES_cbc_encrypt := Load_DES_cbc_encrypt;
  DES_ncbc_encrypt := Load_DES_ncbc_encrypt;
  DES_xcbc_encrypt := Load_DES_xcbc_encrypt;
  DES_cfb_encrypt := Load_DES_cfb_encrypt;
  DES_ecb_encrypt := Load_DES_ecb_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DES_encrypt1 := Load_DES_encrypt1;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DES_encrypt2 := Load_DES_encrypt2;
  DES_encrypt3 := Load_DES_encrypt3;
  DES_decrypt3 := Load_DES_decrypt3;
  DES_ede3_cbc_encrypt := Load_DES_ede3_cbc_encrypt;
  DES_ede3_cfb64_encrypt := Load_DES_ede3_cfb64_encrypt;
  DES_ede3_cfb_encrypt := Load_DES_ede3_cfb_encrypt;
  DES_ede3_ofb64_encrypt := Load_DES_ede3_ofb64_encrypt;
  DES_fcrypt := Load_DES_fcrypt;
  DES_crypt := Load_DES_crypt;
  DES_ofb_encrypt := Load_DES_ofb_encrypt;
  DES_pcbc_encrypt := Load_DES_pcbc_encrypt;
  DES_quad_cksum := Load_DES_quad_cksum;
  DES_random_key := Load_DES_random_key;
  DES_set_odd_parity := Load_DES_set_odd_parity;
  DES_check_key_parity := Load_DES_check_key_parity;
  DES_is_weak_key := Load_DES_is_weak_key;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  DES_set_key := Load_DES_set_key;
  DES_key_sched := Load_DES_key_sched;
  DES_set_key_checked := Load_DES_set_key_checked;
  DES_set_key_unchecked := Load_DES_set_key_unchecked;
  DES_string_to_key := Load_DES_string_to_key;
  DES_string_to_2keys := Load_DES_string_to_2keys;
  DES_cfb64_encrypt := Load_DES_cfb64_encrypt;
  DES_ofb64_encrypt := Load_DES_ofb64_encrypt;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DES}
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



