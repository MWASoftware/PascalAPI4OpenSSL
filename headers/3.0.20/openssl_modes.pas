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

unit openssl_modes;

{
  Generated from OpenSSL 3.0.20 Header File modes.h - Tue 19 May 14:16:10 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_modes.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types;


{* Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_MODES_H}
  {$define OPENSSL_MODES_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_MODES_H}
  {$endif}

type
  {Auto-generated forward references}
  Pblock128_f = ^Tblock128_f;
  PPblock128_f = ^Pblock128_f;
  Pcbc128_f = ^Tcbc128_f;
  PPcbc128_f = ^Pcbc128_f;
  Pecb128_f = ^Tecb128_f;
  PPecb128_f = ^Pecb128_f;
  Pctr128_f = ^Tctr128_f;
  PPctr128_f = ^Pctr128_f;
  Pccm128_f = ^Tccm128_f;
  PPccm128_f = ^Pccm128_f;
  {end of auto-generated forward references}

  Tblock128_f = procedure(in_: array of byte; out_: array of byte; key: pointer); cdecl;
  Tcbc128_f = procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; enc: TOpenSSL_C_INT); cdecl;
  Tecb128_f = procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; enc: TOpenSSL_C_INT); cdecl;
  Tctr128_f = procedure(in_: Pbyte; out_: Pbyte; blocks: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte); cdecl;
  Tccm128_f = procedure(in_: Pbyte; out_: Pbyte; blocks: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cmac: array of byte); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure CRYPTO_cbc128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_cbc128_encrypt';
  procedure CRYPTO_cbc128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_cbc128_decrypt';
  procedure CRYPTO_ctr128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_ctr128_encrypt';
  procedure CRYPTO_ctr128_encrypt_ctr32(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; ctr: Tctr128_f); cdecl; external CLibCrypto name 'CRYPTO_ctr128_encrypt_ctr32';
  procedure CRYPTO_ofb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_ofb128_encrypt';
  procedure CRYPTO_cfb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_cfb128_encrypt';
  procedure CRYPTO_cfb128_8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_cfb128_8_encrypt';
  procedure CRYPTO_cfb128_1_encrypt(in_: Pbyte; out_: Pbyte; bits: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_cfb128_1_encrypt';
  function CRYPTO_cts128_encrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_cts128_encrypt_block';
  function CRYPTO_cts128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_cts128_encrypt';
  function CRYPTO_cts128_decrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_cts128_decrypt_block';
  function CRYPTO_cts128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_cts128_decrypt';
  function CRYPTO_nistcts128_encrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_nistcts128_encrypt_block';
  function CRYPTO_nistcts128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_nistcts128_encrypt';
  function CRYPTO_nistcts128_decrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_nistcts128_decrypt_block';
  function CRYPTO_nistcts128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_nistcts128_decrypt';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM CRYPTO_cbc128_encrypt}
  {$EXTERNALSYM CRYPTO_cbc128_decrypt}
  {$EXTERNALSYM CRYPTO_ctr128_encrypt}
  {$EXTERNALSYM CRYPTO_ctr128_encrypt_ctr32}
  {$EXTERNALSYM CRYPTO_ofb128_encrypt}
  {$EXTERNALSYM CRYPTO_cfb128_encrypt}
  {$EXTERNALSYM CRYPTO_cfb128_8_encrypt}
  {$EXTERNALSYM CRYPTO_cfb128_1_encrypt}
  {$EXTERNALSYM CRYPTO_cts128_encrypt_block}
  {$EXTERNALSYM CRYPTO_cts128_encrypt}
  {$EXTERNALSYM CRYPTO_cts128_decrypt_block}
  {$EXTERNALSYM CRYPTO_cts128_decrypt}
  {$EXTERNALSYM CRYPTO_nistcts128_encrypt_block}
  {$EXTERNALSYM CRYPTO_nistcts128_encrypt}
  {$EXTERNALSYM CRYPTO_nistcts128_decrypt_block}
  {$EXTERNALSYM CRYPTO_nistcts128_decrypt}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_CRYPTO_cbc128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl;
  procedure Load_CRYPTO_cbc128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl;
  procedure Load_CRYPTO_ctr128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; block: Tblock128_f); cdecl;
  procedure Load_CRYPTO_ctr128_encrypt_ctr32(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; ctr: Tctr128_f); cdecl;
  procedure Load_CRYPTO_ofb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; block: Tblock128_f); cdecl;
  procedure Load_CRYPTO_cfb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl;
  procedure Load_CRYPTO_cfb128_8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl;
  procedure Load_CRYPTO_cfb128_1_encrypt(in_: Pbyte; out_: Pbyte; bits: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl;
  function Load_CRYPTO_cts128_encrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_cts128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_cts128_decrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_cts128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_nistcts128_encrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_nistcts128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_nistcts128_decrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_nistcts128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;

var
  CRYPTO_cbc128_encrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl = Load_CRYPTO_cbc128_encrypt;
  CRYPTO_cbc128_decrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl = Load_CRYPTO_cbc128_decrypt;
  CRYPTO_ctr128_encrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; block: Tblock128_f); cdecl = Load_CRYPTO_ctr128_encrypt;
  CRYPTO_ctr128_encrypt_ctr32: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; ctr: Tctr128_f); cdecl = Load_CRYPTO_ctr128_encrypt_ctr32;
  CRYPTO_ofb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; block: Tblock128_f); cdecl = Load_CRYPTO_ofb128_encrypt;
  CRYPTO_cfb128_encrypt: procedure(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl = Load_CRYPTO_cfb128_encrypt;
  CRYPTO_cfb128_8_encrypt: procedure(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl = Load_CRYPTO_cfb128_8_encrypt;
  CRYPTO_cfb128_1_encrypt: procedure(in_: Pbyte; out_: Pbyte; bits: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl = Load_CRYPTO_cfb128_1_encrypt;
  CRYPTO_cts128_encrypt_block: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_cts128_encrypt_block;
  CRYPTO_cts128_encrypt: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_cts128_encrypt;
  CRYPTO_cts128_decrypt_block: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_cts128_decrypt_block;
  CRYPTO_cts128_decrypt: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_cts128_decrypt;
  CRYPTO_nistcts128_encrypt_block: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_nistcts128_encrypt_block;
  CRYPTO_nistcts128_encrypt: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_nistcts128_encrypt;
  CRYPTO_nistcts128_decrypt_block: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_nistcts128_decrypt_block;
  CRYPTO_nistcts128_decrypt: function(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_nistcts128_decrypt;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PGCM128_CONTEXT = ^TGCM128_CONTEXT;
  PPGCM128_CONTEXT = ^PGCM128_CONTEXT;
  {end of auto-generated forward references}

  TGCM128_CONTEXT = record end;



  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function CRYPTO_gcm128_new(key: pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl; external CLibCrypto name 'CRYPTO_gcm128_new';
  procedure CRYPTO_gcm128_init(ctx: PGCM128_CONTEXT; key: pointer; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_gcm128_init';
  procedure CRYPTO_gcm128_setiv(ctx: PGCM128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET); cdecl; external CLibCrypto name 'CRYPTO_gcm128_setiv';
  function CRYPTO_gcm128_aad(ctx: PGCM128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_gcm128_aad';
  function CRYPTO_gcm128_encrypt(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_gcm128_encrypt';
  function CRYPTO_gcm128_decrypt(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_gcm128_decrypt';
  function CRYPTO_gcm128_encrypt_ctr32(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_gcm128_encrypt_ctr32';
  function CRYPTO_gcm128_decrypt_ctr32(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_gcm128_decrypt_ctr32';
  function CRYPTO_gcm128_finish(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_gcm128_finish';
  procedure CRYPTO_gcm128_tag(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET); cdecl; external CLibCrypto name 'CRYPTO_gcm128_tag';
  procedure CRYPTO_gcm128_release(ctx: PGCM128_CONTEXT); cdecl; external CLibCrypto name 'CRYPTO_gcm128_release';
  {$else}
  {$EXTERNALSYM CRYPTO_gcm128_new}
  {$EXTERNALSYM CRYPTO_gcm128_init}
  {$EXTERNALSYM CRYPTO_gcm128_setiv}
  {$EXTERNALSYM CRYPTO_gcm128_aad}
  {$EXTERNALSYM CRYPTO_gcm128_encrypt}
  {$EXTERNALSYM CRYPTO_gcm128_decrypt}
  {$EXTERNALSYM CRYPTO_gcm128_encrypt_ctr32}
  {$EXTERNALSYM CRYPTO_gcm128_decrypt_ctr32}
  {$EXTERNALSYM CRYPTO_gcm128_finish}
  {$EXTERNALSYM CRYPTO_gcm128_tag}
  {$EXTERNALSYM CRYPTO_gcm128_release}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_CRYPTO_gcm128_new(key: pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl;
  procedure Load_CRYPTO_gcm128_init(ctx: PGCM128_CONTEXT; key: pointer; block: Tblock128_f); cdecl;
  procedure Load_CRYPTO_gcm128_setiv(ctx: PGCM128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET); cdecl;
  function Load_CRYPTO_gcm128_aad(ctx: PGCM128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_gcm128_encrypt(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_gcm128_decrypt(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_gcm128_encrypt_ctr32(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_gcm128_decrypt_ctr32(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_gcm128_finish(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  procedure Load_CRYPTO_gcm128_tag(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET); cdecl;
  procedure Load_CRYPTO_gcm128_release(ctx: PGCM128_CONTEXT); cdecl;

var
  CRYPTO_gcm128_new: function(key: pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl = Load_CRYPTO_gcm128_new;
  CRYPTO_gcm128_init: procedure(ctx: PGCM128_CONTEXT; key: pointer; block: Tblock128_f); cdecl = Load_CRYPTO_gcm128_init;
  CRYPTO_gcm128_setiv: procedure(ctx: PGCM128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET); cdecl = Load_CRYPTO_gcm128_setiv;
  CRYPTO_gcm128_aad: function(ctx: PGCM128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_gcm128_aad;
  CRYPTO_gcm128_encrypt: function(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_gcm128_encrypt;
  CRYPTO_gcm128_decrypt: function(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_gcm128_decrypt;
  CRYPTO_gcm128_encrypt_ctr32: function(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl = Load_CRYPTO_gcm128_encrypt_ctr32;
  CRYPTO_gcm128_decrypt_ctr32: function(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl = Load_CRYPTO_gcm128_decrypt_ctr32;
  CRYPTO_gcm128_finish: function(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_gcm128_finish;
  CRYPTO_gcm128_tag: procedure(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET); cdecl = Load_CRYPTO_gcm128_tag;
  CRYPTO_gcm128_release: procedure(ctx: PGCM128_CONTEXT); cdecl = Load_CRYPTO_gcm128_release;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PCCM128_CONTEXT = ^TCCM128_CONTEXT;
  PPCCM128_CONTEXT = ^PCCM128_CONTEXT;
  {end of auto-generated forward references}

  TCCM128_CONTEXT = record end;



  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure CRYPTO_ccm128_init(ctx: PCCM128_CONTEXT; M: TOpenSSL_C_UINT; L: TOpenSSL_C_UINT; key: pointer; block: Tblock128_f); cdecl; external CLibCrypto name 'CRYPTO_ccm128_init';
  function CRYPTO_ccm128_setiv(ctx: PCCM128_CONTEXT; nonce: Pbyte; nlen: TOpenSSL_C_SIZET; mlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ccm128_setiv';
  procedure CRYPTO_ccm128_aad(ctx: PCCM128_CONTEXT; aad: Pbyte; alen: TOpenSSL_C_SIZET); cdecl; external CLibCrypto name 'CRYPTO_ccm128_aad';
  function CRYPTO_ccm128_encrypt(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ccm128_encrypt';
  function CRYPTO_ccm128_decrypt(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ccm128_decrypt';
  function CRYPTO_ccm128_encrypt_ccm64(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ccm128_encrypt_ccm64';
  function CRYPTO_ccm128_decrypt_ccm64(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ccm128_decrypt_ccm64';
  function CRYPTO_ccm128_tag(ctx: PCCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_ccm128_tag';
  {$else}
  {$EXTERNALSYM CRYPTO_ccm128_init}
  {$EXTERNALSYM CRYPTO_ccm128_setiv}
  {$EXTERNALSYM CRYPTO_ccm128_aad}
  {$EXTERNALSYM CRYPTO_ccm128_encrypt}
  {$EXTERNALSYM CRYPTO_ccm128_decrypt}
  {$EXTERNALSYM CRYPTO_ccm128_encrypt_ccm64}
  {$EXTERNALSYM CRYPTO_ccm128_decrypt_ccm64}
  {$EXTERNALSYM CRYPTO_ccm128_tag}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_CRYPTO_ccm128_init(ctx: PCCM128_CONTEXT; M: TOpenSSL_C_UINT; L: TOpenSSL_C_UINT; key: pointer; block: Tblock128_f); cdecl;
  function Load_CRYPTO_ccm128_setiv(ctx: PCCM128_CONTEXT; nonce: Pbyte; nlen: TOpenSSL_C_SIZET; mlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  procedure Load_CRYPTO_ccm128_aad(ctx: PCCM128_CONTEXT; aad: Pbyte; alen: TOpenSSL_C_SIZET); cdecl;
  function Load_CRYPTO_ccm128_encrypt(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ccm128_decrypt(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ccm128_encrypt_ccm64(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ccm128_decrypt_ccm64(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ccm128_tag(ctx: PCCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;

var
  CRYPTO_ccm128_init: procedure(ctx: PCCM128_CONTEXT; M: TOpenSSL_C_UINT; L: TOpenSSL_C_UINT; key: pointer; block: Tblock128_f); cdecl = Load_CRYPTO_ccm128_init;
  CRYPTO_ccm128_setiv: function(ctx: PCCM128_CONTEXT; nonce: Pbyte; nlen: TOpenSSL_C_SIZET; mlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ccm128_setiv;
  CRYPTO_ccm128_aad: procedure(ctx: PCCM128_CONTEXT; aad: Pbyte; alen: TOpenSSL_C_SIZET); cdecl = Load_CRYPTO_ccm128_aad;
  CRYPTO_ccm128_encrypt: function(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ccm128_encrypt;
  CRYPTO_ccm128_decrypt: function(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ccm128_decrypt;
  CRYPTO_ccm128_encrypt_ccm64: function(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ccm128_encrypt_ccm64;
  CRYPTO_ccm128_decrypt_ccm64: function(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ccm128_decrypt_ccm64;
  CRYPTO_ccm128_tag: function(ctx: PCCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_ccm128_tag;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PXTS128_CONTEXT = ^TXTS128_CONTEXT;
  PPXTS128_CONTEXT = ^PXTS128_CONTEXT;
  {end of auto-generated forward references}

  TXTS128_CONTEXT = record end;



  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function CRYPTO_xts128_encrypt(ctx: PXTS128_CONTEXT; iv: array of byte; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_xts128_encrypt';
  function CRYPTO_128_wrap(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_128_wrap';
  function CRYPTO_128_unwrap(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_128_unwrap';
  function CRYPTO_128_wrap_pad(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_128_wrap_pad';
  function CRYPTO_128_unwrap_pad(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'CRYPTO_128_unwrap_pad';
  {$else}
  {$EXTERNALSYM CRYPTO_xts128_encrypt}
  {$EXTERNALSYM CRYPTO_128_wrap}
  {$EXTERNALSYM CRYPTO_128_unwrap}
  {$EXTERNALSYM CRYPTO_128_wrap_pad}
  {$EXTERNALSYM CRYPTO_128_unwrap_pad}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_CRYPTO_xts128_encrypt(ctx: PXTS128_CONTEXT; iv: array of byte; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_128_wrap(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_128_unwrap(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_128_wrap_pad(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
  function Load_CRYPTO_128_unwrap_pad(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;

var
  CRYPTO_xts128_encrypt: function(ctx: PXTS128_CONTEXT; iv: array of byte; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_CRYPTO_xts128_encrypt;
  CRYPTO_128_wrap: function(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_128_wrap;
  CRYPTO_128_unwrap: function(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_128_unwrap;
  CRYPTO_128_wrap_pad: function(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_128_wrap_pad;
  CRYPTO_128_unwrap_pad: function(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl = Load_CRYPTO_128_unwrap_pad;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_OCB}

type
  {Auto-generated forward references}
  POCB128_CONTEXT = ^TOCB128_CONTEXT;
  PPOCB128_CONTEXT = ^POCB128_CONTEXT;
  PSimpleType0 = ^TSimpleType0;
  PPSimpleType0 = ^PSimpleType0;
  Pocb128_f = ^Tocb128_f;
  PPocb128_f = ^Pocb128_f;
  {end of auto-generated forward references}

  TOCB128_CONTEXT = record end;

  TSimpleType0 = array[0..15] of byte;
  Tocb128_f = procedure(in_: Pbyte; out_: Pbyte; blocks: TOpenSSL_C_SIZET; key: pointer; start_block_num: TOpenSSL_C_SIZET; offset_i: array of byte; L_: PSimpleType0; checksum: array of byte); cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function CRYPTO_ocb128_new(keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_new';
  function CRYPTO_ocb128_init(ctx: POCB128_CONTEXT; keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_init';
  function CRYPTO_ocb128_copy_ctx(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: pointer; keydec: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_copy_ctx';
  function CRYPTO_ocb128_setiv(ctx: POCB128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET; taglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_setiv';
  function CRYPTO_ocb128_aad(ctx: POCB128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_aad';
  function CRYPTO_ocb128_encrypt(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_encrypt';
  function CRYPTO_ocb128_decrypt(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_decrypt';
  function CRYPTO_ocb128_finish(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_finish';
  function CRYPTO_ocb128_tag(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'CRYPTO_ocb128_tag';
  procedure CRYPTO_ocb128_cleanup(ctx: POCB128_CONTEXT); cdecl; external CLibCrypto name 'CRYPTO_ocb128_cleanup';
    {$else}
  {$EXTERNALSYM CRYPTO_ocb128_new}
  {$EXTERNALSYM CRYPTO_ocb128_init}
  {$EXTERNALSYM CRYPTO_ocb128_copy_ctx}
  {$EXTERNALSYM CRYPTO_ocb128_setiv}
  {$EXTERNALSYM CRYPTO_ocb128_aad}
  {$EXTERNALSYM CRYPTO_ocb128_encrypt}
  {$EXTERNALSYM CRYPTO_ocb128_decrypt}
  {$EXTERNALSYM CRYPTO_ocb128_finish}
  {$EXTERNALSYM CRYPTO_ocb128_tag}
  {$EXTERNALSYM CRYPTO_ocb128_cleanup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_CRYPTO_ocb128_new(keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl;
  function Load_CRYPTO_ocb128_init(ctx: POCB128_CONTEXT; keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ocb128_copy_ctx(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: pointer; keydec: pointer): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ocb128_setiv(ctx: POCB128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET; taglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ocb128_aad(ctx: POCB128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ocb128_encrypt(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ocb128_decrypt(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ocb128_finish(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_CRYPTO_ocb128_tag(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  procedure Load_CRYPTO_ocb128_cleanup(ctx: POCB128_CONTEXT); cdecl;

var
  CRYPTO_ocb128_new: function(keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl = Load_CRYPTO_ocb128_new;
  CRYPTO_ocb128_init: function(ctx: POCB128_CONTEXT; keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_init;
  CRYPTO_ocb128_copy_ctx: function(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: pointer; keydec: pointer): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_copy_ctx;
  CRYPTO_ocb128_setiv: function(ctx: POCB128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET; taglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_setiv;
  CRYPTO_ocb128_aad: function(ctx: POCB128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_aad;
  CRYPTO_ocb128_encrypt: function(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_encrypt;
  CRYPTO_ocb128_decrypt: function(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_decrypt;
  CRYPTO_ocb128_finish: function(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_finish;
  CRYPTO_ocb128_tag: function(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_CRYPTO_ocb128_tag;
  CRYPTO_ocb128_cleanup: procedure(ctx: POCB128_CONTEXT); cdecl = Load_CRYPTO_ocb128_cleanup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  { OPENSSL_NO_OCB }
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
procedure Load_CRYPTO_cbc128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl;
begin
  CRYPTO_cbc128_encrypt := LoadLibCryptoFunction('CRYPTO_cbc128_encrypt');
  if not assigned(CRYPTO_cbc128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cbc128_encrypt');
  CRYPTO_cbc128_encrypt(in_, out_, len, key, ivec, block);
end;

procedure Load_CRYPTO_cbc128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f); cdecl;
begin
  CRYPTO_cbc128_decrypt := LoadLibCryptoFunction('CRYPTO_cbc128_decrypt');
  if not assigned(CRYPTO_cbc128_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cbc128_decrypt');
  CRYPTO_cbc128_decrypt(in_, out_, len, key, ivec, block);
end;

procedure Load_CRYPTO_ctr128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; block: Tblock128_f); cdecl;
begin
  CRYPTO_ctr128_encrypt := LoadLibCryptoFunction('CRYPTO_ctr128_encrypt');
  if not assigned(CRYPTO_ctr128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ctr128_encrypt');
  CRYPTO_ctr128_encrypt(in_, out_, len, key, ivec, ecount_buf, num, block);
end;

procedure Load_CRYPTO_ctr128_encrypt_ctr32(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; ecount_buf: array of byte; num: POpenSSL_C_UINT; ctr: Tctr128_f); cdecl;
begin
  CRYPTO_ctr128_encrypt_ctr32 := LoadLibCryptoFunction('CRYPTO_ctr128_encrypt_ctr32');
  if not assigned(CRYPTO_ctr128_encrypt_ctr32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ctr128_encrypt_ctr32');
  CRYPTO_ctr128_encrypt_ctr32(in_, out_, len, key, ivec, ecount_buf, num, ctr);
end;

procedure Load_CRYPTO_ofb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; block: Tblock128_f); cdecl;
begin
  CRYPTO_ofb128_encrypt := LoadLibCryptoFunction('CRYPTO_ofb128_encrypt');
  if not assigned(CRYPTO_ofb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ofb128_encrypt');
  CRYPTO_ofb128_encrypt(in_, out_, len, key, ivec, num, block);
end;

procedure Load_CRYPTO_cfb128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl;
begin
  CRYPTO_cfb128_encrypt := LoadLibCryptoFunction('CRYPTO_cfb128_encrypt');
  if not assigned(CRYPTO_cfb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cfb128_encrypt');
  CRYPTO_cfb128_encrypt(in_, out_, len, key, ivec, num, enc, block);
end;

procedure Load_CRYPTO_cfb128_8_encrypt(in_: Pbyte; out_: Pbyte; length: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl;
begin
  CRYPTO_cfb128_8_encrypt := LoadLibCryptoFunction('CRYPTO_cfb128_8_encrypt');
  if not assigned(CRYPTO_cfb128_8_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cfb128_8_encrypt');
  CRYPTO_cfb128_8_encrypt(in_, out_, length, key, ivec, num, enc, block);
end;

procedure Load_CRYPTO_cfb128_1_encrypt(in_: Pbyte; out_: Pbyte; bits: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; num: POpenSSL_C_INT; enc: TOpenSSL_C_INT; block: Tblock128_f); cdecl;
begin
  CRYPTO_cfb128_1_encrypt := LoadLibCryptoFunction('CRYPTO_cfb128_1_encrypt');
  if not assigned(CRYPTO_cfb128_1_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cfb128_1_encrypt');
  CRYPTO_cfb128_1_encrypt(in_, out_, bits, key, ivec, num, enc, block);
end;

function Load_CRYPTO_cts128_encrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_cts128_encrypt_block := LoadLibCryptoFunction('CRYPTO_cts128_encrypt_block');
  if not assigned(CRYPTO_cts128_encrypt_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cts128_encrypt_block');
  Result := CRYPTO_cts128_encrypt_block(in_, out_, len, key, ivec, block);
end;

function Load_CRYPTO_cts128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_cts128_encrypt := LoadLibCryptoFunction('CRYPTO_cts128_encrypt');
  if not assigned(CRYPTO_cts128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cts128_encrypt');
  Result := CRYPTO_cts128_encrypt(in_, out_, len, key, ivec, cbc);
end;

function Load_CRYPTO_cts128_decrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_cts128_decrypt_block := LoadLibCryptoFunction('CRYPTO_cts128_decrypt_block');
  if not assigned(CRYPTO_cts128_decrypt_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cts128_decrypt_block');
  Result := CRYPTO_cts128_decrypt_block(in_, out_, len, key, ivec, block);
end;

function Load_CRYPTO_cts128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_cts128_decrypt := LoadLibCryptoFunction('CRYPTO_cts128_decrypt');
  if not assigned(CRYPTO_cts128_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_cts128_decrypt');
  Result := CRYPTO_cts128_decrypt(in_, out_, len, key, ivec, cbc);
end;

function Load_CRYPTO_nistcts128_encrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_nistcts128_encrypt_block := LoadLibCryptoFunction('CRYPTO_nistcts128_encrypt_block');
  if not assigned(CRYPTO_nistcts128_encrypt_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_nistcts128_encrypt_block');
  Result := CRYPTO_nistcts128_encrypt_block(in_, out_, len, key, ivec, block);
end;

function Load_CRYPTO_nistcts128_encrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_nistcts128_encrypt := LoadLibCryptoFunction('CRYPTO_nistcts128_encrypt');
  if not assigned(CRYPTO_nistcts128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_nistcts128_encrypt');
  Result := CRYPTO_nistcts128_encrypt(in_, out_, len, key, ivec, cbc);
end;

function Load_CRYPTO_nistcts128_decrypt_block(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_nistcts128_decrypt_block := LoadLibCryptoFunction('CRYPTO_nistcts128_decrypt_block');
  if not assigned(CRYPTO_nistcts128_decrypt_block) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_nistcts128_decrypt_block');
  Result := CRYPTO_nistcts128_decrypt_block(in_, out_, len, key, ivec, block);
end;

function Load_CRYPTO_nistcts128_decrypt(in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; key: pointer; ivec: array of byte; cbc: Tcbc128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_nistcts128_decrypt := LoadLibCryptoFunction('CRYPTO_nistcts128_decrypt');
  if not assigned(CRYPTO_nistcts128_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_nistcts128_decrypt');
  Result := CRYPTO_nistcts128_decrypt(in_, out_, len, key, ivec, cbc);
end;

function Load_CRYPTO_gcm128_new(key: pointer; block: Tblock128_f): PGCM128_CONTEXT; cdecl;
begin
  CRYPTO_gcm128_new := LoadLibCryptoFunction('CRYPTO_gcm128_new');
  if not assigned(CRYPTO_gcm128_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_new');
  Result := CRYPTO_gcm128_new(key, block);
end;

procedure Load_CRYPTO_gcm128_init(ctx: PGCM128_CONTEXT; key: pointer; block: Tblock128_f); cdecl;
begin
  CRYPTO_gcm128_init := LoadLibCryptoFunction('CRYPTO_gcm128_init');
  if not assigned(CRYPTO_gcm128_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_init');
  CRYPTO_gcm128_init(ctx, key, block);
end;

procedure Load_CRYPTO_gcm128_setiv(ctx: PGCM128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET); cdecl;
begin
  CRYPTO_gcm128_setiv := LoadLibCryptoFunction('CRYPTO_gcm128_setiv');
  if not assigned(CRYPTO_gcm128_setiv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_setiv');
  CRYPTO_gcm128_setiv(ctx, iv, len);
end;

function Load_CRYPTO_gcm128_aad(ctx: PGCM128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_gcm128_aad := LoadLibCryptoFunction('CRYPTO_gcm128_aad');
  if not assigned(CRYPTO_gcm128_aad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_aad');
  Result := CRYPTO_gcm128_aad(ctx, aad, len);
end;

function Load_CRYPTO_gcm128_encrypt(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_gcm128_encrypt := LoadLibCryptoFunction('CRYPTO_gcm128_encrypt');
  if not assigned(CRYPTO_gcm128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_encrypt');
  Result := CRYPTO_gcm128_encrypt(ctx, in_, out_, len);
end;

function Load_CRYPTO_gcm128_decrypt(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_gcm128_decrypt := LoadLibCryptoFunction('CRYPTO_gcm128_decrypt');
  if not assigned(CRYPTO_gcm128_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_decrypt');
  Result := CRYPTO_gcm128_decrypt(ctx, in_, out_, len);
end;

function Load_CRYPTO_gcm128_encrypt_ctr32(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_gcm128_encrypt_ctr32 := LoadLibCryptoFunction('CRYPTO_gcm128_encrypt_ctr32');
  if not assigned(CRYPTO_gcm128_encrypt_ctr32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_encrypt_ctr32');
  Result := CRYPTO_gcm128_encrypt_ctr32(ctx, in_, out_, len, stream);
end;

function Load_CRYPTO_gcm128_decrypt_ctr32(ctx: PGCM128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tctr128_f): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_gcm128_decrypt_ctr32 := LoadLibCryptoFunction('CRYPTO_gcm128_decrypt_ctr32');
  if not assigned(CRYPTO_gcm128_decrypt_ctr32) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_decrypt_ctr32');
  Result := CRYPTO_gcm128_decrypt_ctr32(ctx, in_, out_, len, stream);
end;

function Load_CRYPTO_gcm128_finish(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_gcm128_finish := LoadLibCryptoFunction('CRYPTO_gcm128_finish');
  if not assigned(CRYPTO_gcm128_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_finish');
  Result := CRYPTO_gcm128_finish(ctx, tag, len);
end;

procedure Load_CRYPTO_gcm128_tag(ctx: PGCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET); cdecl;
begin
  CRYPTO_gcm128_tag := LoadLibCryptoFunction('CRYPTO_gcm128_tag');
  if not assigned(CRYPTO_gcm128_tag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_tag');
  CRYPTO_gcm128_tag(ctx, tag, len);
end;

procedure Load_CRYPTO_gcm128_release(ctx: PGCM128_CONTEXT); cdecl;
begin
  CRYPTO_gcm128_release := LoadLibCryptoFunction('CRYPTO_gcm128_release');
  if not assigned(CRYPTO_gcm128_release) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_gcm128_release');
  CRYPTO_gcm128_release(ctx);
end;

procedure Load_CRYPTO_ccm128_init(ctx: PCCM128_CONTEXT; M: TOpenSSL_C_UINT; L: TOpenSSL_C_UINT; key: pointer; block: Tblock128_f); cdecl;
begin
  CRYPTO_ccm128_init := LoadLibCryptoFunction('CRYPTO_ccm128_init');
  if not assigned(CRYPTO_ccm128_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_init');
  CRYPTO_ccm128_init(ctx, M, L, key, block);
end;

function Load_CRYPTO_ccm128_setiv(ctx: PCCM128_CONTEXT; nonce: Pbyte; nlen: TOpenSSL_C_SIZET; mlen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ccm128_setiv := LoadLibCryptoFunction('CRYPTO_ccm128_setiv');
  if not assigned(CRYPTO_ccm128_setiv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_setiv');
  Result := CRYPTO_ccm128_setiv(ctx, nonce, nlen, mlen);
end;

procedure Load_CRYPTO_ccm128_aad(ctx: PCCM128_CONTEXT; aad: Pbyte; alen: TOpenSSL_C_SIZET); cdecl;
begin
  CRYPTO_ccm128_aad := LoadLibCryptoFunction('CRYPTO_ccm128_aad');
  if not assigned(CRYPTO_ccm128_aad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_aad');
  CRYPTO_ccm128_aad(ctx, aad, alen);
end;

function Load_CRYPTO_ccm128_encrypt(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ccm128_encrypt := LoadLibCryptoFunction('CRYPTO_ccm128_encrypt');
  if not assigned(CRYPTO_ccm128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_encrypt');
  Result := CRYPTO_ccm128_encrypt(ctx, inp, out_, len);
end;

function Load_CRYPTO_ccm128_decrypt(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ccm128_decrypt := LoadLibCryptoFunction('CRYPTO_ccm128_decrypt');
  if not assigned(CRYPTO_ccm128_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_decrypt');
  Result := CRYPTO_ccm128_decrypt(ctx, inp, out_, len);
end;

function Load_CRYPTO_ccm128_encrypt_ccm64(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ccm128_encrypt_ccm64 := LoadLibCryptoFunction('CRYPTO_ccm128_encrypt_ccm64');
  if not assigned(CRYPTO_ccm128_encrypt_ccm64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_encrypt_ccm64');
  Result := CRYPTO_ccm128_encrypt_ccm64(ctx, inp, out_, len, stream);
end;

function Load_CRYPTO_ccm128_decrypt_ccm64(ctx: PCCM128_CONTEXT; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; stream: Tccm128_f): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ccm128_decrypt_ccm64 := LoadLibCryptoFunction('CRYPTO_ccm128_decrypt_ccm64');
  if not assigned(CRYPTO_ccm128_decrypt_ccm64) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_decrypt_ccm64');
  Result := CRYPTO_ccm128_decrypt_ccm64(ctx, inp, out_, len, stream);
end;

function Load_CRYPTO_ccm128_tag(ctx: PCCM128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_ccm128_tag := LoadLibCryptoFunction('CRYPTO_ccm128_tag');
  if not assigned(CRYPTO_ccm128_tag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ccm128_tag');
  Result := CRYPTO_ccm128_tag(ctx, tag, len);
end;

function Load_CRYPTO_xts128_encrypt(ctx: PXTS128_CONTEXT; iv: array of byte; inp: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET; enc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_xts128_encrypt := LoadLibCryptoFunction('CRYPTO_xts128_encrypt');
  if not assigned(CRYPTO_xts128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_xts128_encrypt');
  Result := CRYPTO_xts128_encrypt(ctx, iv, inp, out_, len, enc);
end;

function Load_CRYPTO_128_wrap(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_128_wrap := LoadLibCryptoFunction('CRYPTO_128_wrap');
  if not assigned(CRYPTO_128_wrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_128_wrap');
  Result := CRYPTO_128_wrap(key, iv, out_, in_, inlen, block);
end;

function Load_CRYPTO_128_unwrap(key: pointer; iv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_128_unwrap := LoadLibCryptoFunction('CRYPTO_128_unwrap');
  if not assigned(CRYPTO_128_unwrap) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_128_unwrap');
  Result := CRYPTO_128_unwrap(key, iv, out_, in_, inlen, block);
end;

function Load_CRYPTO_128_wrap_pad(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_128_wrap_pad := LoadLibCryptoFunction('CRYPTO_128_wrap_pad');
  if not assigned(CRYPTO_128_wrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_128_wrap_pad');
  Result := CRYPTO_128_wrap_pad(key, icv, out_, in_, inlen, block);
end;

function Load_CRYPTO_128_unwrap_pad(key: pointer; icv: Pbyte; out_: Pbyte; in_: Pbyte; inlen: TOpenSSL_C_SIZET; block: Tblock128_f): TOpenSSL_C_SIZET; cdecl;
begin
  CRYPTO_128_unwrap_pad := LoadLibCryptoFunction('CRYPTO_128_unwrap_pad');
  if not assigned(CRYPTO_128_unwrap_pad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_128_unwrap_pad');
  Result := CRYPTO_128_unwrap_pad(key, icv, out_, in_, inlen, block);
end;

{$ifndef  OPENSSL_NO_OCB}
function Load_CRYPTO_ocb128_new(keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): POCB128_CONTEXT; cdecl;
begin
  CRYPTO_ocb128_new := LoadLibCryptoFunction('CRYPTO_ocb128_new');
  if not assigned(CRYPTO_ocb128_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_new');
  Result := CRYPTO_ocb128_new(keyenc, keydec, encrypt, decrypt, stream);
end;

function Load_CRYPTO_ocb128_init(ctx: POCB128_CONTEXT; keyenc: pointer; keydec: pointer; encrypt: Tblock128_f; decrypt: Tblock128_f; stream: Tocb128_f): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_init := LoadLibCryptoFunction('CRYPTO_ocb128_init');
  if not assigned(CRYPTO_ocb128_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_init');
  Result := CRYPTO_ocb128_init(ctx, keyenc, keydec, encrypt, decrypt, stream);
end;

function Load_CRYPTO_ocb128_copy_ctx(dest: POCB128_CONTEXT; src: POCB128_CONTEXT; keyenc: pointer; keydec: pointer): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_copy_ctx := LoadLibCryptoFunction('CRYPTO_ocb128_copy_ctx');
  if not assigned(CRYPTO_ocb128_copy_ctx) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_copy_ctx');
  Result := CRYPTO_ocb128_copy_ctx(dest, src, keyenc, keydec);
end;

function Load_CRYPTO_ocb128_setiv(ctx: POCB128_CONTEXT; iv: Pbyte; len: TOpenSSL_C_SIZET; taglen: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_setiv := LoadLibCryptoFunction('CRYPTO_ocb128_setiv');
  if not assigned(CRYPTO_ocb128_setiv) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_setiv');
  Result := CRYPTO_ocb128_setiv(ctx, iv, len, taglen);
end;

function Load_CRYPTO_ocb128_aad(ctx: POCB128_CONTEXT; aad: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_aad := LoadLibCryptoFunction('CRYPTO_ocb128_aad');
  if not assigned(CRYPTO_ocb128_aad) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_aad');
  Result := CRYPTO_ocb128_aad(ctx, aad, len);
end;

function Load_CRYPTO_ocb128_encrypt(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_encrypt := LoadLibCryptoFunction('CRYPTO_ocb128_encrypt');
  if not assigned(CRYPTO_ocb128_encrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_encrypt');
  Result := CRYPTO_ocb128_encrypt(ctx, in_, out_, len);
end;

function Load_CRYPTO_ocb128_decrypt(ctx: POCB128_CONTEXT; in_: Pbyte; out_: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_decrypt := LoadLibCryptoFunction('CRYPTO_ocb128_decrypt');
  if not assigned(CRYPTO_ocb128_decrypt) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_decrypt');
  Result := CRYPTO_ocb128_decrypt(ctx, in_, out_, len);
end;

function Load_CRYPTO_ocb128_finish(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_finish := LoadLibCryptoFunction('CRYPTO_ocb128_finish');
  if not assigned(CRYPTO_ocb128_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_finish');
  Result := CRYPTO_ocb128_finish(ctx, tag, len);
end;

function Load_CRYPTO_ocb128_tag(ctx: POCB128_CONTEXT; tag: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  CRYPTO_ocb128_tag := LoadLibCryptoFunction('CRYPTO_ocb128_tag');
  if not assigned(CRYPTO_ocb128_tag) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_tag');
  Result := CRYPTO_ocb128_tag(ctx, tag, len);
end;

procedure Load_CRYPTO_ocb128_cleanup(ctx: POCB128_CONTEXT); cdecl;
begin
  CRYPTO_ocb128_cleanup := LoadLibCryptoFunction('CRYPTO_ocb128_cleanup');
  if not assigned(CRYPTO_ocb128_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('CRYPTO_ocb128_cleanup');
  CRYPTO_ocb128_cleanup(ctx);
end;

{$endif} { OPENSSL_NO_OCB}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  CRYPTO_cbc128_encrypt := Load_CRYPTO_cbc128_encrypt;
  CRYPTO_cbc128_decrypt := Load_CRYPTO_cbc128_decrypt;
  CRYPTO_ctr128_encrypt := Load_CRYPTO_ctr128_encrypt;
  CRYPTO_ctr128_encrypt_ctr32 := Load_CRYPTO_ctr128_encrypt_ctr32;
  CRYPTO_ofb128_encrypt := Load_CRYPTO_ofb128_encrypt;
  CRYPTO_cfb128_encrypt := Load_CRYPTO_cfb128_encrypt;
  CRYPTO_cfb128_8_encrypt := Load_CRYPTO_cfb128_8_encrypt;
  CRYPTO_cfb128_1_encrypt := Load_CRYPTO_cfb128_1_encrypt;
  CRYPTO_cts128_encrypt_block := Load_CRYPTO_cts128_encrypt_block;
  CRYPTO_cts128_encrypt := Load_CRYPTO_cts128_encrypt;
  CRYPTO_cts128_decrypt_block := Load_CRYPTO_cts128_decrypt_block;
  CRYPTO_cts128_decrypt := Load_CRYPTO_cts128_decrypt;
  CRYPTO_nistcts128_encrypt_block := Load_CRYPTO_nistcts128_encrypt_block;
  CRYPTO_nistcts128_encrypt := Load_CRYPTO_nistcts128_encrypt;
  CRYPTO_nistcts128_decrypt_block := Load_CRYPTO_nistcts128_decrypt_block;
  CRYPTO_nistcts128_decrypt := Load_CRYPTO_nistcts128_decrypt;
  CRYPTO_gcm128_new := Load_CRYPTO_gcm128_new;
  CRYPTO_gcm128_init := Load_CRYPTO_gcm128_init;
  CRYPTO_gcm128_setiv := Load_CRYPTO_gcm128_setiv;
  CRYPTO_gcm128_aad := Load_CRYPTO_gcm128_aad;
  CRYPTO_gcm128_encrypt := Load_CRYPTO_gcm128_encrypt;
  CRYPTO_gcm128_decrypt := Load_CRYPTO_gcm128_decrypt;
  CRYPTO_gcm128_encrypt_ctr32 := Load_CRYPTO_gcm128_encrypt_ctr32;
  CRYPTO_gcm128_decrypt_ctr32 := Load_CRYPTO_gcm128_decrypt_ctr32;
  CRYPTO_gcm128_finish := Load_CRYPTO_gcm128_finish;
  CRYPTO_gcm128_tag := Load_CRYPTO_gcm128_tag;
  CRYPTO_gcm128_release := Load_CRYPTO_gcm128_release;
  CRYPTO_ccm128_init := Load_CRYPTO_ccm128_init;
  CRYPTO_ccm128_setiv := Load_CRYPTO_ccm128_setiv;
  CRYPTO_ccm128_aad := Load_CRYPTO_ccm128_aad;
  CRYPTO_ccm128_encrypt := Load_CRYPTO_ccm128_encrypt;
  CRYPTO_ccm128_decrypt := Load_CRYPTO_ccm128_decrypt;
  CRYPTO_ccm128_encrypt_ccm64 := Load_CRYPTO_ccm128_encrypt_ccm64;
  CRYPTO_ccm128_decrypt_ccm64 := Load_CRYPTO_ccm128_decrypt_ccm64;
  CRYPTO_ccm128_tag := Load_CRYPTO_ccm128_tag;
  CRYPTO_xts128_encrypt := Load_CRYPTO_xts128_encrypt;
  CRYPTO_128_wrap := Load_CRYPTO_128_wrap;
  CRYPTO_128_unwrap := Load_CRYPTO_128_unwrap;
  CRYPTO_128_wrap_pad := Load_CRYPTO_128_wrap_pad;
  CRYPTO_128_unwrap_pad := Load_CRYPTO_128_unwrap_pad;
{$ifndef  OPENSSL_NO_OCB}
  CRYPTO_ocb128_new := Load_CRYPTO_ocb128_new;
  CRYPTO_ocb128_init := Load_CRYPTO_ocb128_init;
  CRYPTO_ocb128_copy_ctx := Load_CRYPTO_ocb128_copy_ctx;
  CRYPTO_ocb128_setiv := Load_CRYPTO_ocb128_setiv;
  CRYPTO_ocb128_aad := Load_CRYPTO_ocb128_aad;
  CRYPTO_ocb128_encrypt := Load_CRYPTO_ocb128_encrypt;
  CRYPTO_ocb128_decrypt := Load_CRYPTO_ocb128_decrypt;
  CRYPTO_ocb128_finish := Load_CRYPTO_ocb128_finish;
  CRYPTO_ocb128_tag := Load_CRYPTO_ocb128_tag;
  CRYPTO_ocb128_cleanup := Load_CRYPTO_ocb128_cleanup;
{$endif} { OPENSSL_NO_OCB}
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



