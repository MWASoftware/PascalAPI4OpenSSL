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

unit openssl_ts;

{
  Generated from OpenSSL 3.0.20 Header File ts.h - Tue 19 May 14:16:49 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_ts.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_pkcs7,openssl_symhacks,openssl_buffer,
     openssl_evp,openssl_bio,openssl_asn1,openssl_safestack,openssl_rsa,openssl_dsa,
     openssl_dh,openssl_tserr,openssl_ess,openssl_x509,openssl_x509v3;


{* Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_TS_H}
  {$define OPENSSL_TS_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_TS_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_TS}

type
  {Auto-generated forward references}
  PTS_msg_imprint_st = ^TTS_MSG_IMPRINT;
  PPTS_msg_imprint_st = ^PTS_msg_imprint_st;
  PTS_MSG_IMPRINT = ^TTS_MSG_IMPRINT;
  PPTS_MSG_IMPRINT = ^PTS_MSG_IMPRINT;
  PTS_req_st = ^TTS_REQ;
  PPTS_req_st = ^PTS_req_st;
  PTS_REQ = ^TTS_REQ;
  PPTS_REQ = ^PTS_REQ;
  PTS_accuracy_st = ^TTS_ACCURACY;
  PPTS_accuracy_st = ^PTS_accuracy_st;
  PTS_ACCURACY = ^TTS_ACCURACY;
  PPTS_ACCURACY = ^PTS_ACCURACY;
  PTS_tst_info_st = ^TTS_TST_INFO;
  PPTS_tst_info_st = ^PTS_tst_info_st;
  PTS_TST_INFO = ^TTS_TST_INFO;
  PPTS_TST_INFO = ^PTS_TST_INFO;
  {end of auto-generated forward references}

  TTS_msg_imprint_st = record end;
  TTS_MSG_IMPRINT = TTS_msg_imprint_st;
  TTS_req_st = record end;
  TTS_REQ = TTS_req_st;
  TTS_accuracy_st = record end;
  TTS_ACCURACY = TTS_accuracy_st;
  TTS_tst_info_st = record end;
  TTS_TST_INFO = TTS_tst_info_st;

const
    { Possible values for status. }
  TS_STATUS_GRANTED = 0;
  TS_STATUS_GRANTED_WITH_MODS = 1;
  TS_STATUS_REJECTION = 2;
  TS_STATUS_WAITING = 3;
  TS_STATUS_REVOCATION_WARNING = 4;
  TS_STATUS_REVOCATION_NOTIFICATION = 5;
    { Possible values for failure_info. }
  TS_INFO_BAD_ALG = 0;
  TS_INFO_BAD_REQUEST = 2;
  TS_INFO_BAD_DATA_FORMAT = 5;
  TS_INFO_TIME_NOT_AVAILABLE = 14;
  TS_INFO_UNACCEPTED_POLICY = 15;
  TS_INFO_UNACCEPTED_EXTENSION = 16;
  TS_INFO_ADD_INFO_NOT_AVAILABLE = 17;
  TS_INFO_SYSTEM_FAILURE = 25;

type
  {Auto-generated forward references}
  PTS_status_info_st = ^TTS_STATUS_INFO;
  PPTS_status_info_st = ^PTS_status_info_st;
  PTS_STATUS_INFO = ^TTS_STATUS_INFO;
  PPTS_STATUS_INFO = ^PTS_STATUS_INFO;
  PTS_resp_st = ^TTS_RESP;
  PPTS_resp_st = ^PTS_resp_st;
  PTS_RESP = ^TTS_RESP;
  PPTS_RESP = ^PTS_RESP;
  {end of auto-generated forward references}

  TTS_status_info_st = record end;
  TTS_STATUS_INFO = TTS_status_info_st;
  TTS_resp_st = record end;
  TTS_RESP = TTS_resp_st;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TS_REQ_new: PTS_REQ; cdecl; external CLibCrypto name 'TS_REQ_new';
  procedure TS_REQ_free(a: PTS_REQ); cdecl; external CLibCrypto name 'TS_REQ_free';
  function d2i_TS_REQ(a: PPTS_REQ; in_: PPbyte; len: TOpenSSL_C_INT): PTS_REQ; cdecl; external CLibCrypto name 'd2i_TS_REQ';
  function i2d_TS_REQ(a: PTS_REQ; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_REQ';
  function TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl; external CLibCrypto name 'TS_REQ_dup';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM TS_REQ_new}
  {$EXTERNALSYM TS_REQ_free}
  {$EXTERNALSYM d2i_TS_REQ}
  {$EXTERNALSYM i2d_TS_REQ}
  {$EXTERNALSYM TS_REQ_dup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TS_REQ_new: PTS_REQ; cdecl;
  procedure Load_TS_REQ_free(a: PTS_REQ); cdecl;
  function Load_d2i_TS_REQ(a: PPTS_REQ; in_: PPbyte; len: TOpenSSL_C_INT): PTS_REQ; cdecl;
  function Load_i2d_TS_REQ(a: PTS_REQ; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl;

var
  TS_REQ_new: function: PTS_REQ; cdecl = Load_TS_REQ_new;
  TS_REQ_free: procedure(a: PTS_REQ); cdecl = Load_TS_REQ_free;
  d2i_TS_REQ: function(a: PPTS_REQ; in_: PPbyte; len: TOpenSSL_C_INT): PTS_REQ; cdecl = Load_d2i_TS_REQ;
  i2d_TS_REQ: function(a: PTS_REQ; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_REQ;
  TS_REQ_dup: function(a: PTS_REQ): PTS_REQ; cdecl = Load_TS_REQ_dup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_STDIO}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_REQ_fp(fp: PFILE; a: PPTS_REQ): PTS_REQ; cdecl; external CLibCrypto name 'd2i_TS_REQ_fp';
  function i2d_TS_REQ_fp(fp: PFILE; a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_REQ_fp';
      {$else}
  {$EXTERNALSYM d2i_TS_REQ_fp}
  {$EXTERNALSYM i2d_TS_REQ_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_REQ_fp(fp: PFILE; a: PPTS_REQ): PTS_REQ; cdecl;
  function Load_i2d_TS_REQ_fp(fp: PFILE; a: PTS_REQ): TOpenSSL_C_INT; cdecl;

var
  d2i_TS_REQ_fp: function(fp: PFILE; a: PPTS_REQ): PTS_REQ; cdecl = Load_d2i_TS_REQ_fp;
  i2d_TS_REQ_fp: function(fp: PFILE; a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_i2d_TS_REQ_fp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl; external CLibCrypto name 'd2i_TS_REQ_bio';
  function i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_REQ_bio';
  function TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_new';
  procedure TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_free';
  function d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; in_: PPbyte; len: TOpenSSL_C_INT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto name 'd2i_TS_MSG_IMPRINT';
  function i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_MSG_IMPRINT';
  function TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_dup';
    {$else}
  {$EXTERNALSYM d2i_TS_REQ_bio}
  {$EXTERNALSYM i2d_TS_REQ_bio}
  {$EXTERNALSYM TS_MSG_IMPRINT_new}
  {$EXTERNALSYM TS_MSG_IMPRINT_free}
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT}
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT}
  {$EXTERNALSYM TS_MSG_IMPRINT_dup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl;
  function Load_i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
  function Load_TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl;
  procedure Load_TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl;
  function Load_d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; in_: PPbyte; len: TOpenSSL_C_INT): PTS_MSG_IMPRINT; cdecl;
  function Load_i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;

var
  d2i_TS_REQ_bio: function(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl = Load_d2i_TS_REQ_bio;
  i2d_TS_REQ_bio: function(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_i2d_TS_REQ_bio;
  TS_MSG_IMPRINT_new: function: PTS_MSG_IMPRINT; cdecl = Load_TS_MSG_IMPRINT_new;
  TS_MSG_IMPRINT_free: procedure(a: PTS_MSG_IMPRINT); cdecl = Load_TS_MSG_IMPRINT_free;
  d2i_TS_MSG_IMPRINT: function(a: PPTS_MSG_IMPRINT; in_: PPbyte; len: TOpenSSL_C_INT): PTS_MSG_IMPRINT; cdecl = Load_d2i_TS_MSG_IMPRINT;
  i2d_TS_MSG_IMPRINT: function(a: PTS_MSG_IMPRINT; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_MSG_IMPRINT;
  TS_MSG_IMPRINT_dup: function(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = Load_TS_MSG_IMPRINT_dup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_STDIO}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_MSG_IMPRINT_fp(fp: PFILE; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto name 'd2i_TS_MSG_IMPRINT_fp';
  function i2d_TS_MSG_IMPRINT_fp(fp: PFILE; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_MSG_IMPRINT_fp';
      {$else}
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT_fp}
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_MSG_IMPRINT_fp(fp: PFILE; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
  function Load_i2d_TS_MSG_IMPRINT_fp(fp: PFILE; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;

var
  d2i_TS_MSG_IMPRINT_fp: function(fp: PFILE; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = Load_d2i_TS_MSG_IMPRINT_fp;
  i2d_TS_MSG_IMPRINT_fp: function(fp: PFILE; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_i2d_TS_MSG_IMPRINT_fp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto name 'd2i_TS_MSG_IMPRINT_bio';
  function i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_MSG_IMPRINT_bio';
  function TS_RESP_new: PTS_RESP; cdecl; external CLibCrypto name 'TS_RESP_new';
  procedure TS_RESP_free(a: PTS_RESP); cdecl; external CLibCrypto name 'TS_RESP_free';
  function d2i_TS_RESP(a: PPTS_RESP; in_: PPbyte; len: TOpenSSL_C_INT): PTS_RESP; cdecl; external CLibCrypto name 'd2i_TS_RESP';
  function i2d_TS_RESP(a: PTS_RESP; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_RESP';
  function TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl; external CLibCrypto name 'TS_RESP_dup';
    {$else}
  {$EXTERNALSYM d2i_TS_MSG_IMPRINT_bio}
  {$EXTERNALSYM i2d_TS_MSG_IMPRINT_bio}
  {$EXTERNALSYM TS_RESP_new}
  {$EXTERNALSYM TS_RESP_free}
  {$EXTERNALSYM d2i_TS_RESP}
  {$EXTERNALSYM i2d_TS_RESP}
  {$EXTERNALSYM TS_RESP_dup}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
  function Load_i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_new: PTS_RESP; cdecl;
  procedure Load_TS_RESP_free(a: PTS_RESP); cdecl;
  function Load_d2i_TS_RESP(a: PPTS_RESP; in_: PPbyte; len: TOpenSSL_C_INT): PTS_RESP; cdecl;
  function Load_i2d_TS_RESP(a: PTS_RESP; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl;

var
  d2i_TS_MSG_IMPRINT_bio: function(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = Load_d2i_TS_MSG_IMPRINT_bio;
  i2d_TS_MSG_IMPRINT_bio: function(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_i2d_TS_MSG_IMPRINT_bio;
  TS_RESP_new: function: PTS_RESP; cdecl = Load_TS_RESP_new;
  TS_RESP_free: procedure(a: PTS_RESP); cdecl = Load_TS_RESP_free;
  d2i_TS_RESP: function(a: PPTS_RESP; in_: PPbyte; len: TOpenSSL_C_INT): PTS_RESP; cdecl = Load_d2i_TS_RESP;
  i2d_TS_RESP: function(a: PTS_RESP; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_RESP;
  TS_RESP_dup: function(a: PTS_RESP): PTS_RESP; cdecl = Load_TS_RESP_dup;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_STDIO}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_RESP_fp(fp: PFILE; a: PPTS_RESP): PTS_RESP; cdecl; external CLibCrypto name 'd2i_TS_RESP_fp';
  function i2d_TS_RESP_fp(fp: PFILE; a: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_RESP_fp';
      {$else}
  {$EXTERNALSYM d2i_TS_RESP_fp}
  {$EXTERNALSYM i2d_TS_RESP_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_RESP_fp(fp: PFILE; a: PPTS_RESP): PTS_RESP; cdecl;
  function Load_i2d_TS_RESP_fp(fp: PFILE; a: PTS_RESP): TOpenSSL_C_INT; cdecl;

var
  d2i_TS_RESP_fp: function(fp: PFILE; a: PPTS_RESP): PTS_RESP; cdecl = Load_d2i_TS_RESP_fp;
  i2d_TS_RESP_fp: function(fp: PFILE; a: PTS_RESP): TOpenSSL_C_INT; cdecl = Load_i2d_TS_RESP_fp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl; external CLibCrypto name 'd2i_TS_RESP_bio';
  function i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_RESP_bio';
  function TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl; external CLibCrypto name 'TS_STATUS_INFO_new';
  procedure TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl; external CLibCrypto name 'TS_STATUS_INFO_free';
  function d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_STATUS_INFO; cdecl; external CLibCrypto name 'd2i_TS_STATUS_INFO';
  function i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_STATUS_INFO';
  function TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl; external CLibCrypto name 'TS_STATUS_INFO_dup';
  function TS_TST_INFO_new: PTS_TST_INFO; cdecl; external CLibCrypto name 'TS_TST_INFO_new';
  procedure TS_TST_INFO_free(a: PTS_TST_INFO); cdecl; external CLibCrypto name 'TS_TST_INFO_free';
  function d2i_TS_TST_INFO(a: PPTS_TST_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_TST_INFO; cdecl; external CLibCrypto name 'd2i_TS_TST_INFO';
  function i2d_TS_TST_INFO(a: PTS_TST_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_TST_INFO';
  function TS_TST_INFO_dup(a: PTS_TST_INFO): PTS_TST_INFO; cdecl; external CLibCrypto name 'TS_TST_INFO_dup';
  function PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_INFO; cdecl; external CLibCrypto name 'PKCS7_to_TS_TST_INFO';
    {$else}
  {$EXTERNALSYM d2i_TS_RESP_bio}
  {$EXTERNALSYM i2d_TS_RESP_bio}
  {$EXTERNALSYM TS_STATUS_INFO_new}
  {$EXTERNALSYM TS_STATUS_INFO_free}
  {$EXTERNALSYM d2i_TS_STATUS_INFO}
  {$EXTERNALSYM i2d_TS_STATUS_INFO}
  {$EXTERNALSYM TS_STATUS_INFO_dup}
  {$EXTERNALSYM TS_TST_INFO_new}
  {$EXTERNALSYM TS_TST_INFO_free}
  {$EXTERNALSYM d2i_TS_TST_INFO}
  {$EXTERNALSYM i2d_TS_TST_INFO}
  {$EXTERNALSYM TS_TST_INFO_dup}
  {$EXTERNALSYM PKCS7_to_TS_TST_INFO}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl;
  function Load_i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
  function Load_TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl;
  procedure Load_TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl;
  function Load_d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_STATUS_INFO; cdecl;
  function Load_i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl;
  function Load_TS_TST_INFO_new: PTS_TST_INFO; cdecl;
  procedure Load_TS_TST_INFO_free(a: PTS_TST_INFO); cdecl;
  function Load_d2i_TS_TST_INFO(a: PPTS_TST_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_TST_INFO; cdecl;
  function Load_i2d_TS_TST_INFO(a: PTS_TST_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_dup(a: PTS_TST_INFO): PTS_TST_INFO; cdecl;
  function Load_PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_INFO; cdecl;

var
  d2i_TS_RESP_bio: function(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl = Load_d2i_TS_RESP_bio;
  i2d_TS_RESP_bio: function(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl = Load_i2d_TS_RESP_bio;
  TS_STATUS_INFO_new: function: PTS_STATUS_INFO; cdecl = Load_TS_STATUS_INFO_new;
  TS_STATUS_INFO_free: procedure(a: PTS_STATUS_INFO); cdecl = Load_TS_STATUS_INFO_free;
  d2i_TS_STATUS_INFO: function(a: PPTS_STATUS_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_STATUS_INFO; cdecl = Load_d2i_TS_STATUS_INFO;
  i2d_TS_STATUS_INFO: function(a: PTS_STATUS_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_STATUS_INFO;
  TS_STATUS_INFO_dup: function(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl = Load_TS_STATUS_INFO_dup;
  TS_TST_INFO_new: function: PTS_TST_INFO; cdecl = Load_TS_TST_INFO_new;
  TS_TST_INFO_free: procedure(a: PTS_TST_INFO); cdecl = Load_TS_TST_INFO_free;
  d2i_TS_TST_INFO: function(a: PPTS_TST_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_TST_INFO; cdecl = Load_d2i_TS_TST_INFO;
  i2d_TS_TST_INFO: function(a: PTS_TST_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_TST_INFO;
  TS_TST_INFO_dup: function(a: PTS_TST_INFO): PTS_TST_INFO; cdecl = Load_TS_TST_INFO_dup;
  PKCS7_to_TS_TST_INFO: function(token: PPKCS7): PTS_TST_INFO; cdecl = Load_PKCS7_to_TS_TST_INFO;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_STDIO}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_TST_INFO_fp(fp: PFILE; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl; external CLibCrypto name 'd2i_TS_TST_INFO_fp';
  function i2d_TS_TST_INFO_fp(fp: PFILE; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_TST_INFO_fp';
      {$else}
  {$EXTERNALSYM d2i_TS_TST_INFO_fp}
  {$EXTERNALSYM i2d_TS_TST_INFO_fp}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_TST_INFO_fp(fp: PFILE; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl;
  function Load_i2d_TS_TST_INFO_fp(fp: PFILE; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;

var
  d2i_TS_TST_INFO_fp: function(fp: PFILE; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl = Load_d2i_TS_TST_INFO_fp;
  i2d_TS_TST_INFO_fp: function(fp: PFILE; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl = Load_i2d_TS_TST_INFO_fp;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl; external CLibCrypto name 'd2i_TS_TST_INFO_bio';
  function i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_TST_INFO_bio';
  function TS_ACCURACY_new: PTS_ACCURACY; cdecl; external CLibCrypto name 'TS_ACCURACY_new';
  procedure TS_ACCURACY_free(a: PTS_ACCURACY); cdecl; external CLibCrypto name 'TS_ACCURACY_free';
  function d2i_TS_ACCURACY(a: PPTS_ACCURACY; in_: PPbyte; len: TOpenSSL_C_INT): PTS_ACCURACY; cdecl; external CLibCrypto name 'd2i_TS_ACCURACY';
  function i2d_TS_ACCURACY(a: PTS_ACCURACY; out_: PPbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'i2d_TS_ACCURACY';
  function TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl; external CLibCrypto name 'TS_ACCURACY_dup';
  function TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_set_version';
  function TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_get_version';
  function TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_STATUS_INFO_set_status';
  function TS_STATUS_INFO_get0_status(a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl; external CLibCrypto name 'TS_STATUS_INFO_get0_status';
  function TS_STATUS_INFO_get0_text(a: PTS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl; external CLibCrypto name 'TS_STATUS_INFO_get0_text';
  function TS_STATUS_INFO_get0_failure_info(a: PTS_STATUS_INFO): PASN1_BIT_STRING; cdecl; external CLibCrypto name 'TS_STATUS_INFO_get0_failure_info';
  function TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_set_msg_imprint';
  function TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl; external CLibCrypto name 'TS_REQ_get_msg_imprint';
  function TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_set_algo';
  function TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOR; cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_get_algo';
  function TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_set_msg';
  function TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_get_msg';
  function TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_set_policy_id';
  function TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl; external CLibCrypto name 'TS_REQ_get_policy_id';
  function TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_set_nonce';
  function TS_REQ_get_nonce(a: PTS_REQ): PASN1_INTEGER; cdecl; external CLibCrypto name 'TS_REQ_get_nonce';
  function TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_set_cert_req';
  function TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_get_cert_req';
  function TS_REQ_get_exts(a: PTS_REQ): Pstack_st_X509_EXTENSION; cdecl; external CLibCrypto name 'TS_REQ_get_exts';
  procedure TS_REQ_ext_free(a: PTS_REQ); cdecl; external CLibCrypto name 'TS_REQ_ext_free';
  function TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_get_ext_count';
  function TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_get_ext_by_NID';
  function TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_get_ext_by_OBJ';
  function TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_get_ext_by_critical';
  function TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto name 'TS_REQ_get_ext';
  function TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto name 'TS_REQ_delete_ext';
  function TS_REQ_add_ext(a: PTS_REQ; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_add_ext';
  function TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'TS_REQ_get_ext_d2i';
  { Function declarations for TS_REQ defined in ts/ts_req_print.c }
  function TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_REQ_print_bio';
  { Function declarations for TS_RESP defined in ts/ts_resp_utils.c }
  function TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_set_status_info';
  function TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl; external CLibCrypto name 'TS_RESP_get_status_info';
  { Caller loses ownership of PKCS7 and TS_TST_INFO objects. }
  procedure TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_INFO); cdecl; external CLibCrypto name 'TS_RESP_set_tst_info';
  function TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl; external CLibCrypto name 'TS_RESP_get_token';
  function TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_INFO; cdecl; external CLibCrypto name 'TS_RESP_get_tst_info';
  function TS_TST_INFO_set_version(a: PTS_TST_INFO; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_version';
  function TS_TST_INFO_get_version(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_version';
  function TS_TST_INFO_set_policy_id(a: PTS_TST_INFO; policy_id: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_policy_id';
  function TS_TST_INFO_get_policy_id(a: PTS_TST_INFO): PASN1_OBJECT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_policy_id';
  function TS_TST_INFO_set_msg_imprint(a: PTS_TST_INFO; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_msg_imprint';
  function TS_TST_INFO_get_msg_imprint(a: PTS_TST_INFO): PTS_MSG_IMPRINT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_msg_imprint';
  function TS_TST_INFO_set_serial(a: PTS_TST_INFO; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_serial';
  function TS_TST_INFO_get_serial(a: PTS_TST_INFO): PASN1_INTEGER; cdecl; external CLibCrypto name 'TS_TST_INFO_get_serial';
  function TS_TST_INFO_set_time(a: PTS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_time';
  function TS_TST_INFO_get_time(a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto name 'TS_TST_INFO_get_time';
  function TS_TST_INFO_set_accuracy(a: PTS_TST_INFO; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_accuracy';
  function TS_TST_INFO_get_accuracy(a: PTS_TST_INFO): PTS_ACCURACY; cdecl; external CLibCrypto name 'TS_TST_INFO_get_accuracy';
  function TS_ACCURACY_set_seconds(a: PTS_ACCURACY; seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_ACCURACY_set_seconds';
  function TS_ACCURACY_get_seconds(a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto name 'TS_ACCURACY_get_seconds';
  function TS_ACCURACY_set_millis(a: PTS_ACCURACY; millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_ACCURACY_set_millis';
  function TS_ACCURACY_get_millis(a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto name 'TS_ACCURACY_get_millis';
  function TS_ACCURACY_set_micros(a: PTS_ACCURACY; micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_ACCURACY_set_micros';
  function TS_ACCURACY_get_micros(a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto name 'TS_ACCURACY_get_micros';
  function TS_TST_INFO_set_ordering(a: PTS_TST_INFO; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_ordering';
  function TS_TST_INFO_get_ordering(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_ordering';
  function TS_TST_INFO_set_nonce(a: PTS_TST_INFO; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_nonce';
  function TS_TST_INFO_get_nonce(a: PTS_TST_INFO): PASN1_INTEGER; cdecl; external CLibCrypto name 'TS_TST_INFO_get_nonce';
  function TS_TST_INFO_set_tsa(a: PTS_TST_INFO; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_set_tsa';
  function TS_TST_INFO_get_tsa(a: PTS_TST_INFO): PGENERAL_NAME; cdecl; external CLibCrypto name 'TS_TST_INFO_get_tsa';
  function TS_TST_INFO_get_exts(a: PTS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl; external CLibCrypto name 'TS_TST_INFO_get_exts';
  procedure TS_TST_INFO_ext_free(a: PTS_TST_INFO); cdecl; external CLibCrypto name 'TS_TST_INFO_ext_free';
  function TS_TST_INFO_get_ext_count(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_ext_count';
  function TS_TST_INFO_get_ext_by_NID(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_ext_by_NID';
  function TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_INFO; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_ext_by_OBJ';
  function TS_TST_INFO_get_ext_by_critical(a: PTS_TST_INFO; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_get_ext_by_critical';
  function TS_TST_INFO_get_ext(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto name 'TS_TST_INFO_get_ext';
  function TS_TST_INFO_delete_ext(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl; external CLibCrypto name 'TS_TST_INFO_delete_ext';
  function TS_TST_INFO_add_ext(a: PTS_TST_INFO; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_add_ext';
  function TS_TST_INFO_get_ext_d2i(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'TS_TST_INFO_get_ext_d2i';
  
  {* Declarations related to response generation, defined in ts/ts_resp_sign.c.
  }
  { Optional flags for response generation. }
  { Don't include the TSA name in response. }
    {$else}
  {$EXTERNALSYM d2i_TS_TST_INFO_bio}
  {$EXTERNALSYM i2d_TS_TST_INFO_bio}
  {$EXTERNALSYM TS_ACCURACY_new}
  {$EXTERNALSYM TS_ACCURACY_free}
  {$EXTERNALSYM d2i_TS_ACCURACY}
  {$EXTERNALSYM i2d_TS_ACCURACY}
  {$EXTERNALSYM TS_ACCURACY_dup}
  {$EXTERNALSYM TS_REQ_set_version}
  {$EXTERNALSYM TS_REQ_get_version}
  {$EXTERNALSYM TS_STATUS_INFO_set_status}
  {$EXTERNALSYM TS_STATUS_INFO_get0_status}
  {$EXTERNALSYM TS_STATUS_INFO_get0_text}
  {$EXTERNALSYM TS_STATUS_INFO_get0_failure_info}
  {$EXTERNALSYM TS_REQ_set_msg_imprint}
  {$EXTERNALSYM TS_REQ_get_msg_imprint}
  {$EXTERNALSYM TS_MSG_IMPRINT_set_algo}
  {$EXTERNALSYM TS_MSG_IMPRINT_get_algo}
  {$EXTERNALSYM TS_MSG_IMPRINT_set_msg}
  {$EXTERNALSYM TS_MSG_IMPRINT_get_msg}
  {$EXTERNALSYM TS_REQ_set_policy_id}
  {$EXTERNALSYM TS_REQ_get_policy_id}
  {$EXTERNALSYM TS_REQ_set_nonce}
  {$EXTERNALSYM TS_REQ_get_nonce}
  {$EXTERNALSYM TS_REQ_set_cert_req}
  {$EXTERNALSYM TS_REQ_get_cert_req}
  {$EXTERNALSYM TS_REQ_get_exts}
  {$EXTERNALSYM TS_REQ_ext_free}
  {$EXTERNALSYM TS_REQ_get_ext_count}
  {$EXTERNALSYM TS_REQ_get_ext_by_NID}
  {$EXTERNALSYM TS_REQ_get_ext_by_OBJ}
  {$EXTERNALSYM TS_REQ_get_ext_by_critical}
  {$EXTERNALSYM TS_REQ_get_ext}
  {$EXTERNALSYM TS_REQ_delete_ext}
  {$EXTERNALSYM TS_REQ_add_ext}
  {$EXTERNALSYM TS_REQ_get_ext_d2i}
  {$EXTERNALSYM TS_REQ_print_bio}
  {$EXTERNALSYM TS_RESP_set_status_info}
  {$EXTERNALSYM TS_RESP_get_status_info}
  {$EXTERNALSYM TS_RESP_set_tst_info}
  {$EXTERNALSYM TS_RESP_get_token}
  {$EXTERNALSYM TS_RESP_get_tst_info}
  {$EXTERNALSYM TS_TST_INFO_set_version}
  {$EXTERNALSYM TS_TST_INFO_get_version}
  {$EXTERNALSYM TS_TST_INFO_set_policy_id}
  {$EXTERNALSYM TS_TST_INFO_get_policy_id}
  {$EXTERNALSYM TS_TST_INFO_set_msg_imprint}
  {$EXTERNALSYM TS_TST_INFO_get_msg_imprint}
  {$EXTERNALSYM TS_TST_INFO_set_serial}
  {$EXTERNALSYM TS_TST_INFO_get_serial}
  {$EXTERNALSYM TS_TST_INFO_set_time}
  {$EXTERNALSYM TS_TST_INFO_get_time}
  {$EXTERNALSYM TS_TST_INFO_set_accuracy}
  {$EXTERNALSYM TS_TST_INFO_get_accuracy}
  {$EXTERNALSYM TS_ACCURACY_set_seconds}
  {$EXTERNALSYM TS_ACCURACY_get_seconds}
  {$EXTERNALSYM TS_ACCURACY_set_millis}
  {$EXTERNALSYM TS_ACCURACY_get_millis}
  {$EXTERNALSYM TS_ACCURACY_set_micros}
  {$EXTERNALSYM TS_ACCURACY_get_micros}
  {$EXTERNALSYM TS_TST_INFO_set_ordering}
  {$EXTERNALSYM TS_TST_INFO_get_ordering}
  {$EXTERNALSYM TS_TST_INFO_set_nonce}
  {$EXTERNALSYM TS_TST_INFO_get_nonce}
  {$EXTERNALSYM TS_TST_INFO_set_tsa}
  {$EXTERNALSYM TS_TST_INFO_get_tsa}
  {$EXTERNALSYM TS_TST_INFO_get_exts}
  {$EXTERNALSYM TS_TST_INFO_ext_free}
  {$EXTERNALSYM TS_TST_INFO_get_ext_count}
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_NID}
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_OBJ}
  {$EXTERNALSYM TS_TST_INFO_get_ext_by_critical}
  {$EXTERNALSYM TS_TST_INFO_get_ext}
  {$EXTERNALSYM TS_TST_INFO_delete_ext}
  {$EXTERNALSYM TS_TST_INFO_add_ext}
  {$EXTERNALSYM TS_TST_INFO_get_ext_d2i}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl;
  function Load_i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
  function Load_TS_ACCURACY_new: PTS_ACCURACY; cdecl;
  procedure Load_TS_ACCURACY_free(a: PTS_ACCURACY); cdecl;
  function Load_d2i_TS_ACCURACY(a: PPTS_ACCURACY; in_: PPbyte; len: TOpenSSL_C_INT): PTS_ACCURACY; cdecl;
  function Load_i2d_TS_ACCURACY(a: PTS_ACCURACY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
  function Load_TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl;
  function Load_TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
  function Load_TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_STATUS_INFO_get0_status(a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl;
  function Load_TS_STATUS_INFO_get0_text(a: PTS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl;
  function Load_TS_STATUS_INFO_get0_failure_info(a: PTS_STATUS_INFO): PASN1_BIT_STRING; cdecl;
  function Load_TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl;
  function Load_TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOR; cdecl;
  function Load_TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl;
  function Load_TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl;
  function Load_TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_nonce(a: PTS_REQ): PASN1_INTEGER; cdecl;
  function Load_TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_exts(a: PTS_REQ): Pstack_st_X509_EXTENSION; cdecl;
  procedure Load_TS_REQ_ext_free(a: PTS_REQ); cdecl;
  function Load_TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
  function Load_TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
  function Load_TS_REQ_add_ext(a: PTS_REQ; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl;
  function Load_TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl;
  procedure Load_TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_INFO); cdecl;
  function Load_TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl;
  function Load_TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_INFO; cdecl;
  function Load_TS_TST_INFO_set_version(a: PTS_TST_INFO; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_version(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_set_policy_id(a: PTS_TST_INFO; policy_id: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_policy_id(a: PTS_TST_INFO): PASN1_OBJECT; cdecl;
  function Load_TS_TST_INFO_set_msg_imprint(a: PTS_TST_INFO; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_msg_imprint(a: PTS_TST_INFO): PTS_MSG_IMPRINT; cdecl;
  function Load_TS_TST_INFO_set_serial(a: PTS_TST_INFO; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_serial(a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
  function Load_TS_TST_INFO_set_time(a: PTS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_time(a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl;
  function Load_TS_TST_INFO_set_accuracy(a: PTS_TST_INFO; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_accuracy(a: PTS_TST_INFO): PTS_ACCURACY; cdecl;
  function Load_TS_ACCURACY_set_seconds(a: PTS_ACCURACY; seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
  function Load_TS_ACCURACY_get_seconds(a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
  function Load_TS_ACCURACY_set_millis(a: PTS_ACCURACY; millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
  function Load_TS_ACCURACY_get_millis(a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
  function Load_TS_ACCURACY_set_micros(a: PTS_ACCURACY; micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
  function Load_TS_ACCURACY_get_micros(a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
  function Load_TS_TST_INFO_set_ordering(a: PTS_TST_INFO; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_ordering(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_set_nonce(a: PTS_TST_INFO; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_nonce(a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
  function Load_TS_TST_INFO_set_tsa(a: PTS_TST_INFO; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_tsa(a: PTS_TST_INFO): PGENERAL_NAME; cdecl;
  function Load_TS_TST_INFO_get_exts(a: PTS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl;
  procedure Load_TS_TST_INFO_ext_free(a: PTS_TST_INFO); cdecl;
  function Load_TS_TST_INFO_get_ext_count(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_ext_by_NID(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_INFO; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_ext_by_critical(a: PTS_TST_INFO; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_ext(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
  function Load_TS_TST_INFO_delete_ext(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
  function Load_TS_TST_INFO_add_ext(a: PTS_TST_INFO; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_get_ext_d2i(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl;

var
  d2i_TS_TST_INFO_bio: function(bio: PBIO; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl = Load_d2i_TS_TST_INFO_bio;
  i2d_TS_TST_INFO_bio: function(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl = Load_i2d_TS_TST_INFO_bio;
  TS_ACCURACY_new: function: PTS_ACCURACY; cdecl = Load_TS_ACCURACY_new;
  TS_ACCURACY_free: procedure(a: PTS_ACCURACY); cdecl = Load_TS_ACCURACY_free;
  d2i_TS_ACCURACY: function(a: PPTS_ACCURACY; in_: PPbyte; len: TOpenSSL_C_INT): PTS_ACCURACY; cdecl = Load_d2i_TS_ACCURACY;
  i2d_TS_ACCURACY: function(a: PTS_ACCURACY; out_: PPbyte): TOpenSSL_C_INT; cdecl = Load_i2d_TS_ACCURACY;
  TS_ACCURACY_dup: function(a: PTS_ACCURACY): PTS_ACCURACY; cdecl = Load_TS_ACCURACY_dup;
  TS_REQ_set_version: function(a: PTS_REQ; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_version;
  TS_REQ_get_version: function(a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_version;
  TS_STATUS_INFO_set_status: function(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_STATUS_INFO_set_status;
  TS_STATUS_INFO_get0_status: function(a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl = Load_TS_STATUS_INFO_get0_status;
  TS_STATUS_INFO_get0_text: function(a: PTS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl = Load_TS_STATUS_INFO_get0_text;
  TS_STATUS_INFO_get0_failure_info: function(a: PTS_STATUS_INFO): PASN1_BIT_STRING; cdecl = Load_TS_STATUS_INFO_get0_failure_info;
  TS_REQ_set_msg_imprint: function(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_msg_imprint;
  TS_REQ_get_msg_imprint: function(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl = Load_TS_REQ_get_msg_imprint;
  TS_MSG_IMPRINT_set_algo: function(a: PTS_MSG_IMPRINT; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_TS_MSG_IMPRINT_set_algo;
  TS_MSG_IMPRINT_get_algo: function(a: PTS_MSG_IMPRINT): PX509_ALGOR; cdecl = Load_TS_MSG_IMPRINT_get_algo;
  TS_MSG_IMPRINT_set_msg: function(a: PTS_MSG_IMPRINT; d: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_MSG_IMPRINT_set_msg;
  TS_MSG_IMPRINT_get_msg: function(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl = Load_TS_MSG_IMPRINT_get_msg;
  TS_REQ_set_policy_id: function(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_policy_id;
  TS_REQ_get_policy_id: function(a: PTS_REQ): PASN1_OBJECT; cdecl = Load_TS_REQ_get_policy_id;
  TS_REQ_set_nonce: function(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_nonce;
  TS_REQ_get_nonce: function(a: PTS_REQ): PASN1_INTEGER; cdecl = Load_TS_REQ_get_nonce;
  TS_REQ_set_cert_req: function(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_set_cert_req;
  TS_REQ_get_cert_req: function(a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_cert_req;
  TS_REQ_get_exts: function(a: PTS_REQ): Pstack_st_X509_EXTENSION; cdecl = Load_TS_REQ_get_exts;
  TS_REQ_ext_free: procedure(a: PTS_REQ); cdecl = Load_TS_REQ_ext_free;
  TS_REQ_get_ext_count: function(a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_count;
  TS_REQ_get_ext_by_NID: function(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_by_NID;
  TS_REQ_get_ext_by_OBJ: function(a: PTS_REQ; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_by_OBJ;
  TS_REQ_get_ext_by_critical: function(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_get_ext_by_critical;
  TS_REQ_get_ext: function(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_TS_REQ_get_ext;
  TS_REQ_delete_ext: function(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_TS_REQ_delete_ext;
  TS_REQ_add_ext: function(a: PTS_REQ; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_REQ_add_ext;
  TS_REQ_get_ext_d2i: function(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl = Load_TS_REQ_get_ext_d2i;
  { Function declarations for TS_REQ defined in ts/ts_req_print.c }
  TS_REQ_print_bio: function(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl = Load_TS_REQ_print_bio;
  { Function declarations for TS_RESP defined in ts/ts_resp_utils.c }
  TS_RESP_set_status_info: function(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl = Load_TS_RESP_set_status_info;
  TS_RESP_get_status_info: function(a: PTS_RESP): PTS_STATUS_INFO; cdecl = Load_TS_RESP_get_status_info;
  { Caller loses ownership of PKCS7 and TS_TST_INFO objects. }
  TS_RESP_set_tst_info: procedure(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_INFO); cdecl = Load_TS_RESP_set_tst_info;
  TS_RESP_get_token: function(a: PTS_RESP): PPKCS7; cdecl = Load_TS_RESP_get_token;
  TS_RESP_get_tst_info: function(a: PTS_RESP): PTS_TST_INFO; cdecl = Load_TS_RESP_get_tst_info;
  TS_TST_INFO_set_version: function(a: PTS_TST_INFO; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_version;
  TS_TST_INFO_get_version: function(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_version;
  TS_TST_INFO_set_policy_id: function(a: PTS_TST_INFO; policy_id: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_policy_id;
  TS_TST_INFO_get_policy_id: function(a: PTS_TST_INFO): PASN1_OBJECT; cdecl = Load_TS_TST_INFO_get_policy_id;
  TS_TST_INFO_set_msg_imprint: function(a: PTS_TST_INFO; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_msg_imprint;
  TS_TST_INFO_get_msg_imprint: function(a: PTS_TST_INFO): PTS_MSG_IMPRINT; cdecl = Load_TS_TST_INFO_get_msg_imprint;
  TS_TST_INFO_set_serial: function(a: PTS_TST_INFO; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_serial;
  TS_TST_INFO_get_serial: function(a: PTS_TST_INFO): PASN1_INTEGER; cdecl = Load_TS_TST_INFO_get_serial;
  TS_TST_INFO_set_time: function(a: PTS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_time;
  TS_TST_INFO_get_time: function(a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl = Load_TS_TST_INFO_get_time;
  TS_TST_INFO_set_accuracy: function(a: PTS_TST_INFO; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_accuracy;
  TS_TST_INFO_get_accuracy: function(a: PTS_TST_INFO): PTS_ACCURACY; cdecl = Load_TS_TST_INFO_get_accuracy;
  TS_ACCURACY_set_seconds: function(a: PTS_ACCURACY; seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ACCURACY_set_seconds;
  TS_ACCURACY_get_seconds: function(a: PTS_ACCURACY): PASN1_INTEGER; cdecl = Load_TS_ACCURACY_get_seconds;
  TS_ACCURACY_set_millis: function(a: PTS_ACCURACY; millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ACCURACY_set_millis;
  TS_ACCURACY_get_millis: function(a: PTS_ACCURACY): PASN1_INTEGER; cdecl = Load_TS_ACCURACY_get_millis;
  TS_ACCURACY_set_micros: function(a: PTS_ACCURACY; micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ACCURACY_set_micros;
  TS_ACCURACY_get_micros: function(a: PTS_ACCURACY): PASN1_INTEGER; cdecl = Load_TS_ACCURACY_get_micros;
  TS_TST_INFO_set_ordering: function(a: PTS_TST_INFO; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_ordering;
  TS_TST_INFO_get_ordering: function(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ordering;
  TS_TST_INFO_set_nonce: function(a: PTS_TST_INFO; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_nonce;
  TS_TST_INFO_get_nonce: function(a: PTS_TST_INFO): PASN1_INTEGER; cdecl = Load_TS_TST_INFO_get_nonce;
  TS_TST_INFO_set_tsa: function(a: PTS_TST_INFO; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_set_tsa;
  TS_TST_INFO_get_tsa: function(a: PTS_TST_INFO): PGENERAL_NAME; cdecl = Load_TS_TST_INFO_get_tsa;
  TS_TST_INFO_get_exts: function(a: PTS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl = Load_TS_TST_INFO_get_exts;
  TS_TST_INFO_ext_free: procedure(a: PTS_TST_INFO); cdecl = Load_TS_TST_INFO_ext_free;
  TS_TST_INFO_get_ext_count: function(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_count;
  TS_TST_INFO_get_ext_by_NID: function(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_by_NID;
  TS_TST_INFO_get_ext_by_OBJ: function(a: PTS_TST_INFO; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_by_OBJ;
  TS_TST_INFO_get_ext_by_critical: function(a: PTS_TST_INFO; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_get_ext_by_critical;
  TS_TST_INFO_get_ext: function(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_TS_TST_INFO_get_ext;
  TS_TST_INFO_delete_ext: function(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl = Load_TS_TST_INFO_delete_ext;
  TS_TST_INFO_add_ext: function(a: PTS_TST_INFO; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_add_ext;
  TS_TST_INFO_get_ext_d2i: function(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl = Load_TS_TST_INFO_get_ext_d2i;
  
  {* Declarations related to response generation, defined in ts/ts_resp_sign.c.
  }
  { Optional flags for response generation. }
  { Don't include the TSA name in response. }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  TS_TSA_NAME = $01;
    { Set ordering to true in response. }
  TS_ORDERING = $02;
    
    {* Include the signer certificate and the other specified certificates in
    * the ESS signing certificate attribute beside the PKCS7 signed data.
    * Only the signer certificates is included by default.
    }
  TS_ESS_CERT_ID_CHAIN = $04;

type
  {Auto-generated forward references}
  PTS_resp_ctx = ^TTS_resp_ctx;
  PPTS_resp_ctx = ^PTS_resp_ctx;
  PTS_serial_cb = ^TTS_serial_cb;
  PPTS_serial_cb = ^PTS_serial_cb;
  PTS_time_cb = ^TTS_time_cb;
  PPTS_time_cb = ^PTS_time_cb;
  PTS_extension_cb = ^TTS_extension_cb;
  PPTS_extension_cb = ^PTS_extension_cb;
  {end of auto-generated forward references}

    { Forward declaration. }
  TTS_resp_ctx = record 
  end;
    { This must return a unique number less than 160 bits long. }
  TTS_serial_cb = function(_param1: PTS_resp_ctx; _param2: pointer): PASN1_INTEGER; cdecl;
    
    {* This must return the seconds and microseconds since Jan 1, 1970 in the sec
    * and usec variables allocated by the caller. Return non-zero for success
    * and zero for failure.
    }
  TTS_time_cb = function(_param1: PTS_resp_ctx; _param2: pointer; sec: POpenSSL_C_INT; usec: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
    
    {* This must process the given extension. It can modify the TS_TST_INFO
    * object of the context. Return values: !0 (processed), 0 (error, it must
    * set the status info/failure info of the response).
    }
  TTS_extension_cb = function(_param1: PTS_resp_ctx; _param2: PX509_EXTENSION; _param3: pointer): TOpenSSL_C_INT; cdecl;


    { Creates a response context that can be used for generating responses. }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TS_RESP_CTX_new: PTS_RESP_CTX; cdecl; external CLibCrypto name 'TS_RESP_CTX_new';
  function TS_RESP_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PAnsiChar): PTS_RESP_CTX; cdecl; external CLibCrypto name 'TS_RESP_CTX_new_ex';
  procedure TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl; external CLibCrypto name 'TS_RESP_CTX_free';
  { This parameter must be set. }
  function TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_signer_cert';
  { This parameter must be set. }
  function TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_signer_key';
  function TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_signer_digest';
  function TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_ess_cert_id_digest';
  { This parameter must be set. }
  function TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_def_policy';
  { No additional certs are included in the response by default. }
  function TS_RESP_CTX_set_certs(ctx: PTS_RESP_CTX; certs: Pstack_st_X509): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_certs';
  
  {* Adds a new acceptable policy, only the default policy is accepted by
  * default.
  }
  function TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_add_policy';
  
  {* Adds a new acceptable message digest. Note that no message digests are
  * accepted by default. The md argument is shared with the caller.
  }
  function TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_add_md';
  { Accuracy is not included by default. }
  function TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_accuracy';
  
  {* Clock precision digits, i.e. the number of decimal digits: '0' means sec,
  * '3' msec, '6' usec, and so on. Default is 0.
  }
  function TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_clock_precision_digits';
  { At most we accept usec precision. }
    {$else}
  {$EXTERNALSYM TS_RESP_CTX_new}
  {$EXTERNALSYM TS_RESP_CTX_new_ex}
  {$EXTERNALSYM TS_RESP_CTX_free}
  {$EXTERNALSYM TS_RESP_CTX_set_signer_cert}
  {$EXTERNALSYM TS_RESP_CTX_set_signer_key}
  {$EXTERNALSYM TS_RESP_CTX_set_signer_digest}
  {$EXTERNALSYM TS_RESP_CTX_set_ess_cert_id_digest}
  {$EXTERNALSYM TS_RESP_CTX_set_def_policy}
  {$EXTERNALSYM TS_RESP_CTX_set_certs}
  {$EXTERNALSYM TS_RESP_CTX_add_policy}
  {$EXTERNALSYM TS_RESP_CTX_add_md}
  {$EXTERNALSYM TS_RESP_CTX_set_accuracy}
  {$EXTERNALSYM TS_RESP_CTX_set_clock_precision_digits}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TS_RESP_CTX_new: PTS_RESP_CTX; cdecl;
  function Load_TS_RESP_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PAnsiChar): PTS_RESP_CTX; cdecl;
  procedure Load_TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl;
  function Load_TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_certs(ctx: PTS_RESP_CTX; certs: Pstack_st_X509): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;

var
  TS_RESP_CTX_new: function: PTS_RESP_CTX; cdecl = Load_TS_RESP_CTX_new;
  TS_RESP_CTX_new_ex: function(libctx: POSSL_LIB_CTX; propq: PAnsiChar): PTS_RESP_CTX; cdecl = Load_TS_RESP_CTX_new_ex;
  TS_RESP_CTX_free: procedure(ctx: PTS_RESP_CTX); cdecl = Load_TS_RESP_CTX_free;
  { This parameter must be set. }
  TS_RESP_CTX_set_signer_cert: function(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_signer_cert;
  { This parameter must be set. }
  TS_RESP_CTX_set_signer_key: function(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_signer_key;
  TS_RESP_CTX_set_signer_digest: function(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_signer_digest;
  TS_RESP_CTX_set_ess_cert_id_digest: function(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_ess_cert_id_digest;
  { This parameter must be set. }
  TS_RESP_CTX_set_def_policy: function(ctx: PTS_RESP_CTX; def_policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_def_policy;
  { No additional certs are included in the response by default. }
  TS_RESP_CTX_set_certs: function(ctx: PTS_RESP_CTX; certs: Pstack_st_X509): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_certs;
  
  {* Adds a new acceptable policy, only the default policy is accepted by
  * default.
  }
  TS_RESP_CTX_add_policy: function(ctx: PTS_RESP_CTX; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_add_policy;
  
  {* Adds a new acceptable message digest. Note that no message digests are
  * accepted by default. The md argument is shared with the caller.
  }
  TS_RESP_CTX_add_md: function(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_add_md;
  { Accuracy is not included by default. }
  TS_RESP_CTX_set_accuracy: function(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_accuracy;
  
  {* Clock precision digits, i.e. the number of decimal digits: '0' means sec,
  * '3' msec, '6' usec, and so on. Default is 0.
  }
  TS_RESP_CTX_set_clock_precision_digits: function(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_clock_precision_digits;
  { At most we accept usec precision. }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  TS_MAX_CLOCK_PRECISION_DIGITS = 6;
    { Maximum status message length }
  TS_MAX_STATUS_LENGTH = 1024*1024;


    { No flags are set by default. }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'TS_RESP_CTX_add_flags';
  { Default callback always returns a constant. }
  procedure TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TTS_serial_cb; data: pointer); cdecl; external CLibCrypto name 'TS_RESP_CTX_set_serial_cb';
  { Default callback uses the gettimeofday() and gmtime() system calls. }
  procedure TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TTS_time_cb; data: pointer); cdecl; external CLibCrypto name 'TS_RESP_CTX_set_time_cb';
  
  {* Default callback rejects all extensions. The extension callback is called
  * when the TS_TST_INFO object is already set up and not signed yet.
  }
  { FIXME: extension handling is not tested yet. }
  procedure TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TTS_extension_cb; data: pointer); cdecl; external CLibCrypto name 'TS_RESP_CTX_set_extension_cb';
  { The following methods can be used in the callbacks. }
  function TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_status_info';
  { Sets the status info only if it is still TS_STATUS_GRANTED. }
  function TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_set_status_info_cond';
  function TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_CTX_add_failure_info';
  { The get methods below can be used in the extension callback. }
  function TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl; external CLibCrypto name 'TS_RESP_CTX_get_request';
  function TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_INFO; cdecl; external CLibCrypto name 'TS_RESP_CTX_get_tst_info';
  
  {* Creates the signed TS_TST_INFO and puts it in TS_RESP.
  * In case of errors it sets the status info properly.
  * Returns NULL only in case of memory allocation/fatal error.
  }
  function TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl; external CLibCrypto name 'TS_RESP_create_response';
  
  {* Declarations related to response verification,
  * they are defined in ts/ts_resp_verify.c.
  }
  function TS_RESP_verify_signature(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_verify_signature';
  { Context structure for the generic verify method. }
  { Verify the signer's certificate and the signature of the response. }
    {$else}
  {$EXTERNALSYM TS_RESP_CTX_add_flags}
  {$EXTERNALSYM TS_RESP_CTX_set_serial_cb}
  {$EXTERNALSYM TS_RESP_CTX_set_time_cb}
  {$EXTERNALSYM TS_RESP_CTX_set_extension_cb}
  {$EXTERNALSYM TS_RESP_CTX_set_status_info}
  {$EXTERNALSYM TS_RESP_CTX_set_status_info_cond}
  {$EXTERNALSYM TS_RESP_CTX_add_failure_info}
  {$EXTERNALSYM TS_RESP_CTX_get_request}
  {$EXTERNALSYM TS_RESP_CTX_get_tst_info}
  {$EXTERNALSYM TS_RESP_create_response}
  {$EXTERNALSYM TS_RESP_verify_signature}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl;
  procedure Load_TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TTS_serial_cb; data: pointer); cdecl;
  procedure Load_TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TTS_time_cb; data: pointer); cdecl;
  procedure Load_TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TTS_extension_cb; data: pointer); cdecl;
  function Load_TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl;
  function Load_TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_INFO; cdecl;
  function Load_TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl;
  function Load_TS_RESP_verify_signature(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TOpenSSL_C_INT; cdecl;

var
  TS_RESP_CTX_add_flags: procedure(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl = Load_TS_RESP_CTX_add_flags;
  { Default callback always returns a constant. }
  TS_RESP_CTX_set_serial_cb: procedure(ctx: PTS_RESP_CTX; cb: TTS_serial_cb; data: pointer); cdecl = Load_TS_RESP_CTX_set_serial_cb;
  { Default callback uses the gettimeofday() and gmtime() system calls. }
  TS_RESP_CTX_set_time_cb: procedure(ctx: PTS_RESP_CTX; cb: TTS_time_cb; data: pointer); cdecl = Load_TS_RESP_CTX_set_time_cb;
  
  {* Default callback rejects all extensions. The extension callback is called
  * when the TS_TST_INFO object is already set up and not signed yet.
  }
  { FIXME: extension handling is not tested yet. }
  TS_RESP_CTX_set_extension_cb: procedure(ctx: PTS_RESP_CTX; cb: TTS_extension_cb; data: pointer); cdecl = Load_TS_RESP_CTX_set_extension_cb;
  { The following methods can be used in the callbacks. }
  TS_RESP_CTX_set_status_info: function(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_status_info;
  { Sets the status info only if it is still TS_STATUS_GRANTED. }
  TS_RESP_CTX_set_status_info_cond: function(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_set_status_info_cond;
  TS_RESP_CTX_add_failure_info: function(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_RESP_CTX_add_failure_info;
  { The get methods below can be used in the extension callback. }
  TS_RESP_CTX_get_request: function(ctx: PTS_RESP_CTX): PTS_REQ; cdecl = Load_TS_RESP_CTX_get_request;
  TS_RESP_CTX_get_tst_info: function(ctx: PTS_RESP_CTX): PTS_TST_INFO; cdecl = Load_TS_RESP_CTX_get_tst_info;
  
  {* Creates the signed TS_TST_INFO and puts it in TS_RESP.
  * In case of errors it sets the status info properly.
  * Returns NULL only in case of memory allocation/fatal error.
  }
  TS_RESP_create_response: function(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl = Load_TS_RESP_create_response;
  
  {* Declarations related to response verification,
  * they are defined in ts/ts_resp_verify.c.
  }
  TS_RESP_verify_signature: function(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TOpenSSL_C_INT; cdecl = Load_TS_RESP_verify_signature;
  { Context structure for the generic verify method. }
  { Verify the signer's certificate and the signature of the response. }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  TS_VFY_SIGNATURE = 1 shl 0;
    { Verify the version number of the response. }
  TS_VFY_VERSION = 1 shl 1;
    { Verify if the policy supplied by the user matches the policy of the TSA. }
  TS_VFY_POLICY = 1 shl 2;
    
    {* Verify the message imprint provided by the user. This flag should not be
    * specified with TS_VFY_DATA.
    }
  TS_VFY_IMPRINT = 1 shl 3;
    
    {* Verify the message imprint computed by the verify method from the user
    * provided data and the MD algorithm of the response. This flag should not
    * be specified with TS_VFY_IMPRINT.
    }
  TS_VFY_DATA = 1 shl 4;
    { Verify the nonce value. }
  TS_VFY_NONCE = 1 shl 5;
    { Verify if the TSA name field matches the signer certificate. }
  TS_VFY_SIGNER = 1 shl 6;
    { Verify if the TSA name field equals to the user provided name. }
  TS_VFY_TSA_NAME = 1 shl 7;
    { You can use the following convenience constants. }
  TS_VFY_ALL_IMPRINT = (((((TS_VFY_SIGNATURE or TS_VFY_VERSION) or TS_VFY_POLICY) or TS_VFY_IMPRINT) or TS_VFY_NONCE) or TS_VFY_SIGNER) or TS_VFY_TSA_NAME;
  TS_VFY_ALL_DATA = (((((TS_VFY_SIGNATURE or TS_VFY_VERSION) or TS_VFY_POLICY) or TS_VFY_DATA) or TS_VFY_NONCE) or TS_VFY_SIGNER) or TS_VFY_TSA_NAME;

type
  {Auto-generated forward references}
  PTS_VERIFY_CTX = ^TTS_VERIFY_CTX;
  PPTS_VERIFY_CTX = ^PTS_VERIFY_CTX;
  {end of auto-generated forward references}

  TTS_VERIFY_CTX = record end;



    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_verify_response';
  function TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_verify_token';
  
  {* Declarations related to response verification context,
  }
  function TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl; external CLibCrypto name 'TS_VERIFY_CTX_new';
  procedure TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto name 'TS_VERIFY_CTX_init';
  procedure TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto name 'TS_VERIFY_CTX_free';
  procedure TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto name 'TS_VERIFY_CTX_cleanup';
  function TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_VERIFY_CTX_set_flags';
  function TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_VERIFY_CTX_add_flags';
  function TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl; external CLibCrypto name 'TS_VERIFY_CTX_set_data';
  function TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: Pbyte; len: TOpenSSL_C_INT): Pbyte; cdecl; external CLibCrypto name 'TS_VERIFY_CTX_set_imprint';
  function TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl; external CLibCrypto name 'TS_VERIFY_CTX_set_store';
    {$else}
  {$EXTERNALSYM TS_RESP_verify_response}
  {$EXTERNALSYM TS_RESP_verify_token}
  {$EXTERNALSYM TS_VERIFY_CTX_new}
  {$EXTERNALSYM TS_VERIFY_CTX_init}
  {$EXTERNALSYM TS_VERIFY_CTX_free}
  {$EXTERNALSYM TS_VERIFY_CTX_cleanup}
  {$EXTERNALSYM TS_VERIFY_CTX_set_flags}
  {$EXTERNALSYM TS_VERIFY_CTX_add_flags}
  {$EXTERNALSYM TS_VERIFY_CTX_set_data}
  {$EXTERNALSYM TS_VERIFY_CTX_set_imprint}
  {$EXTERNALSYM TS_VERIFY_CTX_set_store}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl;
  function Load_TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl;
  function Load_TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl;
  procedure Load_TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl;
  procedure Load_TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl;
  procedure Load_TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl;
  function Load_TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl;
  function Load_TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: Pbyte; len: TOpenSSL_C_INT): Pbyte; cdecl;
  function Load_TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl;

var
  TS_RESP_verify_response: function(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl = Load_TS_RESP_verify_response;
  TS_RESP_verify_token: function(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl = Load_TS_RESP_verify_token;
  
  {* Declarations related to response verification context,
  }
  TS_VERIFY_CTX_new: function: PTS_VERIFY_CTX; cdecl = Load_TS_VERIFY_CTX_new;
  TS_VERIFY_CTX_init: procedure(ctx: PTS_VERIFY_CTX); cdecl = Load_TS_VERIFY_CTX_init;
  TS_VERIFY_CTX_free: procedure(ctx: PTS_VERIFY_CTX); cdecl = Load_TS_VERIFY_CTX_free;
  TS_VERIFY_CTX_cleanup: procedure(ctx: PTS_VERIFY_CTX); cdecl = Load_TS_VERIFY_CTX_cleanup;
  TS_VERIFY_CTX_set_flags: function(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_VERIFY_CTX_set_flags;
  TS_VERIFY_CTX_add_flags: function(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_TS_VERIFY_CTX_add_flags;
  TS_VERIFY_CTX_set_data: function(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl = Load_TS_VERIFY_CTX_set_data;
  TS_VERIFY_CTX_set_imprint: function(ctx: PTS_VERIFY_CTX; hexstr: Pbyte; len: TOpenSSL_C_INT): Pbyte; cdecl = Load_TS_VERIFY_CTX_set_imprint;
  TS_VERIFY_CTX_set_store: function(ctx: PTS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl = Load_TS_VERIFY_CTX_set_store;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


  function TS_VERIFY_CTS_set_certs(ctx:PTS_VERIFY_CTX; cert:Pstack_st_X509): Pstack_st_X509; inline;
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TS_VERIFY_CTX_set_certs(ctx: PTS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl; external CLibCrypto name 'TS_VERIFY_CTX_set_certs';
  {-
  * If ctx is NULL, it allocates and returns a new object, otherwise
  * it returns ctx. It initialises all the members as follows:
  * flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE)
  * certs = NULL
  * store = NULL
  * policy = policy from the request or NULL if absent (in this case
  *      TS_VFY_POLICY is cleared from flags as well)
  * md_alg = MD algorithm from request
  * imprint, imprint_len = imprint from request
  * data = NULL
  * nonce, nonce_len = nonce from the request or NULL if absent (in this case
  *      TS_VFY_NONCE is cleared from flags as well)
  * tsa_name = NULL
  * Important: after calling this method TS_VFY_SIGNATURE should be added!
  }
  function TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl; external CLibCrypto name 'TS_REQ_to_TS_VERIFY_CTX';
  { Function declarations for TS_RESP defined in ts/ts_resp_print.c }
  function TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_RESP_print_bio';
  function TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_STATUS_INFO_print_bio';
  function TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_TST_INFO_print_bio';
  { Common utility functions defined in ts/ts_lib.c }
  function TS_ASN1_INTEGER_print_bio(bio: PBIO; num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_ASN1_INTEGER_print_bio';
  function TS_OBJ_print_bio(bio: PBIO; obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_OBJ_print_bio';
  function TS_ext_print_bio(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_ext_print_bio';
  function TS_X509_ALGOR_print_bio(bio: PBIO; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_X509_ALGOR_print_bio';
  function TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_MSG_IMPRINT_print_bio';
  
  {* Function declarations for handling configuration options, defined in
  * ts/ts_conf.c
  }
  function TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl; external CLibCrypto name 'TS_CONF_load_cert';
  function TS_CONF_load_certs(file_: PAnsiChar): Pstack_st_X509; cdecl; external CLibCrypto name 'TS_CONF_load_certs';
  function TS_CONF_load_key(file_: PAnsiChar; pass: PAnsiChar): PEVP_PKEY; cdecl; external CLibCrypto name 'TS_CONF_load_key';
  function TS_CONF_get_tsa_section(conf: PCONF; section: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto name 'TS_CONF_get_tsa_section';
  function TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TTS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_serial';
    {$else}
  {$EXTERNALSYM TS_VERIFY_CTX_set_certs}
  {$EXTERNALSYM TS_REQ_to_TS_VERIFY_CTX}
  {$EXTERNALSYM TS_RESP_print_bio}
  {$EXTERNALSYM TS_STATUS_INFO_print_bio}
  {$EXTERNALSYM TS_TST_INFO_print_bio}
  {$EXTERNALSYM TS_ASN1_INTEGER_print_bio}
  {$EXTERNALSYM TS_OBJ_print_bio}
  {$EXTERNALSYM TS_ext_print_bio}
  {$EXTERNALSYM TS_X509_ALGOR_print_bio}
  {$EXTERNALSYM TS_MSG_IMPRINT_print_bio}
  {$EXTERNALSYM TS_CONF_load_cert}
  {$EXTERNALSYM TS_CONF_load_certs}
  {$EXTERNALSYM TS_CONF_load_key}
  {$EXTERNALSYM TS_CONF_get_tsa_section}
  {$EXTERNALSYM TS_CONF_set_serial}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TS_VERIFY_CTX_set_certs(ctx: PTS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl;
  function Load_TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl;
  function Load_TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
  function Load_TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
  function Load_TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
  function Load_TS_ASN1_INTEGER_print_bio(bio: PBIO; num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
  function Load_TS_OBJ_print_bio(bio: PBIO; obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
  function Load_TS_ext_print_bio(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TOpenSSL_C_INT; cdecl;
  function Load_TS_X509_ALGOR_print_bio(bio: PBIO; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
  function Load_TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl;
  function Load_TS_CONF_load_certs(file_: PAnsiChar): Pstack_st_X509; cdecl;
  function Load_TS_CONF_load_key(file_: PAnsiChar; pass: PAnsiChar): PEVP_PKEY; cdecl;
  function Load_TS_CONF_get_tsa_section(conf: PCONF; section: PAnsiChar): PAnsiChar; cdecl;
  function Load_TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TTS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;

var
  TS_VERIFY_CTX_set_certs: function(ctx: PTS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl = Load_TS_VERIFY_CTX_set_certs;
  {-
  * If ctx is NULL, it allocates and returns a new object, otherwise
  * it returns ctx. It initialises all the members as follows:
  * flags = TS_VFY_ALL_IMPRINT & ~(TS_VFY_TSA_NAME | TS_VFY_SIGNATURE)
  * certs = NULL
  * store = NULL
  * policy = policy from the request or NULL if absent (in this case
  *      TS_VFY_POLICY is cleared from flags as well)
  * md_alg = MD algorithm from request
  * imprint, imprint_len = imprint from request
  * data = NULL
  * nonce, nonce_len = nonce from the request or NULL if absent (in this case
  *      TS_VFY_NONCE is cleared from flags as well)
  * tsa_name = NULL
  * Important: after calling this method TS_VFY_SIGNATURE should be added!
  }
  TS_REQ_to_TS_VERIFY_CTX: function(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl = Load_TS_REQ_to_TS_VERIFY_CTX;
  { Function declarations for TS_RESP defined in ts/ts_resp_print.c }
  TS_RESP_print_bio: function(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl = Load_TS_RESP_print_bio;
  TS_STATUS_INFO_print_bio: function(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl = Load_TS_STATUS_INFO_print_bio;
  TS_TST_INFO_print_bio: function(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl = Load_TS_TST_INFO_print_bio;
  { Common utility functions defined in ts/ts_lib.c }
  TS_ASN1_INTEGER_print_bio: function(bio: PBIO; num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = Load_TS_ASN1_INTEGER_print_bio;
  TS_OBJ_print_bio: function(bio: PBIO; obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = Load_TS_OBJ_print_bio;
  TS_ext_print_bio: function(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TOpenSSL_C_INT; cdecl = Load_TS_ext_print_bio;
  TS_X509_ALGOR_print_bio: function(bio: PBIO; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl = Load_TS_X509_ALGOR_print_bio;
  TS_MSG_IMPRINT_print_bio: function(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = Load_TS_MSG_IMPRINT_print_bio;
  
  {* Function declarations for handling configuration options, defined in
  * ts/ts_conf.c
  }
  TS_CONF_load_cert: function(file_: PAnsiChar): PX509; cdecl = Load_TS_CONF_load_cert;
  TS_CONF_load_certs: function(file_: PAnsiChar): Pstack_st_X509; cdecl = Load_TS_CONF_load_certs;
  TS_CONF_load_key: function(file_: PAnsiChar; pass: PAnsiChar): PEVP_PKEY; cdecl = Load_TS_CONF_load_key;
  TS_CONF_get_tsa_section: function(conf: PCONF; section: PAnsiChar): PAnsiChar; cdecl = Load_TS_CONF_get_tsa_section;
  TS_CONF_set_serial: function(conf: PCONF; section: PAnsiChar; cb: TTS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_serial;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$ifndef  OPENSSL_NO_ENGINE}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_crypto_device';
  function TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_default_engine';
      {$else}
  {$EXTERNALSYM TS_CONF_set_crypto_device}
  {$EXTERNALSYM TS_CONF_set_default_engine}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  TS_CONF_set_crypto_device: function(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_crypto_device;
  TS_CONF_set_default_engine: function(name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_default_engine;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_signer_cert';
  function TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_certs';
  function TS_CONF_set_signer_key(conf: PCONF; section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_signer_key';
  function TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_signer_digest';
  function TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_def_policy';
  function TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_policies';
  function TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_digests';
  function TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_accuracy';
  function TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_clock_precision_digits';
  function TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_ordering';
  function TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_tsa_name';
  function TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_ess_cert_id_chain';
  function TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'TS_CONF_set_ess_cert_id_digest';
    {$else}
  {$EXTERNALSYM TS_CONF_set_signer_cert}
  {$EXTERNALSYM TS_CONF_set_certs}
  {$EXTERNALSYM TS_CONF_set_signer_key}
  {$EXTERNALSYM TS_CONF_set_signer_digest}
  {$EXTERNALSYM TS_CONF_set_def_policy}
  {$EXTERNALSYM TS_CONF_set_policies}
  {$EXTERNALSYM TS_CONF_set_digests}
  {$EXTERNALSYM TS_CONF_set_accuracy}
  {$EXTERNALSYM TS_CONF_set_clock_precision_digits}
  {$EXTERNALSYM TS_CONF_set_ordering}
  {$EXTERNALSYM TS_CONF_set_tsa_name}
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_chain}
  {$EXTERNALSYM TS_CONF_set_ess_cert_id_digest}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_signer_key(conf: PCONF; section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
  function Load_TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;

var
  TS_CONF_set_signer_cert: function(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_signer_cert;
  TS_CONF_set_certs: function(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_certs;
  TS_CONF_set_signer_key: function(conf: PCONF; section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_signer_key;
  TS_CONF_set_signer_digest: function(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_signer_digest;
  TS_CONF_set_def_policy: function(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_def_policy;
  TS_CONF_set_policies: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_policies;
  TS_CONF_set_digests: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_digests;
  TS_CONF_set_accuracy: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_accuracy;
  TS_CONF_set_clock_precision_digits: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_clock_precision_digits;
  TS_CONF_set_ordering: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_ordering;
  TS_CONF_set_tsa_name: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_tsa_name;
  TS_CONF_set_ess_cert_id_chain: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_ess_cert_id_chain;
  TS_CONF_set_ess_cert_id_digest: function(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = Load_TS_CONF_set_ess_cert_id_digest;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
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

{$ifndef  OPENSSL_NO_TS}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

{# define  TS_VERIFY_CTS_set_certs(ctx,cert) TS_VERIFY_CTX_set_certs(ctx, cert)}

function TS_VERIFY_CTS_set_certs(ctx:PTS_VERIFY_CTX; cert:Pstack_st_X509): Pstack_st_X509;
begin
  Result := Pstack_st_X509(TS_VERIFY_CTX_set_certs(ctx,cert));
end;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_TS}
{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef  OPENSSL_NO_TS}
function Load_TS_REQ_new: PTS_REQ; cdecl;
begin
  TS_REQ_new := LoadLibCryptoFunction('TS_REQ_new');
  if not assigned(TS_REQ_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_new');
  Result := TS_REQ_new;
end;

procedure Load_TS_REQ_free(a: PTS_REQ); cdecl;
begin
  TS_REQ_free := LoadLibCryptoFunction('TS_REQ_free');
  if not assigned(TS_REQ_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_free');
  TS_REQ_free(a);
end;

function Load_d2i_TS_REQ(a: PPTS_REQ; in_: PPbyte; len: TOpenSSL_C_INT): PTS_REQ; cdecl;
begin
  d2i_TS_REQ := LoadLibCryptoFunction('d2i_TS_REQ');
  if not assigned(d2i_TS_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_REQ');
  Result := d2i_TS_REQ(a, in_, len);
end;

function Load_i2d_TS_REQ(a: PTS_REQ; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_REQ := LoadLibCryptoFunction('i2d_TS_REQ');
  if not assigned(i2d_TS_REQ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_REQ');
  Result := i2d_TS_REQ(a, out_);
end;

function Load_TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl;
begin
  TS_REQ_dup := LoadLibCryptoFunction('TS_REQ_dup');
  if not assigned(TS_REQ_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_dup');
  Result := TS_REQ_dup(a);
end;

    {$ifndef  OPENSSL_NO_STDIO}
function Load_d2i_TS_REQ_fp(fp: PFILE; a: PPTS_REQ): PTS_REQ; cdecl;
begin
  d2i_TS_REQ_fp := LoadLibCryptoFunction('d2i_TS_REQ_fp');
  if not assigned(d2i_TS_REQ_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_REQ_fp');
  Result := d2i_TS_REQ_fp(fp, a);
end;

function Load_i2d_TS_REQ_fp(fp: PFILE; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_REQ_fp := LoadLibCryptoFunction('i2d_TS_REQ_fp');
  if not assigned(i2d_TS_REQ_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_REQ_fp');
  Result := i2d_TS_REQ_fp(fp, a);
end;

    {$endif} { OPENSSL_NO_STDIO}
function Load_d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl;
begin
  d2i_TS_REQ_bio := LoadLibCryptoFunction('d2i_TS_REQ_bio');
  if not assigned(d2i_TS_REQ_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_REQ_bio');
  Result := d2i_TS_REQ_bio(fp, a);
end;

function Load_i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_REQ_bio := LoadLibCryptoFunction('i2d_TS_REQ_bio');
  if not assigned(i2d_TS_REQ_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_REQ_bio');
  Result := i2d_TS_REQ_bio(fp, a);
end;

function Load_TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl;
begin
  TS_MSG_IMPRINT_new := LoadLibCryptoFunction('TS_MSG_IMPRINT_new');
  if not assigned(TS_MSG_IMPRINT_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_new');
  Result := TS_MSG_IMPRINT_new;
end;

procedure Load_TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl;
begin
  TS_MSG_IMPRINT_free := LoadLibCryptoFunction('TS_MSG_IMPRINT_free');
  if not assigned(TS_MSG_IMPRINT_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_free');
  TS_MSG_IMPRINT_free(a);
end;

function Load_d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; in_: PPbyte; len: TOpenSSL_C_INT): PTS_MSG_IMPRINT; cdecl;
begin
  d2i_TS_MSG_IMPRINT := LoadLibCryptoFunction('d2i_TS_MSG_IMPRINT');
  if not assigned(d2i_TS_MSG_IMPRINT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_MSG_IMPRINT');
  Result := d2i_TS_MSG_IMPRINT(a, in_, len);
end;

function Load_i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_MSG_IMPRINT := LoadLibCryptoFunction('i2d_TS_MSG_IMPRINT');
  if not assigned(i2d_TS_MSG_IMPRINT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_MSG_IMPRINT');
  Result := i2d_TS_MSG_IMPRINT(a, out_);
end;

function Load_TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
begin
  TS_MSG_IMPRINT_dup := LoadLibCryptoFunction('TS_MSG_IMPRINT_dup');
  if not assigned(TS_MSG_IMPRINT_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_dup');
  Result := TS_MSG_IMPRINT_dup(a);
end;

    {$ifndef  OPENSSL_NO_STDIO}
function Load_d2i_TS_MSG_IMPRINT_fp(fp: PFILE; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
begin
  d2i_TS_MSG_IMPRINT_fp := LoadLibCryptoFunction('d2i_TS_MSG_IMPRINT_fp');
  if not assigned(d2i_TS_MSG_IMPRINT_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_MSG_IMPRINT_fp');
  Result := d2i_TS_MSG_IMPRINT_fp(fp, a);
end;

function Load_i2d_TS_MSG_IMPRINT_fp(fp: PFILE; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_MSG_IMPRINT_fp := LoadLibCryptoFunction('i2d_TS_MSG_IMPRINT_fp');
  if not assigned(i2d_TS_MSG_IMPRINT_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_MSG_IMPRINT_fp');
  Result := i2d_TS_MSG_IMPRINT_fp(fp, a);
end;

    {$endif} { OPENSSL_NO_STDIO}
function Load_d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
begin
  d2i_TS_MSG_IMPRINT_bio := LoadLibCryptoFunction('d2i_TS_MSG_IMPRINT_bio');
  if not assigned(d2i_TS_MSG_IMPRINT_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_MSG_IMPRINT_bio');
  Result := d2i_TS_MSG_IMPRINT_bio(bio, a);
end;

function Load_i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_MSG_IMPRINT_bio := LoadLibCryptoFunction('i2d_TS_MSG_IMPRINT_bio');
  if not assigned(i2d_TS_MSG_IMPRINT_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_MSG_IMPRINT_bio');
  Result := i2d_TS_MSG_IMPRINT_bio(bio, a);
end;

function Load_TS_RESP_new: PTS_RESP; cdecl;
begin
  TS_RESP_new := LoadLibCryptoFunction('TS_RESP_new');
  if not assigned(TS_RESP_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_new');
  Result := TS_RESP_new;
end;

procedure Load_TS_RESP_free(a: PTS_RESP); cdecl;
begin
  TS_RESP_free := LoadLibCryptoFunction('TS_RESP_free');
  if not assigned(TS_RESP_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_free');
  TS_RESP_free(a);
end;

function Load_d2i_TS_RESP(a: PPTS_RESP; in_: PPbyte; len: TOpenSSL_C_INT): PTS_RESP; cdecl;
begin
  d2i_TS_RESP := LoadLibCryptoFunction('d2i_TS_RESP');
  if not assigned(d2i_TS_RESP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_RESP');
  Result := d2i_TS_RESP(a, in_, len);
end;

function Load_i2d_TS_RESP(a: PTS_RESP; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_RESP := LoadLibCryptoFunction('i2d_TS_RESP');
  if not assigned(i2d_TS_RESP) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_RESP');
  Result := i2d_TS_RESP(a, out_);
end;

function Load_TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl;
begin
  TS_RESP_dup := LoadLibCryptoFunction('TS_RESP_dup');
  if not assigned(TS_RESP_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_dup');
  Result := TS_RESP_dup(a);
end;

    {$ifndef  OPENSSL_NO_STDIO}
function Load_d2i_TS_RESP_fp(fp: PFILE; a: PPTS_RESP): PTS_RESP; cdecl;
begin
  d2i_TS_RESP_fp := LoadLibCryptoFunction('d2i_TS_RESP_fp');
  if not assigned(d2i_TS_RESP_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_RESP_fp');
  Result := d2i_TS_RESP_fp(fp, a);
end;

function Load_i2d_TS_RESP_fp(fp: PFILE; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_RESP_fp := LoadLibCryptoFunction('i2d_TS_RESP_fp');
  if not assigned(i2d_TS_RESP_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_RESP_fp');
  Result := i2d_TS_RESP_fp(fp, a);
end;

    {$endif} { OPENSSL_NO_STDIO}
function Load_d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl;
begin
  d2i_TS_RESP_bio := LoadLibCryptoFunction('d2i_TS_RESP_bio');
  if not assigned(d2i_TS_RESP_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_RESP_bio');
  Result := d2i_TS_RESP_bio(bio, a);
end;

function Load_i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_RESP_bio := LoadLibCryptoFunction('i2d_TS_RESP_bio');
  if not assigned(i2d_TS_RESP_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_RESP_bio');
  Result := i2d_TS_RESP_bio(bio, a);
end;

function Load_TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl;
begin
  TS_STATUS_INFO_new := LoadLibCryptoFunction('TS_STATUS_INFO_new');
  if not assigned(TS_STATUS_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_new');
  Result := TS_STATUS_INFO_new;
end;

procedure Load_TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl;
begin
  TS_STATUS_INFO_free := LoadLibCryptoFunction('TS_STATUS_INFO_free');
  if not assigned(TS_STATUS_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_free');
  TS_STATUS_INFO_free(a);
end;

function Load_d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_STATUS_INFO; cdecl;
begin
  d2i_TS_STATUS_INFO := LoadLibCryptoFunction('d2i_TS_STATUS_INFO');
  if not assigned(d2i_TS_STATUS_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_STATUS_INFO');
  Result := d2i_TS_STATUS_INFO(a, in_, len);
end;

function Load_i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_STATUS_INFO := LoadLibCryptoFunction('i2d_TS_STATUS_INFO');
  if not assigned(i2d_TS_STATUS_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_STATUS_INFO');
  Result := i2d_TS_STATUS_INFO(a, out_);
end;

function Load_TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl;
begin
  TS_STATUS_INFO_dup := LoadLibCryptoFunction('TS_STATUS_INFO_dup');
  if not assigned(TS_STATUS_INFO_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_dup');
  Result := TS_STATUS_INFO_dup(a);
end;

function Load_TS_TST_INFO_new: PTS_TST_INFO; cdecl;
begin
  TS_TST_INFO_new := LoadLibCryptoFunction('TS_TST_INFO_new');
  if not assigned(TS_TST_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_new');
  Result := TS_TST_INFO_new;
end;

procedure Load_TS_TST_INFO_free(a: PTS_TST_INFO); cdecl;
begin
  TS_TST_INFO_free := LoadLibCryptoFunction('TS_TST_INFO_free');
  if not assigned(TS_TST_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_free');
  TS_TST_INFO_free(a);
end;

function Load_d2i_TS_TST_INFO(a: PPTS_TST_INFO; in_: PPbyte; len: TOpenSSL_C_INT): PTS_TST_INFO; cdecl;
begin
  d2i_TS_TST_INFO := LoadLibCryptoFunction('d2i_TS_TST_INFO');
  if not assigned(d2i_TS_TST_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_TST_INFO');
  Result := d2i_TS_TST_INFO(a, in_, len);
end;

function Load_i2d_TS_TST_INFO(a: PTS_TST_INFO; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_TST_INFO := LoadLibCryptoFunction('i2d_TS_TST_INFO');
  if not assigned(i2d_TS_TST_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_TST_INFO');
  Result := i2d_TS_TST_INFO(a, out_);
end;

function Load_TS_TST_INFO_dup(a: PTS_TST_INFO): PTS_TST_INFO; cdecl;
begin
  TS_TST_INFO_dup := LoadLibCryptoFunction('TS_TST_INFO_dup');
  if not assigned(TS_TST_INFO_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_dup');
  Result := TS_TST_INFO_dup(a);
end;

function Load_PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_INFO; cdecl;
begin
  PKCS7_to_TS_TST_INFO := LoadLibCryptoFunction('PKCS7_to_TS_TST_INFO');
  if not assigned(PKCS7_to_TS_TST_INFO) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_to_TS_TST_INFO');
  Result := PKCS7_to_TS_TST_INFO(token);
end;

    {$ifndef  OPENSSL_NO_STDIO}
function Load_d2i_TS_TST_INFO_fp(fp: PFILE; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl;
begin
  d2i_TS_TST_INFO_fp := LoadLibCryptoFunction('d2i_TS_TST_INFO_fp');
  if not assigned(d2i_TS_TST_INFO_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_TST_INFO_fp');
  Result := d2i_TS_TST_INFO_fp(fp, a);
end;

function Load_i2d_TS_TST_INFO_fp(fp: PFILE; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_TST_INFO_fp := LoadLibCryptoFunction('i2d_TS_TST_INFO_fp');
  if not assigned(i2d_TS_TST_INFO_fp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_TST_INFO_fp');
  Result := i2d_TS_TST_INFO_fp(fp, a);
end;

    {$endif} { OPENSSL_NO_STDIO}
function Load_d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_INFO): PTS_TST_INFO; cdecl;
begin
  d2i_TS_TST_INFO_bio := LoadLibCryptoFunction('d2i_TS_TST_INFO_bio');
  if not assigned(d2i_TS_TST_INFO_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_TST_INFO_bio');
  Result := d2i_TS_TST_INFO_bio(bio, a);
end;

function Load_i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_TST_INFO_bio := LoadLibCryptoFunction('i2d_TS_TST_INFO_bio');
  if not assigned(i2d_TS_TST_INFO_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_TST_INFO_bio');
  Result := i2d_TS_TST_INFO_bio(bio, a);
end;

function Load_TS_ACCURACY_new: PTS_ACCURACY; cdecl;
begin
  TS_ACCURACY_new := LoadLibCryptoFunction('TS_ACCURACY_new');
  if not assigned(TS_ACCURACY_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_new');
  Result := TS_ACCURACY_new;
end;

procedure Load_TS_ACCURACY_free(a: PTS_ACCURACY); cdecl;
begin
  TS_ACCURACY_free := LoadLibCryptoFunction('TS_ACCURACY_free');
  if not assigned(TS_ACCURACY_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_free');
  TS_ACCURACY_free(a);
end;

function Load_d2i_TS_ACCURACY(a: PPTS_ACCURACY; in_: PPbyte; len: TOpenSSL_C_INT): PTS_ACCURACY; cdecl;
begin
  d2i_TS_ACCURACY := LoadLibCryptoFunction('d2i_TS_ACCURACY');
  if not assigned(d2i_TS_ACCURACY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_ACCURACY');
  Result := d2i_TS_ACCURACY(a, in_, len);
end;

function Load_i2d_TS_ACCURACY(a: PTS_ACCURACY; out_: PPbyte): TOpenSSL_C_INT; cdecl;
begin
  i2d_TS_ACCURACY := LoadLibCryptoFunction('i2d_TS_ACCURACY');
  if not assigned(i2d_TS_ACCURACY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_ACCURACY');
  Result := i2d_TS_ACCURACY(a, out_);
end;

function Load_TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl;
begin
  TS_ACCURACY_dup := LoadLibCryptoFunction('TS_ACCURACY_dup');
  if not assigned(TS_ACCURACY_dup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_dup');
  Result := TS_ACCURACY_dup(a);
end;

function Load_TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_version := LoadLibCryptoFunction('TS_REQ_set_version');
  if not assigned(TS_REQ_set_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_version');
  Result := TS_REQ_set_version(a, version);
end;

function Load_TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_version := LoadLibCryptoFunction('TS_REQ_get_version');
  if not assigned(TS_REQ_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_version');
  Result := TS_REQ_get_version(a);
end;

function Load_TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_STATUS_INFO_set_status := LoadLibCryptoFunction('TS_STATUS_INFO_set_status');
  if not assigned(TS_STATUS_INFO_set_status) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_set_status');
  Result := TS_STATUS_INFO_set_status(a, i);
end;

function Load_TS_STATUS_INFO_get0_status(a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl;
begin
  TS_STATUS_INFO_get0_status := LoadLibCryptoFunction('TS_STATUS_INFO_get0_status');
  if not assigned(TS_STATUS_INFO_get0_status) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_get0_status');
  Result := TS_STATUS_INFO_get0_status(a);
end;

function Load_TS_STATUS_INFO_get0_text(a: PTS_STATUS_INFO): Pstack_st_ASN1_UTF8STRING; cdecl;
begin
  TS_STATUS_INFO_get0_text := LoadLibCryptoFunction('TS_STATUS_INFO_get0_text');
  if not assigned(TS_STATUS_INFO_get0_text) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_get0_text');
  Result := TS_STATUS_INFO_get0_text(a);
end;

function Load_TS_STATUS_INFO_get0_failure_info(a: PTS_STATUS_INFO): PASN1_BIT_STRING; cdecl;
begin
  TS_STATUS_INFO_get0_failure_info := LoadLibCryptoFunction('TS_STATUS_INFO_get0_failure_info');
  if not assigned(TS_STATUS_INFO_get0_failure_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_get0_failure_info');
  Result := TS_STATUS_INFO_get0_failure_info(a);
end;

function Load_TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_msg_imprint := LoadLibCryptoFunction('TS_REQ_set_msg_imprint');
  if not assigned(TS_REQ_set_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_msg_imprint');
  Result := TS_REQ_set_msg_imprint(a, msg_imprint);
end;

function Load_TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl;
begin
  TS_REQ_get_msg_imprint := LoadLibCryptoFunction('TS_REQ_get_msg_imprint');
  if not assigned(TS_REQ_get_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_msg_imprint');
  Result := TS_REQ_get_msg_imprint(a);
end;

function Load_TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  TS_MSG_IMPRINT_set_algo := LoadLibCryptoFunction('TS_MSG_IMPRINT_set_algo');
  if not assigned(TS_MSG_IMPRINT_set_algo) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_set_algo');
  Result := TS_MSG_IMPRINT_set_algo(a, alg);
end;

function Load_TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOR; cdecl;
begin
  TS_MSG_IMPRINT_get_algo := LoadLibCryptoFunction('TS_MSG_IMPRINT_get_algo');
  if not assigned(TS_MSG_IMPRINT_get_algo) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_get_algo');
  Result := TS_MSG_IMPRINT_get_algo(a);
end;

function Load_TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: Pbyte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_MSG_IMPRINT_set_msg := LoadLibCryptoFunction('TS_MSG_IMPRINT_set_msg');
  if not assigned(TS_MSG_IMPRINT_set_msg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_set_msg');
  Result := TS_MSG_IMPRINT_set_msg(a, d, len);
end;

function Load_TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl;
begin
  TS_MSG_IMPRINT_get_msg := LoadLibCryptoFunction('TS_MSG_IMPRINT_get_msg');
  if not assigned(TS_MSG_IMPRINT_get_msg) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_get_msg');
  Result := TS_MSG_IMPRINT_get_msg(a);
end;

function Load_TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_policy_id := LoadLibCryptoFunction('TS_REQ_set_policy_id');
  if not assigned(TS_REQ_set_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_policy_id');
  Result := TS_REQ_set_policy_id(a, policy);
end;

function Load_TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl;
begin
  TS_REQ_get_policy_id := LoadLibCryptoFunction('TS_REQ_get_policy_id');
  if not assigned(TS_REQ_get_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_policy_id');
  Result := TS_REQ_get_policy_id(a);
end;

function Load_TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_nonce := LoadLibCryptoFunction('TS_REQ_set_nonce');
  if not assigned(TS_REQ_set_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_nonce');
  Result := TS_REQ_set_nonce(a, nonce);
end;

function Load_TS_REQ_get_nonce(a: PTS_REQ): PASN1_INTEGER; cdecl;
begin
  TS_REQ_get_nonce := LoadLibCryptoFunction('TS_REQ_get_nonce');
  if not assigned(TS_REQ_get_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_nonce');
  Result := TS_REQ_get_nonce(a);
end;

function Load_TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_set_cert_req := LoadLibCryptoFunction('TS_REQ_set_cert_req');
  if not assigned(TS_REQ_set_cert_req) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_cert_req');
  Result := TS_REQ_set_cert_req(a, cert_req);
end;

function Load_TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_cert_req := LoadLibCryptoFunction('TS_REQ_get_cert_req');
  if not assigned(TS_REQ_get_cert_req) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_cert_req');
  Result := TS_REQ_get_cert_req(a);
end;

function Load_TS_REQ_get_exts(a: PTS_REQ): Pstack_st_X509_EXTENSION; cdecl;
begin
  TS_REQ_get_exts := LoadLibCryptoFunction('TS_REQ_get_exts');
  if not assigned(TS_REQ_get_exts) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_exts');
  Result := TS_REQ_get_exts(a);
end;

procedure Load_TS_REQ_ext_free(a: PTS_REQ); cdecl;
begin
  TS_REQ_ext_free := LoadLibCryptoFunction('TS_REQ_ext_free');
  if not assigned(TS_REQ_ext_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_ext_free');
  TS_REQ_ext_free(a);
end;

function Load_TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_count := LoadLibCryptoFunction('TS_REQ_get_ext_count');
  if not assigned(TS_REQ_get_ext_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_count');
  Result := TS_REQ_get_ext_count(a);
end;

function Load_TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_by_NID := LoadLibCryptoFunction('TS_REQ_get_ext_by_NID');
  if not assigned(TS_REQ_get_ext_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_NID');
  Result := TS_REQ_get_ext_by_NID(a, nid, lastpos);
end;

function Load_TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_by_OBJ := LoadLibCryptoFunction('TS_REQ_get_ext_by_OBJ');
  if not assigned(TS_REQ_get_ext_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_OBJ');
  Result := TS_REQ_get_ext_by_OBJ(a, obj, lastpos);
end;

function Load_TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_get_ext_by_critical := LoadLibCryptoFunction('TS_REQ_get_ext_by_critical');
  if not assigned(TS_REQ_get_ext_by_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_critical');
  Result := TS_REQ_get_ext_by_critical(a, crit, lastpos);
end;

function Load_TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  TS_REQ_get_ext := LoadLibCryptoFunction('TS_REQ_get_ext');
  if not assigned(TS_REQ_get_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext');
  Result := TS_REQ_get_ext(a, loc);
end;

function Load_TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  TS_REQ_delete_ext := LoadLibCryptoFunction('TS_REQ_delete_ext');
  if not assigned(TS_REQ_delete_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_delete_ext');
  Result := TS_REQ_delete_ext(a, loc);
end;

function Load_TS_REQ_add_ext(a: PTS_REQ; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_add_ext := LoadLibCryptoFunction('TS_REQ_add_ext');
  if not assigned(TS_REQ_add_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_add_ext');
  Result := TS_REQ_add_ext(a, ex, loc);
end;

function Load_TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl;
begin
  TS_REQ_get_ext_d2i := LoadLibCryptoFunction('TS_REQ_get_ext_d2i');
  if not assigned(TS_REQ_get_ext_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_d2i');
  Result := TS_REQ_get_ext_d2i(a, nid, crit, idx);
end;

function Load_TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  TS_REQ_print_bio := LoadLibCryptoFunction('TS_REQ_print_bio');
  if not assigned(TS_REQ_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_print_bio');
  Result := TS_REQ_print_bio(bio, a);
end;

function Load_TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_set_status_info := LoadLibCryptoFunction('TS_RESP_set_status_info');
  if not assigned(TS_RESP_set_status_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_set_status_info');
  Result := TS_RESP_set_status_info(a, info);
end;

function Load_TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl;
begin
  TS_RESP_get_status_info := LoadLibCryptoFunction('TS_RESP_get_status_info');
  if not assigned(TS_RESP_get_status_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_status_info');
  Result := TS_RESP_get_status_info(a);
end;

procedure Load_TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_INFO); cdecl;
begin
  TS_RESP_set_tst_info := LoadLibCryptoFunction('TS_RESP_set_tst_info');
  if not assigned(TS_RESP_set_tst_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_set_tst_info');
  TS_RESP_set_tst_info(a, p7, tst_info);
end;

function Load_TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl;
begin
  TS_RESP_get_token := LoadLibCryptoFunction('TS_RESP_get_token');
  if not assigned(TS_RESP_get_token) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_token');
  Result := TS_RESP_get_token(a);
end;

function Load_TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_INFO; cdecl;
begin
  TS_RESP_get_tst_info := LoadLibCryptoFunction('TS_RESP_get_tst_info');
  if not assigned(TS_RESP_get_tst_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_tst_info');
  Result := TS_RESP_get_tst_info(a);
end;

function Load_TS_TST_INFO_set_version(a: PTS_TST_INFO; version: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_version := LoadLibCryptoFunction('TS_TST_INFO_set_version');
  if not assigned(TS_TST_INFO_set_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_version');
  Result := TS_TST_INFO_set_version(a, version);
end;

function Load_TS_TST_INFO_get_version(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_version := LoadLibCryptoFunction('TS_TST_INFO_get_version');
  if not assigned(TS_TST_INFO_get_version) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_version');
  Result := TS_TST_INFO_get_version(a);
end;

function Load_TS_TST_INFO_set_policy_id(a: PTS_TST_INFO; policy_id: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_policy_id := LoadLibCryptoFunction('TS_TST_INFO_set_policy_id');
  if not assigned(TS_TST_INFO_set_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_policy_id');
  Result := TS_TST_INFO_set_policy_id(a, policy_id);
end;

function Load_TS_TST_INFO_get_policy_id(a: PTS_TST_INFO): PASN1_OBJECT; cdecl;
begin
  TS_TST_INFO_get_policy_id := LoadLibCryptoFunction('TS_TST_INFO_get_policy_id');
  if not assigned(TS_TST_INFO_get_policy_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_policy_id');
  Result := TS_TST_INFO_get_policy_id(a);
end;

function Load_TS_TST_INFO_set_msg_imprint(a: PTS_TST_INFO; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_msg_imprint := LoadLibCryptoFunction('TS_TST_INFO_set_msg_imprint');
  if not assigned(TS_TST_INFO_set_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_msg_imprint');
  Result := TS_TST_INFO_set_msg_imprint(a, msg_imprint);
end;

function Load_TS_TST_INFO_get_msg_imprint(a: PTS_TST_INFO): PTS_MSG_IMPRINT; cdecl;
begin
  TS_TST_INFO_get_msg_imprint := LoadLibCryptoFunction('TS_TST_INFO_get_msg_imprint');
  if not assigned(TS_TST_INFO_get_msg_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_msg_imprint');
  Result := TS_TST_INFO_get_msg_imprint(a);
end;

function Load_TS_TST_INFO_set_serial(a: PTS_TST_INFO; serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_serial := LoadLibCryptoFunction('TS_TST_INFO_set_serial');
  if not assigned(TS_TST_INFO_set_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_serial');
  Result := TS_TST_INFO_set_serial(a, serial);
end;

function Load_TS_TST_INFO_get_serial(a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
begin
  TS_TST_INFO_get_serial := LoadLibCryptoFunction('TS_TST_INFO_get_serial');
  if not assigned(TS_TST_INFO_get_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_serial');
  Result := TS_TST_INFO_get_serial(a);
end;

function Load_TS_TST_INFO_set_time(a: PTS_TST_INFO; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_time := LoadLibCryptoFunction('TS_TST_INFO_set_time');
  if not assigned(TS_TST_INFO_set_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_time');
  Result := TS_TST_INFO_set_time(a, gtime);
end;

function Load_TS_TST_INFO_get_time(a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl;
begin
  TS_TST_INFO_get_time := LoadLibCryptoFunction('TS_TST_INFO_get_time');
  if not assigned(TS_TST_INFO_get_time) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_time');
  Result := TS_TST_INFO_get_time(a);
end;

function Load_TS_TST_INFO_set_accuracy(a: PTS_TST_INFO; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_accuracy := LoadLibCryptoFunction('TS_TST_INFO_set_accuracy');
  if not assigned(TS_TST_INFO_set_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_accuracy');
  Result := TS_TST_INFO_set_accuracy(a, accuracy);
end;

function Load_TS_TST_INFO_get_accuracy(a: PTS_TST_INFO): PTS_ACCURACY; cdecl;
begin
  TS_TST_INFO_get_accuracy := LoadLibCryptoFunction('TS_TST_INFO_get_accuracy');
  if not assigned(TS_TST_INFO_get_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_accuracy');
  Result := TS_TST_INFO_get_accuracy(a);
end;

function Load_TS_ACCURACY_set_seconds(a: PTS_ACCURACY; seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ACCURACY_set_seconds := LoadLibCryptoFunction('TS_ACCURACY_set_seconds');
  if not assigned(TS_ACCURACY_set_seconds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_seconds');
  Result := TS_ACCURACY_set_seconds(a, seconds);
end;

function Load_TS_ACCURACY_get_seconds(a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  TS_ACCURACY_get_seconds := LoadLibCryptoFunction('TS_ACCURACY_get_seconds');
  if not assigned(TS_ACCURACY_get_seconds) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_seconds');
  Result := TS_ACCURACY_get_seconds(a);
end;

function Load_TS_ACCURACY_set_millis(a: PTS_ACCURACY; millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ACCURACY_set_millis := LoadLibCryptoFunction('TS_ACCURACY_set_millis');
  if not assigned(TS_ACCURACY_set_millis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_millis');
  Result := TS_ACCURACY_set_millis(a, millis);
end;

function Load_TS_ACCURACY_get_millis(a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  TS_ACCURACY_get_millis := LoadLibCryptoFunction('TS_ACCURACY_get_millis');
  if not assigned(TS_ACCURACY_get_millis) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_millis');
  Result := TS_ACCURACY_get_millis(a);
end;

function Load_TS_ACCURACY_set_micros(a: PTS_ACCURACY; micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ACCURACY_set_micros := LoadLibCryptoFunction('TS_ACCURACY_set_micros');
  if not assigned(TS_ACCURACY_set_micros) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_micros');
  Result := TS_ACCURACY_set_micros(a, micros);
end;

function Load_TS_ACCURACY_get_micros(a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  TS_ACCURACY_get_micros := LoadLibCryptoFunction('TS_ACCURACY_get_micros');
  if not assigned(TS_ACCURACY_get_micros) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_micros');
  Result := TS_ACCURACY_get_micros(a);
end;

function Load_TS_TST_INFO_set_ordering(a: PTS_TST_INFO; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_ordering := LoadLibCryptoFunction('TS_TST_INFO_set_ordering');
  if not assigned(TS_TST_INFO_set_ordering) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_ordering');
  Result := TS_TST_INFO_set_ordering(a, ordering);
end;

function Load_TS_TST_INFO_get_ordering(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ordering := LoadLibCryptoFunction('TS_TST_INFO_get_ordering');
  if not assigned(TS_TST_INFO_get_ordering) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ordering');
  Result := TS_TST_INFO_get_ordering(a);
end;

function Load_TS_TST_INFO_set_nonce(a: PTS_TST_INFO; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_nonce := LoadLibCryptoFunction('TS_TST_INFO_set_nonce');
  if not assigned(TS_TST_INFO_set_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_nonce');
  Result := TS_TST_INFO_set_nonce(a, nonce);
end;

function Load_TS_TST_INFO_get_nonce(a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
begin
  TS_TST_INFO_get_nonce := LoadLibCryptoFunction('TS_TST_INFO_get_nonce');
  if not assigned(TS_TST_INFO_get_nonce) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_nonce');
  Result := TS_TST_INFO_get_nonce(a);
end;

function Load_TS_TST_INFO_set_tsa(a: PTS_TST_INFO; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_set_tsa := LoadLibCryptoFunction('TS_TST_INFO_set_tsa');
  if not assigned(TS_TST_INFO_set_tsa) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_tsa');
  Result := TS_TST_INFO_set_tsa(a, tsa);
end;

function Load_TS_TST_INFO_get_tsa(a: PTS_TST_INFO): PGENERAL_NAME; cdecl;
begin
  TS_TST_INFO_get_tsa := LoadLibCryptoFunction('TS_TST_INFO_get_tsa');
  if not assigned(TS_TST_INFO_get_tsa) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_tsa');
  Result := TS_TST_INFO_get_tsa(a);
end;

function Load_TS_TST_INFO_get_exts(a: PTS_TST_INFO): Pstack_st_X509_EXTENSION; cdecl;
begin
  TS_TST_INFO_get_exts := LoadLibCryptoFunction('TS_TST_INFO_get_exts');
  if not assigned(TS_TST_INFO_get_exts) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_exts');
  Result := TS_TST_INFO_get_exts(a);
end;

procedure Load_TS_TST_INFO_ext_free(a: PTS_TST_INFO); cdecl;
begin
  TS_TST_INFO_ext_free := LoadLibCryptoFunction('TS_TST_INFO_ext_free');
  if not assigned(TS_TST_INFO_ext_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_ext_free');
  TS_TST_INFO_ext_free(a);
end;

function Load_TS_TST_INFO_get_ext_count(a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_count := LoadLibCryptoFunction('TS_TST_INFO_get_ext_count');
  if not assigned(TS_TST_INFO_get_ext_count) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_count');
  Result := TS_TST_INFO_get_ext_count(a);
end;

function Load_TS_TST_INFO_get_ext_by_NID(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_by_NID := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_NID');
  if not assigned(TS_TST_INFO_get_ext_by_NID) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_NID');
  Result := TS_TST_INFO_get_ext_by_NID(a, nid, lastpos);
end;

function Load_TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_INFO; obj: PASN1_OBJECT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_by_OBJ := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_OBJ');
  if not assigned(TS_TST_INFO_get_ext_by_OBJ) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_OBJ');
  Result := TS_TST_INFO_get_ext_by_OBJ(a, obj, lastpos);
end;

function Load_TS_TST_INFO_get_ext_by_critical(a: PTS_TST_INFO; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_get_ext_by_critical := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_critical');
  if not assigned(TS_TST_INFO_get_ext_by_critical) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_critical');
  Result := TS_TST_INFO_get_ext_by_critical(a, crit, lastpos);
end;

function Load_TS_TST_INFO_get_ext(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  TS_TST_INFO_get_ext := LoadLibCryptoFunction('TS_TST_INFO_get_ext');
  if not assigned(TS_TST_INFO_get_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext');
  Result := TS_TST_INFO_get_ext(a, loc);
end;

function Load_TS_TST_INFO_delete_ext(a: PTS_TST_INFO; loc: TOpenSSL_C_INT): PX509_EXTENSION; cdecl;
begin
  TS_TST_INFO_delete_ext := LoadLibCryptoFunction('TS_TST_INFO_delete_ext');
  if not assigned(TS_TST_INFO_delete_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_delete_ext');
  Result := TS_TST_INFO_delete_ext(a, loc);
end;

function Load_TS_TST_INFO_add_ext(a: PTS_TST_INFO; ex: PX509_EXTENSION; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_add_ext := LoadLibCryptoFunction('TS_TST_INFO_add_ext');
  if not assigned(TS_TST_INFO_add_ext) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_add_ext');
  Result := TS_TST_INFO_add_ext(a, ex, loc);
end;

function Load_TS_TST_INFO_get_ext_d2i(a: PTS_TST_INFO; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): pointer; cdecl;
begin
  TS_TST_INFO_get_ext_d2i := LoadLibCryptoFunction('TS_TST_INFO_get_ext_d2i');
  if not assigned(TS_TST_INFO_get_ext_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_d2i');
  Result := TS_TST_INFO_get_ext_d2i(a, nid, crit, idx);
end;

function Load_TS_RESP_CTX_new: PTS_RESP_CTX; cdecl;
begin
  TS_RESP_CTX_new := LoadLibCryptoFunction('TS_RESP_CTX_new');
  if not assigned(TS_RESP_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_new');
  Result := TS_RESP_CTX_new;
end;

function Load_TS_RESP_CTX_new_ex(libctx: POSSL_LIB_CTX; propq: PAnsiChar): PTS_RESP_CTX; cdecl;
begin
  TS_RESP_CTX_new_ex := LoadLibCryptoFunction('TS_RESP_CTX_new_ex');
  if not assigned(TS_RESP_CTX_new_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_new_ex');
  Result := TS_RESP_CTX_new_ex(libctx, propq);
end;

procedure Load_TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl;
begin
  TS_RESP_CTX_free := LoadLibCryptoFunction('TS_RESP_CTX_free');
  if not assigned(TS_RESP_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_free');
  TS_RESP_CTX_free(ctx);
end;

function Load_TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_signer_cert := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_cert');
  if not assigned(TS_RESP_CTX_set_signer_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_cert');
  Result := TS_RESP_CTX_set_signer_cert(ctx, signer);
end;

function Load_TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_signer_key := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_key');
  if not assigned(TS_RESP_CTX_set_signer_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_key');
  Result := TS_RESP_CTX_set_signer_key(ctx, key);
end;

function Load_TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_signer_digest := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_digest');
  if not assigned(TS_RESP_CTX_set_signer_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_digest');
  Result := TS_RESP_CTX_set_signer_digest(ctx, signer_digest);
end;

function Load_TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_ess_cert_id_digest := LoadLibCryptoFunction('TS_RESP_CTX_set_ess_cert_id_digest');
  if not assigned(TS_RESP_CTX_set_ess_cert_id_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_ess_cert_id_digest');
  Result := TS_RESP_CTX_set_ess_cert_id_digest(ctx, md);
end;

function Load_TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_def_policy := LoadLibCryptoFunction('TS_RESP_CTX_set_def_policy');
  if not assigned(TS_RESP_CTX_set_def_policy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_def_policy');
  Result := TS_RESP_CTX_set_def_policy(ctx, def_policy);
end;

function Load_TS_RESP_CTX_set_certs(ctx: PTS_RESP_CTX; certs: Pstack_st_X509): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_certs := LoadLibCryptoFunction('TS_RESP_CTX_set_certs');
  if not assigned(TS_RESP_CTX_set_certs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_certs');
  Result := TS_RESP_CTX_set_certs(ctx, certs);
end;

function Load_TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_add_policy := LoadLibCryptoFunction('TS_RESP_CTX_add_policy');
  if not assigned(TS_RESP_CTX_add_policy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_policy');
  Result := TS_RESP_CTX_add_policy(ctx, policy);
end;

function Load_TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_add_md := LoadLibCryptoFunction('TS_RESP_CTX_add_md');
  if not assigned(TS_RESP_CTX_add_md) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_md');
  Result := TS_RESP_CTX_add_md(ctx, md);
end;

function Load_TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_accuracy := LoadLibCryptoFunction('TS_RESP_CTX_set_accuracy');
  if not assigned(TS_RESP_CTX_set_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_accuracy');
  Result := TS_RESP_CTX_set_accuracy(ctx, secs, millis, micros);
end;

function Load_TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_clock_precision_digits := LoadLibCryptoFunction('TS_RESP_CTX_set_clock_precision_digits');
  if not assigned(TS_RESP_CTX_set_clock_precision_digits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_clock_precision_digits');
  Result := TS_RESP_CTX_set_clock_precision_digits(ctx, clock_precision_digits);
end;

procedure Load_TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  TS_RESP_CTX_add_flags := LoadLibCryptoFunction('TS_RESP_CTX_add_flags');
  if not assigned(TS_RESP_CTX_add_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_flags');
  TS_RESP_CTX_add_flags(ctx, flags);
end;

procedure Load_TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TTS_serial_cb; data: pointer); cdecl;
begin
  TS_RESP_CTX_set_serial_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_serial_cb');
  if not assigned(TS_RESP_CTX_set_serial_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_serial_cb');
  TS_RESP_CTX_set_serial_cb(ctx, cb, data);
end;

procedure Load_TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TTS_time_cb; data: pointer); cdecl;
begin
  TS_RESP_CTX_set_time_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_time_cb');
  if not assigned(TS_RESP_CTX_set_time_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_time_cb');
  TS_RESP_CTX_set_time_cb(ctx, cb, data);
end;

procedure Load_TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TTS_extension_cb; data: pointer); cdecl;
begin
  TS_RESP_CTX_set_extension_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_extension_cb');
  if not assigned(TS_RESP_CTX_set_extension_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_extension_cb');
  TS_RESP_CTX_set_extension_cb(ctx, cb, data);
end;

function Load_TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_status_info := LoadLibCryptoFunction('TS_RESP_CTX_set_status_info');
  if not assigned(TS_RESP_CTX_set_status_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_status_info');
  Result := TS_RESP_CTX_set_status_info(ctx, status, text);
end;

function Load_TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_set_status_info_cond := LoadLibCryptoFunction('TS_RESP_CTX_set_status_info_cond');
  if not assigned(TS_RESP_CTX_set_status_info_cond) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_status_info_cond');
  Result := TS_RESP_CTX_set_status_info_cond(ctx, status, text);
end;

function Load_TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_CTX_add_failure_info := LoadLibCryptoFunction('TS_RESP_CTX_add_failure_info');
  if not assigned(TS_RESP_CTX_add_failure_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_failure_info');
  Result := TS_RESP_CTX_add_failure_info(ctx, failure);
end;

function Load_TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl;
begin
  TS_RESP_CTX_get_request := LoadLibCryptoFunction('TS_RESP_CTX_get_request');
  if not assigned(TS_RESP_CTX_get_request) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_get_request');
  Result := TS_RESP_CTX_get_request(ctx);
end;

function Load_TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_INFO; cdecl;
begin
  TS_RESP_CTX_get_tst_info := LoadLibCryptoFunction('TS_RESP_CTX_get_tst_info');
  if not assigned(TS_RESP_CTX_get_tst_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_get_tst_info');
  Result := TS_RESP_CTX_get_tst_info(ctx);
end;

function Load_TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl;
begin
  TS_RESP_create_response := LoadLibCryptoFunction('TS_RESP_create_response');
  if not assigned(TS_RESP_create_response) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_create_response');
  Result := TS_RESP_create_response(ctx, req_bio);
end;

function Load_TS_RESP_verify_signature(token: PPKCS7; certs: Pstack_st_X509; store: PX509_STORE; signer_out: PPX509): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_verify_signature := LoadLibCryptoFunction('TS_RESP_verify_signature');
  if not assigned(TS_RESP_verify_signature) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_verify_signature');
  Result := TS_RESP_verify_signature(token, certs, store, signer_out);
end;

function Load_TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_verify_response := LoadLibCryptoFunction('TS_RESP_verify_response');
  if not assigned(TS_RESP_verify_response) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_verify_response');
  Result := TS_RESP_verify_response(ctx, response);
end;

function Load_TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_verify_token := LoadLibCryptoFunction('TS_RESP_verify_token');
  if not assigned(TS_RESP_verify_token) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_verify_token');
  Result := TS_RESP_verify_token(ctx, token);
end;

function Load_TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl;
begin
  TS_VERIFY_CTX_new := LoadLibCryptoFunction('TS_VERIFY_CTX_new');
  if not assigned(TS_VERIFY_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_new');
  Result := TS_VERIFY_CTX_new;
end;

procedure Load_TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl;
begin
  TS_VERIFY_CTX_init := LoadLibCryptoFunction('TS_VERIFY_CTX_init');
  if not assigned(TS_VERIFY_CTX_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_init');
  TS_VERIFY_CTX_init(ctx);
end;

procedure Load_TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl;
begin
  TS_VERIFY_CTX_free := LoadLibCryptoFunction('TS_VERIFY_CTX_free');
  if not assigned(TS_VERIFY_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_free');
  TS_VERIFY_CTX_free(ctx);
end;

procedure Load_TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl;
begin
  TS_VERIFY_CTX_cleanup := LoadLibCryptoFunction('TS_VERIFY_CTX_cleanup');
  if not assigned(TS_VERIFY_CTX_cleanup) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_cleanup');
  TS_VERIFY_CTX_cleanup(ctx);
end;

function Load_TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_VERIFY_CTX_set_flags := LoadLibCryptoFunction('TS_VERIFY_CTX_set_flags');
  if not assigned(TS_VERIFY_CTX_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_flags');
  Result := TS_VERIFY_CTX_set_flags(ctx, f);
end;

function Load_TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  TS_VERIFY_CTX_add_flags := LoadLibCryptoFunction('TS_VERIFY_CTX_add_flags');
  if not assigned(TS_VERIFY_CTX_add_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_add_flags');
  Result := TS_VERIFY_CTX_add_flags(ctx, f);
end;

function Load_TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl;
begin
  TS_VERIFY_CTX_set_data := LoadLibCryptoFunction('TS_VERIFY_CTX_set_data');
  if not assigned(TS_VERIFY_CTX_set_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_data');
  Result := TS_VERIFY_CTX_set_data(ctx, b);
end;

function Load_TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: Pbyte; len: TOpenSSL_C_INT): Pbyte; cdecl;
begin
  TS_VERIFY_CTX_set_imprint := LoadLibCryptoFunction('TS_VERIFY_CTX_set_imprint');
  if not assigned(TS_VERIFY_CTX_set_imprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_imprint');
  Result := TS_VERIFY_CTX_set_imprint(ctx, hexstr, len);
end;

function Load_TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_STORE): PX509_STORE; cdecl;
begin
  TS_VERIFY_CTX_set_store := LoadLibCryptoFunction('TS_VERIFY_CTX_set_store');
  if not assigned(TS_VERIFY_CTX_set_store) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_store');
  Result := TS_VERIFY_CTX_set_store(ctx, s);
end;

function Load_TS_VERIFY_CTX_set_certs(ctx: PTS_VERIFY_CTX; certs: Pstack_st_X509): Pstack_st_X509; cdecl;
begin
  TS_VERIFY_CTX_set_certs := LoadLibCryptoFunction('TS_VERIFY_CTX_set_certs');
  if not assigned(TS_VERIFY_CTX_set_certs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_certs');
  Result := TS_VERIFY_CTX_set_certs(ctx, certs);
end;

function Load_TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl;
begin
  TS_REQ_to_TS_VERIFY_CTX := LoadLibCryptoFunction('TS_REQ_to_TS_VERIFY_CTX');
  if not assigned(TS_REQ_to_TS_VERIFY_CTX) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_to_TS_VERIFY_CTX');
  Result := TS_REQ_to_TS_VERIFY_CTX(req, ctx);
end;

function Load_TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  TS_RESP_print_bio := LoadLibCryptoFunction('TS_RESP_print_bio');
  if not assigned(TS_RESP_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_print_bio');
  Result := TS_RESP_print_bio(bio, a);
end;

function Load_TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_STATUS_INFO_print_bio := LoadLibCryptoFunction('TS_STATUS_INFO_print_bio');
  if not assigned(TS_STATUS_INFO_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_print_bio');
  Result := TS_STATUS_INFO_print_bio(bio, a);
end;

function Load_TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_INFO): TOpenSSL_C_INT; cdecl;
begin
  TS_TST_INFO_print_bio := LoadLibCryptoFunction('TS_TST_INFO_print_bio');
  if not assigned(TS_TST_INFO_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_print_bio');
  Result := TS_TST_INFO_print_bio(bio, a);
end;

function Load_TS_ASN1_INTEGER_print_bio(bio: PBIO; num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  TS_ASN1_INTEGER_print_bio := LoadLibCryptoFunction('TS_ASN1_INTEGER_print_bio');
  if not assigned(TS_ASN1_INTEGER_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ASN1_INTEGER_print_bio');
  Result := TS_ASN1_INTEGER_print_bio(bio, num);
end;

function Load_TS_OBJ_print_bio(bio: PBIO; obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  TS_OBJ_print_bio := LoadLibCryptoFunction('TS_OBJ_print_bio');
  if not assigned(TS_OBJ_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_OBJ_print_bio');
  Result := TS_OBJ_print_bio(bio, obj);
end;

function Load_TS_ext_print_bio(bio: PBIO; extensions: Pstack_st_X509_EXTENSION): TOpenSSL_C_INT; cdecl;
begin
  TS_ext_print_bio := LoadLibCryptoFunction('TS_ext_print_bio');
  if not assigned(TS_ext_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ext_print_bio');
  Result := TS_ext_print_bio(bio, extensions);
end;

function Load_TS_X509_ALGOR_print_bio(bio: PBIO; alg: PX509_ALGOR): TOpenSSL_C_INT; cdecl;
begin
  TS_X509_ALGOR_print_bio := LoadLibCryptoFunction('TS_X509_ALGOR_print_bio');
  if not assigned(TS_X509_ALGOR_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_X509_ALGOR_print_bio');
  Result := TS_X509_ALGOR_print_bio(bio, alg);
end;

function Load_TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  TS_MSG_IMPRINT_print_bio := LoadLibCryptoFunction('TS_MSG_IMPRINT_print_bio');
  if not assigned(TS_MSG_IMPRINT_print_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_print_bio');
  Result := TS_MSG_IMPRINT_print_bio(bio, msg);
end;

function Load_TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl;
begin
  TS_CONF_load_cert := LoadLibCryptoFunction('TS_CONF_load_cert');
  if not assigned(TS_CONF_load_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_load_cert');
  Result := TS_CONF_load_cert(file_);
end;

function Load_TS_CONF_load_certs(file_: PAnsiChar): Pstack_st_X509; cdecl;
begin
  TS_CONF_load_certs := LoadLibCryptoFunction('TS_CONF_load_certs');
  if not assigned(TS_CONF_load_certs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_load_certs');
  Result := TS_CONF_load_certs(file_);
end;

function Load_TS_CONF_load_key(file_: PAnsiChar; pass: PAnsiChar): PEVP_PKEY; cdecl;
begin
  TS_CONF_load_key := LoadLibCryptoFunction('TS_CONF_load_key');
  if not assigned(TS_CONF_load_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_load_key');
  Result := TS_CONF_load_key(file_, pass);
end;

function Load_TS_CONF_get_tsa_section(conf: PCONF; section: PAnsiChar): PAnsiChar; cdecl;
begin
  TS_CONF_get_tsa_section := LoadLibCryptoFunction('TS_CONF_get_tsa_section');
  if not assigned(TS_CONF_get_tsa_section) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_get_tsa_section');
  Result := TS_CONF_get_tsa_section(conf, section);
end;

function Load_TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TTS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_serial := LoadLibCryptoFunction('TS_CONF_set_serial');
  if not assigned(TS_CONF_set_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_serial');
  Result := TS_CONF_set_serial(conf, section, cb, ctx);
end;

    {$ifndef  OPENSSL_NO_ENGINE}
function Load_TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_crypto_device := LoadLibCryptoFunction('TS_CONF_set_crypto_device');
  if not assigned(TS_CONF_set_crypto_device) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_crypto_device');
  Result := TS_CONF_set_crypto_device(conf, section, device);
end;

function Load_TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_default_engine := LoadLibCryptoFunction('TS_CONF_set_default_engine');
  if not assigned(TS_CONF_set_default_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_default_engine');
  Result := TS_CONF_set_default_engine(name);
end;

    {$endif} { OPENSSL_NO_ENGINE}
function Load_TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_signer_cert := LoadLibCryptoFunction('TS_CONF_set_signer_cert');
  if not assigned(TS_CONF_set_signer_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_cert');
  Result := TS_CONF_set_signer_cert(conf, section, cert, ctx);
end;

function Load_TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_certs := LoadLibCryptoFunction('TS_CONF_set_certs');
  if not assigned(TS_CONF_set_certs) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_certs');
  Result := TS_CONF_set_certs(conf, section, certs, ctx);
end;

function Load_TS_CONF_set_signer_key(conf: PCONF; section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_signer_key := LoadLibCryptoFunction('TS_CONF_set_signer_key');
  if not assigned(TS_CONF_set_signer_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_key');
  Result := TS_CONF_set_signer_key(conf, section, key, pass, ctx);
end;

function Load_TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_signer_digest := LoadLibCryptoFunction('TS_CONF_set_signer_digest');
  if not assigned(TS_CONF_set_signer_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_digest');
  Result := TS_CONF_set_signer_digest(conf, section, md, ctx);
end;

function Load_TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_def_policy := LoadLibCryptoFunction('TS_CONF_set_def_policy');
  if not assigned(TS_CONF_set_def_policy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_def_policy');
  Result := TS_CONF_set_def_policy(conf, section, policy, ctx);
end;

function Load_TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_policies := LoadLibCryptoFunction('TS_CONF_set_policies');
  if not assigned(TS_CONF_set_policies) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_policies');
  Result := TS_CONF_set_policies(conf, section, ctx);
end;

function Load_TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_digests := LoadLibCryptoFunction('TS_CONF_set_digests');
  if not assigned(TS_CONF_set_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_digests');
  Result := TS_CONF_set_digests(conf, section, ctx);
end;

function Load_TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_accuracy := LoadLibCryptoFunction('TS_CONF_set_accuracy');
  if not assigned(TS_CONF_set_accuracy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_accuracy');
  Result := TS_CONF_set_accuracy(conf, section, ctx);
end;

function Load_TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_clock_precision_digits := LoadLibCryptoFunction('TS_CONF_set_clock_precision_digits');
  if not assigned(TS_CONF_set_clock_precision_digits) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_clock_precision_digits');
  Result := TS_CONF_set_clock_precision_digits(conf, section, ctx);
end;

function Load_TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_ordering := LoadLibCryptoFunction('TS_CONF_set_ordering');
  if not assigned(TS_CONF_set_ordering) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ordering');
  Result := TS_CONF_set_ordering(conf, section, ctx);
end;

function Load_TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_tsa_name := LoadLibCryptoFunction('TS_CONF_set_tsa_name');
  if not assigned(TS_CONF_set_tsa_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_tsa_name');
  Result := TS_CONF_set_tsa_name(conf, section, ctx);
end;

function Load_TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_ess_cert_id_chain := LoadLibCryptoFunction('TS_CONF_set_ess_cert_id_chain');
  if not assigned(TS_CONF_set_ess_cert_id_chain) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ess_cert_id_chain');
  Result := TS_CONF_set_ess_cert_id_chain(conf, section, ctx);
end;

function Load_TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  TS_CONF_set_ess_cert_id_digest := LoadLibCryptoFunction('TS_CONF_set_ess_cert_id_digest');
  if not assigned(TS_CONF_set_ess_cert_id_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ess_cert_id_digest');
  Result := TS_CONF_set_ess_cert_id_digest(conf, section, ctx);
end;

{$endif} { OPENSSL_NO_TS}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_TS}
  TS_REQ_new := Load_TS_REQ_new;
  TS_REQ_free := Load_TS_REQ_free;
  d2i_TS_REQ := Load_d2i_TS_REQ;
  i2d_TS_REQ := Load_i2d_TS_REQ;
  TS_REQ_dup := Load_TS_REQ_dup;
    {$ifndef  OPENSSL_NO_STDIO}
  d2i_TS_REQ_fp := Load_d2i_TS_REQ_fp;
  i2d_TS_REQ_fp := Load_i2d_TS_REQ_fp;
    {$endif} { OPENSSL_NO_STDIO}
  d2i_TS_REQ_bio := Load_d2i_TS_REQ_bio;
  i2d_TS_REQ_bio := Load_i2d_TS_REQ_bio;
  TS_MSG_IMPRINT_new := Load_TS_MSG_IMPRINT_new;
  TS_MSG_IMPRINT_free := Load_TS_MSG_IMPRINT_free;
  d2i_TS_MSG_IMPRINT := Load_d2i_TS_MSG_IMPRINT;
  i2d_TS_MSG_IMPRINT := Load_i2d_TS_MSG_IMPRINT;
  TS_MSG_IMPRINT_dup := Load_TS_MSG_IMPRINT_dup;
    {$ifndef  OPENSSL_NO_STDIO}
  d2i_TS_MSG_IMPRINT_fp := Load_d2i_TS_MSG_IMPRINT_fp;
  i2d_TS_MSG_IMPRINT_fp := Load_i2d_TS_MSG_IMPRINT_fp;
    {$endif} { OPENSSL_NO_STDIO}
  d2i_TS_MSG_IMPRINT_bio := Load_d2i_TS_MSG_IMPRINT_bio;
  i2d_TS_MSG_IMPRINT_bio := Load_i2d_TS_MSG_IMPRINT_bio;
  TS_RESP_new := Load_TS_RESP_new;
  TS_RESP_free := Load_TS_RESP_free;
  d2i_TS_RESP := Load_d2i_TS_RESP;
  i2d_TS_RESP := Load_i2d_TS_RESP;
  TS_RESP_dup := Load_TS_RESP_dup;
    {$ifndef  OPENSSL_NO_STDIO}
  d2i_TS_RESP_fp := Load_d2i_TS_RESP_fp;
  i2d_TS_RESP_fp := Load_i2d_TS_RESP_fp;
    {$endif} { OPENSSL_NO_STDIO}
  d2i_TS_RESP_bio := Load_d2i_TS_RESP_bio;
  i2d_TS_RESP_bio := Load_i2d_TS_RESP_bio;
  TS_STATUS_INFO_new := Load_TS_STATUS_INFO_new;
  TS_STATUS_INFO_free := Load_TS_STATUS_INFO_free;
  d2i_TS_STATUS_INFO := Load_d2i_TS_STATUS_INFO;
  i2d_TS_STATUS_INFO := Load_i2d_TS_STATUS_INFO;
  TS_STATUS_INFO_dup := Load_TS_STATUS_INFO_dup;
  TS_TST_INFO_new := Load_TS_TST_INFO_new;
  TS_TST_INFO_free := Load_TS_TST_INFO_free;
  d2i_TS_TST_INFO := Load_d2i_TS_TST_INFO;
  i2d_TS_TST_INFO := Load_i2d_TS_TST_INFO;
  TS_TST_INFO_dup := Load_TS_TST_INFO_dup;
  PKCS7_to_TS_TST_INFO := Load_PKCS7_to_TS_TST_INFO;
    {$ifndef  OPENSSL_NO_STDIO}
  d2i_TS_TST_INFO_fp := Load_d2i_TS_TST_INFO_fp;
  i2d_TS_TST_INFO_fp := Load_i2d_TS_TST_INFO_fp;
    {$endif} { OPENSSL_NO_STDIO}
  d2i_TS_TST_INFO_bio := Load_d2i_TS_TST_INFO_bio;
  i2d_TS_TST_INFO_bio := Load_i2d_TS_TST_INFO_bio;
  TS_ACCURACY_new := Load_TS_ACCURACY_new;
  TS_ACCURACY_free := Load_TS_ACCURACY_free;
  d2i_TS_ACCURACY := Load_d2i_TS_ACCURACY;
  i2d_TS_ACCURACY := Load_i2d_TS_ACCURACY;
  TS_ACCURACY_dup := Load_TS_ACCURACY_dup;
  TS_REQ_set_version := Load_TS_REQ_set_version;
  TS_REQ_get_version := Load_TS_REQ_get_version;
  TS_STATUS_INFO_set_status := Load_TS_STATUS_INFO_set_status;
  TS_STATUS_INFO_get0_status := Load_TS_STATUS_INFO_get0_status;
  TS_STATUS_INFO_get0_text := Load_TS_STATUS_INFO_get0_text;
  TS_STATUS_INFO_get0_failure_info := Load_TS_STATUS_INFO_get0_failure_info;
  TS_REQ_set_msg_imprint := Load_TS_REQ_set_msg_imprint;
  TS_REQ_get_msg_imprint := Load_TS_REQ_get_msg_imprint;
  TS_MSG_IMPRINT_set_algo := Load_TS_MSG_IMPRINT_set_algo;
  TS_MSG_IMPRINT_get_algo := Load_TS_MSG_IMPRINT_get_algo;
  TS_MSG_IMPRINT_set_msg := Load_TS_MSG_IMPRINT_set_msg;
  TS_MSG_IMPRINT_get_msg := Load_TS_MSG_IMPRINT_get_msg;
  TS_REQ_set_policy_id := Load_TS_REQ_set_policy_id;
  TS_REQ_get_policy_id := Load_TS_REQ_get_policy_id;
  TS_REQ_set_nonce := Load_TS_REQ_set_nonce;
  TS_REQ_get_nonce := Load_TS_REQ_get_nonce;
  TS_REQ_set_cert_req := Load_TS_REQ_set_cert_req;
  TS_REQ_get_cert_req := Load_TS_REQ_get_cert_req;
  TS_REQ_get_exts := Load_TS_REQ_get_exts;
  TS_REQ_ext_free := Load_TS_REQ_ext_free;
  TS_REQ_get_ext_count := Load_TS_REQ_get_ext_count;
  TS_REQ_get_ext_by_NID := Load_TS_REQ_get_ext_by_NID;
  TS_REQ_get_ext_by_OBJ := Load_TS_REQ_get_ext_by_OBJ;
  TS_REQ_get_ext_by_critical := Load_TS_REQ_get_ext_by_critical;
  TS_REQ_get_ext := Load_TS_REQ_get_ext;
  TS_REQ_delete_ext := Load_TS_REQ_delete_ext;
  TS_REQ_add_ext := Load_TS_REQ_add_ext;
  TS_REQ_get_ext_d2i := Load_TS_REQ_get_ext_d2i;
  TS_REQ_print_bio := Load_TS_REQ_print_bio;
  TS_RESP_set_status_info := Load_TS_RESP_set_status_info;
  TS_RESP_get_status_info := Load_TS_RESP_get_status_info;
  TS_RESP_set_tst_info := Load_TS_RESP_set_tst_info;
  TS_RESP_get_token := Load_TS_RESP_get_token;
  TS_RESP_get_tst_info := Load_TS_RESP_get_tst_info;
  TS_TST_INFO_set_version := Load_TS_TST_INFO_set_version;
  TS_TST_INFO_get_version := Load_TS_TST_INFO_get_version;
  TS_TST_INFO_set_policy_id := Load_TS_TST_INFO_set_policy_id;
  TS_TST_INFO_get_policy_id := Load_TS_TST_INFO_get_policy_id;
  TS_TST_INFO_set_msg_imprint := Load_TS_TST_INFO_set_msg_imprint;
  TS_TST_INFO_get_msg_imprint := Load_TS_TST_INFO_get_msg_imprint;
  TS_TST_INFO_set_serial := Load_TS_TST_INFO_set_serial;
  TS_TST_INFO_get_serial := Load_TS_TST_INFO_get_serial;
  TS_TST_INFO_set_time := Load_TS_TST_INFO_set_time;
  TS_TST_INFO_get_time := Load_TS_TST_INFO_get_time;
  TS_TST_INFO_set_accuracy := Load_TS_TST_INFO_set_accuracy;
  TS_TST_INFO_get_accuracy := Load_TS_TST_INFO_get_accuracy;
  TS_ACCURACY_set_seconds := Load_TS_ACCURACY_set_seconds;
  TS_ACCURACY_get_seconds := Load_TS_ACCURACY_get_seconds;
  TS_ACCURACY_set_millis := Load_TS_ACCURACY_set_millis;
  TS_ACCURACY_get_millis := Load_TS_ACCURACY_get_millis;
  TS_ACCURACY_set_micros := Load_TS_ACCURACY_set_micros;
  TS_ACCURACY_get_micros := Load_TS_ACCURACY_get_micros;
  TS_TST_INFO_set_ordering := Load_TS_TST_INFO_set_ordering;
  TS_TST_INFO_get_ordering := Load_TS_TST_INFO_get_ordering;
  TS_TST_INFO_set_nonce := Load_TS_TST_INFO_set_nonce;
  TS_TST_INFO_get_nonce := Load_TS_TST_INFO_get_nonce;
  TS_TST_INFO_set_tsa := Load_TS_TST_INFO_set_tsa;
  TS_TST_INFO_get_tsa := Load_TS_TST_INFO_get_tsa;
  TS_TST_INFO_get_exts := Load_TS_TST_INFO_get_exts;
  TS_TST_INFO_ext_free := Load_TS_TST_INFO_ext_free;
  TS_TST_INFO_get_ext_count := Load_TS_TST_INFO_get_ext_count;
  TS_TST_INFO_get_ext_by_NID := Load_TS_TST_INFO_get_ext_by_NID;
  TS_TST_INFO_get_ext_by_OBJ := Load_TS_TST_INFO_get_ext_by_OBJ;
  TS_TST_INFO_get_ext_by_critical := Load_TS_TST_INFO_get_ext_by_critical;
  TS_TST_INFO_get_ext := Load_TS_TST_INFO_get_ext;
  TS_TST_INFO_delete_ext := Load_TS_TST_INFO_delete_ext;
  TS_TST_INFO_add_ext := Load_TS_TST_INFO_add_ext;
  TS_TST_INFO_get_ext_d2i := Load_TS_TST_INFO_get_ext_d2i;
  TS_RESP_CTX_new := Load_TS_RESP_CTX_new;
  TS_RESP_CTX_new_ex := Load_TS_RESP_CTX_new_ex;
  TS_RESP_CTX_free := Load_TS_RESP_CTX_free;
  TS_RESP_CTX_set_signer_cert := Load_TS_RESP_CTX_set_signer_cert;
  TS_RESP_CTX_set_signer_key := Load_TS_RESP_CTX_set_signer_key;
  TS_RESP_CTX_set_signer_digest := Load_TS_RESP_CTX_set_signer_digest;
  TS_RESP_CTX_set_ess_cert_id_digest := Load_TS_RESP_CTX_set_ess_cert_id_digest;
  TS_RESP_CTX_set_def_policy := Load_TS_RESP_CTX_set_def_policy;
  TS_RESP_CTX_set_certs := Load_TS_RESP_CTX_set_certs;
  TS_RESP_CTX_add_policy := Load_TS_RESP_CTX_add_policy;
  TS_RESP_CTX_add_md := Load_TS_RESP_CTX_add_md;
  TS_RESP_CTX_set_accuracy := Load_TS_RESP_CTX_set_accuracy;
  TS_RESP_CTX_set_clock_precision_digits := Load_TS_RESP_CTX_set_clock_precision_digits;
  TS_RESP_CTX_add_flags := Load_TS_RESP_CTX_add_flags;
  TS_RESP_CTX_set_serial_cb := Load_TS_RESP_CTX_set_serial_cb;
  TS_RESP_CTX_set_time_cb := Load_TS_RESP_CTX_set_time_cb;
  TS_RESP_CTX_set_extension_cb := Load_TS_RESP_CTX_set_extension_cb;
  TS_RESP_CTX_set_status_info := Load_TS_RESP_CTX_set_status_info;
  TS_RESP_CTX_set_status_info_cond := Load_TS_RESP_CTX_set_status_info_cond;
  TS_RESP_CTX_add_failure_info := Load_TS_RESP_CTX_add_failure_info;
  TS_RESP_CTX_get_request := Load_TS_RESP_CTX_get_request;
  TS_RESP_CTX_get_tst_info := Load_TS_RESP_CTX_get_tst_info;
  TS_RESP_create_response := Load_TS_RESP_create_response;
  TS_RESP_verify_signature := Load_TS_RESP_verify_signature;
  TS_RESP_verify_response := Load_TS_RESP_verify_response;
  TS_RESP_verify_token := Load_TS_RESP_verify_token;
  TS_VERIFY_CTX_new := Load_TS_VERIFY_CTX_new;
  TS_VERIFY_CTX_init := Load_TS_VERIFY_CTX_init;
  TS_VERIFY_CTX_free := Load_TS_VERIFY_CTX_free;
  TS_VERIFY_CTX_cleanup := Load_TS_VERIFY_CTX_cleanup;
  TS_VERIFY_CTX_set_flags := Load_TS_VERIFY_CTX_set_flags;
  TS_VERIFY_CTX_add_flags := Load_TS_VERIFY_CTX_add_flags;
  TS_VERIFY_CTX_set_data := Load_TS_VERIFY_CTX_set_data;
  TS_VERIFY_CTX_set_imprint := Load_TS_VERIFY_CTX_set_imprint;
  TS_VERIFY_CTX_set_store := Load_TS_VERIFY_CTX_set_store;
  TS_VERIFY_CTX_set_certs := Load_TS_VERIFY_CTX_set_certs;
  TS_REQ_to_TS_VERIFY_CTX := Load_TS_REQ_to_TS_VERIFY_CTX;
  TS_RESP_print_bio := Load_TS_RESP_print_bio;
  TS_STATUS_INFO_print_bio := Load_TS_STATUS_INFO_print_bio;
  TS_TST_INFO_print_bio := Load_TS_TST_INFO_print_bio;
  TS_ASN1_INTEGER_print_bio := Load_TS_ASN1_INTEGER_print_bio;
  TS_OBJ_print_bio := Load_TS_OBJ_print_bio;
  TS_ext_print_bio := Load_TS_ext_print_bio;
  TS_X509_ALGOR_print_bio := Load_TS_X509_ALGOR_print_bio;
  TS_MSG_IMPRINT_print_bio := Load_TS_MSG_IMPRINT_print_bio;
  TS_CONF_load_cert := Load_TS_CONF_load_cert;
  TS_CONF_load_certs := Load_TS_CONF_load_certs;
  TS_CONF_load_key := Load_TS_CONF_load_key;
  TS_CONF_get_tsa_section := Load_TS_CONF_get_tsa_section;
  TS_CONF_set_serial := Load_TS_CONF_set_serial;
    {$ifndef  OPENSSL_NO_ENGINE}
  TS_CONF_set_crypto_device := Load_TS_CONF_set_crypto_device;
  TS_CONF_set_default_engine := Load_TS_CONF_set_default_engine;
    {$endif} { OPENSSL_NO_ENGINE}
  TS_CONF_set_signer_cert := Load_TS_CONF_set_signer_cert;
  TS_CONF_set_certs := Load_TS_CONF_set_certs;
  TS_CONF_set_signer_key := Load_TS_CONF_set_signer_key;
  TS_CONF_set_signer_digest := Load_TS_CONF_set_signer_digest;
  TS_CONF_set_def_policy := Load_TS_CONF_set_def_policy;
  TS_CONF_set_policies := Load_TS_CONF_set_policies;
  TS_CONF_set_digests := Load_TS_CONF_set_digests;
  TS_CONF_set_accuracy := Load_TS_CONF_set_accuracy;
  TS_CONF_set_clock_precision_digits := Load_TS_CONF_set_clock_precision_digits;
  TS_CONF_set_ordering := Load_TS_CONF_set_ordering;
  TS_CONF_set_tsa_name := Load_TS_CONF_set_tsa_name;
  TS_CONF_set_ess_cert_id_chain := Load_TS_CONF_set_ess_cert_id_chain;
  TS_CONF_set_ess_cert_id_digest := Load_TS_CONF_set_ess_cert_id_digest;
{$endif} { OPENSSL_NO_TS}
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



