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

unit openssl_sha;

{
  Generated from OpenSSL 3.0.20 Header File sha.h - Tue 19 May 14:25:34 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_sha.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2;


{* Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_SHA_H}
  {$define OPENSSL_SHA_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_SHA_H}
  {$endif}

const
  SHA_DIGEST_LENGTH = 20;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PSHA_LONG = ^TSHA_LONG;
  PPSHA_LONG = ^PSHA_LONG;
  {end of auto-generated forward references}

    {-
    * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    * ! SHA_LONG has to be at least 32 bits wide.                    !
    * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    }
  TSHA_LONG = TOpenSSL_C_UINT;

const
  SHA_LBLOCK = 16;
  SHA_CBLOCK = SHA_LBLOCK*4;
  SHA_LAST_BLOCK = SHA_CBLOCK-8;

type
  {Auto-generated forward references}
  PSHAstate_st = ^TSHAstate_st;
  PPSHAstate_st = ^PSHAstate_st;
  PSHA_CTX = ^TSHA_CTX;
  PPSHA_CTX = ^PSHA_CTX;
  {end of auto-generated forward references}

  TSHAstate_st = record 
    h0: TOpenSSL_C_UINT;
    h1: TOpenSSL_C_UINT;
    h2: TOpenSSL_C_UINT;
    h3: TOpenSSL_C_UINT;
    h4: TOpenSSL_C_UINT;
    Nl: TOpenSSL_C_UINT;
    Nh: TOpenSSL_C_UINT;
    data: array[0..15] of TOpenSSL_C_UINT;
    num: TOpenSSL_C_UINT;
  end;
  TSHA_CTX = TSHAstate_st;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA1_Init'; deprecated 'Since OpenSSL 3.0';
  function SHA1_Update(c: PSHA_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA1_Update'; deprecated 'Since OpenSSL 3.0';
  function SHA1_Final(md: Pbyte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA1_Final'; deprecated 'Since OpenSSL 3.0';
  procedure SHA1_Transform(c: PSHA_CTX; data: Pbyte); cdecl; external CLibCrypto name 'SHA1_Transform'; deprecated 'Since OpenSSL 3.0';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM SHA1_Init}
  {$EXTERNALSYM SHA1_Update}
  {$EXTERNALSYM SHA1_Final}
  {$EXTERNALSYM SHA1_Transform}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
  function Load_SHA1_Update(c: PSHA_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_SHA1_Final(md: Pbyte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_SHA1_Transform(c: PSHA_CTX; data: Pbyte); cdecl;

var
  SHA1_Init: function(c: PSHA_CTX): TOpenSSL_C_INT; cdecl = Load_SHA1_Init;
  SHA1_Update: function(c: PSHA_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA1_Update;
  SHA1_Final: function(md: Pbyte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl = Load_SHA1_Final;
  SHA1_Transform: procedure(c: PSHA_CTX; data: Pbyte); cdecl = Load_SHA1_Transform;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function SHA1(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'SHA1';
  {$else}
  {$EXTERNALSYM SHA1}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_SHA1(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;

var
  SHA1: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_SHA1;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
  SHA256_CBLOCK = SHA_LBLOCK*4;

type
  {Auto-generated forward references}
  PSHA256state_st = ^TSHA256state_st;
  PPSHA256state_st = ^PSHA256state_st;
  PSHA256_CTX = ^TSHA256_CTX;
  PPSHA256_CTX = ^PSHA256_CTX;
  {end of auto-generated forward references}

  TSHA256state_st = record 
    h: array[0..7] of TOpenSSL_C_UINT;
    Nl: TOpenSSL_C_UINT;
    Nh: TOpenSSL_C_UINT;
    data: array[0..15] of TOpenSSL_C_UINT;
    num: TOpenSSL_C_UINT;
    md_len: TOpenSSL_C_UINT;
  end;
  TSHA256_CTX = TSHA256state_st;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA224_Init'; deprecated 'Since OpenSSL 3.0';
  function SHA224_Update(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA224_Update'; deprecated 'Since OpenSSL 3.0';
  function SHA224_Final(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA224_Final'; deprecated 'Since OpenSSL 3.0';
  function SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA256_Init'; deprecated 'Since OpenSSL 3.0';
  function SHA256_Update(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA256_Update'; deprecated 'Since OpenSSL 3.0';
  function SHA256_Final(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA256_Final'; deprecated 'Since OpenSSL 3.0';
  procedure SHA256_Transform(c: PSHA256_CTX; data: Pbyte); cdecl; external CLibCrypto name 'SHA256_Transform'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM SHA224_Init}
  {$EXTERNALSYM SHA224_Update}
  {$EXTERNALSYM SHA224_Final}
  {$EXTERNALSYM SHA256_Init}
  {$EXTERNALSYM SHA256_Update}
  {$EXTERNALSYM SHA256_Final}
  {$EXTERNALSYM SHA256_Transform}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
  function Load_SHA224_Update(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_SHA224_Final(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
  function Load_SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
  function Load_SHA256_Update(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_SHA256_Final(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_SHA256_Transform(c: PSHA256_CTX; data: Pbyte); cdecl;

var
  SHA224_Init: function(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA224_Init;
  SHA224_Update: function(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA224_Update;
  SHA224_Final: function(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA224_Final;
  SHA256_Init: function(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA256_Init;
  SHA256_Update: function(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA256_Update;
  SHA256_Final: function(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = Load_SHA256_Final;
  SHA256_Transform: procedure(c: PSHA256_CTX; data: Pbyte); cdecl = Load_SHA256_Transform;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function SHA224(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'SHA224';
  function SHA256(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'SHA256';
  {$else}
  {$EXTERNALSYM SHA224}
  {$EXTERNALSYM SHA256}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_SHA224(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
  function Load_SHA256(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;

var
  SHA224: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_SHA224;
  SHA256: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_SHA256;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  SHA224_DIGEST_LENGTH = 28;
  SHA256_DIGEST_LENGTH = 32;
  SHA384_DIGEST_LENGTH = 48;
  SHA512_DIGEST_LENGTH = 64;
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
    
    {* Unlike 32-bit digest algorithms, SHA-512 *relies* on SHA_LONG64
    * being exactly 64-bit wide. See Implementation Notes in sha512.c
    * for further details.
    }
    
    {* SHA-512 treats input data as a
    * contiguous array of 64 bit
    * wide big-endian values.
    }
  SHA512_CBLOCK = SHA_LBLOCK*8;
    {$if  (defined(_WIN32)  or defined(_WIN64))  and  not defined(__MINGW32__)}

type
  {Auto-generated forward references}
  PSHA_LONG64 = ^TSHA_LONG64;
  PPSHA_LONG64 = ^PSHA_LONG64;
  {end of auto-generated forward references}

  TSHA_LONG64 = TOpenSSL_C_UINT64;
    {$elseif  defined(__arch64__)}

type
  {Auto-generated forward references}
  PSHA_LONG64 = ^TSHA_LONG64;
  PPSHA_LONG64 = ^PSHA_LONG64;
  {end of auto-generated forward references}

  TSHA_LONG64 = TOpenSSL_C_UINT;
    {$else}

type
  {Auto-generated forward references}
  PSHA_LONG64 = ^TSHA_LONG64;
  PPSHA_LONG64 = ^PSHA_LONG64;
  {end of auto-generated forward references}

  TSHA_LONG64 = TOpenSSL_C_UINT64;
    {$endif}

type
  {Auto-generated forward references}
  PSHA512state_st = ^TSHA512state_st;
  PPSHA512state_st = ^PSHA512state_st;
  PSHA512_CTX = ^TSHA512_CTX;
  PPSHA512_CTX = ^PSHA512_CTX;
  {end of auto-generated forward references}

  TSHA512state_st = record 
    h: array[0..7] of TOpenSSL_C_UINT64;
    Nl: TOpenSSL_C_UINT64;
    Nh: TOpenSSL_C_UINT64;
    u: record 
      case integer of 
        0: (d: array[0..15] of TOpenSSL_C_UINT64);
        1: (p: array[0..(16*8)-1] of byte);
    end;
    num: TOpenSSL_C_UINT;
    md_len: TOpenSSL_C_UINT;
  end;
  TSHA512_CTX = TSHA512state_st;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA384_Init'; deprecated 'Since OpenSSL 3.0';
  function SHA384_Update(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA384_Update'; deprecated 'Since OpenSSL 3.0';
  function SHA384_Final(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA384_Final'; deprecated 'Since OpenSSL 3.0';
  function SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA512_Init'; deprecated 'Since OpenSSL 3.0';
  function SHA512_Update(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA512_Update'; deprecated 'Since OpenSSL 3.0';
  function SHA512_Final(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SHA512_Final'; deprecated 'Since OpenSSL 3.0';
  procedure SHA512_Transform(c: PSHA512_CTX; data: Pbyte); cdecl; external CLibCrypto name 'SHA512_Transform'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM SHA384_Init}
  {$EXTERNALSYM SHA384_Update}
  {$EXTERNALSYM SHA384_Final}
  {$EXTERNALSYM SHA512_Init}
  {$EXTERNALSYM SHA512_Update}
  {$EXTERNALSYM SHA512_Final}
  {$EXTERNALSYM SHA512_Transform}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
  function Load_SHA384_Update(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_SHA384_Final(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
  function Load_SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
  function Load_SHA512_Update(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_SHA512_Final(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
  procedure Load_SHA512_Transform(c: PSHA512_CTX; data: Pbyte); cdecl;

var
  SHA384_Init: function(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA384_Init;
  SHA384_Update: function(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA384_Update;
  SHA384_Final: function(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA384_Final;
  SHA512_Init: function(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA512_Init;
  SHA512_Update: function(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SHA512_Update;
  SHA512_Final: function(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = Load_SHA512_Final;
  SHA512_Transform: procedure(c: PSHA512_CTX; data: Pbyte); cdecl = Load_SHA512_Transform;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function SHA384(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'SHA384';
  function SHA512(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'SHA512';
  {$else}
  {$EXTERNALSYM SHA384}
  {$EXTERNALSYM SHA512}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_SHA384(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
  function Load_SHA512(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;

var
  SHA384: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_SHA384;
  SHA512: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_SHA512;
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
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA1_Init := LoadLibCryptoFunction('SHA1_Init');
  if not assigned(SHA1_Init) then
    {$if declared(LEGACY_SHA1_Init)}
    SHA1_Init := @LEGACY_SHA1_Init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Init');
    {$ifend}
  Result := SHA1_Init(c);
end;

function Load_SHA1_Update(c: PSHA_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA1_Update := LoadLibCryptoFunction('SHA1_Update');
  if not assigned(SHA1_Update) then
    {$if declared(LEGACY_SHA1_Update)}
    SHA1_Update := @LEGACY_SHA1_Update;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Update');
    {$ifend}
  Result := SHA1_Update(c, data, len);
end;

function Load_SHA1_Final(md: Pbyte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA1_Final := LoadLibCryptoFunction('SHA1_Final');
  if not assigned(SHA1_Final) then
    {$if declared(LEGACY_SHA1_Final)}
    SHA1_Final := @LEGACY_SHA1_Final;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Final');
    {$ifend}
  Result := SHA1_Final(md, c);
end;

procedure Load_SHA1_Transform(c: PSHA_CTX; data: Pbyte); cdecl;
begin
  SHA1_Transform := LoadLibCryptoFunction('SHA1_Transform');
  if not assigned(SHA1_Transform) then
    {$if declared(LEGACY_SHA1_Transform)}
    SHA1_Transform := @LEGACY_SHA1_Transform;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Transform');
    {$ifend}
  SHA1_Transform(c, data);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_SHA1(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  SHA1 := LoadLibCryptoFunction('SHA1');
  if not assigned(SHA1) then
    {$if declared(LEGACY_SHA1)}
    SHA1 := @LEGACY_SHA1;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1');
    {$ifend}
  Result := SHA1(d, n, md);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA224_Init := LoadLibCryptoFunction('SHA224_Init');
  if not assigned(SHA224_Init) then
    {$if declared(LEGACY_SHA224_Init)}
    SHA224_Init := @LEGACY_SHA224_Init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Init');
    {$ifend}
  Result := SHA224_Init(c);
end;

function Load_SHA224_Update(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA224_Update := LoadLibCryptoFunction('SHA224_Update');
  if not assigned(SHA224_Update) then
    {$if declared(LEGACY_SHA224_Update)}
    SHA224_Update := @LEGACY_SHA224_Update;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Update');
    {$ifend}
  Result := SHA224_Update(c, data, len);
end;

function Load_SHA224_Final(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA224_Final := LoadLibCryptoFunction('SHA224_Final');
  if not assigned(SHA224_Final) then
    {$if declared(LEGACY_SHA224_Final)}
    SHA224_Final := @LEGACY_SHA224_Final;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Final');
    {$ifend}
  Result := SHA224_Final(md, c);
end;

function Load_SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA256_Init := LoadLibCryptoFunction('SHA256_Init');
  if not assigned(SHA256_Init) then
    {$if declared(LEGACY_SHA256_Init)}
    SHA256_Init := @LEGACY_SHA256_Init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Init');
    {$ifend}
  Result := SHA256_Init(c);
end;

function Load_SHA256_Update(c: PSHA256_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA256_Update := LoadLibCryptoFunction('SHA256_Update');
  if not assigned(SHA256_Update) then
    {$if declared(LEGACY_SHA256_Update)}
    SHA256_Update := @LEGACY_SHA256_Update;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Update');
    {$ifend}
  Result := SHA256_Update(c, data, len);
end;

function Load_SHA256_Final(md: Pbyte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA256_Final := LoadLibCryptoFunction('SHA256_Final');
  if not assigned(SHA256_Final) then
    {$if declared(LEGACY_SHA256_Final)}
    SHA256_Final := @LEGACY_SHA256_Final;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Final');
    {$ifend}
  Result := SHA256_Final(md, c);
end;

procedure Load_SHA256_Transform(c: PSHA256_CTX; data: Pbyte); cdecl;
begin
  SHA256_Transform := LoadLibCryptoFunction('SHA256_Transform');
  if not assigned(SHA256_Transform) then
    {$if declared(LEGACY_SHA256_Transform)}
    SHA256_Transform := @LEGACY_SHA256_Transform;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Transform');
    {$ifend}
  SHA256_Transform(c, data);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_SHA224(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  SHA224 := LoadLibCryptoFunction('SHA224');
  if not assigned(SHA224) then
    {$if declared(LEGACY_SHA224)}
    SHA224 := @LEGACY_SHA224;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224');
    {$ifend}
  Result := SHA224(d, n, md);
end;

function Load_SHA256(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  SHA256 := LoadLibCryptoFunction('SHA256');
  if not assigned(SHA256) then
    {$if declared(LEGACY_SHA256)}
    SHA256 := @LEGACY_SHA256;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256');
    {$ifend}
  Result := SHA256(d, n, md);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA384_Init := LoadLibCryptoFunction('SHA384_Init');
  if not assigned(SHA384_Init) then
    {$if declared(LEGACY_SHA384_Init)}
    SHA384_Init := @LEGACY_SHA384_Init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Init');
    {$ifend}
  Result := SHA384_Init(c);
end;

function Load_SHA384_Update(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA384_Update := LoadLibCryptoFunction('SHA384_Update');
  if not assigned(SHA384_Update) then
    {$if declared(LEGACY_SHA384_Update)}
    SHA384_Update := @LEGACY_SHA384_Update;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Update');
    {$ifend}
  Result := SHA384_Update(c, data, len);
end;

function Load_SHA384_Final(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA384_Final := LoadLibCryptoFunction('SHA384_Final');
  if not assigned(SHA384_Final) then
    {$if declared(LEGACY_SHA384_Final)}
    SHA384_Final := @LEGACY_SHA384_Final;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Final');
    {$ifend}
  Result := SHA384_Final(md, c);
end;

function Load_SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA512_Init := LoadLibCryptoFunction('SHA512_Init');
  if not assigned(SHA512_Init) then
    {$if declared(LEGACY_SHA512_Init)}
    SHA512_Init := @LEGACY_SHA512_Init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Init');
    {$ifend}
  Result := SHA512_Init(c);
end;

function Load_SHA512_Update(c: PSHA512_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SHA512_Update := LoadLibCryptoFunction('SHA512_Update');
  if not assigned(SHA512_Update) then
    {$if declared(LEGACY_SHA512_Update)}
    SHA512_Update := @LEGACY_SHA512_Update;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Update');
    {$ifend}
  Result := SHA512_Update(c, data, len);
end;

function Load_SHA512_Final(md: Pbyte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  SHA512_Final := LoadLibCryptoFunction('SHA512_Final');
  if not assigned(SHA512_Final) then
    {$if declared(LEGACY_SHA512_Final)}
    SHA512_Final := @LEGACY_SHA512_Final;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Final');
    {$ifend}
  Result := SHA512_Final(md, c);
end;

procedure Load_SHA512_Transform(c: PSHA512_CTX; data: Pbyte); cdecl;
begin
  SHA512_Transform := LoadLibCryptoFunction('SHA512_Transform');
  if not assigned(SHA512_Transform) then
    {$if declared(LEGACY_SHA512_Transform)}
    SHA512_Transform := @LEGACY_SHA512_Transform;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Transform');
    {$ifend}
  SHA512_Transform(c, data);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_SHA384(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  SHA384 := LoadLibCryptoFunction('SHA384');
  if not assigned(SHA384) then
    {$if declared(LEGACY_SHA384)}
    SHA384 := @LEGACY_SHA384;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384');
    {$ifend}
  Result := SHA384(d, n, md);
end;

function Load_SHA512(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  SHA512 := LoadLibCryptoFunction('SHA512');
  if not assigned(SHA512) then
    {$if declared(LEGACY_SHA512)}
    SHA512 := @LEGACY_SHA512;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512');
    {$ifend}
  Result := SHA512(d, n, md);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  SHA1_Init := Load_SHA1_Init;
  SHA1_Update := Load_SHA1_Update;
  SHA1_Final := Load_SHA1_Final;
  SHA1_Transform := Load_SHA1_Transform;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  SHA1 := Load_SHA1;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  SHA224_Init := Load_SHA224_Init;
  SHA224_Update := Load_SHA224_Update;
  SHA224_Final := Load_SHA224_Final;
  SHA256_Init := Load_SHA256_Init;
  SHA256_Update := Load_SHA256_Update;
  SHA256_Final := Load_SHA256_Final;
  SHA256_Transform := Load_SHA256_Transform;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  SHA224 := Load_SHA224;
  SHA256 := Load_SHA256;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  SHA384_Init := Load_SHA384_Init;
  SHA384_Update := Load_SHA384_Update;
  SHA384_Final := Load_SHA384_Final;
  SHA512_Init := Load_SHA512_Init;
  SHA512_Update := Load_SHA512_Update;
  SHA512_Final := Load_SHA512_Final;
  SHA512_Transform := Load_SHA512_Transform;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  SHA384 := Load_SHA384;
  SHA512 := Load_SHA512;
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



