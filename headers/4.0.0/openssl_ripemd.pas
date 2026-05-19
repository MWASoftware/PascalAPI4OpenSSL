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

unit openssl_ripemd;

{
  Generated from OpenSSL 4.0.0 Header File ripemd.h - Tue 19 May 14:33:10 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_ripemd.obj}
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
{$ifndef  OPENSSL_RIPEMD_H}
  {$define OPENSSL_RIPEMD_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_RIPEMD_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_RMD160}

const
  RIPEMD160_DIGEST_LENGTH = 20;
    {$if  not defined(OPENSSL_NO_DEPRECATED_3_0)}

type
  {Auto-generated forward references}
  PRIPEMD160_LONG = ^TRIPEMD160_LONG;
  PPRIPEMD160_LONG = ^PRIPEMD160_LONG;
  {end of auto-generated forward references}

  TRIPEMD160_LONG = TOpenSSL_C_UINT;

const
  RIPEMD160_CBLOCK = 64;
  RIPEMD160_LBLOCK = RIPEMD160_CBLOCK/4;

type
  {Auto-generated forward references}
  PRIPEMD160state_st = ^TRIPEMD160state_st;
  PPRIPEMD160state_st = ^PRIPEMD160state_st;
  PRIPEMD160_CTX = ^TRIPEMD160_CTX;
  PPRIPEMD160_CTX = ^PRIPEMD160_CTX;
  {end of auto-generated forward references}

  TRIPEMD160state_st = record 
    A: TRIPEMD160_LONG;
    B: TRIPEMD160_LONG;
    C: TRIPEMD160_LONG;
    D: TRIPEMD160_LONG;
    E: TRIPEMD160_LONG;
    Nl: TRIPEMD160_LONG;
    Nh: TRIPEMD160_LONG;
    data: array[0..(64 div 4)-1] of TRIPEMD160_LONG;
    num: TOpenSSL_C_UINT;
  end;
  TRIPEMD160_CTX = TRIPEMD160state_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function RIPEMD160_Init(c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RIPEMD160_Init'; deprecated 'Since OpenSSL 3.0';
  function RIPEMD160_Update(c: PRIPEMD160_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RIPEMD160_Update'; deprecated 'Since OpenSSL 3.0';
  function RIPEMD160_Final(md: Pbyte; c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'RIPEMD160_Final'; deprecated 'Since OpenSSL 3.0';
  function RIPEMD160(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'RIPEMD160'; deprecated 'Since OpenSSL 3.0';
  procedure RIPEMD160_Transform(c: PRIPEMD160_CTX; b: Pbyte); cdecl; external CLibCrypto name 'RIPEMD160_Transform'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM RIPEMD160_Init}
  {$EXTERNALSYM RIPEMD160_Update}
  {$EXTERNALSYM RIPEMD160_Final}
  {$EXTERNALSYM RIPEMD160}
  {$EXTERNALSYM RIPEMD160_Transform}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_RIPEMD160_Init(c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl;
  function Load_RIPEMD160_Update(c: PRIPEMD160_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_RIPEMD160_Final(md: Pbyte; c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl;
  function Load_RIPEMD160(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
  procedure Load_RIPEMD160_Transform(c: PRIPEMD160_CTX; b: Pbyte); cdecl;

var
  RIPEMD160_Init: function(c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl = Load_RIPEMD160_Init;
  RIPEMD160_Update: function(c: PRIPEMD160_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_RIPEMD160_Update;
  RIPEMD160_Final: function(md: Pbyte; c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl = Load_RIPEMD160_Final;
  RIPEMD160: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_RIPEMD160;
  RIPEMD160_Transform: procedure(c: PRIPEMD160_CTX; b: Pbyte); cdecl = Load_RIPEMD160_Transform;
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

{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef  OPENSSL_NO_RMD160}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_RIPEMD160_Init(c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl;
begin
  RIPEMD160_Init := LoadLibCryptoFunction('RIPEMD160_Init');
  if not assigned(RIPEMD160_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RIPEMD160_Init');
  Result := RIPEMD160_Init(c);
end;

function Load_RIPEMD160_Update(c: PRIPEMD160_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  RIPEMD160_Update := LoadLibCryptoFunction('RIPEMD160_Update');
  if not assigned(RIPEMD160_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RIPEMD160_Update');
  Result := RIPEMD160_Update(c, data, len);
end;

function Load_RIPEMD160_Final(md: Pbyte; c: PRIPEMD160_CTX): TOpenSSL_C_INT; cdecl;
begin
  RIPEMD160_Final := LoadLibCryptoFunction('RIPEMD160_Final');
  if not assigned(RIPEMD160_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RIPEMD160_Final');
  Result := RIPEMD160_Final(md, c);
end;

function Load_RIPEMD160(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  RIPEMD160 := LoadLibCryptoFunction('RIPEMD160');
  if not assigned(RIPEMD160) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RIPEMD160');
  Result := RIPEMD160(d, n, md);
end;

procedure Load_RIPEMD160_Transform(c: PRIPEMD160_CTX; b: Pbyte); cdecl;
begin
  RIPEMD160_Transform := LoadLibCryptoFunction('RIPEMD160_Transform');
  if not assigned(RIPEMD160_Transform) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('RIPEMD160_Transform');
  RIPEMD160_Transform(c, b);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RMD160}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_RMD160}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  RIPEMD160_Init := Load_RIPEMD160_Init;
  RIPEMD160_Update := Load_RIPEMD160_Update;
  RIPEMD160_Final := Load_RIPEMD160_Final;
  RIPEMD160 := Load_RIPEMD160;
  RIPEMD160_Transform := Load_RIPEMD160_Transform;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_RMD160}
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



