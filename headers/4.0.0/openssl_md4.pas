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

unit openssl_md4;

{
  Generated from OpenSSL 4.0.0 Header File md4.h - Tue 19 May 14:32:49 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_md4.obj}
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
{$ifndef  OPENSSL_MD4_H}
  {$define OPENSSL_MD4_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_MD4_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_MD4}

const
  MD4_DIGEST_LENGTH = 16;
    {$if  not defined(OPENSSL_NO_DEPRECATED_3_0)}

type
  {Auto-generated forward references}
  PMD4_LONG = ^TMD4_LONG;
  PPMD4_LONG = ^PMD4_LONG;
  {end of auto-generated forward references}

      {-
      * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      * ! MD4_LONG has to be at least 32 bits wide.                     !
      * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      }
  TMD4_LONG = TOpenSSL_C_UINT;

const
  MD4_CBLOCK = 64;
  MD4_LBLOCK = MD4_CBLOCK/4;

type
  {Auto-generated forward references}
  PMD4state_st = ^TMD4state_st;
  PPMD4state_st = ^PMD4state_st;
  PMD4_CTX = ^TMD4_CTX;
  PPMD4_CTX = ^PMD4_CTX;
  {end of auto-generated forward references}

  TMD4state_st = record 
    A: TMD4_LONG;
    B: TMD4_LONG;
    C: TMD4_LONG;
    D: TMD4_LONG;
    Nl: TMD4_LONG;
    Nh: TMD4_LONG;
    data: array[0..(64 div 4)-1] of TMD4_LONG;
    num: TOpenSSL_C_UINT;
  end;
  TMD4_CTX = TMD4state_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function MD4_Init(c: PMD4_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD4_Init'; deprecated 'Since OpenSSL 3.0';
  function MD4_Update(c: PMD4_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD4_Update'; deprecated 'Since OpenSSL 3.0';
  function MD4_Final(md: Pbyte; c: PMD4_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD4_Final'; deprecated 'Since OpenSSL 3.0';
  function MD4(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'MD4'; deprecated 'Since OpenSSL 3.0';
  procedure MD4_Transform(c: PMD4_CTX; b: Pbyte); cdecl; external CLibCrypto name 'MD4_Transform'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM MD4_Init}
  {$EXTERNALSYM MD4_Update}
  {$EXTERNALSYM MD4_Final}
  {$EXTERNALSYM MD4}
  {$EXTERNALSYM MD4_Transform}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_MD4_Init(c: PMD4_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MD4_Update(c: PMD4_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_MD4_Final(md: Pbyte; c: PMD4_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MD4(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
  procedure Load_MD4_Transform(c: PMD4_CTX; b: Pbyte); cdecl;

var
  MD4_Init: function(c: PMD4_CTX): TOpenSSL_C_INT; cdecl = Load_MD4_Init;
  MD4_Update: function(c: PMD4_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_MD4_Update;
  MD4_Final: function(md: Pbyte; c: PMD4_CTX): TOpenSSL_C_INT; cdecl = Load_MD4_Final;
  MD4: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_MD4;
  MD4_Transform: procedure(c: PMD4_CTX; b: Pbyte); cdecl = Load_MD4_Transform;
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
{$ifndef  OPENSSL_NO_MD4}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_MD4_Init(c: PMD4_CTX): TOpenSSL_C_INT; cdecl;
begin
  MD4_Init := LoadLibCryptoFunction('MD4_Init');
  if not assigned(MD4_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD4_Init');
  Result := MD4_Init(c);
end;

function Load_MD4_Update(c: PMD4_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  MD4_Update := LoadLibCryptoFunction('MD4_Update');
  if not assigned(MD4_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD4_Update');
  Result := MD4_Update(c, data, len);
end;

function Load_MD4_Final(md: Pbyte; c: PMD4_CTX): TOpenSSL_C_INT; cdecl;
begin
  MD4_Final := LoadLibCryptoFunction('MD4_Final');
  if not assigned(MD4_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD4_Final');
  Result := MD4_Final(md, c);
end;

function Load_MD4(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  MD4 := LoadLibCryptoFunction('MD4');
  if not assigned(MD4) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD4');
  Result := MD4(d, n, md);
end;

procedure Load_MD4_Transform(c: PMD4_CTX; b: Pbyte); cdecl;
begin
  MD4_Transform := LoadLibCryptoFunction('MD4_Transform');
  if not assigned(MD4_Transform) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD4_Transform');
  MD4_Transform(c, b);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MD4}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_MD4}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  MD4_Init := Load_MD4_Init;
  MD4_Update := Load_MD4_Update;
  MD4_Final := Load_MD4_Final;
  MD4 := Load_MD4;
  MD4_Transform := Load_MD4_Transform;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MD4}
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



