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

unit openssl_md5;

{
  Generated from OpenSSL 3.0.20 Header File md5.h - Tue 19 May 14:25:15 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_md5.obj}
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
{$ifndef  OPENSSL_MD5_H}
  {$define OPENSSL_MD5_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_MD5_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_MD5}

const
  MD5_DIGEST_LENGTH = 16;
    {$if  not defined(OPENSSL_NO_DEPRECATED_3_0)}

type
  {Auto-generated forward references}
  PMD5_LONG = ^TMD5_LONG;
  PPMD5_LONG = ^PMD5_LONG;
  {end of auto-generated forward references}

      
      {* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      * ! MD5_LONG has to be at least 32 bits wide.                     !
      * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
      }
  TMD5_LONG = TOpenSSL_C_UINT;

const
  MD5_CBLOCK = 64;
  MD5_LBLOCK = MD5_CBLOCK/4;

type
  {Auto-generated forward references}
  PMD5state_st = ^TMD5state_st;
  PPMD5state_st = ^PMD5state_st;
  PMD5_CTX = ^TMD5_CTX;
  PPMD5_CTX = ^PMD5_CTX;
  {end of auto-generated forward references}

  TMD5state_st = record 
    A: TOpenSSL_C_UINT;
    B: TOpenSSL_C_UINT;
    C: TOpenSSL_C_UINT;
    D: TOpenSSL_C_UINT;
    Nl: TOpenSSL_C_UINT;
    Nh: TOpenSSL_C_UINT;
    data: array[0..(64 div 4)-1] of TOpenSSL_C_UINT;
    num: TOpenSSL_C_UINT;
  end;
  TMD5_CTX = TMD5state_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function MD5_Init(c: PMD5_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD5_Init'; deprecated 'Since OpenSSL 3.0';
  function MD5_Update(c: PMD5_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD5_Update'; deprecated 'Since OpenSSL 3.0';
  function MD5_Final(md: Pbyte; c: PMD5_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD5_Final'; deprecated 'Since OpenSSL 3.0';
  function MD5(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'MD5'; deprecated 'Since OpenSSL 3.0';
  procedure MD5_Transform(c: PMD5_CTX; b: Pbyte); cdecl; external CLibCrypto name 'MD5_Transform'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM MD5_Init}
  {$EXTERNALSYM MD5_Update}
  {$EXTERNALSYM MD5_Final}
  {$EXTERNALSYM MD5}
  {$EXTERNALSYM MD5_Transform}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_MD5_Init(c: PMD5_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MD5_Update(c: PMD5_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_MD5_Final(md: Pbyte; c: PMD5_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MD5(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
  procedure Load_MD5_Transform(c: PMD5_CTX; b: Pbyte); cdecl;

var
  MD5_Init: function(c: PMD5_CTX): TOpenSSL_C_INT; cdecl = Load_MD5_Init;
  MD5_Update: function(c: PMD5_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_MD5_Update;
  MD5_Final: function(md: Pbyte; c: PMD5_CTX): TOpenSSL_C_INT; cdecl = Load_MD5_Final;
  MD5: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_MD5;
  MD5_Transform: procedure(c: PMD5_CTX; b: Pbyte); cdecl = Load_MD5_Transform;
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
{$ifndef  OPENSSL_NO_MD5}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_MD5_Init(c: PMD5_CTX): TOpenSSL_C_INT; cdecl;
begin
  MD5_Init := LoadLibCryptoFunction('MD5_Init');
  if not assigned(MD5_Init) then
    {$if declared(LEGACY_MD5_Init)}
    MD5_Init := @LEGACY_MD5_Init;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD5_Init');
    {$ifend}
  Result := MD5_Init(c);
end;

function Load_MD5_Update(c: PMD5_CTX; data: pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  MD5_Update := LoadLibCryptoFunction('MD5_Update');
  if not assigned(MD5_Update) then
    {$if declared(LEGACY_MD5_Update)}
    MD5_Update := @LEGACY_MD5_Update;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD5_Update');
    {$ifend}
  Result := MD5_Update(c, data, len);
end;

function Load_MD5_Final(md: Pbyte; c: PMD5_CTX): TOpenSSL_C_INT; cdecl;
begin
  MD5_Final := LoadLibCryptoFunction('MD5_Final');
  if not assigned(MD5_Final) then
    {$if declared(LEGACY_MD5_Final)}
    MD5_Final := @LEGACY_MD5_Final;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD5_Final');
    {$ifend}
  Result := MD5_Final(md, c);
end;

function Load_MD5(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  MD5 := LoadLibCryptoFunction('MD5');
  if not assigned(MD5) then
    {$if declared(LEGACY_MD5)}
    MD5 := @LEGACY_MD5;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD5');
    {$ifend}
  Result := MD5(d, n, md);
end;

procedure Load_MD5_Transform(c: PMD5_CTX; b: Pbyte); cdecl;
begin
  MD5_Transform := LoadLibCryptoFunction('MD5_Transform');
  if not assigned(MD5_Transform) then
    {$if declared(LEGACY_MD5_Transform)}
    MD5_Transform := @LEGACY_MD5_Transform;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD5_Transform');
    {$ifend}
  MD5_Transform(c, b);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MD5}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_MD5}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  MD5_Init := Load_MD5_Init;
  MD5_Update := Load_MD5_Update;
  MD5_Final := Load_MD5_Final;
  MD5 := Load_MD5;
  MD5_Transform := Load_MD5_Transform;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MD5}
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



