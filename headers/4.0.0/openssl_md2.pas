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

unit openssl_md2;

{
  Generated from OpenSSL 4.0.0 Header File md2.h - Tue 19 May 14:32:48 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_md2.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_MD2_H}
  {$define OPENSSL_MD2_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_MD2_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_MD2}

const
  MD2_DIGEST_LENGTH = 16;
    {$if  not defined(OPENSSL_NO_DEPRECATED_3_0)}

type
  {Auto-generated forward references}
  PMD2_INT = ^TMD2_INT;
  PPMD2_INT = ^PMD2_INT;
  {end of auto-generated forward references}

  TMD2_INT = byte;

const
  MD2_BLOCK = 16;

type
  {Auto-generated forward references}
  PMD2state_st = ^TMD2state_st;
  PPMD2state_st = ^PMD2state_st;
  PMD2_CTX = ^TMD2_CTX;
  PPMD2_CTX = ^PMD2_CTX;
  {end of auto-generated forward references}

  TMD2state_st = record 
    num: TOpenSSL_C_UINT;
    data: array[0..15] of byte;
    cksm: array[0..15] of TMD2_INT;
    state: array[0..15] of TMD2_INT;
  end;
  TMD2_CTX = TMD2state_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function MD2_options: PAnsiChar; cdecl; external CLibCrypto name 'MD2_options'; deprecated 'Since OpenSSL 3.0';
  function MD2_Init(c: PMD2_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD2_Init'; deprecated 'Since OpenSSL 3.0';
  function MD2_Update(c: PMD2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD2_Update'; deprecated 'Since OpenSSL 3.0';
  function MD2_Final(md: Pbyte; c: PMD2_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MD2_Final'; deprecated 'Since OpenSSL 3.0';
  function MD2(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'MD2'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM MD2_options}
  {$EXTERNALSYM MD2_Init}
  {$EXTERNALSYM MD2_Update}
  {$EXTERNALSYM MD2_Final}
  {$EXTERNALSYM MD2}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_MD2_options: PAnsiChar; cdecl;
  function Load_MD2_Init(c: PMD2_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MD2_Update(c: PMD2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_MD2_Final(md: Pbyte; c: PMD2_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MD2(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;

var
  MD2_options: function: PAnsiChar; cdecl = Load_MD2_options;
  MD2_Init: function(c: PMD2_CTX): TOpenSSL_C_INT; cdecl = Load_MD2_Init;
  MD2_Update: function(c: PMD2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_MD2_Update;
  MD2_Final: function(md: Pbyte; c: PMD2_CTX): TOpenSSL_C_INT; cdecl = Load_MD2_Final;
  MD2: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_MD2;
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
{$ifndef  OPENSSL_NO_MD2}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_MD2_options: PAnsiChar; cdecl;
begin
  MD2_options := LoadLibCryptoFunction('MD2_options');
  if not assigned(MD2_options) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD2_options');
  Result := MD2_options;
end;

function Load_MD2_Init(c: PMD2_CTX): TOpenSSL_C_INT; cdecl;
begin
  MD2_Init := LoadLibCryptoFunction('MD2_Init');
  if not assigned(MD2_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD2_Init');
  Result := MD2_Init(c);
end;

function Load_MD2_Update(c: PMD2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  MD2_Update := LoadLibCryptoFunction('MD2_Update');
  if not assigned(MD2_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD2_Update');
  Result := MD2_Update(c, data, len);
end;

function Load_MD2_Final(md: Pbyte; c: PMD2_CTX): TOpenSSL_C_INT; cdecl;
begin
  MD2_Final := LoadLibCryptoFunction('MD2_Final');
  if not assigned(MD2_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD2_Final');
  Result := MD2_Final(md, c);
end;

function Load_MD2(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  MD2 := LoadLibCryptoFunction('MD2');
  if not assigned(MD2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MD2');
  Result := MD2(d, n, md);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MD2}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_MD2}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  MD2_options := Load_MD2_options;
  MD2_Init := Load_MD2_Init;
  MD2_Update := Load_MD2_Update;
  MD2_Final := Load_MD2_Final;
  MD2 := Load_MD2;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MD2}
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



