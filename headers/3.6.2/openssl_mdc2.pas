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

unit openssl_mdc2;

{
  Generated from OpenSSL 3.6.2 Header File mdc2.h - Tue 19 May 14:30:15 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_mdc2.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_des;


{* Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_MDC2_H}
  {$define OPENSSL_MDC2_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_MDC2_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_MDC2}

const
  MDC2_DIGEST_LENGTH = 16;
    {$if  not defined(OPENSSL_NO_DEPRECATED_3_0)}

const
  MDC2_BLOCK = 8;

type
  {Auto-generated forward references}
  Pmdc2_ctx_st = ^Tmdc2_ctx_st;
  PPmdc2_ctx_st = ^Pmdc2_ctx_st;
  PMDC2_CTX = ^TMDC2_CTX;
  PPMDC2_CTX = ^PMDC2_CTX;
  {end of auto-generated forward references}

  Tmdc2_ctx_st = record 
    num: TOpenSSL_C_UINT;
    data: array[0..7] of byte;
    h: TDES_cblock;
    hh: TDES_cblock;
    pad_type: TOpenSSL_C_UINT; { either 1 or 2, default 1 }
  end;
  TMDC2_CTX = Tmdc2_ctx_st;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function MDC2_Init(c: PMDC2_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MDC2_Init'; deprecated 'Since OpenSSL 3.0';
  function MDC2_Update(c: PMDC2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MDC2_Update'; deprecated 'Since OpenSSL 3.0';
  function MDC2_Final(md: Pbyte; c: PMDC2_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'MDC2_Final'; deprecated 'Since OpenSSL 3.0';
  function MDC2(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'MDC2'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM MDC2_Init}
  {$EXTERNALSYM MDC2_Update}
  {$EXTERNALSYM MDC2_Final}
  {$EXTERNALSYM MDC2}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_MDC2_Init(c: PMDC2_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MDC2_Update(c: PMDC2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_MDC2_Final(md: Pbyte; c: PMDC2_CTX): TOpenSSL_C_INT; cdecl;
  function Load_MDC2(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;

var
  MDC2_Init: function(c: PMDC2_CTX): TOpenSSL_C_INT; cdecl = Load_MDC2_Init;
  MDC2_Update: function(c: PMDC2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_MDC2_Update;
  MDC2_Final: function(md: Pbyte; c: PMDC2_CTX): TOpenSSL_C_INT; cdecl = Load_MDC2_Final;
  MDC2: function(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_MDC2;
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
{$ifndef  OPENSSL_NO_MDC2}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_MDC2_Init(c: PMDC2_CTX): TOpenSSL_C_INT; cdecl;
begin
  MDC2_Init := LoadLibCryptoFunction('MDC2_Init');
  if not assigned(MDC2_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MDC2_Init');
  Result := MDC2_Init(c);
end;

function Load_MDC2_Update(c: PMDC2_CTX; data: Pbyte; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  MDC2_Update := LoadLibCryptoFunction('MDC2_Update');
  if not assigned(MDC2_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MDC2_Update');
  Result := MDC2_Update(c, data, len);
end;

function Load_MDC2_Final(md: Pbyte; c: PMDC2_CTX): TOpenSSL_C_INT; cdecl;
begin
  MDC2_Final := LoadLibCryptoFunction('MDC2_Final');
  if not assigned(MDC2_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MDC2_Final');
  Result := MDC2_Final(md, c);
end;

function Load_MDC2(d: Pbyte; n: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  MDC2 := LoadLibCryptoFunction('MDC2');
  if not assigned(MDC2) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('MDC2');
  Result := MDC2(d, n, md);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MDC2}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_MDC2}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  MDC2_Init := Load_MDC2_Init;
  MDC2_Update := Load_MDC2_Update;
  MDC2_Final := Load_MDC2_Final;
  MDC2 := Load_MDC2;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_MDC2}
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



