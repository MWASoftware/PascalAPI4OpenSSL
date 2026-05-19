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

unit openssl_whrlpool;

{
  Generated from OpenSSL 3.6.2 Header File whrlpool.h - Tue 19 May 14:31:07 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_whrlpool.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_e_os2;


{* Copyright 2005-2020 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_WHRLPOOL_H}
  {$define OPENSSL_WHRLPOOL_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_WHRLPOOL_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_WHIRLPOOL}

const
  WHIRLPOOL_DIGEST_LENGTH = 512/8;
    {$if  not defined(OPENSSL_NO_DEPRECATED_3_0)}

const
  WHIRLPOOL_BBLOCK = 512;
  WHIRLPOOL_COUNTER = 256/8;

type
  {Auto-generated forward references}
  PWHIRLPOOL_CTX = ^TWHIRLPOOL_CTX;
  PPWHIRLPOOL_CTX = ^PWHIRLPOOL_CTX;
  {end of auto-generated forward references}

  TWHIRLPOOL_CTX = record 
    H: record 
      case integer of 
        0: (c: array[0..(512 div 8)-1] of byte); { double q is here to ensure 64-bit alignment }
        1: (q: array[0..((512 div 8) div (sizeof(TOpenSSL_C_DOUBLE)))-1] of TOpenSSL_C_DOUBLE);
    end;
    data: array[0..(512 div 8)-1] of byte;
    bitoff: TOpenSSL_C_UINT;
    bitlen: array[0..((256 div 8) div (sizeof(TOpenSSL_C_SIZET)))-1] of TOpenSSL_C_SIZET;
  end;
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'WHIRLPOOL_Init'; deprecated 'Since OpenSSL 3.0';
  function WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'WHIRLPOOL_Update'; deprecated 'Since OpenSSL 3.0';
  procedure WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: pointer; bits: TOpenSSL_C_SIZET); cdecl; external CLibCrypto name 'WHIRLPOOL_BitUpdate'; deprecated 'Since OpenSSL 3.0';
  function WHIRLPOOL_Final(md: Pbyte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'WHIRLPOOL_Final'; deprecated 'Since OpenSSL 3.0';
  function WHIRLPOOL(inp: pointer; bytes: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl; external CLibCrypto name 'WHIRLPOOL'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM WHIRLPOOL_Init}
  {$EXTERNALSYM WHIRLPOOL_Update}
  {$EXTERNALSYM WHIRLPOOL_BitUpdate}
  {$EXTERNALSYM WHIRLPOOL_Final}
  {$EXTERNALSYM WHIRLPOOL}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
  function Load_WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  procedure Load_WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: pointer; bits: TOpenSSL_C_SIZET); cdecl;
  function Load_WHIRLPOOL_Final(md: Pbyte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
  function Load_WHIRLPOOL(inp: pointer; bytes: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;

var
  WHIRLPOOL_Init: function(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl = Load_WHIRLPOOL_Init;
  WHIRLPOOL_Update: function(c: PWHIRLPOOL_CTX; inp: pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_WHIRLPOOL_Update;
  WHIRLPOOL_BitUpdate: procedure(c: PWHIRLPOOL_CTX; inp: pointer; bits: TOpenSSL_C_SIZET); cdecl = Load_WHIRLPOOL_BitUpdate;
  WHIRLPOOL_Final: function(md: Pbyte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl = Load_WHIRLPOOL_Final;
  WHIRLPOOL: function(inp: pointer; bytes: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl = Load_WHIRLPOOL;
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
{$ifndef  OPENSSL_NO_WHIRLPOOL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
begin
  WHIRLPOOL_Init := LoadLibCryptoFunction('WHIRLPOOL_Init');
  if not assigned(WHIRLPOOL_Init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Init');
  Result := WHIRLPOOL_Init(c);
end;

function Load_WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  WHIRLPOOL_Update := LoadLibCryptoFunction('WHIRLPOOL_Update');
  if not assigned(WHIRLPOOL_Update) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Update');
  Result := WHIRLPOOL_Update(c, inp, bytes);
end;

procedure Load_WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: pointer; bits: TOpenSSL_C_SIZET); cdecl;
begin
  WHIRLPOOL_BitUpdate := LoadLibCryptoFunction('WHIRLPOOL_BitUpdate');
  if not assigned(WHIRLPOOL_BitUpdate) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_BitUpdate');
  WHIRLPOOL_BitUpdate(c, inp, bits);
end;

function Load_WHIRLPOOL_Final(md: Pbyte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
begin
  WHIRLPOOL_Final := LoadLibCryptoFunction('WHIRLPOOL_Final');
  if not assigned(WHIRLPOOL_Final) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Final');
  Result := WHIRLPOOL_Final(md, c);
end;

function Load_WHIRLPOOL(inp: pointer; bytes: TOpenSSL_C_SIZET; md: Pbyte): Pbyte; cdecl;
begin
  WHIRLPOOL := LoadLibCryptoFunction('WHIRLPOOL');
  if not assigned(WHIRLPOOL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL');
  Result := WHIRLPOOL(inp, bytes, md);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_WHIRLPOOL}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_WHIRLPOOL}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  WHIRLPOOL_Init := Load_WHIRLPOOL_Init;
  WHIRLPOOL_Update := Load_WHIRLPOOL_Update;
  WHIRLPOOL_BitUpdate := Load_WHIRLPOOL_BitUpdate;
  WHIRLPOOL_Final := Load_WHIRLPOOL_Final;
  WHIRLPOOL := Load_WHIRLPOOL;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_WHIRLPOOL}
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



