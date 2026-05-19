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

unit openssl_ebcdic;

{
  Generated from OpenSSL 3.6.2 Header File ebcdic.h - Tue 19 May 14:29:54 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_ebcdic.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_EBCDIC_H}
  {$define OPENSSL_EBCDIC_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_EBCDIC_H}
  {$endif}
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  {$ifdef FPC}

var
  os_toascii: array[0..255] of byte cvar; public;
  os_toebcdic: array[0..255] of byte cvar; public;
  {$endif}
  {$endif} {OPENSSL_STATIC_LINK_MODEL}


  { Avoid name clashes with other applications }
  {#define os_toascii _openssl_os_toascii}
  {#define os_toebcdic _openssl_os_toebcdic}
  {#define ebcdic2ascii _openssl_ebcdic2ascii}
  {#define ascii2ebcdic _openssl_ascii2ebcdic}
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ebcdic2ascii(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl; external CLibCrypto name 'ebcdic2ascii';
  function ascii2ebcdic(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl; external CLibCrypto name 'ascii2ebcdic';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM ebcdic2ascii}
  {$EXTERNALSYM ascii2ebcdic}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ebcdic2ascii(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl;
  function Load_ascii2ebcdic(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl;

var
  ebcdic2ascii: function(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl = Load_ebcdic2ascii;
  ascii2ebcdic: function(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl = Load_ascii2ebcdic;
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
function Load_ebcdic2ascii(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl;
begin
  ebcdic2ascii := LoadLibCryptoFunction('ebcdic2ascii');
  if not assigned(ebcdic2ascii) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ebcdic2ascii');
  Result := ebcdic2ascii(dest, srce, count);
end;

function Load_ascii2ebcdic(dest: pointer; srce: pointer; count: TOpenSSL_C_SIZET): pointer; cdecl;
begin
  ascii2ebcdic := LoadLibCryptoFunction('ascii2ebcdic');
  if not assigned(ascii2ebcdic) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ascii2ebcdic');
  Result := ascii2ebcdic(dest, srce, count);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  ebcdic2ascii := Load_ebcdic2ascii;
  ascii2ebcdic := Load_ascii2ebcdic;
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



