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

unit openssl_cmp_util;

{
  Generated from OpenSSL 4.0.0 Header File cmp_util.h - Tue 19 May 14:32:05 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_cmp_util.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_trace;


{* Copyright 2007-2021 The OpenSSL Project Authors. All Rights Reserved.
* Copyright Nokia 2007-2019
* Copyright Siemens AG 2015-2019
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CMP_UTIL_H}
  {$define OPENSSL_CMP_UTIL_H}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_CMP}
    {$include openssl_macros.inc}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_CMP_log_open: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_CMP_log_open';
  procedure OSSL_CMP_log_close; cdecl; external CLibCrypto name 'OSSL_CMP_log_close';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_CMP_log_open}
  {$EXTERNALSYM OSSL_CMP_log_close}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_CMP_log_open: TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_CMP_log_close; cdecl;

var
  OSSL_CMP_log_open: function: TOpenSSL_C_INT; cdecl = Load_OSSL_CMP_log_open;
  OSSL_CMP_log_close: procedure; cdecl = Load_OSSL_CMP_log_close;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  OSSL_CMP_LOG_PREFIX = 'CMP ';

type
  {Auto-generated forward references}
  POSSL_CMP_severity = ^TOSSL_CMP_severity;
  PPOSSL_CMP_severity = ^POSSL_CMP_severity;
  {end of auto-generated forward references}

    
    {* generalized logging/error callback mirroring the severity levels of syslog.h
    }
  TOSSL_CMP_severity = TOpenSSL_C_INT;

const
  OSSL_CMP_LOG_EMERG = 0;
  OSSL_CMP_LOG_ALERT = 1;
  OSSL_CMP_LOG_CRIT = 2;
  OSSL_CMP_LOG_ERR = 3;
  OSSL_CMP_LOG_WARNING = 4;
  OSSL_CMP_LOG_NOTICE = 5;
  OSSL_CMP_LOG_INFO = 6;
  OSSL_CMP_LOG_DEBUG = 7;
  OSSL_CMP_LOG_TRACE = 8;
  OSSL_CMP_LOG_MAX = OSSL_CMP_LOG_TRACE;

type
  {Auto-generated forward references}
  POSSL_CMP_log_cb_t = ^TOSSL_CMP_log_cb_t;
  PPOSSL_CMP_log_cb_t = ^POSSL_CMP_log_cb_t;
  {end of auto-generated forward references}

  TOSSL_CMP_log_cb_t = function(func: PAnsiChar; file_: PAnsiChar; line: TOpenSSL_C_INT; level: TOSSL_CMP_severity; msg: PAnsiChar): TOpenSSL_C_INT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_CMP_print_to_bio(bio: PBIO; component: PAnsiChar; file_: PAnsiChar; line: TOpenSSL_C_INT; level: TOSSL_CMP_severity; msg: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_CMP_print_to_bio';
  { use of the logging callback for outputting error queue }
  procedure OSSL_CMP_print_errors_cb(log_fn: TOSSL_CMP_log_cb_t); cdecl; external CLibCrypto name 'OSSL_CMP_print_errors_cb';
    {$else}
  {$EXTERNALSYM OSSL_CMP_print_to_bio}
  {$EXTERNALSYM OSSL_CMP_print_errors_cb}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_CMP_print_to_bio(bio: PBIO; component: PAnsiChar; file_: PAnsiChar; line: TOpenSSL_C_INT; level: TOSSL_CMP_severity; msg: PAnsiChar): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_CMP_print_errors_cb(log_fn: TOSSL_CMP_log_cb_t); cdecl;

var
  OSSL_CMP_print_to_bio: function(bio: PBIO; component: PAnsiChar; file_: PAnsiChar; line: TOpenSSL_C_INT; level: TOSSL_CMP_severity; msg: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_CMP_print_to_bio;
  { use of the logging callback for outputting error queue }
  OSSL_CMP_print_errors_cb: procedure(log_fn: TOSSL_CMP_log_cb_t); cdecl = Load_OSSL_CMP_print_errors_cb;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  { !defined(OPENSSL_NO_CMP) }
{$endif}
{ !defined(OPENSSL_CMP_UTIL_H) }

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
{$ifndef  OPENSSL_NO_CMP}
function Load_OSSL_CMP_log_open: TOpenSSL_C_INT; cdecl;
begin
  OSSL_CMP_log_open := LoadLibCryptoFunction('OSSL_CMP_log_open');
  if not assigned(OSSL_CMP_log_open) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_CMP_log_open');
  Result := OSSL_CMP_log_open;
end;

procedure Load_OSSL_CMP_log_close; cdecl;
begin
  OSSL_CMP_log_close := LoadLibCryptoFunction('OSSL_CMP_log_close');
  if not assigned(OSSL_CMP_log_close) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_CMP_log_close');
  OSSL_CMP_log_close;
end;

function Load_OSSL_CMP_print_to_bio(bio: PBIO; component: PAnsiChar; file_: PAnsiChar; line: TOpenSSL_C_INT; level: TOSSL_CMP_severity; msg: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_CMP_print_to_bio := LoadLibCryptoFunction('OSSL_CMP_print_to_bio');
  if not assigned(OSSL_CMP_print_to_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_CMP_print_to_bio');
  Result := OSSL_CMP_print_to_bio(bio, component, file_, line, level, msg);
end;

procedure Load_OSSL_CMP_print_errors_cb(log_fn: TOSSL_CMP_log_cb_t); cdecl;
begin
  OSSL_CMP_print_errors_cb := LoadLibCryptoFunction('OSSL_CMP_print_errors_cb');
  if not assigned(OSSL_CMP_print_errors_cb) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_CMP_print_errors_cb');
  OSSL_CMP_print_errors_cb(log_fn);
end;

{$endif} { OPENSSL_NO_CMP}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_CMP}
  OSSL_CMP_log_open := Load_OSSL_CMP_log_open;
  OSSL_CMP_log_close := Load_OSSL_CMP_log_close;
  OSSL_CMP_print_to_bio := Load_OSSL_CMP_print_to_bio;
  OSSL_CMP_print_errors_cb := Load_OSSL_CMP_print_errors_cb;
{$endif} { OPENSSL_NO_CMP}
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



