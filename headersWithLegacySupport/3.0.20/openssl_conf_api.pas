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

unit openssl_conf_api;

{
  Generated from OpenSSL 3.0.20 Header File conf_api.h - Tue 19 May 14:24:45 BST 2026
  With Legacy Support Option
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_conf_api.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_lhash,openssl_conf;


{* Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CONF_API_H}
  {$define OPENSSL_CONF_API_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_CONF_API_H}
  {$endif}


  { Up until OpenSSL 0.9.5a, this was new_section }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function _CONF_new_section(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl; external CLibCrypto name '_CONF_new_section';
  { Up until OpenSSL 0.9.5a, this was get_section }
  function _CONF_get_section(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl; external CLibCrypto name '_CONF_get_section';
  { Up until OpenSSL 0.9.5a, this was CONF_get_section }
  function _CONF_get_section_values(conf: PCONF; section: PAnsiChar): Pstack_st_CONF_VALUE; cdecl; external CLibCrypto name '_CONF_get_section_values';
  function _CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl; external CLibCrypto name '_CONF_add_string';
  function _CONF_get_string(conf: PCONF; section: PAnsiChar; name: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto name '_CONF_get_string';
  function _CONF_get_number(conf: PCONF; section: PAnsiChar; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name '_CONF_get_number';
  function _CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl; external CLibCrypto name '_CONF_new_data';
  procedure _CONF_free_data(conf: PCONF); cdecl; external CLibCrypto name '_CONF_free_data';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM _CONF_new_section}
  {$EXTERNALSYM _CONF_get_section}
  {$EXTERNALSYM _CONF_get_section_values}
  {$EXTERNALSYM _CONF_add_string}
  {$EXTERNALSYM _CONF_get_string}
  {$EXTERNALSYM _CONF_get_number}
  {$EXTERNALSYM _CONF_new_data}
  {$EXTERNALSYM _CONF_free_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load__CONF_new_section(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl;
  function Load__CONF_get_section(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl;
  function Load__CONF_get_section_values(conf: PCONF; section: PAnsiChar): Pstack_st_CONF_VALUE; cdecl;
  function Load__CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl;
  function Load__CONF_get_string(conf: PCONF; section: PAnsiChar; name: PAnsiChar): PAnsiChar; cdecl;
  function Load__CONF_get_number(conf: PCONF; section: PAnsiChar; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load__CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl;
  procedure Load__CONF_free_data(conf: PCONF); cdecl;

var
  _CONF_new_section: function(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl = Load__CONF_new_section;
  { Up until OpenSSL 0.9.5a, this was get_section }
  _CONF_get_section: function(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl = Load__CONF_get_section;
  { Up until OpenSSL 0.9.5a, this was CONF_get_section }
  _CONF_get_section_values: function(conf: PCONF; section: PAnsiChar): Pstack_st_CONF_VALUE; cdecl = Load__CONF_get_section_values;
  _CONF_add_string: function(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl = Load__CONF_add_string;
  _CONF_get_string: function(conf: PCONF; section: PAnsiChar; name: PAnsiChar): PAnsiChar; cdecl = Load__CONF_get_string;
  _CONF_get_number: function(conf: PCONF; section: PAnsiChar; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load__CONF_get_number;
  _CONF_new_data: function(conf: PCONF): TOpenSSL_C_INT; cdecl = Load__CONF_new_data;
  _CONF_free_data: procedure(conf: PCONF); cdecl = Load__CONF_free_data;
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
function Load__CONF_new_section(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl;
begin
  _CONF_new_section := LoadLibCryptoFunction('_CONF_new_section');
  if not assigned(_CONF_new_section) then
    {$if declared(LEGACY__CONF_new_section)}
    _CONF_new_section := @LEGACY__CONF_new_section;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_new_section');
    {$ifend}
  Result := _CONF_new_section(conf, section);
end;

function Load__CONF_get_section(conf: PCONF; section: PAnsiChar): PCONF_VALUE; cdecl;
begin
  _CONF_get_section := LoadLibCryptoFunction('_CONF_get_section');
  if not assigned(_CONF_get_section) then
    {$if declared(LEGACY__CONF_get_section)}
    _CONF_get_section := @LEGACY__CONF_get_section;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_section');
    {$ifend}
  Result := _CONF_get_section(conf, section);
end;

function Load__CONF_get_section_values(conf: PCONF; section: PAnsiChar): Pstack_st_CONF_VALUE; cdecl;
begin
  _CONF_get_section_values := LoadLibCryptoFunction('_CONF_get_section_values');
  if not assigned(_CONF_get_section_values) then
    {$if declared(LEGACY__CONF_get_section_values)}
    _CONF_get_section_values := @LEGACY__CONF_get_section_values;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_section_values');
    {$ifend}
  Result := _CONF_get_section_values(conf, section);
end;

function Load__CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl;
begin
  _CONF_add_string := LoadLibCryptoFunction('_CONF_add_string');
  if not assigned(_CONF_add_string) then
    {$if declared(LEGACY__CONF_add_string)}
    _CONF_add_string := @LEGACY__CONF_add_string;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_add_string');
    {$ifend}
  Result := _CONF_add_string(conf, section, value);
end;

function Load__CONF_get_string(conf: PCONF; section: PAnsiChar; name: PAnsiChar): PAnsiChar; cdecl;
begin
  _CONF_get_string := LoadLibCryptoFunction('_CONF_get_string');
  if not assigned(_CONF_get_string) then
    {$if declared(LEGACY__CONF_get_string)}
    _CONF_get_string := @LEGACY__CONF_get_string;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_string');
    {$ifend}
  Result := _CONF_get_string(conf, section, name);
end;

function Load__CONF_get_number(conf: PCONF; section: PAnsiChar; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  _CONF_get_number := LoadLibCryptoFunction('_CONF_get_number');
  if not assigned(_CONF_get_number) then
    {$if declared(LEGACY__CONF_get_number)}
    _CONF_get_number := @LEGACY__CONF_get_number;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_number');
    {$ifend}
  Result := _CONF_get_number(conf, section, name);
end;

function Load__CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl;
begin
  _CONF_new_data := LoadLibCryptoFunction('_CONF_new_data');
  if not assigned(_CONF_new_data) then
    {$if declared(LEGACY__CONF_new_data)}
    _CONF_new_data := @LEGACY__CONF_new_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_new_data');
    {$ifend}
  Result := _CONF_new_data(conf);
end;

procedure Load__CONF_free_data(conf: PCONF); cdecl;
begin
  _CONF_free_data := LoadLibCryptoFunction('_CONF_free_data');
  if not assigned(_CONF_free_data) then
    {$if declared(LEGACY__CONF_free_data)}
    _CONF_free_data := @LEGACY__CONF_free_data;
    {$else}
    EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_free_data');
    {$ifend}
  _CONF_free_data(conf);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  _CONF_new_section := Load__CONF_new_section;
  _CONF_get_section := Load__CONF_get_section;
  _CONF_get_section_values := Load__CONF_get_section_values;
  _CONF_add_string := Load__CONF_add_string;
  _CONF_get_string := Load__CONF_get_string;
  _CONF_get_number := Load__CONF_get_number;
  _CONF_new_data := Load__CONF_new_data;
  _CONF_free_data := Load__CONF_free_data;
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



