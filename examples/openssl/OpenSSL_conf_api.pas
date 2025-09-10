(* This unit was generated from the source file conf_api.h2pas 
It should not be modified directly. All changes should be made to conf_api.h2pas
and this file regenerated *)

{$i OpenSSLDefines.inc}

{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License").

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.

    This file includes software copied from the Indy (Internet Direct) project, and which is offered
    under the dual-licensing agreement described on the Indy website. (https://www.indyproject.org/license/)
    }


unit OpenSSL_conf_api;


interface

// Headers for OpenSSL 1.1.1
// conf_api.h


uses
  OpenSSLAPI,
  OpenSSL_conf;

  //* Up until OpenSSL 0.9.5a, this was new_section */
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM _CONF_new_section}
{$EXTERNALSYM _CONF_get_section}
{$EXTERNALSYM _CONF_add_string}
{$EXTERNALSYM _CONF_get_string}
{$EXTERNALSYM _CONF_get_number}
{$EXTERNALSYM _CONF_new_data}
{$EXTERNALSYM _CONF_free_data}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function _CONF_new_section(conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl; external CLibCrypto;
function _CONF_get_section(const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl; external CLibCrypto;
function _CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function _CONF_get_string(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function _CONF_get_number(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function _CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure _CONF_free_data(conf: PCONF); cdecl; external CLibCrypto;

{$ELSE}
var
  _CONF_new_section: function (conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl = nil;
  _CONF_get_section: function (const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl = nil;
  _CONF_add_string: function (conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl = nil;
  _CONF_get_string: function (const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl = nil;
  _CONF_get_number: function (const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TOpenSSL_C_LONG; cdecl = nil;
  _CONF_new_data: function (conf: PCONF): TOpenSSL_C_INT; cdecl = nil;
  _CONF_free_data: procedure (conf: PCONF); cdecl = nil;
{$ENDIF}

implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR__CONF_new_section(conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_new_section');
end;

function ERROR__CONF_get_section(const conf: PCONF; const section: PAnsiChar): PCONF_VALUE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_section');
end;

function ERROR__CONF_add_string(conf: PCONF; section: PCONF_VALUE; value: PCONF_VALUE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_add_string');
end;

function ERROR__CONF_get_string(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_string');
end;

function ERROR__CONF_get_number(const conf: PCONF; const section: PAnsiChar; const name: PAnsiChar): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_get_number');
end;

function ERROR__CONF_new_data(conf: PCONF): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_new_data');
end;

procedure ERROR__CONF_free_data(conf: PCONF); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('_CONF_free_data');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  _CONF_new_section := LoadLibCryptoFunction('_CONF_new_section');
  FuncLoadError := not assigned(_CONF_new_section);
  if FuncLoadError then
  begin
    _CONF_new_section :=  @ERROR__CONF_new_section;
  end;

  _CONF_get_section := LoadLibCryptoFunction('_CONF_get_section');
  FuncLoadError := not assigned(_CONF_get_section);
  if FuncLoadError then
  begin
    _CONF_get_section :=  @ERROR__CONF_get_section;
  end;

  _CONF_add_string := LoadLibCryptoFunction('_CONF_add_string');
  FuncLoadError := not assigned(_CONF_add_string);
  if FuncLoadError then
  begin
    _CONF_add_string :=  @ERROR__CONF_add_string;
  end;

  _CONF_get_string := LoadLibCryptoFunction('_CONF_get_string');
  FuncLoadError := not assigned(_CONF_get_string);
  if FuncLoadError then
  begin
    _CONF_get_string :=  @ERROR__CONF_get_string;
  end;

  _CONF_get_number := LoadLibCryptoFunction('_CONF_get_number');
  FuncLoadError := not assigned(_CONF_get_number);
  if FuncLoadError then
  begin
    _CONF_get_number :=  @ERROR__CONF_get_number;
  end;

  _CONF_new_data := LoadLibCryptoFunction('_CONF_new_data');
  FuncLoadError := not assigned(_CONF_new_data);
  if FuncLoadError then
  begin
    _CONF_new_data :=  @ERROR__CONF_new_data;
  end;

  _CONF_free_data := LoadLibCryptoFunction('_CONF_free_data');
  FuncLoadError := not assigned(_CONF_free_data);
  if FuncLoadError then
  begin
    _CONF_free_data :=  @ERROR__CONF_free_data;
  end;

end;

procedure UnLoad;
begin
  _CONF_new_section := nil;
  _CONF_get_section := nil;
  _CONF_add_string := nil;
  _CONF_get_string := nil;
  _CONF_get_number := nil;
  _CONF_new_data := nil;
  _CONF_free_data := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
