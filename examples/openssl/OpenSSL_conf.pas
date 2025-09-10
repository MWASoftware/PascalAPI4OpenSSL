(* This unit was generated from the source file conf.h2pas 
It should not be modified directly. All changes should be made to conf.h2pas
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


unit OpenSSL_conf;


interface

// Headers for OpenSSL 1.1.1
// conf.h


uses
  OpenSSLAPI,
  OpenSSL_bio,
  OpenSSL_ossl_typ;

type
  CONF_parse_list_list_cb = function (const elem: PAnsiChar; len: TOpenSSL_C_INT; usr: Pointer): TOpenSSL_C_INT;

  CONF_VALUE = record
    section: PAnsiChar;
    name: PAnsiChar;
    value: PAnsiChar;
  end;
  PCONF_VALUE = ^CONF_VALUE;

//DEFINE_STACK_OF(CONF_VALUE)
//DEFINE_LHASH_OF(CONF_VALUE);

  conf_st = type Pointer;
  conf_method_st = type Pointer;
  CONF_METHOD = conf_method_st;
  PCONF_METHOD = ^conf_method_st;
  CONF = conf_st;
  PCONF = ^CONF;

  {conf_method_st = record
    const char *name;
    CONF *(*create) (CONF_METHOD *meth);
    int (*init) (CONF *conf);
    int (*destroy) (CONF *conf);
    int (*destroy_data) (CONF *conf);
    int (*load_bio) (CONF *conf, BIO *bp, long *eline);
    int (*dump) (const CONF *conf, BIO *bp);
    int (*is_number) (const CONF *conf, char c);
    int (*to_int) (const CONF *conf, char c);
    int (*load) (CONF *conf, const char *name, long *eline);
  end; }

//* Module definitions */

  conf_imodule_st = type Pointer;
  CONF_IMODULE = conf_imodule_st;
  PCONF_IMODULE = ^CONF_IMODULE;
  conf_module_st = type Pointer;
  CONF_MODULE = conf_module_st;
  PCONF_MODULE = ^CONF_MODULE;

//DEFINE_STACK_OF(CONF_MODULE)
//DEFINE_STACK_OF(CONF_IMODULE)

//* DSO module function typedefs */
  conf_init_func = function(md: PCONF_IMODULE; const cnf: PCONF): TOpenSSL_C_INT;
  conf_finish_func = procedure(md: PCONF_IMODULE);

const
  CONF_MFLAGS_IGNORE_ERRORS = $1;
  CONF_MFLAGS_IGNORE_RETURN_CODES = $2;
  CONF_MFLAGS_SILENT = $4;
  CONF_MFLAGS_NO_DSO = $8;
  CONF_MFLAGS_IGNORE_MISSING_FILE = $10;
  CONF_MFLAGS_DEFAULT_SECTION = $20;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM CONF_set_default_method}
{$EXTERNALSYM NCONF_new}
{$EXTERNALSYM NCONF_default}
{$EXTERNALSYM NCONF_WIN32}
{$EXTERNALSYM NCONF_free}
{$EXTERNALSYM NCONF_free_data}
{$EXTERNALSYM NCONF_load}
{$EXTERNALSYM NCONF_load_bio}
{$EXTERNALSYM NCONF_get_string}
{$EXTERNALSYM NCONF_get_number_e}
{$EXTERNALSYM NCONF_dump_bio}
{$EXTERNALSYM CONF_modules_load}
{$EXTERNALSYM CONF_modules_load_file}
{$EXTERNALSYM CONF_modules_unload}
{$EXTERNALSYM CONF_modules_finish}
{$EXTERNALSYM CONF_module_add}
{$EXTERNALSYM CONF_imodule_get_usr_data}
{$EXTERNALSYM CONF_imodule_set_usr_data}
{$EXTERNALSYM CONF_imodule_get_module}
{$EXTERNALSYM CONF_imodule_get_flags}
{$EXTERNALSYM CONF_imodule_set_flags}
{$EXTERNALSYM CONF_module_get_usr_data}
{$EXTERNALSYM CONF_module_set_usr_data}
{$EXTERNALSYM CONF_get1_default_config_file}
{$EXTERNALSYM CONF_parse_list}
{$EXTERNALSYM OPENSSL_load_builtin_modules}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function CONF_set_default_method(meth: PCONF_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_new(meth: PCONF_METHOD): PCONF; cdecl; external CLibCrypto;
function NCONF_default: PCONF_METHOD; cdecl; external CLibCrypto;
function NCONF_WIN32: PCONF_METHOD; cdecl; external CLibCrypto;
procedure NCONF_free(conf: PCONF); cdecl; external CLibCrypto;
procedure NCONF_free_data(conf: PCONF); cdecl; external CLibCrypto;
function NCONF_load(conf: PCONF; const file_: PAnsiChar; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_load_bio(conf: PCONF; bp: PBIO; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_get_string(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function NCONF_get_number_e(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function NCONF_dump_bio(const conf: PCONf; out_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CONF_modules_load(const cnf: PCONF; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CONF_modules_load_file(const filename: PAnsiChar; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure CONF_modules_unload(all: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure CONF_modules_finish; cdecl; external CLibCrypto;
function CONF_module_add(const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function CONF_imodule_get_usr_data(const md: PCONF_IMODULE): Pointer; cdecl; external CLibCrypto;
procedure CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl; external CLibCrypto;
function CONF_imodule_get_module(const md: PCONF_IMODULE): PCONF_MODULE; cdecl; external CLibCrypto;
function CONF_imodule_get_flags(const md: PCONF_IMODULE): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TOpenSSL_C_ULONG); cdecl; external CLibCrypto;
function CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl; external CLibCrypto;
procedure CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl; external CLibCrypto;
function CONF_get1_default_config_file: PAnsiChar; cdecl; external CLibCrypto;
function CONF_parse_list(const list: PAnsiChar; sep: TOpenSSL_C_INT; nospc: TOpenSSL_C_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OPENSSL_load_builtin_modules; cdecl; external CLibCrypto;

{$ELSE}
var
  CONF_set_default_method: function (meth: PCONF_METHOD): TOpenSSL_C_INT; cdecl = nil;
  NCONF_new: function (meth: PCONF_METHOD): PCONF; cdecl = nil;
  NCONF_default: function : PCONF_METHOD; cdecl = nil;
  NCONF_WIN32: function : PCONF_METHOD; cdecl = nil;
  NCONF_free: procedure (conf: PCONF); cdecl = nil;
  NCONF_free_data: procedure (conf: PCONF); cdecl = nil;
  NCONF_load: function (conf: PCONF; const file_: PAnsiChar; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  NCONF_load_bio: function (conf: PCONF; bp: PBIO; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  NCONF_get_string: function (const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl = nil;
  NCONF_get_number_e: function (const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  NCONF_dump_bio: function (const conf: PCONf; out_: PBIO): TOpenSSL_C_INT; cdecl = nil;
  CONF_modules_load: function (const cnf: PCONF; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  CONF_modules_load_file: function (const filename: PAnsiChar; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  CONF_modules_unload: procedure (all: TOpenSSL_C_INT); cdecl = nil;
  CONF_modules_finish: procedure ; cdecl = nil;
  CONF_module_add: function (const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TOpenSSL_C_INT; cdecl = nil;
  CONF_imodule_get_usr_data: function (const md: PCONF_IMODULE): Pointer; cdecl = nil;
  CONF_imodule_set_usr_data: procedure (md: PCONF_IMODULE; usr_data: Pointer); cdecl = nil;
  CONF_imodule_get_module: function (const md: PCONF_IMODULE): PCONF_MODULE; cdecl = nil;
  CONF_imodule_get_flags: function (const md: PCONF_IMODULE): TOpenSSL_C_ULONG; cdecl = nil;
  CONF_imodule_set_flags: procedure (md: PCONF_IMODULE; flags: TOpenSSL_C_ULONG); cdecl = nil;
  CONF_module_get_usr_data: function (pmod: PCONF_MODULE): Pointer; cdecl = nil;
  CONF_module_set_usr_data: procedure (pmod: PCONF_MODULE; usr_data: Pointer); cdecl = nil;
  CONF_get1_default_config_file: function : PAnsiChar; cdecl = nil;
  CONF_parse_list: function (const list: PAnsiChar; sep: TOpenSSL_C_INT; nospc: TOpenSSL_C_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  OPENSSL_load_builtin_modules: procedure ; cdecl = nil;
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
function ERROR_CONF_set_default_method(meth: PCONF_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_set_default_method');
end;

function ERROR_NCONF_new(meth: PCONF_METHOD): PCONF; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_new');
end;

function ERROR_NCONF_default: PCONF_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_default');
end;

function ERROR_NCONF_WIN32: PCONF_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_WIN32');
end;

procedure ERROR_NCONF_free(conf: PCONF); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_free');
end;

procedure ERROR_NCONF_free_data(conf: PCONF); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_free_data');
end;

function ERROR_NCONF_load(conf: PCONF; const file_: PAnsiChar; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_load');
end;

function ERROR_NCONF_load_bio(conf: PCONF; bp: PBIO; eline: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_load_bio');
end;

function ERROR_NCONF_get_string(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_get_string');
end;

function ERROR_NCONF_get_number_e(const conf: PCONF; const group: PAnsiChar; const name: PAnsiChar; result_: POpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_get_number_e');
end;

function ERROR_NCONF_dump_bio(const conf: PCONf; out_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('NCONF_dump_bio');
end;

function ERROR_CONF_modules_load(const cnf: PCONF; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_load');
end;

function ERROR_CONF_modules_load_file(const filename: PAnsiChar; const appname: PAnsiChar; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_load_file');
end;

procedure ERROR_CONF_modules_unload(all: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_unload');
end;

procedure ERROR_CONF_modules_finish; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_modules_finish');
end;

function ERROR_CONF_module_add(const name: PAnsiChar; ifunc: conf_init_func; ffunc: conf_finish_func): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_module_add');
end;

function ERROR_CONF_imodule_get_usr_data(const md: PCONF_IMODULE): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_get_usr_data');
end;

procedure ERROR_CONF_imodule_set_usr_data(md: PCONF_IMODULE; usr_data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_set_usr_data');
end;

function ERROR_CONF_imodule_get_module(const md: PCONF_IMODULE): PCONF_MODULE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_get_module');
end;

function ERROR_CONF_imodule_get_flags(const md: PCONF_IMODULE): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_get_flags');
end;

procedure ERROR_CONF_imodule_set_flags(md: PCONF_IMODULE; flags: TOpenSSL_C_ULONG); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_imodule_set_flags');
end;

function ERROR_CONF_module_get_usr_data(pmod: PCONF_MODULE): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_module_get_usr_data');
end;

procedure ERROR_CONF_module_set_usr_data(pmod: PCONF_MODULE; usr_data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_module_set_usr_data');
end;

function ERROR_CONF_get1_default_config_file: PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_get1_default_config_file');
end;

function ERROR_CONF_parse_list(const list: PAnsiChar; sep: TOpenSSL_C_INT; nospc: TOpenSSL_C_INT; list_cb: CONF_parse_list_list_cb; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('CONF_parse_list');
end;

procedure ERROR_OPENSSL_load_builtin_modules; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OPENSSL_load_builtin_modules');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  CONF_set_default_method := LoadLibCryptoFunction('CONF_set_default_method');
  FuncLoadError := not assigned(CONF_set_default_method);
  if FuncLoadError then
  begin
    CONF_set_default_method :=  @ERROR_CONF_set_default_method;
  end;

  NCONF_new := LoadLibCryptoFunction('NCONF_new');
  FuncLoadError := not assigned(NCONF_new);
  if FuncLoadError then
  begin
    NCONF_new :=  @ERROR_NCONF_new;
  end;

  NCONF_default := LoadLibCryptoFunction('NCONF_default');
  FuncLoadError := not assigned(NCONF_default);
  if FuncLoadError then
  begin
    NCONF_default :=  @ERROR_NCONF_default;
  end;

  NCONF_WIN32 := LoadLibCryptoFunction('NCONF_WIN32');
  FuncLoadError := not assigned(NCONF_WIN32);
  if FuncLoadError then
  begin
    NCONF_WIN32 :=  @ERROR_NCONF_WIN32;
  end;

  NCONF_free := LoadLibCryptoFunction('NCONF_free');
  FuncLoadError := not assigned(NCONF_free);
  if FuncLoadError then
  begin
    NCONF_free :=  @ERROR_NCONF_free;
  end;

  NCONF_free_data := LoadLibCryptoFunction('NCONF_free_data');
  FuncLoadError := not assigned(NCONF_free_data);
  if FuncLoadError then
  begin
    NCONF_free_data :=  @ERROR_NCONF_free_data;
  end;

  NCONF_load := LoadLibCryptoFunction('NCONF_load');
  FuncLoadError := not assigned(NCONF_load);
  if FuncLoadError then
  begin
    NCONF_load :=  @ERROR_NCONF_load;
  end;

  NCONF_load_bio := LoadLibCryptoFunction('NCONF_load_bio');
  FuncLoadError := not assigned(NCONF_load_bio);
  if FuncLoadError then
  begin
    NCONF_load_bio :=  @ERROR_NCONF_load_bio;
  end;

  NCONF_get_string := LoadLibCryptoFunction('NCONF_get_string');
  FuncLoadError := not assigned(NCONF_get_string);
  if FuncLoadError then
  begin
    NCONF_get_string :=  @ERROR_NCONF_get_string;
  end;

  NCONF_get_number_e := LoadLibCryptoFunction('NCONF_get_number_e');
  FuncLoadError := not assigned(NCONF_get_number_e);
  if FuncLoadError then
  begin
    NCONF_get_number_e :=  @ERROR_NCONF_get_number_e;
  end;

  NCONF_dump_bio := LoadLibCryptoFunction('NCONF_dump_bio');
  FuncLoadError := not assigned(NCONF_dump_bio);
  if FuncLoadError then
  begin
    NCONF_dump_bio :=  @ERROR_NCONF_dump_bio;
  end;

  CONF_modules_load := LoadLibCryptoFunction('CONF_modules_load');
  FuncLoadError := not assigned(CONF_modules_load);
  if FuncLoadError then
  begin
    CONF_modules_load :=  @ERROR_CONF_modules_load;
  end;

  CONF_modules_load_file := LoadLibCryptoFunction('CONF_modules_load_file');
  FuncLoadError := not assigned(CONF_modules_load_file);
  if FuncLoadError then
  begin
    CONF_modules_load_file :=  @ERROR_CONF_modules_load_file;
  end;

  CONF_modules_unload := LoadLibCryptoFunction('CONF_modules_unload');
  FuncLoadError := not assigned(CONF_modules_unload);
  if FuncLoadError then
  begin
    CONF_modules_unload :=  @ERROR_CONF_modules_unload;
  end;

  CONF_modules_finish := LoadLibCryptoFunction('CONF_modules_finish');
  FuncLoadError := not assigned(CONF_modules_finish);
  if FuncLoadError then
  begin
    CONF_modules_finish :=  @ERROR_CONF_modules_finish;
  end;

  CONF_module_add := LoadLibCryptoFunction('CONF_module_add');
  FuncLoadError := not assigned(CONF_module_add);
  if FuncLoadError then
  begin
    CONF_module_add :=  @ERROR_CONF_module_add;
  end;

  CONF_imodule_get_usr_data := LoadLibCryptoFunction('CONF_imodule_get_usr_data');
  FuncLoadError := not assigned(CONF_imodule_get_usr_data);
  if FuncLoadError then
  begin
    CONF_imodule_get_usr_data :=  @ERROR_CONF_imodule_get_usr_data;
  end;

  CONF_imodule_set_usr_data := LoadLibCryptoFunction('CONF_imodule_set_usr_data');
  FuncLoadError := not assigned(CONF_imodule_set_usr_data);
  if FuncLoadError then
  begin
    CONF_imodule_set_usr_data :=  @ERROR_CONF_imodule_set_usr_data;
  end;

  CONF_imodule_get_module := LoadLibCryptoFunction('CONF_imodule_get_module');
  FuncLoadError := not assigned(CONF_imodule_get_module);
  if FuncLoadError then
  begin
    CONF_imodule_get_module :=  @ERROR_CONF_imodule_get_module;
  end;

  CONF_imodule_get_flags := LoadLibCryptoFunction('CONF_imodule_get_flags');
  FuncLoadError := not assigned(CONF_imodule_get_flags);
  if FuncLoadError then
  begin
    CONF_imodule_get_flags :=  @ERROR_CONF_imodule_get_flags;
  end;

  CONF_imodule_set_flags := LoadLibCryptoFunction('CONF_imodule_set_flags');
  FuncLoadError := not assigned(CONF_imodule_set_flags);
  if FuncLoadError then
  begin
    CONF_imodule_set_flags :=  @ERROR_CONF_imodule_set_flags;
  end;

  CONF_module_get_usr_data := LoadLibCryptoFunction('CONF_module_get_usr_data');
  FuncLoadError := not assigned(CONF_module_get_usr_data);
  if FuncLoadError then
  begin
    CONF_module_get_usr_data :=  @ERROR_CONF_module_get_usr_data;
  end;

  CONF_module_set_usr_data := LoadLibCryptoFunction('CONF_module_set_usr_data');
  FuncLoadError := not assigned(CONF_module_set_usr_data);
  if FuncLoadError then
  begin
    CONF_module_set_usr_data :=  @ERROR_CONF_module_set_usr_data;
  end;

  CONF_get1_default_config_file := LoadLibCryptoFunction('CONF_get1_default_config_file');
  FuncLoadError := not assigned(CONF_get1_default_config_file);
  if FuncLoadError then
  begin
    CONF_get1_default_config_file :=  @ERROR_CONF_get1_default_config_file;
  end;

  CONF_parse_list := LoadLibCryptoFunction('CONF_parse_list');
  FuncLoadError := not assigned(CONF_parse_list);
  if FuncLoadError then
  begin
    CONF_parse_list :=  @ERROR_CONF_parse_list;
  end;

  OPENSSL_load_builtin_modules := LoadLibCryptoFunction('OPENSSL_load_builtin_modules');
  FuncLoadError := not assigned(OPENSSL_load_builtin_modules);
  if FuncLoadError then
  begin
    OPENSSL_load_builtin_modules :=  @ERROR_OPENSSL_load_builtin_modules;
  end;

end;

procedure UnLoad;
begin
  CONF_set_default_method := nil;
  NCONF_new := nil;
  NCONF_default := nil;
  NCONF_WIN32 := nil;
  NCONF_free := nil;
  NCONF_free_data := nil;
  NCONF_load := nil;
  NCONF_load_bio := nil;
  NCONF_get_string := nil;
  NCONF_get_number_e := nil;
  NCONF_dump_bio := nil;
  CONF_modules_load := nil;
  CONF_modules_load_file := nil;
  CONF_modules_unload := nil;
  CONF_modules_finish := nil;
  CONF_module_add := nil;
  CONF_imodule_get_usr_data := nil;
  CONF_imodule_set_usr_data := nil;
  CONF_imodule_get_module := nil;
  CONF_imodule_get_flags := nil;
  CONF_imodule_set_flags := nil;
  CONF_module_get_usr_data := nil;
  CONF_module_set_usr_data := nil;
  CONF_get1_default_config_file := nil;
  CONF_parse_list := nil;
  OPENSSL_load_builtin_modules := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
