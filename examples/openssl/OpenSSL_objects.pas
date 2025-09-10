(* This unit was generated from the source file objects.h2pas 
It should not be modified directly. All changes should be made to objects.h2pas
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


unit OpenSSL_objects;


interface

// Headers for OpenSSL 1.1.1
// objects.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ;

type
  obj_name_st = record
    type_: TOpenSSL_C_INT;
    alias: TOpenSSL_C_INT;
    name: PAnsiChar;
    data: PAnsiChar;
  end;
  OBJ_NAME = obj_name_st;
  POBJ_NAME = ^OBJ_NAME;

//# define         OBJ_create_and_add_object(a,b,c) OBJ_create(a,b,c)

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM OBJ_NAME_init}
{$EXTERNALSYM OBJ_NAME_get}
{$EXTERNALSYM OBJ_NAME_add}
{$EXTERNALSYM OBJ_NAME_remove}
{$EXTERNALSYM OBJ_NAME_cleanup}
{$EXTERNALSYM OBJ_dup}
{$EXTERNALSYM OBJ_nid2obj}
{$EXTERNALSYM OBJ_nid2ln}
{$EXTERNALSYM OBJ_nid2sn}
{$EXTERNALSYM OBJ_obj2nid}
{$EXTERNALSYM OBJ_txt2obj}
{$EXTERNALSYM OBJ_obj2txt}
{$EXTERNALSYM OBJ_txt2nid}
{$EXTERNALSYM OBJ_ln2nid}
{$EXTERNALSYM OBJ_sn2nid}
{$EXTERNALSYM OBJ_cmp}
{$EXTERNALSYM OBJ_new_nid}
{$EXTERNALSYM OBJ_add_object}
{$EXTERNALSYM OBJ_create}
{$EXTERNALSYM OBJ_create_objects}
{$EXTERNALSYM OBJ_length}
{$EXTERNALSYM OBJ_get0_data}
{$EXTERNALSYM OBJ_find_sigid_algs}
{$EXTERNALSYM OBJ_find_sigid_by_algs}
{$EXTERNALSYM OBJ_add_sigid}
{$EXTERNALSYM OBJ_sigid_free}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function OBJ_NAME_init: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_NAME_get(const name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OBJ_NAME_add(const name: PAnsiChar; type_: TOpenSSL_C_INT; const data: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_NAME_remove(const name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function OBJ_dup(const o: PASN1_OBJECT): PASN1_OBJECT; cdecl; external CLibCrypto;
function OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl; external CLibCrypto;
function OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function OBJ_obj2nid(const o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_txt2obj(const s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl; external CLibCrypto;
function OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_txt2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_ln2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_sn2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_cmp(const a: PASN1_OBJECT; const b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_add_object(const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_create(const oid: PAnsiChar; const sn: PAnsiChar; const ln: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_length(const obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function OBJ_get0_data(const obj: PASN1_OBJECT): PByte; cdecl; external CLibCrypto;
function OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure OBJ_sigid_free; cdecl; external CLibCrypto;

{$ELSE}
var
  OBJ_NAME_init: function : TOpenSSL_C_INT; cdecl = nil;
  OBJ_NAME_get: function (const name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  OBJ_NAME_add: function (const name: PAnsiChar; type_: TOpenSSL_C_INT; const data: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  OBJ_NAME_remove: function (const name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_NAME_cleanup: procedure (type_: TOpenSSL_C_INT); cdecl = nil;
  OBJ_dup: function (const o: PASN1_OBJECT): PASN1_OBJECT; cdecl = nil;
  OBJ_nid2obj: function (n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl = nil;
  OBJ_nid2ln: function (n: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  OBJ_nid2sn: function (n: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  OBJ_obj2nid: function (const o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_txt2obj: function (const s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl = nil;
  OBJ_obj2txt: function (buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_txt2nid: function (const s: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  OBJ_ln2nid: function (const s: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  OBJ_sn2nid: function (const s: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  OBJ_cmp: function (const a: PASN1_OBJECT; const b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_new_nid: function (num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_add_object: function (const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_create: function (const oid: PAnsiChar; const sn: PAnsiChar; const ln: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  OBJ_create_objects: function (in_: PBIO): TOpenSSL_C_INT; cdecl = nil;
  OBJ_length: function (const obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl = nil;
  OBJ_get0_data: function (const obj: PASN1_OBJECT): PByte; cdecl = nil;
  OBJ_find_sigid_algs: function (signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_find_sigid_by_algs: function (psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_add_sigid: function (signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  OBJ_sigid_free: procedure ; cdecl = nil;
{$ENDIF}
const
  OBJ_length_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  OBJ_get0_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


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
function ERROR_OBJ_NAME_init: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_init');
end;

function ERROR_OBJ_NAME_get(const name: PAnsiChar; type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_get');
end;

function ERROR_OBJ_NAME_add(const name: PAnsiChar; type_: TOpenSSL_C_INT; const data: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_add');
end;

function ERROR_OBJ_NAME_remove(const name: PAnsiChar; type_: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_remove');
end;

procedure ERROR_OBJ_NAME_cleanup(type_: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_NAME_cleanup');
end;

function ERROR_OBJ_dup(const o: PASN1_OBJECT): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_dup');
end;

function ERROR_OBJ_nid2obj(n: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2obj');
end;

function ERROR_OBJ_nid2ln(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2ln');
end;

function ERROR_OBJ_nid2sn(n: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_nid2sn');
end;

function ERROR_OBJ_obj2nid(const o: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_obj2nid');
end;

function ERROR_OBJ_txt2obj(const s: PAnsiChar; no_name: TOpenSSL_C_INT): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_txt2obj');
end;

function ERROR_OBJ_obj2txt(buf: PAnsiChar; buf_len: TOpenSSL_C_INT; const a: PASN1_OBJECT; no_name: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_obj2txt');
end;

function ERROR_OBJ_txt2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_txt2nid');
end;

function ERROR_OBJ_ln2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_ln2nid');
end;

function ERROR_OBJ_sn2nid(const s: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_sn2nid');
end;

function ERROR_OBJ_cmp(const a: PASN1_OBJECT; const b: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_cmp');
end;

function ERROR_OBJ_new_nid(num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_new_nid');
end;

function ERROR_OBJ_add_object(const obj: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_add_object');
end;

function ERROR_OBJ_create(const oid: PAnsiChar; const sn: PAnsiChar; const ln: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_create');
end;

function ERROR_OBJ_create_objects(in_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_create_objects');
end;

function ERROR_OBJ_length(const obj: PASN1_OBJECT): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_length');
end;

function ERROR_OBJ_get0_data(const obj: PASN1_OBJECT): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_get0_data');
end;

function ERROR_OBJ_find_sigid_algs(signid: TOpenSSL_C_INT; pdig_nid: POpenSSL_C_INT; ppkey_nid: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_find_sigid_algs');
end;

function ERROR_OBJ_find_sigid_by_algs(psignid: POpenSSL_C_INT; dig_nid: TOpenSSL_C_INT; pkey_nid: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_find_sigid_by_algs');
end;

function ERROR_OBJ_add_sigid(signid: TOpenSSL_C_INT; dig_id: TOpenSSL_C_INT; pkey_id: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_add_sigid');
end;

procedure ERROR_OBJ_sigid_free; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('OBJ_sigid_free');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  OBJ_NAME_init := LoadLibCryptoFunction('OBJ_NAME_init');
  FuncLoadError := not assigned(OBJ_NAME_init);
  if FuncLoadError then
  begin
    OBJ_NAME_init :=  @ERROR_OBJ_NAME_init;
  end;

  OBJ_NAME_get := LoadLibCryptoFunction('OBJ_NAME_get');
  FuncLoadError := not assigned(OBJ_NAME_get);
  if FuncLoadError then
  begin
    OBJ_NAME_get :=  @ERROR_OBJ_NAME_get;
  end;

  OBJ_NAME_add := LoadLibCryptoFunction('OBJ_NAME_add');
  FuncLoadError := not assigned(OBJ_NAME_add);
  if FuncLoadError then
  begin
    OBJ_NAME_add :=  @ERROR_OBJ_NAME_add;
  end;

  OBJ_NAME_remove := LoadLibCryptoFunction('OBJ_NAME_remove');
  FuncLoadError := not assigned(OBJ_NAME_remove);
  if FuncLoadError then
  begin
    OBJ_NAME_remove :=  @ERROR_OBJ_NAME_remove;
  end;

  OBJ_NAME_cleanup := LoadLibCryptoFunction('OBJ_NAME_cleanup');
  FuncLoadError := not assigned(OBJ_NAME_cleanup);
  if FuncLoadError then
  begin
    OBJ_NAME_cleanup :=  @ERROR_OBJ_NAME_cleanup;
  end;

  OBJ_dup := LoadLibCryptoFunction('OBJ_dup');
  FuncLoadError := not assigned(OBJ_dup);
  if FuncLoadError then
  begin
    OBJ_dup :=  @ERROR_OBJ_dup;
  end;

  OBJ_nid2obj := LoadLibCryptoFunction('OBJ_nid2obj');
  FuncLoadError := not assigned(OBJ_nid2obj);
  if FuncLoadError then
  begin
    OBJ_nid2obj :=  @ERROR_OBJ_nid2obj;
  end;

  OBJ_nid2ln := LoadLibCryptoFunction('OBJ_nid2ln');
  FuncLoadError := not assigned(OBJ_nid2ln);
  if FuncLoadError then
  begin
    OBJ_nid2ln :=  @ERROR_OBJ_nid2ln;
  end;

  OBJ_nid2sn := LoadLibCryptoFunction('OBJ_nid2sn');
  FuncLoadError := not assigned(OBJ_nid2sn);
  if FuncLoadError then
  begin
    OBJ_nid2sn :=  @ERROR_OBJ_nid2sn;
  end;

  OBJ_obj2nid := LoadLibCryptoFunction('OBJ_obj2nid');
  FuncLoadError := not assigned(OBJ_obj2nid);
  if FuncLoadError then
  begin
    OBJ_obj2nid :=  @ERROR_OBJ_obj2nid;
  end;

  OBJ_txt2obj := LoadLibCryptoFunction('OBJ_txt2obj');
  FuncLoadError := not assigned(OBJ_txt2obj);
  if FuncLoadError then
  begin
    OBJ_txt2obj :=  @ERROR_OBJ_txt2obj;
  end;

  OBJ_obj2txt := LoadLibCryptoFunction('OBJ_obj2txt');
  FuncLoadError := not assigned(OBJ_obj2txt);
  if FuncLoadError then
  begin
    OBJ_obj2txt :=  @ERROR_OBJ_obj2txt;
  end;

  OBJ_txt2nid := LoadLibCryptoFunction('OBJ_txt2nid');
  FuncLoadError := not assigned(OBJ_txt2nid);
  if FuncLoadError then
  begin
    OBJ_txt2nid :=  @ERROR_OBJ_txt2nid;
  end;

  OBJ_ln2nid := LoadLibCryptoFunction('OBJ_ln2nid');
  FuncLoadError := not assigned(OBJ_ln2nid);
  if FuncLoadError then
  begin
    OBJ_ln2nid :=  @ERROR_OBJ_ln2nid;
  end;

  OBJ_sn2nid := LoadLibCryptoFunction('OBJ_sn2nid');
  FuncLoadError := not assigned(OBJ_sn2nid);
  if FuncLoadError then
  begin
    OBJ_sn2nid :=  @ERROR_OBJ_sn2nid;
  end;

  OBJ_cmp := LoadLibCryptoFunction('OBJ_cmp');
  FuncLoadError := not assigned(OBJ_cmp);
  if FuncLoadError then
  begin
    OBJ_cmp :=  @ERROR_OBJ_cmp;
  end;

  OBJ_new_nid := LoadLibCryptoFunction('OBJ_new_nid');
  FuncLoadError := not assigned(OBJ_new_nid);
  if FuncLoadError then
  begin
    OBJ_new_nid :=  @ERROR_OBJ_new_nid;
  end;

  OBJ_add_object := LoadLibCryptoFunction('OBJ_add_object');
  FuncLoadError := not assigned(OBJ_add_object);
  if FuncLoadError then
  begin
    OBJ_add_object :=  @ERROR_OBJ_add_object;
  end;

  OBJ_create := LoadLibCryptoFunction('OBJ_create');
  FuncLoadError := not assigned(OBJ_create);
  if FuncLoadError then
  begin
    OBJ_create :=  @ERROR_OBJ_create;
  end;

  OBJ_create_objects := LoadLibCryptoFunction('OBJ_create_objects');
  FuncLoadError := not assigned(OBJ_create_objects);
  if FuncLoadError then
  begin
    OBJ_create_objects :=  @ERROR_OBJ_create_objects;
  end;

  OBJ_length := LoadLibCryptoFunction('OBJ_length');
  FuncLoadError := not assigned(OBJ_length);
  if FuncLoadError then
  begin
    OBJ_length :=  @ERROR_OBJ_length;
  end;

  OBJ_get0_data := LoadLibCryptoFunction('OBJ_get0_data');
  FuncLoadError := not assigned(OBJ_get0_data);
  if FuncLoadError then
  begin
    OBJ_get0_data :=  @ERROR_OBJ_get0_data;
  end;

  OBJ_find_sigid_algs := LoadLibCryptoFunction('OBJ_find_sigid_algs');
  FuncLoadError := not assigned(OBJ_find_sigid_algs);
  if FuncLoadError then
  begin
    OBJ_find_sigid_algs :=  @ERROR_OBJ_find_sigid_algs;
  end;

  OBJ_find_sigid_by_algs := LoadLibCryptoFunction('OBJ_find_sigid_by_algs');
  FuncLoadError := not assigned(OBJ_find_sigid_by_algs);
  if FuncLoadError then
  begin
    OBJ_find_sigid_by_algs :=  @ERROR_OBJ_find_sigid_by_algs;
  end;

  OBJ_add_sigid := LoadLibCryptoFunction('OBJ_add_sigid');
  FuncLoadError := not assigned(OBJ_add_sigid);
  if FuncLoadError then
  begin
    OBJ_add_sigid :=  @ERROR_OBJ_add_sigid;
  end;

  OBJ_sigid_free := LoadLibCryptoFunction('OBJ_sigid_free');
  FuncLoadError := not assigned(OBJ_sigid_free);
  if FuncLoadError then
  begin
    OBJ_sigid_free :=  @ERROR_OBJ_sigid_free;
  end;

end;

procedure UnLoad;
begin
  OBJ_NAME_init := nil;
  OBJ_NAME_get := nil;
  OBJ_NAME_add := nil;
  OBJ_NAME_remove := nil;
  OBJ_NAME_cleanup := nil;
  OBJ_dup := nil;
  OBJ_nid2obj := nil;
  OBJ_nid2ln := nil;
  OBJ_nid2sn := nil;
  OBJ_obj2nid := nil;
  OBJ_txt2obj := nil;
  OBJ_obj2txt := nil;
  OBJ_txt2nid := nil;
  OBJ_ln2nid := nil;
  OBJ_sn2nid := nil;
  OBJ_cmp := nil;
  OBJ_new_nid := nil;
  OBJ_add_object := nil;
  OBJ_create := nil;
  OBJ_create_objects := nil;
  OBJ_length := nil;
  OBJ_get0_data := nil;
  OBJ_find_sigid_algs := nil;
  OBJ_find_sigid_by_algs := nil;
  OBJ_add_sigid := nil;
  OBJ_sigid_free := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
