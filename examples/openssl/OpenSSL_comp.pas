(* This unit was generated from the source file comp.h2pas 
It should not be modified directly. All changes should be made to comp.h2pas
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


unit OpenSSL_comp;


interface

// Headers for OpenSSL 1.1.1
// comp.h


uses
  OpenSSLAPI,
  OpenSSL_bio,
  OpenSSL_ossl_typ;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM COMP_CTX_new}
{$EXTERNALSYM COMP_CTX_get_method}
{$EXTERNALSYM COMP_CTX_get_type}
{$EXTERNALSYM COMP_get_type}
{$EXTERNALSYM COMP_get_name}
{$EXTERNALSYM COMP_CTX_free}
{$EXTERNALSYM COMP_compress_block}
{$EXTERNALSYM COMP_expand_block}
{$EXTERNALSYM COMP_zlib}
{$EXTERNALSYM BIO_f_zlib}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl; external CLibCrypto;
function COMP_CTX_get_method(const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl; external CLibCrypto;
function COMP_CTX_get_type(const comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_get_type(const meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_get_name(const meth: PCOMP_METHOD): PAnsiChar; cdecl; external CLibCrypto;
procedure COMP_CTX_free(ctx: PCOMP_CTX); cdecl; external CLibCrypto;
function COMP_compress_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_expand_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function COMP_zlib: PCOMP_METHOD; cdecl; external CLibCrypto;
function BIO_f_zlib: PBIO_METHOD; cdecl; external CLibCrypto;

{$ELSE}
var
  COMP_CTX_new: function (meth: PCOMP_METHOD): PCOMP_CTX; cdecl = nil;
  COMP_CTX_get_method: function (const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl = nil;
  COMP_CTX_get_type: function (const comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl = nil;
  COMP_get_type: function (const meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl = nil;
  COMP_get_name: function (const meth: PCOMP_METHOD): PAnsiChar; cdecl = nil;
  COMP_CTX_free: procedure (ctx: PCOMP_CTX); cdecl = nil;
  COMP_compress_block: function (ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  COMP_expand_block: function (ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  COMP_zlib: function : PCOMP_METHOD; cdecl = nil;
  BIO_f_zlib: function : PBIO_METHOD; cdecl = nil;
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
function ERROR_COMP_CTX_new(meth: PCOMP_METHOD): PCOMP_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_new');
end;

function ERROR_COMP_CTX_get_method(const ctx: PCOMP_CTX): PCOMP_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_get_method');
end;

function ERROR_COMP_CTX_get_type(const comp: PCOMP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_get_type');
end;

function ERROR_COMP_get_type(const meth: PCOMP_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_get_type');
end;

function ERROR_COMP_get_name(const meth: PCOMP_METHOD): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_get_name');
end;

procedure ERROR_COMP_CTX_free(ctx: PCOMP_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_CTX_free');
end;

function ERROR_COMP_compress_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_compress_block');
end;

function ERROR_COMP_expand_block(ctx: PCOMP_CTX; out_: PByte; olen: TOpenSSL_C_INT; in_: PByte; ilen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_expand_block');
end;

function ERROR_COMP_zlib: PCOMP_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('COMP_zlib');
end;

function ERROR_BIO_f_zlib: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_zlib');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  COMP_CTX_new := LoadLibCryptoFunction('COMP_CTX_new');
  FuncLoadError := not assigned(COMP_CTX_new);
  if FuncLoadError then
  begin
    COMP_CTX_new :=  @ERROR_COMP_CTX_new;
  end;

  COMP_CTX_get_method := LoadLibCryptoFunction('COMP_CTX_get_method');
  FuncLoadError := not assigned(COMP_CTX_get_method);
  if FuncLoadError then
  begin
    COMP_CTX_get_method :=  @ERROR_COMP_CTX_get_method;
  end;

  COMP_CTX_get_type := LoadLibCryptoFunction('COMP_CTX_get_type');
  FuncLoadError := not assigned(COMP_CTX_get_type);
  if FuncLoadError then
  begin
    COMP_CTX_get_type :=  @ERROR_COMP_CTX_get_type;
  end;

  COMP_get_type := LoadLibCryptoFunction('COMP_get_type');
  FuncLoadError := not assigned(COMP_get_type);
  if FuncLoadError then
  begin
    COMP_get_type :=  @ERROR_COMP_get_type;
  end;

  COMP_get_name := LoadLibCryptoFunction('COMP_get_name');
  FuncLoadError := not assigned(COMP_get_name);
  if FuncLoadError then
  begin
    COMP_get_name :=  @ERROR_COMP_get_name;
  end;

  COMP_CTX_free := LoadLibCryptoFunction('COMP_CTX_free');
  FuncLoadError := not assigned(COMP_CTX_free);
  if FuncLoadError then
  begin
    COMP_CTX_free :=  @ERROR_COMP_CTX_free;
  end;

  COMP_compress_block := LoadLibCryptoFunction('COMP_compress_block');
  FuncLoadError := not assigned(COMP_compress_block);
  if FuncLoadError then
  begin
    COMP_compress_block :=  @ERROR_COMP_compress_block;
  end;

  COMP_expand_block := LoadLibCryptoFunction('COMP_expand_block');
  FuncLoadError := not assigned(COMP_expand_block);
  if FuncLoadError then
  begin
    COMP_expand_block :=  @ERROR_COMP_expand_block;
  end;

  COMP_zlib := LoadLibCryptoFunction('COMP_zlib');
  FuncLoadError := not assigned(COMP_zlib);
  if FuncLoadError then
  begin
    COMP_zlib :=  @ERROR_COMP_zlib;
  end;

  BIO_f_zlib := LoadLibCryptoFunction('BIO_f_zlib');
  FuncLoadError := not assigned(BIO_f_zlib);
  if FuncLoadError then
  begin
    BIO_f_zlib :=  @ERROR_BIO_f_zlib;
  end;

end;

procedure UnLoad;
begin
  COMP_CTX_new := nil;
  COMP_CTX_get_method := nil;
  COMP_CTX_get_type := nil;
  COMP_get_type := nil;
  COMP_get_name := nil;
  COMP_CTX_free := nil;
  COMP_compress_block := nil;
  COMP_expand_block := nil;
  COMP_zlib := nil;
  BIO_f_zlib := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
