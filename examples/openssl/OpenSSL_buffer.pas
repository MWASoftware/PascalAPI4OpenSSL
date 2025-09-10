(* This unit was generated from the source file buffer.h2pas 
It should not be modified directly. All changes should be made to buffer.h2pas
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


unit OpenSSL_buffer;


interface

// Headers for OpenSSL 1.1.1
// buffer.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ;

const
  BUF_MEM_FLAG_SECURE = $01;

type
  buf_mem_st = record
    length: TOpenSSL_C_SIZET;
    data: PAnsiChar;
    max: TOpenSSL_C_SIZET;
    flags: TOpenSSL_C_ULONG;
  end;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BUF_MEM_new}
{$EXTERNALSYM BUF_MEM_new_ex}
{$EXTERNALSYM BUF_MEM_free}
{$EXTERNALSYM BUF_MEM_grow}
{$EXTERNALSYM BUF_MEM_grow_clean}
{$EXTERNALSYM BUF_reverse}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function BUF_MEM_new: PBUF_MEM; cdecl; external CLibCrypto;
function BUF_MEM_new_ex(flags: TOpenSSL_C_ULONG): PBUF_MEM; cdecl; external CLibCrypto;
procedure BUF_MEM_free(a: PBUF_MEM); cdecl; external CLibCrypto;
function BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
procedure BUF_reverse(out_: PByte; const in_: PByte; siz: TOpenSSL_C_SIZET); cdecl; external CLibCrypto;

{$ELSE}
var
  BUF_MEM_new: function : PBUF_MEM; cdecl = nil;
  BUF_MEM_new_ex: function (flags: TOpenSSL_C_ULONG): PBUF_MEM; cdecl = nil;
  BUF_MEM_free: procedure (a: PBUF_MEM); cdecl = nil;
  BUF_MEM_grow: function (str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  BUF_MEM_grow_clean: function (str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl = nil;
  BUF_reverse: procedure (out_: PByte; const in_: PByte; siz: TOpenSSL_C_SIZET); cdecl = nil;
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
function ERROR_BUF_MEM_new: PBUF_MEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_new');
end;

function ERROR_BUF_MEM_new_ex(flags: TOpenSSL_C_ULONG): PBUF_MEM; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_new_ex');
end;

procedure ERROR_BUF_MEM_free(a: PBUF_MEM); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_free');
end;

function ERROR_BUF_MEM_grow(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_grow');
end;

function ERROR_BUF_MEM_grow_clean(str: PBUF_MEM; len: TOpenSSL_C_SIZET): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_MEM_grow_clean');
end;

procedure ERROR_BUF_reverse(out_: PByte; const in_: PByte; siz: TOpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BUF_reverse');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  BUF_MEM_new := LoadLibCryptoFunction('BUF_MEM_new');
  FuncLoadError := not assigned(BUF_MEM_new);
  if FuncLoadError then
  begin
    BUF_MEM_new :=  @ERROR_BUF_MEM_new;
  end;

  BUF_MEM_new_ex := LoadLibCryptoFunction('BUF_MEM_new_ex');
  FuncLoadError := not assigned(BUF_MEM_new_ex);
  if FuncLoadError then
  begin
    BUF_MEM_new_ex :=  @ERROR_BUF_MEM_new_ex;
  end;

  BUF_MEM_free := LoadLibCryptoFunction('BUF_MEM_free');
  FuncLoadError := not assigned(BUF_MEM_free);
  if FuncLoadError then
  begin
    BUF_MEM_free :=  @ERROR_BUF_MEM_free;
  end;

  BUF_MEM_grow := LoadLibCryptoFunction('BUF_MEM_grow');
  FuncLoadError := not assigned(BUF_MEM_grow);
  if FuncLoadError then
  begin
    BUF_MEM_grow :=  @ERROR_BUF_MEM_grow;
  end;

  BUF_MEM_grow_clean := LoadLibCryptoFunction('BUF_MEM_grow_clean');
  FuncLoadError := not assigned(BUF_MEM_grow_clean);
  if FuncLoadError then
  begin
    BUF_MEM_grow_clean :=  @ERROR_BUF_MEM_grow_clean;
  end;

  BUF_reverse := LoadLibCryptoFunction('BUF_reverse');
  FuncLoadError := not assigned(BUF_reverse);
  if FuncLoadError then
  begin
    BUF_reverse :=  @ERROR_BUF_reverse;
  end;

end;

procedure UnLoad;
begin
  BUF_MEM_new := nil;
  BUF_MEM_new_ex := nil;
  BUF_MEM_free := nil;
  BUF_MEM_grow := nil;
  BUF_MEM_grow_clean := nil;
  BUF_reverse := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
