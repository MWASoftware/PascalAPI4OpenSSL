(* This unit was generated from the source file sha.h2pas 
It should not be modified directly. All changes should be made to sha.h2pas
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


unit OpenSSL_sha;


interface

// Headers for OpenSSL 1.1.1
// sha.h


uses
  OpenSSLAPI;

const
  SHA_LBLOCK = 16;
  SHA_CBLOCK = SHA_LBLOCK * 4;

  SHA_LAST_BLOCK = SHA_CBLOCK - 8;
  SHA_DIGEST_LENGTH = 20;

  SHA256_CBLOCK = SHA_LBLOCK * 4;

  SHA224_DIGEST_LENGTH = 28;
  SHA256_DIGEST_LENGTH = 32;
  SHA384_DIGEST_LENGTH = 48;
  SHA512_DIGEST_LENGTH = 64;

  SHA512_CBLOCK = SHA_LBLOCK * 8;

type
  SHA_LONG = TOpenSSL_C_UINT;

  SHAstate_sf = record
    h0, h1, h2, h3, h4: SHA_LONG;
    Nl, Nh: SHA_LONG;
    data: array[0 .. SHA_LAST_BLOCK - 1] of SHA_LONG;
    num: TOpenSSL_C_UINT;
  end;
  SHA_CTX = SHAstate_sf;
  PSHA_CTX = ^SHA_CTX;

  SHAstate256_sf = record
    h: array[0..7] of SHA_LONG;
    Nl, Nh: SHA_LONG;
    data: array[0 .. SHA_LAST_BLOCK - 1] of SHA_LONG;
    num, md_len: TOpenSSL_C_UINT;
  end;
  SHA256_CTX = SHAstate256_sf;
  PSHA256_CTX = ^SHA256_CTX;

  SHA_LONG64 = TOpenSSL_C_UINT64;

  SHA512state_st_u = record
    case Integer of
    0: (d: array[0 .. SHA_LBLOCK - 1] of SHA_LONG64);
    1: (p: array[0 .. SHA512_CBLOCK - 1] of Byte);
  end;

  SHA512state_st = record
    h: array[0..7] of SHA_LONG64;
    Nl, Nh: SHA_LONG64;
    u: SHA512state_st_u;
    num, md_len: TOpenSSL_C_UINT;
  end;
  SHA512_CTX = SHA512state_st;
  PSHA512_CTX = ^SHA512_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM SHA1_Init}
{$EXTERNALSYM SHA1_Update}
{$EXTERNALSYM SHA1_Final}
{$EXTERNALSYM SHA1}
{$EXTERNALSYM SHA1_Transform}
{$EXTERNALSYM SHA224_Init}
{$EXTERNALSYM SHA224_Update}
{$EXTERNALSYM SHA224_Final}
{$EXTERNALSYM SHA224}
{$EXTERNALSYM SHA256_Init}
{$EXTERNALSYM SHA256_Update}
{$EXTERNALSYM SHA256_Final}
{$EXTERNALSYM SHA256}
{$EXTERNALSYM SHA256_Transform}
{$EXTERNALSYM SHA384_Init}
{$EXTERNALSYM SHA384_Update}
{$EXTERNALSYM SHA384_Final}
{$EXTERNALSYM SHA384}
{$EXTERNALSYM SHA512_Init}
{$EXTERNALSYM SHA512_Update}
{$EXTERNALSYM SHA512_Final}
{$EXTERNALSYM SHA512}
{$EXTERNALSYM SHA512_Transform}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA1_Update(c: PSHA_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA1_Final(md: PByte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA1(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
procedure SHA1_Transform(c: PSHA_CTX; const data: PByte); cdecl; external CLibCrypto;
function SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA224_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA224_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA224(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
function SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA256_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA256_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA256(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
procedure SHA256_Transform(c: PSHA256_CTX; const data: PByte); cdecl; external CLibCrypto;
function SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA384_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA384_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA384(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
function SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA512_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA512_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SHA512(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;
procedure SHA512_Transform(c: PSHA512_CTX; const data: PByte); cdecl; external CLibCrypto;

{$ELSE}
var
  SHA1_Init: function (c: PSHA_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA1_Update: function (c: PSHA_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SHA1_Final: function (md: PByte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA1: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = nil;
  SHA1_Transform: procedure (c: PSHA_CTX; const data: PByte); cdecl = nil;
  SHA224_Init: function (c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA224_Update: function (c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SHA224_Final: function (md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA224: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = nil;
  SHA256_Init: function (c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA256_Update: function (c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SHA256_Final: function (md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA256: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = nil;
  SHA256_Transform: procedure (c: PSHA256_CTX; const data: PByte); cdecl = nil;
  SHA384_Init: function (c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA384_Update: function (c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SHA384_Final: function (md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA384: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = nil;
  SHA512_Init: function (c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA512_Update: function (c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  SHA512_Final: function (md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl = nil;
  SHA512: function (const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = nil;
  SHA512_Transform: procedure (c: PSHA512_CTX; const data: PByte); cdecl = nil;
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
function ERROR_SHA1_Init(c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Init');
end;

function ERROR_SHA1_Update(c: PSHA_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Update');
end;

function ERROR_SHA1_Final(md: PByte; c: PSHA_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Final');
end;

function ERROR_SHA1(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1');
end;

procedure ERROR_SHA1_Transform(c: PSHA_CTX; const data: PByte); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA1_Transform');
end;

function ERROR_SHA224_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Init');
end;

function ERROR_SHA224_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Update');
end;

function ERROR_SHA224_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224_Final');
end;

function ERROR_SHA224(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA224');
end;

function ERROR_SHA256_Init(c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Init');
end;

function ERROR_SHA256_Update(c: PSHA256_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Update');
end;

function ERROR_SHA256_Final(md: PByte; c: PSHA256_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Final');
end;

function ERROR_SHA256(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256');
end;

procedure ERROR_SHA256_Transform(c: PSHA256_CTX; const data: PByte); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA256_Transform');
end;

function ERROR_SHA384_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Init');
end;

function ERROR_SHA384_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Update');
end;

function ERROR_SHA384_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384_Final');
end;

function ERROR_SHA384(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA384');
end;

function ERROR_SHA512_Init(c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Init');
end;

function ERROR_SHA512_Update(c: PSHA512_CTX; const data: Pointer; len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Update');
end;

function ERROR_SHA512_Final(md: PByte; c: PSHA512_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Final');
end;

function ERROR_SHA512(const d: PByte; n: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512');
end;

procedure ERROR_SHA512_Transform(c: PSHA512_CTX; const data: PByte); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SHA512_Transform');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  SHA1_Init := LoadLibCryptoFunction('SHA1_Init');
  FuncLoadError := not assigned(SHA1_Init);
  if FuncLoadError then
  begin
    SHA1_Init :=  @ERROR_SHA1_Init;
  end;

  SHA1_Update := LoadLibCryptoFunction('SHA1_Update');
  FuncLoadError := not assigned(SHA1_Update);
  if FuncLoadError then
  begin
    SHA1_Update :=  @ERROR_SHA1_Update;
  end;

  SHA1_Final := LoadLibCryptoFunction('SHA1_Final');
  FuncLoadError := not assigned(SHA1_Final);
  if FuncLoadError then
  begin
    SHA1_Final :=  @ERROR_SHA1_Final;
  end;

  SHA1 := LoadLibCryptoFunction('SHA1');
  FuncLoadError := not assigned(SHA1);
  if FuncLoadError then
  begin
    SHA1 :=  @ERROR_SHA1;
  end;

  SHA1_Transform := LoadLibCryptoFunction('SHA1_Transform');
  FuncLoadError := not assigned(SHA1_Transform);
  if FuncLoadError then
  begin
    SHA1_Transform :=  @ERROR_SHA1_Transform;
  end;

  SHA224_Init := LoadLibCryptoFunction('SHA224_Init');
  FuncLoadError := not assigned(SHA224_Init);
  if FuncLoadError then
  begin
    SHA224_Init :=  @ERROR_SHA224_Init;
  end;

  SHA224_Update := LoadLibCryptoFunction('SHA224_Update');
  FuncLoadError := not assigned(SHA224_Update);
  if FuncLoadError then
  begin
    SHA224_Update :=  @ERROR_SHA224_Update;
  end;

  SHA224_Final := LoadLibCryptoFunction('SHA224_Final');
  FuncLoadError := not assigned(SHA224_Final);
  if FuncLoadError then
  begin
    SHA224_Final :=  @ERROR_SHA224_Final;
  end;

  SHA224 := LoadLibCryptoFunction('SHA224');
  FuncLoadError := not assigned(SHA224);
  if FuncLoadError then
  begin
    SHA224 :=  @ERROR_SHA224;
  end;

  SHA256_Init := LoadLibCryptoFunction('SHA256_Init');
  FuncLoadError := not assigned(SHA256_Init);
  if FuncLoadError then
  begin
    SHA256_Init :=  @ERROR_SHA256_Init;
  end;

  SHA256_Update := LoadLibCryptoFunction('SHA256_Update');
  FuncLoadError := not assigned(SHA256_Update);
  if FuncLoadError then
  begin
    SHA256_Update :=  @ERROR_SHA256_Update;
  end;

  SHA256_Final := LoadLibCryptoFunction('SHA256_Final');
  FuncLoadError := not assigned(SHA256_Final);
  if FuncLoadError then
  begin
    SHA256_Final :=  @ERROR_SHA256_Final;
  end;

  SHA256 := LoadLibCryptoFunction('SHA256');
  FuncLoadError := not assigned(SHA256);
  if FuncLoadError then
  begin
    SHA256 :=  @ERROR_SHA256;
  end;

  SHA256_Transform := LoadLibCryptoFunction('SHA256_Transform');
  FuncLoadError := not assigned(SHA256_Transform);
  if FuncLoadError then
  begin
    SHA256_Transform :=  @ERROR_SHA256_Transform;
  end;

  SHA384_Init := LoadLibCryptoFunction('SHA384_Init');
  FuncLoadError := not assigned(SHA384_Init);
  if FuncLoadError then
  begin
    SHA384_Init :=  @ERROR_SHA384_Init;
  end;

  SHA384_Update := LoadLibCryptoFunction('SHA384_Update');
  FuncLoadError := not assigned(SHA384_Update);
  if FuncLoadError then
  begin
    SHA384_Update :=  @ERROR_SHA384_Update;
  end;

  SHA384_Final := LoadLibCryptoFunction('SHA384_Final');
  FuncLoadError := not assigned(SHA384_Final);
  if FuncLoadError then
  begin
    SHA384_Final :=  @ERROR_SHA384_Final;
  end;

  SHA384 := LoadLibCryptoFunction('SHA384');
  FuncLoadError := not assigned(SHA384);
  if FuncLoadError then
  begin
    SHA384 :=  @ERROR_SHA384;
  end;

  SHA512_Init := LoadLibCryptoFunction('SHA512_Init');
  FuncLoadError := not assigned(SHA512_Init);
  if FuncLoadError then
  begin
    SHA512_Init :=  @ERROR_SHA512_Init;
  end;

  SHA512_Update := LoadLibCryptoFunction('SHA512_Update');
  FuncLoadError := not assigned(SHA512_Update);
  if FuncLoadError then
  begin
    SHA512_Update :=  @ERROR_SHA512_Update;
  end;

  SHA512_Final := LoadLibCryptoFunction('SHA512_Final');
  FuncLoadError := not assigned(SHA512_Final);
  if FuncLoadError then
  begin
    SHA512_Final :=  @ERROR_SHA512_Final;
  end;

  SHA512 := LoadLibCryptoFunction('SHA512');
  FuncLoadError := not assigned(SHA512);
  if FuncLoadError then
  begin
    SHA512 :=  @ERROR_SHA512;
  end;

  SHA512_Transform := LoadLibCryptoFunction('SHA512_Transform');
  FuncLoadError := not assigned(SHA512_Transform);
  if FuncLoadError then
  begin
    SHA512_Transform :=  @ERROR_SHA512_Transform;
  end;

end;

procedure UnLoad;
begin
  SHA1_Init := nil;
  SHA1_Update := nil;
  SHA1_Final := nil;
  SHA1 := nil;
  SHA1_Transform := nil;
  SHA224_Init := nil;
  SHA224_Update := nil;
  SHA224_Final := nil;
  SHA224 := nil;
  SHA256_Init := nil;
  SHA256_Update := nil;
  SHA256_Final := nil;
  SHA256 := nil;
  SHA256_Transform := nil;
  SHA384_Init := nil;
  SHA384_Update := nil;
  SHA384_Final := nil;
  SHA384 := nil;
  SHA512_Init := nil;
  SHA512_Update := nil;
  SHA512_Final := nil;
  SHA512 := nil;
  SHA512_Transform := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
