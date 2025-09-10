(* This unit was generated from the source file whrlpool.h2pas 
It should not be modified directly. All changes should be made to whrlpool.h2pas
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


unit OpenSSL_whrlpool;


interface

// Headers for OpenSSL 1.1.1
// whrlpool.h


uses
  OpenSSLAPI;

const
  WHIRLPOOL_DIGEST_LENGTH = 512 div 8;
  WHIRLPOOL_BBLOCK = 512;
  WHIRLPOOL_COUNTER = 256 div 8;

type
  WHIRLPOOL_CTX_union = record
    case Byte of
      0: (c: array[0 .. WHIRLPOOL_DIGEST_LENGTH -1] of Byte);
      (* double q is here to ensure 64-bit alignment *)
      1: (q: array[0 .. (WHIRLPOOL_DIGEST_LENGTH div SizeOf(TOpenSSL_C_DOUBLE)) -1] of TOpenSSL_C_DOUBLE);
  end;
  WHIRLPOOL_CTX = record
    H: WHIRLPOOL_CTX_union;
    data: array[0 .. (WHIRLPOOL_BBLOCK div 8) -1] of Byte;
    bitoff: TOpenSSL_C_UINT;
    bitlen: array[0 .. (WHIRLPOOL_COUNTER div SizeOf(TOpenSSL_C_SIZET)) -1] of TOpenSSL_C_SIZET;
  end;
  PWHIRLPOOL_CTX = ^WHIRLPOOL_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM WHIRLPOOL_Init}
{$EXTERNALSYM WHIRLPOOL_Update}
{$EXTERNALSYM WHIRLPOOL_BitUpdate}
{$EXTERNALSYM WHIRLPOOL_Final}
{$EXTERNALSYM WHIRLPOOL}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TOpenSSL_C_SIZET); cdecl; external CLibCrypto;
function WHIRLPOOL_Final(md: PByte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function WHIRLPOOL(inp: Pointer; bytes: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl; external CLibCrypto;

{$ELSE}
var
  WHIRLPOOL_Init: function (c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl = nil;
  WHIRLPOOL_Update: function (c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  WHIRLPOOL_BitUpdate: procedure (c: PWHIRLPOOL_CTX; inp: Pointer; bits: TOpenSSL_C_SIZET); cdecl = nil;
  WHIRLPOOL_Final: function (md: PByte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl = nil;
  WHIRLPOOL: function (inp: Pointer; bytes: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl = nil;
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
function ERROR_WHIRLPOOL_Init(c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Init');
end;

function ERROR_WHIRLPOOL_Update(c: PWHIRLPOOL_CTX; inp: Pointer; bytes: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Update');
end;

procedure ERROR_WHIRLPOOL_BitUpdate(c: PWHIRLPOOL_CTX; inp: Pointer; bits: TOpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_BitUpdate');
end;

function ERROR_WHIRLPOOL_Final(md: PByte; c: PWHIRLPOOL_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL_Final');
end;

function ERROR_WHIRLPOOL(inp: Pointer; bytes: TOpenSSL_C_SIZET; md: PByte): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('WHIRLPOOL');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  WHIRLPOOL_Init := LoadLibCryptoFunction('WHIRLPOOL_Init');
  FuncLoadError := not assigned(WHIRLPOOL_Init);
  if FuncLoadError then
  begin
    WHIRLPOOL_Init :=  @ERROR_WHIRLPOOL_Init;
  end;

  WHIRLPOOL_Update := LoadLibCryptoFunction('WHIRLPOOL_Update');
  FuncLoadError := not assigned(WHIRLPOOL_Update);
  if FuncLoadError then
  begin
    WHIRLPOOL_Update :=  @ERROR_WHIRLPOOL_Update;
  end;

  WHIRLPOOL_BitUpdate := LoadLibCryptoFunction('WHIRLPOOL_BitUpdate');
  FuncLoadError := not assigned(WHIRLPOOL_BitUpdate);
  if FuncLoadError then
  begin
    WHIRLPOOL_BitUpdate :=  @ERROR_WHIRLPOOL_BitUpdate;
  end;

  WHIRLPOOL_Final := LoadLibCryptoFunction('WHIRLPOOL_Final');
  FuncLoadError := not assigned(WHIRLPOOL_Final);
  if FuncLoadError then
  begin
    WHIRLPOOL_Final :=  @ERROR_WHIRLPOOL_Final;
  end;

  WHIRLPOOL := LoadLibCryptoFunction('WHIRLPOOL');
  FuncLoadError := not assigned(WHIRLPOOL);
  if FuncLoadError then
  begin
    WHIRLPOOL :=  @ERROR_WHIRLPOOL;
  end;

end;

procedure UnLoad;
begin
  WHIRLPOOL_Init := nil;
  WHIRLPOOL_Update := nil;
  WHIRLPOOL_BitUpdate := nil;
  WHIRLPOOL_Final := nil;
  WHIRLPOOL := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
