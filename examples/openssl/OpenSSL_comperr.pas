(* This unit was generated from the source file comperr.h2pas 
It should not be modified directly. All changes should be made to comperr.h2pas
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


unit OpenSSL_comperr;


interface

// Headers for OpenSSL 1.1.1
// comperr.h


uses
  OpenSSLAPI;

const
///*
// * COMP function codes.
// */
  COMP_F_BIO_ZLIB_FLUSH =      99;
  COMP_F_BIO_ZLIB_NEW =        100;
  COMP_F_BIO_ZLIB_READ =       101;
  COMP_F_BIO_ZLIB_WRITE =      102;
  COMP_F_COMP_CTX_NEW =        103;

///*
// * COMP reason codes.
// */
  COMP_R_ZLIB_DEFLATE_ERROR =  99;
  COMP_R_ZLIB_INFLATE_ERROR =  100;
  COMP_R_ZLIB_NOT_SUPPORTED =  101;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_COMP_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_COMP_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  ERR_load_COMP_strings: function : TOpenSSL_C_INT; cdecl = nil;
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
function ERROR_ERR_load_COMP_strings: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_COMP_strings');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  ERR_load_COMP_strings := LoadLibCryptoFunction('ERR_load_COMP_strings');
  FuncLoadError := not assigned(ERR_load_COMP_strings);
  if FuncLoadError then
  begin
    ERR_load_COMP_strings :=  @ERROR_ERR_load_COMP_strings;
  end;

end;

procedure UnLoad;
begin
  ERR_load_COMP_strings := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
