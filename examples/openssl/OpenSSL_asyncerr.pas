(* This unit was generated from the source file asyncerr.h2pas 
It should not be modified directly. All changes should be made to asyncerr.h2pas
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


unit OpenSSL_asyncerr;


interface

// Headers for OpenSSL 1.1.1
// asyncerr.h


uses
  OpenSSLAPI;

const
  //
  // ASYNC function codes.
  //
  ASYNC_F_ASYNC_CTX_NEW                            = 100;
  ASYNC_F_ASYNC_INIT_THREAD                        = 101;
  ASYNC_F_ASYNC_JOB_NEW                            = 102;
  ASYNC_F_ASYNC_PAUSE_JOB                          = 103;
  ASYNC_F_ASYNC_START_FUNC                         = 104;
  ASYNC_F_ASYNC_START_JOB                          = 105;
  ASYNC_F_ASYNC_WAIT_CTX_SET_WAIT_FD               = 106;

  //
  // ASYNC reason codes.
  //
  ASYNC_R_FAILED_TO_SET_POOL                       = 101;
  ASYNC_R_FAILED_TO_SWAP_CONTEXT                   = 102;
  ASYNC_R_INIT_FAILED                              = 105;
  ASYNC_R_INVALID_POOL_SIZE                        = 103;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_ASYNC_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_ASYNC_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  ERR_load_ASYNC_strings: function : TOpenSSL_C_INT; cdecl = nil;
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
function ERROR_ERR_load_ASYNC_strings: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_ASYNC_strings');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  ERR_load_ASYNC_strings := LoadLibCryptoFunction('ERR_load_ASYNC_strings');
  FuncLoadError := not assigned(ERR_load_ASYNC_strings);
  if FuncLoadError then
  begin
    ERR_load_ASYNC_strings :=  @ERROR_ERR_load_ASYNC_strings;
  end;

end;

procedure UnLoad;
begin
  ERR_load_ASYNC_strings := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
