(* This unit was generated from the source file cterr.h2pas 
It should not be modified directly. All changes should be made to cterr.h2pas
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


unit OpenSSL_cterr;


interface

// Headers for OpenSSL 1.1.1
// cterr.h


uses
  OpenSSLAPI;

const
  ///*
  // * CT function codes.
  // */
  CT_F_CTLOG_NEW = 117;
  CT_F_CTLOG_NEW_FROM_BASE64 = 118;
  CT_F_CTLOG_NEW_FROM_CONF = 119;
  CT_F_CTLOG_STORE_LOAD_CTX_NEW = 122;
  CT_F_CTLOG_STORE_LOAD_FILE = 123;
  CT_F_CTLOG_STORE_LOAD_LOG = 130;
  CT_F_CTLOG_STORE_NEW = 131;
  CT_F_CT_BASE64_DECODE = 124;
  CT_F_CT_POLICY_EVAL_CTX_NEW = 133;
  CT_F_CT_V1_LOG_ID_FROM_PKEY = 125;
  CT_F_I2O_SCT = 107;
  CT_F_I2O_SCT_LIST = 108;
  CT_F_I2O_SCT_SIGNATURE = 109;
  CT_F_O2I_SCT = 110;
  CT_F_O2I_SCT_LIST = 111;
  CT_F_O2I_SCT_SIGNATURE = 112;
  CT_F_SCT_CTX_NEW = 126;
  CT_F_SCT_CTX_VERIFY = 128;
  CT_F_SCT_NEW = 100;
  CT_F_SCT_NEW_FROM_BASE64 = 127;
  CT_F_SCT_SET0_LOG_ID = 101;
  CT_F_SCT_SET1_EXTENSIONS = 114;
  CT_F_SCT_SET1_LOG_ID = 115;
  CT_F_SCT_SET1_SIGNATURE = 116;
  CT_F_SCT_SET_LOG_ENTRY_TYPE = 102;
  CT_F_SCT_SET_SIGNATURE_NID = 103;
  CT_F_SCT_SET_VERSION = 104;


  ///*
  // * CT reason codes.
  // */
  CT_R_BASE64_DECODE_ERROR =  108;
  CT_R_INVALID_LOG_ID_LENGTH =  100;
  CT_R_LOG_CONF_INVALID =  109;
  CT_R_LOG_CONF_INVALID_KEY =  110;
  CT_R_LOG_CONF_MISSING_DESCRIPTION =  111;
  CT_R_LOG_CONF_MISSING_KEY =  112;
  CT_R_LOG_KEY_INVALID =  113;
  CT_R_SCT_FUTURE_TIMESTAMP =  116;
  CT_R_SCT_INVALID =   104;
  CT_R_SCT_INVALID_SIGNATURE =  107;
  CT_R_SCT_LIST_INVALID =  105;
  CT_R_SCT_LOG_ID_MISMATCH =  114;
  CT_R_SCT_NOT_SET =   106;
  CT_R_SCT_UNSUPPORTED_VERSION =  115;
  CT_R_UNRECOGNIZED_SIGNATURE_NID =  101;
  CT_R_UNSUPPORTED_ENTRY_TYPE =  102;
  CT_R_UNSUPPORTED_VERSION =  103;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_load_CT_strings}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ERR_load_CT_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  ERR_load_CT_strings: function : TOpenSSL_C_INT; cdecl = nil;
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
function ERROR_ERR_load_CT_strings: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_CT_strings');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  ERR_load_CT_strings := LoadLibCryptoFunction('ERR_load_CT_strings');
  FuncLoadError := not assigned(ERR_load_CT_strings);
  if FuncLoadError then
  begin
    ERR_load_CT_strings :=  @ERROR_ERR_load_CT_strings;
  end;

end;

procedure UnLoad;
begin
  ERR_load_CT_strings := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
