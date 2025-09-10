(* This unit was generated from the source file srtp.h2pas 
It should not be modified directly. All changes should be made to srtp.h2pas
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


unit OpenSSL_srtp;


interface

// Headers for OpenSSL 1.1.1
// srtp.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_ssl;

const
  SRTP_AES128_CM_SHA1_80 = $0001;
  SRTP_AES128_CM_SHA1_32 = $0002;
  SRTP_AES128_F8_SHA1_80 = $0003;
  SRTP_AES128_F8_SHA1_32 = $0004;
  SRTP_NULL_SHA1_80      = $0005;
  SRTP_NULL_SHA1_32      = $0006;

  (* AEAD SRTP protection profiles from RFC 7714 *)
  SRTP_AEAD_AES_128_GCM = $0007;
  SRTP_AEAD_AES_256_GCM = $0008;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM SSL_CTX_set_tlsext_use_srtp}
{$EXTERNALSYM SSL_set_tlsext_use_srtp}
{$EXTERNALSYM SSL_get_selected_srtp_profile}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SSL_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl; external CLibCrypto;

{$ELSE}
var
  SSL_CTX_set_tlsext_use_srtp: function (ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_set_tlsext_use_srtp: function (ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  SSL_get_selected_srtp_profile: function (s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl = nil;
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
function ERROR_SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_tlsext_use_srtp');
end;

function ERROR_SSL_set_tlsext_use_srtp(ctx: PSSL_CTX; const profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_tlsext_use_srtp');
end;

function ERROR_SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_selected_srtp_profile');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  SSL_CTX_set_tlsext_use_srtp := LoadLibCryptoFunction('SSL_CTX_set_tlsext_use_srtp');
  FuncLoadError := not assigned(SSL_CTX_set_tlsext_use_srtp);
  if FuncLoadError then
  begin
    SSL_CTX_set_tlsext_use_srtp :=  @ERROR_SSL_CTX_set_tlsext_use_srtp;
  end;

  SSL_set_tlsext_use_srtp := LoadLibCryptoFunction('SSL_set_tlsext_use_srtp');
  FuncLoadError := not assigned(SSL_set_tlsext_use_srtp);
  if FuncLoadError then
  begin
    SSL_set_tlsext_use_srtp :=  @ERROR_SSL_set_tlsext_use_srtp;
  end;

  SSL_get_selected_srtp_profile := LoadLibCryptoFunction('SSL_get_selected_srtp_profile');
  FuncLoadError := not assigned(SSL_get_selected_srtp_profile);
  if FuncLoadError then
  begin
    SSL_get_selected_srtp_profile :=  @ERROR_SSL_get_selected_srtp_profile;
  end;

end;

procedure UnLoad;
begin
  SSL_CTX_set_tlsext_use_srtp := nil;
  SSL_set_tlsext_use_srtp := nil;
  SSL_get_selected_srtp_profile := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
