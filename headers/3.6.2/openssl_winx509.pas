{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License").

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.
}

{$include openssl_defines.inc}

unit openssl_winx509;

interface

{$IFDEF OPENSSL_USE_WINDOWS_CERT_STORE}
{$J+}
{$TYPEDADDRESS OFF}

uses classes, sysutils, OpenSSLAPI, Windows, openssl_types;

function HasWindowsCertStore: boolean;
function LoadWindowsCertStore(ctx:PSSL_CTX): integer;

{$ENDIF} //OPENSSL_USE_WINDOWS_CERT_STORE

implementation

{$IFDEF OPENSSL_USE_WINDOWS_CERT_STORE}
uses openssl_x509, openssl_x509_vfy, openssl_err, openssl_x509err, openssl_ssl,
  OpenSSLExceptionHandlers, OpenSSLResourceStrings;

const
  wincryptdll = 'crypt32.dll';
  RootStore = 'ROOT';

type
  HCERTSTORE = THandle;
  HCRYPTPROV_LEGACY = POpenSSL_C_LONG;
  PCERT_INFO = pointer; {don't need to know this structure}
  PCCERT_CONTEXT = ^CERT_CONTEXT;
  CERT_CONTEXT = record
    dwCertEncodingType: DWORD;
    pbCertEncoded: PByte;
    cbCertEncoded: DWORD;
    CertInfo: PCERT_INFO;
    certstore: HCERTSTORE
  end;
  
 {$IFDEF OPENSSL_STATIC_LINK_MODEL}
  function HasWindowsCertStore: boolean;
  begin
    Result := true;
  end;
  
  function CertOpenSystemStoreA(hProv: HCRYPTPROV_LEGACY; szSubsystemProtocol: PAnsiChar):HCERTSTORE; stdcall; external wincryptdll;
  function CertCloseStore(certstore: HCERTSTORE; dwFlags: DWORD): boolean; stdcall; external wincryptdll;
  function CertEnumCertificatesInStore(certstore: HCERTSTORE; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT;  stdcall; external wincryptdll;
{$ELSE}
var 
  CertOpenSystemStoreA: function (hProv: HCRYPTPROV_LEGACY; szSubsystemProtocol: PAnsiChar):HCERTSTORE; stdcall = nil;
  CertCloseStore: function (certstore: HCERTSTORE; dwFlags: DWORD): boolean; stdcall = nil;
  CertEnumCertificatesInStore: function (certstore: HCERTSTORE; pPrevCertContext: PCCERT_CONTEXT): PCCERT_CONTEXT;  stdcall = nil;
  
  
 const 
   FWindowsCertStoreLoadFailed : boolean = false;
   LibWinCrypt: THandle = NilHandle;
   
  procedure Load;
  begin
    LibWinCrypt := SafeLoadLibrary(wincryptdll,SEM_FAILCRITICALERRORS);
    if LibWinCrypt<> NilHandle then
    begin
      CertOpenSystemStoreA := GetProcAddress(LibWinCrypt,'CertOpenSystemStoreA');
      CertCloseStore := GetProcAddress(LibWinCrypt,'CertCloseStore');
      CertEnumCertificatesInStore := GetProcAddress(LibWinCrypt,'CertEnumCertificatesInStore');
    end;
    FWindowsCertStoreLoadFailed := (LibWinCrypt = NilHandle) or not assigned(CertOpenSystemStoreA) or
      not assigned(CertCloseStore) or not assigned(CertEnumCertificatesInStore);
  end;
  
  procedure Unload;
  begin
    CertOpenSystemStoreA := nil;
    CertCloseStore := nil;
    CertEnumCertificatesInStore := nil;
    FWindowsCertStoreLoadFailed := false;
    if LibWinCrypt <> NilHandle then
      FreeLibrary(LibWinCrypt);
    LibWinCrypt := NilHandle;
  end;
  
  function HasWindowsCertStore: boolean;
  begin
    if not FWindowsCertStoreLoadFailed and (LibWinCrypt = NilHandle) then
      Load;
    Result := not FWindowsCertStoreLoadFailed;
  end;
    
  
{$ENDIF} //OPENSSL_STATIC_LINK_MODEL

function LoadWindowsCertStore(ctx:PSSL_CTX) :integer;
var WinCertStore: HCERTSTORE;
    X509Cert: PX509;
    cert_context: PCCERT_CONTEXT;
    error: integer;
    SSLCertStore: PX509_STORE;
    CertEncoded: PByte;
begin
  Result := 0;
  if not HasWindowsCertStore then Exit;
  
  cert_context := nil;
  WinCertStore := CertOpenSystemStoreA(nil,RootStore);
  if WinCertStore = 0 then
    Exit;

  SSLCertStore := SSL_CTX_get_cert_store(ctx);
  try
    cert_context := CertEnumCertificatesInStore(WinCertStore,cert_context);
    while cert_context <> nil do
    begin
      CertEncoded := cert_context^.pbCertEncoded;
      X509Cert := d2i_X509(nil,@CertEncoded, cert_context^.cbCertEncoded);
      if X509Cert <> nil then
      begin
        error := X509_STORE_add_cert(SSLCertStore, X509Cert);
//Ignore if cert already in store
        if error = 0 then
        begin
          if  (ERR_GET_REASON(ERR_get_error()) <> X509_R_CERT_ALREADY_IN_HASH_TABLE) then
            EOpenSSLAPICryptoError.RaiseException(ROSCertificateNotAddedToStore);
        end
        else
          inc(Result);
        X509_free(X509Cert);
      end;
      cert_context := CertEnumCertificatesInStore(WinCertStore,cert_context);
    end;
  finally
     CertCloseStore(WinCertStore, 0);
  end;
end;
  

initialization

{$ifndef OPENSSL_STATIC_LINK_MODEL}
  Register_SSLloader(@Load);
  Register_SSLUnloader(@Unload);
{$endif}

{$ENDIF} //OPENSSL_USE_WINDOWS_CERT_STORE

end.
