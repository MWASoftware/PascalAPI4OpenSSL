{
    This file is part of the MWA Software Pascal API for OpenSSL .

    The MWA Software Pascal API for OpenSSL is free software: you can redistribute it
    and/or modify it under the terms of the Apache License Version 2.0 (the "License"), and as
    a derived work of the OpenSSL Project (see below for the original licence text).

    You may not use this file except in compliance with the License.  You can obtain a copy
    in the file LICENSE.txt in the source distribution or at https://www.openssl.org/source/license.html.

    The MWA Software Pascal API for OpenSSL is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the License for more details.
}

{$include openssl_defines.inc}

unit openssl_self_test;

{
  Generated from OpenSSL 4.0.0 Header File self_test.h - Tue 19 May 14:33:13 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_self_test.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_core;


{* Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_SELF_TEST_H}
  {$define OPENSSL_SELF_TEST_H}

const
  { OSSL_CALLBACK }
  { The test event phases }
  OSSL_SELF_TEST_PHASE_NONE = 'None';
  OSSL_SELF_TEST_PHASE_START = 'Start';
  OSSL_SELF_TEST_PHASE_CORRUPT = 'Corrupt';
  OSSL_SELF_TEST_PHASE_PASS = 'Pass';
  OSSL_SELF_TEST_PHASE_FAIL = 'Fail';
  { Test event categories }
  OSSL_SELF_TEST_TYPE_NONE = 'None';
  OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY = 'Module_Integrity';
  OSSL_SELF_TEST_TYPE_INSTALL_INTEGRITY = 'Install_Integrity';
  OSSL_SELF_TEST_TYPE_CRNG = 'Continuous_RNG_Test';
  OSSL_SELF_TEST_TYPE_PCT = 'Conditional_PCT';
  OSSL_SELF_TEST_TYPE_PCT_KAT = 'Conditional_KAT';
  OSSL_SELF_TEST_TYPE_PCT_IMPORT = 'Import_PCT';
  OSSL_SELF_TEST_TYPE_KAT_INTEGRITY = 'KAT_Integrity';
  OSSL_SELF_TEST_TYPE_KAT_CIPHER = 'KAT_Cipher';
  OSSL_SELF_TEST_TYPE_KAT_ASYM_CIPHER = 'KAT_AsymmetricCipher';
  OSSL_SELF_TEST_TYPE_KAT_ASYM_KEYGEN = 'KAT_AsymmetricKeyGeneration';
  OSSL_SELF_TEST_TYPE_KAT_KEM = 'KAT_KEM';
  OSSL_SELF_TEST_TYPE_KAT_DIGEST = 'KAT_Digest';
  OSSL_SELF_TEST_TYPE_KAT_MAC = 'KAT_Mac';
  OSSL_SELF_TEST_TYPE_KAT_SIGNATURE = 'KAT_Signature';
  OSSL_SELF_TEST_TYPE_PCT_SIGNATURE = 'PCT_Signature';
  OSSL_SELF_TEST_TYPE_KAT_KDF = 'KAT_KDF';
  OSSL_SELF_TEST_TYPE_KAT_KA = 'KAT_KA';
  OSSL_SELF_TEST_TYPE_DRBG = 'DRBG';
  { Test event sub categories }
  OSSL_SELF_TEST_DESC_NONE = 'None';
  OSSL_SELF_TEST_DESC_INTEGRITY_HMAC = 'HMAC';
  OSSL_SELF_TEST_DESC_PCT_RSA = 'RSA';
  OSSL_SELF_TEST_DESC_PCT_RSA_PKCS1 = 'RSA';
  OSSL_SELF_TEST_DESC_PCT_ECDSA = 'ECDSA';
  OSSL_SELF_TEST_DESC_PCT_EDDSA = 'EDDSA';
  OSSL_SELF_TEST_DESC_PCT_DH = 'DH';
  OSSL_SELF_TEST_DESC_PCT_DSA = 'DSA';
  OSSL_SELF_TEST_DESC_PCT_ML_DSA = 'ML-DSA';
  OSSL_SELF_TEST_DESC_PCT_ML_KEM = 'ML-KEM';
  OSSL_SELF_TEST_DESC_PCT_SLH_DSA = 'SLH-DSA';
  OSSL_SELF_TEST_DESC_CIPHER_AES_GCM = 'AES_GCM';
  OSSL_SELF_TEST_DESC_CIPHER_AES_ECB = 'AES_ECB_Decrypt';
  OSSL_SELF_TEST_DESC_CIPHER_TDES = 'TDES';
  OSSL_SELF_TEST_DESC_ASYM_RSA_ENC = 'RSA_Encrypt';
  OSSL_SELF_TEST_DESC_ASYM_RSA_DEC = 'RSA_Decrypt';
  OSSL_SELF_TEST_DESC_MD_SHA1 = 'SHA1';
  OSSL_SELF_TEST_DESC_MD_SHA2 = 'SHA2';
  OSSL_SELF_TEST_DESC_MD_SHA3 = 'SHA3';
  OSSL_SELF_TEST_DESC_SIGN_DSA = 'DSA';
  OSSL_SELF_TEST_DESC_SIGN_RSA = 'RSA';
  OSSL_SELF_TEST_DESC_SIGN_ECDSA = 'ECDSA';
  OSSL_SELF_TEST_DESC_SIGN_DetECDSA = 'DetECDSA';
  OSSL_SELF_TEST_DESC_SIGN_EDDSA = 'EDDSA';
  OSSL_SELF_TEST_DESC_SIGN_LMS = 'LMS';
  OSSL_SELF_TEST_DESC_SIGN_ML_DSA = 'ML-DSA';
  OSSL_SELF_TEST_DESC_SIGN_SLH_DSA = 'SLH-DSA';
  OSSL_SELF_TEST_DESC_KEM = 'KEM';
  OSSL_SELF_TEST_DESC_DRBG_CTR = 'CTR';
  OSSL_SELF_TEST_DESC_DRBG_HASH = 'HASH';
  OSSL_SELF_TEST_DESC_DRBG_HMAC = 'HMAC';
  OSSL_SELF_TEST_DESC_KA_DH = 'DH';
  OSSL_SELF_TEST_DESC_KA_ECDH = 'ECDH';
  OSSL_SELF_TEST_DESC_KDF_HKDF = 'HKDF';
  OSSL_SELF_TEST_DESC_KDF_SSKDF = 'SSKDF';
  OSSL_SELF_TEST_DESC_KDF_X963KDF = 'X963KDF';
  OSSL_SELF_TEST_DESC_KDF_X942KDF = 'X942KDF';
  OSSL_SELF_TEST_DESC_KDF_PBKDF2 = 'PBKDF2';
  OSSL_SELF_TEST_DESC_KDF_SNMPKDF = 'SNMPKDF';
  OSSL_SELF_TEST_DESC_KDF_SRTPKDF = 'SRTPKDF';
  OSSL_SELF_TEST_DESC_KDF_SSHKDF = 'SSHKDF';
  OSSL_SELF_TEST_DESC_KDF_TLS12_PRF = 'TLS12_PRF';
  OSSL_SELF_TEST_DESC_KDF_KBKDF = 'KBKDF';
  OSSL_SELF_TEST_DESC_KDF_KBKDF_KMAC = 'KBKDF_KMAC';
  OSSL_SELF_TEST_DESC_KDF_TLS13_EXTRACT = 'TLS13_KDF_EXTRACT';
  OSSL_SELF_TEST_DESC_KDF_TLS13_EXPAND = 'TLS13_KDF_EXPAND';
  OSSL_SELF_TEST_DESC_RNG = 'RNG';
  OSSL_SELF_TEST_DESC_KEYGEN_ML_DSA = 'ML-DSA';
  OSSL_SELF_TEST_DESC_KEYGEN_ML_KEM = 'ML-KEM';
  OSSL_SELF_TEST_DESC_KEYGEN_SLH_DSA = 'SLH-DSA';
  OSSL_SELF_TEST_DESC_ENCAP_KEM = 'KEM_Encap';
  OSSL_SELF_TEST_DESC_DECAP_KEM = 'KEM_Decap';
  OSSL_SELF_TEST_DESC_DECAP_KEM_FAIL = 'KEM_Decap_Reject';


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OSSL_SELF_TEST_set_callback(libctx: POSSL_LIB_CTX; cb: POSSL_CALLBACK; cbarg: pointer); cdecl; external CLibCrypto name 'OSSL_SELF_TEST_set_callback';
  procedure OSSL_SELF_TEST_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: Ppointer); cdecl; external CLibCrypto name 'OSSL_SELF_TEST_get_callback';
  function OSSL_SELF_TEST_new(cb: POSSL_CALLBACK; cbarg: pointer): POSSL_SELF_TEST; cdecl; external CLibCrypto name 'OSSL_SELF_TEST_new';
  procedure OSSL_SELF_TEST_free(st: POSSL_SELF_TEST); cdecl; external CLibCrypto name 'OSSL_SELF_TEST_free';
  procedure OSSL_SELF_TEST_onbegin(st: POSSL_SELF_TEST; type_: PAnsiChar; desc: PAnsiChar); cdecl; external CLibCrypto name 'OSSL_SELF_TEST_onbegin';
  function OSSL_SELF_TEST_oncorrupt_byte(st: POSSL_SELF_TEST; bytes: Pbyte): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_SELF_TEST_oncorrupt_byte';
  procedure OSSL_SELF_TEST_onend(st: POSSL_SELF_TEST; ret: TOpenSSL_C_INT); cdecl; external CLibCrypto name 'OSSL_SELF_TEST_onend';
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_SELF_TEST_set_callback}
  {$EXTERNALSYM OSSL_SELF_TEST_get_callback}
  {$EXTERNALSYM OSSL_SELF_TEST_new}
  {$EXTERNALSYM OSSL_SELF_TEST_free}
  {$EXTERNALSYM OSSL_SELF_TEST_onbegin}
  {$EXTERNALSYM OSSL_SELF_TEST_oncorrupt_byte}
  {$EXTERNALSYM OSSL_SELF_TEST_onend}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OSSL_SELF_TEST_set_callback(libctx: POSSL_LIB_CTX; cb: POSSL_CALLBACK; cbarg: pointer); cdecl;
  procedure Load_OSSL_SELF_TEST_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: Ppointer); cdecl;
  function Load_OSSL_SELF_TEST_new(cb: POSSL_CALLBACK; cbarg: pointer): POSSL_SELF_TEST; cdecl;
  procedure Load_OSSL_SELF_TEST_free(st: POSSL_SELF_TEST); cdecl;
  procedure Load_OSSL_SELF_TEST_onbegin(st: POSSL_SELF_TEST; type_: PAnsiChar; desc: PAnsiChar); cdecl;
  function Load_OSSL_SELF_TEST_oncorrupt_byte(st: POSSL_SELF_TEST; bytes: Pbyte): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_SELF_TEST_onend(st: POSSL_SELF_TEST; ret: TOpenSSL_C_INT); cdecl;

var
  OSSL_SELF_TEST_set_callback: procedure(libctx: POSSL_LIB_CTX; cb: POSSL_CALLBACK; cbarg: pointer); cdecl = Load_OSSL_SELF_TEST_set_callback;
  OSSL_SELF_TEST_get_callback: procedure(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: Ppointer); cdecl = Load_OSSL_SELF_TEST_get_callback;
  OSSL_SELF_TEST_new: function(cb: POSSL_CALLBACK; cbarg: pointer): POSSL_SELF_TEST; cdecl = Load_OSSL_SELF_TEST_new;
  OSSL_SELF_TEST_free: procedure(st: POSSL_SELF_TEST); cdecl = Load_OSSL_SELF_TEST_free;
  OSSL_SELF_TEST_onbegin: procedure(st: POSSL_SELF_TEST; type_: PAnsiChar; desc: PAnsiChar); cdecl = Load_OSSL_SELF_TEST_onbegin;
  OSSL_SELF_TEST_oncorrupt_byte: function(st: POSSL_SELF_TEST; bytes: Pbyte): TOpenSSL_C_INT; cdecl = Load_OSSL_SELF_TEST_oncorrupt_byte;
  OSSL_SELF_TEST_onend: procedure(st: POSSL_SELF_TEST; ret: TOpenSSL_C_INT); cdecl = Load_OSSL_SELF_TEST_onend;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}
{ OPENSSL_SELF_TEST_H }

implementation

uses Sysutils, variants
  {$ifdef OPENSSL_INTERNAL_NEED_THREADS}
   {$IFNDEF FPC}
     ,System.SyncObjs
     {$IFDEF POSIX}
       ,Posix.Pthread
     {$ELSE}
       ,Windows
     {$ENDIF}
   {$ELSE}
     ,SyncObjs
   {$ENDIF}
  {$endif}
  ,Classes, OpenSSLExceptionHandlers;

  {$if not declared(__FILE__)}
  const
    {$ifdef FPC}
    __FILE__ = {$include %FILE%};
    {$else}
    __FILE__ = '$(INPUTFILENAME)';
    {$endif}
  {$ifend}
  {$if not declared(__LINE__)}
  const
    __LINE__ = 0;
  {$ifend}
  {$if not declared(OPENSSL_FILE)}
  const
    OPENSSL_FILE = __FILE__;
  {$ifend}
  {$if not declared(OPENSSL_LINE)}
  const
    OPENSSL_LINE  = 0;
  {$ifend}

{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Load_OSSL_SELF_TEST_set_callback(libctx: POSSL_LIB_CTX; cb: POSSL_CALLBACK; cbarg: pointer); cdecl;
begin
  OSSL_SELF_TEST_set_callback := LoadLibCryptoFunction('OSSL_SELF_TEST_set_callback');
  if not assigned(OSSL_SELF_TEST_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_SELF_TEST_set_callback');
  OSSL_SELF_TEST_set_callback(libctx, cb, cbarg);
end;

procedure Load_OSSL_SELF_TEST_get_callback(libctx: POSSL_LIB_CTX; cb: PPOSSL_CALLBACK; cbarg: Ppointer); cdecl;
begin
  OSSL_SELF_TEST_get_callback := LoadLibCryptoFunction('OSSL_SELF_TEST_get_callback');
  if not assigned(OSSL_SELF_TEST_get_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_SELF_TEST_get_callback');
  OSSL_SELF_TEST_get_callback(libctx, cb, cbarg);
end;

function Load_OSSL_SELF_TEST_new(cb: POSSL_CALLBACK; cbarg: pointer): POSSL_SELF_TEST; cdecl;
begin
  OSSL_SELF_TEST_new := LoadLibCryptoFunction('OSSL_SELF_TEST_new');
  if not assigned(OSSL_SELF_TEST_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_SELF_TEST_new');
  Result := OSSL_SELF_TEST_new(cb, cbarg);
end;

procedure Load_OSSL_SELF_TEST_free(st: POSSL_SELF_TEST); cdecl;
begin
  OSSL_SELF_TEST_free := LoadLibCryptoFunction('OSSL_SELF_TEST_free');
  if not assigned(OSSL_SELF_TEST_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_SELF_TEST_free');
  OSSL_SELF_TEST_free(st);
end;

procedure Load_OSSL_SELF_TEST_onbegin(st: POSSL_SELF_TEST; type_: PAnsiChar; desc: PAnsiChar); cdecl;
begin
  OSSL_SELF_TEST_onbegin := LoadLibCryptoFunction('OSSL_SELF_TEST_onbegin');
  if not assigned(OSSL_SELF_TEST_onbegin) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_SELF_TEST_onbegin');
  OSSL_SELF_TEST_onbegin(st, type_, desc);
end;

function Load_OSSL_SELF_TEST_oncorrupt_byte(st: POSSL_SELF_TEST; bytes: Pbyte): TOpenSSL_C_INT; cdecl;
begin
  OSSL_SELF_TEST_oncorrupt_byte := LoadLibCryptoFunction('OSSL_SELF_TEST_oncorrupt_byte');
  if not assigned(OSSL_SELF_TEST_oncorrupt_byte) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_SELF_TEST_oncorrupt_byte');
  Result := OSSL_SELF_TEST_oncorrupt_byte(st, bytes);
end;

procedure Load_OSSL_SELF_TEST_onend(st: POSSL_SELF_TEST; ret: TOpenSSL_C_INT); cdecl;
begin
  OSSL_SELF_TEST_onend := LoadLibCryptoFunction('OSSL_SELF_TEST_onend');
  if not assigned(OSSL_SELF_TEST_onend) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_SELF_TEST_onend');
  OSSL_SELF_TEST_onend(st, ret);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_SELF_TEST_set_callback := Load_OSSL_SELF_TEST_set_callback;
  OSSL_SELF_TEST_get_callback := Load_OSSL_SELF_TEST_get_callback;
  OSSL_SELF_TEST_new := Load_OSSL_SELF_TEST_new;
  OSSL_SELF_TEST_free := Load_OSSL_SELF_TEST_free;
  OSSL_SELF_TEST_onbegin := Load_OSSL_SELF_TEST_onbegin;
  OSSL_SELF_TEST_oncorrupt_byte := Load_OSSL_SELF_TEST_oncorrupt_byte;
  OSSL_SELF_TEST_onend := Load_OSSL_SELF_TEST_onend;
end;

{$endif} {OPENSSL_STATIC_LINK_MODEL}

initialization

{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef EMPTY_LOAD_FUNCTION}
Register_SSLloader(@Load);
{$endif}
Register_SSLUnloader(@Unload);
{$endif}
{$if declared(LegacySupport_Initialization)}
LegacySupport_Initialization;
{$ifend}

finalization

{$if declared(LegacySupport_Finalization)}
LegacySupport_Finalization;
{$ifend}

end.



