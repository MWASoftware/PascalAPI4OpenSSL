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

unit openssl_quic;

{
  Generated from OpenSSL 4.0.0 Header File quic.h - Tue 19 May 14:33:08 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_quic.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_ssl;


{* Copyright 2022-2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_QUIC_H}
  {$define OPENSSL_QUIC_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_QUIC}


    
    {* Method used for non-thread-assisted QUIC client operation.
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_QUIC_client_method: PSSL_METHOD; cdecl; external CLibCrypto name 'OSSL_QUIC_client_method';
  
  {* Method used for thread-assisted QUIC client operation.
  }
  function OSSL_QUIC_client_thread_method: PSSL_METHOD; cdecl; external CLibCrypto name 'OSSL_QUIC_client_thread_method';
  
  {* QUIC transport error codes (RFC 9000 s. 20.1)
  }
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_QUIC_client_method}
  {$EXTERNALSYM OSSL_QUIC_client_thread_method}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_QUIC_client_method: PSSL_METHOD; cdecl;
  function Load_OSSL_QUIC_client_thread_method: PSSL_METHOD; cdecl;

var
  OSSL_QUIC_client_method: function: PSSL_METHOD; cdecl = Load_OSSL_QUIC_client_method;
  
  {* Method used for thread-assisted QUIC client operation.
  }
  OSSL_QUIC_client_thread_method: function: PSSL_METHOD; cdecl = Load_OSSL_QUIC_client_thread_method;
  
  {* QUIC transport error codes (RFC 9000 s. 20.1)
  }
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  OSSL_QUIC_ERR_NO_ERROR = $00;
  OSSL_QUIC_ERR_INTERNAL_ERROR = $01;
  OSSL_QUIC_ERR_CONNECTION_REFUSED = $02;
  OSSL_QUIC_ERR_FLOW_CONTROL_ERROR = $03;
  OSSL_QUIC_ERR_STREAM_LIMIT_ERROR = $04;
  OSSL_QUIC_ERR_STREAM_STATE_ERROR = $05;
  OSSL_QUIC_ERR_FINAL_SIZE_ERROR = $06;
  OSSL_QUIC_ERR_FRAME_ENCODING_ERROR = $07;
  OSSL_QUIC_ERR_TRANSPORT_PARAMETER_ERROR = $08;
  OSSL_QUIC_ERR_CONNECTION_ID_LIMIT_ERROR = $09;
  OSSL_QUIC_ERR_PROTOCOL_VIOLATION = $0A;
  OSSL_QUIC_ERR_INVALID_TOKEN = $0B;
  OSSL_QUIC_ERR_APPLICATION_ERROR = $0C;
  OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED = $0D;
  OSSL_QUIC_ERR_KEY_UPDATE_ERROR = $0E;
  OSSL_QUIC_ERR_AEAD_LIMIT_REACHED = $0F;
  OSSL_QUIC_ERR_NO_VIABLE_PATH = $10;
    { Inclusive range for handshake-specific errors. }
  OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN = $0100;
  OSSL_QUIC_ERR_CRYPTO_ERR_END = $01FF;
  {# define  OSSL_QUIC_ERR_CRYPTO_ERR(X) (OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN + (X))} {Macro Return Type unknown at line no 57}


    { Local errors. }
  function OSSL_QUIC_LOCAL_ERR_IDLE_TIMEOUT: TOpenSSL_C_UINT64; inline;
    
    {* Method used for QUIC server operation.
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_QUIC_server_method: PSSL_METHOD; cdecl; external CLibCrypto name 'OSSL_QUIC_server_method';
  
  {* Method used for QUIC client/server connection
  }
  function OSSL_QUIC_method: PSSL_METHOD; cdecl; external CLibCrypto name 'OSSL_QUIC_method';
    {$else}
  {$EXTERNALSYM OSSL_QUIC_server_method}
  {$EXTERNALSYM OSSL_QUIC_method}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_QUIC_server_method: PSSL_METHOD; cdecl;
  function Load_OSSL_QUIC_method: PSSL_METHOD; cdecl;

var
  OSSL_QUIC_server_method: function: PSSL_METHOD; cdecl = Load_OSSL_QUIC_server_method;
  
  {* Method used for QUIC client/server connection
  }
  OSSL_QUIC_method: function: PSSL_METHOD; cdecl = Load_OSSL_QUIC_method;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  { OPENSSL_NO_QUIC }
{$endif}

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

{$ifndef  OPENSSL_NO_QUIC}

{# define  OSSL_QUIC_LOCAL_ERR_IDLE_TIMEOUT ((uint64_t)0xFFFFFFFFFFFFFFFFULL)}

function OSSL_QUIC_LOCAL_ERR_IDLE_TIMEOUT: TOpenSSL_C_UINT64;
begin
  Result := TOpenSSL_C_UINT64(TOpenSSL_C_UINT64($FFFFFFFFFFFFFFFF));
end;
{$endif} { OPENSSL_NO_QUIC}
{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef  OPENSSL_NO_QUIC}
function Load_OSSL_QUIC_client_method: PSSL_METHOD; cdecl;
begin
  OSSL_QUIC_client_method := LoadLibCryptoFunction('OSSL_QUIC_client_method');
  if not assigned(OSSL_QUIC_client_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_QUIC_client_method');
  Result := OSSL_QUIC_client_method;
end;

function Load_OSSL_QUIC_client_thread_method: PSSL_METHOD; cdecl;
begin
  OSSL_QUIC_client_thread_method := LoadLibCryptoFunction('OSSL_QUIC_client_thread_method');
  if not assigned(OSSL_QUIC_client_thread_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_QUIC_client_thread_method');
  Result := OSSL_QUIC_client_thread_method;
end;

function Load_OSSL_QUIC_server_method: PSSL_METHOD; cdecl;
begin
  OSSL_QUIC_server_method := LoadLibCryptoFunction('OSSL_QUIC_server_method');
  if not assigned(OSSL_QUIC_server_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_QUIC_server_method');
  Result := OSSL_QUIC_server_method;
end;

function Load_OSSL_QUIC_method: PSSL_METHOD; cdecl;
begin
  OSSL_QUIC_method := LoadLibCryptoFunction('OSSL_QUIC_method');
  if not assigned(OSSL_QUIC_method) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_QUIC_method');
  Result := OSSL_QUIC_method;
end;

{$endif} { OPENSSL_NO_QUIC}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_QUIC}
  OSSL_QUIC_client_method := Load_OSSL_QUIC_client_method;
  OSSL_QUIC_client_thread_method := Load_OSSL_QUIC_client_thread_method;
  OSSL_QUIC_server_method := Load_OSSL_QUIC_server_method;
  OSSL_QUIC_method := Load_OSSL_QUIC_method;
{$endif} { OPENSSL_NO_QUIC}
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



