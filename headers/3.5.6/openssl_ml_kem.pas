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

unit openssl_ml_kem;

{
  Generated from OpenSSL 3.5.6 Header File ml_kem.h - Tue 19 May 14:27:54 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_ml_kem.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI;


{* Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_ML_KEM_H}
  {$define OPENSSL_ML_KEM_H}

const
  OSSL_ML_KEM_SHARED_SECRET_BYTES = 32;
  OSSL_ML_KEM_512_BITS = 512;
  OSSL_ML_KEM_512_SECURITY_BITS = 128;
  OSSL_ML_KEM_512_CIPHERTEXT_BYTES = 768;
  OSSL_ML_KEM_512_PUBLIC_KEY_BYTES = 800;
  OSSL_ML_KEM_768_BITS = 768;
  OSSL_ML_KEM_768_SECURITY_BITS = 192;
  OSSL_ML_KEM_768_CIPHERTEXT_BYTES = 1088;
  OSSL_ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
  OSSL_ML_KEM_1024_BITS = 1024;
  OSSL_ML_KEM_1024_SECURITY_BITS = 256;
  OSSL_ML_KEM_1024_CIPHERTEXT_BYTES = 1568;
  OSSL_ML_KEM_1024_PUBLIC_KEY_BYTES = 1568;
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

{$ifndef OPENSSL_STATIC_LINK_MODEL}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
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



