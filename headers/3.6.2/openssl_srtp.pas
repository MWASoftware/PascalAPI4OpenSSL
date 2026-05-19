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

unit openssl_srtp;

{
  Generated from OpenSSL 3.6.2 Header File srtp.h - Tue 19 May 14:30:43 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_srtp.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_stack;


{* Copyright 2011-2016 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}

{* DTLS code by Eric Rescorla <ekr@rtfm.com>
*
* Copyright (C) 2006, Network Resonance, Inc. Copyright (C) 2011, RTFM, Inc.
}
{$ifndef  OPENSSL_SRTP_H}
  {$define OPENSSL_SRTP_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_D1_SRTP_H}
  {$endif}

const
  SRTP_AES128_CM_SHA1_80 = $0001;
  SRTP_AES128_CM_SHA1_32 = $0002;
  SRTP_AES128_F8_SHA1_80 = $0003;
  SRTP_AES128_F8_SHA1_32 = $0004;
  SRTP_NULL_SHA1_80 = $0005;
  SRTP_NULL_SHA1_32 = $0006;
  { AEAD SRTP protection profiles from RFC 7714 }
  SRTP_AEAD_AES_128_GCM = $0007;
  SRTP_AEAD_AES_256_GCM = $0008;

type
  {Auto-generated forward references}
  Psrtp_protection_profile_st = ^Tsrtp_protection_profile_st;
  PPsrtp_protection_profile_st = ^Psrtp_protection_profile_st;
  PSRTP_PROTECTION_PROFILE = ^TSRTP_PROTECTION_PROFILE;
  PPSRTP_PROTECTION_PROFILE = ^PSRTP_PROTECTION_PROFILE;
  Pstack_st_SRTP_PROTECTION_PROFILE = ^Tstack_st_SRTP_PROTECTION_PROFILE;
  PPstack_st_SRTP_PROTECTION_PROFILE = ^Pstack_st_SRTP_PROTECTION_PROFILE;
  Psk_SRTP_PROTECTION_PROFILE_compfunc = ^Tsk_SRTP_PROTECTION_PROFILE_compfunc;
  PPsk_SRTP_PROTECTION_PROFILE_compfunc = ^Psk_SRTP_PROTECTION_PROFILE_compfunc;
  Psk_SRTP_PROTECTION_PROFILE_freefunc = ^Tsk_SRTP_PROTECTION_PROFILE_freefunc;
  PPsk_SRTP_PROTECTION_PROFILE_freefunc = ^Psk_SRTP_PROTECTION_PROFILE_freefunc;
  Psk_SRTP_PROTECTION_PROFILE_copyfunc = ^Tsk_SRTP_PROTECTION_PROFILE_copyfunc;
  PPsk_SRTP_PROTECTION_PROFILE_copyfunc = ^Psk_SRTP_PROTECTION_PROFILE_copyfunc;
  {end of auto-generated forward references}

  {Moved for ssl.h}
  { SRTP protection profiles for use with the use_srtp extension (RFC 5764)}
  Tsrtp_protection_profile_st = record 
    name: PAnsiChar;
    id: TOpenSSL_C_UINT;
  end;
  TSRTP_PROTECTION_PROFILE = Tsrtp_protection_profile_st;
  Tstack_st_SRTP_PROTECTION_PROFILE = record 
  end;
  Tsk_SRTP_PROTECTION_PROFILE_compfunc = function(a: PPSRTP_PROTECTION_PROFILE; b: PPSRTP_PROTECTION_PROFILE): TOpenSSL_C_INT; cdecl;
  Tsk_SRTP_PROTECTION_PROFILE_freefunc = procedure(a: PSRTP_PROTECTION_PROFILE); cdecl;
  Tsk_SRTP_PROTECTION_PROFILE_copyfunc = function(a: PSRTP_PROTECTION_PROFILE): PSRTP_PROTECTION_PROFILE; cdecl;


  procedure sk_SRTP_PROTECTION_PROFILE_freefunc_thunk(freefunc_arg: TOPENSSL_sk_freefunc; ptr: pointer); inline;
  function ossl_check_SRTP_PROTECTION_PROFILE_type(ptr: PSRTP_PROTECTION_PROFILE): PSRTP_PROTECTION_PROFILE{Has C Attribute: unused}; inline;
  function ossl_check_const_SRTP_PROTECTION_PROFILE_sk_type(sk: Pstack_st_SRTP_PROTECTION_PROFILE): POPENSSL_STACK{Has C Attribute: unused}; inline;
  function ossl_check_SRTP_PROTECTION_PROFILE_sk_type(sk: Pstack_st_SRTP_PROTECTION_PROFILE): POPENSSL_STACK{Has C Attribute: unused}; inline;
  function ossl_check_SRTP_PROTECTION_PROFILE_compfunc_type(cmp: Tsk_SRTP_PROTECTION_PROFILE_compfunc): TOPENSSL_sk_compfunc{Has C Attribute: unused}; inline;
  function ossl_check_SRTP_PROTECTION_PROFILE_copyfunc_type(cpy: Tsk_SRTP_PROTECTION_PROFILE_copyfunc): TOPENSSL_sk_copyfunc{Has C Attribute: unused}; inline;
  function ossl_check_SRTP_PROTECTION_PROFILE_freefunc_type(fr: Tsk_SRTP_PROTECTION_PROFILE_freefunc): TOPENSSL_sk_freefunc{Has C Attribute: unused}; inline;

const
  { DOUBLE AEAD SRTP protection profiles from RFC 8723 }
  SRTP_DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = $0009;
  SRTP_DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM = $000A;
  { ARIA SRTP protection profiles from RFC 8269 }
  SRTP_ARIA_128_CTR_HMAC_SHA1_80 = $000B;
  SRTP_ARIA_128_CTR_HMAC_SHA1_32 = $000C;
  SRTP_ARIA_256_CTR_HMAC_SHA1_80 = $000D;
  SRTP_ARIA_256_CTR_HMAC_SHA1_32 = $000E;
  SRTP_AEAD_ARIA_128_GCM = $000F;
  SRTP_AEAD_ARIA_256_GCM = $0010;
  {$ifndef  OPENSSL_NO_SRTP}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_CTX_set_tlsext_use_srtp';
  function SSL_set_tlsext_use_srtp(ssl: PSSL; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_set_tlsext_use_srtp';
  function SSL_get_srtp_profiles(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl; external CLibCrypto name 'SSL_get_srtp_profiles';
  function SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl; external CLibCrypto name 'SSL_get_selected_srtp_profile';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM SSL_CTX_set_tlsext_use_srtp}
  {$EXTERNALSYM SSL_set_tlsext_use_srtp}
  {$EXTERNALSYM SSL_get_srtp_profiles}
  {$EXTERNALSYM SSL_get_selected_srtp_profile}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_SSL_set_tlsext_use_srtp(ssl: PSSL; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_SSL_get_srtp_profiles(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl;
  function Load_SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl;

var
  SSL_CTX_set_tlsext_use_srtp: function(ctx: PSSL_CTX; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set_tlsext_use_srtp;
  SSL_set_tlsext_use_srtp: function(ssl: PSSL; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_set_tlsext_use_srtp;
  SSL_get_srtp_profiles: function(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl = Load_SSL_get_srtp_profiles;
  SSL_get_selected_srtp_profile: function(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl = Load_SSL_get_selected_srtp_profile;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
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

procedure sk_SRTP_PROTECTION_PROFILE_freefunc_thunk(freefunc_arg: TOPENSSL_sk_freefunc; ptr: pointer); inline;
begin
  raise Exception.Create('Unable to translate C Function "sk_SRTP_PROTECTION_PROFILE_freefunc_thunk"');

{Error: Line 47: Syntax Error parsing " sk_SRTP_PROTECTION_PROFILE_freefunc freefunc = (sk_SRTP_PROTECTION_PROFILE_freefunc)freefunc_arg; 
freefunc((SRTP_PROTECTION_PROFILE *)ptr); "

 sk_SRTP_PROTECTION_PROFILE_freefunc freefunc = (sk_SRTP_PROTECTION_PROFILE_freefunc)freefunc_arg; freefunc((SRTP_PROTECTION_PROFILE 
*)ptr); }
end;

function ossl_check_SRTP_PROTECTION_PROFILE_type(ptr: PSRTP_PROTECTION_PROFILE): PSRTP_PROTECTION_PROFILE{Has C Attribute: unused}; inline;
begin
   Result := ptr;
end;

function ossl_check_const_SRTP_PROTECTION_PROFILE_sk_type(sk: Pstack_st_SRTP_PROTECTION_PROFILE): POPENSSL_STACK{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STACK(sk);
end;

function ossl_check_SRTP_PROTECTION_PROFILE_sk_type(sk: Pstack_st_SRTP_PROTECTION_PROFILE): POPENSSL_STACK{Has C Attribute: unused}; inline;
begin
   Result := POPENSSL_STACK(sk);
end;

function ossl_check_SRTP_PROTECTION_PROFILE_compfunc_type(cmp: Tsk_SRTP_PROTECTION_PROFILE_compfunc): TOPENSSL_sk_compfunc{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_sk_compfunc(cmp);
end;

function ossl_check_SRTP_PROTECTION_PROFILE_copyfunc_type(cpy: Tsk_SRTP_PROTECTION_PROFILE_copyfunc): TOPENSSL_sk_copyfunc{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_sk_copyfunc(cpy);
end;

function ossl_check_SRTP_PROTECTION_PROFILE_freefunc_type(fr: Tsk_SRTP_PROTECTION_PROFILE_freefunc): TOPENSSL_sk_freefunc{Has C Attribute: unused}; inline;
begin
   Result := TOPENSSL_sk_freefunc(fr);
end;

{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef  OPENSSL_NO_SRTP}
function Load_SSL_CTX_set_tlsext_use_srtp(ctx: PSSL_CTX; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set_tlsext_use_srtp := LoadLibCryptoFunction('SSL_CTX_set_tlsext_use_srtp');
  if not assigned(SSL_CTX_set_tlsext_use_srtp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set_tlsext_use_srtp');
  Result := SSL_CTX_set_tlsext_use_srtp(ctx, profiles);
end;

function Load_SSL_set_tlsext_use_srtp(ssl: PSSL; profiles: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_set_tlsext_use_srtp := LoadLibCryptoFunction('SSL_set_tlsext_use_srtp');
  if not assigned(SSL_set_tlsext_use_srtp) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set_tlsext_use_srtp');
  Result := SSL_set_tlsext_use_srtp(ssl, profiles);
end;

function Load_SSL_get_srtp_profiles(ssl: PSSL): Pstack_st_SRTP_PROTECTION_PROFILE; cdecl;
begin
  SSL_get_srtp_profiles := LoadLibCryptoFunction('SSL_get_srtp_profiles');
  if not assigned(SSL_get_srtp_profiles) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_srtp_profiles');
  Result := SSL_get_srtp_profiles(ssl);
end;

function Load_SSL_get_selected_srtp_profile(s: PSSL): PSRTP_PROTECTION_PROFILE; cdecl;
begin
  SSL_get_selected_srtp_profile := LoadLibCryptoFunction('SSL_get_selected_srtp_profile');
  if not assigned(SSL_get_selected_srtp_profile) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get_selected_srtp_profile');
  Result := SSL_get_selected_srtp_profile(s);
end;

{$endif} { OPENSSL_NO_SRTP}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_SRTP}
  SSL_CTX_set_tlsext_use_srtp := Load_SSL_CTX_set_tlsext_use_srtp;
  SSL_set_tlsext_use_srtp := Load_SSL_set_tlsext_use_srtp;
  SSL_get_srtp_profiles := Load_SSL_get_srtp_profiles;
  SSL_get_selected_srtp_profile := Load_SSL_get_selected_srtp_profile;
{$endif} { OPENSSL_NO_SRTP}
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



