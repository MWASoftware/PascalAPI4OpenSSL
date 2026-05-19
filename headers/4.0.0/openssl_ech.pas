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

unit openssl_ech;

{
  Generated from OpenSSL 4.0.0 Header File ech.h - Tue 19 May 14:32:32 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_ech.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_ssl,openssl_hpke;


{* Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the OpenSSL license (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}

{* Externally-visible data structures and prototypes for handling
* shared-mode Encrypted ClientHello (ECH).
}
{$ifndef  OPENSSL_ECH_H}
  {$define OPENSSL_ECH_H}
  {$ifndef  OPENSSL_NO_ECH}

const
    
    {* Some externally visible limits - most used for sanity checks that could be
    * bigger if needed, but that work for now
    }
  OSSL_ECH_MAX_PAYLOAD_LEN = 1500;
  OSSL_ECH_MIN_ECHCONFIG_LEN = 32;
  OSSL_ECH_MAX_ECHCONFIG_LEN = 1500;
  OSSL_ECH_MAX_ECHCONFIGEXT_LEN = 512;
  OSSL_ECH_MAX_MAXNAMELEN = 255;
  OSSL_ECH_MAX_PUBLICNAME = 255;
  OSSL_ECH_MAX_ALPNLEN = 255;
  OSSL_ECH_OUTERS_MAX = 20;
  OSSL_ECH_ALLEXTS_MAX = 32;
    
    {* ECH version. We only support RFC 9849 as of now.  As/if new ECHConfig
    * versions are added, those will be noted here.
    }
  OSSL_ECH_RFC9849_VERSION = $fe0d;
    { latest version from an RFC }
  OSSL_ECH_CURRENT_VERSION = OSSL_ECH_RFC9849_VERSION;
    { Return codes from SSL_ech_get1_status }
  SSL_ECH_STATUS_BACKEND = 4;
  SSL_ECH_STATUS_GREASE_ECH = 3;
  SSL_ECH_STATUS_GREASE = 2;
  SSL_ECH_STATUS_SUCCESS = 1;
  SSL_ECH_STATUS_FAILED = 0;
  SSL_ECH_STATUS_BAD_CALL = -(100);
  SSL_ECH_STATUS_NOT_TRIED = -(101);
  SSL_ECH_STATUS_BAD_NAME = -(102);
  SSL_ECH_STATUS_NOT_CONFIGURED = -(103);
  SSL_ECH_STATUS_FAILED_ECH = -(105);
  SSL_ECH_STATUS_FAILED_ECH_BAD_NAME = -(106);
    { if a caller wants to index the last entry in the store }
  OSSL_ECHSTORE_LAST = -(1);
    { if a caller wants all entries in the store, e.g. to print public values }
  OSSL_ECHSTORE_ALL = -(2);
    { Values for the for_retry inputs }
  OSSL_ECH_FOR_RETRY = 1;
  OSSL_ECH_NO_RETRY = 0;


    
    {* API calls built around OSSL_ECHSTORE
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_ECHSTORE_new(libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_ECHSTORE; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_new';
  procedure OSSL_ECHSTORE_free(es: POSSL_ECHSTORE); cdecl; external CLibCrypto name 'OSSL_ECHSTORE_free';
  function OSSL_ECHSTORE_new_config(es: POSSL_ECHSTORE; echversion: TOpenSSL_C_UINT16; max_name_length: byte; public_name: PAnsiChar; suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_new_config';
  function OSSL_ECHSTORE_write_pem(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; out_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_write_pem';
  function OSSL_ECHSTORE_read_echconfiglist(es: POSSL_ECHSTORE; in_: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_read_echconfiglist';
  function OSSL_ECHSTORE_get1_info(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; loaded_secs: POpenSSL_C_TIMET; public_name: PPAnsiChar; echconfig: PPAnsiChar; has_private: POpenSSL_C_INT; for_retry: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_get1_info';
  function OSSL_ECHSTORE_downselect(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_downselect';
  function OSSL_ECHSTORE_set1_key_and_read_pem(es: POSSL_ECHSTORE; priv: PEVP_PKEY; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_set1_key_and_read_pem';
  function OSSL_ECHSTORE_read_pem(es: POSSL_ECHSTORE; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_read_pem';
  function OSSL_ECHSTORE_num_entries(es: POSSL_ECHSTORE; numentries: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_num_entries';
  function OSSL_ECHSTORE_num_keys(es: POSSL_ECHSTORE; numkeys: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_num_keys';
  function OSSL_ECHSTORE_flush_keys(es: POSSL_ECHSTORE; age: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_ECHSTORE_flush_keys';
  
  {* APIs relating OSSL_ECHSTORE to SSL/SSL_CTX
  }
  function SSL_CTX_set1_echstore(ctx: PSSL_CTX; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_CTX_set1_echstore';
  function SSL_set1_echstore(s: PSSL; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_set1_echstore';
  function SSL_CTX_get1_echstore(ctx: PSSL_CTX): POSSL_ECHSTORE; cdecl; external CLibCrypto name 'SSL_CTX_get1_echstore';
  function SSL_get1_echstore(s: PSSL): POSSL_ECHSTORE; cdecl; external CLibCrypto name 'SSL_get1_echstore';
  function SSL_ech_set1_server_names(s: PSSL; inner_name: PAnsiChar; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_ech_set1_server_names';
  function SSL_ech_set1_outer_server_name(s: PSSL; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_ech_set1_outer_server_name';
  
  {* Note that this function returns 1 for success and 0 for error. This
  * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
  * returns 0 for success and 1 on error.
  }
  function SSL_ech_set1_outer_alpn_protos(s: PSSL; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_ech_set1_outer_alpn_protos';
  function SSL_ech_get1_status(s: PSSL; inner_sni: PPAnsiChar; outer_sni: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_ech_get1_status';
  function SSL_ech_set1_grease_suite(s: PSSL; suite: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_ech_set1_grease_suite';
  function SSL_ech_set_grease_type(s: PSSL; type_: TOpenSSL_C_UINT16): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_ech_set_grease_type';
    {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_ECHSTORE_new}
  {$EXTERNALSYM OSSL_ECHSTORE_free}
  {$EXTERNALSYM OSSL_ECHSTORE_new_config}
  {$EXTERNALSYM OSSL_ECHSTORE_write_pem}
  {$EXTERNALSYM OSSL_ECHSTORE_read_echconfiglist}
  {$EXTERNALSYM OSSL_ECHSTORE_get1_info}
  {$EXTERNALSYM OSSL_ECHSTORE_downselect}
  {$EXTERNALSYM OSSL_ECHSTORE_set1_key_and_read_pem}
  {$EXTERNALSYM OSSL_ECHSTORE_read_pem}
  {$EXTERNALSYM OSSL_ECHSTORE_num_entries}
  {$EXTERNALSYM OSSL_ECHSTORE_num_keys}
  {$EXTERNALSYM OSSL_ECHSTORE_flush_keys}
  {$EXTERNALSYM SSL_CTX_set1_echstore}
  {$EXTERNALSYM SSL_set1_echstore}
  {$EXTERNALSYM SSL_CTX_get1_echstore}
  {$EXTERNALSYM SSL_get1_echstore}
  {$EXTERNALSYM SSL_ech_set1_server_names}
  {$EXTERNALSYM SSL_ech_set1_outer_server_name}
  {$EXTERNALSYM SSL_ech_set1_outer_alpn_protos}
  {$EXTERNALSYM SSL_ech_get1_status}
  {$EXTERNALSYM SSL_ech_set1_grease_suite}
  {$EXTERNALSYM SSL_ech_set_grease_type}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_ECHSTORE_new(libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_ECHSTORE; cdecl;
  procedure Load_OSSL_ECHSTORE_free(es: POSSL_ECHSTORE); cdecl;
  function Load_OSSL_ECHSTORE_new_config(es: POSSL_ECHSTORE; echversion: TOpenSSL_C_UINT16; max_name_length: byte; public_name: PAnsiChar; suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_write_pem(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; out_: PBIO): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_read_echconfiglist(es: POSSL_ECHSTORE; in_: PBIO): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_get1_info(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; loaded_secs: POpenSSL_C_TIMET; public_name: PPAnsiChar; echconfig: PPAnsiChar; has_private: POpenSSL_C_INT; for_retry: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_downselect(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_set1_key_and_read_pem(es: POSSL_ECHSTORE; priv: PEVP_PKEY; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_read_pem(es: POSSL_ECHSTORE; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_num_entries(es: POSSL_ECHSTORE; numentries: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_num_keys(es: POSSL_ECHSTORE; numkeys: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_ECHSTORE_flush_keys(es: POSSL_ECHSTORE; age: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
  function Load_SSL_CTX_set1_echstore(ctx: PSSL_CTX; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl;
  function Load_SSL_set1_echstore(s: PSSL; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl;
  function Load_SSL_CTX_get1_echstore(ctx: PSSL_CTX): POSSL_ECHSTORE; cdecl;
  function Load_SSL_get1_echstore(s: PSSL): POSSL_ECHSTORE; cdecl;
  function Load_SSL_ech_set1_server_names(s: PSSL; inner_name: PAnsiChar; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_SSL_ech_set1_outer_server_name(s: PSSL; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_SSL_ech_set1_outer_alpn_protos(s: PSSL; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_SSL_ech_get1_status(s: PSSL; inner_sni: PPAnsiChar; outer_sni: PPAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_SSL_ech_set1_grease_suite(s: PSSL; suite: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_SSL_ech_set_grease_type(s: PSSL; type_: TOpenSSL_C_UINT16): TOpenSSL_C_INT; cdecl;

var
  OSSL_ECHSTORE_new: function(libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_ECHSTORE; cdecl = Load_OSSL_ECHSTORE_new;
  OSSL_ECHSTORE_free: procedure(es: POSSL_ECHSTORE); cdecl = Load_OSSL_ECHSTORE_free;
  OSSL_ECHSTORE_new_config: function(es: POSSL_ECHSTORE; echversion: TOpenSSL_C_UINT16; max_name_length: byte; public_name: PAnsiChar; suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_new_config;
  OSSL_ECHSTORE_write_pem: function(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; out_: PBIO): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_write_pem;
  OSSL_ECHSTORE_read_echconfiglist: function(es: POSSL_ECHSTORE; in_: PBIO): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_read_echconfiglist;
  OSSL_ECHSTORE_get1_info: function(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; loaded_secs: POpenSSL_C_TIMET; public_name: PPAnsiChar; echconfig: PPAnsiChar; has_private: POpenSSL_C_INT; for_retry: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_get1_info;
  OSSL_ECHSTORE_downselect: function(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_downselect;
  OSSL_ECHSTORE_set1_key_and_read_pem: function(es: POSSL_ECHSTORE; priv: PEVP_PKEY; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_set1_key_and_read_pem;
  OSSL_ECHSTORE_read_pem: function(es: POSSL_ECHSTORE; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_read_pem;
  OSSL_ECHSTORE_num_entries: function(es: POSSL_ECHSTORE; numentries: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_num_entries;
  OSSL_ECHSTORE_num_keys: function(es: POSSL_ECHSTORE; numkeys: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_num_keys;
  OSSL_ECHSTORE_flush_keys: function(es: POSSL_ECHSTORE; age: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl = Load_OSSL_ECHSTORE_flush_keys;
  
  {* APIs relating OSSL_ECHSTORE to SSL/SSL_CTX
  }
  SSL_CTX_set1_echstore: function(ctx: PSSL_CTX; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_set1_echstore;
  SSL_set1_echstore: function(s: PSSL; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl = Load_SSL_set1_echstore;
  SSL_CTX_get1_echstore: function(ctx: PSSL_CTX): POSSL_ECHSTORE; cdecl = Load_SSL_CTX_get1_echstore;
  SSL_get1_echstore: function(s: PSSL): POSSL_ECHSTORE; cdecl = Load_SSL_get1_echstore;
  SSL_ech_set1_server_names: function(s: PSSL; inner_name: PAnsiChar; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_ech_set1_server_names;
  SSL_ech_set1_outer_server_name: function(s: PSSL; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_SSL_ech_set1_outer_server_name;
  
  {* Note that this function returns 1 for success and 0 for error. This
  * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
  * returns 0 for success and 1 on error.
  }
  SSL_ech_set1_outer_alpn_protos: function(s: PSSL; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_ech_set1_outer_alpn_protos;
  SSL_ech_get1_status: function(s: PSSL; inner_sni: PPAnsiChar; outer_sni: PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_ech_get1_status;
  SSL_ech_set1_grease_suite: function(s: PSSL; suite: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_SSL_ech_set1_grease_suite;
  SSL_ech_set_grease_type: function(s: PSSL; type_: TOpenSSL_C_UINT16): TOpenSSL_C_INT; cdecl = Load_SSL_ech_set_grease_type;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PSSL_ech_cb_func = ^TSSL_ech_cb_func;
  PPSSL_ech_cb_func = ^PSSL_ech_cb_func;
  {end of auto-generated forward references}

  TSSL_ech_cb_func = function(s: PSSL; str: PAnsiChar): TOpenSSL_C_UINT; cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure SSL_ech_set_callback(s: PSSL; f: TSSL_ech_cb_func); cdecl; external CLibCrypto name 'SSL_ech_set_callback';
  function SSL_ech_get1_retry_config(s: PSSL; ec: PPbyte; eclen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_ech_get1_retry_config';
  
  {* Note that this function returns 1 for success and 0 for error. This
  * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
  * returns 0 for success and 1 on error.
  }
  function SSL_CTX_ech_set1_outer_alpn_protos(s: PSSL_CTX; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_CTX_ech_set1_outer_alpn_protos';
  procedure SSL_CTX_ech_set_callback(ctx: PSSL_CTX; f: TSSL_ech_cb_func); cdecl; external CLibCrypto name 'SSL_CTX_ech_set_callback';
  function SSL_set1_ech_config_list(ssl: PSSL; ecl: Pbyte; ecl_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'SSL_set1_ech_config_list';
    {$else}
  {$EXTERNALSYM SSL_ech_set_callback}
  {$EXTERNALSYM SSL_ech_get1_retry_config}
  {$EXTERNALSYM SSL_CTX_ech_set1_outer_alpn_protos}
  {$EXTERNALSYM SSL_CTX_ech_set_callback}
  {$EXTERNALSYM SSL_set1_ech_config_list}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_SSL_ech_set_callback(s: PSSL; f: TSSL_ech_cb_func); cdecl;
  function Load_SSL_ech_get1_retry_config(s: PSSL; ec: PPbyte; eclen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  function Load_SSL_CTX_ech_set1_outer_alpn_protos(s: PSSL_CTX; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
  procedure Load_SSL_CTX_ech_set_callback(ctx: PSSL_CTX; f: TSSL_ech_cb_func); cdecl;
  function Load_SSL_set1_ech_config_list(ssl: PSSL; ecl: Pbyte; ecl_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;

var
  SSL_ech_set_callback: procedure(s: PSSL; f: TSSL_ech_cb_func); cdecl = Load_SSL_ech_set_callback;
  SSL_ech_get1_retry_config: function(s: PSSL; ec: PPbyte; eclen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_ech_get1_retry_config;
  
  {* Note that this function returns 1 for success and 0 for error. This
  * contrasts with SSL_set1_alpn_protos() which (unusually for OpenSSL)
  * returns 0 for success and 1 on error.
  }
  SSL_CTX_ech_set1_outer_alpn_protos: function(s: PSSL_CTX; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_CTX_ech_set1_outer_alpn_protos;
  SSL_CTX_ech_set_callback: procedure(ctx: PSSL_CTX; f: TSSL_ech_cb_func); cdecl = Load_SSL_CTX_ech_set_callback;
  SSL_set1_ech_config_list: function(ssl: PSSL; ecl: Pbyte; ecl_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = Load_SSL_set1_ech_config_list;
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

{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef  OPENSSL_NO_ECH}
function Load_OSSL_ECHSTORE_new(libctx: POSSL_LIB_CTX; propq: PAnsiChar): POSSL_ECHSTORE; cdecl;
begin
  OSSL_ECHSTORE_new := LoadLibCryptoFunction('OSSL_ECHSTORE_new');
  if not assigned(OSSL_ECHSTORE_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_new');
  Result := OSSL_ECHSTORE_new(libctx, propq);
end;

procedure Load_OSSL_ECHSTORE_free(es: POSSL_ECHSTORE); cdecl;
begin
  OSSL_ECHSTORE_free := LoadLibCryptoFunction('OSSL_ECHSTORE_free');
  if not assigned(OSSL_ECHSTORE_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_free');
  OSSL_ECHSTORE_free(es);
end;

function Load_OSSL_ECHSTORE_new_config(es: POSSL_ECHSTORE; echversion: TOpenSSL_C_UINT16; max_name_length: byte; public_name: PAnsiChar; suite: TOSSL_HPKE_SUITE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_new_config := LoadLibCryptoFunction('OSSL_ECHSTORE_new_config');
  if not assigned(OSSL_ECHSTORE_new_config) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_new_config');
  Result := OSSL_ECHSTORE_new_config(es, echversion, max_name_length, public_name, suite);
end;

function Load_OSSL_ECHSTORE_write_pem(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; out_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_write_pem := LoadLibCryptoFunction('OSSL_ECHSTORE_write_pem');
  if not assigned(OSSL_ECHSTORE_write_pem) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_write_pem');
  Result := OSSL_ECHSTORE_write_pem(es, index, out_);
end;

function Load_OSSL_ECHSTORE_read_echconfiglist(es: POSSL_ECHSTORE; in_: PBIO): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_read_echconfiglist := LoadLibCryptoFunction('OSSL_ECHSTORE_read_echconfiglist');
  if not assigned(OSSL_ECHSTORE_read_echconfiglist) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_read_echconfiglist');
  Result := OSSL_ECHSTORE_read_echconfiglist(es, in_);
end;

function Load_OSSL_ECHSTORE_get1_info(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT; loaded_secs: POpenSSL_C_TIMET; public_name: PPAnsiChar; echconfig: PPAnsiChar; has_private: POpenSSL_C_INT; for_retry: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_get1_info := LoadLibCryptoFunction('OSSL_ECHSTORE_get1_info');
  if not assigned(OSSL_ECHSTORE_get1_info) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_get1_info');
  Result := OSSL_ECHSTORE_get1_info(es, index, loaded_secs, public_name, echconfig, has_private, for_retry);
end;

function Load_OSSL_ECHSTORE_downselect(es: POSSL_ECHSTORE; index: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_downselect := LoadLibCryptoFunction('OSSL_ECHSTORE_downselect');
  if not assigned(OSSL_ECHSTORE_downselect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_downselect');
  Result := OSSL_ECHSTORE_downselect(es, index);
end;

function Load_OSSL_ECHSTORE_set1_key_and_read_pem(es: POSSL_ECHSTORE; priv: PEVP_PKEY; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_set1_key_and_read_pem := LoadLibCryptoFunction('OSSL_ECHSTORE_set1_key_and_read_pem');
  if not assigned(OSSL_ECHSTORE_set1_key_and_read_pem) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_set1_key_and_read_pem');
  Result := OSSL_ECHSTORE_set1_key_and_read_pem(es, priv, in_, for_retry);
end;

function Load_OSSL_ECHSTORE_read_pem(es: POSSL_ECHSTORE; in_: PBIO; for_retry: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_read_pem := LoadLibCryptoFunction('OSSL_ECHSTORE_read_pem');
  if not assigned(OSSL_ECHSTORE_read_pem) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_read_pem');
  Result := OSSL_ECHSTORE_read_pem(es, in_, for_retry);
end;

function Load_OSSL_ECHSTORE_num_entries(es: POSSL_ECHSTORE; numentries: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_num_entries := LoadLibCryptoFunction('OSSL_ECHSTORE_num_entries');
  if not assigned(OSSL_ECHSTORE_num_entries) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_num_entries');
  Result := OSSL_ECHSTORE_num_entries(es, numentries);
end;

function Load_OSSL_ECHSTORE_num_keys(es: POSSL_ECHSTORE; numkeys: POpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_num_keys := LoadLibCryptoFunction('OSSL_ECHSTORE_num_keys');
  if not assigned(OSSL_ECHSTORE_num_keys) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_num_keys');
  Result := OSSL_ECHSTORE_num_keys(es, numkeys);
end;

function Load_OSSL_ECHSTORE_flush_keys(es: POSSL_ECHSTORE; age: TOpenSSL_C_TIMET): TOpenSSL_C_INT; cdecl;
begin
  OSSL_ECHSTORE_flush_keys := LoadLibCryptoFunction('OSSL_ECHSTORE_flush_keys');
  if not assigned(OSSL_ECHSTORE_flush_keys) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_ECHSTORE_flush_keys');
  Result := OSSL_ECHSTORE_flush_keys(es, age);
end;

function Load_SSL_CTX_set1_echstore(ctx: PSSL_CTX; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_set1_echstore := LoadLibCryptoFunction('SSL_CTX_set1_echstore');
  if not assigned(SSL_CTX_set1_echstore) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_set1_echstore');
  Result := SSL_CTX_set1_echstore(ctx, es);
end;

function Load_SSL_set1_echstore(s: PSSL; es: POSSL_ECHSTORE): TOpenSSL_C_INT; cdecl;
begin
  SSL_set1_echstore := LoadLibCryptoFunction('SSL_set1_echstore');
  if not assigned(SSL_set1_echstore) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_echstore');
  Result := SSL_set1_echstore(s, es);
end;

function Load_SSL_CTX_get1_echstore(ctx: PSSL_CTX): POSSL_ECHSTORE; cdecl;
begin
  SSL_CTX_get1_echstore := LoadLibCryptoFunction('SSL_CTX_get1_echstore');
  if not assigned(SSL_CTX_get1_echstore) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_get1_echstore');
  Result := SSL_CTX_get1_echstore(ctx);
end;

function Load_SSL_get1_echstore(s: PSSL): POSSL_ECHSTORE; cdecl;
begin
  SSL_get1_echstore := LoadLibCryptoFunction('SSL_get1_echstore');
  if not assigned(SSL_get1_echstore) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_get1_echstore');
  Result := SSL_get1_echstore(s);
end;

function Load_SSL_ech_set1_server_names(s: PSSL; inner_name: PAnsiChar; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_ech_set1_server_names := LoadLibCryptoFunction('SSL_ech_set1_server_names');
  if not assigned(SSL_ech_set1_server_names) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_set1_server_names');
  Result := SSL_ech_set1_server_names(s, inner_name, outer_name, no_outer);
end;

function Load_SSL_ech_set1_outer_server_name(s: PSSL; outer_name: PAnsiChar; no_outer: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  SSL_ech_set1_outer_server_name := LoadLibCryptoFunction('SSL_ech_set1_outer_server_name');
  if not assigned(SSL_ech_set1_outer_server_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_set1_outer_server_name');
  Result := SSL_ech_set1_outer_server_name(s, outer_name, no_outer);
end;

function Load_SSL_ech_set1_outer_alpn_protos(s: PSSL; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_ech_set1_outer_alpn_protos := LoadLibCryptoFunction('SSL_ech_set1_outer_alpn_protos');
  if not assigned(SSL_ech_set1_outer_alpn_protos) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_set1_outer_alpn_protos');
  Result := SSL_ech_set1_outer_alpn_protos(s, protos, protos_len);
end;

function Load_SSL_ech_get1_status(s: PSSL; inner_sni: PPAnsiChar; outer_sni: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_ech_get1_status := LoadLibCryptoFunction('SSL_ech_get1_status');
  if not assigned(SSL_ech_get1_status) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_get1_status');
  Result := SSL_ech_get1_status(s, inner_sni, outer_sni);
end;

function Load_SSL_ech_set1_grease_suite(s: PSSL; suite: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  SSL_ech_set1_grease_suite := LoadLibCryptoFunction('SSL_ech_set1_grease_suite');
  if not assigned(SSL_ech_set1_grease_suite) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_set1_grease_suite');
  Result := SSL_ech_set1_grease_suite(s, suite);
end;

function Load_SSL_ech_set_grease_type(s: PSSL; type_: TOpenSSL_C_UINT16): TOpenSSL_C_INT; cdecl;
begin
  SSL_ech_set_grease_type := LoadLibCryptoFunction('SSL_ech_set_grease_type');
  if not assigned(SSL_ech_set_grease_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_set_grease_type');
  Result := SSL_ech_set_grease_type(s, type_);
end;

procedure Load_SSL_ech_set_callback(s: PSSL; f: TSSL_ech_cb_func); cdecl;
begin
  SSL_ech_set_callback := LoadLibCryptoFunction('SSL_ech_set_callback');
  if not assigned(SSL_ech_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_set_callback');
  SSL_ech_set_callback(s, f);
end;

function Load_SSL_ech_get1_retry_config(s: PSSL; ec: PPbyte; eclen: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_ech_get1_retry_config := LoadLibCryptoFunction('SSL_ech_get1_retry_config');
  if not assigned(SSL_ech_get1_retry_config) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_ech_get1_retry_config');
  Result := SSL_ech_get1_retry_config(s, ec, eclen);
end;

function Load_SSL_CTX_ech_set1_outer_alpn_protos(s: PSSL_CTX; protos: Pbyte; protos_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_CTX_ech_set1_outer_alpn_protos := LoadLibCryptoFunction('SSL_CTX_ech_set1_outer_alpn_protos');
  if not assigned(SSL_CTX_ech_set1_outer_alpn_protos) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_ech_set1_outer_alpn_protos');
  Result := SSL_CTX_ech_set1_outer_alpn_protos(s, protos, protos_len);
end;

procedure Load_SSL_CTX_ech_set_callback(ctx: PSSL_CTX; f: TSSL_ech_cb_func); cdecl;
begin
  SSL_CTX_ech_set_callback := LoadLibCryptoFunction('SSL_CTX_ech_set_callback');
  if not assigned(SSL_CTX_ech_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_CTX_ech_set_callback');
  SSL_CTX_ech_set_callback(ctx, f);
end;

function Load_SSL_set1_ech_config_list(ssl: PSSL; ecl: Pbyte; ecl_len: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  SSL_set1_ech_config_list := LoadLibCryptoFunction('SSL_set1_ech_config_list');
  if not assigned(SSL_set1_ech_config_list) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('SSL_set1_ech_config_list');
  Result := SSL_set1_ech_config_list(ssl, ecl, ecl_len);
end;

{$endif} { OPENSSL_NO_ECH}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_ECH}
  OSSL_ECHSTORE_new := Load_OSSL_ECHSTORE_new;
  OSSL_ECHSTORE_free := Load_OSSL_ECHSTORE_free;
  OSSL_ECHSTORE_new_config := Load_OSSL_ECHSTORE_new_config;
  OSSL_ECHSTORE_write_pem := Load_OSSL_ECHSTORE_write_pem;
  OSSL_ECHSTORE_read_echconfiglist := Load_OSSL_ECHSTORE_read_echconfiglist;
  OSSL_ECHSTORE_get1_info := Load_OSSL_ECHSTORE_get1_info;
  OSSL_ECHSTORE_downselect := Load_OSSL_ECHSTORE_downselect;
  OSSL_ECHSTORE_set1_key_and_read_pem := Load_OSSL_ECHSTORE_set1_key_and_read_pem;
  OSSL_ECHSTORE_read_pem := Load_OSSL_ECHSTORE_read_pem;
  OSSL_ECHSTORE_num_entries := Load_OSSL_ECHSTORE_num_entries;
  OSSL_ECHSTORE_num_keys := Load_OSSL_ECHSTORE_num_keys;
  OSSL_ECHSTORE_flush_keys := Load_OSSL_ECHSTORE_flush_keys;
  SSL_CTX_set1_echstore := Load_SSL_CTX_set1_echstore;
  SSL_set1_echstore := Load_SSL_set1_echstore;
  SSL_CTX_get1_echstore := Load_SSL_CTX_get1_echstore;
  SSL_get1_echstore := Load_SSL_get1_echstore;
  SSL_ech_set1_server_names := Load_SSL_ech_set1_server_names;
  SSL_ech_set1_outer_server_name := Load_SSL_ech_set1_outer_server_name;
  SSL_ech_set1_outer_alpn_protos := Load_SSL_ech_set1_outer_alpn_protos;
  SSL_ech_get1_status := Load_SSL_ech_get1_status;
  SSL_ech_set1_grease_suite := Load_SSL_ech_set1_grease_suite;
  SSL_ech_set_grease_type := Load_SSL_ech_set_grease_type;
  SSL_ech_set_callback := Load_SSL_ech_set_callback;
  SSL_ech_get1_retry_config := Load_SSL_ech_get1_retry_config;
  SSL_CTX_ech_set1_outer_alpn_protos := Load_SSL_CTX_ech_set1_outer_alpn_protos;
  SSL_CTX_ech_set_callback := Load_SSL_CTX_ech_set_callback;
  SSL_set1_ech_config_list := Load_SSL_set1_ech_config_list;
{$endif} { OPENSSL_NO_ECH}
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



