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

unit openssl_http;

{
  Generated from OpenSSL 3.0.20 Header File http.h - Tue 19 May 14:16:08 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_http.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_bio,openssl_asn1,openssl_conf;


{* Copyright 2000-2021 The OpenSSL Project Authors. All Rights Reserved.
* Copyright Siemens AG 2018-2020
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_HTTP_H}
  {$define OPENSSL_HTTP_H}
  {$include openssl_opensslconf.inc}

const
  OSSL_HTTP_NAME = 'http';
  OSSL_HTTPS_NAME = 'https';
  OSSL_HTTP_PREFIX = OSSL_HTTP_NAME + '://';
  OSSL_HTTPS_PREFIX = OSSL_HTTPS_NAME + '://';
  OSSL_HTTP_PORT = '80';
  OSSL_HTTPS_PORT = '443';
  OPENSSL_NO_PROXY = 'NO_PROXY';
  OPENSSL_HTTP_PROXY = 'HTTP_PROXY';
  OPENSSL_HTTPS_PROXY = 'HTTPS_PROXY';
  OSSL_HTTP_DEFAULT_MAX_LINE_LEN = 4*1024;
  OSSL_HTTP_DEFAULT_MAX_RESP_LEN = 100*1024;
  OSSL_HTTP_DEFAULT_MAX_CRL_LEN = (32*1024)*1024;


  { Low-level HTTP API }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_HTTP_REQ_CTX_new(wbio: PBIO; rbio: PBIO; buf_size: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_new';
  procedure OSSL_HTTP_REQ_CTX_free(rctx: POSSL_HTTP_REQ_CTX); cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_free';
  function OSSL_HTTP_REQ_CTX_set_request_line(rctx: POSSL_HTTP_REQ_CTX; method_POST: TOpenSSL_C_INT; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set_request_line';
  function OSSL_HTTP_REQ_CTX_add1_header(rctx: POSSL_HTTP_REQ_CTX; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_add1_header';
  function OSSL_HTTP_REQ_CTX_set_expected(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; asn1: TOpenSSL_C_INT; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set_expected';
  function OSSL_HTTP_REQ_CTX_set1_req(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set1_req';
  function OSSL_HTTP_REQ_CTX_nbio(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_nbio';
  function OSSL_HTTP_REQ_CTX_nbio_d2i(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_nbio_d2i';
  function OSSL_HTTP_REQ_CTX_exchange(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_exchange';
  function OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_get0_mem_bio';
  function OSSL_HTTP_REQ_CTX_get_resp_len(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_SIZET; cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_get_resp_len';
  procedure OSSL_HTTP_REQ_CTX_set_max_response_length(rctx: POSSL_HTTP_REQ_CTX; len: TOpenSSL_C_UINT); cdecl; external CLibCrypto name 'OSSL_HTTP_REQ_CTX_set_max_response_length';
  function OSSL_HTTP_is_alive(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_is_alive';
  { High-level HTTP API }
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_new}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_free}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set_request_line}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_add1_header}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set_expected}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set1_req}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_nbio}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_nbio_d2i}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_exchange}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_get0_mem_bio}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_get_resp_len}
  {$EXTERNALSYM OSSL_HTTP_REQ_CTX_set_max_response_length}
  {$EXTERNALSYM OSSL_HTTP_is_alive}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_HTTP_REQ_CTX_new(wbio: PBIO; rbio: PBIO; buf_size: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl;
  procedure Load_OSSL_HTTP_REQ_CTX_free(rctx: POSSL_HTTP_REQ_CTX); cdecl;
  function Load_OSSL_HTTP_REQ_CTX_set_request_line(rctx: POSSL_HTTP_REQ_CTX; method_POST: TOpenSSL_C_INT; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_add1_header(rctx: POSSL_HTTP_REQ_CTX; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_set_expected(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; asn1: TOpenSSL_C_INT; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_set1_req(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_nbio(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_nbio_d2i(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_exchange(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl;
  function Load_OSSL_HTTP_REQ_CTX_get_resp_len(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_SIZET; cdecl;
  procedure Load_OSSL_HTTP_REQ_CTX_set_max_response_length(rctx: POSSL_HTTP_REQ_CTX; len: TOpenSSL_C_UINT); cdecl;
  function Load_OSSL_HTTP_is_alive(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl;

var
  OSSL_HTTP_REQ_CTX_new: function(wbio: PBIO; rbio: PBIO; buf_size: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl = Load_OSSL_HTTP_REQ_CTX_new;
  OSSL_HTTP_REQ_CTX_free: procedure(rctx: POSSL_HTTP_REQ_CTX); cdecl = Load_OSSL_HTTP_REQ_CTX_free;
  OSSL_HTTP_REQ_CTX_set_request_line: function(rctx: POSSL_HTTP_REQ_CTX; method_POST: TOpenSSL_C_INT; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_REQ_CTX_set_request_line;
  OSSL_HTTP_REQ_CTX_add1_header: function(rctx: POSSL_HTTP_REQ_CTX; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_REQ_CTX_add1_header;
  OSSL_HTTP_REQ_CTX_set_expected: function(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; asn1: TOpenSSL_C_INT; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_REQ_CTX_set_expected;
  OSSL_HTTP_REQ_CTX_set1_req: function(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_REQ_CTX_set1_req;
  OSSL_HTTP_REQ_CTX_nbio: function(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_REQ_CTX_nbio;
  OSSL_HTTP_REQ_CTX_nbio_d2i: function(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_REQ_CTX_nbio_d2i;
  OSSL_HTTP_REQ_CTX_exchange: function(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl = Load_OSSL_HTTP_REQ_CTX_exchange;
  OSSL_HTTP_REQ_CTX_get0_mem_bio: function(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl = Load_OSSL_HTTP_REQ_CTX_get0_mem_bio;
  OSSL_HTTP_REQ_CTX_get_resp_len: function(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_SIZET; cdecl = Load_OSSL_HTTP_REQ_CTX_get_resp_len;
  OSSL_HTTP_REQ_CTX_set_max_response_length: procedure(rctx: POSSL_HTTP_REQ_CTX; len: TOpenSSL_C_UINT); cdecl = Load_OSSL_HTTP_REQ_CTX_set_max_response_length;
  OSSL_HTTP_is_alive: function(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_is_alive;
  { High-level HTTP API }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  POSSL_HTTP_bio_cb_t = ^TOSSL_HTTP_bio_cb_t;
  PPOSSL_HTTP_bio_cb_t = ^POSSL_HTTP_bio_cb_t;
  {end of auto-generated forward references}

  TOSSL_HTTP_bio_cb_t = function(bio: PBIO; arg: pointer; connect: TOpenSSL_C_INT; detail: TOpenSSL_C_INT): PBIO; cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_HTTP_open(server: PAnsiChar; port: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; use_ssl: TOpenSSL_C_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; overall_timeout: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl; external CLibCrypto name 'OSSL_HTTP_open';
  function OSSL_HTTP_proxy_connect(bio: PBIO; server: PAnsiChar; port: PAnsiChar; proxyuser: PAnsiChar; proxypass: PAnsiChar; timeout: TOpenSSL_C_INT; bio_err: PBIO; prog: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_proxy_connect';
  function OSSL_HTTP_set1_request(rctx: POSSL_HTTP_REQ_CTX; path: PAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_set1_request';
  function OSSL_HTTP_exchange(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPAnsiChar): PBIO; cdecl; external CLibCrypto name 'OSSL_HTTP_exchange';
  function OSSL_HTTP_get(url: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto name 'OSSL_HTTP_get';
  function OSSL_HTTP_transfer(prctx: PPOSSL_HTTP_REQ_CTX; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar; use_ssl: TOpenSSL_C_INT; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto name 'OSSL_HTTP_transfer';
  function OSSL_HTTP_close(rctx: POSSL_HTTP_REQ_CTX; ok: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_close';
  { Auxiliary functions }
  function OSSL_parse_url(url: PAnsiChar; pscheme: PPAnsiChar; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_parse_url';
  function OSSL_HTTP_parse_url(url: PAnsiChar; pssl: POpenSSL_C_INT; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_HTTP_parse_url';
  function OSSL_HTTP_adapt_proxy(proxy: PAnsiChar; no_proxy: PAnsiChar; server: PAnsiChar; use_ssl: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_HTTP_adapt_proxy';
  {$else}
  {$EXTERNALSYM OSSL_HTTP_open}
  {$EXTERNALSYM OSSL_HTTP_proxy_connect}
  {$EXTERNALSYM OSSL_HTTP_set1_request}
  {$EXTERNALSYM OSSL_HTTP_exchange}
  {$EXTERNALSYM OSSL_HTTP_get}
  {$EXTERNALSYM OSSL_HTTP_transfer}
  {$EXTERNALSYM OSSL_HTTP_close}
  {$EXTERNALSYM OSSL_parse_url}
  {$EXTERNALSYM OSSL_HTTP_parse_url}
  {$EXTERNALSYM OSSL_HTTP_adapt_proxy}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_HTTP_open(server: PAnsiChar; port: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; use_ssl: TOpenSSL_C_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; overall_timeout: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl;
  function Load_OSSL_HTTP_proxy_connect(bio: PBIO; server: PAnsiChar; port: PAnsiChar; proxyuser: PAnsiChar; proxypass: PAnsiChar; timeout: TOpenSSL_C_INT; bio_err: PBIO; prog: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_set1_request(rctx: POSSL_HTTP_REQ_CTX; path: PAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_exchange(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPAnsiChar): PBIO; cdecl;
  function Load_OSSL_HTTP_get(url: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT): PBIO; cdecl;
  function Load_OSSL_HTTP_transfer(prctx: PPOSSL_HTTP_REQ_CTX; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar; use_ssl: TOpenSSL_C_INT; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): PBIO; cdecl;
  function Load_OSSL_HTTP_close(rctx: POSSL_HTTP_REQ_CTX; ok: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_parse_url(url: PAnsiChar; pscheme: PPAnsiChar; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_parse_url(url: PAnsiChar; pssl: POpenSSL_C_INT; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_HTTP_adapt_proxy(proxy: PAnsiChar; no_proxy: PAnsiChar; server: PAnsiChar; use_ssl: TOpenSSL_C_INT): PAnsiChar; cdecl;

var
  OSSL_HTTP_open: function(server: PAnsiChar; port: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; use_ssl: TOpenSSL_C_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; overall_timeout: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl = Load_OSSL_HTTP_open;
  OSSL_HTTP_proxy_connect: function(bio: PBIO; server: PAnsiChar; port: PAnsiChar; proxyuser: PAnsiChar; proxypass: PAnsiChar; timeout: TOpenSSL_C_INT; bio_err: PBIO; prog: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_proxy_connect;
  OSSL_HTTP_set1_request: function(rctx: POSSL_HTTP_REQ_CTX; path: PAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_set1_request;
  OSSL_HTTP_exchange: function(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPAnsiChar): PBIO; cdecl = Load_OSSL_HTTP_exchange;
  OSSL_HTTP_get: function(url: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT): PBIO; cdecl = Load_OSSL_HTTP_get;
  OSSL_HTTP_transfer: function(prctx: PPOSSL_HTTP_REQ_CTX; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar; use_ssl: TOpenSSL_C_INT; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): PBIO; cdecl = Load_OSSL_HTTP_transfer;
  OSSL_HTTP_close: function(rctx: POSSL_HTTP_REQ_CTX; ok: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_close;
  { Auxiliary functions }
  OSSL_parse_url: function(url: PAnsiChar; pscheme: PPAnsiChar; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_parse_url;
  OSSL_HTTP_parse_url: function(url: PAnsiChar; pssl: POpenSSL_C_INT; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_HTTP_parse_url;
  OSSL_HTTP_adapt_proxy: function(proxy: PAnsiChar; no_proxy: PAnsiChar; server: PAnsiChar; use_ssl: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OSSL_HTTP_adapt_proxy;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
{$endif}
{ !defined(OPENSSL_HTTP_H) }

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
function Load_OSSL_HTTP_REQ_CTX_new(wbio: PBIO; rbio: PBIO; buf_size: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl;
begin
  OSSL_HTTP_REQ_CTX_new := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_new');
  if not assigned(OSSL_HTTP_REQ_CTX_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_new');
  Result := OSSL_HTTP_REQ_CTX_new(wbio, rbio, buf_size);
end;

procedure Load_OSSL_HTTP_REQ_CTX_free(rctx: POSSL_HTTP_REQ_CTX); cdecl;
begin
  OSSL_HTTP_REQ_CTX_free := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_free');
  if not assigned(OSSL_HTTP_REQ_CTX_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_free');
  OSSL_HTTP_REQ_CTX_free(rctx);
end;

function Load_OSSL_HTTP_REQ_CTX_set_request_line(rctx: POSSL_HTTP_REQ_CTX; method_POST: TOpenSSL_C_INT; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_REQ_CTX_set_request_line := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_set_request_line');
  if not assigned(OSSL_HTTP_REQ_CTX_set_request_line) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_set_request_line');
  Result := OSSL_HTTP_REQ_CTX_set_request_line(rctx, method_POST, server, port, path);
end;

function Load_OSSL_HTTP_REQ_CTX_add1_header(rctx: POSSL_HTTP_REQ_CTX; name: PAnsiChar; value: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_REQ_CTX_add1_header := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_add1_header');
  if not assigned(OSSL_HTTP_REQ_CTX_add1_header) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_add1_header');
  Result := OSSL_HTTP_REQ_CTX_add1_header(rctx, name, value);
end;

function Load_OSSL_HTTP_REQ_CTX_set_expected(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; asn1: TOpenSSL_C_INT; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_REQ_CTX_set_expected := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_set_expected');
  if not assigned(OSSL_HTTP_REQ_CTX_set_expected) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_set_expected');
  Result := OSSL_HTTP_REQ_CTX_set_expected(rctx, content_type, asn1, timeout, keep_alive);
end;

function Load_OSSL_HTTP_REQ_CTX_set1_req(rctx: POSSL_HTTP_REQ_CTX; content_type: PAnsiChar; it: PASN1_ITEM; req: PASN1_VALUE): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_REQ_CTX_set1_req := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_set1_req');
  if not assigned(OSSL_HTTP_REQ_CTX_set1_req) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_set1_req');
  Result := OSSL_HTTP_REQ_CTX_set1_req(rctx, content_type, it, req);
end;

function Load_OSSL_HTTP_REQ_CTX_nbio(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_REQ_CTX_nbio := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_nbio');
  if not assigned(OSSL_HTTP_REQ_CTX_nbio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_nbio');
  Result := OSSL_HTTP_REQ_CTX_nbio(rctx);
end;

function Load_OSSL_HTTP_REQ_CTX_nbio_d2i(rctx: POSSL_HTTP_REQ_CTX; pval: PPASN1_VALUE; it: PASN1_ITEM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_REQ_CTX_nbio_d2i := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_nbio_d2i');
  if not assigned(OSSL_HTTP_REQ_CTX_nbio_d2i) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_nbio_d2i');
  Result := OSSL_HTTP_REQ_CTX_nbio_d2i(rctx, pval, it);
end;

function Load_OSSL_HTTP_REQ_CTX_exchange(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl;
begin
  OSSL_HTTP_REQ_CTX_exchange := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_exchange');
  if not assigned(OSSL_HTTP_REQ_CTX_exchange) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_exchange');
  Result := OSSL_HTTP_REQ_CTX_exchange(rctx);
end;

function Load_OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx: POSSL_HTTP_REQ_CTX): PBIO; cdecl;
begin
  OSSL_HTTP_REQ_CTX_get0_mem_bio := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_get0_mem_bio');
  if not assigned(OSSL_HTTP_REQ_CTX_get0_mem_bio) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_get0_mem_bio');
  Result := OSSL_HTTP_REQ_CTX_get0_mem_bio(rctx);
end;

function Load_OSSL_HTTP_REQ_CTX_get_resp_len(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_SIZET; cdecl;
begin
  OSSL_HTTP_REQ_CTX_get_resp_len := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_get_resp_len');
  if not assigned(OSSL_HTTP_REQ_CTX_get_resp_len) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_get_resp_len');
  Result := OSSL_HTTP_REQ_CTX_get_resp_len(rctx);
end;

procedure Load_OSSL_HTTP_REQ_CTX_set_max_response_length(rctx: POSSL_HTTP_REQ_CTX; len: TOpenSSL_C_UINT); cdecl;
begin
  OSSL_HTTP_REQ_CTX_set_max_response_length := LoadLibCryptoFunction('OSSL_HTTP_REQ_CTX_set_max_response_length');
  if not assigned(OSSL_HTTP_REQ_CTX_set_max_response_length) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_REQ_CTX_set_max_response_length');
  OSSL_HTTP_REQ_CTX_set_max_response_length(rctx, len);
end;

function Load_OSSL_HTTP_is_alive(rctx: POSSL_HTTP_REQ_CTX): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_is_alive := LoadLibCryptoFunction('OSSL_HTTP_is_alive');
  if not assigned(OSSL_HTTP_is_alive) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_is_alive');
  Result := OSSL_HTTP_is_alive(rctx);
end;

function Load_OSSL_HTTP_open(server: PAnsiChar; port: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; use_ssl: TOpenSSL_C_INT; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; overall_timeout: TOpenSSL_C_INT): POSSL_HTTP_REQ_CTX; cdecl;
begin
  OSSL_HTTP_open := LoadLibCryptoFunction('OSSL_HTTP_open');
  if not assigned(OSSL_HTTP_open) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_open');
  Result := OSSL_HTTP_open(server, port, proxy, no_proxy, use_ssl, bio, rbio, bio_update_fn, arg, buf_size, overall_timeout);
end;

function Load_OSSL_HTTP_proxy_connect(bio: PBIO; server: PAnsiChar; port: PAnsiChar; proxyuser: PAnsiChar; proxypass: PAnsiChar; timeout: TOpenSSL_C_INT; bio_err: PBIO; prog: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_proxy_connect := LoadLibCryptoFunction('OSSL_HTTP_proxy_connect');
  if not assigned(OSSL_HTTP_proxy_connect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_proxy_connect');
  Result := OSSL_HTTP_proxy_connect(bio, server, port, proxyuser, proxypass, timeout, bio_err, prog);
end;

function Load_OSSL_HTTP_set1_request(rctx: POSSL_HTTP_REQ_CTX; path: PAnsiChar; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_set1_request := LoadLibCryptoFunction('OSSL_HTTP_set1_request');
  if not assigned(OSSL_HTTP_set1_request) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_set1_request');
  Result := OSSL_HTTP_set1_request(rctx, path, headers, content_type, req, expected_content_type, expect_asn1, max_resp_len, timeout, keep_alive);
end;

function Load_OSSL_HTTP_exchange(rctx: POSSL_HTTP_REQ_CTX; redirection_url: PPAnsiChar): PBIO; cdecl;
begin
  OSSL_HTTP_exchange := LoadLibCryptoFunction('OSSL_HTTP_exchange');
  if not assigned(OSSL_HTTP_exchange) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_exchange');
  Result := OSSL_HTTP_exchange(rctx, redirection_url);
end;

function Load_OSSL_HTTP_get(url: PAnsiChar; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT): PBIO; cdecl;
begin
  OSSL_HTTP_get := LoadLibCryptoFunction('OSSL_HTTP_get');
  if not assigned(OSSL_HTTP_get) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_get');
  Result := OSSL_HTTP_get(url, proxy, no_proxy, bio, rbio, bio_update_fn, arg, buf_size, headers, expected_content_type, expect_asn1, max_resp_len, timeout);
end;

function Load_OSSL_HTTP_transfer(prctx: PPOSSL_HTTP_REQ_CTX; server: PAnsiChar; port: PAnsiChar; path: PAnsiChar; use_ssl: TOpenSSL_C_INT; proxy: PAnsiChar; no_proxy: PAnsiChar; bio: PBIO; rbio: PBIO; bio_update_fn: TOSSL_HTTP_bio_cb_t; arg: pointer; buf_size: TOpenSSL_C_INT; headers: Pstack_st_CONF_VALUE; content_type: PAnsiChar; req: PBIO; expected_content_type: PAnsiChar; expect_asn1: TOpenSSL_C_INT; max_resp_len: TOpenSSL_C_SIZET; timeout: TOpenSSL_C_INT; keep_alive: TOpenSSL_C_INT): PBIO; cdecl;
begin
  OSSL_HTTP_transfer := LoadLibCryptoFunction('OSSL_HTTP_transfer');
  if not assigned(OSSL_HTTP_transfer) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_transfer');
  Result := OSSL_HTTP_transfer(prctx, server, port, path, use_ssl, proxy, no_proxy, bio, rbio, bio_update_fn, arg, buf_size, headers, content_type, req, expected_content_type, expect_asn1, max_resp_len, timeout, keep_alive);
end;

function Load_OSSL_HTTP_close(rctx: POSSL_HTTP_REQ_CTX; ok: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_close := LoadLibCryptoFunction('OSSL_HTTP_close');
  if not assigned(OSSL_HTTP_close) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_close');
  Result := OSSL_HTTP_close(rctx, ok);
end;

function Load_OSSL_parse_url(url: PAnsiChar; pscheme: PPAnsiChar; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_parse_url := LoadLibCryptoFunction('OSSL_parse_url');
  if not assigned(OSSL_parse_url) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_parse_url');
  Result := OSSL_parse_url(url, pscheme, puser, phost, pport, pport_num, ppath, pquery, pfrag);
end;

function Load_OSSL_HTTP_parse_url(url: PAnsiChar; pssl: POpenSSL_C_INT; puser: PPAnsiChar; phost: PPAnsiChar; pport: PPAnsiChar; pport_num: POpenSSL_C_INT; ppath: PPAnsiChar; pquery: PPAnsiChar; pfrag: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_HTTP_parse_url := LoadLibCryptoFunction('OSSL_HTTP_parse_url');
  if not assigned(OSSL_HTTP_parse_url) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_parse_url');
  Result := OSSL_HTTP_parse_url(url, pssl, puser, phost, pport, pport_num, ppath, pquery, pfrag);
end;

function Load_OSSL_HTTP_adapt_proxy(proxy: PAnsiChar; no_proxy: PAnsiChar; server: PAnsiChar; use_ssl: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OSSL_HTTP_adapt_proxy := LoadLibCryptoFunction('OSSL_HTTP_adapt_proxy');
  if not assigned(OSSL_HTTP_adapt_proxy) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_HTTP_adapt_proxy');
  Result := OSSL_HTTP_adapt_proxy(proxy, no_proxy, server, use_ssl);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_HTTP_REQ_CTX_new := Load_OSSL_HTTP_REQ_CTX_new;
  OSSL_HTTP_REQ_CTX_free := Load_OSSL_HTTP_REQ_CTX_free;
  OSSL_HTTP_REQ_CTX_set_request_line := Load_OSSL_HTTP_REQ_CTX_set_request_line;
  OSSL_HTTP_REQ_CTX_add1_header := Load_OSSL_HTTP_REQ_CTX_add1_header;
  OSSL_HTTP_REQ_CTX_set_expected := Load_OSSL_HTTP_REQ_CTX_set_expected;
  OSSL_HTTP_REQ_CTX_set1_req := Load_OSSL_HTTP_REQ_CTX_set1_req;
  OSSL_HTTP_REQ_CTX_nbio := Load_OSSL_HTTP_REQ_CTX_nbio;
  OSSL_HTTP_REQ_CTX_nbio_d2i := Load_OSSL_HTTP_REQ_CTX_nbio_d2i;
  OSSL_HTTP_REQ_CTX_exchange := Load_OSSL_HTTP_REQ_CTX_exchange;
  OSSL_HTTP_REQ_CTX_get0_mem_bio := Load_OSSL_HTTP_REQ_CTX_get0_mem_bio;
  OSSL_HTTP_REQ_CTX_get_resp_len := Load_OSSL_HTTP_REQ_CTX_get_resp_len;
  OSSL_HTTP_REQ_CTX_set_max_response_length := Load_OSSL_HTTP_REQ_CTX_set_max_response_length;
  OSSL_HTTP_is_alive := Load_OSSL_HTTP_is_alive;
  OSSL_HTTP_open := Load_OSSL_HTTP_open;
  OSSL_HTTP_proxy_connect := Load_OSSL_HTTP_proxy_connect;
  OSSL_HTTP_set1_request := Load_OSSL_HTTP_set1_request;
  OSSL_HTTP_exchange := Load_OSSL_HTTP_exchange;
  OSSL_HTTP_get := Load_OSSL_HTTP_get;
  OSSL_HTTP_transfer := Load_OSSL_HTTP_transfer;
  OSSL_HTTP_close := Load_OSSL_HTTP_close;
  OSSL_parse_url := Load_OSSL_parse_url;
  OSSL_HTTP_parse_url := Load_OSSL_HTTP_parse_url;
  OSSL_HTTP_adapt_proxy := Load_OSSL_HTTP_adapt_proxy;
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



