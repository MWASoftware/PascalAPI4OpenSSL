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
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}

type
 _PX509_LOOKUP_METHOD      = ^_X509_LOOKUP_METHOD;
 _X509_LOOKUP_METHOD = record
    name : PAnsiChar;
    new_item : function (ctx : PX509_LOOKUP): TOpenSSL_C_INT; cdecl;
    free : procedure (ctx : PX509_LOOKUP); cdecl;
    init : function(ctx : PX509_LOOKUP) : TOpenSSL_C_INT; cdecl;
    shutdown : function(ctx : PX509_LOOKUP) : TOpenSSL_C_INT; cdecl;
    ctrl: function(ctx : PX509_LOOKUP; cmd : TOpenSSL_C_INT; const argc : PAnsiChar; argl : TOpenSSL_C_LONG; out ret : PAnsiChar ) : TOpenSSL_C_INT; cdecl;
    get_by_subject: function(ctx : PX509_LOOKUP; _type : TOpenSSL_C_INT; name : PX509_NAME; ret : PX509_OBJECT ) : TOpenSSL_C_INT; cdecl;
    get_by_issuer_serial : function(ctx : PX509_LOOKUP; _type : TOpenSSL_C_INT; name : PX509_NAME; serial : PASN1_INTEGER; ret : PX509_OBJECT) : TOpenSSL_C_INT; cdecl;
    get_by_fingerprint : function (ctx : PX509_LOOKUP; _type : TOpenSSL_C_INT; bytes : PAnsiChar; len : TOpenSSL_C_INT; ret : PX509_OBJECT): TOpenSSL_C_INT; cdecl;
    get_by_alias : function(ctx : PX509_LOOKUP; _type : TOpenSSL_C_INT; str : PAnsiChar; ret : PX509_OBJECT) : TOpenSSL_C_INT; cdecl;
  end;

const
  OpenSSL_x509_unicode_file_lookup: _X509_LOOKUP_METHOD =
    (
    name: 'Load file into cache';
    new_item: nil; // * new */
    free: nil; // * free */
    init: nil; // * init */
    shutdown: nil; // * shutdown */
    ctrl: nil; // * ctrl */
    get_by_subject: nil; // * get_by_subject */
    get_by_issuer_serial: nil; // * get_by_issuer_serial */
    get_by_fingerprint: nil; // * get_by_fingerprint */
    get_by_alias: nil // * get_by_alias */
    );

function LEGACY_X509_LOOKUP_meth_new(const name: PAnsiChar): PX509_LOOKUP_METHOD;
begin
  Result := @OpenSSL_x509_unicode_file_lookup;
end;

procedure LEGACY_X509_LOOKUP_meth_free(method: PX509_LOOKUP_METHOD);
begin
  //Do nothing
end;

function LEGACY_X509_LOOKUP_meth_set_ctrl(method: PX509_LOOKUP_METHOD; ctrl_fn: TX509_LOOKUP_ctrl_fn): TOpenSSL_C_INT;
begin
  _PX509_LOOKUP_METHOD(method)^.ctrl := @ctrl_fn;
  Result := 1;
end;
(*
struct x509_lookup_st {
    int init;                   /* have we been started */
    int skip;                   /* don't use us. */
    X509_LOOKUP_METHOD *method; /* the functions */
    char *method_data;          /* method data */
    X509_STORE *store_ctx;      /* who owns us */
} /* X509_LOOKUP */ ;
*)

type
  _PX509_LOOKUP = ^_X509_LOOKUP;
  _X509_LOOKUP = record
    init: TOpenSSL_C_INT;
    skip: TOpenSSL_C_INT;
    method: PX509_LOOKUP_METHOD;
    method_data: PAnsiChar;
    store_ctx: PX509_STORE;
  end;

function LEGACY_X509_LOOKUP_get_store(const ctx: PX509_LOOKUP): PX509_STORE;
begin
  Result := _PX509_LOOKUP(ctx)^.store_ctx;
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
