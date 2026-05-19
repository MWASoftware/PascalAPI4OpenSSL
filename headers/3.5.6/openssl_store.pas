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

unit openssl_store;

{
  Generated from OpenSSL 3.5.6 Header File store.h - Tue 19 May 14:28:30 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_store.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_pem,openssl_storeerr;


{* Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_STORE_H}
  {$define OPENSSL_STORE_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_OSSL_STORE_H}
  {$endif}

type
  {Auto-generated forward references}
  Possl_store_ctx_st = ^TOSSL_STORE_CTX;
  PPossl_store_ctx_st = ^Possl_store_ctx_st;
  POSSL_STORE_CTX = ^TOSSL_STORE_CTX;
  PPOSSL_STORE_CTX = ^POSSL_STORE_CTX;
  POSSL_STORE_post_process_info_fn = ^TOSSL_STORE_post_process_info_fn;
  PPOSSL_STORE_post_process_info_fn = ^POSSL_STORE_post_process_info_fn;
  {end of auto-generated forward references}

  {-
  *  The main OSSL_STORE functions.
  *  ------------------------------
  *
  *  These allow applications to open a channel to a resource with supported
  *  data (keys, certs, crls, ...), read the data a piece at a time and decide
  *  what to do with it, and finally close.
  }
  Tossl_store_ctx_st = record end;
  TOSSL_STORE_CTX = Tossl_store_ctx_st;
  
  {* Typedef for the OSSL_STORE_INFO post processing callback.  This can be used
  * to massage the given OSSL_STORE_INFO, or to drop it entirely (by returning
  * NULL).
  }
  TOSSL_STORE_post_process_info_fn = function(_param1: POSSL_STORE_INFO; _param2: pointer): POSSL_STORE_INFO; cdecl;


  
  {* Open a channel given a URI.  The given UI method will be used any time the
  * loader needs extra input, for example when a password or pin is needed, and
  * will be passed the same user data every time it's needed in this context.
  *
  * Returns a context reference which represents the channel to communicate
  * through.
  }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_open(uri: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl; external CLibCrypto name 'OSSL_STORE_open';
  function OSSL_STORE_open_ex(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl; external CLibCrypto name 'OSSL_STORE_open_ex';
  
  {* Control / fine tune the OSSL_STORE channel.  |cmd| determines what is to be
  * done, and depends on the underlying loader (use OSSL_STORE_get0_scheme to
  * determine which loader is used), except for common commands (see below).
  * Each command takes different arguments.
  }
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_STORE_open}
  {$EXTERNALSYM OSSL_STORE_open_ex}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_open(uri: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl;
  function Load_OSSL_STORE_open_ex(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl;

var
  OSSL_STORE_open: function(uri: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl = Load_OSSL_STORE_open;
  OSSL_STORE_open_ex: function(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl = Load_OSSL_STORE_open_ex;
  
  {* Control / fine tune the OSSL_STORE channel.  |cmd| determines what is to be
  * done, and depends on the underlying loader (use OSSL_STORE_get0_scheme to
  * determine which loader is used), except for common commands (see below).
  * Each command takes different arguments.
  }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    { args }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_ctrl(ctx: POSSL_STORE_CTX; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl varargs; external CLibCrypto name 'OSSL_STORE_ctrl'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_vctrl(ctx: POSSL_STORE_CTX; cmd: TOpenSSL_C_INT; args: array of const): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_vctrl'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM OSSL_STORE_ctrl}
  {$EXTERNALSYM OSSL_STORE_vctrl}

var
  OSSL_STORE_ctrl: function(ctx: POSSL_STORE_CTX; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl varargs = nil;
  OSSL_STORE_vctrl: function(ctx: POSSL_STORE_CTX; cmd: TOpenSSL_C_INT; args: array of const): TOpenSSL_C_INT; cdecl = nil;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

const
    
    {* Common ctrl commands that different loaders may choose to support.
    }
    { int on = 0 or 1; STORE_ctrl(ctx, STORE_C_USE_SECMEM, &on); }
  OSSL_STORE_C_USE_SECMEM = 1;
    { Where custom commands start }
  OSSL_STORE_C_CUSTOM_START = 100;
  {$endif}


  
  {* Read one data item (a key, a cert, a CRL) that is supported by the OSSL_STORE
  * functionality, given a context.
  * Returns a OSSL_STORE_INFO pointer, from which OpenSSL typed data can be
  * extracted with OSSL_STORE_INFO_get0_PKEY(), OSSL_STORE_INFO_get0_CERT(), ...
  * NULL is returned on error, which may include that the data found at the URI
  * can't be figured out for certain or is ambiguous.
  }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_load(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_load';
  
  {* Deletes the object in the store by URI.
  * Returns 1 on success, 0 otherwise.
  }
  function OSSL_STORE_delete(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_delete';
  
  {* Check if end of data (end of file) is reached
  * Returns 1 on end, 0 otherwise.
  }
  function OSSL_STORE_eof(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_eof';
  
  {* Check if an error occurred
  * Returns 1 if it did, 0 otherwise.
  }
  function OSSL_STORE_error(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_error';
  
  {* Close the channel
  * Returns 1 on success, 0 on error.
  }
  function OSSL_STORE_close(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_close';
  
  {* Attach to a BIO.  This works like OSSL_STORE_open() except it takes a
  * BIO instead of a uri, along with a scheme to use when reading.
  * The given UI method will be used any time the loader needs extra input,
  * for example when a password or pin is needed, and will be passed the
  * same user data every time it's needed in this context.
  *
  * Returns a context reference which represents the channel to communicate
  * through.
  *
  * Note that this function is considered unsafe, all depending on what the
  * BIO actually reads.
  }
  function OSSL_STORE_attach(bio: PBIO; scheme: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl; external CLibCrypto name 'OSSL_STORE_attach';
  {-
  *  Extracting OpenSSL types from and creating new OSSL_STORE_INFOs
  *  ---------------------------------------------------------------
  }
  
  {* Types of data that can be ossl_stored in a OSSL_STORE_INFO.
  * OSSL_STORE_INFO_NAME is typically found when getting a listing of
  * available "files" / "tokens" / what have you.
  }
  {$else}
  {$EXTERNALSYM OSSL_STORE_load}
  {$EXTERNALSYM OSSL_STORE_delete}
  {$EXTERNALSYM OSSL_STORE_eof}
  {$EXTERNALSYM OSSL_STORE_error}
  {$EXTERNALSYM OSSL_STORE_close}
  {$EXTERNALSYM OSSL_STORE_attach}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_load(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_delete(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_eof(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_error(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_close(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_attach(bio: PBIO; scheme: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl;

var
  OSSL_STORE_load: function(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_load;
  
  {* Deletes the object in the store by URI.
  * Returns 1 on success, 0 otherwise.
  }
  OSSL_STORE_delete: function(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_delete;
  
  {* Check if end of data (end of file) is reached
  * Returns 1 on end, 0 otherwise.
  }
  OSSL_STORE_eof: function(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_eof;
  
  {* Check if an error occurred
  * Returns 1 if it did, 0 otherwise.
  }
  OSSL_STORE_error: function(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_error;
  
  {* Close the channel
  * Returns 1 on success, 0 on error.
  }
  OSSL_STORE_close: function(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_close;
  
  {* Attach to a BIO.  This works like OSSL_STORE_open() except it takes a
  * BIO instead of a uri, along with a scheme to use when reading.
  * The given UI method will be used any time the loader needs extra input,
  * for example when a password or pin is needed, and will be passed the
  * same user data every time it's needed in this context.
  *
  * Returns a context reference which represents the channel to communicate
  * through.
  *
  * Note that this function is considered unsafe, all depending on what the
  * BIO actually reads.
  }
  OSSL_STORE_attach: function(bio: PBIO; scheme: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl = Load_OSSL_STORE_attach;
  {-
  *  Extracting OpenSSL types from and creating new OSSL_STORE_INFOs
  *  ---------------------------------------------------------------
  }
  
  {* Types of data that can be ossl_stored in a OSSL_STORE_INFO.
  * OSSL_STORE_INFO_NAME is typically found when getting a listing of
  * available "files" / "tokens" / what have you.
  }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  OSSL_STORE_INFO_NAME = 1;
  OSSL_STORE_INFO_PARAMS = 2;
  OSSL_STORE_INFO_PUBKEY = 3;
  OSSL_STORE_INFO_PKEY = 4;
  OSSL_STORE_INFO_CERT = 5;
  OSSL_STORE_INFO_CRL = 6;


  
  {* Functions to generate OSSL_STORE_INFOs, one function for each type we
  * support having in them, as well as a generic constructor.
  *
  * In all cases, ownership of the object is transferred to the OSSL_STORE_INFO
  * and will therefore be freed when the OSSL_STORE_INFO is freed.
  }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_INFO_new(type_: TOpenSSL_C_INT; data: pointer): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_new';
  function OSSL_STORE_INFO_new_NAME(name: PAnsiChar): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_new_NAME';
  function OSSL_STORE_INFO_set0_NAME_description(info: POSSL_STORE_INFO; desc: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_set0_NAME_description';
  function OSSL_STORE_INFO_new_PARAMS(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_new_PARAMS';
  function OSSL_STORE_INFO_new_PUBKEY(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_new_PUBKEY';
  function OSSL_STORE_INFO_new_PKEY(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_new_PKEY';
  function OSSL_STORE_INFO_new_CERT(x509: PX509): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_new_CERT';
  function OSSL_STORE_INFO_new_CRL(crl: PX509_CRL): POSSL_STORE_INFO; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_new_CRL';
  
  {* Functions to try to extract data from a OSSL_STORE_INFO.
  }
  function OSSL_STORE_INFO_get_type(info: POSSL_STORE_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get_type';
  function OSSL_STORE_INFO_get0_data(type_: TOpenSSL_C_INT; info: POSSL_STORE_INFO): pointer; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_data';
  function OSSL_STORE_INFO_get0_NAME(info: POSSL_STORE_INFO): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_NAME';
  function OSSL_STORE_INFO_get1_NAME(info: POSSL_STORE_INFO): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get1_NAME';
  function OSSL_STORE_INFO_get0_NAME_description(info: POSSL_STORE_INFO): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_NAME_description';
  function OSSL_STORE_INFO_get1_NAME_description(info: POSSL_STORE_INFO): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get1_NAME_description';
  function OSSL_STORE_INFO_get0_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_PARAMS';
  function OSSL_STORE_INFO_get1_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get1_PARAMS';
  function OSSL_STORE_INFO_get0_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_PUBKEY';
  function OSSL_STORE_INFO_get1_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get1_PUBKEY';
  function OSSL_STORE_INFO_get0_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_PKEY';
  function OSSL_STORE_INFO_get1_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get1_PKEY';
  function OSSL_STORE_INFO_get0_CERT(info: POSSL_STORE_INFO): PX509; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_CERT';
  function OSSL_STORE_INFO_get1_CERT(info: POSSL_STORE_INFO): PX509; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get1_CERT';
  function OSSL_STORE_INFO_get0_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get0_CRL';
  function OSSL_STORE_INFO_get1_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_get1_CRL';
  function OSSL_STORE_INFO_type_string(type_: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_INFO_type_string';
  
  {* Free the OSSL_STORE_INFO
  }
  procedure OSSL_STORE_INFO_free(info: POSSL_STORE_INFO); cdecl; external CLibCrypto name 'OSSL_STORE_INFO_free';
  {-
  *  Functions to construct a search URI from a base URI and search criteria
  *  -----------------------------------------------------------------------
  }
  { OSSL_STORE search types }
  {$else}
  {$EXTERNALSYM OSSL_STORE_INFO_new}
  {$EXTERNALSYM OSSL_STORE_INFO_new_NAME}
  {$EXTERNALSYM OSSL_STORE_INFO_set0_NAME_description}
  {$EXTERNALSYM OSSL_STORE_INFO_new_PARAMS}
  {$EXTERNALSYM OSSL_STORE_INFO_new_PUBKEY}
  {$EXTERNALSYM OSSL_STORE_INFO_new_PKEY}
  {$EXTERNALSYM OSSL_STORE_INFO_new_CERT}
  {$EXTERNALSYM OSSL_STORE_INFO_new_CRL}
  {$EXTERNALSYM OSSL_STORE_INFO_get_type}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_data}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME}
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_NAME_description}
  {$EXTERNALSYM OSSL_STORE_INFO_get1_NAME_description}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PARAMS}
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PARAMS}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PUBKEY}
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PUBKEY}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_PKEY}
  {$EXTERNALSYM OSSL_STORE_INFO_get1_PKEY}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CERT}
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CERT}
  {$EXTERNALSYM OSSL_STORE_INFO_get0_CRL}
  {$EXTERNALSYM OSSL_STORE_INFO_get1_CRL}
  {$EXTERNALSYM OSSL_STORE_INFO_type_string}
  {$EXTERNALSYM OSSL_STORE_INFO_free}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_INFO_new(type_: TOpenSSL_C_INT; data: pointer): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_INFO_new_NAME(name: PAnsiChar): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_INFO_set0_NAME_description(info: POSSL_STORE_INFO; desc: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_INFO_new_PARAMS(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_INFO_new_PUBKEY(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_INFO_new_PKEY(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_INFO_new_CERT(x509: PX509): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_INFO_new_CRL(crl: PX509_CRL): POSSL_STORE_INFO; cdecl;
  function Load_OSSL_STORE_INFO_get_type(info: POSSL_STORE_INFO): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_INFO_get0_data(type_: TOpenSSL_C_INT; info: POSSL_STORE_INFO): pointer; cdecl;
  function Load_OSSL_STORE_INFO_get0_NAME(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
  function Load_OSSL_STORE_INFO_get1_NAME(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
  function Load_OSSL_STORE_INFO_get0_NAME_description(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
  function Load_OSSL_STORE_INFO_get1_NAME_description(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
  function Load_OSSL_STORE_INFO_get0_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
  function Load_OSSL_STORE_INFO_get1_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
  function Load_OSSL_STORE_INFO_get0_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
  function Load_OSSL_STORE_INFO_get1_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
  function Load_OSSL_STORE_INFO_get0_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
  function Load_OSSL_STORE_INFO_get1_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
  function Load_OSSL_STORE_INFO_get0_CERT(info: POSSL_STORE_INFO): PX509; cdecl;
  function Load_OSSL_STORE_INFO_get1_CERT(info: POSSL_STORE_INFO): PX509; cdecl;
  function Load_OSSL_STORE_INFO_get0_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl;
  function Load_OSSL_STORE_INFO_get1_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl;
  function Load_OSSL_STORE_INFO_type_string(type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
  procedure Load_OSSL_STORE_INFO_free(info: POSSL_STORE_INFO); cdecl;

var
  OSSL_STORE_INFO_new: function(type_: TOpenSSL_C_INT; data: pointer): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_INFO_new;
  OSSL_STORE_INFO_new_NAME: function(name: PAnsiChar): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_INFO_new_NAME;
  OSSL_STORE_INFO_set0_NAME_description: function(info: POSSL_STORE_INFO; desc: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_INFO_set0_NAME_description;
  OSSL_STORE_INFO_new_PARAMS: function(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_INFO_new_PARAMS;
  OSSL_STORE_INFO_new_PUBKEY: function(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_INFO_new_PUBKEY;
  OSSL_STORE_INFO_new_PKEY: function(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_INFO_new_PKEY;
  OSSL_STORE_INFO_new_CERT: function(x509: PX509): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_INFO_new_CERT;
  OSSL_STORE_INFO_new_CRL: function(crl: PX509_CRL): POSSL_STORE_INFO; cdecl = Load_OSSL_STORE_INFO_new_CRL;
  
  {* Functions to try to extract data from a OSSL_STORE_INFO.
  }
  OSSL_STORE_INFO_get_type: function(info: POSSL_STORE_INFO): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_INFO_get_type;
  OSSL_STORE_INFO_get0_data: function(type_: TOpenSSL_C_INT; info: POSSL_STORE_INFO): pointer; cdecl = Load_OSSL_STORE_INFO_get0_data;
  OSSL_STORE_INFO_get0_NAME: function(info: POSSL_STORE_INFO): PAnsiChar; cdecl = Load_OSSL_STORE_INFO_get0_NAME;
  OSSL_STORE_INFO_get1_NAME: function(info: POSSL_STORE_INFO): PAnsiChar; cdecl = Load_OSSL_STORE_INFO_get1_NAME;
  OSSL_STORE_INFO_get0_NAME_description: function(info: POSSL_STORE_INFO): PAnsiChar; cdecl = Load_OSSL_STORE_INFO_get0_NAME_description;
  OSSL_STORE_INFO_get1_NAME_description: function(info: POSSL_STORE_INFO): PAnsiChar; cdecl = Load_OSSL_STORE_INFO_get1_NAME_description;
  OSSL_STORE_INFO_get0_PARAMS: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = Load_OSSL_STORE_INFO_get0_PARAMS;
  OSSL_STORE_INFO_get1_PARAMS: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = Load_OSSL_STORE_INFO_get1_PARAMS;
  OSSL_STORE_INFO_get0_PUBKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = Load_OSSL_STORE_INFO_get0_PUBKEY;
  OSSL_STORE_INFO_get1_PUBKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = Load_OSSL_STORE_INFO_get1_PUBKEY;
  OSSL_STORE_INFO_get0_PKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = Load_OSSL_STORE_INFO_get0_PKEY;
  OSSL_STORE_INFO_get1_PKEY: function(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl = Load_OSSL_STORE_INFO_get1_PKEY;
  OSSL_STORE_INFO_get0_CERT: function(info: POSSL_STORE_INFO): PX509; cdecl = Load_OSSL_STORE_INFO_get0_CERT;
  OSSL_STORE_INFO_get1_CERT: function(info: POSSL_STORE_INFO): PX509; cdecl = Load_OSSL_STORE_INFO_get1_CERT;
  OSSL_STORE_INFO_get0_CRL: function(info: POSSL_STORE_INFO): PX509_CRL; cdecl = Load_OSSL_STORE_INFO_get0_CRL;
  OSSL_STORE_INFO_get1_CRL: function(info: POSSL_STORE_INFO): PX509_CRL; cdecl = Load_OSSL_STORE_INFO_get1_CRL;
  OSSL_STORE_INFO_type_string: function(type_: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OSSL_STORE_INFO_type_string;
  
  {* Free the OSSL_STORE_INFO
  }
  OSSL_STORE_INFO_free: procedure(info: POSSL_STORE_INFO); cdecl = Load_OSSL_STORE_INFO_free;
  {-
  *  Functions to construct a search URI from a base URI and search criteria
  *  -----------------------------------------------------------------------
  }
  { OSSL_STORE search types }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

const
  OSSL_STORE_SEARCH_BY_NAME_ = 1;
  OSSL_STORE_SEARCH_BY_ISSUER_SERIAL_ = 2;
  OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT_ = 3;
  OSSL_STORE_SEARCH_BY_ALIAS_ = 4;


  { To check what search types the scheme handler supports }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_supports_search(ctx: POSSL_STORE_CTX; search_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_supports_search';
  { Search term constructors }
  
  {* The input is considered to be owned by the caller, and must therefore
  * remain present throughout the lifetime of the returned OSSL_STORE_SEARCH
  }
  function OSSL_STORE_SEARCH_by_name(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_by_name';
  function OSSL_STORE_SEARCH_by_issuer_serial(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_by_issuer_serial';
  function OSSL_STORE_SEARCH_by_key_fingerprint(digest: PEVP_MD; bytes: Pbyte; len: TOpenSSL_C_SIZET): POSSL_STORE_SEARCH; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_by_key_fingerprint';
  function OSSL_STORE_SEARCH_by_alias(alias: PAnsiChar): POSSL_STORE_SEARCH; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_by_alias';
  { Search term destructor }
  procedure OSSL_STORE_SEARCH_free(search: POSSL_STORE_SEARCH); cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_free';
  { Search term accessors }
  function OSSL_STORE_SEARCH_get_type(criterion: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_get_type';
  function OSSL_STORE_SEARCH_get0_name(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_get0_name';
  function OSSL_STORE_SEARCH_get0_serial(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_get0_serial';
  function OSSL_STORE_SEARCH_get0_bytes(criterion: POSSL_STORE_SEARCH; length: POpenSSL_C_SIZET): Pbyte; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_get0_bytes';
  function OSSL_STORE_SEARCH_get0_string(criterion: POSSL_STORE_SEARCH): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_get0_string';
  function OSSL_STORE_SEARCH_get0_digest(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl; external CLibCrypto name 'OSSL_STORE_SEARCH_get0_digest';
  
  {* Add search criterion and expected return type (which can be unspecified)
  * to the loading channel.  This MUST happen before the first OSSL_STORE_load().
  }
  function OSSL_STORE_expect(ctx: POSSL_STORE_CTX; expected_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_expect';
  function OSSL_STORE_find(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_find';
  {-
  *  Function to fetch a loader and extract data from it
  *  ---------------------------------------------------
  }
  {$else}
  {$EXTERNALSYM OSSL_STORE_supports_search}
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_name}
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_issuer_serial}
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_key_fingerprint}
  {$EXTERNALSYM OSSL_STORE_SEARCH_by_alias}
  {$EXTERNALSYM OSSL_STORE_SEARCH_free}
  {$EXTERNALSYM OSSL_STORE_SEARCH_get_type}
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_name}
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_serial}
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_bytes}
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_string}
  {$EXTERNALSYM OSSL_STORE_SEARCH_get0_digest}
  {$EXTERNALSYM OSSL_STORE_expect}
  {$EXTERNALSYM OSSL_STORE_find}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_supports_search(ctx: POSSL_STORE_CTX; search_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_SEARCH_by_name(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl;
  function Load_OSSL_STORE_SEARCH_by_issuer_serial(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl;
  function Load_OSSL_STORE_SEARCH_by_key_fingerprint(digest: PEVP_MD; bytes: Pbyte; len: TOpenSSL_C_SIZET): POSSL_STORE_SEARCH; cdecl;
  function Load_OSSL_STORE_SEARCH_by_alias(alias: PAnsiChar): POSSL_STORE_SEARCH; cdecl;
  procedure Load_OSSL_STORE_SEARCH_free(search: POSSL_STORE_SEARCH); cdecl;
  function Load_OSSL_STORE_SEARCH_get_type(criterion: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_SEARCH_get0_name(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl;
  function Load_OSSL_STORE_SEARCH_get0_serial(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl;
  function Load_OSSL_STORE_SEARCH_get0_bytes(criterion: POSSL_STORE_SEARCH; length: POpenSSL_C_SIZET): Pbyte; cdecl;
  function Load_OSSL_STORE_SEARCH_get0_string(criterion: POSSL_STORE_SEARCH): PAnsiChar; cdecl;
  function Load_OSSL_STORE_SEARCH_get0_digest(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl;
  function Load_OSSL_STORE_expect(ctx: POSSL_STORE_CTX; expected_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_find(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl;

var
  OSSL_STORE_supports_search: function(ctx: POSSL_STORE_CTX; search_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_supports_search;
  { Search term constructors }
  
  {* The input is considered to be owned by the caller, and must therefore
  * remain present throughout the lifetime of the returned OSSL_STORE_SEARCH
  }
  OSSL_STORE_SEARCH_by_name: function(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl = Load_OSSL_STORE_SEARCH_by_name;
  OSSL_STORE_SEARCH_by_issuer_serial: function(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl = Load_OSSL_STORE_SEARCH_by_issuer_serial;
  OSSL_STORE_SEARCH_by_key_fingerprint: function(digest: PEVP_MD; bytes: Pbyte; len: TOpenSSL_C_SIZET): POSSL_STORE_SEARCH; cdecl = Load_OSSL_STORE_SEARCH_by_key_fingerprint;
  OSSL_STORE_SEARCH_by_alias: function(alias: PAnsiChar): POSSL_STORE_SEARCH; cdecl = Load_OSSL_STORE_SEARCH_by_alias;
  { Search term destructor }
  OSSL_STORE_SEARCH_free: procedure(search: POSSL_STORE_SEARCH); cdecl = Load_OSSL_STORE_SEARCH_free;
  { Search term accessors }
  OSSL_STORE_SEARCH_get_type: function(criterion: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_SEARCH_get_type;
  OSSL_STORE_SEARCH_get0_name: function(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl = Load_OSSL_STORE_SEARCH_get0_name;
  OSSL_STORE_SEARCH_get0_serial: function(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl = Load_OSSL_STORE_SEARCH_get0_serial;
  OSSL_STORE_SEARCH_get0_bytes: function(criterion: POSSL_STORE_SEARCH; length: POpenSSL_C_SIZET): Pbyte; cdecl = Load_OSSL_STORE_SEARCH_get0_bytes;
  OSSL_STORE_SEARCH_get0_string: function(criterion: POSSL_STORE_SEARCH): PAnsiChar; cdecl = Load_OSSL_STORE_SEARCH_get0_string;
  OSSL_STORE_SEARCH_get0_digest: function(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl = Load_OSSL_STORE_SEARCH_get0_digest;
  
  {* Add search criterion and expected return type (which can be unspecified)
  * to the loading channel.  This MUST happen before the first OSSL_STORE_load().
  }
  OSSL_STORE_expect: function(ctx: POSSL_STORE_CTX; expected_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_expect;
  OSSL_STORE_find: function(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_find;
  {-
  *  Function to fetch a loader and extract data from it
  *  ---------------------------------------------------
  }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  Possl_store_loader_st = ^TOSSL_STORE_LOADER;
  PPossl_store_loader_st = ^Possl_store_loader_st;
  POSSL_STORE_LOADER = ^TOSSL_STORE_LOADER;
  PPOSSL_STORE_LOADER = ^POSSL_STORE_LOADER;
  {end of auto-generated forward references}

  Tossl_store_loader_st = record end;
  TOSSL_STORE_LOADER = Tossl_store_loader_st;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_LOADER_fetch(libctx: POSSL_LIB_CTX; scheme: PAnsiChar; properties: PAnsiChar): POSSL_STORE_LOADER; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_fetch';
  function OSSL_STORE_LOADER_up_ref(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_up_ref';
  procedure OSSL_STORE_LOADER_free(loader: POSSL_STORE_LOADER); cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_free';
  function OSSL_STORE_LOADER_get0_provider(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_get0_provider';
  function OSSL_STORE_LOADER_get0_properties(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_get0_properties';
  function OSSL_STORE_LOADER_get0_description(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_get0_description';
  function OSSL_STORE_LOADER_is_a(loader: POSSL_STORE_LOADER; scheme: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_is_a';
  {$else}
  {$EXTERNALSYM OSSL_STORE_LOADER_fetch}
  {$EXTERNALSYM OSSL_STORE_LOADER_up_ref}
  {$EXTERNALSYM OSSL_STORE_LOADER_free}
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_provider}
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_properties}
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_description}
  {$EXTERNALSYM OSSL_STORE_LOADER_is_a}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_LOADER_fetch(libctx: POSSL_LIB_CTX; scheme: PAnsiChar; properties: PAnsiChar): POSSL_STORE_LOADER; cdecl;
  function Load_OSSL_STORE_LOADER_up_ref(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl;
  procedure Load_OSSL_STORE_LOADER_free(loader: POSSL_STORE_LOADER); cdecl;
  function Load_OSSL_STORE_LOADER_get0_provider(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl;
  function Load_OSSL_STORE_LOADER_get0_properties(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl;
  function Load_OSSL_STORE_LOADER_get0_description(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl;
  function Load_OSSL_STORE_LOADER_is_a(loader: POSSL_STORE_LOADER; scheme: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  OSSL_STORE_LOADER_fetch: function(libctx: POSSL_LIB_CTX; scheme: PAnsiChar; properties: PAnsiChar): POSSL_STORE_LOADER; cdecl = Load_OSSL_STORE_LOADER_fetch;
  OSSL_STORE_LOADER_up_ref: function(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_up_ref;
  OSSL_STORE_LOADER_free: procedure(loader: POSSL_STORE_LOADER); cdecl = Load_OSSL_STORE_LOADER_free;
  OSSL_STORE_LOADER_get0_provider: function(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl = Load_OSSL_STORE_LOADER_get0_provider;
  OSSL_STORE_LOADER_get0_properties: function(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl = Load_OSSL_STORE_LOADER_get0_properties;
  OSSL_STORE_LOADER_get0_description: function(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl = Load_OSSL_STORE_LOADER_get0_description;
  OSSL_STORE_LOADER_is_a: function(loader: POSSL_STORE_LOADER; scheme: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_is_a;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  {end of auto-generated forward references}

  TFuncType000 = procedure(loader: POSSL_STORE_LOADER; arg: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure OSSL_STORE_LOADER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_do_all_provided';
  {$else}
  {$EXTERNALSYM OSSL_STORE_LOADER_do_all_provided}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_OSSL_STORE_LOADER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;

var
  OSSL_STORE_LOADER_do_all_provided: procedure(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl = Load_OSSL_STORE_LOADER_do_all_provided;
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = procedure(name: PAnsiChar; data: pointer); cdecl;


  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_LOADER_names_do_all(loader: POSSL_STORE_LOADER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_names_do_all';
  {-
  *  Function to register a loader for the given URI scheme.
  *  -------------------------------------------------------
  *
  *  The loader receives all the main components of an URI except for the
  *  scheme.
  }
  {$else}
  {$EXTERNALSYM OSSL_STORE_LOADER_names_do_all}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_LOADER_names_do_all(loader: POSSL_STORE_LOADER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;

var
  OSSL_STORE_LOADER_names_do_all: function(loader: POSSL_STORE_LOADER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_names_do_all;
  {-
  *  Function to register a loader for the given URI scheme.
  *  -------------------------------------------------------
  *
  *  The loader receives all the main components of an URI except for the
  *  scheme.
  }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  Possl_store_loader_ctx_st = ^TOSSL_STORE_LOADER_CTX;
  PPossl_store_loader_ctx_st = ^Possl_store_loader_ctx_st;
  POSSL_STORE_LOADER_CTX = ^TOSSL_STORE_LOADER_CTX;
  PPOSSL_STORE_LOADER_CTX = ^POSSL_STORE_LOADER_CTX;
  POSSL_STORE_open_fn = ^TOSSL_STORE_open_fn;
  PPOSSL_STORE_open_fn = ^POSSL_STORE_open_fn;
  POSSL_STORE_open_ex_fn = ^TOSSL_STORE_open_ex_fn;
  PPOSSL_STORE_open_ex_fn = ^POSSL_STORE_open_ex_fn;
  POSSL_STORE_attach_fn = ^TOSSL_STORE_attach_fn;
  PPOSSL_STORE_attach_fn = ^POSSL_STORE_attach_fn;
  POSSL_STORE_ctrl_fn = ^TOSSL_STORE_ctrl_fn;
  PPOSSL_STORE_ctrl_fn = ^POSSL_STORE_ctrl_fn;
  POSSL_STORE_expect_fn = ^TOSSL_STORE_expect_fn;
  PPOSSL_STORE_expect_fn = ^POSSL_STORE_expect_fn;
  POSSL_STORE_find_fn = ^TOSSL_STORE_find_fn;
  PPOSSL_STORE_find_fn = ^POSSL_STORE_find_fn;
  POSSL_STORE_load_fn = ^TOSSL_STORE_load_fn;
  PPOSSL_STORE_load_fn = ^POSSL_STORE_load_fn;
  POSSL_STORE_eof_fn = ^TOSSL_STORE_eof_fn;
  PPOSSL_STORE_eof_fn = ^POSSL_STORE_eof_fn;
  POSSL_STORE_error_fn = ^TOSSL_STORE_error_fn;
  PPOSSL_STORE_error_fn = ^POSSL_STORE_error_fn;
  POSSL_STORE_close_fn = ^TOSSL_STORE_close_fn;
  PPOSSL_STORE_close_fn = ^POSSL_STORE_close_fn;
  {end of auto-generated forward references}

    { struct ossl_store_loader_ctx_st is defined differently by each loader }
  Tossl_store_loader_ctx_st = record end;
  TOSSL_STORE_LOADER_CTX = Tossl_store_loader_ctx_st;
  TOSSL_STORE_open_fn = function(loader: POSSL_STORE_LOADER; uri: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer): POSSL_STORE_LOADER_CTX; cdecl;
  TOSSL_STORE_open_ex_fn = function(loader: POSSL_STORE_LOADER; uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer): POSSL_STORE_LOADER_CTX; cdecl;
  TOSSL_STORE_attach_fn = function(loader: POSSL_STORE_LOADER; bio: PBIO; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer): POSSL_STORE_LOADER_CTX; cdecl;
  TOSSL_STORE_ctrl_fn = function(ctx: POSSL_STORE_LOADER_CTX; cmd: TOpenSSL_C_INT; args: array of const): TOpenSSL_C_INT; cdecl;
  TOSSL_STORE_expect_fn = function(ctx: POSSL_STORE_LOADER_CTX; expected: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TOSSL_STORE_find_fn = function(ctx: POSSL_STORE_LOADER_CTX; criteria: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl;
  TOSSL_STORE_load_fn = function(ctx: POSSL_STORE_LOADER_CTX; ui_method: PUI_METHOD; ui_data: pointer): POSSL_STORE_INFO; cdecl;
  TOSSL_STORE_eof_fn = function(ctx: POSSL_STORE_LOADER_CTX): TOpenSSL_C_INT; cdecl;
  TOSSL_STORE_error_fn = function(ctx: POSSL_STORE_LOADER_CTX): TOpenSSL_C_INT; cdecl;
  TOSSL_STORE_close_fn = function(ctx: POSSL_STORE_LOADER_CTX): TOpenSSL_C_INT; cdecl;
  {$endif}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_LOADER_new(e: PENGINE; scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_new'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_open(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_open'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_open_ex(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_open_ex'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_attach(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_attach'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_ctrl(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_ctrl'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_expect(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_expect'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_find(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_find'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_load(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_load'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_eof(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_eof_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_eof'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_error(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_error_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_error'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_set_close(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_set_close'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_get0_engine(loader: POSSL_STORE_LOADER): PENGINE; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_get0_engine'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_LOADER_get0_scheme(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_STORE_LOADER_get0_scheme'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_register_loader(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_register_loader'; deprecated 'Since OpenSSL 3.0';
  function OSSL_STORE_unregister_loader(scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl; external CLibCrypto name 'OSSL_STORE_unregister_loader'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM OSSL_STORE_LOADER_new}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_open}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_open_ex}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_attach}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_ctrl}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_expect}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_find}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_load}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_eof}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_error}
  {$EXTERNALSYM OSSL_STORE_LOADER_set_close}
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_engine}
  {$EXTERNALSYM OSSL_STORE_LOADER_get0_scheme}
  {$EXTERNALSYM OSSL_STORE_register_loader}
  {$EXTERNALSYM OSSL_STORE_unregister_loader}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_LOADER_new(e: PENGINE; scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl;
  function Load_OSSL_STORE_LOADER_set_open(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_open_ex(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_attach(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_ctrl(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_expect(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_find(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_load(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_eof(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_eof_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_error(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_error_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_set_close(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_LOADER_get0_engine(loader: POSSL_STORE_LOADER): PENGINE; cdecl;
  function Load_OSSL_STORE_LOADER_get0_scheme(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl;
  function Load_OSSL_STORE_register_loader(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_STORE_unregister_loader(scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl;

var
  OSSL_STORE_LOADER_new: function(e: PENGINE; scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl = Load_OSSL_STORE_LOADER_new;
  OSSL_STORE_LOADER_set_open: function(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_open;
  OSSL_STORE_LOADER_set_open_ex: function(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_open_ex;
  OSSL_STORE_LOADER_set_attach: function(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_attach;
  OSSL_STORE_LOADER_set_ctrl: function(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_ctrl;
  OSSL_STORE_LOADER_set_expect: function(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_expect;
  OSSL_STORE_LOADER_set_find: function(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_find;
  OSSL_STORE_LOADER_set_load: function(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_load;
  OSSL_STORE_LOADER_set_eof: function(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_eof_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_eof;
  OSSL_STORE_LOADER_set_error: function(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_error_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_error;
  OSSL_STORE_LOADER_set_close: function(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_LOADER_set_close;
  OSSL_STORE_LOADER_get0_engine: function(loader: POSSL_STORE_LOADER): PENGINE; cdecl = Load_OSSL_STORE_LOADER_get0_engine;
  OSSL_STORE_LOADER_get0_scheme: function(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl = Load_OSSL_STORE_LOADER_get0_scheme;
  OSSL_STORE_register_loader: function(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_register_loader;
  OSSL_STORE_unregister_loader: function(scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl = Load_OSSL_STORE_unregister_loader;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$endif}
  {-
  *  Functions to list STORE loaders
  *  -------------------------------
  }
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  {end of auto-generated forward references}

  TFuncType002 = procedure(loader: POSSL_STORE_LOADER; do_arg: pointer); cdecl;


    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_STORE_do_all_loaders(do_function: TFuncType002; do_arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_STORE_do_all_loaders'; deprecated 'Since OpenSSL 3.0';
    {$else}
  {$EXTERNALSYM OSSL_STORE_do_all_loaders}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_STORE_do_all_loaders(do_function: TFuncType002; do_arg: pointer): TOpenSSL_C_INT; cdecl;

var
  OSSL_STORE_do_all_loaders: function(do_function: TFuncType002; do_arg: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_STORE_do_all_loaders;
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
function Load_OSSL_STORE_open(uri: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl;
begin
  OSSL_STORE_open := LoadLibCryptoFunction('OSSL_STORE_open');
  if not assigned(OSSL_STORE_open) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_open');
  Result := OSSL_STORE_open(uri, ui_method, ui_data, post_process, post_process_data);
end;

function Load_OSSL_STORE_open_ex(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl;
begin
  OSSL_STORE_open_ex := LoadLibCryptoFunction('OSSL_STORE_open_ex');
  if not assigned(OSSL_STORE_open_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_open_ex');
  Result := OSSL_STORE_open_ex(uri, libctx, propq, ui_method, ui_data, params, post_process, post_process_data);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_OSSL_STORE_load(ctx: POSSL_STORE_CTX): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_load := LoadLibCryptoFunction('OSSL_STORE_load');
  if not assigned(OSSL_STORE_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_load');
  Result := OSSL_STORE_load(ctx);
end;

function Load_OSSL_STORE_delete(uri: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_delete := LoadLibCryptoFunction('OSSL_STORE_delete');
  if not assigned(OSSL_STORE_delete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_delete');
  Result := OSSL_STORE_delete(uri, libctx, propq, ui_method, ui_data, params);
end;

function Load_OSSL_STORE_eof(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_eof := LoadLibCryptoFunction('OSSL_STORE_eof');
  if not assigned(OSSL_STORE_eof) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_eof');
  Result := OSSL_STORE_eof(ctx);
end;

function Load_OSSL_STORE_error(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_error := LoadLibCryptoFunction('OSSL_STORE_error');
  if not assigned(OSSL_STORE_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_error');
  Result := OSSL_STORE_error(ctx);
end;

function Load_OSSL_STORE_close(ctx: POSSL_STORE_CTX): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_close := LoadLibCryptoFunction('OSSL_STORE_close');
  if not assigned(OSSL_STORE_close) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_close');
  Result := OSSL_STORE_close(ctx);
end;

function Load_OSSL_STORE_attach(bio: PBIO; scheme: PAnsiChar; libctx: POSSL_LIB_CTX; propq: PAnsiChar; ui_method: PUI_METHOD; ui_data: pointer; params: POSSL_PARAM; post_process: TOSSL_STORE_post_process_info_fn; post_process_data: pointer): POSSL_STORE_CTX; cdecl;
begin
  OSSL_STORE_attach := LoadLibCryptoFunction('OSSL_STORE_attach');
  if not assigned(OSSL_STORE_attach) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_attach');
  Result := OSSL_STORE_attach(bio, scheme, libctx, propq, ui_method, ui_data, params, post_process, post_process_data);
end;

function Load_OSSL_STORE_INFO_new(type_: TOpenSSL_C_INT; data: pointer): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_INFO_new := LoadLibCryptoFunction('OSSL_STORE_INFO_new');
  if not assigned(OSSL_STORE_INFO_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_new');
  Result := OSSL_STORE_INFO_new(type_, data);
end;

function Load_OSSL_STORE_INFO_new_NAME(name: PAnsiChar): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_INFO_new_NAME := LoadLibCryptoFunction('OSSL_STORE_INFO_new_NAME');
  if not assigned(OSSL_STORE_INFO_new_NAME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_new_NAME');
  Result := OSSL_STORE_INFO_new_NAME(name);
end;

function Load_OSSL_STORE_INFO_set0_NAME_description(info: POSSL_STORE_INFO; desc: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_INFO_set0_NAME_description := LoadLibCryptoFunction('OSSL_STORE_INFO_set0_NAME_description');
  if not assigned(OSSL_STORE_INFO_set0_NAME_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_set0_NAME_description');
  Result := OSSL_STORE_INFO_set0_NAME_description(info, desc);
end;

function Load_OSSL_STORE_INFO_new_PARAMS(params: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_INFO_new_PARAMS := LoadLibCryptoFunction('OSSL_STORE_INFO_new_PARAMS');
  if not assigned(OSSL_STORE_INFO_new_PARAMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_new_PARAMS');
  Result := OSSL_STORE_INFO_new_PARAMS(params);
end;

function Load_OSSL_STORE_INFO_new_PUBKEY(pubkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_INFO_new_PUBKEY := LoadLibCryptoFunction('OSSL_STORE_INFO_new_PUBKEY');
  if not assigned(OSSL_STORE_INFO_new_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_new_PUBKEY');
  Result := OSSL_STORE_INFO_new_PUBKEY(pubkey);
end;

function Load_OSSL_STORE_INFO_new_PKEY(pkey: PEVP_PKEY): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_INFO_new_PKEY := LoadLibCryptoFunction('OSSL_STORE_INFO_new_PKEY');
  if not assigned(OSSL_STORE_INFO_new_PKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_new_PKEY');
  Result := OSSL_STORE_INFO_new_PKEY(pkey);
end;

function Load_OSSL_STORE_INFO_new_CERT(x509: PX509): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_INFO_new_CERT := LoadLibCryptoFunction('OSSL_STORE_INFO_new_CERT');
  if not assigned(OSSL_STORE_INFO_new_CERT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_new_CERT');
  Result := OSSL_STORE_INFO_new_CERT(x509);
end;

function Load_OSSL_STORE_INFO_new_CRL(crl: PX509_CRL): POSSL_STORE_INFO; cdecl;
begin
  OSSL_STORE_INFO_new_CRL := LoadLibCryptoFunction('OSSL_STORE_INFO_new_CRL');
  if not assigned(OSSL_STORE_INFO_new_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_new_CRL');
  Result := OSSL_STORE_INFO_new_CRL(crl);
end;

function Load_OSSL_STORE_INFO_get_type(info: POSSL_STORE_INFO): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_INFO_get_type := LoadLibCryptoFunction('OSSL_STORE_INFO_get_type');
  if not assigned(OSSL_STORE_INFO_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get_type');
  Result := OSSL_STORE_INFO_get_type(info);
end;

function Load_OSSL_STORE_INFO_get0_data(type_: TOpenSSL_C_INT; info: POSSL_STORE_INFO): pointer; cdecl;
begin
  OSSL_STORE_INFO_get0_data := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_data');
  if not assigned(OSSL_STORE_INFO_get0_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_data');
  Result := OSSL_STORE_INFO_get0_data(type_, info);
end;

function Load_OSSL_STORE_INFO_get0_NAME(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
begin
  OSSL_STORE_INFO_get0_NAME := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_NAME');
  if not assigned(OSSL_STORE_INFO_get0_NAME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_NAME');
  Result := OSSL_STORE_INFO_get0_NAME(info);
end;

function Load_OSSL_STORE_INFO_get1_NAME(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
begin
  OSSL_STORE_INFO_get1_NAME := LoadLibCryptoFunction('OSSL_STORE_INFO_get1_NAME');
  if not assigned(OSSL_STORE_INFO_get1_NAME) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get1_NAME');
  Result := OSSL_STORE_INFO_get1_NAME(info);
end;

function Load_OSSL_STORE_INFO_get0_NAME_description(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
begin
  OSSL_STORE_INFO_get0_NAME_description := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_NAME_description');
  if not assigned(OSSL_STORE_INFO_get0_NAME_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_NAME_description');
  Result := OSSL_STORE_INFO_get0_NAME_description(info);
end;

function Load_OSSL_STORE_INFO_get1_NAME_description(info: POSSL_STORE_INFO): PAnsiChar; cdecl;
begin
  OSSL_STORE_INFO_get1_NAME_description := LoadLibCryptoFunction('OSSL_STORE_INFO_get1_NAME_description');
  if not assigned(OSSL_STORE_INFO_get1_NAME_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get1_NAME_description');
  Result := OSSL_STORE_INFO_get1_NAME_description(info);
end;

function Load_OSSL_STORE_INFO_get0_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
begin
  OSSL_STORE_INFO_get0_PARAMS := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_PARAMS');
  if not assigned(OSSL_STORE_INFO_get0_PARAMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_PARAMS');
  Result := OSSL_STORE_INFO_get0_PARAMS(info);
end;

function Load_OSSL_STORE_INFO_get1_PARAMS(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
begin
  OSSL_STORE_INFO_get1_PARAMS := LoadLibCryptoFunction('OSSL_STORE_INFO_get1_PARAMS');
  if not assigned(OSSL_STORE_INFO_get1_PARAMS) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get1_PARAMS');
  Result := OSSL_STORE_INFO_get1_PARAMS(info);
end;

function Load_OSSL_STORE_INFO_get0_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
begin
  OSSL_STORE_INFO_get0_PUBKEY := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_PUBKEY');
  if not assigned(OSSL_STORE_INFO_get0_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_PUBKEY');
  Result := OSSL_STORE_INFO_get0_PUBKEY(info);
end;

function Load_OSSL_STORE_INFO_get1_PUBKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
begin
  OSSL_STORE_INFO_get1_PUBKEY := LoadLibCryptoFunction('OSSL_STORE_INFO_get1_PUBKEY');
  if not assigned(OSSL_STORE_INFO_get1_PUBKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get1_PUBKEY');
  Result := OSSL_STORE_INFO_get1_PUBKEY(info);
end;

function Load_OSSL_STORE_INFO_get0_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
begin
  OSSL_STORE_INFO_get0_PKEY := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_PKEY');
  if not assigned(OSSL_STORE_INFO_get0_PKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_PKEY');
  Result := OSSL_STORE_INFO_get0_PKEY(info);
end;

function Load_OSSL_STORE_INFO_get1_PKEY(info: POSSL_STORE_INFO): PEVP_PKEY; cdecl;
begin
  OSSL_STORE_INFO_get1_PKEY := LoadLibCryptoFunction('OSSL_STORE_INFO_get1_PKEY');
  if not assigned(OSSL_STORE_INFO_get1_PKEY) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get1_PKEY');
  Result := OSSL_STORE_INFO_get1_PKEY(info);
end;

function Load_OSSL_STORE_INFO_get0_CERT(info: POSSL_STORE_INFO): PX509; cdecl;
begin
  OSSL_STORE_INFO_get0_CERT := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_CERT');
  if not assigned(OSSL_STORE_INFO_get0_CERT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_CERT');
  Result := OSSL_STORE_INFO_get0_CERT(info);
end;

function Load_OSSL_STORE_INFO_get1_CERT(info: POSSL_STORE_INFO): PX509; cdecl;
begin
  OSSL_STORE_INFO_get1_CERT := LoadLibCryptoFunction('OSSL_STORE_INFO_get1_CERT');
  if not assigned(OSSL_STORE_INFO_get1_CERT) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get1_CERT');
  Result := OSSL_STORE_INFO_get1_CERT(info);
end;

function Load_OSSL_STORE_INFO_get0_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl;
begin
  OSSL_STORE_INFO_get0_CRL := LoadLibCryptoFunction('OSSL_STORE_INFO_get0_CRL');
  if not assigned(OSSL_STORE_INFO_get0_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get0_CRL');
  Result := OSSL_STORE_INFO_get0_CRL(info);
end;

function Load_OSSL_STORE_INFO_get1_CRL(info: POSSL_STORE_INFO): PX509_CRL; cdecl;
begin
  OSSL_STORE_INFO_get1_CRL := LoadLibCryptoFunction('OSSL_STORE_INFO_get1_CRL');
  if not assigned(OSSL_STORE_INFO_get1_CRL) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_get1_CRL');
  Result := OSSL_STORE_INFO_get1_CRL(info);
end;

function Load_OSSL_STORE_INFO_type_string(type_: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OSSL_STORE_INFO_type_string := LoadLibCryptoFunction('OSSL_STORE_INFO_type_string');
  if not assigned(OSSL_STORE_INFO_type_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_type_string');
  Result := OSSL_STORE_INFO_type_string(type_);
end;

procedure Load_OSSL_STORE_INFO_free(info: POSSL_STORE_INFO); cdecl;
begin
  OSSL_STORE_INFO_free := LoadLibCryptoFunction('OSSL_STORE_INFO_free');
  if not assigned(OSSL_STORE_INFO_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_INFO_free');
  OSSL_STORE_INFO_free(info);
end;

function Load_OSSL_STORE_supports_search(ctx: POSSL_STORE_CTX; search_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_supports_search := LoadLibCryptoFunction('OSSL_STORE_supports_search');
  if not assigned(OSSL_STORE_supports_search) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_supports_search');
  Result := OSSL_STORE_supports_search(ctx, search_type);
end;

function Load_OSSL_STORE_SEARCH_by_name(name: PX509_NAME): POSSL_STORE_SEARCH; cdecl;
begin
  OSSL_STORE_SEARCH_by_name := LoadLibCryptoFunction('OSSL_STORE_SEARCH_by_name');
  if not assigned(OSSL_STORE_SEARCH_by_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_by_name');
  Result := OSSL_STORE_SEARCH_by_name(name);
end;

function Load_OSSL_STORE_SEARCH_by_issuer_serial(name: PX509_NAME; serial: PASN1_INTEGER): POSSL_STORE_SEARCH; cdecl;
begin
  OSSL_STORE_SEARCH_by_issuer_serial := LoadLibCryptoFunction('OSSL_STORE_SEARCH_by_issuer_serial');
  if not assigned(OSSL_STORE_SEARCH_by_issuer_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_by_issuer_serial');
  Result := OSSL_STORE_SEARCH_by_issuer_serial(name, serial);
end;

function Load_OSSL_STORE_SEARCH_by_key_fingerprint(digest: PEVP_MD; bytes: Pbyte; len: TOpenSSL_C_SIZET): POSSL_STORE_SEARCH; cdecl;
begin
  OSSL_STORE_SEARCH_by_key_fingerprint := LoadLibCryptoFunction('OSSL_STORE_SEARCH_by_key_fingerprint');
  if not assigned(OSSL_STORE_SEARCH_by_key_fingerprint) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_by_key_fingerprint');
  Result := OSSL_STORE_SEARCH_by_key_fingerprint(digest, bytes, len);
end;

function Load_OSSL_STORE_SEARCH_by_alias(alias: PAnsiChar): POSSL_STORE_SEARCH; cdecl;
begin
  OSSL_STORE_SEARCH_by_alias := LoadLibCryptoFunction('OSSL_STORE_SEARCH_by_alias');
  if not assigned(OSSL_STORE_SEARCH_by_alias) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_by_alias');
  Result := OSSL_STORE_SEARCH_by_alias(alias);
end;

procedure Load_OSSL_STORE_SEARCH_free(search: POSSL_STORE_SEARCH); cdecl;
begin
  OSSL_STORE_SEARCH_free := LoadLibCryptoFunction('OSSL_STORE_SEARCH_free');
  if not assigned(OSSL_STORE_SEARCH_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_free');
  OSSL_STORE_SEARCH_free(search);
end;

function Load_OSSL_STORE_SEARCH_get_type(criterion: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_SEARCH_get_type := LoadLibCryptoFunction('OSSL_STORE_SEARCH_get_type');
  if not assigned(OSSL_STORE_SEARCH_get_type) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_get_type');
  Result := OSSL_STORE_SEARCH_get_type(criterion);
end;

function Load_OSSL_STORE_SEARCH_get0_name(criterion: POSSL_STORE_SEARCH): PX509_NAME; cdecl;
begin
  OSSL_STORE_SEARCH_get0_name := LoadLibCryptoFunction('OSSL_STORE_SEARCH_get0_name');
  if not assigned(OSSL_STORE_SEARCH_get0_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_get0_name');
  Result := OSSL_STORE_SEARCH_get0_name(criterion);
end;

function Load_OSSL_STORE_SEARCH_get0_serial(criterion: POSSL_STORE_SEARCH): PASN1_INTEGER; cdecl;
begin
  OSSL_STORE_SEARCH_get0_serial := LoadLibCryptoFunction('OSSL_STORE_SEARCH_get0_serial');
  if not assigned(OSSL_STORE_SEARCH_get0_serial) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_get0_serial');
  Result := OSSL_STORE_SEARCH_get0_serial(criterion);
end;

function Load_OSSL_STORE_SEARCH_get0_bytes(criterion: POSSL_STORE_SEARCH; length: POpenSSL_C_SIZET): Pbyte; cdecl;
begin
  OSSL_STORE_SEARCH_get0_bytes := LoadLibCryptoFunction('OSSL_STORE_SEARCH_get0_bytes');
  if not assigned(OSSL_STORE_SEARCH_get0_bytes) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_get0_bytes');
  Result := OSSL_STORE_SEARCH_get0_bytes(criterion, length);
end;

function Load_OSSL_STORE_SEARCH_get0_string(criterion: POSSL_STORE_SEARCH): PAnsiChar; cdecl;
begin
  OSSL_STORE_SEARCH_get0_string := LoadLibCryptoFunction('OSSL_STORE_SEARCH_get0_string');
  if not assigned(OSSL_STORE_SEARCH_get0_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_get0_string');
  Result := OSSL_STORE_SEARCH_get0_string(criterion);
end;

function Load_OSSL_STORE_SEARCH_get0_digest(criterion: POSSL_STORE_SEARCH): PEVP_MD; cdecl;
begin
  OSSL_STORE_SEARCH_get0_digest := LoadLibCryptoFunction('OSSL_STORE_SEARCH_get0_digest');
  if not assigned(OSSL_STORE_SEARCH_get0_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_SEARCH_get0_digest');
  Result := OSSL_STORE_SEARCH_get0_digest(criterion);
end;

function Load_OSSL_STORE_expect(ctx: POSSL_STORE_CTX; expected_type: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_expect := LoadLibCryptoFunction('OSSL_STORE_expect');
  if not assigned(OSSL_STORE_expect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_expect');
  Result := OSSL_STORE_expect(ctx, expected_type);
end;

function Load_OSSL_STORE_find(ctx: POSSL_STORE_CTX; search: POSSL_STORE_SEARCH): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_find := LoadLibCryptoFunction('OSSL_STORE_find');
  if not assigned(OSSL_STORE_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_find');
  Result := OSSL_STORE_find(ctx, search);
end;

function Load_OSSL_STORE_LOADER_fetch(libctx: POSSL_LIB_CTX; scheme: PAnsiChar; properties: PAnsiChar): POSSL_STORE_LOADER; cdecl;
begin
  OSSL_STORE_LOADER_fetch := LoadLibCryptoFunction('OSSL_STORE_LOADER_fetch');
  if not assigned(OSSL_STORE_LOADER_fetch) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_fetch');
  Result := OSSL_STORE_LOADER_fetch(libctx, scheme, properties);
end;

function Load_OSSL_STORE_LOADER_up_ref(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_up_ref := LoadLibCryptoFunction('OSSL_STORE_LOADER_up_ref');
  if not assigned(OSSL_STORE_LOADER_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_up_ref');
  Result := OSSL_STORE_LOADER_up_ref(loader);
end;

procedure Load_OSSL_STORE_LOADER_free(loader: POSSL_STORE_LOADER); cdecl;
begin
  OSSL_STORE_LOADER_free := LoadLibCryptoFunction('OSSL_STORE_LOADER_free');
  if not assigned(OSSL_STORE_LOADER_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_free');
  OSSL_STORE_LOADER_free(loader);
end;

function Load_OSSL_STORE_LOADER_get0_provider(loader: POSSL_STORE_LOADER): POSSL_PROVIDER; cdecl;
begin
  OSSL_STORE_LOADER_get0_provider := LoadLibCryptoFunction('OSSL_STORE_LOADER_get0_provider');
  if not assigned(OSSL_STORE_LOADER_get0_provider) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_get0_provider');
  Result := OSSL_STORE_LOADER_get0_provider(loader);
end;

function Load_OSSL_STORE_LOADER_get0_properties(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl;
begin
  OSSL_STORE_LOADER_get0_properties := LoadLibCryptoFunction('OSSL_STORE_LOADER_get0_properties');
  if not assigned(OSSL_STORE_LOADER_get0_properties) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_get0_properties');
  Result := OSSL_STORE_LOADER_get0_properties(loader);
end;

function Load_OSSL_STORE_LOADER_get0_description(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl;
begin
  OSSL_STORE_LOADER_get0_description := LoadLibCryptoFunction('OSSL_STORE_LOADER_get0_description');
  if not assigned(OSSL_STORE_LOADER_get0_description) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_get0_description');
  Result := OSSL_STORE_LOADER_get0_description(loader);
end;

function Load_OSSL_STORE_LOADER_is_a(loader: POSSL_STORE_LOADER; scheme: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_is_a := LoadLibCryptoFunction('OSSL_STORE_LOADER_is_a');
  if not assigned(OSSL_STORE_LOADER_is_a) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_is_a');
  Result := OSSL_STORE_LOADER_is_a(loader, scheme);
end;

procedure Load_OSSL_STORE_LOADER_do_all_provided(libctx: POSSL_LIB_CTX; fn: TFuncType000; arg: pointer); cdecl;
begin
  OSSL_STORE_LOADER_do_all_provided := LoadLibCryptoFunction('OSSL_STORE_LOADER_do_all_provided');
  if not assigned(OSSL_STORE_LOADER_do_all_provided) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_do_all_provided');
  OSSL_STORE_LOADER_do_all_provided(libctx, fn, arg);
end;

function Load_OSSL_STORE_LOADER_names_do_all(loader: POSSL_STORE_LOADER; fn: TFuncType001; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_names_do_all := LoadLibCryptoFunction('OSSL_STORE_LOADER_names_do_all');
  if not assigned(OSSL_STORE_LOADER_names_do_all) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_names_do_all');
  Result := OSSL_STORE_LOADER_names_do_all(loader, fn, data);
end;

{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_OSSL_STORE_LOADER_new(e: PENGINE; scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl;
begin
  OSSL_STORE_LOADER_new := LoadLibCryptoFunction('OSSL_STORE_LOADER_new');
  if not assigned(OSSL_STORE_LOADER_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_new');
  Result := OSSL_STORE_LOADER_new(e, scheme);
end;

function Load_OSSL_STORE_LOADER_set_open(loader: POSSL_STORE_LOADER; open_function: TOSSL_STORE_open_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_open := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_open');
  if not assigned(OSSL_STORE_LOADER_set_open) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_open');
  Result := OSSL_STORE_LOADER_set_open(loader, open_function);
end;

function Load_OSSL_STORE_LOADER_set_open_ex(loader: POSSL_STORE_LOADER; open_ex_function: TOSSL_STORE_open_ex_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_open_ex := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_open_ex');
  if not assigned(OSSL_STORE_LOADER_set_open_ex) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_open_ex');
  Result := OSSL_STORE_LOADER_set_open_ex(loader, open_ex_function);
end;

function Load_OSSL_STORE_LOADER_set_attach(loader: POSSL_STORE_LOADER; attach_function: TOSSL_STORE_attach_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_attach := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_attach');
  if not assigned(OSSL_STORE_LOADER_set_attach) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_attach');
  Result := OSSL_STORE_LOADER_set_attach(loader, attach_function);
end;

function Load_OSSL_STORE_LOADER_set_ctrl(loader: POSSL_STORE_LOADER; ctrl_function: TOSSL_STORE_ctrl_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_ctrl := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_ctrl');
  if not assigned(OSSL_STORE_LOADER_set_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_ctrl');
  Result := OSSL_STORE_LOADER_set_ctrl(loader, ctrl_function);
end;

function Load_OSSL_STORE_LOADER_set_expect(loader: POSSL_STORE_LOADER; expect_function: TOSSL_STORE_expect_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_expect := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_expect');
  if not assigned(OSSL_STORE_LOADER_set_expect) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_expect');
  Result := OSSL_STORE_LOADER_set_expect(loader, expect_function);
end;

function Load_OSSL_STORE_LOADER_set_find(loader: POSSL_STORE_LOADER; find_function: TOSSL_STORE_find_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_find := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_find');
  if not assigned(OSSL_STORE_LOADER_set_find) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_find');
  Result := OSSL_STORE_LOADER_set_find(loader, find_function);
end;

function Load_OSSL_STORE_LOADER_set_load(loader: POSSL_STORE_LOADER; load_function: TOSSL_STORE_load_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_load := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_load');
  if not assigned(OSSL_STORE_LOADER_set_load) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_load');
  Result := OSSL_STORE_LOADER_set_load(loader, load_function);
end;

function Load_OSSL_STORE_LOADER_set_eof(loader: POSSL_STORE_LOADER; eof_function: TOSSL_STORE_eof_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_eof := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_eof');
  if not assigned(OSSL_STORE_LOADER_set_eof) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_eof');
  Result := OSSL_STORE_LOADER_set_eof(loader, eof_function);
end;

function Load_OSSL_STORE_LOADER_set_error(loader: POSSL_STORE_LOADER; error_function: TOSSL_STORE_error_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_error := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_error');
  if not assigned(OSSL_STORE_LOADER_set_error) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_error');
  Result := OSSL_STORE_LOADER_set_error(loader, error_function);
end;

function Load_OSSL_STORE_LOADER_set_close(loader: POSSL_STORE_LOADER; close_function: TOSSL_STORE_close_fn): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_LOADER_set_close := LoadLibCryptoFunction('OSSL_STORE_LOADER_set_close');
  if not assigned(OSSL_STORE_LOADER_set_close) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_set_close');
  Result := OSSL_STORE_LOADER_set_close(loader, close_function);
end;

function Load_OSSL_STORE_LOADER_get0_engine(loader: POSSL_STORE_LOADER): PENGINE; cdecl;
begin
  OSSL_STORE_LOADER_get0_engine := LoadLibCryptoFunction('OSSL_STORE_LOADER_get0_engine');
  if not assigned(OSSL_STORE_LOADER_get0_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_get0_engine');
  Result := OSSL_STORE_LOADER_get0_engine(loader);
end;

function Load_OSSL_STORE_LOADER_get0_scheme(loader: POSSL_STORE_LOADER): PAnsiChar; cdecl;
begin
  OSSL_STORE_LOADER_get0_scheme := LoadLibCryptoFunction('OSSL_STORE_LOADER_get0_scheme');
  if not assigned(OSSL_STORE_LOADER_get0_scheme) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_LOADER_get0_scheme');
  Result := OSSL_STORE_LOADER_get0_scheme(loader);
end;

function Load_OSSL_STORE_register_loader(loader: POSSL_STORE_LOADER): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_register_loader := LoadLibCryptoFunction('OSSL_STORE_register_loader');
  if not assigned(OSSL_STORE_register_loader) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_register_loader');
  Result := OSSL_STORE_register_loader(loader);
end;

function Load_OSSL_STORE_unregister_loader(scheme: PAnsiChar): POSSL_STORE_LOADER; cdecl;
begin
  OSSL_STORE_unregister_loader := LoadLibCryptoFunction('OSSL_STORE_unregister_loader');
  if not assigned(OSSL_STORE_unregister_loader) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_unregister_loader');
  Result := OSSL_STORE_unregister_loader(scheme);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_OSSL_STORE_do_all_loaders(do_function: TFuncType002; do_arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_STORE_do_all_loaders := LoadLibCryptoFunction('OSSL_STORE_do_all_loaders');
  if not assigned(OSSL_STORE_do_all_loaders) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_STORE_do_all_loaders');
  Result := OSSL_STORE_do_all_loaders(do_function, do_arg);
end;

{$endif} { OPENSSL_NO_DEPRECATED_3_0}
procedure Load;
begin
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  OSSL_STORE_ctrl := LoadLibCryptoFunction('OSSL_STORE_ctrl');
  OSSL_STORE_vctrl := LoadLibCryptoFunction('OSSL_STORE_vctrl');
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
end;

procedure Unload;
begin
  OSSL_STORE_open := Load_OSSL_STORE_open;
  OSSL_STORE_open_ex := Load_OSSL_STORE_open_ex;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  OSSL_STORE_ctrl := nil;
  OSSL_STORE_vctrl := nil;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
  OSSL_STORE_load := Load_OSSL_STORE_load;
  OSSL_STORE_delete := Load_OSSL_STORE_delete;
  OSSL_STORE_eof := Load_OSSL_STORE_eof;
  OSSL_STORE_error := Load_OSSL_STORE_error;
  OSSL_STORE_close := Load_OSSL_STORE_close;
  OSSL_STORE_attach := Load_OSSL_STORE_attach;
  OSSL_STORE_INFO_new := Load_OSSL_STORE_INFO_new;
  OSSL_STORE_INFO_new_NAME := Load_OSSL_STORE_INFO_new_NAME;
  OSSL_STORE_INFO_set0_NAME_description := Load_OSSL_STORE_INFO_set0_NAME_description;
  OSSL_STORE_INFO_new_PARAMS := Load_OSSL_STORE_INFO_new_PARAMS;
  OSSL_STORE_INFO_new_PUBKEY := Load_OSSL_STORE_INFO_new_PUBKEY;
  OSSL_STORE_INFO_new_PKEY := Load_OSSL_STORE_INFO_new_PKEY;
  OSSL_STORE_INFO_new_CERT := Load_OSSL_STORE_INFO_new_CERT;
  OSSL_STORE_INFO_new_CRL := Load_OSSL_STORE_INFO_new_CRL;
  OSSL_STORE_INFO_get_type := Load_OSSL_STORE_INFO_get_type;
  OSSL_STORE_INFO_get0_data := Load_OSSL_STORE_INFO_get0_data;
  OSSL_STORE_INFO_get0_NAME := Load_OSSL_STORE_INFO_get0_NAME;
  OSSL_STORE_INFO_get1_NAME := Load_OSSL_STORE_INFO_get1_NAME;
  OSSL_STORE_INFO_get0_NAME_description := Load_OSSL_STORE_INFO_get0_NAME_description;
  OSSL_STORE_INFO_get1_NAME_description := Load_OSSL_STORE_INFO_get1_NAME_description;
  OSSL_STORE_INFO_get0_PARAMS := Load_OSSL_STORE_INFO_get0_PARAMS;
  OSSL_STORE_INFO_get1_PARAMS := Load_OSSL_STORE_INFO_get1_PARAMS;
  OSSL_STORE_INFO_get0_PUBKEY := Load_OSSL_STORE_INFO_get0_PUBKEY;
  OSSL_STORE_INFO_get1_PUBKEY := Load_OSSL_STORE_INFO_get1_PUBKEY;
  OSSL_STORE_INFO_get0_PKEY := Load_OSSL_STORE_INFO_get0_PKEY;
  OSSL_STORE_INFO_get1_PKEY := Load_OSSL_STORE_INFO_get1_PKEY;
  OSSL_STORE_INFO_get0_CERT := Load_OSSL_STORE_INFO_get0_CERT;
  OSSL_STORE_INFO_get1_CERT := Load_OSSL_STORE_INFO_get1_CERT;
  OSSL_STORE_INFO_get0_CRL := Load_OSSL_STORE_INFO_get0_CRL;
  OSSL_STORE_INFO_get1_CRL := Load_OSSL_STORE_INFO_get1_CRL;
  OSSL_STORE_INFO_type_string := Load_OSSL_STORE_INFO_type_string;
  OSSL_STORE_INFO_free := Load_OSSL_STORE_INFO_free;
  OSSL_STORE_supports_search := Load_OSSL_STORE_supports_search;
  OSSL_STORE_SEARCH_by_name := Load_OSSL_STORE_SEARCH_by_name;
  OSSL_STORE_SEARCH_by_issuer_serial := Load_OSSL_STORE_SEARCH_by_issuer_serial;
  OSSL_STORE_SEARCH_by_key_fingerprint := Load_OSSL_STORE_SEARCH_by_key_fingerprint;
  OSSL_STORE_SEARCH_by_alias := Load_OSSL_STORE_SEARCH_by_alias;
  OSSL_STORE_SEARCH_free := Load_OSSL_STORE_SEARCH_free;
  OSSL_STORE_SEARCH_get_type := Load_OSSL_STORE_SEARCH_get_type;
  OSSL_STORE_SEARCH_get0_name := Load_OSSL_STORE_SEARCH_get0_name;
  OSSL_STORE_SEARCH_get0_serial := Load_OSSL_STORE_SEARCH_get0_serial;
  OSSL_STORE_SEARCH_get0_bytes := Load_OSSL_STORE_SEARCH_get0_bytes;
  OSSL_STORE_SEARCH_get0_string := Load_OSSL_STORE_SEARCH_get0_string;
  OSSL_STORE_SEARCH_get0_digest := Load_OSSL_STORE_SEARCH_get0_digest;
  OSSL_STORE_expect := Load_OSSL_STORE_expect;
  OSSL_STORE_find := Load_OSSL_STORE_find;
  OSSL_STORE_LOADER_fetch := Load_OSSL_STORE_LOADER_fetch;
  OSSL_STORE_LOADER_up_ref := Load_OSSL_STORE_LOADER_up_ref;
  OSSL_STORE_LOADER_free := Load_OSSL_STORE_LOADER_free;
  OSSL_STORE_LOADER_get0_provider := Load_OSSL_STORE_LOADER_get0_provider;
  OSSL_STORE_LOADER_get0_properties := Load_OSSL_STORE_LOADER_get0_properties;
  OSSL_STORE_LOADER_get0_description := Load_OSSL_STORE_LOADER_get0_description;
  OSSL_STORE_LOADER_is_a := Load_OSSL_STORE_LOADER_is_a;
  OSSL_STORE_LOADER_do_all_provided := Load_OSSL_STORE_LOADER_do_all_provided;
  OSSL_STORE_LOADER_names_do_all := Load_OSSL_STORE_LOADER_names_do_all;
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  OSSL_STORE_LOADER_new := Load_OSSL_STORE_LOADER_new;
  OSSL_STORE_LOADER_set_open := Load_OSSL_STORE_LOADER_set_open;
  OSSL_STORE_LOADER_set_open_ex := Load_OSSL_STORE_LOADER_set_open_ex;
  OSSL_STORE_LOADER_set_attach := Load_OSSL_STORE_LOADER_set_attach;
  OSSL_STORE_LOADER_set_ctrl := Load_OSSL_STORE_LOADER_set_ctrl;
  OSSL_STORE_LOADER_set_expect := Load_OSSL_STORE_LOADER_set_expect;
  OSSL_STORE_LOADER_set_find := Load_OSSL_STORE_LOADER_set_find;
  OSSL_STORE_LOADER_set_load := Load_OSSL_STORE_LOADER_set_load;
  OSSL_STORE_LOADER_set_eof := Load_OSSL_STORE_LOADER_set_eof;
  OSSL_STORE_LOADER_set_error := Load_OSSL_STORE_LOADER_set_error;
  OSSL_STORE_LOADER_set_close := Load_OSSL_STORE_LOADER_set_close;
  OSSL_STORE_LOADER_get0_engine := Load_OSSL_STORE_LOADER_get0_engine;
  OSSL_STORE_LOADER_get0_scheme := Load_OSSL_STORE_LOADER_get0_scheme;
  OSSL_STORE_register_loader := Load_OSSL_STORE_register_loader;
  OSSL_STORE_unregister_loader := Load_OSSL_STORE_unregister_loader;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
{$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  OSSL_STORE_do_all_loaders := Load_OSSL_STORE_do_all_loaders;
{$endif} { OPENSSL_NO_DEPRECATED_3_0}
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



