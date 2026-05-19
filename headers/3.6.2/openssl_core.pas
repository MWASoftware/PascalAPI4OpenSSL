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

unit openssl_core;

{
  Generated from OpenSSL 3.6.2 Header File core.h - Tue 19 May 14:29:43 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_core.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types;


{* Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_CORE_H}
  {$define OPENSSL_CORE_H}

type
  {Auto-generated forward references}
  Possl_core_handle_st = ^TOSSL_CORE_HANDLE;
  PPossl_core_handle_st = ^Possl_core_handle_st;
  POSSL_CORE_HANDLE = ^TOSSL_CORE_HANDLE;
  PPOSSL_CORE_HANDLE = ^POSSL_CORE_HANDLE;
  Popenssl_core_ctx_st = ^TOPENSSL_CORE_CTX;
  PPopenssl_core_ctx_st = ^Popenssl_core_ctx_st;
  POPENSSL_CORE_CTX = ^TOPENSSL_CORE_CTX;
  PPOPENSSL_CORE_CTX = ^POPENSSL_CORE_CTX;
  Possl_core_bio_st = ^TOSSL_CORE_BIO;
  PPossl_core_bio_st = ^Possl_core_bio_st;
  POSSL_CORE_BIO = ^TOSSL_CORE_BIO;
  PPOSSL_CORE_BIO = ^POSSL_CORE_BIO;
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  Possl_dispatch_st = ^Tossl_dispatch_st;
  PPossl_dispatch_st = ^Possl_dispatch_st;
  Possl_item_st = ^Tossl_item_st;
  PPossl_item_st = ^Possl_item_st;
  Possl_algorithm_st = ^Tossl_algorithm_st;
  PPossl_algorithm_st = ^Possl_algorithm_st;
  Possl_param_st = ^Tossl_param_st;
  PPossl_param_st = ^Possl_param_st;
  {end of auto-generated forward references}

  {-
  * Base types
  * ----------
  *
  * These are the types that the OpenSSL core and providers have in common
  * to communicate data between them.
  }
  { Opaque handles to be used with core upcall functions from providers }
  Tossl_core_handle_st = record end;
  TOSSL_CORE_HANDLE = Tossl_core_handle_st;
  Topenssl_core_ctx_st = record end;
  TOPENSSL_CORE_CTX = Topenssl_core_ctx_st;
  Tossl_core_bio_st = record end;
  TOSSL_CORE_BIO = Tossl_core_bio_st;
  
  {* Dispatch table element.  function_id numbers and the functions are defined
  * in core_dispatch.h, see macros with 'OSSL_CORE_MAKE_FUNC' in their names.
  *
  * An array of these is always terminated by function_id == 0
  }
  TFuncType000 = procedure; cdecl;
  Tossl_dispatch_st = record 
    function_id: TOpenSSL_C_INT;
    function_: TFuncType000;
  end;
  (*# define  OSSL_DISPATCH_END { 0, NULL }*)
  
  {* Other items, essentially an int<->pointer map element.
  *
  * We make this type distinct from OSSL_DISPATCH to ensure that dispatch
  * tables remain tables with function pointers only.
  *
  * This is used whenever we need to pass things like a table of error reason
  * codes <-> reason string maps, ...
  *
  * Usage determines which field works as key if any, rather than field order.
  *
  * An array of these is always terminated by id == 0 && ptr == NULL
  }
  Tossl_item_st = record 
    id: TOpenSSL_C_UINT;
    ptr: pointer;
  end;
  
  {* Type to tie together algorithm names, property definition string and
  * the algorithm implementation in the form of a dispatch table.
  *
  * An array of these is always terminated by algorithm_names == NULL
  }
  Tossl_algorithm_st = record 
    algorithm_names: PAnsiChar; { key }
    property_definition: PAnsiChar; { key }
    implementation_: POSSL_DISPATCH;
    algorithm_description: PAnsiChar;
  end;
  
  {* Type to pass object data in a uniform way, without exposing the object
  * structure.
  *
  * An array of these is always terminated by key == NULL
  }
  Tossl_param_st = record 
    key: PAnsiChar; { the name of the parameter }
    data_type: TOpenSSL_C_UINT; { declare what kind of content is in buffer }
    data: pointer; { value being passed in or out }
    data_size: TOpenSSL_C_SIZET; { data size }
    return_size: TOpenSSL_C_SIZET; { returned content size }
  end;

const
  { Currently supported OSSL_PARAM data types }
  
  {* OSSL_PARAM_INTEGER and OSSL_PARAM_UNSIGNED_INTEGER
  * are arbitrary length and therefore require an arbitrarily sized buffer,
  * since they may be used to pass numbers larger than what is natively
  * available.
  *
  * The number must be buffered in native form, i.e. MSB first on B_ENDIAN
  * systems and LSB first on L_ENDIAN systems.  This means that arbitrary
  * native integers can be stored in the buffer, just make sure that the
  * buffer size is correct and the buffer itself is properly aligned (for
  * example by having the buffer field point at a C integer).
  }
  OSSL_PARAM_INTEGER = 1;
  OSSL_PARAM_UNSIGNED_INTEGER = 2;
  {-
  * OSSL_PARAM_REAL
  * is a C binary floating point values in native form and alignment.
  }
  OSSL_PARAM_REAL = 3;
  {-
  * OSSL_PARAM_UTF8_STRING
  * is a printable string.  It is expected to be printed as it is.
  }
  OSSL_PARAM_UTF8_STRING = 4;
  {-
  * OSSL_PARAM_OCTET_STRING
  * is a string of bytes with no further specification.  It is expected to be
  * printed as a hexdump.
  }
  OSSL_PARAM_OCTET_STRING = 5;
  {-
  * OSSL_PARAM_UTF8_PTR
  * is a pointer to a printable string.  It is expected to be printed as it is.
  *
  * The difference between this and OSSL_PARAM_UTF8_STRING is that only pointers
  * are manipulated for this type.
  *
  * This is more relevant for parameter requests, where the responding
  * function doesn't need to copy the data to the provided buffer, but
  * sets the provided buffer to point at the actual data instead.
  *
  * WARNING!  Using these is FRAGILE, as it assumes that the actual
  * data and its location are constant.
  *
  * EXTRA WARNING!  If you are not completely sure you most likely want
  * to use the OSSL_PARAM_UTF8_STRING type.
  }
  OSSL_PARAM_UTF8_PTR = 6;
  {-
  * OSSL_PARAM_OCTET_PTR
  * is a pointer to a string of bytes with no further specification.  It is
  * expected to be printed as a hexdump.
  *
  * The difference between this and OSSL_PARAM_OCTET_STRING is that only pointers
  * are manipulated for this type.
  *
  * This is more relevant for parameter requests, where the responding
  * function doesn't need to copy the data to the provided buffer, but
  * sets the provided buffer to point at the actual data instead.
  *
  * WARNING!  Using these is FRAGILE, as it assumes that the actual
  * data and its location are constant.
  *
  * EXTRA WARNING!  If you are not completely sure you most likely want
  * to use the OSSL_PARAM_OCTET_STRING type.
  }
  OSSL_PARAM_OCTET_PTR = 7;

type
  {Auto-generated forward references}
  POSSL_thread_stop_handler_fn = ^TOSSL_thread_stop_handler_fn;
  PPOSSL_thread_stop_handler_fn = ^POSSL_thread_stop_handler_fn;
  POSSL_provider_init_fn = ^TOSSL_provider_init_fn;
  PPOSSL_provider_init_fn = ^POSSL_provider_init_fn;
  {end of auto-generated forward references}

  
  {* Typedef for the thread stop handling callback. Used both internally and by
  * providers.
  *
  * Providers may register for notifications about threads stopping by
  * registering a callback to hear about such events. Providers register the
  * callback using the OSSL_FUNC_CORE_THREAD_START function in the |in| dispatch
  * table passed to OSSL_provider_init(). The arg passed back to a provider will
  * be the provider side context object.
  }
  TOSSL_thread_stop_handler_fn = procedure(arg: pointer); cdecl;
  {-
  * Provider entry point
  * --------------------
  *
  * This function is expected to be present in any dynamically loadable
  * provider module.  By definition, if this function doesn't exist in a
  * module, that module is not an OpenSSL provider module.
  }
  {-
  * |handle|     pointer to opaque type OSSL_CORE_HANDLE.  This can be used
  *              together with some functions passed via |in| to query data.
  * |in|         is the array of functions that the Core passes to the provider.
  * |out|        will be the array of base functions that the provider passes
  *              back to the Core.
  * |provctx|    a provider side context object, optionally created if the
  *              provider needs it.  This value is passed to other provider
  *              functions, notably other context constructors.
  }
  TOSSL_provider_init_fn = function(handle: POSSL_CORE_HANDLE; in_: POSSL_DISPATCH; out_: PPOSSL_DISPATCH; provctx: Ppointer): TOpenSSL_C_INT; cdecl;
  {$ifdef __VMS}
  {$endif}
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  {$ifdef FPC}

var
  OSSL_provider_init: TOSSL_provider_init_fn cvar; public;
  {$endif}
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$ifdef __VMS}
  {$endif}

type
  {Auto-generated forward references}
  POSSL_CALLBACK = ^TOSSL_CALLBACK;
  PPOSSL_CALLBACK = ^POSSL_CALLBACK;
  POSSL_INOUT_CALLBACK = ^TOSSL_INOUT_CALLBACK;
  PPOSSL_INOUT_CALLBACK = ^POSSL_INOUT_CALLBACK;
  POSSL_PASSPHRASE_CALLBACK = ^TOSSL_PASSPHRASE_CALLBACK;
  PPOSSL_PASSPHRASE_CALLBACK = ^POSSL_PASSPHRASE_CALLBACK;
  {end of auto-generated forward references}

  
  {* Generic callback function signature.
  *
  * The expectation is that any provider function that wants to offer
  * a callback / hook can do so by taking an argument with this type,
  * as well as a pointer to caller-specific data.  When calling the
  * callback, the provider function can populate an OSSL_PARAM array
  * with data of its choice and pass that in the callback call, along
  * with the caller data argument.
  *
  * libcrypto may use the OSSL_PARAM array to create arguments for an
  * application callback it knows about.
  }
  TOSSL_CALLBACK = function(params: POSSL_PARAM; arg: pointer): TOpenSSL_C_INT; cdecl;
  TOSSL_INOUT_CALLBACK = function(in_params: POSSL_PARAM; out_params: POSSL_PARAM; arg: pointer): TOpenSSL_C_INT; cdecl;
  
  {* Passphrase callback function signature
  *
  * This is similar to the generic callback function above, but adds a
  * result parameter.
  }
  TOSSL_PASSPHRASE_CALLBACK = function(pass: PAnsiChar; pass_size: TOpenSSL_C_SIZET; pass_len: POpenSSL_C_SIZET; params: POSSL_PARAM; arg: pointer): TOpenSSL_C_INT; cdecl;
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



