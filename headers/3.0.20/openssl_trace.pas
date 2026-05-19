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

unit openssl_trace;

{
  Generated from OpenSSL 3.0.20 Header File trace.h - Tue 19 May 14:16:47 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_trace.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_types,openssl_bio;


{* Copyright 2019-2023 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_TRACE_H}
  {$define OPENSSL_TRACE_H}

const
  
  {* TRACE CATEGORIES
  }
  
  {* The trace messages of the OpenSSL libraries are organized into different
  * categories. For every trace category, the application can register a separate
  * tracer callback. When a callback is registered, a so called trace channel is
  * created for this category. This channel consists essentially of an internal
  * BIO which sends all trace output it receives to the registered application
  * callback.
  *
  * The ALL category can be used as a fallback category to register a single
  * channel which receives the output from all categories. However, if the
  * application intends to print the trace channel name in the line prefix,
  * it is better to register channels for all categories separately.
  * (This is how the openssl application does it.)
  }
  OSSL_TRACE_CATEGORY_ALL = 0;
  OSSL_TRACE_CATEGORY_TRACE = 1;
  OSSL_TRACE_CATEGORY_INIT = 2;
  OSSL_TRACE_CATEGORY_TLS = 3;
  OSSL_TRACE_CATEGORY_TLS_CIPHER = 4;
  OSSL_TRACE_CATEGORY_CONF = 5;
  OSSL_TRACE_CATEGORY_ENGINE_TABLE = 6;
  OSSL_TRACE_CATEGORY_ENGINE_REF_COUNT = 7;
  OSSL_TRACE_CATEGORY_PKCS5V2 = 8;
  OSSL_TRACE_CATEGORY_PKCS12_KEYGEN = 9;
  OSSL_TRACE_CATEGORY_PKCS12_DECRYPT = 10;
  OSSL_TRACE_CATEGORY_X509V3_POLICY = 11;
  OSSL_TRACE_CATEGORY_BN_CTX = 12;
  OSSL_TRACE_CATEGORY_CMP = 13;
  OSSL_TRACE_CATEGORY_STORE = 14;
  OSSL_TRACE_CATEGORY_DECODER = 15;
  OSSL_TRACE_CATEGORY_ENCODER = 16;
  OSSL_TRACE_CATEGORY_REF_COUNT = 17;
  { Count of available categories. }
  OSSL_TRACE_CATEGORY_NUM = 18;


  { Returns the trace category number for the given |name| }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_trace_get_category_num(name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_trace_get_category_num';
  { Returns the trace category name for the given |num| }
  function OSSL_trace_get_category_name(num: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto name 'OSSL_trace_get_category_name';
  
  {* TRACE CONSUMERS
  }
  
  {* Enables tracing for the given |category| by providing a BIO sink
  * as |channel|. If a null pointer is passed as |channel|, an existing
  * trace channel is removed and tracing for the category is disabled.
  *
  * Returns 1 on success and 0 on failure
  }
  function OSSL_trace_set_channel(category: TOpenSSL_C_INT; channel: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_trace_set_channel';
  
  {* Attach a prefix and a suffix to the given |category|, to be printed at the
  * beginning and at the end of each trace output group, i.e. when
  * OSSL_trace_begin() and OSSL_trace_end() are called.
  * If a null pointer is passed as argument, the existing prefix or suffix is
  * removed.
  *
  * They return 1 on success and 0 on failure
  }
  function OSSL_trace_set_prefix(category: TOpenSSL_C_INT; prefix: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_trace_set_prefix';
  function OSSL_trace_set_suffix(category: TOpenSSL_C_INT; suffix: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_trace_set_suffix';
  
  {* OSSL_trace_cb is the type tracing callback provided by the application.
  * It MUST return the number of bytes written, or 0 on error (in other words,
  * it can never write zero bytes).
  *
  * The |buffer| will always contain text, which may consist of several lines.
  * The |data| argument points to whatever data was provided by the application
  * when registering the tracer function.
  *
  * The |category| number is given, as well as a |cmd| number, described below.
  }
  {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM OSSL_trace_get_category_num}
  {$EXTERNALSYM OSSL_trace_get_category_name}
  {$EXTERNALSYM OSSL_trace_set_channel}
  {$EXTERNALSYM OSSL_trace_set_prefix}
  {$EXTERNALSYM OSSL_trace_set_suffix}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_trace_get_category_num(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_trace_get_category_name(num: TOpenSSL_C_INT): PAnsiChar; cdecl;
  function Load_OSSL_trace_set_channel(category: TOpenSSL_C_INT; channel: PBIO): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_trace_set_prefix(category: TOpenSSL_C_INT; prefix: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_trace_set_suffix(category: TOpenSSL_C_INT; suffix: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  OSSL_trace_get_category_num: function(name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_trace_get_category_num;
  { Returns the trace category name for the given |num| }
  OSSL_trace_get_category_name: function(num: TOpenSSL_C_INT): PAnsiChar; cdecl = Load_OSSL_trace_get_category_name;
  
  {* TRACE CONSUMERS
  }
  
  {* Enables tracing for the given |category| by providing a BIO sink
  * as |channel|. If a null pointer is passed as |channel|, an existing
  * trace channel is removed and tracing for the category is disabled.
  *
  * Returns 1 on success and 0 on failure
  }
  OSSL_trace_set_channel: function(category: TOpenSSL_C_INT; channel: PBIO): TOpenSSL_C_INT; cdecl = Load_OSSL_trace_set_channel;
  
  {* Attach a prefix and a suffix to the given |category|, to be printed at the
  * beginning and at the end of each trace output group, i.e. when
  * OSSL_trace_begin() and OSSL_trace_end() are called.
  * If a null pointer is passed as argument, the existing prefix or suffix is
  * removed.
  *
  * They return 1 on success and 0 on failure
  }
  OSSL_trace_set_prefix: function(category: TOpenSSL_C_INT; prefix: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_trace_set_prefix;
  OSSL_trace_set_suffix: function(category: TOpenSSL_C_INT; suffix: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_OSSL_trace_set_suffix;
  
  {* OSSL_trace_cb is the type tracing callback provided by the application.
  * It MUST return the number of bytes written, or 0 on error (in other words,
  * it can never write zero bytes).
  *
  * The |buffer| will always contain text, which may consist of several lines.
  * The |data| argument points to whatever data was provided by the application
  * when registering the tracer function.
  *
  * The |category| number is given, as well as a |cmd| number, described below.
  }
  {$endif} {OPENSSL_STATIC_LINK_MODEL}

type
  {Auto-generated forward references}
  POSSL_trace_cb = ^TOSSL_trace_cb;
  PPOSSL_trace_cb = ^POSSL_trace_cb;
  {end of auto-generated forward references}

  TOSSL_trace_cb = function(buffer: PAnsiChar; count: TOpenSSL_C_SIZET; category: TOpenSSL_C_INT; cmd: TOpenSSL_C_INT; data: pointer): TOpenSSL_C_SIZET; cdecl;

const
  
  {* Possible |cmd| numbers.
  }
  OSSL_TRACE_CTRL_BEGIN = 0;
  OSSL_TRACE_CTRL_WRITE = 1;
  OSSL_TRACE_CTRL_END = 2;


  
  {* Enables tracing for the given |category| by creating an internal
  * trace channel which sends the output to the given |callback|.
  * If a null pointer is passed as callback, an existing trace channel
  * is removed and tracing for the category is disabled.
  *
  * NOTE: OSSL_trace_set_channel() and OSSL_trace_set_callback() are mutually
  *       exclusive.
  *
  * Returns 1 on success and 0 on failure
  }
  {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function OSSL_trace_set_callback(category: TOpenSSL_C_INT; callback: TOSSL_trace_cb; data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_trace_set_callback';
  
  {* TRACE PRODUCERS
  }
  
  {* Returns 1 if tracing for the specified category is enabled, otherwise 0
  }
  function OSSL_trace_enabled(category: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'OSSL_trace_enabled';
  
  (** Wrap a group of tracing output calls.  OSSL_trace_begin() locks tracing and
  * returns the trace channel associated with the given category, or NULL if no
  * channel is associated with the category.  OSSL_trace_end() unlocks tracing.
  *
  * Usage:
  *
  *    BIO *out;
  *    if ((out = OSSL_trace_begin(category)) != NULL) {
  *        ...
  *        BIO_fprintf(out, ...);
  *        ...
  *        OSSL_trace_end(category, out);
  *    }
  *
  * See also the convenience macros OSSL_TRACE_BEGIN and OSSL_TRACE_END below.
  *)
  function OSSL_trace_begin(category: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto name 'OSSL_trace_begin';
  procedure OSSL_trace_end(category: TOpenSSL_C_INT; channel: PBIO); cdecl; external CLibCrypto name 'OSSL_trace_end';
  
  {* OSSL_TRACE* Convenience Macros
  }
  
  {* When the tracing feature is disabled, these macros are defined to
  * produce dead code, which a good compiler should eliminate.
  }
  
  (** OSSL_TRACE_BEGIN, OSSL_TRACE_END - Define a Trace Group
  *
  * These two macros can be used to create a block which is executed only
  * if the corresponding trace category is enabled. Inside this block, a
  * local variable named |trc_out| is defined, which points to the channel
  * associated with the given trace category.
  *
  * Usage: (using 'TLS' as an example category)
  *
  *     OSSL_TRACE_BEGIN(TLS) {
  *
  *         BIO_fprintf(trc_out, ... );
  *
  *     } OSSL_TRACE_END(TLS);
  *
  *
  * This expands to the following code
  *
  *     do {
  *         BIO *trc_out = OSSL_trace_begin(OSSL_TRACE_CATEGORY_TLS);
  *         if (trc_out != NULL) {
  *             ...
  *             BIO_fprintf(trc_out, ...);
  *         }
  *         OSSL_trace_end(OSSL_TRACE_CATEGORY_TLS, trc_out);
  *     } while (0);
  *
  * The use of the inner '{...}' group and the trailing ';' is enforced
  * by the definition of the macros in order to make the code look as much
  * like C code as possible.
  *
  * Before returning from inside the trace block, it is necessary to
  * call OSSL_TRACE_CANCEL(category).
  *)
  {$else}
  {$EXTERNALSYM OSSL_trace_set_callback}
  {$EXTERNALSYM OSSL_trace_enabled}
  {$EXTERNALSYM OSSL_trace_begin}
  {$EXTERNALSYM OSSL_trace_end}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_OSSL_trace_set_callback(category: TOpenSSL_C_INT; callback: TOSSL_trace_cb; data: pointer): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_trace_enabled(category: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_OSSL_trace_begin(category: TOpenSSL_C_INT): PBIO; cdecl;
  procedure Load_OSSL_trace_end(category: TOpenSSL_C_INT; channel: PBIO); cdecl;

var
  OSSL_trace_set_callback: function(category: TOpenSSL_C_INT; callback: TOSSL_trace_cb; data: pointer): TOpenSSL_C_INT; cdecl = Load_OSSL_trace_set_callback;
  
  {* TRACE PRODUCERS
  }
  
  {* Returns 1 if tracing for the specified category is enabled, otherwise 0
  }
  OSSL_trace_enabled: function(category: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_OSSL_trace_enabled;
  
  (** Wrap a group of tracing output calls.  OSSL_trace_begin() locks tracing and
  * returns the trace channel associated with the given category, or NULL if no
  * channel is associated with the category.  OSSL_trace_end() unlocks tracing.
  *
  * Usage:
  *
  *    BIO *out;
  *    if ((out = OSSL_trace_begin(category)) != NULL) {
  *        ...
  *        BIO_fprintf(out, ...);
  *        ...
  *        OSSL_trace_end(category, out);
  *    }
  *
  * See also the convenience macros OSSL_TRACE_BEGIN and OSSL_TRACE_END below.
  *)
  OSSL_trace_begin: function(category: TOpenSSL_C_INT): PBIO; cdecl = Load_OSSL_trace_begin;
  OSSL_trace_end: procedure(category: TOpenSSL_C_INT; channel: PBIO); cdecl = Load_OSSL_trace_end;
  
  {* OSSL_TRACE* Convenience Macros
  }
  
  {* When the tracing feature is disabled, these macros are defined to
  * produce dead code, which a good compiler should eliminate.
  }
  
  (** OSSL_TRACE_BEGIN, OSSL_TRACE_END - Define a Trace Group
  *
  * These two macros can be used to create a block which is executed only
  * if the corresponding trace category is enabled. Inside this block, a
  * local variable named |trc_out| is defined, which points to the channel
  * associated with the given trace category.
  *
  * Usage: (using 'TLS' as an example category)
  *
  *     OSSL_TRACE_BEGIN(TLS) {
  *
  *         BIO_fprintf(trc_out, ... );
  *
  *     } OSSL_TRACE_END(TLS);
  *
  *
  * This expands to the following code
  *
  *     do {
  *         BIO *trc_out = OSSL_trace_begin(OSSL_TRACE_CATEGORY_TLS);
  *         if (trc_out != NULL) {
  *             ...
  *             BIO_fprintf(trc_out, ...);
  *         }
  *         OSSL_trace_end(OSSL_TRACE_CATEGORY_TLS, trc_out);
  *     } while (0);
  *
  * The use of the inner '{...}' group and the trailing ';' is enforced
  * by the definition of the macros in order to make the code look as much
  * like C code as possible.
  *
  * Before returning from inside the trace block, it is necessary to
  * call OSSL_TRACE_CANCEL(category).
  *)
  {$endif} {OPENSSL_STATIC_LINK_MODEL}
  {$if  not defined(OPENSSL_NO_TRACE)  and  not defined(FIPS_MODULE)}
(*# define  OSSL_TRACE_BEGIN(category) do { BIO *trc_out = OSSL_trace_begin(OSSL_TRACE_CATEGORY_ ##category); if (trc_out != NULL)*)
(*# define  OSSL_TRACE_END(category) OSSL_trace_end(OSSL_TRACE_CATEGORY_ ##category, trc_out); } while (0)*)
{# define  OSSL_TRACE_CANCEL(category) OSSL_trace_end(OSSL_TRACE_CATEGORY_ ##category, trc_out)}
  {$else}
(*# define  OSSL_TRACE_BEGIN(category) do { BIO *trc_out = NULL; if (0)*)
(*# define  OSSL_TRACE_END(category) } while (0)*)
{# define  OSSL_TRACE_CANCEL(category) ((void)0)} { Blacklisted Macro}
  {$endif}
  
  (** OSSL_TRACE_ENABLED() - Check whether tracing is enabled for |category|
  *
  * Usage:
  *
  *     if (OSSL_TRACE_ENABLED(TLS)) {
  *         ...
  *     }
  *)
  {$if  not defined(OPENSSL_NO_TRACE)  and  not defined(FIPS_MODULE)}
{# define  OSSL_TRACE_ENABLED(category) OSSL_trace_enabled(OSSL_TRACE_CATEGORY_ ##category)}
  {$else}
{# define  OSSL_TRACE_ENABLED(category) (0)} { Blacklisted Macro}
  {$endif}
  
  {* OSSL_TRACE*() - OneShot Trace Macros
  *
  * These macros are intended to produce a simple printf-style trace output.
  * Unfortunately, C90 macros don't support variable arguments, so the
  * "vararg" OSSL_TRACEV() macro has a rather weird usage pattern:
  *
  *    OSSL_TRACEV(category, (trc_out, "format string", ...args...));
  *
  * Where 'channel' is the literal symbol of this name, not a variable.
  * For that reason, it is currently not intended to be used directly,
  * but only as helper macro for the other oneshot trace macros
  * OSSL_TRACE(), OSSL_TRACE1(), OSSL_TRACE2(), ...
  *
  * Usage:
  *
  *    OSSL_TRACE(INIT, "Hello world!n");
  *    OSSL_TRACE1(TLS, "The answer is %dn", 42);
  *    OSSL_TRACE2(TLS, "The ultimate question to answer %d is '%s'n",
  *                42, "What do you get when you multiply six by nine?");
  }
  {$if  not defined(OPENSSL_NO_TRACE)  and  not defined(FIPS_MODULE)}
{# define  OSSL_TRACEV(category,args) OSSL_TRACE_BEGIN(category) BIO_printf args; OSSL_TRACE_END(category)}
  {$else}
{# define  OSSL_TRACEV(category,args) ((void)0)} { Blacklisted Macro}
  {$endif}
{# define  OSSL_TRACE(category,text) OSSL_TRACEV(category, (trc_out, "%s", text))}
{# define  OSSL_TRACE1(category,format,arg1) OSSL_TRACEV(category, (trc_out, format, arg1))}
{# define  OSSL_TRACE2(category,format,arg1,arg2) OSSL_TRACEV(category, (trc_out, format, arg1, arg2))}
{# define  OSSL_TRACE3(category,format,arg1,arg2,arg3) OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3))}
{# define  OSSL_TRACE4(category,format,arg1,arg2,arg3,arg4) OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4))}
{# define  OSSL_TRACE5(category,format,arg1,arg2,arg3,arg4,arg5) OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, arg4,
 arg5))}
{# define  OSSL_TRACE6(category,format,arg1,arg2,arg3,arg4,arg5,arg6) OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3, 
arg4, arg5, arg6))}
{# define  OSSL_TRACE7(category,format,arg1,arg2,arg3,arg4,arg5,arg6,arg7) OSSL_TRACEV(category, (trc_out, format, arg1, arg2, arg3,
 arg4, arg5, arg6, arg7))}
{# define  OSSL_TRACE8(category,format,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8) OSSL_TRACEV(category, (trc_out, format, arg1, arg2,
 arg3, arg4, arg5, arg6, arg7, arg8))}
{# define  OSSL_TRACE9(category,format,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8,arg9) OSSL_TRACEV(category, (trc_out, format, arg1,
 arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9))}
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
function Load_OSSL_trace_get_category_num(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_trace_get_category_num := LoadLibCryptoFunction('OSSL_trace_get_category_num');
  if not assigned(OSSL_trace_get_category_num) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_get_category_num');
  Result := OSSL_trace_get_category_num(name);
end;

function Load_OSSL_trace_get_category_name(num: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  OSSL_trace_get_category_name := LoadLibCryptoFunction('OSSL_trace_get_category_name');
  if not assigned(OSSL_trace_get_category_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_get_category_name');
  Result := OSSL_trace_get_category_name(num);
end;

function Load_OSSL_trace_set_channel(category: TOpenSSL_C_INT; channel: PBIO): TOpenSSL_C_INT; cdecl;
begin
  OSSL_trace_set_channel := LoadLibCryptoFunction('OSSL_trace_set_channel');
  if not assigned(OSSL_trace_set_channel) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_set_channel');
  Result := OSSL_trace_set_channel(category, channel);
end;

function Load_OSSL_trace_set_prefix(category: TOpenSSL_C_INT; prefix: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_trace_set_prefix := LoadLibCryptoFunction('OSSL_trace_set_prefix');
  if not assigned(OSSL_trace_set_prefix) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_set_prefix');
  Result := OSSL_trace_set_prefix(category, prefix);
end;

function Load_OSSL_trace_set_suffix(category: TOpenSSL_C_INT; suffix: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  OSSL_trace_set_suffix := LoadLibCryptoFunction('OSSL_trace_set_suffix');
  if not assigned(OSSL_trace_set_suffix) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_set_suffix');
  Result := OSSL_trace_set_suffix(category, suffix);
end;

function Load_OSSL_trace_set_callback(category: TOpenSSL_C_INT; callback: TOSSL_trace_cb; data: pointer): TOpenSSL_C_INT; cdecl;
begin
  OSSL_trace_set_callback := LoadLibCryptoFunction('OSSL_trace_set_callback');
  if not assigned(OSSL_trace_set_callback) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_set_callback');
  Result := OSSL_trace_set_callback(category, callback, data);
end;

function Load_OSSL_trace_enabled(category: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  OSSL_trace_enabled := LoadLibCryptoFunction('OSSL_trace_enabled');
  if not assigned(OSSL_trace_enabled) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_enabled');
  Result := OSSL_trace_enabled(category);
end;

function Load_OSSL_trace_begin(category: TOpenSSL_C_INT): PBIO; cdecl;
begin
  OSSL_trace_begin := LoadLibCryptoFunction('OSSL_trace_begin');
  if not assigned(OSSL_trace_begin) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_begin');
  Result := OSSL_trace_begin(category);
end;

procedure Load_OSSL_trace_end(category: TOpenSSL_C_INT; channel: PBIO); cdecl;
begin
  OSSL_trace_end := LoadLibCryptoFunction('OSSL_trace_end');
  if not assigned(OSSL_trace_end) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('OSSL_trace_end');
  OSSL_trace_end(category, channel);
end;

procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
  OSSL_trace_get_category_num := Load_OSSL_trace_get_category_num;
  OSSL_trace_get_category_name := Load_OSSL_trace_get_category_name;
  OSSL_trace_set_channel := Load_OSSL_trace_set_channel;
  OSSL_trace_set_prefix := Load_OSSL_trace_set_prefix;
  OSSL_trace_set_suffix := Load_OSSL_trace_set_suffix;
  OSSL_trace_set_callback := Load_OSSL_trace_set_callback;
  OSSL_trace_enabled := Load_OSSL_trace_enabled;
  OSSL_trace_begin := Load_OSSL_trace_begin;
  OSSL_trace_end := Load_OSSL_trace_end;
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



