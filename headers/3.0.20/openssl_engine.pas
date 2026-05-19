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

unit openssl_engine;

{
  Generated from OpenSSL 3.0.20 Header File engine.h - Tue 19 May 14:15:59 BST 2026
}

{$IFNDEF FPC}
{$IFDEF OPENSSL_USE_STATIC_LIBRARY}
{$LINK openssl_engine.obj}
{$ENDIF}
{$ENDIF}

interface

uses OpenSSLAPI,openssl_bn,openssl_rsa,openssl_dsa,openssl_dh,openssl_ec,
     openssl_rand,openssl_ui,openssl_err,openssl_types,openssl_symhacks,openssl_x509,
     openssl_engineerr;


{* Copyright 2000-2022 The OpenSSL Project Authors. All Rights Reserved.
* Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
}
{$ifndef  OPENSSL_ENGINE_H}
  {$define OPENSSL_ENGINE_H}
  {$include openssl_macros.inc}
  {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
    {$define HEADER_ENGINE_H}
  {$endif}
  {$include openssl_opensslconf.inc}
  {$ifndef  OPENSSL_NO_ENGINE}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
    {$endif}


    
    {* These flags are used to control combinations of algorithm (methods) by
    * bitwise "OR"ing.
    }
  function ENGINE_METHOD_RSA: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_DSA: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_DH: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_RAND: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_CIPHERS: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_DIGESTS: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_PKEY_METHS: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_PKEY_ASN1_METHS: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_EC: TOpenSSL_C_UINT; inline;
    { Obvious all-or-nothing cases. }
  function ENGINE_METHOD_ALL: TOpenSSL_C_UINT; inline;
  function ENGINE_METHOD_NONE: TOpenSSL_C_UINT; inline;
    
    {* This(ese) flag(s) controls behaviour of the ENGINE_TABLE mechanism used
    * internally to control registration of ENGINE implementations, and can be
    * set by ENGINE_set_table_flags(). The "NOINIT" flag prevents attempts to
    * initialise registered ENGINEs if they are not already initialised.
    }
  function ENGINE_TABLE_FLAG_NOINIT: TOpenSSL_C_UINT; inline;
    { ENGINE flags that can be set by ENGINE_set_flags(). }
    { Not used }
    { #define ENGINE_FLAGS_MALLOCED        0x0001 }
    
    {* This flag is for ENGINEs that wish to handle the various 'CMD'-related
    * control commands on their own. Without this flag, ENGINE_ctrl() handles
    * these control commands on behalf of the ENGINE using their "cmd_defns"
    * data.
    }
  function ENGINE_FLAGS_MANUAL_CMD_CTRL: TOpenSSL_C_INT; inline;
    
    {* This flag is for ENGINEs who return new duplicate structures when found
    * via "ENGINE_by_id()". When an ENGINE must store state (eg. if
    * ENGINE_ctrl() commands are called in sequence as part of some stateful
    * process like key-generation setup and execution), it can set this flag -
    * then each attempt to obtain the ENGINE will result in it being copied into
    * a new structure. Normally, ENGINEs don't declare this flag so
    * ENGINE_by_id() just increments the existing ENGINE's structural reference
    * count.
    }
  function ENGINE_FLAGS_BY_ID_COPY: TOpenSSL_C_INT; inline;
    
    {* This flag if for an ENGINE that does not want its methods registered as
    * part of ENGINE_register_all_complete() for example if the methods are not
    * usable as default methods.
    }
  function ENGINE_FLAGS_NO_REGISTER_ALL: TOpenSSL_C_INT; inline;
    
    {* ENGINEs can support their own command types, and these flags are used in
    * ENGINE_CTRL_GET_CMD_FLAGS to indicate to the caller what kind of input
    * each command expects. Currently only numeric and string input is
    * supported. If a control command supports none of the _NUMERIC, _STRING, or
    * _NO_INPUT options, then it is regarded as an "internal" control command -
    * and not for use in config setting situations. As such, they're not
    * available to the ENGINE_ctrl_cmd_string() function, only raw ENGINE_ctrl()
    * access. Changes to this list of 'command types' should be reflected
    * carefully in ENGINE_cmd_is_executable() and ENGINE_ctrl_cmd_string().
    }
    { accepts a 'long' input value (3rd parameter to ENGINE_ctrl) }
  function ENGINE_CMD_FLAG_NUMERIC: TOpenSSL_C_UINT; inline;
    
    {* accepts string input (cast from 'void*' to 'const char *', 4th parameter
    * to ENGINE_ctrl)
    }
  function ENGINE_CMD_FLAG_STRING: TOpenSSL_C_UINT; inline;
    
    {* Indicates that the control command takes *no* input. Ie. the control
    * command is unparameterised.
    }
  function ENGINE_CMD_FLAG_NO_INPUT: TOpenSSL_C_UINT; inline;
    
    {* Indicates that the control command is internal. This control command won't
    * be shown in any output, and is only usable through the ENGINE_ctrl_cmd()
    * function.
    }
  function ENGINE_CMD_FLAG_INTERNAL: TOpenSSL_C_UINT; inline;

const
    
    {* NB: These 3 control commands are deprecated and should not be used.
    * ENGINEs relying on these commands should compile conditional support for
    * compatibility (eg. if these symbols are defined) but should also migrate
    * the same functionality to their own ENGINE-specific control functions that
    * can be "discovered" by calling applications. The fact these control
    * commands wouldn't be "executable" (ie. usable by text-based config)
    * doesn't change the fact that application code can find and use them
    * without requiring per-ENGINE hacking.
    }
    
    {* These flags are used to tell the ctrl function what should be done. All
    * command numbers are shared between all engines, even if some don't make
    * sense to some engines.  In such a case, they do nothing but return the
    * error ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED.
    }
  ENGINE_CTRL_SET_LOGSTREAM = 1;
  ENGINE_CTRL_SET_PASSWORD_CALLBACK = 2;
  ENGINE_CTRL_HUP = 3;
  ENGINE_CTRL_SET_USER_INTERFACE = 4;
  ENGINE_CTRL_SET_CALLBACK_DATA = 5;
  ENGINE_CTRL_LOAD_CONFIGURATION = 6;
  ENGINE_CTRL_LOAD_SECTION = 7;
    
    {* These control commands allow an application to deal with an arbitrary
    * engine in a dynamic way. Warn: Negative return values indicate errors FOR
    * THESE COMMANDS because zero is used to indicate 'end-of-list'. Other
    * commands, including ENGINE-specific command types, return zero for an
    * error. An ENGINE can choose to implement these ctrl functions, and can
    * internally manage things however it chooses - it does so by setting the
    * ENGINE_FLAGS_MANUAL_CMD_CTRL flag (using ENGINE_set_flags()). Otherwise
    * the ENGINE_ctrl() code handles this on the ENGINE's behalf using the
    * cmd_defns data (set using ENGINE_set_cmd_defns()). This means an ENGINE's
    * ctrl() handler need only implement its own commands - the above "meta"
    * commands will be taken care of.
    }
    
    {* Returns non-zero if the supplied ENGINE has a ctrl() handler. If "not",
    * then all the remaining control commands will return failure, so it is
    * worth checking this first if the caller is trying to "discover" the
    * engine's capabilities and doesn't want errors generated unnecessarily.
    }
  ENGINE_CTRL_HAS_CTRL_FUNCTION = 10;
    
    {* Returns a positive command number for the first command supported by the
    * engine. Returns zero if no ctrl commands are supported.
    }
  ENGINE_CTRL_GET_FIRST_CMD_TYPE = 11;
    
    {* The 'long' argument specifies a command implemented by the engine, and the
    * return value is the next command supported, or zero if there are no more.
    }
  ENGINE_CTRL_GET_NEXT_CMD_TYPE = 12;
    
    {* The 'void*' argument is a command name (cast from 'const char *'), and the
    * return value is the command that corresponds to it.
    }
  ENGINE_CTRL_GET_CMD_FROM_NAME = 13;
    
    {* The next two allow a command to be converted into its corresponding string
    * form. In each case, the 'long' argument supplies the command. In the
    * NAME_LEN case, the return value is the length of the command name (not
    * counting a trailing EOL). In the NAME case, the 'void*' argument must be a
    * string buffer large enough, and it will be populated with the name of the
    * command (WITH a trailing EOL).
    }
  ENGINE_CTRL_GET_NAME_LEN_FROM_CMD = 14;
  ENGINE_CTRL_GET_NAME_FROM_CMD = 15;
    { The next two are similar but give a "short description" of a command. }
  ENGINE_CTRL_GET_DESC_LEN_FROM_CMD = 16;
  ENGINE_CTRL_GET_DESC_FROM_CMD = 17;
    
    {* With this command, the return value is the OR'd combination of
    * ENGINE_CMD_FLAG_*** values that indicate what kind of input a given
    * engine-specific ctrl command expects.
    }
  ENGINE_CTRL_GET_CMD_FLAGS = 18;
    
    {* ENGINE implementations should start the numbering of their own control
    * commands from this value. (ie. ENGINE_CMD_BASE, ENGINE_CMD_BASE + 1, etc).
    }
  ENGINE_CMD_BASE = 200;
    
    {* NB: These 2 nCipher "chil" control commands are deprecated, and their
    * functionality is now available through ENGINE-specific control commands
    * (exposed through the above-mentioned 'CMD'-handling). Code using these 2
    * commands should be migrated to the more general command handling before
    * these are removed.
    }
    { Flags specific to the nCipher "chil" engine }
  ENGINE_CTRL_CHIL_SET_FORKCHECK = 100;
    
    {* Depending on the value of the (long)i argument, this sets or
    * unsets the SimpleForkCheck flag in the CHIL API to enable or
    * disable checking and workarounds for applications that fork().
    }
  ENGINE_CTRL_CHIL_NO_LOCKING = 101;

type
  {Auto-generated forward references}
  PENGINE_CMD_DEFN_st = ^TENGINE_CMD_DEFN_st;
  PPENGINE_CMD_DEFN_st = ^PENGINE_CMD_DEFN_st;
  PENGINE_CMD_DEFN = ^TENGINE_CMD_DEFN;
  PPENGINE_CMD_DEFN = ^PENGINE_CMD_DEFN;
  PENGINE_GEN_FUNC_PTR = ^TENGINE_GEN_FUNC_PTR;
  PPENGINE_GEN_FUNC_PTR = ^PENGINE_GEN_FUNC_PTR;
  PENGINE_GEN_INT_FUNC_PTR = ^TENGINE_GEN_INT_FUNC_PTR;
  PPENGINE_GEN_INT_FUNC_PTR = ^PENGINE_GEN_INT_FUNC_PTR;
  PFuncType000 = ^TFuncType000;
  PPFuncType000 = ^PFuncType000;
  PENGINE_CTRL_FUNC_PTR = ^TENGINE_CTRL_FUNC_PTR;
  PPENGINE_CTRL_FUNC_PTR = ^PENGINE_CTRL_FUNC_PTR;
  PENGINE_LOAD_KEY_PTR = ^TENGINE_LOAD_KEY_PTR;
  PPENGINE_LOAD_KEY_PTR = ^PENGINE_LOAD_KEY_PTR;
  PENGINE_SSL_CLIENT_CERT_PTR = ^TENGINE_SSL_CLIENT_CERT_PTR;
  PPENGINE_SSL_CLIENT_CERT_PTR = ^PENGINE_SSL_CLIENT_CERT_PTR;
  PENGINE_CIPHERS_PTR = ^TENGINE_CIPHERS_PTR;
  PPENGINE_CIPHERS_PTR = ^PENGINE_CIPHERS_PTR;
  PENGINE_DIGESTS_PTR = ^TENGINE_DIGESTS_PTR;
  PPENGINE_DIGESTS_PTR = ^PENGINE_DIGESTS_PTR;
  PENGINE_PKEY_METHS_PTR = ^TENGINE_PKEY_METHS_PTR;
  PPENGINE_PKEY_METHS_PTR = ^PENGINE_PKEY_METHS_PTR;
  PENGINE_PKEY_ASN1_METHS_PTR = ^TENGINE_PKEY_ASN1_METHS_PTR;
  PPENGINE_PKEY_ASN1_METHS_PTR = ^PENGINE_PKEY_ASN1_METHS_PTR;
  {end of auto-generated forward references}

    
    {* This prevents the initialisation function from providing mutex
    * callbacks to the nCipher library.
    }
    
    {* If an ENGINE supports its own specific control commands and wishes the
    * framework to handle the above 'ENGINE_CMD_***'-manipulation commands on
    * its behalf, it should supply a null-terminated array of ENGINE_CMD_DEFN
    * entries to ENGINE_set_cmd_defns(). It should also implement a ctrl()
    * handler that supports the stated commands (ie. the "cmd_num" entries as
    * described by the array). NB: The array must be ordered in increasing order
    * of cmd_num. "null-terminated" means that the last ENGINE_CMD_DEFN element
    * has cmd_num set to zero and/or cmd_name set to NULL.
    }
  TENGINE_CMD_DEFN_st = record 
    cmd_num: TOpenSSL_C_UINT; { The command number }
    cmd_name: PAnsiChar; { The command name itself }
    cmd_desc: PAnsiChar; { A short description of the command }
    cmd_flags: TOpenSSL_C_UINT; { The input the command expects }
  end;
  TENGINE_CMD_DEFN = TENGINE_CMD_DEFN_st;
    { Generic function pointer }
  TENGINE_GEN_FUNC_PTR = function: TOpenSSL_C_INT; cdecl;
    { Generic function pointer taking no arguments }
  TENGINE_GEN_INT_FUNC_PTR = function(_param1: PENGINE): TOpenSSL_C_INT; cdecl;
    { Specific control function pointer }
  TFuncType000 = procedure; cdecl;
  TENGINE_CTRL_FUNC_PTR = function(_param1: PENGINE; _param2: TOpenSSL_C_INT; _param3: TOpenSSL_C_INT; _param4: pointer; f: TFuncType000): TOpenSSL_C_INT; cdecl;
    { Generic load_key function pointer }
  TENGINE_LOAD_KEY_PTR = function(_param1: PENGINE; _param2: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl;
  TENGINE_SSL_CLIENT_CERT_PTR = function(_param1: PENGINE; ssl: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; pkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: pointer): TOpenSSL_C_INT; cdecl;
    {-
    * These callback types are for an ENGINE's handler for cipher and digest logic.
    * These handlers have these prototypes;
    *   int foo(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
    *   int foo(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
    * Looking at how to implement these handlers in the case of cipher support, if
    * the framework wants the EVP_CIPHER for 'nid', it will call;
    *   foo(e, &p_evp_cipher, NULL, nid);    (return zero for failure)
    * If the framework wants a list of supported 'nid's, it will call;
    *   foo(e, NULL, &p_nids, 0); (returns number of 'nids' or -1 for error)
    }
    
    {* Returns to a pointer to the array of supported cipher 'nid's. If the
    * second parameter is non-NULL it is set to the size of the returned array.
    }
  TENGINE_CIPHERS_PTR = function(_param1: PENGINE; _param2: PPEVP_CIPHER; _param3: PPOpenSSL_C_INT; _param4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TENGINE_DIGESTS_PTR = function(_param1: PENGINE; _param2: PPEVP_MD; _param3: PPOpenSSL_C_INT; _param4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TENGINE_PKEY_METHS_PTR = function(_param1: PENGINE; _param2: PPEVP_PKEY_METHOD; _param3: PPOpenSSL_C_INT; _param4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  TENGINE_PKEY_ASN1_METHS_PTR = function(_param1: PENGINE; _param2: PPEVP_PKEY_ASN1_METHOD; _param3: PPOpenSSL_C_INT; _param4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
    
    {* STRUCTURE functions ... all of these functions deal with pointers to
    * ENGINE structures where the pointers have a "structural reference". This
    * means that their reference is to allowed access to the structure but it
    * does not imply that the structure is functional. To simply increment or
    * decrement the structural reference count, use ENGINE_by_id and
    * ENGINE_free. NB: This is not required when iterating using ENGINE_get_next
    * as it will automatically decrement the structural reference count of the
    * "current" ENGINE and increment the structural reference count of the
    * ENGINE it returns (unless it is NULL).
    }
    { Get the first/last "ENGINE" type available. }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_first: PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_first'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_last: PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_last'; deprecated 'Since OpenSSL 3.0';
      {$else}
  { The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows:

  The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header
  files generated for C++. }
  {$EXTERNALSYM ENGINE_get_first}
  {$EXTERNALSYM ENGINE_get_last}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_first: PENGINE; cdecl;
  function Load_ENGINE_get_last: PENGINE; cdecl;

var
  ENGINE_get_first: function: PENGINE; cdecl = Load_ENGINE_get_first;
  ENGINE_get_last: function: PENGINE; cdecl = Load_ENGINE_get_last;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { Iterate to the next/previous "ENGINE" type (NULL = end of the list). }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_next(e: PENGINE): PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_next'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_prev(e: PENGINE): PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_prev'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_get_next}
  {$EXTERNALSYM ENGINE_get_prev}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_next(e: PENGINE): PENGINE; cdecl;
  function Load_ENGINE_get_prev(e: PENGINE): PENGINE; cdecl;

var
  ENGINE_get_next: function(e: PENGINE): PENGINE; cdecl = Load_ENGINE_get_next;
  ENGINE_get_prev: function(e: PENGINE): PENGINE; cdecl = Load_ENGINE_get_prev;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { Add another "ENGINE" type into the array. }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_add(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_add'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_add}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_add(e: PENGINE): TOpenSSL_C_INT; cdecl;

var
  ENGINE_add: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_add;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { Remove an existing "ENGINE" type from the array. }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_remove(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_remove'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_remove}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_remove(e: PENGINE): TOpenSSL_C_INT; cdecl;

var
  ENGINE_remove: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_remove;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { Retrieve an engine from the list by its unique "id" value. }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_by_id(id: PAnsiChar): PENGINE; cdecl; external CLibCrypto name 'ENGINE_by_id'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_by_id}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_by_id(id: PAnsiChar): PENGINE; cdecl;

var
  ENGINE_by_id: function(id: PAnsiChar): PENGINE; cdecl = Load_ENGINE_by_id;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{# define  ENGINE_load_openssl() OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_OPENSSL, NULL)} {Macro Return Type unknown at line no 344}
{# define  ENGINE_load_dynamic() OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_DYNAMIC, NULL)} {Macro Return Type unknown at line no 346}
      {$ifndef  OPENSSL_NO_STATIC_ENGINE}
{# define  ENGINE_load_padlock() OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_PADLOCK, NULL)} {Macro Return Type unknown at line no 349}
{# define  ENGINE_load_capi() OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CAPI, NULL)} {Macro Return Type unknown at line no 351}
{# define  ENGINE_load_afalg() OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_AFALG, NULL)} {Macro Return Type unknown at line no 353}
      {$endif}
{# define  ENGINE_load_cryptodev() OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_CRYPTODEV, NULL)} {Macro Return Type unknown at line no 356}
{# define  ENGINE_load_rdrand() OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_RDRAND, NULL)} {Macro Return Type unknown at line no 358}
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ENGINE_load_builtin_engines; cdecl; external CLibCrypto name 'ENGINE_load_builtin_engines'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_load_builtin_engines}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ENGINE_load_builtin_engines; cdecl;

var
  ENGINE_load_builtin_engines: procedure; cdecl = Load_ENGINE_load_builtin_engines;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* Get and set global flags (ENGINE_TABLE_FLAG_***) for the implementation
    * "registry" handling.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_table_flags: TOpenSSL_C_UINT; cdecl; external CLibCrypto name 'ENGINE_get_table_flags'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_set_table_flags(flags: TOpenSSL_C_UINT); cdecl; external CLibCrypto name 'ENGINE_set_table_flags'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_get_table_flags}
  {$EXTERNALSYM ENGINE_set_table_flags}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_table_flags: TOpenSSL_C_UINT; cdecl;
  procedure Load_ENGINE_set_table_flags(flags: TOpenSSL_C_UINT); cdecl;

var
  ENGINE_get_table_flags: function: TOpenSSL_C_UINT; cdecl = Load_ENGINE_get_table_flags;
  ENGINE_set_table_flags: procedure(flags: TOpenSSL_C_UINT); cdecl = Load_ENGINE_set_table_flags;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {- Manage registration of ENGINEs per "table". For each type, there are 3
    * functions;
    *   ENGINE_register_***(e) - registers the implementation from 'e' (if it has one)
    *   ENGINE_unregister_***(e) - unregister the implementation from 'e'
    *   ENGINE_register_all_***() - call ENGINE_register_***() for each 'e' in the list
    * Cleanup is automatically registered from each table when required.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_register_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_RSA'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_RSA(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_RSA'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_RSA; cdecl; external CLibCrypto name 'ENGINE_register_all_RSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_DSA'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_DSA(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_DSA'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_DSA; cdecl; external CLibCrypto name 'ENGINE_register_all_DSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_EC(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_EC'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_EC(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_EC'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_EC; cdecl; external CLibCrypto name 'ENGINE_register_all_EC'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_DH(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_DH'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_DH(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_DH'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_DH; cdecl; external CLibCrypto name 'ENGINE_register_all_DH'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_RAND'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_RAND(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_RAND'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_RAND; cdecl; external CLibCrypto name 'ENGINE_register_all_RAND'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_ciphers'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_ciphers(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_ciphers'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_ciphers; cdecl; external CLibCrypto name 'ENGINE_register_all_ciphers'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_digests(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_digests'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_digests(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_digests'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_digests; cdecl; external CLibCrypto name 'ENGINE_register_all_digests'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_pkey_meths'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_pkey_meths(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_pkey_meths'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_pkey_meths; cdecl; external CLibCrypto name 'ENGINE_register_all_pkey_meths'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_pkey_asn1_meths'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl; external CLibCrypto name 'ENGINE_unregister_pkey_asn1_meths'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_register_all_pkey_asn1_meths; cdecl; external CLibCrypto name 'ENGINE_register_all_pkey_asn1_meths'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_register_RSA}
  {$EXTERNALSYM ENGINE_unregister_RSA}
  {$EXTERNALSYM ENGINE_register_all_RSA}
  {$EXTERNALSYM ENGINE_register_DSA}
  {$EXTERNALSYM ENGINE_unregister_DSA}
  {$EXTERNALSYM ENGINE_register_all_DSA}
  {$EXTERNALSYM ENGINE_register_EC}
  {$EXTERNALSYM ENGINE_unregister_EC}
  {$EXTERNALSYM ENGINE_register_all_EC}
  {$EXTERNALSYM ENGINE_register_DH}
  {$EXTERNALSYM ENGINE_unregister_DH}
  {$EXTERNALSYM ENGINE_register_all_DH}
  {$EXTERNALSYM ENGINE_register_RAND}
  {$EXTERNALSYM ENGINE_unregister_RAND}
  {$EXTERNALSYM ENGINE_register_all_RAND}
  {$EXTERNALSYM ENGINE_register_ciphers}
  {$EXTERNALSYM ENGINE_unregister_ciphers}
  {$EXTERNALSYM ENGINE_register_all_ciphers}
  {$EXTERNALSYM ENGINE_register_digests}
  {$EXTERNALSYM ENGINE_unregister_digests}
  {$EXTERNALSYM ENGINE_register_all_digests}
  {$EXTERNALSYM ENGINE_register_pkey_meths}
  {$EXTERNALSYM ENGINE_unregister_pkey_meths}
  {$EXTERNALSYM ENGINE_register_all_pkey_meths}
  {$EXTERNALSYM ENGINE_register_pkey_asn1_meths}
  {$EXTERNALSYM ENGINE_unregister_pkey_asn1_meths}
  {$EXTERNALSYM ENGINE_register_all_pkey_asn1_meths}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_register_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_RSA(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_RSA; cdecl;
  function Load_ENGINE_register_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_DSA(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_DSA; cdecl;
  function Load_ENGINE_register_EC(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_EC(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_EC; cdecl;
  function Load_ENGINE_register_DH(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_DH(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_DH; cdecl;
  function Load_ENGINE_register_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_RAND(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_RAND; cdecl;
  function Load_ENGINE_register_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_ciphers(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_ciphers; cdecl;
  function Load_ENGINE_register_digests(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_digests(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_digests; cdecl;
  function Load_ENGINE_register_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_pkey_meths(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_pkey_meths; cdecl;
  function Load_ENGINE_register_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl;
  procedure Load_ENGINE_register_all_pkey_asn1_meths; cdecl;

var
  ENGINE_register_RSA: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_RSA;
  ENGINE_unregister_RSA: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_RSA;
  ENGINE_register_all_RSA: procedure; cdecl = Load_ENGINE_register_all_RSA;
  ENGINE_register_DSA: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_DSA;
  ENGINE_unregister_DSA: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_DSA;
  ENGINE_register_all_DSA: procedure; cdecl = Load_ENGINE_register_all_DSA;
  ENGINE_register_EC: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_EC;
  ENGINE_unregister_EC: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_EC;
  ENGINE_register_all_EC: procedure; cdecl = Load_ENGINE_register_all_EC;
  ENGINE_register_DH: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_DH;
  ENGINE_unregister_DH: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_DH;
  ENGINE_register_all_DH: procedure; cdecl = Load_ENGINE_register_all_DH;
  ENGINE_register_RAND: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_RAND;
  ENGINE_unregister_RAND: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_RAND;
  ENGINE_register_all_RAND: procedure; cdecl = Load_ENGINE_register_all_RAND;
  ENGINE_register_ciphers: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_ciphers;
  ENGINE_unregister_ciphers: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_ciphers;
  ENGINE_register_all_ciphers: procedure; cdecl = Load_ENGINE_register_all_ciphers;
  ENGINE_register_digests: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_digests;
  ENGINE_unregister_digests: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_digests;
  ENGINE_register_all_digests: procedure; cdecl = Load_ENGINE_register_all_digests;
  ENGINE_register_pkey_meths: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_pkey_meths;
  ENGINE_unregister_pkey_meths: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_pkey_meths;
  ENGINE_register_all_pkey_meths: procedure; cdecl = Load_ENGINE_register_all_pkey_meths;
  ENGINE_register_pkey_asn1_meths: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_pkey_asn1_meths;
  ENGINE_unregister_pkey_asn1_meths: procedure(e: PENGINE); cdecl = Load_ENGINE_unregister_pkey_asn1_meths;
  ENGINE_register_all_pkey_asn1_meths: procedure; cdecl = Load_ENGINE_register_all_pkey_asn1_meths;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* These functions register all support from the above categories. Note, use
    * of these functions can result in static linkage of code your application
    * may not need. If you only need a subset of functionality, consider using
    * more selective initialisation.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_register_complete(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_complete'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_register_all_complete: TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_register_all_complete'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_register_complete}
  {$EXTERNALSYM ENGINE_register_all_complete}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_register_complete(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_register_all_complete: TOpenSSL_C_INT; cdecl;

var
  ENGINE_register_complete: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_register_complete;
  ENGINE_register_all_complete: function: TOpenSSL_C_INT; cdecl = Load_ENGINE_register_all_complete;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* Send parameterised control commands to the engine. The possibilities to
    * send down an integer, a pointer to data or a function pointer are
    * provided. Any of the parameters may or may not be NULL, depending on the
    * command number. In actuality, this function only requires a structural
    * (rather than functional) reference to an engine, but many control commands
    * may require the engine be functional. The caller should be aware of trying
    * commands that require an operational ENGINE, and only use functional
    * references in such situations.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PFuncType001 = ^TFuncType001;
  PPFuncType001 = ^PFuncType001;
  {end of auto-generated forward references}

  TFuncType001 = procedure; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_ctrl(e: PENGINE; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_INT; p: pointer; f: TFuncType001): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_ctrl'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_ctrl}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_ctrl(e: PENGINE; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_INT; p: pointer; f: TFuncType001): TOpenSSL_C_INT; cdecl;

var
  ENGINE_ctrl: function(e: PENGINE; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_INT; p: pointer; f: TFuncType001): TOpenSSL_C_INT; cdecl = Load_ENGINE_ctrl;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* This function tests if an ENGINE-specific command is usable as a
    * "setting". Eg. in an application's config file that gets processed through
    * ENGINE_ctrl_cmd_string(). If this returns zero, it is not available to
    * ENGINE_ctrl_cmd_string(), only ENGINE_ctrl().
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_cmd_is_executable(e: PENGINE; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_cmd_is_executable'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_cmd_is_executable}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_cmd_is_executable(e: PENGINE; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  ENGINE_cmd_is_executable: function(e: PENGINE; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ENGINE_cmd_is_executable;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* This function works like ENGINE_ctrl() with the exception of taking a
    * command name instead of a command number, and can handle optional
    * commands. See the comment on ENGINE_ctrl_cmd_string() for an explanation
    * on how to use the cmd_name and cmd_optional.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}

type
  {Auto-generated forward references}
  PFuncType002 = ^TFuncType002;
  PPFuncType002 = ^PFuncType002;
  {end of auto-generated forward references}

  TFuncType002 = procedure; cdecl;


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_ctrl_cmd(e: PENGINE; cmd_name: PAnsiChar; i: TOpenSSL_C_INT; p: pointer; f: TFuncType002; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_ctrl_cmd'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_ctrl_cmd}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_ctrl_cmd(e: PENGINE; cmd_name: PAnsiChar; i: TOpenSSL_C_INT; p: pointer; f: TFuncType002; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  ENGINE_ctrl_cmd: function(e: PENGINE; cmd_name: PAnsiChar; i: TOpenSSL_C_INT; p: pointer; f: TFuncType002; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ENGINE_ctrl_cmd;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* This function passes a command-name and argument to an ENGINE. The
    * cmd_name is converted to a command number and the control command is
    * called using 'arg' as an argument (unless the ENGINE doesn't support such
    * a command, in which case no control command is called). The command is
    * checked for input flags, and if necessary the argument will be converted
    * to a numeric value. If cmd_optional is non-zero, then if the ENGINE
    * doesn't support the given cmd_name the return value will be success
    * anyway. This function is intended for applications to use so that users
    * (or config files) can supply engine-specific config data to the ENGINE at
    * run-time to control behaviour of specific engines. As such, it shouldn't
    * be used for calling ENGINE_ctrl() functions that return data, deal with
    * binary data, or that are otherwise supposed to be used directly through
    * ENGINE_ctrl() in application code. Any "return" data from an ENGINE_ctrl()
    * operation in this function will be lost - the return value is interpreted
    * as failure if the return value is zero, success otherwise, and this
    * function returns a boolean value as a result. In other words, vendors of
    * 'ENGINE'-enabled devices should write ENGINE implementations with
    * parameterisations that work in this scheme, so that compliant ENGINE-based
    * applications can work consistently with the same configuration for the
    * same ENGINE-enabled devices, across applications.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_ctrl_cmd_string(e: PENGINE; cmd_name: PAnsiChar; arg: PAnsiChar; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_ctrl_cmd_string'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_ctrl_cmd_string}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_ctrl_cmd_string(e: PENGINE; cmd_name: PAnsiChar; arg: PAnsiChar; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

var
  ENGINE_ctrl_cmd_string: function(e: PENGINE; cmd_name: PAnsiChar; arg: PAnsiChar; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ENGINE_ctrl_cmd_string;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* These functions are useful for manufacturing new ENGINE structures. They
    * don't address reference counting at all - one uses them to populate an
    * ENGINE structure with personalised implementations of things prior to
    * using it directly or adding it to the builtin ENGINE list in OpenSSL.
    * These are also here so that the ENGINE structure doesn't have to be
    * exposed and break binary compatibility!
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_new: PENGINE; cdecl; external CLibCrypto name 'ENGINE_new'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_free(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_free'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_up_ref(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_up_ref'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_id(e: PENGINE; id: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_id'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_name(e: PENGINE; name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_name'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_RSA(e: PENGINE; rsa_meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_RSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_DSA(e: PENGINE; dsa_meth: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_DSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_EC(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_EC'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_DH(e: PENGINE; dh_meth: PDH_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_DH'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_RAND(e: PENGINE; rand_meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_RAND'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_destroy_function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_destroy_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_init_function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_init_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_finish_function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_finish_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_ctrl_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_load_privkey_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_load_pubkey_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_load_ssl_client_cert_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_ciphers(e: PENGINE; f: TENGINE_CIPHERS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_ciphers'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_digests(e: PENGINE; f: TENGINE_DIGESTS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_digests'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_pkey_meths(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_pkey_meths'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_pkey_asn1_meths(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_pkey_asn1_meths'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_flags(e: PENGINE; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_flags'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_cmd_defns(e: PENGINE; defns: PENGINE_CMD_DEFN): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_cmd_defns'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_new}
  {$EXTERNALSYM ENGINE_free}
  {$EXTERNALSYM ENGINE_up_ref}
  {$EXTERNALSYM ENGINE_set_id}
  {$EXTERNALSYM ENGINE_set_name}
  {$EXTERNALSYM ENGINE_set_RSA}
  {$EXTERNALSYM ENGINE_set_DSA}
  {$EXTERNALSYM ENGINE_set_EC}
  {$EXTERNALSYM ENGINE_set_DH}
  {$EXTERNALSYM ENGINE_set_RAND}
  {$EXTERNALSYM ENGINE_set_destroy_function}
  {$EXTERNALSYM ENGINE_set_init_function}
  {$EXTERNALSYM ENGINE_set_finish_function}
  {$EXTERNALSYM ENGINE_set_ctrl_function}
  {$EXTERNALSYM ENGINE_set_load_privkey_function}
  {$EXTERNALSYM ENGINE_set_load_pubkey_function}
  {$EXTERNALSYM ENGINE_set_load_ssl_client_cert_function}
  {$EXTERNALSYM ENGINE_set_ciphers}
  {$EXTERNALSYM ENGINE_set_digests}
  {$EXTERNALSYM ENGINE_set_pkey_meths}
  {$EXTERNALSYM ENGINE_set_pkey_asn1_meths}
  {$EXTERNALSYM ENGINE_set_flags}
  {$EXTERNALSYM ENGINE_set_cmd_defns}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_new: PENGINE; cdecl;
  function Load_ENGINE_free(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_up_ref(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_id(e: PENGINE; id: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_name(e: PENGINE; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_RSA(e: PENGINE; rsa_meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_DSA(e: PENGINE; dsa_meth: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_EC(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_DH(e: PENGINE; dh_meth: PDH_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_RAND(e: PENGINE; rand_meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_destroy_function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_init_function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_finish_function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_ciphers(e: PENGINE; f: TENGINE_CIPHERS_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_digests(e: PENGINE; f: TENGINE_DIGESTS_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_pkey_meths(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_pkey_asn1_meths(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_flags(e: PENGINE; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_cmd_defns(e: PENGINE; defns: PENGINE_CMD_DEFN): TOpenSSL_C_INT; cdecl;

var
  ENGINE_new: function: PENGINE; cdecl = Load_ENGINE_new;
  ENGINE_free: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_free;
  ENGINE_up_ref: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_up_ref;
  ENGINE_set_id: function(e: PENGINE; id: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_id;
  ENGINE_set_name: function(e: PENGINE; name: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_name;
  ENGINE_set_RSA: function(e: PENGINE; rsa_meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_RSA;
  ENGINE_set_DSA: function(e: PENGINE; dsa_meth: PDSA_METHOD): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_DSA;
  ENGINE_set_EC: function(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_EC;
  ENGINE_set_DH: function(e: PENGINE; dh_meth: PDH_METHOD): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_DH;
  ENGINE_set_RAND: function(e: PENGINE; rand_meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_RAND;
  ENGINE_set_destroy_function: function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_destroy_function;
  ENGINE_set_init_function: function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_init_function;
  ENGINE_set_finish_function: function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_finish_function;
  ENGINE_set_ctrl_function: function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_ctrl_function;
  ENGINE_set_load_privkey_function: function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_load_privkey_function;
  ENGINE_set_load_pubkey_function: function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_load_pubkey_function;
  ENGINE_set_load_ssl_client_cert_function: function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_load_ssl_client_cert_function;
  ENGINE_set_ciphers: function(e: PENGINE; f: TENGINE_CIPHERS_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_ciphers;
  ENGINE_set_digests: function(e: PENGINE; f: TENGINE_DIGESTS_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_digests;
  ENGINE_set_pkey_meths: function(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_pkey_meths;
  ENGINE_set_pkey_asn1_meths: function(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_pkey_asn1_meths;
  ENGINE_set_flags: function(e: PENGINE; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_flags;
  ENGINE_set_cmd_defns: function(e: PENGINE; defns: PENGINE_CMD_DEFN): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_cmd_defns;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
{# define  ENGINE_get_ex_new_index(l,p,newf,dupf,freef) CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_ENGINE, l, p, newf, dupf, freef)} {Macro Return Type unknown at line no 534}
    { These functions allow control over any per-structure ENGINE data. }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_set_ex_data(e: PENGINE; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_ex_data'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_ex_data(e: PENGINE; idx: TOpenSSL_C_INT): pointer; cdecl; external CLibCrypto name 'ENGINE_get_ex_data'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_set_ex_data}
  {$EXTERNALSYM ENGINE_get_ex_data}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_set_ex_data(e: PENGINE; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_get_ex_data(e: PENGINE; idx: TOpenSSL_C_INT): pointer; cdecl;

var
  ENGINE_set_ex_data: function(e: PENGINE; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_ex_data;
  ENGINE_get_ex_data: function(e: PENGINE; idx: TOpenSSL_C_INT): pointer; cdecl = Load_ENGINE_get_ex_data;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
{# define  ENGINE_cleanup() while (0) continue}
      
      {* This function previously cleaned up anything that needs it. Auto-deinit will
      * now take care of it so it is no longer required to call this function.
      }
    {$endif}
    
    {* These return values from within the ENGINE structure. These can be useful
    * with functional references as well as structural references - it depends
    * which you obtained. Using the result for functional purposes if you only
    * obtained a structural reference may be problematic!
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_id(e: PENGINE): PAnsiChar; cdecl; external CLibCrypto name 'ENGINE_get_id'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_name(e: PENGINE): PAnsiChar; cdecl; external CLibCrypto name 'ENGINE_get_name'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_RSA(e: PENGINE): PRSA_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_RSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_DSA(e: PENGINE): PDSA_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_DSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_EC(e: PENGINE): PEC_KEY_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_EC'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_DH(e: PENGINE): PDH_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_DH'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_RAND(e: PENGINE): PRAND_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_RAND'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_destroy_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl; external CLibCrypto name 'ENGINE_get_destroy_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_init_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl; external CLibCrypto name 'ENGINE_get_init_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_finish_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl; external CLibCrypto name 'ENGINE_get_finish_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_ctrl_function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl; external CLibCrypto name 'ENGINE_get_ctrl_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_load_privkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl; external CLibCrypto name 'ENGINE_get_load_privkey_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_load_pubkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl; external CLibCrypto name 'ENGINE_get_load_pubkey_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_ssl_client_cert_function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl; external CLibCrypto name 'ENGINE_get_ssl_client_cert_function'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_ciphers(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl; external CLibCrypto name 'ENGINE_get_ciphers'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_digests(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl; external CLibCrypto name 'ENGINE_get_digests'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_pkey_meths(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl; external CLibCrypto name 'ENGINE_get_pkey_meths'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_pkey_asn1_meths(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl; external CLibCrypto name 'ENGINE_get_pkey_asn1_meths'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_cipher(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_CIPHER; cdecl; external CLibCrypto name 'ENGINE_get_cipher'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_digest(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_MD; cdecl; external CLibCrypto name 'ENGINE_get_digest'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_pkey_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_pkey_meth'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_pkey_asn1_meth'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_pkey_asn1_meth_str(e: PENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'ENGINE_get_pkey_asn1_meth_str'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_pkey_asn1_find_str(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto name 'ENGINE_pkey_asn1_find_str'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_cmd_defns(e: PENGINE): PENGINE_CMD_DEFN; cdecl; external CLibCrypto name 'ENGINE_get_cmd_defns'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_flags(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_get_flags'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_get_id}
  {$EXTERNALSYM ENGINE_get_name}
  {$EXTERNALSYM ENGINE_get_RSA}
  {$EXTERNALSYM ENGINE_get_DSA}
  {$EXTERNALSYM ENGINE_get_EC}
  {$EXTERNALSYM ENGINE_get_DH}
  {$EXTERNALSYM ENGINE_get_RAND}
  {$EXTERNALSYM ENGINE_get_destroy_function}
  {$EXTERNALSYM ENGINE_get_init_function}
  {$EXTERNALSYM ENGINE_get_finish_function}
  {$EXTERNALSYM ENGINE_get_ctrl_function}
  {$EXTERNALSYM ENGINE_get_load_privkey_function}
  {$EXTERNALSYM ENGINE_get_load_pubkey_function}
  {$EXTERNALSYM ENGINE_get_ssl_client_cert_function}
  {$EXTERNALSYM ENGINE_get_ciphers}
  {$EXTERNALSYM ENGINE_get_digests}
  {$EXTERNALSYM ENGINE_get_pkey_meths}
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meths}
  {$EXTERNALSYM ENGINE_get_cipher}
  {$EXTERNALSYM ENGINE_get_digest}
  {$EXTERNALSYM ENGINE_get_pkey_meth}
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth}
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_str}
  {$EXTERNALSYM ENGINE_pkey_asn1_find_str}
  {$EXTERNALSYM ENGINE_get_cmd_defns}
  {$EXTERNALSYM ENGINE_get_flags}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_id(e: PENGINE): PAnsiChar; cdecl;
  function Load_ENGINE_get_name(e: PENGINE): PAnsiChar; cdecl;
  function Load_ENGINE_get_RSA(e: PENGINE): PRSA_METHOD; cdecl;
  function Load_ENGINE_get_DSA(e: PENGINE): PDSA_METHOD; cdecl;
  function Load_ENGINE_get_EC(e: PENGINE): PEC_KEY_METHOD; cdecl;
  function Load_ENGINE_get_DH(e: PENGINE): PDH_METHOD; cdecl;
  function Load_ENGINE_get_RAND(e: PENGINE): PRAND_METHOD; cdecl;
  function Load_ENGINE_get_destroy_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl;
  function Load_ENGINE_get_init_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl;
  function Load_ENGINE_get_finish_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl;
  function Load_ENGINE_get_ctrl_function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl;
  function Load_ENGINE_get_load_privkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl;
  function Load_ENGINE_get_load_pubkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl;
  function Load_ENGINE_get_ssl_client_cert_function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl;
  function Load_ENGINE_get_ciphers(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl;
  function Load_ENGINE_get_digests(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl;
  function Load_ENGINE_get_pkey_meths(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl;
  function Load_ENGINE_get_pkey_asn1_meths(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl;
  function Load_ENGINE_get_cipher(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
  function Load_ENGINE_get_digest(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_MD; cdecl;
  function Load_ENGINE_get_pkey_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
  function Load_ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
  function Load_ENGINE_get_pkey_asn1_meth_str(e: PENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
  function Load_ENGINE_pkey_asn1_find_str(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
  function Load_ENGINE_get_cmd_defns(e: PENGINE): PENGINE_CMD_DEFN; cdecl;
  function Load_ENGINE_get_flags(e: PENGINE): TOpenSSL_C_INT; cdecl;

var
  ENGINE_get_id: function(e: PENGINE): PAnsiChar; cdecl = Load_ENGINE_get_id;
  ENGINE_get_name: function(e: PENGINE): PAnsiChar; cdecl = Load_ENGINE_get_name;
  ENGINE_get_RSA: function(e: PENGINE): PRSA_METHOD; cdecl = Load_ENGINE_get_RSA;
  ENGINE_get_DSA: function(e: PENGINE): PDSA_METHOD; cdecl = Load_ENGINE_get_DSA;
  ENGINE_get_EC: function(e: PENGINE): PEC_KEY_METHOD; cdecl = Load_ENGINE_get_EC;
  ENGINE_get_DH: function(e: PENGINE): PDH_METHOD; cdecl = Load_ENGINE_get_DH;
  ENGINE_get_RAND: function(e: PENGINE): PRAND_METHOD; cdecl = Load_ENGINE_get_RAND;
  ENGINE_get_destroy_function: function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl = Load_ENGINE_get_destroy_function;
  ENGINE_get_init_function: function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl = Load_ENGINE_get_init_function;
  ENGINE_get_finish_function: function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl = Load_ENGINE_get_finish_function;
  ENGINE_get_ctrl_function: function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl = Load_ENGINE_get_ctrl_function;
  ENGINE_get_load_privkey_function: function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl = Load_ENGINE_get_load_privkey_function;
  ENGINE_get_load_pubkey_function: function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl = Load_ENGINE_get_load_pubkey_function;
  ENGINE_get_ssl_client_cert_function: function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl = Load_ENGINE_get_ssl_client_cert_function;
  ENGINE_get_ciphers: function(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl = Load_ENGINE_get_ciphers;
  ENGINE_get_digests: function(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl = Load_ENGINE_get_digests;
  ENGINE_get_pkey_meths: function(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl = Load_ENGINE_get_pkey_meths;
  ENGINE_get_pkey_asn1_meths: function(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl = Load_ENGINE_get_pkey_asn1_meths;
  ENGINE_get_cipher: function(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_CIPHER; cdecl = Load_ENGINE_get_cipher;
  ENGINE_get_digest: function(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_MD; cdecl = Load_ENGINE_get_digest;
  ENGINE_get_pkey_meth: function(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = Load_ENGINE_get_pkey_meth;
  ENGINE_get_pkey_asn1_meth: function(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_ENGINE_get_pkey_asn1_meth;
  ENGINE_get_pkey_asn1_meth_str: function(e: PENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_ENGINE_get_pkey_asn1_meth_str;
  ENGINE_pkey_asn1_find_str: function(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = Load_ENGINE_pkey_asn1_find_str;
  ENGINE_get_cmd_defns: function(e: PENGINE): PENGINE_CMD_DEFN; cdecl = Load_ENGINE_get_cmd_defns;
  ENGINE_get_flags: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_get_flags;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* FUNCTIONAL functions. These functions deal with ENGINE structures that
    * have (or will) be initialised for use. Broadly speaking, the structural
    * functions are useful for iterating the list of available engine types,
    * creating new engine types, and other "list" operations. These functions
    * actually deal with ENGINEs that are to be used. As such these functions
    * can fail (if applicable) when particular engines are unavailable - eg. if
    * a hardware accelerator is not attached or not functioning correctly. Each
    * ENGINE has 2 reference counts; structural and functional. Every time a
    * functional reference is obtained or released, a corresponding structural
    * reference is automatically obtained or released too.
    }
    
    {* Initialise a engine type for use (or up its reference count if it's
    * already in use). This will fail if the engine is not currently operational
    * and cannot initialise.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_init(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_init'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_init}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_init(e: PENGINE): TOpenSSL_C_INT; cdecl;

var
  ENGINE_init: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_init;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* Free a functional reference to a engine type. This does not require a
    * corresponding call to ENGINE_free as it also releases a structural
    * reference.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_finish(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_finish'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_finish}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_finish(e: PENGINE): TOpenSSL_C_INT; cdecl;

var
  ENGINE_finish: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_finish;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* The following functions handle keys that are stored in some secondary
    * location, handled by the engine.  The storage may be on a card or
    * whatever.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_load_private_key(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'ENGINE_load_private_key'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_load_public_key(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl; external CLibCrypto name 'ENGINE_load_public_key'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_load_ssl_client_cert'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_load_private_key}
  {$EXTERNALSYM ENGINE_load_public_key}
  {$EXTERNALSYM ENGINE_load_ssl_client_cert}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_load_private_key(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl;
  function Load_ENGINE_load_public_key(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl;
  function Load_ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: pointer): TOpenSSL_C_INT; cdecl;

var
  ENGINE_load_private_key: function(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl = Load_ENGINE_load_private_key;
  ENGINE_load_public_key: function(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl = Load_ENGINE_load_public_key;
  ENGINE_load_ssl_client_cert: function(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: pointer): TOpenSSL_C_INT; cdecl = Load_ENGINE_load_ssl_client_cert;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* This returns a pointer for the current ENGINE structure that is (by
    * default) performing any RSA operations. The value returned is an
    * incremented reference, so it should be free'd (ENGINE_finish) before it is
    * discarded.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_default_RSA: PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_default_RSA'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_get_default_RSA}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_default_RSA: PENGINE; cdecl;

var
  ENGINE_get_default_RSA: function: PENGINE; cdecl = Load_ENGINE_get_default_RSA;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { Same for the other "methods" }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_default_DSA: PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_default_DSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_default_EC: PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_default_EC'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_default_DH: PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_default_DH'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_default_RAND: PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_default_RAND'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_get_default_DSA}
  {$EXTERNALSYM ENGINE_get_default_EC}
  {$EXTERNALSYM ENGINE_get_default_DH}
  {$EXTERNALSYM ENGINE_get_default_RAND}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_default_DSA: PENGINE; cdecl;
  function Load_ENGINE_get_default_EC: PENGINE; cdecl;
  function Load_ENGINE_get_default_DH: PENGINE; cdecl;
  function Load_ENGINE_get_default_RAND: PENGINE; cdecl;

var
  ENGINE_get_default_DSA: function: PENGINE; cdecl = Load_ENGINE_get_default_DSA;
  ENGINE_get_default_EC: function: PENGINE; cdecl = Load_ENGINE_get_default_EC;
  ENGINE_get_default_DH: function: PENGINE; cdecl = Load_ENGINE_get_default_DH;
  ENGINE_get_default_RAND: function: PENGINE; cdecl = Load_ENGINE_get_default_RAND;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* These functions can be used to get a functional reference to perform
    * ciphering or digesting corresponding to "nid".
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_cipher_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_cipher_engine'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_digest_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_digest_engine'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_pkey_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_pkey_meth_engine'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_get_pkey_asn1_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto name 'ENGINE_get_pkey_asn1_meth_engine'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_get_cipher_engine}
  {$EXTERNALSYM ENGINE_get_digest_engine}
  {$EXTERNALSYM ENGINE_get_pkey_meth_engine}
  {$EXTERNALSYM ENGINE_get_pkey_asn1_meth_engine}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_cipher_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
  function Load_ENGINE_get_digest_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
  function Load_ENGINE_get_pkey_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
  function Load_ENGINE_get_pkey_asn1_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;

var
  ENGINE_get_cipher_engine: function(nid: TOpenSSL_C_INT): PENGINE; cdecl = Load_ENGINE_get_cipher_engine;
  ENGINE_get_digest_engine: function(nid: TOpenSSL_C_INT): PENGINE; cdecl = Load_ENGINE_get_digest_engine;
  ENGINE_get_pkey_meth_engine: function(nid: TOpenSSL_C_INT): PENGINE; cdecl = Load_ENGINE_get_pkey_meth_engine;
  ENGINE_get_pkey_asn1_meth_engine: function(nid: TOpenSSL_C_INT): PENGINE; cdecl = Load_ENGINE_get_pkey_asn1_meth_engine;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* This sets a new default ENGINE structure for performing RSA operations. If
    * the result is non-zero (success) then the ENGINE structure will have had
    * its reference count up'd so the caller should still free their own
    * reference 'e'.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_set_default_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_RSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_string(e: PENGINE; def_list: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_string'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_set_default_RSA}
  {$EXTERNALSYM ENGINE_set_default_string}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_set_default_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_string(e: PENGINE; def_list: PAnsiChar): TOpenSSL_C_INT; cdecl;

var
  ENGINE_set_default_RSA: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_RSA;
  ENGINE_set_default_string: function(e: PENGINE; def_list: PAnsiChar): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_string;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    { Same for the other "methods" }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_set_default_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_DSA'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_EC(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_EC'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_DH(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_DH'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_RAND'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_ciphers'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_digests(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_digests'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_pkey_meths'; deprecated 'Since OpenSSL 3.0';
  function ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default_pkey_asn1_meths'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_set_default_DSA}
  {$EXTERNALSYM ENGINE_set_default_EC}
  {$EXTERNALSYM ENGINE_set_default_DH}
  {$EXTERNALSYM ENGINE_set_default_RAND}
  {$EXTERNALSYM ENGINE_set_default_ciphers}
  {$EXTERNALSYM ENGINE_set_default_digests}
  {$EXTERNALSYM ENGINE_set_default_pkey_meths}
  {$EXTERNALSYM ENGINE_set_default_pkey_asn1_meths}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_set_default_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_EC(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_DH(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_digests(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
  function Load_ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;

var
  ENGINE_set_default_DSA: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_DSA;
  ENGINE_set_default_EC: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_EC;
  ENGINE_set_default_DH: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_DH;
  ENGINE_set_default_RAND: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_RAND;
  ENGINE_set_default_ciphers: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_ciphers;
  ENGINE_set_default_digests: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_digests;
  ENGINE_set_default_pkey_meths: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_pkey_meths;
  ENGINE_set_default_pkey_asn1_meths: function(e: PENGINE): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default_pkey_asn1_meths;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}
    
    {* The combination "set" - the flags are bitwise "OR"d from the
    * ENGINE_METHOD_*** defines above. As with the "ENGINE_register_complete()"
    * function, this function can result in unnecessary static linkage. If your
    * application requires only specific functionality, consider using more
    * selective functions.
    }
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}


      {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_set_default(e: PENGINE; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto name 'ENGINE_set_default'; deprecated 'Since OpenSSL 3.0';
  procedure ENGINE_add_conf_module; cdecl; external CLibCrypto name 'ENGINE_add_conf_module'; deprecated 'Since OpenSSL 3.0';
      {$else}
  {$EXTERNALSYM ENGINE_set_default}
  {$EXTERNALSYM ENGINE_add_conf_module}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_set_default(e: PENGINE; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
  procedure Load_ENGINE_add_conf_module; cdecl;

var
  ENGINE_set_default: function(e: PENGINE; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = Load_ENGINE_set_default;
  ENGINE_add_conf_module: procedure; cdecl = Load_ENGINE_add_conf_module;
      {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$endif}


    { Deprecated functions ... }
    { int ENGINE_clear_defaults(void); }
    {************************}
    { DYNAMIC ENGINE SUPPORT }
    {************************}
    { Binary/behaviour compatibility levels }
  function OSSL_DYNAMIC_VERSION: TOpenSSL_C_UINT; inline;
    
    {* Binary versions older than this are too old for us (whether we're a loader
    * or a loadee)
    }
  function OSSL_DYNAMIC_OLDEST: TOpenSSL_C_UINT; inline;

type
  {Auto-generated forward references}
  Pdyn_MEM_malloc_fn = ^Tdyn_MEM_malloc_fn;
  PPdyn_MEM_malloc_fn = ^Pdyn_MEM_malloc_fn;
  Pdyn_MEM_realloc_fn = ^Tdyn_MEM_realloc_fn;
  PPdyn_MEM_realloc_fn = ^Pdyn_MEM_realloc_fn;
  Pdyn_MEM_free_fn = ^Tdyn_MEM_free_fn;
  PPdyn_MEM_free_fn = ^Pdyn_MEM_free_fn;
  Pst_dynamic_MEM_fns = ^Tst_dynamic_MEM_fns;
  PPst_dynamic_MEM_fns = ^Pst_dynamic_MEM_fns;
  Pdynamic_MEM_fns = ^Tdynamic_MEM_fns;
  PPdynamic_MEM_fns = ^Pdynamic_MEM_fns;
  Pst_dynamic_fns = ^Tst_dynamic_fns;
  PPst_dynamic_fns = ^Pst_dynamic_fns;
  Pdynamic_fns = ^Tdynamic_fns;
  PPdynamic_fns = ^Pdynamic_fns;
  Pdynamic_v_check_fn = ^Tdynamic_v_check_fn;
  PPdynamic_v_check_fn = ^Pdynamic_v_check_fn;
  Pdynamic_bind_engine = ^Tdynamic_bind_engine;
  PPdynamic_bind_engine = ^Pdynamic_bind_engine;
  {end of auto-generated forward references}

    
    {* When compiling an ENGINE entirely as an external shared library, loadable
    * by the "dynamic" ENGINE, these types are needed. The 'dynamic_fns'
    * structure type provides the calling application's (or library's) error
    * functionality and memory management function pointers to the loaded
    * library. These should be used/set in the loaded library code so that the
    * loading application's 'state' will be used/changed in all operations. The
    * 'static_state' pointer allows the loaded library to know if it shares the
    * same static data as the calling application (or library), and thus whether
    * these callbacks need to be set or not.
    }
  Tdyn_MEM_malloc_fn = function(_param1: TOpenSSL_C_SIZET; _param2: PAnsiChar; _param3: TOpenSSL_C_INT): pointer; cdecl;
  Tdyn_MEM_realloc_fn = function(_param1: pointer; _param2: TOpenSSL_C_SIZET; _param3: PAnsiChar; _param4: TOpenSSL_C_INT): pointer; cdecl;
  Tdyn_MEM_free_fn = procedure(_param1: pointer; _param2: PAnsiChar; _param3: TOpenSSL_C_INT); cdecl;
  Tst_dynamic_MEM_fns = record 
    malloc_fn: Tdyn_MEM_malloc_fn;
    realloc_fn: Tdyn_MEM_realloc_fn;
    free_fn: Tdyn_MEM_free_fn;
  end;
  Tdynamic_MEM_fns = Tst_dynamic_MEM_fns;
    
    {* FIXME: Perhaps the memory and locking code (crypto.h) should declare and
    * use these types so we (and any other dependent code) can simplify a bit??
    }
    { The top-level structure }
  Tst_dynamic_fns = record 
    static_state: pointer;
    mem_fns: Tdynamic_MEM_fns;
  end;
  Tdynamic_fns = Tst_dynamic_fns;
    
    {* The version checking function should be of this prototype. NB: The
    * ossl_version value passed in is the OSSL_DYNAMIC_VERSION of the loading
    * code. If this function returns zero, it indicates a (potential) version
    * incompatibility and the loaded library doesn't believe it can proceed.
    * Otherwise, the returned value is the (latest) version supported by the
    * loading library. The loader may still decide that the loaded code's
    * version is unsatisfactory and could veto the load. The function is
    * expected to be implemented with the symbol name "v_check", and a default
    * implementation can be fully instantiated with
    * IMPLEMENT_DYNAMIC_CHECK_FN().
    }
  Tdynamic_v_check_fn = function(ossl_version: TOpenSSL_C_UINT): TOpenSSL_C_UINT; cdecl;
  (*# define  IMPLEMENT_DYNAMIC_CHECK_FN() OPENSSL_EXPORT unsigned long v_check(unsigned long v); OPENSSL_EXPORT unsigned long v_check(unsigned 
long v) { if (v >= OSSL_DYNAMIC_OLDEST) return OSSL_DYNAMIC_VERSION; return 0; }*)
    
    {* This function is passed the ENGINE structure to initialise with its own
    * function and command settings. It should not adjust the structural or
    * functional reference counts. If this function returns zero, (a) the load
    * will be aborted, (b) the previous ENGINE state will be memcpy'd back onto
    * the structure, and (c) the shared library will be unloaded. So
    * implementations should do their own internal cleanup in failure
    * circumstances otherwise they could leak. The 'id' parameter, if non-NULL,
    * represents the ENGINE id that the loader is looking for. If this is NULL,
    * the shared library can choose to return failure or to initialise a
    * 'default' ENGINE. If non-NULL, the shared library must initialise only an
    * ENGINE matching the passed 'id'. The function is expected to be
    * implemented with the symbol name "bind_engine". A standard implementation
    * can be instantiated with IMPLEMENT_DYNAMIC_BIND_FN(fn) where the parameter
    * 'fn' is a callback function that populates the ENGINE structure and
    * returns an int value (zero for failure). 'fn' should have prototype;
    * [static] int fn(ENGINE *e, const char *id);
    }
  Tdynamic_bind_engine = function(e: PENGINE; id: PAnsiChar; fns: Pdynamic_fns): TOpenSSL_C_INT; cdecl;
  (*# define  IMPLEMENT_DYNAMIC_BIND_FN(fn) OPENSSL_EXPORT int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns); OPENSSL_EXPORT 
int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) { if (ENGINE_get_static_state() == fns->static_state) goto skip_cbs; 
CRYPTO_set_mem_functions(fns->mem_fns.malloc_fn, fns->mem_fns.realloc_fn, fns->mem_fns.free_fn); OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT,
 NULL); skip_cbs: if (!fn(e, id)) return 0; return 1; }*)


    
    {* If the loading application (or library) and the loaded ENGINE library
    * share the same static data (eg. they're both dynamically linked to the
    * same libcrypto.so) we need a way to avoid trying to set system callbacks -
    * this would fail, and for the same reason that it's unnecessary to try. If
    * the loaded ENGINE has (or gets from through the loader) its own copy of
    * the libcrypto static data, we will need to set the callbacks. The easiest
    * way to detect this is to have a function that returns a pointer to some
    * static data and let the loading application and loaded ENGINE compare
    * their respective values.
    }
    {$ifdef OPENSSL_STATIC_LINK_MODEL}
  function ENGINE_get_static_state: pointer; cdecl; external CLibCrypto name 'ENGINE_get_static_state';
    {$else}
  {$EXTERNALSYM ENGINE_get_static_state}
  {Do not call Function LoadDeclarations. Internal use only}
  function Load_ENGINE_get_static_state: pointer; cdecl;

var
  ENGINE_get_static_state: function: pointer; cdecl = Load_ENGINE_get_static_state;
    {$endif} {OPENSSL_STATIC_LINK_MODEL}
    {$if  defined(__OpenBSD__)  or defined(__FreeBSD__)  or defined(__DragonFly__)}
      {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}


        {$ifdef OPENSSL_STATIC_LINK_MODEL}
  procedure ENGINE_setup_bsd_cryptodev; cdecl; external CLibCrypto name 'ENGINE_setup_bsd_cryptodev'; deprecated 'Since OpenSSL 1.1.0';
        {$else}
  {$EXTERNALSYM ENGINE_setup_bsd_cryptodev}
  {Do not call Function LoadDeclarations. Internal use only}
  procedure Load_ENGINE_setup_bsd_cryptodev; cdecl;

var
  ENGINE_setup_bsd_cryptodev: procedure; cdecl = Load_ENGINE_setup_bsd_cryptodev;
        {$endif} {OPENSSL_STATIC_LINK_MODEL}
      {$endif}
    {$endif}
  {$endif}
  { OPENSSL_NO_ENGINE }
{$endif}
{ OPENSSL_ENGINE_H }

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

{$ifndef  OPENSSL_NO_ENGINE}

{# define  ENGINE_METHOD_RSA (unsigned int)0x0001}

function ENGINE_METHOD_RSA: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0001));
end;

{# define  ENGINE_METHOD_DSA (unsigned int)0x0002}

function ENGINE_METHOD_DSA: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0002));
end;

{# define  ENGINE_METHOD_DH (unsigned int)0x0004}

function ENGINE_METHOD_DH: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0004));
end;

{# define  ENGINE_METHOD_RAND (unsigned int)0x0008}

function ENGINE_METHOD_RAND: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0008));
end;

{# define  ENGINE_METHOD_CIPHERS (unsigned int)0x0040}

function ENGINE_METHOD_CIPHERS: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0040));
end;

{# define  ENGINE_METHOD_DIGESTS (unsigned int)0x0080}

function ENGINE_METHOD_DIGESTS: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0080));
end;

{# define  ENGINE_METHOD_PKEY_METHS (unsigned int)0x0200}

function ENGINE_METHOD_PKEY_METHS: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0200));
end;

{# define  ENGINE_METHOD_PKEY_ASN1_METHS (unsigned int)0x0400}

function ENGINE_METHOD_PKEY_ASN1_METHS: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0400));
end;

{# define  ENGINE_METHOD_EC (unsigned int)0x0800}

function ENGINE_METHOD_EC: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0800));
end;

{# define  ENGINE_METHOD_ALL (unsigned int)0xFFFF}

function ENGINE_METHOD_ALL: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($FFFF));
end;

{# define  ENGINE_METHOD_NONE (unsigned int)0x0000}

function ENGINE_METHOD_NONE: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0000));
end;

{# define  ENGINE_TABLE_FLAG_NOINIT (unsigned int)0x0001}

function ENGINE_TABLE_FLAG_NOINIT: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0001));
end;

{# define  ENGINE_FLAGS_MANUAL_CMD_CTRL (int)0x0002}

function ENGINE_FLAGS_MANUAL_CMD_CTRL: TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(TOpenSSL_C_INT($0002));
end;

{# define  ENGINE_FLAGS_BY_ID_COPY (int)0x0004}

function ENGINE_FLAGS_BY_ID_COPY: TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(TOpenSSL_C_INT($0004));
end;

{# define  ENGINE_FLAGS_NO_REGISTER_ALL (int)0x0008}

function ENGINE_FLAGS_NO_REGISTER_ALL: TOpenSSL_C_INT;
begin
  Result := TOpenSSL_C_INT(TOpenSSL_C_INT($0008));
end;

{# define  ENGINE_CMD_FLAG_NUMERIC (unsigned int)0x0001}

function ENGINE_CMD_FLAG_NUMERIC: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0001));
end;

{# define  ENGINE_CMD_FLAG_STRING (unsigned int)0x0002}

function ENGINE_CMD_FLAG_STRING: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0002));
end;

{# define  ENGINE_CMD_FLAG_NO_INPUT (unsigned int)0x0004}

function ENGINE_CMD_FLAG_NO_INPUT: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0004));
end;

{# define  ENGINE_CMD_FLAG_INTERNAL (unsigned int)0x0008}

function ENGINE_CMD_FLAG_INTERNAL: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($0008));
end;

{# define  OSSL_DYNAMIC_VERSION (unsigned long)0x00030000}

function OSSL_DYNAMIC_VERSION: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($00030000));
end;

{# define  OSSL_DYNAMIC_OLDEST (unsigned long)0x00030000}

function OSSL_DYNAMIC_OLDEST: TOpenSSL_C_UINT;
begin
  Result := TOpenSSL_C_UINT(TOpenSSL_C_UINT($00030000));
end;
{$endif} { OPENSSL_NO_ENGINE}
{$ifndef OPENSSL_STATIC_LINK_MODEL}
{$ifndef  OPENSSL_NO_ENGINE}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_first: PENGINE; cdecl;
begin
  ENGINE_get_first := LoadLibCryptoFunction('ENGINE_get_first');
  if not assigned(ENGINE_get_first) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_first');
  Result := ENGINE_get_first;
end;

function Load_ENGINE_get_last: PENGINE; cdecl;
begin
  ENGINE_get_last := LoadLibCryptoFunction('ENGINE_get_last');
  if not assigned(ENGINE_get_last) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_last');
  Result := ENGINE_get_last;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_next(e: PENGINE): PENGINE; cdecl;
begin
  ENGINE_get_next := LoadLibCryptoFunction('ENGINE_get_next');
  if not assigned(ENGINE_get_next) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_next');
  Result := ENGINE_get_next(e);
end;

function Load_ENGINE_get_prev(e: PENGINE): PENGINE; cdecl;
begin
  ENGINE_get_prev := LoadLibCryptoFunction('ENGINE_get_prev');
  if not assigned(ENGINE_get_prev) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_prev');
  Result := ENGINE_get_prev(e);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_add(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_add := LoadLibCryptoFunction('ENGINE_add');
  if not assigned(ENGINE_add) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_add');
  Result := ENGINE_add(e);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_remove(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_remove := LoadLibCryptoFunction('ENGINE_remove');
  if not assigned(ENGINE_remove) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_remove');
  Result := ENGINE_remove(e);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_by_id(id: PAnsiChar): PENGINE; cdecl;
begin
  ENGINE_by_id := LoadLibCryptoFunction('ENGINE_by_id');
  if not assigned(ENGINE_by_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_by_id');
  Result := ENGINE_by_id(id);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
procedure Load_ENGINE_load_builtin_engines; cdecl;
begin
  ENGINE_load_builtin_engines := LoadLibCryptoFunction('ENGINE_load_builtin_engines');
  if not assigned(ENGINE_load_builtin_engines) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_load_builtin_engines');
  ENGINE_load_builtin_engines;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_table_flags: TOpenSSL_C_UINT; cdecl;
begin
  ENGINE_get_table_flags := LoadLibCryptoFunction('ENGINE_get_table_flags');
  if not assigned(ENGINE_get_table_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_table_flags');
  Result := ENGINE_get_table_flags;
end;

procedure Load_ENGINE_set_table_flags(flags: TOpenSSL_C_UINT); cdecl;
begin
  ENGINE_set_table_flags := LoadLibCryptoFunction('ENGINE_set_table_flags');
  if not assigned(ENGINE_set_table_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_table_flags');
  ENGINE_set_table_flags(flags);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_register_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_RSA := LoadLibCryptoFunction('ENGINE_register_RSA');
  if not assigned(ENGINE_register_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_RSA');
  Result := ENGINE_register_RSA(e);
end;

procedure Load_ENGINE_unregister_RSA(e: PENGINE); cdecl;
begin
  ENGINE_unregister_RSA := LoadLibCryptoFunction('ENGINE_unregister_RSA');
  if not assigned(ENGINE_unregister_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_RSA');
  ENGINE_unregister_RSA(e);
end;

procedure Load_ENGINE_register_all_RSA; cdecl;
begin
  ENGINE_register_all_RSA := LoadLibCryptoFunction('ENGINE_register_all_RSA');
  if not assigned(ENGINE_register_all_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_RSA');
  ENGINE_register_all_RSA;
end;

function Load_ENGINE_register_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_DSA := LoadLibCryptoFunction('ENGINE_register_DSA');
  if not assigned(ENGINE_register_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_DSA');
  Result := ENGINE_register_DSA(e);
end;

procedure Load_ENGINE_unregister_DSA(e: PENGINE); cdecl;
begin
  ENGINE_unregister_DSA := LoadLibCryptoFunction('ENGINE_unregister_DSA');
  if not assigned(ENGINE_unregister_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_DSA');
  ENGINE_unregister_DSA(e);
end;

procedure Load_ENGINE_register_all_DSA; cdecl;
begin
  ENGINE_register_all_DSA := LoadLibCryptoFunction('ENGINE_register_all_DSA');
  if not assigned(ENGINE_register_all_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_DSA');
  ENGINE_register_all_DSA;
end;

function Load_ENGINE_register_EC(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_EC := LoadLibCryptoFunction('ENGINE_register_EC');
  if not assigned(ENGINE_register_EC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_EC');
  Result := ENGINE_register_EC(e);
end;

procedure Load_ENGINE_unregister_EC(e: PENGINE); cdecl;
begin
  ENGINE_unregister_EC := LoadLibCryptoFunction('ENGINE_unregister_EC');
  if not assigned(ENGINE_unregister_EC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_EC');
  ENGINE_unregister_EC(e);
end;

procedure Load_ENGINE_register_all_EC; cdecl;
begin
  ENGINE_register_all_EC := LoadLibCryptoFunction('ENGINE_register_all_EC');
  if not assigned(ENGINE_register_all_EC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_EC');
  ENGINE_register_all_EC;
end;

function Load_ENGINE_register_DH(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_DH := LoadLibCryptoFunction('ENGINE_register_DH');
  if not assigned(ENGINE_register_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_DH');
  Result := ENGINE_register_DH(e);
end;

procedure Load_ENGINE_unregister_DH(e: PENGINE); cdecl;
begin
  ENGINE_unregister_DH := LoadLibCryptoFunction('ENGINE_unregister_DH');
  if not assigned(ENGINE_unregister_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_DH');
  ENGINE_unregister_DH(e);
end;

procedure Load_ENGINE_register_all_DH; cdecl;
begin
  ENGINE_register_all_DH := LoadLibCryptoFunction('ENGINE_register_all_DH');
  if not assigned(ENGINE_register_all_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_DH');
  ENGINE_register_all_DH;
end;

function Load_ENGINE_register_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_RAND := LoadLibCryptoFunction('ENGINE_register_RAND');
  if not assigned(ENGINE_register_RAND) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_RAND');
  Result := ENGINE_register_RAND(e);
end;

procedure Load_ENGINE_unregister_RAND(e: PENGINE); cdecl;
begin
  ENGINE_unregister_RAND := LoadLibCryptoFunction('ENGINE_unregister_RAND');
  if not assigned(ENGINE_unregister_RAND) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_RAND');
  ENGINE_unregister_RAND(e);
end;

procedure Load_ENGINE_register_all_RAND; cdecl;
begin
  ENGINE_register_all_RAND := LoadLibCryptoFunction('ENGINE_register_all_RAND');
  if not assigned(ENGINE_register_all_RAND) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_RAND');
  ENGINE_register_all_RAND;
end;

function Load_ENGINE_register_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_ciphers := LoadLibCryptoFunction('ENGINE_register_ciphers');
  if not assigned(ENGINE_register_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_ciphers');
  Result := ENGINE_register_ciphers(e);
end;

procedure Load_ENGINE_unregister_ciphers(e: PENGINE); cdecl;
begin
  ENGINE_unregister_ciphers := LoadLibCryptoFunction('ENGINE_unregister_ciphers');
  if not assigned(ENGINE_unregister_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_ciphers');
  ENGINE_unregister_ciphers(e);
end;

procedure Load_ENGINE_register_all_ciphers; cdecl;
begin
  ENGINE_register_all_ciphers := LoadLibCryptoFunction('ENGINE_register_all_ciphers');
  if not assigned(ENGINE_register_all_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_ciphers');
  ENGINE_register_all_ciphers;
end;

function Load_ENGINE_register_digests(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_digests := LoadLibCryptoFunction('ENGINE_register_digests');
  if not assigned(ENGINE_register_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_digests');
  Result := ENGINE_register_digests(e);
end;

procedure Load_ENGINE_unregister_digests(e: PENGINE); cdecl;
begin
  ENGINE_unregister_digests := LoadLibCryptoFunction('ENGINE_unregister_digests');
  if not assigned(ENGINE_unregister_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_digests');
  ENGINE_unregister_digests(e);
end;

procedure Load_ENGINE_register_all_digests; cdecl;
begin
  ENGINE_register_all_digests := LoadLibCryptoFunction('ENGINE_register_all_digests');
  if not assigned(ENGINE_register_all_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_digests');
  ENGINE_register_all_digests;
end;

function Load_ENGINE_register_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_pkey_meths := LoadLibCryptoFunction('ENGINE_register_pkey_meths');
  if not assigned(ENGINE_register_pkey_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_pkey_meths');
  Result := ENGINE_register_pkey_meths(e);
end;

procedure Load_ENGINE_unregister_pkey_meths(e: PENGINE); cdecl;
begin
  ENGINE_unregister_pkey_meths := LoadLibCryptoFunction('ENGINE_unregister_pkey_meths');
  if not assigned(ENGINE_unregister_pkey_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_pkey_meths');
  ENGINE_unregister_pkey_meths(e);
end;

procedure Load_ENGINE_register_all_pkey_meths; cdecl;
begin
  ENGINE_register_all_pkey_meths := LoadLibCryptoFunction('ENGINE_register_all_pkey_meths');
  if not assigned(ENGINE_register_all_pkey_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_pkey_meths');
  ENGINE_register_all_pkey_meths;
end;

function Load_ENGINE_register_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_register_pkey_asn1_meths');
  if not assigned(ENGINE_register_pkey_asn1_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_pkey_asn1_meths');
  Result := ENGINE_register_pkey_asn1_meths(e);
end;

procedure Load_ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl;
begin
  ENGINE_unregister_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_unregister_pkey_asn1_meths');
  if not assigned(ENGINE_unregister_pkey_asn1_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_pkey_asn1_meths');
  ENGINE_unregister_pkey_asn1_meths(e);
end;

procedure Load_ENGINE_register_all_pkey_asn1_meths; cdecl;
begin
  ENGINE_register_all_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_register_all_pkey_asn1_meths');
  if not assigned(ENGINE_register_all_pkey_asn1_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_pkey_asn1_meths');
  ENGINE_register_all_pkey_asn1_meths;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_register_complete(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_complete := LoadLibCryptoFunction('ENGINE_register_complete');
  if not assigned(ENGINE_register_complete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_complete');
  Result := ENGINE_register_complete(e);
end;

function Load_ENGINE_register_all_complete: TOpenSSL_C_INT; cdecl;
begin
  ENGINE_register_all_complete := LoadLibCryptoFunction('ENGINE_register_all_complete');
  if not assigned(ENGINE_register_all_complete) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_complete');
  Result := ENGINE_register_all_complete;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_ctrl(e: PENGINE; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_INT; p: pointer; f: TFuncType001): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_ctrl := LoadLibCryptoFunction('ENGINE_ctrl');
  if not assigned(ENGINE_ctrl) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_ctrl');
  Result := ENGINE_ctrl(e, cmd, i, p, f);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_cmd_is_executable(e: PENGINE; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_cmd_is_executable := LoadLibCryptoFunction('ENGINE_cmd_is_executable');
  if not assigned(ENGINE_cmd_is_executable) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_cmd_is_executable');
  Result := ENGINE_cmd_is_executable(e, cmd);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_ctrl_cmd(e: PENGINE; cmd_name: PAnsiChar; i: TOpenSSL_C_INT; p: pointer; f: TFuncType002; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_ctrl_cmd := LoadLibCryptoFunction('ENGINE_ctrl_cmd');
  if not assigned(ENGINE_ctrl_cmd) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_ctrl_cmd');
  Result := ENGINE_ctrl_cmd(e, cmd_name, i, p, f, cmd_optional);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_ctrl_cmd_string(e: PENGINE; cmd_name: PAnsiChar; arg: PAnsiChar; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_ctrl_cmd_string := LoadLibCryptoFunction('ENGINE_ctrl_cmd_string');
  if not assigned(ENGINE_ctrl_cmd_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_ctrl_cmd_string');
  Result := ENGINE_ctrl_cmd_string(e, cmd_name, arg, cmd_optional);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_new: PENGINE; cdecl;
begin
  ENGINE_new := LoadLibCryptoFunction('ENGINE_new');
  if not assigned(ENGINE_new) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_new');
  Result := ENGINE_new;
end;

function Load_ENGINE_free(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_free := LoadLibCryptoFunction('ENGINE_free');
  if not assigned(ENGINE_free) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_free');
  Result := ENGINE_free(e);
end;

function Load_ENGINE_up_ref(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_up_ref := LoadLibCryptoFunction('ENGINE_up_ref');
  if not assigned(ENGINE_up_ref) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_up_ref');
  Result := ENGINE_up_ref(e);
end;

function Load_ENGINE_set_id(e: PENGINE; id: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_id := LoadLibCryptoFunction('ENGINE_set_id');
  if not assigned(ENGINE_set_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_id');
  Result := ENGINE_set_id(e, id);
end;

function Load_ENGINE_set_name(e: PENGINE; name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_name := LoadLibCryptoFunction('ENGINE_set_name');
  if not assigned(ENGINE_set_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_name');
  Result := ENGINE_set_name(e, name);
end;

function Load_ENGINE_set_RSA(e: PENGINE; rsa_meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_RSA := LoadLibCryptoFunction('ENGINE_set_RSA');
  if not assigned(ENGINE_set_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_RSA');
  Result := ENGINE_set_RSA(e, rsa_meth);
end;

function Load_ENGINE_set_DSA(e: PENGINE; dsa_meth: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_DSA := LoadLibCryptoFunction('ENGINE_set_DSA');
  if not assigned(ENGINE_set_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_DSA');
  Result := ENGINE_set_DSA(e, dsa_meth);
end;

function Load_ENGINE_set_EC(e: PENGINE; ecdsa_meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_EC := LoadLibCryptoFunction('ENGINE_set_EC');
  if not assigned(ENGINE_set_EC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_EC');
  Result := ENGINE_set_EC(e, ecdsa_meth);
end;

function Load_ENGINE_set_DH(e: PENGINE; dh_meth: PDH_METHOD): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_DH := LoadLibCryptoFunction('ENGINE_set_DH');
  if not assigned(ENGINE_set_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_DH');
  Result := ENGINE_set_DH(e, dh_meth);
end;

function Load_ENGINE_set_RAND(e: PENGINE; rand_meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_RAND := LoadLibCryptoFunction('ENGINE_set_RAND');
  if not assigned(ENGINE_set_RAND) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_RAND');
  Result := ENGINE_set_RAND(e, rand_meth);
end;

function Load_ENGINE_set_destroy_function(e: PENGINE; destroy_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_destroy_function := LoadLibCryptoFunction('ENGINE_set_destroy_function');
  if not assigned(ENGINE_set_destroy_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_destroy_function');
  Result := ENGINE_set_destroy_function(e, destroy_f);
end;

function Load_ENGINE_set_init_function(e: PENGINE; init_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_init_function := LoadLibCryptoFunction('ENGINE_set_init_function');
  if not assigned(ENGINE_set_init_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_init_function');
  Result := ENGINE_set_init_function(e, init_f);
end;

function Load_ENGINE_set_finish_function(e: PENGINE; finish_f: TENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_finish_function := LoadLibCryptoFunction('ENGINE_set_finish_function');
  if not assigned(ENGINE_set_finish_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_finish_function');
  Result := ENGINE_set_finish_function(e, finish_f);
end;

function Load_ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: TENGINE_CTRL_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_ctrl_function := LoadLibCryptoFunction('ENGINE_set_ctrl_function');
  if not assigned(ENGINE_set_ctrl_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_ctrl_function');
  Result := ENGINE_set_ctrl_function(e, ctrl_f);
end;

function Load_ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_load_privkey_function := LoadLibCryptoFunction('ENGINE_set_load_privkey_function');
  if not assigned(ENGINE_set_load_privkey_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_load_privkey_function');
  Result := ENGINE_set_load_privkey_function(e, loadpriv_f);
end;

function Load_ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: TENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_load_pubkey_function := LoadLibCryptoFunction('ENGINE_set_load_pubkey_function');
  if not assigned(ENGINE_set_load_pubkey_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_load_pubkey_function');
  Result := ENGINE_set_load_pubkey_function(e, loadpub_f);
end;

function Load_ENGINE_set_load_ssl_client_cert_function(e: PENGINE; loadssl_f: TENGINE_SSL_CLIENT_CERT_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_load_ssl_client_cert_function := LoadLibCryptoFunction('ENGINE_set_load_ssl_client_cert_function');
  if not assigned(ENGINE_set_load_ssl_client_cert_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_load_ssl_client_cert_function');
  Result := ENGINE_set_load_ssl_client_cert_function(e, loadssl_f);
end;

function Load_ENGINE_set_ciphers(e: PENGINE; f: TENGINE_CIPHERS_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_ciphers := LoadLibCryptoFunction('ENGINE_set_ciphers');
  if not assigned(ENGINE_set_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_ciphers');
  Result := ENGINE_set_ciphers(e, f);
end;

function Load_ENGINE_set_digests(e: PENGINE; f: TENGINE_DIGESTS_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_digests := LoadLibCryptoFunction('ENGINE_set_digests');
  if not assigned(ENGINE_set_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_digests');
  Result := ENGINE_set_digests(e, f);
end;

function Load_ENGINE_set_pkey_meths(e: PENGINE; f: TENGINE_PKEY_METHS_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_pkey_meths := LoadLibCryptoFunction('ENGINE_set_pkey_meths');
  if not assigned(ENGINE_set_pkey_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_pkey_meths');
  Result := ENGINE_set_pkey_meths(e, f);
end;

function Load_ENGINE_set_pkey_asn1_meths(e: PENGINE; f: TENGINE_PKEY_ASN1_METHS_PTR): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_set_pkey_asn1_meths');
  if not assigned(ENGINE_set_pkey_asn1_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_pkey_asn1_meths');
  Result := ENGINE_set_pkey_asn1_meths(e, f);
end;

function Load_ENGINE_set_flags(e: PENGINE; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_flags := LoadLibCryptoFunction('ENGINE_set_flags');
  if not assigned(ENGINE_set_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_flags');
  Result := ENGINE_set_flags(e, flags);
end;

function Load_ENGINE_set_cmd_defns(e: PENGINE; defns: PENGINE_CMD_DEFN): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_cmd_defns := LoadLibCryptoFunction('ENGINE_set_cmd_defns');
  if not assigned(ENGINE_set_cmd_defns) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_cmd_defns');
  Result := ENGINE_set_cmd_defns(e, defns);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_set_ex_data(e: PENGINE; idx: TOpenSSL_C_INT; arg: pointer): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_ex_data := LoadLibCryptoFunction('ENGINE_set_ex_data');
  if not assigned(ENGINE_set_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_ex_data');
  Result := ENGINE_set_ex_data(e, idx, arg);
end;

function Load_ENGINE_get_ex_data(e: PENGINE; idx: TOpenSSL_C_INT): pointer; cdecl;
begin
  ENGINE_get_ex_data := LoadLibCryptoFunction('ENGINE_get_ex_data');
  if not assigned(ENGINE_get_ex_data) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_ex_data');
  Result := ENGINE_get_ex_data(e, idx);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_id(e: PENGINE): PAnsiChar; cdecl;
begin
  ENGINE_get_id := LoadLibCryptoFunction('ENGINE_get_id');
  if not assigned(ENGINE_get_id) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_id');
  Result := ENGINE_get_id(e);
end;

function Load_ENGINE_get_name(e: PENGINE): PAnsiChar; cdecl;
begin
  ENGINE_get_name := LoadLibCryptoFunction('ENGINE_get_name');
  if not assigned(ENGINE_get_name) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_name');
  Result := ENGINE_get_name(e);
end;

function Load_ENGINE_get_RSA(e: PENGINE): PRSA_METHOD; cdecl;
begin
  ENGINE_get_RSA := LoadLibCryptoFunction('ENGINE_get_RSA');
  if not assigned(ENGINE_get_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_RSA');
  Result := ENGINE_get_RSA(e);
end;

function Load_ENGINE_get_DSA(e: PENGINE): PDSA_METHOD; cdecl;
begin
  ENGINE_get_DSA := LoadLibCryptoFunction('ENGINE_get_DSA');
  if not assigned(ENGINE_get_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_DSA');
  Result := ENGINE_get_DSA(e);
end;

function Load_ENGINE_get_EC(e: PENGINE): PEC_KEY_METHOD; cdecl;
begin
  ENGINE_get_EC := LoadLibCryptoFunction('ENGINE_get_EC');
  if not assigned(ENGINE_get_EC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_EC');
  Result := ENGINE_get_EC(e);
end;

function Load_ENGINE_get_DH(e: PENGINE): PDH_METHOD; cdecl;
begin
  ENGINE_get_DH := LoadLibCryptoFunction('ENGINE_get_DH');
  if not assigned(ENGINE_get_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_DH');
  Result := ENGINE_get_DH(e);
end;

function Load_ENGINE_get_RAND(e: PENGINE): PRAND_METHOD; cdecl;
begin
  ENGINE_get_RAND := LoadLibCryptoFunction('ENGINE_get_RAND');
  if not assigned(ENGINE_get_RAND) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_RAND');
  Result := ENGINE_get_RAND(e);
end;

function Load_ENGINE_get_destroy_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  ENGINE_get_destroy_function := LoadLibCryptoFunction('ENGINE_get_destroy_function');
  if not assigned(ENGINE_get_destroy_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_destroy_function');
  Result := ENGINE_get_destroy_function(e);
end;

function Load_ENGINE_get_init_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  ENGINE_get_init_function := LoadLibCryptoFunction('ENGINE_get_init_function');
  if not assigned(ENGINE_get_init_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_init_function');
  Result := ENGINE_get_init_function(e);
end;

function Load_ENGINE_get_finish_function(e: PENGINE): TENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  ENGINE_get_finish_function := LoadLibCryptoFunction('ENGINE_get_finish_function');
  if not assigned(ENGINE_get_finish_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_finish_function');
  Result := ENGINE_get_finish_function(e);
end;

function Load_ENGINE_get_ctrl_function(e: PENGINE): TENGINE_CTRL_FUNC_PTR; cdecl;
begin
  ENGINE_get_ctrl_function := LoadLibCryptoFunction('ENGINE_get_ctrl_function');
  if not assigned(ENGINE_get_ctrl_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_ctrl_function');
  Result := ENGINE_get_ctrl_function(e);
end;

function Load_ENGINE_get_load_privkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl;
begin
  ENGINE_get_load_privkey_function := LoadLibCryptoFunction('ENGINE_get_load_privkey_function');
  if not assigned(ENGINE_get_load_privkey_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_load_privkey_function');
  Result := ENGINE_get_load_privkey_function(e);
end;

function Load_ENGINE_get_load_pubkey_function(e: PENGINE): TENGINE_LOAD_KEY_PTR; cdecl;
begin
  ENGINE_get_load_pubkey_function := LoadLibCryptoFunction('ENGINE_get_load_pubkey_function');
  if not assigned(ENGINE_get_load_pubkey_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_load_pubkey_function');
  Result := ENGINE_get_load_pubkey_function(e);
end;

function Load_ENGINE_get_ssl_client_cert_function(e: PENGINE): TENGINE_SSL_CLIENT_CERT_PTR; cdecl;
begin
  ENGINE_get_ssl_client_cert_function := LoadLibCryptoFunction('ENGINE_get_ssl_client_cert_function');
  if not assigned(ENGINE_get_ssl_client_cert_function) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_ssl_client_cert_function');
  Result := ENGINE_get_ssl_client_cert_function(e);
end;

function Load_ENGINE_get_ciphers(e: PENGINE): TENGINE_CIPHERS_PTR; cdecl;
begin
  ENGINE_get_ciphers := LoadLibCryptoFunction('ENGINE_get_ciphers');
  if not assigned(ENGINE_get_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_ciphers');
  Result := ENGINE_get_ciphers(e);
end;

function Load_ENGINE_get_digests(e: PENGINE): TENGINE_DIGESTS_PTR; cdecl;
begin
  ENGINE_get_digests := LoadLibCryptoFunction('ENGINE_get_digests');
  if not assigned(ENGINE_get_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_digests');
  Result := ENGINE_get_digests(e);
end;

function Load_ENGINE_get_pkey_meths(e: PENGINE): TENGINE_PKEY_METHS_PTR; cdecl;
begin
  ENGINE_get_pkey_meths := LoadLibCryptoFunction('ENGINE_get_pkey_meths');
  if not assigned(ENGINE_get_pkey_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_meths');
  Result := ENGINE_get_pkey_meths(e);
end;

function Load_ENGINE_get_pkey_asn1_meths(e: PENGINE): TENGINE_PKEY_ASN1_METHS_PTR; cdecl;
begin
  ENGINE_get_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meths');
  if not assigned(ENGINE_get_pkey_asn1_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meths');
  Result := ENGINE_get_pkey_asn1_meths(e);
end;

function Load_ENGINE_get_cipher(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
begin
  ENGINE_get_cipher := LoadLibCryptoFunction('ENGINE_get_cipher');
  if not assigned(ENGINE_get_cipher) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_cipher');
  Result := ENGINE_get_cipher(e, nid);
end;

function Load_ENGINE_get_digest(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_MD; cdecl;
begin
  ENGINE_get_digest := LoadLibCryptoFunction('ENGINE_get_digest');
  if not assigned(ENGINE_get_digest) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_digest');
  Result := ENGINE_get_digest(e, nid);
end;

function Load_ENGINE_get_pkey_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  ENGINE_get_pkey_meth := LoadLibCryptoFunction('ENGINE_get_pkey_meth');
  if not assigned(ENGINE_get_pkey_meth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_meth');
  Result := ENGINE_get_pkey_meth(e, nid);
end;

function Load_ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  ENGINE_get_pkey_asn1_meth := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meth');
  if not assigned(ENGINE_get_pkey_asn1_meth) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meth');
  Result := ENGINE_get_pkey_asn1_meth(e, nid);
end;

function Load_ENGINE_get_pkey_asn1_meth_str(e: PENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  ENGINE_get_pkey_asn1_meth_str := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meth_str');
  if not assigned(ENGINE_get_pkey_asn1_meth_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meth_str');
  Result := ENGINE_get_pkey_asn1_meth_str(e, str, len);
end;

function Load_ENGINE_pkey_asn1_find_str(pe: PPENGINE; str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  ENGINE_pkey_asn1_find_str := LoadLibCryptoFunction('ENGINE_pkey_asn1_find_str');
  if not assigned(ENGINE_pkey_asn1_find_str) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_pkey_asn1_find_str');
  Result := ENGINE_pkey_asn1_find_str(pe, str, len);
end;

function Load_ENGINE_get_cmd_defns(e: PENGINE): PENGINE_CMD_DEFN; cdecl;
begin
  ENGINE_get_cmd_defns := LoadLibCryptoFunction('ENGINE_get_cmd_defns');
  if not assigned(ENGINE_get_cmd_defns) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_cmd_defns');
  Result := ENGINE_get_cmd_defns(e);
end;

function Load_ENGINE_get_flags(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_get_flags := LoadLibCryptoFunction('ENGINE_get_flags');
  if not assigned(ENGINE_get_flags) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_flags');
  Result := ENGINE_get_flags(e);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_init(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_init := LoadLibCryptoFunction('ENGINE_init');
  if not assigned(ENGINE_init) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_init');
  Result := ENGINE_init(e);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_finish(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_finish := LoadLibCryptoFunction('ENGINE_finish');
  if not assigned(ENGINE_finish) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_finish');
  Result := ENGINE_finish(e);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_load_private_key(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl;
begin
  ENGINE_load_private_key := LoadLibCryptoFunction('ENGINE_load_private_key');
  if not assigned(ENGINE_load_private_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_load_private_key');
  Result := ENGINE_load_private_key(e, key_id, ui_method, callback_data);
end;

function Load_ENGINE_load_public_key(e: PENGINE; key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: pointer): PEVP_PKEY; cdecl;
begin
  ENGINE_load_public_key := LoadLibCryptoFunction('ENGINE_load_public_key');
  if not assigned(ENGINE_load_public_key) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_load_public_key');
  Result := ENGINE_load_public_key(e, key_id, ui_method, callback_data);
end;

function Load_ENGINE_load_ssl_client_cert(e: PENGINE; s: PSSL; ca_dn: Pstack_st_X509_NAME; pcert: PPX509; ppkey: PPEVP_PKEY; pother: PPstack_st_X509; ui_method: PUI_METHOD; callback_data: pointer): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_load_ssl_client_cert := LoadLibCryptoFunction('ENGINE_load_ssl_client_cert');
  if not assigned(ENGINE_load_ssl_client_cert) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_load_ssl_client_cert');
  Result := ENGINE_load_ssl_client_cert(e, s, ca_dn, pcert, ppkey, pother, ui_method, callback_data);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_default_RSA: PENGINE; cdecl;
begin
  ENGINE_get_default_RSA := LoadLibCryptoFunction('ENGINE_get_default_RSA');
  if not assigned(ENGINE_get_default_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_RSA');
  Result := ENGINE_get_default_RSA;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_default_DSA: PENGINE; cdecl;
begin
  ENGINE_get_default_DSA := LoadLibCryptoFunction('ENGINE_get_default_DSA');
  if not assigned(ENGINE_get_default_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_DSA');
  Result := ENGINE_get_default_DSA;
end;

function Load_ENGINE_get_default_EC: PENGINE; cdecl;
begin
  ENGINE_get_default_EC := LoadLibCryptoFunction('ENGINE_get_default_EC');
  if not assigned(ENGINE_get_default_EC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_EC');
  Result := ENGINE_get_default_EC;
end;

function Load_ENGINE_get_default_DH: PENGINE; cdecl;
begin
  ENGINE_get_default_DH := LoadLibCryptoFunction('ENGINE_get_default_DH');
  if not assigned(ENGINE_get_default_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_DH');
  Result := ENGINE_get_default_DH;
end;

function Load_ENGINE_get_default_RAND: PENGINE; cdecl;
begin
  ENGINE_get_default_RAND := LoadLibCryptoFunction('ENGINE_get_default_RAND');
  if not assigned(ENGINE_get_default_RAND) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_RAND');
  Result := ENGINE_get_default_RAND;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_cipher_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  ENGINE_get_cipher_engine := LoadLibCryptoFunction('ENGINE_get_cipher_engine');
  if not assigned(ENGINE_get_cipher_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_cipher_engine');
  Result := ENGINE_get_cipher_engine(nid);
end;

function Load_ENGINE_get_digest_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  ENGINE_get_digest_engine := LoadLibCryptoFunction('ENGINE_get_digest_engine');
  if not assigned(ENGINE_get_digest_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_digest_engine');
  Result := ENGINE_get_digest_engine(nid);
end;

function Load_ENGINE_get_pkey_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  ENGINE_get_pkey_meth_engine := LoadLibCryptoFunction('ENGINE_get_pkey_meth_engine');
  if not assigned(ENGINE_get_pkey_meth_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_meth_engine');
  Result := ENGINE_get_pkey_meth_engine(nid);
end;

function Load_ENGINE_get_pkey_asn1_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  ENGINE_get_pkey_asn1_meth_engine := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meth_engine');
  if not assigned(ENGINE_get_pkey_asn1_meth_engine) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meth_engine');
  Result := ENGINE_get_pkey_asn1_meth_engine(nid);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_set_default_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_RSA := LoadLibCryptoFunction('ENGINE_set_default_RSA');
  if not assigned(ENGINE_set_default_RSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_RSA');
  Result := ENGINE_set_default_RSA(e);
end;

function Load_ENGINE_set_default_string(e: PENGINE; def_list: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_string := LoadLibCryptoFunction('ENGINE_set_default_string');
  if not assigned(ENGINE_set_default_string) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_string');
  Result := ENGINE_set_default_string(e, def_list);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_set_default_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_DSA := LoadLibCryptoFunction('ENGINE_set_default_DSA');
  if not assigned(ENGINE_set_default_DSA) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_DSA');
  Result := ENGINE_set_default_DSA(e);
end;

function Load_ENGINE_set_default_EC(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_EC := LoadLibCryptoFunction('ENGINE_set_default_EC');
  if not assigned(ENGINE_set_default_EC) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_EC');
  Result := ENGINE_set_default_EC(e);
end;

function Load_ENGINE_set_default_DH(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_DH := LoadLibCryptoFunction('ENGINE_set_default_DH');
  if not assigned(ENGINE_set_default_DH) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_DH');
  Result := ENGINE_set_default_DH(e);
end;

function Load_ENGINE_set_default_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_RAND := LoadLibCryptoFunction('ENGINE_set_default_RAND');
  if not assigned(ENGINE_set_default_RAND) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_RAND');
  Result := ENGINE_set_default_RAND(e);
end;

function Load_ENGINE_set_default_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_ciphers := LoadLibCryptoFunction('ENGINE_set_default_ciphers');
  if not assigned(ENGINE_set_default_ciphers) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_ciphers');
  Result := ENGINE_set_default_ciphers(e);
end;

function Load_ENGINE_set_default_digests(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_digests := LoadLibCryptoFunction('ENGINE_set_default_digests');
  if not assigned(ENGINE_set_default_digests) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_digests');
  Result := ENGINE_set_default_digests(e);
end;

function Load_ENGINE_set_default_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_pkey_meths := LoadLibCryptoFunction('ENGINE_set_default_pkey_meths');
  if not assigned(ENGINE_set_default_pkey_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_pkey_meths');
  Result := ENGINE_set_default_pkey_meths(e);
end;

function Load_ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_set_default_pkey_asn1_meths');
  if not assigned(ENGINE_set_default_pkey_asn1_meths) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_pkey_asn1_meths');
  Result := ENGINE_set_default_pkey_asn1_meths(e);
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_set_default(e: PENGINE; flags: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  ENGINE_set_default := LoadLibCryptoFunction('ENGINE_set_default');
  if not assigned(ENGINE_set_default) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default');
  Result := ENGINE_set_default(e, flags);
end;

procedure Load_ENGINE_add_conf_module; cdecl;
begin
  ENGINE_add_conf_module := LoadLibCryptoFunction('ENGINE_add_conf_module');
  if not assigned(ENGINE_add_conf_module) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_add_conf_module');
  ENGINE_add_conf_module;
end;

    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
function Load_ENGINE_get_static_state: pointer; cdecl;
begin
  ENGINE_get_static_state := LoadLibCryptoFunction('ENGINE_get_static_state');
  if not assigned(ENGINE_get_static_state) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_static_state');
  Result := ENGINE_get_static_state;
end;

    {$if  defined(__OpenBSD__)  or defined(__FreeBSD__)  or defined(__DragonFly__)}
        {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
procedure Load_ENGINE_setup_bsd_cryptodev; cdecl;
begin
  ENGINE_setup_bsd_cryptodev := LoadLibCryptoFunction('ENGINE_setup_bsd_cryptodev');
  if not assigned(ENGINE_setup_bsd_cryptodev) then
    EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_setup_bsd_cryptodev');
  ENGINE_setup_bsd_cryptodev;
end;

        {$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
    {$endif} { defined(__OpenBSD__)  or  defined(__FreeBSD__)  or  defined(__DragonFly__)}
{$endif} { OPENSSL_NO_ENGINE}
procedure Load;
begin
  {$define EMPTY_LOAD_FUNCTION}
end;

procedure Unload;
begin
{$ifndef  OPENSSL_NO_ENGINE}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_first := Load_ENGINE_get_first;
  ENGINE_get_last := Load_ENGINE_get_last;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_next := Load_ENGINE_get_next;
  ENGINE_get_prev := Load_ENGINE_get_prev;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_add := Load_ENGINE_add;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_remove := Load_ENGINE_remove;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_by_id := Load_ENGINE_by_id;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_load_builtin_engines := Load_ENGINE_load_builtin_engines;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_table_flags := Load_ENGINE_get_table_flags;
  ENGINE_set_table_flags := Load_ENGINE_set_table_flags;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_register_RSA := Load_ENGINE_register_RSA;
  ENGINE_unregister_RSA := Load_ENGINE_unregister_RSA;
  ENGINE_register_all_RSA := Load_ENGINE_register_all_RSA;
  ENGINE_register_DSA := Load_ENGINE_register_DSA;
  ENGINE_unregister_DSA := Load_ENGINE_unregister_DSA;
  ENGINE_register_all_DSA := Load_ENGINE_register_all_DSA;
  ENGINE_register_EC := Load_ENGINE_register_EC;
  ENGINE_unregister_EC := Load_ENGINE_unregister_EC;
  ENGINE_register_all_EC := Load_ENGINE_register_all_EC;
  ENGINE_register_DH := Load_ENGINE_register_DH;
  ENGINE_unregister_DH := Load_ENGINE_unregister_DH;
  ENGINE_register_all_DH := Load_ENGINE_register_all_DH;
  ENGINE_register_RAND := Load_ENGINE_register_RAND;
  ENGINE_unregister_RAND := Load_ENGINE_unregister_RAND;
  ENGINE_register_all_RAND := Load_ENGINE_register_all_RAND;
  ENGINE_register_ciphers := Load_ENGINE_register_ciphers;
  ENGINE_unregister_ciphers := Load_ENGINE_unregister_ciphers;
  ENGINE_register_all_ciphers := Load_ENGINE_register_all_ciphers;
  ENGINE_register_digests := Load_ENGINE_register_digests;
  ENGINE_unregister_digests := Load_ENGINE_unregister_digests;
  ENGINE_register_all_digests := Load_ENGINE_register_all_digests;
  ENGINE_register_pkey_meths := Load_ENGINE_register_pkey_meths;
  ENGINE_unregister_pkey_meths := Load_ENGINE_unregister_pkey_meths;
  ENGINE_register_all_pkey_meths := Load_ENGINE_register_all_pkey_meths;
  ENGINE_register_pkey_asn1_meths := Load_ENGINE_register_pkey_asn1_meths;
  ENGINE_unregister_pkey_asn1_meths := Load_ENGINE_unregister_pkey_asn1_meths;
  ENGINE_register_all_pkey_asn1_meths := Load_ENGINE_register_all_pkey_asn1_meths;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_register_complete := Load_ENGINE_register_complete;
  ENGINE_register_all_complete := Load_ENGINE_register_all_complete;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_ctrl := Load_ENGINE_ctrl;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_cmd_is_executable := Load_ENGINE_cmd_is_executable;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_ctrl_cmd := Load_ENGINE_ctrl_cmd;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_ctrl_cmd_string := Load_ENGINE_ctrl_cmd_string;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_new := Load_ENGINE_new;
  ENGINE_free := Load_ENGINE_free;
  ENGINE_up_ref := Load_ENGINE_up_ref;
  ENGINE_set_id := Load_ENGINE_set_id;
  ENGINE_set_name := Load_ENGINE_set_name;
  ENGINE_set_RSA := Load_ENGINE_set_RSA;
  ENGINE_set_DSA := Load_ENGINE_set_DSA;
  ENGINE_set_EC := Load_ENGINE_set_EC;
  ENGINE_set_DH := Load_ENGINE_set_DH;
  ENGINE_set_RAND := Load_ENGINE_set_RAND;
  ENGINE_set_destroy_function := Load_ENGINE_set_destroy_function;
  ENGINE_set_init_function := Load_ENGINE_set_init_function;
  ENGINE_set_finish_function := Load_ENGINE_set_finish_function;
  ENGINE_set_ctrl_function := Load_ENGINE_set_ctrl_function;
  ENGINE_set_load_privkey_function := Load_ENGINE_set_load_privkey_function;
  ENGINE_set_load_pubkey_function := Load_ENGINE_set_load_pubkey_function;
  ENGINE_set_load_ssl_client_cert_function := Load_ENGINE_set_load_ssl_client_cert_function;
  ENGINE_set_ciphers := Load_ENGINE_set_ciphers;
  ENGINE_set_digests := Load_ENGINE_set_digests;
  ENGINE_set_pkey_meths := Load_ENGINE_set_pkey_meths;
  ENGINE_set_pkey_asn1_meths := Load_ENGINE_set_pkey_asn1_meths;
  ENGINE_set_flags := Load_ENGINE_set_flags;
  ENGINE_set_cmd_defns := Load_ENGINE_set_cmd_defns;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_set_ex_data := Load_ENGINE_set_ex_data;
  ENGINE_get_ex_data := Load_ENGINE_get_ex_data;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_id := Load_ENGINE_get_id;
  ENGINE_get_name := Load_ENGINE_get_name;
  ENGINE_get_RSA := Load_ENGINE_get_RSA;
  ENGINE_get_DSA := Load_ENGINE_get_DSA;
  ENGINE_get_EC := Load_ENGINE_get_EC;
  ENGINE_get_DH := Load_ENGINE_get_DH;
  ENGINE_get_RAND := Load_ENGINE_get_RAND;
  ENGINE_get_destroy_function := Load_ENGINE_get_destroy_function;
  ENGINE_get_init_function := Load_ENGINE_get_init_function;
  ENGINE_get_finish_function := Load_ENGINE_get_finish_function;
  ENGINE_get_ctrl_function := Load_ENGINE_get_ctrl_function;
  ENGINE_get_load_privkey_function := Load_ENGINE_get_load_privkey_function;
  ENGINE_get_load_pubkey_function := Load_ENGINE_get_load_pubkey_function;
  ENGINE_get_ssl_client_cert_function := Load_ENGINE_get_ssl_client_cert_function;
  ENGINE_get_ciphers := Load_ENGINE_get_ciphers;
  ENGINE_get_digests := Load_ENGINE_get_digests;
  ENGINE_get_pkey_meths := Load_ENGINE_get_pkey_meths;
  ENGINE_get_pkey_asn1_meths := Load_ENGINE_get_pkey_asn1_meths;
  ENGINE_get_cipher := Load_ENGINE_get_cipher;
  ENGINE_get_digest := Load_ENGINE_get_digest;
  ENGINE_get_pkey_meth := Load_ENGINE_get_pkey_meth;
  ENGINE_get_pkey_asn1_meth := Load_ENGINE_get_pkey_asn1_meth;
  ENGINE_get_pkey_asn1_meth_str := Load_ENGINE_get_pkey_asn1_meth_str;
  ENGINE_pkey_asn1_find_str := Load_ENGINE_pkey_asn1_find_str;
  ENGINE_get_cmd_defns := Load_ENGINE_get_cmd_defns;
  ENGINE_get_flags := Load_ENGINE_get_flags;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_init := Load_ENGINE_init;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_finish := Load_ENGINE_finish;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_load_private_key := Load_ENGINE_load_private_key;
  ENGINE_load_public_key := Load_ENGINE_load_public_key;
  ENGINE_load_ssl_client_cert := Load_ENGINE_load_ssl_client_cert;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_default_RSA := Load_ENGINE_get_default_RSA;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_default_DSA := Load_ENGINE_get_default_DSA;
  ENGINE_get_default_EC := Load_ENGINE_get_default_EC;
  ENGINE_get_default_DH := Load_ENGINE_get_default_DH;
  ENGINE_get_default_RAND := Load_ENGINE_get_default_RAND;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_cipher_engine := Load_ENGINE_get_cipher_engine;
  ENGINE_get_digest_engine := Load_ENGINE_get_digest_engine;
  ENGINE_get_pkey_meth_engine := Load_ENGINE_get_pkey_meth_engine;
  ENGINE_get_pkey_asn1_meth_engine := Load_ENGINE_get_pkey_asn1_meth_engine;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_set_default_RSA := Load_ENGINE_set_default_RSA;
  ENGINE_set_default_string := Load_ENGINE_set_default_string;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_set_default_DSA := Load_ENGINE_set_default_DSA;
  ENGINE_set_default_EC := Load_ENGINE_set_default_EC;
  ENGINE_set_default_DH := Load_ENGINE_set_default_DH;
  ENGINE_set_default_RAND := Load_ENGINE_set_default_RAND;
  ENGINE_set_default_ciphers := Load_ENGINE_set_default_ciphers;
  ENGINE_set_default_digests := Load_ENGINE_set_default_digests;
  ENGINE_set_default_pkey_meths := Load_ENGINE_set_default_pkey_meths;
  ENGINE_set_default_pkey_asn1_meths := Load_ENGINE_set_default_pkey_asn1_meths;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
    {$ifndef  OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_set_default := Load_ENGINE_set_default;
  ENGINE_add_conf_module := Load_ENGINE_add_conf_module;
    {$endif} { OPENSSL_NO_DEPRECATED_3_0}
  ENGINE_get_static_state := Load_ENGINE_get_static_state;
    {$if  defined(__OpenBSD__)  or defined(__FreeBSD__)  or defined(__DragonFly__)}
        {$ifndef  OPENSSL_NO_DEPRECATED_1_1_0}
  ENGINE_setup_bsd_cryptodev := Load_ENGINE_setup_bsd_cryptodev;
        {$endif} { OPENSSL_NO_DEPRECATED_1_1_0}
    {$endif} { defined(__OpenBSD__)  or  defined(__FreeBSD__)  or  defined(__DragonFly__)}
{$endif} { OPENSSL_NO_ENGINE}
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



