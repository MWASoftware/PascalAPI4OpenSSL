(* This unit was generated from the source file engine.h2pas 
It should not be modified directly. All changes should be made to engine.h2pas
and this file regenerated *)

{$i OpenSSLDefines.inc}

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


unit OpenSSL_engine;


interface

// Headers for OpenSSL 1.1.1
// engine.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_ec;

const
  (*
   * These flags are used to control combinations of algorithm (methods) by
   * bitwise "OR"ing.
   *)
  ENGINE_METHOD_RSA               = TOpenSSL_C_UINT($0001);
  ENGINE_METHOD_DSA               = TOpenSSL_C_UINT($0002);
  ENGINE_METHOD_DH                = TOpenSSL_C_UINT($0004);
  ENGINE_METHOD_RAND              = TOpenSSL_C_UINT($0008);
  ENGINE_METHOD_CIPHERS           = TOpenSSL_C_UINT($0040);
  ENGINE_METHOD_DIGESTS           = TOpenSSL_C_UINT($0080);
  ENGINE_METHOD_PKEY_METHS        = TOpenSSL_C_UINT($0200);
  ENGINE_METHOD_PKEY_ASN1_METHS   = TOpenSSL_C_UINT($0400);
  ENGINE_METHOD_EC                = TOpenSSL_C_UINT($0800);
  (* Obvious all-or-nothing cases. *)
  ENGINE_METHOD_ALL               = TOpenSSL_C_UINT($FFFF);
  ENGINE_METHOD_NONE              = TOpenSSL_C_UINT($0000);

  //
  // This(ese) flag(s) controls behaviour of the ENGINE_TABLE mechanism used
  // internally to control registration of ENGINE implementations, and can be
  // set by ENGINE_set_table_flags(). The "NOINIT" flag prevents attempts to
  // initialise registered ENGINEs if they are not already initialised.
  //
  ENGINE_TABLE_FLAG_NOINIT        = TOpenSSL_C_UINT($0001);

  //
  // This flag is for ENGINEs that wish to handle the various 'CMD'-related
  // control commands on their own. Without this flag, ENGINE_ctrl() handles
  // these control commands on behalf of the ENGINE using their "cmd_defns"
  // data.
  //
  ENGINE_FLAGS_MANUAL_CMD_CTRL    = TOpenSSL_C_INT($0002);

  //
  // This flag is for ENGINEs who return new duplicate structures when found
  // via "ENGINE_by_id()". When an ENGINE must store state (eg. if
  // ENGINE_ctrl() commands are called in sequence as part of some stateful
  // process like key-generation setup and execution), it can set this flag -
  // then each attempt to obtain the ENGINE will result in it being copied intoo
  // a new structure. Normally, ENGINEs don't declare this flag so
  // ENGINE_by_id() just increments the existing ENGINE's structural reference
  // count.
  //
  ENGINE_FLAGS_BY_ID_COPY         = TOpenSSL_C_INT($0004);

  //
  // This flag if for an ENGINE that does not want its methods registered as
  // part of ENGINE_register_all_complete() for example if the methods are not
  // usable as default methods.
  //

  ENGINE_FLAGS_NO_REGISTER_ALL    = TOpenSSL_C_INT($0008);

  //
  // ENGINEs can support their own command types, and these flags are used in
  // ENGINE_CTRL_GET_CMD_FLAGS to indicate to the caller what kind of input
  // each command expects. Currently only numeric and string input is
  // supported. If a control command supports none of the _NUMERIC, _STRING, or
  // _NO_INPUT options, then it is regarded as an "internal" control command -
  // and not for use in config setting situations. As such, they're not
  // available to the ENGINE_ctrl_cmd_string() function, only raw ENGINE_ctrl()
  // access. Changes to this list of 'command types' should be reflected
  // carefully in ENGINE_cmd_is_executable() and ENGINE_ctrl_cmd_string().
  //

  // accepts a 'long' input value (3rd parameter to ENGINE_ctrl) */
  ENGINE_CMD_FLAG_NUMERIC         = TOpenSSL_C_UINT($0001);
  //
  // accepts string input (cast from 'void*' to 'const char *', 4th parameter
  // to ENGINE_ctrl)
  //
  ENGINE_CMD_FLAG_STRING          = TOpenSSL_C_UINT($0002);
  //
  // Indicates that the control command takes *no* input. Ie. the control
  // command is unparameterised.
  //
  ENGINE_CMD_FLAG_NO_INPUT        = TOpenSSL_C_UINT($0004);
  //
  // Indicates that the control command is internal. This control command won't
  // be shown in any output, and is only usable through the ENGINE_ctrl_cmd()
  // function.
  //
  ENGINE_CMD_FLAG_INTERNAL        = TOpenSSL_C_UINT($0008);

  //
  // NB: These 3 control commands are deprecated and should not be used.
  // ENGINEs relying on these commands should compile conditional support for
  // compatibility (eg. if these symbols are defined) but should also migrate
  // the same functionality to their own ENGINE-specific control functions that
  // can be "discovered" by calling applications. The fact these control
  // commands wouldn't be "executable" (ie. usable by text-based config)
  // doesn't change the fact that application code can find and use them
  // without requiring per-ENGINE hacking.
  //

  //
  // These flags are used to tell the ctrl function what should be done. All
  // command numbers are shared between all engines, even if some don't make
  // sense to some engines.  In such a case, they do nothing but return the
  // error ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED.
  //
  ENGINE_CTRL_SET_LOGSTREAM              = 1;
  ENGINE_CTRL_SET_PASSWORD_CALLBACK      = 2;
  ENGINE_CTRL_HUP                        = 3;// Close and reinitialise
                                             // any handles/connections
                                             // etc.
  ENGINE_CTRL_SET_USER_INTERFACE         = 4;// Alternative to callback
  ENGINE_CTRL_SET_CALLBACK_DATA          = 5;// User-specific data, used
                                             // when calling the password
                                             // callback and the user
                                             // interface
  ENGINE_CTRL_LOAD_CONFIGURATION         = 6;// Load a configuration,
                                             // given a string that
                                             // represents a file name
                                             // or so
  ENGINE_CTRL_LOAD_SECTION               = 7;// Load data from a given
                                             // section in the already
                                             // loaded configuration

  //
  // These control commands allow an application to deal with an arbitrary
  // engine in a dynamic way. Warn: Negative return values indicate errors FOR
  // THESE COMMANDS because zero is used to indicate 'end-of-list'. Other
  // commands, including ENGINE-specific command types, return zero for an
  // error. An ENGINE can choose to implement these ctrl functions, and can
  // internally manage things however it chooses - it does so by setting the
  // ENGINE_FLAGS_MANUAL_CMD_CTRL flag (using ENGINE_set_flags()). Otherwise
  // the ENGINE_ctrl() code handles this on the ENGINE's behalf using the
  // cmd_defns data (set using ENGINE_set_cmd_defns()). This means an ENGINE's
  // ctrl() handler need only implement its own commands - the above "meta"
  // commands will be taken care of.
  //

  //
  // Returns non-zero if the supplied ENGINE has a ctrl() handler. If "not",
  // then all the remaining control commands will return failure, so it is
  // worth checking this first if the caller is trying to "discover" the
  // engine's capabilities and doesn't want errors generated unnecessarily.
  //
  ENGINE_CTRL_HAS_CTRL_FUNCTION          = 10;
  //
  // Returns a positive command number for the first command supported by the
  // engine. Returns zero if no ctrl commands are supported.
  //
  ENGINE_CTRL_GET_FIRST_CMD_TYPE         = 11;
  //
  // The 'long' argument specifies a command implemented by the engine, and the
  // return value is the next command supported, or zero if there are no more.
  //
  ENGINE_CTRL_GET_NEXT_CMD_TYPE          = 12;
  //
  // The 'void*' argument is a command name (cast from 'const char *'), and the
  // return value is the command that corresponds to it.
  //
  ENGINE_CTRL_GET_CMD_FROM_NAME          = 13;
  //
  // The next two allow a command to be converted into its corresponding string
  // form. In each case, the 'long' argument supplies the command. In the
  // NAME_LEN case, the return value is the length of the command name (not
  // counting a trailing EOL). In the NAME case, the 'void*' argument must be a
  // string buffer large enough, and it will be populated with the name of the
  // command (WITH a trailing EOL).
  //
  ENGINE_CTRL_GET_NAME_LEN_FROM_CMD      = 14;
  ENGINE_CTRL_GET_NAME_FROM_CMD          = 15;
  // The next two are similar but give a "short description" of a command. */
  ENGINE_CTRL_GET_DESC_LEN_FROM_CMD      = 16;
  ENGINE_CTRL_GET_DESC_FROM_CMD          = 17;
  //
  // With this command, the return value is the OR'd combination of
  // ENGINE_CMD_FLAG_*** values that indicate what kind of input a given
  // engine-specific ctrl command expects.
  //
  ENGINE_CTRL_GET_CMD_FLAGS              = 18;

  //
  // ENGINE implementations should start the numbering of their own control
  // commands from this value. (ie. ENGINE_CMD_BASE, ENGINE_CMD_BASE += 1, etc).
  //
  ENGINE_CMD_BASE                        = 200;

  //
  // NB: These 2 nCipher "chil" control commands are deprecated, and their
  // functionality is now available through ENGINE-specific control commands
  // (exposed through the above-mentioned 'CMD'-handling). Code using these 2
  // commands should be migrated to the more general command handling before
  // these are removed.
  //

  // Flags specific to the nCipher "chil" engine */
  ENGINE_CTRL_CHIL_SET_FORKCHECK         = 100;
  //
  // Depending on the value of the (long)i argument, this sets or
  // unsets the SimpleForkCheck flag in the CHIL API to enable or
  // disable checking and workarounds for applications that fork().
  //
  ENGINE_CTRL_CHIL_NO_LOCKING            = 101;
  //
  // This prevents the initialisation function from providing mutex
  // callbacks to the nCipher library.
  //

type
  //
  // If an ENGINE supports its own specific control commands and wishes the
  // framework to handle the above 'ENGINE_CMD_***'-manipulation commands on
  // its behalf, it should supply a null-terminated array of ENGINE_CMD_DEFN
  // entries to ENGINE_set_cmd_defns(). It should also implement a ctrl()
  // handler that supports the stated commands (ie. the "cmd_num" entries as
  // described by the array). NB: The array must be ordered in increasing order
  // of cmd_num. "null-terminated" means that the last ENGINE_CMD_DEFN element
  // has cmd_num set to zero and/or cmd_name set to NULL.
  //
  ENGINE_CMD_DEFN_st = record
    cmd_num: TOpenSSL_C_UINT;
    cmd_name: PAnsiChar;
    cmd_desc: PAnsiChar;
    cmd_flags: TOpenSSL_C_UINT;
  end;
  ENGINE_CMD_DEFN = ENGINE_CMD_DEFN_st;
  PENGINE_CMD_DEFN = ^ENGINE_CMD_DEFN;

  // Generic function pointer */
  ENGINE_GEN_FUNC_PTR = function: TOpenSSL_C_INT; cdecl;
  // Generic function pointer taking no arguments */
  ENGINE_GEN_INT_FUNC_PTR = function(v1: PENGINE): TOpenSSL_C_INT; cdecl;
  // Specific control function pointer */
  f = procedure; cdecl;
  ENGINE_CTRL_FUNC_PTR = function(v1: PENGINE; v2: TOpenSSL_C_INT; v3: TOpenSSL_C_LONG; v4: Pointer; v5: f): TOpenSSL_C_INT; cdecl;
  // Generic load_key function pointer */
  ENGINE_LOAD_KEY_PTR = function(v1: PENGINE; const v2: PAnsiChar;
    ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl;
  //ENGINE_SSL_CLIENT_CERT_PTR = function(v1: PENGINE; ssl: PSSL;
  //  {STACK_OF(X509_NAME) *ca_dn;} pcert: PPX509; pkey: PPEVP_PKEY;
  //  {STACK_OF(X509) **pother;} ui_method: PUI_METHOD; callback_data: Pointer): TOpenSSL_C_INT; cdecl;

  //
  // These callback types are for an ENGINE's handler for cipher and digest logic.
  // These handlers have these prototypes;
  //   int foo(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
  //   int foo(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
  // Looking at how to implement these handlers in the case of cipher support, if
  // the framework wants the EVP_CIPHER for 'nid', it will call;
  //   foo(e, &p_evp_cipher, NULL, nid);    (return zero for failure)
  // If the framework wants a list of supported 'nid's, it will call;
  //   foo(e, NULL, &p_nids, 0); (returns number of 'nids' or -1 for error)
  //
  //
  // Returns to a pointer to the array of supported cipher 'nid's. If the
  // second parameter is non-NULL it is set to the size of the returned array.
  //
  ENGINE_CIPHERS_PTR = function(v1: PENGINE; const v2: PPEVP_CIPHER;
    const v3: PPOpenSSL_C_INT; v4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  ENGINE_DIGESTS_PTR = function(v1: PENGINE; const v2: PPEVP_MD;
    const v3: PPOpenSSL_C_INT; v4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  ENGINE_PKEY_METHS_PTR = function(v1: PENGINE; v2: PPEVP_PKEY_METHOD;
    const v3: PPOpenSSL_C_INT; v4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
  ENGINE_PKEY_ASN1_METHS_PTR = function(v1: PENGINE; v2: PPEVP_PKEY_ASN1_METHOD;
    const v3: PPOpenSSL_C_INT; v4: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

  dyn_MEM_malloc_fn = function(v1: TOpenSSL_C_SIZET; const v2: PAnsiChar; v3: TOpenSSL_C_INT): Pointer; cdecl;
  dyn_MEM_realloc_fn = function(v1: Pointer; v2: TOpenSSL_C_SIZET; const v3: PAnsiChar; v4: TOpenSSL_C_INT): Pointer; cdecl;
  dyn_MEM_free_fn = procedure(v1: Pointer; const v2: PAnsiChar; v3: TOpenSSL_C_INT); cdecl;

  st_dynamic_MEM_fns = record
    malloc_fn: dyn_MEM_malloc_fn;
    realloc_fn: dyn_MEM_realloc_fn;
    free_fn: dyn_MEM_free_fn;
  end;
  dynamic_MEM_fns = st_dynamic_MEM_fns;
  
  //*
  // * FIXME: Perhaps the memory and locking code (crypto.h) should declare and
  // * use these types so we (and any other dependent code) can simplify a bit??
  // */
  //* The top-level structure */
  st_dynamic_fns = record
    static_state: Pointer;
    mem_fns: dynamic_MEM_fns;
  end;
  dynamic_fns = st_dynamic_fns;

  //*
  // * The version checking function should be of this prototype. NB: The
  // * ossl_version value passed in is the OSSL_DYNAMIC_VERSION of the loading
  // * code. If this function returns zero, it indicates a (potential) version
  // * incompatibility and the loaded library doesn't believe it can proceed.
  // * Otherwise, the returned value is the (latest) version supported by the
  // * loading library. The loader may still decide that the loaded code's
  // * version is unsatisfactory and could veto the load. The function is
  // * expected to be implemented with the symbol name "v_check", and a default
  // * implementation can be fully instantiated with
  // * IMPLEMENT_DYNAMIC_CHECK_FN().
  // */
  dynamic_v_check_fn = function(ossl_version: TOpenSSL_C_ULONG): TOpenSSL_C_ULONG; cdecl;
  //# define IMPLEMENT_DYNAMIC_CHECK_FN() \
  //        OPENSSL_EXPORT unsigned long v_check(unsigned long v); \
  //        OPENSSL_EXPORT unsigned long v_check(unsigned long v) { \
  //                if (v >= OSSL_DYNAMIC_OLDEST) return OSSL_DYNAMIC_VERSION; \
  //                return 0; }

  //*
  // * This function is passed the ENGINE structure to initialise with its own
  // * function and command settings. It should not adjust the structural or
  // * functional reference counts. If this function returns zero, (a) the load
  // * will be aborted, (b) the previous ENGINE state will be memcpy'd back onto
  // * the structure, and (c) the shared library will be unloaded. So
  // * implementations should do their own internal cleanup in failure
  // * circumstances otherwise they could leak. The 'id' parameter, if non-NULL,
  // * represents the ENGINE id that the loader is looking for. If this is NULL,
  // * the shared library can choose to return failure or to initialise a
  // * 'default' ENGINE. If non-NULL, the shared library must initialise only an
  // * ENGINE matching the passed 'id'. The function is expected to be
  // * implemented with the symbol name "bind_engine". A standard implementation
  // * can be instantiated with IMPLEMENT_DYNAMIC_BIND_FN(fn) where the parameter
  // * 'fn' is a callback function that populates the ENGINE structure and
  // * returns an int value (zero for failure). 'fn' should have prototype;
  // * [static] int fn(ENGINE *e, const char *id);
  // */
  dynamic_bind_engine = function(e: PENGINE; const id: PAnsiChar;
    const fns: dynamic_fns): TOpenSSL_C_INT; cdecl;

  //
  // STRUCTURE functions ... all of these functions deal with pointers to
  // ENGINE structures where the pointers have a "structural reference". This
  // means that their reference is to allowed access to the structure but it
  // does not imply that the structure is functional. To simply increment or
  // decrement the structural reference count, use ENGINE_by_id and
  // ENGINE_free. NB: This is not required when iterating using ENGINE_get_next
  // as it will automatically decrement the structural reference count of the
  // "current" ENGINE and increment the structural reference count of the
  // ENGINE it returns (unless it is NULL).
  //
  // Get the first/last "ENGINE" type available. */
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ENGINE_get_first}
{$EXTERNALSYM ENGINE_get_last}
{$EXTERNALSYM ENGINE_get_next}
{$EXTERNALSYM ENGINE_get_prev}
{$EXTERNALSYM ENGINE_add}
{$EXTERNALSYM ENGINE_remove}
{$EXTERNALSYM ENGINE_by_id}
{$EXTERNALSYM ENGINE_load_builtin_engines}
{$EXTERNALSYM ENGINE_get_table_flags}
{$EXTERNALSYM ENGINE_set_table_flags}
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
{$EXTERNALSYM ENGINE_register_complete}
{$EXTERNALSYM ENGINE_register_all_complete}
{$EXTERNALSYM ENGINE_ctrl}
{$EXTERNALSYM ENGINE_cmd_is_executable}
{$EXTERNALSYM ENGINE_ctrl_cmd}
{$EXTERNALSYM ENGINE_ctrl_cmd_string}
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
{$EXTERNALSYM ENGINE_set_ciphers}
{$EXTERNALSYM ENGINE_set_digests}
{$EXTERNALSYM ENGINE_set_pkey_meths}
{$EXTERNALSYM ENGINE_set_pkey_asn1_meths}
{$EXTERNALSYM ENGINE_set_flags}
{$EXTERNALSYM ENGINE_set_cmd_defns}
{$EXTERNALSYM ENGINE_set_ex_data}
{$EXTERNALSYM ENGINE_get_ex_data}
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
{$EXTERNALSYM ENGINE_init}
{$EXTERNALSYM ENGINE_finish}
{$EXTERNALSYM ENGINE_load_private_key}
{$EXTERNALSYM ENGINE_load_public_key}
{$EXTERNALSYM ENGINE_get_default_RSA}
{$EXTERNALSYM ENGINE_get_default_DSA}
{$EXTERNALSYM ENGINE_get_default_EC}
{$EXTERNALSYM ENGINE_get_default_DH}
{$EXTERNALSYM ENGINE_get_default_RAND}
{$EXTERNALSYM ENGINE_get_cipher_engine}
{$EXTERNALSYM ENGINE_get_digest_engine}
{$EXTERNALSYM ENGINE_get_pkey_meth_engine}
{$EXTERNALSYM ENGINE_get_pkey_asn1_meth_engine}
{$EXTERNALSYM ENGINE_set_default_RSA}
{$EXTERNALSYM ENGINE_set_default_string}
{$EXTERNALSYM ENGINE_set_default_DSA}
{$EXTERNALSYM ENGINE_set_default_EC}
{$EXTERNALSYM ENGINE_set_default_DH}
{$EXTERNALSYM ENGINE_set_default_RAND}
{$EXTERNALSYM ENGINE_set_default_ciphers}
{$EXTERNALSYM ENGINE_set_default_digests}
{$EXTERNALSYM ENGINE_set_default_pkey_meths}
{$EXTERNALSYM ENGINE_set_default_pkey_asn1_meths}
{$EXTERNALSYM ENGINE_set_default}
{$EXTERNALSYM ENGINE_add_conf_module}
{$EXTERNALSYM ENGINE_get_static_state}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function ENGINE_get_first: PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_last: PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_next(e: PENGINE): PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_prev(e: PENGINE): PENGINE; cdecl; external CLibCrypto;
function ENGINE_add(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_remove(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_by_id(const id: PAnsiChar): PENGINE; cdecl; external CLibCrypto;
procedure ENGINE_load_builtin_engines; cdecl; external CLibCrypto;
function ENGINE_get_table_flags: TOpenSSL_C_UINT; cdecl; external CLibCrypto;
procedure ENGINE_set_table_flags(flags: TOpenSSL_C_UINT); cdecl; external CLibCrypto;
function ENGINE_register_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_RSA(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_RSA; cdecl; external CLibCrypto;
function ENGINE_register_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_DSA(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_DSA; cdecl; external CLibCrypto;
function ENGINE_register_EC(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_EC(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_EC; cdecl; external CLibCrypto;
function ENGINE_register_DH(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_DH(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_DH; cdecl; external CLibCrypto;
function ENGINE_register_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_RAND(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_RAND; cdecl; external CLibCrypto;
function ENGINE_register_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_ciphers(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_ciphers; cdecl; external CLibCrypto;
function ENGINE_register_digests(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_digests(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_digests; cdecl; external CLibCrypto;
function ENGINE_register_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_pkey_meths(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_pkey_meths; cdecl; external CLibCrypto;
function ENGINE_register_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl; external CLibCrypto;
procedure ENGINE_register_all_pkey_asn1_meths; cdecl; external CLibCrypto;
function ENGINE_register_complete(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_register_all_complete: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_ctrl(e: PENGINE; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; v1: f): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_cmd_is_executable(e: PENGINE; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_ctrl_cmd(e: PENGINE; const cmd_name: PAnsiChar; i: TOpenSSL_C_LONG; p: Pointer; v1: f; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_ctrl_cmd_string(e: PENGINE; const cmd_name: PAnsiChar; const arg: PAnsiChar; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_new: PENGINE; cdecl; external CLibCrypto;
function ENGINE_free(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_up_ref(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_id(e: PENGINE; const id: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_name(e: PENGINE; const name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_RSA(e: PENGINE; const rsa_meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_DSA(e: PENGINE; const dsa_meth: PDSA_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_EC(e: PENGINE; const ecdsa_meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_DH(e: PENGINE; const dh_meth: PDH_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_RAND(e: PENGINE; const rand_meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_destroy_function(e: PENGINE; destroy_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_init_function(e: PENGINE; init_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_finish_function(e: PENGINE; finish_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: ENGINE_CTRL_FUNC_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: ENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: ENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_ciphers(e: PENGINE; f: ENGINE_CIPHERS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_digests(e: PENGINE; f: ENGINE_DIGESTS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_pkey_meths(e: PENGINE; f: ENGINE_PKEY_METHS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_pkey_asn1_meths(e: PENGINE; f: ENGINE_PKEY_ASN1_METHS_PTR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_flags(e: PENGINE; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_cmd_defns(e: PENGINE; const defns: PENGINE_CMD_DEFN): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_ex_data(e: PENGINE; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_get_ex_data(const e: PENGINE; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function ENGINE_get_id(const e: PENGINE): PAnsiChar; cdecl; external CLibCrypto;
function ENGINE_get_name(const e: PENGINE): PAnsiChar; cdecl; external CLibCrypto;
function ENGINE_get_RSA(const e: PENGINE): PRSA_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_DSA(const e: PENGINE): PDSA_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_EC(const e: PENGINE): PEC_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_DH(const e: PENGINE): PDH_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_RAND(const e: PENGINE): PRAND_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_destroy_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl; external CLibCrypto;
function ENGINE_get_init_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl; external CLibCrypto;
function ENGINE_get_finish_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl; external CLibCrypto;
function ENGINE_get_ctrl_function(const e: PENGINE): ENGINE_CTRL_FUNC_PTR; cdecl; external CLibCrypto;
function ENGINE_get_load_privkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl; external CLibCrypto;
function ENGINE_get_load_pubkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl; external CLibCrypto;
function ENGINE_get_ciphers(const e: PENGINE): ENGINE_CIPHERS_PTR; cdecl; external CLibCrypto;
function ENGINE_get_digests(const e: PENGINE): ENGINE_DIGESTS_PTR; cdecl; external CLibCrypto;
function ENGINE_get_pkey_meths(const e: PENGINE): ENGINE_PKEY_METHS_PTR; cdecl; external CLibCrypto;
function ENGINE_get_pkey_asn1_meths(const e: PENGINE): ENGINE_PKEY_ASN1_METHS_PTR; cdecl; external CLibCrypto;
function ENGINE_get_cipher(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_CIPHER; cdecl; external CLibCrypto;
function ENGINE_get_digest(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_MD; cdecl; external CLibCrypto;
function ENGINE_get_pkey_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_pkey_asn1_meth_str(e: PENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function ENGINE_pkey_asn1_find_str(pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl; external CLibCrypto;
function ENGINE_get_cmd_defns(const e: PENGINE): PENGINE_CMD_DEFN; cdecl; external CLibCrypto;
function ENGINE_get_flags(const e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_init(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_finish(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_load_private_key(e: PENGINE; const key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function ENGINE_load_public_key(e: PENGINE; const key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl; external CLibCrypto;
function ENGINE_get_default_RSA: PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_default_DSA: PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_default_EC: PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_default_DH: PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_default_RAND: PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_cipher_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_digest_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_pkey_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto;
function ENGINE_get_pkey_asn1_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl; external CLibCrypto;
function ENGINE_set_default_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_string(e: PENGINE; const def_list: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_EC(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_DH(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_digests(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ENGINE_set_default(e: PENGINE; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure ENGINE_add_conf_module; cdecl; external CLibCrypto;
function ENGINE_get_static_state: Pointer; cdecl; external CLibCrypto;

{$ELSE}
var
  ENGINE_get_first: function : PENGINE; cdecl = nil;
  ENGINE_get_last: function : PENGINE; cdecl = nil;
  ENGINE_get_next: function (e: PENGINE): PENGINE; cdecl = nil;
  ENGINE_get_prev: function (e: PENGINE): PENGINE; cdecl = nil;
  ENGINE_add: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_remove: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_by_id: function (const id: PAnsiChar): PENGINE; cdecl = nil;
  ENGINE_load_builtin_engines: procedure ; cdecl = nil;
  ENGINE_get_table_flags: function : TOpenSSL_C_UINT; cdecl = nil;
  ENGINE_set_table_flags: procedure (flags: TOpenSSL_C_UINT); cdecl = nil;
  ENGINE_register_RSA: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_RSA: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_RSA: procedure ; cdecl = nil;
  ENGINE_register_DSA: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_DSA: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_DSA: procedure ; cdecl = nil;
  ENGINE_register_EC: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_EC: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_EC: procedure ; cdecl = nil;
  ENGINE_register_DH: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_DH: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_DH: procedure ; cdecl = nil;
  ENGINE_register_RAND: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_RAND: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_RAND: procedure ; cdecl = nil;
  ENGINE_register_ciphers: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_ciphers: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_ciphers: procedure ; cdecl = nil;
  ENGINE_register_digests: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_digests: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_digests: procedure ; cdecl = nil;
  ENGINE_register_pkey_meths: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_pkey_meths: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_pkey_meths: procedure ; cdecl = nil;
  ENGINE_register_pkey_asn1_meths: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_unregister_pkey_asn1_meths: procedure (e: PENGINE); cdecl = nil;
  ENGINE_register_all_pkey_asn1_meths: procedure ; cdecl = nil;
  ENGINE_register_complete: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_register_all_complete: function : TOpenSSL_C_INT; cdecl = nil;
  ENGINE_ctrl: function (e: PENGINE; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; v1: f): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_cmd_is_executable: function (e: PENGINE; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_ctrl_cmd: function (e: PENGINE; const cmd_name: PAnsiChar; i: TOpenSSL_C_LONG; p: Pointer; v1: f; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_ctrl_cmd_string: function (e: PENGINE; const cmd_name: PAnsiChar; const arg: PAnsiChar; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_new: function : PENGINE; cdecl = nil;
  ENGINE_free: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_up_ref: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_id: function (e: PENGINE; const id: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_name: function (e: PENGINE; const name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_RSA: function (e: PENGINE; const rsa_meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_DSA: function (e: PENGINE; const dsa_meth: PDSA_METHOD): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_EC: function (e: PENGINE; const ecdsa_meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_DH: function (e: PENGINE; const dh_meth: PDH_METHOD): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_RAND: function (e: PENGINE; const rand_meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_destroy_function: function (e: PENGINE; destroy_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_init_function: function (e: PENGINE; init_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_finish_function: function (e: PENGINE; finish_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_ctrl_function: function (e: PENGINE; ctrl_f: ENGINE_CTRL_FUNC_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_load_privkey_function: function (e: PENGINE; loadpriv_f: ENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_load_pubkey_function: function (e: PENGINE; loadpub_f: ENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_ciphers: function (e: PENGINE; f: ENGINE_CIPHERS_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_digests: function (e: PENGINE; f: ENGINE_DIGESTS_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_pkey_meths: function (e: PENGINE; f: ENGINE_PKEY_METHS_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_pkey_asn1_meths: function (e: PENGINE; f: ENGINE_PKEY_ASN1_METHS_PTR): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_flags: function (e: PENGINE; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_cmd_defns: function (e: PENGINE; const defns: PENGINE_CMD_DEFN): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_ex_data: function (e: PENGINE; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_get_ex_data: function (const e: PENGINE; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  ENGINE_get_id: function (const e: PENGINE): PAnsiChar; cdecl = nil;
  ENGINE_get_name: function (const e: PENGINE): PAnsiChar; cdecl = nil;
  ENGINE_get_RSA: function (const e: PENGINE): PRSA_METHOD; cdecl = nil;
  ENGINE_get_DSA: function (const e: PENGINE): PDSA_METHOD; cdecl = nil;
  ENGINE_get_EC: function (const e: PENGINE): PEC_METHOD; cdecl = nil;
  ENGINE_get_DH: function (const e: PENGINE): PDH_METHOD; cdecl = nil;
  ENGINE_get_RAND: function (const e: PENGINE): PRAND_METHOD; cdecl = nil;
  ENGINE_get_destroy_function: function (const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
  ENGINE_get_init_function: function (const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
  ENGINE_get_finish_function: function (const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl = nil;
  ENGINE_get_ctrl_function: function (const e: PENGINE): ENGINE_CTRL_FUNC_PTR; cdecl = nil;
  ENGINE_get_load_privkey_function: function (const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl = nil;
  ENGINE_get_load_pubkey_function: function (const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl = nil;
  ENGINE_get_ciphers: function (const e: PENGINE): ENGINE_CIPHERS_PTR; cdecl = nil;
  ENGINE_get_digests: function (const e: PENGINE): ENGINE_DIGESTS_PTR; cdecl = nil;
  ENGINE_get_pkey_meths: function (const e: PENGINE): ENGINE_PKEY_METHS_PTR; cdecl = nil;
  ENGINE_get_pkey_asn1_meths: function (const e: PENGINE): ENGINE_PKEY_ASN1_METHS_PTR; cdecl = nil;
  ENGINE_get_cipher: function (e: PENGINE; nid: TOpenSSL_C_INT): PEVP_CIPHER; cdecl = nil;
  ENGINE_get_digest: function (e: PENGINE; nid: TOpenSSL_C_INT): PEVP_MD; cdecl = nil;
  ENGINE_get_pkey_meth: function (e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl = nil;
  ENGINE_get_pkey_asn1_meth: function (e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  ENGINE_get_pkey_asn1_meth_str: function (e: PENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  ENGINE_pkey_asn1_find_str: function (pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl = nil;
  ENGINE_get_cmd_defns: function (const e: PENGINE): PENGINE_CMD_DEFN; cdecl = nil;
  ENGINE_get_flags: function (const e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_init: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_finish: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_load_private_key: function (e: PENGINE; const key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl = nil;
  ENGINE_load_public_key: function (e: PENGINE; const key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl = nil;
  ENGINE_get_default_RSA: function : PENGINE; cdecl = nil;
  ENGINE_get_default_DSA: function : PENGINE; cdecl = nil;
  ENGINE_get_default_EC: function : PENGINE; cdecl = nil;
  ENGINE_get_default_DH: function : PENGINE; cdecl = nil;
  ENGINE_get_default_RAND: function : PENGINE; cdecl = nil;
  ENGINE_get_cipher_engine: function (nid: TOpenSSL_C_INT): PENGINE; cdecl = nil;
  ENGINE_get_digest_engine: function (nid: TOpenSSL_C_INT): PENGINE; cdecl = nil;
  ENGINE_get_pkey_meth_engine: function (nid: TOpenSSL_C_INT): PENGINE; cdecl = nil;
  ENGINE_get_pkey_asn1_meth_engine: function (nid: TOpenSSL_C_INT): PENGINE; cdecl = nil;
  ENGINE_set_default_RSA: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_string: function (e: PENGINE; const def_list: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_DSA: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_EC: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_DH: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_RAND: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_ciphers: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_digests: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_pkey_meths: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default_pkey_asn1_meths: function (e: PENGINE): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_set_default: function (e: PENGINE; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl = nil;
  ENGINE_add_conf_module: procedure ; cdecl = nil;
  ENGINE_get_static_state: function : Pointer; cdecl = nil;
{$ENDIF}

implementation



uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
function ERROR_ENGINE_get_first: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_first');
end;

function ERROR_ENGINE_get_last: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_last');
end;

function ERROR_ENGINE_get_next(e: PENGINE): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_next');
end;

function ERROR_ENGINE_get_prev(e: PENGINE): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_prev');
end;

function ERROR_ENGINE_add(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_add');
end;

function ERROR_ENGINE_remove(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_remove');
end;

function ERROR_ENGINE_by_id(const id: PAnsiChar): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_by_id');
end;

procedure ERROR_ENGINE_load_builtin_engines; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_load_builtin_engines');
end;

function ERROR_ENGINE_get_table_flags: TOpenSSL_C_UINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_table_flags');
end;

procedure ERROR_ENGINE_set_table_flags(flags: TOpenSSL_C_UINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_table_flags');
end;

function ERROR_ENGINE_register_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_RSA');
end;

procedure ERROR_ENGINE_unregister_RSA(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_RSA');
end;

procedure ERROR_ENGINE_register_all_RSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_RSA');
end;

function ERROR_ENGINE_register_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_DSA');
end;

procedure ERROR_ENGINE_unregister_DSA(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_DSA');
end;

procedure ERROR_ENGINE_register_all_DSA; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_DSA');
end;

function ERROR_ENGINE_register_EC(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_EC');
end;

procedure ERROR_ENGINE_unregister_EC(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_EC');
end;

procedure ERROR_ENGINE_register_all_EC; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_EC');
end;

function ERROR_ENGINE_register_DH(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_DH');
end;

procedure ERROR_ENGINE_unregister_DH(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_DH');
end;

procedure ERROR_ENGINE_register_all_DH; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_DH');
end;

function ERROR_ENGINE_register_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_RAND');
end;

procedure ERROR_ENGINE_unregister_RAND(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_RAND');
end;

procedure ERROR_ENGINE_register_all_RAND; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_RAND');
end;

function ERROR_ENGINE_register_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_ciphers');
end;

procedure ERROR_ENGINE_unregister_ciphers(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_ciphers');
end;

procedure ERROR_ENGINE_register_all_ciphers; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_ciphers');
end;

function ERROR_ENGINE_register_digests(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_digests');
end;

procedure ERROR_ENGINE_unregister_digests(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_digests');
end;

procedure ERROR_ENGINE_register_all_digests; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_digests');
end;

function ERROR_ENGINE_register_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_pkey_meths');
end;

procedure ERROR_ENGINE_unregister_pkey_meths(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_pkey_meths');
end;

procedure ERROR_ENGINE_register_all_pkey_meths; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_pkey_meths');
end;

function ERROR_ENGINE_register_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_pkey_asn1_meths');
end;

procedure ERROR_ENGINE_unregister_pkey_asn1_meths(e: PENGINE); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_unregister_pkey_asn1_meths');
end;

procedure ERROR_ENGINE_register_all_pkey_asn1_meths; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_pkey_asn1_meths');
end;

function ERROR_ENGINE_register_complete(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_complete');
end;

function ERROR_ENGINE_register_all_complete: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_register_all_complete');
end;

function ERROR_ENGINE_ctrl(e: PENGINE; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; v1: f): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_ctrl');
end;

function ERROR_ENGINE_cmd_is_executable(e: PENGINE; cmd: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_cmd_is_executable');
end;

function ERROR_ENGINE_ctrl_cmd(e: PENGINE; const cmd_name: PAnsiChar; i: TOpenSSL_C_LONG; p: Pointer; v1: f; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_ctrl_cmd');
end;

function ERROR_ENGINE_ctrl_cmd_string(e: PENGINE; const cmd_name: PAnsiChar; const arg: PAnsiChar; cmd_optional: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_ctrl_cmd_string');
end;

function ERROR_ENGINE_new: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_new');
end;

function ERROR_ENGINE_free(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_free');
end;

function ERROR_ENGINE_up_ref(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_up_ref');
end;

function ERROR_ENGINE_set_id(e: PENGINE; const id: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_id');
end;

function ERROR_ENGINE_set_name(e: PENGINE; const name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_name');
end;

function ERROR_ENGINE_set_RSA(e: PENGINE; const rsa_meth: PRSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_RSA');
end;

function ERROR_ENGINE_set_DSA(e: PENGINE; const dsa_meth: PDSA_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_DSA');
end;

function ERROR_ENGINE_set_EC(e: PENGINE; const ecdsa_meth: PEC_KEY_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_EC');
end;

function ERROR_ENGINE_set_DH(e: PENGINE; const dh_meth: PDH_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_DH');
end;

function ERROR_ENGINE_set_RAND(e: PENGINE; const rand_meth: PRAND_METHOD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_RAND');
end;

function ERROR_ENGINE_set_destroy_function(e: PENGINE; destroy_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_destroy_function');
end;

function ERROR_ENGINE_set_init_function(e: PENGINE; init_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_init_function');
end;

function ERROR_ENGINE_set_finish_function(e: PENGINE; finish_f: ENGINE_GEN_INT_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_finish_function');
end;

function ERROR_ENGINE_set_ctrl_function(e: PENGINE; ctrl_f: ENGINE_CTRL_FUNC_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_ctrl_function');
end;

function ERROR_ENGINE_set_load_privkey_function(e: PENGINE; loadpriv_f: ENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_load_privkey_function');
end;

function ERROR_ENGINE_set_load_pubkey_function(e: PENGINE; loadpub_f: ENGINE_LOAD_KEY_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_load_pubkey_function');
end;

function ERROR_ENGINE_set_ciphers(e: PENGINE; f: ENGINE_CIPHERS_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_ciphers');
end;

function ERROR_ENGINE_set_digests(e: PENGINE; f: ENGINE_DIGESTS_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_digests');
end;

function ERROR_ENGINE_set_pkey_meths(e: PENGINE; f: ENGINE_PKEY_METHS_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_pkey_meths');
end;

function ERROR_ENGINE_set_pkey_asn1_meths(e: PENGINE; f: ENGINE_PKEY_ASN1_METHS_PTR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_pkey_asn1_meths');
end;

function ERROR_ENGINE_set_flags(e: PENGINE; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_flags');
end;

function ERROR_ENGINE_set_cmd_defns(e: PENGINE; const defns: PENGINE_CMD_DEFN): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_cmd_defns');
end;

function ERROR_ENGINE_set_ex_data(e: PENGINE; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_ex_data');
end;

function ERROR_ENGINE_get_ex_data(const e: PENGINE; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_ex_data');
end;

function ERROR_ENGINE_get_id(const e: PENGINE): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_id');
end;

function ERROR_ENGINE_get_name(const e: PENGINE): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_name');
end;

function ERROR_ENGINE_get_RSA(const e: PENGINE): PRSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_RSA');
end;

function ERROR_ENGINE_get_DSA(const e: PENGINE): PDSA_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_DSA');
end;

function ERROR_ENGINE_get_EC(const e: PENGINE): PEC_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_EC');
end;

function ERROR_ENGINE_get_DH(const e: PENGINE): PDH_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_DH');
end;

function ERROR_ENGINE_get_RAND(const e: PENGINE): PRAND_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_RAND');
end;

function ERROR_ENGINE_get_destroy_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_destroy_function');
end;

function ERROR_ENGINE_get_init_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_init_function');
end;

function ERROR_ENGINE_get_finish_function(const e: PENGINE): ENGINE_GEN_INT_FUNC_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_finish_function');
end;

function ERROR_ENGINE_get_ctrl_function(const e: PENGINE): ENGINE_CTRL_FUNC_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_ctrl_function');
end;

function ERROR_ENGINE_get_load_privkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_load_privkey_function');
end;

function ERROR_ENGINE_get_load_pubkey_function(const e: PENGINE): ENGINE_LOAD_KEY_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_load_pubkey_function');
end;

function ERROR_ENGINE_get_ciphers(const e: PENGINE): ENGINE_CIPHERS_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_ciphers');
end;

function ERROR_ENGINE_get_digests(const e: PENGINE): ENGINE_DIGESTS_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_digests');
end;

function ERROR_ENGINE_get_pkey_meths(const e: PENGINE): ENGINE_PKEY_METHS_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_meths');
end;

function ERROR_ENGINE_get_pkey_asn1_meths(const e: PENGINE): ENGINE_PKEY_ASN1_METHS_PTR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meths');
end;

function ERROR_ENGINE_get_cipher(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_CIPHER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_cipher');
end;

function ERROR_ENGINE_get_digest(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_MD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_digest');
end;

function ERROR_ENGINE_get_pkey_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_meth');
end;

function ERROR_ENGINE_get_pkey_asn1_meth(e: PENGINE; nid: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meth');
end;

function ERROR_ENGINE_get_pkey_asn1_meth_str(e: PENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meth_str');
end;

function ERROR_ENGINE_pkey_asn1_find_str(pe: PPENGINE; const str: PAnsiChar; len: TOpenSSL_C_INT): PEVP_PKEY_ASN1_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_pkey_asn1_find_str');
end;

function ERROR_ENGINE_get_cmd_defns(const e: PENGINE): PENGINE_CMD_DEFN; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_cmd_defns');
end;

function ERROR_ENGINE_get_flags(const e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_flags');
end;

function ERROR_ENGINE_init(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_init');
end;

function ERROR_ENGINE_finish(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_finish');
end;

function ERROR_ENGINE_load_private_key(e: PENGINE; const key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_load_private_key');
end;

function ERROR_ENGINE_load_public_key(e: PENGINE; const key_id: PAnsiChar; ui_method: PUI_METHOD; callback_data: Pointer): PEVP_PKEY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_load_public_key');
end;

function ERROR_ENGINE_get_default_RSA: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_RSA');
end;

function ERROR_ENGINE_get_default_DSA: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_DSA');
end;

function ERROR_ENGINE_get_default_EC: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_EC');
end;

function ERROR_ENGINE_get_default_DH: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_DH');
end;

function ERROR_ENGINE_get_default_RAND: PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_default_RAND');
end;

function ERROR_ENGINE_get_cipher_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_cipher_engine');
end;

function ERROR_ENGINE_get_digest_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_digest_engine');
end;

function ERROR_ENGINE_get_pkey_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_meth_engine');
end;

function ERROR_ENGINE_get_pkey_asn1_meth_engine(nid: TOpenSSL_C_INT): PENGINE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_pkey_asn1_meth_engine');
end;

function ERROR_ENGINE_set_default_RSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_RSA');
end;

function ERROR_ENGINE_set_default_string(e: PENGINE; const def_list: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_string');
end;

function ERROR_ENGINE_set_default_DSA(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_DSA');
end;

function ERROR_ENGINE_set_default_EC(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_EC');
end;

function ERROR_ENGINE_set_default_DH(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_DH');
end;

function ERROR_ENGINE_set_default_RAND(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_RAND');
end;

function ERROR_ENGINE_set_default_ciphers(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_ciphers');
end;

function ERROR_ENGINE_set_default_digests(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_digests');
end;

function ERROR_ENGINE_set_default_pkey_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_pkey_meths');
end;

function ERROR_ENGINE_set_default_pkey_asn1_meths(e: PENGINE): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default_pkey_asn1_meths');
end;

function ERROR_ENGINE_set_default(e: PENGINE; flags: TOpenSSL_C_ULONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_set_default');
end;

procedure ERROR_ENGINE_add_conf_module; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_add_conf_module');
end;

function ERROR_ENGINE_get_static_state: Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ENGINE_get_static_state');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  ENGINE_get_first := LoadLibCryptoFunction('ENGINE_get_first');
  FuncLoadError := not assigned(ENGINE_get_first);
  if FuncLoadError then
  begin
    ENGINE_get_first :=  @ERROR_ENGINE_get_first;
  end;

  ENGINE_get_last := LoadLibCryptoFunction('ENGINE_get_last');
  FuncLoadError := not assigned(ENGINE_get_last);
  if FuncLoadError then
  begin
    ENGINE_get_last :=  @ERROR_ENGINE_get_last;
  end;

  ENGINE_get_next := LoadLibCryptoFunction('ENGINE_get_next');
  FuncLoadError := not assigned(ENGINE_get_next);
  if FuncLoadError then
  begin
    ENGINE_get_next :=  @ERROR_ENGINE_get_next;
  end;

  ENGINE_get_prev := LoadLibCryptoFunction('ENGINE_get_prev');
  FuncLoadError := not assigned(ENGINE_get_prev);
  if FuncLoadError then
  begin
    ENGINE_get_prev :=  @ERROR_ENGINE_get_prev;
  end;

  ENGINE_add := LoadLibCryptoFunction('ENGINE_add');
  FuncLoadError := not assigned(ENGINE_add);
  if FuncLoadError then
  begin
    ENGINE_add :=  @ERROR_ENGINE_add;
  end;

  ENGINE_remove := LoadLibCryptoFunction('ENGINE_remove');
  FuncLoadError := not assigned(ENGINE_remove);
  if FuncLoadError then
  begin
    ENGINE_remove :=  @ERROR_ENGINE_remove;
  end;

  ENGINE_by_id := LoadLibCryptoFunction('ENGINE_by_id');
  FuncLoadError := not assigned(ENGINE_by_id);
  if FuncLoadError then
  begin
    ENGINE_by_id :=  @ERROR_ENGINE_by_id;
  end;

  ENGINE_load_builtin_engines := LoadLibCryptoFunction('ENGINE_load_builtin_engines');
  FuncLoadError := not assigned(ENGINE_load_builtin_engines);
  if FuncLoadError then
  begin
    ENGINE_load_builtin_engines :=  @ERROR_ENGINE_load_builtin_engines;
  end;

  ENGINE_get_table_flags := LoadLibCryptoFunction('ENGINE_get_table_flags');
  FuncLoadError := not assigned(ENGINE_get_table_flags);
  if FuncLoadError then
  begin
    ENGINE_get_table_flags :=  @ERROR_ENGINE_get_table_flags;
  end;

  ENGINE_set_table_flags := LoadLibCryptoFunction('ENGINE_set_table_flags');
  FuncLoadError := not assigned(ENGINE_set_table_flags);
  if FuncLoadError then
  begin
    ENGINE_set_table_flags :=  @ERROR_ENGINE_set_table_flags;
  end;

  ENGINE_register_RSA := LoadLibCryptoFunction('ENGINE_register_RSA');
  FuncLoadError := not assigned(ENGINE_register_RSA);
  if FuncLoadError then
  begin
    ENGINE_register_RSA :=  @ERROR_ENGINE_register_RSA;
  end;

  ENGINE_unregister_RSA := LoadLibCryptoFunction('ENGINE_unregister_RSA');
  FuncLoadError := not assigned(ENGINE_unregister_RSA);
  if FuncLoadError then
  begin
    ENGINE_unregister_RSA :=  @ERROR_ENGINE_unregister_RSA;
  end;

  ENGINE_register_all_RSA := LoadLibCryptoFunction('ENGINE_register_all_RSA');
  FuncLoadError := not assigned(ENGINE_register_all_RSA);
  if FuncLoadError then
  begin
    ENGINE_register_all_RSA :=  @ERROR_ENGINE_register_all_RSA;
  end;

  ENGINE_register_DSA := LoadLibCryptoFunction('ENGINE_register_DSA');
  FuncLoadError := not assigned(ENGINE_register_DSA);
  if FuncLoadError then
  begin
    ENGINE_register_DSA :=  @ERROR_ENGINE_register_DSA;
  end;

  ENGINE_unregister_DSA := LoadLibCryptoFunction('ENGINE_unregister_DSA');
  FuncLoadError := not assigned(ENGINE_unregister_DSA);
  if FuncLoadError then
  begin
    ENGINE_unregister_DSA :=  @ERROR_ENGINE_unregister_DSA;
  end;

  ENGINE_register_all_DSA := LoadLibCryptoFunction('ENGINE_register_all_DSA');
  FuncLoadError := not assigned(ENGINE_register_all_DSA);
  if FuncLoadError then
  begin
    ENGINE_register_all_DSA :=  @ERROR_ENGINE_register_all_DSA;
  end;

  ENGINE_register_EC := LoadLibCryptoFunction('ENGINE_register_EC');
  FuncLoadError := not assigned(ENGINE_register_EC);
  if FuncLoadError then
  begin
    ENGINE_register_EC :=  @ERROR_ENGINE_register_EC;
  end;

  ENGINE_unregister_EC := LoadLibCryptoFunction('ENGINE_unregister_EC');
  FuncLoadError := not assigned(ENGINE_unregister_EC);
  if FuncLoadError then
  begin
    ENGINE_unregister_EC :=  @ERROR_ENGINE_unregister_EC;
  end;

  ENGINE_register_all_EC := LoadLibCryptoFunction('ENGINE_register_all_EC');
  FuncLoadError := not assigned(ENGINE_register_all_EC);
  if FuncLoadError then
  begin
    ENGINE_register_all_EC :=  @ERROR_ENGINE_register_all_EC;
  end;

  ENGINE_register_DH := LoadLibCryptoFunction('ENGINE_register_DH');
  FuncLoadError := not assigned(ENGINE_register_DH);
  if FuncLoadError then
  begin
    ENGINE_register_DH :=  @ERROR_ENGINE_register_DH;
  end;

  ENGINE_unregister_DH := LoadLibCryptoFunction('ENGINE_unregister_DH');
  FuncLoadError := not assigned(ENGINE_unregister_DH);
  if FuncLoadError then
  begin
    ENGINE_unregister_DH :=  @ERROR_ENGINE_unregister_DH;
  end;

  ENGINE_register_all_DH := LoadLibCryptoFunction('ENGINE_register_all_DH');
  FuncLoadError := not assigned(ENGINE_register_all_DH);
  if FuncLoadError then
  begin
    ENGINE_register_all_DH :=  @ERROR_ENGINE_register_all_DH;
  end;

  ENGINE_register_RAND := LoadLibCryptoFunction('ENGINE_register_RAND');
  FuncLoadError := not assigned(ENGINE_register_RAND);
  if FuncLoadError then
  begin
    ENGINE_register_RAND :=  @ERROR_ENGINE_register_RAND;
  end;

  ENGINE_unregister_RAND := LoadLibCryptoFunction('ENGINE_unregister_RAND');
  FuncLoadError := not assigned(ENGINE_unregister_RAND);
  if FuncLoadError then
  begin
    ENGINE_unregister_RAND :=  @ERROR_ENGINE_unregister_RAND;
  end;

  ENGINE_register_all_RAND := LoadLibCryptoFunction('ENGINE_register_all_RAND');
  FuncLoadError := not assigned(ENGINE_register_all_RAND);
  if FuncLoadError then
  begin
    ENGINE_register_all_RAND :=  @ERROR_ENGINE_register_all_RAND;
  end;

  ENGINE_register_ciphers := LoadLibCryptoFunction('ENGINE_register_ciphers');
  FuncLoadError := not assigned(ENGINE_register_ciphers);
  if FuncLoadError then
  begin
    ENGINE_register_ciphers :=  @ERROR_ENGINE_register_ciphers;
  end;

  ENGINE_unregister_ciphers := LoadLibCryptoFunction('ENGINE_unregister_ciphers');
  FuncLoadError := not assigned(ENGINE_unregister_ciphers);
  if FuncLoadError then
  begin
    ENGINE_unregister_ciphers :=  @ERROR_ENGINE_unregister_ciphers;
  end;

  ENGINE_register_all_ciphers := LoadLibCryptoFunction('ENGINE_register_all_ciphers');
  FuncLoadError := not assigned(ENGINE_register_all_ciphers);
  if FuncLoadError then
  begin
    ENGINE_register_all_ciphers :=  @ERROR_ENGINE_register_all_ciphers;
  end;

  ENGINE_register_digests := LoadLibCryptoFunction('ENGINE_register_digests');
  FuncLoadError := not assigned(ENGINE_register_digests);
  if FuncLoadError then
  begin
    ENGINE_register_digests :=  @ERROR_ENGINE_register_digests;
  end;

  ENGINE_unregister_digests := LoadLibCryptoFunction('ENGINE_unregister_digests');
  FuncLoadError := not assigned(ENGINE_unregister_digests);
  if FuncLoadError then
  begin
    ENGINE_unregister_digests :=  @ERROR_ENGINE_unregister_digests;
  end;

  ENGINE_register_all_digests := LoadLibCryptoFunction('ENGINE_register_all_digests');
  FuncLoadError := not assigned(ENGINE_register_all_digests);
  if FuncLoadError then
  begin
    ENGINE_register_all_digests :=  @ERROR_ENGINE_register_all_digests;
  end;

  ENGINE_register_pkey_meths := LoadLibCryptoFunction('ENGINE_register_pkey_meths');
  FuncLoadError := not assigned(ENGINE_register_pkey_meths);
  if FuncLoadError then
  begin
    ENGINE_register_pkey_meths :=  @ERROR_ENGINE_register_pkey_meths;
  end;

  ENGINE_unregister_pkey_meths := LoadLibCryptoFunction('ENGINE_unregister_pkey_meths');
  FuncLoadError := not assigned(ENGINE_unregister_pkey_meths);
  if FuncLoadError then
  begin
    ENGINE_unregister_pkey_meths :=  @ERROR_ENGINE_unregister_pkey_meths;
  end;

  ENGINE_register_all_pkey_meths := LoadLibCryptoFunction('ENGINE_register_all_pkey_meths');
  FuncLoadError := not assigned(ENGINE_register_all_pkey_meths);
  if FuncLoadError then
  begin
    ENGINE_register_all_pkey_meths :=  @ERROR_ENGINE_register_all_pkey_meths;
  end;

  ENGINE_register_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_register_pkey_asn1_meths');
  FuncLoadError := not assigned(ENGINE_register_pkey_asn1_meths);
  if FuncLoadError then
  begin
    ENGINE_register_pkey_asn1_meths :=  @ERROR_ENGINE_register_pkey_asn1_meths;
  end;

  ENGINE_unregister_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_unregister_pkey_asn1_meths');
  FuncLoadError := not assigned(ENGINE_unregister_pkey_asn1_meths);
  if FuncLoadError then
  begin
    ENGINE_unregister_pkey_asn1_meths :=  @ERROR_ENGINE_unregister_pkey_asn1_meths;
  end;

  ENGINE_register_all_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_register_all_pkey_asn1_meths');
  FuncLoadError := not assigned(ENGINE_register_all_pkey_asn1_meths);
  if FuncLoadError then
  begin
    ENGINE_register_all_pkey_asn1_meths :=  @ERROR_ENGINE_register_all_pkey_asn1_meths;
  end;

  ENGINE_register_complete := LoadLibCryptoFunction('ENGINE_register_complete');
  FuncLoadError := not assigned(ENGINE_register_complete);
  if FuncLoadError then
  begin
    ENGINE_register_complete :=  @ERROR_ENGINE_register_complete;
  end;

  ENGINE_register_all_complete := LoadLibCryptoFunction('ENGINE_register_all_complete');
  FuncLoadError := not assigned(ENGINE_register_all_complete);
  if FuncLoadError then
  begin
    ENGINE_register_all_complete :=  @ERROR_ENGINE_register_all_complete;
  end;

  ENGINE_ctrl := LoadLibCryptoFunction('ENGINE_ctrl');
  FuncLoadError := not assigned(ENGINE_ctrl);
  if FuncLoadError then
  begin
    ENGINE_ctrl :=  @ERROR_ENGINE_ctrl;
  end;

  ENGINE_cmd_is_executable := LoadLibCryptoFunction('ENGINE_cmd_is_executable');
  FuncLoadError := not assigned(ENGINE_cmd_is_executable);
  if FuncLoadError then
  begin
    ENGINE_cmd_is_executable :=  @ERROR_ENGINE_cmd_is_executable;
  end;

  ENGINE_ctrl_cmd := LoadLibCryptoFunction('ENGINE_ctrl_cmd');
  FuncLoadError := not assigned(ENGINE_ctrl_cmd);
  if FuncLoadError then
  begin
    ENGINE_ctrl_cmd :=  @ERROR_ENGINE_ctrl_cmd;
  end;

  ENGINE_ctrl_cmd_string := LoadLibCryptoFunction('ENGINE_ctrl_cmd_string');
  FuncLoadError := not assigned(ENGINE_ctrl_cmd_string);
  if FuncLoadError then
  begin
    ENGINE_ctrl_cmd_string :=  @ERROR_ENGINE_ctrl_cmd_string;
  end;

  ENGINE_new := LoadLibCryptoFunction('ENGINE_new');
  FuncLoadError := not assigned(ENGINE_new);
  if FuncLoadError then
  begin
    ENGINE_new :=  @ERROR_ENGINE_new;
  end;

  ENGINE_free := LoadLibCryptoFunction('ENGINE_free');
  FuncLoadError := not assigned(ENGINE_free);
  if FuncLoadError then
  begin
    ENGINE_free :=  @ERROR_ENGINE_free;
  end;

  ENGINE_up_ref := LoadLibCryptoFunction('ENGINE_up_ref');
  FuncLoadError := not assigned(ENGINE_up_ref);
  if FuncLoadError then
  begin
    ENGINE_up_ref :=  @ERROR_ENGINE_up_ref;
  end;

  ENGINE_set_id := LoadLibCryptoFunction('ENGINE_set_id');
  FuncLoadError := not assigned(ENGINE_set_id);
  if FuncLoadError then
  begin
    ENGINE_set_id :=  @ERROR_ENGINE_set_id;
  end;

  ENGINE_set_name := LoadLibCryptoFunction('ENGINE_set_name');
  FuncLoadError := not assigned(ENGINE_set_name);
  if FuncLoadError then
  begin
    ENGINE_set_name :=  @ERROR_ENGINE_set_name;
  end;

  ENGINE_set_RSA := LoadLibCryptoFunction('ENGINE_set_RSA');
  FuncLoadError := not assigned(ENGINE_set_RSA);
  if FuncLoadError then
  begin
    ENGINE_set_RSA :=  @ERROR_ENGINE_set_RSA;
  end;

  ENGINE_set_DSA := LoadLibCryptoFunction('ENGINE_set_DSA');
  FuncLoadError := not assigned(ENGINE_set_DSA);
  if FuncLoadError then
  begin
    ENGINE_set_DSA :=  @ERROR_ENGINE_set_DSA;
  end;

  ENGINE_set_EC := LoadLibCryptoFunction('ENGINE_set_EC');
  FuncLoadError := not assigned(ENGINE_set_EC);
  if FuncLoadError then
  begin
    ENGINE_set_EC :=  @ERROR_ENGINE_set_EC;
  end;

  ENGINE_set_DH := LoadLibCryptoFunction('ENGINE_set_DH');
  FuncLoadError := not assigned(ENGINE_set_DH);
  if FuncLoadError then
  begin
    ENGINE_set_DH :=  @ERROR_ENGINE_set_DH;
  end;

  ENGINE_set_RAND := LoadLibCryptoFunction('ENGINE_set_RAND');
  FuncLoadError := not assigned(ENGINE_set_RAND);
  if FuncLoadError then
  begin
    ENGINE_set_RAND :=  @ERROR_ENGINE_set_RAND;
  end;

  ENGINE_set_destroy_function := LoadLibCryptoFunction('ENGINE_set_destroy_function');
  FuncLoadError := not assigned(ENGINE_set_destroy_function);
  if FuncLoadError then
  begin
    ENGINE_set_destroy_function :=  @ERROR_ENGINE_set_destroy_function;
  end;

  ENGINE_set_init_function := LoadLibCryptoFunction('ENGINE_set_init_function');
  FuncLoadError := not assigned(ENGINE_set_init_function);
  if FuncLoadError then
  begin
    ENGINE_set_init_function :=  @ERROR_ENGINE_set_init_function;
  end;

  ENGINE_set_finish_function := LoadLibCryptoFunction('ENGINE_set_finish_function');
  FuncLoadError := not assigned(ENGINE_set_finish_function);
  if FuncLoadError then
  begin
    ENGINE_set_finish_function :=  @ERROR_ENGINE_set_finish_function;
  end;

  ENGINE_set_ctrl_function := LoadLibCryptoFunction('ENGINE_set_ctrl_function');
  FuncLoadError := not assigned(ENGINE_set_ctrl_function);
  if FuncLoadError then
  begin
    ENGINE_set_ctrl_function :=  @ERROR_ENGINE_set_ctrl_function;
  end;

  ENGINE_set_load_privkey_function := LoadLibCryptoFunction('ENGINE_set_load_privkey_function');
  FuncLoadError := not assigned(ENGINE_set_load_privkey_function);
  if FuncLoadError then
  begin
    ENGINE_set_load_privkey_function :=  @ERROR_ENGINE_set_load_privkey_function;
  end;

  ENGINE_set_load_pubkey_function := LoadLibCryptoFunction('ENGINE_set_load_pubkey_function');
  FuncLoadError := not assigned(ENGINE_set_load_pubkey_function);
  if FuncLoadError then
  begin
    ENGINE_set_load_pubkey_function :=  @ERROR_ENGINE_set_load_pubkey_function;
  end;

  ENGINE_set_ciphers := LoadLibCryptoFunction('ENGINE_set_ciphers');
  FuncLoadError := not assigned(ENGINE_set_ciphers);
  if FuncLoadError then
  begin
    ENGINE_set_ciphers :=  @ERROR_ENGINE_set_ciphers;
  end;

  ENGINE_set_digests := LoadLibCryptoFunction('ENGINE_set_digests');
  FuncLoadError := not assigned(ENGINE_set_digests);
  if FuncLoadError then
  begin
    ENGINE_set_digests :=  @ERROR_ENGINE_set_digests;
  end;

  ENGINE_set_pkey_meths := LoadLibCryptoFunction('ENGINE_set_pkey_meths');
  FuncLoadError := not assigned(ENGINE_set_pkey_meths);
  if FuncLoadError then
  begin
    ENGINE_set_pkey_meths :=  @ERROR_ENGINE_set_pkey_meths;
  end;

  ENGINE_set_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_set_pkey_asn1_meths');
  FuncLoadError := not assigned(ENGINE_set_pkey_asn1_meths);
  if FuncLoadError then
  begin
    ENGINE_set_pkey_asn1_meths :=  @ERROR_ENGINE_set_pkey_asn1_meths;
  end;

  ENGINE_set_flags := LoadLibCryptoFunction('ENGINE_set_flags');
  FuncLoadError := not assigned(ENGINE_set_flags);
  if FuncLoadError then
  begin
    ENGINE_set_flags :=  @ERROR_ENGINE_set_flags;
  end;

  ENGINE_set_cmd_defns := LoadLibCryptoFunction('ENGINE_set_cmd_defns');
  FuncLoadError := not assigned(ENGINE_set_cmd_defns);
  if FuncLoadError then
  begin
    ENGINE_set_cmd_defns :=  @ERROR_ENGINE_set_cmd_defns;
  end;

  ENGINE_set_ex_data := LoadLibCryptoFunction('ENGINE_set_ex_data');
  FuncLoadError := not assigned(ENGINE_set_ex_data);
  if FuncLoadError then
  begin
    ENGINE_set_ex_data :=  @ERROR_ENGINE_set_ex_data;
  end;

  ENGINE_get_ex_data := LoadLibCryptoFunction('ENGINE_get_ex_data');
  FuncLoadError := not assigned(ENGINE_get_ex_data);
  if FuncLoadError then
  begin
    ENGINE_get_ex_data :=  @ERROR_ENGINE_get_ex_data;
  end;

  ENGINE_get_id := LoadLibCryptoFunction('ENGINE_get_id');
  FuncLoadError := not assigned(ENGINE_get_id);
  if FuncLoadError then
  begin
    ENGINE_get_id :=  @ERROR_ENGINE_get_id;
  end;

  ENGINE_get_name := LoadLibCryptoFunction('ENGINE_get_name');
  FuncLoadError := not assigned(ENGINE_get_name);
  if FuncLoadError then
  begin
    ENGINE_get_name :=  @ERROR_ENGINE_get_name;
  end;

  ENGINE_get_RSA := LoadLibCryptoFunction('ENGINE_get_RSA');
  FuncLoadError := not assigned(ENGINE_get_RSA);
  if FuncLoadError then
  begin
    ENGINE_get_RSA :=  @ERROR_ENGINE_get_RSA;
  end;

  ENGINE_get_DSA := LoadLibCryptoFunction('ENGINE_get_DSA');
  FuncLoadError := not assigned(ENGINE_get_DSA);
  if FuncLoadError then
  begin
    ENGINE_get_DSA :=  @ERROR_ENGINE_get_DSA;
  end;

  ENGINE_get_EC := LoadLibCryptoFunction('ENGINE_get_EC');
  FuncLoadError := not assigned(ENGINE_get_EC);
  if FuncLoadError then
  begin
    ENGINE_get_EC :=  @ERROR_ENGINE_get_EC;
  end;

  ENGINE_get_DH := LoadLibCryptoFunction('ENGINE_get_DH');
  FuncLoadError := not assigned(ENGINE_get_DH);
  if FuncLoadError then
  begin
    ENGINE_get_DH :=  @ERROR_ENGINE_get_DH;
  end;

  ENGINE_get_RAND := LoadLibCryptoFunction('ENGINE_get_RAND');
  FuncLoadError := not assigned(ENGINE_get_RAND);
  if FuncLoadError then
  begin
    ENGINE_get_RAND :=  @ERROR_ENGINE_get_RAND;
  end;

  ENGINE_get_destroy_function := LoadLibCryptoFunction('ENGINE_get_destroy_function');
  FuncLoadError := not assigned(ENGINE_get_destroy_function);
  if FuncLoadError then
  begin
    ENGINE_get_destroy_function :=  @ERROR_ENGINE_get_destroy_function;
  end;

  ENGINE_get_init_function := LoadLibCryptoFunction('ENGINE_get_init_function');
  FuncLoadError := not assigned(ENGINE_get_init_function);
  if FuncLoadError then
  begin
    ENGINE_get_init_function :=  @ERROR_ENGINE_get_init_function;
  end;

  ENGINE_get_finish_function := LoadLibCryptoFunction('ENGINE_get_finish_function');
  FuncLoadError := not assigned(ENGINE_get_finish_function);
  if FuncLoadError then
  begin
    ENGINE_get_finish_function :=  @ERROR_ENGINE_get_finish_function;
  end;

  ENGINE_get_ctrl_function := LoadLibCryptoFunction('ENGINE_get_ctrl_function');
  FuncLoadError := not assigned(ENGINE_get_ctrl_function);
  if FuncLoadError then
  begin
    ENGINE_get_ctrl_function :=  @ERROR_ENGINE_get_ctrl_function;
  end;

  ENGINE_get_load_privkey_function := LoadLibCryptoFunction('ENGINE_get_load_privkey_function');
  FuncLoadError := not assigned(ENGINE_get_load_privkey_function);
  if FuncLoadError then
  begin
    ENGINE_get_load_privkey_function :=  @ERROR_ENGINE_get_load_privkey_function;
  end;

  ENGINE_get_load_pubkey_function := LoadLibCryptoFunction('ENGINE_get_load_pubkey_function');
  FuncLoadError := not assigned(ENGINE_get_load_pubkey_function);
  if FuncLoadError then
  begin
    ENGINE_get_load_pubkey_function :=  @ERROR_ENGINE_get_load_pubkey_function;
  end;

  ENGINE_get_ciphers := LoadLibCryptoFunction('ENGINE_get_ciphers');
  FuncLoadError := not assigned(ENGINE_get_ciphers);
  if FuncLoadError then
  begin
    ENGINE_get_ciphers :=  @ERROR_ENGINE_get_ciphers;
  end;

  ENGINE_get_digests := LoadLibCryptoFunction('ENGINE_get_digests');
  FuncLoadError := not assigned(ENGINE_get_digests);
  if FuncLoadError then
  begin
    ENGINE_get_digests :=  @ERROR_ENGINE_get_digests;
  end;

  ENGINE_get_pkey_meths := LoadLibCryptoFunction('ENGINE_get_pkey_meths');
  FuncLoadError := not assigned(ENGINE_get_pkey_meths);
  if FuncLoadError then
  begin
    ENGINE_get_pkey_meths :=  @ERROR_ENGINE_get_pkey_meths;
  end;

  ENGINE_get_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meths');
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meths);
  if FuncLoadError then
  begin
    ENGINE_get_pkey_asn1_meths :=  @ERROR_ENGINE_get_pkey_asn1_meths;
  end;

  ENGINE_get_cipher := LoadLibCryptoFunction('ENGINE_get_cipher');
  FuncLoadError := not assigned(ENGINE_get_cipher);
  if FuncLoadError then
  begin
    ENGINE_get_cipher :=  @ERROR_ENGINE_get_cipher;
  end;

  ENGINE_get_digest := LoadLibCryptoFunction('ENGINE_get_digest');
  FuncLoadError := not assigned(ENGINE_get_digest);
  if FuncLoadError then
  begin
    ENGINE_get_digest :=  @ERROR_ENGINE_get_digest;
  end;

  ENGINE_get_pkey_meth := LoadLibCryptoFunction('ENGINE_get_pkey_meth');
  FuncLoadError := not assigned(ENGINE_get_pkey_meth);
  if FuncLoadError then
  begin
    ENGINE_get_pkey_meth :=  @ERROR_ENGINE_get_pkey_meth;
  end;

  ENGINE_get_pkey_asn1_meth := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meth');
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth);
  if FuncLoadError then
  begin
    ENGINE_get_pkey_asn1_meth :=  @ERROR_ENGINE_get_pkey_asn1_meth;
  end;

  ENGINE_get_pkey_asn1_meth_str := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meth_str');
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth_str);
  if FuncLoadError then
  begin
    ENGINE_get_pkey_asn1_meth_str :=  @ERROR_ENGINE_get_pkey_asn1_meth_str;
  end;

  ENGINE_pkey_asn1_find_str := LoadLibCryptoFunction('ENGINE_pkey_asn1_find_str');
  FuncLoadError := not assigned(ENGINE_pkey_asn1_find_str);
  if FuncLoadError then
  begin
    ENGINE_pkey_asn1_find_str :=  @ERROR_ENGINE_pkey_asn1_find_str;
  end;

  ENGINE_get_cmd_defns := LoadLibCryptoFunction('ENGINE_get_cmd_defns');
  FuncLoadError := not assigned(ENGINE_get_cmd_defns);
  if FuncLoadError then
  begin
    ENGINE_get_cmd_defns :=  @ERROR_ENGINE_get_cmd_defns;
  end;

  ENGINE_get_flags := LoadLibCryptoFunction('ENGINE_get_flags');
  FuncLoadError := not assigned(ENGINE_get_flags);
  if FuncLoadError then
  begin
    ENGINE_get_flags :=  @ERROR_ENGINE_get_flags;
  end;

  ENGINE_init := LoadLibCryptoFunction('ENGINE_init');
  FuncLoadError := not assigned(ENGINE_init);
  if FuncLoadError then
  begin
    ENGINE_init :=  @ERROR_ENGINE_init;
  end;

  ENGINE_finish := LoadLibCryptoFunction('ENGINE_finish');
  FuncLoadError := not assigned(ENGINE_finish);
  if FuncLoadError then
  begin
    ENGINE_finish :=  @ERROR_ENGINE_finish;
  end;

  ENGINE_load_private_key := LoadLibCryptoFunction('ENGINE_load_private_key');
  FuncLoadError := not assigned(ENGINE_load_private_key);
  if FuncLoadError then
  begin
    ENGINE_load_private_key :=  @ERROR_ENGINE_load_private_key;
  end;

  ENGINE_load_public_key := LoadLibCryptoFunction('ENGINE_load_public_key');
  FuncLoadError := not assigned(ENGINE_load_public_key);
  if FuncLoadError then
  begin
    ENGINE_load_public_key :=  @ERROR_ENGINE_load_public_key;
  end;

  ENGINE_get_default_RSA := LoadLibCryptoFunction('ENGINE_get_default_RSA');
  FuncLoadError := not assigned(ENGINE_get_default_RSA);
  if FuncLoadError then
  begin
    ENGINE_get_default_RSA :=  @ERROR_ENGINE_get_default_RSA;
  end;

  ENGINE_get_default_DSA := LoadLibCryptoFunction('ENGINE_get_default_DSA');
  FuncLoadError := not assigned(ENGINE_get_default_DSA);
  if FuncLoadError then
  begin
    ENGINE_get_default_DSA :=  @ERROR_ENGINE_get_default_DSA;
  end;

  ENGINE_get_default_EC := LoadLibCryptoFunction('ENGINE_get_default_EC');
  FuncLoadError := not assigned(ENGINE_get_default_EC);
  if FuncLoadError then
  begin
    ENGINE_get_default_EC :=  @ERROR_ENGINE_get_default_EC;
  end;

  ENGINE_get_default_DH := LoadLibCryptoFunction('ENGINE_get_default_DH');
  FuncLoadError := not assigned(ENGINE_get_default_DH);
  if FuncLoadError then
  begin
    ENGINE_get_default_DH :=  @ERROR_ENGINE_get_default_DH;
  end;

  ENGINE_get_default_RAND := LoadLibCryptoFunction('ENGINE_get_default_RAND');
  FuncLoadError := not assigned(ENGINE_get_default_RAND);
  if FuncLoadError then
  begin
    ENGINE_get_default_RAND :=  @ERROR_ENGINE_get_default_RAND;
  end;

  ENGINE_get_cipher_engine := LoadLibCryptoFunction('ENGINE_get_cipher_engine');
  FuncLoadError := not assigned(ENGINE_get_cipher_engine);
  if FuncLoadError then
  begin
    ENGINE_get_cipher_engine :=  @ERROR_ENGINE_get_cipher_engine;
  end;

  ENGINE_get_digest_engine := LoadLibCryptoFunction('ENGINE_get_digest_engine');
  FuncLoadError := not assigned(ENGINE_get_digest_engine);
  if FuncLoadError then
  begin
    ENGINE_get_digest_engine :=  @ERROR_ENGINE_get_digest_engine;
  end;

  ENGINE_get_pkey_meth_engine := LoadLibCryptoFunction('ENGINE_get_pkey_meth_engine');
  FuncLoadError := not assigned(ENGINE_get_pkey_meth_engine);
  if FuncLoadError then
  begin
    ENGINE_get_pkey_meth_engine :=  @ERROR_ENGINE_get_pkey_meth_engine;
  end;

  ENGINE_get_pkey_asn1_meth_engine := LoadLibCryptoFunction('ENGINE_get_pkey_asn1_meth_engine');
  FuncLoadError := not assigned(ENGINE_get_pkey_asn1_meth_engine);
  if FuncLoadError then
  begin
    ENGINE_get_pkey_asn1_meth_engine :=  @ERROR_ENGINE_get_pkey_asn1_meth_engine;
  end;

  ENGINE_set_default_RSA := LoadLibCryptoFunction('ENGINE_set_default_RSA');
  FuncLoadError := not assigned(ENGINE_set_default_RSA);
  if FuncLoadError then
  begin
    ENGINE_set_default_RSA :=  @ERROR_ENGINE_set_default_RSA;
  end;

  ENGINE_set_default_string := LoadLibCryptoFunction('ENGINE_set_default_string');
  FuncLoadError := not assigned(ENGINE_set_default_string);
  if FuncLoadError then
  begin
    ENGINE_set_default_string :=  @ERROR_ENGINE_set_default_string;
  end;

  ENGINE_set_default_DSA := LoadLibCryptoFunction('ENGINE_set_default_DSA');
  FuncLoadError := not assigned(ENGINE_set_default_DSA);
  if FuncLoadError then
  begin
    ENGINE_set_default_DSA :=  @ERROR_ENGINE_set_default_DSA;
  end;

  ENGINE_set_default_EC := LoadLibCryptoFunction('ENGINE_set_default_EC');
  FuncLoadError := not assigned(ENGINE_set_default_EC);
  if FuncLoadError then
  begin
    ENGINE_set_default_EC :=  @ERROR_ENGINE_set_default_EC;
  end;

  ENGINE_set_default_DH := LoadLibCryptoFunction('ENGINE_set_default_DH');
  FuncLoadError := not assigned(ENGINE_set_default_DH);
  if FuncLoadError then
  begin
    ENGINE_set_default_DH :=  @ERROR_ENGINE_set_default_DH;
  end;

  ENGINE_set_default_RAND := LoadLibCryptoFunction('ENGINE_set_default_RAND');
  FuncLoadError := not assigned(ENGINE_set_default_RAND);
  if FuncLoadError then
  begin
    ENGINE_set_default_RAND :=  @ERROR_ENGINE_set_default_RAND;
  end;

  ENGINE_set_default_ciphers := LoadLibCryptoFunction('ENGINE_set_default_ciphers');
  FuncLoadError := not assigned(ENGINE_set_default_ciphers);
  if FuncLoadError then
  begin
    ENGINE_set_default_ciphers :=  @ERROR_ENGINE_set_default_ciphers;
  end;

  ENGINE_set_default_digests := LoadLibCryptoFunction('ENGINE_set_default_digests');
  FuncLoadError := not assigned(ENGINE_set_default_digests);
  if FuncLoadError then
  begin
    ENGINE_set_default_digests :=  @ERROR_ENGINE_set_default_digests;
  end;

  ENGINE_set_default_pkey_meths := LoadLibCryptoFunction('ENGINE_set_default_pkey_meths');
  FuncLoadError := not assigned(ENGINE_set_default_pkey_meths);
  if FuncLoadError then
  begin
    ENGINE_set_default_pkey_meths :=  @ERROR_ENGINE_set_default_pkey_meths;
  end;

  ENGINE_set_default_pkey_asn1_meths := LoadLibCryptoFunction('ENGINE_set_default_pkey_asn1_meths');
  FuncLoadError := not assigned(ENGINE_set_default_pkey_asn1_meths);
  if FuncLoadError then
  begin
    ENGINE_set_default_pkey_asn1_meths :=  @ERROR_ENGINE_set_default_pkey_asn1_meths;
  end;

  ENGINE_set_default := LoadLibCryptoFunction('ENGINE_set_default');
  FuncLoadError := not assigned(ENGINE_set_default);
  if FuncLoadError then
  begin
    ENGINE_set_default :=  @ERROR_ENGINE_set_default;
  end;

  ENGINE_add_conf_module := LoadLibCryptoFunction('ENGINE_add_conf_module');
  FuncLoadError := not assigned(ENGINE_add_conf_module);
  if FuncLoadError then
  begin
    ENGINE_add_conf_module :=  @ERROR_ENGINE_add_conf_module;
  end;

  ENGINE_get_static_state := LoadLibCryptoFunction('ENGINE_get_static_state');
  FuncLoadError := not assigned(ENGINE_get_static_state);
  if FuncLoadError then
  begin
    ENGINE_get_static_state :=  @ERROR_ENGINE_get_static_state;
  end;

end;

procedure UnLoad;
begin
  ENGINE_get_first := nil;
  ENGINE_get_last := nil;
  ENGINE_get_next := nil;
  ENGINE_get_prev := nil;
  ENGINE_add := nil;
  ENGINE_remove := nil;
  ENGINE_by_id := nil;
  ENGINE_load_builtin_engines := nil;
  ENGINE_get_table_flags := nil;
  ENGINE_set_table_flags := nil;
  ENGINE_register_RSA := nil;
  ENGINE_unregister_RSA := nil;
  ENGINE_register_all_RSA := nil;
  ENGINE_register_DSA := nil;
  ENGINE_unregister_DSA := nil;
  ENGINE_register_all_DSA := nil;
  ENGINE_register_EC := nil;
  ENGINE_unregister_EC := nil;
  ENGINE_register_all_EC := nil;
  ENGINE_register_DH := nil;
  ENGINE_unregister_DH := nil;
  ENGINE_register_all_DH := nil;
  ENGINE_register_RAND := nil;
  ENGINE_unregister_RAND := nil;
  ENGINE_register_all_RAND := nil;
  ENGINE_register_ciphers := nil;
  ENGINE_unregister_ciphers := nil;
  ENGINE_register_all_ciphers := nil;
  ENGINE_register_digests := nil;
  ENGINE_unregister_digests := nil;
  ENGINE_register_all_digests := nil;
  ENGINE_register_pkey_meths := nil;
  ENGINE_unregister_pkey_meths := nil;
  ENGINE_register_all_pkey_meths := nil;
  ENGINE_register_pkey_asn1_meths := nil;
  ENGINE_unregister_pkey_asn1_meths := nil;
  ENGINE_register_all_pkey_asn1_meths := nil;
  ENGINE_register_complete := nil;
  ENGINE_register_all_complete := nil;
  ENGINE_ctrl := nil;
  ENGINE_cmd_is_executable := nil;
  ENGINE_ctrl_cmd := nil;
  ENGINE_ctrl_cmd_string := nil;
  ENGINE_new := nil;
  ENGINE_free := nil;
  ENGINE_up_ref := nil;
  ENGINE_set_id := nil;
  ENGINE_set_name := nil;
  ENGINE_set_RSA := nil;
  ENGINE_set_DSA := nil;
  ENGINE_set_EC := nil;
  ENGINE_set_DH := nil;
  ENGINE_set_RAND := nil;
  ENGINE_set_destroy_function := nil;
  ENGINE_set_init_function := nil;
  ENGINE_set_finish_function := nil;
  ENGINE_set_ctrl_function := nil;
  ENGINE_set_load_privkey_function := nil;
  ENGINE_set_load_pubkey_function := nil;
  ENGINE_set_ciphers := nil;
  ENGINE_set_digests := nil;
  ENGINE_set_pkey_meths := nil;
  ENGINE_set_pkey_asn1_meths := nil;
  ENGINE_set_flags := nil;
  ENGINE_set_cmd_defns := nil;
  ENGINE_set_ex_data := nil;
  ENGINE_get_ex_data := nil;
  ENGINE_get_id := nil;
  ENGINE_get_name := nil;
  ENGINE_get_RSA := nil;
  ENGINE_get_DSA := nil;
  ENGINE_get_EC := nil;
  ENGINE_get_DH := nil;
  ENGINE_get_RAND := nil;
  ENGINE_get_destroy_function := nil;
  ENGINE_get_init_function := nil;
  ENGINE_get_finish_function := nil;
  ENGINE_get_ctrl_function := nil;
  ENGINE_get_load_privkey_function := nil;
  ENGINE_get_load_pubkey_function := nil;
  ENGINE_get_ciphers := nil;
  ENGINE_get_digests := nil;
  ENGINE_get_pkey_meths := nil;
  ENGINE_get_pkey_asn1_meths := nil;
  ENGINE_get_cipher := nil;
  ENGINE_get_digest := nil;
  ENGINE_get_pkey_meth := nil;
  ENGINE_get_pkey_asn1_meth := nil;
  ENGINE_get_pkey_asn1_meth_str := nil;
  ENGINE_pkey_asn1_find_str := nil;
  ENGINE_get_cmd_defns := nil;
  ENGINE_get_flags := nil;
  ENGINE_init := nil;
  ENGINE_finish := nil;
  ENGINE_load_private_key := nil;
  ENGINE_load_public_key := nil;
  ENGINE_get_default_RSA := nil;
  ENGINE_get_default_DSA := nil;
  ENGINE_get_default_EC := nil;
  ENGINE_get_default_DH := nil;
  ENGINE_get_default_RAND := nil;
  ENGINE_get_cipher_engine := nil;
  ENGINE_get_digest_engine := nil;
  ENGINE_get_pkey_meth_engine := nil;
  ENGINE_get_pkey_asn1_meth_engine := nil;
  ENGINE_set_default_RSA := nil;
  ENGINE_set_default_string := nil;
  ENGINE_set_default_DSA := nil;
  ENGINE_set_default_EC := nil;
  ENGINE_set_default_DH := nil;
  ENGINE_set_default_RAND := nil;
  ENGINE_set_default_ciphers := nil;
  ENGINE_set_default_digests := nil;
  ENGINE_set_default_pkey_meths := nil;
  ENGINE_set_default_pkey_asn1_meths := nil;
  ENGINE_set_default := nil;
  ENGINE_add_conf_module := nil;
  ENGINE_get_static_state := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
