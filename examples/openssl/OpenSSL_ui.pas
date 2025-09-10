(* This unit was generated from the source file ui.h2pas 
It should not be modified directly. All changes should be made to ui.h2pas
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


unit OpenSSL_ui;


interface

// Headers for OpenSSL 1.1.1
// ui.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ,
  OpenSSL_crypto,
  OpenSSL_pem,
  OpenSSL_uierr;

{$MINENUMSIZE 4}

const
  (* These are the possible flags.  They can be or'ed together. *)
  (* Use to have echoing of input *)
  UI_INPUT_FLAG_ECHO = $01;
  (*
   * Use a default password.  Where that password is found is completely up to
   * the application, it might for example be in the user data set with
   * UI_add_user_data().  It is not recommended to have more than one input in
   * each UI being marked with this flag, or the application might get
   * confused.
   *)
  UI_INPUT_FLAG_DEFAULT_PWD = $02;


  (*
   * The user of these routines may want to define flags of their own.  The core
   * UI won't look at those, but will pass them on to the method routines.  They
   * must use higher bits so they don't get confused with the UI bits above.
   * UI_INPUT_FLAG_USER_BASE tells which is the lowest bit to use.  A good
   * example of use is this:
   *
   *    #define MY_UI_FLAG1       (0x01 << UI_INPUT_FLAG_USER_BASE)
   *
  *)
  UI_INPUT_FLAG_USER_BASE = 16;

  (* The commands *)
  (*
   * Use UI_CONTROL_PRINT_ERRORS with the value 1 to have UI_process print the
   * OpenSSL error stack before printing any info or added error messages and
   * before any prompting.
   *)
  UI_CTRL_PRINT_ERRORS = 1;
  (*
   * Check if a UI_process() is possible to do again with the same instance of
   * a user interface.  This makes UI_ctrl() return 1 if it is redoable, and 0
   * if not.
   *)
  UI_CTRL_IS_REDOABLE = 2;

type
  (*
   * Give a user interface parameterised control commands.  This can be used to
   * send down an integer, a data pointer or a function pointer, as well as be
   * used to get information from a UI.
   *)
  UI_ctrl_f = procedure;

  (*
   * The UI_STRING type is the data structure that contains all the needed info
   * about a string or a prompt, including test data for a verification prompt.
   *)
  ui_string_st = type Pointer;
  UI_STRING = ui_string_st;
  PUI_STRING = ^UI_STRING;
// DEFINE_STACK_OF(UI_STRING)

  (*
   * The different types of strings that are currently supported. This is only
   * needed by method authors.
   *)
  UI_string_types = (
    UIT_NONE = 0,
    UIT_PROMPT,                 (* Prompt for a string *)
    UIT_VERIFY,                 (* Prompt for a string and verify *)
    UIT_BOOLEAN,                (* Prompt for a yes/no response *)
    UIT_INFO,                   (* Send info to the user *)
    UIT_ERROR                   (* Send an error message to the user *)
  );

  (* Create and manipulate methods *)
  UI_method_opener_cb = function(ui: PUI): TOpenSSL_C_INT;
  UI_method_writer_cb = function(ui: PUI; uis: PUI_String): TOpenSSL_C_INT;
  UI_method_flusher_cb = function(ui: PUI): TOpenSSL_C_INT;
  UI_method_reader_cb = function(ui: PUI; uis: PUI_String): TOpenSSL_C_INT;
  UI_method_closer_cb = function(ui: PUI): TOpenSSL_C_INT;
  UI_method_data_duplicator_cb = function(ui: PUI; ui_data: Pointer): Pointer;
  UI_method_data_destructor_cb = procedure(ui: PUI; ui_data: Pointer);
  UI_method_prompt_constructor_cb = function(ui: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar;

  (*
   * All the following functions return -1 or NULL on error and in some cases
   * (UI_process()) -2 if interrupted or in some other way cancelled. When
   * everything is fine, they return 0, a positive value or a non-NULL pointer,
   * all depending on their purpose.
   *)

  (* Creators and destructor.   *)
  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM UI_new}
{$EXTERNALSYM UI_new_method}
{$EXTERNALSYM UI_free}
{$EXTERNALSYM UI_add_input_string}
{$EXTERNALSYM UI_dup_input_string}
{$EXTERNALSYM UI_add_verify_string}
{$EXTERNALSYM UI_dup_verify_string}
{$EXTERNALSYM UI_add_input_boolean}
{$EXTERNALSYM UI_dup_input_boolean}
{$EXTERNALSYM UI_add_info_string}
{$EXTERNALSYM UI_dup_info_string}
{$EXTERNALSYM UI_add_error_string}
{$EXTERNALSYM UI_dup_error_string}
{$EXTERNALSYM UI_construct_prompt}
{$EXTERNALSYM UI_add_user_data}
{$EXTERNALSYM UI_dup_user_data}
{$EXTERNALSYM UI_get0_user_data}
{$EXTERNALSYM UI_get0_result}
{$EXTERNALSYM UI_get_result_length}
{$EXTERNALSYM UI_process}
{$EXTERNALSYM UI_ctrl}
{$EXTERNALSYM UI_set_ex_data}
{$EXTERNALSYM UI_get_ex_data}
{$EXTERNALSYM UI_set_default_method}
{$EXTERNALSYM UI_get_default_method}
{$EXTERNALSYM UI_get_method}
{$EXTERNALSYM UI_set_method}
{$EXTERNALSYM UI_OpenSSL}
{$EXTERNALSYM UI_null}
{$EXTERNALSYM UI_create_method}
{$EXTERNALSYM UI_destroy_method}
{$EXTERNALSYM UI_method_set_opener}
{$EXTERNALSYM UI_method_set_writer}
{$EXTERNALSYM UI_method_set_flusher}
{$EXTERNALSYM UI_method_set_reader}
{$EXTERNALSYM UI_method_set_closer}
{$EXTERNALSYM UI_method_set_data_duplicator}
{$EXTERNALSYM UI_method_set_prompt_constructor}
{$EXTERNALSYM UI_method_set_ex_data}
{$EXTERNALSYM UI_method_get_opener}
{$EXTERNALSYM UI_method_get_writer}
{$EXTERNALSYM UI_method_get_flusher}
{$EXTERNALSYM UI_method_get_reader}
{$EXTERNALSYM UI_method_get_closer}
{$EXTERNALSYM UI_method_get_prompt_constructor}
{$EXTERNALSYM UI_method_get_data_duplicator}
{$EXTERNALSYM UI_method_get_data_destructor}
{$EXTERNALSYM UI_method_get_ex_data}
{$EXTERNALSYM UI_get_string_type}
{$EXTERNALSYM UI_get_input_flags}
{$EXTERNALSYM UI_get0_output_string}
{$EXTERNALSYM UI_get0_action_string}
{$EXTERNALSYM UI_get0_result_string}
{$EXTERNALSYM UI_get_result_string_length}
{$EXTERNALSYM UI_get0_test_string}
{$EXTERNALSYM UI_get_result_minsize}
{$EXTERNALSYM UI_get_result_maxsize}
{$EXTERNALSYM UI_set_result}
{$EXTERNALSYM UI_set_result_ex}
{$EXTERNALSYM UI_UTIL_read_pw_string}
{$EXTERNALSYM UI_UTIL_read_pw}
{$EXTERNALSYM UI_UTIL_wrap_read_pem_callback}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function UI_new: PUI; cdecl; external CLibCrypto;
function UI_new_method(const method: PUI_Method): PUI; cdecl; external CLibCrypto;
procedure UI_free(ui: PUI); cdecl; external CLibCrypto;
function UI_add_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_add_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_dup_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_construct_prompt(ui_method: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl; external CLibCrypto;
function UI_dup_user_data(ui: PUI; user_data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get0_user_data(ui: PUI): Pointer; cdecl; external CLibCrypto;
function UI_get0_result(ui: PUI; i: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function UI_get_result_length(ui: PUI; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_process(ui: PUI): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_ctrl(ui: PUI; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; f: UI_ctrl_f): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_set_ex_data(r: PUI; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get_ex_data(r: PUI; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
procedure UI_set_default_method(const meth: PUI_Method); cdecl; external CLibCrypto;
function UI_get_default_method: PUI_METHOD; cdecl; external CLibCrypto;
function UI_get_method(ui: PUI): PUI_METHOD; cdecl; external CLibCrypto;
function UI_set_method(ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl; external CLibCrypto;
function UI_OpenSSL: PUI_Method; cdecl; external CLibCrypto;
function UI_null: PUI_METHOD; cdecl; external CLibCrypto;
function UI_create_method(const name: PAnsiChar): PUI_Method; cdecl; external CLibCrypto;
procedure UI_destroy_method(ui_method: PUI_Method); cdecl; external CLibCrypto;
function UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_flusher(method: PUI_Method; flusher: UI_method_flusher_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_data_duplicator(method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_prompt_constructor(method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_set_ex_data(method: PUI_Method; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_method_get_opener(const method: PUI_METHOD): UI_method_opener_cb; cdecl; external CLibCrypto;
function UI_method_get_writer(const method: PUI_METHOD): UI_method_writer_cb; cdecl; external CLibCrypto;
function UI_method_get_flusher(const method: PUI_METHOD): UI_method_flusher_cb; cdecl; external CLibCrypto;
function UI_method_get_reader(const method: PUI_METHOD): UI_method_reader_cb; cdecl; external CLibCrypto;
function UI_method_get_closer(const method: PUI_METHOD): UI_method_closer_cb; cdecl; external CLibCrypto;
function UI_method_get_prompt_constructor(const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl; external CLibCrypto;
function UI_method_get_data_duplicator(const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl; external CLibCrypto;
function UI_method_get_data_destructor(const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl; external CLibCrypto;
function UI_method_get_ex_data(const method: PUI_METHOD; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function UI_get_string_type(uis: PUI_String): UI_string_types; cdecl; external CLibCrypto;
function UI_get_input_flags(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get0_output_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get0_action_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get0_result_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get_result_string_length(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get0_test_string(uis: PUI_String): PAnsiChar; cdecl; external CLibCrypto;
function UI_get_result_minsize(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_get_result_maxsize(uis: PUI_String): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_set_result(ui: PUI; uis: PUI_String; const result_: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_set_result_ex(ui: PUI; uis: PUI_String; const result_: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_UTIL_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_UTIL_read_pw(buf: PAnsiChar; buff: PAnsiChar; size: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TOpenSSL_C_INT): PUI_Method; cdecl; external CLibCrypto;

{$ELSE}
var
  UI_new: function : PUI; cdecl = nil;
  UI_new_method: function (const method: PUI_Method): PUI; cdecl = nil;
  UI_free: procedure (ui: PUI); cdecl = nil;
  UI_add_input_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  UI_dup_input_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  UI_add_verify_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_dup_verify_string: function (ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_add_input_boolean: function (ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_dup_input_boolean: function (ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_add_info_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_dup_info_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_add_error_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_dup_error_string: function (ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_construct_prompt: function (ui_method: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar; cdecl = nil;
  UI_add_user_data: function (ui: PUI; user_data: Pointer): Pointer; cdecl = nil;
  UI_dup_user_data: function (ui: PUI; user_data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  UI_get0_user_data: function (ui: PUI): Pointer; cdecl = nil;
  UI_get0_result: function (ui: PUI; i: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  UI_get_result_length: function (ui: PUI; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  UI_process: function (ui: PUI): TOpenSSL_C_INT; cdecl = nil;
  UI_ctrl: function (ui: PUI; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; f: UI_ctrl_f): TOpenSSL_C_INT; cdecl = nil;
  UI_set_ex_data: function (r: PUI; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  UI_get_ex_data: function (r: PUI; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  UI_set_default_method: procedure (const meth: PUI_Method); cdecl = nil;
  UI_get_default_method: function : PUI_METHOD; cdecl = nil;
  UI_get_method: function (ui: PUI): PUI_METHOD; cdecl = nil;
  UI_set_method: function (ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl = nil;
  UI_OpenSSL: function : PUI_Method; cdecl = nil;
  UI_null: function : PUI_METHOD; cdecl = nil;
  UI_create_method: function (const name: PAnsiChar): PUI_Method; cdecl = nil;
  UI_destroy_method: procedure (ui_method: PUI_Method); cdecl = nil;
  UI_method_set_opener: function (method: PUI_Method; opener: UI_method_opener_cb): TOpenSSL_C_INT; cdecl = nil;
  UI_method_set_writer: function (method: PUI_Method; writer: UI_method_writer_cb): TOpenSSL_C_INT; cdecl = nil;
  UI_method_set_flusher: function (method: PUI_Method; flusher: UI_method_flusher_cb): TOpenSSL_C_INT; cdecl = nil;
  UI_method_set_reader: function (method: PUI_Method; reader: UI_method_reader_cb): TOpenSSL_C_INT; cdecl = nil;
  UI_method_set_closer: function (method: PUI_Method; closer: UI_method_closer_cb): TOpenSSL_C_INT; cdecl = nil;
  UI_method_set_data_duplicator: function (method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TOpenSSL_C_INT; cdecl = nil;
  UI_method_set_prompt_constructor: function (method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TOpenSSL_C_INT; cdecl = nil;
  UI_method_set_ex_data: function (method: PUI_Method; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  UI_method_get_opener: function (const method: PUI_METHOD): UI_method_opener_cb; cdecl = nil;
  UI_method_get_writer: function (const method: PUI_METHOD): UI_method_writer_cb; cdecl = nil;
  UI_method_get_flusher: function (const method: PUI_METHOD): UI_method_flusher_cb; cdecl = nil;
  UI_method_get_reader: function (const method: PUI_METHOD): UI_method_reader_cb; cdecl = nil;
  UI_method_get_closer: function (const method: PUI_METHOD): UI_method_closer_cb; cdecl = nil;
  UI_method_get_prompt_constructor: function (const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl = nil;
  UI_method_get_data_duplicator: function (const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl = nil;
  UI_method_get_data_destructor: function (const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl = nil;
  UI_method_get_ex_data: function (const method: PUI_METHOD; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  UI_get_string_type: function (uis: PUI_String): UI_string_types; cdecl = nil;
  UI_get_input_flags: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = nil;
  UI_get0_output_string: function (uis: PUI_String): PAnsiChar; cdecl = nil;
  UI_get0_action_string: function (uis: PUI_String): PAnsiChar; cdecl = nil;
  UI_get0_result_string: function (uis: PUI_String): PAnsiChar; cdecl = nil;
  UI_get_result_string_length: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = nil;
  UI_get0_test_string: function (uis: PUI_String): PAnsiChar; cdecl = nil;
  UI_get_result_minsize: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = nil;
  UI_get_result_maxsize: function (uis: PUI_String): TOpenSSL_C_INT; cdecl = nil;
  UI_set_result: function (ui: PUI; uis: PUI_String; const result_: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  UI_set_result_ex: function (ui: PUI; uis: PUI_String; const result_: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  UI_UTIL_read_pw_string: function (buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  UI_UTIL_read_pw: function (buf: PAnsiChar; buff: PAnsiChar; size: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  UI_UTIL_wrap_read_pem_callback: function (cb: pem_password_cb; rwflag: TOpenSSL_C_INT): PUI_Method; cdecl = nil;
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
function ERROR_UI_new: PUI; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_new');
end;

function ERROR_UI_new_method(const method: PUI_Method): PUI; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_new_method');
end;

procedure ERROR_UI_free(ui: PUI); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_free');
end;

function ERROR_UI_add_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_input_string');
end;

function ERROR_UI_dup_input_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_input_string');
end;

function ERROR_UI_add_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_verify_string');
end;

function ERROR_UI_dup_verify_string(ui: PUI; const prompt: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar; minsize: TOpenSSL_C_INT; maxsize: TOpenSSL_C_INT; const test_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_verify_string');
end;

function ERROR_UI_add_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_input_boolean');
end;

function ERROR_UI_dup_input_boolean(ui: PUI; const prompt: PAnsiChar; const action_desc: PAnsiChar; const ok_chars: PAnsiChar; const cancel_chars: PAnsiChar; flags: TOpenSSL_C_INT; result_buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_input_boolean');
end;

function ERROR_UI_add_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_info_string');
end;

function ERROR_UI_dup_info_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_info_string');
end;

function ERROR_UI_add_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_error_string');
end;

function ERROR_UI_dup_error_string(ui: PUI; const text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_error_string');
end;

function ERROR_UI_construct_prompt(ui_method: PUI; const object_desc: PAnsiChar; const object_name: PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_construct_prompt');
end;

function ERROR_UI_add_user_data(ui: PUI; user_data: Pointer): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_add_user_data');
end;

function ERROR_UI_dup_user_data(ui: PUI; user_data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_dup_user_data');
end;

function ERROR_UI_get0_user_data(ui: PUI): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_user_data');
end;

function ERROR_UI_get0_result(ui: PUI; i: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_result');
end;

function ERROR_UI_get_result_length(ui: PUI; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_length');
end;

function ERROR_UI_process(ui: PUI): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_process');
end;

function ERROR_UI_ctrl(ui: PUI; cmd: TOpenSSL_C_INT; i: TOpenSSL_C_LONG; p: Pointer; f: UI_ctrl_f): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_ctrl');
end;

function ERROR_UI_set_ex_data(r: PUI; idx: TOpenSSL_C_INT; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_ex_data');
end;

function ERROR_UI_get_ex_data(r: PUI; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_ex_data');
end;

procedure ERROR_UI_set_default_method(const meth: PUI_Method); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_default_method');
end;

function ERROR_UI_get_default_method: PUI_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_default_method');
end;

function ERROR_UI_get_method(ui: PUI): PUI_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_method');
end;

function ERROR_UI_set_method(ui: PUI; const meth: PUI_METHOD): PUI_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_method');
end;

function ERROR_UI_OpenSSL: PUI_Method; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_OpenSSL');
end;

function ERROR_UI_null: PUI_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_null');
end;

function ERROR_UI_create_method(const name: PAnsiChar): PUI_Method; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_create_method');
end;

procedure ERROR_UI_destroy_method(ui_method: PUI_Method); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_destroy_method');
end;

function ERROR_UI_method_set_opener(method: PUI_Method; opener: UI_method_opener_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_opener');
end;

function ERROR_UI_method_set_writer(method: PUI_Method; writer: UI_method_writer_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_writer');
end;

function ERROR_UI_method_set_flusher(method: PUI_Method; flusher: UI_method_flusher_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_flusher');
end;

function ERROR_UI_method_set_reader(method: PUI_Method; reader: UI_method_reader_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_reader');
end;

function ERROR_UI_method_set_closer(method: PUI_Method; closer: UI_method_closer_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_closer');
end;

function ERROR_UI_method_set_data_duplicator(method: PUI_Method; duplicator: UI_method_data_duplicator_cb; destructor_: UI_method_data_destructor_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_data_duplicator');
end;

function ERROR_UI_method_set_prompt_constructor(method: PUI_Method; prompt_constructor: UI_method_prompt_constructor_cb): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_prompt_constructor');
end;

function ERROR_UI_method_set_ex_data(method: PUI_Method; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_set_ex_data');
end;

function ERROR_UI_method_get_opener(const method: PUI_METHOD): UI_method_opener_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_opener');
end;

function ERROR_UI_method_get_writer(const method: PUI_METHOD): UI_method_writer_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_writer');
end;

function ERROR_UI_method_get_flusher(const method: PUI_METHOD): UI_method_flusher_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_flusher');
end;

function ERROR_UI_method_get_reader(const method: PUI_METHOD): UI_method_reader_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_reader');
end;

function ERROR_UI_method_get_closer(const method: PUI_METHOD): UI_method_closer_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_closer');
end;

function ERROR_UI_method_get_prompt_constructor(const method: PUI_METHOD): UI_method_prompt_constructor_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_prompt_constructor');
end;

function ERROR_UI_method_get_data_duplicator(const method: PUI_METHOD): UI_method_data_duplicator_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_data_duplicator');
end;

function ERROR_UI_method_get_data_destructor(const method: PUI_METHOD): UI_method_data_destructor_cb; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_data_destructor');
end;

function ERROR_UI_method_get_ex_data(const method: PUI_METHOD; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_method_get_ex_data');
end;

function ERROR_UI_get_string_type(uis: PUI_String): UI_string_types; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_string_type');
end;

function ERROR_UI_get_input_flags(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_input_flags');
end;

function ERROR_UI_get0_output_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_output_string');
end;

function ERROR_UI_get0_action_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_action_string');
end;

function ERROR_UI_get0_result_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_result_string');
end;

function ERROR_UI_get_result_string_length(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_string_length');
end;

function ERROR_UI_get0_test_string(uis: PUI_String): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get0_test_string');
end;

function ERROR_UI_get_result_minsize(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_minsize');
end;

function ERROR_UI_get_result_maxsize(uis: PUI_String): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_get_result_maxsize');
end;

function ERROR_UI_set_result(ui: PUI; uis: PUI_String; const result_: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_result');
end;

function ERROR_UI_set_result_ex(ui: PUI; uis: PUI_String; const result_: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_set_result_ex');
end;

function ERROR_UI_UTIL_read_pw_string(buf: PAnsiChar; length: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_UTIL_read_pw_string');
end;

function ERROR_UI_UTIL_read_pw(buf: PAnsiChar; buff: PAnsiChar; size: TOpenSSL_C_INT; const prompt: PAnsiChar; verify: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_UTIL_read_pw');
end;

function ERROR_UI_UTIL_wrap_read_pem_callback(cb: pem_password_cb; rwflag: TOpenSSL_C_INT): PUI_Method; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('UI_UTIL_wrap_read_pem_callback');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  UI_new := LoadLibCryptoFunction('UI_new');
  FuncLoadError := not assigned(UI_new);
  if FuncLoadError then
  begin
    UI_new :=  @ERROR_UI_new;
  end;

  UI_new_method := LoadLibCryptoFunction('UI_new_method');
  FuncLoadError := not assigned(UI_new_method);
  if FuncLoadError then
  begin
    UI_new_method :=  @ERROR_UI_new_method;
  end;

  UI_free := LoadLibCryptoFunction('UI_free');
  FuncLoadError := not assigned(UI_free);
  if FuncLoadError then
  begin
    UI_free :=  @ERROR_UI_free;
  end;

  UI_add_input_string := LoadLibCryptoFunction('UI_add_input_string');
  FuncLoadError := not assigned(UI_add_input_string);
  if FuncLoadError then
  begin
    UI_add_input_string :=  @ERROR_UI_add_input_string;
  end;

  UI_dup_input_string := LoadLibCryptoFunction('UI_dup_input_string');
  FuncLoadError := not assigned(UI_dup_input_string);
  if FuncLoadError then
  begin
    UI_dup_input_string :=  @ERROR_UI_dup_input_string;
  end;

  UI_add_verify_string := LoadLibCryptoFunction('UI_add_verify_string');
  FuncLoadError := not assigned(UI_add_verify_string);
  if FuncLoadError then
  begin
    UI_add_verify_string :=  @ERROR_UI_add_verify_string;
  end;

  UI_dup_verify_string := LoadLibCryptoFunction('UI_dup_verify_string');
  FuncLoadError := not assigned(UI_dup_verify_string);
  if FuncLoadError then
  begin
    UI_dup_verify_string :=  @ERROR_UI_dup_verify_string;
  end;

  UI_add_input_boolean := LoadLibCryptoFunction('UI_add_input_boolean');
  FuncLoadError := not assigned(UI_add_input_boolean);
  if FuncLoadError then
  begin
    UI_add_input_boolean :=  @ERROR_UI_add_input_boolean;
  end;

  UI_dup_input_boolean := LoadLibCryptoFunction('UI_dup_input_boolean');
  FuncLoadError := not assigned(UI_dup_input_boolean);
  if FuncLoadError then
  begin
    UI_dup_input_boolean :=  @ERROR_UI_dup_input_boolean;
  end;

  UI_add_info_string := LoadLibCryptoFunction('UI_add_info_string');
  FuncLoadError := not assigned(UI_add_info_string);
  if FuncLoadError then
  begin
    UI_add_info_string :=  @ERROR_UI_add_info_string;
  end;

  UI_dup_info_string := LoadLibCryptoFunction('UI_dup_info_string');
  FuncLoadError := not assigned(UI_dup_info_string);
  if FuncLoadError then
  begin
    UI_dup_info_string :=  @ERROR_UI_dup_info_string;
  end;

  UI_add_error_string := LoadLibCryptoFunction('UI_add_error_string');
  FuncLoadError := not assigned(UI_add_error_string);
  if FuncLoadError then
  begin
    UI_add_error_string :=  @ERROR_UI_add_error_string;
  end;

  UI_dup_error_string := LoadLibCryptoFunction('UI_dup_error_string');
  FuncLoadError := not assigned(UI_dup_error_string);
  if FuncLoadError then
  begin
    UI_dup_error_string :=  @ERROR_UI_dup_error_string;
  end;

  UI_construct_prompt := LoadLibCryptoFunction('UI_construct_prompt');
  FuncLoadError := not assigned(UI_construct_prompt);
  if FuncLoadError then
  begin
    UI_construct_prompt :=  @ERROR_UI_construct_prompt;
  end;

  UI_add_user_data := LoadLibCryptoFunction('UI_add_user_data');
  FuncLoadError := not assigned(UI_add_user_data);
  if FuncLoadError then
  begin
    UI_add_user_data :=  @ERROR_UI_add_user_data;
  end;

  UI_dup_user_data := LoadLibCryptoFunction('UI_dup_user_data');
  FuncLoadError := not assigned(UI_dup_user_data);
  if FuncLoadError then
  begin
    UI_dup_user_data :=  @ERROR_UI_dup_user_data;
  end;

  UI_get0_user_data := LoadLibCryptoFunction('UI_get0_user_data');
  FuncLoadError := not assigned(UI_get0_user_data);
  if FuncLoadError then
  begin
    UI_get0_user_data :=  @ERROR_UI_get0_user_data;
  end;

  UI_get0_result := LoadLibCryptoFunction('UI_get0_result');
  FuncLoadError := not assigned(UI_get0_result);
  if FuncLoadError then
  begin
    UI_get0_result :=  @ERROR_UI_get0_result;
  end;

  UI_get_result_length := LoadLibCryptoFunction('UI_get_result_length');
  FuncLoadError := not assigned(UI_get_result_length);
  if FuncLoadError then
  begin
    UI_get_result_length :=  @ERROR_UI_get_result_length;
  end;

  UI_process := LoadLibCryptoFunction('UI_process');
  FuncLoadError := not assigned(UI_process);
  if FuncLoadError then
  begin
    UI_process :=  @ERROR_UI_process;
  end;

  UI_ctrl := LoadLibCryptoFunction('UI_ctrl');
  FuncLoadError := not assigned(UI_ctrl);
  if FuncLoadError then
  begin
    UI_ctrl :=  @ERROR_UI_ctrl;
  end;

  UI_set_ex_data := LoadLibCryptoFunction('UI_set_ex_data');
  FuncLoadError := not assigned(UI_set_ex_data);
  if FuncLoadError then
  begin
    UI_set_ex_data :=  @ERROR_UI_set_ex_data;
  end;

  UI_get_ex_data := LoadLibCryptoFunction('UI_get_ex_data');
  FuncLoadError := not assigned(UI_get_ex_data);
  if FuncLoadError then
  begin
    UI_get_ex_data :=  @ERROR_UI_get_ex_data;
  end;

  UI_set_default_method := LoadLibCryptoFunction('UI_set_default_method');
  FuncLoadError := not assigned(UI_set_default_method);
  if FuncLoadError then
  begin
    UI_set_default_method :=  @ERROR_UI_set_default_method;
  end;

  UI_get_default_method := LoadLibCryptoFunction('UI_get_default_method');
  FuncLoadError := not assigned(UI_get_default_method);
  if FuncLoadError then
  begin
    UI_get_default_method :=  @ERROR_UI_get_default_method;
  end;

  UI_get_method := LoadLibCryptoFunction('UI_get_method');
  FuncLoadError := not assigned(UI_get_method);
  if FuncLoadError then
  begin
    UI_get_method :=  @ERROR_UI_get_method;
  end;

  UI_set_method := LoadLibCryptoFunction('UI_set_method');
  FuncLoadError := not assigned(UI_set_method);
  if FuncLoadError then
  begin
    UI_set_method :=  @ERROR_UI_set_method;
  end;

  UI_OpenSSL := LoadLibCryptoFunction('UI_OpenSSL');
  FuncLoadError := not assigned(UI_OpenSSL);
  if FuncLoadError then
  begin
    UI_OpenSSL :=  @ERROR_UI_OpenSSL;
  end;

  UI_null := LoadLibCryptoFunction('UI_null');
  FuncLoadError := not assigned(UI_null);
  if FuncLoadError then
  begin
    UI_null :=  @ERROR_UI_null;
  end;

  UI_create_method := LoadLibCryptoFunction('UI_create_method');
  FuncLoadError := not assigned(UI_create_method);
  if FuncLoadError then
  begin
    UI_create_method :=  @ERROR_UI_create_method;
  end;

  UI_destroy_method := LoadLibCryptoFunction('UI_destroy_method');
  FuncLoadError := not assigned(UI_destroy_method);
  if FuncLoadError then
  begin
    UI_destroy_method :=  @ERROR_UI_destroy_method;
  end;

  UI_method_set_opener := LoadLibCryptoFunction('UI_method_set_opener');
  FuncLoadError := not assigned(UI_method_set_opener);
  if FuncLoadError then
  begin
    UI_method_set_opener :=  @ERROR_UI_method_set_opener;
  end;

  UI_method_set_writer := LoadLibCryptoFunction('UI_method_set_writer');
  FuncLoadError := not assigned(UI_method_set_writer);
  if FuncLoadError then
  begin
    UI_method_set_writer :=  @ERROR_UI_method_set_writer;
  end;

  UI_method_set_flusher := LoadLibCryptoFunction('UI_method_set_flusher');
  FuncLoadError := not assigned(UI_method_set_flusher);
  if FuncLoadError then
  begin
    UI_method_set_flusher :=  @ERROR_UI_method_set_flusher;
  end;

  UI_method_set_reader := LoadLibCryptoFunction('UI_method_set_reader');
  FuncLoadError := not assigned(UI_method_set_reader);
  if FuncLoadError then
  begin
    UI_method_set_reader :=  @ERROR_UI_method_set_reader;
  end;

  UI_method_set_closer := LoadLibCryptoFunction('UI_method_set_closer');
  FuncLoadError := not assigned(UI_method_set_closer);
  if FuncLoadError then
  begin
    UI_method_set_closer :=  @ERROR_UI_method_set_closer;
  end;

  UI_method_set_data_duplicator := LoadLibCryptoFunction('UI_method_set_data_duplicator');
  FuncLoadError := not assigned(UI_method_set_data_duplicator);
  if FuncLoadError then
  begin
    UI_method_set_data_duplicator :=  @ERROR_UI_method_set_data_duplicator;
  end;

  UI_method_set_prompt_constructor := LoadLibCryptoFunction('UI_method_set_prompt_constructor');
  FuncLoadError := not assigned(UI_method_set_prompt_constructor);
  if FuncLoadError then
  begin
    UI_method_set_prompt_constructor :=  @ERROR_UI_method_set_prompt_constructor;
  end;

  UI_method_set_ex_data := LoadLibCryptoFunction('UI_method_set_ex_data');
  FuncLoadError := not assigned(UI_method_set_ex_data);
  if FuncLoadError then
  begin
    UI_method_set_ex_data :=  @ERROR_UI_method_set_ex_data;
  end;

  UI_method_get_opener := LoadLibCryptoFunction('UI_method_get_opener');
  FuncLoadError := not assigned(UI_method_get_opener);
  if FuncLoadError then
  begin
    UI_method_get_opener :=  @ERROR_UI_method_get_opener;
  end;

  UI_method_get_writer := LoadLibCryptoFunction('UI_method_get_writer');
  FuncLoadError := not assigned(UI_method_get_writer);
  if FuncLoadError then
  begin
    UI_method_get_writer :=  @ERROR_UI_method_get_writer;
  end;

  UI_method_get_flusher := LoadLibCryptoFunction('UI_method_get_flusher');
  FuncLoadError := not assigned(UI_method_get_flusher);
  if FuncLoadError then
  begin
    UI_method_get_flusher :=  @ERROR_UI_method_get_flusher;
  end;

  UI_method_get_reader := LoadLibCryptoFunction('UI_method_get_reader');
  FuncLoadError := not assigned(UI_method_get_reader);
  if FuncLoadError then
  begin
    UI_method_get_reader :=  @ERROR_UI_method_get_reader;
  end;

  UI_method_get_closer := LoadLibCryptoFunction('UI_method_get_closer');
  FuncLoadError := not assigned(UI_method_get_closer);
  if FuncLoadError then
  begin
    UI_method_get_closer :=  @ERROR_UI_method_get_closer;
  end;

  UI_method_get_prompt_constructor := LoadLibCryptoFunction('UI_method_get_prompt_constructor');
  FuncLoadError := not assigned(UI_method_get_prompt_constructor);
  if FuncLoadError then
  begin
    UI_method_get_prompt_constructor :=  @ERROR_UI_method_get_prompt_constructor;
  end;

  UI_method_get_data_duplicator := LoadLibCryptoFunction('UI_method_get_data_duplicator');
  FuncLoadError := not assigned(UI_method_get_data_duplicator);
  if FuncLoadError then
  begin
    UI_method_get_data_duplicator :=  @ERROR_UI_method_get_data_duplicator;
  end;

  UI_method_get_data_destructor := LoadLibCryptoFunction('UI_method_get_data_destructor');
  FuncLoadError := not assigned(UI_method_get_data_destructor);
  if FuncLoadError then
  begin
    UI_method_get_data_destructor :=  @ERROR_UI_method_get_data_destructor;
  end;

  UI_method_get_ex_data := LoadLibCryptoFunction('UI_method_get_ex_data');
  FuncLoadError := not assigned(UI_method_get_ex_data);
  if FuncLoadError then
  begin
    UI_method_get_ex_data :=  @ERROR_UI_method_get_ex_data;
  end;

  UI_get_string_type := LoadLibCryptoFunction('UI_get_string_type');
  FuncLoadError := not assigned(UI_get_string_type);
  if FuncLoadError then
  begin
    UI_get_string_type :=  @ERROR_UI_get_string_type;
  end;

  UI_get_input_flags := LoadLibCryptoFunction('UI_get_input_flags');
  FuncLoadError := not assigned(UI_get_input_flags);
  if FuncLoadError then
  begin
    UI_get_input_flags :=  @ERROR_UI_get_input_flags;
  end;

  UI_get0_output_string := LoadLibCryptoFunction('UI_get0_output_string');
  FuncLoadError := not assigned(UI_get0_output_string);
  if FuncLoadError then
  begin
    UI_get0_output_string :=  @ERROR_UI_get0_output_string;
  end;

  UI_get0_action_string := LoadLibCryptoFunction('UI_get0_action_string');
  FuncLoadError := not assigned(UI_get0_action_string);
  if FuncLoadError then
  begin
    UI_get0_action_string :=  @ERROR_UI_get0_action_string;
  end;

  UI_get0_result_string := LoadLibCryptoFunction('UI_get0_result_string');
  FuncLoadError := not assigned(UI_get0_result_string);
  if FuncLoadError then
  begin
    UI_get0_result_string :=  @ERROR_UI_get0_result_string;
  end;

  UI_get_result_string_length := LoadLibCryptoFunction('UI_get_result_string_length');
  FuncLoadError := not assigned(UI_get_result_string_length);
  if FuncLoadError then
  begin
    UI_get_result_string_length :=  @ERROR_UI_get_result_string_length;
  end;

  UI_get0_test_string := LoadLibCryptoFunction('UI_get0_test_string');
  FuncLoadError := not assigned(UI_get0_test_string);
  if FuncLoadError then
  begin
    UI_get0_test_string :=  @ERROR_UI_get0_test_string;
  end;

  UI_get_result_minsize := LoadLibCryptoFunction('UI_get_result_minsize');
  FuncLoadError := not assigned(UI_get_result_minsize);
  if FuncLoadError then
  begin
    UI_get_result_minsize :=  @ERROR_UI_get_result_minsize;
  end;

  UI_get_result_maxsize := LoadLibCryptoFunction('UI_get_result_maxsize');
  FuncLoadError := not assigned(UI_get_result_maxsize);
  if FuncLoadError then
  begin
    UI_get_result_maxsize :=  @ERROR_UI_get_result_maxsize;
  end;

  UI_set_result := LoadLibCryptoFunction('UI_set_result');
  FuncLoadError := not assigned(UI_set_result);
  if FuncLoadError then
  begin
    UI_set_result :=  @ERROR_UI_set_result;
  end;

  UI_set_result_ex := LoadLibCryptoFunction('UI_set_result_ex');
  FuncLoadError := not assigned(UI_set_result_ex);
  if FuncLoadError then
  begin
    UI_set_result_ex :=  @ERROR_UI_set_result_ex;
  end;

  UI_UTIL_read_pw_string := LoadLibCryptoFunction('UI_UTIL_read_pw_string');
  FuncLoadError := not assigned(UI_UTIL_read_pw_string);
  if FuncLoadError then
  begin
    UI_UTIL_read_pw_string :=  @ERROR_UI_UTIL_read_pw_string;
  end;

  UI_UTIL_read_pw := LoadLibCryptoFunction('UI_UTIL_read_pw');
  FuncLoadError := not assigned(UI_UTIL_read_pw);
  if FuncLoadError then
  begin
    UI_UTIL_read_pw :=  @ERROR_UI_UTIL_read_pw;
  end;

  UI_UTIL_wrap_read_pem_callback := LoadLibCryptoFunction('UI_UTIL_wrap_read_pem_callback');
  FuncLoadError := not assigned(UI_UTIL_wrap_read_pem_callback);
  if FuncLoadError then
  begin
    UI_UTIL_wrap_read_pem_callback :=  @ERROR_UI_UTIL_wrap_read_pem_callback;
  end;

end;

procedure UnLoad;
begin
  UI_new := nil;
  UI_new_method := nil;
  UI_free := nil;
  UI_add_input_string := nil;
  UI_dup_input_string := nil;
  UI_add_verify_string := nil;
  UI_dup_verify_string := nil;
  UI_add_input_boolean := nil;
  UI_dup_input_boolean := nil;
  UI_add_info_string := nil;
  UI_dup_info_string := nil;
  UI_add_error_string := nil;
  UI_dup_error_string := nil;
  UI_construct_prompt := nil;
  UI_add_user_data := nil;
  UI_dup_user_data := nil;
  UI_get0_user_data := nil;
  UI_get0_result := nil;
  UI_get_result_length := nil;
  UI_process := nil;
  UI_ctrl := nil;
  UI_set_ex_data := nil;
  UI_get_ex_data := nil;
  UI_set_default_method := nil;
  UI_get_default_method := nil;
  UI_get_method := nil;
  UI_set_method := nil;
  UI_OpenSSL := nil;
  UI_null := nil;
  UI_create_method := nil;
  UI_destroy_method := nil;
  UI_method_set_opener := nil;
  UI_method_set_writer := nil;
  UI_method_set_flusher := nil;
  UI_method_set_reader := nil;
  UI_method_set_closer := nil;
  UI_method_set_data_duplicator := nil;
  UI_method_set_prompt_constructor := nil;
  UI_method_set_ex_data := nil;
  UI_method_get_opener := nil;
  UI_method_get_writer := nil;
  UI_method_get_flusher := nil;
  UI_method_get_reader := nil;
  UI_method_get_closer := nil;
  UI_method_get_prompt_constructor := nil;
  UI_method_get_data_duplicator := nil;
  UI_method_get_data_destructor := nil;
  UI_method_get_ex_data := nil;
  UI_get_string_type := nil;
  UI_get_input_flags := nil;
  UI_get0_output_string := nil;
  UI_get0_action_string := nil;
  UI_get0_result_string := nil;
  UI_get_result_string_length := nil;
  UI_get0_test_string := nil;
  UI_get_result_minsize := nil;
  UI_get_result_maxsize := nil;
  UI_set_result := nil;
  UI_set_result_ex := nil;
  UI_UTIL_read_pw_string := nil;
  UI_UTIL_read_pw := nil;
  UI_UTIL_wrap_read_pem_callback := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
