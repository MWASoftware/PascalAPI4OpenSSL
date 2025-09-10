(* This unit was generated from the source file err.h2pas 
It should not be modified directly. All changes should be made to err.h2pas
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


unit OpenSSL_err;


interface

// Headers for OpenSSL 1.1.1
// err.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ;

const
  ERR_TXT_MALLOCED = $01;
  ERR_TXT_STRING = $02;
  ERR_FLAG_MARK = $01;
  ERR_FLAG_CLEAR = $02;

  ERR_NUM_ERRORS = 16;

//* library */
  ERR_LIB_SYS =    2;
  ERR_LIB_BN =    3;
  ERR_LIB_RSA =    4;
  ERR_LIB_DH =    5;
  ERR_LIB_EVP =    6;
  ERR_LIB_BUF =    7;
  ERR_LIB_OBJ =    8;
  ERR_LIB_PEM =    9;
  ERR_LIB_DSA =    10;
  ERR_LIB_X509 =    11;
  // ERR_LIB_METH         12
  ERR_LIB_ASN1 =    13;
  ERR_LIB_CONF =    14;
  ERR_LIB_CRYPTO =   15;
  ERR_LIB_EC =    16;
  ERR_LIB_SSL =    20;
(* #define ERR_LIB_SSL23        21 *)
(* #define ERR_LIB_SSL2         22 *)
(* #define ERR_LIB_SSL3         23 *)
(* #define ERR_LIB_RSAREF       30 *)
(* #define ERR_LIB_PROXY        31 *)
  ERR_LIB_BIO =    32;
  ERR_LIB_PKCS7 =    33;
  ERR_LIB_X509V3 =   34;
  ERR_LIB_PKCS12 =   35;
  ERR_LIB_RAND =    36;
  ERR_LIB_DSO =    37;
  ERR_LIB_ENGINE =   38;
  ERR_LIB_OCSP =    39;
  ERR_LIB_UI =    40;
  ERR_LIB_COMP =    41;
  ERR_LIB_ECDSA =    42;
  ERR_LIB_ECDH =    43;
  ERR_LIB_OSSL_STORE =  44;
  ERR_LIB_FIPS =    45;
  ERR_LIB_CMS =    46;
  ERR_LIB_TS =    47;
  ERR_LIB_HMAC =    48;
(* # define ERR_LIB_JPAKE       49 *)
  ERR_LIB_CT =    50;
  ERR_LIB_ASYNC =    51;
  ERR_LIB_KDF =    52;
  ERR_LIB_SM2 =    53;
  ERR_LIB_USER =    128;
  
//* OS functions */
  SYS_F_FOPEN = 1;
  SYS_F_CONNECT = 2;
  SYS_F_GETSERVBYNAME = 3;
  SYS_F_SOCKET = 4;
  SYS_F_IOCTLSOCKET = 5;
  SYS_F_BIND = 6;
  SYS_F_LISTEN = 7;
  SYS_F_ACCEPT = 8;
  SYS_F_WSASTARTUP = 9; (* Winsock stuff *)
  SYS_F_OPENDIR = 10;
  SYS_F_FREAD = 11;
  SYS_F_GETADDRINFO = 12;
  SYS_F_GETNAMEINFO = 13;
  SYS_F_SETSOCKOPT = 14;
  SYS_F_GETSOCKOPT = 15;
  SYS_F_GETSOCKNAME = 16;
  SYS_F_GETHOSTBYNAME = 17;
  SYS_F_FFLUSH = 18;
  SYS_F_OPEN = 19;
  SYS_F_CLOSE = 20;
  SYS_F_IOCTL = 21;
  SYS_F_STAT = 22;
  SYS_F_FCNTL = 23;
  SYS_F_FSTAT = 24;

//* reasons */
  ERR_R_SYS_LIB = ERR_LIB_SYS; //2
  ERR_R_BN_LIB = ERR_LIB_BN; //3
  ERR_R_RSA_LIB = ERR_LIB_RSA; //4
  ERR_R_DH_LIB = ERR_LIB_DH; //5
  ERR_R_EVP_LIB = ERR_LIB_EVP; //6
  ERR_R_BUF_LIB = ERR_LIB_BUF; //7
  ERR_R_OBJ_LIB = ERR_LIB_OBJ; //8
  ERR_R_PEM_LIB = ERR_LIB_PEM; //9
  ERR_R_DSA_LIB = ERR_LIB_DSA; //10
  ERR_R_X509_LIB = ERR_LIB_X509; //11
  ERR_R_ASN1_LIB = ERR_LIB_ASN1; //13
  ERR_R_EC_LIB = ERR_LIB_EC; //16
  ERR_R_BIO_LIB = ERR_LIB_BIO; //32
  ERR_R_PKCS7_LIB = ERR_LIB_PKCS7; //33
  ERR_R_X509V3_LIB = ERR_LIB_X509V3; //34
  ERR_R_ENGINE_LIB = ERR_LIB_ENGINE; //38
  ERR_R_UI_LIB = ERR_LIB_UI; //40
  ERR_R_ECDSA_LIB = ERR_LIB_ECDSA; //42
  ERR_R_OSSL_STORE_LIB = ERR_LIB_OSSL_STORE; //44

  ERR_R_NESTED_ASN1_ERROR =  58;
  ERR_R_MISSING_ASN1_EOS =  63;

  //* fatal error */
  ERR_R_FATAL =  64;
  ERR_R_MALLOC_FAILURE = (1 or ERR_R_FATAL);
  ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED = (2 or ERR_R_FATAL);
  ERR_R_PASSED_NULL_PARAMETER = (3 or ERR_R_FATAL);
  ERR_R_INTERNAL_ERROR = (4 or ERR_R_FATAL);
  ERR_R_DISABLED = (5 or ERR_R_FATAL);
  ERR_R_INIT_FAIL = (6 or ERR_R_FATAL);
  ERR_R_PASSED_INVALID_ARGUMENT = (7);
  ERR_R_OPERATION_FAIL = (8 or ERR_R_FATAL);
  ERR_R_PKCS12_LIB = ERR_LIB_PKCS12;


(*
 * 99 is the maximum possible ERR_R_... code, higher values are reserved for
 * the individual libraries
 *)

type
  err_state_st = record
    err_flags: array[0..ERR_NUM_ERRORS -1] of TOpenSSL_C_INT;
    err_buffer: array[0..ERR_NUM_ERRORS -1] of TOpenSSL_C_ULONG;
    err_data: array[0..ERR_NUM_ERRORS -1] of PAnsiChar;
    err_data_flags: array[0..ERR_NUM_ERRORS -1] of TOpenSSL_C_INT;
    err_file: array[0..ERR_NUM_ERRORS -1] of PAnsiChar;
    err_line: array[0..ERR_NUM_ERRORS -1] of TOpenSSL_C_INT;
    top, bottom: TOpenSSL_C_INT;
  end;
  ERR_STATE = err_state_st;
  PERR_STATE = ^ERR_STATE;

  ERR_string_data_st = record
    error: TOpenSSL_C_ULONG;
    string_: PAnsiChar;
  end;
  ERR_STRING_DATA = ERR_string_data_st;
  PERR_STRING_DATA = ^ERR_STRING_DATA;

  ERR_print_errors_cb_cb = function(str: PAnsiChar; len: TOpenSSL_C_SIZET; u: Pointer): TOpenSSL_C_INT; cdecl;

// DEFINE_LHASH_OF(ERR_STRING_DATA);

  

function ERR_GET_LIB(l: TOpenSSL_C_INT): TOpenSSL_C_ULONG;

{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM ERR_new}
{$EXTERNALSYM ERR_set_debug}
{$EXTERNALSYM ERR_set_error}
{$EXTERNALSYM ERR_set_error_data}
{$EXTERNALSYM ERR_get_error}
{$EXTERNALSYM ERR_get_error_line}
{$EXTERNALSYM ERR_get_error_line_data}
{$EXTERNALSYM ERR_peek_error}
{$EXTERNALSYM ERR_peek_error_line}
{$EXTERNALSYM ERR_peek_error_line_data}
{$EXTERNALSYM ERR_peek_last_error}
{$EXTERNALSYM ERR_peek_last_error_line}
{$EXTERNALSYM ERR_peek_last_error_line_data}
{$EXTERNALSYM ERR_clear_error}
{$EXTERNALSYM ERR_error_string}
{$EXTERNALSYM ERR_error_string_n}
{$EXTERNALSYM ERR_lib_error_string}
{$EXTERNALSYM ERR_func_error_string}
{$EXTERNALSYM ERR_reason_error_string}
{$EXTERNALSYM ERR_print_errors_cb}
{$EXTERNALSYM ERR_print_errors}
{$EXTERNALSYM ERR_load_strings}
{$EXTERNALSYM ERR_load_strings_const}
{$EXTERNALSYM ERR_unload_strings}
{$EXTERNALSYM ERR_load_ERR_strings}
{$EXTERNALSYM ERR_get_state}
{$EXTERNALSYM ERR_get_next_error_library}
{$EXTERNALSYM ERR_set_mark}
{$EXTERNALSYM ERR_pop_to_mark}
{$EXTERNALSYM ERR_clear_last_mark}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
procedure ERR_new; cdecl; external CLibCrypto;
procedure ERR_set_debug(const file_: PAnsiChar; line: integer; const func: PAnsiChar); cdecl; external CLibCrypto;
procedure ERR_set_error(lib: integer; reason: integer; fmt: PAnsiChar); cdecl varargs; external CLibCrypto;
procedure ERR_set_error_data(data: PAnsiChar; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function ERR_get_error: TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_get_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_get_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_peek_error: TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_peek_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_peek_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_peek_last_error: TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_peek_last_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
function ERR_peek_last_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl; external CLibCrypto;
procedure ERR_clear_error; cdecl; external CLibCrypto;
function ERR_error_string(e: TOpenSSL_C_ULONG; buf: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
procedure ERR_error_string_n(e: TOpenSSL_C_ULONG; buf: PAnsiChar; len: TOpenSSL_C_SIZET); cdecl; external CLibCrypto;
function ERR_lib_error_string(e: TOpenSSL_C_ULONG): PAnsiChar; cdecl; external CLibCrypto;
function ERR_func_error_string(e: TOpenSSL_C_ULONG): PAnsiChar; cdecl; external CLibCrypto;
function ERR_reason_error_string(e: TOpenSSL_C_ULONG): PAnsiChar; cdecl; external CLibCrypto;
procedure ERR_print_errors_cb(cb: ERR_print_errors_cb_cb; u: Pointer); cdecl; external CLibCrypto;
procedure ERR_print_errors(bp: PBIO); cdecl; external CLibCrypto;
function ERR_load_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ERR_load_strings_const(str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ERR_unload_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ERR_load_ERR_strings: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ERR_get_state: PERR_STATE; cdecl; external CLibCrypto;
function ERR_get_next_error_library: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ERR_set_mark: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ERR_pop_to_mark: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function ERR_clear_last_mark: TOpenSSL_C_INT; cdecl; external CLibCrypto;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERR_put_error(lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; file_: PAnsiChar; line: TOpenSSL_C_INT); {removed 3.0.0}
procedure SSLErr(func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT); {removed 1.0.0}
procedure X509err(const f,r : TOpenSSL_C_INT); {removed 1.0.0}
function ERR_GET_REASON(const l : TOpenSSL_C_INT): TOpenSSL_C_INT; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  ERR_new: procedure ; cdecl = nil;
  ERR_set_debug: procedure (const file_: PAnsiChar; line: integer; const func: PAnsiChar); cdecl = nil;
  ERR_set_error: procedure (lib: integer; reason: integer; fmt: PAnsiChar); cdecl varargs = nil;
  ERR_set_error_data: procedure (data: PAnsiChar; flags: TOpenSSL_C_INT); cdecl = nil;
  ERR_get_error: function : TOpenSSL_C_ULONG; cdecl = nil;
  ERR_get_error_line: function (file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;
  ERR_get_error_line_data: function (file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;
  ERR_peek_error: function : TOpenSSL_C_ULONG; cdecl = nil;
  ERR_peek_error_line: function (file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;
  ERR_peek_error_line_data: function (file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;
  ERR_peek_last_error: function : TOpenSSL_C_ULONG; cdecl = nil;
  ERR_peek_last_error_line: function (file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;
  ERR_peek_last_error_line_data: function (file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl = nil;
  ERR_clear_error: procedure ; cdecl = nil;
  ERR_error_string: function (e: TOpenSSL_C_ULONG; buf: PAnsiChar): PAnsiChar; cdecl = nil;
  ERR_error_string_n: procedure (e: TOpenSSL_C_ULONG; buf: PAnsiChar; len: TOpenSSL_C_SIZET); cdecl = nil;
  ERR_lib_error_string: function (e: TOpenSSL_C_ULONG): PAnsiChar; cdecl = nil;
  ERR_func_error_string: function (e: TOpenSSL_C_ULONG): PAnsiChar; cdecl = nil;
  ERR_reason_error_string: function (e: TOpenSSL_C_ULONG): PAnsiChar; cdecl = nil;
  ERR_print_errors_cb: procedure (cb: ERR_print_errors_cb_cb; u: Pointer); cdecl = nil;
  ERR_print_errors: procedure (bp: PBIO); cdecl = nil;
  ERR_load_strings: function (lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl = nil;
  ERR_load_strings_const: function (str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl = nil;
  ERR_unload_strings: function (lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl = nil;
  ERR_load_ERR_strings: function : TOpenSSL_C_INT; cdecl = nil;
  ERR_get_state: function : PERR_STATE; cdecl = nil;
  ERR_get_next_error_library: function : TOpenSSL_C_INT; cdecl = nil;
  ERR_set_mark: function : TOpenSSL_C_INT; cdecl = nil;
  ERR_pop_to_mark: function : TOpenSSL_C_INT; cdecl = nil;
  ERR_clear_last_mark: function : TOpenSSL_C_INT; cdecl = nil;




{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  ERR_put_error: procedure (lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl = nil; {removed 3.0.0}
  SSLErr: procedure (func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT); cdecl = nil; {removed 1.0.0}
  X509err: procedure (const f,r : TOpenSSL_C_INT); cdecl = nil; {removed 1.0.0}
  ERR_GET_REASON: function (const l : TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  ERR_put_error_removed = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 3.0.0}
  ERR_new_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  ERR_set_debug_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  ERR_set_error_introduced = ((((((byte(3) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 3.0.0}
  ERR_load_strings_const_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  ERR_clear_last_mark_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  SSLErr_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  X509err_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  ERR_GET_REASON_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}


implementation


uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}

function ERR_GET_LIB(l: TOpenSSL_C_INT): TOpenSSL_C_ULONG;
begin
  Result := (l shr 24) and $ff;
end;

{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure SSLErr(func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT);

begin
  ERR_put_error(ERR_LIB_SSL,func,reason,'',0);
end; 



procedure ERR_put_error(lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; file_: PAnsiChar; line: TOpenSSL_C_INT);

{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), ''))}
begin
  ERR_new;
  ERR_set_debug(file_,line, '');
  ERR_set_error(lib,reason,'');
end;



procedure X509err(const f,r : TOpenSSL_C_INT);

begin
  ERR_PUT_error(ERR_LIB_X509,f,r,nil,0);
end;



function ERR_GET_REASON(const l : TOpenSSL_C_INT): TOpenSSL_C_INT;

begin
  Result := l and $fff;
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure COMPAT_SSLErr(func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT); cdecl;

begin
  ERR_put_error(ERR_LIB_SSL,func,reason,'',0);
end; 



procedure COMPAT_ERR_put_error(lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl;

{ From 3.0 onwards, replaced by a macro
  define ERR_put_error(lib, func, reason, file, line)
    (ERR_new(),
     ERR_set_debug((file), (line), OPENSSL_FUNC),
     ERR_set_error((lib), (reason), ''))}
begin
  ERR_new;
  ERR_set_debug(file_,line, '');
  ERR_set_error(lib,reason,'');
end;



procedure COMPAT_X509err(const f,r : TOpenSSL_C_INT); cdecl;

begin
  ERR_PUT_error(ERR_LIB_X509,f,r,nil,0);
end;



function COMPAT_ERR_GET_REASON(const l : TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

begin
  Result := l and $fff;
end;


{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_ERR_put_error(lib: TOpenSSL_C_INT; func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT; file_: PAnsiChar; line: TOpenSSL_C_INT); cdecl; {removed 3.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_put_error');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

procedure ERROR_ERR_new; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_new');
end;

procedure ERROR_ERR_set_debug(const file_: PAnsiChar; line: integer; const func: PAnsiChar); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_set_debug');
end;

procedure ERROR_ERR_set_error(lib: integer; reason: integer; fmt: PAnsiChar); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_set_error');
end;

procedure ERROR_ERR_set_error_data(data: PAnsiChar; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_set_error_data');
end;

function ERROR_ERR_get_error: TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_error');
end;

function ERROR_ERR_get_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_error_line');
end;

function ERROR_ERR_get_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_error_line_data');
end;

function ERROR_ERR_peek_error: TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error');
end;

function ERROR_ERR_peek_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error_line');
end;

function ERROR_ERR_peek_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_error_line_data');
end;

function ERROR_ERR_peek_last_error: TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error');
end;

function ERROR_ERR_peek_last_error_line(file_: PPAnsiChar; line: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error_line');
end;

function ERROR_ERR_peek_last_error_line_data(file_: PPAnsiChar; line: POpenSSL_C_INT; data: PPAnsiChar; flags: POpenSSL_C_INT): TOpenSSL_C_ULONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_peek_last_error_line_data');
end;

procedure ERROR_ERR_clear_error; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_clear_error');
end;

function ERROR_ERR_error_string(e: TOpenSSL_C_ULONG; buf: PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_error_string');
end;

procedure ERROR_ERR_error_string_n(e: TOpenSSL_C_ULONG; buf: PAnsiChar; len: TOpenSSL_C_SIZET); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_error_string_n');
end;

function ERROR_ERR_lib_error_string(e: TOpenSSL_C_ULONG): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_lib_error_string');
end;

function ERROR_ERR_func_error_string(e: TOpenSSL_C_ULONG): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_func_error_string');
end;

function ERROR_ERR_reason_error_string(e: TOpenSSL_C_ULONG): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_reason_error_string');
end;

procedure ERROR_ERR_print_errors_cb(cb: ERR_print_errors_cb_cb; u: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_print_errors_cb');
end;

procedure ERROR_ERR_print_errors(bp: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_print_errors');
end;

function ERROR_ERR_load_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_strings');
end;

function ERROR_ERR_load_strings_const(str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_strings_const');
end;

function ERROR_ERR_unload_strings(lib: TOpenSSL_C_INT; str: PERR_STRING_DATA): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_unload_strings');
end;

function ERROR_ERR_load_ERR_strings: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_load_ERR_strings');
end;

function ERROR_ERR_get_state: PERR_STATE; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_state');
end;

function ERROR_ERR_get_next_error_library: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_get_next_error_library');
end;

function ERROR_ERR_set_mark: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_set_mark');
end;

function ERROR_ERR_pop_to_mark: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_pop_to_mark');
end;

function ERROR_ERR_clear_last_mark: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_clear_last_mark');
end;

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_SSLErr(func: TOpenSSL_C_INT; reason: TOpenSSL_C_INT); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('SSLErr');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_X509err(const f,r : TOpenSSL_C_INT); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('X509err');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_ERR_GET_REASON(const l : TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ERR_GET_REASON');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  ERR_put_error := LoadLibCryptoFunction('ERR_put_error');
  FuncLoadError := not assigned(ERR_put_error);
  if FuncLoadError then
  begin
    ERR_put_error := @COMPAT_ERR_put_error;
    if ERR_put_error_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('ERR_put_error');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  ERR_new := LoadLibCryptoFunction('ERR_new');
  FuncLoadError := not assigned(ERR_new);
  if FuncLoadError then
  begin
    ERR_new :=  @ERROR_ERR_new;
  end;

  ERR_set_debug := LoadLibCryptoFunction('ERR_set_debug');
  FuncLoadError := not assigned(ERR_set_debug);
  if FuncLoadError then
  begin
    ERR_set_debug :=  @ERROR_ERR_set_debug;
  end;

  ERR_set_error := LoadLibCryptoFunction('ERR_set_error');
  FuncLoadError := not assigned(ERR_set_error);
  if FuncLoadError then
  begin
    ERR_set_error :=  @ERROR_ERR_set_error;
  end;

  ERR_set_error_data := LoadLibCryptoFunction('ERR_set_error_data');
  FuncLoadError := not assigned(ERR_set_error_data);
  if FuncLoadError then
  begin
    ERR_set_error_data :=  @ERROR_ERR_set_error_data;
  end;

  ERR_get_error := LoadLibCryptoFunction('ERR_get_error');
  FuncLoadError := not assigned(ERR_get_error);
  if FuncLoadError then
  begin
    ERR_get_error :=  @ERROR_ERR_get_error;
  end;

  ERR_get_error_line := LoadLibCryptoFunction('ERR_get_error_line');
  FuncLoadError := not assigned(ERR_get_error_line);
  if FuncLoadError then
  begin
    ERR_get_error_line :=  @ERROR_ERR_get_error_line;
  end;

  ERR_get_error_line_data := LoadLibCryptoFunction('ERR_get_error_line_data');
  FuncLoadError := not assigned(ERR_get_error_line_data);
  if FuncLoadError then
  begin
    ERR_get_error_line_data :=  @ERROR_ERR_get_error_line_data;
  end;

  ERR_peek_error := LoadLibCryptoFunction('ERR_peek_error');
  FuncLoadError := not assigned(ERR_peek_error);
  if FuncLoadError then
  begin
    ERR_peek_error :=  @ERROR_ERR_peek_error;
  end;

  ERR_peek_error_line := LoadLibCryptoFunction('ERR_peek_error_line');
  FuncLoadError := not assigned(ERR_peek_error_line);
  if FuncLoadError then
  begin
    ERR_peek_error_line :=  @ERROR_ERR_peek_error_line;
  end;

  ERR_peek_error_line_data := LoadLibCryptoFunction('ERR_peek_error_line_data');
  FuncLoadError := not assigned(ERR_peek_error_line_data);
  if FuncLoadError then
  begin
    ERR_peek_error_line_data :=  @ERROR_ERR_peek_error_line_data;
  end;

  ERR_peek_last_error := LoadLibCryptoFunction('ERR_peek_last_error');
  FuncLoadError := not assigned(ERR_peek_last_error);
  if FuncLoadError then
  begin
    ERR_peek_last_error :=  @ERROR_ERR_peek_last_error;
  end;

  ERR_peek_last_error_line := LoadLibCryptoFunction('ERR_peek_last_error_line');
  FuncLoadError := not assigned(ERR_peek_last_error_line);
  if FuncLoadError then
  begin
    ERR_peek_last_error_line :=  @ERROR_ERR_peek_last_error_line;
  end;

  ERR_peek_last_error_line_data := LoadLibCryptoFunction('ERR_peek_last_error_line_data');
  FuncLoadError := not assigned(ERR_peek_last_error_line_data);
  if FuncLoadError then
  begin
    ERR_peek_last_error_line_data :=  @ERROR_ERR_peek_last_error_line_data;
  end;

  ERR_clear_error := LoadLibCryptoFunction('ERR_clear_error');
  FuncLoadError := not assigned(ERR_clear_error);
  if FuncLoadError then
  begin
    ERR_clear_error :=  @ERROR_ERR_clear_error;
  end;

  ERR_error_string := LoadLibCryptoFunction('ERR_error_string');
  FuncLoadError := not assigned(ERR_error_string);
  if FuncLoadError then
  begin
    ERR_error_string :=  @ERROR_ERR_error_string;
  end;

  ERR_error_string_n := LoadLibCryptoFunction('ERR_error_string_n');
  FuncLoadError := not assigned(ERR_error_string_n);
  if FuncLoadError then
  begin
    ERR_error_string_n :=  @ERROR_ERR_error_string_n;
  end;

  ERR_lib_error_string := LoadLibCryptoFunction('ERR_lib_error_string');
  FuncLoadError := not assigned(ERR_lib_error_string);
  if FuncLoadError then
  begin
    ERR_lib_error_string :=  @ERROR_ERR_lib_error_string;
  end;

  ERR_func_error_string := LoadLibCryptoFunction('ERR_func_error_string');
  FuncLoadError := not assigned(ERR_func_error_string);
  if FuncLoadError then
  begin
    ERR_func_error_string :=  @ERROR_ERR_func_error_string;
  end;

  ERR_reason_error_string := LoadLibCryptoFunction('ERR_reason_error_string');
  FuncLoadError := not assigned(ERR_reason_error_string);
  if FuncLoadError then
  begin
    ERR_reason_error_string :=  @ERROR_ERR_reason_error_string;
  end;

  ERR_print_errors_cb := LoadLibCryptoFunction('ERR_print_errors_cb');
  FuncLoadError := not assigned(ERR_print_errors_cb);
  if FuncLoadError then
  begin
    ERR_print_errors_cb :=  @ERROR_ERR_print_errors_cb;
  end;

  ERR_print_errors := LoadLibCryptoFunction('ERR_print_errors');
  FuncLoadError := not assigned(ERR_print_errors);
  if FuncLoadError then
  begin
    ERR_print_errors :=  @ERROR_ERR_print_errors;
  end;

  ERR_load_strings := LoadLibCryptoFunction('ERR_load_strings');
  FuncLoadError := not assigned(ERR_load_strings);
  if FuncLoadError then
  begin
    ERR_load_strings :=  @ERROR_ERR_load_strings;
  end;

  ERR_load_strings_const := LoadLibCryptoFunction('ERR_load_strings_const');
  FuncLoadError := not assigned(ERR_load_strings_const);
  if FuncLoadError then
  begin
    ERR_load_strings_const :=  @ERROR_ERR_load_strings_const;
  end;

  ERR_unload_strings := LoadLibCryptoFunction('ERR_unload_strings');
  FuncLoadError := not assigned(ERR_unload_strings);
  if FuncLoadError then
  begin
    ERR_unload_strings :=  @ERROR_ERR_unload_strings;
  end;

  ERR_load_ERR_strings := LoadLibCryptoFunction('ERR_load_ERR_strings');
  FuncLoadError := not assigned(ERR_load_ERR_strings);
  if FuncLoadError then
  begin
    ERR_load_ERR_strings :=  @ERROR_ERR_load_ERR_strings;
  end;

  ERR_get_state := LoadLibCryptoFunction('ERR_get_state');
  FuncLoadError := not assigned(ERR_get_state);
  if FuncLoadError then
  begin
    ERR_get_state :=  @ERROR_ERR_get_state;
  end;

  ERR_get_next_error_library := LoadLibCryptoFunction('ERR_get_next_error_library');
  FuncLoadError := not assigned(ERR_get_next_error_library);
  if FuncLoadError then
  begin
    ERR_get_next_error_library :=  @ERROR_ERR_get_next_error_library;
  end;

  ERR_set_mark := LoadLibCryptoFunction('ERR_set_mark');
  FuncLoadError := not assigned(ERR_set_mark);
  if FuncLoadError then
  begin
    ERR_set_mark :=  @ERROR_ERR_set_mark;
  end;

  ERR_pop_to_mark := LoadLibCryptoFunction('ERR_pop_to_mark');
  FuncLoadError := not assigned(ERR_pop_to_mark);
  if FuncLoadError then
  begin
    ERR_pop_to_mark :=  @ERROR_ERR_pop_to_mark;
  end;

  ERR_clear_last_mark := LoadLibCryptoFunction('ERR_clear_last_mark');
  FuncLoadError := not assigned(ERR_clear_last_mark);
  if FuncLoadError then
  begin
    ERR_clear_last_mark :=  @ERROR_ERR_clear_last_mark;
  end;

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLErr := LoadLibCryptoFunction('SSLErr');
  FuncLoadError := not assigned(SSLErr);
  if FuncLoadError then
  begin
    SSLErr := @COMPAT_SSLErr;
    if SSLErr_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('SSLErr');
  end;

  X509err := LoadLibCryptoFunction('X509err');
  FuncLoadError := not assigned(X509err);
  if FuncLoadError then
  begin
    X509err := @COMPAT_X509err;
    if X509err_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('X509err');
  end;

  ERR_GET_REASON := LoadLibCryptoFunction('ERR_GET_REASON');
  FuncLoadError := not assigned(ERR_GET_REASON);
  if FuncLoadError then
  begin
    ERR_GET_REASON := @COMPAT_ERR_GET_REASON;
    if ERR_GET_REASON_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('ERR_GET_REASON');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  ERR_put_error := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  ERR_new := nil;
  ERR_set_debug := nil;
  ERR_set_error := nil;
  ERR_set_error_data := nil;
  ERR_get_error := nil;
  ERR_get_error_line := nil;
  ERR_get_error_line_data := nil;
  ERR_peek_error := nil;
  ERR_peek_error_line := nil;
  ERR_peek_error_line_data := nil;
  ERR_peek_last_error := nil;
  ERR_peek_last_error_line := nil;
  ERR_peek_last_error_line_data := nil;
  ERR_clear_error := nil;
  ERR_error_string := nil;
  ERR_error_string_n := nil;
  ERR_lib_error_string := nil;
  ERR_func_error_string := nil;
  ERR_reason_error_string := nil;
  ERR_print_errors_cb := nil;
  ERR_print_errors := nil;
  ERR_load_strings := nil;
  ERR_load_strings_const := nil;
  ERR_unload_strings := nil;
  ERR_load_ERR_strings := nil;
  ERR_get_state := nil;
  ERR_get_next_error_library := nil;
  ERR_set_mark := nil;
  ERR_pop_to_mark := nil;
  ERR_clear_last_mark := nil;
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  SSLErr := nil;
  X509err := nil;
  ERR_GET_REASON := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
