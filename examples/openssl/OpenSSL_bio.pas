(* This unit was generated from the source file bio.h2pas 
It should not be modified directly. All changes should be made to bio.h2pas
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


unit OpenSSL_bio;


interface

// Headers for OpenSSL 1.1.1
// bio.h


uses
  OpenSSLAPI,
  OpenSSL_ossl_typ;

{$MINENUMSIZE 4}

const
  (* There are the classes of BIOs *)
  BIO_TYPE_DESCRIPTOR = $0100;
  BIO_TYPE_FILTER = $0200;
  BIO_TYPE_SOURCE_SINK = $0400;

  (* These are the 'types' of BIOs *)
  BIO_TYPE_NONE = 0;
  BIO_TYPE_MEM =  1 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_FILE =  2 or BIO_TYPE_SOURCE_SINK;

  BIO_TYPE_FD          =  4 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_SOCKET      =  5 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_NULL        =  6 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_SSL         =  7 or BIO_TYPE_FILTER;
  BIO_TYPE_MD          =  8 or BIO_TYPE_FILTER;
  BIO_TYPE_BUFFER      =  9 or BIO_TYPE_FILTER;
  BIO_TYPE_CIPHER      = 10 or BIO_TYPE_FILTER;
  BIO_TYPE_BASE64      = 11 or BIO_TYPE_FILTER;
  BIO_TYPE_CONNECT     = 12 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_ACCEPT      = 13 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;

  BIO_TYPE_NBIO_TEST   = 16 or BIO_TYPE_FILTER;
  BIO_TYPE_NULL_FILTER = 17 or BIO_TYPE_FILTER;
  BIO_TYPE_BIO         = 19 or BIO_TYPE_SOURCE_SINK;
  BIO_TYPE_LINEBUFFER  = 20 or BIO_TYPE_FILTER;
  BIO_TYPE_DGRAM       = 21 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;
  BIO_TYPE_ASN1        = 22 or BIO_TYPE_FILTER;
  BIO_TYPE_COMP        = 23 or BIO_TYPE_FILTER;
  BIO_TYPE_DGRAM_SCTP  = 24 or BIO_TYPE_SOURCE_SINK or BIO_TYPE_DESCRIPTOR;

  BIO_TYPE_START = 128;

  (*
   * BIO_FILENAME_READ|BIO_CLOSE to open or close on free.
   * BIO_set_fp(in,stdin,BIO_NOCLOSE);
   *)
  BIO_NOCLOSE = $00;
  BIO_CLOSE   = $01;

  (*
   * These are used in the following macros and are passed to BIO_ctrl()
   *)
  BIO_CTRL_RESET        = 1;(* opt - rewind/zero etc *)
  BIO_CTRL_EOF          = 2;(* opt - are we at the eof *)
  BIO_CTRL_INFO         = 3;(* opt - extra tit-bits *)
  BIO_CTRL_SET          = 4;(* man - set the 'IO' type *)
  BIO_CTRL_GET          = 5;(* man - get the 'IO' type *)
  BIO_CTRL_PUSH         = 6;(* opt - internal, used to signify change *)
  BIO_CTRL_POP          = 7;(* opt - internal, used to signify change *)
  BIO_CTRL_GET_CLOSE    = 8;(* man - set the 'close' on free *)
  BIO_CTRL_SET_CLOSE    = 9;(* man - set the 'close' on free *)
  // Added "_const" to prevent naming clashes
  BIO_CTRL_PENDING_const      = 10;(* opt - is their more data buffered *)
  BIO_CTRL_FLUSH        = 11;(* opt - 'flush' buffered output *)
  BIO_CTRL_DUP          = 12;(* man - extra stuff for 'duped' BIO *)
  // Added "_const" to prevent naming clashes
  BIO_CTRL_WPENDING_const     = 13;(* opt - number of bytes still to write *)
  BIO_CTRL_SET_CALLBACK = 14;(* opt - set callback function *)
  BIO_CTRL_GET_CALLBACK = 15;(* opt - set callback function *)

  BIO_CTRL_PEEK         = 29;(* BIO_f_buffer special *)
  BIO_CTRL_SET_FILENAME = 30;(* BIO_s_file special *)

  (* dgram BIO stuff *)
  BIO_CTRL_DGRAM_CONNECT       = 31;(* BIO dgram special *)
  BIO_CTRL_DGRAM_SET_CONNECTED = 32;(* allow for an externally connected
                                           * socket to be passed in *)
  BIO_CTRL_DGRAM_SET_RECV_TIMEOUT = 33;(* setsockopt, essentially *)
  BIO_CTRL_DGRAM_GET_RECV_TIMEOUT = 34;(* getsockopt, essentially *)
  BIO_CTRL_DGRAM_SET_SEND_TIMEOUT = 35;(* setsockopt, essentially *)
  BIO_CTRL_DGRAM_GET_SEND_TIMEOUT = 36;(* getsockopt, essentially *)

  BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP = 37;(* flag whether the last *)
  BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP = 38;(* I/O operation tiemd out *)

  BIO_CTRL_DGRAM_MTU_DISCOVER     = 39;(* set DF bit on egress packets *)

  BIO_CTRL_DGRAM_QUERY_MTU        = 40;(* as kernel for current MTU *)
  BIO_CTRL_DGRAM_GET_FALLBACK_MTU = 47;
  BIO_CTRL_DGRAM_GET_MTU          = 41;(* get cached value for MTU *)
  BIO_CTRL_DGRAM_SET_MTU          = 42;(* set cached value for MTU.
                                                * want to use this if asking
                                                * the kernel fails *)

  BIO_CTRL_DGRAM_MTU_EXCEEDED     = 43;(* check whether the MTU was
                                                * exceed in the previous write
                                                * operation *)

  BIO_CTRL_DGRAM_GET_PEER         = 46;
  BIO_CTRL_DGRAM_SET_PEER         = 44;(* Destination for the data *)

  BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;(* Next DTLS handshake timeout
                                                * to adjust socket timeouts *)
  BIO_CTRL_DGRAM_SET_DONT_FRAG    = 48;

  BIO_CTRL_DGRAM_GET_MTU_OVERHEAD = 49;

  (* Deliberately outside of OPENSSL_NO_SCTP - used in bss_dgram.c *)
  BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE  = 50;
  (* SCTP stuff *)
  BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY      = 51;
  BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY     = 52;
  BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD     = 53;
  BIO_CTRL_DGRAM_SCTP_GET_SNDINFO       = 60;
  BIO_CTRL_DGRAM_SCTP_SET_SNDINFO       = 61;
  BIO_CTRL_DGRAM_SCTP_GET_RCVINFO       = 62;
  BIO_CTRL_DGRAM_SCTP_SET_RCVINFO       = 63;
  BIO_CTRL_DGRAM_SCTP_GET_PRINFO        = 64;
  BIO_CTRL_DGRAM_SCTP_SET_PRINFO        = 65;
  BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN     = 70;

  BIO_CTRL_DGRAM_SET_PEEK_MODE          = 71;

  (* modifiers *)
  BIO_FP_READ            = $02;
  BIO_FP_WRITE           = $04;
  BIO_FP_APPEND          = $08;
  BIO_FP_TEXT            = $10;

  BIO_FLAGS_READ         = $01;
  BIO_FLAGS_WRITE        = $02;
  BIO_FLAGS_IO_SPECIAL   = $04;
  BIO_FLAGS_RWS          = BIO_FLAGS_READ or BIO_FLAGS_WRITE or BIO_FLAGS_IO_SPECIAL;
  BIO_FLAGS_SHOULD_RETRY = $08;

  BIO_FLAGS_BASE64_NO_NL = $100;

  (*
   * This is used with memory BIOs:
   * BIO_FLAGS_MEM_RDONLY means we shouldn't free up or change the data in any way;
   * BIO_FLAGS_NONCLEAR_RST means we shouldn't clear data on reset.
   *)
  BIO_FLAGS_MEM_RDONLY   = $200;
  BIO_FLAGS_NONCLEAR_RST = $400;

  BIO_RR_SSL_X509_LOOKUP = $01;
  (* Returned from the connect BIO when a connect would have blocked *)
  BIO_RR_CONNECT         = $02;
  (* Returned from the accept BIO when an accept would have blocked *)
  BIO_RR_ACCEPT          = $03;

  (* These are passed by the BIO callback *)
  BIO_CB_FREE  = $01;
  BIO_CB_READ  = $02;
  BIO_CB_WRITE = $03;
  BIO_CB_PUTS  = $04;
  BIO_CB_GETS  = $05;
  BIO_CB_CTRL  = $06;
///*
// * The callback is called before and after the underling operation, The
// * BIO_CB_RETURN flag indicates if it is after the call
// */
//# define BIO_CB_RETURN   0x80
//# define BIO_CB_return(a) ((a)|BIO_CB_RETURN)
//# define BIO_cb_pre(a)   (!((a)&BIO_CB_RETURN))
//# define BIO_cb_post(a)  ((a)&BIO_CB_RETURN)

  BIO_C_SET_CONNECT                 = 100;
  BIO_C_DO_STATE_MACHINE            = 101;
  BIO_C_SET_NBIO                    = 102;
  (* BIO_C_SET_PROXY_PARAM            = 103 *)
  BIO_C_SET_FD                      = 104;
  BIO_C_GET_FD                      = 105;
  BIO_C_SET_FILE_PTR                = 106;
  BIO_C_GET_FILE_PTR                = 107;
  BIO_C_SET_FILENAME                = 108;
  BIO_C_SET_SSL                     = 109;
  BIO_C_GET_SSL                     = 110;
  BIO_C_SET_MD                      = 111;
  BIO_C_GET_MD                      = 112;
  BIO_C_GET_CIPHER_STATUS           = 113;
  BIO_C_SET_BUF_MEM                 = 114;
  BIO_C_GET_BUF_MEM_PTR             = 115;
  BIO_C_GET_BUFF_NUM_LINES          = 116;
  BIO_C_SET_BUFF_SIZE               = 117;
  BIO_C_SET_ACCEPT                  = 118;
  BIO_C_SSL_MODE                    = 119;
  BIO_C_GET_MD_CTX                  = 120;
  (* BIO_C_GET_PROXY_PARAM             = 121 *)
  BIO_C_SET_BUFF_READ_DATA          = 122;(* data to read first *)
  BIO_C_GET_CONNECT                 = 123;
  BIO_C_GET_ACCEPT                  = 124;
  BIO_C_SET_SSL_RENEGOTIATE_BYTES   = 125;
  BIO_C_GET_SSL_NUM_RENEGOTIATES    = 126;
  BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
  BIO_C_FILE_SEEK                   = 128;
  BIO_C_GET_CIPHER_CTX              = 129;
  BIO_C_SET_BUF_MEM_EOF_RETURN      = 130;(* return end of input
                                                       * value *)
  BIO_C_SET_BIND_MODE               = 131;
  BIO_C_GET_BIND_MODE               = 132;
  BIO_C_FILE_TELL                   = 133;
  BIO_C_GET_SOCKS                   = 134;
  BIO_C_SET_SOCKS                   = 135;

  BIO_C_SET_WRITE_BUF_SIZE          = 136;(* for BIO_s_bio *)
  BIO_C_GET_WRITE_BUF_SIZE          = 137;
  BIO_C_MAKE_BIO_PAIR               = 138;
  BIO_C_DESTROY_BIO_PAIR            = 139;
  BIO_C_GET_WRITE_GUARANTEE         = 140;
  BIO_C_GET_READ_REQUEST            = 141;
  BIO_C_SHUTDOWN_WR                 = 142;
  BIO_C_NREAD0                      = 143;
  BIO_C_NREAD                       = 144;
  BIO_C_NWRITE0                     = 145;
  BIO_C_NWRITE                      = 146;
  BIO_C_RESET_READ_REQUEST          = 147;
  BIO_C_SET_MD_CTX                  = 148;

  BIO_C_SET_PREFIX                  = 149;
  BIO_C_GET_PREFIX                  = 150;
  BIO_C_SET_SUFFIX                  = 151;
  BIO_C_GET_SUFFIX                  = 152;

  BIO_C_SET_EX_ARG                  = 153;
  BIO_C_GET_EX_ARG                  = 154;

  BIO_C_SET_CONNECT_MODE            = 155;

  BIO_SOCK_REUSEADDR = $01;
  BIO_SOCK_V6_ONLY   = $02;
  BIO_SOCK_KEEPALIVE = $04;
  BIO_SOCK_NONBLOCK  = $08;
  BIO_SOCK_NODELAY   = $10;

type
  BIO_ADDR = Pointer; // bio_addr_st
  PBIO_ADDR = ^BIO_ADDR;
  BIO_ADDRINFO = Pointer; // bio_addrinfo_st
  PBIO_ADDRINFO = ^BIO_ADDRINFO;
  PPBIO_ADDRINFO = ^PBIO_ADDRINFO;
  BIO_callback_fn = function(b: PBIO; oper: TOpenSSL_C_INT; const argp: PAnsiChar; 
    argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG;
  BIO_callback_fn_ex = function(b: PBIO; oper: TOpenSSL_C_INT; const argp: PAnsiChar; len: TOpenSSL_C_SIZET; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_INT; processed: POpenSSL_C_SIZET): TOpenSSL_C_LONG;
  BIO_METHOD = Pointer; // bio_method_st
  PBIO_METHOD = ^BIO_METHOD;
  BIO_info_cb = function(v1: PBIO; v2: TOpenSSL_C_INT; v3: TOpenSSL_C_INT): TOpenSSL_C_INT;
  PBIO_info_cb = ^BIO_info_cb;
  asn1_ps_func = function(b: PBIO; pbuf: PPAnsiChar; plen: POpenSSL_C_INT; parg: Pointer): TOpenSSL_C_INT;

  bio_dgram_sctp_sndinfo = record
    snd_sid: TOpenSSL_C_UINT16;
    snd_flags: TOpenSSL_C_UINT16;
    snd_ppid: TOpenSSL_C_UINT32;
    snd_context: TOpenSSL_C_UINT32;
  end;

  bio_dgram_sctp_rcvinfo = record
    rcv_sid: TOpenSSL_C_UINT16;
    rcv_ssn: TOpenSSL_C_UINT16;
    rcv_flags: TOpenSSL_C_UINT16;
    rcv_ppid: TOpenSSL_C_UINT32;
    rcv_tsn: TOpenSSL_C_UINT32;
    rcv_cumtsn: TOpenSSL_C_UINT32;
    rcv_context: TOpenSSL_C_UINT32;
  end;

  bio_dgram_sctp_prinfo = record
    pr_policy: TOpenSSL_C_UINT16;
    pr_value: TOpenSSL_C_UINT32;
  end;

  BIO_hostserv_priorities = (BIO_PARSE_PRIO_HOST, BIO_PARSE_PRIO_SERV);

  BIO_lookup_type = (BIO_LOOKUP_CLIENT, BIO_LOOKUP_SERVER);

  BIO_sock_info_u = record
    addr: PBIO_ADDR;
  end;
  PBIO_sock_info_u = ^BIO_sock_info_u;

  BIO_sock_info_type = (BIO_SOCK_INFO_ADDRESS);


{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM BIO_get_new_index}
{$EXTERNALSYM BIO_set_flags}
{$EXTERNALSYM BIO_test_flags}
{$EXTERNALSYM BIO_clear_flags}
{$EXTERNALSYM BIO_get_callback}
{$EXTERNALSYM BIO_set_callback}
{$EXTERNALSYM BIO_get_callback_ex}
{$EXTERNALSYM BIO_set_callback_ex}
{$EXTERNALSYM BIO_get_callback_arg}
{$EXTERNALSYM BIO_set_callback_arg}
{$EXTERNALSYM BIO_method_name}
{$EXTERNALSYM BIO_method_type}
{$EXTERNALSYM BIO_ctrl_pending}
{$EXTERNALSYM BIO_ctrl_wpending}
{$EXTERNALSYM BIO_ctrl_get_write_guarantee}
{$EXTERNALSYM BIO_ctrl_get_read_request}
{$EXTERNALSYM BIO_ctrl_reset_read_request}
{$EXTERNALSYM BIO_set_ex_data}
{$EXTERNALSYM BIO_get_ex_data}
{$EXTERNALSYM BIO_number_read}
{$EXTERNALSYM BIO_number_written}
{$EXTERNALSYM BIO_s_file}
{$EXTERNALSYM BIO_new_file}
{$EXTERNALSYM BIO_new}
{$EXTERNALSYM BIO_free}
{$EXTERNALSYM BIO_set_data}
{$EXTERNALSYM BIO_get_data}
{$EXTERNALSYM BIO_set_init}
{$EXTERNALSYM BIO_get_init}
{$EXTERNALSYM BIO_set_shutdown}
{$EXTERNALSYM BIO_get_shutdown}
{$EXTERNALSYM BIO_vfree}
{$EXTERNALSYM BIO_up_ref}
{$EXTERNALSYM BIO_read}
{$EXTERNALSYM BIO_read_ex}
{$EXTERNALSYM BIO_gets}
{$EXTERNALSYM BIO_write}
{$EXTERNALSYM BIO_write_ex}
{$EXTERNALSYM BIO_puts}
{$EXTERNALSYM BIO_indent}
{$EXTERNALSYM BIO_ctrl}
{$EXTERNALSYM BIO_callback_ctrl}
{$EXTERNALSYM BIO_ptr_ctrl}
{$EXTERNALSYM BIO_int_ctrl}
{$EXTERNALSYM BIO_push}
{$EXTERNALSYM BIO_pop}
{$EXTERNALSYM BIO_free_all}
{$EXTERNALSYM BIO_find_type}
{$EXTERNALSYM BIO_next}
{$EXTERNALSYM BIO_set_next}
{$EXTERNALSYM BIO_get_retry_BIO}
{$EXTERNALSYM BIO_get_retry_reason}
{$EXTERNALSYM BIO_set_retry_reason}
{$EXTERNALSYM BIO_dup_chain}
{$EXTERNALSYM BIO_nread0}
{$EXTERNALSYM BIO_nread}
{$EXTERNALSYM BIO_nwrite0}
{$EXTERNALSYM BIO_nwrite}
{$EXTERNALSYM BIO_debug_callback}
{$EXTERNALSYM BIO_s_mem}
{$EXTERNALSYM BIO_s_secmem}
{$EXTERNALSYM BIO_new_mem_buf}
{$EXTERNALSYM BIO_s_socket}
{$EXTERNALSYM BIO_s_connect}
{$EXTERNALSYM BIO_s_accept}
{$EXTERNALSYM BIO_s_fd}
{$EXTERNALSYM BIO_s_log}
{$EXTERNALSYM BIO_s_bio}
{$EXTERNALSYM BIO_s_null}
{$EXTERNALSYM BIO_f_null}
{$EXTERNALSYM BIO_f_buffer}
{$EXTERNALSYM BIO_f_linebuffer}
{$EXTERNALSYM BIO_f_nbio_test}
{$EXTERNALSYM BIO_s_datagram}
{$EXTERNALSYM BIO_dgram_non_fatal_error}
{$EXTERNALSYM BIO_new_dgram}
{$EXTERNALSYM BIO_sock_should_retry}
{$EXTERNALSYM BIO_sock_non_fatal_error}
{$EXTERNALSYM BIO_fd_should_retry}
{$EXTERNALSYM BIO_fd_non_fatal_error}
{$EXTERNALSYM BIO_dump}
{$EXTERNALSYM BIO_dump_indent}
{$EXTERNALSYM BIO_hex_string}
{$EXTERNALSYM BIO_ADDR_new}
{$EXTERNALSYM BIO_ADDR_rawmake}
{$EXTERNALSYM BIO_ADDR_free}
{$EXTERNALSYM BIO_ADDR_clear}
{$EXTERNALSYM BIO_ADDR_family}
{$EXTERNALSYM BIO_ADDR_rawaddress}
{$EXTERNALSYM BIO_ADDR_rawport}
{$EXTERNALSYM BIO_ADDR_hostname_string}
{$EXTERNALSYM BIO_ADDR_service_string}
{$EXTERNALSYM BIO_ADDR_path_string}
{$EXTERNALSYM BIO_ADDRINFO_next}
{$EXTERNALSYM BIO_ADDRINFO_family}
{$EXTERNALSYM BIO_ADDRINFO_socktype}
{$EXTERNALSYM BIO_ADDRINFO_protocol}
{$EXTERNALSYM BIO_ADDRINFO_address}
{$EXTERNALSYM BIO_ADDRINFO_free}
{$EXTERNALSYM BIO_parse_hostserv}
{$EXTERNALSYM BIO_lookup}
{$EXTERNALSYM BIO_lookup_ex}
{$EXTERNALSYM BIO_sock_error}
{$EXTERNALSYM BIO_socket_ioctl}
{$EXTERNALSYM BIO_socket_nbio}
{$EXTERNALSYM BIO_sock_init}
{$EXTERNALSYM BIO_set_tcp_ndelay}
{$EXTERNALSYM BIO_sock_info}
{$EXTERNALSYM BIO_socket}
{$EXTERNALSYM BIO_connect}
{$EXTERNALSYM BIO_bind}
{$EXTERNALSYM BIO_listen}
{$EXTERNALSYM BIO_accept_ex}
{$EXTERNALSYM BIO_closesocket}
{$EXTERNALSYM BIO_new_socket}
{$EXTERNALSYM BIO_new_connect}
{$EXTERNALSYM BIO_new_accept}
{$EXTERNALSYM BIO_new_fd}
{$EXTERNALSYM BIO_new_bio_pair}
{$EXTERNALSYM BIO_copy_next_retry}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function BIO_get_new_index: TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_test_flags(const b: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_clear_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_get_callback(b: PBIO): BIO_callback_fn; cdecl; external CLibCrypto;
procedure BIO_set_callback(b: PBIO; callback: BIO_callback_fn); cdecl; external CLibCrypto;
function BIO_get_callback_ex(b: PBIO): BIO_callback_fn_ex; cdecl; external CLibCrypto;
procedure BIO_set_callback_ex(b: PBIO; callback: BIO_callback_fn_ex); cdecl; external CLibCrypto;
function BIO_get_callback_arg(const b: PBIO): PAnsiChar; cdecl; external CLibCrypto;
procedure BIO_set_callback_arg(var b: PBIO; arg: PAnsiChar); cdecl; external CLibCrypto;
function BIO_method_name(const b: PBIO): PAnsiChar; cdecl; external CLibCrypto;
function BIO_method_type(const b: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ctrl_pending(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_wpending(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_get_write_guarantee(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_get_read_request(b: PBIO): TOpenSSL_C_SIZET; cdecl; external CLibCrypto;
function BIO_ctrl_reset_read_request(b: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_set_ex_data(bio: PBIO; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_get_ex_data(bio: PBIO; idx: TOpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function BIO_number_read(bio: PBIO): TOpenSSL_C_UINT64; cdecl; external CLibCrypto;
function BIO_number_written(bio: PBIO): TOpenSSL_C_UINT64; cdecl; external CLibCrypto;
function BIO_s_file: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_new_file(const filename: PAnsiChar; const mode: PAnsiChar): PBIO; cdecl; external CLibCrypto;
function BIO_new(const cType: PBIO_METHOD): PBIO; cdecl; external CLibCrypto;
function BIO_free(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_data(a: PBIO; ptr: Pointer); cdecl; external CLibCrypto;
function BIO_get_data(a: PBIO): Pointer; cdecl; external CLibCrypto;
procedure BIO_set_init(a: PBIO; init: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_get_init(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_shutdown(a: PBIO; shut: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_get_shutdown(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_vfree(a: PBIO); cdecl; external CLibCrypto;
function BIO_up_ref(a: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_read(b: PBIO; data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_read_ex(b: PBIO; data: Pointer; dlen: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_gets( bp: PBIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_write(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_write_ex(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_puts(bp: PBIO; const buf: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_indent(b: PBIO; indent: TOpenSSL_C_INT; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_callback_ctrl(b: PBIO; cmd: TOpenSSL_C_INT; fp: PBIO_info_cb): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_ptr_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG): Pointer; cdecl; external CLibCrypto;
function BIO_int_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; iarg: TOpenSSL_C_INT): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_push(b: PBIO; append: PBIO): PBIO; cdecl; external CLibCrypto;
function BIO_pop(b: PBIO): PBIO; cdecl; external CLibCrypto;
procedure BIO_free_all(a: PBIO); cdecl; external CLibCrypto;
function BIO_find_type(b: PBIO; bio_type: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_next(b: PBIO): PBIO; cdecl; external CLibCrypto;
procedure BIO_set_next(b: PBIO; next: PBIO); cdecl; external CLibCrypto;
function BIO_get_retry_BIO(bio: PBIO; reason: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_get_retry_reason(bio: PBIO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_set_retry_reason(bio: PBIO; reason: TOpenSSL_C_INT); cdecl; external CLibCrypto;
function BIO_dup_chain(in_: PBIO): PBIO; cdecl; external CLibCrypto;
function BIO_nread0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_nread(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_nwrite0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_nwrite(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_debug_callback(bio: PBIO; cmd: TOpenSSL_C_INT; const argp: PAnsiChar; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function BIO_s_mem: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_secmem: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_new_mem_buf(const buf: Pointer; len: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_s_socket: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_connect: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_accept: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_fd: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_log: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_bio: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_null: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_null: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_buffer: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_linebuffer: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_f_nbio_test: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_s_datagram: PBIO_METHOD; cdecl; external CLibCrypto;
function BIO_dgram_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_new_dgram(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_sock_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_fd_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_fd_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_dump(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_dump_indent(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_hex_string(out_: PBIO; indent: TOpenSSL_C_INT; width: TOpenSSL_C_INT; data: PByte; datalen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDR_new: PBIO_ADDR; cdecl; external CLibCrypto;
function BIO_ADDR_rawmake(ap: PBIO_ADDR; familiy: TOpenSSL_C_INT; const where: Pointer; wherelen: TOpenSSL_C_SIZET; port: TOpenSSL_C_SHORT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_ADDR_free(a: PBIO_ADDR); cdecl; external CLibCrypto;
procedure BIO_ADDR_clear(ap: PBIO_ADDR); cdecl; external CLibCrypto;
function BIO_ADDR_family(const ap: PBIO_ADDR): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDR_rawaddress(const ap: PBIO_ADDR; p: Pointer; l: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDR_rawport(const ap: PBIO_ADDR): TOpenSSL_C_SHORT; cdecl; external CLibCrypto;
function BIO_ADDR_hostname_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function BIO_ADDR_service_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl; external CLibCrypto;
function BIO_ADDR_path_string(const ap: PBIO_ADDR): PAnsiChar; cdecl; external CLibCrypto;
function BIO_ADDRINFO_next(const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl; external CLibCrypto;
function BIO_ADDRINFO_family(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDRINFO_socktype(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDRINFO_protocol(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_ADDRINFO_address(const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl; external CLibCrypto;
procedure BIO_ADDRINFO_free(bai: PBIO_ADDRINFO); cdecl; external CLibCrypto;
function BIO_parse_hostserv(const hostserv: PAnsiChar; host: PPAnsiChar; service: PPAnsiChar; hostserv_prio: BIO_hostserv_priorities): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_lookup(const host: PAnsiChar; const service: PAnsiChar; lookup_type: BIO_lookup_type; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_lookup_ex(const host: PAnsiChar; const service: PAnsiChar; lookup_type: TOpenSSL_C_INT; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_error(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_socket_ioctl(fd: TOpenSSL_C_INT; cType: TOpenSSL_C_LONG; arg: Pointer): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_socket_nbio(fd: TOpenSSL_C_INT; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_init: TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_set_tcp_ndelay(sock: TOpenSSL_C_INT; turn_on: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_sock_info(sock: TOpenSSL_C_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_socket(domain: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_connect(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_bind(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_listen(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_accept_ex(accept_sock: TOpenSSL_C_INT; addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_closesocket(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function BIO_new_socket(sock: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_new_connect(const host_port: PAnsiChar): PBIO; cdecl; external CLibCrypto;
function BIO_new_accept(const host_port: PAnsiChar): PBIO; cdecl; external CLibCrypto;
function BIO_new_fd(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl; external CLibCrypto;
function BIO_new_bio_pair(bio1: PPBIO; writebuf1: TOpenSSL_C_SIZET; bio2: PPBIO; writebuf2: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure BIO_copy_next_retry(b: PBIO); cdecl; external CLibCrypto;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function BIO_get_flags(const b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
procedure BIO_set_retry_special(b: PBIO); {removed 1.0.0}
procedure BIO_set_retry_read(b: PBIO); {removed 1.0.0}
procedure BIO_set_retry_write(b: PBIO); {removed 1.0.0}
procedure BIO_clear_retry_flags(b: PBIO); {removed 1.0.0}
function BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_read(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_write(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_io_special(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_retry_type(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_should_retry(b: PBIO): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_do_connect(b: PBIO): TOpenSSL_C_LONG; {removed 1.0.0}
function BIO_do_accept(b: PBIO): TOpenSSL_C_LONG; {removed 1.0.0}
function BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG; {removed 1.0.0}
function BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; {removed 1.0.0}
function BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
var
  BIO_get_new_index: function : TOpenSSL_C_INT; cdecl = nil;
  BIO_set_flags: procedure (b: PBIO; flags: TOpenSSL_C_INT); cdecl = nil;
  BIO_test_flags: function (const b: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_clear_flags: procedure (b: PBIO; flags: TOpenSSL_C_INT); cdecl = nil;
  BIO_get_callback: function (b: PBIO): BIO_callback_fn; cdecl = nil;
  BIO_set_callback: procedure (b: PBIO; callback: BIO_callback_fn); cdecl = nil;
  BIO_get_callback_ex: function (b: PBIO): BIO_callback_fn_ex; cdecl = nil;
  BIO_set_callback_ex: procedure (b: PBIO; callback: BIO_callback_fn_ex); cdecl = nil;
  BIO_get_callback_arg: function (const b: PBIO): PAnsiChar; cdecl = nil;
  BIO_set_callback_arg: procedure (var b: PBIO; arg: PAnsiChar); cdecl = nil;
  BIO_method_name: function (const b: PBIO): PAnsiChar; cdecl = nil;
  BIO_method_type: function (const b: PBIO): TOpenSSL_C_INT; cdecl = nil;
  BIO_ctrl_pending: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = nil;
  BIO_ctrl_wpending: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = nil;
  BIO_ctrl_get_write_guarantee: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = nil;
  BIO_ctrl_get_read_request: function (b: PBIO): TOpenSSL_C_SIZET; cdecl = nil;
  BIO_ctrl_reset_read_request: function (b: PBIO): TOpenSSL_C_INT; cdecl = nil;
  BIO_set_ex_data: function (bio: PBIO; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl = nil;
  BIO_get_ex_data: function (bio: PBIO; idx: TOpenSSL_C_INT): Pointer; cdecl = nil;
  BIO_number_read: function (bio: PBIO): TOpenSSL_C_UINT64; cdecl = nil;
  BIO_number_written: function (bio: PBIO): TOpenSSL_C_UINT64; cdecl = nil;
  BIO_s_file: function : PBIO_METHOD; cdecl = nil;
  BIO_new_file: function (const filename: PAnsiChar; const mode: PAnsiChar): PBIO; cdecl = nil;
  BIO_new: function (const cType: PBIO_METHOD): PBIO; cdecl = nil;
  BIO_free: function (a: PBIO): TOpenSSL_C_INT; cdecl = nil;
  BIO_set_data: procedure (a: PBIO; ptr: Pointer); cdecl = nil;
  BIO_get_data: function (a: PBIO): Pointer; cdecl = nil;
  BIO_set_init: procedure (a: PBIO; init: TOpenSSL_C_INT); cdecl = nil;
  BIO_get_init: function (a: PBIO): TOpenSSL_C_INT; cdecl = nil;
  BIO_set_shutdown: procedure (a: PBIO; shut: TOpenSSL_C_INT); cdecl = nil;
  BIO_get_shutdown: function (a: PBIO): TOpenSSL_C_INT; cdecl = nil;
  BIO_vfree: procedure (a: PBIO); cdecl = nil;
  BIO_up_ref: function (a: PBIO): TOpenSSL_C_INT; cdecl = nil;
  BIO_read: function (b: PBIO; data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_read_ex: function (b: PBIO; data: Pointer; dlen: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  BIO_gets: function ( bp: PBIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_write: function (b: PBIO; const data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_write_ex: function (b: PBIO; const data: Pointer; dlen: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  BIO_puts: function (bp: PBIO; const buf: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  BIO_indent: function (b: PBIO; indent: TOpenSSL_C_INT; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_ctrl: function (bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl = nil;
  BIO_callback_ctrl: function (b: PBIO; cmd: TOpenSSL_C_INT; fp: PBIO_info_cb): TOpenSSL_C_LONG; cdecl = nil;
  BIO_ptr_ctrl: function (bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG): Pointer; cdecl = nil;
  BIO_int_ctrl: function (bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; iarg: TOpenSSL_C_INT): TOpenSSL_C_LONG; cdecl = nil;
  BIO_push: function (b: PBIO; append: PBIO): PBIO; cdecl = nil;
  BIO_pop: function (b: PBIO): PBIO; cdecl = nil;
  BIO_free_all: procedure (a: PBIO); cdecl = nil;
  BIO_find_type: function (b: PBIO; bio_type: TOpenSSL_C_INT): PBIO; cdecl = nil;
  BIO_next: function (b: PBIO): PBIO; cdecl = nil;
  BIO_set_next: procedure (b: PBIO; next: PBIO); cdecl = nil;
  BIO_get_retry_BIO: function (bio: PBIO; reason: TOpenSSL_C_INT): PBIO; cdecl = nil;
  BIO_get_retry_reason: function (bio: PBIO): TOpenSSL_C_INT; cdecl = nil;
  BIO_set_retry_reason: procedure (bio: PBIO; reason: TOpenSSL_C_INT); cdecl = nil;
  BIO_dup_chain: function (in_: PBIO): PBIO; cdecl = nil;
  BIO_nread0: function (bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  BIO_nread: function (bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_nwrite0: function (bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  BIO_nwrite: function (bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_debug_callback: function (bio: PBIO; cmd: TOpenSSL_C_INT; const argp: PAnsiChar; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl = nil;
  BIO_s_mem: function : PBIO_METHOD; cdecl = nil;
  BIO_s_secmem: function : PBIO_METHOD; cdecl = nil;
  BIO_new_mem_buf: function (const buf: Pointer; len: TOpenSSL_C_INT): PBIO; cdecl = nil;
  BIO_s_socket: function : PBIO_METHOD; cdecl = nil;
  BIO_s_connect: function : PBIO_METHOD; cdecl = nil;
  BIO_s_accept: function : PBIO_METHOD; cdecl = nil;
  BIO_s_fd: function : PBIO_METHOD; cdecl = nil;
  BIO_s_log: function : PBIO_METHOD; cdecl = nil;
  BIO_s_bio: function : PBIO_METHOD; cdecl = nil;
  BIO_s_null: function : PBIO_METHOD; cdecl = nil;
  BIO_f_null: function : PBIO_METHOD; cdecl = nil;
  BIO_f_buffer: function : PBIO_METHOD; cdecl = nil;
  BIO_f_linebuffer: function : PBIO_METHOD; cdecl = nil;
  BIO_f_nbio_test: function : PBIO_METHOD; cdecl = nil;
  BIO_s_datagram: function : PBIO_METHOD; cdecl = nil;
  BIO_dgram_non_fatal_error: function (error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_new_dgram: function (fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl = nil;
  BIO_sock_should_retry: function (i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_sock_non_fatal_error: function (error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_fd_should_retry: function (i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_fd_non_fatal_error: function (error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_dump: function (b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_dump_indent: function (b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_hex_string: function (out_: PBIO; indent: TOpenSSL_C_INT; width: TOpenSSL_C_INT; data: PByte; datalen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_ADDR_new: function : PBIO_ADDR; cdecl = nil;
  BIO_ADDR_rawmake: function (ap: PBIO_ADDR; familiy: TOpenSSL_C_INT; const where: Pointer; wherelen: TOpenSSL_C_SIZET; port: TOpenSSL_C_SHORT): TOpenSSL_C_INT; cdecl = nil;
  BIO_ADDR_free: procedure (a: PBIO_ADDR); cdecl = nil;
  BIO_ADDR_clear: procedure (ap: PBIO_ADDR); cdecl = nil;
  BIO_ADDR_family: function (const ap: PBIO_ADDR): TOpenSSL_C_INT; cdecl = nil;
  BIO_ADDR_rawaddress: function (const ap: PBIO_ADDR; p: Pointer; l: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  BIO_ADDR_rawport: function (const ap: PBIO_ADDR): TOpenSSL_C_SHORT; cdecl = nil;
  BIO_ADDR_hostname_string: function (const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  BIO_ADDR_service_string: function (const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl = nil;
  BIO_ADDR_path_string: function (const ap: PBIO_ADDR): PAnsiChar; cdecl = nil;
  BIO_ADDRINFO_next: function (const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl = nil;
  BIO_ADDRINFO_family: function (const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = nil;
  BIO_ADDRINFO_socktype: function (const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = nil;
  BIO_ADDRINFO_protocol: function (const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = nil;
  BIO_ADDRINFO_address: function (const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl = nil;
  BIO_ADDRINFO_free: procedure (bai: PBIO_ADDRINFO); cdecl = nil;
  BIO_parse_hostserv: function (const hostserv: PAnsiChar; host: PPAnsiChar; service: PPAnsiChar; hostserv_prio: BIO_hostserv_priorities): TOpenSSL_C_INT; cdecl = nil;
  BIO_lookup: function (const host: PAnsiChar; const service: PAnsiChar; lookup_type: BIO_lookup_type; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = nil;
  BIO_lookup_ex: function (const host: PAnsiChar; const service: PAnsiChar; lookup_type: TOpenSSL_C_INT; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl = nil;
  BIO_sock_error: function (sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_socket_ioctl: function (fd: TOpenSSL_C_INT; cType: TOpenSSL_C_LONG; arg: Pointer): TOpenSSL_C_INT; cdecl = nil;
  BIO_socket_nbio: function (fd: TOpenSSL_C_INT; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_sock_init: function : TOpenSSL_C_INT; cdecl = nil;
  BIO_set_tcp_ndelay: function (sock: TOpenSSL_C_INT; turn_on: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_sock_info: function (sock: TOpenSSL_C_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TOpenSSL_C_INT; cdecl = nil;
  BIO_socket: function (domain: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_connect: function (sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_bind: function (sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_listen: function (sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_accept_ex: function (accept_sock: TOpenSSL_C_INT; addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_closesocket: function (sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  BIO_new_socket: function (sock: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl = nil;
  BIO_new_connect: function (const host_port: PAnsiChar): PBIO; cdecl = nil;
  BIO_new_accept: function (const host_port: PAnsiChar): PBIO; cdecl = nil;
  BIO_new_fd: function (fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl = nil;
  BIO_new_bio_pair: function (bio1: PPBIO; writebuf1: TOpenSSL_C_SIZET; bio2: PPBIO; writebuf2: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl = nil;
  BIO_copy_next_retry: procedure (b: PBIO); cdecl = nil;

{Removed functions for which legacy support available - use is deprecated}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
var
  BIO_get_flags: function (const b: PBIO): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_set_retry_special: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}
  BIO_set_retry_read: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}
  BIO_set_retry_write: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}
  BIO_clear_retry_flags: procedure (b: PBIO); cdecl = nil; {removed 1.0.0}
  BIO_get_retry_flags: function (b: PBIO): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_should_read: function (b: PBIO): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_should_write: function (b: PBIO): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_should_io_special: function (b: PBIO): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_retry_type: function (b: PBIO): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_should_retry: function (b: PBIO): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_do_connect: function (b: PBIO): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  BIO_do_accept: function (b: PBIO): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  BIO_do_handshake: function (b: PBIO): TOpenSSL_C_LONG; cdecl = nil; {removed 1.0.0}
  BIO_get_mem_data: function (b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_set_mem_buf: function (b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_get_mem_ptr: function (b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
  BIO_set_mem_eof_return: function (b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil; {removed 1.0.0}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
const
  BIO_get_flags_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_retry_special_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_retry_read_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_retry_write_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_clear_retry_flags_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_retry_flags_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_read_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_write_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_io_special_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_retry_type_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_should_retry_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_do_connect_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_do_accept_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_do_handshake_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_mem_data_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_mem_buf_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_mem_ptr_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_set_mem_eof_return_removed = ((((((byte(1) shl 8) or byte(0)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {removed 1.0.0}
  BIO_get_new_index_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_callback_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_callback_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_data_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_init_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_shutdown_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_get_shutdown_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_up_ref_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_read_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_write_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_next_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_set_retry_reason_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_s_secmem_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_f_linebuffer_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_new_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_rawmake_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_clear_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_family_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_rawaddress_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_rawport_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_hostname_string_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_service_string_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDR_path_string_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_next_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_family_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_socktype_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_protocol_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_address_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_ADDRINFO_free_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_parse_hostserv_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_lookup_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_lookup_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_sock_info_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_socket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_connect_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_bind_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_listen_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_accept_ex_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}
  BIO_closesocket_introduced = ((((((byte(1) shl 8) or byte(1)) shl 8) or byte(0)) shl 8) or byte(0)) shl 4; {introduced 1.1.0}


implementation

// # define BIO_get_flags(b) BIO_test_flags(b, ~(0x0))

uses Classes,
     OpenSSLExceptionHandlers,
     OpenSSLResourceStrings;

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ENDIF}
{$IFDEF OPENSSL_STATIC_LINK_MODEL}

{Legacy Support Functions}

{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function BIO_get_flags(const b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, not $0);
end;

//# define BIO_set_retry_special(b) \
//                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_set_retry_special(b: PBIO);

begin
  BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_read(b) \
//                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_set_retry_read(b: PBIO);

begin
  BIO_set_flags(b, BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_write(b) \
//                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_set_retry_write(b: PBIO);

begin
  BIO_set_flags(b, BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_clear_retry_flags(b) \
//                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


procedure BIO_clear_retry_flags(b: PBIO);

begin
  BIO_clear_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_get_retry_flags(b) \
//                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


function BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)


function BIO_should_read(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_READ);
end;

//# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)


function BIO_should_write(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_WRITE);
end;

//# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)


function BIO_should_io_special(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_IO_SPECIAL);
end;

//# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)


function BIO_retry_type(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS);
end;

//# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)


function BIO_should_retry(b: PBIO): TOpenSSL_C_INT;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY);
end;

//#  define BIO_do_connect(b)       BIO_do_handshake(b)


function BIO_do_connect(b: PBIO): TOpenSSL_C_LONG;

begin
  Result := BIO_do_handshake(b);
end;

//#  define BIO_do_accept(b)        BIO_do_handshake(b)


function BIO_do_accept(b: PBIO): TOpenSSL_C_LONG;

begin
  Result := BIO_do_handshake(b);
end;

//# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)


function BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG;

begin
  Result := BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, nil);
end;

//# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char (pp))


function BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, pp);
end;

//# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char (bm))


function BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM, c, bm);
end;

//# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char (pp))


function BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, pp);
end;

//# define BIO_set_mem_eof_return(b,v) BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,0)


function BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, nil);
end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}
{$ELSE}
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
function COMPAT_BIO_get_flags(const b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, not $0);
end;

//# define BIO_set_retry_special(b) \
//                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_set_retry_special(b: PBIO); cdecl;

begin
  BIO_set_flags(b, BIO_FLAGS_IO_SPECIAL or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_read(b) \
//                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_set_retry_read(b: PBIO); cdecl;

begin
  BIO_set_flags(b, BIO_FLAGS_READ or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_set_retry_write(b) \
//                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_set_retry_write(b: PBIO); cdecl;

begin
  BIO_set_flags(b, BIO_FLAGS_WRITE or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_clear_retry_flags(b) \
//                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


procedure COMPAT_BIO_clear_retry_flags(b: PBIO); cdecl;

begin
  BIO_clear_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_get_retry_flags(b) \
//                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))


function COMPAT_BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS or BIO_FLAGS_SHOULD_RETRY);
end;

//# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)


function COMPAT_BIO_should_read(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_READ);
end;

//# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)


function COMPAT_BIO_should_write(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_WRITE);
end;

//# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)


function COMPAT_BIO_should_io_special(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_IO_SPECIAL);
end;

//# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)


function COMPAT_BIO_retry_type(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_RWS);
end;

//# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)


function COMPAT_BIO_should_retry(b: PBIO): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_test_flags(b, BIO_FLAGS_SHOULD_RETRY);
end;

//#  define BIO_do_connect(b)       BIO_do_handshake(b)


function COMPAT_BIO_do_connect(b: PBIO): TOpenSSL_C_LONG; cdecl;

begin
  Result := BIO_do_handshake(b);
end;

//#  define BIO_do_accept(b)        BIO_do_handshake(b)


function COMPAT_BIO_do_accept(b: PBIO): TOpenSSL_C_LONG; cdecl;

begin
  Result := BIO_do_handshake(b);
end;

//# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)


function COMPAT_BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_DO_STATE_MACHINE, 0, nil);
end;

//# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char (pp))


function COMPAT_BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_CTRL_INFO, 0, pp);
end;

//# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char (bm))


function COMPAT_BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM, c, bm);
end;

//# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char (pp))


function COMPAT_BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_GET_BUF_MEM_PTR, 0, pp);
end;

//# define BIO_set_mem_eof_return(b,v) BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,0)


function COMPAT_BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;

begin
  Result := BIO_ctrl(b, BIO_C_SET_BUF_MEM_EOF_RETURN, v, nil);
end;





{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$WARN  NO_RETVAL OFF}
{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_get_flags(const b: PBIO): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_flags');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_BIO_set_retry_special(b: PBIO); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_retry_special');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_BIO_set_retry_read(b: PBIO); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_retry_read');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_BIO_set_retry_write(b: PBIO); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_retry_write');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
procedure ERROR_BIO_clear_retry_flags(b: PBIO); cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_clear_retry_flags');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_get_retry_flags(b: PBIO): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_retry_flags');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_should_read(b: PBIO): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_should_read');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_should_write(b: PBIO): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_should_write');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_should_io_special(b: PBIO): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_should_io_special');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_retry_type(b: PBIO): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_retry_type');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_should_retry(b: PBIO): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_should_retry');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_do_connect(b: PBIO): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_do_connect');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_do_accept(b: PBIO): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_do_accept');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_do_handshake(b: PBIO): TOpenSSL_C_LONG; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_do_handshake');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_get_mem_data(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_mem_data');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_set_mem_buf(b: PBIO; bm: PAnsiChar; c: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_mem_buf');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_get_mem_ptr(b: PBIO; pp: PAnsiChar): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_mem_ptr');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

{$IFDEF OPENSSL_NO_LEGACY_SUPPORT}
function ERROR_BIO_set_mem_eof_return(b: PBIO; v: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; {removed 1.0.0}
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_mem_eof_return');
end;
{$ENDIF} { End of OPENSSL_NO_LEGACY_SUPPORT}

function ERROR_BIO_get_new_index: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_new_index');
end;

procedure ERROR_BIO_set_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_flags');
end;

function ERROR_BIO_test_flags(const b: PBIO; flags: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_test_flags');
end;

procedure ERROR_BIO_clear_flags(b: PBIO; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_clear_flags');
end;

function ERROR_BIO_get_callback(b: PBIO): BIO_callback_fn; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_callback');
end;

procedure ERROR_BIO_set_callback(b: PBIO; callback: BIO_callback_fn); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_callback');
end;

function ERROR_BIO_get_callback_ex(b: PBIO): BIO_callback_fn_ex; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_callback_ex');
end;

procedure ERROR_BIO_set_callback_ex(b: PBIO; callback: BIO_callback_fn_ex); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_callback_ex');
end;

function ERROR_BIO_get_callback_arg(const b: PBIO): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_callback_arg');
end;

procedure ERROR_BIO_set_callback_arg(var b: PBIO; arg: PAnsiChar); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_callback_arg');
end;

function ERROR_BIO_method_name(const b: PBIO): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_method_name');
end;

function ERROR_BIO_method_type(const b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_method_type');
end;

function ERROR_BIO_ctrl_pending(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_pending');
end;

function ERROR_BIO_ctrl_wpending(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_wpending');
end;

function ERROR_BIO_ctrl_get_write_guarantee(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_get_write_guarantee');
end;

function ERROR_BIO_ctrl_get_read_request(b: PBIO): TOpenSSL_C_SIZET; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_get_read_request');
end;

function ERROR_BIO_ctrl_reset_read_request(b: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl_reset_read_request');
end;

function ERROR_BIO_set_ex_data(bio: PBIO; idx: TOpenSSL_C_INT; data: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_ex_data');
end;

function ERROR_BIO_get_ex_data(bio: PBIO; idx: TOpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_ex_data');
end;

function ERROR_BIO_number_read(bio: PBIO): TOpenSSL_C_UINT64; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_number_read');
end;

function ERROR_BIO_number_written(bio: PBIO): TOpenSSL_C_UINT64; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_number_written');
end;

function ERROR_BIO_s_file: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_file');
end;

function ERROR_BIO_new_file(const filename: PAnsiChar; const mode: PAnsiChar): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_file');
end;

function ERROR_BIO_new(const cType: PBIO_METHOD): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new');
end;

function ERROR_BIO_free(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_free');
end;

procedure ERROR_BIO_set_data(a: PBIO; ptr: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_data');
end;

function ERROR_BIO_get_data(a: PBIO): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_data');
end;

procedure ERROR_BIO_set_init(a: PBIO; init: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_init');
end;

function ERROR_BIO_get_init(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_init');
end;

procedure ERROR_BIO_set_shutdown(a: PBIO; shut: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_shutdown');
end;

function ERROR_BIO_get_shutdown(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_shutdown');
end;

procedure ERROR_BIO_vfree(a: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_vfree');
end;

function ERROR_BIO_up_ref(a: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_up_ref');
end;

function ERROR_BIO_read(b: PBIO; data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_read');
end;

function ERROR_BIO_read_ex(b: PBIO; data: Pointer; dlen: TOpenSSL_C_SIZET; readbytes: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_read_ex');
end;

function ERROR_BIO_gets( bp: PBIO; buf: PAnsiChar; size: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_gets');
end;

function ERROR_BIO_write(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_write');
end;

function ERROR_BIO_write_ex(b: PBIO; const data: Pointer; dlen: TOpenSSL_C_SIZET; written: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_write_ex');
end;

function ERROR_BIO_puts(bp: PBIO; const buf: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_puts');
end;

function ERROR_BIO_indent(b: PBIO; indent: TOpenSSL_C_INT; max: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_indent');
end;

function ERROR_BIO_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; parg: Pointer): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ctrl');
end;

function ERROR_BIO_callback_ctrl(b: PBIO; cmd: TOpenSSL_C_INT; fp: PBIO_info_cb): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_callback_ctrl');
end;

function ERROR_BIO_ptr_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ptr_ctrl');
end;

function ERROR_BIO_int_ctrl(bp: PBIO; cmd: TOpenSSL_C_INT; larg: TOpenSSL_C_LONG; iarg: TOpenSSL_C_INT): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_int_ctrl');
end;

function ERROR_BIO_push(b: PBIO; append: PBIO): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_push');
end;

function ERROR_BIO_pop(b: PBIO): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_pop');
end;

procedure ERROR_BIO_free_all(a: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_free_all');
end;

function ERROR_BIO_find_type(b: PBIO; bio_type: TOpenSSL_C_INT): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_find_type');
end;

function ERROR_BIO_next(b: PBIO): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_next');
end;

procedure ERROR_BIO_set_next(b: PBIO; next: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_next');
end;

function ERROR_BIO_get_retry_BIO(bio: PBIO; reason: TOpenSSL_C_INT): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_retry_BIO');
end;

function ERROR_BIO_get_retry_reason(bio: PBIO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_get_retry_reason');
end;

procedure ERROR_BIO_set_retry_reason(bio: PBIO; reason: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_retry_reason');
end;

function ERROR_BIO_dup_chain(in_: PBIO): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dup_chain');
end;

function ERROR_BIO_nread0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nread0');
end;

function ERROR_BIO_nread(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nread');
end;

function ERROR_BIO_nwrite0(bio: PBIO; buf: PPAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nwrite0');
end;

function ERROR_BIO_nwrite(bio: PBIO; buf: PPAnsiChar; num: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_nwrite');
end;

function ERROR_BIO_debug_callback(bio: PBIO; cmd: TOpenSSL_C_INT; const argp: PAnsiChar; argi: TOpenSSL_C_INT; argl: TOpenSSL_C_LONG; ret: TOpenSSL_C_LONG): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_debug_callback');
end;

function ERROR_BIO_s_mem: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_mem');
end;

function ERROR_BIO_s_secmem: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_secmem');
end;

function ERROR_BIO_new_mem_buf(const buf: Pointer; len: TOpenSSL_C_INT): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_mem_buf');
end;

function ERROR_BIO_s_socket: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_socket');
end;

function ERROR_BIO_s_connect: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_connect');
end;

function ERROR_BIO_s_accept: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_accept');
end;

function ERROR_BIO_s_fd: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_fd');
end;

function ERROR_BIO_s_log: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_log');
end;

function ERROR_BIO_s_bio: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_bio');
end;

function ERROR_BIO_s_null: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_null');
end;

function ERROR_BIO_f_null: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_null');
end;

function ERROR_BIO_f_buffer: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_buffer');
end;

function ERROR_BIO_f_linebuffer: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_linebuffer');
end;

function ERROR_BIO_f_nbio_test: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_f_nbio_test');
end;

function ERROR_BIO_s_datagram: PBIO_METHOD; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_s_datagram');
end;

function ERROR_BIO_dgram_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dgram_non_fatal_error');
end;

function ERROR_BIO_new_dgram(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_dgram');
end;

function ERROR_BIO_sock_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_should_retry');
end;

function ERROR_BIO_sock_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_non_fatal_error');
end;

function ERROR_BIO_fd_should_retry(i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_fd_should_retry');
end;

function ERROR_BIO_fd_non_fatal_error(error: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_fd_non_fatal_error');
end;

function ERROR_BIO_dump(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dump');
end;

function ERROR_BIO_dump_indent(b: PBIO; const bytes: PAnsiChar; len: TOpenSSL_C_INT; indent: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_dump_indent');
end;

function ERROR_BIO_hex_string(out_: PBIO; indent: TOpenSSL_C_INT; width: TOpenSSL_C_INT; data: PByte; datalen: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_hex_string');
end;

function ERROR_BIO_ADDR_new: PBIO_ADDR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_new');
end;

function ERROR_BIO_ADDR_rawmake(ap: PBIO_ADDR; familiy: TOpenSSL_C_INT; const where: Pointer; wherelen: TOpenSSL_C_SIZET; port: TOpenSSL_C_SHORT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_rawmake');
end;

procedure ERROR_BIO_ADDR_free(a: PBIO_ADDR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_free');
end;

procedure ERROR_BIO_ADDR_clear(ap: PBIO_ADDR); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_clear');
end;

function ERROR_BIO_ADDR_family(const ap: PBIO_ADDR): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_family');
end;

function ERROR_BIO_ADDR_rawaddress(const ap: PBIO_ADDR; p: Pointer; l: POpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_rawaddress');
end;

function ERROR_BIO_ADDR_rawport(const ap: PBIO_ADDR): TOpenSSL_C_SHORT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_rawport');
end;

function ERROR_BIO_ADDR_hostname_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_hostname_string');
end;

function ERROR_BIO_ADDR_service_string(const ap: PBIO_ADDR; numeric: TOpenSSL_C_INT): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_service_string');
end;

function ERROR_BIO_ADDR_path_string(const ap: PBIO_ADDR): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDR_path_string');
end;

function ERROR_BIO_ADDRINFO_next(const bai: PBIO_ADDRINFO): PBIO_ADDRINFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_next');
end;

function ERROR_BIO_ADDRINFO_family(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_family');
end;

function ERROR_BIO_ADDRINFO_socktype(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_socktype');
end;

function ERROR_BIO_ADDRINFO_protocol(const bai: PBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_protocol');
end;

function ERROR_BIO_ADDRINFO_address(const bai: PBIO_ADDRINFO): PBIO_ADDR; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_address');
end;

procedure ERROR_BIO_ADDRINFO_free(bai: PBIO_ADDRINFO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_ADDRINFO_free');
end;

function ERROR_BIO_parse_hostserv(const hostserv: PAnsiChar; host: PPAnsiChar; service: PPAnsiChar; hostserv_prio: BIO_hostserv_priorities): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_parse_hostserv');
end;

function ERROR_BIO_lookup(const host: PAnsiChar; const service: PAnsiChar; lookup_type: BIO_lookup_type; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_lookup');
end;

function ERROR_BIO_lookup_ex(const host: PAnsiChar; const service: PAnsiChar; lookup_type: TOpenSSL_C_INT; family: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; res: PPBIO_ADDRINFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_lookup_ex');
end;

function ERROR_BIO_sock_error(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_error');
end;

function ERROR_BIO_socket_ioctl(fd: TOpenSSL_C_INT; cType: TOpenSSL_C_LONG; arg: Pointer): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_socket_ioctl');
end;

function ERROR_BIO_socket_nbio(fd: TOpenSSL_C_INT; mode: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_socket_nbio');
end;

function ERROR_BIO_sock_init: TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_init');
end;

function ERROR_BIO_set_tcp_ndelay(sock: TOpenSSL_C_INT; turn_on: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_set_tcp_ndelay');
end;

function ERROR_BIO_sock_info(sock: TOpenSSL_C_INT; type_: BIO_sock_info_type; info: PBIO_sock_info_u): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_sock_info');
end;

function ERROR_BIO_socket(domain: TOpenSSL_C_INT; socktype: TOpenSSL_C_INT; protocol: TOpenSSL_C_INT; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_socket');
end;

function ERROR_BIO_connect(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_connect');
end;

function ERROR_BIO_bind(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_bind');
end;

function ERROR_BIO_listen(sock: TOpenSSL_C_INT; const addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_listen');
end;

function ERROR_BIO_accept_ex(accept_sock: TOpenSSL_C_INT; addr: PBIO_ADDR; options: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_accept_ex');
end;

function ERROR_BIO_closesocket(sock: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_closesocket');
end;

function ERROR_BIO_new_socket(sock: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_socket');
end;

function ERROR_BIO_new_connect(const host_port: PAnsiChar): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_connect');
end;

function ERROR_BIO_new_accept(const host_port: PAnsiChar): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_accept');
end;

function ERROR_BIO_new_fd(fd: TOpenSSL_C_INT; close_flag: TOpenSSL_C_INT): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_fd');
end;

function ERROR_BIO_new_bio_pair(bio1: PPBIO; writebuf1: TOpenSSL_C_SIZET; bio2: PPBIO; writebuf2: TOpenSSL_C_SIZET): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_new_bio_pair');
end;

procedure ERROR_BIO_copy_next_retry(b: PBIO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('BIO_copy_next_retry');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  BIO_get_flags := LoadLibCryptoFunction('BIO_get_flags');
  FuncLoadError := not assigned(BIO_get_flags);
  if FuncLoadError then
  begin
    BIO_get_flags := @COMPAT_BIO_get_flags;
    if BIO_get_flags_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_get_flags');
  end;

  BIO_set_retry_special := LoadLibCryptoFunction('BIO_set_retry_special');
  FuncLoadError := not assigned(BIO_set_retry_special);
  if FuncLoadError then
  begin
    BIO_set_retry_special := @COMPAT_BIO_set_retry_special;
    if BIO_set_retry_special_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_set_retry_special');
  end;

  BIO_set_retry_read := LoadLibCryptoFunction('BIO_set_retry_read');
  FuncLoadError := not assigned(BIO_set_retry_read);
  if FuncLoadError then
  begin
    BIO_set_retry_read := @COMPAT_BIO_set_retry_read;
    if BIO_set_retry_read_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_set_retry_read');
  end;

  BIO_set_retry_write := LoadLibCryptoFunction('BIO_set_retry_write');
  FuncLoadError := not assigned(BIO_set_retry_write);
  if FuncLoadError then
  begin
    BIO_set_retry_write := @COMPAT_BIO_set_retry_write;
    if BIO_set_retry_write_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_set_retry_write');
  end;

  BIO_clear_retry_flags := LoadLibCryptoFunction('BIO_clear_retry_flags');
  FuncLoadError := not assigned(BIO_clear_retry_flags);
  if FuncLoadError then
  begin
    BIO_clear_retry_flags := @COMPAT_BIO_clear_retry_flags;
    if BIO_clear_retry_flags_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_clear_retry_flags');
  end;

  BIO_get_retry_flags := LoadLibCryptoFunction('BIO_get_retry_flags');
  FuncLoadError := not assigned(BIO_get_retry_flags);
  if FuncLoadError then
  begin
    BIO_get_retry_flags := @COMPAT_BIO_get_retry_flags;
    if BIO_get_retry_flags_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_get_retry_flags');
  end;

  BIO_should_read := LoadLibCryptoFunction('BIO_should_read');
  FuncLoadError := not assigned(BIO_should_read);
  if FuncLoadError then
  begin
    BIO_should_read := @COMPAT_BIO_should_read;
    if BIO_should_read_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_should_read');
  end;

  BIO_should_write := LoadLibCryptoFunction('BIO_should_write');
  FuncLoadError := not assigned(BIO_should_write);
  if FuncLoadError then
  begin
    BIO_should_write := @COMPAT_BIO_should_write;
    if BIO_should_write_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_should_write');
  end;

  BIO_should_io_special := LoadLibCryptoFunction('BIO_should_io_special');
  FuncLoadError := not assigned(BIO_should_io_special);
  if FuncLoadError then
  begin
    BIO_should_io_special := @COMPAT_BIO_should_io_special;
    if BIO_should_io_special_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_should_io_special');
  end;

  BIO_retry_type := LoadLibCryptoFunction('BIO_retry_type');
  FuncLoadError := not assigned(BIO_retry_type);
  if FuncLoadError then
  begin
    BIO_retry_type := @COMPAT_BIO_retry_type;
    if BIO_retry_type_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_retry_type');
  end;

  BIO_should_retry := LoadLibCryptoFunction('BIO_should_retry');
  FuncLoadError := not assigned(BIO_should_retry);
  if FuncLoadError then
  begin
    BIO_should_retry := @COMPAT_BIO_should_retry;
    if BIO_should_retry_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_should_retry');
  end;

  BIO_do_connect := LoadLibCryptoFunction('BIO_do_connect');
  FuncLoadError := not assigned(BIO_do_connect);
  if FuncLoadError then
  begin
    BIO_do_connect := @COMPAT_BIO_do_connect;
    if BIO_do_connect_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_do_connect');
  end;

  BIO_do_accept := LoadLibCryptoFunction('BIO_do_accept');
  FuncLoadError := not assigned(BIO_do_accept);
  if FuncLoadError then
  begin
    BIO_do_accept := @COMPAT_BIO_do_accept;
    if BIO_do_accept_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_do_accept');
  end;

  BIO_do_handshake := LoadLibCryptoFunction('BIO_do_handshake');
  FuncLoadError := not assigned(BIO_do_handshake);
  if FuncLoadError then
  begin
    BIO_do_handshake := @COMPAT_BIO_do_handshake;
    if BIO_do_handshake_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_do_handshake');
  end;

  BIO_get_mem_data := LoadLibCryptoFunction('BIO_get_mem_data');
  FuncLoadError := not assigned(BIO_get_mem_data);
  if FuncLoadError then
  begin
    BIO_get_mem_data := @COMPAT_BIO_get_mem_data;
    if BIO_get_mem_data_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_get_mem_data');
  end;

  BIO_set_mem_buf := LoadLibCryptoFunction('BIO_set_mem_buf');
  FuncLoadError := not assigned(BIO_set_mem_buf);
  if FuncLoadError then
  begin
    BIO_set_mem_buf := @COMPAT_BIO_set_mem_buf;
    if BIO_set_mem_buf_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_set_mem_buf');
  end;

  BIO_get_mem_ptr := LoadLibCryptoFunction('BIO_get_mem_ptr');
  FuncLoadError := not assigned(BIO_get_mem_ptr);
  if FuncLoadError then
  begin
    BIO_get_mem_ptr := @COMPAT_BIO_get_mem_ptr;
    if BIO_get_mem_ptr_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_get_mem_ptr');
  end;

  BIO_set_mem_eof_return := LoadLibCryptoFunction('BIO_set_mem_eof_return');
  FuncLoadError := not assigned(BIO_set_mem_eof_return);
  if FuncLoadError then
  begin
    BIO_set_mem_eof_return := @COMPAT_BIO_set_mem_eof_return;
    if BIO_set_mem_eof_return_removed <= LibVersion then
      FuncLoadError := false;
    if FuncLoadError then
      AFailed.Add('BIO_set_mem_eof_return');
  end;

{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  BIO_get_new_index := LoadLibCryptoFunction('BIO_get_new_index');
  FuncLoadError := not assigned(BIO_get_new_index);
  if FuncLoadError then
  begin
    BIO_get_new_index :=  @ERROR_BIO_get_new_index;
  end;

  BIO_set_flags := LoadLibCryptoFunction('BIO_set_flags');
  FuncLoadError := not assigned(BIO_set_flags);
  if FuncLoadError then
  begin
    BIO_set_flags :=  @ERROR_BIO_set_flags;
  end;

  BIO_test_flags := LoadLibCryptoFunction('BIO_test_flags');
  FuncLoadError := not assigned(BIO_test_flags);
  if FuncLoadError then
  begin
    BIO_test_flags :=  @ERROR_BIO_test_flags;
  end;

  BIO_clear_flags := LoadLibCryptoFunction('BIO_clear_flags');
  FuncLoadError := not assigned(BIO_clear_flags);
  if FuncLoadError then
  begin
    BIO_clear_flags :=  @ERROR_BIO_clear_flags;
  end;

  BIO_get_callback := LoadLibCryptoFunction('BIO_get_callback');
  FuncLoadError := not assigned(BIO_get_callback);
  if FuncLoadError then
  begin
    BIO_get_callback :=  @ERROR_BIO_get_callback;
  end;

  BIO_set_callback := LoadLibCryptoFunction('BIO_set_callback');
  FuncLoadError := not assigned(BIO_set_callback);
  if FuncLoadError then
  begin
    BIO_set_callback :=  @ERROR_BIO_set_callback;
  end;

  BIO_get_callback_ex := LoadLibCryptoFunction('BIO_get_callback_ex');
  FuncLoadError := not assigned(BIO_get_callback_ex);
  if FuncLoadError then
  begin
    BIO_get_callback_ex :=  @ERROR_BIO_get_callback_ex;
  end;

  BIO_set_callback_ex := LoadLibCryptoFunction('BIO_set_callback_ex');
  FuncLoadError := not assigned(BIO_set_callback_ex);
  if FuncLoadError then
  begin
    BIO_set_callback_ex :=  @ERROR_BIO_set_callback_ex;
  end;

  BIO_get_callback_arg := LoadLibCryptoFunction('BIO_get_callback_arg');
  FuncLoadError := not assigned(BIO_get_callback_arg);
  if FuncLoadError then
  begin
    BIO_get_callback_arg :=  @ERROR_BIO_get_callback_arg;
  end;

  BIO_set_callback_arg := LoadLibCryptoFunction('BIO_set_callback_arg');
  FuncLoadError := not assigned(BIO_set_callback_arg);
  if FuncLoadError then
  begin
    BIO_set_callback_arg :=  @ERROR_BIO_set_callback_arg;
  end;

  BIO_method_name := LoadLibCryptoFunction('BIO_method_name');
  FuncLoadError := not assigned(BIO_method_name);
  if FuncLoadError then
  begin
    BIO_method_name :=  @ERROR_BIO_method_name;
  end;

  BIO_method_type := LoadLibCryptoFunction('BIO_method_type');
  FuncLoadError := not assigned(BIO_method_type);
  if FuncLoadError then
  begin
    BIO_method_type :=  @ERROR_BIO_method_type;
  end;

  BIO_ctrl_pending := LoadLibCryptoFunction('BIO_ctrl_pending');
  FuncLoadError := not assigned(BIO_ctrl_pending);
  if FuncLoadError then
  begin
    BIO_ctrl_pending :=  @ERROR_BIO_ctrl_pending;
  end;

  BIO_ctrl_wpending := LoadLibCryptoFunction('BIO_ctrl_wpending');
  FuncLoadError := not assigned(BIO_ctrl_wpending);
  if FuncLoadError then
  begin
    BIO_ctrl_wpending :=  @ERROR_BIO_ctrl_wpending;
  end;

  BIO_ctrl_get_write_guarantee := LoadLibCryptoFunction('BIO_ctrl_get_write_guarantee');
  FuncLoadError := not assigned(BIO_ctrl_get_write_guarantee);
  if FuncLoadError then
  begin
    BIO_ctrl_get_write_guarantee :=  @ERROR_BIO_ctrl_get_write_guarantee;
  end;

  BIO_ctrl_get_read_request := LoadLibCryptoFunction('BIO_ctrl_get_read_request');
  FuncLoadError := not assigned(BIO_ctrl_get_read_request);
  if FuncLoadError then
  begin
    BIO_ctrl_get_read_request :=  @ERROR_BIO_ctrl_get_read_request;
  end;

  BIO_ctrl_reset_read_request := LoadLibCryptoFunction('BIO_ctrl_reset_read_request');
  FuncLoadError := not assigned(BIO_ctrl_reset_read_request);
  if FuncLoadError then
  begin
    BIO_ctrl_reset_read_request :=  @ERROR_BIO_ctrl_reset_read_request;
  end;

  BIO_set_ex_data := LoadLibCryptoFunction('BIO_set_ex_data');
  FuncLoadError := not assigned(BIO_set_ex_data);
  if FuncLoadError then
  begin
    BIO_set_ex_data :=  @ERROR_BIO_set_ex_data;
  end;

  BIO_get_ex_data := LoadLibCryptoFunction('BIO_get_ex_data');
  FuncLoadError := not assigned(BIO_get_ex_data);
  if FuncLoadError then
  begin
    BIO_get_ex_data :=  @ERROR_BIO_get_ex_data;
  end;

  BIO_number_read := LoadLibCryptoFunction('BIO_number_read');
  FuncLoadError := not assigned(BIO_number_read);
  if FuncLoadError then
  begin
    BIO_number_read :=  @ERROR_BIO_number_read;
  end;

  BIO_number_written := LoadLibCryptoFunction('BIO_number_written');
  FuncLoadError := not assigned(BIO_number_written);
  if FuncLoadError then
  begin
    BIO_number_written :=  @ERROR_BIO_number_written;
  end;

  BIO_s_file := LoadLibCryptoFunction('BIO_s_file');
  FuncLoadError := not assigned(BIO_s_file);
  if FuncLoadError then
  begin
    BIO_s_file :=  @ERROR_BIO_s_file;
  end;

  BIO_new_file := LoadLibCryptoFunction('BIO_new_file');
  FuncLoadError := not assigned(BIO_new_file);
  if FuncLoadError then
  begin
    BIO_new_file :=  @ERROR_BIO_new_file;
  end;

  BIO_new := LoadLibCryptoFunction('BIO_new');
  FuncLoadError := not assigned(BIO_new);
  if FuncLoadError then
  begin
    BIO_new :=  @ERROR_BIO_new;
  end;

  BIO_free := LoadLibCryptoFunction('BIO_free');
  FuncLoadError := not assigned(BIO_free);
  if FuncLoadError then
  begin
    BIO_free :=  @ERROR_BIO_free;
  end;

  BIO_set_data := LoadLibCryptoFunction('BIO_set_data');
  FuncLoadError := not assigned(BIO_set_data);
  if FuncLoadError then
  begin
    BIO_set_data :=  @ERROR_BIO_set_data;
  end;

  BIO_get_data := LoadLibCryptoFunction('BIO_get_data');
  FuncLoadError := not assigned(BIO_get_data);
  if FuncLoadError then
  begin
    BIO_get_data :=  @ERROR_BIO_get_data;
  end;

  BIO_set_init := LoadLibCryptoFunction('BIO_set_init');
  FuncLoadError := not assigned(BIO_set_init);
  if FuncLoadError then
  begin
    BIO_set_init :=  @ERROR_BIO_set_init;
  end;

  BIO_get_init := LoadLibCryptoFunction('BIO_get_init');
  FuncLoadError := not assigned(BIO_get_init);
  if FuncLoadError then
  begin
    BIO_get_init :=  @ERROR_BIO_get_init;
  end;

  BIO_set_shutdown := LoadLibCryptoFunction('BIO_set_shutdown');
  FuncLoadError := not assigned(BIO_set_shutdown);
  if FuncLoadError then
  begin
    BIO_set_shutdown :=  @ERROR_BIO_set_shutdown;
  end;

  BIO_get_shutdown := LoadLibCryptoFunction('BIO_get_shutdown');
  FuncLoadError := not assigned(BIO_get_shutdown);
  if FuncLoadError then
  begin
    BIO_get_shutdown :=  @ERROR_BIO_get_shutdown;
  end;

  BIO_vfree := LoadLibCryptoFunction('BIO_vfree');
  FuncLoadError := not assigned(BIO_vfree);
  if FuncLoadError then
  begin
    BIO_vfree :=  @ERROR_BIO_vfree;
  end;

  BIO_up_ref := LoadLibCryptoFunction('BIO_up_ref');
  FuncLoadError := not assigned(BIO_up_ref);
  if FuncLoadError then
  begin
    BIO_up_ref :=  @ERROR_BIO_up_ref;
  end;

  BIO_read := LoadLibCryptoFunction('BIO_read');
  FuncLoadError := not assigned(BIO_read);
  if FuncLoadError then
  begin
    BIO_read :=  @ERROR_BIO_read;
  end;

  BIO_read_ex := LoadLibCryptoFunction('BIO_read_ex');
  FuncLoadError := not assigned(BIO_read_ex);
  if FuncLoadError then
  begin
    BIO_read_ex :=  @ERROR_BIO_read_ex;
  end;

  BIO_gets := LoadLibCryptoFunction('BIO_gets');
  FuncLoadError := not assigned(BIO_gets);
  if FuncLoadError then
  begin
    BIO_gets :=  @ERROR_BIO_gets;
  end;

  BIO_write := LoadLibCryptoFunction('BIO_write');
  FuncLoadError := not assigned(BIO_write);
  if FuncLoadError then
  begin
    BIO_write :=  @ERROR_BIO_write;
  end;

  BIO_write_ex := LoadLibCryptoFunction('BIO_write_ex');
  FuncLoadError := not assigned(BIO_write_ex);
  if FuncLoadError then
  begin
    BIO_write_ex :=  @ERROR_BIO_write_ex;
  end;

  BIO_puts := LoadLibCryptoFunction('BIO_puts');
  FuncLoadError := not assigned(BIO_puts);
  if FuncLoadError then
  begin
    BIO_puts :=  @ERROR_BIO_puts;
  end;

  BIO_indent := LoadLibCryptoFunction('BIO_indent');
  FuncLoadError := not assigned(BIO_indent);
  if FuncLoadError then
  begin
    BIO_indent :=  @ERROR_BIO_indent;
  end;

  BIO_ctrl := LoadLibCryptoFunction('BIO_ctrl');
  FuncLoadError := not assigned(BIO_ctrl);
  if FuncLoadError then
  begin
    BIO_ctrl :=  @ERROR_BIO_ctrl;
  end;

  BIO_callback_ctrl := LoadLibCryptoFunction('BIO_callback_ctrl');
  FuncLoadError := not assigned(BIO_callback_ctrl);
  if FuncLoadError then
  begin
    BIO_callback_ctrl :=  @ERROR_BIO_callback_ctrl;
  end;

  BIO_ptr_ctrl := LoadLibCryptoFunction('BIO_ptr_ctrl');
  FuncLoadError := not assigned(BIO_ptr_ctrl);
  if FuncLoadError then
  begin
    BIO_ptr_ctrl :=  @ERROR_BIO_ptr_ctrl;
  end;

  BIO_int_ctrl := LoadLibCryptoFunction('BIO_int_ctrl');
  FuncLoadError := not assigned(BIO_int_ctrl);
  if FuncLoadError then
  begin
    BIO_int_ctrl :=  @ERROR_BIO_int_ctrl;
  end;

  BIO_push := LoadLibCryptoFunction('BIO_push');
  FuncLoadError := not assigned(BIO_push);
  if FuncLoadError then
  begin
    BIO_push :=  @ERROR_BIO_push;
  end;

  BIO_pop := LoadLibCryptoFunction('BIO_pop');
  FuncLoadError := not assigned(BIO_pop);
  if FuncLoadError then
  begin
    BIO_pop :=  @ERROR_BIO_pop;
  end;

  BIO_free_all := LoadLibCryptoFunction('BIO_free_all');
  FuncLoadError := not assigned(BIO_free_all);
  if FuncLoadError then
  begin
    BIO_free_all :=  @ERROR_BIO_free_all;
  end;

  BIO_find_type := LoadLibCryptoFunction('BIO_find_type');
  FuncLoadError := not assigned(BIO_find_type);
  if FuncLoadError then
  begin
    BIO_find_type :=  @ERROR_BIO_find_type;
  end;

  BIO_next := LoadLibCryptoFunction('BIO_next');
  FuncLoadError := not assigned(BIO_next);
  if FuncLoadError then
  begin
    BIO_next :=  @ERROR_BIO_next;
  end;

  BIO_set_next := LoadLibCryptoFunction('BIO_set_next');
  FuncLoadError := not assigned(BIO_set_next);
  if FuncLoadError then
  begin
    BIO_set_next :=  @ERROR_BIO_set_next;
  end;

  BIO_get_retry_BIO := LoadLibCryptoFunction('BIO_get_retry_BIO');
  FuncLoadError := not assigned(BIO_get_retry_BIO);
  if FuncLoadError then
  begin
    BIO_get_retry_BIO :=  @ERROR_BIO_get_retry_BIO;
  end;

  BIO_get_retry_reason := LoadLibCryptoFunction('BIO_get_retry_reason');
  FuncLoadError := not assigned(BIO_get_retry_reason);
  if FuncLoadError then
  begin
    BIO_get_retry_reason :=  @ERROR_BIO_get_retry_reason;
  end;

  BIO_set_retry_reason := LoadLibCryptoFunction('BIO_set_retry_reason');
  FuncLoadError := not assigned(BIO_set_retry_reason);
  if FuncLoadError then
  begin
    BIO_set_retry_reason :=  @ERROR_BIO_set_retry_reason;
  end;

  BIO_dup_chain := LoadLibCryptoFunction('BIO_dup_chain');
  FuncLoadError := not assigned(BIO_dup_chain);
  if FuncLoadError then
  begin
    BIO_dup_chain :=  @ERROR_BIO_dup_chain;
  end;

  BIO_nread0 := LoadLibCryptoFunction('BIO_nread0');
  FuncLoadError := not assigned(BIO_nread0);
  if FuncLoadError then
  begin
    BIO_nread0 :=  @ERROR_BIO_nread0;
  end;

  BIO_nread := LoadLibCryptoFunction('BIO_nread');
  FuncLoadError := not assigned(BIO_nread);
  if FuncLoadError then
  begin
    BIO_nread :=  @ERROR_BIO_nread;
  end;

  BIO_nwrite0 := LoadLibCryptoFunction('BIO_nwrite0');
  FuncLoadError := not assigned(BIO_nwrite0);
  if FuncLoadError then
  begin
    BIO_nwrite0 :=  @ERROR_BIO_nwrite0;
  end;

  BIO_nwrite := LoadLibCryptoFunction('BIO_nwrite');
  FuncLoadError := not assigned(BIO_nwrite);
  if FuncLoadError then
  begin
    BIO_nwrite :=  @ERROR_BIO_nwrite;
  end;

  BIO_debug_callback := LoadLibCryptoFunction('BIO_debug_callback');
  FuncLoadError := not assigned(BIO_debug_callback);
  if FuncLoadError then
  begin
    BIO_debug_callback :=  @ERROR_BIO_debug_callback;
  end;

  BIO_s_mem := LoadLibCryptoFunction('BIO_s_mem');
  FuncLoadError := not assigned(BIO_s_mem);
  if FuncLoadError then
  begin
    BIO_s_mem :=  @ERROR_BIO_s_mem;
  end;

  BIO_s_secmem := LoadLibCryptoFunction('BIO_s_secmem');
  FuncLoadError := not assigned(BIO_s_secmem);
  if FuncLoadError then
  begin
    BIO_s_secmem :=  @ERROR_BIO_s_secmem;
  end;

  BIO_new_mem_buf := LoadLibCryptoFunction('BIO_new_mem_buf');
  FuncLoadError := not assigned(BIO_new_mem_buf);
  if FuncLoadError then
  begin
    BIO_new_mem_buf :=  @ERROR_BIO_new_mem_buf;
  end;

  BIO_s_socket := LoadLibCryptoFunction('BIO_s_socket');
  FuncLoadError := not assigned(BIO_s_socket);
  if FuncLoadError then
  begin
    BIO_s_socket :=  @ERROR_BIO_s_socket;
  end;

  BIO_s_connect := LoadLibCryptoFunction('BIO_s_connect');
  FuncLoadError := not assigned(BIO_s_connect);
  if FuncLoadError then
  begin
    BIO_s_connect :=  @ERROR_BIO_s_connect;
  end;

  BIO_s_accept := LoadLibCryptoFunction('BIO_s_accept');
  FuncLoadError := not assigned(BIO_s_accept);
  if FuncLoadError then
  begin
    BIO_s_accept :=  @ERROR_BIO_s_accept;
  end;

  BIO_s_fd := LoadLibCryptoFunction('BIO_s_fd');
  FuncLoadError := not assigned(BIO_s_fd);
  if FuncLoadError then
  begin
    BIO_s_fd :=  @ERROR_BIO_s_fd;
  end;

  BIO_s_log := LoadLibCryptoFunction('BIO_s_log');
  FuncLoadError := not assigned(BIO_s_log);
  if FuncLoadError then
  begin
    BIO_s_log :=  @ERROR_BIO_s_log;
  end;

  BIO_s_bio := LoadLibCryptoFunction('BIO_s_bio');
  FuncLoadError := not assigned(BIO_s_bio);
  if FuncLoadError then
  begin
    BIO_s_bio :=  @ERROR_BIO_s_bio;
  end;

  BIO_s_null := LoadLibCryptoFunction('BIO_s_null');
  FuncLoadError := not assigned(BIO_s_null);
  if FuncLoadError then
  begin
    BIO_s_null :=  @ERROR_BIO_s_null;
  end;

  BIO_f_null := LoadLibCryptoFunction('BIO_f_null');
  FuncLoadError := not assigned(BIO_f_null);
  if FuncLoadError then
  begin
    BIO_f_null :=  @ERROR_BIO_f_null;
  end;

  BIO_f_buffer := LoadLibCryptoFunction('BIO_f_buffer');
  FuncLoadError := not assigned(BIO_f_buffer);
  if FuncLoadError then
  begin
    BIO_f_buffer :=  @ERROR_BIO_f_buffer;
  end;

  BIO_f_linebuffer := LoadLibCryptoFunction('BIO_f_linebuffer');
  FuncLoadError := not assigned(BIO_f_linebuffer);
  if FuncLoadError then
  begin
    BIO_f_linebuffer :=  @ERROR_BIO_f_linebuffer;
  end;

  BIO_f_nbio_test := LoadLibCryptoFunction('BIO_f_nbio_test');
  FuncLoadError := not assigned(BIO_f_nbio_test);
  if FuncLoadError then
  begin
    BIO_f_nbio_test :=  @ERROR_BIO_f_nbio_test;
  end;

  BIO_s_datagram := LoadLibCryptoFunction('BIO_s_datagram');
  FuncLoadError := not assigned(BIO_s_datagram);
  if FuncLoadError then
  begin
    BIO_s_datagram :=  @ERROR_BIO_s_datagram;
  end;

  BIO_dgram_non_fatal_error := LoadLibCryptoFunction('BIO_dgram_non_fatal_error');
  FuncLoadError := not assigned(BIO_dgram_non_fatal_error);
  if FuncLoadError then
  begin
    BIO_dgram_non_fatal_error :=  @ERROR_BIO_dgram_non_fatal_error;
  end;

  BIO_new_dgram := LoadLibCryptoFunction('BIO_new_dgram');
  FuncLoadError := not assigned(BIO_new_dgram);
  if FuncLoadError then
  begin
    BIO_new_dgram :=  @ERROR_BIO_new_dgram;
  end;

  BIO_sock_should_retry := LoadLibCryptoFunction('BIO_sock_should_retry');
  FuncLoadError := not assigned(BIO_sock_should_retry);
  if FuncLoadError then
  begin
    BIO_sock_should_retry :=  @ERROR_BIO_sock_should_retry;
  end;

  BIO_sock_non_fatal_error := LoadLibCryptoFunction('BIO_sock_non_fatal_error');
  FuncLoadError := not assigned(BIO_sock_non_fatal_error);
  if FuncLoadError then
  begin
    BIO_sock_non_fatal_error :=  @ERROR_BIO_sock_non_fatal_error;
  end;

  BIO_fd_should_retry := LoadLibCryptoFunction('BIO_fd_should_retry');
  FuncLoadError := not assigned(BIO_fd_should_retry);
  if FuncLoadError then
  begin
    BIO_fd_should_retry :=  @ERROR_BIO_fd_should_retry;
  end;

  BIO_fd_non_fatal_error := LoadLibCryptoFunction('BIO_fd_non_fatal_error');
  FuncLoadError := not assigned(BIO_fd_non_fatal_error);
  if FuncLoadError then
  begin
    BIO_fd_non_fatal_error :=  @ERROR_BIO_fd_non_fatal_error;
  end;

  BIO_dump := LoadLibCryptoFunction('BIO_dump');
  FuncLoadError := not assigned(BIO_dump);
  if FuncLoadError then
  begin
    BIO_dump :=  @ERROR_BIO_dump;
  end;

  BIO_dump_indent := LoadLibCryptoFunction('BIO_dump_indent');
  FuncLoadError := not assigned(BIO_dump_indent);
  if FuncLoadError then
  begin
    BIO_dump_indent :=  @ERROR_BIO_dump_indent;
  end;

  BIO_hex_string := LoadLibCryptoFunction('BIO_hex_string');
  FuncLoadError := not assigned(BIO_hex_string);
  if FuncLoadError then
  begin
    BIO_hex_string :=  @ERROR_BIO_hex_string;
  end;

  BIO_ADDR_new := LoadLibCryptoFunction('BIO_ADDR_new');
  FuncLoadError := not assigned(BIO_ADDR_new);
  if FuncLoadError then
  begin
    BIO_ADDR_new :=  @ERROR_BIO_ADDR_new;
  end;

  BIO_ADDR_rawmake := LoadLibCryptoFunction('BIO_ADDR_rawmake');
  FuncLoadError := not assigned(BIO_ADDR_rawmake);
  if FuncLoadError then
  begin
    BIO_ADDR_rawmake :=  @ERROR_BIO_ADDR_rawmake;
  end;

  BIO_ADDR_free := LoadLibCryptoFunction('BIO_ADDR_free');
  FuncLoadError := not assigned(BIO_ADDR_free);
  if FuncLoadError then
  begin
    BIO_ADDR_free :=  @ERROR_BIO_ADDR_free;
  end;

  BIO_ADDR_clear := LoadLibCryptoFunction('BIO_ADDR_clear');
  FuncLoadError := not assigned(BIO_ADDR_clear);
  if FuncLoadError then
  begin
    BIO_ADDR_clear :=  @ERROR_BIO_ADDR_clear;
  end;

  BIO_ADDR_family := LoadLibCryptoFunction('BIO_ADDR_family');
  FuncLoadError := not assigned(BIO_ADDR_family);
  if FuncLoadError then
  begin
    BIO_ADDR_family :=  @ERROR_BIO_ADDR_family;
  end;

  BIO_ADDR_rawaddress := LoadLibCryptoFunction('BIO_ADDR_rawaddress');
  FuncLoadError := not assigned(BIO_ADDR_rawaddress);
  if FuncLoadError then
  begin
    BIO_ADDR_rawaddress :=  @ERROR_BIO_ADDR_rawaddress;
  end;

  BIO_ADDR_rawport := LoadLibCryptoFunction('BIO_ADDR_rawport');
  FuncLoadError := not assigned(BIO_ADDR_rawport);
  if FuncLoadError then
  begin
    BIO_ADDR_rawport :=  @ERROR_BIO_ADDR_rawport;
  end;

  BIO_ADDR_hostname_string := LoadLibCryptoFunction('BIO_ADDR_hostname_string');
  FuncLoadError := not assigned(BIO_ADDR_hostname_string);
  if FuncLoadError then
  begin
    BIO_ADDR_hostname_string :=  @ERROR_BIO_ADDR_hostname_string;
  end;

  BIO_ADDR_service_string := LoadLibCryptoFunction('BIO_ADDR_service_string');
  FuncLoadError := not assigned(BIO_ADDR_service_string);
  if FuncLoadError then
  begin
    BIO_ADDR_service_string :=  @ERROR_BIO_ADDR_service_string;
  end;

  BIO_ADDR_path_string := LoadLibCryptoFunction('BIO_ADDR_path_string');
  FuncLoadError := not assigned(BIO_ADDR_path_string);
  if FuncLoadError then
  begin
    BIO_ADDR_path_string :=  @ERROR_BIO_ADDR_path_string;
  end;

  BIO_ADDRINFO_next := LoadLibCryptoFunction('BIO_ADDRINFO_next');
  FuncLoadError := not assigned(BIO_ADDRINFO_next);
  if FuncLoadError then
  begin
    BIO_ADDRINFO_next :=  @ERROR_BIO_ADDRINFO_next;
  end;

  BIO_ADDRINFO_family := LoadLibCryptoFunction('BIO_ADDRINFO_family');
  FuncLoadError := not assigned(BIO_ADDRINFO_family);
  if FuncLoadError then
  begin
    BIO_ADDRINFO_family :=  @ERROR_BIO_ADDRINFO_family;
  end;

  BIO_ADDRINFO_socktype := LoadLibCryptoFunction('BIO_ADDRINFO_socktype');
  FuncLoadError := not assigned(BIO_ADDRINFO_socktype);
  if FuncLoadError then
  begin
    BIO_ADDRINFO_socktype :=  @ERROR_BIO_ADDRINFO_socktype;
  end;

  BIO_ADDRINFO_protocol := LoadLibCryptoFunction('BIO_ADDRINFO_protocol');
  FuncLoadError := not assigned(BIO_ADDRINFO_protocol);
  if FuncLoadError then
  begin
    BIO_ADDRINFO_protocol :=  @ERROR_BIO_ADDRINFO_protocol;
  end;

  BIO_ADDRINFO_address := LoadLibCryptoFunction('BIO_ADDRINFO_address');
  FuncLoadError := not assigned(BIO_ADDRINFO_address);
  if FuncLoadError then
  begin
    BIO_ADDRINFO_address :=  @ERROR_BIO_ADDRINFO_address;
  end;

  BIO_ADDRINFO_free := LoadLibCryptoFunction('BIO_ADDRINFO_free');
  FuncLoadError := not assigned(BIO_ADDRINFO_free);
  if FuncLoadError then
  begin
    BIO_ADDRINFO_free :=  @ERROR_BIO_ADDRINFO_free;
  end;

  BIO_parse_hostserv := LoadLibCryptoFunction('BIO_parse_hostserv');
  FuncLoadError := not assigned(BIO_parse_hostserv);
  if FuncLoadError then
  begin
    BIO_parse_hostserv :=  @ERROR_BIO_parse_hostserv;
  end;

  BIO_lookup := LoadLibCryptoFunction('BIO_lookup');
  FuncLoadError := not assigned(BIO_lookup);
  if FuncLoadError then
  begin
    BIO_lookup :=  @ERROR_BIO_lookup;
  end;

  BIO_lookup_ex := LoadLibCryptoFunction('BIO_lookup_ex');
  FuncLoadError := not assigned(BIO_lookup_ex);
  if FuncLoadError then
  begin
    BIO_lookup_ex :=  @ERROR_BIO_lookup_ex;
  end;

  BIO_sock_error := LoadLibCryptoFunction('BIO_sock_error');
  FuncLoadError := not assigned(BIO_sock_error);
  if FuncLoadError then
  begin
    BIO_sock_error :=  @ERROR_BIO_sock_error;
  end;

  BIO_socket_ioctl := LoadLibCryptoFunction('BIO_socket_ioctl');
  FuncLoadError := not assigned(BIO_socket_ioctl);
  if FuncLoadError then
  begin
    BIO_socket_ioctl :=  @ERROR_BIO_socket_ioctl;
  end;

  BIO_socket_nbio := LoadLibCryptoFunction('BIO_socket_nbio');
  FuncLoadError := not assigned(BIO_socket_nbio);
  if FuncLoadError then
  begin
    BIO_socket_nbio :=  @ERROR_BIO_socket_nbio;
  end;

  BIO_sock_init := LoadLibCryptoFunction('BIO_sock_init');
  FuncLoadError := not assigned(BIO_sock_init);
  if FuncLoadError then
  begin
    BIO_sock_init :=  @ERROR_BIO_sock_init;
  end;

  BIO_set_tcp_ndelay := LoadLibCryptoFunction('BIO_set_tcp_ndelay');
  FuncLoadError := not assigned(BIO_set_tcp_ndelay);
  if FuncLoadError then
  begin
    BIO_set_tcp_ndelay :=  @ERROR_BIO_set_tcp_ndelay;
  end;

  BIO_sock_info := LoadLibCryptoFunction('BIO_sock_info');
  FuncLoadError := not assigned(BIO_sock_info);
  if FuncLoadError then
  begin
    BIO_sock_info :=  @ERROR_BIO_sock_info;
  end;

  BIO_socket := LoadLibCryptoFunction('BIO_socket');
  FuncLoadError := not assigned(BIO_socket);
  if FuncLoadError then
  begin
    BIO_socket :=  @ERROR_BIO_socket;
  end;

  BIO_connect := LoadLibCryptoFunction('BIO_connect');
  FuncLoadError := not assigned(BIO_connect);
  if FuncLoadError then
  begin
    BIO_connect :=  @ERROR_BIO_connect;
  end;

  BIO_bind := LoadLibCryptoFunction('BIO_bind');
  FuncLoadError := not assigned(BIO_bind);
  if FuncLoadError then
  begin
    BIO_bind :=  @ERROR_BIO_bind;
  end;

  BIO_listen := LoadLibCryptoFunction('BIO_listen');
  FuncLoadError := not assigned(BIO_listen);
  if FuncLoadError then
  begin
    BIO_listen :=  @ERROR_BIO_listen;
  end;

  BIO_accept_ex := LoadLibCryptoFunction('BIO_accept_ex');
  FuncLoadError := not assigned(BIO_accept_ex);
  if FuncLoadError then
  begin
    BIO_accept_ex :=  @ERROR_BIO_accept_ex;
  end;

  BIO_closesocket := LoadLibCryptoFunction('BIO_closesocket');
  FuncLoadError := not assigned(BIO_closesocket);
  if FuncLoadError then
  begin
    BIO_closesocket :=  @ERROR_BIO_closesocket;
  end;

  BIO_new_socket := LoadLibCryptoFunction('BIO_new_socket');
  FuncLoadError := not assigned(BIO_new_socket);
  if FuncLoadError then
  begin
    BIO_new_socket :=  @ERROR_BIO_new_socket;
  end;

  BIO_new_connect := LoadLibCryptoFunction('BIO_new_connect');
  FuncLoadError := not assigned(BIO_new_connect);
  if FuncLoadError then
  begin
    BIO_new_connect :=  @ERROR_BIO_new_connect;
  end;

  BIO_new_accept := LoadLibCryptoFunction('BIO_new_accept');
  FuncLoadError := not assigned(BIO_new_accept);
  if FuncLoadError then
  begin
    BIO_new_accept :=  @ERROR_BIO_new_accept;
  end;

  BIO_new_fd := LoadLibCryptoFunction('BIO_new_fd');
  FuncLoadError := not assigned(BIO_new_fd);
  if FuncLoadError then
  begin
    BIO_new_fd :=  @ERROR_BIO_new_fd;
  end;

  BIO_new_bio_pair := LoadLibCryptoFunction('BIO_new_bio_pair');
  FuncLoadError := not assigned(BIO_new_bio_pair);
  if FuncLoadError then
  begin
    BIO_new_bio_pair :=  @ERROR_BIO_new_bio_pair;
  end;

  BIO_copy_next_retry := LoadLibCryptoFunction('BIO_copy_next_retry');
  FuncLoadError := not assigned(BIO_copy_next_retry);
  if FuncLoadError then
  begin
    BIO_copy_next_retry :=  @ERROR_BIO_copy_next_retry;
  end;

end;

procedure UnLoad;
begin
{$IFNDEF OPENSSL_NO_LEGACY_SUPPORT}
  BIO_get_flags := nil;
  BIO_set_retry_special := nil;
  BIO_set_retry_read := nil;
  BIO_set_retry_write := nil;
  BIO_clear_retry_flags := nil;
  BIO_get_retry_flags := nil;
  BIO_should_read := nil;
  BIO_should_write := nil;
  BIO_should_io_special := nil;
  BIO_retry_type := nil;
  BIO_should_retry := nil;
  BIO_do_connect := nil;
  BIO_do_accept := nil;
  BIO_do_handshake := nil;
  BIO_get_mem_data := nil;
  BIO_set_mem_buf := nil;
  BIO_get_mem_ptr := nil;
  BIO_set_mem_eof_return := nil;
{$ENDIF} //of OPENSSL_NO_LEGACY_SUPPORT
  BIO_get_new_index := nil;
  BIO_set_flags := nil;
  BIO_test_flags := nil;
  BIO_clear_flags := nil;
  BIO_get_callback := nil;
  BIO_set_callback := nil;
  BIO_get_callback_ex := nil;
  BIO_set_callback_ex := nil;
  BIO_get_callback_arg := nil;
  BIO_set_callback_arg := nil;
  BIO_method_name := nil;
  BIO_method_type := nil;
  BIO_ctrl_pending := nil;
  BIO_ctrl_wpending := nil;
  BIO_ctrl_get_write_guarantee := nil;
  BIO_ctrl_get_read_request := nil;
  BIO_ctrl_reset_read_request := nil;
  BIO_set_ex_data := nil;
  BIO_get_ex_data := nil;
  BIO_number_read := nil;
  BIO_number_written := nil;
  BIO_s_file := nil;
  BIO_new_file := nil;
  BIO_new := nil;
  BIO_free := nil;
  BIO_set_data := nil;
  BIO_get_data := nil;
  BIO_set_init := nil;
  BIO_get_init := nil;
  BIO_set_shutdown := nil;
  BIO_get_shutdown := nil;
  BIO_vfree := nil;
  BIO_up_ref := nil;
  BIO_read := nil;
  BIO_read_ex := nil;
  BIO_gets := nil;
  BIO_write := nil;
  BIO_write_ex := nil;
  BIO_puts := nil;
  BIO_indent := nil;
  BIO_ctrl := nil;
  BIO_callback_ctrl := nil;
  BIO_ptr_ctrl := nil;
  BIO_int_ctrl := nil;
  BIO_push := nil;
  BIO_pop := nil;
  BIO_free_all := nil;
  BIO_find_type := nil;
  BIO_next := nil;
  BIO_set_next := nil;
  BIO_get_retry_BIO := nil;
  BIO_get_retry_reason := nil;
  BIO_set_retry_reason := nil;
  BIO_dup_chain := nil;
  BIO_nread0 := nil;
  BIO_nread := nil;
  BIO_nwrite0 := nil;
  BIO_nwrite := nil;
  BIO_debug_callback := nil;
  BIO_s_mem := nil;
  BIO_s_secmem := nil;
  BIO_new_mem_buf := nil;
  BIO_s_socket := nil;
  BIO_s_connect := nil;
  BIO_s_accept := nil;
  BIO_s_fd := nil;
  BIO_s_log := nil;
  BIO_s_bio := nil;
  BIO_s_null := nil;
  BIO_f_null := nil;
  BIO_f_buffer := nil;
  BIO_f_linebuffer := nil;
  BIO_f_nbio_test := nil;
  BIO_s_datagram := nil;
  BIO_dgram_non_fatal_error := nil;
  BIO_new_dgram := nil;
  BIO_sock_should_retry := nil;
  BIO_sock_non_fatal_error := nil;
  BIO_fd_should_retry := nil;
  BIO_fd_non_fatal_error := nil;
  BIO_dump := nil;
  BIO_dump_indent := nil;
  BIO_hex_string := nil;
  BIO_ADDR_new := nil;
  BIO_ADDR_rawmake := nil;
  BIO_ADDR_free := nil;
  BIO_ADDR_clear := nil;
  BIO_ADDR_family := nil;
  BIO_ADDR_rawaddress := nil;
  BIO_ADDR_rawport := nil;
  BIO_ADDR_hostname_string := nil;
  BIO_ADDR_service_string := nil;
  BIO_ADDR_path_string := nil;
  BIO_ADDRINFO_next := nil;
  BIO_ADDRINFO_family := nil;
  BIO_ADDRINFO_socktype := nil;
  BIO_ADDRINFO_protocol := nil;
  BIO_ADDRINFO_address := nil;
  BIO_ADDRINFO_free := nil;
  BIO_parse_hostserv := nil;
  BIO_lookup := nil;
  BIO_lookup_ex := nil;
  BIO_sock_error := nil;
  BIO_socket_ioctl := nil;
  BIO_socket_nbio := nil;
  BIO_sock_init := nil;
  BIO_set_tcp_ndelay := nil;
  BIO_sock_info := nil;
  BIO_socket := nil;
  BIO_connect := nil;
  BIO_bind := nil;
  BIO_listen := nil;
  BIO_accept_ex := nil;
  BIO_closesocket := nil;
  BIO_new_socket := nil;
  BIO_new_connect := nil;
  BIO_new_accept := nil;
  BIO_new_fd := nil;
  BIO_new_bio_pair := nil;
  BIO_copy_next_retry := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
