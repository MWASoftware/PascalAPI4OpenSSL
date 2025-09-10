(* This unit was generated from the source file ts.h2pas 
It should not be modified directly. All changes should be made to ts.h2pas
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


unit OpenSSL_ts;


interface

// Headers for OpenSSL 1.1.1
// ts.h


uses
  OpenSSLAPI,
  OpenSSL_asn1,
  OpenSSL_bio,
  OpenSSL_ossl_typ,
  OpenSSL_pkcs7,
  OpenSSL_rsa,
  OpenSSL_tserr,
  OpenSSL_x509,
  OpenSSL_x509v3;

const
  (* Possible values for status. *)
  TS_STATUS_GRANTED = 0;
  TS_STATUS_GRANTED_WITH_MODS = 1;
  TS_STATUS_REJECTION = 2;
  TS_STATUS_WAITING = 3;
  TS_STATUS_REVOCATION_WARNING = 4;
  TS_STATUS_REVOCATION_NOTIFICATION = 5;


  (* Possible values for failure_info. *)
  TS_INFO_BAD_ALG = 0;
  TS_INFO_BAD_REQUEST = 2;
  TS_INFO_BAD_DATA_FORMAT = 5;
  TS_INFO_TIME_NOT_AVAILABLE = 14;
  TS_INFO_UNACCEPTED_POLICY = 15;
  TS_INFO_UNACCEPTED_EXTENSION = 16;
  TS_INFO_ADD_INFO_NOT_AVAILABLE = 17;
  TS_INFO_SYSTEM_FAILURE = 25;

  (* Optional flags for response generation. *)

  (* Don't include the TSA name in response. *)
  TS_TSA_NAME = $01;

  (* Set ordering to true in response. *)
  TS_ORDERING = $02;

  (*
   * Include the signer certificate and the other specified certificates in
   * the ESS signing certificate attribute beside the PKCS7 signed data.
   * Only the signer certificates is included by default.
   *)
  TS_ESS_CERT_ID_CHAIN = $04;

  (* At most we accept usec precision. *)
  TS_MAX_CLOCK_PRECISION_DIGITS = 6;

  (* Maximum status message length *)
  TS_MAX_STATUS_LENGTH = 1024 * 1024;

  (* Verify the signer's certificate and the signature of the response. *)
  TS_VFY_SIGNATURE = TOpenSSL_C_UINT(1) shl 0;
  (* Verify the version number of the response. *)
  TS_VFY_VERSION = TOpenSSL_C_UINT(1) shl 1;
  (* Verify if the policy supplied by the user matches the policy of the TSA. *)
  TS_VFY_POLICY = TOpenSSL_C_UINT(1) shl 2;
  (*
   * Verify the message imprint provided by the user. This flag should not be
   * specified with TS_VFY_DATA.
   *)
  TS_VFY_IMPRINT = TOpenSSL_C_UINT(1) shl 3;
  (*
   * Verify the message imprint computed by the verify method from the user
   * provided data and the MD algorithm of the response. This flag should not
   * be specified with TS_VFY_IMPRINT.
   *)
  TS_VFY_DATA = TOpenSSL_C_UINT(1) shl 4;
  (* Verify the nonce value. *)
  TS_VFY_NONCE = TOpenSSL_C_UINT(1) shl 5;
  (* Verify if the TSA name field matches the signer certificate. *)
  TS_VFY_SIGNER = TOpenSSL_C_UINT(1) shl 6;
  (* Verify if the TSA name field equals to the user provided name. *)
  TS_VFY_TSA_NAME = TOpenSSL_C_UINT(1) shl 7;

  (* You can use the following convenience constants. *)
  TS_VFY_ALL_IMPRINT = TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY
    or TS_VFY_IMPRINT or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME;

  TS_VFY_ALL_DATA = TS_VFY_SIGNATURE or TS_VFY_VERSION or TS_VFY_POLICY
    or TS_VFY_DATA or TS_VFY_NONCE or TS_VFY_SIGNER or TS_VFY_TSA_NAME;

type
  TS_msg_imprint_st = type Pointer;
  TS_req_st = type Pointer;
  TS_accuracy_st = type Pointer;
  TS_tst_info_st = type Pointer;

  TS_MSG_IMPRINT = TS_msg_imprint_st;
  PTS_MSG_IMPRINT = ^TS_MSG_IMPRINT;
  PPTS_MSG_IMPRINT = ^PTS_MSG_IMPRINT;

  TS_REQ = TS_req_st;
  PTS_REQ = ^TS_REQ;
  PPTS_REQ = ^PTS_REQ;

  TS_ACCURACY = TS_accuracy_st;
  PTS_ACCURACY = ^TS_ACCURACY;
  PPTS_ACCURACY = ^PTS_ACCURACY;

  TS_TST_INFO = TS_tst_info_st;
  PTS_TST_INFO = ^TS_TST_INFO;
  PPTS_TST_INFO = ^PTS_TST_INFO;

  TS_status_info_st = type Pointer;
  ESS_issuer_serial_st = type Pointer;
  ESS_cert_id_st = type Pointer;
  ESS_signing_cert_st = type Pointer;
  ESS_cert_id_v2_st = type Pointer;
  ESS_signing_cert_v2_st = type Pointer;

  TS_STATUS_INFO = TS_status_info_st;
  PTS_STATUS_INFO = ^TS_STATUS_INFO;
  PPTS_STATUS_INFO = ^PTS_STATUS_INFO;

  ESS_ISSUER_SERIAL = ESS_issuer_serial_st;
  PESS_ISSUER_SERIAL = ^ESS_ISSUER_SERIAL;
  PPESS_ISSUER_SERIAL = ^PESS_ISSUER_SERIAL;

  ESS_CERT_ID = ESS_cert_id_st;
  PESS_CERT_ID = ^ESS_CERT_ID;
  PPESS_CERT_ID = ^PESS_CERT_ID;

  ESS_SIGNING_CERT = ESS_signing_cert_st;
  PESS_SIGNING_CERT = ^ESS_SIGNING_CERT;
  PPESS_SIGNING_CERT = ^PESS_SIGNING_CERT;

// DEFINE_STACK_OF(ESS_CERT_ID)

  ESS_CERT_ID_V2 = ESS_cert_id_v2_st;
  PESS_CERT_ID_V2 = ^ESS_CERT_ID_V2;
  PPESS_CERT_ID_V2 = ^PESS_CERT_ID_V2;

  ESS_SIGNING_CERT_V2 = ESS_signing_cert_v2_st;
  PESS_SIGNING_CERT_V2 = ^ESS_SIGNING_CERT_V2;
  PPESS_SIGNING_CERT_V2 = ^PESS_SIGNING_CERT_V2;

// DEFINE_STACK_OF(ESS_CERT_ID_V2)
  TS_resp_st = type Pointer;
  TS_RESP = TS_resp_st;
  PTS_RESP = ^TS_RESP;
  PPTS_RESP = ^PTS_RESP;

  (* Forward declaration. *)
  TS_resp_ctx = type Pointer;
  PTS_resp_ctx = ^TS_resp_ctx;
  PPTS_resp_ctx = ^PTS_resp_ctx;

  (* This must return a unique number less than 160 bits long. *)
  TS_serial_cb = function({struct} v1: PTS_resp_ctx; v2: Pointer): PASN1_INTEGER;

  (*
   * This must return the seconds and microseconds since Jan 1, 1970 in the sec
   * and usec variables allocated by the caller. Return non-zero for success
   * and zero for failure.
   *)
  TS_time_cb = function({struct} v1: PTS_resp_ctx; v2: Pointer; sec: POpenSSL_C_LONG; usec: POpenSSL_C_LONG): TOpenSSL_C_INT;

  (*
   * This must process the given extension. It can modify the TS_TST_INFO
   * object of the context. Return values: !0 (processed), 0 (error, it must
   * set the status info/failure info of the response).
   *)
  TS_extension_cb = function({struct} v1: PTS_resp_ctx; v2: PX509_Extension; v3: Pointer): TOpenSSL_C_INT;

//  TS_VERIFY_CTX = TS_verify_ctx;
  TS_VERIFY_CTX = type Pointer;
  PTS_VERIFY_CTX = ^TS_VERIFY_CTX;

  
{ The EXTERNALSYM directive is ignored by FPC, however, it is used by Delphi as follows: 

The EXTERNALSYM directive prevents the specified Delphi symbol from appearing in header 
files generated for C++. }

{$EXTERNALSYM TS_REQ_new}
{$EXTERNALSYM TS_REQ_free}
{$EXTERNALSYM i2d_TS_REQ}
{$EXTERNALSYM d2i_TS_REQ}
{$EXTERNALSYM TS_REQ_dup}
{$EXTERNALSYM d2i_TS_REQ_bio}
{$EXTERNALSYM i2d_TS_REQ_bio}
{$EXTERNALSYM TS_MSG_IMPRINT_new}
{$EXTERNALSYM TS_MSG_IMPRINT_free}
{$EXTERNALSYM i2d_TS_MSG_IMPRINT}
{$EXTERNALSYM d2i_TS_MSG_IMPRINT}
{$EXTERNALSYM TS_MSG_IMPRINT_dup}
{$EXTERNALSYM d2i_TS_MSG_IMPRINT_bio}
{$EXTERNALSYM i2d_TS_MSG_IMPRINT_bio}
{$EXTERNALSYM TS_RESP_new}
{$EXTERNALSYM TS_RESP_free}
{$EXTERNALSYM i2d_TS_RESP}
{$EXTERNALSYM d2i_TS_RESP}
{$EXTERNALSYM PKCS7_to_TS_TST_INFO}
{$EXTERNALSYM TS_RESP_dup}
{$EXTERNALSYM d2i_TS_RESP_bio}
{$EXTERNALSYM i2d_TS_RESP_bio}
{$EXTERNALSYM TS_STATUS_INFO_new}
{$EXTERNALSYM TS_STATUS_INFO_free}
{$EXTERNALSYM i2d_TS_STATUS_INFO}
{$EXTERNALSYM d2i_TS_STATUS_INFO}
{$EXTERNALSYM TS_STATUS_INFO_dup}
{$EXTERNALSYM TS_TST_INFO_new}
{$EXTERNALSYM TS_TST_INFO_free}
{$EXTERNALSYM i2d_TS_TST_INFO}
{$EXTERNALSYM d2i_TS_TST_INFO}
{$EXTERNALSYM TS_TST_INFO_dup}
{$EXTERNALSYM d2i_TS_TST_INFO_bio}
{$EXTERNALSYM i2d_TS_TST_INFO_bio}
{$EXTERNALSYM TS_ACCURACY_new}
{$EXTERNALSYM TS_ACCURACY_free}
{$EXTERNALSYM i2d_TS_ACCURACY}
{$EXTERNALSYM d2i_TS_ACCURACY}
{$EXTERNALSYM TS_ACCURACY_dup}
{$EXTERNALSYM ESS_ISSUER_SERIAL_new}
{$EXTERNALSYM ESS_ISSUER_SERIAL_free}
{$EXTERNALSYM i2d_ESS_ISSUER_SERIAL}
{$EXTERNALSYM d2i_ESS_ISSUER_SERIAL}
{$EXTERNALSYM ESS_ISSUER_SERIAL_dup}
{$EXTERNALSYM ESS_CERT_ID_new}
{$EXTERNALSYM ESS_CERT_ID_free}
{$EXTERNALSYM i2d_ESS_CERT_ID}
{$EXTERNALSYM d2i_ESS_CERT_ID}
{$EXTERNALSYM ESS_CERT_ID_dup}
{$EXTERNALSYM ESS_SIGNING_CERT_new}
{$EXTERNALSYM ESS_SIGNING_CERT_free}
{$EXTERNALSYM i2d_ESS_SIGNING_CERT}
{$EXTERNALSYM d2i_ESS_SIGNING_CERT}
{$EXTERNALSYM ESS_SIGNING_CERT_dup}
{$EXTERNALSYM ESS_CERT_ID_V2_new}
{$EXTERNALSYM ESS_CERT_ID_V2_free}
{$EXTERNALSYM i2d_ESS_CERT_ID_V2}
{$EXTERNALSYM d2i_ESS_CERT_ID_V2}
{$EXTERNALSYM ESS_CERT_ID_V2_dup}
{$EXTERNALSYM ESS_SIGNING_CERT_V2_new}
{$EXTERNALSYM ESS_SIGNING_CERT_V2_free}
{$EXTERNALSYM i2d_ESS_SIGNING_CERT_V2}
{$EXTERNALSYM d2i_ESS_SIGNING_CERT_V2}
{$EXTERNALSYM ESS_SIGNING_CERT_V2_dup}
{$EXTERNALSYM TS_REQ_set_version}
{$EXTERNALSYM TS_REQ_get_version}
{$EXTERNALSYM TS_STATUS_INFO_set_status}
{$EXTERNALSYM TS_STATUS_INFO_get0_status}
{$EXTERNALSYM TS_REQ_set_msg_imprint}
{$EXTERNALSYM TS_REQ_get_msg_imprint}
{$EXTERNALSYM TS_MSG_IMPRINT_set_algo}
{$EXTERNALSYM TS_MSG_IMPRINT_get_algo}
{$EXTERNALSYM TS_MSG_IMPRINT_set_msg}
{$EXTERNALSYM TS_MSG_IMPRINT_get_msg}
{$EXTERNALSYM TS_REQ_set_policy_id}
{$EXTERNALSYM TS_REQ_get_policy_id}
{$EXTERNALSYM TS_REQ_set_nonce}
{$EXTERNALSYM TS_REQ_get_nonce}
{$EXTERNALSYM TS_REQ_set_cert_req}
{$EXTERNALSYM TS_REQ_get_cert_req}
{$EXTERNALSYM TS_REQ_ext_free}
{$EXTERNALSYM TS_REQ_get_ext_count}
{$EXTERNALSYM TS_REQ_get_ext_by_NID}
{$EXTERNALSYM TS_REQ_get_ext_by_OBJ}
{$EXTERNALSYM TS_REQ_get_ext_by_critical}
{$EXTERNALSYM TS_REQ_get_ext}
{$EXTERNALSYM TS_REQ_delete_ext}
{$EXTERNALSYM TS_REQ_add_ext}
{$EXTERNALSYM TS_REQ_get_ext_d2i}
{$EXTERNALSYM TS_REQ_print_bio}
{$EXTERNALSYM TS_RESP_set_status_info}
{$EXTERNALSYM TS_RESP_get_status_info}
{$EXTERNALSYM TS_RESP_set_tst_info}
{$EXTERNALSYM TS_RESP_get_token}
{$EXTERNALSYM TS_RESP_get_tst_info}
{$EXTERNALSYM TS_TST_INFO_set_version}
{$EXTERNALSYM TS_TST_INFO_get_version}
{$EXTERNALSYM TS_TST_INFO_set_policy_id}
{$EXTERNALSYM TS_TST_INFO_get_policy_id}
{$EXTERNALSYM TS_TST_INFO_set_msg_imprint}
{$EXTERNALSYM TS_TST_INFO_get_msg_imprint}
{$EXTERNALSYM TS_TST_INFO_set_serial}
{$EXTERNALSYM TS_TST_INFO_get_serial}
{$EXTERNALSYM TS_TST_INFO_set_time}
{$EXTERNALSYM TS_TST_INFO_get_time}
{$EXTERNALSYM TS_TST_INFO_set_accuracy}
{$EXTERNALSYM TS_TST_INFO_get_accuracy}
{$EXTERNALSYM TS_ACCURACY_set_seconds}
{$EXTERNALSYM TS_ACCURACY_get_seconds}
{$EXTERNALSYM TS_ACCURACY_set_millis}
{$EXTERNALSYM TS_ACCURACY_get_millis}
{$EXTERNALSYM TS_ACCURACY_set_micros}
{$EXTERNALSYM TS_ACCURACY_get_micros}
{$EXTERNALSYM TS_TST_INFO_set_ordering}
{$EXTERNALSYM TS_TST_INFO_get_ordering}
{$EXTERNALSYM TS_TST_INFO_set_nonce}
{$EXTERNALSYM TS_TST_INFO_get_nonce}
{$EXTERNALSYM TS_TST_INFO_set_tsa}
{$EXTERNALSYM TS_TST_INFO_get_tsa}
{$EXTERNALSYM TS_TST_INFO_ext_free}
{$EXTERNALSYM TS_TST_INFO_get_ext_count}
{$EXTERNALSYM TS_TST_INFO_get_ext_by_NID}
{$EXTERNALSYM TS_TST_INFO_get_ext_by_OBJ}
{$EXTERNALSYM TS_TST_INFO_get_ext_by_critical}
{$EXTERNALSYM TS_TST_INFO_get_ext}
{$EXTERNALSYM TS_TST_INFO_delete_ext}
{$EXTERNALSYM TS_TST_INFO_add_ext}
{$EXTERNALSYM TS_TST_INFO_get_ext_d2i}
{$EXTERNALSYM TS_RESP_CTX_new}
{$EXTERNALSYM TS_RESP_CTX_free}
{$EXTERNALSYM TS_RESP_CTX_set_signer_cert}
{$EXTERNALSYM TS_RESP_CTX_set_signer_key}
{$EXTERNALSYM TS_RESP_CTX_set_signer_digest}
{$EXTERNALSYM TS_RESP_CTX_set_ess_cert_id_digest}
{$EXTERNALSYM TS_RESP_CTX_set_def_policy}
{$EXTERNALSYM TS_RESP_CTX_add_policy}
{$EXTERNALSYM TS_RESP_CTX_add_md}
{$EXTERNALSYM TS_RESP_CTX_set_accuracy}
{$EXTERNALSYM TS_RESP_CTX_set_clock_precision_digits}
{$EXTERNALSYM TS_RESP_CTX_add_flags}
{$EXTERNALSYM TS_RESP_CTX_set_serial_cb}
{$EXTERNALSYM TS_RESP_CTX_set_time_cb}
{$EXTERNALSYM TS_RESP_CTX_set_extension_cb}
{$EXTERNALSYM TS_RESP_CTX_set_status_info}
{$EXTERNALSYM TS_RESP_CTX_set_status_info_cond}
{$EXTERNALSYM TS_RESP_CTX_add_failure_info}
{$EXTERNALSYM TS_RESP_CTX_get_request}
{$EXTERNALSYM TS_RESP_CTX_get_tst_info}
{$EXTERNALSYM TS_RESP_create_response}
{$EXTERNALSYM TS_RESP_verify_response}
{$EXTERNALSYM TS_RESP_verify_token}
{$EXTERNALSYM TS_VERIFY_CTX_new}
{$EXTERNALSYM TS_VERIFY_CTX_init}
{$EXTERNALSYM TS_VERIFY_CTX_free}
{$EXTERNALSYM TS_VERIFY_CTX_cleanup}
{$EXTERNALSYM TS_VERIFY_CTX_set_flags}
{$EXTERNALSYM TS_VERIFY_CTX_add_flags}
{$EXTERNALSYM TS_VERIFY_CTX_set_data}
{$EXTERNALSYM TS_VERIFY_CTX_set_imprint}
{$EXTERNALSYM TS_VERIFY_CTX_set_store}
{$EXTERNALSYM TS_REQ_to_TS_VERIFY_CTX}
{$EXTERNALSYM TS_RESP_print_bio}
{$EXTERNALSYM TS_STATUS_INFO_print_bio}
{$EXTERNALSYM TS_TST_INFO_print_bio}
{$EXTERNALSYM TS_ASN1_INTEGER_print_bio}
{$EXTERNALSYM TS_OBJ_print_bio}
{$EXTERNALSYM TS_X509_ALGOR_print_bio}
{$EXTERNALSYM TS_MSG_IMPRINT_print_bio}
{$EXTERNALSYM TS_CONF_load_cert}
{$EXTERNALSYM TS_CONF_load_key}
{$EXTERNALSYM TS_CONF_set_serial}
{$EXTERNALSYM TS_CONF_get_tsa_section}
{$EXTERNALSYM TS_CONF_set_crypto_device}
{$EXTERNALSYM TS_CONF_set_default_engine}
{$EXTERNALSYM TS_CONF_set_signer_cert}
{$EXTERNALSYM TS_CONF_set_certs}
{$EXTERNALSYM TS_CONF_set_signer_key}
{$EXTERNALSYM TS_CONF_set_signer_digest}
{$EXTERNALSYM TS_CONF_set_def_policy}
{$EXTERNALSYM TS_CONF_set_policies}
{$EXTERNALSYM TS_CONF_set_digests}
{$EXTERNALSYM TS_CONF_set_accuracy}
{$EXTERNALSYM TS_CONF_set_clock_precision_digits}
{$EXTERNALSYM TS_CONF_set_ordering}
{$EXTERNALSYM TS_CONF_set_tsa_name}
{$EXTERNALSYM TS_CONF_set_ess_cert_id_chain}
{$EXTERNALSYM TS_CONF_set_ess_cert_id_digest}

{$IFDEF OPENSSL_STATIC_LINK_MODEL}
function TS_REQ_new: PTS_REQ; cdecl; external CLibCrypto;
procedure TS_REQ_free(a: PTS_REQ); cdecl; external CLibCrypto;
function i2d_TS_REQ(a: PTS_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_REQ(a: PPTS_REQ; pp: PPByte; length: TOpenSSL_C_LONG): PTS_REQ; cdecl; external CLibCrypto;
function TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl; external CLibCrypto;
function d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl; external CLibCrypto;
function i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
procedure TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl; external CLibCrypto;
function i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; pp: PPByte; length: TOpenSSL_C_LONG): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_new: PTS_RESP; cdecl; external CLibCrypto;
procedure TS_RESP_free(a: PTS_RESP); cdecl; external CLibCrypto;
function i2d_TS_RESP(a: PTS_RESP; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_RESP(a: PPTS_RESP; pp: PPByte; length: TOpenSSL_C_LONG): PTS_RESP; cdecl; external CLibCrypto;
function PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl; external CLibCrypto;
function d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl; external CLibCrypto;
function i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl; external CLibCrypto;
procedure TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl; external CLibCrypto;
function i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; pp: PPByte; length: TOpenSSL_C_LONG): PTS_STATUS_INFO; cdecl; external CLibCrypto;
function TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl; external CLibCrypto;
function TS_TST_INFO_new: PTS_TST_Info; cdecl; external CLibCrypto;
procedure TS_TST_INFO_free(a: PTS_TST_Info); cdecl; external CLibCrypto;
function i2d_TS_TST_INFO(a: PTS_TST_Info; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_TST_INFO(a: PPTS_TST_Info; pp: PPByte; length: TOpenSSL_C_LONG): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_TST_INFO_dup(a: PTS_TST_Info): PTS_TST_Info; cdecl; external CLibCrypto;
function d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl; external CLibCrypto;
function i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_new: PTS_ACCURACY; cdecl; external CLibCrypto;
procedure TS_ACCURACY_free(a: PTS_ACCURACY); cdecl; external CLibCrypto;
function i2d_TS_ACCURACY(a: PTS_ACCURACY; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_TS_ACCURACY(a: PPTS_ACCURACY; pp: PPByte; length: TOpenSSL_C_LONG): PTS_ACCURACY; cdecl; external CLibCrypto;
function TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl; external CLibCrypto;
function ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl; external CLibCrypto;
procedure ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl; external CLibCrypto;
function i2d_ESS_ISSUER_SERIAL( a: PESS_ISSUER_SERIAL; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; pp: PPByte; length: TOpenSSL_C_LONG): PESS_ISSUER_SERIAL; cdecl; external CLibCrypto;
function ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl; external CLibCrypto;
function ESS_CERT_ID_new: PESS_CERT_ID; cdecl; external CLibCrypto;
procedure ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl; external CLibCrypto;
function i2d_ESS_CERT_ID(a: PESS_CERT_ID; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_CERT_ID(a: PPESS_CERT_ID; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID; cdecl; external CLibCrypto;
function ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_new: PESS_SIGNING_Cert; cdecl; external CLibCrypto;
procedure ESS_SIGNING_CERT_free(a: PESS_SIGNING_Cert); cdecl; external CLibCrypto;
function i2d_ESS_SIGNING_CERT( a: PESS_SIGNING_Cert; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_Cert; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_Cert; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_dup(a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl; external CLibCrypto;
function ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl; external CLibCrypto;
procedure ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl; external CLibCrypto;
function i2d_ESS_CERT_ID_V2( a: PESS_CERT_ID_V2; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID_V2; cdecl; external CLibCrypto;
function ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl; external CLibCrypto;
procedure ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl; external CLibCrypto;
function i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; pp: PPByte): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_CERT_V2; cdecl; external CLibCrypto;
function ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl; external CLibCrypto;
function TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_STATUS_INFO_get0_status(const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl; external CLibCrypto;
function TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl; external CLibCrypto;
function TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_nonce(const a: PTS_REQ): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure TS_REQ_ext_free(a: PTS_REQ); cdecl; external CLibCrypto;
function TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_REQ_add_ext(a: PTS_REQ; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl; external CLibCrypto;
procedure TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl; external CLibCrypto;
function TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl; external CLibCrypto;
function TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_TST_INFO_set_version(a: PTS_TST_Info; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_version(const a: PTS_TST_Info): TOpenSSL_C_LONG; cdecl; external CLibCrypto;
function TS_TST_INFO_set_policy_id(a: PTS_TST_Info; policy_id: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_policy_id(a: PTS_TST_Info): PASN1_Object; cdecl; external CLibCrypto;
function TS_TST_INFO_set_msg_imprint(a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_msg_imprint(a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl; external CLibCrypto;
function TS_TST_INFO_set_serial(a: PTS_TST_Info; const serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_serial(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_TST_INFO_set_time(a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_time(const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl; external CLibCrypto;
function TS_TST_INFO_set_accuracy(a: PTS_TST_Info; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_accuracy(a: PTS_TST_Info): PTS_ACCURACY; cdecl; external CLibCrypto;
function TS_ACCURACY_set_seconds(a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_get_seconds(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_ACCURACY_set_millis(a: PTS_ACCURACY; const millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_get_millis(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_ACCURACY_set_micros(a: PTS_ACCURACY; const micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ACCURACY_get_micros(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_TST_INFO_set_ordering(a: PTS_TST_Info; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ordering(const a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_set_nonce(a: PTS_TST_Info; const nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_nonce(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl; external CLibCrypto;
function TS_TST_INFO_set_tsa(a: PTS_TST_Info; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_tsa(a: PTS_TST_Info): PGENERAL_NAME; cdecl; external CLibCrypto;
procedure TS_TST_INFO_ext_free(a: PTS_TST_Info); cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_count(a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_by_NID(a: PTS_TST_Info; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_by_critical(a: PTS_TST_Info; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_TST_INFO_delete_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl; external CLibCrypto;
function TS_TST_INFO_add_ext(a: PTS_TST_Info; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_get_ext_d2i(a: PTS_TST_Info; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl; external CLibCrypto;
function TS_RESP_CTX_new: PTS_RESP_CTX; cdecl; external CLibCrypto;
procedure TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl; external CLibCrypto;
function TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; const policy: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; const md: PEVP_MD): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
procedure TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl; external CLibCrypto;
procedure TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl; external CLibCrypto;
procedure TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl; external CLibCrypto;
procedure TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl; external CLibCrypto;
function TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl; external CLibCrypto;
function TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl; external CLibCrypto;
function TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl; external CLibCrypto;
function TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl; external CLibCrypto;
procedure TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto;
procedure TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto;
procedure TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TOpenSSL_C_LONG): PByte; cdecl; external CLibCrypto;
function TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl; external CLibCrypto;
function TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl; external CLibCrypto;
function TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_ASN1_INTEGER_print_bio(bio: PBIO; const num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_OBJ_print_bio(bio: PBIO; const obj: PASN1_Object): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_X509_ALGOR_print_bio(bio: PBIO; const alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl; external CLibCrypto;
function TS_CONF_load_key( file_: PAnsiChar; pass: PAnsiChar): PEVP_PKey; cdecl; external CLibCrypto;
function TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_get_tsa_section(conf: PCONF; const section: PAnsiChar): PAnsiChar; cdecl; external CLibCrypto;
function TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_signer_key(conf: PCONF; const section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;
function TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl; external CLibCrypto;

{$ELSE}
var
  TS_REQ_new: function : PTS_REQ; cdecl = nil;
  TS_REQ_free: procedure (a: PTS_REQ); cdecl = nil;
  i2d_TS_REQ: function (a: PTS_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_TS_REQ: function (a: PPTS_REQ; pp: PPByte; length: TOpenSSL_C_LONG): PTS_REQ; cdecl = nil;
  TS_REQ_dup: function (a: PTS_REQ): PTS_REQ; cdecl = nil;
  d2i_TS_REQ_bio: function (fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl = nil;
  i2d_TS_REQ_bio: function (fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl = nil;
  TS_MSG_IMPRINT_new: function : PTS_MSG_IMPRINT; cdecl = nil;
  TS_MSG_IMPRINT_free: procedure (a: PTS_MSG_IMPRINT); cdecl = nil;
  i2d_TS_MSG_IMPRINT: function (a: PTS_MSG_IMPRINT; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_TS_MSG_IMPRINT: function (a: PPTS_MSG_IMPRINT; pp: PPByte; length: TOpenSSL_C_LONG): PTS_MSG_IMPRINT; cdecl = nil;
  TS_MSG_IMPRINT_dup: function (a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = nil;
  d2i_TS_MSG_IMPRINT_bio: function (bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl = nil;
  i2d_TS_MSG_IMPRINT_bio: function (bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_new: function : PTS_RESP; cdecl = nil;
  TS_RESP_free: procedure (a: PTS_RESP); cdecl = nil;
  i2d_TS_RESP: function (a: PTS_RESP; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_TS_RESP: function (a: PPTS_RESP; pp: PPByte; length: TOpenSSL_C_LONG): PTS_RESP; cdecl = nil;
  PKCS7_to_TS_TST_INFO: function (token: PPKCS7): PTS_TST_Info; cdecl = nil;
  TS_RESP_dup: function (a: PTS_RESP): PTS_RESP; cdecl = nil;
  d2i_TS_RESP_bio: function (bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl = nil;
  i2d_TS_RESP_bio: function (bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl = nil;
  TS_STATUS_INFO_new: function : PTS_STATUS_INFO; cdecl = nil;
  TS_STATUS_INFO_free: procedure (a: PTS_STATUS_INFO); cdecl = nil;
  i2d_TS_STATUS_INFO: function (a: PTS_STATUS_INFO; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_TS_STATUS_INFO: function (a: PPTS_STATUS_INFO; pp: PPByte; length: TOpenSSL_C_LONG): PTS_STATUS_INFO; cdecl = nil;
  TS_STATUS_INFO_dup: function (a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl = nil;
  TS_TST_INFO_new: function : PTS_TST_Info; cdecl = nil;
  TS_TST_INFO_free: procedure (a: PTS_TST_Info); cdecl = nil;
  i2d_TS_TST_INFO: function (a: PTS_TST_Info; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_TS_TST_INFO: function (a: PPTS_TST_Info; pp: PPByte; length: TOpenSSL_C_LONG): PTS_TST_Info; cdecl = nil;
  TS_TST_INFO_dup: function (a: PTS_TST_Info): PTS_TST_Info; cdecl = nil;
  d2i_TS_TST_INFO_bio: function (bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl = nil;
  i2d_TS_TST_INFO_bio: function (bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = nil;
  TS_ACCURACY_new: function : PTS_ACCURACY; cdecl = nil;
  TS_ACCURACY_free: procedure (a: PTS_ACCURACY); cdecl = nil;
  i2d_TS_ACCURACY: function (a: PTS_ACCURACY; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_TS_ACCURACY: function (a: PPTS_ACCURACY; pp: PPByte; length: TOpenSSL_C_LONG): PTS_ACCURACY; cdecl = nil;
  TS_ACCURACY_dup: function (a: PTS_ACCURACY): PTS_ACCURACY; cdecl = nil;
  ESS_ISSUER_SERIAL_new: function : PESS_ISSUER_SERIAL; cdecl = nil;
  ESS_ISSUER_SERIAL_free: procedure (a: PESS_ISSUER_SERIAL); cdecl = nil;
  i2d_ESS_ISSUER_SERIAL: function ( a: PESS_ISSUER_SERIAL; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_ESS_ISSUER_SERIAL: function (a: PPESS_ISSUER_SERIAL; pp: PPByte; length: TOpenSSL_C_LONG): PESS_ISSUER_SERIAL; cdecl = nil;
  ESS_ISSUER_SERIAL_dup: function (a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl = nil;
  ESS_CERT_ID_new: function : PESS_CERT_ID; cdecl = nil;
  ESS_CERT_ID_free: procedure (a: PESS_CERT_ID); cdecl = nil;
  i2d_ESS_CERT_ID: function (a: PESS_CERT_ID; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_ESS_CERT_ID: function (a: PPESS_CERT_ID; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID; cdecl = nil;
  ESS_CERT_ID_dup: function (a: PESS_CERT_ID): PESS_CERT_ID; cdecl = nil;
  ESS_SIGNING_CERT_new: function : PESS_SIGNING_Cert; cdecl = nil;
  ESS_SIGNING_CERT_free: procedure (a: PESS_SIGNING_Cert); cdecl = nil;
  i2d_ESS_SIGNING_CERT: function ( a: PESS_SIGNING_Cert; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_ESS_SIGNING_CERT: function (a: PPESS_SIGNING_Cert; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_Cert; cdecl = nil;
  ESS_SIGNING_CERT_dup: function (a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl = nil;
  ESS_CERT_ID_V2_new: function : PESS_CERT_ID_V2; cdecl = nil;
  ESS_CERT_ID_V2_free: procedure (a: PESS_CERT_ID_V2); cdecl = nil;
  i2d_ESS_CERT_ID_V2: function ( a: PESS_CERT_ID_V2; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_ESS_CERT_ID_V2: function (a: PPESS_CERT_ID_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID_V2; cdecl = nil;
  ESS_CERT_ID_V2_dup: function (a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl = nil;
  ESS_SIGNING_CERT_V2_new: function : PESS_SIGNING_CERT_V2; cdecl = nil;
  ESS_SIGNING_CERT_V2_free: procedure (a: PESS_SIGNING_CERT_V2); cdecl = nil;
  i2d_ESS_SIGNING_CERT_V2: function (a: PESS_SIGNING_CERT_V2; pp: PPByte): TOpenSSL_C_INT; cdecl = nil;
  d2i_ESS_SIGNING_CERT_V2: function (a: PPESS_SIGNING_CERT_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_CERT_V2; cdecl = nil;
  ESS_SIGNING_CERT_V2_dup: function (a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl = nil;
  TS_REQ_set_version: function (a: PTS_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_version: function (a: PTS_REQ): TOpenSSL_C_LONG; cdecl = nil;
  TS_STATUS_INFO_set_status: function (a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_STATUS_INFO_get0_status: function (const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl = nil;
  TS_REQ_set_msg_imprint: function (a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_msg_imprint: function (a: PTS_REQ): PTS_MSG_IMPRINT; cdecl = nil;
  TS_MSG_IMPRINT_set_algo: function (a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl = nil;
  TS_MSG_IMPRINT_get_algo: function (a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl = nil;
  TS_MSG_IMPRINT_set_msg: function (a: PTS_MSG_IMPRINT; d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_MSG_IMPRINT_get_msg: function (a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl = nil;
  TS_REQ_set_policy_id: function (a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_policy_id: function (a: PTS_REQ): PASN1_OBJECT; cdecl = nil;
  TS_REQ_set_nonce: function (a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_nonce: function (const a: PTS_REQ): PASN1_INTEGER; cdecl = nil;
  TS_REQ_set_cert_req: function (a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_cert_req: function (a: PTS_REQ): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_ext_free: procedure (a: PTS_REQ); cdecl = nil;
  TS_REQ_get_ext_count: function (a: PTS_REQ): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_ext_by_NID: function (a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_ext_by_OBJ: function (a: PTS_REQ; obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_ext_by_critical: function (a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_ext: function (a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = nil;
  TS_REQ_delete_ext: function (a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = nil;
  TS_REQ_add_ext: function (a: PTS_REQ; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_REQ_get_ext_d2i: function (a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = nil;
  TS_REQ_print_bio: function (bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_set_status_info: function (a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_get_status_info: function (a: PTS_RESP): PTS_STATUS_INFO; cdecl = nil;
  TS_RESP_set_tst_info: procedure (a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl = nil;
  TS_RESP_get_token: function (a: PTS_RESP): PPKCS7; cdecl = nil;
  TS_RESP_get_tst_info: function (a: PTS_RESP): PTS_TST_Info; cdecl = nil;
  TS_TST_INFO_set_version: function (a: PTS_TST_Info; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_version: function (const a: PTS_TST_Info): TOpenSSL_C_LONG; cdecl = nil;
  TS_TST_INFO_set_policy_id: function (a: PTS_TST_Info; policy_id: PASN1_Object): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_policy_id: function (a: PTS_TST_Info): PASN1_Object; cdecl = nil;
  TS_TST_INFO_set_msg_imprint: function (a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_msg_imprint: function (a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl = nil;
  TS_TST_INFO_set_serial: function (a: PTS_TST_Info; const serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_serial: function (const a: PTS_TST_INFO): PASN1_INTEGER; cdecl = nil;
  TS_TST_INFO_set_time: function (a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_time: function (const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl = nil;
  TS_TST_INFO_set_accuracy: function (a: PTS_TST_Info; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_accuracy: function (a: PTS_TST_Info): PTS_ACCURACY; cdecl = nil;
  TS_ACCURACY_set_seconds: function (a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  TS_ACCURACY_get_seconds: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = nil;
  TS_ACCURACY_set_millis: function (a: PTS_ACCURACY; const millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  TS_ACCURACY_get_millis: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = nil;
  TS_ACCURACY_set_micros: function (a: PTS_ACCURACY; const micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  TS_ACCURACY_get_micros: function (const a: PTS_ACCURACY): PASN1_INTEGER; cdecl = nil;
  TS_TST_INFO_set_ordering: function (a: PTS_TST_Info; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_ordering: function (const a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_set_nonce: function (a: PTS_TST_Info; const nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_nonce: function (const a: PTS_TST_INFO): PASN1_INTEGER; cdecl = nil;
  TS_TST_INFO_set_tsa: function (a: PTS_TST_Info; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_tsa: function (a: PTS_TST_Info): PGENERAL_NAME; cdecl = nil;
  TS_TST_INFO_ext_free: procedure (a: PTS_TST_Info); cdecl = nil;
  TS_TST_INFO_get_ext_count: function (a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_ext_by_NID: function (a: PTS_TST_Info; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_ext_by_OBJ: function (a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_ext_by_critical: function (a: PTS_TST_Info; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_ext: function (a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = nil;
  TS_TST_INFO_delete_ext: function (a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl = nil;
  TS_TST_INFO_add_ext: function (a: PTS_TST_Info; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_get_ext_d2i: function (a: PTS_TST_Info; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl = nil;
  TS_RESP_CTX_new: function : PTS_RESP_CTX; cdecl = nil;
  TS_RESP_CTX_free: procedure (ctx: PTS_RESP_CTX); cdecl = nil;
  TS_RESP_CTX_set_signer_cert: function (ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_set_signer_key: function (ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_set_signer_digest: function (ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_set_ess_cert_id_digest: function (ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_set_def_policy: function (ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_add_policy: function (ctx: PTS_RESP_CTX; const policy: PASN1_Object): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_add_md: function (ctx: PTS_RESP_CTX; const md: PEVP_MD): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_set_accuracy: function (ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_set_clock_precision_digits: function (ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_add_flags: procedure (ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl = nil;
  TS_RESP_CTX_set_serial_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl = nil;
  TS_RESP_CTX_set_time_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl = nil;
  TS_RESP_CTX_set_extension_cb: procedure (ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl = nil;
  TS_RESP_CTX_set_status_info: function (ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_set_status_info_cond: function (ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_add_failure_info: function (ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_CTX_get_request: function (ctx: PTS_RESP_CTX): PTS_REQ; cdecl = nil;
  TS_RESP_CTX_get_tst_info: function (ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl = nil;
  TS_RESP_create_response: function (ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl = nil;
  TS_RESP_verify_response: function (ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl = nil;
  TS_RESP_verify_token: function (ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl = nil;
  TS_VERIFY_CTX_new: function : PTS_VERIFY_CTX; cdecl = nil;
  TS_VERIFY_CTX_init: procedure (ctx: PTS_VERIFY_CTX); cdecl = nil;
  TS_VERIFY_CTX_free: procedure (ctx: PTS_VERIFY_CTX); cdecl = nil;
  TS_VERIFY_CTX_cleanup: procedure (ctx: PTS_VERIFY_CTX); cdecl = nil;
  TS_VERIFY_CTX_set_flags: function (ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_VERIFY_CTX_add_flags: function (ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl = nil;
  TS_VERIFY_CTX_set_data: function (ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl = nil;
  TS_VERIFY_CTX_set_imprint: function (ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TOpenSSL_C_LONG): PByte; cdecl = nil;
  TS_VERIFY_CTX_set_store: function (ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl = nil;
  TS_REQ_to_TS_VERIFY_CTX: function (req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl = nil;
  TS_RESP_print_bio: function (bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl = nil;
  TS_STATUS_INFO_print_bio: function (bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl = nil;
  TS_TST_INFO_print_bio: function (bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl = nil;
  TS_ASN1_INTEGER_print_bio: function (bio: PBIO; const num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl = nil;
  TS_OBJ_print_bio: function (bio: PBIO; const obj: PASN1_Object): TOpenSSL_C_INT; cdecl = nil;
  TS_X509_ALGOR_print_bio: function (bio: PBIO; const alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl = nil;
  TS_MSG_IMPRINT_print_bio: function (bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_load_cert: function (file_: PAnsiChar): PX509; cdecl = nil;
  TS_CONF_load_key: function ( file_: PAnsiChar; pass: PAnsiChar): PEVP_PKey; cdecl = nil;
  TS_CONF_set_serial: function (conf: PCONF; section: PAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_get_tsa_section: function (conf: PCONF; const section: PAnsiChar): PAnsiChar; cdecl = nil;
  TS_CONF_set_crypto_device: function (conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_default_engine: function (name: PAnsiChar): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_signer_cert: function (conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_certs: function (conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_signer_key: function (conf: PCONF; const section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_signer_digest: function (conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_def_policy: function (conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_policies: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_digests: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_accuracy: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_clock_precision_digits: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_ordering: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_tsa_name: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_ess_cert_id_chain: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
  TS_CONF_set_ess_cert_id_digest: function (conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl = nil;
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
function ERROR_TS_REQ_new: PTS_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_new');
end;

procedure ERROR_TS_REQ_free(a: PTS_REQ); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_free');
end;

function ERROR_i2d_TS_REQ(a: PTS_REQ; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_REQ');
end;

function ERROR_d2i_TS_REQ(a: PPTS_REQ; pp: PPByte; length: TOpenSSL_C_LONG): PTS_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_REQ');
end;

function ERROR_TS_REQ_dup(a: PTS_REQ): PTS_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_dup');
end;

function ERROR_d2i_TS_REQ_bio(fp: PBIO; a: PPTS_REQ): PTS_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_REQ_bio');
end;

function ERROR_i2d_TS_REQ_bio(fp: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_REQ_bio');
end;

function ERROR_TS_MSG_IMPRINT_new: PTS_MSG_IMPRINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_new');
end;

procedure ERROR_TS_MSG_IMPRINT_free(a: PTS_MSG_IMPRINT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_free');
end;

function ERROR_i2d_TS_MSG_IMPRINT(a: PTS_MSG_IMPRINT; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_MSG_IMPRINT');
end;

function ERROR_d2i_TS_MSG_IMPRINT(a: PPTS_MSG_IMPRINT; pp: PPByte; length: TOpenSSL_C_LONG): PTS_MSG_IMPRINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_MSG_IMPRINT');
end;

function ERROR_TS_MSG_IMPRINT_dup(a: PTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_dup');
end;

function ERROR_d2i_TS_MSG_IMPRINT_bio(bio: PBIO; a: PPTS_MSG_IMPRINT): PTS_MSG_IMPRINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_MSG_IMPRINT_bio');
end;

function ERROR_i2d_TS_MSG_IMPRINT_bio(bio: PBIO; a: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_MSG_IMPRINT_bio');
end;

function ERROR_TS_RESP_new: PTS_RESP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_new');
end;

procedure ERROR_TS_RESP_free(a: PTS_RESP); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_free');
end;

function ERROR_i2d_TS_RESP(a: PTS_RESP; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_RESP');
end;

function ERROR_d2i_TS_RESP(a: PPTS_RESP; pp: PPByte; length: TOpenSSL_C_LONG): PTS_RESP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_RESP');
end;

function ERROR_PKCS7_to_TS_TST_INFO(token: PPKCS7): PTS_TST_Info; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('PKCS7_to_TS_TST_INFO');
end;

function ERROR_TS_RESP_dup(a: PTS_RESP): PTS_RESP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_dup');
end;

function ERROR_d2i_TS_RESP_bio(bio: PBIO; a: PPTS_RESP): PTS_RESP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_RESP_bio');
end;

function ERROR_i2d_TS_RESP_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_RESP_bio');
end;

function ERROR_TS_STATUS_INFO_new: PTS_STATUS_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_new');
end;

procedure ERROR_TS_STATUS_INFO_free(a: PTS_STATUS_INFO); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_free');
end;

function ERROR_i2d_TS_STATUS_INFO(a: PTS_STATUS_INFO; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_STATUS_INFO');
end;

function ERROR_d2i_TS_STATUS_INFO(a: PPTS_STATUS_INFO; pp: PPByte; length: TOpenSSL_C_LONG): PTS_STATUS_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_STATUS_INFO');
end;

function ERROR_TS_STATUS_INFO_dup(a: PTS_STATUS_INFO): PTS_STATUS_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_dup');
end;

function ERROR_TS_TST_INFO_new: PTS_TST_Info; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_new');
end;

procedure ERROR_TS_TST_INFO_free(a: PTS_TST_Info); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_free');
end;

function ERROR_i2d_TS_TST_INFO(a: PTS_TST_Info; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_TST_INFO');
end;

function ERROR_d2i_TS_TST_INFO(a: PPTS_TST_Info; pp: PPByte; length: TOpenSSL_C_LONG): PTS_TST_Info; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_TST_INFO');
end;

function ERROR_TS_TST_INFO_dup(a: PTS_TST_Info): PTS_TST_Info; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_dup');
end;

function ERROR_d2i_TS_TST_INFO_bio(bio: PBIO; a: PPTS_TST_Info): PTS_TST_Info; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_TST_INFO_bio');
end;

function ERROR_i2d_TS_TST_INFO_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_TST_INFO_bio');
end;

function ERROR_TS_ACCURACY_new: PTS_ACCURACY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_new');
end;

procedure ERROR_TS_ACCURACY_free(a: PTS_ACCURACY); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_free');
end;

function ERROR_i2d_TS_ACCURACY(a: PTS_ACCURACY; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_TS_ACCURACY');
end;

function ERROR_d2i_TS_ACCURACY(a: PPTS_ACCURACY; pp: PPByte; length: TOpenSSL_C_LONG): PTS_ACCURACY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_TS_ACCURACY');
end;

function ERROR_TS_ACCURACY_dup(a: PTS_ACCURACY): PTS_ACCURACY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_dup');
end;

function ERROR_ESS_ISSUER_SERIAL_new: PESS_ISSUER_SERIAL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_ISSUER_SERIAL_new');
end;

procedure ERROR_ESS_ISSUER_SERIAL_free(a: PESS_ISSUER_SERIAL); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_ISSUER_SERIAL_free');
end;

function ERROR_i2d_ESS_ISSUER_SERIAL( a: PESS_ISSUER_SERIAL; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_ISSUER_SERIAL');
end;

function ERROR_d2i_ESS_ISSUER_SERIAL(a: PPESS_ISSUER_SERIAL; pp: PPByte; length: TOpenSSL_C_LONG): PESS_ISSUER_SERIAL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_ISSUER_SERIAL');
end;

function ERROR_ESS_ISSUER_SERIAL_dup(a: PESS_ISSUER_SERIAL): PESS_ISSUER_SERIAL; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_ISSUER_SERIAL_dup');
end;

function ERROR_ESS_CERT_ID_new: PESS_CERT_ID; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_new');
end;

procedure ERROR_ESS_CERT_ID_free(a: PESS_CERT_ID); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_free');
end;

function ERROR_i2d_ESS_CERT_ID(a: PESS_CERT_ID; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_CERT_ID');
end;

function ERROR_d2i_ESS_CERT_ID(a: PPESS_CERT_ID; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_CERT_ID');
end;

function ERROR_ESS_CERT_ID_dup(a: PESS_CERT_ID): PESS_CERT_ID; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_dup');
end;

function ERROR_ESS_SIGNING_CERT_new: PESS_SIGNING_Cert; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_new');
end;

procedure ERROR_ESS_SIGNING_CERT_free(a: PESS_SIGNING_Cert); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_free');
end;

function ERROR_i2d_ESS_SIGNING_CERT( a: PESS_SIGNING_Cert; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_SIGNING_CERT');
end;

function ERROR_d2i_ESS_SIGNING_CERT(a: PPESS_SIGNING_Cert; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_Cert; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_SIGNING_CERT');
end;

function ERROR_ESS_SIGNING_CERT_dup(a: PESS_SIGNING_Cert): PESS_SIGNING_Cert; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_dup');
end;

function ERROR_ESS_CERT_ID_V2_new: PESS_CERT_ID_V2; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_V2_new');
end;

procedure ERROR_ESS_CERT_ID_V2_free(a: PESS_CERT_ID_V2); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_V2_free');
end;

function ERROR_i2d_ESS_CERT_ID_V2( a: PESS_CERT_ID_V2; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_CERT_ID_V2');
end;

function ERROR_d2i_ESS_CERT_ID_V2(a: PPESS_CERT_ID_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_CERT_ID_V2; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_CERT_ID_V2');
end;

function ERROR_ESS_CERT_ID_V2_dup(a: PESS_CERT_ID_V2): PESS_CERT_ID_V2; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_CERT_ID_V2_dup');
end;

function ERROR_ESS_SIGNING_CERT_V2_new: PESS_SIGNING_CERT_V2; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_V2_new');
end;

procedure ERROR_ESS_SIGNING_CERT_V2_free(a: PESS_SIGNING_CERT_V2); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_V2_free');
end;

function ERROR_i2d_ESS_SIGNING_CERT_V2(a: PESS_SIGNING_CERT_V2; pp: PPByte): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('i2d_ESS_SIGNING_CERT_V2');
end;

function ERROR_d2i_ESS_SIGNING_CERT_V2(a: PPESS_SIGNING_CERT_V2; pp: PPByte; length: TOpenSSL_C_LONG): PESS_SIGNING_CERT_V2; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('d2i_ESS_SIGNING_CERT_V2');
end;

function ERROR_ESS_SIGNING_CERT_V2_dup(a: PESS_SIGNING_CERT_V2): PESS_SIGNING_CERT_V2; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('ESS_SIGNING_CERT_V2_dup');
end;

function ERROR_TS_REQ_set_version(a: PTS_REQ; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_version');
end;

function ERROR_TS_REQ_get_version(a: PTS_REQ): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_version');
end;

function ERROR_TS_STATUS_INFO_set_status(a: PTS_STATUS_INFO; i: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_set_status');
end;

function ERROR_TS_STATUS_INFO_get0_status(const a: PTS_STATUS_INFO): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_get0_status');
end;

function ERROR_TS_REQ_set_msg_imprint(a: PTS_REQ; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_msg_imprint');
end;

function ERROR_TS_REQ_get_msg_imprint(a: PTS_REQ): PTS_MSG_IMPRINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_msg_imprint');
end;

function ERROR_TS_MSG_IMPRINT_set_algo(a: PTS_MSG_IMPRINT; alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_set_algo');
end;

function ERROR_TS_MSG_IMPRINT_get_algo(a: PTS_MSG_IMPRINT): PX509_ALGOr; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_get_algo');
end;

function ERROR_TS_MSG_IMPRINT_set_msg(a: PTS_MSG_IMPRINT; d: PByte; len: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_set_msg');
end;

function ERROR_TS_MSG_IMPRINT_get_msg(a: PTS_MSG_IMPRINT): PASN1_OCTET_STRING; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_get_msg');
end;

function ERROR_TS_REQ_set_policy_id(a: PTS_REQ; policy: PASN1_OBJECT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_policy_id');
end;

function ERROR_TS_REQ_get_policy_id(a: PTS_REQ): PASN1_OBJECT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_policy_id');
end;

function ERROR_TS_REQ_set_nonce(a: PTS_REQ; nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_nonce');
end;

function ERROR_TS_REQ_get_nonce(const a: PTS_REQ): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_nonce');
end;

function ERROR_TS_REQ_set_cert_req(a: PTS_REQ; cert_req: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_set_cert_req');
end;

function ERROR_TS_REQ_get_cert_req(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_cert_req');
end;

procedure ERROR_TS_REQ_ext_free(a: PTS_REQ); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_ext_free');
end;

function ERROR_TS_REQ_get_ext_count(a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_count');
end;

function ERROR_TS_REQ_get_ext_by_NID(a: PTS_REQ; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_NID');
end;

function ERROR_TS_REQ_get_ext_by_OBJ(a: PTS_REQ; obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_OBJ');
end;

function ERROR_TS_REQ_get_ext_by_critical(a: PTS_REQ; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_by_critical');
end;

function ERROR_TS_REQ_get_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext');
end;

function ERROR_TS_REQ_delete_ext(a: PTS_REQ; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_delete_ext');
end;

function ERROR_TS_REQ_add_ext(a: PTS_REQ; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_add_ext');
end;

function ERROR_TS_REQ_get_ext_d2i(a: PTS_REQ; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_get_ext_d2i');
end;

function ERROR_TS_REQ_print_bio(bio: PBIO; a: PTS_REQ): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_print_bio');
end;

function ERROR_TS_RESP_set_status_info(a: PTS_RESP; info: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_set_status_info');
end;

function ERROR_TS_RESP_get_status_info(a: PTS_RESP): PTS_STATUS_INFO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_status_info');
end;

procedure ERROR_TS_RESP_set_tst_info(a: PTS_RESP; p7: PPKCS7; tst_info: PTS_TST_Info); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_set_tst_info');
end;

function ERROR_TS_RESP_get_token(a: PTS_RESP): PPKCS7; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_token');
end;

function ERROR_TS_RESP_get_tst_info(a: PTS_RESP): PTS_TST_Info; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_get_tst_info');
end;

function ERROR_TS_TST_INFO_set_version(a: PTS_TST_Info; version: TOpenSSL_C_LONG): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_version');
end;

function ERROR_TS_TST_INFO_get_version(const a: PTS_TST_Info): TOpenSSL_C_LONG; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_version');
end;

function ERROR_TS_TST_INFO_set_policy_id(a: PTS_TST_Info; policy_id: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_policy_id');
end;

function ERROR_TS_TST_INFO_get_policy_id(a: PTS_TST_Info): PASN1_Object; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_policy_id');
end;

function ERROR_TS_TST_INFO_set_msg_imprint(a: PTS_TST_Info; msg_imprint: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_msg_imprint');
end;

function ERROR_TS_TST_INFO_get_msg_imprint(a: PTS_TST_Info): PTS_MSG_IMPRINT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_msg_imprint');
end;

function ERROR_TS_TST_INFO_set_serial(a: PTS_TST_Info; const serial: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_serial');
end;

function ERROR_TS_TST_INFO_get_serial(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_serial');
end;

function ERROR_TS_TST_INFO_set_time(a: PTS_TST_Info; gtime: PASN1_GENERALIZEDTIME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_time');
end;

function ERROR_TS_TST_INFO_get_time(const a: PTS_TST_INFO): PASN1_GENERALIZEDTIME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_time');
end;

function ERROR_TS_TST_INFO_set_accuracy(a: PTS_TST_Info; accuracy: PTS_ACCURACY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_accuracy');
end;

function ERROR_TS_TST_INFO_get_accuracy(a: PTS_TST_Info): PTS_ACCURACY; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_accuracy');
end;

function ERROR_TS_ACCURACY_set_seconds(a: PTS_ACCURACY; const seconds: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_seconds');
end;

function ERROR_TS_ACCURACY_get_seconds(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_seconds');
end;

function ERROR_TS_ACCURACY_set_millis(a: PTS_ACCURACY; const millis: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_millis');
end;

function ERROR_TS_ACCURACY_get_millis(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_millis');
end;

function ERROR_TS_ACCURACY_set_micros(a: PTS_ACCURACY; const micros: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_set_micros');
end;

function ERROR_TS_ACCURACY_get_micros(const a: PTS_ACCURACY): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ACCURACY_get_micros');
end;

function ERROR_TS_TST_INFO_set_ordering(a: PTS_TST_Info; ordering: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_ordering');
end;

function ERROR_TS_TST_INFO_get_ordering(const a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ordering');
end;

function ERROR_TS_TST_INFO_set_nonce(a: PTS_TST_Info; const nonce: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_nonce');
end;

function ERROR_TS_TST_INFO_get_nonce(const a: PTS_TST_INFO): PASN1_INTEGER; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_nonce');
end;

function ERROR_TS_TST_INFO_set_tsa(a: PTS_TST_Info; tsa: PGENERAL_NAME): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_set_tsa');
end;

function ERROR_TS_TST_INFO_get_tsa(a: PTS_TST_Info): PGENERAL_NAME; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_tsa');
end;

procedure ERROR_TS_TST_INFO_ext_free(a: PTS_TST_Info); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_ext_free');
end;

function ERROR_TS_TST_INFO_get_ext_count(a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_count');
end;

function ERROR_TS_TST_INFO_get_ext_by_NID(a: PTS_TST_Info; nid: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_NID');
end;

function ERROR_TS_TST_INFO_get_ext_by_OBJ(a: PTS_TST_Info; const obj: PASN1_Object; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_OBJ');
end;

function ERROR_TS_TST_INFO_get_ext_by_critical(a: PTS_TST_Info; crit: TOpenSSL_C_INT; lastpos: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_by_critical');
end;

function ERROR_TS_TST_INFO_get_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext');
end;

function ERROR_TS_TST_INFO_delete_ext(a: PTS_TST_Info; loc: TOpenSSL_C_INT): PX509_Extension; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_delete_ext');
end;

function ERROR_TS_TST_INFO_add_ext(a: PTS_TST_Info; ex: PX509_Extension; loc: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_add_ext');
end;

function ERROR_TS_TST_INFO_get_ext_d2i(a: PTS_TST_Info; nid: TOpenSSL_C_INT; crit: POpenSSL_C_INT; idx: POpenSSL_C_INT): Pointer; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_get_ext_d2i');
end;

function ERROR_TS_RESP_CTX_new: PTS_RESP_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_new');
end;

procedure ERROR_TS_RESP_CTX_free(ctx: PTS_RESP_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_free');
end;

function ERROR_TS_RESP_CTX_set_signer_cert(ctx: PTS_RESP_CTX; signer: PX509): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_cert');
end;

function ERROR_TS_RESP_CTX_set_signer_key(ctx: PTS_RESP_CTX; key: PEVP_PKEY): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_key');
end;

function ERROR_TS_RESP_CTX_set_signer_digest(ctx: PTS_RESP_CTX; signer_digest: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_signer_digest');
end;

function ERROR_TS_RESP_CTX_set_ess_cert_id_digest(ctx: PTS_RESP_CTX; md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_ess_cert_id_digest');
end;

function ERROR_TS_RESP_CTX_set_def_policy(ctx: PTS_RESP_CTX; def_policy: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_def_policy');
end;

function ERROR_TS_RESP_CTX_add_policy(ctx: PTS_RESP_CTX; const policy: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_policy');
end;

function ERROR_TS_RESP_CTX_add_md(ctx: PTS_RESP_CTX; const md: PEVP_MD): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_md');
end;

function ERROR_TS_RESP_CTX_set_accuracy(ctx: PTS_RESP_CTX; secs: TOpenSSL_C_INT; millis: TOpenSSL_C_INT; micros: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_accuracy');
end;

function ERROR_TS_RESP_CTX_set_clock_precision_digits(ctx: PTS_RESP_CTX; clock_precision_digits: TOpenSSL_C_UINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_clock_precision_digits');
end;

procedure ERROR_TS_RESP_CTX_add_flags(ctx: PTS_RESP_CTX; flags: TOpenSSL_C_INT); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_flags');
end;

procedure ERROR_TS_RESP_CTX_set_serial_cb(ctx: PTS_RESP_CTX; cb: TS_serial_cb; data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_serial_cb');
end;

procedure ERROR_TS_RESP_CTX_set_time_cb(ctx: PTS_RESP_CTX; cb: TS_time_cb; data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_time_cb');
end;

procedure ERROR_TS_RESP_CTX_set_extension_cb(ctx: PTS_RESP_CTX; cb: TS_extension_cb; data: Pointer); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_extension_cb');
end;

function ERROR_TS_RESP_CTX_set_status_info(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_status_info');
end;

function ERROR_TS_RESP_CTX_set_status_info_cond(ctx: PTS_RESP_CTX; status: TOpenSSL_C_INT; text: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_set_status_info_cond');
end;

function ERROR_TS_RESP_CTX_add_failure_info(ctx: PTS_RESP_CTX; failure: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_add_failure_info');
end;

function ERROR_TS_RESP_CTX_get_request(ctx: PTS_RESP_CTX): PTS_REQ; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_get_request');
end;

function ERROR_TS_RESP_CTX_get_tst_info(ctx: PTS_RESP_CTX): PTS_TST_Info; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_CTX_get_tst_info');
end;

function ERROR_TS_RESP_create_response(ctx: PTS_RESP_CTX; req_bio: PBIO): PTS_RESP; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_create_response');
end;

function ERROR_TS_RESP_verify_response(ctx: PTS_VERIFY_CTX; response: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_verify_response');
end;

function ERROR_TS_RESP_verify_token(ctx: PTS_VERIFY_CTX; token: PPKCS7): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_verify_token');
end;

function ERROR_TS_VERIFY_CTX_new: PTS_VERIFY_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_new');
end;

procedure ERROR_TS_VERIFY_CTX_init(ctx: PTS_VERIFY_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_init');
end;

procedure ERROR_TS_VERIFY_CTX_free(ctx: PTS_VERIFY_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_free');
end;

procedure ERROR_TS_VERIFY_CTX_cleanup(ctx: PTS_VERIFY_CTX); cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_cleanup');
end;

function ERROR_TS_VERIFY_CTX_set_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_flags');
end;

function ERROR_TS_VERIFY_CTX_add_flags(ctx: PTS_VERIFY_CTX; f: TOpenSSL_C_INT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_add_flags');
end;

function ERROR_TS_VERIFY_CTX_set_data(ctx: PTS_VERIFY_CTX; b: PBIO): PBIO; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_data');
end;

function ERROR_TS_VERIFY_CTX_set_imprint(ctx: PTS_VERIFY_CTX; hexstr: PByte; len: TOpenSSL_C_LONG): PByte; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_imprint');
end;

function ERROR_TS_VERIFY_CTX_set_store(ctx: PTS_VERIFY_CTX; s: PX509_Store): PX509_Store; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_VERIFY_CTX_set_store');
end;

function ERROR_TS_REQ_to_TS_VERIFY_CTX(req: PTS_REQ; ctx: PTS_VERIFY_CTX): PTS_VERIFY_CTX; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_REQ_to_TS_VERIFY_CTX');
end;

function ERROR_TS_RESP_print_bio(bio: PBIO; a: PTS_RESP): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_RESP_print_bio');
end;

function ERROR_TS_STATUS_INFO_print_bio(bio: PBIO; a: PTS_STATUS_INFO): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_STATUS_INFO_print_bio');
end;

function ERROR_TS_TST_INFO_print_bio(bio: PBIO; a: PTS_TST_Info): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_TST_INFO_print_bio');
end;

function ERROR_TS_ASN1_INTEGER_print_bio(bio: PBIO; const num: PASN1_INTEGER): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_ASN1_INTEGER_print_bio');
end;

function ERROR_TS_OBJ_print_bio(bio: PBIO; const obj: PASN1_Object): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_OBJ_print_bio');
end;

function ERROR_TS_X509_ALGOR_print_bio(bio: PBIO; const alg: PX509_ALGOr): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_X509_ALGOR_print_bio');
end;

function ERROR_TS_MSG_IMPRINT_print_bio(bio: PBIO; msg: PTS_MSG_IMPRINT): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_MSG_IMPRINT_print_bio');
end;

function ERROR_TS_CONF_load_cert(file_: PAnsiChar): PX509; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_load_cert');
end;

function ERROR_TS_CONF_load_key( file_: PAnsiChar; pass: PAnsiChar): PEVP_PKey; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_load_key');
end;

function ERROR_TS_CONF_set_serial(conf: PCONF; section: PAnsiChar; cb: TS_serial_cb; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_serial');
end;

function ERROR_TS_CONF_get_tsa_section(conf: PCONF; const section: PAnsiChar): PAnsiChar; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_get_tsa_section');
end;

function ERROR_TS_CONF_set_crypto_device(conf: PCONF; section: PAnsiChar; device: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_crypto_device');
end;

function ERROR_TS_CONF_set_default_engine(name: PAnsiChar): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_default_engine');
end;

function ERROR_TS_CONF_set_signer_cert(conf: PCONF; section: PAnsiChar; cert: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_cert');
end;

function ERROR_TS_CONF_set_certs(conf: PCONF; section: PAnsiChar; certs: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_certs');
end;

function ERROR_TS_CONF_set_signer_key(conf: PCONF; const section: PAnsiChar; key: PAnsiChar; pass: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_key');
end;

function ERROR_TS_CONF_set_signer_digest(conf: PCONF; section: PAnsiChar; md: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_signer_digest');
end;

function ERROR_TS_CONF_set_def_policy(conf: PCONF; section: PAnsiChar; policy: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_def_policy');
end;

function ERROR_TS_CONF_set_policies(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_policies');
end;

function ERROR_TS_CONF_set_digests(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_digests');
end;

function ERROR_TS_CONF_set_accuracy(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_accuracy');
end;

function ERROR_TS_CONF_set_clock_precision_digits(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_clock_precision_digits');
end;

function ERROR_TS_CONF_set_ordering(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ordering');
end;

function ERROR_TS_CONF_set_tsa_name(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_tsa_name');
end;

function ERROR_TS_CONF_set_ess_cert_id_chain(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ess_cert_id_chain');
end;

function ERROR_TS_CONF_set_ess_cert_id_digest(conf: PCONF; section: PAnsiChar; ctx: PTS_RESP_CTX): TOpenSSL_C_INT; cdecl;
begin
  EOpenSSLAPIFunctionNotPresent.RaiseException('TS_CONF_set_ess_cert_id_digest');
end;

{$WARN  NO_RETVAL ON}
procedure Load(LibVersion: TOpenSSL_C_UINT; const AFailed: TStringList);
var FuncLoadError: boolean;
begin
  TS_REQ_new := LoadLibCryptoFunction('TS_REQ_new');
  FuncLoadError := not assigned(TS_REQ_new);
  if FuncLoadError then
  begin
    TS_REQ_new :=  @ERROR_TS_REQ_new;
  end;

  TS_REQ_free := LoadLibCryptoFunction('TS_REQ_free');
  FuncLoadError := not assigned(TS_REQ_free);
  if FuncLoadError then
  begin
    TS_REQ_free :=  @ERROR_TS_REQ_free;
  end;

  i2d_TS_REQ := LoadLibCryptoFunction('i2d_TS_REQ');
  FuncLoadError := not assigned(i2d_TS_REQ);
  if FuncLoadError then
  begin
    i2d_TS_REQ :=  @ERROR_i2d_TS_REQ;
  end;

  d2i_TS_REQ := LoadLibCryptoFunction('d2i_TS_REQ');
  FuncLoadError := not assigned(d2i_TS_REQ);
  if FuncLoadError then
  begin
    d2i_TS_REQ :=  @ERROR_d2i_TS_REQ;
  end;

  TS_REQ_dup := LoadLibCryptoFunction('TS_REQ_dup');
  FuncLoadError := not assigned(TS_REQ_dup);
  if FuncLoadError then
  begin
    TS_REQ_dup :=  @ERROR_TS_REQ_dup;
  end;

  d2i_TS_REQ_bio := LoadLibCryptoFunction('d2i_TS_REQ_bio');
  FuncLoadError := not assigned(d2i_TS_REQ_bio);
  if FuncLoadError then
  begin
    d2i_TS_REQ_bio :=  @ERROR_d2i_TS_REQ_bio;
  end;

  i2d_TS_REQ_bio := LoadLibCryptoFunction('i2d_TS_REQ_bio');
  FuncLoadError := not assigned(i2d_TS_REQ_bio);
  if FuncLoadError then
  begin
    i2d_TS_REQ_bio :=  @ERROR_i2d_TS_REQ_bio;
  end;

  TS_MSG_IMPRINT_new := LoadLibCryptoFunction('TS_MSG_IMPRINT_new');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_new);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_new :=  @ERROR_TS_MSG_IMPRINT_new;
  end;

  TS_MSG_IMPRINT_free := LoadLibCryptoFunction('TS_MSG_IMPRINT_free');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_free);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_free :=  @ERROR_TS_MSG_IMPRINT_free;
  end;

  i2d_TS_MSG_IMPRINT := LoadLibCryptoFunction('i2d_TS_MSG_IMPRINT');
  FuncLoadError := not assigned(i2d_TS_MSG_IMPRINT);
  if FuncLoadError then
  begin
    i2d_TS_MSG_IMPRINT :=  @ERROR_i2d_TS_MSG_IMPRINT;
  end;

  d2i_TS_MSG_IMPRINT := LoadLibCryptoFunction('d2i_TS_MSG_IMPRINT');
  FuncLoadError := not assigned(d2i_TS_MSG_IMPRINT);
  if FuncLoadError then
  begin
    d2i_TS_MSG_IMPRINT :=  @ERROR_d2i_TS_MSG_IMPRINT;
  end;

  TS_MSG_IMPRINT_dup := LoadLibCryptoFunction('TS_MSG_IMPRINT_dup');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_dup);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_dup :=  @ERROR_TS_MSG_IMPRINT_dup;
  end;

  d2i_TS_MSG_IMPRINT_bio := LoadLibCryptoFunction('d2i_TS_MSG_IMPRINT_bio');
  FuncLoadError := not assigned(d2i_TS_MSG_IMPRINT_bio);
  if FuncLoadError then
  begin
    d2i_TS_MSG_IMPRINT_bio :=  @ERROR_d2i_TS_MSG_IMPRINT_bio;
  end;

  i2d_TS_MSG_IMPRINT_bio := LoadLibCryptoFunction('i2d_TS_MSG_IMPRINT_bio');
  FuncLoadError := not assigned(i2d_TS_MSG_IMPRINT_bio);
  if FuncLoadError then
  begin
    i2d_TS_MSG_IMPRINT_bio :=  @ERROR_i2d_TS_MSG_IMPRINT_bio;
  end;

  TS_RESP_new := LoadLibCryptoFunction('TS_RESP_new');
  FuncLoadError := not assigned(TS_RESP_new);
  if FuncLoadError then
  begin
    TS_RESP_new :=  @ERROR_TS_RESP_new;
  end;

  TS_RESP_free := LoadLibCryptoFunction('TS_RESP_free');
  FuncLoadError := not assigned(TS_RESP_free);
  if FuncLoadError then
  begin
    TS_RESP_free :=  @ERROR_TS_RESP_free;
  end;

  i2d_TS_RESP := LoadLibCryptoFunction('i2d_TS_RESP');
  FuncLoadError := not assigned(i2d_TS_RESP);
  if FuncLoadError then
  begin
    i2d_TS_RESP :=  @ERROR_i2d_TS_RESP;
  end;

  d2i_TS_RESP := LoadLibCryptoFunction('d2i_TS_RESP');
  FuncLoadError := not assigned(d2i_TS_RESP);
  if FuncLoadError then
  begin
    d2i_TS_RESP :=  @ERROR_d2i_TS_RESP;
  end;

  PKCS7_to_TS_TST_INFO := LoadLibCryptoFunction('PKCS7_to_TS_TST_INFO');
  FuncLoadError := not assigned(PKCS7_to_TS_TST_INFO);
  if FuncLoadError then
  begin
    PKCS7_to_TS_TST_INFO :=  @ERROR_PKCS7_to_TS_TST_INFO;
  end;

  TS_RESP_dup := LoadLibCryptoFunction('TS_RESP_dup');
  FuncLoadError := not assigned(TS_RESP_dup);
  if FuncLoadError then
  begin
    TS_RESP_dup :=  @ERROR_TS_RESP_dup;
  end;

  d2i_TS_RESP_bio := LoadLibCryptoFunction('d2i_TS_RESP_bio');
  FuncLoadError := not assigned(d2i_TS_RESP_bio);
  if FuncLoadError then
  begin
    d2i_TS_RESP_bio :=  @ERROR_d2i_TS_RESP_bio;
  end;

  i2d_TS_RESP_bio := LoadLibCryptoFunction('i2d_TS_RESP_bio');
  FuncLoadError := not assigned(i2d_TS_RESP_bio);
  if FuncLoadError then
  begin
    i2d_TS_RESP_bio :=  @ERROR_i2d_TS_RESP_bio;
  end;

  TS_STATUS_INFO_new := LoadLibCryptoFunction('TS_STATUS_INFO_new');
  FuncLoadError := not assigned(TS_STATUS_INFO_new);
  if FuncLoadError then
  begin
    TS_STATUS_INFO_new :=  @ERROR_TS_STATUS_INFO_new;
  end;

  TS_STATUS_INFO_free := LoadLibCryptoFunction('TS_STATUS_INFO_free');
  FuncLoadError := not assigned(TS_STATUS_INFO_free);
  if FuncLoadError then
  begin
    TS_STATUS_INFO_free :=  @ERROR_TS_STATUS_INFO_free;
  end;

  i2d_TS_STATUS_INFO := LoadLibCryptoFunction('i2d_TS_STATUS_INFO');
  FuncLoadError := not assigned(i2d_TS_STATUS_INFO);
  if FuncLoadError then
  begin
    i2d_TS_STATUS_INFO :=  @ERROR_i2d_TS_STATUS_INFO;
  end;

  d2i_TS_STATUS_INFO := LoadLibCryptoFunction('d2i_TS_STATUS_INFO');
  FuncLoadError := not assigned(d2i_TS_STATUS_INFO);
  if FuncLoadError then
  begin
    d2i_TS_STATUS_INFO :=  @ERROR_d2i_TS_STATUS_INFO;
  end;

  TS_STATUS_INFO_dup := LoadLibCryptoFunction('TS_STATUS_INFO_dup');
  FuncLoadError := not assigned(TS_STATUS_INFO_dup);
  if FuncLoadError then
  begin
    TS_STATUS_INFO_dup :=  @ERROR_TS_STATUS_INFO_dup;
  end;

  TS_TST_INFO_new := LoadLibCryptoFunction('TS_TST_INFO_new');
  FuncLoadError := not assigned(TS_TST_INFO_new);
  if FuncLoadError then
  begin
    TS_TST_INFO_new :=  @ERROR_TS_TST_INFO_new;
  end;

  TS_TST_INFO_free := LoadLibCryptoFunction('TS_TST_INFO_free');
  FuncLoadError := not assigned(TS_TST_INFO_free);
  if FuncLoadError then
  begin
    TS_TST_INFO_free :=  @ERROR_TS_TST_INFO_free;
  end;

  i2d_TS_TST_INFO := LoadLibCryptoFunction('i2d_TS_TST_INFO');
  FuncLoadError := not assigned(i2d_TS_TST_INFO);
  if FuncLoadError then
  begin
    i2d_TS_TST_INFO :=  @ERROR_i2d_TS_TST_INFO;
  end;

  d2i_TS_TST_INFO := LoadLibCryptoFunction('d2i_TS_TST_INFO');
  FuncLoadError := not assigned(d2i_TS_TST_INFO);
  if FuncLoadError then
  begin
    d2i_TS_TST_INFO :=  @ERROR_d2i_TS_TST_INFO;
  end;

  TS_TST_INFO_dup := LoadLibCryptoFunction('TS_TST_INFO_dup');
  FuncLoadError := not assigned(TS_TST_INFO_dup);
  if FuncLoadError then
  begin
    TS_TST_INFO_dup :=  @ERROR_TS_TST_INFO_dup;
  end;

  d2i_TS_TST_INFO_bio := LoadLibCryptoFunction('d2i_TS_TST_INFO_bio');
  FuncLoadError := not assigned(d2i_TS_TST_INFO_bio);
  if FuncLoadError then
  begin
    d2i_TS_TST_INFO_bio :=  @ERROR_d2i_TS_TST_INFO_bio;
  end;

  i2d_TS_TST_INFO_bio := LoadLibCryptoFunction('i2d_TS_TST_INFO_bio');
  FuncLoadError := not assigned(i2d_TS_TST_INFO_bio);
  if FuncLoadError then
  begin
    i2d_TS_TST_INFO_bio :=  @ERROR_i2d_TS_TST_INFO_bio;
  end;

  TS_ACCURACY_new := LoadLibCryptoFunction('TS_ACCURACY_new');
  FuncLoadError := not assigned(TS_ACCURACY_new);
  if FuncLoadError then
  begin
    TS_ACCURACY_new :=  @ERROR_TS_ACCURACY_new;
  end;

  TS_ACCURACY_free := LoadLibCryptoFunction('TS_ACCURACY_free');
  FuncLoadError := not assigned(TS_ACCURACY_free);
  if FuncLoadError then
  begin
    TS_ACCURACY_free :=  @ERROR_TS_ACCURACY_free;
  end;

  i2d_TS_ACCURACY := LoadLibCryptoFunction('i2d_TS_ACCURACY');
  FuncLoadError := not assigned(i2d_TS_ACCURACY);
  if FuncLoadError then
  begin
    i2d_TS_ACCURACY :=  @ERROR_i2d_TS_ACCURACY;
  end;

  d2i_TS_ACCURACY := LoadLibCryptoFunction('d2i_TS_ACCURACY');
  FuncLoadError := not assigned(d2i_TS_ACCURACY);
  if FuncLoadError then
  begin
    d2i_TS_ACCURACY :=  @ERROR_d2i_TS_ACCURACY;
  end;

  TS_ACCURACY_dup := LoadLibCryptoFunction('TS_ACCURACY_dup');
  FuncLoadError := not assigned(TS_ACCURACY_dup);
  if FuncLoadError then
  begin
    TS_ACCURACY_dup :=  @ERROR_TS_ACCURACY_dup;
  end;

  ESS_ISSUER_SERIAL_new := LoadLibCryptoFunction('ESS_ISSUER_SERIAL_new');
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_new);
  if FuncLoadError then
  begin
    ESS_ISSUER_SERIAL_new :=  @ERROR_ESS_ISSUER_SERIAL_new;
  end;

  ESS_ISSUER_SERIAL_free := LoadLibCryptoFunction('ESS_ISSUER_SERIAL_free');
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_free);
  if FuncLoadError then
  begin
    ESS_ISSUER_SERIAL_free :=  @ERROR_ESS_ISSUER_SERIAL_free;
  end;

  i2d_ESS_ISSUER_SERIAL := LoadLibCryptoFunction('i2d_ESS_ISSUER_SERIAL');
  FuncLoadError := not assigned(i2d_ESS_ISSUER_SERIAL);
  if FuncLoadError then
  begin
    i2d_ESS_ISSUER_SERIAL :=  @ERROR_i2d_ESS_ISSUER_SERIAL;
  end;

  d2i_ESS_ISSUER_SERIAL := LoadLibCryptoFunction('d2i_ESS_ISSUER_SERIAL');
  FuncLoadError := not assigned(d2i_ESS_ISSUER_SERIAL);
  if FuncLoadError then
  begin
    d2i_ESS_ISSUER_SERIAL :=  @ERROR_d2i_ESS_ISSUER_SERIAL;
  end;

  ESS_ISSUER_SERIAL_dup := LoadLibCryptoFunction('ESS_ISSUER_SERIAL_dup');
  FuncLoadError := not assigned(ESS_ISSUER_SERIAL_dup);
  if FuncLoadError then
  begin
    ESS_ISSUER_SERIAL_dup :=  @ERROR_ESS_ISSUER_SERIAL_dup;
  end;

  ESS_CERT_ID_new := LoadLibCryptoFunction('ESS_CERT_ID_new');
  FuncLoadError := not assigned(ESS_CERT_ID_new);
  if FuncLoadError then
  begin
    ESS_CERT_ID_new :=  @ERROR_ESS_CERT_ID_new;
  end;

  ESS_CERT_ID_free := LoadLibCryptoFunction('ESS_CERT_ID_free');
  FuncLoadError := not assigned(ESS_CERT_ID_free);
  if FuncLoadError then
  begin
    ESS_CERT_ID_free :=  @ERROR_ESS_CERT_ID_free;
  end;

  i2d_ESS_CERT_ID := LoadLibCryptoFunction('i2d_ESS_CERT_ID');
  FuncLoadError := not assigned(i2d_ESS_CERT_ID);
  if FuncLoadError then
  begin
    i2d_ESS_CERT_ID :=  @ERROR_i2d_ESS_CERT_ID;
  end;

  d2i_ESS_CERT_ID := LoadLibCryptoFunction('d2i_ESS_CERT_ID');
  FuncLoadError := not assigned(d2i_ESS_CERT_ID);
  if FuncLoadError then
  begin
    d2i_ESS_CERT_ID :=  @ERROR_d2i_ESS_CERT_ID;
  end;

  ESS_CERT_ID_dup := LoadLibCryptoFunction('ESS_CERT_ID_dup');
  FuncLoadError := not assigned(ESS_CERT_ID_dup);
  if FuncLoadError then
  begin
    ESS_CERT_ID_dup :=  @ERROR_ESS_CERT_ID_dup;
  end;

  ESS_SIGNING_CERT_new := LoadLibCryptoFunction('ESS_SIGNING_CERT_new');
  FuncLoadError := not assigned(ESS_SIGNING_CERT_new);
  if FuncLoadError then
  begin
    ESS_SIGNING_CERT_new :=  @ERROR_ESS_SIGNING_CERT_new;
  end;

  ESS_SIGNING_CERT_free := LoadLibCryptoFunction('ESS_SIGNING_CERT_free');
  FuncLoadError := not assigned(ESS_SIGNING_CERT_free);
  if FuncLoadError then
  begin
    ESS_SIGNING_CERT_free :=  @ERROR_ESS_SIGNING_CERT_free;
  end;

  i2d_ESS_SIGNING_CERT := LoadLibCryptoFunction('i2d_ESS_SIGNING_CERT');
  FuncLoadError := not assigned(i2d_ESS_SIGNING_CERT);
  if FuncLoadError then
  begin
    i2d_ESS_SIGNING_CERT :=  @ERROR_i2d_ESS_SIGNING_CERT;
  end;

  d2i_ESS_SIGNING_CERT := LoadLibCryptoFunction('d2i_ESS_SIGNING_CERT');
  FuncLoadError := not assigned(d2i_ESS_SIGNING_CERT);
  if FuncLoadError then
  begin
    d2i_ESS_SIGNING_CERT :=  @ERROR_d2i_ESS_SIGNING_CERT;
  end;

  ESS_SIGNING_CERT_dup := LoadLibCryptoFunction('ESS_SIGNING_CERT_dup');
  FuncLoadError := not assigned(ESS_SIGNING_CERT_dup);
  if FuncLoadError then
  begin
    ESS_SIGNING_CERT_dup :=  @ERROR_ESS_SIGNING_CERT_dup;
  end;

  ESS_CERT_ID_V2_new := LoadLibCryptoFunction('ESS_CERT_ID_V2_new');
  FuncLoadError := not assigned(ESS_CERT_ID_V2_new);
  if FuncLoadError then
  begin
    ESS_CERT_ID_V2_new :=  @ERROR_ESS_CERT_ID_V2_new;
  end;

  ESS_CERT_ID_V2_free := LoadLibCryptoFunction('ESS_CERT_ID_V2_free');
  FuncLoadError := not assigned(ESS_CERT_ID_V2_free);
  if FuncLoadError then
  begin
    ESS_CERT_ID_V2_free :=  @ERROR_ESS_CERT_ID_V2_free;
  end;

  i2d_ESS_CERT_ID_V2 := LoadLibCryptoFunction('i2d_ESS_CERT_ID_V2');
  FuncLoadError := not assigned(i2d_ESS_CERT_ID_V2);
  if FuncLoadError then
  begin
    i2d_ESS_CERT_ID_V2 :=  @ERROR_i2d_ESS_CERT_ID_V2;
  end;

  d2i_ESS_CERT_ID_V2 := LoadLibCryptoFunction('d2i_ESS_CERT_ID_V2');
  FuncLoadError := not assigned(d2i_ESS_CERT_ID_V2);
  if FuncLoadError then
  begin
    d2i_ESS_CERT_ID_V2 :=  @ERROR_d2i_ESS_CERT_ID_V2;
  end;

  ESS_CERT_ID_V2_dup := LoadLibCryptoFunction('ESS_CERT_ID_V2_dup');
  FuncLoadError := not assigned(ESS_CERT_ID_V2_dup);
  if FuncLoadError then
  begin
    ESS_CERT_ID_V2_dup :=  @ERROR_ESS_CERT_ID_V2_dup;
  end;

  ESS_SIGNING_CERT_V2_new := LoadLibCryptoFunction('ESS_SIGNING_CERT_V2_new');
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_new);
  if FuncLoadError then
  begin
    ESS_SIGNING_CERT_V2_new :=  @ERROR_ESS_SIGNING_CERT_V2_new;
  end;

  ESS_SIGNING_CERT_V2_free := LoadLibCryptoFunction('ESS_SIGNING_CERT_V2_free');
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_free);
  if FuncLoadError then
  begin
    ESS_SIGNING_CERT_V2_free :=  @ERROR_ESS_SIGNING_CERT_V2_free;
  end;

  i2d_ESS_SIGNING_CERT_V2 := LoadLibCryptoFunction('i2d_ESS_SIGNING_CERT_V2');
  FuncLoadError := not assigned(i2d_ESS_SIGNING_CERT_V2);
  if FuncLoadError then
  begin
    i2d_ESS_SIGNING_CERT_V2 :=  @ERROR_i2d_ESS_SIGNING_CERT_V2;
  end;

  d2i_ESS_SIGNING_CERT_V2 := LoadLibCryptoFunction('d2i_ESS_SIGNING_CERT_V2');
  FuncLoadError := not assigned(d2i_ESS_SIGNING_CERT_V2);
  if FuncLoadError then
  begin
    d2i_ESS_SIGNING_CERT_V2 :=  @ERROR_d2i_ESS_SIGNING_CERT_V2;
  end;

  ESS_SIGNING_CERT_V2_dup := LoadLibCryptoFunction('ESS_SIGNING_CERT_V2_dup');
  FuncLoadError := not assigned(ESS_SIGNING_CERT_V2_dup);
  if FuncLoadError then
  begin
    ESS_SIGNING_CERT_V2_dup :=  @ERROR_ESS_SIGNING_CERT_V2_dup;
  end;

  TS_REQ_set_version := LoadLibCryptoFunction('TS_REQ_set_version');
  FuncLoadError := not assigned(TS_REQ_set_version);
  if FuncLoadError then
  begin
    TS_REQ_set_version :=  @ERROR_TS_REQ_set_version;
  end;

  TS_REQ_get_version := LoadLibCryptoFunction('TS_REQ_get_version');
  FuncLoadError := not assigned(TS_REQ_get_version);
  if FuncLoadError then
  begin
    TS_REQ_get_version :=  @ERROR_TS_REQ_get_version;
  end;

  TS_STATUS_INFO_set_status := LoadLibCryptoFunction('TS_STATUS_INFO_set_status');
  FuncLoadError := not assigned(TS_STATUS_INFO_set_status);
  if FuncLoadError then
  begin
    TS_STATUS_INFO_set_status :=  @ERROR_TS_STATUS_INFO_set_status;
  end;

  TS_STATUS_INFO_get0_status := LoadLibCryptoFunction('TS_STATUS_INFO_get0_status');
  FuncLoadError := not assigned(TS_STATUS_INFO_get0_status);
  if FuncLoadError then
  begin
    TS_STATUS_INFO_get0_status :=  @ERROR_TS_STATUS_INFO_get0_status;
  end;

  TS_REQ_set_msg_imprint := LoadLibCryptoFunction('TS_REQ_set_msg_imprint');
  FuncLoadError := not assigned(TS_REQ_set_msg_imprint);
  if FuncLoadError then
  begin
    TS_REQ_set_msg_imprint :=  @ERROR_TS_REQ_set_msg_imprint;
  end;

  TS_REQ_get_msg_imprint := LoadLibCryptoFunction('TS_REQ_get_msg_imprint');
  FuncLoadError := not assigned(TS_REQ_get_msg_imprint);
  if FuncLoadError then
  begin
    TS_REQ_get_msg_imprint :=  @ERROR_TS_REQ_get_msg_imprint;
  end;

  TS_MSG_IMPRINT_set_algo := LoadLibCryptoFunction('TS_MSG_IMPRINT_set_algo');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_set_algo);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_set_algo :=  @ERROR_TS_MSG_IMPRINT_set_algo;
  end;

  TS_MSG_IMPRINT_get_algo := LoadLibCryptoFunction('TS_MSG_IMPRINT_get_algo');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_get_algo);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_get_algo :=  @ERROR_TS_MSG_IMPRINT_get_algo;
  end;

  TS_MSG_IMPRINT_set_msg := LoadLibCryptoFunction('TS_MSG_IMPRINT_set_msg');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_set_msg);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_set_msg :=  @ERROR_TS_MSG_IMPRINT_set_msg;
  end;

  TS_MSG_IMPRINT_get_msg := LoadLibCryptoFunction('TS_MSG_IMPRINT_get_msg');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_get_msg);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_get_msg :=  @ERROR_TS_MSG_IMPRINT_get_msg;
  end;

  TS_REQ_set_policy_id := LoadLibCryptoFunction('TS_REQ_set_policy_id');
  FuncLoadError := not assigned(TS_REQ_set_policy_id);
  if FuncLoadError then
  begin
    TS_REQ_set_policy_id :=  @ERROR_TS_REQ_set_policy_id;
  end;

  TS_REQ_get_policy_id := LoadLibCryptoFunction('TS_REQ_get_policy_id');
  FuncLoadError := not assigned(TS_REQ_get_policy_id);
  if FuncLoadError then
  begin
    TS_REQ_get_policy_id :=  @ERROR_TS_REQ_get_policy_id;
  end;

  TS_REQ_set_nonce := LoadLibCryptoFunction('TS_REQ_set_nonce');
  FuncLoadError := not assigned(TS_REQ_set_nonce);
  if FuncLoadError then
  begin
    TS_REQ_set_nonce :=  @ERROR_TS_REQ_set_nonce;
  end;

  TS_REQ_get_nonce := LoadLibCryptoFunction('TS_REQ_get_nonce');
  FuncLoadError := not assigned(TS_REQ_get_nonce);
  if FuncLoadError then
  begin
    TS_REQ_get_nonce :=  @ERROR_TS_REQ_get_nonce;
  end;

  TS_REQ_set_cert_req := LoadLibCryptoFunction('TS_REQ_set_cert_req');
  FuncLoadError := not assigned(TS_REQ_set_cert_req);
  if FuncLoadError then
  begin
    TS_REQ_set_cert_req :=  @ERROR_TS_REQ_set_cert_req;
  end;

  TS_REQ_get_cert_req := LoadLibCryptoFunction('TS_REQ_get_cert_req');
  FuncLoadError := not assigned(TS_REQ_get_cert_req);
  if FuncLoadError then
  begin
    TS_REQ_get_cert_req :=  @ERROR_TS_REQ_get_cert_req;
  end;

  TS_REQ_ext_free := LoadLibCryptoFunction('TS_REQ_ext_free');
  FuncLoadError := not assigned(TS_REQ_ext_free);
  if FuncLoadError then
  begin
    TS_REQ_ext_free :=  @ERROR_TS_REQ_ext_free;
  end;

  TS_REQ_get_ext_count := LoadLibCryptoFunction('TS_REQ_get_ext_count');
  FuncLoadError := not assigned(TS_REQ_get_ext_count);
  if FuncLoadError then
  begin
    TS_REQ_get_ext_count :=  @ERROR_TS_REQ_get_ext_count;
  end;

  TS_REQ_get_ext_by_NID := LoadLibCryptoFunction('TS_REQ_get_ext_by_NID');
  FuncLoadError := not assigned(TS_REQ_get_ext_by_NID);
  if FuncLoadError then
  begin
    TS_REQ_get_ext_by_NID :=  @ERROR_TS_REQ_get_ext_by_NID;
  end;

  TS_REQ_get_ext_by_OBJ := LoadLibCryptoFunction('TS_REQ_get_ext_by_OBJ');
  FuncLoadError := not assigned(TS_REQ_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    TS_REQ_get_ext_by_OBJ :=  @ERROR_TS_REQ_get_ext_by_OBJ;
  end;

  TS_REQ_get_ext_by_critical := LoadLibCryptoFunction('TS_REQ_get_ext_by_critical');
  FuncLoadError := not assigned(TS_REQ_get_ext_by_critical);
  if FuncLoadError then
  begin
    TS_REQ_get_ext_by_critical :=  @ERROR_TS_REQ_get_ext_by_critical;
  end;

  TS_REQ_get_ext := LoadLibCryptoFunction('TS_REQ_get_ext');
  FuncLoadError := not assigned(TS_REQ_get_ext);
  if FuncLoadError then
  begin
    TS_REQ_get_ext :=  @ERROR_TS_REQ_get_ext;
  end;

  TS_REQ_delete_ext := LoadLibCryptoFunction('TS_REQ_delete_ext');
  FuncLoadError := not assigned(TS_REQ_delete_ext);
  if FuncLoadError then
  begin
    TS_REQ_delete_ext :=  @ERROR_TS_REQ_delete_ext;
  end;

  TS_REQ_add_ext := LoadLibCryptoFunction('TS_REQ_add_ext');
  FuncLoadError := not assigned(TS_REQ_add_ext);
  if FuncLoadError then
  begin
    TS_REQ_add_ext :=  @ERROR_TS_REQ_add_ext;
  end;

  TS_REQ_get_ext_d2i := LoadLibCryptoFunction('TS_REQ_get_ext_d2i');
  FuncLoadError := not assigned(TS_REQ_get_ext_d2i);
  if FuncLoadError then
  begin
    TS_REQ_get_ext_d2i :=  @ERROR_TS_REQ_get_ext_d2i;
  end;

  TS_REQ_print_bio := LoadLibCryptoFunction('TS_REQ_print_bio');
  FuncLoadError := not assigned(TS_REQ_print_bio);
  if FuncLoadError then
  begin
    TS_REQ_print_bio :=  @ERROR_TS_REQ_print_bio;
  end;

  TS_RESP_set_status_info := LoadLibCryptoFunction('TS_RESP_set_status_info');
  FuncLoadError := not assigned(TS_RESP_set_status_info);
  if FuncLoadError then
  begin
    TS_RESP_set_status_info :=  @ERROR_TS_RESP_set_status_info;
  end;

  TS_RESP_get_status_info := LoadLibCryptoFunction('TS_RESP_get_status_info');
  FuncLoadError := not assigned(TS_RESP_get_status_info);
  if FuncLoadError then
  begin
    TS_RESP_get_status_info :=  @ERROR_TS_RESP_get_status_info;
  end;

  TS_RESP_set_tst_info := LoadLibCryptoFunction('TS_RESP_set_tst_info');
  FuncLoadError := not assigned(TS_RESP_set_tst_info);
  if FuncLoadError then
  begin
    TS_RESP_set_tst_info :=  @ERROR_TS_RESP_set_tst_info;
  end;

  TS_RESP_get_token := LoadLibCryptoFunction('TS_RESP_get_token');
  FuncLoadError := not assigned(TS_RESP_get_token);
  if FuncLoadError then
  begin
    TS_RESP_get_token :=  @ERROR_TS_RESP_get_token;
  end;

  TS_RESP_get_tst_info := LoadLibCryptoFunction('TS_RESP_get_tst_info');
  FuncLoadError := not assigned(TS_RESP_get_tst_info);
  if FuncLoadError then
  begin
    TS_RESP_get_tst_info :=  @ERROR_TS_RESP_get_tst_info;
  end;

  TS_TST_INFO_set_version := LoadLibCryptoFunction('TS_TST_INFO_set_version');
  FuncLoadError := not assigned(TS_TST_INFO_set_version);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_version :=  @ERROR_TS_TST_INFO_set_version;
  end;

  TS_TST_INFO_get_version := LoadLibCryptoFunction('TS_TST_INFO_get_version');
  FuncLoadError := not assigned(TS_TST_INFO_get_version);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_version :=  @ERROR_TS_TST_INFO_get_version;
  end;

  TS_TST_INFO_set_policy_id := LoadLibCryptoFunction('TS_TST_INFO_set_policy_id');
  FuncLoadError := not assigned(TS_TST_INFO_set_policy_id);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_policy_id :=  @ERROR_TS_TST_INFO_set_policy_id;
  end;

  TS_TST_INFO_get_policy_id := LoadLibCryptoFunction('TS_TST_INFO_get_policy_id');
  FuncLoadError := not assigned(TS_TST_INFO_get_policy_id);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_policy_id :=  @ERROR_TS_TST_INFO_get_policy_id;
  end;

  TS_TST_INFO_set_msg_imprint := LoadLibCryptoFunction('TS_TST_INFO_set_msg_imprint');
  FuncLoadError := not assigned(TS_TST_INFO_set_msg_imprint);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_msg_imprint :=  @ERROR_TS_TST_INFO_set_msg_imprint;
  end;

  TS_TST_INFO_get_msg_imprint := LoadLibCryptoFunction('TS_TST_INFO_get_msg_imprint');
  FuncLoadError := not assigned(TS_TST_INFO_get_msg_imprint);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_msg_imprint :=  @ERROR_TS_TST_INFO_get_msg_imprint;
  end;

  TS_TST_INFO_set_serial := LoadLibCryptoFunction('TS_TST_INFO_set_serial');
  FuncLoadError := not assigned(TS_TST_INFO_set_serial);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_serial :=  @ERROR_TS_TST_INFO_set_serial;
  end;

  TS_TST_INFO_get_serial := LoadLibCryptoFunction('TS_TST_INFO_get_serial');
  FuncLoadError := not assigned(TS_TST_INFO_get_serial);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_serial :=  @ERROR_TS_TST_INFO_get_serial;
  end;

  TS_TST_INFO_set_time := LoadLibCryptoFunction('TS_TST_INFO_set_time');
  FuncLoadError := not assigned(TS_TST_INFO_set_time);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_time :=  @ERROR_TS_TST_INFO_set_time;
  end;

  TS_TST_INFO_get_time := LoadLibCryptoFunction('TS_TST_INFO_get_time');
  FuncLoadError := not assigned(TS_TST_INFO_get_time);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_time :=  @ERROR_TS_TST_INFO_get_time;
  end;

  TS_TST_INFO_set_accuracy := LoadLibCryptoFunction('TS_TST_INFO_set_accuracy');
  FuncLoadError := not assigned(TS_TST_INFO_set_accuracy);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_accuracy :=  @ERROR_TS_TST_INFO_set_accuracy;
  end;

  TS_TST_INFO_get_accuracy := LoadLibCryptoFunction('TS_TST_INFO_get_accuracy');
  FuncLoadError := not assigned(TS_TST_INFO_get_accuracy);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_accuracy :=  @ERROR_TS_TST_INFO_get_accuracy;
  end;

  TS_ACCURACY_set_seconds := LoadLibCryptoFunction('TS_ACCURACY_set_seconds');
  FuncLoadError := not assigned(TS_ACCURACY_set_seconds);
  if FuncLoadError then
  begin
    TS_ACCURACY_set_seconds :=  @ERROR_TS_ACCURACY_set_seconds;
  end;

  TS_ACCURACY_get_seconds := LoadLibCryptoFunction('TS_ACCURACY_get_seconds');
  FuncLoadError := not assigned(TS_ACCURACY_get_seconds);
  if FuncLoadError then
  begin
    TS_ACCURACY_get_seconds :=  @ERROR_TS_ACCURACY_get_seconds;
  end;

  TS_ACCURACY_set_millis := LoadLibCryptoFunction('TS_ACCURACY_set_millis');
  FuncLoadError := not assigned(TS_ACCURACY_set_millis);
  if FuncLoadError then
  begin
    TS_ACCURACY_set_millis :=  @ERROR_TS_ACCURACY_set_millis;
  end;

  TS_ACCURACY_get_millis := LoadLibCryptoFunction('TS_ACCURACY_get_millis');
  FuncLoadError := not assigned(TS_ACCURACY_get_millis);
  if FuncLoadError then
  begin
    TS_ACCURACY_get_millis :=  @ERROR_TS_ACCURACY_get_millis;
  end;

  TS_ACCURACY_set_micros := LoadLibCryptoFunction('TS_ACCURACY_set_micros');
  FuncLoadError := not assigned(TS_ACCURACY_set_micros);
  if FuncLoadError then
  begin
    TS_ACCURACY_set_micros :=  @ERROR_TS_ACCURACY_set_micros;
  end;

  TS_ACCURACY_get_micros := LoadLibCryptoFunction('TS_ACCURACY_get_micros');
  FuncLoadError := not assigned(TS_ACCURACY_get_micros);
  if FuncLoadError then
  begin
    TS_ACCURACY_get_micros :=  @ERROR_TS_ACCURACY_get_micros;
  end;

  TS_TST_INFO_set_ordering := LoadLibCryptoFunction('TS_TST_INFO_set_ordering');
  FuncLoadError := not assigned(TS_TST_INFO_set_ordering);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_ordering :=  @ERROR_TS_TST_INFO_set_ordering;
  end;

  TS_TST_INFO_get_ordering := LoadLibCryptoFunction('TS_TST_INFO_get_ordering');
  FuncLoadError := not assigned(TS_TST_INFO_get_ordering);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_ordering :=  @ERROR_TS_TST_INFO_get_ordering;
  end;

  TS_TST_INFO_set_nonce := LoadLibCryptoFunction('TS_TST_INFO_set_nonce');
  FuncLoadError := not assigned(TS_TST_INFO_set_nonce);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_nonce :=  @ERROR_TS_TST_INFO_set_nonce;
  end;

  TS_TST_INFO_get_nonce := LoadLibCryptoFunction('TS_TST_INFO_get_nonce');
  FuncLoadError := not assigned(TS_TST_INFO_get_nonce);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_nonce :=  @ERROR_TS_TST_INFO_get_nonce;
  end;

  TS_TST_INFO_set_tsa := LoadLibCryptoFunction('TS_TST_INFO_set_tsa');
  FuncLoadError := not assigned(TS_TST_INFO_set_tsa);
  if FuncLoadError then
  begin
    TS_TST_INFO_set_tsa :=  @ERROR_TS_TST_INFO_set_tsa;
  end;

  TS_TST_INFO_get_tsa := LoadLibCryptoFunction('TS_TST_INFO_get_tsa');
  FuncLoadError := not assigned(TS_TST_INFO_get_tsa);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_tsa :=  @ERROR_TS_TST_INFO_get_tsa;
  end;

  TS_TST_INFO_ext_free := LoadLibCryptoFunction('TS_TST_INFO_ext_free');
  FuncLoadError := not assigned(TS_TST_INFO_ext_free);
  if FuncLoadError then
  begin
    TS_TST_INFO_ext_free :=  @ERROR_TS_TST_INFO_ext_free;
  end;

  TS_TST_INFO_get_ext_count := LoadLibCryptoFunction('TS_TST_INFO_get_ext_count');
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_count);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_ext_count :=  @ERROR_TS_TST_INFO_get_ext_count;
  end;

  TS_TST_INFO_get_ext_by_NID := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_NID');
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_by_NID);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_ext_by_NID :=  @ERROR_TS_TST_INFO_get_ext_by_NID;
  end;

  TS_TST_INFO_get_ext_by_OBJ := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_OBJ');
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_by_OBJ);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_ext_by_OBJ :=  @ERROR_TS_TST_INFO_get_ext_by_OBJ;
  end;

  TS_TST_INFO_get_ext_by_critical := LoadLibCryptoFunction('TS_TST_INFO_get_ext_by_critical');
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_by_critical);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_ext_by_critical :=  @ERROR_TS_TST_INFO_get_ext_by_critical;
  end;

  TS_TST_INFO_get_ext := LoadLibCryptoFunction('TS_TST_INFO_get_ext');
  FuncLoadError := not assigned(TS_TST_INFO_get_ext);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_ext :=  @ERROR_TS_TST_INFO_get_ext;
  end;

  TS_TST_INFO_delete_ext := LoadLibCryptoFunction('TS_TST_INFO_delete_ext');
  FuncLoadError := not assigned(TS_TST_INFO_delete_ext);
  if FuncLoadError then
  begin
    TS_TST_INFO_delete_ext :=  @ERROR_TS_TST_INFO_delete_ext;
  end;

  TS_TST_INFO_add_ext := LoadLibCryptoFunction('TS_TST_INFO_add_ext');
  FuncLoadError := not assigned(TS_TST_INFO_add_ext);
  if FuncLoadError then
  begin
    TS_TST_INFO_add_ext :=  @ERROR_TS_TST_INFO_add_ext;
  end;

  TS_TST_INFO_get_ext_d2i := LoadLibCryptoFunction('TS_TST_INFO_get_ext_d2i');
  FuncLoadError := not assigned(TS_TST_INFO_get_ext_d2i);
  if FuncLoadError then
  begin
    TS_TST_INFO_get_ext_d2i :=  @ERROR_TS_TST_INFO_get_ext_d2i;
  end;

  TS_RESP_CTX_new := LoadLibCryptoFunction('TS_RESP_CTX_new');
  FuncLoadError := not assigned(TS_RESP_CTX_new);
  if FuncLoadError then
  begin
    TS_RESP_CTX_new :=  @ERROR_TS_RESP_CTX_new;
  end;

  TS_RESP_CTX_free := LoadLibCryptoFunction('TS_RESP_CTX_free');
  FuncLoadError := not assigned(TS_RESP_CTX_free);
  if FuncLoadError then
  begin
    TS_RESP_CTX_free :=  @ERROR_TS_RESP_CTX_free;
  end;

  TS_RESP_CTX_set_signer_cert := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_cert');
  FuncLoadError := not assigned(TS_RESP_CTX_set_signer_cert);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_signer_cert :=  @ERROR_TS_RESP_CTX_set_signer_cert;
  end;

  TS_RESP_CTX_set_signer_key := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_key');
  FuncLoadError := not assigned(TS_RESP_CTX_set_signer_key);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_signer_key :=  @ERROR_TS_RESP_CTX_set_signer_key;
  end;

  TS_RESP_CTX_set_signer_digest := LoadLibCryptoFunction('TS_RESP_CTX_set_signer_digest');
  FuncLoadError := not assigned(TS_RESP_CTX_set_signer_digest);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_signer_digest :=  @ERROR_TS_RESP_CTX_set_signer_digest;
  end;

  TS_RESP_CTX_set_ess_cert_id_digest := LoadLibCryptoFunction('TS_RESP_CTX_set_ess_cert_id_digest');
  FuncLoadError := not assigned(TS_RESP_CTX_set_ess_cert_id_digest);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_ess_cert_id_digest :=  @ERROR_TS_RESP_CTX_set_ess_cert_id_digest;
  end;

  TS_RESP_CTX_set_def_policy := LoadLibCryptoFunction('TS_RESP_CTX_set_def_policy');
  FuncLoadError := not assigned(TS_RESP_CTX_set_def_policy);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_def_policy :=  @ERROR_TS_RESP_CTX_set_def_policy;
  end;

  TS_RESP_CTX_add_policy := LoadLibCryptoFunction('TS_RESP_CTX_add_policy');
  FuncLoadError := not assigned(TS_RESP_CTX_add_policy);
  if FuncLoadError then
  begin
    TS_RESP_CTX_add_policy :=  @ERROR_TS_RESP_CTX_add_policy;
  end;

  TS_RESP_CTX_add_md := LoadLibCryptoFunction('TS_RESP_CTX_add_md');
  FuncLoadError := not assigned(TS_RESP_CTX_add_md);
  if FuncLoadError then
  begin
    TS_RESP_CTX_add_md :=  @ERROR_TS_RESP_CTX_add_md;
  end;

  TS_RESP_CTX_set_accuracy := LoadLibCryptoFunction('TS_RESP_CTX_set_accuracy');
  FuncLoadError := not assigned(TS_RESP_CTX_set_accuracy);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_accuracy :=  @ERROR_TS_RESP_CTX_set_accuracy;
  end;

  TS_RESP_CTX_set_clock_precision_digits := LoadLibCryptoFunction('TS_RESP_CTX_set_clock_precision_digits');
  FuncLoadError := not assigned(TS_RESP_CTX_set_clock_precision_digits);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_clock_precision_digits :=  @ERROR_TS_RESP_CTX_set_clock_precision_digits;
  end;

  TS_RESP_CTX_add_flags := LoadLibCryptoFunction('TS_RESP_CTX_add_flags');
  FuncLoadError := not assigned(TS_RESP_CTX_add_flags);
  if FuncLoadError then
  begin
    TS_RESP_CTX_add_flags :=  @ERROR_TS_RESP_CTX_add_flags;
  end;

  TS_RESP_CTX_set_serial_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_serial_cb');
  FuncLoadError := not assigned(TS_RESP_CTX_set_serial_cb);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_serial_cb :=  @ERROR_TS_RESP_CTX_set_serial_cb;
  end;

  TS_RESP_CTX_set_time_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_time_cb');
  FuncLoadError := not assigned(TS_RESP_CTX_set_time_cb);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_time_cb :=  @ERROR_TS_RESP_CTX_set_time_cb;
  end;

  TS_RESP_CTX_set_extension_cb := LoadLibCryptoFunction('TS_RESP_CTX_set_extension_cb');
  FuncLoadError := not assigned(TS_RESP_CTX_set_extension_cb);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_extension_cb :=  @ERROR_TS_RESP_CTX_set_extension_cb;
  end;

  TS_RESP_CTX_set_status_info := LoadLibCryptoFunction('TS_RESP_CTX_set_status_info');
  FuncLoadError := not assigned(TS_RESP_CTX_set_status_info);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_status_info :=  @ERROR_TS_RESP_CTX_set_status_info;
  end;

  TS_RESP_CTX_set_status_info_cond := LoadLibCryptoFunction('TS_RESP_CTX_set_status_info_cond');
  FuncLoadError := not assigned(TS_RESP_CTX_set_status_info_cond);
  if FuncLoadError then
  begin
    TS_RESP_CTX_set_status_info_cond :=  @ERROR_TS_RESP_CTX_set_status_info_cond;
  end;

  TS_RESP_CTX_add_failure_info := LoadLibCryptoFunction('TS_RESP_CTX_add_failure_info');
  FuncLoadError := not assigned(TS_RESP_CTX_add_failure_info);
  if FuncLoadError then
  begin
    TS_RESP_CTX_add_failure_info :=  @ERROR_TS_RESP_CTX_add_failure_info;
  end;

  TS_RESP_CTX_get_request := LoadLibCryptoFunction('TS_RESP_CTX_get_request');
  FuncLoadError := not assigned(TS_RESP_CTX_get_request);
  if FuncLoadError then
  begin
    TS_RESP_CTX_get_request :=  @ERROR_TS_RESP_CTX_get_request;
  end;

  TS_RESP_CTX_get_tst_info := LoadLibCryptoFunction('TS_RESP_CTX_get_tst_info');
  FuncLoadError := not assigned(TS_RESP_CTX_get_tst_info);
  if FuncLoadError then
  begin
    TS_RESP_CTX_get_tst_info :=  @ERROR_TS_RESP_CTX_get_tst_info;
  end;

  TS_RESP_create_response := LoadLibCryptoFunction('TS_RESP_create_response');
  FuncLoadError := not assigned(TS_RESP_create_response);
  if FuncLoadError then
  begin
    TS_RESP_create_response :=  @ERROR_TS_RESP_create_response;
  end;

  TS_RESP_verify_response := LoadLibCryptoFunction('TS_RESP_verify_response');
  FuncLoadError := not assigned(TS_RESP_verify_response);
  if FuncLoadError then
  begin
    TS_RESP_verify_response :=  @ERROR_TS_RESP_verify_response;
  end;

  TS_RESP_verify_token := LoadLibCryptoFunction('TS_RESP_verify_token');
  FuncLoadError := not assigned(TS_RESP_verify_token);
  if FuncLoadError then
  begin
    TS_RESP_verify_token :=  @ERROR_TS_RESP_verify_token;
  end;

  TS_VERIFY_CTX_new := LoadLibCryptoFunction('TS_VERIFY_CTX_new');
  FuncLoadError := not assigned(TS_VERIFY_CTX_new);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_new :=  @ERROR_TS_VERIFY_CTX_new;
  end;

  TS_VERIFY_CTX_init := LoadLibCryptoFunction('TS_VERIFY_CTX_init');
  FuncLoadError := not assigned(TS_VERIFY_CTX_init);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_init :=  @ERROR_TS_VERIFY_CTX_init;
  end;

  TS_VERIFY_CTX_free := LoadLibCryptoFunction('TS_VERIFY_CTX_free');
  FuncLoadError := not assigned(TS_VERIFY_CTX_free);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_free :=  @ERROR_TS_VERIFY_CTX_free;
  end;

  TS_VERIFY_CTX_cleanup := LoadLibCryptoFunction('TS_VERIFY_CTX_cleanup');
  FuncLoadError := not assigned(TS_VERIFY_CTX_cleanup);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_cleanup :=  @ERROR_TS_VERIFY_CTX_cleanup;
  end;

  TS_VERIFY_CTX_set_flags := LoadLibCryptoFunction('TS_VERIFY_CTX_set_flags');
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_flags);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_set_flags :=  @ERROR_TS_VERIFY_CTX_set_flags;
  end;

  TS_VERIFY_CTX_add_flags := LoadLibCryptoFunction('TS_VERIFY_CTX_add_flags');
  FuncLoadError := not assigned(TS_VERIFY_CTX_add_flags);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_add_flags :=  @ERROR_TS_VERIFY_CTX_add_flags;
  end;

  TS_VERIFY_CTX_set_data := LoadLibCryptoFunction('TS_VERIFY_CTX_set_data');
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_data);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_set_data :=  @ERROR_TS_VERIFY_CTX_set_data;
  end;

  TS_VERIFY_CTX_set_imprint := LoadLibCryptoFunction('TS_VERIFY_CTX_set_imprint');
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_imprint);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_set_imprint :=  @ERROR_TS_VERIFY_CTX_set_imprint;
  end;

  TS_VERIFY_CTX_set_store := LoadLibCryptoFunction('TS_VERIFY_CTX_set_store');
  FuncLoadError := not assigned(TS_VERIFY_CTX_set_store);
  if FuncLoadError then
  begin
    TS_VERIFY_CTX_set_store :=  @ERROR_TS_VERIFY_CTX_set_store;
  end;

  TS_REQ_to_TS_VERIFY_CTX := LoadLibCryptoFunction('TS_REQ_to_TS_VERIFY_CTX');
  FuncLoadError := not assigned(TS_REQ_to_TS_VERIFY_CTX);
  if FuncLoadError then
  begin
    TS_REQ_to_TS_VERIFY_CTX :=  @ERROR_TS_REQ_to_TS_VERIFY_CTX;
  end;

  TS_RESP_print_bio := LoadLibCryptoFunction('TS_RESP_print_bio');
  FuncLoadError := not assigned(TS_RESP_print_bio);
  if FuncLoadError then
  begin
    TS_RESP_print_bio :=  @ERROR_TS_RESP_print_bio;
  end;

  TS_STATUS_INFO_print_bio := LoadLibCryptoFunction('TS_STATUS_INFO_print_bio');
  FuncLoadError := not assigned(TS_STATUS_INFO_print_bio);
  if FuncLoadError then
  begin
    TS_STATUS_INFO_print_bio :=  @ERROR_TS_STATUS_INFO_print_bio;
  end;

  TS_TST_INFO_print_bio := LoadLibCryptoFunction('TS_TST_INFO_print_bio');
  FuncLoadError := not assigned(TS_TST_INFO_print_bio);
  if FuncLoadError then
  begin
    TS_TST_INFO_print_bio :=  @ERROR_TS_TST_INFO_print_bio;
  end;

  TS_ASN1_INTEGER_print_bio := LoadLibCryptoFunction('TS_ASN1_INTEGER_print_bio');
  FuncLoadError := not assigned(TS_ASN1_INTEGER_print_bio);
  if FuncLoadError then
  begin
    TS_ASN1_INTEGER_print_bio :=  @ERROR_TS_ASN1_INTEGER_print_bio;
  end;

  TS_OBJ_print_bio := LoadLibCryptoFunction('TS_OBJ_print_bio');
  FuncLoadError := not assigned(TS_OBJ_print_bio);
  if FuncLoadError then
  begin
    TS_OBJ_print_bio :=  @ERROR_TS_OBJ_print_bio;
  end;

  TS_X509_ALGOR_print_bio := LoadLibCryptoFunction('TS_X509_ALGOR_print_bio');
  FuncLoadError := not assigned(TS_X509_ALGOR_print_bio);
  if FuncLoadError then
  begin
    TS_X509_ALGOR_print_bio :=  @ERROR_TS_X509_ALGOR_print_bio;
  end;

  TS_MSG_IMPRINT_print_bio := LoadLibCryptoFunction('TS_MSG_IMPRINT_print_bio');
  FuncLoadError := not assigned(TS_MSG_IMPRINT_print_bio);
  if FuncLoadError then
  begin
    TS_MSG_IMPRINT_print_bio :=  @ERROR_TS_MSG_IMPRINT_print_bio;
  end;

  TS_CONF_load_cert := LoadLibCryptoFunction('TS_CONF_load_cert');
  FuncLoadError := not assigned(TS_CONF_load_cert);
  if FuncLoadError then
  begin
    TS_CONF_load_cert :=  @ERROR_TS_CONF_load_cert;
  end;

  TS_CONF_load_key := LoadLibCryptoFunction('TS_CONF_load_key');
  FuncLoadError := not assigned(TS_CONF_load_key);
  if FuncLoadError then
  begin
    TS_CONF_load_key :=  @ERROR_TS_CONF_load_key;
  end;

  TS_CONF_set_serial := LoadLibCryptoFunction('TS_CONF_set_serial');
  FuncLoadError := not assigned(TS_CONF_set_serial);
  if FuncLoadError then
  begin
    TS_CONF_set_serial :=  @ERROR_TS_CONF_set_serial;
  end;

  TS_CONF_get_tsa_section := LoadLibCryptoFunction('TS_CONF_get_tsa_section');
  FuncLoadError := not assigned(TS_CONF_get_tsa_section);
  if FuncLoadError then
  begin
    TS_CONF_get_tsa_section :=  @ERROR_TS_CONF_get_tsa_section;
  end;

  TS_CONF_set_crypto_device := LoadLibCryptoFunction('TS_CONF_set_crypto_device');
  FuncLoadError := not assigned(TS_CONF_set_crypto_device);
  if FuncLoadError then
  begin
    TS_CONF_set_crypto_device :=  @ERROR_TS_CONF_set_crypto_device;
  end;

  TS_CONF_set_default_engine := LoadLibCryptoFunction('TS_CONF_set_default_engine');
  FuncLoadError := not assigned(TS_CONF_set_default_engine);
  if FuncLoadError then
  begin
    TS_CONF_set_default_engine :=  @ERROR_TS_CONF_set_default_engine;
  end;

  TS_CONF_set_signer_cert := LoadLibCryptoFunction('TS_CONF_set_signer_cert');
  FuncLoadError := not assigned(TS_CONF_set_signer_cert);
  if FuncLoadError then
  begin
    TS_CONF_set_signer_cert :=  @ERROR_TS_CONF_set_signer_cert;
  end;

  TS_CONF_set_certs := LoadLibCryptoFunction('TS_CONF_set_certs');
  FuncLoadError := not assigned(TS_CONF_set_certs);
  if FuncLoadError then
  begin
    TS_CONF_set_certs :=  @ERROR_TS_CONF_set_certs;
  end;

  TS_CONF_set_signer_key := LoadLibCryptoFunction('TS_CONF_set_signer_key');
  FuncLoadError := not assigned(TS_CONF_set_signer_key);
  if FuncLoadError then
  begin
    TS_CONF_set_signer_key :=  @ERROR_TS_CONF_set_signer_key;
  end;

  TS_CONF_set_signer_digest := LoadLibCryptoFunction('TS_CONF_set_signer_digest');
  FuncLoadError := not assigned(TS_CONF_set_signer_digest);
  if FuncLoadError then
  begin
    TS_CONF_set_signer_digest :=  @ERROR_TS_CONF_set_signer_digest;
  end;

  TS_CONF_set_def_policy := LoadLibCryptoFunction('TS_CONF_set_def_policy');
  FuncLoadError := not assigned(TS_CONF_set_def_policy);
  if FuncLoadError then
  begin
    TS_CONF_set_def_policy :=  @ERROR_TS_CONF_set_def_policy;
  end;

  TS_CONF_set_policies := LoadLibCryptoFunction('TS_CONF_set_policies');
  FuncLoadError := not assigned(TS_CONF_set_policies);
  if FuncLoadError then
  begin
    TS_CONF_set_policies :=  @ERROR_TS_CONF_set_policies;
  end;

  TS_CONF_set_digests := LoadLibCryptoFunction('TS_CONF_set_digests');
  FuncLoadError := not assigned(TS_CONF_set_digests);
  if FuncLoadError then
  begin
    TS_CONF_set_digests :=  @ERROR_TS_CONF_set_digests;
  end;

  TS_CONF_set_accuracy := LoadLibCryptoFunction('TS_CONF_set_accuracy');
  FuncLoadError := not assigned(TS_CONF_set_accuracy);
  if FuncLoadError then
  begin
    TS_CONF_set_accuracy :=  @ERROR_TS_CONF_set_accuracy;
  end;

  TS_CONF_set_clock_precision_digits := LoadLibCryptoFunction('TS_CONF_set_clock_precision_digits');
  FuncLoadError := not assigned(TS_CONF_set_clock_precision_digits);
  if FuncLoadError then
  begin
    TS_CONF_set_clock_precision_digits :=  @ERROR_TS_CONF_set_clock_precision_digits;
  end;

  TS_CONF_set_ordering := LoadLibCryptoFunction('TS_CONF_set_ordering');
  FuncLoadError := not assigned(TS_CONF_set_ordering);
  if FuncLoadError then
  begin
    TS_CONF_set_ordering :=  @ERROR_TS_CONF_set_ordering;
  end;

  TS_CONF_set_tsa_name := LoadLibCryptoFunction('TS_CONF_set_tsa_name');
  FuncLoadError := not assigned(TS_CONF_set_tsa_name);
  if FuncLoadError then
  begin
    TS_CONF_set_tsa_name :=  @ERROR_TS_CONF_set_tsa_name;
  end;

  TS_CONF_set_ess_cert_id_chain := LoadLibCryptoFunction('TS_CONF_set_ess_cert_id_chain');
  FuncLoadError := not assigned(TS_CONF_set_ess_cert_id_chain);
  if FuncLoadError then
  begin
    TS_CONF_set_ess_cert_id_chain :=  @ERROR_TS_CONF_set_ess_cert_id_chain;
  end;

  TS_CONF_set_ess_cert_id_digest := LoadLibCryptoFunction('TS_CONF_set_ess_cert_id_digest');
  FuncLoadError := not assigned(TS_CONF_set_ess_cert_id_digest);
  if FuncLoadError then
  begin
    TS_CONF_set_ess_cert_id_digest :=  @ERROR_TS_CONF_set_ess_cert_id_digest;
  end;

end;

procedure UnLoad;
begin
  TS_REQ_new := nil;
  TS_REQ_free := nil;
  i2d_TS_REQ := nil;
  d2i_TS_REQ := nil;
  TS_REQ_dup := nil;
  d2i_TS_REQ_bio := nil;
  i2d_TS_REQ_bio := nil;
  TS_MSG_IMPRINT_new := nil;
  TS_MSG_IMPRINT_free := nil;
  i2d_TS_MSG_IMPRINT := nil;
  d2i_TS_MSG_IMPRINT := nil;
  TS_MSG_IMPRINT_dup := nil;
  d2i_TS_MSG_IMPRINT_bio := nil;
  i2d_TS_MSG_IMPRINT_bio := nil;
  TS_RESP_new := nil;
  TS_RESP_free := nil;
  i2d_TS_RESP := nil;
  d2i_TS_RESP := nil;
  PKCS7_to_TS_TST_INFO := nil;
  TS_RESP_dup := nil;
  d2i_TS_RESP_bio := nil;
  i2d_TS_RESP_bio := nil;
  TS_STATUS_INFO_new := nil;
  TS_STATUS_INFO_free := nil;
  i2d_TS_STATUS_INFO := nil;
  d2i_TS_STATUS_INFO := nil;
  TS_STATUS_INFO_dup := nil;
  TS_TST_INFO_new := nil;
  TS_TST_INFO_free := nil;
  i2d_TS_TST_INFO := nil;
  d2i_TS_TST_INFO := nil;
  TS_TST_INFO_dup := nil;
  d2i_TS_TST_INFO_bio := nil;
  i2d_TS_TST_INFO_bio := nil;
  TS_ACCURACY_new := nil;
  TS_ACCURACY_free := nil;
  i2d_TS_ACCURACY := nil;
  d2i_TS_ACCURACY := nil;
  TS_ACCURACY_dup := nil;
  ESS_ISSUER_SERIAL_new := nil;
  ESS_ISSUER_SERIAL_free := nil;
  i2d_ESS_ISSUER_SERIAL := nil;
  d2i_ESS_ISSUER_SERIAL := nil;
  ESS_ISSUER_SERIAL_dup := nil;
  ESS_CERT_ID_new := nil;
  ESS_CERT_ID_free := nil;
  i2d_ESS_CERT_ID := nil;
  d2i_ESS_CERT_ID := nil;
  ESS_CERT_ID_dup := nil;
  ESS_SIGNING_CERT_new := nil;
  ESS_SIGNING_CERT_free := nil;
  i2d_ESS_SIGNING_CERT := nil;
  d2i_ESS_SIGNING_CERT := nil;
  ESS_SIGNING_CERT_dup := nil;
  ESS_CERT_ID_V2_new := nil;
  ESS_CERT_ID_V2_free := nil;
  i2d_ESS_CERT_ID_V2 := nil;
  d2i_ESS_CERT_ID_V2 := nil;
  ESS_CERT_ID_V2_dup := nil;
  ESS_SIGNING_CERT_V2_new := nil;
  ESS_SIGNING_CERT_V2_free := nil;
  i2d_ESS_SIGNING_CERT_V2 := nil;
  d2i_ESS_SIGNING_CERT_V2 := nil;
  ESS_SIGNING_CERT_V2_dup := nil;
  TS_REQ_set_version := nil;
  TS_REQ_get_version := nil;
  TS_STATUS_INFO_set_status := nil;
  TS_STATUS_INFO_get0_status := nil;
  TS_REQ_set_msg_imprint := nil;
  TS_REQ_get_msg_imprint := nil;
  TS_MSG_IMPRINT_set_algo := nil;
  TS_MSG_IMPRINT_get_algo := nil;
  TS_MSG_IMPRINT_set_msg := nil;
  TS_MSG_IMPRINT_get_msg := nil;
  TS_REQ_set_policy_id := nil;
  TS_REQ_get_policy_id := nil;
  TS_REQ_set_nonce := nil;
  TS_REQ_get_nonce := nil;
  TS_REQ_set_cert_req := nil;
  TS_REQ_get_cert_req := nil;
  TS_REQ_ext_free := nil;
  TS_REQ_get_ext_count := nil;
  TS_REQ_get_ext_by_NID := nil;
  TS_REQ_get_ext_by_OBJ := nil;
  TS_REQ_get_ext_by_critical := nil;
  TS_REQ_get_ext := nil;
  TS_REQ_delete_ext := nil;
  TS_REQ_add_ext := nil;
  TS_REQ_get_ext_d2i := nil;
  TS_REQ_print_bio := nil;
  TS_RESP_set_status_info := nil;
  TS_RESP_get_status_info := nil;
  TS_RESP_set_tst_info := nil;
  TS_RESP_get_token := nil;
  TS_RESP_get_tst_info := nil;
  TS_TST_INFO_set_version := nil;
  TS_TST_INFO_get_version := nil;
  TS_TST_INFO_set_policy_id := nil;
  TS_TST_INFO_get_policy_id := nil;
  TS_TST_INFO_set_msg_imprint := nil;
  TS_TST_INFO_get_msg_imprint := nil;
  TS_TST_INFO_set_serial := nil;
  TS_TST_INFO_get_serial := nil;
  TS_TST_INFO_set_time := nil;
  TS_TST_INFO_get_time := nil;
  TS_TST_INFO_set_accuracy := nil;
  TS_TST_INFO_get_accuracy := nil;
  TS_ACCURACY_set_seconds := nil;
  TS_ACCURACY_get_seconds := nil;
  TS_ACCURACY_set_millis := nil;
  TS_ACCURACY_get_millis := nil;
  TS_ACCURACY_set_micros := nil;
  TS_ACCURACY_get_micros := nil;
  TS_TST_INFO_set_ordering := nil;
  TS_TST_INFO_get_ordering := nil;
  TS_TST_INFO_set_nonce := nil;
  TS_TST_INFO_get_nonce := nil;
  TS_TST_INFO_set_tsa := nil;
  TS_TST_INFO_get_tsa := nil;
  TS_TST_INFO_ext_free := nil;
  TS_TST_INFO_get_ext_count := nil;
  TS_TST_INFO_get_ext_by_NID := nil;
  TS_TST_INFO_get_ext_by_OBJ := nil;
  TS_TST_INFO_get_ext_by_critical := nil;
  TS_TST_INFO_get_ext := nil;
  TS_TST_INFO_delete_ext := nil;
  TS_TST_INFO_add_ext := nil;
  TS_TST_INFO_get_ext_d2i := nil;
  TS_RESP_CTX_new := nil;
  TS_RESP_CTX_free := nil;
  TS_RESP_CTX_set_signer_cert := nil;
  TS_RESP_CTX_set_signer_key := nil;
  TS_RESP_CTX_set_signer_digest := nil;
  TS_RESP_CTX_set_ess_cert_id_digest := nil;
  TS_RESP_CTX_set_def_policy := nil;
  TS_RESP_CTX_add_policy := nil;
  TS_RESP_CTX_add_md := nil;
  TS_RESP_CTX_set_accuracy := nil;
  TS_RESP_CTX_set_clock_precision_digits := nil;
  TS_RESP_CTX_add_flags := nil;
  TS_RESP_CTX_set_serial_cb := nil;
  TS_RESP_CTX_set_time_cb := nil;
  TS_RESP_CTX_set_extension_cb := nil;
  TS_RESP_CTX_set_status_info := nil;
  TS_RESP_CTX_set_status_info_cond := nil;
  TS_RESP_CTX_add_failure_info := nil;
  TS_RESP_CTX_get_request := nil;
  TS_RESP_CTX_get_tst_info := nil;
  TS_RESP_create_response := nil;
  TS_RESP_verify_response := nil;
  TS_RESP_verify_token := nil;
  TS_VERIFY_CTX_new := nil;
  TS_VERIFY_CTX_init := nil;
  TS_VERIFY_CTX_free := nil;
  TS_VERIFY_CTX_cleanup := nil;
  TS_VERIFY_CTX_set_flags := nil;
  TS_VERIFY_CTX_add_flags := nil;
  TS_VERIFY_CTX_set_data := nil;
  TS_VERIFY_CTX_set_imprint := nil;
  TS_VERIFY_CTX_set_store := nil;
  TS_REQ_to_TS_VERIFY_CTX := nil;
  TS_RESP_print_bio := nil;
  TS_STATUS_INFO_print_bio := nil;
  TS_TST_INFO_print_bio := nil;
  TS_ASN1_INTEGER_print_bio := nil;
  TS_OBJ_print_bio := nil;
  TS_X509_ALGOR_print_bio := nil;
  TS_MSG_IMPRINT_print_bio := nil;
  TS_CONF_load_cert := nil;
  TS_CONF_load_key := nil;
  TS_CONF_set_serial := nil;
  TS_CONF_get_tsa_section := nil;
  TS_CONF_set_crypto_device := nil;
  TS_CONF_set_default_engine := nil;
  TS_CONF_set_signer_cert := nil;
  TS_CONF_set_certs := nil;
  TS_CONF_set_signer_key := nil;
  TS_CONF_set_signer_digest := nil;
  TS_CONF_set_def_policy := nil;
  TS_CONF_set_policies := nil;
  TS_CONF_set_digests := nil;
  TS_CONF_set_accuracy := nil;
  TS_CONF_set_clock_precision_digits := nil;
  TS_CONF_set_ordering := nil;
  TS_CONF_set_tsa_name := nil;
  TS_CONF_set_ess_cert_id_chain := nil;
  TS_CONF_set_ess_cert_id_digest := nil;
end;
{$ENDIF}

initialization

{$IFNDEF OPENSSL_STATIC_LINK_MODEL}
Register_SSLLoader(@Load);
Register_SSLUnloader(@Unload);
{$ENDIF}
finalization


end.
